use super::event::{ApiEvent, EventType, Item, PollEventsResponse};
use super::limits::StreamLimits;
use super::source::{ApiChannelBackend, BackendError, PollEventsSource, TickingNotifier};
use super::sse::{ApiChannelState, SseBody, SseConfig, StreamRequest, event_frame, handle_stream};
use super::stream_conversation_id;
use crate::notifier::{ActivityNotifier, InMemoryNotifier, NotifyEvent};
use crate::websocket::pump::{ActivitySource, Pump, PumpFrame};
use async_trait::async_trait;
use http_body_util::BodyExt;
use hyper::StatusCode;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// A conversation log held in memory. `retained_from` models a trimmed log.
struct FakeBackend {
    events: Mutex<Vec<ApiEvent>>,
    retained_from: Mutex<u64>,
    authorized: bool,
    polls: AtomicUsize,
}

impl FakeBackend {
    fn new(authorized: bool) -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            retained_from: Mutex::new(0),
            authorized,
            polls: AtomicUsize::new(0),
        })
    }

    fn append(&self, text: &str) -> u64 {
        let mut events = self.events.lock().expect("lock");
        let cursor = events.last().map(|e| e.cursor + 1).unwrap_or(0);
        events.push(ApiEvent {
            cursor,
            kind: EventType::Message,
            items: vec![Item::Text { text: text.into() }],
            ts: "2026-10-14T10:00:00Z".into(),
            code: None,
        });
        cursor
    }

    fn trim_before(&self, cursor: u64) {
        *self.retained_from.lock().expect("lock") = cursor;
        self.events
            .lock()
            .expect("lock")
            .retain(|e| e.cursor >= cursor);
    }
}

#[async_trait]
impl ApiChannelBackend for FakeBackend {
    async fn authorize(&self) -> Result<(), BackendError> {
        if self.authorized {
            Ok(())
        } else {
            Err(BackendError::Unauthorized)
        }
    }

    async fn poll_events(
        &self,
        _conversation_id: &str,
        since: u64,
    ) -> Result<PollEventsResponse, BackendError> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        let events = self.events.lock().expect("lock");
        let next_cursor = events.last().map(|e| e.cursor + 1).unwrap_or(0);
        Ok(PollEventsResponse {
            events: events
                .iter()
                .filter(|e| e.cursor >= since)
                .cloned()
                .collect(),
            next_cursor,
        })
    }
}

fn state(config: SseConfig, max_streams: usize) -> (ApiChannelState, Arc<InMemoryNotifier>) {
    let notifier = Arc::new(InMemoryNotifier::new(16));
    (
        ApiChannelState {
            notifier: notifier.clone(),
            limits: Arc::new(StreamLimits::new(max_streams)),
            config,
        },
        notifier,
    )
}

fn fast_config() -> SseConfig {
    SseConfig {
        heartbeat: Duration::from_secs(15),
        max_lifetime: Duration::from_secs(300),
        poll_interval: Duration::from_secs(3600),
        max_replay: 1000,
    }
}

fn request(token: Option<&str>, last_event_id: Option<&str>) -> StreamRequest {
    StreamRequest {
        tenant_id: "t1".into(),
        conversation_id: "c1".into(),
        bearer: token.map(str::to_string),
        last_event_id: last_event_id.map(str::to_string),
    }
}

async fn next_chunk(body: &mut SseBody) -> Option<String> {
    let frame = tokio::time::timeout(Duration::from_secs(60), body.frame())
        .await
        .expect("a frame arrives in time")?
        .expect("infallible");
    frame
        .into_data()
        .ok()
        .map(|b| String::from_utf8(b.to_vec()).expect("utf8"))
}

// --- the transport-neutrality proof -------------------------------------

#[tokio::test]
async fn pump_drives_an_sse_style_consumer_through_the_poll_events_source() {
    let backend = FakeBackend::new(true);
    backend.append("a");
    backend.append("b");
    let source: Arc<dyn ActivitySource> = Arc::new(PollEventsSource {
        backend: backend.clone(),
    });
    let notifier = Arc::new(InMemoryNotifier::new(8));
    let pump = Pump::new(source, notifier.clone(), 1000);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let task = tokio::spawn(async move { pump.run("t1".into(), "c1".into(), 0, tx).await });

    let Some(PumpFrame::Activities {
        activities,
        next_watermark,
    }) = rx.recv().await
    else {
        panic!("expected the replay");
    };
    assert_eq!(activities.len(), 2);
    assert_eq!(next_watermark, 2);

    let cursor = backend.append("c");
    notifier
        .publish(NotifyEvent {
            tenant_id: "t1".into(),
            conversation_id: "c1".into(),
            new_watermark: cursor + 1,
        })
        .await;
    let Some(PumpFrame::Activities { activities, .. }) = rx.recv().await else {
        panic!("expected the live event");
    };
    // Exactly the new event: the `channelData.watermark` stamp is what keeps
    // the pump's live filter from re-sending the previous one.
    assert_eq!(activities.len(), 1);
    assert_eq!(activities[0]["items"][0]["text"], "c");
    task.abort();
}

// --- the SSE route -------------------------------------------------------

#[tokio::test]
async fn an_event_frame_matches_the_shared_fixture_byte_for_byte() {
    let raw = std::fs::read_to_string(format!(
        "{}/docs/fixtures/api-channel/message.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture");
    let data = raw.trim_end_matches('\n');
    let event: ApiEvent = serde_json::from_str(data).expect("parse");
    assert_eq!(
        event_frame(&event).expect("frame"),
        format!("id: 7\nevent: message\ndata: {data}\n\n")
    );
}

#[tokio::test]
async fn a_fresh_stream_replays_the_log_then_pushes_live_events() {
    let backend = FakeBackend::new(true);
    backend.append("one");
    let (state, notifier) = state(fast_config(), 4);
    let response = handle_stream(request(Some("k"), None), backend.clone(), &state).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let mut body = response.into_body();

    let first = next_chunk(&mut body).await.expect("replay frame");
    assert!(first.starts_with("id: 0\nevent: message\n"), "{first}");

    let cursor = backend.append("two");
    notifier
        .publish(NotifyEvent {
            tenant_id: "t1".into(),
            conversation_id: "c1".into(),
            new_watermark: cursor + 1,
        })
        .await;
    let second = next_chunk(&mut body).await.expect("live frame");
    assert!(second.starts_with("id: 1\n"), "{second}");
}

#[tokio::test]
async fn last_event_id_resumes_after_the_cursor_without_repeating_it() {
    let backend = FakeBackend::new(true);
    for text in ["a", "b", "c"] {
        backend.append(text);
    }
    let (state, _n) = state(fast_config(), 4);
    let response = handle_stream(request(Some("k"), Some("1")), backend, &state).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let first = next_chunk(&mut body).await.expect("frame");
    assert!(
        first.starts_with("id: 2\n"),
        "resume must start at cursor+1: {first}"
    );
}

#[tokio::test]
async fn a_cursor_older_than_the_retained_log_is_gone_with_the_oldest_cursor() {
    let backend = FakeBackend::new(true);
    for text in ["a", "b", "c", "d"] {
        backend.append(text);
    }
    backend.trim_before(3);
    let (state, _n) = state(fast_config(), 4);
    let response = handle_stream(request(Some("k"), Some("0")), backend, &state).await;
    assert_eq!(response.status(), StatusCode::GONE);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(json["error"]["oldest_cursor"], 3);
}

#[tokio::test]
async fn a_stream_without_last_event_id_starts_at_the_oldest_retained_event() {
    let backend = FakeBackend::new(true);
    for text in ["a", "b", "c", "d"] {
        backend.append(text);
    }
    backend.trim_before(3);
    let (state, _n) = state(fast_config(), 4);
    let response = handle_stream(request(Some("k"), None), backend, &state).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    assert!(
        next_chunk(&mut body)
            .await
            .expect("frame")
            .starts_with("id: 3\n")
    );
}

#[tokio::test]
async fn a_malformed_last_event_id_is_a_bad_request() {
    let backend = FakeBackend::new(true);
    let (state, _n) = state(fast_config(), 4);
    let response = handle_stream(request(Some("k"), Some("abc")), backend, &state).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_or_refused_credentials_are_401_before_the_log_is_read() {
    let (state, _n) = state(fast_config(), 4);
    let backend = FakeBackend::new(true);
    let missing = handle_stream(request(None, None), backend.clone(), &state).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let refused_backend = FakeBackend::new(false);
    let refused = handle_stream(
        request(Some("wrong"), None),
        refused_backend.clone(),
        &state,
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let body = refused
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert!(body.is_empty(), "a 401 carries no detail");
    assert_eq!(backend.polls.load(Ordering::SeqCst), 0);
    assert_eq!(refused_backend.polls.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_quiet_stream_sends_a_heartbeat_comment() {
    let backend = FakeBackend::new(true);
    let (state, _n) = state(fast_config(), 4);
    let response = handle_stream(request(Some("k"), None), backend, &state).await;
    let mut body = response.into_body();
    assert_eq!(
        next_chunk(&mut body).await.as_deref(),
        Some(": keep-alive\n\n")
    );
}

#[tokio::test(start_paused = true)]
async fn a_stream_ends_after_its_bounded_lifetime() {
    let backend = FakeBackend::new(true);
    let config = SseConfig {
        max_lifetime: Duration::from_secs(20),
        ..fast_config()
    };
    let (state, _n) = state(config, 4);
    let response = handle_stream(request(Some("k"), None), backend, &state).await;
    let mut body = response.into_body();
    assert_eq!(
        next_chunk(&mut body).await.as_deref(),
        Some(": keep-alive\n\n")
    );
    assert_eq!(next_chunk(&mut body).await, None, "the stream must end");
}

#[tokio::test]
async fn a_disconnect_releases_the_slot_and_stops_polling() {
    let backend = FakeBackend::new(true);
    let config = SseConfig {
        poll_interval: Duration::from_millis(10),
        ..fast_config()
    };
    let (state, _n) = state(config, 1);
    let response = handle_stream(request(Some("k"), None), backend.clone(), &state).await;
    assert_eq!(response.status(), StatusCode::OK);

    // The only slot is held by the live stream.
    let refused = handle_stream(request(Some("k"), None), backend.clone(), &state).await;
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);

    drop(response); // the client disconnects
    tokio::time::sleep(Duration::from_millis(100)).await;
    let polls = backend.polls.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        backend.polls.load(Ordering::SeqCst),
        polls,
        "the pump task must stop polling after the disconnect"
    );

    // The slot is free again.
    let again = handle_stream(request(Some("k"), None), backend, &state).await;
    assert_eq!(again.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_ticking_notifier_delivers_events_nobody_published() {
    let backend = FakeBackend::new(true);
    let source: Arc<dyn ActivitySource> = Arc::new(PollEventsSource {
        backend: backend.clone(),
    });
    let notifier: Arc<dyn ActivityNotifier> = Arc::new(TickingNotifier {
        inner: Arc::new(InMemoryNotifier::new(8)),
        period: Duration::from_millis(10),
    });
    let pump = Pump::new(source, notifier, 1000);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let task = tokio::spawn(async move { pump.run("t1".into(), "c1".into(), 0, tx).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    backend.append("late");
    let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("a tick wakes the pump")
        .expect("frame");
    let PumpFrame::Activities { activities, .. } = frame else {
        panic!("expected activities");
    };
    assert_eq!(activities.len(), 1);
    task.abort();
}

#[test]
fn only_non_directline_stream_paths_belong_to_the_api_channel() {
    assert_eq!(
        stream_conversation_id("/v1/messaging/api/t1/conversations/abc/stream"),
        Some("abc".into())
    );
    assert_eq!(
        stream_conversation_id("/v1/messaging/webchat/t1/v3/directline/conversations/abc/stream"),
        None
    );
    assert_eq!(stream_conversation_id("/conversations/abc/messages"), None);
}
