//! Cursor boundaries against a backend that follows the `messaging-api`
//! pack's exact `poll_events` rules: cursors start at 1, `since = 0` means
//! everything retained, `next_cursor` is the last returned cursor + 1 (or
//! `since` when nothing is returned), and a nonzero `since` older than the
//! oldest retained cursor is `cursor_expired`.
//!
//! The wire rule under test: `Last-Event-ID: N` resumes at `N + 1`, every
//! event reaches the client exactly once, and none is skipped.

use super::event::{ApiEvent, EventType, Item, PollEventsResponse};
use super::limits::StreamLimits;
use super::source::{ApiChannelBackend, BackendError, parse_poll_output};
use super::sse::{ApiChannelState, SseBody, SseConfig, StreamRequest, handle_stream};
use crate::notifier::{ActivityNotifier, InMemoryNotifier, NotifyEvent};
use async_trait::async_trait;
use http_body_util::BodyExt;
use hyper::StatusCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct PackLikeBackend {
    events: Mutex<Vec<ApiEvent>>,
    oldest: Mutex<u64>,
}

impl PackLikeBackend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            oldest: Mutex::new(1),
        })
    }

    fn append(&self, text: &str) -> u64 {
        let mut events = self.events.lock().expect("lock");
        let cursor = events.last().map(|e| e.cursor + 1).unwrap_or(1);
        events.push(ApiEvent {
            cursor,
            kind: EventType::Message,
            code: None,
            items: vec![Item::Text { text: text.into() }],
            ts: "2026-10-14T10:00:00Z".into(),
        });
        cursor
    }

    fn trim_before(&self, cursor: u64) {
        *self.oldest.lock().expect("lock") = cursor;
        self.events
            .lock()
            .expect("lock")
            .retain(|e| e.cursor >= cursor);
    }
}

#[async_trait]
impl ApiChannelBackend for PackLikeBackend {
    async fn authorize(&self) -> Result<(), BackendError> {
        Ok(())
    }

    async fn poll_events(
        &self,
        _conversation_id: &str,
        since: u64,
    ) -> Result<PollEventsResponse, BackendError> {
        let oldest = *self.oldest.lock().expect("lock");
        if since != 0 && since < oldest {
            // The same shape the pack emits, through the real decoder.
            return parse_poll_output(serde_json::json!({
                "error": {"code": "cursor_expired", "oldest_cursor": oldest}
            }));
        }
        let start = since.max(oldest);
        let events: Vec<ApiEvent> = self
            .events
            .lock()
            .expect("lock")
            .iter()
            .filter(|e| e.cursor >= start)
            .cloned()
            .collect();
        let next_cursor = events.last().map(|e| e.cursor + 1).unwrap_or(start);
        Ok(PollEventsResponse {
            events,
            next_cursor,
        })
    }
}

fn state() -> (ApiChannelState, Arc<InMemoryNotifier>) {
    let notifier = Arc::new(InMemoryNotifier::new(16));
    (
        ApiChannelState {
            notifier: notifier.clone(),
            limits: Arc::new(StreamLimits::new(4)),
            config: SseConfig {
                heartbeat: Duration::from_secs(3600),
                max_lifetime: Duration::from_secs(3600),
                poll_interval: Duration::from_secs(3600),
                max_replay: 1000,
            },
        },
        notifier,
    )
}

fn request(last_event_id: Option<&str>) -> StreamRequest {
    StreamRequest {
        tenant_id: "t1".into(),
        conversation_id: "c1".into(),
        bearer: Some("k".into()),
        last_event_id: last_event_id.map(str::to_string),
    }
}

async fn wake(notifier: &InMemoryNotifier, cursor: u64) {
    notifier
        .publish(NotifyEvent {
            tenant_id: "t1".into(),
            conversation_id: "c1".into(),
            new_watermark: cursor + 1,
        })
        .await;
}

async fn open(
    backend: &Arc<PackLikeBackend>,
    state: &ApiChannelState,
    last_event_id: Option<&str>,
) -> SseBody {
    let response = handle_stream(request(last_event_id), backend.clone(), state).await;
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body()
}

/// The SSE `id:` of the next frame.
async fn next_id(body: &mut SseBody) -> u64 {
    let frame = tokio::time::timeout(Duration::from_secs(60), body.frame())
        .await
        .expect("a frame arrives in time")
        .expect("the body is still open")
        .expect("infallible");
    let text = String::from_utf8(frame.into_data().expect("data").to_vec()).expect("utf8");
    text.strip_prefix("id: ")
        .and_then(|rest| rest.split('\n').next())
        .and_then(|id| id.parse().ok())
        .unwrap_or_else(|| panic!("not an event frame: {text}"))
}

/// Nothing is sent within a short window.
async fn assert_quiet(body: &mut SseBody) {
    let waited = tokio::time::timeout(Duration::from_millis(300), body.frame()).await;
    assert!(waited.is_err(), "unexpected frame: {waited:?}");
}

#[tokio::test]
async fn first_poll_of_an_empty_log_sends_each_later_event_once() {
    let backend = PackLikeBackend::new();
    let (state, notifier) = state();
    let mut body = open(&backend, &state, None).await;
    assert_quiet(&mut body).await;

    let first = backend.append("a");
    wake(&notifier, first).await;
    assert_eq!(next_id(&mut body).await, 1);

    let second = backend.append("b");
    wake(&notifier, second).await;
    assert_eq!(next_id(&mut body).await, 2);
    // A wake-up with nothing new must not repeat the last event.
    wake(&notifier, second).await;
    assert_quiet(&mut body).await;
}

#[tokio::test]
async fn first_poll_replays_everything_retained_in_order() {
    let backend = PackLikeBackend::new();
    for text in ["a", "b", "c"] {
        backend.append(text);
    }
    let (state, _n) = state();
    let mut body = open(&backend, &state, None).await;
    assert_eq!(next_id(&mut body).await, 1);
    assert_eq!(next_id(&mut body).await, 2);
    assert_eq!(next_id(&mut body).await, 3);
}

#[tokio::test]
async fn resume_continues_at_last_event_id_plus_one_then_goes_live() {
    let backend = PackLikeBackend::new();
    for text in ["a", "b", "c"] {
        backend.append(text);
    }
    let (state, notifier) = state();
    let mut body = open(&backend, &state, Some("2")).await;
    assert_eq!(next_id(&mut body).await, 3, "no skip, no repeat of 2");
    assert_quiet(&mut body).await;

    let live = backend.append("d");
    wake(&notifier, live).await;
    assert_eq!(next_id(&mut body).await, 4, "3 must not be sent twice");
}

#[tokio::test]
async fn resume_with_nothing_new_is_quiet_then_delivers_the_next_event() {
    let backend = PackLikeBackend::new();
    for text in ["a", "b", "c"] {
        backend.append(text);
    }
    let (state, notifier) = state();
    let mut body = open(&backend, &state, Some("3")).await;
    assert_quiet(&mut body).await;
    wake(&notifier, 3).await;
    assert_quiet(&mut body).await;

    let live = backend.append("d");
    wake(&notifier, live).await;
    assert_eq!(next_id(&mut body).await, 4);
}

#[tokio::test]
async fn resume_at_the_oldest_retained_boundary_is_not_expired() {
    let backend = PackLikeBackend::new();
    for text in ["a", "b", "c", "d", "e"] {
        backend.append(text);
    }
    backend.trim_before(3);
    let (state, _n) = state();
    // Having seen cursor 2, the next wanted is 3: exactly the oldest retained.
    let mut body = open(&backend, &state, Some("2")).await;
    assert_eq!(next_id(&mut body).await, 3);
}

#[tokio::test]
async fn an_explicit_cursor_expired_from_the_provider_is_410_with_the_oldest_cursor() {
    let backend = PackLikeBackend::new();
    for text in ["a", "b", "c", "d", "e"] {
        backend.append(text);
    }
    backend.trim_before(4);
    let (state, _n) = state();
    // since = 2 < oldest 4: the provider says `cursor_expired`.
    let response = handle_stream(request(Some("1")), backend, &state).await;
    assert_eq!(response.status(), StatusCode::GONE);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(json["error"]["code"], "cursor_expired");
    assert_eq!(json["error"]["oldest_cursor"], 4);
}

#[test]
fn the_provider_error_shapes_decode_to_typed_failures() {
    let expired = parse_poll_output(serde_json::json!(
        {"error": {"code": "cursor_expired", "oldest_cursor": 9}}
    ));
    assert_eq!(
        expired.unwrap_err(),
        BackendError::CursorExpired { oldest_cursor: 9 }
    );
    let missing = parse_poll_output(serde_json::json!(
        {"error": {"code": "conversation_not_found"}}
    ));
    assert_eq!(missing.unwrap_err(), BackendError::NotFound);
    let other = parse_poll_output(serde_json::json!({"error": {"code": "store_failure"}}));
    assert_eq!(other.unwrap_err(), BackendError::Unavailable);
    let no_oldest = parse_poll_output(serde_json::json!({"error": {"code": "cursor_expired"}}));
    assert_eq!(no_oldest.unwrap_err(), BackendError::Unavailable);
    let ok = parse_poll_output(serde_json::json!({"events": [], "next_cursor": 1}));
    assert_eq!(ok.expect("ok").next_cursor, 1);
}
