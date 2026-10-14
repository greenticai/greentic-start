//! The SSE stream: `GET .../conversations/{id}/stream`.
//!
//! `Last-Event-ID` is the cursor of the last event the client saw, so the
//! stream resumes at `cursor + 1`. A quiet stream sends a comment every
//! [`SseConfig::heartbeat`] so idle timeouts on a load balancer or CDN do not
//! cut it, and ends after [`SseConfig::max_lifetime`]; the client resumes with
//! `Last-Event-ID`.
//!
//! One task owns the connection. It runs `Pump` as a child and exits when the
//! client goes away, the lifetime is up, or the pump ends; on every exit it
//! aborts the pump and drops the limits permit, so nothing outlives the
//! response body.

use super::event::ApiEvent;
use super::limits::{Refusal, StreamLimits, StreamPermit, credential_key};
use super::source::{
    ApiChannelBackend, BackendError, PollEventsSource, TickingNotifier, activity_to_event,
};
use crate::notifier::ActivityNotifier;
use crate::operator_log;
use crate::websocket::pump::{ActivitySource, Pump, PumpError, PumpFrame};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Bytes;
use hyper::body::Frame;
use hyper::{Response, StatusCode, header};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub(crate) type SseBody = BoxBody<Bytes, Infallible>;

#[derive(Debug, Clone)]
pub(crate) struct SseConfig {
    pub heartbeat: Duration,
    pub max_lifetime: Duration,
    /// How often a stream asks the provider for new events on its own.
    pub poll_interval: Duration,
    /// Most events one replay may carry before the stream is refused.
    pub max_replay: usize,
}

impl Default for SseConfig {
    fn default() -> Self {
        Self {
            heartbeat: Duration::from_secs(15),
            max_lifetime: Duration::from_secs(300),
            poll_interval: Duration::from_secs(2),
            max_replay: 1000,
        }
    }
}

/// Shared by every stream of one process.
pub(crate) struct ApiChannelState {
    pub notifier: Arc<dyn ActivityNotifier>,
    pub limits: StreamLimits,
    pub config: SseConfig,
}

/// What the HTTP layer extracted from one request.
pub(crate) struct StreamRequest {
    pub tenant_id: String,
    pub conversation_id: String,
    /// The bearer token, if one was sent. Never logged.
    pub bearer: Option<String>,
    /// The raw `Last-Event-ID` header value.
    pub last_event_id: Option<String>,
}

fn plain(status: StatusCode) -> Response<SseBody> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()).boxed())
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()))
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<SseBody> {
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(bytes)).boxed())
        .unwrap_or_else(|_| plain(status))
}

/// `since` for a `Last-Event-ID`: the next cursor after the one seen.
fn resume_point(last_event_id: Option<&str>) -> Result<Option<u64>, ()> {
    match last_event_id.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(raw) => raw
            .parse::<u64>()
            .ok()
            .and_then(|last| last.checked_add(1))
            .map(Some)
            .ok_or(()),
    }
}

/// Answer one stream request. Order is deliberate: a credential is checked
/// before anything else is revealed or counted, so an unauthenticated caller
/// learns nothing and creates no limiter entry.
pub(crate) async fn handle_stream(
    request: StreamRequest,
    backend: Arc<dyn ApiChannelBackend>,
    state: &ApiChannelState,
) -> Response<SseBody> {
    let Some(bearer) = request.bearer.as_deref().filter(|b| !b.is_empty()) else {
        return plain(StatusCode::UNAUTHORIZED);
    };
    match backend.authorize().await {
        Ok(()) => {}
        Err(BackendError::Unauthorized) => return plain(StatusCode::UNAUTHORIZED),
        Err(BackendError::NotFound) => return plain(StatusCode::NOT_FOUND),
        Err(BackendError::Unavailable) => return plain(StatusCode::BAD_GATEWAY),
    }

    let permit = match state.limits.admit(&credential_key(bearer)) {
        Ok(permit) => permit,
        Err(Refusal::RateLimited { retry_after_secs }) => {
            let mut response = plain(StatusCode::TOO_MANY_REQUESTS);
            if let Ok(value) = header::HeaderValue::from_str(&retry_after_secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            return response;
        }
        Err(Refusal::TooManyStreams) => {
            let mut response = plain(StatusCode::TOO_MANY_REQUESTS);
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
            return response;
        }
    };

    let Ok(resume) = resume_point(request.last_event_id.as_deref()) else {
        return plain(StatusCode::BAD_REQUEST);
    };
    let since = resume.unwrap_or(0);

    // A resume must continue exactly where the client stopped. If the first
    // retained event is later than the one asked for, the log was trimmed past
    // the client's cursor and an honest stream is impossible: say so, with the
    // oldest cursor still available. A fresh client (no `Last-Event-ID`) just
    // starts at the oldest event.
    if resume.is_some() {
        match backend.poll_events(&request.conversation_id, since).await {
            Ok(response) => {
                if let Some(first) = response.events.first()
                    && first.cursor > since
                {
                    return json_response(
                        StatusCode::GONE,
                        serde_json::json!({
                            "error": "cursor_expired",
                            "oldest_cursor": first.cursor,
                        }),
                    );
                }
            }
            Err(BackendError::NotFound) => return plain(StatusCode::NOT_FOUND),
            Err(BackendError::Unauthorized) => return plain(StatusCode::UNAUTHORIZED),
            Err(BackendError::Unavailable) => return plain(StatusCode::BAD_GATEWAY),
        }
    }

    let source: Arc<dyn ActivitySource> = Arc::new(PollEventsSource { backend });
    let notifier: Arc<dyn ActivityNotifier> = Arc::new(TickingNotifier {
        inner: Arc::clone(&state.notifier),
        period: state.config.poll_interval,
    });
    let body = stream_body(
        source,
        notifier,
        state.config.clone(),
        request.tenant_id,
        request.conversation_id,
        since,
        permit,
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache, no-transform")
        .header("x-accel-buffering", "no")
        .body(body)
        .unwrap_or_else(|_| plain(StatusCode::INTERNAL_SERVER_ERROR))
}

/// One SSE frame for a log event: the cursor is the SSE `id`.
pub(crate) fn event_frame(event: &ApiEvent) -> Result<String, serde_json::Error> {
    let data = serde_json::to_string(event)?;
    Ok(format!(
        "id: {}\nevent: {}\ndata: {}\n\n",
        event.cursor,
        event.kind.as_str(),
        data
    ))
}

const HEARTBEAT_FRAME: &str = ": keep-alive\n\n";

fn stream_error_frame(code: &str) -> String {
    format!("event: stream_error\ndata: {{\"code\":\"{code}\"}}\n\n")
}

/// Build the response body and spawn the task that feeds it.
pub(crate) fn stream_body(
    source: Arc<dyn ActivitySource>,
    notifier: Arc<dyn ActivityNotifier>,
    config: SseConfig,
    tenant_id: String,
    conversation_id: String,
    since: u64,
    permit: StreamPermit,
) -> SseBody {
    let (out_tx, out_rx) = mpsc::channel::<Bytes>(16);
    tokio::spawn(drive(
        source,
        notifier,
        config,
        tenant_id,
        conversation_id,
        since,
        permit,
        out_tx,
    ));
    let stream = futures_util::stream::unfold(out_rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|bytes| (Ok::<_, Infallible>(Frame::data(bytes)), rx))
    });
    StreamBody::new(stream).boxed()
}

#[allow(clippy::too_many_arguments)]
async fn drive(
    source: Arc<dyn ActivitySource>,
    notifier: Arc<dyn ActivityNotifier>,
    config: SseConfig,
    tenant_id: String,
    conversation_id: String,
    since: u64,
    // Held, not read: dropping it frees the credential's slot.
    _permit: StreamPermit,
    out: mpsc::Sender<Bytes>,
) {
    let (frame_tx, mut frame_rx) = mpsc::channel::<PumpFrame>(16);
    let pump = Pump::new(source, notifier, config.max_replay);
    let mut pump_task =
        tokio::spawn(async move { pump.run(tenant_id, conversation_id, since, frame_tx).await });

    let mut heartbeat = tokio::time::interval(config.heartbeat);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await; // the first tick is immediate
    let lifetime = tokio::time::sleep(config.max_lifetime);
    tokio::pin!(lifetime);

    loop {
        tokio::select! {
            // The client went away: hyper dropped the body, and with it the
            // receiver.
            () = out.closed() => break,
            () = &mut lifetime => break,
            _ = heartbeat.tick() => {
                if out.send(Bytes::from_static(HEARTBEAT_FRAME.as_bytes())).await.is_err() {
                    break;
                }
            }
            frame = frame_rx.recv() => match frame {
                Some(PumpFrame::Activities { activities, .. }) => {
                    if !send_events(&out, activities).await {
                        break;
                    }
                }
                Some(PumpFrame::Error(_)) => {
                    // The source's text is never forwarded: it can name hosts.
                    if out.send(Bytes::from(stream_error_frame("poll_failed"))).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            result = &mut pump_task => {
                // Frames the pump queued before it ended still belong to the client.
                while let Ok(PumpFrame::Activities { activities, .. }) = frame_rx.try_recv() {
                    if !send_events(&out, activities).await {
                        return;
                    }
                }
                if let Ok(Err(err)) = result {
                    let code = match err {
                        PumpError::ReplayTooLarge { .. } => "replay_too_large",
                        PumpError::Source(_) => "poll_failed",
                        PumpError::Notifier(_) => "unavailable",
                    };
                    let _ = out.send(Bytes::from(stream_error_frame(code))).await;
                }
                return;
            }
        }
    }
    pump_task.abort();
    let _ = pump_task.await;
}

/// `false` when the client is gone.
async fn send_events(out: &mpsc::Sender<Bytes>, activities: Vec<serde_json::Value>) -> bool {
    for activity in activities {
        let frame = match activity_to_event(activity).map(|e| event_frame(&e)) {
            Ok(Ok(frame)) => frame,
            _ => {
                operator_log::warn(
                    module_path!(),
                    "[api-channel] dropped an event that does not match the schema",
                );
                continue;
            }
        };
        if out.send(Bytes::from(frame)).await.is_err() {
            return false;
        }
    }
    true
}
