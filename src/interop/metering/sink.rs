//! The task that drains the usage queue and POSTs each event (§8.2, §8.3).
//!
//! Fire-and-forget: an event that cannot be delivered is DROPPED, never
//! retried in place. Retrying here would turn an admin outage into a growing
//! backlog held in a container's memory, and the queue in front of this task
//! is already the bound that matters.
//!
//! What it does instead is stop asking for a while. Every failure suspends the
//! ENDPOINT — not the queue — for a bounded window, during which its events
//! are dropped without a request. That is the difference between a degraded
//! admin costing one request per turn and costing none.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use hyper::StatusCode;
use tokio::sync::mpsc;

use super::Queued;
use crate::operator_log;

/// A usage POST sits behind no caller, so it may be patient — but not so
/// patient that a hung admin pins the single drain task for a minute per
/// event while the queue behind it overflows.
const POST_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a `401`/`403` stops this runtime asking. Both mean the staged
/// token is wrong or revoked, and neither is fixed without a redeploy — so
/// the window is long, and the point of it expiring at all is that an admin
/// that was briefly misconfigured recovers without one.
const AUTH_SUSPENSION: Duration = Duration::from_secs(300);

/// Longest a `429`'s `Retry-After` is honoured. A hostile or broken value
/// must not be able to switch metering off for the life of the process.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

/// Ceiling on the exponential backoff after a transport error or a `5xx`.
const MAX_TRANSIENT_BACKOFF: Duration = Duration::from_secs(60);

/// Endpoints tracked at once. One per unit this process serves, so this is
/// far above any real deployment; it exists so a pathological config cannot
/// grow the map without bound.
const MAX_TRACKED_ENDPOINTS: usize = 64;

/// The outbound client, built once, mirroring
/// [`crate::interop::mcp::jwks`]'s: `None` when it cannot be built, which
/// costs metering and nothing else. The rustls provider is installed first
/// because this binary carries both `ring` and `aws-lc-rs`, so rustls cannot
/// auto-select one and the builder panics without a process default.
static CLIENT: LazyLock<Option<reqwest::Client>> = LazyLock::new(|| {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    match reqwest::Client::builder().timeout(POST_TIMEOUT).build() {
        Ok(client) => Some(client),
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!("interop usage metering has no HTTP client ({err}); no usage is recorded"),
            );
            None
        }
    }
});

/// What one delivery attempt decided.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// `2xx`. Includes the admin's idempotent `stored:false` for a duplicate,
    /// which is a success: fire-and-forget makes duplicates likely, not
    /// hypothetical, and the admin is what de-duplicates them.
    Accepted,
    /// This event is unacceptable and another one probably is not. Dropped,
    /// nothing suspended.
    Rejected,
    /// Stop asking this endpoint for a while.
    Suspend {
        window: Duration,
        reason: &'static str,
    },
}

/// Per-endpoint delivery state.
#[derive(Default)]
struct EndpointState {
    suspended_until: Option<Instant>,
    consecutive_failures: u32,
    last_used: Option<Instant>,
}

/// Drain the queue until every sender is gone.
pub(super) async fn run(mut receiver: mpsc::Receiver<Queued>) {
    let mut endpoints: HashMap<String, EndpointState> = HashMap::new();
    while let Some(queued) = receiver.recv().await {
        let now = Instant::now();
        sweep(&mut endpoints, now);
        let state = endpoints.entry(queued.endpoint.clone()).or_default();
        state.last_used = Some(now);
        if state.suspended_until.is_some_and(|until| now < until) {
            continue;
        }
        state.suspended_until = None;
        let failures = state.consecutive_failures;
        let outcome = deliver(&queued, failures).await;
        // Re-entered rather than held across the await: `deliver` is the only
        // thing in this loop that yields, and holding a `&mut` into the map
        // over it would borrow the map for the whole request.
        let state = endpoints.entry(queued.endpoint.clone()).or_default();
        match outcome {
            Outcome::Accepted => {
                state.consecutive_failures = 0;
            }
            Outcome::Rejected => {}
            Outcome::Suspend { window, reason } => {
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                state.suspended_until = Some(Instant::now() + window);
                // One line per suspension, not one per event: entering a
                // suspension is the transition, and every event that arrives
                // during the window is dropped above without reaching here.
                operator_log::warn(
                    module_path!(),
                    format!(
                        "interop usage metering: {reason} from `{}`; not sending usage there for \
                         {}s",
                        queued.endpoint,
                        window.as_secs()
                    ),
                );
            }
        }
    }
}

/// Forget endpoints nothing has used for a while, so a process that serves
/// many units over its life does not hold state for all of them.
fn sweep(endpoints: &mut HashMap<String, EndpointState>, now: Instant) {
    if endpoints.len() <= MAX_TRACKED_ENDPOINTS {
        return;
    }
    endpoints.retain(|_, state| {
        state.suspended_until.is_some_and(|until| now < until)
            || state
                .last_used
                .is_some_and(|last| now.saturating_duration_since(last) < AUTH_SUSPENSION)
    });
}

/// POST one event.
async fn deliver(queued: &Queued, failures: u32) -> Outcome {
    let Some(client) = CLIENT.as_ref() else {
        return Outcome::Suspend {
            window: MAX_TRANSIENT_BACKOFF,
            reason: "no HTTP client",
        };
    };
    let body = match serde_json::to_vec(&queued.event) {
        Ok(body) => body,
        Err(err) => {
            // The event is a fixed set of scalars, so this cannot happen from
            // data; it is handled rather than unwrapped because this is a
            // long-lived task and a panic here would silently end metering.
            operator_log::warn(
                module_path!(),
                format!("interop usage metering: an event could not be serialised ({err})"),
            );
            return Outcome::Rejected;
        }
    };
    let response = client
        .post(&queued.endpoint)
        // The ONE place the token is used. `bearer_auth` puts it in the
        // header; it is never in the URL, the body, or a log line.
        .bearer_auth(queued.token.expose())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await;
    match response {
        Ok(response) => {
            let status = response.status();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            classify(status, retry_after.as_deref(), failures)
        }
        // The error can name the endpoint and the transport failure; it never
        // carries the token, which was only ever a header on the request.
        Err(_) => Outcome::Suspend {
            window: transient_backoff(failures),
            reason: "the usage endpoint could not be reached",
        },
    }
}

/// Decide what one answer means. Pure, so every arm is a test rather than a
/// stub server.
pub(super) fn classify(status: StatusCode, retry_after: Option<&str>, failures: u32) -> Outcome {
    if status.is_success() {
        return Outcome::Accepted;
    }
    match status {
        // The staged token is not accepted, or names another tenant. Neither
        // is fixed by asking again, and both are operator-visible only if we
        // say so — hence a suspension with a log line rather than a silent
        // drop per turn.
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Outcome::Suspend {
            window: AUTH_SUSPENSION,
            reason: "the usage token was refused",
        },
        StatusCode::TOO_MANY_REQUESTS => Outcome::Suspend {
            window: parse_retry_after(retry_after),
            reason: "the usage endpoint is rate limiting us",
        },
        // `413` on a body this small, and `400`/`422`, are facts about THIS
        // event or this build's shape. Suspending would hide every later
        // event behind one bad one; the log line is what makes it visible.
        StatusCode::PAYLOAD_TOO_LARGE
        | StatusCode::BAD_REQUEST
        | StatusCode::UNPROCESSABLE_ENTITY => {
            operator_log::warn(
                module_path!(),
                format!("interop usage metering: the admin refused a usage event with {status}"),
            );
            Outcome::Rejected
        }
        _ if status.is_server_error() => Outcome::Suspend {
            window: transient_backoff(failures),
            reason: "the usage endpoint is failing",
        },
        _ => Outcome::Rejected,
    }
}

/// `Retry-After` as a delay, clamped. Only the delta-seconds form is read: the
/// HTTP-date form would need this runtime to trust the admin's clock against
/// its own, and a wrong answer there silently switches metering off.
fn parse_retry_after(raw: Option<&str>) -> Duration {
    let seconds = raw
        .map(str::trim)
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(1);
    Duration::from_secs(seconds.clamp(1, MAX_RETRY_AFTER.as_secs()))
}

/// `2^failures` seconds, capped. Doubling from one second, so a brief blip
/// costs one skipped event and a sustained outage costs one request a minute.
fn transient_backoff(failures: u32) -> Duration {
    let seconds = 1u64.checked_shl(failures.min(63)).unwrap_or(u64::MAX);
    Duration::from_secs(seconds).min(MAX_TRANSIENT_BACKOFF)
}

#[cfg(test)]
#[path = "sink_tests.rs"]
mod sink_tests;
