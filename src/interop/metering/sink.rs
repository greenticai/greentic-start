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
//!
//! # A dropped event must say why it was dropped
//!
//! §8 exists so an operator can tell a mis-staged token from a worker nobody
//! called. A silent drop defeats that, and this module dropped every transport
//! failure silently until 2026-09-23: the error was discarded with `Err(_)`
//! and the one warn per suspension window said the endpoint "could not be
//! reached" — never that it TIMED OUT, never against which host.
//!
//! What produced it: a host with an RA-advertised IPv6 default route and no
//! working IPv6 egress. Every POST spent **21.3 s** inside the connector while
//! turns answered normally and the admin's table stayed empty; `curl` finished
//! the same POST in 270 ms over IPv4, so nothing an operator could reach for
//! reproduced it. Three things changed, and each is load-bearing on its own:
//!
//! - **The error is classified and printed** ([`TransportFailure`], plus the
//!   error's whole source chain). A connect timeout, a refusal and a stalled
//!   answer are three different faults with three different remedies, and they
//!   arrived here as one sentence.
//! - **The connector is bounded separately from the request**
//!   ([`CONNECT_TIMEOUT`] vs [`POST_TIMEOUT`]). `reqwest` makes
//!   `connect_timeout` the OUTERMOST connector layer, so it covers DNS, the
//!   address walk and the TLS handshake as one — which is the whole of the
//!   21.3 s above, whichever of the three it was spent in. Read off
//!   `reqwest` 0.13.4 (`connect.rs`: the `TimeoutLayer` wraps the assembled
//!   connector service), not inferred from the flag's name.
//! - **Drops are counted per endpoint** and the count rides the suspension
//!   line, so one `grep` answers "how much usage was lost", not just "some".
//!
//! # Why the address family is not chosen here
//!
//! It is tempting to pin IPv4. Do not: `hyper-util`'s connector already races
//! the two families with a 300 ms head start for whichever DNS returned first
//! — Happy Eyeballs, on by default (`hyper-util` 0.1.20,
//! `connect/http.rs`: `happy_eyeballs_timeout: Some(300ms)`). So pinning
//! would buy nothing on a healthy host and would break an IPv6-only
//! deployment outright — and Cloud Run, where this feature actually runs
//! today, has working IPv6.
//!
//! What was missing was never a family preference; it was a BOUND and a NAME.
//! A dead family now costs [`CONNECT_TIMEOUT`] and reports
//! [`TransportFailure::ConnectTimeout`] naming the endpoint, which points at
//! the two remedies this runtime cannot apply for the operator:
//! fix the host's IPv6 route, or stage an `endpoint` whose name carries no
//! `AAAA` record.
//!
//! # Two different drop counters, on purpose
//!
//! [`super::Meter::record`] counts events dropped because the QUEUE was full —
//! the sink not keeping up. This module counts events dropped because the
//! ENDPOINT would not take them. They are different faults with different
//! fixes, so they are different lines; an operator seeing only the second one
//! knows the queue was fine.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use hyper::StatusCode;
use tokio::sync::mpsc;

use super::Queued;
use crate::operator_log;

/// Budget for the whole connector: DNS, the address walk, and the TLS
/// handshake. `reqwest` installs this as the OUTERMOST connector layer, so
/// all three are inside it and no one of them can spend the request's budget
/// on its own.
///
/// Three seconds is far above a healthy connect (a loopback or same-region
/// TLS handshake is milliseconds) and far below the point at which a stalled
/// address family is indistinguishable from a slow one. It is what turns "the
/// endpoint could not be reached, eventually" into
/// [`TransportFailure::ConnectTimeout`] with a bound an operator can reason
/// about.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// A usage POST sits behind no caller, so it may be patient — but not so
/// patient that a hung admin pins the single drain task for a minute per
/// event while the queue behind it overflows.
///
/// **This must stay strictly larger than [`CONNECT_TIMEOUT`]**, and the gap
/// must leave room for the request and its answer. If the request budget can
/// elapse while the connector is still running, the connector's own timeout
/// never fires, every connect fault is reported as
/// [`TransportFailure::Timeout`], and the classification this module exists
/// for says nothing. Fifteen seconds is three for the connector plus twelve
/// for a slow but working admin — deliberately generous, because the
/// suspension below is what bounds the cost of a dead one, not this.
const POST_TIMEOUT: Duration = Duration::from_secs(15);

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

/// Longest an error's source chain may be when rendered into one warn line.
/// A chain is short in practice; the cap exists so a pathological one cannot
/// push an operator's own log lines off a bounded console.
const MAX_DETAIL_CHARS: usize = 400;

/// Install a process-level rustls provider, once.
///
/// This binary carries both `ring` and `aws-lc-rs`, so rustls cannot
/// auto-select one and the client builder panics without a default.
fn install_crypto_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// The outbound client, built once, mirroring
/// [`crate::interop::mcp::jwks`]'s: `None` when it cannot be built, which
/// costs metering and nothing else.
static CLIENT: std::sync::LazyLock<Option<reqwest::Client>> = std::sync::LazyLock::new(|| {
    install_crypto_provider();
    match reqwest::Client::builder()
        .timeout(POST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
    {
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
        /// The failure's own words, where there were any — the error chain
        /// for a transport failure, `None` for a suspension decided from a
        /// status code, which `reason` already states in full.
        detail: Option<String>,
    },
}

/// Which part of a POST failed.
///
/// The three that matter have three different remedies — a stalled connector
/// is a route or a resolver, a refusal is a wrong host or a dead admin, a
/// stalled answer is an overloaded admin — and this module reported all of
/// them as "could not be reached" until they were split.
///
/// DNS and TLS deliberately have no variant of their own: `reqwest` exposes
/// no predicate that separates either from a connect failure, and a variant
/// inferred from error text would be a guess about another crate's wording.
/// They are named instead by [`error_detail`], which prints the chain
/// verbatim — a DNS failure says `dns error`, a rejected certificate says so
/// in rustls's own words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TransportFailure {
    /// No connection was established inside [`CONNECT_TIMEOUT`]. This is what
    /// a black-holed address family, an unreachable resolver or a stalled TLS
    /// handshake all look like.
    ConnectTimeout,
    /// A connection was attempted and failed outright — refused, unreachable,
    /// unresolvable, or rejected by TLS.
    Connect,
    /// A connection was established and the answer did not arrive inside
    /// [`POST_TIMEOUT`].
    Timeout,
    /// The request or its answer was cut short mid-body.
    Body,
    /// Anything else `reqwest` can hand back from `send`.
    Other,
}

impl TransportFailure {
    /// Classify one `send` failure.
    ///
    /// **Order matters.** A connect timeout satisfies BOTH `is_timeout` and
    /// `is_connect` — the connector's timeout layer raises `reqwest`'s own
    /// `TimedOut` inside a `hyper-util` connect error — so the conjunction
    /// must be tested first. Testing `is_timeout` alone first would report
    /// every stalled connector as an overloaded admin, which is the exact
    /// misdirection the 21.3 s incident above cost a day to.
    pub(super) fn of(err: &reqwest::Error) -> Self {
        match (err.is_connect(), err.is_timeout()) {
            (true, true) => Self::ConnectTimeout,
            (true, false) => Self::Connect,
            (false, true) => Self::Timeout,
            (false, false) if err.is_body() || err.is_decode() => Self::Body,
            (false, false) => Self::Other,
        }
    }

    /// The operator-facing sentence. Each names a different remedy, which is
    /// the whole point of the split.
    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::ConnectTimeout => {
                "no connection to the usage endpoint was established in time (DNS, the address \
                 walk or the TLS handshake)"
            }
            Self::Connect => "the connection to the usage endpoint failed",
            Self::Timeout => "the usage endpoint did not answer in time",
            Self::Body => "the usage request or its answer was cut short",
            Self::Other => "the usage endpoint could not be reached",
        }
    }
}

/// Per-endpoint delivery state.
#[derive(Default)]
struct EndpointState {
    suspended_until: Option<Instant>,
    consecutive_failures: u32,
    last_used: Option<Instant>,
    /// Usage events this endpoint has lost: refused, failed, or never
    /// attempted because it was suspended. Reported on every suspension line
    /// so one `grep` answers how much was lost rather than that some was.
    dropped: u64,
}

/// The drain task's own state: what it knows about each endpoint.
///
/// Split out from the loop so the bookkeeping — which events counted as
/// dropped, what the operator is told, and when the endpoint is asked again —
/// is synchronous and testable without a server or a log sink.
#[derive(Default)]
pub(super) struct Sink {
    endpoints: HashMap<String, EndpointState>,
}

impl Sink {
    /// Decide whether to POST to `endpoint` now.
    ///
    /// `Some(consecutive_failures)` means attempt it; `None` means the
    /// endpoint is suspended and THIS EVENT IS LOST, which is counted here
    /// because nothing downstream will see it again.
    fn begin(&mut self, endpoint: &str, now: Instant) -> Option<u32> {
        self.sweep(now);
        let state = self.endpoints.entry(endpoint.to_string()).or_default();
        state.last_used = Some(now);
        if state.suspended_until.is_some_and(|until| now < until) {
            state.dropped = state.dropped.saturating_add(1);
            return None;
        }
        state.suspended_until = None;
        Some(state.consecutive_failures)
    }

    /// Record what one attempt decided, and return the operator line it owes.
    ///
    /// Exactly one line per SUSPENSION, not one per event: entering a
    /// suspension is the transition, and every event that arrives during the
    /// window is dropped by [`Sink::begin`] without reaching here.
    fn finish(&mut self, endpoint: &str, outcome: Outcome, now: Instant) -> Option<String> {
        let state = self.endpoints.entry(endpoint.to_string()).or_default();
        match outcome {
            Outcome::Accepted => {
                state.consecutive_failures = 0;
                None
            }
            // Refused per-event: the endpoint is healthy, this event is gone.
            Outcome::Rejected => {
                state.dropped = state.dropped.saturating_add(1);
                None
            }
            Outcome::Suspend {
                window,
                reason,
                detail,
            } => {
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                state.suspended_until = Some(now + window);
                state.dropped = state.dropped.saturating_add(1);
                Some(suspension_line(
                    endpoint,
                    reason,
                    detail.as_deref(),
                    window,
                    state.dropped,
                ))
            }
        }
    }

    /// Forget endpoints nothing has used for a while, so a process that serves
    /// many units over its life does not hold state for all of them.
    ///
    /// A swept endpoint loses its drop count with the rest of its state. That
    /// is accepted rather than worked around: the count is there to size one
    /// outage on one endpoint, and this only fires once a process is tracking
    /// more than [`MAX_TRACKED_ENDPOINTS`] of them.
    fn sweep(&mut self, now: Instant) {
        if self.endpoints.len() <= MAX_TRACKED_ENDPOINTS {
            return;
        }
        self.endpoints.retain(|_, state| {
            state.suspended_until.is_some_and(|until| now < until)
                || state
                    .last_used
                    .is_some_and(|last| now.saturating_duration_since(last) < AUTH_SUSPENSION)
        });
    }

    #[cfg(test)]
    fn dropped(&self, endpoint: &str) -> u64 {
        self.endpoints
            .get(endpoint)
            .map(|state| state.dropped)
            .unwrap_or_default()
    }
}

/// Drain the queue until every sender is gone.
pub(super) async fn run(mut receiver: mpsc::Receiver<Queued>) {
    let mut sink = Sink::default();
    while let Some(queued) = receiver.recv().await {
        let Some(failures) = sink.begin(&queued.endpoint, Instant::now()) else {
            continue;
        };
        let outcome = deliver(&queued, failures).await;
        if let Some(line) = sink.finish(&queued.endpoint, outcome, Instant::now()) {
            operator_log::warn(module_path!(), line);
        }
    }
}

/// The one operator line a suspension produces.
///
/// Pure, so a test asserts the sentence an operator reads rather than that
/// something was logged.
fn suspension_line(
    endpoint: &str,
    reason: &str,
    detail: Option<&str>,
    window: Duration,
    dropped: u64,
) -> String {
    let mut line = format!(
        "interop usage metering: {reason} at `{}`",
        endpoint_label(endpoint)
    );
    if let Some(detail) = detail.map(str::trim).filter(|detail| !detail.is_empty()) {
        line.push_str(&format!(" ({detail})"));
    }
    line.push_str(&format!(
        "; not sending usage there for {}s; usage events dropped for this endpoint so far: \
         {dropped}",
        window.as_secs()
    ));
    line
}

/// The endpoint as a log line may name it.
///
/// An endpoint is not a credential and is already printed by
/// [`super::MeteringRefusal`] — but nothing constrains a staged one to carry
/// no `?token=` and no `user:password@`, and this is the one place a WORKING
/// endpoint is printed. So the two parts of a URL that can hold a secret are
/// removed rather than trusted to be absent. An endpoint that does not parse
/// is reported as unparseable rather than echoed.
fn endpoint_label(endpoint: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(endpoint) else {
        return "an unparseable endpoint".to_string();
    };
    url.set_query(None);
    url.set_fragment(None);
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.to_string()
}

/// The error's own words: its whole source chain, joined.
///
/// `reqwest::Error`'s own `Display` is a one-line summary ("error sending
/// request"). Everything that says WHAT failed — `dns error`, `tcp connect
/// error`, `Connection refused (os error 111)`, a rustls certificate
/// rejection — is in the chain beneath it, which is why the chain is walked
/// rather than the top line printed.
///
/// The URL is dropped first: `Display` appends it verbatim, query string and
/// userinfo included, and [`endpoint_label`] is what names the endpoint
/// safely. No link in the chain can carry the token — it was only ever a
/// request header, and a header is not part of any error here.
fn error_detail(err: reqwest::Error) -> String {
    let err = err.without_url();
    let mut parts: Vec<String> = Vec::new();
    let mut next: Option<&(dyn std::error::Error + 'static)> = Some(&err);
    while let Some(current) = next {
        let text = current.to_string();
        if !text.is_empty() && !parts.iter().any(|seen| seen == &text) {
            parts.push(text);
        }
        next = current.source();
    }
    let detail = parts.join(": ");
    if detail.chars().count() > MAX_DETAIL_CHARS {
        let kept: String = detail.chars().take(MAX_DETAIL_CHARS).collect();
        return format!("{kept}...");
    }
    detail
}

/// POST one event.
async fn deliver(queued: &Queued, failures: u32) -> Outcome {
    let Some(client) = CLIENT.as_ref() else {
        return Outcome::Suspend {
            window: MAX_TRANSIENT_BACKOFF,
            reason: "no HTTP client",
            detail: None,
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
        // Classified and printed rather than discarded. The error can name
        // the transport failure and the OS or TLS error under it; it never
        // carries the token, which was only ever a header on the request.
        Err(err) => Outcome::Suspend {
            window: transient_backoff(failures),
            reason: TransportFailure::of(&err).reason(),
            detail: Some(error_detail(err)),
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
            detail: None,
        },
        StatusCode::TOO_MANY_REQUESTS => Outcome::Suspend {
            window: parse_retry_after(retry_after),
            reason: "the usage endpoint is rate limiting us",
            detail: None,
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
            detail: None,
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
