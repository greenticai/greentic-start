//! One span per interop request (A2A technical design PR-15:
//! task/request/audit/latency/error telemetry).
//!
//! An interop turn was METERED — [`super::metering`] records what it spent —
//! and not TRACED. The two answer different questions and neither substitutes
//! for the other: a usage event says a turn ran and what it cost, and is
//! emitted ONLY for a turn that ran, so every refusal the surface makes (a bad
//! bearer, the rate limiter, a version it does not speak, a malformed request)
//! left no record at all. Metering can therefore only ever show that working
//! requests work.
//!
//! This is the other half: one `greentic.interop.request` span per request,
//! whatever the outcome, carrying who called, what they asked for, how it
//! ended and how long it took.
//!
//! # Three properties that must survive any change here
//!
//! - **One span per request, not one per layer.** The ingress builds one
//!   [`RequestTrace`]; the auth check, the binding handler and the turn each
//!   record FIELDS on it. The span is emitted from [`Drop`], so every exit a
//!   request has — an early refusal, an error path, a cancelled connection —
//!   emits exactly once. A tail statement would miss the paths that return
//!   before it, which is the shape the designer's own unreported-stream warn
//!   was moved into a `Drop` for.
//! - **Every value is server-minted, a token from a closed set, or a number.**
//!   No caller-supplied string reaches a field. That is stronger than "do not
//!   log the bearer": the bearer, the message body, the `contextId` and the
//!   JSON-RPC method name are all caller-controlled, and the first two are the
//!   tenant's or the caller's secrets while the last two are unbounded text
//!   that would land in a trace backend's index. The method is recorded only
//!   when it is one of the eleven names this server serves, and
//!   `a2a::rpc::rpc_tests::no_caller_supplied_string_or_turn_content_reaches_a_field`
//!   drives a real request whose every caller-controlled input is distinctive
//!   and asserts none of it is emitted.
//! - **A refusal is as distinguishable as a success.** [`Outcome`] names each
//!   one, and the JSON-RPC code rides beside it, so `-32601` (a method this
//!   server does not have) and `-32602` (params it could not read) do not
//!   collapse into one "rejected".
//!
//! # What is deliberately NOT recorded
//!
//! The task id. `Task.id` is the caller's own `contextId` (worker-interop
//! contract D9), i.e. caller-supplied free text, and recording it would break
//! the rule above for every request. Correlating one task to its request needs
//! an id this server mints, which the stateless MVP (contract D4) does not
//! have. `interop.task_state` says WHICH state was answered with, not which
//! task.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use greentic_telemetry::TelemetryCtx;

use super::metering::event::Surface;

/// The span every interop request emits.
pub(crate) const SPAN_NAME: &str = "greentic.interop.request";

/// How one request ended, in one stable token.
///
/// Every variant is a distinct thing an operator would act on differently.
/// `Rejected` is the one catch-all, and it never travels without
/// `interop.rpc_error_code` or `interop.http_status` saying which rejection it
/// was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The request was answered without running a turn: the agent card, or
    /// an RPC this server answers from its own state (`ListTasks`).
    Served,
    /// The caller's `If-None-Match` matched; the card was unchanged.
    NotModified,
    /// The turn ran and the worker answered.
    Completed,
    /// The turn ran and parked, asking the caller for input.
    InputRequired,
    /// The turn ran and the flow ended at a failure. The caller got the
    /// categorized error, not an answer.
    FlowFailed,
    /// The turn could not run at all.
    TurnFailed,
    /// No bearer, or not one this unit accepts.
    Unauthenticated,
    /// The per-credential rate limiter refused it.
    RateLimited,
    /// Every concurrent-turn slot for this deployment was in use.
    Busy,
    /// The caller asked for a protocol version this server does not speak.
    VersionUnsupported,
    /// The request was malformed, or named something this server does not
    /// serve. `interop.rpc_error_code` / `interop.http_status` say which.
    Rejected,
}

impl Outcome {
    /// The stable token emitted as `interop.outcome`. Hand-written rather than
    /// derived from `Debug`, because these travel into a trace backend's
    /// filters and a rename must be a deliberate edit.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Outcome::Served => "served",
            Outcome::NotModified => "not_modified",
            Outcome::Completed => "completed",
            Outcome::InputRequired => "input_required",
            Outcome::FlowFailed => "flow_failed",
            Outcome::TurnFailed => "turn_failed",
            Outcome::Unauthenticated => "unauthenticated",
            Outcome::RateLimited => "rate_limited",
            Outcome::Busy => "busy",
            Outcome::VersionUnsupported => "version_unsupported",
            Outcome::Rejected => "rejected",
        }
    }
}

/// Recorded when a request reached [`Drop`] without any path naming an
/// outcome. A missing field would read as "this backend does not collect
/// outcomes"; this reads as the bug it is.
pub(crate) const UNRECORDED_OUTCOME: &str = "unrecorded";

/// One emitted field's value.
///
/// Counts stay numeric rather than being stringified, because a latency a
/// backend cannot aggregate is not latency telemetry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FieldValue {
    Text(String),
    Count(u64),
}

impl FieldValue {
    #[cfg(test)]
    pub(crate) fn as_text(&self) -> Option<&str> {
        match self {
            FieldValue::Text(text) => Some(text),
            FieldValue::Count(_) => None,
        }
    }
}

#[derive(Default)]
struct Recorded {
    route: Option<&'static str>,
    method: Option<&'static str>,
    credential_id: Option<String>,
    outcome: Option<Outcome>,
    task_state: Option<&'static str>,
    artifacts: Option<u64>,
    rpc_error_code: Option<i64>,
    http_status: Option<u16>,
    turn_duration_ms: Option<u64>,
}

/// The facts one interop request accumulates, emitted once when it is dropped.
///
/// Interior mutability rather than `&mut`, because the handlers reach it
/// through the shared request context they already carry — a context they hold
/// across `await` points, which is why this is a `Mutex` and not a `Cell`.
pub(crate) struct RequestTrace {
    surface: Surface,
    /// Tenant / deployment / bundle, as the `gt.*` attribution every other
    /// telemetry site in this binary uses.
    tctx: TelemetryCtx,
    started: Instant,
    recorded: Mutex<Recorded>,
}

impl RequestTrace {
    pub(crate) fn new(surface: Surface, tctx: TelemetryCtx) -> Self {
        Self {
            surface,
            tctx,
            started: Instant::now(),
            recorded: Mutex::new(Recorded::default()),
        }
    }

    fn with<R>(&self, edit: impl FnOnce(&mut Recorded) -> R) -> Option<R> {
        self.recorded
            .lock()
            .ok()
            .map(|mut recorded| edit(&mut recorded))
    }

    /// Which of the unit's reserved paths was asked for. A fixed token, never
    /// the request path — a path is caller text.
    pub(crate) fn route(&self, route: &'static str) {
        self.with(|recorded| recorded.route = Some(route));
    }

    /// The RPC this request named, from the closed set of method names this
    /// server serves.
    ///
    /// Takes an already-matched `&'static str` rather than the caller's own
    /// string, so there is no path by which caller text becomes a field: an
    /// unrecognised method records nothing and is visible as
    /// [`Outcome::Rejected`] with `-32601`.
    pub(crate) fn method(&self, method: &'static str) {
        self.with(|recorded| recorded.method = Some(method));
    }

    /// The verified credential the caller presented — the staged credential's
    /// ID, never the token.
    ///
    /// The id is not secret: it is the rate-limiter's own key, the designer
    /// writes it, and it is what contract §6 means by auditing caller
    /// identity. The token that proves possession of it never leaves
    /// [`crate::ingress_auth`].
    pub(crate) fn credential(&self, credential_id: &str) {
        self.with(|recorded| recorded.credential_id = Some(credential_id.to_string()));
    }

    /// Name how the request ended. FIRST call wins: the layer closest to the
    /// fact records it, and the generic rejection recorder behind it must not
    /// overwrite a specific one.
    pub(crate) fn outcome(&self, outcome: Outcome) {
        self.with(|recorded| {
            recorded.outcome.get_or_insert(outcome);
        });
    }

    /// The A2A task state this request answered with, in its wire spelling.
    /// Absent when the answer was a `Message` — which is itself the fact that
    /// no task was created.
    pub(crate) fn task_state(&self, state: &'static str) {
        self.with(|recorded| recorded.task_state = Some(state));
    }

    /// How many artifacts rode on the answer.
    pub(crate) fn artifacts(&self, count: u64) {
        self.with(|recorded| recorded.artifacts = Some(count));
    }

    /// Record a JSON-RPC refusal: always the code, and [`Outcome::Rejected`]
    /// only when no more specific outcome was recorded first.
    pub(crate) fn rpc_error(&self, code: i64) {
        self.with(|recorded| {
            recorded.rpc_error_code = Some(code);
            recorded.outcome.get_or_insert(Outcome::Rejected);
        });
    }

    /// The HTTP status the caller received.
    pub(crate) fn http_status(&self, status: u16) {
        self.with(|recorded| recorded.http_status = Some(status));
    }

    /// How long the TURN took, when one ran — measured around the runner call
    /// alone, the same span [`super::metering`] bills. `interop.duration_ms`
    /// is the whole request, so the difference is what authentication, the
    /// limiter and the projection cost.
    pub(crate) fn turn_duration(&self, elapsed: Duration) {
        let millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        self.with(|recorded| recorded.turn_duration_ms = Some(millis));
    }

    /// Exactly what [`Self::emit`] records on the span, in emission order.
    ///
    /// The single accessor, so a test that asserts on this is asserting on the
    /// emitted fields and not on a parallel description of them.
    pub(crate) fn fields(&self) -> Vec<(&'static str, FieldValue)> {
        let mut fields = vec![(
            "interop.surface",
            FieldValue::Text(self.surface.as_str().to_string()),
        )];
        let Some(recorded) = self.recorded.lock().ok() else {
            return fields;
        };
        let mut text = |key: &'static str, value: &str| {
            fields.push((key, FieldValue::Text(value.to_string())));
        };
        if let Some(route) = recorded.route {
            text("interop.route", route);
        }
        if let Some(method) = recorded.method {
            text("interop.method", method);
        }
        if let Some(credential_id) = recorded.credential_id.as_deref() {
            text("interop.credential_id", credential_id);
        }
        text(
            "interop.outcome",
            recorded.outcome.map_or(UNRECORDED_OUTCOME, Outcome::as_str),
        );
        if let Some(state) = recorded.task_state {
            text("interop.task_state", state);
        }
        for (key, value) in self.tctx.kv() {
            if let Some(value) = value {
                text(key, value);
            }
        }
        if let Some(artifacts) = recorded.artifacts {
            fields.push(("interop.artifacts", FieldValue::Count(artifacts)));
        }
        if let Some(code) = recorded.rpc_error_code {
            // As a string: the codes are negative and a trace backend reads
            // this as a discriminant, not as a quantity to aggregate.
            fields.push(("interop.rpc_error_code", FieldValue::Text(code.to_string())));
        }
        if let Some(status) = recorded.http_status {
            fields.push(("interop.http_status", FieldValue::Count(u64::from(status))));
        }
        if let Some(turn_ms) = recorded.turn_duration_ms {
            fields.push(("interop.turn_duration_ms", FieldValue::Count(turn_ms)));
        }
        fields.push((
            "interop.duration_ms",
            FieldValue::Count(
                u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            ),
        ));
        fields
    }

    /// Emit the one span for this request.
    ///
    /// Every field is declared at the callsite and populated with
    /// [`tracing::Span::record`], the pattern `greentic_telemetry`'s own
    /// rollout emitter uses: a field a subscriber never saw declared is
    /// silently dropped, and declaring them here is what makes
    /// [`Self::fields`] and the emitted span the same set. The inner `info!`
    /// keeps the request visible to a log-only subscriber, which emits nothing
    /// for a span on its own.
    fn emit(&self) {
        let span = tracing::info_span!(
            SPAN_NAME,
            interop.surface = tracing::field::Empty,
            interop.route = tracing::field::Empty,
            interop.method = tracing::field::Empty,
            interop.credential_id = tracing::field::Empty,
            interop.outcome = tracing::field::Empty,
            interop.task_state = tracing::field::Empty,
            interop.artifacts = tracing::field::Empty,
            interop.rpc_error_code = tracing::field::Empty,
            interop.http_status = tracing::field::Empty,
            interop.turn_duration_ms = tracing::field::Empty,
            interop.duration_ms = tracing::field::Empty,
            gt.tenant = tracing::field::Empty,
            gt.team = tracing::field::Empty,
            gt.session = tracing::field::Empty,
            gt.flow = tracing::field::Empty,
            gt.node = tracing::field::Empty,
            gt.provider = tracing::field::Empty,
            gt.env = tracing::field::Empty,
            gt.customer_id = tracing::field::Empty,
            gt.deployment_id = tracing::field::Empty,
            gt.bundle_id = tracing::field::Empty,
            gt.revision_id = tracing::field::Empty,
            gt.pack_id = tracing::field::Empty,
            gt.env_pack_kind = tracing::field::Empty,
            gt.generation = tracing::field::Empty,
            gt.messaging_endpoint_id = tracing::field::Empty,
        );
        for (key, value) in self.fields() {
            match value {
                FieldValue::Text(text) => span.record(key, text.as_str()),
                FieldValue::Count(count) => span.record(key, count),
            };
        }
        let _enter = span.enter();
        tracing::info!("interop request");
    }
}

impl Drop for RequestTrace {
    fn drop(&mut self) {
        self.emit();
    }
}

#[cfg(test)]
#[path = "telemetry_tests.rs"]
mod tests;
