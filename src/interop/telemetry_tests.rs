//! What one interop request's span carries, asserted on the fields a
//! subscriber really receives rather than on the recorder's own bookkeeping.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

use super::*;

/// Everything a subscriber saw on one `greentic.interop.request` span.
#[derive(Clone, Default)]
struct Captured {
    spans: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
}

impl Captured {
    fn spans(&self) -> Vec<BTreeMap<String, String>> {
        self.spans.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// The one span this suite's requests emit.
    fn only(&self) -> BTreeMap<String, String> {
        let spans = self.spans();
        assert_eq!(spans.len(), 1, "expected exactly one span: {spans:?}");
        spans.into_iter().next().unwrap_or_default()
    }
}

#[derive(Default)]
struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
}

/// Collects the fields recorded on every span this module emits.
///
/// `on_record` is what sees a `Span::record` of a field declared `Empty` —
/// which is every field here — so a field the span's callsite forgot to
/// declare is invisible to this layer and fails the tests below. That is the
/// silent failure it exists to catch.
struct CaptureLayer(Captured);

impl<S> Layer<S> for CaptureLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        if attrs.metadata().name() != SPAN_NAME {
            return;
        }
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(fields);
        }
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id)
            && let Some(fields) = span.extensions_mut().get_mut::<Fields>()
        {
            values.record(fields);
        }
    }

    fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        if span.metadata().name() != SPAN_NAME {
            return;
        }
        let recorded = span
            .extensions()
            .get::<Fields>()
            .map(|fields| fields.0.clone())
            .unwrap_or_default();
        if let Ok(mut spans) = self.0.spans.lock() {
            spans.push(recorded);
        }
    }
}

/// Run `drive` with a capturing subscriber installed, and return what the one
/// emitted span carried.
fn capture(drive: impl FnOnce(&RequestTrace)) -> BTreeMap<String, String> {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::registry().with(CaptureLayer(captured.clone()));
    tracing::subscriber::with_default(subscriber, || {
        let trace = RequestTrace::new(
            Surface::A2a,
            TelemetryCtx::new("acme").with_bundle_id("support-bot"),
        );
        drive(&trace);
        drop(trace);
    });
    captured.only()
}

fn plain_trace() -> RequestTrace {
    RequestTrace::new(
        Surface::A2a,
        TelemetryCtx::new("acme").with_bundle_id("support-bot"),
    )
}

fn field<'a>(fields: &'a [(&'static str, FieldValue)], key: &str) -> Option<&'a FieldValue> {
    fields
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value)
}

// ---------------------------------------------------------------------------
// The emitted span
// ---------------------------------------------------------------------------

/// The whole point of `Drop`: a request that exited early still emits.
#[test]
fn a_request_that_recorded_nothing_but_a_refusal_still_emits_one_span() {
    let emitted = capture(|trace| {
        trace.route("jsonrpc");
        trace.outcome(Outcome::Unauthenticated);
        trace.http_status(401);
    });
    assert_eq!(
        emitted.get("interop.outcome").map(String::as_str),
        Some("unauthenticated")
    );
    assert_eq!(
        emitted.get("interop.route").map(String::as_str),
        Some("jsonrpc")
    );
    assert_eq!(
        emitted.get("interop.http_status").map(String::as_str),
        Some("401")
    );
    assert_eq!(emitted.get("gt.tenant").map(String::as_str), Some("acme"));
}

/// Every field the recorder can produce has to be DECLARED at the span's
/// callsite or `Span::record` drops it silently. Drive one request that
/// records all of them and assert the subscriber saw every one.
#[test]
fn every_recordable_field_reaches_the_subscriber() {
    let emitted = capture(|trace| {
        trace.route("jsonrpc");
        trace.method("SendMessage");
        trace.credential("c1");
        trace.outcome(Outcome::Completed);
        trace.task_state("TASK_STATE_COMPLETED");
        trace.artifacts(2);
        trace.rpc_error(-32602);
        trace.http_status(200);
        trace.turn_duration(Duration::from_millis(7));
    });
    for key in [
        "interop.surface",
        "interop.route",
        "interop.method",
        "interop.credential_id",
        "interop.outcome",
        "interop.task_state",
        "interop.artifacts",
        "interop.rpc_error_code",
        "interop.http_status",
        "interop.turn_duration_ms",
        "interop.duration_ms",
        "gt.tenant",
        "gt.bundle_id",
    ] {
        assert!(
            emitted.contains_key(key),
            "{key} was not emitted: {emitted:?}"
        );
    }
    assert_eq!(
        emitted.get("interop.artifacts").map(String::as_str),
        Some("2")
    );
    assert_eq!(
        emitted.get("interop.turn_duration_ms").map(String::as_str),
        Some("7")
    );
}

/// A path that answered without naming an outcome is a bug in THIS module's
/// wiring, and it must read as one rather than as a backend that does not
/// collect outcomes.
#[test]
fn a_request_that_named_no_outcome_says_so() {
    let emitted = capture(|trace| trace.route("jsonrpc"));
    assert_eq!(
        emitted.get("interop.outcome").map(String::as_str),
        Some(UNRECORDED_OUTCOME)
    );
}

// ---------------------------------------------------------------------------
// The recorder
// ---------------------------------------------------------------------------

/// `fields()` is what `emit` records, so a test asserting on it is asserting
/// on the wire. Pinned by driving both and comparing the key sets.
#[test]
fn the_accessor_and_the_emitted_span_carry_the_same_keys() {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::registry().with(CaptureLayer(captured.clone()));
    let accessor_keys = tracing::subscriber::with_default(subscriber, || {
        let trace = plain_trace();
        trace.route("rest_send");
        trace.method("SendMessage");
        trace.credential("c1");
        trace.outcome(Outcome::InputRequired);
        trace.task_state("TASK_STATE_INPUT_REQUIRED");
        trace.artifacts(1);
        trace.http_status(200);
        let keys: Vec<&'static str> = trace.fields().into_iter().map(|(key, _)| key).collect();
        drop(trace);
        keys
    });
    let emitted = captured.only();
    for key in &accessor_keys {
        assert!(emitted.contains_key(*key), "{key} missing from the span");
    }
    // `interop.duration_ms` is recomputed at emit time, so the span may carry
    // keys the accessor snapshot did not — but never the reverse.
    assert_eq!(emitted.len(), accessor_keys.len());
}

/// The layer closest to the fact names it; the generic rejection recorder
/// behind it must not overwrite a specific outcome with `rejected`.
#[test]
fn the_first_outcome_recorded_wins() {
    let trace = plain_trace();
    trace.outcome(Outcome::TurnFailed);
    trace.rpc_error(-32603);
    let fields = trace.fields();
    assert_eq!(
        field(&fields, "interop.outcome").and_then(FieldValue::as_text),
        Some("turn_failed")
    );
    assert_eq!(
        field(&fields, "interop.rpc_error_code").and_then(FieldValue::as_text),
        Some("-32603")
    );
}

/// A refusal with no more specific outcome still names itself, and the code
/// is what tells two rejections apart.
#[test]
fn a_bare_rejection_carries_the_code_that_distinguishes_it() {
    for (code, _) in [(-32601_i64, "method not found"), (-32602, "invalid params")] {
        let trace = plain_trace();
        trace.rpc_error(code);
        let fields = trace.fields();
        assert_eq!(
            field(&fields, "interop.outcome").and_then(FieldValue::as_text),
            Some("rejected")
        );
        assert_eq!(
            field(&fields, "interop.rpc_error_code").and_then(FieldValue::as_text),
            Some(code.to_string().as_str())
        );
    }
}

/// Each refusal this surface can make is a distinct token, so a trace can
/// answer "which refusals are we making" rather than only "how many".
#[test]
fn every_refusal_has_its_own_token() {
    let refusals = [
        Outcome::Unauthenticated,
        Outcome::RateLimited,
        Outcome::Busy,
        Outcome::VersionUnsupported,
        Outcome::Rejected,
        Outcome::TurnFailed,
        Outcome::FlowFailed,
    ];
    let mut tokens: Vec<&str> = refusals.iter().map(|o| o.as_str()).collect();
    tokens.sort_unstable();
    let count = tokens.len();
    tokens.dedup();
    assert_eq!(tokens.len(), count, "two refusals share a token");
    // And none of them collides with a success.
    for success in [Outcome::Completed, Outcome::InputRequired, Outcome::Served] {
        assert!(!tokens.contains(&success.as_str()), "{}", success.as_str());
    }
}

/// Latency is a number, not a string: a backend cannot aggregate a duration
/// it has to parse.
#[test]
fn durations_are_recorded_as_counts() {
    let trace = plain_trace();
    trace.turn_duration(Duration::from_millis(42));
    let fields = trace.fields();
    assert_eq!(
        field(&fields, "interop.turn_duration_ms"),
        Some(&FieldValue::Count(42))
    );
    assert!(matches!(
        field(&fields, "interop.duration_ms"),
        Some(FieldValue::Count(_))
    ));
}

/// A turn that never ran records no turn duration — zero would read as a
/// turn that took no time.
#[test]
fn a_request_with_no_turn_records_no_turn_duration() {
    let trace = plain_trace();
    trace.outcome(Outcome::Unauthenticated);
    assert!(field(&trace.fields(), "interop.turn_duration_ms").is_none());
}
