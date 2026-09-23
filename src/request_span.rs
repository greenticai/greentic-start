//! Shared `http.request` span for both HTTP ingress boot paths.
//!
//! `http_ingress::handle_request` (the `--bundle` boot path) and
//! `revision_serve::handle_connection` (the `--store-root` boot path, used by
//! every env-canvas lane) each open one span per inbound request through this
//! module, so a trace exporter sees one consistent shape regardless of which
//! path served the request. Before this module existed, the store-root path
//! created no span at all — a 2026-09-18 measurement against a real collector
//! saw logs and metrics from every lane but zero traces from env-canvas ones.
//!
//! Attributes follow OTel HTTP semantic conventions: span name
//! `"{method} {route}"`, `http.request.method`, `http.route`,
//! `http.response.status_code`.
//!
//! `http.route` is always [`crate::metrics::normalise_route`]'s output, never
//! the raw path — high cardinality, and a raw path can carry an id.

use tracing::field::Empty;

use crate::metrics::normalise_route;

/// Open the `http.request` span for one inbound request. The caller enters
/// it (directly via [`tracing::Span::enter`], or asynchronously via
/// [`tracing::Instrument`]) around the work that serves the request, then
/// calls [`record_status`] once the response status is known.
pub(crate) fn request_span(method: &str, path: &str) -> tracing::Span {
    let route = normalise_route(path);
    tracing::info_span!(
        "http.request",
        otel.name = %format!("{method} {route}"),
        http.request.method = %method,
        http.route = %route,
        http.response.status_code = Empty,
    )
}

/// Record the final HTTP status code on a span opened by [`request_span`].
///
/// Recorded as `i64`, not `u64`: `tracing-opentelemetry` has no `record_u64`
/// arm, so a `u64` falls through to `record_debug` and exports as a STRING
/// attribute, while OTel HTTP semconv defines `http.response.status_code` as
/// an int. `i64` maps to an OTel `Int`.
pub(crate) fn record_status(span: &tracing::Span, status: u16) {
    span.record("http.response.status_code", i64::from(status));
}

/// Test-only capturing `tracing` layer shared by tests in other modules that
/// need to assert on span names, recorded field values (including whether a
/// value arrived as an integer) and parent/child structure.
#[cfg(test)]
pub(crate) mod capture {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use tracing::Subscriber;
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::LookupSpan;

    /// One captured span.
    #[derive(Clone, Debug, Default)]
    pub(crate) struct SpanRecord {
        pub(crate) id: u64,
        pub(crate) name: &'static str,
        /// Registry id of the parent span, if any.
        pub(crate) parent: Option<u64>,
        pub(crate) fields: BTreeMap<String, String>,
        /// Fields recorded through `record_i64` (exported by the OTel bridge
        /// as `Int`).
        pub(crate) i64_fields: BTreeMap<String, i64>,
    }

    #[derive(Clone, Default)]
    pub(crate) struct Captured(Arc<Mutex<Vec<SpanRecord>>>);

    impl Captured {
        pub(crate) fn spans(&self) -> Vec<SpanRecord> {
            self.0.lock().map(|g| g.clone()).unwrap_or_default()
        }

        pub(crate) fn named(&self, name: &str) -> Vec<SpanRecord> {
            self.spans()
                .into_iter()
                .filter(|s| s.name == name)
                .collect()
        }
    }

    struct Visitor<'a>(&'a mut SpanRecord);

    impl Visit for Visitor<'_> {
        fn record_i64(&mut self, field: &Field, value: i64) {
            self.0.i64_fields.insert(field.name().to_string(), value);
            self.0
                .fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.0
                .fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .fields
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    struct CaptureLayer(Captured);

    impl<S> Layer<S> for CaptureLayer
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
            let parent = ctx
                .span(id)
                .and_then(|span| span.parent())
                .map(|parent| parent.id().into_u64());
            let mut record = SpanRecord {
                id: id.into_u64(),
                name: attrs.metadata().name(),
                parent,
                ..SpanRecord::default()
            };
            attrs.record(&mut Visitor(&mut record));
            if let Ok(mut spans) = (self.0).0.lock() {
                spans.push(record);
            }
        }

        fn on_record(&self, id: &Id, values: &Record<'_>, _ctx: Context<'_, S>) {
            if let Ok(mut spans) = (self.0).0.lock()
                && let Some(record) = spans.iter_mut().rev().find(|s| s.id == id.into_u64())
            {
                values.record(&mut Visitor(record));
            }
        }
    }

    /// Keeps a SECOND dispatcher registered with `tracing-core` for the life
    /// of the test binary, which is what makes a capture subscriber reliable
    /// when tests run in parallel.
    ///
    /// `tracing` caches each callsite's `Interest` globally. With exactly one
    /// dispatcher registered, a rebuild — which any `Dispatch::new`, i.e. any
    /// other test installing a subscriber, triggers — recomputes every
    /// callsite against `dispatcher::get_default()` **on the rebuilding
    /// thread**. That thread usually has no subscriber, so `http.request`
    /// caches `Interest::never` and a capture test running concurrently sees
    /// ZERO spans: not a missing span, a disabled callsite. With two
    /// dispatchers registered, tracing-core instead ANDs their answers, and
    /// `never.and(always)` is `sometimes` — "ask per call" — which is exactly
    /// the behaviour a thread-local subscriber needs.
    ///
    /// This inert dispatcher is never installed as anyone's default, so it
    /// records nothing; registration alone is the point. It fixes a flake
    /// that predates the worker-interop work
    /// (`handle_connection_records_the_status_on_the_request_span` failed
    /// roughly two runs in eight on `origin/develop` at 6d5a981) and that
    /// grew more frequent as the binary gained callsites.
    static INTEREST_KEEPALIVE: std::sync::LazyLock<tracing::Dispatch> =
        std::sync::LazyLock::new(|| tracing::Dispatch::new(tracing_subscriber::registry()));

    /// A subscriber that records every span into the returned [`Captured`].
    /// Install it with `tracing::subscriber::with_default`.
    pub(crate) fn subscriber() -> (impl Subscriber + Send + Sync, Captured) {
        // Touch the keepalive so it is registered before the caller's own
        // dispatcher starts recording. See [`INTEREST_KEEPALIVE`].
        std::sync::LazyLock::force(&INTEREST_KEEPALIVE);
        let captured = Captured::default();
        let subscriber = tracing_subscriber::registry().with(CaptureLayer(captured.clone()));
        (subscriber, captured)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use tracing::Subscriber;
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::LookupSpan;

    use super::{record_status, request_span};

    /// Collects every field recorded for the one span this test cares about
    /// (there is only ever one, since each test opens exactly one span) into
    /// a flat, string-valued map — enough to assert on names and values
    /// without reimplementing `tracing`'s field-value dispatch.
    #[derive(Default)]
    struct Captured {
        span_name: Mutex<Option<&'static str>>,
        fields: Mutex<BTreeMap<String, String>>,
        /// Fields that arrived through `record_i64` — i.e. that an OTel
        /// bridge would export as an `Int` attribute.
        i64_fields: Mutex<BTreeMap<String, i64>>,
    }

    struct FieldVisitor<'a> {
        fields: &'a mut BTreeMap<String, String>,
        i64_fields: &'a mut BTreeMap<String, i64>,
    }

    impl Visit for FieldVisitor<'_> {
        fn record_i64(&mut self, field: &Field, value: i64) {
            self.i64_fields.insert(field.name().to_string(), value);
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    struct CapturingLayer(Arc<Captured>);

    impl<S> Layer<S> for CapturingLayer
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_new_span(&self, attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
            *self.0.span_name.lock().expect("span_name mutex poisoned") =
                Some(attrs.metadata().name());
            let mut fields = self.0.fields.lock().expect("fields mutex poisoned");
            let mut i64_fields = self.0.i64_fields.lock().expect("i64 mutex poisoned");
            attrs.record(&mut FieldVisitor {
                fields: &mut fields,
                i64_fields: &mut i64_fields,
            });
        }

        fn on_record(&self, _id: &Id, values: &Record<'_>, _ctx: Context<'_, S>) {
            let mut fields = self.0.fields.lock().expect("fields mutex poisoned");
            let mut i64_fields = self.0.i64_fields.lock().expect("i64 mutex poisoned");
            values.record(&mut FieldVisitor {
                fields: &mut fields,
                i64_fields: &mut i64_fields,
            });
        }
    }

    fn run_captured(f: impl FnOnce()) -> Arc<Captured> {
        let captured = Arc::new(Captured::default());
        let layer = CapturingLayer(Arc::clone(&captured));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, f);
        captured
    }

    #[test]
    fn request_span_names_and_normalises_the_route() {
        let captured = run_captured(|| {
            let span = request_span(
                "GET",
                "/v1/web/webchat/demo/sessions/edbd06e4-5a10-40db-b226-38deb55ea0bd",
            );
            let _entered = span.enter();
        });

        assert_eq!(
            *captured.span_name.lock().expect("mutex poisoned"),
            Some("http.request")
        );
        let fields = captured.fields.lock().expect("mutex poisoned");
        assert_eq!(
            fields.get("http.route").map(String::as_str),
            Some("/v1/web/webchat/demo/sessions/:id"),
            "route must be normalised, never the raw uuid"
        );
        assert_eq!(
            fields.get("otel.name").map(String::as_str),
            Some("GET /v1/web/webchat/demo/sessions/:id")
        );
        assert_eq!(
            fields.get("http.request.method").map(String::as_str),
            Some("GET")
        );
    }

    #[test]
    fn record_status_sets_the_response_status_code() {
        let captured = run_captured(|| {
            let span = request_span("POST", "/healthz");
            record_status(&span, 201);
        });

        let fields = captured.fields.lock().expect("mutex poisoned");
        assert_eq!(
            fields.get("http.response.status_code").map(String::as_str),
            Some("201")
        );
        let ints = captured.i64_fields.lock().expect("mutex poisoned");
        assert_eq!(
            ints.get("http.response.status_code"),
            Some(&201),
            "status must be recorded as an integer so OTel exports Int, not Str"
        );
    }
}
