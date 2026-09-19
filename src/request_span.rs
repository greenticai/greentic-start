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
pub(crate) fn record_status(span: &tracing::Span, status: u16) {
    span.record("http.response.status_code", status as u64);
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
    }

    struct FieldVisitor<'a>(&'a mut BTreeMap<String, String>);

    impl Visit for FieldVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
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
            attrs.record(&mut FieldVisitor(&mut fields));
        }

        fn on_record(&self, _id: &Id, values: &Record<'_>, _ctx: Context<'_, S>) {
            let mut fields = self.0.fields.lock().expect("fields mutex poisoned");
            values.record(&mut FieldVisitor(&mut fields));
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
    }
}
