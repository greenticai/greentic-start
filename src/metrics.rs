//! Application-level metrics for greentic-start: HTTP ingress and webchat
//! session lifecycle. Each helper is safe to call unconditionally — when no
//! meter provider is installed (e.g. unit tests, or `gtc start` without a
//! `telemetry:` block) the no-op global meter short-circuits.

use std::sync::OnceLock;

use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter, UpDownCounter};

static METER: OnceLock<Meter> = OnceLock::new();
static HTTP_REQUESTS: OnceLock<Counter<u64>> = OnceLock::new();
static HTTP_DURATION: OnceLock<Histogram<f64>> = OnceLock::new();
static SESSION_STARTS: OnceLock<Counter<u64>> = OnceLock::new();
static CONVERSATIONS_ACTIVE: OnceLock<UpDownCounter<i64>> = OnceLock::new();

fn meter() -> &'static Meter {
    METER.get_or_init(|| global::meter("greentic-start"))
}

fn http_requests() -> &'static Counter<u64> {
    HTTP_REQUESTS.get_or_init(|| {
        meter()
            .u64_counter("greentic.http.requests")
            .with_description("Total HTTP requests handled by the runner ingress")
            .build()
    })
}

fn http_duration() -> &'static Histogram<f64> {
    HTTP_DURATION.get_or_init(|| {
        meter()
            .f64_histogram("greentic.http.request_duration_ms")
            .with_description("Duration of HTTP requests handled by the runner ingress")
            .with_unit("ms")
            .build()
    })
}

fn session_starts() -> &'static Counter<u64> {
    SESSION_STARTS.get_or_init(|| {
        meter()
            .u64_counter("greentic.session.starts")
            .with_description("Total webchat sessions opened")
            .build()
    })
}

fn conversations_active() -> &'static UpDownCounter<i64> {
    CONVERSATIONS_ACTIVE.get_or_init(|| {
        meter()
            .i64_up_down_counter("greentic.conversations.active")
            .with_description("Currently active webchat conversations")
            .build()
    })
}

/// Record one HTTP request handled by the ingress.
pub fn record_http_request(method: &str, route: &str, status_code: u16, duration_ms: f64) {
    let attrs = [
        KeyValue::new("method", method.to_string()),
        KeyValue::new("route", route.to_string()),
        KeyValue::new("status_code", status_code as i64),
    ];
    http_requests().add(1, &attrs);
    http_duration().record(duration_ms, &attrs);
}

/// Record a new webchat session being opened. Pair every call with a matching
/// [`record_session_end`] so [`greentic.conversations.active`] stays consistent.
pub fn record_session_start(tenant: &str, provider: &str) {
    let attrs = [
        KeyValue::new("tenant", tenant.to_string()),
        KeyValue::new("provider", provider.to_string()),
    ];
    session_starts().add(1, &attrs);
    conversations_active().add(1, &attrs);
}

/// Record a webchat session ending. Decrements the active-conversations gauge.
pub fn record_session_end(tenant: &str, provider: &str) {
    let attrs = [
        KeyValue::new("tenant", tenant.to_string()),
        KeyValue::new("provider", provider.to_string()),
    ];
    conversations_active().add(-1, &attrs);
}

/// Normalise an HTTP path to a metric-friendly route, collapsing high-cardinality
/// segments (uuids, conversation ids, etc.) to placeholders.
pub fn normalise_route(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for seg in path.split('/') {
        if seg.is_empty() {
            out.push('/');
            continue;
        }
        let bytes = seg.as_bytes();
        let looks_like_id = bytes.iter().all(|b| b.is_ascii_hexdigit() || *b == b'-')
            && (seg.len() >= 16 || seg.contains('-'));
        if looks_like_id {
            out.push_str(":id");
        } else {
            out.push_str(seg);
        }
        out.push('/');
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::normalise_route;

    #[test]
    fn collapses_uuids() {
        assert_eq!(
            normalise_route("/v1/web/webchat/demo/sessions/edbd06e4-5a10-40db-b226-38deb55ea0bd"),
            "/v1/web/webchat/demo/sessions/:id"
        );
    }

    #[test]
    fn keeps_static_segments() {
        assert_eq!(normalise_route("/healthz"), "/healthz");
        assert_eq!(
            normalise_route("/admin/packs/status"),
            "/admin/packs/status"
        );
    }
}
