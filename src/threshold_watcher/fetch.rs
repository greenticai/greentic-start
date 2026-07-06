//! Metric fetch: HTTP GET the configured [`MetricSource`] and extract a
//! numeric value from the JSON body by a dotted path.
//!
//! [`extract_number`] is pure (no I/O) and does the fully-testable work:
//! walking a `serde_json::Value` by a dotted path and coercing the leaf to
//! `f64`. [`fetch_metric`] is the thin `ureq`-backed wrapper around it; its
//! HTTP behavior is covered by the poll-loop integration test (Task 5)
//! against a local stub server, not by a real-network unit test here.
//!
//! Every error path returns `Err` rather than panicking: a transient fetch
//! failure must never crash the watcher, just skip that tick (see
//! `Global Constraints` in the task brief — fail-safe, never a spurious
//! fire).

use std::time::Duration;

use serde_json::Value;

use super::config::MetricSource;

/// Short timeout for metric-source GETs. The watcher polls on a fixed
/// interval; a hung upstream must not block the poll loop indefinitely.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Walk `body` along the dotted `json_path` (e.g. `"data.available"`) and
/// return the leaf as `f64`.
///
/// Accepts either a JSON number or a string that parses as `f64` at the
/// leaf. Returns `None` if any path segment is missing, the path traverses
/// through a non-object, or the leaf isn't numeric.
pub fn extract_number(body: &Value, json_path: &str) -> Option<f64> {
    let mut current = body;
    for segment in json_path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    match current {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

/// Fetch `source.url`, applying `source.headers`, and extract the numeric
/// metric at `source.json_path`.
///
/// Any transport error, non-2xx response, body-parse failure, or missing/
/// non-numeric path yields `Err` with a human-readable message. Never
/// panics.
pub fn fetch_metric(source: &MetricSource) -> Result<f64, String> {
    let mut request = ureq::get(&source.url)
        .config()
        .timeout_global(Some(FETCH_TIMEOUT))
        .build();
    for (name, value) in &source.headers {
        request = request.header(name, value);
    }

    let mut response = request
        .call()
        .map_err(|err| format!("GET {} failed: {err}", source.url))?;

    let body: Value = response
        .body_mut()
        .read_json()
        .map_err(|err| format!("decode {} body failed: {err}", source.url))?;

    extract_number(&body, &source.json_path).ok_or_else(|| {
        format!(
            "no numeric value at json_path {:?} in response from {}",
            source.json_path, source.url
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_number_from_nested_number() {
        let body = json!({"data": {"available": 12}});
        assert_eq!(extract_number(&body, "data.available"), Some(12.0));
    }

    #[test]
    fn extract_number_from_numeric_string() {
        let body = json!({"data": {"available": "12.5"}});
        assert_eq!(extract_number(&body, "data.available"), Some(12.5));
    }

    #[test]
    fn extract_number_missing_path_is_none() {
        let body = json!({"data": {"available": 12}});
        assert_eq!(extract_number(&body, "data.missing"), None);
    }

    #[test]
    fn extract_number_non_numeric_leaf_is_none() {
        let body = json!({"data": {"available": true}});
        assert_eq!(extract_number(&body, "data.available"), None);
    }

    #[test]
    fn extract_number_non_numeric_string_is_none() {
        let body = json!({"data": {"available": "not-a-number"}});
        assert_eq!(extract_number(&body, "data.available"), None);
    }

    #[test]
    fn extract_number_top_level_path() {
        let body = json!({"available": 42});
        assert_eq!(extract_number(&body, "available"), Some(42.0));
    }

    #[test]
    fn extract_number_traverses_through_array_is_none() {
        let body = json!({"data": [1, 2, 3]});
        assert_eq!(extract_number(&body, "data.available"), None);
    }

    /// Live network test — intentionally `#[ignore]`d; the real fetch path
    /// is covered by Task 5's stub-server integration test.
    #[test]
    #[ignore]
    fn fetch_metric_live_smoke() {
        let source = MetricSource {
            url: "https://httpbin.org/json".to_string(),
            json_path: "slideshow.author".to_string(),
            headers: Vec::new(),
        };
        let _ = fetch_metric(&source);
    }
}
