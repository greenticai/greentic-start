//! M1 IID.4d wrapper-payload construction for `identify-instance` probes.
//!
//! The host forwards `payload` opaque to every probed provider component
//! (see [`crate::endpoint_resolver::resolve`]); the wrapper convention
//! defined here gives header-discriminated providers (Telegram via
//! `x-telegram-bot-api-secret-token`) access to the routing-relevant
//! request headers without breaking body-discriminated providers (Teams,
//! Slack, Webex, etc.) — components that ignore the wrapper continue
//! reading from `body`.
//!
//! Wrapper shape:
//!
//! ```json
//! {
//!   "headers": [ { "name": "x-…", "value": "…" } ],
//!   "body":    <the parsed request body, or null>
//! }
//! ```
//!
//! See `greentic:provider-instance-identity@0.1.0/identify-instance` for
//! the contract docstring.
//!
//! The header allowlist forwards `x-*` headers only and explicitly drops
//! `authorization` / `cookie` / proxy-auth variants so a compromised
//! identify-instance probe (the probe currently runs with full host
//! imports — Phase D hardening tracked at `pack.rs::invoke_identify_instance`)
//! cannot see bearer tokens or session cookies that arrived on the same
//! request.

use hyper::HeaderMap;
use serde_json::{Value, json};

/// Headers explicitly excluded from the forwarded identify payload, even
/// when they happen to start with `x-`. Names are lowercase ASCII.
const DENY_HEADER_NAMES: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "proxy-authenticate",
];

/// Collect the routing-relevant request headers in `(name_lowercase, value)`
/// form for inclusion in the identify-instance wrapper. Forwards every
/// header whose name starts with `x-` (case-insensitive) except those in
/// [`DENY_HEADER_NAMES`].
///
/// Multi-value headers are flattened — each occurrence becomes its own
/// `(name, value)` pair. Headers with non-UTF-8 values are dropped (the
/// wrapper is JSON; `identify-instance` is a non-authoritative routing
/// hint, so silently skipping malformed values is safer than producing
/// `Err`).
pub(crate) fn collect_identify_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            if !name.starts_with("x-") || DENY_HEADER_NAMES.contains(&name.as_str()) {
                return None;
            }
            let value = value.to_str().ok()?.to_string();
            Some((name, value))
        })
        .collect()
}

/// Build the M1 IID.4d wrapper bytes from a header list and the parsed
/// request body. `body` is the [`Value`] revision_serve already parsed
/// from the raw bytes — bodies that didn't parse as JSON were normalized
/// to [`Value::Null`] by the caller, so the wrapper's `body` field is
/// guaranteed to round-trip through `serde_json`.
pub(crate) fn build_identify_payload(headers: &[(String, String)], body: &Value) -> Vec<u8> {
    let wrapper = json!({
        "headers": headers
            .iter()
            .map(|(name, value)| json!({ "name": name, "value": value }))
            .collect::<Vec<_>>(),
        "body": body,
    });
    serde_json::to_vec(&wrapper).expect("wrapper payload always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::header::{AUTHORIZATION, COOKIE, HeaderName, HeaderValue};

    fn header_map(entries: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in entries {
            map.append(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        map
    }

    #[test]
    fn collects_x_prefixed_headers_lowercased() {
        let headers = header_map(&[
            ("x-telegram-bot-api-secret-token", "tok-abc"),
            ("x-slack-signature", "v0=sig"),
        ]);
        let mut out = collect_identify_headers(&headers);
        out.sort();
        assert_eq!(
            out,
            vec![
                ("x-slack-signature".to_string(), "v0=sig".to_string()),
                (
                    "x-telegram-bot-api-secret-token".to_string(),
                    "tok-abc".to_string(),
                ),
            ]
        );
    }

    #[test]
    fn drops_non_x_prefixed_headers() {
        let headers = header_map(&[
            ("host", "example.com"),
            ("user-agent", "test"),
            ("x-keep", "yes"),
        ]);
        let mut out = collect_identify_headers(&headers);
        out.sort();
        assert_eq!(out, vec![("x-keep".to_string(), "yes".to_string())]);
    }

    #[test]
    fn drops_authorization_and_cookie_even_when_x_prefixed() {
        // No real client sends `x-authorization`, but the deny list applies
        // by exact lowercase match — `authorization` is dropped on its own
        // and so are cookie / proxy-auth variants.
        let mut map = HeaderMap::new();
        map.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        map.insert(COOKIE, HeaderValue::from_static("session=xyz"));
        map.insert(
            HeaderName::from_static("proxy-authorization"),
            HeaderValue::from_static("Basic abc"),
        );
        map.insert(
            HeaderName::from_static("x-allow-me"),
            HeaderValue::from_static("yes"),
        );
        let mut out = collect_identify_headers(&map);
        out.sort();
        assert_eq!(out, vec![("x-allow-me".to_string(), "yes".to_string())]);
    }

    #[test]
    fn drops_headers_with_non_utf8_values() {
        let mut map = HeaderMap::new();
        map.insert(
            HeaderName::from_static("x-good"),
            HeaderValue::from_static("ok"),
        );
        // Construct a non-UTF8 value via raw bytes.
        let bad = HeaderValue::from_bytes(&[0xff, 0xfe]).expect("raw bytes header");
        map.insert(HeaderName::from_static("x-bad"), bad);
        let out = collect_identify_headers(&map);
        assert_eq!(out, vec![("x-good".to_string(), "ok".to_string())]);
    }

    #[test]
    fn flattens_multi_value_headers() {
        let mut map = HeaderMap::new();
        map.append(
            HeaderName::from_static("x-multi"),
            HeaderValue::from_static("a"),
        );
        map.append(
            HeaderName::from_static("x-multi"),
            HeaderValue::from_static("b"),
        );
        let mut out = collect_identify_headers(&map);
        out.sort();
        assert_eq!(
            out,
            vec![
                ("x-multi".to_string(), "a".to_string()),
                ("x-multi".to_string(), "b".to_string()),
            ]
        );
    }

    #[test]
    fn build_identify_payload_emits_wrapper_with_object_body() {
        let headers = vec![(
            "x-telegram-bot-api-secret-token".to_string(),
            "tok-1".to_string(),
        )];
        let body = json!({ "update_id": 42, "message": { "text": "hi" } });
        let bytes = build_identify_payload(&headers, &body);
        let parsed: Value = serde_json::from_slice(&bytes).expect("wrapper parses");
        assert_eq!(
            parsed["headers"],
            json!([{ "name": "x-telegram-bot-api-secret-token", "value": "tok-1" }])
        );
        assert_eq!(
            parsed["body"],
            json!({ "update_id": 42, "message": { "text": "hi" } })
        );
    }

    #[test]
    fn build_identify_payload_passes_null_body_through() {
        let bytes = build_identify_payload(&[], &Value::Null);
        let parsed: Value = serde_json::from_slice(&bytes).expect("wrapper parses");
        assert_eq!(parsed["headers"], json!([]));
        assert_eq!(parsed["body"], Value::Null);
    }
}
