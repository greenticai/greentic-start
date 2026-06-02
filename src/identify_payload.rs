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
//! Header allowlist is **explicit per-header**, not a prefix match. Only
//! known routing discriminators ride the wrapper:
//!
//! - `x-telegram-bot-api-secret-token` — Telegram's per-bot shared
//!   secret, set by the operator at `setWebhook` time.
//!
//! Future providers with header-based discriminators (e.g. a future
//! `x-slack-signature` use case) must add their header name to
//! [`IDENTIFY_HEADER_ALLOWLIST`] explicitly. The narrow allowlist limits
//! the cross-provider blast radius: every declared `provider_type`'s
//! probe receives the SAME wrapper (the runner-host fan-out is
//! single-payload), so any header we forward is visible to EVERY
//! probed component. Per-provider scoping (different wrappers per
//! probe) is tracked as Phase D hardening; until it lands, the
//! allowlist stays minimal.
//!
//! Headers we never forward, regardless of name:
//!
//! - `Authorization` / `Cookie` / `Set-Cookie` / `Proxy-*-Authorization`
//!   variants — bearer tokens and session cookies have no place in a
//!   non-authoritative routing probe.
//! - `x-greentic-*` operator-internal trust signals — they are consumed
//!   by greentic-start itself (caller identity, session hints, header-
//!   pinned eid) and must never reach untrusted WASM probes.

use hyper::HeaderMap;
use serde_json::{Value, json};

/// Explicit allowlist of HTTP header names forwarded to identify-instance
/// probes. Names MUST be lowercase ASCII (the [`HeaderMap`] yields
/// canonical-cased keys, but [`collect_identify_headers`] lowercases
/// before matching).
///
/// Adding an entry expands the cross-provider blast radius — every
/// probed `provider_type` receives the SAME wrapper, so any allowlisted
/// header is visible to EVERY probed component. Keep this list minimal
/// and stop adding to it once per-provider scoping ships in Phase D.
const IDENTIFY_HEADER_ALLOWLIST: &[&str] = &["x-telegram-bot-api-secret-token"];

/// Collect the routing-relevant request headers in `(name_lowercase, value)`
/// form for inclusion in the identify-instance wrapper. Forwards ONLY
/// headers whose lowercase name appears in [`IDENTIFY_HEADER_ALLOWLIST`].
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
            if !IDENTIFY_HEADER_ALLOWLIST.contains(&name.as_str()) {
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
    fn collects_telegram_secret_token_header() {
        let headers = header_map(&[
            ("x-telegram-bot-api-secret-token", "tok-abc"),
            ("x-slack-signature", "v0=sig"),
            ("x-forwarded-for", "203.0.113.42"),
            ("user-agent", "test"),
        ]);
        let out = collect_identify_headers(&headers);
        assert_eq!(
            out,
            vec![(
                "x-telegram-bot-api-secret-token".to_string(),
                "tok-abc".to_string()
            )]
        );
    }

    #[test]
    fn drops_non_allowlisted_x_prefixed_headers() {
        // x-api-key, x-greentic-user, x-forwarded-for etc. are all x-*
        // but NOT on the allowlist — they must not reach the probe.
        let headers = header_map(&[
            ("x-api-key", "secret-abc"),
            ("x-greentic-user", "alice"),
            ("x-greentic-session", "sess-xyz"),
            ("x-forwarded-for", "203.0.113.42"),
            ("x-slack-signature", "v0=sig"),
            ("x-spark-signature", "sig=xyz"),
            ("x-hub-signature-256", "sha256=xyz"),
        ]);
        let out = collect_identify_headers(&headers);
        assert!(out.is_empty(), "expected empty, got {:?}", out);
    }

    #[test]
    fn drops_authorization_and_cookie_variants() {
        let mut map = HeaderMap::new();
        map.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        map.insert(COOKIE, HeaderValue::from_static("session=xyz"));
        map.insert(
            HeaderName::from_static("proxy-authorization"),
            HeaderValue::from_static("Basic abc"),
        );
        let out = collect_identify_headers(&map);
        assert!(out.is_empty(), "expected empty, got {:?}", out);
    }

    #[test]
    fn drops_headers_with_non_utf8_values() {
        let mut map = HeaderMap::new();
        map.insert(
            HeaderName::from_static("x-telegram-bot-api-secret-token"),
            HeaderValue::from_static("ok"),
        );
        // Construct a non-UTF8 value via raw bytes — use a second,
        // non-allowlisted header so the non-UTF8 path is exercised
        // without masking the allowlist filter.
        let bad = HeaderValue::from_bytes(&[0xff, 0xfe]).expect("raw bytes header");
        map.insert(HeaderName::from_static("x-bad"), bad);
        let out = collect_identify_headers(&map);
        assert_eq!(
            out,
            vec![(
                "x-telegram-bot-api-secret-token".to_string(),
                "ok".to_string()
            )]
        );
    }

    #[test]
    fn flattens_multi_value_headers() {
        let mut map = HeaderMap::new();
        map.append(
            HeaderName::from_static("x-telegram-bot-api-secret-token"),
            HeaderValue::from_static("a"),
        );
        map.append(
            HeaderName::from_static("x-telegram-bot-api-secret-token"),
            HeaderValue::from_static("b"),
        );
        let mut out = collect_identify_headers(&map);
        out.sort();
        assert_eq!(
            out,
            vec![
                (
                    "x-telegram-bot-api-secret-token".to_string(),
                    "a".to_string()
                ),
                (
                    "x-telegram-bot-api-secret-token".to_string(),
                    "b".to_string()
                ),
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
