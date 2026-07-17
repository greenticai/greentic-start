//! M1 IID.4 header-allowlist for `identify-instance` probes.
//!
//! [`collect_identify_headers`] is the start-side trust gate: only headers
//! whose name appears in [`IDENTIFY_HEADER_ALLOWLIST`] are forwarded to the
//! resolver. The runner then builds the per-provider wrapper from the
//! component's `describe-identify-instance` hint (see
//! [`RunnerHost::identify_messaging_endpoints_for_revision_scoped`]) — each
//! probed `provider_type` only sees the headers its hint declares. This
//! module owns the start-side allowlist (which headers may LEAVE
//! greentic-start at all); the runner owns the per-provider scoping (which
//! of those headers each component actually receives).
//!
//! [`RunnerHost::identify_messaging_endpoints_for_revision_scoped`]:
//!     greentic_runner_host::RunnerHost::identify_messaging_endpoints_for_revision_scoped

use hyper::HeaderMap;

/// Explicit allowlist of HTTP header names forwarded to identify-instance
/// probes. Names MUST be lowercase ASCII (the [`HeaderMap`] yields
/// canonical-cased keys, but [`collect_identify_headers`] lowercases
/// before matching).
///
/// Current entries:
///
/// - `x-telegram-bot-api-secret-token` — Telegram's per-bot shared
///   secret, set by the operator at `setWebhook` time. Telegram is the
///   only provider whose discriminator does not live in the body.
///
/// Adding an entry expands the trust surface — every probed component
/// can read it via its hint. Per-provider scoping (the runner's
/// `describe-identify-instance` cache) narrows which component receives
/// which header, but only headers in this allowlist can EVER reach a
/// probe in the first place. Keep this list minimal.
///
/// Categories that MUST never be added here, regardless of any future
/// provider need:
///
/// - `Authorization` / `Cookie` / `Set-Cookie` / `Proxy-*-Authorization`
///   variants — bearer tokens and session cookies have no place in a
///   non-authoritative routing probe.
/// - `x-greentic-*` operator-internal trust signals — they are consumed
///   by greentic-start itself (caller identity, session hints, header-
///   pinned eid) and must never reach untrusted WASM probes.
const IDENTIFY_HEADER_ALLOWLIST: &[&str] = &["x-telegram-bot-api-secret-token"];

/// Collect the routing-relevant request headers in `(name_lowercase, value)`
/// form for the identify-instance resolver. Forwards ONLY headers whose
/// lowercase name appears in [`IDENTIFY_HEADER_ALLOWLIST`].
///
/// Multi-value headers are flattened — each occurrence becomes its own
/// `(name, value)` pair. Headers with non-UTF-8 values are dropped
/// (`identify-instance` is a non-authoritative routing hint, so silently
/// skipping malformed values is safer than producing `Err`).
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
}
