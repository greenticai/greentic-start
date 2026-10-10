//! The host-to-provider "this request was authenticated" marker.
//!
//! A provider component cannot authenticate a webhook on the revision path: the
//! shared secret lives in the host's secrets plane and the provider never sees
//! it (see [`crate::provider_auth`]). Yet a provider that wants to stamp a
//! VERIFIED caller on the turn (so a per-end-user ledger can key on it) must
//! know the request passed that gate. This module is the one channel for that
//! fact: a reserved request header, [`VERIFIED_HEADER`], placed on the
//! `HttpInV1.headers` the provider's `ingest_http` receives.
//!
//! Two rules make the marker unforgeable, and both live here so they cannot
//! drift apart:
//!
//! 1. **Strip first.** [`strip_reserved`] removes every client-supplied
//!    occurrence (any ASCII case) before anything else reads the headers. A
//!    caller has no legitimate reason to send it.
//! 2. **Stamp only on proof.** [`stamp_if_authenticated`] adds it only for an
//!    [`AuthOutcome::Authenticated`] outcome, which `provider_auth` returns
//!    solely when an endpoint HAS a `webhook_secret_ref` AND the inbound header
//!    matched it. `Skipped` (legacy endpoint, no ref) never stamps.
//!
//! The value names the provider class whose gate passed (`telegram`), so a
//! provider can refuse a marker meant for another class.

use std::borrow::Cow;

use crate::ingress_types::IngressRequestV1;
use crate::provider_auth::AuthOutcome;

/// Reserved header carrying the marker to the provider's `ingest_http`.
pub(crate) const VERIFIED_HEADER: &str = "x-greentic-auth-verified";

/// Value stamped for a Telegram webhook that passed the secret-token gate.
pub(crate) const TELEGRAM_VERIFIED: &str = "telegram";

/// `headers` without any occurrence of [`VERIFIED_HEADER`], whatever its case.
pub(crate) fn strip_reserved(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case(VERIFIED_HEADER))
        .cloned()
        .collect()
}

/// The legacy `http_ingress` path never authenticates a provider webhook with
/// this gate, so it must never carry the marker either: `request` with any
/// client-supplied occurrence removed. Borrows when there is nothing to strip.
pub(crate) fn sanitize_ingress(request: &IngressRequestV1) -> Cow<'_, IngressRequestV1> {
    if request
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(VERIFIED_HEADER))
    {
        let mut cleaned = request.clone();
        cleaned.headers = strip_reserved(&request.headers);
        Cow::Owned(cleaned)
    } else {
        Cow::Borrowed(request)
    }
}

/// Append the marker to `headers` iff `outcome` is an authenticated one.
///
/// `headers` must already have been through [`strip_reserved`]; any stale
/// occurrence is removed again here so a mistaken call order cannot leave two.
pub(crate) fn stamp_if_authenticated(headers: &mut Vec<(String, String)>, outcome: &AuthOutcome) {
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case(VERIFIED_HEADER));
    if matches!(outcome, AuthOutcome::Authenticated(_)) {
        headers.push((VERIFIED_HEADER.to_string(), TELEGRAM_VERIFIED.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    #[test]
    fn strip_removes_every_case_variant_and_keeps_the_rest() {
        let headers = vec![
            h("x-greentic-auth-verified", "telegram"),
            h("X-Greentic-Auth-Verified", "telegram"),
            h("content-type", "application/json"),
            h("x-telegram-bot-api-secret-token", "s"),
        ];
        let out = strip_reserved(&headers);
        assert_eq!(
            out,
            vec![
                h("content-type", "application/json"),
                h("x-telegram-bot-api-secret-token", "s")
            ]
        );
    }

    fn ingress(headers: Vec<(String, String)>) -> IngressRequestV1 {
        IngressRequestV1 {
            v: 1,
            domain: "messaging".into(),
            provider: "messaging-telegram".into(),
            handler: None,
            tenant: "t".into(),
            team: None,
            method: "POST".into(),
            path: "/".into(),
            query: vec![],
            headers,
            body: b"{}".to_vec(),
            correlation_id: None,
            remote_addr: None,
        }
    }

    #[test]
    fn legacy_ingress_never_forwards_a_client_marker() {
        let req = ingress(vec![h("X-Greentic-Auth-Verified", "telegram"), h("a", "b")]);
        let clean = sanitize_ingress(&req);
        assert_eq!(clean.headers, vec![h("a", "b")]);
        assert_eq!(clean.body, req.body);
        let untouched = ingress(vec![h("a", "b")]);
        assert!(matches!(sanitize_ingress(&untouched), Cow::Borrowed(_)));
    }

    #[test]
    fn authenticated_outcome_is_stamped() {
        let mut headers = vec![h("content-type", "application/json")];
        stamp_if_authenticated(&mut headers, &AuthOutcome::Authenticated("e".into()));
        assert!(headers.contains(&h(VERIFIED_HEADER, TELEGRAM_VERIFIED)));
    }

    #[test]
    fn skipped_outcome_is_never_stamped() {
        let mut headers = vec![h("content-type", "application/json")];
        stamp_if_authenticated(&mut headers, &AuthOutcome::Skipped);
        assert!(!headers.iter().any(|(n, _)| n == VERIFIED_HEADER));
    }

    #[test]
    fn a_forged_marker_does_not_survive_a_skipped_outcome() {
        // Even if a caller forgot to strip first, Skipped must leave none.
        let mut headers = vec![h("X-Greentic-Auth-Verified", "telegram")];
        stamp_if_authenticated(&mut headers, &AuthOutcome::Skipped);
        assert!(headers.is_empty());
    }

    #[test]
    fn an_authenticated_outcome_yields_exactly_one_marker() {
        let mut headers = vec![h("X-Greentic-Auth-Verified", "forged")];
        stamp_if_authenticated(&mut headers, &AuthOutcome::Authenticated("e".into()));
        let markers: Vec<_> = headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(VERIFIED_HEADER))
            .collect();
        assert_eq!(markers, vec![&h(VERIFIED_HEADER, TELEGRAM_VERIFIED)]);
    }
}

/// Ordering ratchet: the strip must precede every read of the inbound headers
/// in `dispatch_provider_route`, and the stamp must precede the provider input.
#[cfg(test)]
mod ratchet {
    #[test]
    fn dispatch_strips_before_gating_and_stamps_before_building_the_input() {
        let src = include_str!("revision_serve.rs");
        let body = src
            .split("async fn dispatch_provider_route(")
            .nth(1)
            .expect("dispatch_provider_route exists");
        let strip = body
            .find("provider_auth_marker::strip_reserved(")
            .expect("strip");
        let gate = body
            .find("provider_auth::authenticate_provider_webhook(")
            .expect("gate");
        let stamp = body
            .find("provider_auth_marker::stamp_if_authenticated(")
            .expect("stamp");
        let build = body.find("build_provider_http_in(").expect("build");
        assert!(strip < gate, "strip must precede the auth gate");
        assert!(
            gate < stamp && stamp < build,
            "stamp sits between gate and input"
        );
    }
}
