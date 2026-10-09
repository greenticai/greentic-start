//! Inbound provider webhook authentication for the revision ingress.
//!
//! Closes the gap flagged in [`project-telegram-secret-token-auth-deferred`]:
//! Telegram's `x-telegram-bot-api-secret-token` header was the routing
//! discriminator (M1 IID) but never an authenticator. This gate makes the
//! header a real auth challenge against the per-endpoint `webhook_secret_ref`
//! the deployer auto-provisioned on `op messaging endpoint add` (PR #246).
//!
//! Posture per endpoint:
//! - `webhook_secret_ref = Some(_)` ⇒ this gate enforces. The
//!   [`SETUP_WEBHOOK_OP`] installation planted the *resolved* secret value on
//!   the provider side; the same value must arrive in the inbound header.
//! - `webhook_secret_ref = None` ⇒ legacy posture (back-compat). The
//!   [`crate::endpoint_resolver`] still resolves by `provider_id`; no auth
//!   gate runs. Envs deployed before PR #246 continue to work.
//!
//! Provider-class coverage is currently Telegram-only, matching the only
//! provider whose [`describe-identify-instance`] declares a secret-bearing
//! header. Other classes are no-ops in this gate.
//!
//! [`SETUP_WEBHOOK_OP`]: crate::revision_webhook_register
//! [`describe-identify-instance`]: crate::endpoint_resolver

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use subtle::ConstantTimeEq;

use crate::endpoint_admit::EndpointAdmit;
use crate::http_routes::RevisionScope;
use crate::http_routes::derive_provider_name;
use crate::revision_serve::error_response;
use crate::secrets_gate::DynSecretsManager;
use crate::webhook_secret_resolver::secret_ref_to_store_uri;

/// Telegram's per-update secret-token header. Documented at
/// <https://core.telegram.org/bots/api#setwebhook>: Telegram sends every
/// update with the value that was passed to `setWebhook(secret_token=...)`.
/// The dispatcher constant-time compares it against the resolved
/// `webhook_secret_ref` value.
const TELEGRAM_SECRET_TOKEN_HEADER: &str = "x-telegram-bot-api-secret-token";

/// Outcome of the auth gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthOutcome {
    /// Auth succeeded against an endpoint whose `webhook_secret_ref` resolved
    /// to the inbound header. The returned `endpoint_id` is what the
    /// [`crate::endpoint_resolver`] would otherwise have computed; the
    /// dispatcher uses it directly so the IID probe is skipped.
    Authenticated(String),
    /// Auth was skipped: no Telegram-class endpoints under this bundle declare
    /// `webhook_secret_ref`. The dispatcher continues on the legacy
    /// `provider_id`-based path.
    Skipped,
}

/// Authenticate an inbound provider webhook against the env's
/// per-endpoint webhook secrets.
///
/// Returns `Ok(AuthOutcome::Authenticated(eid))` when the inbound header
/// matches one endpoint's resolved `webhook_secret_ref`,
/// `Ok(AuthOutcome::Skipped)` when no endpoint linked to `scope.bundle_id`
/// for this provider class carries a ref (back-compat), and `Err(response)`
/// (HTTP 401) when at least one candidate carries a ref but the header is
/// missing, the value resolves but does not match, or the secrets backend
/// errors on every candidate.
///
/// The constant-time compare is bounded per endpoint, so total work is
/// `O(n_candidates)` reads — typically `n=1`.
pub(crate) async fn authenticate_provider_webhook(
    admit: &EndpointAdmit,
    secrets: &DynSecretsManager,
    scope: &RevisionScope,
    provider_type: &str,
    request_headers: &[(String, String)],
) -> Result<AuthOutcome, Response<Full<Bytes>>> {
    // Provider-class gate: only Telegram is wired here (its identify hint is
    // the only one that declares a header-borne secret). Other classes
    // legitimately reach this site and are a no-op for THIS gate, so adding
    // the field to a non-Telegram endpoint doesn't fail the request before the
    // component sees it. That is not the same as their being unauthenticated:
    // a provider that signs its requests rather than echoing a shared secret
    // (Slack) is gated immediately after this one, by
    // [`crate::provider_webhook_verify`]. The provider component's own
    // `ingest_http` verifies nothing on the revision path — do not read a
    // `Skipped` here as "the component will check it".
    if derive_provider_name(provider_type).as_deref() != Some("telegram") {
        return Ok(AuthOutcome::Skipped);
    }

    // Candidate endpoints: Telegram-class (same canonical name) AND linked to
    // this scope's bundle (the dispatched bundle is the only one whose
    // component can legitimately handle this request). An endpoint linked to
    // a sibling bundle MUST NOT auth a request routed to a different bundle.
    // The route's `provider_type` (e.g. `messaging.telegram.bot`) and the
    // endpoint's stored `provider_type` (e.g. `telegram`) reconcile via
    // `derive_provider_name`, same as the registration code in
    // `revision_webhook_register`.
    let candidates: Vec<(&str, &greentic_deploy_spec::SecretRef)> = admit
        .endpoints_with_webhook_secret_ref()
        .filter(|(_, endpoint_provider_type, _)| {
            derive_provider_name(endpoint_provider_type).as_deref() == Some("telegram")
        })
        .filter(|(eid, _, _)| {
            admit
                .linked_bundles(eid)
                .is_some_and(|set| set.contains(scope.bundle_id.as_str()))
        })
        .map(|(eid, _, ref_)| (eid, ref_))
        .collect();

    if candidates.is_empty() {
        return Ok(AuthOutcome::Skipped);
    }

    let header_value = find_header_value(request_headers, TELEGRAM_SECRET_TOKEN_HEADER);
    let Some(header_value) = header_value else {
        // At least one endpoint expects auth, but the inbound request carries
        // no token. Telegram would never deliver an update without it, so
        // this is either a misconfiguration on the provider side OR an
        // unauthenticated direct hit. Reject.
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "missing x-telegram-bot-api-secret-token header",
        ));
    };
    let header_bytes = header_value.as_bytes();

    for (eid, secret_ref) in &candidates {
        let uri = secret_ref_to_store_uri(secret_ref);
        let Ok(value) = secrets.read(&uri).await else {
            // A single missing/erroring secret should not poison the gate —
            // the next candidate may resolve. Log nothing here so we don't
            // disclose which URI failed (`provider_auth` is on the request
            // path; the boot/reload registration already surfaced backend
            // failures).
            continue;
        };
        if header_bytes.ct_eq(&value).into() {
            return Ok(AuthOutcome::Authenticated((*eid).to_string()));
        }
    }

    Err(error_response(
        StatusCode::UNAUTHORIZED,
        "x-telegram-bot-api-secret-token did not match any registered endpoint",
    ))
}

fn find_header_value<'a>(headers: &'a [(String, String)], target: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(target))
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{
        FakeSecrets, endpoint_typed, env_with, telegram_endpoint_with_webhook_secret,
    };
    use greentic_deploy_spec::{BundleId, DeploymentId, RevisionId, SecretRef};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn scope_for(bundle: &str) -> RevisionScope {
        RevisionScope {
            deployment_id: DeploymentId::new(),
            bundle_id: BundleId::new(bundle),
            revision_id: RevisionId::new(),
        }
    }

    fn header(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(name.to_string(), value.to_string())]
    }

    fn seed_secret(secrets: &mut HashMap<String, Vec<u8>>, ref_: &SecretRef, value: &[u8]) {
        secrets.insert(secret_ref_to_store_uri(ref_), value.to_vec());
    }

    #[tokio::test]
    async fn skipped_for_non_telegram_provider_class() {
        let ep = telegram_endpoint_with_webhook_secret("tg-bot", &["b"]);
        let admit = EndpointAdmit::from_environment(&env_with(vec![ep]));
        let secrets: DynSecretsManager = Arc::new(FakeSecrets(HashMap::new()));

        // Slack-class request body — the gate must not poke the Telegram
        // table.
        let outcome = authenticate_provider_webhook(
            &admit,
            &secrets,
            &scope_for("b"),
            "messaging.slack",
            &[],
        )
        .await
        .unwrap();
        assert_eq!(outcome, AuthOutcome::Skipped);
    }

    #[tokio::test]
    async fn skipped_when_no_telegram_endpoint_carries_webhook_secret_ref() {
        // Legacy posture: Telegram endpoint exists but without ref.
        let ep = endpoint_typed("telegram", "tg-legacy-id", &["b"]);
        let admit = EndpointAdmit::from_environment(&env_with(vec![ep]));
        let secrets: DynSecretsManager = Arc::new(FakeSecrets(HashMap::new()));

        let outcome = authenticate_provider_webhook(
            &admit,
            &secrets,
            &scope_for("b"),
            "messaging.telegram",
            &header(TELEGRAM_SECRET_TOKEN_HEADER, "anything"),
        )
        .await
        .unwrap();
        assert_eq!(outcome, AuthOutcome::Skipped);
    }

    #[tokio::test]
    async fn authenticates_endpoint_whose_resolved_secret_matches_inbound_header() {
        let ep = telegram_endpoint_with_webhook_secret("tg-bot", &["legal-bundle"]);
        let ref_ = ep.webhook_secret_ref.clone().unwrap();
        let eid = ep.endpoint_id.to_string();
        let admit = EndpointAdmit::from_environment(&env_with(vec![ep]));
        let mut secret_values = HashMap::new();
        seed_secret(&mut secret_values, &ref_, b"abc123");
        let secrets: DynSecretsManager = Arc::new(FakeSecrets(secret_values));

        let outcome = authenticate_provider_webhook(
            &admit,
            &secrets,
            &scope_for("legal-bundle"),
            "messaging.telegram",
            &header(TELEGRAM_SECRET_TOKEN_HEADER, "abc123"),
        )
        .await
        .unwrap();
        assert_eq!(outcome, AuthOutcome::Authenticated(eid));
    }

    #[tokio::test]
    async fn rejects_when_header_does_not_match_any_resolved_secret() {
        let ep = telegram_endpoint_with_webhook_secret("tg-bot", &["b"]);
        let ref_ = ep.webhook_secret_ref.clone().unwrap();
        let admit = EndpointAdmit::from_environment(&env_with(vec![ep]));
        let mut secret_values = HashMap::new();
        seed_secret(&mut secret_values, &ref_, b"expected");
        let secrets: DynSecretsManager = Arc::new(FakeSecrets(secret_values));

        let response = authenticate_provider_webhook(
            &admit,
            &secrets,
            &scope_for("b"),
            "messaging.telegram",
            &header(TELEGRAM_SECRET_TOKEN_HEADER, "wrong"),
        )
        .await
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_when_header_missing_and_endpoint_expects_auth() {
        let ep = telegram_endpoint_with_webhook_secret("tg-bot", &["b"]);
        let ref_ = ep.webhook_secret_ref.clone().unwrap();
        let admit = EndpointAdmit::from_environment(&env_with(vec![ep]));
        let mut secret_values = HashMap::new();
        seed_secret(&mut secret_values, &ref_, b"abc123");
        let secrets: DynSecretsManager = Arc::new(FakeSecrets(secret_values));

        let response = authenticate_provider_webhook(
            &admit,
            &secrets,
            &scope_for("b"),
            "messaging.telegram",
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn endpoint_linked_to_sibling_bundle_does_not_authenticate_this_request() {
        // The endpoint's ref WOULD match the inbound header, but the
        // endpoint is linked to `sibling-bundle` while the dispatched scope
        // is `target-bundle`. Crossing bundles would let one endpoint
        // authenticate another bundle's traffic.
        let ep = telegram_endpoint_with_webhook_secret("tg-bot", &["sibling-bundle"]);
        let ref_ = ep.webhook_secret_ref.clone().unwrap();
        let admit = EndpointAdmit::from_environment(&env_with(vec![ep]));
        let mut secret_values = HashMap::new();
        seed_secret(&mut secret_values, &ref_, b"abc123");
        let secrets: DynSecretsManager = Arc::new(FakeSecrets(secret_values));

        // No candidate endpoints for `target-bundle` → Skipped (back-compat).
        let outcome = authenticate_provider_webhook(
            &admit,
            &secrets,
            &scope_for("target-bundle"),
            "messaging.telegram",
            &header(TELEGRAM_SECRET_TOKEN_HEADER, "abc123"),
        )
        .await
        .unwrap();
        assert_eq!(outcome, AuthOutcome::Skipped);
    }

    #[tokio::test]
    async fn first_matching_endpoint_wins_when_multiple_endpoints_share_a_value() {
        // Two endpoints linked to the same bundle, both Telegram-class, both
        // with refs that resolve to the SAME value (the deployer rejects this
        // at validate-time, but auth must still be deterministic if the
        // condition somehow reaches the dispatcher). Iteration order over the
        // HashMap-keyed admit is unspecified, but at least ONE endpoint must
        // authenticate — `first match wins` is the contract.
        let ep_a = telegram_endpoint_with_webhook_secret("tg-a", &["b"]);
        let ep_b = telegram_endpoint_with_webhook_secret("tg-b", &["b"]);
        let ref_a = ep_a.webhook_secret_ref.clone().unwrap();
        let ref_b = ep_b.webhook_secret_ref.clone().unwrap();
        let eid_a = ep_a.endpoint_id.to_string();
        let eid_b = ep_b.endpoint_id.to_string();
        let admit = EndpointAdmit::from_environment(&env_with(vec![ep_a, ep_b]));
        let mut secret_values = HashMap::new();
        seed_secret(&mut secret_values, &ref_a, b"abc123");
        seed_secret(&mut secret_values, &ref_b, b"abc123");
        let secrets: DynSecretsManager = Arc::new(FakeSecrets(secret_values));

        let outcome = authenticate_provider_webhook(
            &admit,
            &secrets,
            &scope_for("b"),
            "messaging.telegram",
            &header(TELEGRAM_SECRET_TOKEN_HEADER, "abc123"),
        )
        .await
        .unwrap();
        match outcome {
            AuthOutcome::Authenticated(eid) => assert!(eid == eid_a || eid == eid_b),
            AuthOutcome::Skipped => panic!("expected Authenticated"),
        }
    }
}
