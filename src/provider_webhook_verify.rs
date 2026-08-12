//! Transport-layer signature verification for provider webhooks served by the
//! revision path ([`crate::revision_serve::dispatch_provider_route`]).
//!
//! # The hole this closes
//!
//! The legacy [`crate::http_ingress`] server dispatches a provider webhook
//! through the pack's `messaging.provider_ingress.v1` extension
//! ([`crate::ingress_dispatch::dispatch_http_ingress_with_op`]) whenever the
//! pack declares one. For Slack that extension is `messaging-ingress-slack`,
//! and it is the ONLY place in the shipped Slack pack where the
//! `X-Slack-Signature` HMAC is checked.
//!
//! The revision path does not go through that extension. It calls the provider
//! component's `ingest_http` op directly via
//! `RunnerHost::invoke_provider_for_revision`, and
//! `messaging-provider-slack`'s `ingest_http` performs no verification at all —
//! it stores `SLACK_SIGNING_SECRET` during setup and never reads it back on the
//! inbound path. So every Slack webhook served by a revision-path deployment
//! (`greentic start --env`, i.e. `gtc op` environments, Cloud Run, ECS, K8s)
//! was parsed and routed into the tenant's flows without any proof it came
//! from Slack. The public webhook URL is registered with Slack by
//! [`crate::revision_webhook_register`], so it is discoverable, and anyone who
//! has it could post a forged `event_callback`.
//!
//! # Shape
//!
//! This module does not verify anything itself — it *delegates* to the same
//! pack component the legacy path uses, through
//! [`crate::runner_host::invoke_pack_ingress_extension`]. A second HMAC
//! comparison living here would be free to drift from the one in the pack, and
//! the copy that drifts is always the one nobody is looking at. The normalized
//! body the component returns is deliberately discarded: this is a gate, not a
//! parse. The provider's own `ingest_http` still does the real work afterwards,
//! so downstream behaviour is unchanged for a request that verifies.
//!
//! # Fail closed, including when no secret is configured
//!
//! `messaging-ingress-slack` reads its signing secret through an *optional*
//! read and skips verification when the store answers `Ok(None)`. That branch
//! turns out to be unreachable under this host — `SecretsStoreHost::get` in
//! `greentic-runner-host` maps a missing secret to `Err(NotFound)`, not
//! `Ok(None)` — so the shipped component already refuses a request it cannot
//! verify. Confirmed by running the real
//! `packs/messaging-slack/components/messaging-ingress-slack.wasm` with the
//! secret absent: it answers `transport error: secret store error: … not-found`
//! and this gate refuses.
//!
//! That is a property of a dependency, though, not of this module, and it is
//! one line away from flipping. So the gate does not take "the component said
//! OK" as proof. It runs a **negative control**: before the real request, the
//! same instance is asked to handle the same request with a deliberately
//! corrupted signature header. A component that is verifying rejects it. A
//! component that accepted it has not verified anything — whether because the
//! store started answering `Ok(None)`, the secret is unreadable, or it is
//! scoped somewhere this call cannot see — and the request is refused.
//!
//! The alternative, resolving the secret host-side and checking it is present,
//! would be a second copy of the component's secret-resolution rules (key name,
//! canonicalization, tenant/team/pack scoping) and could disagree with what the
//! component actually reads. The negative control asks the component directly
//! and cannot disagree with it.
//!
//! Consequence, stated plainly: a Slack deployment with no signing secret
//! configured stops accepting webhooks instead of accepting forged ones. The
//! refusal log names the secret so an operator can fix it.
//!
//! # Cost
//!
//! Verification instantiates the component (a wasm compile) and makes two calls
//! against that one instance, measured at ~0.2 s per webhook against the real
//! Slack ingress component on a developer box. Slack's ack budget is 3 s. The
//! two calls MUST share an instantiation — that is why
//! [`invoke_pack_ingress_extension`] takes a batch rather than a single call.

use std::path::Path;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::http_routes::derive_provider_name;
use crate::operator_log;
use crate::revision_serve::error_response;
use crate::runner_host::{
    IngressExtensionCall, invoke_pack_ingress_extension, read_provider_ingress_extension,
};
use crate::secrets_gate::DynSecretsManager;

/// A provider class that carries a transport-layer request signature, and the
/// header that signature arrives in.
struct SignedProviderClass {
    /// Provider family, matched against [`derive_provider_name`]'s output —
    /// see [`class_matches`] for why that is a family and not an equality.
    provider: &'static str,
    /// Header carrying the signature, lowercase.
    signature_header: &'static str,
    /// Secret the pack's ingress component needs in order to verify. Used only
    /// in the operator-facing refusal message — nothing here resolves it.
    secret_key: &'static str,
}

/// Provider classes this gate enforces.
///
/// Deliberately a short, explicit list rather than "anything whose pack sets
/// `supports_webhook_validation: true`". That capability flag is advisory and
/// already inaccurate in the shipped packs: `messaging-telegram` declares it
/// `true` while `messaging-ingress-telegram`'s `handle_webhook` ignores the
/// headers entirely — Telegram is authenticated host-side instead, by
/// [`crate::provider_auth`], against the per-endpoint `webhook_secret_ref`.
/// Enforcing off the flag would refuse every Telegram webhook.
///
/// Adding a class here is a claim that the pack's ingress component really does
/// verify a signature from `signature_header`. The negative control keeps that
/// claim honest at run time, but it will refuse live traffic if the claim is
/// wrong, so verify the component before adding an entry.
const SIGNED_PROVIDER_CLASSES: &[SignedProviderClass] = &[SignedProviderClass {
    provider: "slack",
    signature_header: "x-slack-signature",
    secret_key: "SLACK_SIGNING_SECRET",
}];

/// Outcome of the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebhookVerification {
    /// The request carried a signature the pack's ingress component accepted,
    /// and that component demonstrably rejects a corrupted one.
    Verified,
    /// This provider class carries no transport signature this gate knows how
    /// to enforce. Unchanged behaviour — any authentication for it lives
    /// elsewhere (e.g. [`crate::provider_auth`] for Telegram) or nowhere.
    NotApplicable,
}

/// Why a request was refused. Separated from the HTTP response so the decision
/// is unit-testable without building a `Response`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// The request carried no signature header at all.
    MissingSignature,
    /// The pack ships no ingress component, so nothing can verify it.
    NoVerifier,
    /// The ingress component accepted a corrupted signature — verification is
    /// not actually running (almost always: the signing secret is not
    /// configured for this deployment).
    VerificationInactive,
    /// The ingress component rejected the signature.
    InvalidSignature,
    /// The ingress component could not be run at all.
    VerifierUnavailable,
}

impl Refusal {
    /// Client-facing text. Deliberately terse: an unauthenticated caller learns
    /// only that it was refused, never which of the internal conditions fired.
    fn client_message(self) -> &'static str {
        match self {
            Refusal::MissingSignature | Refusal::InvalidSignature => {
                "webhook signature verification failed"
            }
            Refusal::NoVerifier | Refusal::VerificationInactive | Refusal::VerifierUnavailable => {
                "webhook signature verification is unavailable"
            }
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Refusal::MissingSignature | Refusal::InvalidSignature => StatusCode::UNAUTHORIZED,
            // Not the caller's fault and retryable once an operator acts.
            Refusal::NoVerifier | Refusal::VerificationInactive | Refusal::VerifierUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    }
}

/// Result of running the pack's ingress component for one call.
type IngressCallResult = Result<JsonValue, String>;

/// Verify an inbound provider webhook before its body is trusted.
///
/// `pack_path` is the `.gtpack` the matched route came from; `pack_id` scopes
/// the component's secret reads. `headers` are the raw request headers,
/// `body` the raw request body — both exactly as received, because the
/// signature covers the bytes on the wire.
/// Does this provider class need [`verify_inbound_provider_webhook`]?
///
/// A cheap, allocation-light pre-check so the dispatcher can skip the blocking
/// hop entirely for the classes this gate does not cover — DirectLine/WebChat
/// is chatty and pays that hop per poll otherwise.
pub(crate) fn requires_verification(provider_type: &str) -> bool {
    signed_provider_class(provider_type).is_some()
}

pub(crate) fn verify_inbound_provider_webhook(
    provider_type: &str,
    pack_id: &str,
    pack_path: &Path,
    secrets: DynSecretsManager,
    tenant: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<WebhookVerification, Box<Response<Full<Bytes>>>> {
    let Some(class) = signed_provider_class(provider_type) else {
        return Ok(WebhookVerification::NotApplicable);
    };

    let extension = match read_provider_ingress_extension(pack_path) {
        Ok(Some(extension)) => extension,
        Ok(None) => return Err(refuse(class, Refusal::NoVerifier, None)),
        Err(err) => {
            return Err(refuse(class, Refusal::NoVerifier, Some(format!("{err:#}"))));
        }
    };

    verify_with(class, headers, body, |calls| {
        invoke_pack_ingress_extension(
            pack_path, pack_id, &extension, secrets,
            // The gate needs no state store: it discards the normalized body
            // and only reads the accept/reject decision. A component that
            // reaches for state here fails the call, which refuses the request
            // rather than passing it — the safe direction.
            None, tenant,
            // Matches the `ExecCtx` `RunnerHost::invoke_provider_for_revision`
            // builds for this same pack (team: None). Secret scoping keys off
            // the team, so a different value here would read a different URI
            // than every other secret this pack resolves on this path.
            None, None, calls,
        )
    })
}

/// The decision, with the component invocation injected.
///
/// Split out so tests can drive every branch with a stand-in component. The
/// stand-in is what makes the "remove the check and a test goes red" property
/// real: the crypto itself belongs to the pack and is tested there.
fn verify_with<F>(
    class: &SignedProviderClass,
    headers: &[(String, String)],
    body: &[u8],
    invoke: F,
) -> Result<WebhookVerification, Box<Response<Full<Bytes>>>>
where
    F: FnOnce(&[IngressExtensionCall]) -> anyhow::Result<Vec<IngressCallResult>>,
{
    // No signature at all: refuse before running anything. Slack never delivers
    // an event without one, so this is either a misconfiguration or a direct
    // unauthenticated hit.
    if find_header(headers, class.signature_header).is_none() {
        return Err(refuse(class, Refusal::MissingSignature, None));
    }

    let body_json = match std::str::from_utf8(body) {
        Ok(body) => body.to_string(),
        // The signature covers the raw bytes and the component takes a string;
        // a non-utf8 body cannot be handed over intact, so it cannot be
        // verified, so it is refused.
        Err(_) => return Err(refuse(class, Refusal::InvalidSignature, None)),
    };

    let real_headers = headers_json(headers, None);
    let probe_headers = headers_json(headers, Some(class.signature_header));

    // Negative control first: if the component accepts a corrupted signature
    // there is nothing to learn from the real one.
    let calls = [
        IngressExtensionCall {
            headers_json: probe_headers,
            body_json: body_json.clone(),
        },
        IngressExtensionCall {
            headers_json: real_headers,
            body_json,
        },
    ];

    let results = match invoke(&calls) {
        Ok(results) if results.len() == calls.len() => results,
        Ok(results) => {
            return Err(refuse(
                class,
                Refusal::VerifierUnavailable,
                Some(format!(
                    "ingress component returned {} result(s) for {} call(s)",
                    results.len(),
                    calls.len()
                )),
            ));
        }
        Err(err) => {
            return Err(refuse(
                class,
                Refusal::VerifierUnavailable,
                Some(format!("{err:#}")),
            ));
        }
    };

    if results[0].is_ok() {
        return Err(refuse(class, Refusal::VerificationInactive, None));
    }
    match &results[1] {
        Ok(_) => Ok(WebhookVerification::Verified),
        Err(message) => Err(refuse(
            class,
            Refusal::InvalidSignature,
            Some(message.clone()),
        )),
    }
}

fn signed_provider_class(provider_type: &str) -> Option<&'static SignedProviderClass> {
    let name = derive_provider_name(provider_type)?;
    SIGNED_PROVIDER_CLASSES
        .iter()
        .find(|class| class_matches(&name, class.provider))
}

/// Does a derived provider name belong to `family`?
///
/// [`derive_provider_name`] only strips a trailing kind segment it recognises
/// (`bot`, `graph`, `client`, `gui`, `webhook`) and joins whatever is left with
/// `-`. The shipped Slack pack declares `provider_type: messaging.slack.api`,
/// and `api` is not on that list, so the derived name is `slack-api`, not
/// `slack`. An equality match here would therefore have silently failed to gate
/// the one provider this module exists for — the gate would compile, pass its
/// own tests, and never fire in production.
///
/// So a family matches its own name or any `<family>-<kind>` refinement of it.
/// `-` is the segment joiner, so this cannot reach across into an unrelated
/// provider whose name merely starts with the same letters.
fn class_matches(derived_name: &str, family: &str) -> bool {
    derived_name == family
        || derived_name
            .strip_prefix(family)
            .is_some_and(|rest| rest.starts_with('-'))
}

/// Serialize the request headers into the `{name: value}` object the
/// `provider:common/ingress` contract passes to `handle-webhook`.
///
/// When `corrupt` names a header, that header's value is mutated so a correct
/// signature check must reject it. Appending a character is enough for every
/// signature scheme in use (hex digests are fixed-length and compared for
/// equality) and keeps the header present, so the component takes the same
/// branch it would for a genuine request rather than an early "missing header"
/// return — which would make the probe prove nothing.
fn headers_json(headers: &[(String, String)], corrupt: Option<&str>) -> String {
    let mut map = JsonMap::new();
    for (name, value) in headers {
        let value = match corrupt {
            Some(target) if name.eq_ignore_ascii_case(target) => format!("{value}0"),
            _ => value.clone(),
        };
        map.insert(name.clone(), JsonValue::String(value));
    }
    // Infallible: every value is a string.
    JsonValue::Object(map).to_string()
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn refuse(
    class: &SignedProviderClass,
    refusal: Refusal,
    detail: Option<String>,
) -> Box<Response<Full<Bytes>>> {
    let detail = detail.unwrap_or_default();
    let message = match refusal {
        Refusal::MissingSignature => format!(
            "refusing {} webhook: no {} header",
            class.provider, class.signature_header
        ),
        Refusal::NoVerifier => format!(
            "refusing {} webhook: the pack declares no messaging.provider_ingress.v1 \
             component, so its signature cannot be verified. {detail}",
            class.provider
        ),
        Refusal::VerificationInactive => format!(
            "refusing {} webhook: the pack's ingress component accepted a corrupted \
             signature, so it is not verifying anything. Configure the `{}` secret for \
             this deployment.",
            class.provider, class.secret_key
        ),
        Refusal::InvalidSignature => {
            format!("refusing {} webhook: {detail}", class.provider)
        }
        Refusal::VerifierUnavailable => format!(
            "refusing {} webhook: the pack's ingress component could not be run: {detail}",
            class.provider
        ),
    };
    operator_log::warn(module_path!(), message);
    // Boxed: `Response` dwarfs the `Ok` variant, and this `Result` is threaded
    // through `spawn_blocking`. Mirrors `resolve_endpoint_admission`.
    Box::new(error_response(refusal.status(), refusal.client_message()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SLACK: &SignedProviderClass = &SIGNED_PROVIDER_CLASSES[0];

    fn signed_headers() -> Vec<(String, String)> {
        vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Slack-Signature".to_string(), "v0=abc".to_string()),
            (
                "x-slack-request-timestamp".to_string(),
                "1700000000".to_string(),
            ),
        ]
    }

    /// A stand-in for `messaging-ingress-slack` that really does check the
    /// signature: it accepts exactly the expected value and rejects anything
    /// else, which is the only property the gate depends on.
    fn verifying_component(
        calls: &[IngressExtensionCall],
    ) -> anyhow::Result<Vec<IngressCallResult>> {
        Ok(calls
            .iter()
            .map(|call| {
                let headers: JsonValue = serde_json::from_str(&call.headers_json).expect("headers");
                let signature = headers
                    .as_object()
                    .and_then(|map| {
                        map.iter()
                            .find(|(name, _)| name.eq_ignore_ascii_case("x-slack-signature"))
                    })
                    .and_then(|(_, value)| value.as_str())
                    .unwrap_or_default()
                    .to_string();
                if signature == "v0=abc" {
                    Ok(json!({"ok": true}))
                } else {
                    Err("validation error: invalid signature".to_string())
                }
            })
            .collect())
    }

    /// A stand-in for the same component with no signing secret configured:
    /// it normalizes everything and never rejects. This is exactly what the
    /// shipped component does today when `SLACK_SIGNING_SECRET` is absent.
    fn unverifying_component(
        calls: &[IngressExtensionCall],
    ) -> anyhow::Result<Vec<IngressCallResult>> {
        Ok(calls.iter().map(|_| Ok(json!({"ok": true}))).collect())
    }

    #[test]
    fn a_correctly_signed_slack_webhook_is_admitted() {
        let outcome = verify_with(SLACK, &signed_headers(), b"{}", verifying_component)
            .expect("correctly signed request should be admitted");
        assert_eq!(outcome, WebhookVerification::Verified);
    }

    #[test]
    fn a_forged_slack_signature_is_refused() {
        let mut headers = signed_headers();
        headers[1].1 = "v0=deadbeef".to_string();
        let response = verify_with(SLACK, &headers, b"{}", verifying_component)
            .expect_err("a forged signature must be refused");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn a_slack_webhook_with_no_signature_header_is_refused() {
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        let response = verify_with(SLACK, &headers, b"{}", verifying_component)
            .expect_err("an unsigned request must be refused");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// The fail-closed property this module exists for: a component that is not
    /// actually verifying (no signing secret configured) must not be able to
    /// wave traffic through, even though it answers "ok" to everything.
    #[test]
    fn a_component_that_accepts_a_corrupted_signature_cannot_admit_anything() {
        let response = verify_with(SLACK, &signed_headers(), b"{}", unverifying_component)
            .expect_err("a component that verifies nothing must not admit a request");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn a_verifier_that_cannot_be_run_refuses_rather_than_passing() {
        let response = verify_with(SLACK, &signed_headers(), b"{}", |_| {
            Err(anyhow::anyhow!("component instantiation failed"))
        })
        .expect_err("an unrunnable verifier must refuse");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn a_short_result_batch_refuses_rather_than_indexing_past_the_end() {
        let response = verify_with(SLACK, &signed_headers(), b"{}", |_| Ok(vec![]))
            .expect_err("a truncated result batch must refuse");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn the_probe_corrupts_only_the_signature_header_and_keeps_it_present() {
        let headers = signed_headers();
        let probe: JsonValue =
            serde_json::from_str(&headers_json(&headers, Some("x-slack-signature")))
                .expect("probe headers");
        assert_eq!(probe["X-Slack-Signature"], json!("v0=abc0"));
        assert_eq!(probe["x-slack-request-timestamp"], json!("1700000000"));
        assert_eq!(probe["Content-Type"], json!("application/json"));
    }

    #[test]
    fn the_real_call_carries_the_headers_verbatim() {
        let headers = signed_headers();
        let real: JsonValue =
            serde_json::from_str(&headers_json(&headers, None)).expect("real headers");
        assert_eq!(real["X-Slack-Signature"], json!("v0=abc"));
    }

    /// The `provider_type` the shipped `messaging-slack` pack actually
    /// declares. Pinned as a constant so the reason this exact string matters
    /// is visible: `derive_provider_name` renders it `slack-api`, and an
    /// equality match against `slack` would leave the real pack ungated.
    const SHIPPED_SLACK_PROVIDER_TYPE: &str = "messaging.slack.api";

    #[test]
    fn the_provider_type_the_shipped_slack_pack_declares_is_gated() {
        assert_eq!(
            signed_provider_class(SHIPPED_SLACK_PROVIDER_TYPE).map(|class| class.provider),
            Some("slack"),
            "messaging-slack declares `{SHIPPED_SLACK_PROVIDER_TYPE}`; if this stops \
             matching, Slack webhooks are served unverified again"
        );
    }

    #[test]
    fn only_provider_classes_with_a_known_signature_are_gated() {
        assert_eq!(
            signed_provider_class("messaging.slack").map(|class| class.provider),
            Some("slack")
        );
        assert_eq!(
            signed_provider_class("messaging.slack.client").map(|class| class.provider),
            Some("slack")
        );
        // A different provider that merely starts with the same letters is not
        // a Slack refinement — `-` is the segment joiner.
        assert!(signed_provider_class("messaging.slackalike").is_none());
        // Telegram is authenticated by `provider_auth` against the endpoint's
        // `webhook_secret_ref`; its ingress component checks nothing, so
        // gating it here would refuse every legitimate update.
        assert!(signed_provider_class("messaging.telegram.bot").is_none());
        assert!(signed_provider_class("messaging.webchat.gui").is_none());
    }

    #[test]
    fn a_non_utf8_body_cannot_be_verified_and_is_refused() {
        let response = verify_with(SLACK, &signed_headers(), &[0xff, 0xfe], verifying_component)
            .expect_err("a body that cannot be handed to the verifier must be refused");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn refusal_text_sent_to_the_caller_never_names_the_internal_condition() {
        for refusal in [
            Refusal::MissingSignature,
            Refusal::NoVerifier,
            Refusal::VerificationInactive,
            Refusal::InvalidSignature,
            Refusal::VerifierUnavailable,
        ] {
            let message = refusal.client_message();
            assert!(
                !message.contains("secret") && !message.contains("component"),
                "client-facing refusal leaked an internal detail: {message}"
            );
        }
    }
}
