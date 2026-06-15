//! URI-scheme bridge between the deploy-spec [`SecretRef`] (`secret://`,
//! singular) and the runtime dev-store [`SecretsManager`] URIs
//! (`secrets://`, plural). The deployer writes the value at the dev-store
//! URI; the runtime reads it back at the same URI. This module hosts the
//! single shared helper that flips the prefix so producer and consumer
//! never drift on the exact key.
//!
//! Used by [`crate::revision_webhook_register`] (to fetch the IID
//! `secret_token` it installs on the provider side via
//! [`crate::revision_webhook_register::SETUP_WEBHOOK_OP`]) and by
//! [`crate::revision_serve`]'s `dispatch_provider_route` (to authenticate
//! inbound provider webhooks against the expected per-endpoint value).
//!
//! [`SecretsManager`]: greentic_secrets_lib::SecretsManager

use greentic_deploy_spec::SecretRef;

/// Convert the deploy-spec `secret://` ref into the dev-store `secrets://`
/// URI. The two schemes refer to the same logical secret but live in
/// different layers of the stack: the deployer's deploy-spec uses
/// `secret://` (singular) on persisted artifacts; the runtime's
/// `DevStore`-backed `SecretsManager` uses `secrets://` (plural).
///
/// Delegates to the single authoritative converter in `greentic-secrets`
/// (`greentic_secrets_lib::SecretRef::to_store_uri`), which also
/// re-canonicalizes the team segment (`default` → `_`) so a ref written under
/// either form resolves to the same store location — the "`_` everywhere"
/// rule. This replaces the hand-maintained `replacen` copy that previously had
/// to be kept in sync with the deployer's.
///
/// The deploy-spec ref's raw string is re-parsed through the lib's
/// [`greentic_secrets_lib::SecretRef`] so this stays decoupled from whichever
/// `greentic-deploy-spec` version is in the tree. Webhook refs are always
/// store-aligned 5-segment refs, so the conversion succeeds; the prefix-flip
/// fallback only guards a malformed ref the converter rejects, preserving the
/// previous infallible behavior rather than panicking on an unexpected shape.
pub(crate) fn secret_ref_to_store_uri(secret_ref: &SecretRef) -> String {
    greentic_secrets_lib::SecretRef::try_new(secret_ref.as_str())
        .ok()
        .and_then(|store_aligned| store_aligned.to_store_uri().ok())
        .map(|uri| uri.to_string())
        .unwrap_or_else(|| secret_ref.as_str().replacen("secret://", "secrets://", 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flips_singular_secret_prefix_to_plural() {
        let r =
            SecretRef::try_new("secret://local/default/_/messaging-abc/webhook_secret".to_string())
                .unwrap();
        assert_eq!(
            secret_ref_to_store_uri(&r),
            "secrets://local/default/_/messaging-abc/webhook_secret"
        );
    }

    #[test]
    fn flip_replaces_only_the_first_occurrence() {
        // `secret://` appears nested in the URI's tail — only the leading
        // prefix flips, never an embedded substring (the dev-store name
        // can legally contain the substring `secret`).
        let r =
            SecretRef::try_new("secret://local/default/_/messaging-abc/secret_field".to_string())
                .unwrap();
        assert_eq!(
            secret_ref_to_store_uri(&r),
            "secrets://local/default/_/messaging-abc/secret_field"
        );
    }

    #[test]
    fn normalizes_default_team_to_underscore() {
        // A ref carrying the literal `default` team resolves to the same `_`
        // store location as one carrying `_`, so the deployer (producer) and
        // the runtime (reader) can never drift on the team segment.
        let defaulted = SecretRef::try_new(
            "secret://local/acme/default/messaging-abc/webhook_secret".to_string(),
        )
        .unwrap();
        assert_eq!(
            secret_ref_to_store_uri(&defaulted),
            "secrets://local/acme/_/messaging-abc/webhook_secret"
        );
    }
}
