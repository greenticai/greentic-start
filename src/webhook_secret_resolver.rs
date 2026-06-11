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

/// Flip the deploy-spec `secret://` prefix to the dev-store `secrets://`
/// prefix. The two schemes refer to the same logical URI but live in
/// different layers of the stack: the deployer's deploy-spec uses
/// `secret://` (singular) on persisted artifacts; the runtime's
/// `DevStore`-backed `SecretsManager` uses `secrets://` (plural). Mirrors
/// the deployer-side helper at `cli::secrets::secret_ref_to_store_uri`,
/// kept in sync deliberately — drift breaks the producer/consumer
/// contract silently.
pub(crate) fn secret_ref_to_store_uri(secret_ref: &SecretRef) -> String {
    secret_ref.as_str().replacen("secret://", "secrets://", 1)
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
}
