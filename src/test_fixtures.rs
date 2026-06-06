//! Test fixtures shared across the messaging-endpoint admit + resolver
//! modules. Kept `pub(crate)` and `#[cfg(test)]` so they never appear in
//! release builds and never leak out of the crate.
//!
//! Centralized because [`endpoint_admit::tests`] and
//! [`endpoint_resolver::tests`] otherwise drift on the same
//! `MessagingEndpoint` / `Environment` construction boilerplate every time
//! the deploy-spec adds a field.
//!
//! [`endpoint_admit::tests`]: crate::endpoint_admit
//! [`endpoint_resolver::tests`]: crate::endpoint_resolver

use std::collections::HashMap;

use greentic_deploy_spec::{
    BundleId, Environment, EnvironmentHostConfig, MessagingEndpoint, MessagingEndpointId,
    SchemaVersion, SecretRef,
};
use greentic_secrets_lib::{Result as SecretResult, SecretError, SecretsManager};
use greentic_types::EnvId;

pub(crate) fn env_id() -> EnvId {
    EnvId::try_from("local").unwrap()
}

/// Build a `MessagingEndpoint` for tests. Defaults `provider_type` to
/// `"teams"`; use [`endpoint_typed`] when the test cares about cross-type
/// behavior.
pub(crate) fn endpoint(provider_id: &str, bundles: &[&str]) -> MessagingEndpoint {
    endpoint_typed("teams", provider_id, bundles)
}

pub(crate) fn endpoint_typed(
    provider_type: &str,
    provider_id: &str,
    bundles: &[&str],
) -> MessagingEndpoint {
    let now = chrono::Utc::now();
    MessagingEndpoint {
        schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
        env_id: env_id(),
        endpoint_id: MessagingEndpointId::new(),
        provider_id: provider_id.to_string(),
        provider_type: provider_type.to_string(),
        display_name: provider_id.to_string(),
        secret_refs: Vec::new(),
        webhook_secret_ref: None,
        linked_bundles: bundles.iter().map(|b| BundleId::new(*b)).collect(),
        welcome_flow: None,
        generation: 1,
        created_at: now,
        updated_at: now,
        updated_by: "test".to_string(),
    }
}

/// Build a Telegram-class endpoint with a `webhook_secret_ref` set. The
/// returned URI is well-formed for the current env id (`local`) and
/// matches the deployer's auto-gen URI scheme; tests that need to
/// resolve it through a `SecretsManager` must seed the value at the
/// canonical 5-segment dev-store path (`secrets://...`).
pub(crate) fn telegram_endpoint_with_webhook_secret(
    provider_id: &str,
    bundles: &[&str],
) -> MessagingEndpoint {
    let mut ep = endpoint_typed("telegram", provider_id, bundles);
    let eid_lower = ep.endpoint_id.to_string().to_lowercase();
    ep.webhook_secret_ref = Some(
        SecretRef::try_new(format!(
            "secret://{}/default/_/messaging-{}/webhook_secret",
            env_id(),
            eid_lower
        ))
        .expect("well-formed secret ref"),
    );
    ep
}

/// In-memory `SecretsManager` for tests. Keyed on the canonical dev-store
/// URI (`secrets://...`), so seeding uses
/// [`crate::webhook_secret_resolver::secret_ref_to_store_uri`] for parity
/// with the real producer/consumer flow. Centralized here to avoid drift
/// when the `SecretsManager` trait gains required methods — three modules
/// (`provider_auth::tests`, `revision_webhook_register::tests`, and any
/// future webhook-secret consumer) share the same mock.
pub(crate) struct FakeSecrets(pub(crate) HashMap<String, Vec<u8>>);

#[async_trait::async_trait]
impl SecretsManager for FakeSecrets {
    async fn read(&self, path: &str) -> SecretResult<Vec<u8>> {
        self.0
            .get(path)
            .cloned()
            .ok_or_else(|| SecretError::NotFound(path.to_string()))
    }
    async fn write(&self, _: &str, _: &[u8]) -> SecretResult<()> {
        Err(SecretError::Permission("read-only".into()))
    }
    async fn delete(&self, _: &str) -> SecretResult<()> {
        Err(SecretError::Permission("read-only".into()))
    }
}

/// Build a minimal `Environment` carrying just the messaging endpoints — the
/// rest of the deploy-spec fields default to empty. Sufficient for admit /
/// resolver tests, which only consult `messaging_endpoints`.
pub(crate) fn env_with(endpoints: Vec<MessagingEndpoint>) -> Environment {
    Environment {
        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
        environment_id: env_id(),
        name: "local".to_string(),
        host_config: EnvironmentHostConfig {
            env_id: env_id(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
        },
        packs: Vec::new(),
        messaging_endpoints: endpoints,
        extensions: Vec::new(),
        credentials_ref: None,
        bundles: Vec::new(),
        revisions: Vec::new(),
        traffic_splits: Vec::new(),
        revocation: Default::default(),
        retention: Default::default(),
        health: Default::default(),
    }
}
