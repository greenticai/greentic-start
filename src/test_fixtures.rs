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

use greentic_deploy_spec::{
    BundleId, Environment, EnvironmentHostConfig, MessagingEndpoint, MessagingEndpointId,
    SchemaVersion,
};
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
        linked_bundles: bundles.iter().map(|b| BundleId::new(*b)).collect(),
        welcome_flow: None,
        generation: 1,
        created_at: now,
        updated_at: now,
        updated_by: "test".to_string(),
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
        credentials_ref: None,
        bundles: Vec::new(),
        revisions: Vec::new(),
        traffic_splits: Vec::new(),
        revocation: Default::default(),
        retention: Default::default(),
        health: Default::default(),
    }
}
