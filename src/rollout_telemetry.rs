//! C5.3 rollout-event emission helpers.
//!
//! Wraps [`greentic_telemetry::emit_rollout_event`] with greentic-start's
//! local attribution sources so every emission site shares the same
//! tenant-fallback and cardinality discipline. Centralizing the
//! `TelemetryCtx` construction keeps the `gt.*` field set in lockstep
//! across the drain coordinator and health gate.
//!
//! ## Tenant attribution
//!
//! - Drain transitions ride a per-invocation `DrainRequest`, which carries
//!   `tenant` explicitly.
//! - Health-gate transitions only see [`Environment`], which carries
//!   `host_config.tenant_org_id: Option<String>` (the env owner). We use
//!   that with a `"local"` fallback for envs without an owner (the
//!   single-process dev env).
//!
//! ## Sites currently NOT emitting
//!
//! - [`RevisionDispatcher::apply_traffic_split`](crate::revision_dispatcher::RevisionDispatcher::apply_traffic_split):
//!   tenant context isn't reachable at the dispatcher layer (the dispatcher
//!   is per-env, not per-tenant). The corresponding `TrafficSplitApplied`
//!   event lands in a Phase-D PR that threads tenant through the caller
//!   (operator CLI, HTTP ingress).
//! - `RevisionStaged` / `RevisionWarmed`: no live producer at this layer;
//!   covered by Phase D.

use greentic_deploy_spec::{BundleId, DeploymentId, Environment, Revision, RevisionId};
use greentic_telemetry::{RolloutEvent, TelemetryCtx, emit_rollout_event};

/// Fallback tenant for envs without an owner — matches the operator's
/// single-process `local` convention.
const LOCAL_TENANT_FALLBACK: &str = "local";

/// Build the [`TelemetryCtx`] for a drain transition — tenant + env +
/// deployment + bundle + revision. Pure, no I/O, so it can be inspected in
/// unit tests via [`TelemetryCtx::kv`] without standing up a subscriber.
pub(crate) fn build_drain_ctx(
    tenant: &str,
    env_id: &str,
    deployment_id: DeploymentId,
    bundle_id: &BundleId,
    revision_id: RevisionId,
) -> TelemetryCtx {
    TelemetryCtx::new(tenant)
        .with_env(env_id)
        .with_deployment_id(deployment_id.to_string())
        .with_bundle_id(bundle_id.to_string())
        .with_revision_id(revision_id.to_string())
}

/// Build the [`TelemetryCtx`] for a health-gate transition. Pure (same
/// rationale as [`build_drain_ctx`]).
///
/// Uses the env's `host_config.tenant_org_id` as the tenant (the env owner),
/// falling back to [`LOCAL_TENANT_FALLBACK`] for envs without an owner.
pub(crate) fn build_health_gate_ctx(env: &Environment, revision: &Revision) -> TelemetryCtx {
    let tenant = env
        .host_config
        .tenant_org_id
        .as_deref()
        .unwrap_or(LOCAL_TENANT_FALLBACK);
    TelemetryCtx::new(tenant)
        .with_env(env.environment_id.as_str())
        .with_deployment_id(revision.deployment_id.to_string())
        .with_bundle_id(revision.bundle_id.to_string())
        .with_revision_id(revision.revision_id.to_string())
}

/// Emit a per-revision drain transition (`RevisionDraining` or
/// `RevisionEvicted`) with the attribution available at the drain
/// coordinator: tenant + env + deployment + bundle + revision.
pub(crate) fn emit_drain_transition(
    event: RolloutEvent,
    tenant: &str,
    env_id: &str,
    deployment_id: DeploymentId,
    bundle_id: &BundleId,
    revision_id: RevisionId,
) {
    let ctx = build_drain_ctx(tenant, env_id, deployment_id, bundle_id, revision_id);
    emit_rollout_event(event, &ctx);
}

/// Emit a health-gate transition (`HealthGatePassed` or `HealthGateFailed`).
///
/// Uses the env's `host_config.tenant_org_id` as the tenant (the env owner),
/// falling back to `"local"` for envs without an owner (the single-process
/// dev env). The revision carries its own bundle/deployment/revision IDs.
pub(crate) fn emit_health_gate_transition(
    event: RolloutEvent,
    env: &Environment,
    revision: &Revision,
) {
    let ctx = build_health_gate_ctx(env, revision);
    emit_rollout_event(event, &ctx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use greentic_deploy_spec::{
        BundleId, DeploymentId, EnvId, Environment, EnvironmentHostConfig, PackId, PackListEntry,
        Revision, RevisionId, RevisionLifecycle, SchemaVersion, SemVer,
    };
    use std::path::PathBuf;

    fn env_with_owner(owner: Option<&str>) -> Environment {
        Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: EnvId::try_from("prod-eu").unwrap(),
            name: "prod-eu".into(),
            host_config: EnvironmentHostConfig {
                env_id: EnvId::try_from("prod-eu").unwrap(),
                region: None,
                tenant_org_id: owner.map(str::to_string),
                listen_addr: None,
            },
            packs: Vec::new(),
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        }
    }

    fn sample_revision() -> Revision {
        Revision {
            schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
            revision_id: RevisionId::new(),
            env_id: EnvId::try_from("prod-eu").unwrap(),
            bundle_id: BundleId::new("customer.support"),
            deployment_id: DeploymentId::new(),
            sequence: 1,
            created_at: Utc.timestamp_opt(0, 0).unwrap(),
            bundle_digest: "sha256:00".into(),
            pack_list: vec![PackListEntry {
                pack_id: PackId::new("greentic.support.pack"),
                version: SemVer::new(1, 0, 0),
                digest: "sha256:00".into(),
                source_uri: None,
            }],
            pack_list_lock_ref: PathBuf::from("pack-list.lock"),
            config_digest: "sha256:00".into(),
            signature_sidecar_ref: PathBuf::from("rev.sig"),
            lifecycle: RevisionLifecycle::Warming,
            staged_at: None,
            warmed_at: None,
            drain_seconds: 30,
            abort_metrics: Vec::new(),
        }
    }

    fn get<'a>(kv: &'a [(&'static str, Option<&str>)], key: &str) -> Option<&'a str> {
        kv.iter().find(|(k, _)| *k == key).and_then(|(_, v)| *v)
    }

    #[test]
    fn drain_ctx_populates_tenant_env_deployment_bundle_revision() {
        let deployment_id = DeploymentId::new();
        let bundle_id = BundleId::new("customer.support");
        let revision_id = RevisionId::new();
        let ctx = build_drain_ctx("acme", "prod-eu", deployment_id, &bundle_id, revision_id);
        let kv = ctx.kv();
        assert_eq!(get(&kv, "gt.tenant"), Some("acme"));
        assert_eq!(get(&kv, "gt.env"), Some("prod-eu"));
        assert_eq!(
            get(&kv, "gt.deployment_id"),
            Some(deployment_id.to_string().as_str())
        );
        assert_eq!(get(&kv, "gt.bundle_id"), Some("customer.support"));
        assert_eq!(
            get(&kv, "gt.revision_id"),
            Some(revision_id.to_string().as_str())
        );
        // C5.3 does not stamp pack_id / env_pack_kind / generation at the
        // drain layer (see module doc).
        assert!(get(&kv, "gt.pack_id").is_none());
        assert!(get(&kv, "gt.env_pack_kind").is_none());
        assert!(get(&kv, "gt.generation").is_none());
    }

    #[test]
    fn health_gate_ctx_uses_env_tenant_org_id_when_set() {
        let env = env_with_owner(Some("acme"));
        let rev = sample_revision();
        let ctx = build_health_gate_ctx(&env, &rev);
        let kv = ctx.kv();
        assert_eq!(get(&kv, "gt.tenant"), Some("acme"));
        assert_eq!(get(&kv, "gt.env"), Some("prod-eu"));
        assert_eq!(get(&kv, "gt.bundle_id"), Some("customer.support"));
        assert_eq!(
            get(&kv, "gt.deployment_id"),
            Some(rev.deployment_id.to_string().as_str())
        );
        assert_eq!(
            get(&kv, "gt.revision_id"),
            Some(rev.revision_id.to_string().as_str())
        );
    }

    /// `local` envs have `host_config.tenant_org_id == None`; the helper
    /// falls back to [`LOCAL_TENANT_FALLBACK`] so the emitted
    /// `gt.tenant` attribute is never empty.
    #[test]
    fn health_gate_ctx_falls_back_to_local_tenant_when_unowned() {
        let env = env_with_owner(None);
        let rev = sample_revision();
        let ctx = build_health_gate_ctx(&env, &rev);
        assert_eq!(get(&ctx.kv(), "gt.tenant"), Some(LOCAL_TENANT_FALLBACK));
    }

    /// The `emit_*` wrappers don't panic when no subscriber is installed —
    /// matches the contract `emit_rollout_event` itself guarantees in
    /// greentic-telemetry. Cheap smoke test so the wrappers stay safe.
    #[test]
    fn emit_helpers_do_not_panic_without_subscriber() {
        let deployment_id = DeploymentId::new();
        let bundle_id = BundleId::new("customer.support");
        let revision_id = RevisionId::new();
        emit_drain_transition(
            RolloutEvent::RevisionDraining,
            "acme",
            "prod-eu",
            deployment_id,
            &bundle_id,
            revision_id,
        );
        emit_drain_transition(
            RolloutEvent::RevisionEvicted,
            "acme",
            "prod-eu",
            deployment_id,
            &bundle_id,
            revision_id,
        );
        let env = env_with_owner(Some("acme"));
        let rev = sample_revision();
        emit_health_gate_transition(RolloutEvent::HealthGatePassed, &env, &rev);
        emit_health_gate_transition(RolloutEvent::HealthGateFailed, &env, &rev);
    }
}
