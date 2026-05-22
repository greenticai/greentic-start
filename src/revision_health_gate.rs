//! Warm/ready health-gate consumer (B9b of `plans/next-gen-deployment.md`).
//!
//! B9a shipped the seam in `greentic-deployer`:
//! [`HealthCheckId`](greentic_deployer::environment::HealthCheckId),
//! [`HealthGateFailure`](greentic_deployer::environment::HealthGateFailure),
//! [`apply_revision_transition_with_health_gate`](greentic_deployer::environment::apply_revision_transition_with_health_gate),
//! and the [`warm_with_health_gate`](greentic_deployer::cli::revisions::warm_with_health_gate)
//! adapter that accepts a `FnOnce(&Environment, &Revision) -> Result<(),
//! HealthGateFailure>` closure.
//!
//! B9b is the consumer in `greentic-start`. The closure-friendly seam in
//! the deployer is wrapped here as a [`RevisionHealthGate`] trait so a
//! Phase-D operator HTTP handler can hold one `Arc<dyn RevisionHealthGate>`
//! and use it across many warm requests. Producer wiring (operator
//! `/deployments/warm` handler → `Arc<dyn RevisionHealthGate>` → closure
//! adapter passed to `warm_with_health_gate`) is Phase D — this module
//! ships the trait, the no-op default for tests, and a real
//! [`StartRevisionHealthGate`] that exercises the checks whose producers
//! land at or before B9 (runtime-config loader from B0; signature_sidecar
//! _ref existence as a placeholder for Phase-C2 DSSE verification).
//!
//! The remaining two checks — `RouteTable` and `ProviderHealth` — are
//! Phase-D `Ok(())` stubs in [`StartRevisionHealthGate`]. The
//! static-route validator (B8) currently lives behind `pub(crate)` in
//! `greentic-operator`; provider health probes need a real runner runtime.
//! Both will move out of stub status when their producers land.
//!
//! ## Scaffold-ahead-of-producer
//!
//! Same shape as B0/B1/B2/B3/B7a/B8: this module ships a typed seam +
//! tests + a real impl, but no caller in greentic-start invokes the gate
//! yet — the production call site lives behind the operator's Phase-D
//! HTTP wiring. The deployer's CLI `warm` (the path operators hit via
//! `gtc op revisions warm`) still funnels through a noop gate today,
//! preserving Phase-A/B behavior for non-HTTP callers until Phase-D
//! flips the operator handler to `warm_with_health_gate(..., gate)`.

use std::path::PathBuf;

use greentic_deploy_spec::{Environment, Revision};
use greentic_deployer::environment::{HealthCheckId, HealthGateFailure};

/// A gate that decides whether a revision is ready to transition to
/// `Ready` (or to be admitted to live traffic on apply-time gates).
///
/// Implementors run their checks against the post-chain `(env, revision)`
/// view passed by the lifecycle helper — see
/// [`apply_revision_transition_with_health_gate`](greentic_deployer::environment::apply_revision_transition_with_health_gate)
/// for the exact contract. Multiple check failures should be aggregated
/// into a single [`HealthGateFailure`] so the operator sees every reason
/// the warm was rejected, not just the first.
///
/// `Send + Sync` so a Phase-D operator handler can hold `Arc<dyn
/// RevisionHealthGate>` across `tokio::spawn_blocking` calls into the
/// deployer's blocking CLI verbs.
pub trait RevisionHealthGate: Send + Sync {
    fn check(&self, env: &Environment, revision: &Revision) -> Result<(), HealthGateFailure>;
}

/// Always-pass gate. The deployer's `warm` CLI (no `_with_health_gate`
/// variant) uses an inline `|_, _| Ok(())` closure equivalent to this
/// impl; this struct is the trait-shape analog, used by tests and as the
/// default when a producer has not wired a real gate.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRevisionHealthGate;

impl RevisionHealthGate for NoopRevisionHealthGate {
    fn check(&self, _env: &Environment, _revision: &Revision) -> Result<(), HealthGateFailure> {
        Ok(())
    }
}

/// Default greentic-start health gate.
///
/// Runs the four B9 checks; today only two have producers:
/// - [`HealthCheckId::RuntimeConfig`] — if `<env_root>/<env_id>/runtime-
///   config.json` exists, it must load and validate through the B0 loader
///   ([`crate::runtime_config::load_in`]). Absent runtime-config is OK
///   (the common case until Phase-D producers materialize the file).
/// - [`HealthCheckId::SignatureStatus`] — `<env_root>/<env_id>/<revision.
///   signature_sidecar_ref>` must exist on disk. Phase-C2 will replace
///   this existence check with real DSSE verification.
/// - [`HealthCheckId::RouteTable`] — Phase-D stub (always Ok). The
///   static-route validator (B8) lives behind `pub(crate)` in
///   `greentic-operator`; lifting it across the crate boundary belongs
///   to the producer gate.
/// - [`HealthCheckId::ProviderHealth`] — Phase-D stub (always Ok). Real
///   probes need a provider runner + network IO.
///
/// All failures are aggregated into one `HealthGateFailure` so the
/// operator sees every reason a warm was rejected, not just the first.
#[derive(Debug, Clone)]
pub struct StartRevisionHealthGate {
    env_root: PathBuf,
}

impl StartRevisionHealthGate {
    /// Construct a gate rooted at `env_root`. Each `env_id` resolves to
    /// `<env_root>/<env_id>` for runtime-config + signature lookups.
    pub fn new(env_root: PathBuf) -> Self {
        Self { env_root }
    }

    /// Construct a gate rooted at the operator's default store root
    /// (`~/.greentic/environments/` on POSIX). Returns an error if the
    /// process has no resolvable home directory.
    pub fn default_root() -> anyhow::Result<Self> {
        let env_root =
            greentic_deployer::environment::LocalFsStore::default_root().ok_or_else(|| {
                anyhow::anyhow!(
                    "cannot determine the default environment store root (no home directory)"
                )
            })?;
        Ok(Self { env_root })
    }
}

impl RevisionHealthGate for StartRevisionHealthGate {
    fn check(&self, env: &Environment, revision: &Revision) -> Result<(), HealthGateFailure> {
        let mut failed_checks: Vec<HealthCheckId> = Vec::new();
        let mut messages: Vec<String> = Vec::new();

        let env_id = env.environment_id.as_str();

        // 1. Runtime config (B0): if the file is present, it must load.
        match crate::runtime_config::load_in(&self.env_root, env_id) {
            Ok(_) => {}
            Err(e) => {
                failed_checks.push(HealthCheckId::RuntimeConfig);
                messages.push(format!("runtime-config load failed: {e:#}"));
            }
        }

        // 2. Signature status (placeholder for Phase-C2 DSSE verify):
        // `signature_sidecar_ref` is an env-relative path that MUST exist
        // on disk when warming. Future DSSE verification slots in here.
        let env_dir = self.env_root.join(env_id);
        let sig_path = env_dir.join(&revision.signature_sidecar_ref);
        if !sig_path.is_file() {
            failed_checks.push(HealthCheckId::SignatureStatus);
            messages.push(format!(
                "signature_sidecar_ref `{}` does not exist or is not a regular file",
                sig_path.display()
            ));
        }

        // 3. Route table — Phase-D stub.
        // 4. Provider health — Phase-D stub.

        if failed_checks.is_empty() {
            Ok(())
        } else {
            Err(HealthGateFailure {
                failed_checks,
                message: messages.join("; "),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use greentic_deploy_spec::{
        BundleId, DeploymentId, EnvId, EnvironmentHostConfig, PackId, PackListEntry, Revision,
        RevisionId, RevisionLifecycle, SchemaVersion, SemVer,
    };
    use tempfile::TempDir;

    const ENV_ID: &str = "local";

    fn fixed_now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 22, 12, 0, 0).unwrap()
    }

    fn env_id() -> EnvId {
        EnvId::try_from(ENV_ID).unwrap()
    }

    fn make_env() -> Environment {
        Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id(),
            name: ENV_ID.to_string(),
            host_config: EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
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

    fn make_revision(sig_ref: PathBuf) -> Revision {
        Revision {
            schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
            revision_id: RevisionId::new(),
            env_id: env_id(),
            bundle_id: BundleId::new("fast2flow"),
            deployment_id: DeploymentId::new(),
            sequence: 1,
            created_at: fixed_now(),
            bundle_digest: "sha256:00".to_string(),
            pack_list: vec![PackListEntry {
                pack_id: PackId::new("greentic.test.pack"),
                version: SemVer::new(1, 0, 0),
                digest: "sha256:00".to_string(),
                source_uri: None,
            }],
            pack_list_lock_ref: PathBuf::from("pack-list.lock"),
            config_digest: "sha256:00".to_string(),
            signature_sidecar_ref: sig_ref,
            lifecycle: RevisionLifecycle::Warming,
            staged_at: Some(fixed_now()),
            warmed_at: None,
            drain_seconds: 30,
            abort_metrics: Vec::new(),
        }
    }

    /// Seeds `<tmp>/local/` with the directory layout the gate inspects.
    /// `sig_present == true` materializes the signature sidecar file at
    /// the relative path `rev.sig` (matches `seed_one_revision`'s default
    /// in the deployer's lifecycle tests).
    fn seed_env(sig_present: bool) -> (TempDir, PathBuf, Revision) {
        let tmp = tempfile::tempdir().unwrap();
        let env_dir = tmp.path().join(ENV_ID);
        std::fs::create_dir_all(&env_dir).unwrap();
        let sig_ref = PathBuf::from("rev.sig");
        if sig_present {
            std::fs::write(env_dir.join(&sig_ref), b"placeholder").unwrap();
        }
        let revision = make_revision(sig_ref);
        let env_root = tmp.path().to_path_buf();
        (tmp, env_root, revision)
    }

    #[test]
    fn noop_always_passes() {
        let (_tmp, _env_root, revision) = seed_env(false);
        let env = make_env();
        let gate = NoopRevisionHealthGate;
        assert!(gate.check(&env, &revision).is_ok());
    }

    #[test]
    fn start_passes_when_signature_present_and_no_runtime_config() {
        let (_tmp, env_root, revision) = seed_env(true);
        let env = make_env();
        let gate = StartRevisionHealthGate::new(env_root);
        let result = gate.check(&env, &revision);
        assert!(result.is_ok(), "expected pass, got `{:?}`", result.err());
    }

    #[test]
    fn start_fails_signature_status_when_sidecar_missing() {
        let (_tmp, env_root, revision) = seed_env(false);
        let env = make_env();
        let gate = StartRevisionHealthGate::new(env_root);
        let err = gate.check(&env, &revision).unwrap_err();
        assert_eq!(err.failed_checks, vec![HealthCheckId::SignatureStatus]);
        assert!(
            err.message.contains("signature_sidecar_ref"),
            "msg: {}",
            err.message
        );
    }

    #[test]
    fn start_fails_runtime_config_when_file_malformed() {
        let (_tmp, env_root, revision) = seed_env(true);
        // Drop a malformed runtime-config.json into the env dir.
        let env_dir = env_root.join(ENV_ID);
        std::fs::write(
            env_dir.join("runtime-config.json"),
            b"{not even close to json",
        )
        .unwrap();
        let env = make_env();
        let gate = StartRevisionHealthGate::new(env_root);
        let err = gate.check(&env, &revision).unwrap_err();
        assert_eq!(err.failed_checks, vec![HealthCheckId::RuntimeConfig]);
        assert!(
            err.message.contains("runtime-config load failed"),
            "msg: {}",
            err.message
        );
    }

    #[test]
    fn start_aggregates_multiple_failures() {
        let (_tmp, env_root, revision) = seed_env(false);
        let env_dir = env_root.join(ENV_ID);
        std::fs::write(env_dir.join("runtime-config.json"), b"{bad").unwrap();
        let env = make_env();
        let gate = StartRevisionHealthGate::new(env_root);
        let err = gate.check(&env, &revision).unwrap_err();
        // Order: RuntimeConfig check runs first, then SignatureStatus.
        assert_eq!(
            err.failed_checks,
            vec![HealthCheckId::RuntimeConfig, HealthCheckId::SignatureStatus]
        );
        assert!(err.message.contains("runtime-config load failed"));
        assert!(err.message.contains("signature_sidecar_ref"));
        // Joiner is "; " so the message reads as two clauses.
        assert!(err.message.contains("; "));
    }

    #[test]
    fn start_passes_with_absent_runtime_config_and_present_signature() {
        // The common case today: nothing materializes runtime-config.json
        // until Phase-D producers land, but the revision's signature
        // sidecar must exist. The gate must NOT flag a missing
        // runtime-config as a failure.
        let (_tmp, env_root, revision) = seed_env(true);
        // Confirm runtime-config.json is absent in our fixture.
        assert!(!env_root.join(ENV_ID).join("runtime-config.json").exists());
        let env = make_env();
        let gate = StartRevisionHealthGate::new(env_root);
        assert!(gate.check(&env, &revision).is_ok());
    }

    /// Trait-object usage: a Phase-D operator handler holds an `Arc<dyn
    /// RevisionHealthGate>` and dispatches via dynamic call. Verify both
    /// concrete impls work behind a trait object.
    #[test]
    fn dyn_trait_object_dispatch_works_for_both_impls() {
        let (_tmp, env_root, revision) = seed_env(true);
        let env = make_env();

        let gates: Vec<std::sync::Arc<dyn RevisionHealthGate>> = vec![
            std::sync::Arc::new(NoopRevisionHealthGate),
            std::sync::Arc::new(StartRevisionHealthGate::new(env_root)),
        ];
        for g in &gates {
            assert!(g.check(&env, &revision).is_ok());
        }
    }

    /// The trait method signature matches what the deployer's
    /// `warm_with_health_gate` closure expects, so an `Arc<dyn
    /// RevisionHealthGate>` adapts to a `FnOnce(&Environment, &Revision)
    /// -> Result<(), HealthGateFailure>` via a thin closure. Compile-time
    /// smoke test confirms the wiring shape Phase-D consumers will use.
    #[test]
    fn adapts_to_warm_with_health_gate_closure_shape() {
        let (_tmp, env_root, revision) = seed_env(true);
        let env = make_env();
        let gate: std::sync::Arc<dyn RevisionHealthGate> =
            std::sync::Arc::new(StartRevisionHealthGate::new(env_root));
        // The closure Phase-D will pass to warm_with_health_gate.
        let closure = |e: &Environment, r: &Revision| gate.check(e, r);
        assert!(closure(&env, &revision).is_ok());
    }
}
