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
//! _ref DSSE verification against the env trust root, Phase-C2).
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

use std::io::Read;
use std::path::PathBuf;

use greentic_deploy_spec::{Environment, Revision};
use greentic_deployer::environment::{HealthCheckId, HealthGateFailure};

/// Upper bound on bytes read for a DSSE signature sidecar. A real
/// single-signature in-toto/DSSE envelope is a few KB; this cap lets the gate
/// fail fast on a malformed or hostile oversized sidecar *before* allocating,
/// since `verify_signature_status` may run while the env transaction lock is
/// held (`warm_with_health_gate`) — an unbounded read there would block that
/// env's recovery operations.
const MAX_SIDECAR_BYTES: u64 = 1 << 20; // 1 MiB

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
/// - [`HealthCheckId::SignatureStatus`] — the revision's
///   `signature_sidecar_ref` must resolve (contained under the env dir) to a
///   DSSE envelope that verifies against this env's closed-by-default trust
///   root and whose in-toto subject pins `revision.bundle_digest`. See
///   [`StartRevisionHealthGate::verify_signature_status`].
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

    /// Verify the revision's DSSE signature sidecar (Phase-C2).
    ///
    /// Returns the rejection reason on any failure; `Ok(())` only when the
    /// sidecar is a contained regular file holding a DSSE envelope that
    /// verifies against this env's closed-by-default trust root and whose
    /// in-toto subject pins `revision.bundle_digest`.
    ///
    /// The containment root is resolved through `env_dir_in` (NOT a raw
    /// `self.env_root.join(env_id)`) so a `.`/`..` env id is rejected here
    /// too — `validate_identifier` permits all-dot ids, which would
    /// otherwise widen the root to the parent of `env_root` for this check
    /// alone. `normalize_under_root` then rejects absolute refs and
    /// canonicalizes (resolving symlinks) before a containment test, so an
    /// absolute / `..` / symlink-escape ref cannot pull in a file outside the
    /// store. The trust root is closed-by-default: a missing or empty
    /// `trust-root.json` yields an empty `TrustRoot`, so verification fails
    /// closed because no signing key matches.
    fn verify_signature_status(&self, env_id: &str, revision: &Revision) -> Result<(), String> {
        // Reject a degenerate/empty bundle digest before any I/O. An empty
        // expected digest would match an envelope whose subject pins an empty
        // sha256, binding the signature to NO artifact. `verify_artifact_dsse`
        // strips a `sha256:` prefix on both sides, so "", "sha256:" and
        // "SHA256:" are all equivalently empty here; mirror that strip so the
        // guard can't be sidestepped by the prefix.
        let digest_hex = revision
            .bundle_digest
            .strip_prefix("sha256:")
            .or_else(|| revision.bundle_digest.strip_prefix("SHA256:"))
            .unwrap_or(revision.bundle_digest.as_str());
        if digest_hex.is_empty() {
            return Err(format!(
                "revision bundle_digest `{}` carries no digest to verify the signature against",
                revision.bundle_digest
            ));
        }

        let env_dir = crate::runtime_config::env_dir_in(&self.env_root, env_id).map_err(|e| {
            format!("environment id `{env_id}` is not a safe directory segment: {e:#}")
        })?;

        // Establish trust before touching the artifact: load the env's
        // closed-by-default trust root first, so a missing/malformed trust
        // root fails the gate without reading the attacker-influenced sidecar.
        let trust_root = greentic_deployer::environment::load_trust_root(&env_dir)
            .map_err(|e| format!("trust root for env `{env_id}` could not be loaded: {e}"))?;

        let sig_path = greentic_deployer::path_safety::normalize_under_root(
            &env_dir,
            &revision.signature_sidecar_ref,
        )
        .map_err(|e| {
            format!(
                "signature_sidecar_ref `{}` is not a contained, existing sidecar: {e:#}",
                revision.signature_sidecar_ref.display()
            )
        })?;

        // `normalize_under_root` returns Ok only when the path canonicalizes
        // (i.e. exists) and stays under `env_dir`; the residual `is_file`
        // guard rejects a contained directory.
        let meta = std::fs::metadata(&sig_path).map_err(|e| {
            format!(
                "signature sidecar `{}` could not be stat'd: {e}",
                sig_path.display()
            )
        })?;
        if !meta.is_file() {
            return Err(format!(
                "signature_sidecar_ref resolves to `{}`, which is not a regular file",
                sig_path.display()
            ));
        }
        // Bounded read (Codex hardening): reject oversized sidecars on the
        // cheap stat'd length, then read through a `take` cap so a file that
        // grows after the stat (TOCTOU) still can't drive allocation past the
        // limit. See `MAX_SIDECAR_BYTES`.
        if meta.len() > MAX_SIDECAR_BYTES {
            return Err(format!(
                "signature sidecar `{}` is {} bytes, which exceeds the {MAX_SIDECAR_BYTES}-byte limit",
                sig_path.display(),
                meta.len()
            ));
        }
        let mut envelope_bytes = Vec::with_capacity(meta.len() as usize);
        std::fs::File::open(&sig_path)
            .and_then(|f| {
                f.take(MAX_SIDECAR_BYTES + 1)
                    .read_to_end(&mut envelope_bytes)
                    .map(|_| ())
            })
            .map_err(|e| {
                format!(
                    "signature sidecar `{}` could not be read: {e}",
                    sig_path.display()
                )
            })?;
        if envelope_bytes.len() as u64 > MAX_SIDECAR_BYTES {
            return Err(format!(
                "signature sidecar `{}` exceeds the {MAX_SIDECAR_BYTES}-byte limit",
                sig_path.display()
            ));
        }

        greentic_distributor_client::signing::verify_artifact_dsse(
            &envelope_bytes,
            &revision.bundle_digest,
            &trust_root,
        )
        .map_err(|e| format!("DSSE signature verification failed: {e}"))?;

        Ok(())
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

        // 2. Signature status (Phase-C2 DSSE verification): the revision's
        // `signature_sidecar_ref` must resolve (contained under the env dir)
        // to a DSSE envelope that verifies against this env's
        // closed-by-default trust root and pins `revision.bundle_digest`.
        // See `verify_signature_status` for the path-containment + verify
        // contract.
        if let Err(msg) = self.verify_signature_status(env_id, revision) {
            failed_checks.push(HealthCheckId::SignatureStatus);
            messages.push(msg);
        }

        // 3. Route table — Phase-D stub.
        // 4. Provider health — Phase-D stub.

        if failed_checks.is_empty() {
            // C5.3: gate passed — emit before returning so the lifecycle
            // event rides the same call.
            crate::rollout_telemetry::emit_health_gate_transition(
                greentic_telemetry::RolloutEvent::HealthGatePassed,
                env,
                revision,
            );
            Ok(())
        } else {
            crate::rollout_telemetry::emit_health_gate_transition(
                greentic_telemetry::RolloutEvent::HealthGateFailed,
                env,
                revision,
            );
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
    use greentic_distributor_client::signing::{
        InTotoStatement, SlsaProvenance, TrustedKey, key_id_for_public_key_pem, sign_statement,
    };
    use std::path::Path;
    use tempfile::TempDir;

    const ENV_ID: &str = "local";

    /// Bare-hex sha256 the fixture revision's bundle is pinned to; signed
    /// sidecars pin this same digest so a valid signature verifies.
    const BUNDLE_DIGEST_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    /// Deterministic Ed25519 keypair from a seed byte:
    /// `(pkcs8 private PEM, spki public PEM, key_id)`.
    fn keypair(seed: u8) -> (String, String, String) {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
        use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        let priv_pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let pub_pem = vk.to_public_key_pem(LineEnding::LF).unwrap();
        let key_id = key_id_for_public_key_pem(&pub_pem).unwrap();
        (priv_pem, pub_pem, key_id)
    }

    /// Serialized DSSE envelope signing a statement that pins `digest_hex`
    /// (bare hex), signed by `priv_pem`/`key_id`.
    fn envelope_bytes(digest_hex: &str, priv_pem: &str, key_id: &str) -> Vec<u8> {
        let stmt = InTotoStatement::provenance(
            "revision.bundle",
            digest_hex,
            SlsaProvenance {
                builder_id: "greentic-start/test".into(),
                build_type: "gtbundle".into(),
                built_at: None,
                tlog_entry_id: None,
            },
        );
        let env = sign_statement(&stmt, priv_pem, key_id).unwrap();
        serde_json::to_vec(&env).unwrap()
    }

    /// Writes a valid signed sidecar to `<env_dir>/<sig_name>` pinning the
    /// fixture bundle digest, then seeds `trust-root.json` (via the deployer's
    /// production writer) trusting the signer.
    fn write_signed_sidecar_and_trust(env_dir: &Path, sig_name: &str) {
        let (priv_pem, pub_pem, key_id) = keypair(1);
        let bytes = envelope_bytes(BUNDLE_DIGEST_HEX, &priv_pem, &key_id);
        std::fs::write(env_dir.join(sig_name), &bytes).unwrap();
        greentic_deployer::environment::add_trusted_key(
            env_dir,
            TrustedKey {
                key_id,
                public_key_pem: pub_pem,
            },
        )
        .unwrap();
    }

    /// Seeds `<tmp>/local/` with a VALID signed sidecar at `rev.sig` plus a
    /// trust root trusting the signer — the happy-path layout the gate accepts.
    fn seed_signed_env() -> (TempDir, PathBuf, Revision) {
        let tmp = tempfile::tempdir().unwrap();
        let env_dir = tmp.path().join(ENV_ID);
        std::fs::create_dir_all(&env_dir).unwrap();
        write_signed_sidecar_and_trust(&env_dir, "rev.sig");
        let revision = make_revision(PathBuf::from("rev.sig"));
        let env_root = tmp.path().to_path_buf();
        (tmp, env_root, revision)
    }

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
            bundle_digest: format!("sha256:{BUNDLE_DIGEST_HEX}"),
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
    fn start_passes_when_signature_verifies_and_no_runtime_config() {
        let (_tmp, env_root, revision) = seed_signed_env();
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
        // Signature must verify so only RuntimeConfig is left to fail.
        let (_tmp, env_root, revision) = seed_signed_env();
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

    /// Codex adversarial finding (high): an ABSOLUTE `signature_sidecar_ref`
    /// must not satisfy the check — `join` would otherwise discard `env_dir`
    /// and resolve the absolute path directly, accepting any existing file
    /// outside the store.
    #[test]
    fn start_fails_signature_status_on_absolute_sidecar_ref() {
        let (_tmp, env_root, mut revision) = seed_env(true);
        // Point at a real, existing absolute file outside the env dir.
        let outside = tempfile::NamedTempFile::new().unwrap();
        assert!(outside.path().is_absolute());
        revision.signature_sidecar_ref = outside.path().to_path_buf();
        let env = make_env();
        let gate = StartRevisionHealthGate::new(env_root);
        let err = gate.check(&env, &revision).unwrap_err();
        assert!(
            err.failed_checks.contains(&HealthCheckId::SignatureStatus),
            "expected SignatureStatus failure, got {:?}",
            err.failed_checks
        );
    }

    /// Codex adversarial finding (high): a `..` parent-traversal
    /// `signature_sidecar_ref` must not satisfy the check even though the
    /// target file exists — it lives outside the environment directory.
    #[test]
    fn start_fails_signature_status_on_parent_traversal_sidecar_ref() {
        let (_tmp, env_root, mut revision) = seed_env(true);
        // A real file in env_root (the PARENT of env_dir = env_root/local),
        // reachable from env_dir only via `..`.
        std::fs::write(env_root.join("outside.sig"), b"escaped").unwrap();
        revision.signature_sidecar_ref = PathBuf::from("../outside.sig");
        let env = make_env();
        let gate = StartRevisionHealthGate::new(env_root);
        let err = gate.check(&env, &revision).unwrap_err();
        assert!(
            err.failed_checks.contains(&HealthCheckId::SignatureStatus),
            "expected SignatureStatus failure, got {:?}",
            err.failed_checks
        );
    }

    /// Codex adversarial finding (high): a SYMLINK inside the env dir that
    /// points OUTSIDE the env root must not satisfy the check.
    /// `normalize_under_root` canonicalizes (resolving the symlink) before
    /// the containment test, so the escape is caught.
    #[cfg(unix)]
    #[test]
    fn start_fails_signature_status_on_symlink_escape() {
        let (_tmp, env_root, mut revision) = seed_env(false);
        // Real sidecar-shaped file in a directory outside the env root.
        let outside_dir = tempfile::tempdir().unwrap();
        let outside_file = outside_dir.path().join("real.sig");
        std::fs::write(&outside_file, b"escaped").unwrap();
        // Symlink inside env_dir pointing at the outside file.
        let env_dir = env_root.join(ENV_ID);
        std::os::unix::fs::symlink(&outside_file, env_dir.join("rev.sig")).unwrap();
        revision.signature_sidecar_ref = PathBuf::from("rev.sig");
        let env = make_env();
        let gate = StartRevisionHealthGate::new(env_root);
        let err = gate.check(&env, &revision).unwrap_err();
        assert!(
            err.failed_checks.contains(&HealthCheckId::SignatureStatus),
            "expected SignatureStatus failure, got {:?}",
            err.failed_checks
        );
    }

    /// `/code-review` finding: a `..` (or `.`) `environment_id` must not let
    /// the signature check widen its containment root to the parent of
    /// `env_root`. `validate_identifier` permits all-dot ids, so `EnvId("..")`
    /// is constructible; the gate must reject it on BOTH env-dir-dependent
    /// checks (RuntimeConfig via `load_in`, SignatureStatus via `env_dir_in`),
    /// not lean on aggregation from a single check.
    #[test]
    fn start_rejects_dotdot_env_id_on_both_dependent_checks() {
        let (_tmp, env_root, revision) = seed_env(true);
        let mut env = make_env();
        env.environment_id = EnvId::try_from("..").unwrap();
        let gate = StartRevisionHealthGate::new(env_root);
        let err = gate.check(&env, &revision).unwrap_err();
        assert!(
            err.failed_checks.contains(&HealthCheckId::SignatureStatus),
            "signature check must reject `..` env_id, got {:?}",
            err.failed_checks
        );
        assert!(
            err.failed_checks.contains(&HealthCheckId::RuntimeConfig),
            "runtime-config check must reject `..` env_id, got {:?}",
            err.failed_checks
        );
        assert!(
            err.message.contains("not a safe directory segment"),
            "msg: {}",
            err.message
        );
    }

    /// Containment is about ESCAPE, not symlinks per se: a symlink that
    /// stays INSIDE the env dir resolves cleanly and still passes. Guards
    /// against an over-broad fix that rejects all symlinks.
    #[cfg(unix)]
    #[test]
    fn start_passes_on_contained_symlink_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let env_dir = tmp.path().join(ENV_ID);
        std::fs::create_dir_all(&env_dir).unwrap();
        // Real signed envelope inside the env dir + a symlink (also inside)
        // to it; the symlink resolves cleanly and the envelope verifies.
        write_signed_sidecar_and_trust(&env_dir, "actual.sig");
        std::os::unix::fs::symlink(env_dir.join("actual.sig"), env_dir.join("rev.sig")).unwrap();
        let revision = make_revision(PathBuf::from("rev.sig"));
        let env = make_env();
        let gate = StartRevisionHealthGate::new(tmp.path().to_path_buf());
        assert!(
            gate.check(&env, &revision).is_ok(),
            "a contained symlink to a valid envelope should pass"
        );
    }

    #[test]
    fn start_passes_with_absent_runtime_config_and_verifying_signature() {
        // The common case once a producer signs revisions: nothing
        // materializes runtime-config.json until Phase-D producers land, but
        // the revision's signature must verify. The gate must NOT flag a
        // missing runtime-config as a failure.
        let (_tmp, env_root, revision) = seed_signed_env();
        // Confirm runtime-config.json is absent in our fixture.
        assert!(!env_root.join(ENV_ID).join("runtime-config.json").exists());
        let env = make_env();
        let gate = StartRevisionHealthGate::new(env_root);
        assert!(gate.check(&env, &revision).is_ok());
    }

    /// Closed-by-default: a valid envelope present but NO `trust-root.json`
    /// must fail — `load_trust_root` yields an empty `TrustRoot`, which
    /// matches no signing key.
    #[test]
    fn start_fails_signature_status_when_trust_root_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let env_dir = tmp.path().join(ENV_ID);
        std::fs::create_dir_all(&env_dir).unwrap();
        let (priv_pem, _pub_pem, key_id) = keypair(1);
        let bytes = envelope_bytes(BUNDLE_DIGEST_HEX, &priv_pem, &key_id);
        std::fs::write(env_dir.join("rev.sig"), &bytes).unwrap();
        // Deliberately NO add_trusted_key → no trust-root.json.
        let revision = make_revision(PathBuf::from("rev.sig"));
        let env = make_env();
        let gate = StartRevisionHealthGate::new(tmp.path().to_path_buf());
        let err = gate.check(&env, &revision).unwrap_err();
        assert_eq!(err.failed_checks, vec![HealthCheckId::SignatureStatus]);
        assert!(
            err.message.contains("DSSE signature verification failed"),
            "msg: {}",
            err.message
        );
    }

    /// A signature from a key NOT in the trust root must fail closed.
    #[test]
    fn start_fails_signature_status_when_signed_by_untrusted_key() {
        let tmp = tempfile::tempdir().unwrap();
        let env_dir = tmp.path().join(ENV_ID);
        std::fs::create_dir_all(&env_dir).unwrap();
        // Sign with key 2 but trust only key 1.
        let (signer_priv, _signer_pub, signer_id) = keypair(2);
        let (_trusted_priv, trusted_pub, trusted_id) = keypair(1);
        let bytes = envelope_bytes(BUNDLE_DIGEST_HEX, &signer_priv, &signer_id);
        std::fs::write(env_dir.join("rev.sig"), &bytes).unwrap();
        greentic_deployer::environment::add_trusted_key(
            &env_dir,
            TrustedKey {
                key_id: trusted_id,
                public_key_pem: trusted_pub,
            },
        )
        .unwrap();
        let revision = make_revision(PathBuf::from("rev.sig"));
        let env = make_env();
        let gate = StartRevisionHealthGate::new(tmp.path().to_path_buf());
        let err = gate.check(&env, &revision).unwrap_err();
        assert!(
            err.failed_checks.contains(&HealthCheckId::SignatureStatus),
            "expected SignatureStatus failure, got {:?}",
            err.failed_checks
        );
    }

    /// An envelope whose subject pins a DIFFERENT digest than the revision's
    /// `bundle_digest` must fail (subject-digest mismatch), even when signed
    /// by a trusted key.
    #[test]
    fn start_fails_signature_status_on_digest_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let env_dir = tmp.path().join(ENV_ID);
        std::fs::create_dir_all(&env_dir).unwrap();
        let (priv_pem, pub_pem, key_id) = keypair(1);
        let other_digest = "2222222222222222222222222222222222222222222222222222222222222222";
        let bytes = envelope_bytes(other_digest, &priv_pem, &key_id);
        std::fs::write(env_dir.join("rev.sig"), &bytes).unwrap();
        greentic_deployer::environment::add_trusted_key(
            &env_dir,
            TrustedKey {
                key_id,
                public_key_pem: pub_pem,
            },
        )
        .unwrap();
        let revision = make_revision(PathBuf::from("rev.sig"));
        let env = make_env();
        let gate = StartRevisionHealthGate::new(tmp.path().to_path_buf());
        let err = gate.check(&env, &revision).unwrap_err();
        assert!(
            err.failed_checks.contains(&HealthCheckId::SignatureStatus),
            "expected SignatureStatus failure, got {:?}",
            err.failed_checks
        );
    }

    /// A present-but-not-a-DSSE-envelope sidecar (the legacy placeholder)
    /// must now fail: the existence-only check is gone. A trust root IS seeded
    /// here so the sole failure reason is the unparseable content, not the
    /// closed-by-default empty-trust-root path (covered separately above).
    #[test]
    fn start_fails_signature_status_when_sidecar_not_an_envelope() {
        let tmp = tempfile::tempdir().unwrap();
        let env_dir = tmp.path().join(ENV_ID);
        std::fs::create_dir_all(&env_dir).unwrap();
        std::fs::write(env_dir.join("rev.sig"), b"placeholder").unwrap();
        let (_priv_pem, pub_pem, key_id) = keypair(1);
        greentic_deployer::environment::add_trusted_key(
            &env_dir,
            TrustedKey {
                key_id,
                public_key_pem: pub_pem,
            },
        )
        .unwrap();
        let revision = make_revision(PathBuf::from("rev.sig"));
        let env = make_env();
        let gate = StartRevisionHealthGate::new(tmp.path().to_path_buf());
        let err = gate.check(&env, &revision).unwrap_err();
        assert_eq!(err.failed_checks, vec![HealthCheckId::SignatureStatus]);
        assert!(
            err.message.contains("DSSE signature verification failed"),
            "msg: {}",
            err.message
        );
    }

    /// A degenerate `bundle_digest` (empty, or just the `sha256:` prefix) must
    /// be rejected before verification — otherwise a trusted signer could bind
    /// an empty-subject envelope to a revision that pins no real digest.
    #[test]
    fn start_fails_signature_status_on_empty_bundle_digest() {
        let (_tmp, env_root, mut revision) = seed_signed_env();
        revision.bundle_digest = "sha256:".to_string();
        let env = make_env();
        let gate = StartRevisionHealthGate::new(env_root);
        let err = gate.check(&env, &revision).unwrap_err();
        assert_eq!(err.failed_checks, vec![HealthCheckId::SignatureStatus]);
        assert!(
            err.message.contains("carries no digest"),
            "msg: {}",
            err.message
        );
    }

    /// A `signature_sidecar_ref` that resolves (contained) to a DIRECTORY must
    /// be rejected by the `is_file` guard, not stat'd-and-read as if a file.
    #[test]
    fn start_fails_signature_status_on_contained_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let env_dir = tmp.path().join(ENV_ID);
        std::fs::create_dir_all(env_dir.join("rev.sig")).unwrap();
        let revision = make_revision(PathBuf::from("rev.sig"));
        let env = make_env();
        let gate = StartRevisionHealthGate::new(tmp.path().to_path_buf());
        let err = gate.check(&env, &revision).unwrap_err();
        assert_eq!(err.failed_checks, vec![HealthCheckId::SignatureStatus]);
        assert!(
            err.message.contains("not a regular file"),
            "msg: {}",
            err.message
        );
    }

    /// Codex hardening: an oversized sidecar must be rejected on the size cap
    /// before allocation/parse, even with a valid trust root present — the
    /// gate may run while holding the env transaction lock.
    #[test]
    fn start_fails_signature_status_on_oversized_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let env_dir = tmp.path().join(ENV_ID);
        std::fs::create_dir_all(&env_dir).unwrap();
        // Trust root present + a real key, so the ONLY failure is the size cap.
        let (_priv_pem, pub_pem, key_id) = keypair(1);
        std::fs::write(
            env_dir.join("rev.sig"),
            vec![b'x'; (MAX_SIDECAR_BYTES + 1) as usize],
        )
        .unwrap();
        greentic_deployer::environment::add_trusted_key(
            &env_dir,
            TrustedKey {
                key_id,
                public_key_pem: pub_pem,
            },
        )
        .unwrap();
        let revision = make_revision(PathBuf::from("rev.sig"));
        let env = make_env();
        let gate = StartRevisionHealthGate::new(tmp.path().to_path_buf());
        let err = gate.check(&env, &revision).unwrap_err();
        assert_eq!(err.failed_checks, vec![HealthCheckId::SignatureStatus]);
        assert!(
            err.message.contains("exceeds the") && err.message.contains("limit"),
            "msg: {}",
            err.message
        );
    }

    /// Trait-object usage: a Phase-D operator handler holds an `Arc<dyn
    /// RevisionHealthGate>` and dispatches via dynamic call. Verify both
    /// concrete impls work behind a trait object.
    #[test]
    fn dyn_trait_object_dispatch_works_for_both_impls() {
        let (_tmp, env_root, revision) = seed_signed_env();
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
        let (_tmp, env_root, revision) = seed_signed_env();
        let env = make_env();
        let gate: std::sync::Arc<dyn RevisionHealthGate> =
            std::sync::Arc::new(StartRevisionHealthGate::new(env_root));
        // The closure Phase-D will pass to warm_with_health_gate.
        let closure = |e: &Environment, r: &Revision| gate.check(e, r);
        assert!(closure(&env, &revision).is_ok());
    }
}
