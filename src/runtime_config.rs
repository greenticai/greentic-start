//! `greentic.runtime-config.v1` loader (Phase B / B0).
//!
//! The operator materializes a [`RuntimeConfig`](greentic_deploy_spec::RuntimeConfig)
//! from an `Environment` plus its ready `Revision`s and `TrafficSplit`s into
//! `~/.greentic/environments/<env>/runtime-config.json`. When `greentic-start`
//! is launched without a `--bundle` root, it loads that file and boots from the
//! revision blocks instead of from a single bundle directory.
//!
//! B0 is the loader, validation, and pack-ref resolution only. Activating packs
//! from the resolved refs is B2 (`ActivePacks::load_revision`) and per-revision
//! routing is B3, so this module deliberately stops at a validated, path-resolved
//! boot plan and hands a typed [`LoadedRuntimeConfig`] to the boot seam.
//!
//! The deploy-spec type is aliased to [`MaterializedRuntimeConfig`] because
//! `crate::runtime` already owns an unrelated `RuntimeConfig` (the public-base-URL
//! flavour).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use greentic_deploy_spec::{RuntimeConfig as MaterializedRuntimeConfig, SchemaVersion};
use greentic_deployer::environment::LocalFsStore;
use greentic_types::EnvId;

/// Filename of the materialized runtime-config inside an environment directory.
const RUNTIME_CONFIG_FILE: &str = "runtime-config.json";

/// Basis points are out of 10_000 (100%).
const MAX_WEIGHT_BPS: u32 = 10_000;

/// A revision block whose env-relative pack refs have been resolved to absolute
/// paths under the environment directory and confirmed to exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedRevisionBlock {
    pub(crate) deployment_id: String,
    pub(crate) revision_id: String,
    pub(crate) bundle_id: String,
    pub(crate) pack_list_refs: Vec<PathBuf>,
    pub(crate) pack_config_refs: Vec<PathBuf>,
    pub(crate) weight_bps: u32,
}

/// A loaded and validated `runtime-config.v1`, ready to hand to revision
/// activation (B2). Every pack ref is an absolute, canonicalized path proven to
/// live under the environment directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LoadedRuntimeConfig {
    pub(crate) env_id: String,
    pub(crate) revisions: Vec<ResolvedRevisionBlock>,
}

/// Resolves the environment directory for `env_id` under the default store root.
///
/// `EnvId` construction rejects path separators (`/`, `\`, `:`, NUL) and any
/// non-identifier character, but [`greentic_types::validate_identifier`] permits
/// bare `.` and `..` (they are all-dots). `LocalFsStore::safe_env_segment` guards
/// that gap on the deployer side; we mirror it here because that helper is not
/// public and `greentic-start` consumes the deployer as a registry crate.
fn env_dir(env_id: &str) -> anyhow::Result<PathBuf> {
    if env_id == "." || env_id == ".." {
        bail!("environment id `{env_id}` is not a safe directory segment");
    }
    // Validates the segment (separators, NUL, charset) and gives a typed id.
    EnvId::new(env_id).with_context(|| format!("invalid environment id `{env_id}`"))?;
    let root = LocalFsStore::default_root()
        .context("cannot determine the default environment store root (no home directory)")?;
    Ok(root.join(env_id))
}

/// Loads and validates the materialized runtime-config for `env_id`.
///
/// Returns `Ok(None)` when no runtime-config exists for the env (the common case
/// today: nothing materializes the file until the operator handlers land). Returns
/// `Err` when the file exists but is malformed, names the wrong schema or env,
/// carries no revisions, or references pack files that escape the env directory
/// or are missing.
pub(crate) fn load(env_id: &str) -> anyhow::Result<Option<LoadedRuntimeConfig>> {
    let dir = env_dir(env_id)?;
    let path = dir.join(RUNTIME_CONFIG_FILE);
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading runtime-config at {}", path.display()))?;
    let parsed: MaterializedRuntimeConfig = serde_json::from_str(&raw)
        .with_context(|| format!("parsing runtime-config at {}", path.display()))?;
    validate_and_resolve(parsed, env_id, &dir).map(Some)
}

fn validate_and_resolve(
    cfg: MaterializedRuntimeConfig,
    env_id: &str,
    env_dir: &Path,
) -> anyhow::Result<LoadedRuntimeConfig> {
    if cfg.schema.as_str() != SchemaVersion::RUNTIME_CONFIG_V1 {
        bail!(
            "runtime-config has schema `{}`, expected `{}`",
            cfg.schema.as_str(),
            SchemaVersion::RUNTIME_CONFIG_V1
        );
    }
    if cfg.env_id.as_str() != env_id {
        bail!(
            "runtime-config declares env `{}` but was loaded for env `{env_id}`",
            cfg.env_id.as_str()
        );
    }
    if cfg.revisions.is_empty() {
        bail!("runtime-config for env `{env_id}` declares no revisions");
    }

    let mut revisions = Vec::with_capacity(cfg.revisions.len());
    for block in cfg.revisions {
        let deployment_id = block.deployment_id.to_string();
        let revision_id = block.revision_id.to_string();
        if block.weight_bps > MAX_WEIGHT_BPS {
            bail!(
                "revision `{revision_id}` (deployment `{deployment_id}`) has weight {} bps, \
                 max is {MAX_WEIGHT_BPS}",
                block.weight_bps
            );
        }
        let pack_list_refs = resolve_refs(
            env_dir,
            &block.pack_list_refs,
            "pack_list_ref",
            &revision_id,
        )?;
        let pack_config_refs = resolve_refs(
            env_dir,
            &block.pack_config_refs,
            "pack_config_ref",
            &revision_id,
        )?;
        revisions.push(ResolvedRevisionBlock {
            deployment_id,
            revision_id,
            bundle_id: block.bundle_id.to_string(),
            pack_list_refs,
            pack_config_refs,
            weight_bps: block.weight_bps,
        });
    }

    validate_traffic_invariants(&revisions)?;

    Ok(LoadedRuntimeConfig {
        env_id: env_id.to_string(),
        revisions,
    })
}

/// Enforces the per-deployment `TrafficSplit` invariants (deploy-spec §5.3) on
/// the materialized revision blocks: one bundle per deployment, no duplicate
/// revision ids within a deployment, and weights summing to exactly 10,000 bps.
/// B3 routing trusts this, so a partially-materialized config must fail here.
fn validate_traffic_invariants(revisions: &[ResolvedRevisionBlock]) -> anyhow::Result<()> {
    struct Deployment<'a> {
        bundle_id: &'a str,
        revision_ids: Vec<&'a str>,
        weight_sum: u64,
    }
    let mut by_deployment: BTreeMap<&str, Deployment> = BTreeMap::new();
    for block in revisions {
        let entry = by_deployment
            .entry(&block.deployment_id)
            .or_insert_with(|| Deployment {
                bundle_id: &block.bundle_id,
                revision_ids: Vec::new(),
                weight_sum: 0,
            });
        if entry.bundle_id != block.bundle_id {
            bail!(
                "deployment `{}` mixes bundles `{}` and `{}`; one deployment binds a single bundle",
                block.deployment_id,
                entry.bundle_id,
                block.bundle_id
            );
        }
        if entry.revision_ids.contains(&block.revision_id.as_str()) {
            bail!(
                "deployment `{}` lists revision `{}` more than once",
                block.deployment_id,
                block.revision_id
            );
        }
        entry.revision_ids.push(&block.revision_id);
        entry.weight_sum += u64::from(block.weight_bps);
    }
    for (deployment_id, deployment) in &by_deployment {
        if deployment.weight_sum != u64::from(MAX_WEIGHT_BPS) {
            bail!(
                "deployment `{deployment_id}` revision weights sum to {} bps, must equal {MAX_WEIGHT_BPS}",
                deployment.weight_sum
            );
        }
    }
    Ok(())
}

/// Resolves a list of env-relative refs to canonical paths proven to live under
/// `env_dir`, rejecting any ref that is absolute, escapes the env directory, or
/// is missing.
fn resolve_refs(
    env_dir: &Path,
    refs: &[PathBuf],
    label: &str,
    revision_id: &str,
) -> anyhow::Result<Vec<PathBuf>> {
    refs.iter()
        .map(|rel| resolve_ref(env_dir, rel, label, revision_id))
        .collect()
}

fn resolve_ref(
    env_dir: &Path,
    rel: &Path,
    label: &str,
    revision_id: &str,
) -> anyhow::Result<PathBuf> {
    // `normalize_under_root` rejects absolute paths and canonicalizes the joined
    // path, so a `..` or a symlinked file/parent that escapes the env dir fails
    // closed (and a missing ref fails to canonicalize). B2 trusts the returned
    // path, so we additionally require it to be a regular file, not a directory.
    let canon =
        greentic_deployer::path_safety::normalize_under_root(env_dir, rel).with_context(|| {
            format!(
                "revision `{revision_id}` {label} `{}` is not a valid pack ref",
                rel.display()
            )
        })?;
    if !canon.is_file() {
        bail!(
            "revision `{revision_id}` {label} `{}` does not resolve to a file ({})",
            rel.display(),
            canon.display()
        );
    }
    Ok(canon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::{BundleId, DeploymentId, RevisionId, RevisionRuntimeBlock};
    use std::fs;
    use tempfile::TempDir;

    fn write_pack_files(env_dir: &Path) {
        fs::create_dir_all(env_dir.join("revisions/r1")).unwrap();
        fs::write(env_dir.join("revisions/r1/pack.lock"), "lock").unwrap();
        fs::write(env_dir.join("revisions/r1/pack-config.json"), "{}").unwrap();
    }

    fn one_revision_cfg() -> MaterializedRuntimeConfig {
        MaterializedRuntimeConfig {
            schema: SchemaVersion::new(SchemaVersion::RUNTIME_CONFIG_V1),
            env_id: EnvId::new("local").unwrap(),
            revisions: vec![RevisionRuntimeBlock {
                deployment_id: DeploymentId::new(),
                revision_id: RevisionId::new(),
                bundle_id: BundleId::from("bundle1"),
                pack_list_refs: vec![PathBuf::from("revisions/r1/pack.lock")],
                pack_config_refs: vec![PathBuf::from("revisions/r1/pack-config.json")],
                weight_bps: 10_000,
            }],
        }
    }

    #[test]
    fn validate_and_resolve_accepts_valid_single_revision() {
        let tmp = TempDir::new().unwrap();
        let env_dir = tmp.path();
        write_pack_files(env_dir);

        let cfg = one_revision_cfg();
        let expected_dep = cfg.revisions[0].deployment_id.to_string();
        let expected_rev = cfg.revisions[0].revision_id.to_string();
        let loaded = validate_and_resolve(cfg, "local", env_dir).unwrap();
        assert_eq!(loaded.env_id, "local");
        assert_eq!(loaded.revisions.len(), 1);
        let block = &loaded.revisions[0];
        assert_eq!(block.deployment_id, expected_dep);
        assert_eq!(block.revision_id, expected_rev);
        assert_eq!(block.bundle_id, "bundle1");
        assert_eq!(block.weight_bps, 10_000);
        let canon = env_dir.canonicalize().unwrap();
        assert_eq!(
            block.pack_list_refs,
            vec![canon.join("revisions/r1/pack.lock")]
        );
        assert_eq!(
            block.pack_config_refs,
            vec![canon.join("revisions/r1/pack-config.json")]
        );
    }

    #[test]
    fn rejects_wrong_schema() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = one_revision_cfg();
        cfg.schema = SchemaVersion::new("greentic.environment.v1");
        let err = validate_and_resolve(cfg, "local", tmp.path()).unwrap_err();
        assert!(err.to_string().contains("schema"), "{err}");
    }

    #[test]
    fn rejects_env_mismatch() {
        let tmp = TempDir::new().unwrap();
        let err = validate_and_resolve(one_revision_cfg(), "staging", tmp.path()).unwrap_err();
        assert!(err.to_string().contains("declares env"), "{err}");
    }

    #[test]
    fn rejects_empty_revisions() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = one_revision_cfg();
        cfg.revisions.clear();
        let err = validate_and_resolve(cfg, "local", tmp.path()).unwrap_err();
        assert!(err.to_string().contains("no revisions"), "{err}");
    }

    #[test]
    fn rejects_weight_over_max() {
        let tmp = TempDir::new().unwrap();
        write_pack_files(tmp.path());
        let mut cfg = one_revision_cfg();
        cfg.revisions[0].weight_bps = 10_001;
        let err = validate_and_resolve(cfg, "local", tmp.path()).unwrap_err();
        assert!(err.to_string().contains("max is 10000"), "{err}");
    }

    #[test]
    fn rejects_missing_pack_ref() {
        let tmp = TempDir::new().unwrap();
        // No pack files written; refs cannot canonicalize.
        let err = validate_and_resolve(one_revision_cfg(), "local", tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("is not a valid pack ref"),
            "{err:#}"
        );
    }

    #[test]
    fn rejects_directory_pack_ref() {
        let tmp = TempDir::new().unwrap();
        write_pack_files(tmp.path());
        let mut cfg = one_revision_cfg();
        // `revisions/r1` exists but is a directory, not a file.
        cfg.revisions[0].pack_list_refs = vec![PathBuf::from("revisions/r1")];
        let err = validate_and_resolve(cfg, "local", tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("does not resolve to a file"),
            "{err:#}"
        );
    }

    #[test]
    fn rejects_escaping_pack_ref() {
        let tmp = TempDir::new().unwrap();
        let env_dir = tmp.path().join("env");
        write_pack_files(&env_dir);
        // The target exists, but outside the env dir, so containment must reject it.
        fs::write(tmp.path().join("escape.lock"), "secret").unwrap();
        let mut cfg = one_revision_cfg();
        cfg.revisions[0].pack_list_refs = vec![PathBuf::from("../escape.lock")];
        let err = validate_and_resolve(cfg, "local", &env_dir).unwrap_err();
        assert!(format!("{err:#}").contains("escapes root"), "{err:#}");
    }

    #[test]
    fn rejects_absolute_pack_ref() {
        let tmp = TempDir::new().unwrap();
        write_pack_files(tmp.path());
        let mut cfg = one_revision_cfg();
        cfg.revisions[0].pack_config_refs = vec![PathBuf::from("/etc/passwd")];
        let err = validate_and_resolve(cfg, "local", tmp.path()).unwrap_err();
        assert!(format!("{err:#}").contains("absolute paths"), "{err:#}");
    }

    #[test]
    fn env_dir_rejects_traversal_segments() {
        assert!(env_dir("..").is_err());
        assert!(env_dir(".").is_err());
        assert!(env_dir("a/b").is_err());
    }

    // ---- symlink containment ---------------------------------------------

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_file_escaping_env() {
        let tmp = TempDir::new().unwrap();
        let env_dir = tmp.path().join("env");
        fs::create_dir_all(env_dir.join("revisions/r1")).unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(
            outside.join("secret.txt"),
            env_dir.join("revisions/r1/pack.lock"),
        )
        .unwrap();

        let mut cfg = one_revision_cfg();
        cfg.revisions[0].pack_config_refs.clear();
        let err = validate_and_resolve(cfg, "local", &env_dir).unwrap_err();
        assert!(format!("{err:#}").contains("escapes root"), "{err:#}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_parent_escaping_env() {
        let tmp = TempDir::new().unwrap();
        let env_dir = tmp.path().join("env");
        fs::create_dir_all(env_dir.join("revisions")).unwrap();
        let outside = tmp.path().join("outside/r1");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("pack.lock"), "secret").unwrap();
        // `revisions/r1` is a symlink to a directory outside the env.
        std::os::unix::fs::symlink(tmp.path().join("outside/r1"), env_dir.join("revisions/r1"))
            .unwrap();

        let mut cfg = one_revision_cfg();
        cfg.revisions[0].pack_config_refs.clear();
        let err = validate_and_resolve(cfg, "local", &env_dir).unwrap_err();
        assert!(format!("{err:#}").contains("escapes root"), "{err:#}");
    }

    // ---- per-deployment traffic invariants -------------------------------

    fn block(
        deployment_id: DeploymentId,
        revision_id: RevisionId,
        bundle_id: &str,
        weight_bps: u32,
    ) -> RevisionRuntimeBlock {
        RevisionRuntimeBlock {
            deployment_id,
            revision_id,
            bundle_id: BundleId::from(bundle_id),
            pack_list_refs: vec![],
            pack_config_refs: vec![],
            weight_bps,
        }
    }

    fn cfg_with(revisions: Vec<RevisionRuntimeBlock>) -> MaterializedRuntimeConfig {
        MaterializedRuntimeConfig {
            schema: SchemaVersion::new(SchemaVersion::RUNTIME_CONFIG_V1),
            env_id: EnvId::new("local").unwrap(),
            revisions,
        }
    }

    #[test]
    fn accepts_two_revisions_summing_to_full_split() {
        let tmp = TempDir::new().unwrap();
        let dep = DeploymentId::new();
        let cfg = cfg_with(vec![
            block(dep, RevisionId::new(), "bundle1", 9_900),
            block(dep, RevisionId::new(), "bundle1", 100),
        ]);
        let loaded = validate_and_resolve(cfg, "local", tmp.path()).unwrap();
        assert_eq!(loaded.revisions.len(), 2);
    }

    #[test]
    fn accepts_multiple_deployments_each_full() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_with(vec![
            block(DeploymentId::new(), RevisionId::new(), "bundle1", 10_000),
            block(DeploymentId::new(), RevisionId::new(), "bundle2", 10_000),
        ]);
        let loaded = validate_and_resolve(cfg, "local", tmp.path()).unwrap();
        assert_eq!(loaded.revisions.len(), 2);
    }

    #[test]
    fn rejects_weight_sum_below_full() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_with(vec![block(
            DeploymentId::new(),
            RevisionId::new(),
            "bundle1",
            5_000,
        )]);
        let err = validate_and_resolve(cfg, "local", tmp.path()).unwrap_err();
        assert!(err.to_string().contains("sum to 5000 bps"), "{err}");
    }

    #[test]
    fn rejects_weight_sum_above_full() {
        let tmp = TempDir::new().unwrap();
        let dep = DeploymentId::new();
        let cfg = cfg_with(vec![
            block(dep, RevisionId::new(), "bundle1", 10_000),
            block(dep, RevisionId::new(), "bundle1", 10_000),
        ]);
        let err = validate_and_resolve(cfg, "local", tmp.path()).unwrap_err();
        assert!(err.to_string().contains("sum to 20000 bps"), "{err}");
    }

    #[test]
    fn rejects_duplicate_revision_in_deployment() {
        let tmp = TempDir::new().unwrap();
        let dep = DeploymentId::new();
        let rev = RevisionId::new();
        let cfg = cfg_with(vec![
            block(dep, rev, "bundle1", 5_000),
            block(dep, rev, "bundle1", 5_000),
        ]);
        let err = validate_and_resolve(cfg, "local", tmp.path()).unwrap_err();
        assert!(err.to_string().contains("more than once"), "{err}");
    }

    #[test]
    fn rejects_mixed_bundle_in_deployment() {
        let tmp = TempDir::new().unwrap();
        let dep = DeploymentId::new();
        let cfg = cfg_with(vec![
            block(dep, RevisionId::new(), "bundle1", 5_000),
            block(dep, RevisionId::new(), "bundle2", 5_000),
        ]);
        let err = validate_and_resolve(cfg, "local", tmp.path()).unwrap_err();
        assert!(err.to_string().contains("mixes bundles"), "{err}");
    }
}
