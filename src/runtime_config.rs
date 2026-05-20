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

use std::path::{Component, Path, PathBuf};

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
/// activation (B2). All ref paths are absolute and confirmed to live under
/// `env_dir`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LoadedRuntimeConfig {
    pub(crate) env_id: String,
    pub(crate) env_dir: PathBuf,
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

    Ok(LoadedRuntimeConfig {
        env_id: env_id.to_string(),
        env_dir: env_dir.to_path_buf(),
        revisions,
    })
}

/// Resolves a list of env-relative refs to absolute paths under `env_dir`,
/// rejecting any ref that is absolute, escapes the env directory, or is missing.
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
    if !is_contained_relative(rel) {
        bail!(
            "revision `{revision_id}` {label} `{}` must be a relative path that stays inside the environment directory",
            rel.display()
        );
    }
    let abs = env_dir.join(rel);
    if !abs.is_file() {
        bail!(
            "revision `{revision_id}` {label} `{}` does not resolve to a file ({})",
            rel.display(),
            abs.display()
        );
    }
    Ok(abs)
}

/// True when `rel` is a non-empty relative path whose components stay at or below
/// the joining root (no `RootDir`, `Prefix`, or `ParentDir` components).
fn is_contained_relative(rel: &Path) -> bool {
    if rel.as_os_str().is_empty() {
        return false;
    }
    rel.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
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
        assert_eq!(
            block.pack_list_refs,
            vec![env_dir.join("revisions/r1/pack.lock")]
        );
        assert_eq!(
            block.pack_config_refs,
            vec![env_dir.join("revisions/r1/pack-config.json")]
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
        // No pack files written; refs cannot resolve to files.
        let err = validate_and_resolve(one_revision_cfg(), "local", tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("does not resolve to a file"),
            "{err}"
        );
    }

    #[test]
    fn rejects_escaping_pack_ref() {
        let tmp = TempDir::new().unwrap();
        write_pack_files(tmp.path());
        let mut cfg = one_revision_cfg();
        cfg.revisions[0].pack_list_refs = vec![PathBuf::from("../escape.lock")];
        let err = validate_and_resolve(cfg, "local", tmp.path()).unwrap_err();
        assert!(err.to_string().contains("stays inside"), "{err}");
    }

    #[test]
    fn rejects_absolute_pack_ref() {
        let tmp = TempDir::new().unwrap();
        write_pack_files(tmp.path());
        let mut cfg = one_revision_cfg();
        cfg.revisions[0].pack_config_refs = vec![PathBuf::from("/etc/passwd")];
        let err = validate_and_resolve(cfg, "local", tmp.path()).unwrap_err();
        assert!(err.to_string().contains("stays inside"), "{err}");
    }

    #[test]
    fn is_contained_relative_rules() {
        assert!(is_contained_relative(Path::new("a/b.lock")));
        assert!(is_contained_relative(Path::new("./a/b.lock")));
        assert!(!is_contained_relative(Path::new("")));
        assert!(!is_contained_relative(Path::new("../a")));
        assert!(!is_contained_relative(Path::new("a/../../b")));
        assert!(!is_contained_relative(Path::new("/abs")));
    }

    #[test]
    fn env_dir_rejects_traversal_segments() {
        assert!(env_dir("..").is_err());
        assert!(env_dir(".").is_err());
        assert!(env_dir("a/b").is_err());
    }
}
