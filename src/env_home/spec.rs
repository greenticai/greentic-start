//! Mirrored serde structs for `greentic-deploy-spec`'s wire formats.
//!
//! We deliberately do NOT depend on the `greentic-deploy-spec` crate here: it
//! pins `greentic-types "<1.2.0-0"`, which is unsatisfiable in this repo's
//! dependency graph. Instead we mirror the on-wire JSON shape of
//! `RuntimeConfig` / `RevisionRuntimeBlock` (`runtime_config.rs`) and
//! `PackListLock` / `LockedPack` (`pack_list_lock.rs`) as plain-`String`/
//! `PathBuf` structs. The upstream ID newtypes (`DeploymentId`, `RevisionId`,
//! `BundleId`, `PackId`) and `SchemaVersion` are all `#[serde(transparent)]`
//! wrappers around `String` (or, for `RevisionId`/`DeploymentId`, a ULID that
//! itself serializes as its 26-char string form via the `ulid` crate's
//! `serde` feature), so representing them as plain `String` here is
//! wire-compatible.
//!
//! Field names below were confirmed against the upstream source
//! (`greentic-deployer/crates/greentic-deploy-spec/src/{runtime_config,pack_list_lock}.rs`)
//! as of this writing. `PackListLock` upstream additionally carries `schema`
//! and `revision_id` fields not present in the original task sketch; both are
//! included here so the mirror matches the real contract.

use super::EnvHomeError;
use serde::Deserialize;
use std::path::PathBuf;

/// Schema discriminator for `runtime-config.json` (`greentic.runtime-config.v1`).
pub const RUNTIME_CONFIG_SCHEMA: &str = "greentic.runtime-config.v1";

/// Schema discriminator for `pack-list.lock` (`greentic.pack-list-lock.v1`).
pub const PACK_LIST_LOCK_SCHEMA: &str = "greentic.pack-list-lock.v1";

/// Mirrors `greentic_deploy_spec::runtime_config::RuntimeConfig`.
#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeConfig {
    pub schema: String,
    pub env_id: String,
    pub revisions: Vec<RevisionRuntimeBlock>,
}

/// Mirrors `greentic_deploy_spec::runtime_config::RevisionRuntimeBlock`.
#[derive(Debug, Clone, Deserialize)]
pub struct RevisionRuntimeBlock {
    pub deployment_id: String,
    pub revision_id: String,
    pub bundle_id: String,
    /// Env-relative paths to pinned per-pack lockfiles.
    #[serde(default)]
    pub pack_list_refs: Vec<PathBuf>,
    /// Env-relative paths to `pack-config.v1` documents per pack.
    #[serde(default)]
    pub pack_config_refs: Vec<PathBuf>,
    pub weight_bps: u32,
}

/// Mirrors `greentic_deploy_spec::pack_list_lock::PackListLock`.
///
/// Deviation from the original task sketch: upstream also carries `schema`
/// and `revision_id` fields (confirmed in `pack_list_lock.rs`), binding the
/// lockfile to its owning revision. Included here so later tasks that parse
/// `pack-list.lock` can validate schema/ownership without re-touching this
/// struct.
#[derive(Debug, Clone, Deserialize)]
pub struct PackListLock {
    pub schema: String,
    pub revision_id: String,
    pub packs: Vec<LockedPack>,
}

/// Mirrors `greentic_deploy_spec::pack_list_lock::LockedPack`.
#[derive(Debug, Clone, Deserialize)]
pub struct LockedPack {
    pub pack_id: String,
    pub path: PathBuf,
    /// Content digest of the artifact at `path`, `sha256:<hex>` (lowercase hex).
    pub digest: String,
}

/// Parse and validate a `runtime-config.json` document.
///
/// Returns [`EnvHomeError::Json`] on malformed JSON and
/// [`EnvHomeError::SchemaMismatch`] if the `schema` field doesn't match
/// [`RUNTIME_CONFIG_SCHEMA`].
pub fn parse_runtime_config(bytes: &[u8]) -> Result<RuntimeConfig, EnvHomeError> {
    let rc: RuntimeConfig = serde_json::from_slice(bytes).map_err(|source| EnvHomeError::Json {
        path: PathBuf::from("runtime-config.json"),
        source,
    })?;
    if rc.schema != RUNTIME_CONFIG_SCHEMA {
        return Err(EnvHomeError::SchemaMismatch { got: rc.schema });
    }
    Ok(rc)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "schema": "greentic.runtime-config.v1",
        "env_id": "local",
        "revisions": [{
            "deployment_id": "dep-1",
            "revision_id": "rev-1",
            "bundle_id": "app",
            "pack_list_refs": ["revisions/rev-1/pack-list.lock"],
            "pack_config_refs": [],
            "weight_bps": 10000
        }]
    }"#;

    #[test]
    fn parses_valid_runtime_config() {
        let rc = parse_runtime_config(SAMPLE.as_bytes()).expect("parse");
        assert_eq!(rc.schema, RUNTIME_CONFIG_SCHEMA);
        assert_eq!(rc.revisions.len(), 1);
        assert_eq!(rc.revisions[0].weight_bps, 10000);
        assert_eq!(
            rc.revisions[0].pack_list_refs[0],
            std::path::PathBuf::from("revisions/rev-1/pack-list.lock")
        );
    }

    #[test]
    fn rejects_wrong_schema() {
        let bad = SAMPLE.replace("greentic.runtime-config.v1", "greentic.runtime-config.v2");
        let err = parse_runtime_config(bad.as_bytes()).unwrap_err();
        assert!(matches!(err, EnvHomeError::SchemaMismatch { .. }));
    }
}
