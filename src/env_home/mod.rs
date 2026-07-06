//! Boot greentic-start from a greentic-deployer environment home.
//!
//! `greentic-deployer` writes an "environment home" directory tree
//! (`runtime-config.json`, per-revision `pack-list.lock` files, extracted
//! `.gtpack` artifacts) that this module teaches `greentic-start` to read at
//! boot, instead of relying solely on ad-hoc bundle refs. See the sub-project
//! spec/plan docs under `.superpowers/sdd/` for the full slice-1a design.
mod loader;
mod route;
mod spec;
mod verify;

pub(crate) use loader::{load_env_home, resolve_routed_bundle_dir};
pub use route::select_routed_revisions;
pub use spec::{
    LockedPack, PACK_LIST_LOCK_SCHEMA, PackListLock, RUNTIME_CONFIG_SCHEMA, RevisionRuntimeBlock,
    RuntimeConfig, parse_runtime_config,
};
pub use verify::verify_pack_list;

use std::path::PathBuf;
use std::time::SystemTime;

/// Poll-based change detection for `<env-home>/runtime-config.json`, used by
/// the foreground shutdown loop (see `wait_for_shutdown` in `lib.rs`) to
/// trigger a clean restart when greentic-deployer writes a new revision.
///
/// Returns `true` when `path`'s mtime is strictly newer than `baseline`, or
/// when the file can no longer be read (e.g. deleted because traffic was
/// cleared from the env). Slice-1a semantics: deletion is treated the same as
/// a change — the supervisor is expected to restart into whatever state
/// (redeployed or torn down) is now on disk, rather than have this process
/// keep running against a stale/removed config.
pub fn runtime_config_changed(path: &std::path::Path, baseline: SystemTime) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|modified| modified > baseline)
        .unwrap_or(true)
}

#[derive(Debug, thiserror::Error)]
pub enum EnvHomeError {
    #[error("environment `{env}` is not deployed (no runtime-config.json under {path})")]
    NotDeployed { env: String, path: PathBuf },
    #[error("unexpected runtime-config schema: got `{got}`, expected `{RUNTIME_CONFIG_SCHEMA}`")]
    SchemaMismatch { got: String },
    #[error(
        "invalid traffic split for deployment `{deployment_id}`: weights sum to {sum} bps, expected 10000"
    )]
    InvalidTrafficSplit { deployment_id: String, sum: u32 },
    #[error("partial traffic split for deployment `{deployment_id}` is not supported in slice 1a")]
    UnsupportedSplit { deployment_id: String },
    #[error("pack `{pack_id}` digest mismatch: on-disk {actual} != pinned {expected}")]
    DigestMismatch {
        pack_id: String,
        expected: String,
        actual: String,
    },
    #[error("missing artifact at {0}")]
    MissingArtifact(PathBuf),
    #[error("no routed revision in runtime-config.json for env `{env}`")]
    NoRoutedRevision { env: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("malformed json in {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}
