//! Boot greentic-start from a greentic-deployer environment home.
//!
//! `greentic-deployer` writes an "environment home" directory tree
//! (`runtime-config.json`, per-revision `pack-list.lock` files, extracted
//! `.gtpack` artifacts) that this module teaches `greentic-start` to read at
//! boot, instead of relying solely on ad-hoc bundle refs. See the sub-project
//! spec/plan docs under `.superpowers/sdd/` for the full slice-1a design.
mod route;
mod spec;
mod verify;

pub use route::select_routed_revisions;
pub use spec::{
    LockedPack, PACK_LIST_LOCK_SCHEMA, PackListLock, RUNTIME_CONFIG_SCHEMA, RevisionRuntimeBlock,
    RuntimeConfig, parse_runtime_config,
};
pub use verify::verify_pack_list;

use std::path::PathBuf;

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
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("malformed json in {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}
