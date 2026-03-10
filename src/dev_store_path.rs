#![allow(dead_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

const STORE_RELATIVE: &str = ".greentic/dev/.dev.secrets.env";
const STORE_STATE_RELATIVE: &str = ".greentic/state/dev/.dev.secrets.env";
const OVERRIDE_ENV: &str = "GREENTIC_DEV_SECRETS_PATH";

/// Returns a path explicitly configured via `$GREENTIC_DEV_SECRETS_PATH`.
pub fn override_path() -> Option<PathBuf> {
    env::var(OVERRIDE_ENV).ok().map(PathBuf::from)
}

/// Checks for an existing dev store inside the bundle root.
pub fn find_existing(bundle_root: &Path) -> Option<PathBuf> {
    find_existing_with_override(bundle_root, override_path().as_deref())
}

/// Looks for an existing dev store using an override path before consulting default candidates.
pub fn find_existing_with_override(
    bundle_root: &Path,
    override_path: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(path) = override_path
        && path.exists()
    {
        return Some(path.to_path_buf());
    }
    candidate_paths(bundle_root)
        .into_iter()
        .find(|candidate| candidate.exists())
}

/// Ensures the default dev store path exists (creating parent directories) before returning it.
pub fn ensure_path(bundle_root: &Path) -> Result<PathBuf> {
    if let Some(path) = override_path() {
        ensure_parent(&path)?;
        return Ok(path);
    }
    let path = bundle_root.join(STORE_RELATIVE);
    ensure_parent(&path)?;
    Ok(path)
}

pub fn default_path(bundle_root: &Path) -> PathBuf {
    bundle_root.join(STORE_RELATIVE)
}

fn candidate_paths(bundle_root: &Path) -> [PathBuf; 2] {
    [
        bundle_root.join(STORE_RELATIVE),
        bundle_root.join(STORE_STATE_RELATIVE),
    ]
}

fn ensure_parent(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}
