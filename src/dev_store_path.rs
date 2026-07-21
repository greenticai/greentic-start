#![allow(dead_code)]

//! Dev-store path resolution for the runtime (reader) side.
//!
//! Mirrors `greentic-setup/src/secrets.rs`'s path helpers verbatim so the
//! `setup` (writer) and `start` (reader) sides resolve the dev store to the
//! *same* shared environment store
//! (`~/.greentic/environments/<env>/.greentic/dev/.dev.secrets.env`). This lets
//! `gtc setup` and `gtc start` rendezvous on one file across invocations,
//! independent of any ephemeral bundle extraction dir, and unifies bundle-path
//! secrets with the env-path (`op secrets` / `provider add`) store.
//!
//! The logic is duplicated (not shared via `greentic_setup`) on purpose: the
//! two crates publish on independent cadences and this crate builds against a
//! *registry* `greentic-setup`, so a call into it would resolve the old
//! bundle-local behavior. Keep the two copies in lock-step.

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

/// Dev-store path inside the shared environment store:
///   `~/.greentic/environments/<env>/.greentic/dev/.dev.secrets.env`
///
/// The same file `gtc op secrets` / `provider add` and `gtc setup` write, so the
/// serve loop reads exactly what setup registered. Returns `None` when the
/// environment-store root can't be resolved (no `HOME`/`USERPROFILE`), letting
/// callers fall back to a bundle-local path.
pub fn env_store_dev_secrets_path(env: &str) -> Option<PathBuf> {
    greentic_deployer::environment::LocalFsStore::default_root()
        .map(|root| root.join(env).join(STORE_RELATIVE))
}

/// The explicitly-selected environment, or `None` when `$GREENTIC_ENV` is unset.
/// Bare callers route to the shared env store only when an env is selected;
/// `start` sets `$GREENTIC_ENV` at boot, so production always resolves it, while
/// unit tests (which leave it unset) stay on the hermetic bundle-local store.
fn selected_env() -> Option<String> {
    env::var("GREENTIC_ENV")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|raw| crate::resolve_env(Some(&raw)))
}

/// The path a *write* should target for an explicit env: the shared env store
/// when resolvable, otherwise the legacy bundle-local path.
fn write_path_for_env(bundle_root: &Path, env: &str) -> PathBuf {
    env_store_dev_secrets_path(env).unwrap_or_else(|| bundle_root.join(STORE_RELATIVE))
}

/// The write path for a bare caller: the shared env store when an env is
/// selected via `$GREENTIC_ENV`, else the legacy bundle-local path.
fn bare_write_path(bundle_root: &Path) -> PathBuf {
    selected_env()
        .and_then(|env| env_store_dev_secrets_path(&env))
        .unwrap_or_else(|| bundle_root.join(STORE_RELATIVE))
}

/// Read-preference order: the shared env store (when an env is selected), then
/// legacy bundle-local candidates (for already-configured bundle directories).
fn read_candidate_paths(bundle_root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(env_store) = selected_env().and_then(|env| env_store_dev_secrets_path(&env)) {
        out.push(env_store);
    }
    out.push(bundle_root.join(STORE_RELATIVE));
    out.push(bundle_root.join(STORE_STATE_RELATIVE));
    out
}

/// Checks for an existing dev store: override, then env store, then bundle-local.
pub fn find_existing(bundle_root: &Path) -> Option<PathBuf> {
    find_existing_with_override(bundle_root, override_path().as_deref())
}

/// Looks for an existing dev store using an override path before consulting the
/// shared env store and then legacy bundle-local candidates.
pub fn find_existing_with_override(
    bundle_root: &Path,
    override_path: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(path) = override_path
        && path.exists()
    {
        return Some(path.to_path_buf());
    }
    read_candidate_paths(bundle_root)
        .into_iter()
        .find(|candidate| candidate.exists())
}

/// Ensures the default dev store path exists (creating parent directories).
/// Routes to the shared env store when `$GREENTIC_ENV` is set.
pub fn ensure_path(bundle_root: &Path) -> Result<PathBuf> {
    if let Some(path) = override_path() {
        ensure_parent(&path)?;
        return Ok(path);
    }
    let path = bare_write_path(bundle_root);
    ensure_parent(&path)?;
    Ok(path)
}

/// Like [`ensure_path`], but with an explicit environment — always the shared
/// env store (when resolvable), independent of `$GREENTIC_ENV`.
pub fn ensure_path_for_env(bundle_root: &Path, env: &str) -> Result<PathBuf> {
    if let Some(path) = override_path() {
        ensure_parent(&path)?;
        return Ok(path);
    }
    let path = write_path_for_env(bundle_root, env);
    ensure_parent(&path)?;
    Ok(path)
}

/// Returns the default dev store path without creating anything.
pub fn default_path(bundle_root: &Path) -> PathBuf {
    override_path().unwrap_or_else(|| bare_write_path(bundle_root))
}

fn ensure_parent(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}
