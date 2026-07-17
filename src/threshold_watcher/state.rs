//! Durable per-watch edge-state store for the threshold watcher.
//!
//! Persists the last observed [`Side`] (plus the last sampled value and
//! timestamp) for each `(tenant, watch name)` pair, so a watch fires exactly
//! once per genuine crossing and survives a process restart. The state file
//! lives at `{state_dir}/threshold/{tenant}/{name}.json`.
//!
//! Reads are fail-safe: a missing or corrupt/unparseable state file yields
//! `Side::Unknown` rather than panicking or propagating an error — an
//! `Unknown` prior side never participates in a crossing (see
//! `eval::crossing`), so this can never fabricate a spurious fire. Writes are
//! atomic: the new state is written to a `.tmp` sibling file and then
//! renamed into place, so a crash mid-write cannot leave a corrupt/partial
//! state file behind.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::eval::Side;

/// The last observed edge state for a single watch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatchState {
    pub last_side: Side,
    pub last_value: Option<f64>,
    pub last_checked: Option<String>,
}

/// Path to the durable state file for a given `(tenant, name)` watch.
fn state_path(state_dir: &Path, tenant: &str, name: &str) -> PathBuf {
    state_dir
        .join("threshold")
        .join(tenant)
        .join(format!("{name}.json"))
}

/// Load the durable edge state for `(tenant, name)`.
///
/// A missing file or a file that fails to parse yields the fail-safe default
/// (`Side::Unknown`, no value, no timestamp) — this function never panics
/// and never returns an error.
pub fn load_state(state_dir: &Path, tenant: &str, name: &str) -> WatchState {
    let path = state_path(state_dir, tenant, name);
    let fallback = || WatchState {
        last_side: Side::Unknown,
        last_value: None,
        last_checked: None,
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(_) => return fallback(),
    };
    match serde_json::from_str(&contents) {
        Ok(state) => state,
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "corrupt threshold watch state file; treating as unknown"
            );
            fallback()
        }
    }
}

/// Persist the durable edge state for `(tenant, name)`.
///
/// Creates the parent directory tree if needed, then writes atomically: the
/// serialized state is written to a `{name}.json.tmp` sibling file and
/// renamed into place, so a crash mid-write never leaves a partially-written
/// state file at the canonical path.
pub fn save_state(
    state_dir: &Path,
    tenant: &str,
    name: &str,
    state: &WatchState,
) -> std::io::Result<()> {
    let path = state_path(state_dir, tenant, name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(state)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_round_trips_side_and_value() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = WatchState {
            last_side: Side::Above,
            last_value: Some(97.5),
            last_checked: Some("2026-07-03T00:00:00Z".to_string()),
        };

        save_state(temp.path(), "acme", "cpu-high", &state).expect("save_state");
        let loaded = load_state(temp.path(), "acme", "cpu-high");

        assert_eq!(loaded, state);
    }

    #[test]
    fn load_missing_file_returns_unknown() {
        let temp = tempfile::tempdir().expect("tempdir");

        let loaded = load_state(temp.path(), "acme", "cpu-high");

        assert_eq!(loaded.last_side, Side::Unknown);
        assert_eq!(loaded.last_value, None);
        assert_eq!(loaded.last_checked, None);
    }

    #[test]
    fn load_corrupt_file_returns_unknown_without_panicking() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("threshold").join("acme");
        std::fs::create_dir_all(&dir).expect("create dirs");
        std::fs::write(dir.join("cpu-high.json"), "{ not json").expect("write corrupt file");

        let loaded = load_state(temp.path(), "acme", "cpu-high");

        assert_eq!(loaded.last_side, Side::Unknown);
        assert_eq!(loaded.last_value, None);
        assert_eq!(loaded.last_checked, None);
    }

    #[test]
    fn save_state_leaves_no_tmp_file_behind() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = WatchState {
            last_side: Side::Below,
            last_value: Some(1.0),
            last_checked: None,
        };

        save_state(temp.path(), "acme", "cpu-high", &state).expect("save_state");

        let dir = temp.path().join("threshold").join("acme");
        let tmp_path = dir.join("cpu-high.json.tmp");
        assert!(!tmp_path.exists(), "temp file should not remain after save");
        assert!(dir.join("cpu-high.json").exists());
    }
}
