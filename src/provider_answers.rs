//! Where a provider's `setup-answers.json` lives.
//!
//! The twin of `greentic-setup/src/provider_answers.rs`. Answers are scoped
//! `state/config/<provider>/<tenant>/<team>/` because every other piece of
//! per-provider setup state is tenant-scoped; unscoped, a second tenant read
//! back the first one's answers.
//!
//! `answers_path_contract_do_not_change` below pins the exact same string that
//! setup's test of the same name pins. Both must move together or setup-written
//! answers silently stop being found here.

use std::path::{Path, PathBuf};

const ANSWERS_FILE: &str = "setup-answers.json";

fn provider_dir(bundle_root: &Path, provider_id: &str) -> PathBuf {
    bundle_root.join("state").join("config").join(provider_id)
}

/// The tenant-scoped path. Mirrors setup's writer.
pub(crate) fn answers_path(
    bundle_root: &Path,
    provider_id: &str,
    tenant: &str,
    team: &str,
) -> PathBuf {
    provider_dir(bundle_root, provider_id)
        .join(normalize_segment(tenant))
        .join(normalize_segment(team))
        .join(ANSWERS_FILE)
}

/// Pre-tenant path: read as a fallback, never written.
pub(crate) fn legacy_answers_path(bundle_root: &Path, provider_id: &str) -> PathBuf {
    provider_dir(bundle_root, provider_id).join(ANSWERS_FILE)
}

/// Scoped file if present, else legacy. Neither present → the scoped path, so
/// "missing" names what setup would create.
pub(crate) fn answers_path_for_read(
    bundle_root: &Path,
    provider_id: &str,
    tenant: &str,
    team: &str,
) -> PathBuf {
    let scoped = answers_path(bundle_root, provider_id, tenant, team);
    if scoped.is_file() {
        return scoped;
    }
    let legacy = legacy_answers_path(bundle_root, provider_id);
    if legacy.is_file() {
        return legacy;
    }
    scoped
}

/// Keeps a tenant/team from escaping the provider dir. Empty → `default`.
fn normalize_segment(value: &str) -> String {
    let cleaned: String = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CROSS-SYSTEM ANSWERS CONTRACT — DO NOT CHANGE THIS TEST.
    ///
    /// The golden string MUST equal the one pinned by
    /// `answers_path_contract_do_not_change` in greentic-setup's
    /// `src/provider_answers.rs`.
    #[test]
    fn answers_path_contract_do_not_change() {
        assert_eq!(
            answers_path(
                Path::new("/bundle"),
                "messaging-telegram",
                "acme",
                "default"
            ),
            Path::new("/bundle/state/config/messaging-telegram/acme/default/setup-answers.json"),
        );
    }

    #[test]
    fn read_prefers_the_scoped_file_but_falls_back_to_legacy() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let legacy = legacy_answers_path(root, "messaging-telegram");
        std::fs::create_dir_all(legacy.parent().expect("legacy dir")).expect("dir");
        std::fs::write(&legacy, "{}").expect("write legacy");

        assert_eq!(
            answers_path_for_read(root, "messaging-telegram", "acme", "default"),
            legacy,
            "an older bundle with only the legacy file must keep working",
        );

        let scoped = answers_path(root, "messaging-telegram", "acme", "default");
        std::fs::create_dir_all(scoped.parent().expect("scoped dir")).expect("dir");
        std::fs::write(&scoped, "{}").expect("write scoped");
        assert_eq!(
            answers_path_for_read(root, "messaging-telegram", "acme", "default"),
            scoped,
        );
        assert_eq!(
            answers_path_for_read(root, "messaging-telegram", "other", "default"),
            legacy,
            "one tenant's scoped file must not be visible to another tenant",
        );
    }

    #[test]
    fn path_traversal_in_tenant_cannot_escape_the_provider_directory() {
        let path = answers_path(
            Path::new("/bundle"),
            "messaging-telegram",
            "../../etc",
            "default",
        );
        assert!(
            path.starts_with("/bundle/state/config/messaging-telegram"),
            "escaped the provider dir: {}",
            path.display(),
        );
    }
}
