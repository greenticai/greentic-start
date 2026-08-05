//! The single place greentic-start decides which secret address to read.
//!
//! Four call paths used to build candidates independently — `secret_read_uris`,
//! `revision_serve::read_provider_signing_key`, and two in `webhook_updater`
//! that built no candidate list at all. A fifth would eventually have been
//! written; instead they all come here.
//!
//! A bundle records the address of its own secret in its answers file (written
//! by greentic-setup's `secret_ref`). Reading that back — rather than deriving
//! it — is what lets two bundles under one tenant hold different tokens without
//! either repo deriving a shared string.

use std::path::Path;

use crate::operator_log;

/// Addresses to try, in order.
///
/// A recorded ref is returned ALONE. The bundle has declared where its secret
/// lives, and falling through to the tenant-scoped key would read whatever the
/// last bundle to run setup wrote there — precisely the cross-bundle collision
/// this resolver exists to close.
pub(crate) fn secret_candidates(
    bundle_root: Option<&Path>,
    env: &str,
    tenant: &str,
    team: Option<&str>,
    provider: &str,
    key: &str,
) -> Vec<String> {
    if let Some(recorded) =
        bundle_root.and_then(|root| recorded_ref(root, tenant, team, provider, key))
    {
        return vec![recorded];
    }

    let team_segment = crate::secrets_manager::canonical_team(team);
    let raw_provider = if provider.is_empty() {
        "messaging"
    } else {
        provider
    };
    let raw_uri = format!("secrets://{env}/{tenant}/{team_segment}/{raw_provider}/{key}");
    let canonical_uri = crate::secrets_gate::canonical_secret_uri(env, tenant, team, provider, key);
    if raw_uri == canonical_uri {
        vec![raw_uri]
    } else {
        vec![raw_uri, canonical_uri]
    }
}

/// Read the address the bundle itself recorded for `key`, if any.
///
/// Distinguishes two very different situations:
/// - the answers file simply does not exist — normal for a bundle that
///   predates bundle-scoped secrets, or one that has not run setup for this
///   provider yet. Stay silent.
/// - the answers file exists but cannot be read as a JSON object — that is
///   not normal, and is logged so an operator can notice a corrupted or
///   hand-edited answers file rather than silently falling back to a key
///   another bundle may own.
///
/// A key that is simply absent from an otherwise well-formed answers file, or
/// whose value is not a `secrets://` URI, is treated the same as "no ref
/// recorded" and returns `None` without logging — most answers files hold
/// plaintext values, not secret refs, and that is expected.
fn recorded_ref(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
    provider: &str,
    key: &str,
) -> Option<String> {
    let path = crate::provider_answers::answers_path_for_read(
        bundle_root,
        provider,
        tenant,
        team.unwrap_or("default"),
    );
    if !path.is_file() {
        return None;
    }

    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "[secret-resolve] answers file {} for provider {provider} exists but could not be read: {err}",
                    path.display()
                ),
            );
            return None;
        }
    };

    let answers: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "[secret-resolve] answers file {} for provider {provider} is not valid JSON: {err}",
                    path.display()
                ),
            );
            return None;
        }
    };

    let Some(object) = answers.as_object() else {
        operator_log::warn(
            module_path!(),
            format!(
                "[secret-resolve] answers file {} for provider {provider} is not a JSON object",
                path.display()
            ),
        );
        return None;
    };

    object
        .get(key)?
        .as_str()
        .filter(|value| value.starts_with("secrets://"))
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_ref_is_the_only_candidate() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let scoped =
            crate::provider_answers::answers_path(root, "messaging-telegram", "demo", "default");
        std::fs::create_dir_all(scoped.parent().expect("dir")).expect("dir");
        std::fs::write(
            &scoped,
            r#"{"bot_token":"secrets://dev/demo/_/messaging_telegram_a7f3c/bot_token"}"#,
        )
        .expect("write answers");

        let candidates = secret_candidates(
            Some(root),
            "dev",
            "demo",
            None,
            "messaging-telegram",
            "bot_token",
        );

        assert_eq!(
            candidates,
            vec!["secrets://dev/demo/_/messaging_telegram_a7f3c/bot_token".to_string()],
            "a declared address must not fall back to a key another bundle may own",
        );
    }

    #[test]
    fn without_a_ref_the_legacy_candidates_are_unchanged() {
        let candidates =
            secret_candidates(None, "dev", "demo", None, "messaging-telegram", "bot_token");
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0],
            "secrets://dev/demo/_/messaging-telegram/bot_token"
        );
        assert_eq!(
            candidates[1],
            "secrets://dev/demo/_/messaging_telegram/bot_token"
        );
    }

    #[test]
    fn missing_answers_file_is_silent_no_ref() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();

        // No answers file at all under `root` for this provider/tenant.
        let candidates = secret_candidates(
            Some(root),
            "dev",
            "demo",
            None,
            "messaging-telegram",
            "bot_token",
        );

        // Falls through to the legacy pair, same as `bundle_root: None`.
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn corrupt_answers_file_falls_back_without_panicking() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let scoped =
            crate::provider_answers::answers_path(root, "messaging-telegram", "demo", "default");
        std::fs::create_dir_all(scoped.parent().expect("dir")).expect("dir");
        std::fs::write(&scoped, "not valid json").expect("write corrupt answers");

        let candidates = secret_candidates(
            Some(root),
            "dev",
            "demo",
            None,
            "messaging-telegram",
            "bot_token",
        );

        assert_eq!(
            candidates.len(),
            2,
            "an unparseable answers file must fall back to the legacy pair, not panic",
        );
    }

    #[test]
    fn key_absent_from_a_well_formed_answers_file_falls_back_silently() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let scoped =
            crate::provider_answers::answers_path(root, "messaging-telegram", "demo", "default");
        std::fs::create_dir_all(scoped.parent().expect("dir")).expect("dir");
        std::fs::write(&scoped, r#"{"other_field":"plain value"}"#).expect("write answers");

        let candidates = secret_candidates(
            Some(root),
            "dev",
            "demo",
            None,
            "messaging-telegram",
            "bot_token",
        );

        assert_eq!(candidates.len(), 2);
    }

    /// CROSS-SYSTEM SECRET CONTRACT — DO NOT CHANGE THIS TEST.
    ///
    /// greentic-setup WRITES a bundle's secret under the address it records in
    /// that bundle's answers file (via `secret_ref::resolve_secret_uri`). The
    /// runtime READS that address back verbatim. If either side starts deriving
    /// the address instead of recording/reading it, two bundles under one tenant
    /// silently share a token again.
    ///
    /// The golden string below MUST exactly match what greentic-setup writes in
    /// the answers file. Do NOT edit the expected value to make a build pass.
    /// Changing the secret-uri scheme requires a NEW secrets plan verified
    /// end-to-end on BOTH binaries (setup + start) and BOTH backends (local
    /// dev-store + cloud vault) and public.
    #[test]
    fn recorded_secret_ref_contract_do_not_change() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let scoped =
            crate::provider_answers::answers_path(root, "messaging-telegram", "demo", "default");
        std::fs::create_dir_all(scoped.parent().expect("dir")).expect("dir");
        std::fs::write(
            &scoped,
            r#"{"bot_token":"secrets://dev/demo/_/messaging_telegram_a7f3c/bot_token"}"#,
        )
        .expect("write answers");

        assert_eq!(
            secret_candidates(
                Some(root),
                "dev",
                "demo",
                None,
                "messaging-telegram",
                "bot_token"
            ),
            vec!["secrets://dev/demo/_/messaging_telegram_a7f3c/bot_token".to_string()],
        );
    }
}
