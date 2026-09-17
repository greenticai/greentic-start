//! `HttpInV1.config` for provider ingress on the revision-serve path (#585).
//!
//! The legacy host resolves a provider's config through
//! [`crate::ingress_dispatch::build_injected_config`]. The revision path used
//! to send `config: None`, so every deploy-time provider answer (webchat's
//! `auto_start_on_open`, say) was inert on the `op` lineage. This module
//! resolves the same config through the same
//! [`ProviderConfigDraft`](crate::ingress_dispatch::ProviderConfigDraft) and
//! differs only where the revision path genuinely differs:
//!
//! - the bundle root is the extracted revision bundle the pack was pinned
//!   from, found by walking up from the pack file;
//! - the revision's pinned `pack-config.v1.non_secret` map is layered in;
//! - secrets are read asynchronously from the runner host's secrets manager,
//!   with the same URI candidates `DemoRunnerHost::get_secret` tries.
//!
//! Secret VALUES are never logged — only key names.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use serde_json::Value;

use crate::ingress_dispatch::{ProviderConfigDraft, ProviderConfigSources};
use crate::operator_log;
use crate::secrets_gate::DynSecretsManager;

/// The marker `greentic-deployer` requires of an extracted revision bundle.
const BUNDLE_MANIFEST_FILE: &str = "bundle-manifest.json";

/// What the revision path knows about the provider pack behind a route.
pub(crate) struct RevisionProviderPack {
    /// Provider id: the pack id, which is also the `.providers/` and
    /// `state/config/` directory name and the secret-store provider segment.
    pub pack_id: String,
    pub pack_path: PathBuf,
    pub pack_non_secret: Option<Arc<BTreeMap<String, Value>>>,
}

impl RevisionProviderPack {
    pub(crate) fn from_descriptor(descriptor: &crate::http_routes::HttpRouteDescriptor) -> Self {
        Self {
            pack_id: descriptor.pack_id.clone(),
            pack_path: descriptor.pack_path.clone(),
            pack_non_secret: descriptor.pack_non_secret.clone(),
        }
    }
}

/// Resolve the provider's `HttpInV1.config`, or `None` when nothing applies.
///
/// Errors only when a config source is unresolvable (an `ext://` reference
/// naming an unbound extension) — the same fail-closed contract as the legacy
/// host, which refuses the ingress rather than hand the component an opaque
/// reference.
pub(crate) async fn resolve_revision_provider_config(
    secrets: &DynSecretsManager,
    pack: RevisionProviderPack,
    tenant: &str,
    team: Option<&str>,
) -> anyhow::Result<Option<Value>> {
    let provider = pack.pack_id.clone();
    // Reading the pack's setup form opens the `.gtpack` archive, and `ext://`
    // resolution reads the environment store: both are blocking file I/O.
    let mut draft = tokio::task::spawn_blocking(move || {
        let bundle_root = revision_bundle_root_for_pack(&pack.pack_path);
        ProviderConfigDraft::resolve(&ProviderConfigSources {
            bundle_root: bundle_root.as_deref(),
            pack_path: &pack.pack_path,
            provider: &pack.pack_id,
            pack_non_secret: pack.pack_non_secret.as_deref(),
        })
    })
    .await
    .context("provider config resolution task did not complete")??;

    let env = crate::resolve_env(None);
    let keys = draft.secret_keys_to_fetch();
    for (key, bytes) in fetch_secrets(secrets, &env, tenant, team, &provider, &keys).await {
        draft.insert_secret(&key, &bytes);
    }
    Ok(draft.into_config())
}

/// The extracted revision bundle a pinned pack came from: the nearest
/// ancestor carrying `bundle-manifest.json`. `None` for a pack staged without
/// one, in which case only the pinned pack-config and secrets apply.
pub(crate) fn revision_bundle_root_for_pack(pack_path: &Path) -> Option<PathBuf> {
    pack_path
        .ancestors()
        .skip(1)
        .find(|dir| dir.join(BUNDLE_MANIFEST_FILE).is_file())
        .map(Path::to_path_buf)
}

/// Read each key through the same URI candidates the legacy host tries. A
/// missing secret is skipped (the component may still read the store itself);
/// a failed read is logged by key name and skipped.
async fn fetch_secrets(
    secrets: &DynSecretsManager,
    env: &str,
    tenant: &str,
    team: Option<&str>,
    provider: &str,
    keys: &[String],
) -> Vec<(String, Vec<u8>)> {
    let mut found = Vec::new();
    'keys: for key in keys {
        for uri in crate::runner_host::secret_read_uris(env, tenant, team, provider, key) {
            match secrets.read(&uri).await {
                Ok(bytes) => {
                    found.push((key.clone(), bytes));
                    continue 'keys;
                }
                Err(err) if crate::runner_host::is_secret_not_found(&err) => continue,
                Err(err) => {
                    operator_log::debug(
                        module_path!(),
                        format!(
                            "failed to fetch secret {key} for provider {provider}: {err}, \
                             component will try secrets_store"
                        ),
                    );
                    continue 'keys;
                }
            }
        }
        operator_log::debug(
            module_path!(),
            format!(
                "secret {key} not found for provider {provider}, component will try secrets_store"
            ),
        );
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::json;
    use std::collections::HashMap;

    struct MapSecrets(HashMap<String, Vec<u8>>);

    #[async_trait::async_trait]
    impl greentic_secrets_lib::SecretsManager for MapSecrets {
        async fn read(&self, path: &str) -> greentic_secrets_lib::Result<Vec<u8>> {
            self.0
                .get(path)
                .cloned()
                .ok_or_else(|| greentic_secrets_lib::SecretError::NotFound(path.to_string()))
        }
        async fn write(&self, _path: &str, _bytes: &[u8]) -> greentic_secrets_lib::Result<()> {
            Ok(())
        }
        async fn delete(&self, _path: &str) -> greentic_secrets_lib::Result<()> {
            Ok(())
        }
    }

    fn no_secrets() -> DynSecretsManager {
        Arc::new(MapSecrets(HashMap::new()))
    }

    /// `<rev>/bundle/providers/messaging/<pack>.gtpack` under an extracted
    /// bundle — the layout `greentic-deployer`'s bundle stage produces.
    fn staged_bundle(root: &Path, pack_id: &str) -> (PathBuf, PathBuf) {
        let bundle = root.join("revisions/r1/bundle");
        let pack_dir = bundle.join("providers/messaging");
        std::fs::create_dir_all(&pack_dir).unwrap();
        std::fs::write(bundle.join(BUNDLE_MANIFEST_FILE), b"{}").unwrap();
        let pack_path = pack_dir.join(format!("{pack_id}.gtpack"));
        std::fs::write(&pack_path, b"not a real pack").unwrap();
        (bundle, pack_path)
    }

    fn b64(config: &Value, key: &str) -> Option<String> {
        let encoded = config.get(format!("{key}_b64"))?.as_str()?;
        String::from_utf8(STANDARD.decode(encoded).ok()?).ok()
    }

    #[test]
    fn bundle_root_is_the_nearest_ancestor_with_a_bundle_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let (bundle, pack_path) = staged_bundle(tmp.path(), "messaging-webchat-gui");
        assert_eq!(revision_bundle_root_for_pack(&pack_path), Some(bundle));
    }

    #[test]
    fn bundle_root_is_none_without_a_bundle_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let pack_path = tmp.path().join("packs/p.gtpack");
        std::fs::create_dir_all(pack_path.parent().unwrap()).unwrap();
        std::fs::write(&pack_path, b"x").unwrap();
        assert_eq!(revision_bundle_root_for_pack(&pack_path), None);
    }

    #[tokio::test]
    async fn stored_setup_answers_reach_the_config() {
        let tmp = tempfile::tempdir().unwrap();
        let pack_id = "messaging-provider-under-test";
        let (bundle, pack_path) = staged_bundle(tmp.path(), pack_id);
        let answers_dir = bundle.join("state/config").join(pack_id);
        std::fs::create_dir_all(&answers_dir).unwrap();
        std::fs::write(
            answers_dir.join("setup-answers.json"),
            serde_json::to_vec(&json!({"auto_start_on_open": true, "greeting": "hi"})).unwrap(),
        )
        .unwrap();

        let config = resolve_revision_provider_config(
            &no_secrets(),
            RevisionProviderPack {
                pack_id: pack_id.to_string(),
                pack_path,
                pack_non_secret: None,
            },
            "acme",
            Some("default"),
        )
        .await
        .unwrap()
        .expect("setup answers resolve to a config");

        assert_eq!(b64(&config, "auto_start_on_open").as_deref(), Some("true"));
        assert_eq!(b64(&config, "greeting").as_deref(), Some("hi"));
    }

    #[tokio::test]
    async fn pinned_pack_config_overrides_the_bundle_answers() {
        let tmp = tempfile::tempdir().unwrap();
        let pack_id = "messaging-provider-under-test";
        let (bundle, pack_path) = staged_bundle(tmp.path(), pack_id);
        let answers_dir = bundle.join("state/config").join(pack_id);
        std::fs::create_dir_all(&answers_dir).unwrap();
        std::fs::write(
            answers_dir.join("setup-answers.json"),
            br#"{"auto_start_on_open": false, "greeting": "hi"}"#,
        )
        .unwrap();
        let pinned = BTreeMap::from([("auto_start_on_open".to_string(), json!(true))]);

        let config = resolve_revision_provider_config(
            &no_secrets(),
            RevisionProviderPack {
                pack_id: pack_id.to_string(),
                pack_path,
                pack_non_secret: Some(Arc::new(pinned)),
            },
            "acme",
            None,
        )
        .await
        .unwrap()
        .expect("config");

        assert_eq!(b64(&config, "auto_start_on_open").as_deref(), Some("true"));
        assert_eq!(b64(&config, "greeting").as_deref(), Some("hi"));
    }

    #[tokio::test]
    async fn pinned_pack_config_applies_without_an_extracted_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let pack_path = tmp.path().join("p.gtpack");
        std::fs::write(&pack_path, b"x").unwrap();
        let pinned = BTreeMap::from([("route".to_string(), json!("support"))]);

        let config = resolve_revision_provider_config(
            &no_secrets(),
            RevisionProviderPack {
                pack_id: "messaging-provider-under-test".to_string(),
                pack_path,
                pack_non_secret: Some(Arc::new(pinned)),
            },
            "acme",
            None,
        )
        .await
        .unwrap()
        .expect("config");

        assert_eq!(b64(&config, "route").as_deref(), Some("support"));
    }

    #[tokio::test]
    async fn nothing_to_resolve_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let pack_path = tmp.path().join("p.gtpack");
        std::fs::write(&pack_path, b"x").unwrap();
        let config = resolve_revision_provider_config(
            &no_secrets(),
            RevisionProviderPack {
                pack_id: "messaging-provider-under-test".to_string(),
                pack_path,
                pack_non_secret: None,
            },
            "acme",
            None,
        )
        .await
        .unwrap();
        assert_eq!(config, None);
    }

    #[tokio::test]
    async fn secrets_are_read_through_the_legacy_uri_candidates() {
        let env = crate::resolve_env(None);
        let uris = crate::runner_host::secret_read_uris(
            &env,
            "acme",
            Some("default"),
            "messaging-provider-under-test",
            "bot_token",
        );
        let stored = uris.last().expect("at least one candidate").clone();
        let secrets: DynSecretsManager =
            Arc::new(MapSecrets(HashMap::from([(stored, b"s3cr3t".to_vec())])));

        let found = fetch_secrets(
            &secrets,
            &env,
            "acme",
            Some("default"),
            "messaging-provider-under-test",
            &["bot_token".to_string(), "absent_key".to_string()],
        )
        .await;

        assert_eq!(found, vec![("bot_token".to_string(), b"s3cr3t".to_vec())]);
    }
}
