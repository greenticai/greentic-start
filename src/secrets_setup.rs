#![allow(dead_code)]

//! SecretsSetup is the single entrypoint for secrets initialization and resolution inside greentic-operator.
//!
//! Inputs:
//! - the bundle root where the operator bundle puts state and the `.greentic/dev/.dev.secrets.env` dev store
//! - the environment, tenant, and optional team that define canonical secret URIs
//! - optional seeds documents embedded in the bundle (`seeds.yaml` or `<bundle>/state/seeds.yaml`)
//!
//! Guarantees:
//! - exactly one dev store backend is opened per operator process and owned for the lifetime of SecretsSetup
//! - every required secret discovered from packs/providers is canonicalized and registered in that store
//! - missing secrets are seeded either from the documents above or with deterministic placeholders
//!
//! Non-goals:
//! - interactive prompting for secrets or manual overrides
//! - legacy fallback lookups against other namespaces/storage backends
//! - implicit provider-specific secret inference beyond the declared canonical URIs

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use greentic_secrets_lib::core::Error as SecretError;
use greentic_secrets_lib::{
    ApplyOptions, DevStore, SecretFormat, SecretsStore, SeedDoc, SeedEntry, SeedValue, apply_seed,
};
use tracing::{debug, info};

use crate::{
    dev_store_path, secret_requirements::load_secret_keys_from_pack,
    secrets_gate::canonical_secret_uri,
};

pub fn resolve_env(override_env: Option<&str>) -> String {
    override_env
        .map(|value| value.to_string())
        .or_else(|| std::env::var("GREENTIC_ENV").ok())
        .unwrap_or_else(|| "dev".to_string())
}

pub struct SecretsSetup {
    store: DevStore,
    store_path: PathBuf,
    env: String,
    tenant: String,
    team: Option<String>,
    seeds: HashMap<String, SeedEntry>,
}

impl SecretsSetup {
    pub fn new(bundle_root: &Path, env: &str, tenant: &str, team: Option<&str>) -> Result<Self> {
        let store_path = dev_store_path::ensure_path(bundle_root)?;
        info!(path = %store_path.display(), "secrets: using dev store backend");
        let store = DevStore::with_path(&store_path).map_err(|err| {
            anyhow!(
                "failed to open dev secrets store {}: {err}",
                store_path.display()
            )
        })?;
        let seeds = load_seed_entries(bundle_root)?;
        Ok(Self {
            store,
            store_path,
            env: env.to_string(),
            tenant: tenant.to_string(),
            team: team.map(|value| value.to_string()),
            seeds,
        })
    }

    pub fn store_path(&self) -> &Path {
        &self.store_path
    }

    pub async fn ensure_pack_secrets(&self, pack_path: &Path, provider_id: &str) -> Result<()> {
        let keys = load_secret_keys_from_pack(pack_path)?;
        if keys.is_empty() {
            return Ok(());
        }
        let mut missing = Vec::new();
        for key in keys {
            let uri = canonical_secret_uri(
                &self.env,
                &self.tenant,
                self.team.as_deref(),
                provider_id,
                &key,
            );
            debug!(uri = %uri, provider = %provider_id, key = %key, "canonicalized secret requirement");
            match self.store.get(&uri).await {
                Ok(_) => continue,
                Err(SecretError::NotFound { .. }) => {
                    let source = if self.seeds.contains_key(&uri) {
                        "seeds.yaml"
                    } else {
                        "placeholder"
                    };
                    debug!(uri = %uri, source, "seeding missing secret");
                    missing.push(
                        self.seeds
                            .get(&uri)
                            .cloned()
                            .unwrap_or_else(|| placeholder_entry(uri.clone())),
                    );
                }
                Err(err) => {
                    return Err(anyhow!("failed to read secret {}: {err}", uri));
                }
            }
        }
        if missing.is_empty() {
            return Ok(());
        }
        let report = apply_seed(
            &self.store,
            &SeedDoc { entries: missing },
            ApplyOptions::default(),
        )
        .await;
        if !report.failed.is_empty() {
            return Err(anyhow!("failed to seed secrets: {:?}", report.failed));
        }
        Ok(())
    }
}

fn load_seed_entries(bundle_root: &Path) -> Result<HashMap<String, SeedEntry>> {
    for candidate in seed_paths(bundle_root) {
        if candidate.exists() {
            let contents = std::fs::read_to_string(&candidate)?;
            let doc: SeedDoc = serde_yaml_bw::from_str(&contents)?;
            return Ok(doc
                .entries
                .into_iter()
                .map(|entry| (entry.uri.clone(), entry))
                .collect());
        }
    }
    Ok(HashMap::new())
}

fn seed_paths(bundle_root: &Path) -> [PathBuf; 2] {
    [
        bundle_root.join("seeds.yaml"),
        bundle_root.join("state").join("seeds.yaml"),
    ]
}

fn placeholder_entry(uri: String) -> SeedEntry {
    let text = placeholder_text_for_uri(&uri);
    SeedEntry {
        uri: uri.clone(),
        format: SecretFormat::Text,
        value: SeedValue::Text { text },
        description: Some("auto-applied placeholder".to_string()),
    }
}

fn placeholder_text_for_uri(uri: &str) -> String {
    let lower = uri.to_ascii_lowercase();
    if matches!(lower.rsplit('/').next(), Some("api_key_secret")) {
        "ollama-placeholder".to_string()
    } else {
        format!("placeholder for {uri}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets_gate::canonical_secret_uri;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_pack_with_secret_requirements(path: &Path, keys: &[&str]) {
        let file = std::fs::File::create(path).expect("pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "assets/secret-requirements.json",
            zip::write::FileOptions::<()>::default(),
        )
        .expect("start file");
        let requirements = serde_json::to_vec(
            &keys
                .iter()
                .map(|key| serde_json::json!({ "key": key }))
                .collect::<Vec<_>>(),
        )
        .expect("requirements");
        zip.write_all(&requirements).expect("write");
        zip.finish().expect("finish");
    }

    fn write_seed_doc(path: &Path, entries: Vec<SeedEntry>) {
        let doc = SeedDoc { entries };
        let yaml = serde_yaml_bw::to_string(&doc).expect("yaml");
        std::fs::write(path, yaml).expect("seed file");
    }

    #[test]
    fn resolve_env_prefers_override_then_env_then_dev() {
        assert_eq!(resolve_env(Some("stage")), "stage");
        unsafe {
            std::env::set_var("GREENTIC_ENV", "prod");
        }
        assert_eq!(resolve_env(None), "prod");
        unsafe {
            std::env::remove_var("GREENTIC_ENV");
        }
        assert_eq!(resolve_env(None), "dev");
    }

    #[test]
    fn seed_helpers_load_existing_docs_and_build_placeholders() {
        let dir = tempdir().expect("tempdir");
        let seed_uri = "secrets://dev/demo/default/provider/token";
        write_seed_doc(
            &dir.path().join("seeds.yaml"),
            vec![SeedEntry {
                uri: seed_uri.to_string(),
                format: SecretFormat::Text,
                value: SeedValue::Text {
                    text: "seeded-value".to_string(),
                },
                description: None,
            }],
        );

        let paths = seed_paths(dir.path());
        assert_eq!(paths[0], dir.path().join("seeds.yaml"));
        assert_eq!(paths[1], dir.path().join("state").join("seeds.yaml"));

        let seeds = load_seed_entries(dir.path()).expect("load seeds");
        assert_eq!(seeds.get(seed_uri).expect("seed").uri, seed_uri);

        let placeholder = placeholder_entry(seed_uri.to_string());
        assert_eq!(placeholder.uri, seed_uri);
        assert_eq!(
            placeholder.description.as_deref(),
            Some("auto-applied placeholder")
        );
    }

    #[tokio::test]
    async fn ensure_pack_secrets_seeds_missing_values_from_seed_doc_and_placeholders() {
        let dir = tempdir().expect("tempdir");
        let pack = dir.path().join("provider.gtpack");
        write_pack_with_secret_requirements(&pack, &["BOT_TOKEN", "API_KEY"]);

        let seeded_uri = canonical_secret_uri(
            "dev",
            "demo",
            Some("default"),
            "messaging-slack",
            "BOT_TOKEN",
        );
        write_seed_doc(
            &dir.path().join("seeds.yaml"),
            vec![SeedEntry {
                uri: seeded_uri.clone(),
                format: SecretFormat::Text,
                value: SeedValue::Text {
                    text: "seeded-bot-token".to_string(),
                },
                description: None,
            }],
        );

        let setup = SecretsSetup::new(dir.path(), "dev", "demo", Some("default")).expect("setup");
        setup
            .ensure_pack_secrets(&pack, "messaging-slack")
            .await
            .expect("ensure secrets");

        let seeded = setup.store.get(&seeded_uri).await.expect("seeded");
        assert_eq!(String::from_utf8(seeded).expect("utf8"), "seeded-bot-token");

        let placeholder_uri =
            canonical_secret_uri("dev", "demo", Some("default"), "messaging-slack", "API_KEY");
        let placeholder = setup
            .store
            .get(&placeholder_uri)
            .await
            .expect("placeholder");
        assert!(
            String::from_utf8(placeholder)
                .expect("utf8")
                .contains("placeholder for")
        );
    }

    #[test]
    fn placeholder_entry_uses_dummy_value_for_api_key_secret_uri() {
        let entry =
            placeholder_entry("secrets://dev/demo/_/deep-research-demo/api_key_secret".to_string());
        let SeedValue::Text { text } = entry.value else {
            panic!("expected text seed value");
        };
        assert_eq!(text, "ollama-placeholder");
    }

    #[test]
    fn placeholder_entry_keeps_generic_placeholder_for_other_api_key_uris() {
        let entry =
            placeholder_entry("secrets://dev/demo/_/deep-research-demo/api_key".to_string());
        let SeedValue::Text { text } = entry.value else {
            panic!("expected text seed value");
        };
        assert!(text.contains("placeholder for"));
        assert!(text.contains("/api_key"));
    }

    #[tokio::test]
    async fn ensure_pack_secrets_skips_when_pack_declares_no_secret_requirements() {
        let dir = tempdir().expect("tempdir");
        let pack = dir.path().join("provider.gtpack");
        let file = std::fs::File::create(&pack).expect("pack");
        let zip = zip::ZipWriter::new(file);
        zip.finish().expect("finish");

        let setup = SecretsSetup::new(dir.path(), "dev", "demo", Some("default")).expect("setup");
        setup
            .ensure_pack_secrets(&pack, "messaging-slack")
            .await
            .expect("ensure");
        assert!(load_seed_entries(dir.path()).expect("seeds").is_empty());
    }
}
