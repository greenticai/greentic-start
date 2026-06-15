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
    ApplyOptions, DevStore, GeneratedSecretRequirement, PackSecretRequirement, SecretFormat,
    SecretsStore, SeedDoc, SeedEntry, SeedValue, apply_seed, generate_secret_value,
    generated_scope_team,
};
use tracing::{debug, info};

use crate::{
    dev_store_path, secret_requirements::load_secret_requirements_from_pack,
    secrets_gate::canonical_secret_uri,
};

/// Re-export of the crate-level [`crate::resolve_env`] for callers that
/// still import `secrets_setup::resolve_env`. The A4b compat alias is
/// applied inside `crate::resolve_env` so every consumer sees the same
/// remap behavior.
pub use crate::resolve_env;

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
        let requirements = load_secret_requirements_from_pack(pack_path)?;
        self.ensure_requirements(provider_id, requirements).await
    }

    pub async fn ensure_pack_generated_secrets(
        &self,
        pack_path: &Path,
        provider_id: &str,
    ) -> Result<()> {
        let requirements = load_secret_requirements_from_pack(pack_path)?
            .into_iter()
            .filter(|requirement| requirement.generated.is_some())
            .collect();
        self.ensure_requirements(provider_id, requirements).await
    }

    async fn ensure_requirements(
        &self,
        provider_id: &str,
        requirements: Vec<PackSecretRequirement>,
    ) -> Result<()> {
        if requirements.is_empty() {
            return Ok(());
        }
        let mut missing = Vec::new();
        for requirement in requirements {
            let uri = self.requirement_uri(
                provider_id,
                &requirement.key,
                requirement.generated.as_ref(),
            );
            debug!(uri = %uri, provider = %provider_id, key = %requirement.key, "canonicalized secret requirement");
            match self.requirement_exists(provider_id, &requirement).await {
                Ok(true) if !requirement_allows_regeneration(&requirement) => continue,
                Ok(true) => continue,
                Ok(false) => {
                    let source = if requirement.generated.is_some() {
                        "generated"
                    } else if self.seeds.contains_key(&uri) {
                        "seeds.yaml"
                    } else {
                        "placeholder"
                    };
                    debug!(uri = %uri, source, "seeding missing secret");
                    missing.push(self.seed_entry_for_requirement(uri.clone(), &requirement)?);
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

    async fn requirement_exists(
        &self,
        provider_id: &str,
        requirement: &PackSecretRequirement,
    ) -> Result<bool> {
        for key in std::iter::once(requirement.key.as_str())
            .chain(requirement.aliases.iter().map(String::as_str))
        {
            let uri = self.requirement_uri(provider_id, key, requirement.generated.as_ref());
            match self.store.get(&uri).await {
                Ok(_) => return Ok(true),
                Err(SecretError::NotFound { .. }) => continue,
                Err(err) => return Err(anyhow!("failed to read secret {}: {err}", uri)),
            }
        }
        Ok(false)
    }

    fn requirement_uri(
        &self,
        provider_id: &str,
        key: &str,
        generated: Option<&GeneratedSecretRequirement>,
    ) -> String {
        let team = if let Some(generated) = generated {
            generated_scope_team(generated, self.team.as_deref())
        } else {
            self.team.as_deref()
        };
        canonical_secret_uri(&self.env, &self.tenant, team, provider_id, key)
    }

    fn seed_entry_for_requirement(
        &self,
        uri: String,
        requirement: &PackSecretRequirement,
    ) -> Result<SeedEntry> {
        if let Some(generated) = &requirement.generated {
            return generated_entry(uri, generated);
        }
        Ok(self
            .seeds
            .get(&uri)
            .cloned()
            .unwrap_or_else(|| placeholder_entry(uri.clone())))
    }
}

fn requirement_allows_regeneration(requirement: &PackSecretRequirement) -> bool {
    requirement
        .generated
        .as_ref()
        .is_some_and(|generated| generated.regenerate_if_present)
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

fn generated_entry(uri: String, generated: &GeneratedSecretRequirement) -> Result<SeedEntry> {
    let (bytes, format) = generate_secret_value(generated)
        .map_err(|err| anyhow!("failed to generate secret for {uri}: {err}"))?;
    let text = String::from_utf8(bytes)
        .map_err(|err| anyhow!("generated secret for {uri} was not valid UTF-8: {err}"))?;
    Ok(SeedEntry {
        uri,
        format,
        value: SeedValue::Text { text },
        description: Some("auto-generated provider runtime secret".to_string()),
    })
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

    fn write_pack_with_requirements_json(path: &Path, requirements: serde_json::Value) {
        let file = std::fs::File::create(path).expect("pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "assets/secret-requirements.json",
            zip::write::FileOptions::<()>::default(),
        )
        .expect("start file");
        zip.write_all(&serde_json::to_vec(&requirements).expect("requirements"))
            .expect("write");
        zip.finish().expect("finish");
    }

    fn write_seed_doc(path: &Path, entries: Vec<SeedEntry>) {
        let doc = SeedDoc { entries };
        let yaml = serde_yaml_bw::to_string(&doc).expect("yaml");
        std::fs::write(path, yaml).expect("seed file");
    }

    #[test]
    fn resolve_env_prefers_override_then_env_then_default() {
        // Updated for A4b: the bare default is now `local` (was `dev`),
        // and any `dev` value goes through the compat-alias remap.
        // Env-var mutation is serialized via the shared `ENV_LOCK` /
        // `with_clean_env` helper in `lib.rs::tests`; this test stays
        // intentionally simple by avoiding `GREENTIC_DISABLE_DEV_ALIAS`
        // (the gate is tested in `lib.rs`).
        assert_eq!(resolve_env(Some("stage")), "stage");
        unsafe {
            std::env::set_var("GREENTIC_ENV", "prod");
        }
        assert_eq!(resolve_env(None), "prod");
        unsafe {
            std::env::remove_var("GREENTIC_ENV");
        }
        assert_eq!(resolve_env(None), "local");
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

    #[tokio::test]
    async fn ensure_pack_secrets_generates_declared_tenant_secret() {
        let dir = tempdir().expect("tempdir");
        let pack = dir.path().join("provider.gtpack");
        write_pack_with_requirements_json(
            &pack,
            serde_json::json!([
                {
                    "key": "jwt_signing_key",
                    "required": true,
                    "generated": {
                        "policy": "random",
                        "length": 20,
                        "encoding": "raw_text",
                        "scope": {
                            "level": "tenant",
                            "team": "_"
                        },
                        "regenerate_if_present": false
                    }
                }
            ]),
        );

        let setup = SecretsSetup::new(dir.path(), "dev", "demo", Some("default")).expect("setup");
        setup
            .ensure_pack_secrets(&pack, "messaging-webchat-gui")
            .await
            .expect("ensure secrets");

        let tenant_uri = canonical_secret_uri(
            "dev",
            "demo",
            None,
            "messaging-webchat-gui",
            "jwt_signing_key",
        );
        let generated = setup.store.get(&tenant_uri).await.expect("generated");
        let generated = String::from_utf8(generated).expect("utf8");
        assert_eq!(generated.len(), 20);
        assert!(!generated.contains("placeholder"));
    }

    #[tokio::test]
    async fn ensure_pack_secrets_preserves_existing_generated_secret() {
        let dir = tempdir().expect("tempdir");
        let pack = dir.path().join("provider.gtpack");
        write_pack_with_requirements_json(
            &pack,
            serde_json::json!([
                {
                    "key": "webex_webhook_secret",
                    "required": true,
                    "generated": {
                        "policy": "random",
                        "length": 20,
                        "encoding": "raw_text",
                        "scope": {
                            "level": "tenant",
                            "team": "_"
                        },
                        "regenerate_if_present": false
                    }
                }
            ]),
        );

        let setup = SecretsSetup::new(dir.path(), "dev", "demo", Some("default")).expect("setup");
        let uri = canonical_secret_uri(
            "dev",
            "demo",
            None,
            "messaging-webex",
            "webex_webhook_secret",
        );
        setup
            .store
            .put(&uri, SecretFormat::Text, b"existing-webhook-secret")
            .await
            .expect("seed existing");

        setup
            .ensure_pack_secrets(&pack, "messaging-webex")
            .await
            .expect("ensure secrets");

        let value = setup.store.get(&uri).await.expect("existing");
        assert_eq!(value, b"existing-webhook-secret".to_vec());
    }

    #[tokio::test]
    async fn ensure_pack_secrets_considers_generated_aliases_existing() {
        let dir = tempdir().expect("tempdir");
        let pack = dir.path().join("provider.gtpack");
        write_pack_with_requirements_json(
            &pack,
            serde_json::json!([
                {
                    "key": "jwt_signing_key",
                    "aliases": ["legacy_jwt_key"],
                    "required": true,
                    "generated": {
                        "policy": "random",
                        "length": 20,
                        "encoding": "raw_text",
                        "scope": {
                            "level": "tenant",
                            "team": "_"
                        },
                        "regenerate_if_present": false
                    }
                }
            ]),
        );

        let setup = SecretsSetup::new(dir.path(), "dev", "demo", Some("default")).expect("setup");
        let alias_uri = canonical_secret_uri(
            "dev",
            "demo",
            None,
            "messaging-webchat-gui",
            "legacy_jwt_key",
        );
        setup
            .store
            .put(&alias_uri, SecretFormat::Text, b"existing-alias-secret")
            .await
            .expect("seed alias");

        setup
            .ensure_pack_secrets(&pack, "messaging-webchat-gui")
            .await
            .expect("ensure secrets");

        let alias_value = setup.store.get(&alias_uri).await.expect("alias");
        assert_eq!(alias_value, b"existing-alias-secret".to_vec());
        let canonical_uri = canonical_secret_uri(
            "dev",
            "demo",
            None,
            "messaging-webchat-gui",
            "jwt_signing_key",
        );
        assert!(matches!(
            setup.store.get(&canonical_uri).await,
            Err(SecretError::NotFound { .. })
        ));
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
