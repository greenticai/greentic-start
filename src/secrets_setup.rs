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
use serde_yaml_bw;
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
    SeedEntry {
        uri: uri.clone(),
        format: SecretFormat::Text,
        value: SeedValue::Text {
            text: format!("placeholder for {uri}"),
        },
        description: Some("auto-applied placeholder".to_string()),
    }
}
