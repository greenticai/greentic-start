use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde_json::Value;

use crate::secrets_backend::{self, SecretsBackendKind};

pub const SCHEMA_VERSION: &str = "greentic.secrets.binding.v1";

const BINDING_PATHS: &[&str] = &[
    "state/config/platform/secrets-provider.json",
    "config/platform/secrets-provider.json",
];

#[derive(Clone, Debug, Deserialize)]
pub struct SecretsProviderBinding {
    pub schema_version: String,
    pub provider_id: String,
    pub pack: Option<String>,
    #[serde(default)]
    pub config: Value,
}

impl SecretsProviderBinding {
    pub fn load_from_bundle(bundle_root: &Path) -> Result<Option<(PathBuf, Self)>> {
        for relative in BINDING_PATHS {
            let path = bundle_root.join(relative);
            if path.is_file() {
                let binding = Self::load(&path)?;
                binding.validate()?;
                return Ok(Some((path, binding)));
            }
        }
        Ok(None)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read secrets provider binding {}", path.display()))?;
        serde_json::from_str(&contents)
            .with_context(|| format!("parse secrets provider binding {}", path.display()))
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(anyhow!(
                "unsupported secrets provider binding schema_version `{}`",
                self.schema_version
            ));
        }
        if self.provider_id.trim().is_empty() {
            return Err(anyhow!("secrets provider binding provider_id is required"));
        }
        Ok(())
    }

    pub fn resolved_pack_path(&self, bundle_root: &Path) -> Option<PathBuf> {
        let pack = self.pack.as_ref()?.trim();
        if pack.is_empty() {
            return None;
        }
        let path = PathBuf::from(pack);
        if path.is_absolute() {
            Some(path)
        } else {
            Some(bundle_root.join(path))
        }
    }

    pub fn backend_kind(&self, bundle_root: &Path) -> Result<Option<SecretsBackendKind>> {
        if let Some(kind) = self.backend_kind_from_config()? {
            return Ok(Some(kind));
        }
        let Some(pack_path) = self.resolved_pack_path(bundle_root) else {
            return Ok(None);
        };
        if !pack_path.exists() {
            return Err(anyhow!(
                "secrets provider binding pack {} not found",
                pack_path.display()
            ));
        }
        Ok(Some(secrets_backend::backend_kind_from_pack(&pack_path)?))
    }

    fn backend_kind_from_config(&self) -> Result<Option<SecretsBackendKind>> {
        let Some(value) = self
            .config
            .get("backend")
            .or_else(|| self.config.get("runtime_backend"))
            .or_else(|| self.config.get("adapter"))
        else {
            return Ok(None);
        };
        let Some(kind) = value.as_str() else {
            return Err(anyhow!(
                "secrets provider binding backend config must be a string"
            ));
        };
        SecretsBackendKind::parse(kind).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn loads_and_validates_binding_from_stable_path() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let binding_dir = dir.path().join("state/config/platform");
        fs::create_dir_all(&binding_dir)?;
        fs::write(
            binding_dir.join("secrets-provider.json"),
            r#"{
              "schema_version": "greentic.secrets.binding.v1",
              "provider_id": "greentic.secrets.custom",
              "pack": "providers/secrets/custom.gtpack",
              "config": {"backend": "env"}
            }"#,
        )?;

        let (path, binding) =
            SecretsProviderBinding::load_from_bundle(dir.path())?.expect("binding");

        assert!(path.ends_with("state/config/platform/secrets-provider.json"));
        assert_eq!(binding.provider_id, "greentic.secrets.custom");
        assert_eq!(
            binding.backend_kind(dir.path())?,
            Some(SecretsBackendKind::Env)
        );
        assert_eq!(
            binding.resolved_pack_path(dir.path()).unwrap(),
            dir.path().join("providers/secrets/custom.gtpack")
        );
        Ok(())
    }

    #[test]
    fn rejects_wrong_schema_version() -> anyhow::Result<()> {
        let binding: SecretsProviderBinding = serde_json::from_str(
            r#"{
              "schema_version": "other",
              "provider_id": "greentic.secrets.custom",
              "config": {}
            }"#,
        )?;

        let err = binding.validate().unwrap_err();

        assert!(err.to_string().contains("schema_version"));
        Ok(())
    }
}
