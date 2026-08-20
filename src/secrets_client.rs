use crate::dev_store_path;
use anyhow::{Result as AnyhowResult, anyhow};
use async_trait::async_trait;
use greentic_secrets_lib::{
    Result as SecretResult, SecretError, SecretFormat, SecretsManager, SecretsStore,
    core::{Error as CoreError, seed::DevStore},
};
use std::path::{Path, PathBuf};

use crate::secret_name;

pub struct SecretsClient {
    store_path: PathBuf,
}

impl SecretsClient {
    pub fn open(bundle_root: &Path) -> AnyhowResult<Self> {
        let override_path = dev_store_path::override_path();
        if let Some(path) =
            dev_store_path::find_existing_with_override(bundle_root, override_path.as_deref())
        {
            return Self::open_with_path(path);
        }
        let store_path = dev_store_path::ensure_path(bundle_root)?;
        Self::open_with_path(store_path)
    }

    pub fn open_with_path(path: PathBuf) -> AnyhowResult<Self> {
        DevStore::with_path(path.clone())
            .map_err(|err| anyhow!("failed to open dev secrets store: {err}"))?;
        Ok(Self { store_path: path })
    }

    pub fn store_path(&self) -> Option<&Path> {
        Some(self.store_path.as_path())
    }
}

#[async_trait]
impl SecretsManager for SecretsClient {
    async fn read(&self, path: &str) -> SecretResult<Vec<u8>> {
        // Re-open the persisted dev store on each read so runtime setup changes
        // become visible without restarting the operator process.
        let store = DevStore::with_path(self.store_path.clone())
            .map_err(|err| SecretError::Backend(err.to_string().into()))?;
        let canonical_path = canonicalize_dev_store_secret_uri(path);
        let result = store.get(canonical_path.as_deref().unwrap_or(path)).await;
        match result {
            Ok(value) => Ok(value),
            Err(CoreError::NotFound { entity }) => Err(SecretError::NotFound(entity)),
            Err(err) => Err(SecretError::Backend(err.to_string().into())),
        }
    }

    async fn write(&self, path: &str, bytes: &[u8]) -> SecretResult<()> {
        let store = DevStore::with_path(self.store_path.clone())
            .map_err(|err| SecretError::Backend(err.to_string().into()))?;
        let canonical_path = canonicalize_dev_store_secret_uri(path);
        store
            .put(
                canonical_path.as_deref().unwrap_or(path),
                SecretFormat::Bytes,
                bytes,
            )
            .await
            .map_err(|err| SecretError::Backend(err.to_string().into()))
    }

    async fn delete(&self, _: &str) -> SecretResult<()> {
        Err(SecretError::Permission(
            "dev secrets store is read-only".into(),
        ))
    }
}

/// Provider segment whose key is stored verbatim — see
/// `canonicalize_dev_store_secret_uri`.
const MCP_CATEGORY: &str = "mcp";

fn canonicalize_dev_store_secret_uri(path: &str) -> Option<String> {
    let trimmed = path.strip_prefix("secrets://")?;
    let mut segments = trimmed.split('/').collect::<Vec<_>>();
    if segments.len() != 5 {
        return None;
    }
    // The `mcp` category is exempt. greentic-designer-admin keys an MCP
    // server's credential by its hyphenated UUID and writes it VERBATIM, and
    // greentic-runner reads it verbatim through
    // `greentic_aw_runtime::mcp_secrets`. Canonicalizing here (lowercase, and
    // `-` to `_`) rewrote the lookup to `…/mcp/ff308b9c_951a_…` and resolved
    // nothing — silently, because an unresolved credential surfaces only as an
    // ordinary MCP node error. Every other category keeps normalizing.
    if segments[3] == MCP_CATEGORY {
        return None;
    }

    let canonical_key = secret_name::canonical_secret_key_path(segments[4]);
    if canonical_key == segments[4] {
        return None;
    }
    segments[4] = &canonical_key;
    Some(format!("secrets://{}", segments.join("/")))
}

#[cfg(test)]
mod mcp_uri_tests {
    use super::canonicalize_dev_store_secret_uri;

    /// The `mcp` category is keyed by a hyphenated server UUID that
    /// greentic-designer-admin writes VERBATIM, and greentic-runner reads
    /// verbatim via `greentic_aw_runtime::mcp_secrets`. Canonicalizing it here
    /// rewrote the lookup to `ff308b9c_951a_…` and resolved nothing — silently,
    /// because a missing credential is reported as an ordinary MCP node error.
    #[test]
    fn an_mcp_uri_is_never_canonicalized() {
        let uri = "secrets://default/acme/_/mcp/ff308b9c-951a-40b8-acea-f62cdd19c8f3";
        assert_eq!(
            canonicalize_dev_store_secret_uri(uri),
            None,
            "an mcp key must reach the store byte-for-byte"
        );
    }

    /// Every other category keeps the existing behaviour.
    #[test]
    fn a_non_mcp_uri_still_canonicalizes() {
        let uri = "secrets://local/acme/_/messaging-telegram/BOT-TOKEN";
        assert_eq!(
            canonicalize_dev_store_secret_uri(uri).as_deref(),
            Some("secrets://local/acme/_/messaging-telegram/bot_token"),
            "non-mcp keys must still be normalized"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_lib::{
        SecretFormat, SeedDoc, SeedEntry, SeedValue,
        core::seed::{ApplyOptions, DevStore, apply_seed},
    };
    use tempfile::tempdir;
    use tokio::runtime::Runtime;

    #[test]
    fn reads_seeded_secret_from_dev_store() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let store_path = dir.path().join("secrets.env");
        let store = DevStore::with_path(store_path.clone())?;
        let seed = SeedDoc {
            entries: vec![SeedEntry {
                uri: "secrets://demo/acme/_/mypack/my_secret".to_string(),
                format: SecretFormat::Text,
                value: SeedValue::Text {
                    text: "hello world".to_string(),
                },
                description: None,
            }],
        };
        let runtime = Runtime::new()?;
        let report =
            runtime.block_on(async { apply_seed(&store, &seed, ApplyOptions::default()).await });
        assert_eq!(report.ok, 1);
        let client = SecretsClient::open_with_path(store_path.clone())?;
        let value = runtime
            .block_on(async { client.read("secrets://demo/acme/_/mypack/my_secret").await })?;
        assert_eq!(value, b"hello world".to_vec());
        Ok(())
    }

    #[test]
    fn reads_secrets_written_after_client_startup() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let store_path = dir.path().join("secrets.env");
        let store = DevStore::with_path(store_path.clone())?;
        let client = SecretsClient::open_with_path(store_path.clone())?;
        let runtime = Runtime::new()?;

        let seed = SeedDoc {
            entries: vec![SeedEntry {
                uri: "secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key".to_string(),
                format: SecretFormat::Text,
                value: SeedValue::Text {
                    text: "after-startup".to_string(),
                },
                description: None,
            }],
        };
        let report =
            runtime.block_on(async { apply_seed(&store, &seed, ApplyOptions::default()).await });
        assert_eq!(report.ok, 1);

        let value = runtime.block_on(async {
            client
                .read("secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key")
                .await
        })?;
        assert_eq!(value, b"after-startup".to_vec());
        Ok(())
    }

    #[test]
    fn writes_secret_to_dev_store() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let store_path = dir.path().join("secrets.env");
        let client = SecretsClient::open_with_path(store_path.clone())?;
        let runtime = Runtime::new()?;
        let uri = "secrets://dev/demo/default/messaging-slack/SLACK_CONFIGURATION_ACCESS_TOKEN";

        runtime.block_on(async { client.write(uri, b"xoxe-access").await })?;

        let store = DevStore::with_path(store_path)?;
        let canonical_uri =
            "secrets://dev/demo/default/messaging-slack/slack_configuration_access_token";
        let value = runtime.block_on(async { store.get(canonical_uri).await })?;
        assert_eq!(value, b"xoxe-access".to_vec());
        let value = runtime.block_on(async { client.read(uri).await })?;
        assert_eq!(value, b"xoxe-access".to_vec());
        Ok(())
    }
}
