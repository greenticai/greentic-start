//! Auto-update webhooks and secrets when public URL changes at startup.
//!
//! When the tunnel URL changes (e.g., cloudflared/ngrok restart), this module
//! detects the change and:
//! 1. Updates the `public_base_url` secret for all messaging providers
//! 2. Re-registers webhooks for providers that support it (Telegram, Slack, Webex)

use std::path::Path;

use anyhow::Result;
use greentic_secrets_lib::{DevStore, SecretFormat, SecretsStore};
use serde_json::Value;
use tokio::runtime::Builder as TokioBuilder;

use crate::discovery::{DetectedProvider, DiscoveryResult};
use crate::operator_log;
use crate::secret_requirements::load_secret_keys_from_pack;
use crate::secrets_gate::{SecretsManagerHandle, canonical_secret_uri};
use crate::secrets_setup::resolve_env;

/// Read previous public URL from startup contract if it exists.
pub fn read_previous_public_url(runtime_root: &Path) -> Option<String> {
    let contract_path = runtime_root.join("startup_contract.json");
    if !contract_path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(&contract_path).ok()?;
    let contract: Value = serde_json::from_str(&content).ok()?;
    contract
        .get("public_base_url")
        .and_then(Value::as_str)
        .map(String::from)
}

/// Summary of a webhook update operation.
#[derive(Debug, Default)]
pub struct WebhookUpdateSummary {
    /// Per-provider results: (provider_id, webhook_count or description).
    pub results: Vec<(String, String)>,
}

impl WebhookUpdateSummary {}

/// Check if public URL changed and update webhooks for messaging providers.
///
/// This function compares the previous URL with the new tunnel URL and
/// re-registers webhooks for all messaging providers if the URL changed.
///
/// # Arguments
///
/// * `config_dir` - Bundle root directory
/// * `discovery` - Discovery result containing detected providers
/// * `secrets_handle` - Handle to the secrets manager
/// * `tenant` - Tenant ID
/// * `team` - Team ID
/// * `previous_url` - Previous public URL (from startup_contract.json)
/// * `new_url` - New public URL from tunnel
///
/// # Returns
///
/// Returns a `WebhookUpdateSummary` with per-provider results.
pub fn update_webhooks_if_url_changed(
    config_dir: &Path,
    discovery: &DiscoveryResult,
    secrets_handle: &SecretsManagerHandle,
    tenant: &str,
    team: &str,
    previous_url: Option<&str>,
    new_url: &str,
) -> Result<WebhookUpdateSummary> {
    // Only HTTPS URLs are valid for webhooks
    if !new_url.starts_with("https://") {
        operator_log::debug(
            module_path!(),
            format!(
                "[webhook-updater] skipping webhook update: URL is not HTTPS ({})",
                new_url
            ),
        );
        return Ok(WebhookUpdateSummary::default());
    }

    // Check if URL actually changed
    if previous_url == Some(new_url) {
        operator_log::debug(
            module_path!(),
            "[webhook-updater] public URL unchanged, skipping webhook update",
        );
        return Ok(WebhookUpdateSummary::default());
    }

    operator_log::info(
        module_path!(),
        format!(
            "[webhook-updater] public URL changed: {:?} → {}",
            previous_url, new_url
        ),
    );

    // Filter messaging providers only
    let messaging_providers: Vec<&DetectedProvider> = discovery
        .providers
        .iter()
        .filter(|p| p.domain == "messaging")
        .collect();

    if messaging_providers.is_empty() {
        operator_log::debug(
            module_path!(),
            "[webhook-updater] no messaging providers found, skipping webhook update",
        );
        return Ok(WebhookUpdateSummary::default());
    }

    let mut summary = WebhookUpdateSummary::default();

    for provider in &messaging_providers {
        let mut provider_webhook_count: u32 = 0;

        // Step 1: Update public_base_url secret for this provider
        match update_provider_public_url_secret(
            secrets_handle,
            tenant,
            team,
            &provider.provider_id,
            new_url,
        ) {
            Ok(true) => {
                operator_log::info(
                    module_path!(),
                    format!(
                        "[webhook-updater] public_base_url secret updated for {}",
                        provider.provider_id
                    ),
                );
            }
            Ok(false) => {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "[webhook-updater] public_base_url secret unchanged for {}",
                        provider.provider_id
                    ),
                );
            }
            Err(err) => {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "[webhook-updater] failed to update public_base_url secret for {}: {}",
                        provider.provider_id, err
                    ),
                );
            }
        }

        // Step 2: Update webhook for this provider (if supported)
        match update_provider_webhook(
            config_dir,
            secrets_handle,
            tenant,
            team,
            &provider.provider_id,
            &provider.pack_path,
            new_url,
        ) {
            Ok(true) => {
                provider_webhook_count += 1;
                operator_log::info(
                    module_path!(),
                    format!(
                        "[webhook-updater] webhook updated for {}",
                        provider.provider_id
                    ),
                );
            }
            Ok(false) => {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "[webhook-updater] webhook not applicable for {}",
                        provider.provider_id
                    ),
                );
            }
            Err(err) => {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "[webhook-updater] failed to update webhook for {}: {}",
                        provider.provider_id, err
                    ),
                );
            }
        }

        if provider_webhook_count > 0 {
            let desc = if provider_webhook_count == 1 {
                "webhook updated".to_string()
            } else {
                format!("{provider_webhook_count} webhooks updated")
            };
            summary.results.push((provider.provider_id.clone(), desc));
        }
    }

    Ok(summary)
}

/// Update the public_base_url secret for a single provider.
///
/// Returns Ok(true) if secret was updated, Ok(false) if unchanged or not applicable.
fn update_provider_public_url_secret(
    secrets_handle: &SecretsManagerHandle,
    tenant: &str,
    team: &str,
    provider_id: &str,
    new_url: &str,
) -> Result<bool> {
    let env = resolve_env(None);
    let uri = canonical_secret_uri(&env, tenant, Some(team), provider_id, "public_base_url");

    let rt = TokioBuilder::new_current_thread().enable_all().build()?;

    // Check if current value is different
    let current_value = read_secret_bytes(&rt, secrets_handle, &uri).ok();
    let current_url = current_value
        .as_ref()
        .and_then(|v| String::from_utf8(v.clone()).ok());

    if current_url.as_deref() == Some(new_url) {
        // Already up to date
        return Ok(false);
    }

    // `SecretsClient` is intentionally read-only, so use the writable dev store when present.
    if let Some(path) = secrets_handle.dev_store_path.as_ref() {
        let store = DevStore::with_path(path.clone())?;
        rt.block_on(store.put(&uri, SecretFormat::Text, new_url.as_bytes()))
            .map_err(|e| anyhow::anyhow!("failed to write secret: {:?}", e))?;
    } else {
        rt.block_on(secrets_handle.manager().write(&uri, new_url.as_bytes()))
            .map_err(|e| anyhow::anyhow!("failed to write secret: {:?}", e))?;
    }

    Ok(true)
}

fn read_secret_bytes(
    rt: &tokio::runtime::Runtime,
    secrets_handle: &SecretsManagerHandle,
    uri: &str,
) -> Result<Vec<u8>> {
    if let Some(path) = secrets_handle.dev_store_path.as_ref() {
        let store = DevStore::with_path(path.clone())?;
        return rt
            .block_on(store.get(uri))
            .map_err(|e| anyhow::anyhow!("failed to read secret: {:?}", e));
    }
    rt.block_on(secrets_handle.manager().read(uri))
        .map_err(|e| anyhow::anyhow!("failed to read secret: {:?}", e))
}

/// Update webhook for a single provider.
///
/// Returns Ok(true) if webhook was updated, Ok(false) if not applicable.
fn update_provider_webhook(
    config_dir: &Path,
    secrets_handle: &SecretsManagerHandle,
    tenant: &str,
    team: &str,
    provider_id: &str,
    pack_path: &Path,
    new_url: &str,
) -> Result<bool> {
    // Build config with secrets + new public_base_url
    let config = build_provider_config(
        config_dir,
        secrets_handle,
        tenant,
        team,
        provider_id,
        pack_path,
        new_url,
    )?;

    // Call webhook registration
    let result =
        greentic_setup::webhook::register_webhook(provider_id, &config, tenant, Some(team));

    match result {
        Some(result_value) => {
            let ok = result_value
                .get("ok")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if ok {
                Ok(true)
            } else {
                let err = result_value
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error");
                operator_log::warn(
                    module_path!(),
                    format!(
                        "[webhook-updater] webhook registration failed for {}: {}",
                        provider_id, err
                    ),
                );
                Ok(false)
            }
        }
        None => {
            // Provider doesn't support webhook registration (not Telegram/Slack/Webex)
            // or missing required config
            Ok(false)
        }
    }
}

/// Build provider config by reading secrets and merging with public_base_url.
fn build_provider_config(
    _config_dir: &Path,
    secrets_handle: &SecretsManagerHandle,
    tenant: &str,
    team: &str,
    provider_id: &str,
    pack_path: &Path,
    new_url: &str,
) -> Result<Value> {
    let mut config = serde_json::Map::new();

    // Add new public_base_url
    config.insert(
        "public_base_url".to_string(),
        Value::String(new_url.to_string()),
    );

    // Load secret keys from pack manifest
    let secret_keys = load_secret_keys_from_pack(pack_path).unwrap_or_default();

    if secret_keys.is_empty() {
        return Ok(Value::Object(config));
    }

    // Read secrets and add to config
    let env = resolve_env(None);
    let rt = TokioBuilder::new_current_thread().enable_all().build()?;

    for key in &secret_keys {
        let uri = canonical_secret_uri(&env, tenant, Some(team), provider_id, key);

        match read_secret_bytes(&rt, secrets_handle, &uri) {
            Ok(bytes) => {
                // Try to decode as UTF-8 string first
                if let Ok(value_str) = String::from_utf8(bytes.clone()) {
                    config.insert(key.clone(), Value::String(value_str));
                } else {
                    // Fall back to base64 encoding for binary data
                    use base64::Engine;
                    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
                    config.insert(format!("{}_b64", key), Value::String(encoded));
                }
            }
            Err(err) => {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "[webhook-updater] secret {} not found for {}: {}",
                        key, provider_id, err
                    ),
                );
            }
        }
    }

    Ok(Value::Object(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{DetectedDomains, DiscoveryResult};
    use crate::secrets_gate;
    use crate::secrets_setup::resolve_env;
    use serde_json::json;
    use std::io::Write;
    use tempfile::TempDir;
    use tokio::runtime::Runtime;

    #[test]
    fn read_previous_public_url_missing_file() {
        let tmp = TempDir::new().unwrap();
        let result = read_previous_public_url(tmp.path());
        assert!(result.is_none());
    }

    #[test]
    fn read_previous_public_url_valid() {
        let tmp = TempDir::new().unwrap();
        let contract = json!({
            "public_base_url": "https://example.trycloudflare.com"
        });
        std::fs::write(
            tmp.path().join("startup_contract.json"),
            serde_json::to_string(&contract).unwrap(),
        )
        .unwrap();

        let result = read_previous_public_url(tmp.path());
        assert_eq!(
            result,
            Some("https://example.trycloudflare.com".to_string())
        );
    }

    #[test]
    fn read_previous_public_url_no_url_field() {
        let tmp = TempDir::new().unwrap();
        let contract = json!({
            "http_listener_enabled": true
        });
        std::fs::write(
            tmp.path().join("startup_contract.json"),
            serde_json::to_string(&contract).unwrap(),
        )
        .unwrap();

        let result = read_previous_public_url(tmp.path());
        assert!(result.is_none());
    }

    #[test]
    fn update_webhooks_if_url_changed_skips_non_https_unchanged_and_non_messaging_discovery() {
        let tmp = TempDir::new().unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(tmp.path(), "demo", Some("default"))
                .expect("secrets");

        let empty = DiscoveryResult {
            domains: DetectedDomains {
                messaging: false,
                events: false,
                oauth: false,
            },
            providers: Vec::new(),
        };
        let skipped = update_webhooks_if_url_changed(
            tmp.path(),
            &empty,
            &secrets_handle,
            "demo",
            "default",
            None,
            "http://example.com",
        )
        .expect("non-https skip");
        assert!(skipped.results.is_empty());

        let unchanged = update_webhooks_if_url_changed(
            tmp.path(),
            &empty,
            &secrets_handle,
            "demo",
            "default",
            Some("https://example.com"),
            "https://example.com",
        )
        .expect("unchanged skip");
        assert!(unchanged.results.is_empty());
    }

    #[test]
    fn build_provider_config_returns_public_url_when_pack_has_no_secret_requirements() {
        let tmp = TempDir::new().unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(tmp.path(), "demo", Some("default"))
                .expect("secrets");
        let pack_path = tmp.path().join("provider.gtpack");
        let file = std::fs::File::create(&pack_path).expect("pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", zip::write::FileOptions::<()>::default())
            .expect("manifest");
        zip.write_all(b"a0").expect("empty cbor map");
        zip.finish().expect("finish pack");

        let config = build_provider_config(
            tmp.path(),
            &secrets_handle,
            "demo",
            "default",
            "provider-a",
            &pack_path,
            "https://demo.example",
        )
        .expect("provider config");
        assert_eq!(config["public_base_url"], "https://demo.example");
        assert_eq!(config.as_object().map(|m| m.len()), Some(1));
    }

    #[test]
    fn update_provider_public_url_secret_writes_then_detects_unchanged_value() {
        let tmp = TempDir::new().unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(tmp.path(), "demo", Some("default")).unwrap();
        let env = resolve_env(None);
        let uri = secrets_gate::canonical_secret_uri(
            &env,
            "demo",
            Some("default"),
            "messaging-slack",
            "public_base_url",
        );

        assert!(
            update_provider_public_url_secret(
                &secrets_handle,
                "demo",
                "default",
                "messaging-slack",
                "https://demo.example",
            )
            .unwrap()
        );
        assert!(
            !update_provider_public_url_secret(
                &secrets_handle,
                "demo",
                "default",
                "messaging-slack",
                "https://demo.example",
            )
            .unwrap()
        );

        let runtime = Runtime::new().unwrap();
        let store = DevStore::with_path(secrets_handle.dev_store_path.clone().unwrap()).unwrap();
        let stored = runtime.block_on(store.get(&uri)).expect("stored secret");
        assert_eq!(String::from_utf8(stored).unwrap(), "https://demo.example");
    }

    #[test]
    fn build_provider_config_reads_text_and_binary_secret_values() {
        let tmp = TempDir::new().unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(tmp.path(), "demo", Some("default")).unwrap();
        let env = resolve_env(None);
        let runtime = Runtime::new().unwrap();

        let token_uri = secrets_gate::canonical_secret_uri(
            &env,
            "demo",
            Some("default"),
            "messaging-slack",
            "bot_token",
        );
        let store = DevStore::with_path(secrets_handle.dev_store_path.clone().unwrap()).unwrap();
        runtime
            .block_on(store.put(&token_uri, SecretFormat::Text, b"xoxb-123"))
            .unwrap();

        let cert_uri = secrets_gate::canonical_secret_uri(
            &env,
            "demo",
            Some("default"),
            "messaging-slack",
            "cert",
        );
        runtime
            .block_on(store.put(&cert_uri, SecretFormat::Bytes, &[0, 159, 146, 150]))
            .unwrap();

        let pack_path = tmp.path().join("provider.gtpack");
        let file = std::fs::File::create(&pack_path).expect("pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "assets/secret-requirements.json",
            zip::write::FileOptions::<()>::default(),
        )
        .expect("requirements");
        zip.write_all(
            serde_json::to_string(&json!([
                {"key": "bot_token", "required": true},
                {"key": "cert", "required": true}
            ]))
            .unwrap()
            .as_bytes(),
        )
        .expect("write requirements");
        zip.finish().expect("finish pack");

        let config = build_provider_config(
            tmp.path(),
            &secrets_handle,
            "demo",
            "default",
            "messaging-slack",
            &pack_path,
            "https://demo.example",
        )
        .unwrap();

        assert_eq!(config["public_base_url"], "https://demo.example");
        assert_eq!(config["bot_token"], "xoxb-123");
        assert_eq!(config["cert_b64"], "AJ+Slg==");
    }
}
