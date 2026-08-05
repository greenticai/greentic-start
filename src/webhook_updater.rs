//! Auto-update webhooks and secrets when public URL changes at startup.
//!
//! When the tunnel URL changes (e.g., cloudflared/ngrok restart), this module
//! detects the change and:
//! 1. Updates the `public_base_url` secret for all messaging providers
//! 2. Re-registers webhooks for providers that declare webhook ops

use std::path::Path;
use std::{future::Future, thread};

use anyhow::{Context, Result};
use greentic_secrets_lib::{DevStore, SecretFormat, SecretsStore};
use serde_json::{Map, Value};

use crate::discovery::{DetectedProvider, DiscoveryResult};
use crate::domains::Domain;
use crate::operator_log;
use crate::runner_host::{DemoRunnerHost, OperatorContext};
use crate::secret_name;
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
#[allow(clippy::too_many_arguments)]
pub fn update_webhooks_if_url_changed(
    config_dir: &Path,
    discovery: &DiscoveryResult,
    secrets_handle: &SecretsManagerHandle,
    runner_host: Option<&DemoRunnerHost>,
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

    // Log whether the URL changed (secrets are always refreshed so
    // webhooks are re-registered on every start, ensuring the console
    // always shows webhook status).
    if previous_url == Some(new_url) {
        operator_log::info(
            module_path!(),
            format!(
                "[webhook-updater] public URL unchanged ({}), re-registering webhooks",
                new_url
            ),
        );
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
    operator_log::info(
        module_path!(),
        format!(
            "[webhook-updater] messaging providers discovered count={} providers={}",
            messaging_providers.len(),
            messaging_providers
                .iter()
                .map(|provider| provider.provider_id.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
    );

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
        operator_log::info(
            module_path!(),
            format!(
                "[webhook-updater] provider={} webhook check started",
                provider.provider_id
            ),
        );

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
            runner_host,
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
                operator_log::info(
                    module_path!(),
                    format!(
                        "[webhook-updater] webhook skipped for {}",
                        provider.provider_id
                    ),
                );
                summary
                    .results
                    .push((provider.provider_id.clone(), "skipped".to_string()));
            }
            Err(err) => {
                let msg = format!("{err}");
                operator_log::warn(
                    module_path!(),
                    format!(
                        "[webhook-updater] failed to update webhook for {}: {}",
                        provider.provider_id, msg
                    ),
                );
                summary
                    .results
                    .push((provider.provider_id.clone(), format!("Error: {msg}")));
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
    // Written exclusively at the canonical address, matching every other
    // writer in this codebase (greentic-setup included). Checked for
    // staleness via the full candidate chain — no bundle root is in scope
    // here, so that chain is the legacy raw/canonical pair — so a value a
    // prior release left under the raw form is still recognized as current.
    let uri = canonical_secret_uri(&env, tenant, Some(team), provider_id, "public_base_url");
    let read_candidates = crate::secret_resolve::secret_candidates(
        None,
        &env,
        tenant,
        Some(team),
        provider_id,
        "public_base_url",
    );

    // Check if current value is different
    let current_url = read_candidates.iter().find_map(|candidate| {
        read_secret_bytes(secrets_handle, candidate)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    });

    if current_url.as_deref() == Some(new_url) {
        // Already up to date
        return Ok(false);
    }

    // `SecretsClient` is intentionally read-only, so use the writable dev store when present.
    if let Some(path) = secrets_handle.dev_store_path.as_ref() {
        let store = DevStore::with_path(path.clone())?;
        let uri = uri.clone();
        let bytes = new_url.as_bytes().to_vec();
        block_on_temp_runtime(async move { store.put(&uri, SecretFormat::Text, &bytes).await })
            .map_err(|e| anyhow::anyhow!("failed to write secret: {:?}", e))?;
    } else {
        let manager = secrets_handle.manager();
        let uri = uri.clone();
        let bytes = new_url.as_bytes().to_vec();
        block_on_temp_runtime(async move { manager.write(&uri, &bytes).await })
            .map_err(|e| anyhow::anyhow!("failed to write secret: {:?}", e))?;
    }

    Ok(true)
}

fn read_secret_bytes(secrets_handle: &SecretsManagerHandle, uri: &str) -> Result<Vec<u8>> {
    if let Some(path) = secrets_handle.dev_store_path.as_ref() {
        let store = DevStore::with_path(path.clone())?;
        let uri = uri.to_string();
        return block_on_temp_runtime(async move { store.get(&uri).await })
            .map_err(|e| anyhow::anyhow!("failed to read secret: {:?}", e));
    }
    let manager = secrets_handle.manager();
    let uri = uri.to_string();
    block_on_temp_runtime(async move { manager.read(&uri).await })
        .map_err(|e| anyhow::anyhow!("failed to read secret: {:?}", e))
}

fn block_on_temp_runtime<F, T>(future: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let run = move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build temporary tokio runtime")
            .block_on(future)
    };
    if tokio::runtime::Handle::try_current().is_ok() {
        thread::spawn(run)
            .join()
            .expect("temporary tokio runtime thread panicked")
    } else {
        run()
    }
}

/// Update webhook for a single provider.
///
/// Returns Ok(true) if webhook was updated, Ok(false) if not applicable.
#[allow(clippy::too_many_arguments)]
fn update_provider_webhook(
    config_dir: &Path,
    secrets_handle: &SecretsManagerHandle,
    runner_host: Option<&DemoRunnerHost>,
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

    // Try declared ops from config first
    if let Some(result_value) =
        greentic_setup::webhook::register_webhook(provider_id, &config, tenant, Some(team))
    {
        let ok = result_value
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if ok {
            return Ok(true);
        }
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
        return Ok(false);
    }

    // Fallback: invoke provider WASM setup_webhook op directly
    let Some(host) = runner_host else {
        operator_log::info(
            module_path!(),
            format!(
                "[webhook-updater] provider={provider_id} webhook skipped reason=runner_host_unavailable"
            ),
        );
        return Ok(false);
    };
    if !host.supports_op(Domain::Messaging, provider_id, "setup_webhook") {
        operator_log::info(
            module_path!(),
            format!(
                "[webhook-updater] provider={provider_id} webhook skipped reason=no_setup_webhook_op"
            ),
        );
        return Ok(false);
    }
    let ctx = OperatorContext {
        tenant: tenant.to_string(),
        team: Some(team.to_string()),
        correlation_id: None,
    };
    let payload = serde_json::to_vec(&config)?;
    match host.invoke_provider_op(
        Domain::Messaging,
        provider_id,
        "setup_webhook",
        &payload,
        &ctx,
    ) {
        Ok(outcome) if outcome.success => {
            // WASM invocation succeeded — but also check the output payload
            // for {"ok": false} which indicates the op ran but failed logically.
            let output_ok = outcome
                .output
                .as_ref()
                .and_then(|v| v.get("ok"))
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if output_ok {
                operator_log::info(
                    module_path!(),
                    format!(
                        "[webhook-updater] WASM setup_webhook succeeded for {}",
                        provider_id
                    ),
                );
                Ok(true)
            } else {
                let err_msg = outcome
                    .output
                    .as_ref()
                    .and_then(|v| v.get("error"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                operator_log::warn(
                    module_path!(),
                    format!(
                        "[webhook-updater] WASM setup_webhook returned error for {}: {}",
                        provider_id, err_msg
                    ),
                );
                Err(anyhow::anyhow!("{err_msg}"))
            }
        }
        Ok(outcome) => {
            let err_msg = outcome.error.as_deref().unwrap_or("unknown").to_string();
            operator_log::warn(
                module_path!(),
                format!(
                    "[webhook-updater] WASM setup_webhook failed for {}: {}",
                    provider_id, err_msg
                ),
            );
            Err(anyhow::anyhow!("{err_msg}"))
        }
        Err(err) => {
            operator_log::debug(
                module_path!(),
                format!(
                    "[webhook-updater] WASM setup_webhook not available for {}: {err:#}",
                    provider_id
                ),
            );
            Ok(false)
        }
    }
}

/// Build provider config by reading secrets and merging with public_base_url.
pub(crate) fn build_provider_config(
    config_dir: &Path,
    secrets_handle: &SecretsManagerHandle,
    tenant: &str,
    team: &str,
    provider_id: &str,
    pack_path: &Path,
    new_url: &str,
) -> Result<Value> {
    let mut config = Map::new();

    merge_provider_setup_answers(config_dir, provider_id, tenant, team, &mut config)?;

    // Add new public_base_url and tenant/team so provider can build
    // the correct webhook URL (e.g. /v1/messaging/ingress/{provider}/{tenant}/{team})
    config.insert(
        "public_base_url".to_string(),
        Value::String(new_url.to_string()),
    );
    config.insert("tenant".to_string(), Value::String(tenant.to_string()));
    config.insert("team".to_string(), Value::String(team.to_string()));
    config.insert(
        "provider_id".to_string(),
        Value::String(provider_id.to_string()),
    );

    // Load secret keys from pack manifest
    let secret_keys = load_secret_keys_from_pack(pack_path).unwrap_or_default();

    if secret_keys.is_empty() {
        return Ok(Value::Object(config));
    }

    remove_declared_secret_values_from_setup_answers(&mut config, &secret_keys);

    // Read secrets and add to config
    let env = resolve_env(None);

    for key in &secret_keys {
        // `config_dir` is the bundle root, so a ref the bundle recorded in its
        // own answers file is honored alone; absent that, the legacy
        // raw/canonical pair is tried in order.
        let candidates = crate::secret_resolve::secret_candidates(
            Some(config_dir),
            &env,
            tenant,
            Some(team),
            provider_id,
            key,
        );
        let mut last_err = None;
        let read_result = candidates
            .iter()
            .find_map(
                |candidate| match read_secret_bytes(secrets_handle, candidate) {
                    Ok(bytes) => Some(bytes),
                    Err(err) => {
                        last_err = Some(err);
                        None
                    }
                },
            )
            .ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("secret not found")));

        match read_result {
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

fn remove_declared_secret_values_from_setup_answers(
    config: &mut Map<String, Value>,
    keys: &[String],
) {
    for key in keys {
        let canonical = secret_name::canonical_secret_name(key);
        config.remove(key);
        config.remove(&canonical);
        config.remove(&key.to_lowercase());
        config.remove(&key.to_uppercase());
    }
}

fn merge_provider_setup_answers(
    config_dir: &Path,
    provider_id: &str,
    tenant: &str,
    team: &str,
    config: &mut Map<String, Value>,
) -> Result<()> {
    let setup_answers_path =
        crate::provider_answers::answers_path_for_read(config_dir, provider_id, tenant, team);

    if !setup_answers_path.exists() {
        return Ok(());
    }

    let contents = std::fs::read_to_string(&setup_answers_path)
        .with_context(|| format!("failed to read {}", setup_answers_path.display()))?;
    let value: Value = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse {}", setup_answers_path.display()))?;
    let Some(answers) = value.as_object() else {
        return Ok(());
    };

    for (key, value) in answers {
        if provider_config_value_is_present(value) {
            config.insert(key.clone(), value.clone());
        }
    }

    Ok(())
}

fn provider_config_value_is_present(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(s) => !s.trim().is_empty(),
        _ => true,
    }
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

    /// Resolve a secrets manager with the dev store pinned under `tmp`.
    ///
    /// Unrelated tests set `$GREENTIC_ENV` without a lock; with the env-store
    /// gating (`selected_env`) that would route these tests' secret resolution to
    /// the shared real env store and cross-contaminate. Pin
    /// `$GREENTIC_DEV_SECRETS_PATH` to a *touched* file under `tmp` so
    /// `find_existing` returns it ahead of any env-store candidate (immune to a
    /// leaked `$GREENTIC_ENV`), serialized via the crate-wide env lock.
    fn isolated_secrets_handle(tmp: &Path) -> SecretsManagerHandle {
        let _guard = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let store = tmp.join(".greentic").join("dev").join(".dev.secrets.env");
        std::fs::create_dir_all(store.parent().expect("store parent")).expect("dev store dir");
        std::fs::File::create(&store).expect("touch dev store");
        let prev = std::env::var_os("GREENTIC_DEV_SECRETS_PATH");
        // SAFETY: serialized by the crate-wide test env lock held above.
        unsafe { std::env::set_var("GREENTIC_DEV_SECRETS_PATH", &store) };
        let handle =
            secrets_gate::resolve_secrets_manager(tmp, "demo", Some("default")).expect("secrets");
        match prev {
            Some(value) => unsafe { std::env::set_var("GREENTIC_DEV_SECRETS_PATH", value) },
            None => unsafe { std::env::remove_var("GREENTIC_DEV_SECRETS_PATH") },
        }
        handle
    }

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
        let secrets_handle = isolated_secrets_handle(tmp.path());

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
            None,
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
            None,
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
        let secrets_handle = isolated_secrets_handle(tmp.path());
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
        assert_eq!(config["tenant"], "demo");
        assert_eq!(config["team"], "default");
        assert_eq!(config["provider_id"], "provider-a");
        assert_eq!(config.as_object().map(|m| m.len()), Some(4));
    }

    #[test]
    fn build_provider_config_merges_setup_answers_and_runtime_fields_win() {
        let tmp = TempDir::new().unwrap();
        let provider_config_dir = tmp
            .path()
            .join("state")
            .join("config")
            .join("messaging-provider");
        std::fs::create_dir_all(&provider_config_dir).expect("provider config dir");
        std::fs::write(
            provider_config_dir.join("setup-answers.json"),
            serde_json::to_vec(&json!({
                "public_base_url": "https://old.example",
                "tenant_id": "tenant-from-setup",
                "client_id": "client-from-setup",
                "refresh_token": "refresh-from-setup",
                "team_id": "team-from-setup",
                "channel_id": "channel-from-setup",
                "subscription_ops": [{"op": "sync_subscriptions"}],
                "empty_value": "",
                "null_value": null
            }))
            .unwrap(),
        )
        .expect("setup answers");

        let secrets_handle = isolated_secrets_handle(tmp.path());
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
            "messaging-provider",
            &pack_path,
            "https://new.example",
        )
        .expect("provider config");

        assert_eq!(config["public_base_url"], "https://new.example");
        assert_eq!(config["tenant"], "demo");
        assert_eq!(config["team"], "default");
        assert_eq!(config["provider_id"], "messaging-provider");
        assert_eq!(config["tenant_id"], "tenant-from-setup");
        assert_eq!(config["client_id"], "client-from-setup");
        assert_eq!(config["refresh_token"], "refresh-from-setup");
        assert_eq!(config["team_id"], "team-from-setup");
        assert_eq!(config["channel_id"], "channel-from-setup");
        assert_eq!(config["subscription_ops"][0]["op"], "sync_subscriptions");
        assert!(config.get("empty_value").is_none());
        assert!(config.get("null_value").is_none());
    }

    #[test]
    fn update_provider_public_url_secret_writes_then_detects_unchanged_value() {
        let tmp = TempDir::new().unwrap();
        let secrets_handle = isolated_secrets_handle(tmp.path());
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
        let secrets_handle = isolated_secrets_handle(tmp.path());
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

    #[test]
    fn build_provider_config_does_not_preserve_stale_setup_secret_values() {
        let tmp = TempDir::new().unwrap();
        let provider_config_dir = tmp
            .path()
            .join("state")
            .join("config")
            .join("messaging-slack");
        std::fs::create_dir_all(&provider_config_dir).expect("provider config dir");
        std::fs::write(
            provider_config_dir.join("setup-answers.json"),
            serde_json::to_vec(&json!({
                "slack_configuration_access_token": "stale-access",
                "SLACK_CONFIGURATION_REFRESH_TOKEN": "stale-refresh",
                "default_channel": "C123"
            }))
            .unwrap(),
        )
        .expect("setup answers");

        let secrets_handle = isolated_secrets_handle(tmp.path());
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
                {"key": "SLACK_CONFIGURATION_ACCESS_TOKEN"},
                {"key": "SLACK_CONFIGURATION_REFRESH_TOKEN"}
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

        assert_eq!(config["default_channel"], "C123");
        assert!(config.get("slack_configuration_access_token").is_none());
        assert!(config.get("SLACK_CONFIGURATION_REFRESH_TOKEN").is_none());
    }

    #[test]
    fn build_provider_config_overlays_current_secret_after_scrubbing_setup_value() {
        let tmp = TempDir::new().unwrap();
        let provider_config_dir = tmp
            .path()
            .join("state")
            .join("config")
            .join("messaging-slack");
        std::fs::create_dir_all(&provider_config_dir).expect("provider config dir");
        std::fs::write(
            provider_config_dir.join("setup-answers.json"),
            serde_json::to_vec(&json!({
                "slack_configuration_access_token": "stale-access"
            }))
            .unwrap(),
        )
        .expect("setup answers");

        let secrets_handle = isolated_secrets_handle(tmp.path());
        let env = resolve_env(None);
        let runtime = Runtime::new().unwrap();
        let token_uri = secrets_gate::canonical_secret_uri(
            &env,
            "demo",
            Some("default"),
            "messaging-slack",
            "SLACK_CONFIGURATION_ACCESS_TOKEN",
        );
        let store = DevStore::with_path(secrets_handle.dev_store_path.clone().unwrap()).unwrap();
        runtime
            .block_on(store.put(&token_uri, SecretFormat::Text, b"fresh-access"))
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
                {"key": "SLACK_CONFIGURATION_ACCESS_TOKEN"}
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

        assert_eq!(config["slack_configuration_access_token"], "fresh-access");
    }
}
