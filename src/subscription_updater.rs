//! Generic startup reconciliation for provider-declared messaging subscriptions.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{Duration, SecondsFormat, Utc};
use greentic_types::{ExtensionInline, decode_pack_manifest};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zip::ZipArchive;

use crate::discovery::DiscoveryResult;
use crate::domains::{Domain, ProviderPack};
use crate::operator_log;
use crate::runner_host::{DemoRunnerHost, OperatorContext};
use crate::runtime_state::write_json;
use crate::secrets_gate::SecretsManagerHandle;
use crate::webhook_updater::build_provider_config;

const EXT_MESSAGING_SUBSCRIPTIONS_V1: &str = "messaging.subscriptions.v1";

#[derive(Debug, Default, Serialize)]
pub struct SubscriptionUpdateSummary {
    pub results: Vec<(String, String)>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct MessagingSubscriptionsExtension {
    component_ref: String,
    #[serde(rename = "export")]
    export_name: String,
    #[serde(default)]
    renewal_window_hours: Option<i64>,
    #[serde(default)]
    state_template: Option<Value>,
    #[serde(default)]
    desired_state_template: Option<Value>,
    #[serde(default)]
    desired_subscriptions: Option<Value>,
    #[serde(default)]
    component_config: Option<ComponentConfigDeclaration>,
    #[serde(default)]
    desired_state: Option<DesiredStateDeclaration>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
struct ComponentConfigDeclaration {
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    include: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
struct DesiredStateDeclaration {
    #[serde(default)]
    output_key: Option<String>,
    #[serde(default)]
    defaults: Map<String, Value>,
    #[serde(default)]
    notification_url: Option<NotificationUrlDeclaration>,
    #[serde(default)]
    lifecycle_notification_url: Option<NotificationUrlDeclaration>,
    #[serde(default)]
    expiration_policy: Option<ExpirationPolicyDeclaration>,
    #[serde(default)]
    templates: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct NotificationUrlDeclaration {
    template: String,
    #[serde(default)]
    state_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct ExpirationPolicyDeclaration {
    #[serde(default)]
    state_key: Option<String>,
    #[serde(default)]
    host_supplied: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn sync_subscriptions_if_public_url_available(
    config_dir: &Path,
    discovery: &DiscoveryResult,
    secrets_handle: &SecretsManagerHandle,
    runner_host: Option<&DemoRunnerHost>,
    tenant: &str,
    team: &str,
    public_base_url: &str,
) -> Result<SubscriptionUpdateSummary> {
    let mut summary = SubscriptionUpdateSummary::default();
    let public_url_ready = public_base_url.starts_with("https://");
    if !public_url_ready {
        operator_log::debug(
            module_path!(),
            format!(
                "[subscription-updater] skipping subscription sync: URL is not HTTPS ({})",
                public_base_url
            ),
        );
    }

    let messaging_providers = discovery
        .providers
        .iter()
        .filter(|provider| provider.domain == "messaging")
        .collect::<Vec<_>>();
    operator_log::info(
        module_path!(),
        format!(
            "[subscription-updater] messaging providers discovered count={} providers={}",
            messaging_providers.len(),
            messaging_providers
                .iter()
                .map(|provider| provider.provider_id.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
    );
    operator_log::info(
        module_path!(),
        format!(
            "[subscription-updater] subscription extension status {}",
            messaging_providers
                .iter()
                .map(|provider| {
                    let status = match read_subscriptions_extension(&provider.pack_path) {
                        Ok(Some(_)) => "yes".to_string(),
                        Ok(None) => "no".to_string(),
                        Err(err) => format!("error:{err}"),
                    };
                    format!("{}={}", provider.provider_id, status)
                })
                .collect::<Vec<_>>()
                .join(" ")
        ),
    );

    for provider in messaging_providers {
        let extension = match read_subscriptions_extension(&provider.pack_path) {
            Ok(Some(extension)) => extension,
            Ok(None) => {
                let message = "skipped: no subscription extension".to_string();
                operator_log::info(
                    module_path!(),
                    format!(
                        "[subscription-updater] provider={} subscriptions skipped reason=no_subscription_extension",
                        provider.provider_id
                    ),
                );
                summary
                    .results
                    .push((provider.provider_id.clone(), message));
                continue;
            }
            Err(err) => {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "[subscription-updater] failed to read subscription extension for {}: {}",
                        provider.provider_id, err
                    ),
                );
                summary.results.push((
                    provider.provider_id.clone(),
                    format!("Error: failed to read subscription metadata: {err}"),
                ));
                continue;
            }
        };

        if !public_url_ready {
            summary.results.push((
                provider.provider_id.clone(),
                "skipped: public HTTPS URL unavailable".to_string(),
            ));
            continue;
        }
        let Some(host) = runner_host else {
            summary.results.push((
                provider.provider_id.clone(),
                "skipped: runner host unavailable".to_string(),
            ));
            continue;
        };

        let setup_answers = read_provider_setup_answers(config_dir, &provider.provider_id)?;
        let Some(state) = build_subscription_state(
            &extension,
            setup_answers.as_ref(),
            &provider.provider_id,
            tenant,
            team,
            public_base_url,
        ) else {
            let message = "skipped: no desired subscription state".to_string();
            operator_log::info(
                module_path!(),
                format!(
                    "[subscription-updater] {} {}",
                    provider.provider_id, message
                ),
            );
            summary
                .results
                .push((provider.provider_id.clone(), message));
            continue;
        };

        let config = build_provider_config(
            config_dir,
            secrets_handle,
            tenant,
            team,
            &provider.provider_id,
            &provider.pack_path,
            public_base_url,
        )?;
        let config = filter_config_for_subscription_component(
            &extension,
            &provider.pack_path,
            &extension.component_ref,
            config,
        )?;
        let config_keys = object_keys_label(&config);
        let diagnostic = subscription_state_diagnostic(&state);
        let attempt_path = write_subscription_attempt_audit(
            config_dir,
            &provider.provider_id,
            &extension,
            &state,
            &config_keys,
            None,
        )?;
        operator_log::info(
            module_path!(),
            format!(
                "[subscription-updater] provider={} component={} export={} config_keys={} desired={}",
                provider.provider_id,
                extension.component_ref,
                extension.export_name,
                config_keys,
                diagnostic
            ),
        );
        summary.results.push((
            provider.provider_id.clone(),
            format!(
                "loaded: {diagnostic}; config_keys={config_keys}; audit={}",
                attempt_path.display()
            ),
        ));
        let pack = ProviderPack {
            pack_id: provider.provider_id.clone(),
            display_name: None,
            description: None,
            tags: Vec::new(),
            file_name: provider
                .pack_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_string(),
            path: provider.pack_path.clone(),
            entry_flows: Vec::new(),
        };
        let ctx = OperatorContext {
            tenant: tenant.to_string(),
            team: Some(team.to_string()),
            correlation_id: None,
        };
        let mut outcome = host.invoke_pack_component_op_direct(
            Domain::Messaging,
            &pack,
            &extension.component_ref,
            &extension.export_name,
            &config,
            &state,
            &ctx,
        )?;
        if !outcome.success
            && let Some(expected_fields) =
                expected_config_fields_from_invalid_config_error(&outcome)
        {
            let retry_config = filter_config_by_allowed_fields(config.clone(), &expected_fields);
            if retry_config != config {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "[subscription-updater] retrying {} with component-declared config fields: {}",
                        provider.provider_id,
                        expected_fields.join(", ")
                    ),
                );
                outcome = host.invoke_pack_component_op_direct(
                    Domain::Messaging,
                    &pack,
                    &extension.component_ref,
                    &extension.export_name,
                    &retry_config,
                    &state,
                    &ctx,
                )?;
            }
        }

        if outcome.success {
            operator_log::info(
                module_path!(),
                format!(
                    "[subscription-updater] provider={} subscription sync succeeded output_keys={}",
                    provider.provider_id,
                    outcome
                        .output
                        .as_ref()
                        .map(object_keys_label)
                        .unwrap_or_else(|| "-".to_string())
                ),
            );
            let state_path = config_dir
                .join("state")
                .join("subscriptions")
                .join(format!("{}.json", provider.provider_id));
            let persisted = json!({
                "provider_id": provider.provider_id,
                "component_ref": extension.component_ref,
                "export": extension.export_name,
                "state": state,
                "output": outcome.output,
            });
            write_json(&state_path, &persisted)?;
            summary.results.push((
                provider.provider_id.clone(),
                subscription_result_description(&state, setup_answers.as_ref()),
            ));
        } else {
            let error = outcome
                .error
                .or(outcome.raw)
                .unwrap_or_else(|| "unknown subscription sync failure".to_string());
            let attempt_path = write_subscription_attempt_audit(
                config_dir,
                &provider.provider_id,
                &extension,
                &state,
                &config_keys,
                Some(&error),
            )?;
            let detail = format!(
                "{error}; {diagnostic}; config_keys={config_keys}; audit={}",
                attempt_path.display()
            );
            operator_log::warn(
                module_path!(),
                format!(
                    "[subscription-updater] provider={} subscription sync failed {}",
                    provider.provider_id, detail
                ),
            );
            summary
                .results
                .push((provider.provider_id.clone(), format!("Error: {detail}")));
        }
    }

    Ok(summary)
}

fn subscription_result_description(state: &Value, setup_answers: Option<&Value>) -> String {
    let desired = state
        .get("desired_subscriptions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if desired.is_empty() {
        return "synced: no requested subscriptions".to_string();
    }

    let count = desired.len();
    let mut parts = desired
        .iter()
        .take(3)
        .map(subscription_target_label)
        .collect::<Vec<_>>();
    if desired.len() > parts.len() {
        parts.push(format!("+{} more", desired.len() - parts.len()));
    }

    let setup_label = setup_answer_display_label(setup_answers)
        .map(|label| format!(" for {label}"))
        .unwrap_or_default();
    let expires = first_expiration(&desired)
        .map(|value| format!("; renews until {value}"))
        .unwrap_or_default();
    let noun = if count == 1 {
        "subscription"
    } else {
        "subscriptions"
    };
    format!(
        "synced {count} {noun}{setup_label}: {}{expires}",
        parts.join(", ")
    )
}

fn write_subscription_attempt_audit(
    config_dir: &Path,
    provider_id: &str,
    extension: &MessagingSubscriptionsExtension,
    state: &Value,
    config_keys: &str,
    error: Option<&str>,
) -> Result<std::path::PathBuf> {
    let path = config_dir
        .join("state")
        .join("subscriptions")
        .join(format!("{provider_id}.attempt.json"));
    let audit = json!({
        "provider_id": provider_id,
        "component_ref": extension.component_ref,
        "export": extension.export_name,
        "config_keys": config_keys,
        "diagnostic": subscription_state_diagnostic(state),
        "state": state,
        "error": error,
    });
    write_json(&path, &audit)?;
    Ok(path)
}

fn subscription_target_label(value: &Value) -> String {
    for key in ["label", "display_name", "name", "resource"] {
        if let Some(label) = value
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|label| !label.is_empty())
        {
            return label.to_string();
        }
    }
    "requested subscription".to_string()
}

fn subscription_state_diagnostic(state: &Value) -> String {
    let desired = state
        .get("desired_subscriptions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let notification_url = state
        .get("notification_url")
        .or_else(|| state.get("webhook_url"))
        .and_then(Value::as_str)
        .map(redact_url_for_log)
        .unwrap_or_else(|| "-".to_string());
    let lifecycle_url = state
        .get("lifecycle_notification_url")
        .and_then(Value::as_str)
        .map(redact_url_for_log)
        .or_else(|| {
            desired
                .iter()
                .find_map(|entry| {
                    entry
                        .get("lifecycle_notification_url")
                        .and_then(Value::as_str)
                })
                .map(redact_url_for_log)
        })
        .unwrap_or_else(|| "-".to_string());
    let resources = desired
        .iter()
        .take(3)
        .map(subscription_target_label)
        .collect::<Vec<_>>()
        .join(", ");
    let resource_label = if resources.is_empty() {
        "-".to_string()
    } else {
        resources
    };
    let expires = first_expiration(&desired).unwrap_or_else(|| "-".to_string());
    format!(
        "count={} resources=[{}] notification_url={} lifecycle_notification_url={} expiration={} unresolved_placeholders={}",
        desired.len(),
        resource_label,
        notification_url,
        lifecycle_url,
        expires,
        unresolved_placeholder_paths(state).join(",")
    )
}

fn unresolved_placeholder_paths(value: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    collect_unresolved_placeholder_paths(value, "$", &mut paths);
    paths
}

fn collect_unresolved_placeholder_paths(value: &Value, path: &str, paths: &mut Vec<String>) {
    match value {
        Value::String(value) if value.contains('{') && value.contains('}') => {
            paths.push(path.to_string());
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_unresolved_placeholder_paths(item, &format!("{path}[{index}]"), paths);
            }
        }
        Value::Object(map) => {
            for (key, value) in map {
                collect_unresolved_placeholder_paths(value, &format!("{path}.{key}"), paths);
            }
        }
        _ => {}
    }
}

fn object_keys_label(value: &Value) -> String {
    let Some(map) = value.as_object() else {
        return "-".to_string();
    };
    let mut keys = map.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    if keys.is_empty() {
        "-".to_string()
    } else {
        keys.join(",")
    }
}

fn redact_url_for_log(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    format!("{scheme}://{host}/{path}")
}

fn setup_answer_display_label(setup_answers: Option<&Value>) -> Option<String> {
    let answers = setup_answers.and_then(Value::as_object)?;
    for suffix in [
        "channel_name",
        "calendar_name",
        "mailbox_name",
        "folder_name",
        "chat_name",
    ] {
        if let Some(label) = answers
            .get(suffix)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|label| !label.is_empty())
        {
            return Some(label.to_string());
        }
    }
    None
}

fn first_expiration(desired: &[Value]) -> Option<String> {
    desired.iter().find_map(|value| {
        value
            .get("expiration_datetime")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn read_subscriptions_extension(
    pack_path: &Path,
) -> Result<Option<MessagingSubscriptionsExtension>> {
    if let Some(decoded) = read_subscriptions_extension_cbor(pack_path)? {
        return Ok(Some(decoded));
    }
    read_subscriptions_extension_json(pack_path)
}

fn read_subscriptions_extension_cbor(
    pack_path: &Path,
) -> Result<Option<MessagingSubscriptionsExtension>> {
    let Some(bytes) = read_pack_manifest_cbor_bytes(pack_path)? else {
        return Ok(None);
    };
    let manifest = decode_pack_manifest(&bytes)
        .with_context(|| format!("failed to decode pack manifest in {}", pack_path.display()))?;
    let Some(extension) = manifest
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get(EXT_MESSAGING_SUBSCRIPTIONS_V1))
    else {
        return Ok(None);
    };
    let inline = extension.inline.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "{} extension inline payload missing in {}",
            EXT_MESSAGING_SUBSCRIPTIONS_V1,
            pack_path.display()
        )
    })?;
    let ExtensionInline::Other(value) = inline else {
        anyhow::bail!(
            "{} extension inline payload has unexpected type",
            EXT_MESSAGING_SUBSCRIPTIONS_V1
        );
    };
    parse_subscriptions_extension_value(value.clone(), pack_path)
}

fn read_subscriptions_extension_json(
    pack_path: &Path,
) -> Result<Option<MessagingSubscriptionsExtension>> {
    let Some(manifest) = read_pack_manifest_json(pack_path)? else {
        return Ok(None);
    };
    let Some(extension) = manifest
        .get("extensions")
        .and_then(|extensions| extensions.get(EXT_MESSAGING_SUBSCRIPTIONS_V1))
    else {
        return Ok(None);
    };
    let inline = extension.get("inline").ok_or_else(|| {
        anyhow::anyhow!(
            "{} extension inline payload missing in {}",
            EXT_MESSAGING_SUBSCRIPTIONS_V1,
            pack_path.display()
        )
    })?;
    parse_subscriptions_extension_value(inline.clone(), pack_path)
}

fn parse_subscriptions_extension_value(
    value: Value,
    pack_path: &Path,
) -> Result<Option<MessagingSubscriptionsExtension>> {
    let decoded = serde_json::from_value(value).with_context(|| {
        format!(
            "failed to parse {} extension in {}",
            EXT_MESSAGING_SUBSCRIPTIONS_V1,
            pack_path.display()
        )
    })?;
    Ok(Some(decoded))
}

fn filter_config_for_subscription_component(
    extension: &MessagingSubscriptionsExtension,
    pack_path: &Path,
    component_ref: &str,
    config: Value,
) -> Result<Value> {
    if let Some(component_config) = &extension.component_config
        && !component_config.include.is_empty()
    {
        return Ok(filter_config_by_allowed_fields(
            config,
            &component_config.include,
        ));
    }

    let Some(schema) = read_component_config_schema(pack_path, component_ref)? else {
        return Ok(config);
    };
    Ok(filter_config_by_schema(config, &schema))
}

fn filter_config_by_schema(config: Value, schema: &Value) -> Value {
    let Some(config_map) = config.as_object() else {
        return config;
    };
    let Some(schema_obj) = schema.as_object() else {
        return config;
    };
    let Some(properties) = schema_obj.get("properties").and_then(Value::as_object) else {
        return config;
    };
    if properties.is_empty() {
        return config;
    }

    Value::Object(
        config_map
            .iter()
            .filter(|(key, _)| properties.contains_key(*key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

fn filter_config_by_allowed_fields(config: Value, allowed_fields: &[String]) -> Value {
    let Some(config_map) = config.as_object() else {
        return config;
    };
    Value::Object(
        config_map
            .iter()
            .filter(|(key, _)| allowed_fields.iter().any(|allowed| allowed == *key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

fn expected_config_fields_from_invalid_config_error(
    outcome: &crate::runner_host::FlowOutcome,
) -> Option<Vec<String>> {
    let message = outcome
        .error
        .as_deref()
        .or(outcome.raw.as_deref())
        .or_else(|| {
            outcome
                .output
                .as_ref()
                .and_then(|value| value.get("error"))
                .and_then(Value::as_str)
        })?;
    parse_expected_config_fields(message)
}

fn parse_expected_config_fields(message: &str) -> Option<Vec<String>> {
    if !message.contains("invalid config: unknown field") {
        return None;
    }
    let (_, expected) = message.split_once("expected one of ")?;
    let expected = expected
        .split(" at line ")
        .next()
        .unwrap_or(expected)
        .trim()
        .trim_end_matches('.');
    let fields = expected
        .split(',')
        .map(|field| field.trim().trim_matches('`').trim_matches('"'))
        .filter(|field| !field.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if fields.is_empty() {
        None
    } else {
        Some(fields)
    }
}

fn read_component_config_schema(pack_path: &Path, component_ref: &str) -> Result<Option<Value>> {
    if let Some(manifest) = read_pack_manifest_json(pack_path)?
        && let Some(schema) = manifest
            .get("components")
            .and_then(Value::as_array)
            .and_then(|components| {
                components
                    .iter()
                    .find(|component| {
                        component
                            .get("id")
                            .and_then(Value::as_str)
                            .is_some_and(|id| id == component_ref)
                    })
                    .or_else(|| components.first())
            })
            .and_then(|component| component.get("config_schema"))
            .cloned()
    {
        return Ok(Some(schema));
    }

    let Some(bytes) = read_pack_manifest_cbor_bytes(pack_path)? else {
        return Ok(None);
    };
    let manifest = decode_pack_manifest(&bytes)
        .with_context(|| format!("failed to decode pack manifest in {}", pack_path.display()))?;
    Ok(manifest
        .components
        .iter()
        .find(|component| component.id.as_str() == component_ref)
        .or_else(|| manifest.components.first())
        .and_then(|component| component.config_schema.clone()))
}

fn read_pack_manifest_cbor_bytes(pack_path: &Path) -> Result<Option<Vec<u8>>> {
    if pack_path.is_dir() {
        let path = pack_path.join("manifest.cbor");
        if !path.exists() {
            return Ok(None);
        }
        return std::fs::read(&path)
            .map(Some)
            .with_context(|| format!("failed to read {}", path.display()));
    }
    let file =
        File::open(pack_path).with_context(|| format!("failed to open {}", pack_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("failed to read pack archive {}", pack_path.display()))?;
    let mut manifest_entry = match archive.by_name("manifest.cbor") {
        Ok(file) => file,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut bytes = Vec::new();
    manifest_entry.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn read_pack_manifest_json(pack_path: &Path) -> Result<Option<Value>> {
    let bytes = if pack_path.is_dir() {
        let path = pack_path.join("pack.manifest.json");
        if !path.exists() {
            return Ok(None);
        }
        std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?
    } else {
        let file = File::open(pack_path)
            .with_context(|| format!("failed to open {}", pack_path.display()))?;
        let mut archive = ZipArchive::new(file)
            .with_context(|| format!("failed to read pack archive {}", pack_path.display()))?;
        let mut manifest_entry = match archive.by_name("pack.manifest.json") {
            Ok(file) => file,
            Err(zip::result::ZipError::FileNotFound) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let mut bytes = Vec::new();
        manifest_entry.read_to_end(&mut bytes)?;
        bytes
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .with_context(|| format!("failed to parse pack manifest in {}", pack_path.display()))
}

fn read_provider_setup_answers(config_dir: &Path, provider_id: &str) -> Result<Option<Value>> {
    let path = config_dir
        .join("state")
        .join("config")
        .join(provider_id)
        .join("setup-answers.json");
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let value = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(value))
}

fn build_subscription_state(
    extension: &MessagingSubscriptionsExtension,
    setup_answers: Option<&Value>,
    provider_id: &str,
    tenant: &str,
    team: &str,
    public_base_url: &str,
) -> Option<Value> {
    let notification_url = format!(
        "{}/v1/messaging/ingress/{}/{}/{}",
        public_base_url.trim_end_matches('/'),
        provider_id,
        tenant,
        team
    );
    let context = template_context(
        setup_answers,
        provider_id,
        tenant,
        team,
        public_base_url,
        &notification_url,
    );

    if let Some(template) = extension
        .state_template
        .as_ref()
        .or(extension.desired_state_template.as_ref())
    {
        return Some(expand_template_value(template, &context));
    }

    if let Some(desired_state) = &extension.desired_state {
        return build_declared_desired_state(extension, desired_state, &context, &notification_url);
    }

    if let Some(desired) = setup_answers
        .and_then(|answers| answers.get("desired_subscriptions"))
        .or(extension.desired_subscriptions.as_ref())
    {
        return Some(json!({
            "webhook_url": notification_url,
            "notification_url": notification_url,
            "desired_subscriptions": expand_template_value(desired, &context),
        }));
    }

    None
}

fn build_declared_desired_state(
    extension: &MessagingSubscriptionsExtension,
    desired_state: &DesiredStateDeclaration,
    base_context: &BTreeMap<String, String>,
    default_notification_url: &str,
) -> Option<Value> {
    let mut context = base_context.clone();
    let notification_url = desired_state
        .notification_url
        .as_ref()
        .map(|decl| expand_template_string(&decl.template, &context))
        .unwrap_or_else(|| default_notification_url.to_string());
    context.insert("notification_url".to_string(), notification_url.clone());
    context.insert("webhook_url".to_string(), notification_url.clone());
    let lifecycle_notification_url = desired_state
        .lifecycle_notification_url
        .as_ref()
        .map(|decl| expand_template_string(&decl.template, &context));
    if let Some(value) = lifecycle_notification_url.as_ref() {
        context.insert("lifecycle_notification_url".to_string(), value.clone());
    }

    if let Some(policy) = &desired_state.expiration_policy
        && policy.host_supplied
        && let Some(state_key) = policy.state_key.as_deref()
    {
        context
            .entry(state_key.to_string())
            .or_insert_with(|| generated_expiration_datetime(extension.renewal_window_hours));
    }

    let desired = desired_state
        .templates
        .iter()
        .filter_map(|template| {
            build_desired_subscription_from_template(template, desired_state, &context)
        })
        .map(|entry| default_lifecycle_notification_url(entry, &notification_url))
        .collect::<Vec<_>>();
    if desired.is_empty() {
        return None;
    }

    let output_key = desired_state
        .output_key
        .as_deref()
        .unwrap_or("desired_subscriptions");
    let notification_state_key = desired_state
        .notification_url
        .as_ref()
        .and_then(|decl| decl.state_key.as_deref())
        .unwrap_or("notification_url");
    let mut state = Map::new();
    state.insert(
        "webhook_url".to_string(),
        Value::String(notification_url.clone()),
    );
    state.insert(
        "notification_url".to_string(),
        Value::String(notification_url.clone()),
    );
    state.insert(
        notification_state_key.to_string(),
        Value::String(notification_url),
    );
    if let Some(value) = lifecycle_notification_url {
        let state_key = desired_state
            .lifecycle_notification_url
            .as_ref()
            .and_then(|decl| decl.state_key.as_deref())
            .unwrap_or("lifecycle_notification_url");
        state.insert(state_key.to_string(), Value::String(value));
    }
    if let Some(policy) = &desired_state.expiration_policy
        && let Some(state_key) = policy.state_key.as_deref()
        && let Some(value) = context.get(state_key)
    {
        state.insert(state_key.to_string(), Value::String(value.clone()));
    }
    state.insert(output_key.to_string(), Value::Array(desired));
    Some(Value::Object(state))
}

fn default_lifecycle_notification_url(mut entry: Value, notification_url: &str) -> Value {
    let Some(map) = entry.as_object_mut() else {
        return entry;
    };
    if map
        .get("lifecycle_notification_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
    {
        return entry;
    }
    if map
        .get("expiration_datetime")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return entry;
    }
    let fallback = map
        .get("notification_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(notification_url);
    map.insert(
        "lifecycle_notification_url".to_string(),
        Value::String(fallback.to_string()),
    );
    entry
}

fn build_desired_subscription_from_template(
    template: &Value,
    desired_state: &DesiredStateDeclaration,
    context: &BTreeMap<String, String>,
) -> Option<Value> {
    let template = template.as_object()?;
    if !template_conditions_match(template, context) {
        return None;
    }

    let mut entry = desired_state.defaults.clone();
    for (key, value) in template {
        match key.as_str() {
            "id" | "when_all" => {}
            "resource_template" => {
                entry.insert(
                    "resource".to_string(),
                    expand_template_value(value, context),
                );
            }
            _ => {
                entry.insert(key.clone(), expand_template_value(value, context));
            }
        }
    }
    Some(Value::Object(entry))
}

fn template_conditions_match(
    template: &Map<String, Value>,
    context: &BTreeMap<String, String>,
) -> bool {
    template
        .get("when_all")
        .and_then(Value::as_array)
        .map(|keys| {
            keys.iter().all(|key| {
                key.as_str()
                    .and_then(|name| context.get(name))
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false)
            })
        })
        .unwrap_or(true)
}

fn generated_expiration_datetime(renewal_window_hours: Option<i64>) -> String {
    let hours = renewal_window_hours.unwrap_or(24).max(1);
    (Utc::now() + Duration::hours(hours)).to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn template_context(
    setup_answers: Option<&Value>,
    provider_id: &str,
    tenant: &str,
    team: &str,
    public_base_url: &str,
    notification_url: &str,
) -> BTreeMap<String, String> {
    let mut context = BTreeMap::new();
    if let Some(answers) = setup_answers.and_then(Value::as_object) {
        for (key, value) in answers {
            if let Some(s) = value.as_str() {
                context.insert(key.clone(), s.to_string());
            }
        }
    }
    context.insert("provider_id".to_string(), provider_id.to_string());
    context.insert("tenant".to_string(), tenant.to_string());
    context.insert("team".to_string(), team.to_string());
    context.insert("public_base_url".to_string(), public_base_url.to_string());
    context.insert("webhook_url".to_string(), notification_url.to_string());
    context.insert("notification_url".to_string(), notification_url.to_string());
    context
}

fn expand_template_value(value: &Value, context: &BTreeMap<String, String>) -> Value {
    match value {
        Value::String(s) => Value::String(expand_template_string(s, context)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| expand_template_value(item, context))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), expand_template_value(value, context)))
                .collect::<Map<_, _>>(),
        ),
        other => other.clone(),
    }
}

fn expand_template_string(input: &str, context: &BTreeMap<String, String>) -> String {
    let mut out = input.to_string();
    for (key, value) in context {
        out = out.replace(&format!("{{{key}}}"), value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{DetectedDomains, DetectedProvider, DiscoveryResult, ProviderIdSource};
    use greentic_types::{
        ExtensionInline, ExtensionRef, PackKind, PackManifest, PackSignatures, encode_pack_manifest,
    };
    use semver::Version;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::ZipWriter;
    use zip::write::FileOptions;

    fn extension_with_state_template(template: Value) -> MessagingSubscriptionsExtension {
        MessagingSubscriptionsExtension {
            component_ref: "subscription-component".to_string(),
            export_name: "sync-subscriptions".to_string(),
            renewal_window_hours: None,
            state_template: Some(template),
            desired_state_template: None,
            desired_subscriptions: None,
            component_config: None,
            desired_state: None,
        }
    }

    #[test]
    fn builds_state_from_provider_declared_template_without_provider_specific_logic() {
        let extension = extension_with_state_template(json!({
            "webhook_url": "{notification_url}",
            "desired_subscriptions": [{
                "resource": "/generic/{account_id}/{stream_id}",
                "change_type": "created",
                "label": "{stream_name}"
            }]
        }));
        let setup = json!({
            "account_id": "acct-1",
            "stream_id": "stream-2",
            "stream_name": "Default stream"
        });

        let state = build_subscription_state(
            &extension,
            Some(&setup),
            "messaging-generic",
            "demo",
            "default",
            "https://public.example",
        )
        .expect("state");

        assert_eq!(
            state["webhook_url"],
            "https://public.example/v1/messaging/ingress/messaging-generic/demo/default"
        );
        assert_eq!(
            state["desired_subscriptions"][0]["resource"],
            "/generic/acct-1/stream-2"
        );
        assert_eq!(state["desired_subscriptions"][0]["label"], "Default stream");
    }

    #[test]
    fn builds_state_from_explicit_desired_subscriptions_setup_answer() {
        let extension = MessagingSubscriptionsExtension {
            component_ref: "subscription-component".to_string(),
            export_name: "sync-subscriptions".to_string(),
            renewal_window_hours: None,
            state_template: None,
            desired_state_template: None,
            desired_subscriptions: None,
            component_config: None,
            desired_state: None,
        };
        let setup = json!({
            "desired_subscriptions": [{
                "resource": "/streams/{stream_id}",
                "stream_id": "literal"
            }],
            "stream_id": "abc"
        });

        let state = build_subscription_state(
            &extension,
            Some(&setup),
            "messaging-generic",
            "demo",
            "default",
            "https://public.example/",
        )
        .expect("state");

        assert_eq!(
            state["notification_url"],
            "https://public.example/v1/messaging/ingress/messaging-generic/demo/default"
        );
        assert_eq!(
            state["desired_subscriptions"][0]["resource"],
            "/streams/abc"
        );
        assert_eq!(state["desired_subscriptions"][0]["stream_id"], "literal");
    }

    #[test]
    fn skips_when_extension_and_setup_do_not_declare_desired_state() {
        let extension = MessagingSubscriptionsExtension {
            component_ref: "subscription-component".to_string(),
            export_name: "sync-subscriptions".to_string(),
            renewal_window_hours: None,
            state_template: None,
            desired_state_template: None,
            desired_subscriptions: None,
            component_config: None,
            desired_state: None,
        };

        assert!(
            build_subscription_state(
                &extension,
                Some(&json!({"channel_id": "opaque"})),
                "messaging-generic",
                "demo",
                "default",
                "https://public.example",
            )
            .is_none()
        );
    }

    #[test]
    fn filters_subscription_component_config_to_declared_schema_properties() {
        let config = json!({
            "tenant_id": "tenant",
            "client_id": "client",
            "channel_id": "setup-only",
            "public_base_url": "https://public.example",
            "tenant": "demo",
            "team": "default"
        });
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "tenant_id": {"type": "string"},
                "client_id": {"type": "string"}
            }
        });

        let filtered = filter_config_by_schema(config, &schema);

        assert_eq!(
            filtered,
            json!({
                "tenant_id": "tenant",
                "client_id": "client"
            })
        );
    }

    #[test]
    fn filters_subscription_component_config_to_declared_metadata_include_list() {
        let extension = MessagingSubscriptionsExtension {
            component_ref: "subscription-component".to_string(),
            export_name: "sync-subscriptions".to_string(),
            renewal_window_hours: None,
            state_template: None,
            desired_state_template: None,
            desired_subscriptions: None,
            component_config: Some(ComponentConfigDeclaration {
                source: Some("setup_answers".to_string()),
                include: vec![
                    "tenant_id".to_string(),
                    "client_id".to_string(),
                    "graph_base_url".to_string(),
                    "auth_base_url".to_string(),
                    "token_scope".to_string(),
                ],
            }),
            desired_state: None,
        };

        let filtered = filter_config_for_subscription_component(
            &extension,
            std::path::Path::new("/missing.gtpack"),
            "subscription-component",
            json!({
                "tenant_id": "tenant",
                "client_id": "client",
                "channel_id": "setup-only",
                "public_base_url": "https://public.example"
            }),
        )
        .expect("filtered config");

        assert_eq!(
            filtered,
            json!({
                "tenant_id": "tenant",
                "client_id": "client"
            })
        );
    }

    #[test]
    fn parses_expected_config_fields_from_component_error() {
        let fields = parse_expected_config_fields(
            "invalid config: unknown field `channel_id`, expected one of `tenant_id`, `client_id`, `graph_base_url`, `auth_base_url`, `token_scope` at line 1 column 65",
        )
        .expect("fields");

        assert_eq!(
            fields,
            vec![
                "tenant_id".to_string(),
                "client_id".to_string(),
                "graph_base_url".to_string(),
                "auth_base_url".to_string(),
                "token_scope".to_string(),
            ]
        );
    }

    #[test]
    fn builds_state_from_declared_desired_state_templates() {
        let extension = MessagingSubscriptionsExtension {
            component_ref: "subscription-component".to_string(),
            export_name: "sync-subscriptions".to_string(),
            renewal_window_hours: Some(6),
            state_template: None,
            desired_state_template: None,
            desired_subscriptions: None,
            component_config: None,
            desired_state: Some(DesiredStateDeclaration {
                output_key: Some("desired_subscriptions".to_string()),
                defaults: Map::from_iter([(
                    "change_type".to_string(),
                    Value::String("created".to_string()),
                )]),
                notification_url: Some(NotificationUrlDeclaration {
                    template: "{public_base_url}/hooks/{provider_id}/{tenant}/{team}".to_string(),
                    state_key: Some("notification_url".to_string()),
                }),
                lifecycle_notification_url: Some(NotificationUrlDeclaration {
                    template: "{public_base_url}/lifecycle/{provider_id}/{tenant}/{team}"
                        .to_string(),
                    state_key: Some("lifecycle_notification_url".to_string()),
                }),
                expiration_policy: Some(ExpirationPolicyDeclaration {
                    state_key: Some("expiration_datetime".to_string()),
                    host_supplied: true,
                }),
                templates: vec![
                    json!({
                        "id": "account_stream_messages",
                        "when_all": ["account_id", "stream_id"],
                        "resource_template": "/accounts/{account_id}/streams/{stream_id}/messages",
                        "expiration_datetime": "{expiration_datetime}",
                        "notification_url": "{notification_url}",
                        "lifecycle_notification_url": "{lifecycle_notification_url}"
                    }),
                    json!({
                        "id": "direct_messages",
                        "when_all": ["chat_id"],
                        "resource_template": "/chats/{chat_id}/messages"
                    }),
                ],
            }),
        };
        let setup = json!({
            "account_id": "acct-1",
            "stream_id": "stream-2"
        });

        let state = build_subscription_state(
            &extension,
            Some(&setup),
            "messaging-generic",
            "demo",
            "default",
            "https://public.example",
        )
        .expect("state");

        assert_eq!(
            state["webhook_url"],
            "https://public.example/hooks/messaging-generic/demo/default"
        );
        assert_eq!(
            state["desired_subscriptions"][0]["resource"],
            "/accounts/acct-1/streams/stream-2/messages"
        );
        assert_eq!(
            state["desired_subscriptions"][0]["notification_url"],
            "https://public.example/hooks/messaging-generic/demo/default"
        );
        assert_eq!(
            state["desired_subscriptions"][0]["lifecycle_notification_url"],
            "https://public.example/lifecycle/messaging-generic/demo/default"
        );
        assert_eq!(
            state["lifecycle_notification_url"],
            "https://public.example/lifecycle/messaging-generic/demo/default"
        );
        assert_eq!(state["desired_subscriptions"].as_array().unwrap().len(), 1);
        let expiration = state["desired_subscriptions"][0]["expiration_datetime"]
            .as_str()
            .expect("expiration");
        assert!(expiration.ends_with('Z'));
        assert!(chrono::DateTime::parse_from_rfc3339(expiration).is_ok());
    }

    #[test]
    fn defaults_lifecycle_notification_url_when_subscription_has_expiration() {
        let entry = default_lifecycle_notification_url(
            json!({
                "resource": "/teams/team/channels/channel/messages",
                "notification_url": "https://public.example/notify",
                "expiration_datetime": "2026-06-01T20:41:19Z"
            }),
            "https://public.example/default",
        );

        assert_eq!(
            entry["lifecycle_notification_url"],
            "https://public.example/notify"
        );
    }

    #[test]
    fn subscription_result_description_names_requested_targets() {
        let state = json!({
            "desired_subscriptions": [{
                "resource": "/accounts/acct-1/streams/stream-2/messages",
                "expiration_datetime": "2026-01-01T00:00:00Z"
            }]
        });
        let setup = json!({
            "channel_name": "Support"
        });

        assert_eq!(
            subscription_result_description(&state, Some(&setup)),
            "synced 1 subscription for Support: /accounts/acct-1/streams/stream-2/messages; renews until 2026-01-01T00:00:00Z"
        );
    }

    #[test]
    fn reports_subscription_provider_when_public_url_is_unavailable() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let pack_dir = dir.path().join("provider.gtpack");
        std::fs::create_dir(&pack_dir)?;
        std::fs::write(
            pack_dir.join("pack.manifest.json"),
            serde_json::to_vec(&json!({
                "extensions": {
                    "messaging.subscriptions.v1": {
                        "inline": {
                            "component_ref": "subscription-component",
                            "export": "sync-subscriptions"
                        }
                    }
                }
            }))?,
        )?;
        let discovery = DiscoveryResult {
            domains: DetectedDomains {
                messaging: true,
                events: false,
                oauth: false,
            },
            providers: vec![DetectedProvider {
                provider_id: "messaging-generic".to_string(),
                domain: "messaging".to_string(),
                pack_path: pack_dir,
                id_source: ProviderIdSource::Manifest,
            }],
        };

        let secrets_handle =
            crate::secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default"))?;
        let summary = sync_subscriptions_if_public_url_available(
            dir.path(),
            &discovery,
            &secrets_handle,
            None,
            "demo",
            "default",
            "",
        )?;

        assert_eq!(
            summary.results,
            vec![(
                "messaging-generic".to_string(),
                "skipped: public HTTPS URL unavailable".to_string()
            )]
        );
        Ok(())
    }

    #[test]
    fn reads_subscriptions_extension_from_cbor_pack_manifest() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let pack_path = dir.path().join("provider.gtpack");
        let mut extensions = BTreeMap::new();
        extensions.insert(
            EXT_MESSAGING_SUBSCRIPTIONS_V1.to_string(),
            ExtensionRef {
                kind: EXT_MESSAGING_SUBSCRIPTIONS_V1.to_string(),
                version: "1".to_string(),
                digest: None,
                location: None,
                inline: Some(ExtensionInline::Other(json!({
                    "component_ref": "messaging-ingress-teams",
                    "export": "sync-subscriptions",
                    "component_config": {
                        "source": "setup_answers",
                        "include": ["tenant_id", "client_id"]
                    }
                }))),
            },
        );
        let manifest = PackManifest {
            agents: Default::default(),
            schema_version: "1".to_string(),
            pack_id: "messaging-teams".parse()?,
            name: None,
            version: Version::parse("0.0.0")?,
            kind: PackKind::Provider,
            publisher: "test".to_string(),
            components: Vec::new(),
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            secret_requirements: Vec::new(),
            signatures: PackSignatures::default(),
            bootstrap: None,
            extensions: Some(extensions),
        };
        let mut zip = ZipWriter::new(std::fs::File::create(&pack_path)?);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())?;
        zip.write_all(&encode_pack_manifest(&manifest)?)?;
        zip.finish()?;

        let extension = read_subscriptions_extension(&pack_path)?.expect("extension");
        assert_eq!(extension.component_ref, "messaging-ingress-teams");
        assert_eq!(extension.export_name, "sync-subscriptions");
        assert_eq!(
            extension
                .component_config
                .expect("component config")
                .include,
            vec!["tenant_id".to_string(), "client_id".to_string()]
        );
        Ok(())
    }

    #[test]
    fn filters_subscription_config_from_cbor_pack_metadata() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let pack_path = dir.path().join("provider.gtpack");
        let mut extensions = BTreeMap::new();
        extensions.insert(
            EXT_MESSAGING_SUBSCRIPTIONS_V1.to_string(),
            ExtensionRef {
                kind: EXT_MESSAGING_SUBSCRIPTIONS_V1.to_string(),
                version: "1".to_string(),
                digest: None,
                location: None,
                inline: Some(ExtensionInline::Other(json!({
                    "component_ref": "messaging-ingress-teams",
                    "export": "sync-subscriptions",
                    "component_config": {
                        "source": "setup_answers",
                        "include": [
                            "tenant_id",
                            "client_id",
                            "graph_base_url",
                            "auth_base_url",
                            "token_scope"
                        ]
                    }
                }))),
            },
        );
        let manifest = PackManifest {
            agents: Default::default(),
            schema_version: "1".to_string(),
            pack_id: "messaging-teams".parse()?,
            name: None,
            version: Version::parse("0.0.0")?,
            kind: PackKind::Provider,
            publisher: "test".to_string(),
            components: Vec::new(),
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            secret_requirements: Vec::new(),
            signatures: PackSignatures::default(),
            bootstrap: None,
            extensions: Some(extensions),
        };
        let mut zip = ZipWriter::new(std::fs::File::create(&pack_path)?);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())?;
        zip.write_all(&encode_pack_manifest(&manifest)?)?;
        zip.finish()?;

        let extension = read_subscriptions_extension(&pack_path)?.expect("extension");
        let filtered = filter_config_for_subscription_component(
            &extension,
            &pack_path,
            &extension.component_ref,
            json!({
                "tenant_id": "tenant",
                "client_id": "client",
                "graph_base_url": "https://graph.microsoft.com/v1.0",
                "auth_base_url": "https://login.microsoftonline.com",
                "token_scope": "https://graph.microsoft.com/.default",
                "channel_id": "setup-only",
                "public_base_url": "https://public.example",
                "tenant": "demo",
                "team": "default",
                "provider_id": "messaging-teams"
            }),
        )?;

        assert_eq!(
            filtered,
            json!({
                "tenant_id": "tenant",
                "client_id": "client",
                "graph_base_url": "https://graph.microsoft.com/v1.0",
                "auth_base_url": "https://login.microsoftonline.com",
                "token_scope": "https://graph.microsoft.com/.default"
            })
        );
        Ok(())
    }

    #[test]
    fn local_teams_pack_filters_subscription_config_when_available() -> anyhow::Result<()> {
        let pack_path = std::path::Path::new(
            "../greentic-messaging-providers/packs/messaging-teams/dist/messaging-teams.gtpack",
        );
        if !pack_path.exists() {
            return Ok(());
        }

        let extension = read_subscriptions_extension(pack_path)?.expect("extension");
        let config = json!({
            "tenant_id": "tenant",
            "client_id": "client",
            "graph_base_url": "https://graph.microsoft.com/v1.0",
            "auth_base_url": "https://login.microsoftonline.com",
            "token_scope": "https://graph.microsoft.com/.default",
            "channel_id": "setup-only",
            "team_id": "setup-only",
            "public_base_url": "https://public.example",
            "tenant": "demo",
            "team": "default",
            "provider_id": "messaging-teams"
        });
        let filtered = filter_config_for_subscription_component(
            &extension,
            pack_path,
            &extension.component_ref,
            config.clone(),
        )?;
        let filtered = if filtered == config {
            let expected = parse_expected_config_fields(
                "invalid config: unknown field `channel_id`, expected one of `tenant_id`, `client_id`, `graph_base_url`, `auth_base_url`, `token_scope` at line 1 column 65",
            )
            .expect("expected fields");
            filter_config_by_allowed_fields(filtered, &expected)
        } else {
            filtered
        };

        assert_eq!(
            filtered,
            json!({
                "tenant_id": "tenant",
                "client_id": "client",
                "graph_base_url": "https://graph.microsoft.com/v1.0",
                "auth_base_url": "https://login.microsoftonline.com",
                "token_scope": "https://graph.microsoft.com/.default"
            })
        );
        Ok(())
    }
}
