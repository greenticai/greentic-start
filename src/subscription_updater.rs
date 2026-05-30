//! Generic startup reconciliation for provider-declared messaging subscriptions.

use std::collections::BTreeMap;
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
    desired_state: Option<DesiredStateDeclaration>,
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
    if !public_base_url.starts_with("https://") {
        operator_log::debug(
            module_path!(),
            format!(
                "[subscription-updater] skipping subscription sync: URL is not HTTPS ({})",
                public_base_url
            ),
        );
        return Ok(SubscriptionUpdateSummary::default());
    }

    let Some(host) = runner_host else {
        return Ok(SubscriptionUpdateSummary::default());
    };

    let mut summary = SubscriptionUpdateSummary::default();
    for provider in discovery
        .providers
        .iter()
        .filter(|provider| provider.domain == "messaging")
    {
        let Some(extension) = read_subscriptions_extension(&provider.pack_path)? else {
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
            operator_log::debug(
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
        let outcome = host.invoke_pack_component_op_direct(
            Domain::Messaging,
            &pack,
            &extension.component_ref,
            &extension.export_name,
            &config,
            &state,
            &ctx,
        )?;

        if outcome.success {
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
            operator_log::warn(
                module_path!(),
                format!(
                    "[subscription-updater] subscription sync failed for {}: {}",
                    provider.provider_id, error
                ),
            );
            summary
                .results
                .push((provider.provider_id.clone(), format!("Error: {error}")));
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
    let file = std::fs::File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest_entry = match archive.by_name("manifest.cbor") {
        Ok(file) => file,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut bytes = Vec::new();
    manifest_entry.read_to_end(&mut bytes)?;
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
    let decoded = serde_json::from_value(value.clone()).with_context(|| {
        format!(
            "failed to parse {} extension in {}",
            EXT_MESSAGING_SUBSCRIPTIONS_V1,
            pack_path.display()
        )
    })?;
    Ok(Some(decoded))
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
    if let Some(policy) = &desired_state.expiration_policy
        && let Some(state_key) = policy.state_key.as_deref()
        && let Some(value) = context.get(state_key)
    {
        state.insert(state_key.to_string(), Value::String(value.clone()));
    }
    state.insert(output_key.to_string(), Value::Array(desired));
    Some(Value::Object(state))
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
    use serde_json::json;

    fn extension_with_state_template(template: Value) -> MessagingSubscriptionsExtension {
        MessagingSubscriptionsExtension {
            component_ref: "subscription-component".to_string(),
            export_name: "sync-subscriptions".to_string(),
            renewal_window_hours: None,
            state_template: Some(template),
            desired_state_template: None,
            desired_subscriptions: None,
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
    fn builds_state_from_declared_desired_state_templates() {
        let extension = MessagingSubscriptionsExtension {
            component_ref: "subscription-component".to_string(),
            export_name: "sync-subscriptions".to_string(),
            renewal_window_hours: Some(6),
            state_template: None,
            desired_state_template: None,
            desired_subscriptions: None,
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
                        "notification_url": "{notification_url}"
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
        assert_eq!(state["desired_subscriptions"].as_array().unwrap().len(), 1);
        let expiration = state["desired_subscriptions"][0]["expiration_datetime"]
            .as_str()
            .expect("expiration");
        assert!(expiration.ends_with('Z'));
        assert!(chrono::DateTime::parse_from_rfc3339(expiration).is_ok());
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
}
