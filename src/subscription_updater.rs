//! Generic startup reconciliation for provider-declared messaging subscriptions.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
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
    state_template: Option<Value>,
    #[serde(default)]
    desired_state_template: Option<Value>,
    #[serde(default)]
    desired_subscriptions: Option<Value>,
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
            summary
                .results
                .push((provider.provider_id.clone(), "skipped".to_string()));
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
            summary
                .results
                .push((provider.provider_id.clone(), "synced".to_string()));
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
            state_template: Some(template),
            desired_state_template: None,
            desired_subscriptions: None,
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
            state_template: None,
            desired_state_template: None,
            desired_subscriptions: None,
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
            state_template: None,
            desired_state_template: None,
            desired_subscriptions: None,
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
}
