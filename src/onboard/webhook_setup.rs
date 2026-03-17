use serde_json::{Value, json};

use crate::domains::{Domain, ProviderPack};
use crate::operator_log;

pub fn webhook_result_from_flow_output(output: Option<&Value>) -> Option<Value> {
    let output = output?;
    let webhook_ops = output.get("webhook_ops")?.as_array()?;
    if webhook_ops.is_empty() {
        return None;
    }
    let subscription_ops = output
        .get("subscription_ops")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let oauth_ops = output
        .get("oauth_ops")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    Some(json!({
        "ok": true,
        "mode": "flow_output",
        "webhook_ops": webhook_ops,
        "subscription_ops": subscription_ops,
        "oauth_ops": oauth_ops,
    }))
}

/// After submit, register webhooks with external APIs where applicable.
///
/// This makes native HTTP calls from the operator (not through WASM) so
/// it can reliably reach external APIs. Currently supports Telegram, Slack, and Webex.
pub fn try_provider_setup_webhook(
    _bundle_root: &std::path::Path,
    _domain: Domain,
    _pack: &ProviderPack,
    provider_id: &str,
    tenant: &str,
    team: Option<&str>,
    config: &Value,
) -> Option<Value> {
    let public_base_url = config.get("public_base_url").and_then(Value::as_str)?;
    if public_base_url.is_empty() || !public_base_url.starts_with("https://") {
        return None;
    }

    let team = team.unwrap_or("default");

    let provider_short = provider_id
        .strip_prefix("messaging-")
        .unwrap_or(provider_id);

    match provider_short {
        "telegram" => setup_telegram_webhook(config, public_base_url, provider_id, tenant, team),
        "slack" => setup_slack_manifest(config, public_base_url, provider_id, tenant, team),
        "webex" => setup_webex_webhook(config, public_base_url, provider_id, tenant, team),
        _ => None,
    }
}

// ── Telegram ────────────────────────────────────────────────────────────────

/// Call Telegram Bot API `setWebhook` to register the webhook URL.
fn setup_telegram_webhook(
    config: &Value,
    public_base_url: &str,
    provider_id: &str,
    tenant: &str,
    team: &str,
) -> Option<Value> {
    let bot_token = config.get("bot_token").and_then(Value::as_str)?;
    if bot_token.is_empty() {
        return Some(json!({"ok": false, "error": "bot_token is empty"}));
    }

    let api_base = config
        .get("api_base_url")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.contains("telegram.org"))
        .unwrap_or("https://api.telegram.org");

    let webhook_url = build_webhook_url(public_base_url, provider_id, tenant, team);

    let url = format!("{api_base}/bot{bot_token}/setWebhook");
    let body = json!({
        "url": webhook_url,
        "allowed_updates": ["message", "callback_query", "edited_message"]
    });

    let token_preview = if bot_token.len() > 10 {
        format!(
            "{}...{}",
            &bot_token[..5],
            &bot_token[bot_token.len() - 4..]
        )
    } else {
        "***".to_string()
    };
    operator_log::info(
        module_path!(),
        format!(
            "[onboard] telegram setWebhook url={} token_preview={} api={}",
            webhook_url, token_preview, api_base
        ),
    );

    match ureq::post(&url)
        .header("Content-Type", "application/json")
        .send_json(&body)
    {
        Ok(mut resp) => {
            let status = resp.status().as_u16();
            let raw_body = resp.body_mut().read_to_string().unwrap_or_default();
            operator_log::info(
                module_path!(),
                format!(
                    "[onboard] telegram setWebhook response status={} body={}",
                    status, raw_body
                ),
            );
            let resp_body: Value = serde_json::from_str(&raw_body).unwrap_or(Value::Null);
            let tg_ok = resp_body
                .get("ok")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let description = resp_body
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            Some(json!({
                "ok": tg_ok,
                "webhook_url": webhook_url,
                "description": description,
                "http_status": status,
                "telegram_response": resp_body,
            }))
        }
        Err(err) => Some(json!({
            "ok": false,
            "error": format!("request failed: {err}"),
            "webhook_url": webhook_url,
        })),
    }
}

// ── Slack ────────────────────────────────────────────────────────────────────

/// Call Slack `apps.manifest.export` + `apps.manifest.update` to set event subscription
/// and interactivity URLs in the app manifest automatically.
fn setup_slack_manifest(
    config: &Value,
    public_base_url: &str,
    provider_id: &str,
    tenant: &str,
    team: &str,
) -> Option<Value> {
    let app_id = config
        .get("slack_app_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let config_token = config
        .get("slack_configuration_token")
        .and_then(Value::as_str)
        .unwrap_or("");

    if app_id.is_empty() || config_token.is_empty() {
        operator_log::info(
            module_path!(),
            "[onboard] slack manifest: skipping — slack_app_id or slack_configuration_token not provided",
        );
        return None;
    }

    let webhook_url = build_webhook_url(public_base_url, provider_id, tenant, team);

    operator_log::info(
        module_path!(),
        format!(
            "[onboard] slack manifest: exporting manifest for app_id={} webhook_url={}",
            app_id, webhook_url
        ),
    );

    // 1. Export current manifest
    let mut manifest = match slack_export_manifest(app_id, config_token) {
        Ok(m) => m,
        Err(err_json) => {
            return Some(json!({
                "ok": false,
                "error": err_json,
                "webhook_url": webhook_url,
            }));
        }
    };

    // 2. Update manifest URLs in-place
    slack_update_manifest_urls(&mut manifest, &webhook_url);

    operator_log::info(
        module_path!(),
        format!(
            "[onboard] slack manifest: updating manifest for app_id={}",
            app_id
        ),
    );

    // 3. Push updated manifest
    slack_push_manifest(app_id, config_token, &manifest, &webhook_url)
}

/// Export the current Slack app manifest via `apps.manifest.export`.
fn slack_export_manifest(app_id: &str, config_token: &str) -> Result<Value, String> {
    let resp = ureq::post("https://slack.com/api/apps.manifest.export")
        .header("Authorization", &format!("Bearer {config_token}"))
        .header("Content-Type", "application/json")
        .send_json(json!({ "app_id": app_id }));

    match resp {
        Ok(mut resp) => {
            let raw = resp.body_mut().read_to_string().unwrap_or_default();
            let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
            let ok = parsed.get("ok").and_then(Value::as_bool).unwrap_or(false);
            if !ok {
                let err = parsed
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                operator_log::error(
                    module_path!(),
                    format!("[onboard] slack apps.manifest.export failed: {err}"),
                );
                return Err(format!("apps.manifest.export failed: {err}"));
            }
            parsed.get("manifest").cloned().ok_or_else(|| {
                operator_log::error(
                    module_path!(),
                    "[onboard] slack apps.manifest.export: response missing 'manifest' field",
                );
                "export response missing manifest field".to_string()
            })
        }
        Err(err) => Err(format!("apps.manifest.export request failed: {err}")),
    }
}

/// Update event_subscriptions and interactivity URLs in the manifest.
fn slack_update_manifest_urls(manifest: &mut Value, webhook_url: &str) {
    if let Some(settings) = manifest.get_mut("settings").and_then(Value::as_object_mut) {
        if let Some(es) = settings
            .get_mut("event_subscriptions")
            .and_then(Value::as_object_mut)
        {
            es.insert(
                "request_url".to_string(),
                Value::String(webhook_url.to_string()),
            );
        } else {
            settings.insert(
                "event_subscriptions".to_string(),
                json!({ "request_url": webhook_url }),
            );
        }
        if let Some(ir) = settings
            .get_mut("interactivity")
            .and_then(Value::as_object_mut)
        {
            ir.insert(
                "request_url".to_string(),
                Value::String(webhook_url.to_string()),
            );
            ir.insert("is_enabled".to_string(), Value::Bool(true));
        } else {
            settings.insert(
                "interactivity".to_string(),
                json!({ "is_enabled": true, "request_url": webhook_url }),
            );
        }
    } else if let Some(obj) = manifest.as_object_mut() {
        obj.insert(
            "settings".to_string(),
            json!({
                "event_subscriptions": { "request_url": webhook_url },
                "interactivity": { "is_enabled": true, "request_url": webhook_url }
            }),
        );
    }
}

/// Push the updated manifest via `apps.manifest.update`.
fn slack_push_manifest(
    app_id: &str,
    config_token: &str,
    manifest: &Value,
    webhook_url: &str,
) -> Option<Value> {
    let resp = ureq::post("https://slack.com/api/apps.manifest.update")
        .header("Authorization", &format!("Bearer {config_token}"))
        .header("Content-Type", "application/json")
        .send_json(json!({
            "app_id": app_id,
            "manifest": manifest,
        }));

    match resp {
        Ok(mut resp) => {
            let status = resp.status().as_u16();
            let raw = resp.body_mut().read_to_string().unwrap_or_default();
            let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
            let ok = parsed.get("ok").and_then(Value::as_bool).unwrap_or(false);

            operator_log::info(
                module_path!(),
                format!(
                    "[onboard] slack apps.manifest.update response status={} ok={}",
                    status, ok
                ),
            );

            Some(json!({
                "ok": ok,
                "webhook_url": webhook_url,
                "http_status": status,
                "slack_response": parsed,
            }))
        }
        Err(err) => Some(json!({
            "ok": false,
            "error": format!("apps.manifest.update request failed: {err}"),
            "webhook_url": webhook_url,
        })),
    }
}

// ── Webex ───────────────────────────────────────────────────────────────────

/// Register (or update) Webex webhooks so incoming messages AND card actions
/// are forwarded to the operator's ingress endpoint.
///
/// Two webhooks are managed:
/// - `messages.created` — new text/file messages
/// - `attachmentActions.created` — Adaptive Card button clicks
///
/// Flow: list existing webhooks → find matching ones by name → create or update.
fn setup_webex_webhook(
    config: &Value,
    public_base_url: &str,
    provider_id: &str,
    tenant: &str,
    team: &str,
) -> Option<Value> {
    let bot_token = config
        .get("bot_token")
        .or_else(|| config.get("webex_bot_token"))
        .and_then(Value::as_str)
        .unwrap_or("");

    if bot_token.is_empty() {
        operator_log::info(
            module_path!(),
            "[onboard] webex webhook: skipping — bot_token not provided",
        );
        return None;
    }

    let api_base = config
        .get("api_base_url")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("https://webexapis.com/v1");

    let webhook_url = build_webhook_url(public_base_url, provider_id, tenant, team);
    let base_name = format!("greentic:{}:{}:webex", tenant, team);

    let token_preview = if bot_token.len() > 10 {
        format!(
            "{}...{}",
            &bot_token[..5],
            &bot_token[bot_token.len() - 4..]
        )
    } else {
        "***".to_string()
    };
    operator_log::info(
        module_path!(),
        format!(
            "[onboard] webex webhook: target_url={} name={} token_preview={}",
            webhook_url, base_name, token_preview
        ),
    );

    // 1. List existing webhooks
    let existing = match webex_list_webhooks(api_base, bot_token) {
        Ok(hooks) => hooks,
        Err(err) => {
            return Some(json!({
                "ok": false,
                "error": err,
                "webhook_url": webhook_url,
            }));
        }
    };

    // 2. Reconcile both webhook types
    let subscriptions: &[(&str, &str, &str)] = &[
        ("messages", "created", &base_name),
        (
            "attachmentActions",
            "created",
            &format!("{base_name}:cards"),
        ),
    ];

    let mut results = Vec::new();
    let mut all_ok = true;

    for &(resource, event, name) in subscriptions {
        let result = webex_reconcile_one(
            api_base,
            bot_token,
            &existing,
            name,
            &webhook_url,
            resource,
            event,
        );
        if let Some(ref r) = result
            && !r.get("ok").and_then(Value::as_bool).unwrap_or(false)
        {
            all_ok = false;
        }
        results.push(json!({
            "resource": resource,
            "event": event,
            "name": name,
            "result": result,
        }));
    }

    Some(json!({
        "ok": all_ok,
        "webhook_url": webhook_url,
        "webhooks": results,
    }))
}

/// Reconcile a single Webex webhook: find by name → create or update.
fn webex_reconcile_one(
    api_base: &str,
    token: &str,
    existing: &[Value],
    name: &str,
    target_url: &str,
    resource: &str,
    event: &str,
) -> Option<Value> {
    let matching = existing
        .iter()
        .find(|hook| hook.get("name").and_then(Value::as_str) == Some(name));

    if let Some(hook) = matching {
        let hook_id = hook.get("id").and_then(Value::as_str).unwrap_or("");
        let current_url = hook.get("targetUrl").and_then(Value::as_str).unwrap_or("");

        if current_url == target_url {
            operator_log::info(
                module_path!(),
                format!(
                    "[onboard] webex webhook: already up-to-date name={} id={}",
                    name, hook_id
                ),
            );
            return Some(json!({
                "ok": true,
                "webhook_id": hook_id,
                "action": "noop",
            }));
        }

        operator_log::info(
            module_path!(),
            format!(
                "[onboard] webex webhook: updating name={} id={} old_url={}",
                name, hook_id, current_url
            ),
        );
        webex_update_webhook(api_base, token, hook_id, name, target_url)
    } else {
        operator_log::info(
            module_path!(),
            format!(
                "[onboard] webex webhook: creating name={} resource={} event={}",
                name, resource, event
            ),
        );
        webex_create_webhook_with_resource(api_base, token, name, target_url, resource, event)
    }
}

/// List all webhooks registered for the bot.
fn webex_list_webhooks(api_base: &str, token: &str) -> Result<Vec<Value>, String> {
    let url = format!("{}/webhooks", api_base.trim_end_matches('/'));
    match ureq::get(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .call()
    {
        Ok(mut resp) => {
            let raw = resp.body_mut().read_to_string().unwrap_or_default();
            let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
            Ok(parsed
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default())
        }
        Err(err) => Err(format!("GET /webhooks failed: {err}")),
    }
}

/// Create a new Webex webhook for the given resource/event.
fn webex_create_webhook_with_resource(
    api_base: &str,
    token: &str,
    name: &str,
    target_url: &str,
    resource: &str,
    event: &str,
) -> Option<Value> {
    let url = format!("{}/webhooks", api_base.trim_end_matches('/'));
    let body = json!({
        "name": name,
        "targetUrl": target_url,
        "resource": resource,
        "event": event,
    });

    match ureq::post(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .send_json(&body)
    {
        Ok(mut resp) => {
            let status = resp.status().as_u16();
            let raw = resp.body_mut().read_to_string().unwrap_or_default();
            let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
            let hook_id = parsed
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            operator_log::info(
                module_path!(),
                format!(
                    "[onboard] webex webhook: created id={} status={}",
                    hook_id, status
                ),
            );

            Some(json!({
                "ok": (200..300).contains(&status),
                "webhook_url": target_url,
                "webhook_id": hook_id,
                "action": "create",
                "http_status": status,
                "webex_response": parsed,
            }))
        }
        Err(err) => Some(json!({
            "ok": false,
            "error": format!("POST /webhooks failed: {err}"),
            "webhook_url": target_url,
        })),
    }
}

/// Update an existing Webex webhook's target URL.
fn webex_update_webhook(
    api_base: &str,
    token: &str,
    webhook_id: &str,
    name: &str,
    target_url: &str,
) -> Option<Value> {
    let url = format!("{}/webhooks/{}", api_base.trim_end_matches('/'), webhook_id);
    let body = json!({
        "name": name,
        "targetUrl": target_url,
    });

    match ureq::put(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .send_json(&body)
    {
        Ok(mut resp) => {
            let status = resp.status().as_u16();
            let raw = resp.body_mut().read_to_string().unwrap_or_default();
            let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);

            operator_log::info(
                module_path!(),
                format!(
                    "[onboard] webex webhook: updated id={} status={}",
                    webhook_id, status
                ),
            );

            Some(json!({
                "ok": (200..300).contains(&status),
                "webhook_url": target_url,
                "webhook_id": webhook_id,
                "action": "update",
                "http_status": status,
                "webex_response": parsed,
            }))
        }
        Err(err) => Some(json!({
            "ok": false,
            "error": format!("PUT /webhooks/{} failed: {err}", webhook_id),
            "webhook_url": target_url,
        })),
    }
}

// ── Shared helpers ──────────────────────────────────────────────────────────

fn build_webhook_url(public_base_url: &str, provider_id: &str, tenant: &str, team: &str) -> String {
    format!(
        "{}/v1/messaging/ingress/{}/{}/{}",
        public_base_url.trim_end_matches('/'),
        provider_id,
        tenant,
        team,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_output_webhook_result_uses_declared_ops() {
        let output = json!({
            "config_patch": {"public_base_url": "https://demo.example"},
            "webhook_ops": [{"op": "register", "url": "https://demo.example/webhook"}],
            "subscription_ops": [{"op": "sync", "provider": "graph"}],
            "oauth_ops": []
        });

        let result = webhook_result_from_flow_output(Some(&output)).expect("flow result");
        assert_eq!(result["ok"], Value::Bool(true));
        assert_eq!(result["mode"], Value::String("flow_output".to_string()));
        assert_eq!(
            result["webhook_ops"][0]["op"],
            Value::String("register".to_string())
        );
        assert_eq!(
            result["subscription_ops"][0]["op"],
            Value::String("sync".to_string())
        );
    }

    #[test]
    fn flow_output_webhook_result_skips_empty_ops() {
        let output = json!({
            "webhook_ops": [],
            "subscription_ops": [{"op": "sync"}]
        });

        assert!(webhook_result_from_flow_output(Some(&output)).is_none());
    }
}
