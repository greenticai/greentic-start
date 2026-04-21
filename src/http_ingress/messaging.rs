use std::path::Path;

use base64::Engine as _;
use greentic_types::ChannelMessageEnvelope;
use greentic_types::{EnvId, StateKey, TenantCtx, TenantId};
use serde_json::{Value as JsonValue, json};

use crate::domains::Domain;
use crate::messaging_app as app;
use crate::messaging_dto::ProviderPayloadV1;
use crate::messaging_egress as egress;
use crate::operator_log;
use crate::runner_host::{DemoRunnerHost, OperatorContext};

pub(super) fn route_messaging_envelopes(
    bundle: &Path,
    runner_host: &DemoRunnerHost,
    provider: &str,
    ctx: &OperatorContext,
    envelopes: Vec<ChannelMessageEnvelope>,
) -> anyhow::Result<()> {
    let team = ctx.team.as_deref();
    let app_pack_path = app::resolve_app_pack_path(bundle, &ctx.tenant, team, None)
        .context("resolve app pack for messaging pipeline")?;
    let pack_info = app::load_app_pack_info(&app_pack_path).context("load app pack manifest")?;
    let flow = app::select_app_flow(&pack_info).context("select app default flow")?;

    operator_log::info(
        module_path!(),
        format!(
            "[demo messaging] routing {} envelope(s) through app flow={} pack={}",
            envelopes.len(),
            flow.id,
            pack_info.pack_id
        ),
    );

    for envelope in &envelopes {
        let outputs = if let Some(route_to_card) = envelope.metadata.get("routeToCardId") {
            match read_card_from_pack(&app_pack_path, route_to_card) {
                Some(mut card_json) => {
                    operator_log::info(
                        module_path!(),
                        format!(
                            "[demo messaging] card routing: {} -> card asset found",
                            route_to_card
                        ),
                    );
                    let from_id = envelope.from.as_ref().map(|f| f.id.as_str()).unwrap_or("?");
                    crate::flow_log::log(
                        "CARD",
                        &format!(
                            "pack={} routeToCardId={} tenant={} from={}",
                            pack_info.pack_id, route_to_card, ctx.tenant, from_id
                        ),
                    );
                    // Resolve {{i18n:KEY}} tokens from pack i18n bundle
                    let locale = envelope
                        .metadata
                        .get("locale")
                        .map(String::as_str)
                        .unwrap_or("en");
                    resolve_i18n_tokens(&mut card_json, &app_pack_path, locale);
                    // Replace ${key} placeholders and carry form data forward
                    // through Action.Submit buttons so subsequent cards can
                    // also access the original form values.
                    resolve_placeholders(&mut card_json, &envelope.metadata);
                    carry_form_data_to_actions(&mut card_json, &envelope.metadata);
                    let mut reply = envelope.clone();
                    reply.metadata.insert(
                        "adaptive_card".to_string(),
                        serde_json::to_string(&card_json).unwrap_or_default(),
                    );
                    reply.text = None;
                    vec![reply]
                }
                None => {
                    operator_log::warn(
                        module_path!(),
                        format!(
                            "[demo messaging] card routing: {} -> card asset NOT found, using app flow",
                            route_to_card
                        ),
                    );
                    run_app_flow_safe(
                        bundle,
                        runner_host,
                        ctx,
                        &app_pack_path,
                        &pack_info,
                        flow,
                        envelope,
                    )
                }
            }
        } else {
            run_app_flow_safe(
                bundle,
                runner_host,
                ctx,
                &app_pack_path,
                &pack_info,
                flow,
                envelope,
            )
        };
        update_conversation_history(runner_host, ctx, envelope, &outputs);

        for mut out_envelope in outputs {
            if let Some(team) = &ctx.team {
                out_envelope
                    .metadata
                    .entry("team".to_string())
                    .or_insert_with(|| team.clone());
            }

            // Ensure i18n tokens are resolved in any adaptive card.  The WASM
            // component *should* resolve them, but when running through
            // greentic-runner-desktop the host resolver is not registered so the
            // component falls back to Handlebars which silently eats unresolved
            // `{{i18n:KEY}}` tokens.  Re-read the card from the pack and apply
            // i18n as a safety net.
            ensure_card_i18n_resolved(&mut out_envelope, &app_pack_path);

            // Standard egress pipeline: render → encode → send_payload.
            // All providers (including webchat) use this path. The webchat provider's
            // send_payload writes bot activities to the conversation state store for
            // client polling via DirectLine GET /activities.
            let message_value = serde_json::to_value(&out_envelope)?;
            let has_adaptive_card = message_value
                .get("metadata")
                .and_then(|m| m.get("adaptive_card"))
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            operator_log::info(
                module_path!(),
                format!(
                    "[demo messaging] pre-encode adaptive_card={} text_present={} session_id={} route={} tenant={} metadata_keys={}",
                    has_adaptive_card,
                    message_value
                        .get("text")
                        .and_then(|v| v.as_str())
                        .map(|s| !s.is_empty())
                        .unwrap_or(false),
                    message_value
                        .get("session_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    message_value
                        .get("metadata")
                        .and_then(|m| m.get("route"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    message_value
                        .get("metadata")
                        .and_then(|m| m.get("tenant"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    message_value
                        .get("metadata")
                        .and_then(|v| v.as_object())
                        .map(|o| o.keys().cloned().collect::<Vec<_>>().join(","))
                        .unwrap_or_default()
                ),
            );

            let plan = match egress::render_plan(runner_host, ctx, provider, message_value.clone())
            {
                Ok(plan) => plan,
                Err(err) => {
                    operator_log::warn(
                        module_path!(),
                        format!("[demo messaging] render_plan failed: {err}; using empty plan"),
                    );
                    json!({})
                }
            };

            let payload = match egress::encode_payload(
                runner_host,
                ctx,
                provider,
                message_value.clone(),
                plan,
            ) {
                Ok(payload) => payload,
                Err(err) => {
                    operator_log::warn(
                        module_path!(),
                        format!("[demo messaging] encode failed: {err}; using fallback payload"),
                    );
                    let body_bytes = serde_json::to_vec(&message_value)?;
                    ProviderPayloadV1 {
                        content_type: "application/json".to_string(),
                        body_b64: base64::engine::general_purpose::STANDARD.encode(&body_bytes),
                        metadata_json: Some(serde_json::to_string(&message_value)?),
                        metadata: None,
                    }
                }
            };

            let provider_type = runner_host.canonical_provider_type(Domain::Messaging, provider);
            let send_input =
                egress::build_send_payload(payload, &provider_type, &ctx.tenant, ctx.team.clone());
            let send_bytes = serde_json::to_vec(&send_input)?;
            let outcome = runner_host.invoke_provider_op(
                Domain::Messaging,
                provider,
                "send_payload",
                &send_bytes,
                ctx,
            )?;

            let provider_ok = outcome
                .output
                .as_ref()
                .and_then(|v| v.get("ok"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if outcome.success && provider_ok {
                operator_log::info(
                    module_path!(),
                    format!(
                        "[demo messaging] send succeeded provider={} envelope_id={}",
                        provider, out_envelope.id
                    ),
                );
            } else {
                let provider_msg = outcome
                    .output
                    .as_ref()
                    .and_then(|v| v.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let err_msg = outcome
                    .error
                    .clone()
                    .unwrap_or_else(|| provider_msg.to_string());
                operator_log::error(
                    module_path!(),
                    format!(
                        "[demo messaging] send failed provider={} provider_ok={} err={}",
                        provider, provider_ok, err_msg
                    ),
                );
            }
        }
    }
    Ok(())
}

fn read_card_from_pack(pack_path: &Path, card_key: &str) -> Option<serde_json::Value> {
    let file = std::fs::File::open(pack_path).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;
    let asset_path = format!("assets/cards/{card_key}.json");
    let mut entry = archive.by_name(&asset_path).ok()?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

fn run_app_flow_safe(
    bundle: &Path,
    runner_host: &DemoRunnerHost,
    ctx: &OperatorContext,
    app_pack_path: &Path,
    pack_info: &app::AppPackInfo,
    flow: &app::AppFlowInfo,
    envelope: &ChannelMessageEnvelope,
) -> Vec<ChannelMessageEnvelope> {
    if should_ignore_empty_envelope(envelope) {
        operator_log::info(
            module_path!(),
            format!(
                "[demo messaging] ignoring empty bootstrap envelope id={} session={}",
                envelope.id, envelope.session_id
            ),
        );
        return Vec::new();
    }

    let messages = conversation_messages_for_envelope(runner_host, ctx, envelope);
    match app::run_app_flow(
        bundle,
        ctx,
        app_pack_path,
        &pack_info.pack_id,
        &flow.id,
        envelope,
        messages,
    ) {
        Ok(outputs) => outputs,
        Err(err) => {
            operator_log::error(
                module_path!(),
                format!("[demo messaging] app flow failed: {err}"),
            );
            vec![envelope.clone()]
        }
    }
}

fn should_ignore_empty_envelope(envelope: &ChannelMessageEnvelope) -> bool {
    if !envelope.attachments.is_empty() {
        return false;
    }

    let has_text = envelope
        .text
        .as_deref()
        .is_some_and(|text| !text.trim().is_empty());
    if has_text {
        return false;
    }

    let action_keys = [
        "routeToCardId",
        "toCardId",
        "action_id",
        "adaptive_card",
        "mcp_wizard",
        "mcp_operation",
    ];
    !action_keys
        .iter()
        .any(|key| envelope.metadata.contains_key(*key))
}

use anyhow::Context;

const CONVERSATION_MESSAGE_LIMIT: usize = 12;
const CONVERSATION_HISTORY_LIMIT: usize = 24;
const CONVERSATION_STATE_PREFIX: &str = "runner";

fn conversation_history_state_key(team: &str, session_id: &str) -> StateKey {
    StateKey::from(format!("messaging:history:{team}:{session_id}"))
}

fn conversation_messages_for_envelope(
    runner_host: &DemoRunnerHost,
    ctx: &OperatorContext,
    envelope: &ChannelMessageEnvelope,
) -> Option<JsonValue> {
    let tenant_ctx = TenantCtx::new(
        EnvId::new(crate::secrets_setup::resolve_env(None)).ok()?,
        TenantId::new(ctx.tenant.clone()).ok()?,
    );
    let team = ctx
        .team
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("_");
    let session_id = envelope.session_id.trim();
    if session_id.is_empty() {
        return None;
    }
    let env = crate::secrets_setup::resolve_env(None);
    let history_key = conversation_history_state_key(team, session_id);
    if let Some(messages) = runner_host
        .read_state_json(&tenant_ctx, CONVERSATION_STATE_PREFIX, &history_key)
        .ok()
        .flatten()
        .and_then(|value| value.get("messages").cloned())
        .and_then(|value| value.as_array().cloned())
        .filter(|messages| !messages.is_empty())
    {
        let start = messages.len().saturating_sub(CONVERSATION_MESSAGE_LIMIT);
        return Some(JsonValue::Array(messages[start..].to_vec()));
    }

    let key = StateKey::from(format!(
        "webchat:conv:{}:{}:{}:{}",
        env, ctx.tenant, team, session_id
    ));
    let value = runner_host
        .read_state_json(&tenant_ctx, "runner", &key)
        .ok()??;
    let activities = value.get("activities")?.as_array()?;
    let current_user = envelope
        .from
        .as_ref()
        .map(|from| from.id.as_str())
        .unwrap_or("anonymous");

    let messages = activities
        .iter()
        .filter(|activity| activity.get("type").and_then(JsonValue::as_str) == Some("message"))
        .filter_map(|activity| {
            let text = activity
                .get("text")
                .and_then(JsonValue::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())?;
            let from_id = activity
                .get("from")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            let role = if from_id == "bot" {
                "assistant"
            } else if from_id == current_user || !from_id.is_empty() {
                "user"
            } else {
                return None;
            };
            Some(json!({
                "role": role,
                "content": text,
            }))
        })
        .collect::<Vec<_>>();

    if messages.is_empty() {
        None
    } else {
        let start = messages.len().saturating_sub(CONVERSATION_MESSAGE_LIMIT);
        Some(JsonValue::Array(messages[start..].to_vec()))
    }
}

fn update_conversation_history(
    runner_host: &DemoRunnerHost,
    ctx: &OperatorContext,
    envelope: &ChannelMessageEnvelope,
    outputs: &[ChannelMessageEnvelope],
) {
    let session_id = envelope.session_id.trim();
    if session_id.is_empty() {
        return;
    }
    let env = match EnvId::new(crate::secrets_setup::resolve_env(None)) {
        Ok(value) => value,
        Err(_) => return,
    };
    let tenant = match TenantId::new(ctx.tenant.clone()) {
        Ok(value) => value,
        Err(_) => return,
    };
    let tenant_ctx = TenantCtx::new(env, tenant);
    let team = ctx
        .team
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("_");
    let key = conversation_history_state_key(team, session_id);

    let mut messages = runner_host
        .read_state_json(&tenant_ctx, CONVERSATION_STATE_PREFIX, &key)
        .ok()
        .flatten()
        .and_then(|value| value.get("messages").cloned())
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();

    if let Some(text) = envelope
        .text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let entry = json!({
            "role": "user",
            "content": text,
        });
        if messages.last() != Some(&entry) {
            messages.push(entry);
        }
    }

    for output in outputs {
        if let Some(text) = output
            .text
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let entry = json!({
                "role": "assistant",
                "content": text,
            });
            if messages.last() != Some(&entry) {
                messages.push(entry);
            }
        }
    }

    if messages.is_empty() {
        return;
    }
    let start = messages.len().saturating_sub(CONVERSATION_HISTORY_LIMIT);
    let payload = json!({
        "messages": messages[start..].to_vec(),
    });
    if let Err(err) =
        runner_host.write_state_json(&tenant_ctx, CONVERSATION_STATE_PREFIX, &key, &payload)
    {
        operator_log::warn(
            module_path!(),
            format!(
                "[demo messaging] failed to persist conversation history session={} err={err}",
                session_id
            ),
        );
    }
}

/// Keys that are part of the card routing protocol and should not be forwarded
/// as user-supplied form data into action buttons.
const ROUTING_META_KEYS: &[&str] = &[
    "routeToCardId",
    "toCardId",
    "action_id",
    "adaptive_card",
    "locale",
    "autoStart",
    "mcp_wizard",
    "mcp_operation",
];

/// Inject form data from envelope metadata into every `Action.Submit` `data`
/// object found in the card.  This ensures that when a user clicks a button on
/// a display-only card (no input fields), the form data collected in a previous
/// card is forwarded to the next card transition.
fn carry_form_data_to_actions(
    card: &mut serde_json::Value,
    metadata: &std::collections::BTreeMap<String, String>,
) {
    let form_fields: Vec<(String, String)> = metadata
        .iter()
        .filter(|(k, _)| !ROUTING_META_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if form_fields.is_empty() {
        return;
    }
    inject_form_data_recursive(card, &form_fields);
}

fn inject_form_data_recursive(value: &mut serde_json::Value, fields: &[(String, String)]) {
    match value {
        serde_json::Value::Object(map) => {
            // If this is an Action.Submit, inject form data into its "data" object
            if map.get("type").and_then(|v| v.as_str()) == Some("Action.Submit")
                && let Some(data) = map.get_mut("data").and_then(|d| d.as_object_mut())
            {
                for (k, v) in fields {
                    if !data.contains_key(k) {
                        data.insert(k.clone(), serde_json::Value::String(v.clone()));
                    }
                }
            }
            for val in map.values_mut() {
                inject_form_data_recursive(val, fields);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                inject_form_data_recursive(item, fields);
            }
        }
        _ => {}
    }
}

/// Replace `${key}` placeholders in card JSON strings with values looked up
/// from the provided metadata map.  This is the lightweight binding pass used
/// by the card-routing shortcut so that form data from a previous Action.Submit
/// is visible in the next card (e.g. a review/confirmation screen).
fn resolve_placeholders(
    value: &mut serde_json::Value,
    metadata: &std::collections::BTreeMap<String, String>,
) {
    match value {
        serde_json::Value::String(text) if text.contains("${") => {
            let mut output = String::with_capacity(text.len());
            let mut rest = text.as_str();
            loop {
                let Some(start) = rest.find("${") else {
                    output.push_str(rest);
                    break;
                };
                output.push_str(&rest[..start]);
                let after = &rest[start + 2..];
                let Some(end) = after.find('}') else {
                    output.push_str(&rest[start..]);
                    break;
                };
                let key = after[..end].trim();
                if let Some(val) = metadata.get(key) {
                    output.push_str(val);
                } else {
                    // Keep the original placeholder when no value is found
                    output.push_str(&rest[start..start + 2 + end + 1]);
                }
                rest = &after[end + 1..];
            }
            *text = output;
        }
        serde_json::Value::Array(items) => {
            for item in items {
                resolve_placeholders(item, metadata);
            }
        }
        serde_json::Value::Object(map) => {
            for val in map.values_mut() {
                resolve_placeholders(val, metadata);
            }
        }
        _ => {}
    }
}

/// Read i18n bundle from pack and resolve `{{i18n:KEY}}` tokens in card JSON.
fn resolve_i18n_tokens(card: &mut serde_json::Value, pack_path: &Path, locale: &str) {
    let bundle = read_i18n_bundle(pack_path, locale).or_else(|| read_i18n_bundle(pack_path, "en"));
    let Some(bundle) = bundle else { return };
    replace_tokens_recursive(card, &bundle);
}

fn read_i18n_bundle(
    pack_path: &Path,
    locale: &str,
) -> Option<std::collections::HashMap<String, String>> {
    let file = std::fs::File::open(pack_path).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;
    let asset_path = format!("assets/i18n/{locale}.json");
    let mut entry = archive.by_name(&asset_path).ok()?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

fn replace_tokens_recursive(
    value: &mut serde_json::Value,
    bundle: &std::collections::HashMap<String, String>,
) {
    match value {
        serde_json::Value::String(text) if text.contains("{{i18n:") => {
            let mut output = String::with_capacity(text.len());
            let mut rest = text.as_str();
            loop {
                let Some(start) = rest.find("{{i18n:") else {
                    output.push_str(rest);
                    break;
                };
                output.push_str(&rest[..start]);
                let token_start = start + "{{i18n:".len();
                let after = &rest[token_start..];
                let Some(end) = after.find("}}") else {
                    output.push_str(&rest[start..]);
                    break;
                };
                let key = after[..end].trim();
                output.push_str(bundle.get(key).map(String::as_str).unwrap_or(key));
                rest = &after[end + 2..];
            }
            *text = output;
        }
        serde_json::Value::Array(items) => {
            for item in items {
                replace_tokens_recursive(item, bundle);
            }
        }
        serde_json::Value::Object(map) => {
            for val in map.values_mut() {
                replace_tokens_recursive(val, bundle);
            }
        }
        _ => {}
    }
}

/// Re-read the adaptive card from the pack and apply i18n when the card has
/// empty text fields.  This compensates for the WASM component not having a
/// host asset resolver for `i18n_bundle_path` when running through the desktop
/// runner path.
fn ensure_card_i18n_resolved(envelope: &mut ChannelMessageEnvelope, pack_path: &Path) {
    let Some(ac_str) = envelope.metadata.get("adaptive_card") else {
        return;
    };
    let Ok(card) = serde_json::from_str::<serde_json::Value>(ac_str) else {
        return;
    };
    // Only act if the card has a greentic.cardId (cards2pack-generated).
    let card_id = card
        .pointer("/greentic/cardId")
        .and_then(serde_json::Value::as_str);
    let Some(card_id) = card_id else { return };
    // Check if any body text is empty (i18n failed).
    let has_empty_text = card
        .get("body")
        .and_then(serde_json::Value::as_array)
        .map(|body| {
            body.iter().any(|item| {
                item.get("text")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(str::is_empty)
            })
        })
        .unwrap_or(false);
    if !has_empty_text {
        return;
    }
    // Re-read the original card from the pack and apply i18n.
    let Some(mut fresh_card) = read_card_from_pack(pack_path, card_id) else {
        return;
    };
    let locale = envelope
        .metadata
        .get("locale")
        .map(String::as_str)
        .unwrap_or("en");
    resolve_i18n_tokens(&mut fresh_card, pack_path, locale);
    if let Ok(resolved) = serde_json::to_string(&fresh_card) {
        envelope
            .metadata
            .insert("adaptive_card".to_string(), resolved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging_app::{AppFlowInfo, AppPackInfo};
    use crate::secrets_gate;
    use tempfile::tempdir;
    use zip::write::FileOptions;

    fn envelope() -> ChannelMessageEnvelope {
        serde_json::from_value(json!({
            "id": "msg-1",
            "tenant": {
                "env": "dev",
                "tenant": "demo",
                "tenant_id": "demo",
                "team": "default",
                "attempt": 0
            },
            "channel": "conv-1",
            "session_id": "conv-1",
            "from": {
                "id": "user-1",
                "kind": "user"
            },
            "text": "hello",
            "metadata": {}
        }))
        .expect("envelope")
    }

    fn write_test_app_pack(pack_path: &Path) {
        use greentic_types::pack_manifest::{
            PackFlowEntry, PackKind, PackManifest, PackSignatures,
        };
        use greentic_types::{Flow, FlowId, FlowKind, PackId};
        use semver::Version;

        let file = std::fs::File::create(pack_path).expect("create pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())
            .expect("start manifest");
        let flow = Flow {
            schema_version: "flow-v1".to_string(),
            id: FlowId::new("default").expect("flow id"),
            kind: FlowKind::Messaging,
            entrypoints: std::collections::BTreeMap::from([(
                "default".to_string(),
                serde_json::Value::Null,
            )]),
            nodes: Default::default(),
            metadata: Default::default(),
        };
        let manifest = PackManifest {
            schema_version: "pack-v1".into(),
            pack_id: PackId::new("demo-app").expect("pack id"),
            name: Some("demo-app".into()),
            version: Version::parse("0.1.0").expect("version"),
            kind: PackKind::Application,
            publisher: "demo".into(),
            components: Vec::new(),
            flows: vec![PackFlowEntry {
                id: FlowId::new("default").expect("flow id"),
                kind: FlowKind::Messaging,
                flow,
                tags: vec!["default".to_string()],
                entrypoints: vec!["default".to_string()],
            }],
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            secret_requirements: Vec::new(),
            signatures: PackSignatures::default(),
            bootstrap: None,
            extensions: None,
        };
        let bytes = greentic_types::encode_pack_manifest(&manifest).expect("encode manifest");
        zip.write_all(&bytes).expect("write manifest");
        zip.start_file("assets/cards/welcome.json", FileOptions::<()>::default())
            .expect("start card");
        zip.write_all(br#"{"body":[{"text":"Welcome card"}]}"#)
            .expect("write card");
        zip.finish().expect("finish pack");
    }

    #[test]
    fn read_card_from_pack_loads_card_assets_and_handles_missing_cards() {
        let dir = tempdir().expect("tempdir");
        let pack_path = dir.path().join("app.gtpack");
        let file = std::fs::File::create(&pack_path).expect("create pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("assets/cards/welcome.json", FileOptions::<()>::default())
            .expect("start file");
        zip.write_all(br#"{"body":[{"text":"Welcome card"}]}"#)
            .expect("write card");
        zip.finish().expect("finish pack");

        let card = read_card_from_pack(&pack_path, "welcome").expect("card");
        assert_eq!(card["body"][0]["text"], "Welcome card");
        assert!(read_card_from_pack(&pack_path, "missing").is_none());
    }

    fn demo_runner_host(bundle: &Path) -> DemoRunnerHost {
        let discovery = crate::discovery::discover(bundle).expect("discovery");
        let secrets_handle = secrets_gate::resolve_secrets_manager(bundle, "demo", Some("default"))
            .expect("secrets");
        DemoRunnerHost::new(
            bundle.to_path_buf(),
            &discovery,
            None,
            secrets_handle,
            false,
        )
        .expect("runner host")
    }

    #[test]
    fn run_app_flow_safe_falls_back_to_original_envelope_on_errors() {
        let dir = tempdir().expect("tempdir");
        let original = envelope();
        let runner_host = demo_runner_host(dir.path());
        let outputs = run_app_flow_safe(
            dir.path(),
            &runner_host,
            &OperatorContext {
                tenant: "demo".to_string(),
                team: Some("default".to_string()),
                correlation_id: None,
            },
            &dir.path().join("missing.gtpack"),
            &AppPackInfo {
                pack_id: "app-pack".to_string(),
                flows: vec![],
            },
            &AppFlowInfo {
                id: "default".to_string(),
                kind: "messaging".to_string(),
            },
            &original,
        );

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].id, original.id);
        assert_eq!(outputs[0].text, original.text);
    }

    #[test]
    fn run_app_flow_safe_ignores_blank_bootstrap_envelopes() {
        let dir = tempdir().expect("tempdir");
        let mut original = envelope();
        original.text = Some("   ".to_string());
        let runner_host = demo_runner_host(dir.path());

        let outputs = run_app_flow_safe(
            dir.path(),
            &runner_host,
            &OperatorContext {
                tenant: "demo".to_string(),
                team: Some("default".to_string()),
                correlation_id: None,
            },
            &dir.path().join("missing.gtpack"),
            &AppPackInfo {
                pack_id: "app-pack".to_string(),
                flows: vec![],
            },
            &AppFlowInfo {
                id: "default".to_string(),
                kind: "messaging".to_string(),
            },
            &original,
        );

        assert!(outputs.is_empty());
    }

    #[test]
    fn read_card_from_pack_rejects_invalid_card_json() {
        let dir = tempdir().expect("tempdir");
        let pack_path = dir.path().join("app.gtpack");
        let file = std::fs::File::create(&pack_path).expect("create pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("assets/cards/broken.json", FileOptions::<()>::default())
            .expect("start file");
        zip.write_all(b"{not-json").expect("write broken card");
        zip.finish().expect("finish pack");

        assert!(read_card_from_pack(&pack_path, "broken").is_none());
    }

    #[test]
    fn route_messaging_envelopes_errors_when_no_app_pack_is_available() {
        let dir = tempdir().expect("tempdir");
        let discovery = crate::discovery::discover(dir.path()).expect("discovery");
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default"))
                .expect("secrets");
        let runner_host = DemoRunnerHost::new(
            dir.path().to_path_buf(),
            &discovery,
            None,
            secrets_handle,
            false,
        )
        .expect("runner host");

        let err = route_messaging_envelopes(
            dir.path(),
            &runner_host,
            "messaging-webchat",
            &OperatorContext {
                tenant: "demo".to_string(),
                team: Some("default".to_string()),
                correlation_id: None,
            },
            vec![envelope()],
        )
        .unwrap_err();

        assert!(err.to_string().contains("resolve app pack"));
    }

    #[test]
    fn route_messaging_envelopes_card_routing_uses_standard_egress_pipeline() {
        // After removing DirectLine injection, all providers (including webchat)
        // use the standard egress pipeline: render_plan → encode → send_payload.
        // Without a provider pack in the test bundle, egress fails — confirming
        // that webchat now goes through the same path as all other providers.
        let dir = tempdir().expect("tempdir");
        let packs_dir = dir.path().join("packs");
        std::fs::create_dir_all(&packs_dir).expect("packs dir");
        let app_pack = packs_dir.join("default.gtpack");
        write_test_app_pack(&app_pack);

        let discovery = crate::discovery::discover(dir.path()).expect("discovery");
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default"))
                .expect("secrets");
        let runner_host = DemoRunnerHost::new(
            dir.path().to_path_buf(),
            &discovery,
            None,
            secrets_handle,
            false,
        )
        .expect("runner host");

        let mut card_routed = envelope();
        card_routed
            .metadata
            .insert("routeToCardId".to_string(), "welcome".to_string());

        // Without a messaging provider pack, egress fails because render_plan
        // can't find the provider. This proves webchat uses standard egress.
        let result = route_messaging_envelopes(
            dir.path(),
            &runner_host,
            "messaging-webchat",
            &OperatorContext {
                tenant: "demo".to_string(),
                team: Some("default".to_string()),
                correlation_id: None,
            },
            vec![card_routed],
        );
        assert!(
            result.is_err(),
            "expected error because no messaging provider pack is available"
        );
    }

    use std::io::Write;

    #[test]
    fn resolve_placeholders_replaces_known_keys_and_preserves_unknown() {
        let mut card = json!({
            "body": [
                { "type": "FactSet", "facts": [
                    { "title": "Name", "value": "${full_name}" },
                    { "title": "Email", "value": "${email}" },
                    { "title": "Missing", "value": "${unknown_key}" }
                ]}
            ]
        });
        let mut meta = std::collections::BTreeMap::new();
        meta.insert("full_name".to_string(), "Alice".to_string());
        meta.insert("email".to_string(), "alice@example.com".to_string());

        resolve_placeholders(&mut card, &meta);

        assert_eq!(card["body"][0]["facts"][0]["value"], "Alice");
        assert_eq!(card["body"][0]["facts"][1]["value"], "alice@example.com");
        assert_eq!(card["body"][0]["facts"][2]["value"], "${unknown_key}");
    }

    #[test]
    fn carry_form_data_injects_into_action_submit_and_skips_routing_keys() {
        let mut card = json!({
            "actions": [
                {
                    "type": "Action.Submit",
                    "data": { "action_id": "next", "routeToCardId": "success" }
                },
                {
                    "type": "Action.OpenUrl",
                    "url": "https://example.com"
                }
            ]
        });
        let mut meta = std::collections::BTreeMap::new();
        meta.insert("full_name".to_string(), "Alice".to_string());
        meta.insert("routeToCardId".to_string(), "review".to_string());
        meta.insert("action_id".to_string(), "goto_review".to_string());

        carry_form_data_to_actions(&mut card, &meta);

        // Action.Submit should have full_name injected but not routing keys
        let data = &card["actions"][0]["data"];
        assert_eq!(data["full_name"], "Alice");
        assert_eq!(data["action_id"], "next"); // original preserved, not overwritten
        // Action.OpenUrl should be untouched
        assert!(card["actions"][1].get("data").is_none());
    }
}
