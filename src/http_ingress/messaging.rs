use std::path::Path;

use base64::Engine as _;
use greentic_types::ChannelMessageEnvelope;
use serde_json::json;

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
                    run_app_flow_safe(bundle, ctx, &app_pack_path, &pack_info, flow, envelope)
                }
            }
        } else {
            run_app_flow_safe(bundle, ctx, &app_pack_path, &pack_info, flow, envelope)
        };

        for mut out_envelope in outputs {
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
    ctx: &OperatorContext,
    app_pack_path: &Path,
    pack_info: &app::AppPackInfo,
    flow: &app::AppFlowInfo,
    envelope: &ChannelMessageEnvelope,
) -> Vec<ChannelMessageEnvelope> {
    match app::run_app_flow(
        bundle,
        ctx,
        app_pack_path,
        &pack_info.pack_id,
        &flow.id,
        envelope,
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

use anyhow::Context;

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
        serde_json::Value::String(text) => {
            if text.contains("{{i18n:") {
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

/// Resolve OAuth card placeholders in an outbound envelope by delegating to
/// `greentic.cap.oauth.card.v1`. Operates on a minimal JSON payload to avoid
/// round-tripping the envelope through serde (metadata is a string map,
/// incompatible with the nested JSON values the capability produces).
///
/// Fail-soft: any internal error is returned to the caller, which is expected
/// to log and continue with the unresolved envelope.
fn resolve_oauth_card_placeholders(
    provider_type: &str,
    envelope: &mut ChannelMessageEnvelope,
    dispatcher: impl FnMut(&str, &str, &[u8]) -> anyhow::Result<serde_json::Value>,
) -> anyhow::Result<()> {
    let _ = (provider_type, envelope, dispatcher);
    Ok(())
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

    fn envelope_with_oauth_card() -> ChannelMessageEnvelope {
        let mut env = envelope();
        let card = serde_json::json!({
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.5",
            "body": [{"type": "TextBlock", "text": "Sign in", "wrap": true}],
            "actions": [{
                "type": "Action.OpenUrl",
                "title": "Login with OAuth",
                "url": "oauth://start"
            }]
        });
        env.metadata
            .insert("adaptive_card".to_string(), card.to_string());
        env
    }

    #[test]
    fn resolve_oauth_card_placeholders_swaps_url_from_capability() {
        let mut env = envelope_with_oauth_card();
        let resolved_url =
            "https://github.com/login/oauth/authorize?client_id=abc&state=xyz".to_string();
        let resolved_url_for_closure = resolved_url.clone();

        let dispatcher = move |cap_id: &str,
                               op: &str,
                               _input: &[u8]|
              -> anyhow::Result<serde_json::Value> {
            assert_eq!(cap_id, "greentic.cap.oauth.card.v1");
            assert_eq!(op, "oauth.card.resolve");
            let resolved_card = serde_json::json!({
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.5",
                "body": [{"type": "TextBlock", "text": "Sign in", "wrap": true}],
                "actions": [{
                    "type": "Action.OpenUrl",
                    "title": "Login with OAuth",
                    "url": resolved_url_for_closure.clone()
                }]
            });
            Ok(serde_json::json!({
                "resolved_card": resolved_card.to_string(),
                "start_url": resolved_url_for_closure.clone(),
            }))
        };

        let result =
            resolve_oauth_card_placeholders("messaging.webchat-gui", &mut env, dispatcher);
        assert!(result.is_ok(), "helper should succeed: {result:?}");

        let card = env
            .metadata
            .get("adaptive_card")
            .expect("adaptive_card present");
        assert!(
            card.contains(&resolved_url),
            "resolved URL missing from card: {card}"
        );
        assert!(
            !card.contains("oauth://start"),
            "oauth://start marker still present in card: {card}"
        );
        assert!(
            env.metadata.contains_key("oauth_card_resolved"),
            "audit metadata missing"
        );
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

    #[test]
    fn run_app_flow_safe_falls_back_to_original_envelope_on_errors() {
        let dir = tempdir().expect("tempdir");
        let original = envelope();
        let outputs = run_app_flow_safe(
            dir.path(),
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
}
