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
    dl_inject: Option<(&crate::directline::DirectLineState, &str)>,
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
                    let from_id = envelope
                        .from
                        .as_ref()
                        .map(|f| f.id.as_str())
                        .unwrap_or("?");
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

        for out_envelope in outputs {
            // For webchat-gui with DirectLine, skip the 3-step egress pipeline
            // (render_plan/encode/send_payload) since the WASM component doesn't
            // support those ops. Instead inject the bot response directly into
            // the DirectLine conversation state for client polling.
            if let Some((dl_state, conv_id)) = dl_inject {
                let locale = envelope
                    .metadata
                    .get("locale")
                    .map(String::as_str)
                    .unwrap_or("en");
                let attachments = out_envelope
                    .metadata
                    .get("adaptive_card")
                    .and_then(|card_str| serde_json::from_str::<serde_json::Value>(card_str).ok())
                    .map(|mut card| {
                        // Resolve {{i18n:KEY}} tokens from pack i18n bundle
                        resolve_i18n_tokens(&mut card, &app_pack_path, locale);
                        json!([{
                            "contentType": "application/vnd.microsoft.card.adaptive",
                            "content": card
                        }])
                    });
                // Suppress text when there is an adaptive card attachment to
                // prevent webchat SDK from rendering a redundant text bubble
                // above the card.
                let text = if attachments.is_some() {
                    None
                } else {
                    out_envelope.text.clone()
                };
                if let Some(bot_id) = dl_state.add_bot_activity(conv_id, text, attachments) {
                    operator_log::info(
                        module_path!(),
                        format!(
                            "[webchat] injected bot activity id={bot_id} conv={conv_id} provider={provider}"
                        ),
                    );
                }
                continue;
            }

            // Standard egress pipeline for non-DirectLine providers (Slack, Teams, Webex, etc.)
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
            None,
        )
        .unwrap_err();

        assert!(err.to_string().contains("resolve app pack"));
    }

    #[test]
    fn route_messaging_envelopes_injects_directline_card_reply_without_egress() {
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
        let dl_state = crate::directline::DirectLineState::new();
        assert!(dl_state.create_conversation("conv-1"));

        let mut card_routed = envelope();
        card_routed
            .metadata
            .insert("routeToCardId".to_string(), "welcome".to_string());

        route_messaging_envelopes(
            dir.path(),
            &runner_host,
            "messaging-webchat-gui",
            &OperatorContext {
                tenant: "demo".to_string(),
                team: Some("default".to_string()),
                correlation_id: None,
            },
            vec![card_routed],
            Some((&dl_state, "conv-1")),
        )
        .expect("route envelopes");

        let (activities, watermark) = dl_state
            .get_activities("conv-1", None)
            .expect("directline activities");
        assert_eq!(watermark, "1");
        assert_eq!(activities.len(), 1);
        assert!(activities[0]["text"].is_null());
        assert_eq!(
            activities[0]["attachments"][0]["contentType"],
            "application/vnd.microsoft.card.adaptive"
        );
        assert_eq!(
            activities[0]["attachments"][0]["content"]["body"][0]["text"],
            "Welcome card"
        );
    }

    use std::io::Write;
}
