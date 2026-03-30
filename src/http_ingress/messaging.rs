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
                Some(card_json) => {
                    operator_log::info(
                        module_path!(),
                        format!(
                            "[demo messaging] card routing: {} -> card asset found",
                            route_to_card
                        ),
                    );
                    let mut reply = envelope.clone();
                    reply.metadata.insert(
                        "adaptive_card".to_string(),
                        serde_json::to_string(&card_json).unwrap_or_default(),
                    );
                    let summary = card_json
                        .get("body")
                        .and_then(|b| b.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|item| item.get("text"))
                        .and_then(|t| t.as_str())
                        .unwrap_or(route_to_card)
                        .to_string();
                    reply.text = Some(summary);
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
                let text = out_envelope.text.clone();
                let attachments = out_envelope
                    .metadata
                    .get("adaptive_card")
                    .and_then(|card_str| serde_json::from_str::<serde_json::Value>(card_str).ok())
                    .map(|card| {
                        json!([{
                            "contentType": "application/vnd.microsoft.card.adaptive",
                            "content": card
                        }])
                    });
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
