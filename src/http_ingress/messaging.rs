use std::path::Path;

use base64::Engine as _;
use greentic_types::ChannelMessageEnvelope;
use serde_json::json;

use crate::capabilities::CAP_OAUTH_CARD_V1;
use crate::domains::Domain;
use crate::messaging_app as app;
use crate::messaging_dto::ProviderPayloadV1;
use crate::messaging_egress as egress;
use crate::oauth_session_store::OauthSessionStore;
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

        let provider_type = runner_host.canonical_provider_type(Domain::Messaging, provider);

        for mut out_envelope in outputs {
            // Ensure i18n tokens are resolved in any adaptive card.  The WASM
            // component *should* resolve them, but when running through
            // greentic-runner-desktop the host resolver is not registered so the
            // component falls back to Handlebars which silently eats unresolved
            // `{{i18n:KEY}}` tokens.  Re-read the card from the pack and apply
            // i18n as a safety net.
            ensure_card_i18n_resolved(&mut out_envelope, &app_pack_path);

            // Resolve OAuth card placeholders. Phase 2: also persists a
            // session record so the upcoming /v1/oauth/callback/{provider_id}
            // can recover state + PKCE verifier.
            let session_store = OauthSessionStore::new(bundle.to_path_buf());
            let conversation_id = out_envelope.session_id.clone();
            if let Err(err) = resolve_oauth_card_placeholders(
                &provider_type,
                &mut out_envelope,
                &session_store,
                "oauth-oidc-generic",
                &conversation_id,
                |cap_id, op, input| {
                    let outcome = runner_host.invoke_capability(cap_id, op, input, ctx)?;
                    if !outcome.success {
                        return Err(anyhow::anyhow!(
                            "capability {}:{} failed: {}",
                            cap_id,
                            op,
                            outcome
                                .error
                                .clone()
                                .unwrap_or_else(|| "unknown".to_string())
                        ));
                    }
                    outcome.output.ok_or_else(|| {
                        anyhow::anyhow!(
                            "capability {}:{} returned no structured output",
                            cap_id,
                            op
                        )
                    })
                },
            ) {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "[demo messaging] oauth card resolve failed for provider={} envelope_id={}: {err}; sending unresolved",
                        provider, out_envelope.id
                    ),
                );
            }

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

fn resolve_oauth_card_placeholders(
    provider_type: &str,
    envelope: &mut ChannelMessageEnvelope,
    session_store: &OauthSessionStore,
    provider_pack_id: &str,
    conversation_id: &str,
    mut dispatcher: impl FnMut(&str, &str, &[u8]) -> anyhow::Result<serde_json::Value>,
) -> anyhow::Result<()> {
    let _ = provider_type; // Reserved for future Teams native handling
    let Some(card_str) = envelope.metadata.get("adaptive_card").cloned() else {
        return Ok(());
    };
    if !card_str.contains("oauth://start")
        && !card_str.contains("{{oauth.start_url}}")
        && !card_str.contains("{{oauth.teams.connectionName}}")
    {
        return Ok(());
    }

    // Create a session and persist verifier+challenge for the upcoming callback.
    let team = envelope
        .tenant
        .team
        .as_ref()
        .map(|t| t.as_str())
        .or_else(|| envelope.tenant.team_id.as_ref().map(|t| t.as_str()));
    let provider_id_for_session = derive_provider_id_from_pack(provider_pack_id);
    let ticket = session_store.create(
        &provider_id_for_session,
        provider_pack_id,
        envelope.tenant.tenant_id.as_str(),
        team,
        conversation_id,
    )?;

    // Build the dispatcher input matching CardResolveDispatchInput in
    // oidc-provider-runtime/src/lib.rs (handle_resolve_card).
    let inner_input = serde_json::json!({
        "adaptive_card": card_str,
        "tenant": envelope.tenant.tenant_id.as_str(),
        "state": ticket.state_token,
        "code_challenge": ticket.code_challenge,
        "scopes": serde_json::Value::Null, // provider config supplies default_scopes
        "native_oauth_card": false,
    });
    let input_bytes =
        serde_json::to_vec(&inner_input).map_err(|err| anyhow::anyhow!("serialize: {err}"))?;

    let resolve_result = dispatcher(CAP_OAUTH_CARD_V1, "oauth.card.resolve", &input_bytes)?;

    let resolved_card = resolve_result
        .get("resolved_card")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("oauth.card.resolve output missing resolved_card"))?;

    envelope
        .metadata
        .insert("adaptive_card".to_string(), resolved_card.to_string());

    // Audit fields stored as compact JSON strings (BTreeMap<String,String>).
    let mut audit = resolve_result.clone();
    if let Some(obj) = audit.as_object_mut() {
        obj.remove("resolved_card");
    }
    envelope
        .metadata
        .insert("oauth_card_resolved".to_string(), audit.to_string());
    if let Some(downgrade) = resolve_result.get("downgrade").filter(|v| !v.is_null()) {
        envelope
            .metadata
            .insert("oauth_card_downgrade".to_string(), downgrade.to_string());
    }
    Ok(())
}

/// Derive a provider_id given the pack id. Hardcoded for the only supported
/// OAuth provider pack. TODO: discover from setup-answers.json or capability binding.
fn derive_provider_id_from_pack(provider_pack_id: &str) -> String {
    match provider_pack_id {
        "oauth-oidc-generic" => "github".to_string(),
        other => other.to_string(),
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

        let dispatcher =
            move |cap_id: &str, op: &str, _input: &[u8]| -> anyhow::Result<serde_json::Value> {
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
                // Only `resolved_card` is load-bearing; `start_url` is informational
                // and ends up inside the oauth_card_resolved audit metadata.
                Ok(serde_json::json!({
                    "ok": true,
                    "resolved_card": resolved_card.to_string(),
                    "start_url": resolved_url_for_closure.clone(),
                    "native_oauth_card": false,
                }))
            };

        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        let result = resolve_oauth_card_placeholders(
            "messaging.webchat-gui",
            &mut env,
            &store,
            "oauth-oidc-generic",
            "test-conv-1",
            dispatcher,
        );
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

    #[test]
    fn resolve_oauth_card_placeholders_fails_soft_when_dispatcher_errors() {
        let mut env = envelope_with_oauth_card();
        let original_card = env
            .metadata
            .get("adaptive_card")
            .cloned()
            .expect("seed card");

        let dispatcher =
            |_cap_id: &str, _op: &str, _input: &[u8]| -> anyhow::Result<serde_json::Value> {
                Err(anyhow::anyhow!("capability not installed"))
            };

        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        let result = resolve_oauth_card_placeholders(
            "messaging.webchat-gui",
            &mut env,
            &store,
            "oauth-oidc-generic",
            "test-conv-1",
            dispatcher,
        );

        // The helper propagates the error so the caller can log it. The
        // envelope must be left untouched so the caller can still send the
        // card unresolved as a fail-soft fallback.
        // NOTE: A session file IS created before the dispatcher call (by design).
        assert!(result.is_err(), "dispatcher error should be propagated");
        assert_eq!(
            env.metadata.get("adaptive_card"),
            Some(&original_card),
            "envelope card should be unchanged on dispatcher error"
        );
        assert!(
            !env.metadata.contains_key("oauth_card_resolved"),
            "no audit should be stored on error"
        );
    }

    #[test]
    fn resolve_oauth_card_placeholders_noop_when_no_card_in_metadata() {
        let mut env = envelope(); // no adaptive_card in metadata
        let called = std::cell::Cell::new(false);
        let dispatcher =
            |_cap_id: &str, _op: &str, _input: &[u8]| -> anyhow::Result<serde_json::Value> {
                called.set(true);
                Ok(serde_json::json!({}))
            };

        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        resolve_oauth_card_placeholders(
            "messaging.webchat-gui",
            &mut env,
            &store,
            "oauth-oidc-generic",
            "test-conv-1",
            dispatcher,
        )
        .expect("no-op succeeds");
        assert!(
            !called.get(),
            "dispatcher should not be invoked when no card"
        );
        assert!(
            env.metadata.is_empty(),
            "metadata must be untouched on no-op"
        );
    }

    #[test]
    fn resolve_oauth_card_placeholders_propagates_team_id_when_team_is_none() {
        // Regression test: TenantCtx has both `team` and `team_id`. If only
        // `team_id` is set on the envelope, the session store must still
        // record it. The dispatcher input now uses the new inner_input shape
        // (tenant, state, code_challenge, etc.) rather than the old flat
        // CardRenderer shape. Team propagation is verified via the session
        // file on disk.
        let mut env: ChannelMessageEnvelope = serde_json::from_value(serde_json::json!({
            "id": "msg-team-id-only",
            "tenant": {
                "env": "dev",
                "tenant": "demo",
                "tenant_id": "demo",
                "team_id": "ops",
                "attempt": 0
            },
            "channel": "conv-1",
            "session_id": "conv-1",
            "from": {
                "id": "user-1",
                "kind": "user"
            },
            "text": null,
            "metadata": {}
        }))
        .expect("envelope");

        // Add the OAuth card to metadata (same shape as envelope_with_oauth_card).
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

        let captured_input = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
        let captured_input_for_closure = captured_input.clone();
        let dispatcher =
            move |_cap_id: &str, _op: &str, input: &[u8]| -> anyhow::Result<serde_json::Value> {
                captured_input_for_closure
                    .borrow_mut()
                    .extend_from_slice(input);
                let resolved_card = serde_json::json!({
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.5",
                    "body": [],
                    "actions": [{
                        "type": "Action.OpenUrl",
                        "title": "Login",
                        "url": "https://example.com/oauth"
                    }]
                });
                Ok(serde_json::json!({
                    "ok": true,
                    "resolved_card": resolved_card.to_string(),
                    "native_oauth_card": false,
                }))
            };

        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        resolve_oauth_card_placeholders(
            "messaging.webchat-gui",
            &mut env,
            &store,
            "oauth-oidc-generic",
            "conv-1",
            dispatcher,
        )
        .expect("resolution should succeed");

        // Parse the captured dispatcher input and verify the new inner_input shape.
        let captured = captured_input.borrow().clone();
        let parsed: serde_json::Value =
            serde_json::from_slice(&captured).expect("dispatcher input is valid json");
        // New shape: adaptive_card, tenant (string), state, code_challenge, native_oauth_card
        assert!(
            parsed
                .get("adaptive_card")
                .and_then(|v| v.as_str())
                .is_some(),
            "dispatcher input must contain adaptive_card"
        );
        assert_eq!(
            parsed.get("tenant").and_then(|v| v.as_str()),
            Some("demo"),
            "tenant key should be populated from envelope.tenant.tenant_id"
        );
        assert!(
            parsed
                .get("state")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "state token must be present and non-empty"
        );
        assert!(
            parsed
                .get("code_challenge")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "code_challenge must be present and non-empty"
        );
        assert_eq!(
            parsed.get("native_oauth_card").and_then(|v| v.as_bool()),
            Some(false),
            "native_oauth_card should be false"
        );

        // Verify team propagation reached the session file on disk.
        let sessions_dir = dir.path().join("state/oauth-sessions");
        let session_files: Vec<_> = std::fs::read_dir(&sessions_dir)
            .expect("sessions_dir exists")
            .map(|e| e.expect("readdir entry").path())
            .collect();
        assert_eq!(session_files.len(), 1, "expected exactly one session file");
        let session_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&session_files[0]).expect("read session file"),
        )
        .expect("session file is valid json");
        assert_eq!(
            session_json.get("team"),
            Some(&serde_json::Value::String("ops".to_string())),
            "team should propagate from envelope.tenant.team_id"
        );
        assert_eq!(
            session_json.get("tenant"),
            Some(&serde_json::Value::String("demo".to_string())),
            "tenant should be from envelope.tenant.tenant_id"
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
            8080,
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
            8080,
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
