use anyhow::Context;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use greentic_deploy_spec::DeploymentId;
use serde_json::{Value as JsonValue, json};

use crate::deployment_routes::DeploymentConfigOverrides;
use crate::domains::Domain;
use crate::messaging_dto::{
    EncodeInV1, ProviderPayloadV1, RenderPlanInV1, SendPayloadInV1, TenantHint,
};
use crate::runner_host::{DemoRunnerHost, FlowOutcome, OperatorContext};

/// Pick the override map for a `(deployment_id, pack_id)` pair, materialized
/// as a JSON object ready to hand to [`build_send_payload`]. Returns `None`
/// when no overrides are configured for the pack or the inner map is empty —
/// the egress path skips config injection in that case (preserves the
/// "no config" behaviour for packs the operator hasn't touched).
pub fn pack_config_overrides_as_json(
    table: &DeploymentConfigOverrides,
    deployment_id: DeploymentId,
    pack_id: &str,
) -> Option<JsonValue> {
    table
        .get(&deployment_id)
        .and_then(|by_pack| by_pack.get(pack_id))
        .filter(|cfg| !cfg.is_empty())
        .map(|cfg| {
            serde_json::to_value(cfg).expect("BTreeMap<String, JsonValue> serializes infallibly")
        })
}

pub fn build_render_plan_input(message: JsonValue) -> RenderPlanInV1 {
    RenderPlanInV1 { v: 1, message }
}

pub fn build_encode_input(message: JsonValue, plan: JsonValue) -> EncodeInV1 {
    EncodeInV1 {
        v: 1,
        message,
        plan,
    }
}

pub fn build_send_payload(
    mut payload: ProviderPayloadV1,
    provider_type: impl Into<String>,
    tenant: impl Into<String>,
    team: Option<String>,
    config: Option<JsonValue>,
) -> SendPayloadInV1 {
    if let Some(config) = config.as_ref() {
        inject_config_into_envelope_payload(&mut payload, config);
    }
    SendPayloadInV1 {
        v: 1,
        provider_type: provider_type.into(),
        payload,
        tenant: TenantHint {
            tenant: tenant.into(),
            team,
            user: None,
            correlation_id: None,
        },
        reply_scope: None,
        config,
    }
}

fn inject_config_into_envelope_payload(payload: &mut ProviderPayloadV1, config: &JsonValue) {
    if config.as_object().is_none_or(serde_json::Map::is_empty) {
        return;
    }
    if !payload.content_type.contains("json") {
        return;
    }
    let Ok(bytes) = STANDARD.decode(&payload.body_b64) else {
        return;
    };
    let Ok(mut body) = serde_json::from_slice::<JsonValue>(&bytes) else {
        return;
    };
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    // Only augment Greentic envelope-shaped payloads. Provider-native JSON bodies
    // may be sent directly to third-party APIs and must not receive config.
    if !(obj.contains_key("tenant") && obj.contains_key("session_id")) {
        return;
    }
    obj.entry("config".to_string())
        .or_insert_with(|| config.clone());
    if let Ok(bytes) = serde_json::to_vec(&body) {
        payload.body_b64 = STANDARD.encode(bytes);
    }
}

pub fn render_plan(
    runner_host: &DemoRunnerHost,
    ctx: &OperatorContext,
    provider: &str,
    message: JsonValue,
) -> anyhow::Result<JsonValue> {
    let input = build_render_plan_input(message);
    let outcome = invoke_flow(
        runner_host,
        ctx,
        provider,
        "render_plan",
        serde_json::to_value(&input)?,
    )?;
    let validated = ensure_success(&outcome, provider, "render_plan")?;
    Ok(validated.output.clone().unwrap_or_else(|| json!({})))
}

pub fn encode_payload(
    runner_host: &DemoRunnerHost,
    ctx: &OperatorContext,
    provider: &str,
    message: JsonValue,
    plan: JsonValue,
) -> anyhow::Result<ProviderPayloadV1> {
    let input = build_encode_input(message, plan);
    let outcome = invoke_flow(
        runner_host,
        ctx,
        provider,
        "encode",
        serde_json::to_value(&input)?,
    )?;
    let validated = ensure_success(&outcome, provider, "encode")?;
    let value = validated.output.clone().unwrap_or_else(|| json!({}));
    let payload_value = value.get("payload").cloned().unwrap_or(value);
    serde_json::from_value(payload_value)
        .context("failed to parse ProviderPayloadV1 from encode output")
}

fn invoke_flow(
    runner_host: &DemoRunnerHost,
    ctx: &OperatorContext,
    provider: &str,
    op: &str,
    payload: JsonValue,
) -> anyhow::Result<FlowOutcome> {
    let input_bytes = serde_json::to_vec(&payload)?;
    runner_host.invoke_provider_op(Domain::Messaging, provider, op, &input_bytes, ctx)
}

fn ensure_success<'a>(
    outcome: &'a FlowOutcome,
    provider: &str,
    op: &str,
) -> anyhow::Result<&'a FlowOutcome> {
    if outcome.success {
        Ok(outcome)
    } else {
        Err(anyhow::anyhow!(
            "{provider}.{op} failed: {}",
            outcome
                .error
                .clone()
                .unwrap_or_else(|| "unknown error".to_string())
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_inputs_wrap_message_plan_and_tenant_hints() {
        let render = build_render_plan_input(json!({"text": "hello"}));
        assert_eq!(render.v, 1);
        assert_eq!(render.message["text"], "hello");

        let encode = build_encode_input(json!({"text": "hello"}), json!({"steps": []}));
        assert_eq!(encode.v, 1);
        assert_eq!(encode.plan["steps"], json!([]));

        let send = build_send_payload(
            ProviderPayloadV1 {
                content_type: "application/json".to_string(),
                body_b64: "e30=".to_string(),
                metadata_json: Some("{}".to_string()),
                metadata: None,
            },
            "messaging-slack",
            "demo",
            Some("ops".to_string()),
            Some(json!({"tenant_id": "tenant-1"})),
        );
        assert_eq!(send.v, 1);
        assert_eq!(send.provider_type, "messaging-slack");
        assert_eq!(send.tenant.tenant, "demo");
        assert_eq!(send.tenant.team.as_deref(), Some("ops"));
        assert!(send.reply_scope.is_none());
        assert_eq!(send.config, Some(json!({"tenant_id": "tenant-1"})));
    }

    #[test]
    fn build_send_payload_injects_config_into_envelope_body() {
        let envelope = json!({
            "tenant": {"tenant": "demo"},
            "session_id": "session-1",
            "text": "hello"
        });
        let send = build_send_payload(
            ProviderPayloadV1 {
                content_type: "application/json".to_string(),
                body_b64: STANDARD.encode(serde_json::to_vec(&envelope).unwrap()),
                metadata_json: None,
                metadata: None,
            },
            "messaging-teams",
            "demo",
            None,
            Some(json!({"tenant_id": "tenant-1", "client_id": "client-1"})),
        );
        let body = STANDARD.decode(send.payload.body_b64).unwrap();
        let body: JsonValue = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["config"]["tenant_id"], "tenant-1");
        assert_eq!(
            send.config,
            Some(json!({"tenant_id": "tenant-1", "client_id": "client-1"}))
        );
    }

    #[test]
    fn build_send_payload_does_not_inject_config_into_provider_native_body() {
        let native = json!({
            "channel": "C123",
            "text": "hello"
        });
        let send = build_send_payload(
            ProviderPayloadV1 {
                content_type: "application/json".to_string(),
                body_b64: STANDARD.encode(serde_json::to_vec(&native).unwrap()),
                metadata_json: None,
                metadata: None,
            },
            "messaging-slack",
            "demo",
            None,
            Some(json!({"token": "secret"})),
        );
        let body = STANDARD.decode(send.payload.body_b64).unwrap();
        let body: JsonValue = serde_json::from_slice(&body).unwrap();
        assert!(body.get("config").is_none());
    }

    #[test]
    fn pack_config_overrides_round_trip_through_send_payload_body() {
        // End-to-end projection: BundleDeployment.config_overrides →
        // routing.deployment_config_overrides → pack_config_overrides_as_json →
        // build_send_payload → injected into the envelope body. This is the
        // chain run_reply_egress walks at egress time.
        use std::collections::BTreeMap;

        let pack_id = "telegram-pack";
        let dep_id = DeploymentId::new();
        let mut table = DeploymentConfigOverrides::new();
        table.insert(
            dep_id,
            BTreeMap::from([(
                pack_id.to_string(),
                BTreeMap::from([
                    (
                        "api_base_url".to_string(),
                        JsonValue::String("https://staging.example.com".to_string()),
                    ),
                    (
                        "default_chat_id".to_string(),
                        JsonValue::String("-100123".to_string()),
                    ),
                ]),
            )]),
        );

        // Lookup returns the per-pack overrides as a JSON object.
        let config = pack_config_overrides_as_json(&table, dep_id, pack_id)
            .expect("override config must be present for the matched pack");
        assert_eq!(config["api_base_url"], "https://staging.example.com");

        // Cross-pack lookup: same deployment, different pack → None.
        assert!(pack_config_overrides_as_json(&table, dep_id, "slack-pack").is_none());

        // build_send_payload injects the looked-up config into the envelope body.
        let envelope = json!({
            "tenant": {"tenant": "demo"},
            "session_id": "s-1",
            "text": "hello",
        });
        let payload = ProviderPayloadV1 {
            content_type: "application/json".to_string(),
            body_b64: STANDARD.encode(serde_json::to_vec(&envelope).unwrap()),
            metadata_json: None,
            metadata: None,
        };
        let send = build_send_payload(payload, "messaging-telegram", "demo", None, Some(config));
        let body = STANDARD.decode(&send.payload.body_b64).unwrap();
        let body: JsonValue = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["config"]["api_base_url"], "https://staging.example.com",
            "config_overrides must reach the WASM provider via the envelope body"
        );
        assert_eq!(body["config"]["default_chat_id"], "-100123");
    }

    #[test]
    fn ensure_success_returns_errors_with_provider_and_op_context() {
        let ok = FlowOutcome {
            success: true,
            output: Some(
                json!({"payload": {"body_b64": "e30=", "content_type": "application/json"}}),
            ),
            raw: None,
            error: None,
            mode: crate::runner_host::RunnerExecutionMode::Exec,
        };
        assert!(ensure_success(&ok, "provider-a", "encode").is_ok());

        let failed = FlowOutcome {
            success: false,
            output: None,
            raw: None,
            error: Some("boom".to_string()),
            mode: crate::runner_host::RunnerExecutionMode::Exec,
        };
        match ensure_success(&failed, "provider-a", "encode") {
            Ok(_) => panic!("expected error"),
            Err(err) => assert!(err.to_string().contains("provider-a.encode failed: boom")),
        }
    }
}
