use anyhow::Context;
use serde_json::{Value as JsonValue, json};

use crate::domains::Domain;
use crate::messaging_dto::{
    EncodeInV1, ProviderPayloadV1, RenderPlanInV1, SendPayloadInV1, TenantHint,
};
use crate::runner_host::{DemoRunnerHost, FlowOutcome, OperatorContext};

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
    payload: ProviderPayloadV1,
    provider_type: impl Into<String>,
    tenant: impl Into<String>,
    team: Option<String>,
) -> SendPayloadInV1 {
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
        );
        assert_eq!(send.v, 1);
        assert_eq!(send.provider_type, "messaging-slack");
        assert_eq!(send.tenant.tenant, "demo");
        assert_eq!(send.tenant.team.as_deref(), Some("ops"));
        assert!(send.reply_scope.is_none());
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
