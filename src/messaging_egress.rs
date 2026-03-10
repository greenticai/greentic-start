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
