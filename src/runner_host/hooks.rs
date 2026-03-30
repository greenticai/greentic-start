#![allow(dead_code)]

use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose};
use greentic_types::cbor::canonical;
use serde_json::Value as JsonValue;

use crate::capabilities::{
    CAP_OAUTH_TOKEN_VALIDATION_V1, CapabilityBinding, HookStage, ResolveScope, is_binding_ready,
};
use crate::operator_log;

use super::DemoRunnerHost;
use super::token_validation::{evaluate_token_validation_output, extract_token_validation_request};
use super::types::{
    HookChainOutcome, HookEvalRequest, HookEvalResponse, OperationEnvelope, OperatorContext,
    TokenValidationDecision,
};

impl DemoRunnerHost {
    pub(super) fn evaluate_hook_chain(
        &self,
        chain: &[CapabilityBinding],
        stage: HookStage,
        envelope: &mut OperationEnvelope,
    ) -> anyhow::Result<HookChainOutcome> {
        for binding in chain {
            let Some(pack) = self.packs_by_path.get(&binding.pack_path) else {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "hook binding skipped; pack not found stable_id={} path={}",
                        binding.stable_id,
                        binding.pack_path.display()
                    ),
                );
                continue;
            };

            let payload = canonical::to_canonical_cbor(&HookEvalRequest {
                stage: match stage {
                    HookStage::Pre => "pre",
                    HookStage::Post => "post",
                }
                .to_string(),
                op_name: envelope.op_name.clone(),
                envelope: envelope.clone(),
            })
            .map_err(|err| anyhow!("failed to encode hook request as cbor: {err}"))?;
            let ctx = OperatorContext {
                tenant: envelope.ctx.tenant.clone(),
                team: envelope.ctx.team.clone(),
                correlation_id: envelope.ctx.correlation_id.clone(),
            };
            let outcome = self.invoke_provider_component_op(
                binding.domain,
                pack,
                &binding.pack_id,
                &binding.provider_op,
                &payload,
                &ctx,
            )?;
            if !outcome.success {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "hook invocation failed stage={:?} binding={} err={}",
                        stage,
                        binding.stable_id,
                        outcome.error.unwrap_or_else(|| "unknown error".to_string())
                    ),
                );
                continue;
            }
            let Some(output) = outcome.output else {
                continue;
            };
            let parsed: HookEvalResponse = match decode_hook_response(&output) {
                Ok(value) => value,
                Err(err) => {
                    operator_log::warn(
                        module_path!(),
                        format!(
                            "hook response decode failed stage={:?} binding={} err={} (expected cbor, with legacy json fallback)",
                            stage, binding.stable_id, err
                        ),
                    );
                    continue;
                }
            };
            if let Some(updated) = parsed.envelope {
                *envelope = updated;
            }
            if parsed.decision.eq_ignore_ascii_case("deny") && matches!(stage, HookStage::Pre) {
                let reason = parsed
                    .reason
                    .unwrap_or_else(|| "hook denied operation".to_string());
                return Ok(HookChainOutcome::Denied(reason));
            }
        }
        Ok(HookChainOutcome::Continue)
    }

    pub(super) fn evaluate_token_validation_pre_hook(
        &self,
        envelope: &mut OperationEnvelope,
        payload_bytes: &[u8],
        ctx: &OperatorContext,
    ) -> anyhow::Result<HookChainOutcome> {
        if envelope
            .op_name
            .starts_with(&format!("cap.invoke:{CAP_OAUTH_TOKEN_VALIDATION_V1}"))
        {
            return Ok(HookChainOutcome::Continue);
        }
        let Some(validation_request) = extract_token_validation_request(payload_bytes) else {
            return Ok(HookChainOutcome::Continue);
        };
        let scope = ResolveScope {
            env: Some(std::env::var("GREENTIC_ENV").unwrap_or_else(|_| "dev".to_string())),
            tenant: Some(ctx.tenant.clone()),
            team: ctx.team.clone(),
        };
        let Some(binding) = self.resolve_capability(CAP_OAUTH_TOKEN_VALIDATION_V1, None, scope)
        else {
            return Ok(HookChainOutcome::Continue);
        };
        if !is_binding_ready(
            &self.bundle_root,
            &ctx.tenant,
            ctx.team.as_deref(),
            &binding,
        )? {
            return Ok(HookChainOutcome::Denied(format!(
                "token validation capability is not installed (stable_id={})",
                binding.stable_id
            )));
        }
        let Some(pack) = self.packs_by_path.get(&binding.pack_path) else {
            return Ok(HookChainOutcome::Denied(format!(
                "token validation pack not found at {}",
                binding.pack_path.display()
            )));
        };
        let request_bytes = serde_json::to_vec(&validation_request)
            .map_err(|err| anyhow!("failed to encode token validation payload: {err}"))?;
        let outcome = self.invoke_provider_component_op(
            binding.domain,
            pack,
            &binding.pack_id,
            &binding.provider_op,
            &request_bytes,
            ctx,
        )?;
        if !outcome.success {
            let reason = outcome
                .error
                .unwrap_or_else(|| "token validation capability invocation failed".to_string());
            return Ok(HookChainOutcome::Denied(reason));
        }
        let Some(output) = outcome.output else {
            return Ok(HookChainOutcome::Denied(
                "token validation returned no output".to_string(),
            ));
        };
        match evaluate_token_validation_output(&output) {
            TokenValidationDecision::Allow(claims) => {
                envelope.ctx.auth_claims = claims;
                Ok(HookChainOutcome::Continue)
            }
            TokenValidationDecision::Deny(reason) => Ok(HookChainOutcome::Denied(reason)),
        }
    }

    pub(super) fn emit_pre_sub(&self, envelope: &OperationEnvelope) {
        operator_log::info(
            module_path!(),
            format!(
                "sub.pre op={} status={:?} tenant={} team={}",
                envelope.op_name,
                envelope.status,
                envelope.ctx.tenant,
                envelope.ctx.team.as_deref().unwrap_or("default")
            ),
        );
    }

    pub(super) fn emit_post_sub(&self, envelope: &OperationEnvelope) {
        operator_log::info(
            module_path!(),
            format!(
                "sub.post op={} status={:?} tenant={} team={}",
                envelope.op_name,
                envelope.status,
                envelope.ctx.tenant,
                envelope.ctx.team.as_deref().unwrap_or("default")
            ),
        );
    }
}

pub(super) fn decode_hook_response(value: &JsonValue) -> anyhow::Result<HookEvalResponse> {
    if let Some(cbor) = extract_cbor_blob(value)
        && let Ok(parsed) = serde_cbor::from_slice::<HookEvalResponse>(&cbor)
    {
        return Ok(parsed);
    }
    serde_json::from_value(value.clone())
        .map_err(|err| anyhow!("hook response is not valid cbor or legacy json: {err}"))
}

pub(super) fn extract_cbor_blob(value: &JsonValue) -> Option<Vec<u8>> {
    match value {
        JsonValue::Array(items) => items
            .iter()
            .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect::<Option<Vec<u8>>>(),
        JsonValue::String(s) => general_purpose::STANDARD.decode(s).ok(),
        JsonValue::Object(map) => {
            for key in ["hook_decision_cbor_b64", "cbor_b64", "hook_decision_cbor"] {
                let Some(raw) = map.get(key) else {
                    continue;
                };
                if let JsonValue::String(s) = raw
                    && let Ok(bytes) = general_purpose::STANDARD.decode(s)
                {
                    return Some(bytes);
                }
                if let Some(bytes) = extract_cbor_blob(raw) {
                    return Some(bytes);
                }
            }
            None
        }
        _ => None,
    }
}

pub(super) fn json_to_canonical_cbor(value: &JsonValue) -> Option<Vec<u8>> {
    canonical::to_canonical_cbor_allow_floats(value).ok()
}
