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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner_host::types::{OperationEnvelope, OperationStatus};

    fn sample_envelope() -> OperationEnvelope {
        OperationEnvelope {
            op_id: "op-1".to_string(),
            op_name: "ingest_http".to_string(),
            ctx: super::super::types::OperationEnvelopeContext {
                tenant: "demo".to_string(),
                team: Some("ops".to_string()),
                correlation_id: Some("corr-1".to_string()),
                auth_claims: None,
            },
            payload_cbor: vec![1, 2, 3],
            meta_cbor: None,
            status: OperationStatus::Pending,
            result_cbor: None,
        }
    }

    #[test]
    fn extract_cbor_blob_supports_arrays_strings_and_nested_objects() {
        let cbor = serde_cbor::to_vec(&serde_json::json!({
            "decision": "continue",
            "reason": null,
            "envelope": null
        }))
        .unwrap();
        let b64 = general_purpose::STANDARD.encode(&cbor);

        assert_eq!(
            extract_cbor_blob(&JsonValue::Array(
                cbor.iter().copied().map(JsonValue::from).collect()
            )),
            Some(cbor.clone())
        );
        assert_eq!(
            extract_cbor_blob(&JsonValue::String(b64.clone())),
            Some(cbor.clone())
        );
        assert_eq!(
            extract_cbor_blob(&serde_json::json!({"hook_decision_cbor_b64": b64})),
            Some(cbor)
        );
    }

    #[test]
    fn decode_hook_response_prefers_cbor_and_falls_back_to_legacy_json() {
        let response = serde_json::json!({
            "decision": "deny",
            "reason": "nope",
            "envelope": sample_envelope()
        });
        let cbor = serde_cbor::to_vec(&response).unwrap();
        let cbor_json = serde_json::json!({
            "cbor_b64": general_purpose::STANDARD.encode(&cbor)
        });
        let decoded = decode_hook_response(&cbor_json).unwrap();
        assert_eq!(decoded.decision, "deny");
        assert_eq!(decoded.reason.as_deref(), Some("nope"));
        assert_eq!(decoded.envelope.unwrap().op_name, "ingest_http");

        let legacy = serde_json::json!({
            "decision": "continue",
            "reason": "legacy"
        });
        let decoded = decode_hook_response(&legacy).unwrap();
        assert_eq!(decoded.decision, "continue");
        assert_eq!(decoded.reason.as_deref(), Some("legacy"));
    }

    #[test]
    fn json_to_canonical_cbor_round_trips_simple_values() {
        let value = serde_json::json!({
            "decision": "continue",
            "score": 1.5
        });
        let bytes = json_to_canonical_cbor(&value).expect("canonical cbor");
        let decoded: serde_json::Value = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(decoded["decision"], "continue");
        assert_eq!(decoded["score"], 1.5);
    }

    #[test]
    fn extract_cbor_blob_rejects_invalid_shapes() {
        assert_eq!(
            extract_cbor_blob(&serde_json::json!({"cbor_b64": 42})),
            None
        );
        assert_eq!(extract_cbor_blob(&serde_json::json!(true)), None);
        assert_eq!(extract_cbor_blob(&serde_json::json!(["x", 1])), None);
    }

    #[test]
    fn decode_hook_response_rejects_invalid_payloads() {
        let err = decode_hook_response(&serde_json::json!({"cbor_b64": "%%%"})).unwrap_err();
        assert!(err.to_string().contains("not valid cbor or legacy json"));
    }

    #[test]
    fn extract_cbor_blob_supports_nested_array_payloads() {
        let bytes = vec![1_u8, 2, 3, 4];
        let value = serde_json::json!({
            "hook_decision_cbor": bytes.iter().copied().map(serde_json::Value::from).collect::<Vec<_>>()
        });
        assert_eq!(extract_cbor_blob(&value), Some(bytes));
    }

    #[test]
    fn emit_pre_and_post_sub_accept_envelopes() {
        let host = crate::runner_host::tests::empty_host_for_tests();
        let envelope = sample_envelope();
        host.emit_pre_sub(&envelope);
        host.emit_post_sub(&envelope);
    }

    #[test]
    fn decode_hook_response_accepts_raw_cbor_byte_arrays() {
        let cbor = serde_cbor::to_vec(&serde_json::json!({
            "decision": "continue",
            "reason": "array-form"
        }))
        .unwrap();
        let value = JsonValue::Array(cbor.into_iter().map(JsonValue::from).collect());
        let decoded = decode_hook_response(&value).unwrap();
        assert_eq!(decoded.decision, "continue");
        assert_eq!(decoded.reason.as_deref(), Some("array-form"));
    }
}
