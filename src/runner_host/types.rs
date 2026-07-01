#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::path::PathBuf;

use crate::runner_integration::RunnerFlavor;

#[derive(Clone)]
pub struct OperatorContext {
    pub tenant: String,
    pub team: Option<String>,
    pub correlation_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerExecutionMode {
    Exec,
    Integration,
}

#[derive(Clone)]
pub struct FlowOutcome {
    pub success: bool,
    pub output: Option<JsonValue>,
    pub raw: Option<String>,
    pub error: Option<String>,
    pub mode: RunnerExecutionMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OperationStatus {
    Pending,
    Denied,
    Ok,
    Err,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct OperationEnvelopeContext {
    pub(super) tenant: String,
    pub(super) team: Option<String>,
    pub(super) correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) auth_claims: Option<JsonValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct OperationEnvelope {
    pub(super) op_id: String,
    pub(super) op_name: String,
    pub(super) ctx: OperationEnvelopeContext,
    pub(super) payload_cbor: Vec<u8>,
    pub(super) meta_cbor: Option<Vec<u8>>,
    pub(super) status: OperationStatus,
    pub(super) result_cbor: Option<Vec<u8>>,
}

impl OperationEnvelope {
    pub(super) fn new(op_name: &str, payload: &[u8], ctx: &OperatorContext) -> Self {
        Self {
            op_id: uuid::Uuid::new_v4().to_string(),
            op_name: op_name.to_string(),
            ctx: OperationEnvelopeContext {
                tenant: ctx.tenant.clone(),
                team: ctx.team.clone(),
                correlation_id: ctx.correlation_id.clone(),
                auth_claims: None,
            },
            payload_cbor: payload.to_vec(),
            meta_cbor: None,
            status: OperationStatus::Pending,
            result_cbor: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct HookEvalRequest {
    pub(super) stage: String,
    pub(super) op_name: String,
    pub(super) envelope: OperationEnvelope,
}

#[derive(Debug, Deserialize)]
pub(super) struct HookEvalResponse {
    pub(super) decision: String,
    #[serde(default)]
    pub(super) reason: Option<String>,
    #[serde(default)]
    pub(super) envelope: Option<OperationEnvelope>,
}

#[derive(Debug)]
pub(super) enum HookChainOutcome {
    Continue,
    Denied(String),
}

#[derive(Clone, Debug)]
pub(super) enum RunnerMode {
    Exec,
    Integration {
        binary: PathBuf,
        flavor: RunnerFlavor,
    },
}

pub(super) enum TokenValidationDecision {
    Allow(Option<JsonValue>),
    Deny(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_envelope_new_copies_context_and_payload() {
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: Some("ops".to_string()),
            correlation_id: Some("corr-1".to_string()),
        };
        let envelope = OperationEnvelope::new("ingest_http", &[1, 2, 3], &ctx);

        assert_eq!(envelope.op_name, "ingest_http");
        assert_eq!(envelope.ctx.tenant, "demo");
        assert_eq!(envelope.ctx.team.as_deref(), Some("ops"));
        assert_eq!(envelope.ctx.correlation_id.as_deref(), Some("corr-1"));
        assert_eq!(envelope.payload_cbor, vec![1, 2, 3]);
        match envelope.status {
            OperationStatus::Pending => {}
            _ => panic!("expected pending status"),
        }
        assert!(envelope.meta_cbor.is_none());
        assert!(envelope.result_cbor.is_none());
        assert!(!envelope.op_id.is_empty());
    }

    #[test]
    fn types_cover_flow_outcome_hook_eval_and_runner_modes() {
        let outcome = FlowOutcome {
            success: true,
            output: Some(serde_json::json!({"ok": true})),
            raw: Some("raw".to_string()),
            error: None,
            mode: RunnerExecutionMode::Integration,
        };
        assert!(outcome.success);
        assert_eq!(outcome.mode, RunnerExecutionMode::Integration);

        let response = HookEvalResponse {
            decision: "deny".to_string(),
            reason: Some("blocked".to_string()),
            envelope: None,
        };
        assert_eq!(response.decision, "deny");
        assert_eq!(response.reason.as_deref(), Some("blocked"));

        let mode = RunnerMode::Integration {
            binary: PathBuf::from("/tmp/runner"),
            flavor: RunnerFlavor::RunSubcommand,
        };
        match mode {
            RunnerMode::Integration { binary, .. } => {
                assert_eq!(binary, PathBuf::from("/tmp/runner"));
            }
            RunnerMode::Exec => panic!("expected integration mode"),
        }

        match TokenValidationDecision::Allow(Some(serde_json::json!({"sub": "user"}))) {
            TokenValidationDecision::Allow(Some(claims)) => assert_eq!(claims["sub"], "user"),
            _ => panic!("expected allow"),
        }
        match TokenValidationDecision::Deny("nope".to_string()) {
            TokenValidationDecision::Deny(reason) => assert_eq!(reason, "nope"),
            _ => panic!("expected deny"),
        }
    }
}
