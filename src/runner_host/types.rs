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
