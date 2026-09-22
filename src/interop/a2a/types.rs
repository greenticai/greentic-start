//! A2A v1.0.1 wire types for the SERVER side, hand-rolled (research spec §5.4:
//! the Rust A2A crates on crates.io do not survive a provenance check).
//!
//! The proto (`specification/a2a.proto`, release v1.0.1) is authoritative. It
//! is snake_case; the JSON is camelCase, so every struct carries
//! `rename_all = "camelCase"`. The shapes agree with greentic-runner's
//! `greentic-a2a` client crate, so our own client can call our own server.
//!
//! Four traps (research §5.1a), each pinned by a golden test below:
//!
//! 1. [`SecurityScheme`] is a proto `oneof`: the JSON has NO `type` field,
//!    the member name (`httpAuthSecurityScheme`) discriminates.
//! 2. `AgentInterface.tenant`: when a server sets it, every request MUST echo
//!    it. This server does not set it, so it accepts and ignores a `tenant`.
//! 3. Versions negotiate on `Major.Minor` only ([`ProtocolVersion`]).
//! 4. RPC names are PascalCase (`SendMessage`), not the 0.x `message/send`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Agent card
// ---------------------------------------------------------------------------

/// What `GET /.well-known/agent-card.json` serves.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AgentCard {
    pub name: String,
    pub description: String,
    /// Ordered; the first entry is the preferred interface.
    pub supported_interfaces: Vec<AgentInterface>,
    pub version: String,
    pub capabilities: AgentCapabilities,
    pub default_input_modes: Vec<String>,
    pub default_output_modes: Vec<String>,
    pub skills: Vec<AgentSkill>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<AgentProvider>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub security_schemes: BTreeMap<String, SecurityScheme>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AgentInterface {
    pub url: String,
    /// `JSONRPC`, `GRPC` or `HTTP+JSON`.
    pub protocol_binding: String,
    /// `Major.Minor`.
    pub protocol_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AgentCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_notifications: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_agent_card: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AgentSkill {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_modes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_modes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AgentProvider {
    pub url: String,
    pub organization: String,
}

/// How to authenticate. Externally tagged: the JSON object carries exactly
/// one key, the member name. `{"type":"http",…}` is OpenAPI, not A2A.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum SecurityScheme {
    #[serde(rename = "httpAuthSecurityScheme")]
    HttpAuth(HttpAuthSecurityScheme),
    #[serde(rename = "apiKeySecurityScheme")]
    ApiKey(ApiKeySecurityScheme),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpAuthSecurityScheme {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_format: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiKeySecurityScheme {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `query`, `header` or `cookie`.
    pub location: String,
    pub name: String,
}

// ---------------------------------------------------------------------------
// Messages and tasks
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Role {
    #[serde(rename = "ROLE_UNSPECIFIED")]
    Unspecified,
    #[serde(rename = "ROLE_USER")]
    User,
    #[serde(rename = "ROLE_AGENT")]
    Agent,
}

/// One piece of a message. The proto content is a `oneof` (`text | raw | url
/// | data`) with `metadata`, `filename` and `mediaType` as SIBLINGS, so the
/// JSON is flat: `{"text":"hi"}`, never `{"text":{"text":"hi"}}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Part {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Inline bytes, base64 in JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

impl Part {
    pub(crate) fn text(text: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            ..Self::default()
        }
    }

    pub(crate) fn data(data: Value, media_type: &str) -> Self {
        Self {
            data: Some(data),
            media_type: Some(media_type.to_string()),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Message {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    pub role: Role,
    pub parts: Vec<Part>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reference_task_ids: Vec<String>,
}

/// Task lifecycle. One `l` in `CANCELED` (v1.0 renamed the 0.x spelling).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum TaskState {
    #[serde(rename = "TASK_STATE_UNSPECIFIED")]
    Unspecified,
    #[serde(rename = "TASK_STATE_SUBMITTED")]
    Submitted,
    #[serde(rename = "TASK_STATE_WORKING")]
    Working,
    #[serde(rename = "TASK_STATE_COMPLETED")]
    Completed,
    #[serde(rename = "TASK_STATE_FAILED")]
    Failed,
    #[serde(rename = "TASK_STATE_CANCELED")]
    Canceled,
    #[serde(rename = "TASK_STATE_INPUT_REQUIRED")]
    InputRequired,
    #[serde(rename = "TASK_STATE_REJECTED")]
    Rejected,
    #[serde(rename = "TASK_STATE_AUTH_REQUIRED")]
    AuthRequired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaskStatus {
    pub state: TaskState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Artifact {
    pub artifact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Task {
    pub id: String,
    pub context_id: String,
    pub status: TaskStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<Artifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<Message>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

// ---------------------------------------------------------------------------
// Requests and responses
// ---------------------------------------------------------------------------

/// `SendMessageRequest`. `configuration` is accepted and ignored: this server
/// always answers synchronously with a `Message` (contract D4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendMessageRequest {
    pub message: Message,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<SendMessageConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendMessageConfiguration {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_output_modes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking: Option<bool>,
}

/// `SendMessageResponse`: a proto `oneof`, so `{"message": …}` or
/// `{"task": …}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SendMessageResponse {
    Message(Message),
    Task(Task),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetTaskRequest {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CancelTaskRequest {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListTasksRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
}

/// `ListTasksResponse`. `nextPageToken`, `pageSize` and `totalSize` are
/// required on the proto, so they are always emitted.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListTasksResponse {
    pub tasks: Vec<Task>,
    pub next_page_token: String,
    pub page_size: i32,
    pub total_size: i32,
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 envelope
// ---------------------------------------------------------------------------

/// `string | number | null`. A server MUST echo the id it received.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum JsonRpcId {
    Number(i64),
    Str(String),
    Null,
}

/// An incoming request. `params` stays a raw value so each method parses its
/// own shape and an invalid one answers `-32602`, not `-32600`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub(crate) struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<JsonRpcId>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: JsonRpcId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub(crate) fn ok(id: JsonRpcId, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub(crate) fn err(id: JsonRpcId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// The JSON-RPC and A2A error codes this server emits (A2A v1.0 §5.4).
pub(crate) mod codes {
    pub(crate) const PARSE_ERROR: i64 = -32700;
    pub(crate) const INVALID_REQUEST: i64 = -32600;
    pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
    pub(crate) const INVALID_PARAMS: i64 = -32602;
    pub(crate) const INTERNAL_ERROR: i64 = -32603;
    pub(crate) const TASK_NOT_FOUND: i64 = -32001;
    pub(crate) const PUSH_NOTIFICATION_NOT_SUPPORTED: i64 = -32003;
    pub(crate) const UNSUPPORTED_OPERATION: i64 = -32004;
    pub(crate) const CONTENT_TYPE_NOT_SUPPORTED: i64 = -32005;
    pub(crate) const EXTENDED_AGENT_CARD_NOT_CONFIGURED: i64 = -32007;
    pub(crate) const VERSION_NOT_SUPPORTED: i64 = -32009;
}

/// The eleven `A2AService` RPC names, PascalCase.
pub(crate) mod methods {
    pub(crate) const SEND_MESSAGE: &str = "SendMessage";
    pub(crate) const SEND_STREAMING_MESSAGE: &str = "SendStreamingMessage";
    pub(crate) const GET_TASK: &str = "GetTask";
    pub(crate) const LIST_TASKS: &str = "ListTasks";
    pub(crate) const CANCEL_TASK: &str = "CancelTask";
    pub(crate) const SUBSCRIBE_TO_TASK: &str = "SubscribeToTask";
    pub(crate) const CREATE_PUSH_CONFIG: &str = "CreateTaskPushNotificationConfig";
    pub(crate) const GET_PUSH_CONFIG: &str = "GetTaskPushNotificationConfig";
    pub(crate) const LIST_PUSH_CONFIGS: &str = "ListTaskPushNotificationConfigs";
    pub(crate) const DELETE_PUSH_CONFIG: &str = "DeleteTaskPushNotificationConfig";
    pub(crate) const GET_EXTENDED_AGENT_CARD: &str = "GetExtendedAgentCard";
}

// ---------------------------------------------------------------------------
// Version negotiation
// ---------------------------------------------------------------------------

/// A `Major.Minor` protocol version. Patch is parsed and DISCARDED: A2A §3.6
/// says patch numbers MUST NOT be considered when negotiating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
}

impl ProtocolVersion {
    /// The one version this server speaks.
    pub(crate) const SUPPORTED: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };

    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.trim().split('.');
        let major = parts.next()?.trim().parse().ok()?;
        let minor = parts.next().map_or(Some(0), |m| m.trim().parse().ok())?;
        // A patch segment is allowed and ignored; anything past it is not.
        if let Some(patch) = parts.next() {
            patch.trim().parse::<u32>().ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        Some(Self { major, minor })
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
