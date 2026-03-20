use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInV1 {
    pub v: u32,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_hint: Option<String>,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    pub body_b64: String,
    /// Host-injected configuration (e.g., pre-fetched secrets for provider_core_only mode)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderPlanInV1 {
    pub v: u32,
    pub message: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodeInV1 {
    pub v: u32,
    pub message: serde_json::Value,
    pub plan: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderPayloadV1 {
    pub content_type: String,
    pub body_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPayloadInV1 {
    pub v: u32,
    pub provider_type: String,
    pub payload: ProviderPayloadV1,
    pub tenant: TenantHint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_scope: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantHint {
    pub tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}
