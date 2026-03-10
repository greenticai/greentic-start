use greentic_types::ChannelMessageEnvelope;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngressRequestV1 {
    pub v: u8,
    pub domain: String,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<String>,
    pub tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: Vec<(String, String)>,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngressHttpResponse {
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventSourceV1 {
    pub domain: String,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventScopeV1 {
    pub tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventEnvelopeV1 {
    pub event_id: String,
    pub event_type: String,
    pub occurred_at: String,
    pub source: EventSourceV1,
    pub scope: EventScopeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub payload: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Clone, Debug)]
pub struct IngressDispatchResult {
    pub response: IngressHttpResponse,
    pub events: Vec<EventEnvelopeV1>,
    pub messaging_envelopes: Vec<ChannelMessageEnvelope>,
}
