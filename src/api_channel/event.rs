//! The API channel's cross-repo event schema and the `poll_events` provider
//! op payloads.
//!
//! The shapes are a contract shared with the `messaging-api` provider pack and
//! the designer. They are typed rather than passed through as `Value` so that
//! a drift fails here, and so that the bytes written to an SSE `data:` line
//! are the same bytes the fixtures in `docs/fixtures/api-channel/` hold.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The provider op the host calls to read the conversation log.
pub(crate) const POLL_EVENTS_OP: &str = "poll_events";

/// What happened in the conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EventType {
    Message,
    InputRequired,
    Error,
    Done,
    DeliveryFailed,
}

impl EventType {
    /// The SSE `event:` name; identical to the wire `type`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            EventType::Message => "message",
            EventType::InputRequired => "input_required",
            EventType::Error => "error",
            EventType::Done => "done",
            EventType::DeliveryFailed => "delivery_failed",
        }
    }
}

/// One element of an event's `items`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Item {
    Text { text: String },
    Card { card: Value, fallback: String },
}

/// One entry of the conversation log. `cursor` is the `Pump` watermark.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ApiEvent {
    pub cursor: u64,
    #[serde(rename = "type")]
    pub kind: EventType,
    pub items: Vec<Item>,
    pub ts: String,
    /// Present on `error` events only; never provider text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Input of the `poll_events` provider op.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PollEventsRequest {
    pub conversation_id: String,
    pub since: u64,
}

/// Output of the `poll_events` provider op: events with `cursor >= since`,
/// ascending.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PollEventsResponse {
    pub events: Vec<ApiEvent>,
    pub next_cursor: u64,
}
