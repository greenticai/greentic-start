//! Two small, pure decisions the messaging ingress makes around Fast2Flow:
//!
//! * what a free-text turn does when routing resolved nothing ([`miss_action`]);
//! * how a routed turn is reported on its replies ([`RouteSignal`]).
//!
//! Kept out of `messaging.rs` so both can be tested without a runner host.

use greentic_types::ChannelMessageEnvelope;
use greentic_types::messaging::extensions::ext_keys;
use serde_json::{Value as JsonValue, json};

use crate::fast2flow::{FAST2FLOW_CAPABILITY, FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY};

/// The fixed reply a Fast2Flow pack gets on a routing miss, unless it opted
/// into [`FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY`].
pub(super) const MISS_REPLY_TEXT: &str =
    "I'm not sure what you meant. Tap one of the menu options or rephrase your request.";

/// Reply key carrying the route signal: in `metadata` as a JSON string, and in
/// `extensions["channel_data"]` as a JSON object.
///
/// Both, because the metadata copy is what the ask names, and the webchat
/// provider (Direct Line) copies no arbitrary metadata key into an activity —
/// its encoder reads a fixed allow-list — while it forwards
/// `extensions["channel_data"]` as the activity's `channelData`. That is the
/// same seam `crate::agent_provenance` uses for `greenticProvenance`.
pub(super) const ROUTE_METADATA_KEY: &str = "fast2flow";

/// What an unrouted turn (no card target, no dispatched flow) does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MissAction {
    /// Not a Fast2Flow miss — the default flow runs, exactly as before.
    RunDefaultFlow,
    /// A Fast2Flow miss on a pack that did not opt in: the fixed reply, so a
    /// card-menu pack does not re-echo its welcome menu.
    FixedReply,
    /// A Fast2Flow miss on a pack declaring
    /// [`FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY`]: the default flow runs
    /// with the original message.
    DefaultFlowOnMiss,
}

/// Decide an unrouted turn.
///
/// A turn is a Fast2Flow miss only when the conversation is not owned by a
/// flow (a sticky resume is never routed, so it cannot miss), the pack
/// declares [`FAST2FLOW_CAPABILITY`], and the user sent non-blank text.
pub(super) fn miss_action(
    owns_conversation: bool,
    capabilities: &[String],
    text: Option<&str>,
) -> MissAction {
    let declares = |cap: &str| capabilities.iter().any(|c| c == cap);
    let free_text = text.is_some_and(|t| !t.trim().is_empty());
    if owns_conversation || !declares(FAST2FLOW_CAPABILITY) || !free_text {
        return MissAction::RunDefaultFlow;
    }
    if declares(FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY) {
        MissAction::DefaultFlowOnMiss
    } else {
        MissAction::FixedReply
    }
}

/// The fixed miss reply, addressed like the inbound message.
pub(super) fn miss_reply(envelope: &ChannelMessageEnvelope) -> ChannelMessageEnvelope {
    let mut reply = envelope.clone();
    reply.metadata.remove("adaptive_card");
    reply.text = Some(MISS_REPLY_TEXT.to_string());
    reply
}

/// Which router produced a dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RouteSource {
    /// Fast2Flow's deterministic (BM25) routing host.
    Bm25,
    /// The embedded LLM fallback.
    Llm,
}

impl RouteSource {
    /// Prefix used in operator log lines (unchanged from before this type).
    pub(super) fn log_label(self) -> &'static str {
        match self {
            Self::Bm25 => "fast2flow",
            Self::Llm => "fast2flow:llm",
        }
    }

    fn wire(self) -> &'static str {
        match self {
            Self::Bm25 => "bm25",
            Self::Llm => "llm",
        }
    }
}

/// How a routed turn was routed, stamped on every reply of that turn.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct RouteSignal {
    /// The card node a node dispatch (`routeToCardId`) targeted; `None` for a
    /// whole-flow dispatch.
    pub(super) node: Option<String>,
    pub(super) confidence: Option<f32>,
    pub(super) source: RouteSource,
}

impl RouteSignal {
    /// The signal as JSON:
    ///
    /// * flow dispatch — `{"flow":"<flow id>","confidence":0.92,"source":"bm25"}`
    /// * node dispatch — `{"flow":"<flow the node runs in>","node":"<node id>",...}`
    ///
    /// `flow` is always the flow that ran the turn; `node` is present only for
    /// a node route. `confidence` is `null` when the router reported none (or
    /// a non-finite one). `source` is `"bm25"` or `"llm"`.
    pub(super) fn to_json(&self, flow_id: &str) -> JsonValue {
        let confidence = self
            .confidence
            .filter(|c| c.is_finite())
            .map(|c| json!(c))
            .unwrap_or(JsonValue::Null);
        let mut value = json!({
            "flow": flow_id,
            "confidence": confidence,
            "source": self.source.wire(),
        });
        if let (Some(node), Some(map)) = (&self.node, value.as_object_mut()) {
            map.insert("node".to_string(), json!(node));
        }
        value
    }
}

/// Stamp (or clear) the route signal on a turn's replies.
///
/// A routed turn gets [`ROUTE_METADATA_KEY`] on every reply, in `metadata`
/// (JSON string) and in `extensions["channel_data"]` (JSON object; merged into
/// an existing object, never clobbering one that is not an object). Any other
/// turn — default flow, sticky resume, the fixed miss reply — has the key
/// REMOVED from both, because a reply is often a clone of the inbound envelope
/// and an inbound message must not be able to forge a routing signal.
pub(super) fn stamp_route(
    outputs: &mut [ChannelMessageEnvelope],
    signal: Option<&RouteSignal>,
    flow_id: &str,
) {
    let value = signal.map(|s| s.to_json(flow_id));
    for out in outputs {
        match &value {
            Some(v) => {
                out.metadata
                    .insert(ROUTE_METADATA_KEY.to_string(), v.to_string());
                match out.extensions.get_mut(ext_keys::CHANNEL_DATA) {
                    None => {
                        out.extensions.insert(
                            ext_keys::CHANNEL_DATA.to_string(),
                            json!({ ROUTE_METADATA_KEY: v }),
                        );
                    }
                    Some(JsonValue::Object(existing)) => {
                        existing.insert(ROUTE_METADATA_KEY.to_string(), v.clone());
                    }
                    // A non-object channelData is someone else's value; it
                    // stays as-is and only the metadata copy is set.
                    Some(_) => {}
                }
            }
            None => {
                out.metadata.remove(ROUTE_METADATA_KEY);
                if let Some(JsonValue::Object(existing)) =
                    out.extensions.get_mut(ext_keys::CHANNEL_DATA)
                {
                    existing.remove(ROUTE_METADATA_KEY);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "fast2flow_turn_tests.rs"]
mod tests;
