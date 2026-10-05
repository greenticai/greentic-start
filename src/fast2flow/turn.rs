//! Small, pure decisions the messaging ingress makes around Fast2Flow:
//!
//! * how the host router and the LLM fallback combine ([`probe_turn`]);
//! * what a free-text turn does when routing resolved nothing ([`miss_action`]);
//! * how a routed turn is reported on its replies ([`RouteSignal`]).
//!
//! Path-neutral: kept free of any ingress so it can be tested without a
//! runner host, and so the legacy messaging ingress
//! (`http_ingress/messaging.rs`) and the revision-serve path can share one copy.

use greentic_types::ChannelMessageEnvelope;
use greentic_types::messaging::extensions::ext_keys;
use serde_json::{Value as JsonValue, json};

use super::{FAST2FLOW_CAPABILITY, FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY};

/// The fixed reply a Fast2Flow pack gets on a routing miss, unless it opted
/// into [`FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY`].
pub(crate) const MISS_REPLY_TEXT: &str =
    "I'm not sure what you meant. Tap one of the menu options or rephrase your request.";

/// Reply key carrying the route signal: in `metadata` as a JSON string, and in
/// `extensions["channel_data"]` as a JSON object.
///
/// Both, because the metadata copy is what the ask names, and the webchat
/// provider (Direct Line) copies no arbitrary metadata key into an activity —
/// its encoder reads a fixed allow-list — while it forwards
/// `extensions["channel_data"]` as the activity's `channelData`. That is the
/// same seam `crate::agent_provenance` uses for `greenticProvenance`.
pub(crate) const ROUTE_METADATA_KEY: &str = "fast2flow";

/// Why a routed-eligible turn was NOT routed. Only the log line differs between
/// the first three; [`Unrouted::Unhandled`] also changes what the turn does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unrouted {
    /// The router ran and found nothing (and so did the LLM fallback).
    NoMatch,
    /// The router was not asked: gate closed, no index path or no index.
    RouterNotConfigured(String),
    /// The router was asked and failed; the reason is operator-readable.
    RouterFailed(String),
    /// Fast2Flow answered `Deny` or `Respond`, which this path does not handle
    /// yet. It stops routing (no LLM fallback) and never runs the default flow.
    Unhandled(&'static str),
}

impl Unrouted {
    /// A short description for operator logs. Never message text.
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::NoMatch => "no dispatch".to_string(),
            Self::RouterNotConfigured(reason) => format!("router not configured ({reason})"),
            Self::RouterFailed(reason) => format!("router FAILED ({reason})"),
            Self::Unhandled(kind) => format!("unhandled {kind} directive"),
        }
    }
}

/// Combine the host router's answer with the LLM fallback.
///
/// A route from the host wins. A `Deny`/`Respond` from the host stops routing
/// for the turn: consulting the LLM there would let a model override a policy
/// refusal. Any other miss asks the LLM, and when that finds nothing too the
/// HOST's cause is kept — a failed router must not be reported as "no match".
pub(crate) fn probe_turn<T>(
    host: Result<T, Unrouted>,
    llm: impl FnOnce() -> Option<T>,
) -> Result<T, Unrouted> {
    match host {
        Ok(routed) => Ok(routed),
        Err(stop @ Unrouted::Unhandled(_)) => Err(stop),
        Err(cause) => llm().ok_or(cause),
    }
}

/// What an unrouted turn (no card target, no dispatched flow) does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MissAction {
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
/// A conversation owned by a flow (a sticky resume) is never routed, so it
/// never misses. A Fast2Flow `Deny`/`Respond` ([`Unrouted::Unhandled`]) always
/// gets the fixed reply, opt-in or not. Otherwise a turn is a Fast2Flow miss
/// when the pack declares [`FAST2FLOW_CAPABILITY`] and the user sent non-blank
/// text — whatever the cause (no match, router not configured, router failed).
pub(crate) fn miss_action(
    owns_conversation: bool,
    capabilities: &[String],
    text: Option<&str>,
    unrouted: Option<&Unrouted>,
) -> MissAction {
    if owns_conversation {
        return MissAction::RunDefaultFlow;
    }
    if matches!(unrouted, Some(Unrouted::Unhandled(_))) {
        return MissAction::FixedReply;
    }
    let declares = |cap: &str| capabilities.iter().any(|c| c == cap);
    let free_text = text.is_some_and(|t| !t.trim().is_empty());
    if !declares(FAST2FLOW_CAPABILITY) || !free_text {
        return MissAction::RunDefaultFlow;
    }
    if declares(FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY) {
        MissAction::DefaultFlowOnMiss
    } else {
        MissAction::FixedReply
    }
}

/// The fixed miss reply, addressed like the inbound message.
pub(crate) fn miss_reply(envelope: &ChannelMessageEnvelope) -> ChannelMessageEnvelope {
    let mut reply = envelope.clone();
    reply.metadata.remove("adaptive_card");
    reply.text = Some(MISS_REPLY_TEXT.to_string());
    reply
}

/// Which router produced a dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteSource {
    /// Fast2Flow's deterministic (BM25) routing host.
    Bm25,
    /// The embedded LLM fallback.
    Llm,
}

impl RouteSource {
    /// Prefix used in operator log lines (unchanged from before this type).
    pub(crate) fn log_label(self) -> &'static str {
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
pub(crate) struct RouteSignal {
    /// The card node a node dispatch (`routeToCardId`) targeted; `None` for a
    /// whole-flow dispatch.
    pub(crate) node: Option<String>,
    pub(crate) confidence: Option<f32>,
    pub(crate) source: RouteSource,
}

impl RouteSignal {
    /// The signal as JSON:
    ///
    /// * flow dispatch — `{"flow":"<flow id>","confidence":0.92,"source":"bm25"}`
    /// * node dispatch — `{"flow":"<flow the node runs in>","node":"<node id>",...}`
    ///
    /// `flow` is always the flow that ran the turn; `node` is present only for
    /// a node route — and for a node rendered straight from a card asset,
    /// `flow` names the default flow even though no flow ran. `confidence` is
    /// the router's value as its shortest decimal (`0.92`, not the f32 noise
    /// `0.9200000166893005`), and `null` when none was reported or it is
    /// non-finite or outside `[0, 1]`. `source` is `"bm25"` or `"llm"`.
    pub(crate) fn to_json(&self, flow_id: &str) -> JsonValue {
        let confidence = self
            .confidence
            .filter(|c| c.is_finite() && (0.0..=1.0).contains(c))
            // f32's Display is the shortest decimal that round-trips, so this
            // turns 0.92f32 into 0.92 rather than widening its binary value.
            .and_then(|c| c.to_string().parse::<f64>().ok())
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
/// turn — default flow, sticky resume, the fixed miss reply, and a routed turn
/// whose flow FAILED (callers pass `None` then) — has the key REMOVED from
/// both, because a reply is often a clone of the inbound envelope and an
/// inbound message must not be able to forge a routing signal. That removal
/// also drops a `fast2flow` key a flow emitted itself; this is intentional.
pub(crate) fn stamp_route(
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
                    Some(other) => {
                        crate::operator_log::debug(
                            module_path!(),
                            format!(
                                "[fast2flow] channel_data is a JSON {}, not an object; route signal set in metadata only",
                                json_type(other)
                            ),
                        );
                    }
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

fn json_type(value: &JsonValue) -> &'static str {
    match value {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "bool",
        JsonValue::Number(_) => "number",
        JsonValue::String(_) => "string",
        JsonValue::Array(_) => "array",
        JsonValue::Object(_) => "object",
    }
}

#[cfg(test)]
#[path = "turn_tests.rs"]
mod tests;
