//! The usage event one interop turn produces (worker-interop contract §8.2),
//! and where its numbers come from.
//!
//! **Nothing here may carry message content.** The event is a fixed set of
//! identifiers and counters; no field holds text the caller sent, text the
//! worker replied, a card, or a prompt.
//! [`event_tests::the_event_carries_only_identifiers_and_counters`] pins the
//! type's serialized key set, and
//! `crate::interop::a2a::rpc::rpc_tests::no_turn_content_reaches_the_recorded_event`
//! drives a REAL turn whose every reply shape carries distinctive content and
//! asserts the recorded event contains none of it.

use greentic_runner_host::Activity;
use serde::Serialize;
use serde_json::Value;

/// Which interop binding ran the turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Surface {
    A2a,
    Mcp,
}

impl Surface {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Surface::A2a => "a2a",
            Surface::Mcp => "mcp",
        }
    }
}

/// What one turn spent, summed across every `dw.agent` node that ran in it.
///
/// Mirrors `greentic_aw_runtime::StepUsage`, which is what the `dw.agent`
/// node output's `usage` object serialises from — see
/// [`crate::agent_provenance`]'s `runtime_contract_tests`, which pins that
/// wrapper shape against the real runtime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TurnUsage {
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub iterations: u64,
}

/// One metered turn, serialised exactly as the admin's ingest door reads it.
///
/// **`tenant_slug` is not an `Option`**, because the admin's ingest door
/// declares it required and refuses a body whose value disagrees with the
/// token's tenant (§8.3). An event that omitted it could only ever be a
/// `400`, recorded nowhere. A unit whose staged document carries no slug is
/// refused metering outright instead — see
/// [`super::MeteringRefusal::NoTenantSlug`] — so there is no path by which
/// this field can be missing.
///
/// `credential_id` IS optional, and is omitted rather than emptied: an OAuth
/// MCP caller genuinely has no staged credential id, and the admin made the
/// field optional for exactly that caller.
///
/// **There is no model id**, and there cannot be one at this layer: the model
/// lives in the agent's `AgentConfig` inside `greentic-aw-runtime` and reaches
/// neither the node output nor the reply activity. §8.4 names carrying it as a
/// precondition of ever charging from these rows, and closing it means a new
/// field on `StepUsage` upstream.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct UsageEvent {
    pub event_id: String,
    pub occurred_at: String,
    pub tenant_slug: String,
    pub deployment_id: String,
    pub bundle_id: String,
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    pub surface: &'static str,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub iterations: u64,
    /// How long the TURN took: measured around the runner call alone, not
    /// around the request. Time spent authenticating, waiting on the rate
    /// limiter or projecting the reply is not what the worker spent.
    pub duration_ms: u64,
}

/// An RFC 3339 instant with a literal `Z`, never `+00:00`.
pub(crate) fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// A fresh event id. A ULID rather than a UUID because the admin makes it the
/// primary key of a time-ordered table and dedupes on it (§8.3).
pub(crate) fn new_event_id() -> String {
    ulid::Ulid::new().to_string()
}

/// Wrapper keys a node output can be nested under, the same set
/// `revision_serve::find_rendered_card` walks. Kept in step with it on
/// purpose: a reply shape one of them can reach is a reply shape the other
/// must be able to read usage out of.
const WRAPPER_KEYS: &[&str] = &[
    "outputs",
    "result",
    "structured_content",
    "payload",
    "response",
];

/// Total the `usage` objects carried by one turn's reply activities.
///
/// A turn with no usage anywhere totals to zero, which is emitted rather than
/// suppressed: "a turn ran and cost nothing measurable" and "no turn ran" are
/// different facts (§8.2), and only the first produces an event at all.
pub(crate) fn usage_from_replies(replies: &[Activity]) -> TurnUsage {
    let mut total = TurnUsage::default();
    for reply in replies {
        accumulate(reply.payload(), &mut total);
    }
    total
}

/// Walk one payload for `usage` objects.
///
/// **An object that carries a usage STOPS the descent below it.** A node
/// output is routinely echoed under a wrapper as well as at the root, and
/// counting both would double every turn — the failure mode being avoided is
/// silent inflation of a number nobody can check against the provider's bill.
/// An ARRAY still fans out, because the runner appends one entry per node and
/// two `dw.agent` nodes in one turn really did spend twice.
fn accumulate(value: &Value, total: &mut TurnUsage) {
    match value {
        Value::Object(map) => {
            if let Some(usage) = map.get("usage").and_then(read_usage) {
                total.tokens_in = total.tokens_in.saturating_add(usage.tokens_in);
                total.tokens_out = total.tokens_out.saturating_add(usage.tokens_out);
                total.iterations = total.iterations.saturating_add(usage.iterations);
                return;
            }
            for key in WRAPPER_KEYS {
                if let Some(nested) = map.get(*key) {
                    accumulate(nested, total);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| accumulate(item, total)),
        _ => {}
    }
}

/// Read one `usage` object, if it plausibly is one.
///
/// At least one of the three counters has to be a number. Without that check
/// any object under the key `usage` — a component's own output, say — would
/// be read as a zero reading and end the descent, hiding the real one below
/// it.
fn read_usage(value: &Value) -> Option<TurnUsage> {
    let map = value.as_object()?;
    let tokens_in = map.get("tokens_in").and_then(Value::as_u64);
    let tokens_out = map.get("tokens_out").and_then(Value::as_u64);
    let iterations = map.get("iterations").and_then(Value::as_u64);
    if tokens_in.is_none() && tokens_out.is_none() && iterations.is_none() {
        return None;
    }
    Some(TurnUsage {
        tokens_in: tokens_in.unwrap_or_default(),
        tokens_out: tokens_out.unwrap_or_default(),
        iterations: iterations.unwrap_or_default(),
    })
}

#[cfg(test)]
#[path = "event_tests.rs"]
mod event_tests;
