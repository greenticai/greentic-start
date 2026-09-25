//! The structured value a turn produced, as opposed to the prose it said.
//!
//! A Greentic turn answers in prose: a `dw.agent` `reply`, a card's fallback
//! text, a component's `result.content[].text`. A caller that is a program
//! wants the OBJECT a node produced, and until this module existed there was
//! exactly one place such an object could go — the shared reply shaper's last
//! text fallback, which does
//! `value["result"]["structured_content"].to_string()`
//! ([`crate::messaging_app::parse_envelopes`]). So a flow that produced
//! `{"temp_c": 21.3}` handed an agent caller the STRING `{"temp_c":21.3}` in
//! a text part, and a flow that produced both `result.content[].text` and
//! `result.structured_content` handed it the text and dropped the object
//! entirely — that branch is `.or()`-chained and the text wins.
//!
//! # What counts as a structured output
//!
//! `result.structured_content`, and nothing else. It is not a guess: it is
//! the one position in the runner's node-output contract that is declared to
//! hold a structured value (it is also the MCP tool-result field name the
//! component lane reuses), it is the only one the shaper stringifies, and
//! [`crate::interop::metering::event`] and
//! [`crate::revision_serve`]'s card walk already treat it as a node-output
//! wrapper key. Everything else a turn carries is either prose, routing, or
//! an Adaptive Card.
//!
//! Four rules, each of which fails silently if changed:
//!
//! - **An Adaptive Card is never a structured output** (worker-interop
//!   contract D10). The card reaches an agent caller only when it asked for
//!   one; a `structured_content` that carries a `renderedCard` is the card
//!   being transported under a wrapper — a real shape, which
//!   `revision_serve`'s `find_rendered_card` hoists — so it is SKIPPED rather
//!   than stripped. Stripping would need this module to decide which half of
//!   such an object is the result, and getting that wrong smuggles the card
//!   back in through the one door the contract closed.
//! - **Only an object or an array counts.** A scalar under that key is prose
//!   or a number the turn already said; shipping it as a structured result
//!   would be a re-shaping of the text, not a fact the turn produced.
//! - **A `structured_content` is taken whole or not at all.** The walk never
//!   descends into one, so a business object that happens to contain the key
//!   again is one result, not two.
//! - **Duplicates within ONE payload are one output.** A node output is
//!   routinely echoed under a wrapper as well as at the root (the same reason
//!   [`crate::interop::metering::event`]'s usage walk stops at a `usage`), and
//!   two identical artifacts would have a caller believe the flow produced two
//!   results. Across two reply activities they are kept: those are two nodes.

use serde_json::Value;

/// The node-output wrappers a structured value can sit under. The same set
/// [`crate::interop::metering::event`] and `revision_serve::find_rendered_card`
/// walk — a shape one of them can reach is a shape this one must reach, or a
/// caller gets a card and no result, or usage and no result.
const WRAPPER_KEYS: &[&str] = &[
    "outputs",
    "result",
    "structured_content",
    "payload",
    "response",
];

/// The key holding a node's structured value.
const STRUCTURED_KEY: &str = "structured_content";

/// One structured value a turn produced.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StructuredOutput {
    /// The node that produced it, when the runtime named one. It does so on
    /// the transcript lane (`{"node_id": …, "outputs": …}`) and on the error
    /// path; a plain in-process success output carries no name, and this is
    /// then `None` rather than an invented label.
    pub node_id: Option<String>,
    pub value: Value,
}

/// Every structured output one reply activity's payload carries, in the order
/// the runtime appended them.
pub(crate) fn collect(payload: &Value) -> Vec<StructuredOutput> {
    let mut out = Vec::new();
    walk(payload, None, &mut out);
    out
}

fn walk(value: &Value, node_id: Option<&str>, out: &mut Vec<StructuredOutput>) {
    match value {
        Value::Object(map) => {
            // The nearest enclosing `node_id` names everything below it.
            let node_id = map
                .get("node_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .or(node_id);
            if let Some(structured) = map.get(STRUCTURED_KEY)
                && is_structured_result(structured)
            {
                let candidate = StructuredOutput {
                    node_id: node_id.map(str::to_string),
                    value: structured.clone(),
                };
                // Within one payload the same value under two wrappers is one
                // output echoed, not two results.
                if !out.iter().any(|seen| seen.value == candidate.value) {
                    out.push(candidate);
                }
            }
            for key in WRAPPER_KEYS {
                // Never descend into a `structured_content`: it is a result,
                // taken whole or not at all.
                if *key != STRUCTURED_KEY
                    && let Some(nested) = map.get(*key)
                {
                    walk(nested, node_id, out);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| walk(item, node_id, out)),
        _ => {}
    }
}

/// Whether this value is a result a program can read, rather than a scalar or
/// an Adaptive Card under a wrapper.
fn is_structured_result(value: &Value) -> bool {
    matches!(value, Value::Object(_) | Value::Array(_)) && !carries_a_card(value)
}

/// Whether this value is, or contains anywhere, an Adaptive Card.
///
/// Deliberately a DEEP search, and deliberately conservative in the safe
/// direction: a business object with a field genuinely called `renderedCard`
/// loses its artifact, which is a missing output; a card that slips through is
/// a contract-D10 breach on a caller that declared it cannot render one.
fn carries_a_card(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            if map.get("renderedCard").is_some_and(|card| !card.is_null())
                || map.get("type").and_then(Value::as_str) == Some("AdaptiveCard")
            {
                return true;
            }
            map.values().any(carries_a_card)
        }
        Value::Array(items) => items.iter().any(carries_a_card),
        _ => false,
    }
}

#[cfg(test)]
#[path = "structured_output_tests.rs"]
mod tests;
