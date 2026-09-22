//! Turn a flow turn's reply activities into protocol-neutral reply items.
//!
//! Built on the ONE reply shaper the messaging channels use
//! ([`crate::revision_serve::build_reply_envelopes`] →
//! [`crate::messaging_app::parse_envelopes`]), so an interop caller sees
//! exactly what a webchat user would: a `dw.agent` `reply`, a top-level or
//! nested `renderedCard`, `messages[]`, result text, a categorized flow error.
//! `activity_to_worker_message` (the `/workers/invoke` projector) is NOT
//! reused, because it does not read the `dw.agent` `reply` field.

use greentic_runner_host::Activity;
use greentic_types::ChannelMessageEnvelope;
use greentic_types::messaging::extensions::ext_keys;
use serde_json::{Value, json};

/// One user-visible piece of a reply.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ReplyItem {
    Text(String),
    /// An Adaptive Card body, plus its plain-text fallback.
    Card {
        card: Value,
        fallback: String,
    },
}

/// Everything one turn produced.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ProjectedReply {
    pub items: Vec<ReplyItem>,
    /// The flow parked waiting for the caller (a card or form awaiting
    /// submit). The caller's next message in the same conversation resumes it.
    pub awaiting_input: bool,
}

/// Project every reply of one turn. `channel` names the protocol for the
/// synthetic ingress envelope the shared shaper routes replies from.
pub(crate) fn project_replies(
    replies: &[Activity],
    channel: &str,
    tenant: &str,
    bundle_id: &str,
    session_hint: &str,
) -> ProjectedReply {
    let ingress = synthetic_ingress(channel, tenant, session_hint);
    let mut projected = ProjectedReply::default();
    for reply in replies {
        if is_pending(reply.payload()) {
            projected.awaiting_input = true;
        }
        let Some(ingress) = ingress.as_ref() else {
            // Unreachable in practice (the envelope is a fixed shape); keep
            // the plain text rather than losing the turn.
            if let Some(text) = reply.payload().get("text").and_then(Value::as_str) {
                projected.items.push(ReplyItem::Text(text.to_string()));
            }
            continue;
        };
        let pack_id = reply.pack_id().unwrap_or(bundle_id);
        for envelope in
            crate::revision_serve::build_reply_envelopes(ingress, reply, pack_id, tenant)
        {
            push_envelope(&mut projected.items, &envelope);
        }
    }
    projected
}

fn push_envelope(items: &mut Vec<ReplyItem>, envelope: &ChannelMessageEnvelope) {
    let card = envelope
        .extensions
        .get(ext_keys::ADAPTIVE_CARD)
        .cloned()
        .or_else(|| {
            envelope
                .metadata
                .get("adaptive_card")
                .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        })
        .filter(|card| !card.is_null());
    if let Some(text) = envelope
        .text
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        items.push(ReplyItem::Text(text.to_string()));
    }
    if let Some(card) = card {
        let fallback = card_fallback_text(&card);
        items.push(ReplyItem::Card { card, fallback });
    }
}

/// `session.wait` wraps a parked turn's output as `{"status":"pending",…}`.
fn is_pending(payload: &Value) -> bool {
    payload.get("status").and_then(Value::as_str) == Some("pending")
}

/// The card's own `fallbackText`, else its `TextBlock` texts in order, else a
/// placeholder — so a caller that cannot render cards still reads something.
pub(crate) fn card_fallback_text(card: &Value) -> String {
    if let Some(text) = card
        .get("fallbackText")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        return text.to_string();
    }
    let mut texts = Vec::new();
    collect_text_blocks(card, &mut texts);
    if texts.is_empty() {
        "[Adaptive Card]".to_string()
    } else {
        texts.join("\n")
    }
}

fn collect_text_blocks(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if map.get("type").and_then(Value::as_str) == Some("TextBlock")
                && let Some(text) = map
                    .get("text")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
            {
                out.push(text.to_string());
            }
            for child in map.values() {
                collect_text_blocks(child, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_text_blocks(item, out)),
        _ => {}
    }
}

fn synthetic_ingress(channel: &str, tenant: &str, session: &str) -> Option<ChannelMessageEnvelope> {
    let env = crate::resolve_env(None);
    serde_json::from_value(json!({
        "id": ulid::Ulid::new().to_string(),
        "tenant": {"env": env, "tenant": tenant, "tenant_id": tenant, "attempt": 0},
        "channel": channel,
        "session_id": session,
    }))
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(replies: &[Activity]) -> ProjectedReply {
        project_replies(replies, "a2a", "acme", "support-bot", "a2a:c1:ctx")
    }

    #[test]
    fn the_synthetic_ingress_envelope_is_well_formed() {
        assert!(synthetic_ingress("a2a", "acme", "s").is_some());
    }

    #[test]
    fn a_text_reply() {
        let got = project(&[Activity::text("hello")]);
        assert_eq!(got.items, vec![ReplyItem::Text("hello".into())]);
        assert!(!got.awaiting_input);
    }

    #[test]
    fn a_dw_agent_reply() {
        let reply = Activity::custom(
            "response",
            json!({"reply": "the answer", "trail": [], "terminated_by": "final"}),
        );
        assert_eq!(
            project(&[reply]).items,
            vec![ReplyItem::Text("the answer".into())]
        );
    }

    #[test]
    fn a_nested_card_with_its_text_fallback() {
        let card = json!({
            "type": "AdaptiveCard", "version": "1.6",
            "body": [{"type": "TextBlock", "text": "Pick one"}, {"type": "Container",
                "items": [{"type": "TextBlock", "text": "Nested"}]}]
        });
        let reply = Activity::custom(
            "response",
            json!({"outputs": {"result": {"renderedCard": card.clone()}}}),
        );
        assert_eq!(
            project(&[reply]).items,
            vec![ReplyItem::Card {
                card,
                fallback: "Pick one\nNested".into()
            }]
        );
    }

    #[test]
    fn a_pending_turn_is_awaiting_input() {
        let card = json!({"type": "AdaptiveCard", "fallbackText": "Fill the form"});
        let reply = Activity::custom(
            "response",
            json!({"status": "pending", "response": {"renderedCard": card.clone()}}),
        );
        let got = project(&[reply]);
        assert!(got.awaiting_input);
        assert_eq!(
            got.items,
            vec![ReplyItem::Card {
                card,
                fallback: "Fill the form".into()
            }]
        );
    }

    #[test]
    fn a_flow_error_becomes_a_user_safe_text() {
        let reply = Activity::custom(
            "response",
            json!({"metadata": {"error_kind": "component", "error_message": "API key is invalid"}}),
        );
        let got = project(&[reply]);
        assert_eq!(got.items.len(), 1);
        let ReplyItem::Text(text) = &got.items[0] else {
            panic!("expected text, got {:?}", got.items);
        };
        assert!(!text.is_empty());
        assert!(!got.awaiting_input);
    }

    #[test]
    fn fallback_text_placeholder() {
        assert_eq!(
            card_fallback_text(&json!({"type": "AdaptiveCard"})),
            "[Adaptive Card]"
        );
    }
}
