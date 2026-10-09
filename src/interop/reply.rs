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

use super::structured_output::{self, StructuredOutput};

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
    /// The flow ENDED AT A FAILURE and the text above is the categorized
    /// error, not an answer. A protocol that can say so (MCP's `isError`)
    /// must, or the error reads to a caller as the worker's reply.
    pub flow_error: bool,
    /// The Adaptive Card the PARKING reply carried, when it carried one.
    ///
    /// A turn may produce several cards; only this one is the question being
    /// asked, so only this one may be turned into an input request
    /// ([`crate::interop::input_request`]). A `session.wait` that rendered no
    /// card parks with `None`, which is a question with no named fields —
    /// not the absence of a question.
    pub parked_card: Option<Value>,
    /// The structured values the turn's nodes produced, in the order the
    /// runtime appended them ([`super::structured_output`]).
    ///
    /// Read off the raw reply activities, NOT off [`Self::items`]: by the
    /// time the shared shaper has run, a structured value has already been
    /// stringified into a text part or dropped in favour of one. Nothing here
    /// is derived from the prose — a turn that produced no structured value
    /// carries an empty list, which is a different fact from producing an
    /// empty one.
    pub structured: Vec<StructuredOutput>,
}

impl ProjectedReply {
    /// The question a parked turn is asking, in prose.
    ///
    /// The parked card's own fallback text, else everything the turn said —
    /// a `session.wait` with no card still asked something. One spelling, so
    /// the A2A and MCP surfaces cannot present the same parked turn with two
    /// different questions.
    pub(crate) fn parked_prompt(&self) -> String {
        if let Some(card) = self.parked_card.as_ref() {
            return card_fallback_text(card);
        }
        self.items
            .iter()
            .map(|item| match item {
                ReplyItem::Text(text) => text.as_str(),
                ReplyItem::Card { fallback, .. } => fallback.as_str(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The contract §9.2 document for a parked turn, ready to ride as a
    /// `data` part.
    pub(crate) fn input_request(&self) -> Value {
        crate::interop::input_request::input_request(
            &self.parked_prompt(),
            self.parked_card.as_ref(),
        )
    }
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
        let parks = is_pending(reply.payload());
        if parks {
            projected.awaiting_input = true;
        }
        // From the RAW payload, before the shaper has had a chance to
        // stringify it into prose or drop it for a text sibling.
        projected
            .structured
            .extend(structured_output::collect(reply.payload()));
        // Where THIS reply's items start, so the card it parked on can be
        // told apart from a card an earlier reply of the same turn rendered.
        let first_item = projected.items.len();
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
            // `parse_envelopes`' flow-error branch is the ONLY one that stamps
            // `error_kind`, and it stamps it on the reply it categorized.
            if envelope.metadata.contains_key("error_kind") {
                projected.flow_error = true;
            }
            push_envelope(&mut projected.items, &envelope);
        }
        if parks {
            // The LAST card this reply produced: a parking reply that
            // rendered several has parked on the one the caller is looking
            // at. A later parking reply supersedes an earlier one for the
            // same reason.
            if let Some(card) =
                projected.items[first_item..]
                    .iter()
                    .rev()
                    .find_map(|item| match item {
                        ReplyItem::Card { card, .. } => Some(card.clone()),
                        ReplyItem::Text(_) => None,
                    })
            {
                projected.parked_card = Some(card);
            }
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
        assert!(!got.flow_error, "an ordinary reply is not an error");
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
                card: card.clone(),
                fallback: "Fill the form".into()
            }]
        );
        assert_eq!(got.parked_card, Some(card));
        assert_eq!(got.parked_prompt(), "Fill the form");
    }

    /// A turn may render a card and THEN park on another. Only the card the
    /// turn parked on is the question being asked, so only that one may
    /// become an input request.
    #[test]
    fn only_the_parking_replys_card_is_the_parked_card() {
        let answered = json!({"type": "AdaptiveCard", "fallbackText": "Here is your summary"});
        let asking = json!({"type": "AdaptiveCard", "fallbackText": "Now pick one"});
        let got = project(&[
            Activity::custom(
                "response",
                json!({"outputs": {"result": {"renderedCard": answered}}}),
            ),
            Activity::custom(
                "response",
                json!({"status": "pending", "response": {"renderedCard": asking.clone()}}),
            ),
        ]);
        assert!(got.awaiting_input);
        assert_eq!(got.items.len(), 2, "both cards still reach the caller");
        assert_eq!(got.parked_card, Some(asking));
        assert_eq!(got.parked_prompt(), "Now pick one");
    }

    /// A `session.wait` with no card at all parks on a question the turn
    /// asked in prose.
    #[test]
    fn a_parked_turn_with_no_card_still_has_a_prompt() {
        let reply = Activity::custom(
            "response",
            json!({"status": "pending", "response": {"text": "What is the order number?"}}),
        );
        let got = project(&[reply]);
        assert!(got.awaiting_input);
        assert_eq!(got.parked_card, None);
        assert_eq!(got.parked_prompt(), "What is the order number?");
        assert_eq!(
            got.input_request(),
            json!({"prompt": "What is the order number?", "fields": [], "actions": []}),
            "no card is a question with no named fields, not the absence of one"
        );
    }

    /// A completed turn's card is NOT a parked card: nothing is waiting, so
    /// nothing may be presented as a question.
    #[test]
    fn a_completed_turn_has_no_parked_card() {
        let card = json!({"type": "AdaptiveCard", "fallbackText": "Your receipt"});
        let got = project(&[Activity::custom(
            "response",
            json!({"outputs": {"result": {"renderedCard": card}}}),
        )]);
        assert!(!got.awaiting_input);
        assert_eq!(got.parked_card, None);
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
        assert!(
            got.flow_error,
            "a failed flow must be reportable as an error"
        );
    }

    /// The structured value is read off the RAW activity, so it survives the
    /// shaper turning it into a text part.
    #[test]
    fn a_structured_output_is_projected_beside_the_prose_the_shaper_made_of_it() {
        let reply = Activity::custom(
            "response",
            json!({"result": {"structured_content": {"temp_c": 21.3}}}),
        );
        let got = project(&[reply]);
        assert_eq!(got.structured.len(), 1);
        assert_eq!(got.structured[0].value, json!({"temp_c": 21.3}));
        assert!(
            !got.items.is_empty(),
            "the prose the shaper produced is untouched"
        );
    }

    /// The case that used to lose the object outright: `result.content[].text`
    /// wins the shaper's `.or()` chain, so the structure reached nobody.
    #[test]
    fn a_structured_output_survives_a_text_sibling_that_beats_it_in_the_shaper() {
        let reply = Activity::custom(
            "response",
            json!({"result": {
                "content": [{"type": "text", "text": "21.3 degrees"}],
                "structured_content": {"temp_c": 21.3}
            }}),
        );
        let got = project(&[reply]);
        assert_eq!(got.items, vec![ReplyItem::Text("21.3 degrees".into())]);
        assert_eq!(got.structured.len(), 1);
        assert_eq!(got.structured[0].value, json!({"temp_c": 21.3}));
    }

    #[test]
    fn a_prose_only_turn_projects_no_structured_output() {
        let reply = Activity::custom(
            "response",
            json!({"reply": "the answer", "trail": [], "terminated_by": "final"}),
        );
        assert!(project(&[reply]).structured.is_empty());
    }

    /// Two replies are two nodes, so two structured outputs, in order.
    #[test]
    fn each_reply_contributes_its_own_structured_output() {
        let got = project(&[
            Activity::custom(
                "response",
                json!({"result": {"structured_content": {"step": 1}}}),
            ),
            Activity::custom(
                "response",
                json!({"result": {"structured_content": {"step": 2}}}),
            ),
        ]);
        let values: Vec<_> = got.structured.iter().map(|o| o.value.clone()).collect();
        assert_eq!(values, vec![json!({"step": 1}), json!({"step": 2})]);
    }

    #[test]
    fn fallback_text_placeholder() {
        assert_eq!(
            card_fallback_text(&json!({"type": "AdaptiveCard"})),
            "[Adaptive Card]"
        );
    }
}
