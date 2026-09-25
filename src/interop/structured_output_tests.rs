//! What counts as a turn's structured output, and what deliberately does not.

use super::*;
use serde_json::json;

fn values(payload: &Value) -> Vec<Value> {
    collect(payload).into_iter().map(|out| out.value).collect()
}

/// The shape the shared reply shaper stringifies into a text part
/// (`parse_envelopes`' `structured_text` fallback). This is the whole reason
/// the module exists.
#[test]
fn a_components_result_object_is_a_structured_output() {
    let payload = json!({"result": {"structured_content": {"temp_c": 21.3}}});
    assert_eq!(values(&payload), vec![json!({"temp_c": 21.3})]);
}

/// The transcript-lane node-output shape, which names its node.
#[test]
fn the_producing_node_names_the_output_when_the_runtime_named_one() {
    let payload = json!({
        "node_id": "call_weather",
        "outputs": {"ok": true, "result": {"structured_content": {"temp_c": 21.3}}}
    });
    let collected = collect(&payload);
    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0].node_id.as_deref(), Some("call_weather"));
    assert_eq!(collected[0].value, json!({"temp_c": 21.3}));
}

/// An in-process success output carries no node name, and an invented one
/// would be a label a caller could not correlate with anything.
#[test]
fn an_unnamed_output_stays_unnamed() {
    let payload = json!({"result": {"structured_content": {"ok": true}}});
    assert_eq!(collect(&payload)[0].node_id, None);
}

/// The `session.wait` wrapper is one of the walked keys, so a parked turn's
/// structured output is still found.
#[test]
fn a_parked_turns_structured_output_is_found_under_the_pending_wrapper() {
    let payload = json!({
        "status": "pending",
        "response": {"result": {"structured_content": {"quote_id": "q-1"}}}
    });
    assert_eq!(values(&payload), vec![json!({"quote_id": "q-1"})]);
}

/// A dw.agent turn is prose. Nothing here may manufacture a structure from it.
#[test]
fn a_prose_reply_has_no_structured_output() {
    let payload = json!({"reply": "the answer", "trail": [], "terminated_by": "final"});
    assert!(collect(&payload).is_empty());
}

#[test]
fn a_plain_text_reply_has_no_structured_output() {
    assert!(collect(&json!({"text": "hello"})).is_empty());
}

/// Contract D10: a card reaches an agent caller only through the opt-in, so a
/// `structured_content` that is really card transport is skipped whole.
#[test]
fn a_card_carried_under_the_structured_key_is_not_a_structured_output() {
    let payload =
        json!({"result": {"structured_content": {"renderedCard": {"type": "AdaptiveCard"}}}});
    assert!(collect(&payload).is_empty());
}

/// Skipped rather than stripped: this module must not have to decide which
/// half of such an object is the result.
#[test]
fn a_result_mixed_with_a_card_is_skipped_rather_than_stripped() {
    let payload = json!({"result": {"structured_content": {
        "renderedCard": {"type": "AdaptiveCard"},
        "order_id": "A-1"
    }}});
    assert!(collect(&payload).is_empty());
}

#[test]
fn a_card_nested_deep_inside_a_result_still_disqualifies_it() {
    let payload = json!({"result": {"structured_content": {
        "page": {"widgets": [{"renderedCard": {"type": "AdaptiveCard"}}]}
    }}});
    assert!(collect(&payload).is_empty());
}

#[test]
fn a_bare_adaptive_card_under_the_structured_key_is_not_a_structured_output() {
    let payload = json!({"result": {"structured_content": {
        "type": "AdaptiveCard", "version": "1.6", "body": []
    }}});
    assert!(collect(&payload).is_empty());
}

/// A scalar is something the turn already said in prose.
#[test]
fn a_scalar_structured_content_is_not_a_structured_output() {
    for scalar in [json!("hello"), json!(3), json!(true), json!(null)] {
        let payload = json!({"result": {"structured_content": scalar}});
        assert!(collect(&payload).is_empty(), "{scalar}");
    }
}

/// An array is a real structure — a list of rows is the commonest structured
/// answer there is.
#[test]
fn an_array_is_a_structured_output() {
    let payload = json!({"result": {"structured_content": [{"id": 1}, {"id": 2}]}});
    assert_eq!(values(&payload), vec![json!([{"id": 1}, {"id": 2}])]);
}

/// A node output echoed under a wrapper AND at the root is one result.
#[test]
fn an_echoed_output_is_reported_once() {
    let payload = json!({
        "result": {"structured_content": {"temp_c": 21.3}},
        "outputs": {"result": {"structured_content": {"temp_c": 21.3}}}
    });
    assert_eq!(values(&payload), vec![json!({"temp_c": 21.3})]);
}

/// Two genuinely different node outputs in one payload are two results, in
/// the order the runtime appended them.
#[test]
fn two_different_outputs_in_one_payload_are_both_reported_in_order() {
    let payload = json!({"outputs": [
        {"result": {"structured_content": {"step": 1}}},
        {"result": {"structured_content": {"step": 2}}}
    ]});
    assert_eq!(
        values(&payload),
        vec![json!({"step": 1}), json!({"step": 2})]
    );
}

/// Taken whole: a business object that happens to carry the key again is one
/// result, not two.
#[test]
fn the_walk_never_descends_into_a_structured_content() {
    let payload = json!({"result": {"structured_content": {
        "structured_content": {"inner": true}
    }}});
    assert_eq!(
        values(&payload),
        vec![json!({"structured_content": {"inner": true}})]
    );
}

/// The walk is confined to the known wrapper keys, so an unrelated
/// `structured_content` somewhere else in the payload is not mistaken for a
/// node output — the same confinement `find_rendered_card` applies.
#[test]
fn an_unrelated_structured_content_outside_the_wrappers_is_not_collected() {
    let payload = json!({"metadata": {"structured_content": {"not": "a result"}}});
    assert!(collect(&payload).is_empty());
}
