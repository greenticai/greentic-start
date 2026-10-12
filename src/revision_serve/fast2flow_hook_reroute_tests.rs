//! Pure pieces of the re-route-a-parked-conversation path.

use serde_json::json;

use super::{is_free_text, snapshot_ran};
use crate::revision_serve::fast2flow_hook_tests::envelope;

#[test]
fn plain_text_is_free_text() {
    assert!(is_free_text(&envelope("I need a freight quote")));
}

#[test]
fn blank_text_is_not_free_text() {
    assert!(!is_free_text(&envelope("   ")));
}

#[test]
fn a_card_action_is_not_free_text() {
    let mut env = envelope("submit");
    env.metadata.insert("action".to_string(), "submit".into());
    assert!(!is_free_text(&env));
}

#[test]
fn a_node_that_ran_is_found_in_the_snapshot() {
    let snap = json!({"state": {"nodes": {"ask_partner": {"ok": true}}}});
    assert!(snapshot_ran(&snap, "ask_partner"));
    assert!(!snapshot_ran(&snap, "ask_freight"));
}

#[test]
fn a_snapshot_without_node_outputs_ran_nothing() {
    assert!(!snapshot_ran(&json!({}), "ask_partner"));
    assert!(!snapshot_ran(
        &json!({"state": {"nodes": []}}),
        "ask_partner"
    ));
}
