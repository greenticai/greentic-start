//! What a turn's usage is read from, and what the body must never carry.

use super::*;
use serde_json::json;

/// The `dw.agent` node output greentic-runner-host builds for a successful
/// turn, byte-for-byte: `{"reply","trail","terminated_by","usage"}`. Pinned
/// against the REAL runtime by
/// [`crate::agent_provenance`]'s `runtime_contract_tests`; this module reads
/// the same wrapper.
fn dw_agent_reply(reply: &str, tokens_in: u64, tokens_out: u64, iterations: u64) -> Activity {
    Activity::custom(
        "response",
        json!({
            "reply": reply,
            "trail": [{"kind": "llm_call", "model": "stub"}],
            "terminated_by": "final",
            "usage": {"tokens_in": tokens_in, "tokens_out": tokens_out, "iterations": iterations},
        }),
    )
}

#[test]
fn a_dw_agent_reply_yields_its_usage() {
    let usage = usage_from_replies(&[dw_agent_reply("the answer", 120, 45, 2)]);
    assert_eq!(
        usage,
        TurnUsage {
            tokens_in: 120,
            tokens_out: 45,
            iterations: 2
        }
    );
}

#[test]
fn a_turn_with_no_usage_reads_as_zero() {
    let replies = vec![
        Activity::text("hello"),
        Activity::custom("response", json!({"reply": "hi", "trail": []})),
    ];
    assert_eq!(usage_from_replies(&replies), TurnUsage::default());
    assert_eq!(usage_from_replies(&[]), TurnUsage::default());
}

/// `session.wait` wraps a parked turn as `{"status":"pending","response":…}`,
/// and the adaptive-card `card` op nests its output under the runner's
/// wrapper keys. A turn that parked still spent.
#[test]
fn usage_is_found_through_the_pending_and_wrapper_nestings() {
    let parked = Activity::custom(
        "response",
        json!({"status": "pending", "response": {"reply": "", "usage": {"tokens_in": 7, "tokens_out": 3, "iterations": 1}}}),
    );
    assert_eq!(
        usage_from_replies(&[parked]),
        TurnUsage {
            tokens_in: 7,
            tokens_out: 3,
            iterations: 1
        }
    );

    let nested = Activity::custom(
        "response",
        json!({"outputs": {"result": {"usage": {"tokens_in": 5, "tokens_out": 1, "iterations": 1}}}}),
    );
    assert_eq!(
        usage_from_replies(&[nested]),
        TurnUsage {
            tokens_in: 5,
            tokens_out: 1,
            iterations: 1
        }
    );
}

/// Two `dw.agent` nodes in one turn really did spend twice, and two replies
/// really are two node outputs.
#[test]
fn two_agent_outputs_in_one_turn_are_summed() {
    let replies = vec![
        dw_agent_reply("first", 10, 2, 1),
        dw_agent_reply("second", 5, 3, 2),
    ];
    assert_eq!(
        usage_from_replies(&replies),
        TurnUsage {
            tokens_in: 15,
            tokens_out: 5,
            iterations: 3
        }
    );
    let array = Activity::custom(
        "response",
        json!({"outputs": [
            {"usage": {"tokens_in": 1, "tokens_out": 1, "iterations": 1}},
            {"usage": {"tokens_in": 2, "tokens_out": 2, "iterations": 1}}
        ]}),
    );
    assert_eq!(
        usage_from_replies(&[array]),
        TurnUsage {
            tokens_in: 3,
            tokens_out: 3,
            iterations: 2
        }
    );
}

/// The runner routinely echoes a node output under a wrapper as well as at
/// the root. Counting both would silently double every turn's tokens — a
/// number nobody can check against the provider's own bill.
#[test]
fn an_echoed_node_output_is_counted_once() {
    let echoed = Activity::custom(
        "response",
        json!({
            "reply": "answer",
            "usage": {"tokens_in": 100, "tokens_out": 20, "iterations": 1},
            "outputs": {"result": {
                "reply": "answer",
                "usage": {"tokens_in": 100, "tokens_out": 20, "iterations": 1}
            }}
        }),
    );
    assert_eq!(
        usage_from_replies(&[echoed]),
        TurnUsage {
            tokens_in: 100,
            tokens_out: 20,
            iterations: 1
        }
    );
}

/// An object under the key `usage` that carries none of the three counters is
/// not a `StepUsage`. Reading it as a zero would END the descent and hide the
/// real one below it.
#[test]
fn an_unrelated_usage_key_does_not_shadow_the_real_one() {
    let reply = Activity::custom(
        "response",
        json!({
            "usage": {"policy": "fair-use"},
            "outputs": {"result": {"usage": {"tokens_in": 9, "tokens_out": 4, "iterations": 1}}}
        }),
    );
    assert_eq!(
        usage_from_replies(&[reply]),
        TurnUsage {
            tokens_in: 9,
            tokens_out: 4,
            iterations: 1
        }
    );
}

#[test]
fn occurred_at_is_z_normalised() {
    let now = now_rfc3339();
    assert!(now.ends_with('Z'), "{now}");
    assert!(!now.contains('+'), "{now}");
    assert!(
        chrono::DateTime::parse_from_rfc3339(&now).is_ok(),
        "{now} is not RFC 3339"
    );
}

#[test]
fn an_event_id_is_a_ulid() {
    let id = new_event_id();
    assert_eq!(id.len(), 26, "{id}");
    assert!(ulid::Ulid::from_string(&id).is_ok(), "{id}");
    assert_ne!(id, new_event_id());
}

/// The event type has no field that could hold turn content, and this is the
/// assertion that says so at the TYPE's own level: every serialized key is
/// one of a closed list of identifiers and counters.
///
/// It is the cheap half of the property. The expensive half — that nothing
/// along the production chain PUTS content into one — is
/// `a2a::rpc::rpc_tests::no_turn_content_reaches_the_recorded_event`, which
/// drives a real turn.
#[test]
fn the_event_carries_only_identifiers_and_counters() {
    let event = UsageEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339(),
        tenant_slug: "acme".into(),
        deployment_id: "01J0000000000000000000000".into(),
        bundle_id: "support-bot".into(),
        agent_id: "support-agent".into(),
        credential_id: Some("c_01J".into()),
        surface: Surface::A2a.as_str(),
        tokens_in: 120,
        tokens_out: 45,
        iterations: 2,
        duration_ms: 1234,
    };
    let body = serde_json::to_value(&event).expect("serialise");
    let mut keys: Vec<&str> = body
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "agent_id",
            "bundle_id",
            "credential_id",
            "deployment_id",
            "duration_ms",
            "event_id",
            "iterations",
            "occurred_at",
            "surface",
            "tenant_slug",
            "tokens_in",
            "tokens_out",
        ],
        "a new field on the usage event must be justified against \"no message content\": {body}"
    );
}

/// An OAuth MCP caller has no staged credential id, and absent is not the
/// same fact as empty — so the field is omitted, never emitted as `""`.
/// `tenant_slug` is NOT optional and so is always present.
#[test]
fn an_absent_credential_is_omitted_not_emptied() {
    let event = UsageEvent {
        event_id: "e".into(),
        occurred_at: "2026-09-23T00:00:00.000Z".into(),
        tenant_slug: "acme".into(),
        deployment_id: "d".into(),
        bundle_id: "b".into(),
        agent_id: "a".into(),
        credential_id: None,
        surface: Surface::Mcp.as_str(),
        tokens_in: 0,
        tokens_out: 0,
        iterations: 0,
        duration_ms: 0,
    };
    let body = serde_json::to_value(&event).expect("serialise");
    assert_eq!(body["tenant_slug"], "acme");
    assert!(body.get("credential_id").is_none(), "{body}");
    assert_eq!(body["surface"], "mcp");
    assert_eq!(body["tokens_in"], 0);
}
