//! Pure decisions around Fast2Flow: the routing-miss policy and the route
//! signal stamped on replies.

use greentic_types::ChannelMessageEnvelope;
use greentic_types::messaging::extensions::ext_keys;
use serde_json::{Value as JsonValue, json};

use super::*;

fn caps(list: &[&str]) -> Vec<String> {
    list.iter().map(|c| c.to_string()).collect()
}

fn envelope() -> ChannelMessageEnvelope {
    serde_json::from_value(json!({
        "id": "msg-1",
        "tenant": {
            "env": "dev", "tenant": "demo", "tenant_id": "demo",
            "team": "default", "attempt": 0
        },
        "channel": "conv-1",
        "session_id": "conv-1",
        "from": { "id": "user-1", "kind": "user" },
        "text": "something the router does not know",
        "metadata": { "adaptive_card": "{}" }
    }))
    .expect("envelope")
}

fn metadata_signal(out: &ChannelMessageEnvelope) -> Option<JsonValue> {
    out.metadata
        .get(ROUTE_METADATA_KEY)
        .map(|raw| serde_json::from_str(raw).expect("metadata value is JSON"))
}

fn channel_data_signal(out: &ChannelMessageEnvelope) -> Option<&JsonValue> {
    out.extensions
        .get(ext_keys::CHANNEL_DATA)?
        .get(ROUTE_METADATA_KEY)
}

// ---- routing miss ---------------------------------------------------------

#[test]
fn a_miss_without_the_opt_in_keeps_the_fixed_reply() {
    let action = miss_action(false, &caps(&[FAST2FLOW_CAPABILITY]), Some("hello"), None);
    assert_eq!(action, MissAction::FixedReply);

    let reply = miss_reply(&envelope());
    assert_eq!(reply.text.as_deref(), Some(MISS_REPLY_TEXT));
    assert!(!reply.metadata.contains_key("adaptive_card"));
}

#[test]
fn a_miss_with_the_opt_in_runs_the_default_flow() {
    let action = miss_action(
        false,
        &caps(&[
            FAST2FLOW_CAPABILITY,
            FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY,
        ]),
        Some("hello"),
        None,
    );
    assert_eq!(action, MissAction::DefaultFlowOnMiss);
}

#[test]
fn the_opt_in_alone_does_nothing_without_fast2flow() {
    let action = miss_action(
        false,
        &caps(&[FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY]),
        Some("hello"),
        None,
    );
    assert_eq!(action, MissAction::RunDefaultFlow);
}

#[test]
fn an_owned_conversation_never_misses() {
    for list in [
        caps(&[FAST2FLOW_CAPABILITY]),
        caps(&[
            FAST2FLOW_CAPABILITY,
            FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY,
        ]),
    ] {
        assert_eq!(
            miss_action(true, &list, Some("hello"), None),
            MissAction::RunDefaultFlow
        );
    }
}

#[test]
fn blank_or_absent_text_is_not_a_miss() {
    let list = caps(&[FAST2FLOW_CAPABILITY]);
    for text in [None, Some(""), Some("   \n")] {
        assert_eq!(
            miss_action(false, &list, text, None),
            MissAction::RunDefaultFlow
        );
    }
}

// ---- route signal ---------------------------------------------------------

#[test]
fn a_flow_route_names_the_flow_and_no_node() {
    let signal = RouteSignal {
        node: None,
        confidence: Some(0.5),
        source: RouteSource::Bm25,
    };
    assert_eq!(
        signal.to_json("refund"),
        json!({"flow": "refund", "confidence": 0.5, "source": "bm25"})
    );
}

#[test]
fn a_node_route_names_the_node_and_the_flow_it_runs_in() {
    let signal = RouteSignal {
        node: Some("refund_card".into()),
        confidence: Some(0.25),
        source: RouteSource::Llm,
    };
    assert_eq!(
        signal.to_json("default"),
        json!({
            "flow": "default", "node": "refund_card",
            "confidence": 0.25, "source": "llm"
        })
    );
}

#[test]
fn an_absent_or_non_finite_confidence_is_null() {
    for confidence in [None, Some(f32::NAN), Some(f32::INFINITY)] {
        let signal = RouteSignal {
            node: None,
            confidence,
            source: RouteSource::Bm25,
        };
        assert_eq!(signal.to_json("f")["confidence"], JsonValue::Null);
    }
}

#[test]
fn a_routed_turn_stamps_metadata_and_channel_data_on_every_reply() {
    let signal = RouteSignal {
        node: None,
        confidence: Some(0.5),
        source: RouteSource::Bm25,
    };
    let mut outputs = vec![envelope(), envelope()];
    stamp_route(&mut outputs, Some(&signal), "refund");
    let expected = json!({"flow": "refund", "confidence": 0.5, "source": "bm25"});
    for out in &outputs {
        assert_eq!(metadata_signal(out), Some(expected.clone()));
        assert_eq!(channel_data_signal(out), Some(&expected));
    }
}

#[test]
fn stamping_merges_into_existing_channel_data_and_spares_a_non_object() {
    let signal = RouteSignal {
        node: None,
        confidence: None,
        source: RouteSource::Llm,
    };
    let mut merged = envelope();
    merged.extensions.insert(
        ext_keys::CHANNEL_DATA.to_string(),
        json!({"greenticProvenance": {"tools": []}}),
    );
    let mut opaque = envelope();
    opaque
        .extensions
        .insert(ext_keys::CHANNEL_DATA.to_string(), json!("runner-owned"));
    let mut outputs = vec![merged, opaque];
    stamp_route(&mut outputs, Some(&signal), "f");

    let channel_data = &outputs[0].extensions[ext_keys::CHANNEL_DATA];
    assert!(channel_data.get("greenticProvenance").is_some());
    assert_eq!(channel_data[ROUTE_METADATA_KEY]["source"], "llm");
    assert_eq!(
        outputs[1].extensions[ext_keys::CHANNEL_DATA],
        json!("runner-owned")
    );
    assert!(metadata_signal(&outputs[1]).is_some());
}

#[test]
fn an_unrouted_turn_carries_no_signal_even_when_the_inbound_forged_one() {
    let mut forged = envelope();
    forged
        .metadata
        .insert(ROUTE_METADATA_KEY.to_string(), "{\"flow\":\"x\"}".into());
    forged.extensions.insert(
        ext_keys::CHANNEL_DATA.to_string(),
        json!({ ROUTE_METADATA_KEY: {"flow": "x"}, "other": 1 }),
    );
    let mut outputs = vec![forged];
    stamp_route(&mut outputs, None, "default");
    assert!(metadata_signal(&outputs[0]).is_none());
    assert!(channel_data_signal(&outputs[0]).is_none());
    assert_eq!(outputs[0].extensions[ext_keys::CHANNEL_DATA]["other"], 1);
}

#[test]
fn an_unhandled_directive_gets_the_fixed_reply_even_with_the_opt_in() {
    let list = caps(&[
        FAST2FLOW_CAPABILITY,
        FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY,
    ]);
    let deny = Unrouted::Unhandled("deny");
    assert_eq!(
        miss_action(false, &list, Some("hello"), Some(&deny)),
        MissAction::FixedReply
    );
    let failed = Unrouted::RouterFailed("exit 1".into());
    assert_eq!(
        miss_action(false, &list, Some("hello"), Some(&failed)),
        MissAction::DefaultFlowOnMiss
    );
}

#[test]
fn probe_turn_keeps_the_host_cause_and_stops_on_unhandled() {
    let failed = || Err::<u8, _>(Unrouted::RouterFailed("exit 1".into()));
    assert_eq!(probe_turn(failed(), || None), failed());
    assert_eq!(probe_turn(failed(), || Some(7)), Ok(7));
    assert_eq!(
        probe_turn(Err::<u8, _>(Unrouted::Unhandled("respond")), || {
            panic!("no LLM after an unhandled directive")
        }),
        Err(Unrouted::Unhandled("respond"))
    );
}

#[test]
fn confidence_serialises_as_its_shortest_decimal() {
    for (confidence, text) in [(0.92f32, "0.92"), (0.9f32, "0.9")] {
        let signal = RouteSignal {
            node: None,
            confidence: Some(confidence),
            source: RouteSource::Bm25,
        };
        let serialised = signal.to_json("f").to_string();
        assert!(
            serialised.contains(&format!("\"confidence\":{text},")),
            "{serialised}"
        );
    }
}

#[test]
fn confidence_outside_the_unit_interval_is_null() {
    for confidence in [-0.1f32, 1.5] {
        let signal = RouteSignal {
            node: None,
            confidence: Some(confidence),
            source: RouteSource::Bm25,
        };
        assert_eq!(signal.to_json("f")["confidence"], JsonValue::Null);
    }
}
