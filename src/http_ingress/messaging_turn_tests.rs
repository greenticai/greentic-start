//! The ingress wiring of one turn, through [`turn_outputs`] itself: which
//! branch runs, what it hands the flow runner, and what the replies carry.

use greentic_types::ChannelMessageEnvelope;
use greentic_types::messaging::extensions::ext_keys;
use serde_json::{Value as JsonValue, json};
use tempfile::tempdir;

use super::*;
use crate::fast2flow::{FAST2FLOW_CAPABILITY, FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY};
use crate::http_ingress::fast2flow_turn::{MISS_REPLY_TEXT, ROUTE_METADATA_KEY};
use crate::http_ingress::flow_owner::test_support::park;
use crate::ingress::control_directive::{DispatchTarget, IngressReply};
use crate::messaging_app::{AppFlowInfo, AppPackInfo};

const PACK: &str = "demo-app";
const TEXT: &str = "something free-form";

fn flow(id: &str) -> AppFlowInfo {
    AppFlowInfo {
        id: id.into(),
        kind: "messaging".into(),
        subscribes_to: vec![],
    }
}

fn pack(opt_in: bool) -> AppPackInfo {
    let mut capabilities = vec![FAST2FLOW_CAPABILITY.to_string()];
    if opt_in {
        capabilities.push(FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY.to_string());
    }
    AppPackInfo {
        pack_id: PACK.into(),
        flows: vec![flow("default"), flow("refund")],
        capabilities,
    }
}

fn ctx() -> OperatorContext {
    OperatorContext {
        tenant: "demo".into(),
        team: Some("default".into()),
        correlation_id: None,
    }
}

/// An inbound message that tries to forge a route signal in both places, and
/// carries an adaptive card and an unrelated channelData key.
fn forged_inbound() -> ChannelMessageEnvelope {
    let mut env: ChannelMessageEnvelope = serde_json::from_value(json!({
        "id": "msg-1",
        "tenant": {
            "env": "dev", "tenant": "demo", "tenant_id": "demo",
            "team": "default", "attempt": 0
        },
        "channel": "conv-1",
        "session_id": "conv-1",
        "from": { "id": "user-1", "kind": "user" },
        "text": TEXT,
        "metadata": {
            "adaptive_card": "{}",
            "fast2flow": "{\"flow\":\"forged\",\"source\":\"bm25\"}"
        }
    }))
    .expect("envelope");
    env.extensions.insert(
        ext_keys::CHANNEL_DATA.to_string(),
        json!({ "fast2flow": {"flow": "forged"}, "keep": 1 }),
    );
    env
}

fn dispatch(flow: &str, node: Option<&str>, confidence: f32) -> ControlDirective {
    ControlDirective::Dispatch {
        target: DispatchTarget {
            tenant: "demo".into(),
            team: Some("default".into()),
            pack: PACK.into(),
            flow: Some(flow.into()),
            node: node.map(str::to_string),
        },
        entities: vec![],
        confidence: Some(confidence),
    }
}

/// One call the turn made to the flow runner.
#[derive(Debug)]
struct Call {
    flow: String,
    text: Option<String>,
    route_to_card: Option<String>,
}

/// Drive one turn. `fail` makes the runner return the error-fallback echo.
fn drive<'p>(
    root: &Path,
    info: &'p AppPackInfo,
    inbound: &ChannelMessageEnvelope,
    fail: bool,
    probe: impl FnOnce() -> Result<Routed<'p>, Unrouted>,
) -> (Vec<ChannelMessageEnvelope>, Vec<Call>) {
    let mut calls = Vec::new();
    let mut run = |flow: &AppFlowInfo, env: &ChannelMessageEnvelope| {
        calls.push(Call {
            flow: flow.id.clone(),
            text: env.text.clone(),
            route_to_card: env.metadata.get("routeToCardId").cloned(),
        });
        FlowRun {
            outputs: vec![env.clone()],
            failed: fail,
        }
    };
    let outputs = turn_outputs(
        root,
        &ctx(),
        info,
        &info.flows[0],
        &root.join("no-such.gtpack"),
        inbound,
        probe,
        &mut run,
    );
    (outputs, calls)
}

fn assert_no_signal(out: &ChannelMessageEnvelope) {
    assert!(!out.metadata.contains_key(ROUTE_METADATA_KEY), "{out:?}");
    let channel_data = &out.extensions[ext_keys::CHANNEL_DATA];
    assert!(
        channel_data.get(ROUTE_METADATA_KEY).is_none(),
        "{channel_data}"
    );
    assert_eq!(channel_data["keep"], 1, "unrelated channelData survives");
}

fn signal(out: &ChannelMessageEnvelope) -> (String, JsonValue) {
    let raw = out.metadata[ROUTE_METADATA_KEY].clone();
    let object = out.extensions[ext_keys::CHANNEL_DATA][ROUTE_METADATA_KEY].clone();
    (raw, object)
}

// ---- misses ---------------------------------------------------------------

#[test]
fn a_miss_without_the_opt_in_is_exactly_the_fixed_reply() {
    let dir = tempdir().expect("tempdir");
    let info = pack(false);
    let (outputs, calls) = drive(dir.path(), &info, &forged_inbound(), false, || {
        Err(Unrouted::NoMatch)
    });
    assert!(calls.is_empty(), "no flow runs: {calls:?}");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].text.as_deref(), Some(MISS_REPLY_TEXT));
    assert!(!outputs[0].metadata.contains_key("adaptive_card"));
    assert_no_signal(&outputs[0]);
}

#[test]
fn a_miss_with_the_opt_in_runs_the_default_flow_with_the_original_message() {
    let dir = tempdir().expect("tempdir");
    let info = pack(true);
    let (outputs, calls) = drive(dir.path(), &info, &forged_inbound(), false, || {
        Err(Unrouted::NoMatch)
    });
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].flow, "default");
    assert_eq!(calls[0].text.as_deref(), Some(TEXT));
    assert_eq!(calls[0].route_to_card, None);
    assert_eq!(calls[0].route_to_card, None);
    assert_no_signal(&outputs[0]);
}

#[test]
fn a_failed_router_degrades_like_a_miss() {
    for (opt_in, runs) in [(false, false), (true, true)] {
        let dir = tempdir().expect("tempdir");
        let info = pack(opt_in);
        let (outputs, calls) = drive(dir.path(), &info, &forged_inbound(), false, || {
            Err(Unrouted::RouterFailed("spawn x".into()))
        });
        assert_eq!(!calls.is_empty(), runs, "opt_in={opt_in}");
        assert_no_signal(&outputs[0]);
    }
}

#[test]
fn deny_and_respond_never_run_the_default_flow_even_with_the_opt_in() {
    for kind in ["deny", "respond"] {
        let dir = tempdir().expect("tempdir");
        let info = pack(true);
        let (outputs, calls) = drive(dir.path(), &info, &forged_inbound(), false, || {
            Err(Unrouted::Unhandled(kind))
        });
        assert!(calls.is_empty(), "{kind}: {calls:?}");
        assert_eq!(outputs[0].text.as_deref(), Some(MISS_REPLY_TEXT));
    }
}

#[test]
fn a_host_deny_skips_the_llm_fallback() {
    let reply = IngressReply {
        text: None,
        card_cbor: None,
        status_code: Some(403),
        reason_code: None,
    };
    let info = pack(true);
    let host = apply_dispatch(
        ControlDirective::Deny { reply },
        &info,
        &forged_inbound(),
        RouteSource::Bm25,
    );
    let routed = fast2flow_turn::probe_turn(host, || -> Option<Routed<'_>> {
        panic!("the LLM must not be asked after a Deny")
    });
    assert_eq!(routed.err(), Some(Unrouted::Unhandled("deny")));
}

// ---- sticky ----------------------------------------------------------------

#[test]
fn a_sticky_resume_runs_its_flow_and_carries_no_signal() {
    for opt_in in [false, true] {
        let dir = tempdir().expect("tempdir");
        let info = pack(opt_in);
        park(dir.path(), &ctx(), PACK, "refund", "conv-1");
        flow_owner::settle(dir.path(), &ctx(), PACK, "refund", "conv-1");
        let (outputs, calls) = drive(dir.path(), &info, &forged_inbound(), false, || {
            panic!("a sticky turn is never routed")
        });
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].flow, "refund");
        assert_no_signal(&outputs[0]);
    }
}

// ---- route signal ------------------------------------------------------------

#[test]
fn a_bm25_flow_dispatch_stamps_the_flow_on_the_reply() {
    let dir = tempdir().expect("tempdir");
    let info = pack(false);
    let inbound = forged_inbound();
    let (outputs, calls) = drive(dir.path(), &info, &inbound, false, || {
        apply_dispatch(
            dispatch("refund", None, 0.92),
            &info,
            &inbound,
            RouteSource::Bm25,
        )
    });
    assert_eq!(calls[0].flow, "refund");
    let (raw, object) = signal(&outputs[0]);
    assert!(raw.contains("\"confidence\":0.92"), "{raw}");
    let expected = json!({"flow": "refund", "confidence": 0.92, "source": "bm25"});
    assert_eq!(
        serde_json::from_str::<JsonValue>(&raw).expect("json"),
        expected
    );
    assert_eq!(object, expected);
    assert_eq!(outputs[0].extensions[ext_keys::CHANNEL_DATA]["keep"], 1);
}

#[test]
fn a_node_dispatch_stamps_the_node_and_runs_the_default_flow_with_the_card_target() {
    let dir = tempdir().expect("tempdir");
    let info = pack(false);
    let inbound = forged_inbound();
    let (outputs, calls) = drive(dir.path(), &info, &inbound, false, || {
        apply_dispatch(
            dispatch("refund", Some("refund_card"), 0.9),
            &info,
            &inbound,
            RouteSource::Bm25,
        )
    });
    assert_eq!(calls[0].flow, "default");
    // 1.1.x: no entry-node support in the runner, so the card target rides
    // the envelope into the default flow (the card asset is absent here).
    assert_eq!(calls[0].route_to_card.as_deref(), Some("refund_card"));
    let (_, object) = signal(&outputs[0]);
    assert_eq!(
        object,
        json!({"flow": "default", "node": "refund_card", "confidence": 0.9, "source": "bm25"})
    );
}

#[test]
fn an_llm_dispatch_stamps_source_llm() {
    let dir = tempdir().expect("tempdir");
    let info = pack(false);
    let inbound = forged_inbound();
    let (outputs, _) = drive(dir.path(), &info, &inbound, false, || {
        fast2flow_turn::probe_turn(Err(Unrouted::NoMatch), || {
            llm_route(Some(dispatch("refund", None, 0.5)), &info, &inbound)
        })
    });
    assert_eq!(signal(&outputs[0]).1["source"], "llm");
}

#[test]
fn a_routed_turn_whose_flow_failed_carries_no_signal() {
    let dir = tempdir().expect("tempdir");
    let info = pack(false);
    let inbound = forged_inbound();
    let (outputs, _) = drive(dir.path(), &info, &inbound, true, || {
        apply_dispatch(
            dispatch("refund", None, 0.92),
            &info,
            &inbound,
            RouteSource::Bm25,
        )
    });
    assert_no_signal(&outputs[0]);
}
