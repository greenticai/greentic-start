//! Flow-level Fast2Flow dispatch and conversation ownership
//! (greentic-start#590, option A).

use std::io::Write as _;
use std::path::Path;

use greentic_types::ChannelMessageEnvelope;
use serde_json::json;
use tempfile::tempdir;
use zip::write::FileOptions;

use super::*;
use crate::http_ingress::flow_owner::test_support::{complete, has_record, park};
use crate::ingress::control_directive::{IngressReply, PrefillEntity};
use crate::messaging_app::{AppFlowInfo, AppPackInfo};
use crate::secrets_gate;

const PACK: &str = "demo-app";

fn flow(id: &str, kind: &str) -> AppFlowInfo {
    AppFlowInfo {
        id: id.into(),
        kind: kind.into(),
        subscribes_to: vec![],
        node_ids: vec![],
    }
}

fn pack_info() -> AppPackInfo {
    AppPackInfo {
        pack_id: PACK.into(),
        flows: vec![
            flow("default", "messaging"),
            flow("refund", "messaging"),
            flow("on_event", "events"),
        ],
        capabilities: vec![crate::fast2flow::FAST2FLOW_CAPABILITY.to_string()],
    }
}

fn ctx(tenant: &str) -> OperatorContext {
    OperatorContext {
        tenant: tenant.into(),
        team: Some("default".into()),
        correlation_id: None,
    }
}

fn envelope(session: &str) -> ChannelMessageEnvelope {
    serde_json::from_value(json!({
        "id": "msg-1",
        "tenant": {
            "env": "dev", "tenant": "demo", "tenant_id": "demo",
            "team": "default", "attempt": 0
        },
        "channel": session,
        "session_id": session,
        "from": { "id": "user-1", "kind": "user" },
        "text": "I want a refund",
        "metadata": {}
    }))
    .expect("envelope")
}

fn target(pack: &str, flow: Option<&str>, node: Option<&str>) -> DispatchTarget {
    DispatchTarget {
        tenant: "demo".into(),
        team: Some("default".into()),
        pack: pack.into(),
        flow: flow.map(str::to_string),
        node: node.map(str::to_string),
    }
}

fn dispatch(pack: &str, flow: Option<&str>, node: Option<&str>) -> ControlDirective {
    ControlDirective::Dispatch {
        target: target(pack, flow, node),
        entities: vec![PrefillEntity {
            kind: "order".into(),
            normalized: "A-17".into(),
            role: None,
            formats: Default::default(),
        }],
    }
}

// ---- which targets name a flow -------------------------------------------

#[test]
fn a_pack_flow_target_names_a_messaging_flow_of_the_app_pack() {
    let info = pack_info();
    let found = dispatch_flow(&info, &target(PACK, Some("refund"), None));
    assert_eq!(found.map(|f| f.id.as_str()), Some("refund"));
}

#[test]
fn targets_that_are_not_a_runnable_flow_of_this_pack_name_none() {
    let info = pack_info();
    for (t, why) in [
        (target(PACK, Some("refund"), Some("card")), "node target"),
        (target("other-pack", Some("refund"), None), "another pack"),
        (target(PACK, Some("missing"), None), "unknown flow"),
        (target(PACK, Some("on_event"), None), "non-messaging flow"),
        (target(PACK, None, None), "pack only"),
    ] {
        assert!(dispatch_flow(&info, &t).is_none(), "{why}");
    }
}

#[test]
fn a_card_node_dispatch_still_routes_to_the_card_in_the_default_flow() {
    let info = pack_info();
    let original = envelope("conv-1");
    match apply_dispatch(
        dispatch(PACK, Some("refund"), Some("refund_card")),
        &info,
        &original,
        "test",
    ) {
        Some(Routed::Node(env)) => {
            assert_eq!(
                env.metadata.get("routeToCardId").map(String::as_str),
                Some("refund_card")
            );
            assert_eq!(
                env.metadata.get("prefill_order").map(String::as_str),
                Some("A-17")
            );
        }
        _ => panic!("expected a node route"),
    }
}

#[test]
fn a_flow_dispatch_routes_to_that_flow_without_a_card_target() {
    let info = pack_info();
    let original = envelope("conv-1");
    match apply_dispatch(
        dispatch(PACK, Some("refund"), None),
        &info,
        &original,
        "test",
    ) {
        Some(Routed::Flow(flow, env)) => {
            assert_eq!(flow.id, "refund");
            assert!(card_nav_target(&env).is_none());
            assert_eq!(
                env.metadata.get("prefill_order").map(String::as_str),
                Some("A-17")
            );
        }
        _ => panic!("expected a flow route"),
    }
}

#[test]
fn directives_that_route_nothing_fall_through() {
    let info = pack_info();
    let original = envelope("conv-1");
    let reply = IngressReply {
        text: Some("hi".into()),
        card_cbor: None,
        status_code: Some(200),
        reason_code: None,
    };
    for directive in [
        ControlDirective::Continue,
        ControlDirective::Respond { reply },
        dispatch(PACK, Some("missing"), None),
    ] {
        assert!(apply_dispatch(directive, &info, &original, "test").is_none());
    }
}

// ---- turn resolution and stickiness --------------------------------------

fn probe_flow<'p>(info: &'p AppPackInfo, flow_id: &str) -> Option<Routed<'p>> {
    apply_dispatch(
        dispatch(PACK, Some(flow_id), None),
        info,
        &envelope("unused"),
        "test",
    )
}

#[test]
fn a_dispatched_flow_keeps_the_conversation_until_it_completes() {
    let dir = tempdir().expect("tempdir");
    let (root, c, info) = (dir.path(), ctx("demo"), pack_info());
    let default_flow = &info.flows[0];
    let original = envelope("conv-1");

    // Turn 1: the router dispatches to `refund`, which runs and parks.
    let turn = resolve_turn(root, &c, &info, default_flow, &original, || {
        probe_flow(&info, "refund")
    });
    assert_eq!(turn.flow.id, "refund");
    assert!(turn.owns_conversation);
    park(root, &c, PACK, "refund", "conv-1");
    flow_owner::settle(root, &c, PACK, "refund", "conv-1");

    // Turn 2: `refund` is parked, so it resumes and the router is not asked.
    let turn = resolve_turn(root, &c, &info, default_flow, &original, || {
        panic!("a parked flow's conversation must not be re-routed")
    });
    assert_eq!(turn.flow.id, "refund");
    assert!(turn.owns_conversation);
    assert!(card_nav_target(&turn.envelope).is_none());

    // `refund` completes on that turn; ownership is released.
    complete(root, &c, PACK, "refund", "conv-1");
    flow_owner::settle(root, &c, PACK, "refund", "conv-1");
    assert!(!has_record(root, &c, PACK, "conv-1"));

    // Turn 3: routed afresh — the router runs, and with no decision the
    // default flow takes the turn.
    let mut probed = false;
    let turn = resolve_turn(root, &c, &info, default_flow, &original, || {
        probed = true;
        None
    });
    assert!(probed);
    assert_eq!(turn.flow.id, "default");
    assert!(!turn.owns_conversation);
}

#[test]
fn a_flow_that_completes_on_its_dispatch_turn_leaves_the_next_turn_to_routing() {
    let dir = tempdir().expect("tempdir");
    let (root, c, info) = (dir.path(), ctx("demo"), pack_info());
    let default_flow = &info.flows[0];
    let original = envelope("conv-1");

    let turn = resolve_turn(root, &c, &info, default_flow, &original, || {
        probe_flow(&info, "refund")
    });
    // Nothing parked: a single-turn flow.
    flow_owner::settle(root, &c, PACK, &turn.flow.id, "conv-1");

    let mut probed = false;
    resolve_turn(root, &c, &info, default_flow, &original, || {
        probed = true;
        None
    });
    assert!(probed);
}

#[test]
fn without_a_dispatch_the_default_flow_runs_and_takes_no_ownership() {
    let dir = tempdir().expect("tempdir");
    let (root, c, info) = (dir.path(), ctx("demo"), pack_info());
    let original = envelope("conv-1");
    let turn = resolve_turn(root, &c, &info, &info.flows[0], &original, || None);
    assert_eq!(turn.flow.id, "default");
    assert!(!turn.owns_conversation);
    assert_eq!(turn.envelope.text, original.text);
}

#[test]
fn a_card_node_turn_runs_the_default_flow_and_takes_no_ownership() {
    let dir = tempdir().expect("tempdir");
    let (root, c, info) = (dir.path(), ctx("demo"), pack_info());
    let original = envelope("conv-1");
    let turn = resolve_turn(root, &c, &info, &info.flows[0], &original, || {
        apply_dispatch(
            dispatch(PACK, Some("default"), Some("welcome")),
            &info,
            &original,
            "test",
        )
    });
    assert_eq!(turn.flow.id, "default");
    assert!(!turn.owns_conversation);
    assert_eq!(
        card_nav_target(&turn.envelope).map(String::as_str),
        Some("welcome")
    );
}

#[test]
fn one_conversations_owner_does_not_capture_another() {
    let dir = tempdir().expect("tempdir");
    let (root, c, info) = (dir.path(), ctx("demo"), pack_info());
    park(root, &c, PACK, "refund", "conv-1");
    flow_owner::settle(root, &c, PACK, "refund", "conv-1");

    let turn = resolve_turn(root, &c, &info, &info.flows[0], &envelope("conv-2"), || {
        None
    });
    assert_eq!(turn.flow.id, "default");
    let turn = resolve_turn(root, &c, &info, &info.flows[0], &envelope("conv-1"), || {
        None
    });
    assert_eq!(turn.flow.id, "refund");
}

#[test]
fn ownership_does_not_cross_tenants() {
    let dir = tempdir().expect("tempdir");
    let (root, info) = (dir.path(), pack_info());
    let owner = ctx("demo");
    park(root, &owner, PACK, "refund", "conv-1");
    flow_owner::settle(root, &owner, PACK, "refund", "conv-1");

    let turn = resolve_turn(
        root,
        &ctx("other"),
        &info,
        &info.flows[0],
        &envelope("conv-1"),
        || None,
    );
    assert_eq!(turn.flow.id, "default");
}

// ---- through the ingress --------------------------------------------------

/// An app pack with a `default` and a `refund` messaging flow, neither
/// declaring Fast2Flow. Enough for the ingress to choose and start a flow.
fn write_two_flow_pack(pack_path: &Path) {
    use greentic_types::pack_manifest::{PackFlowEntry, PackKind, PackManifest, PackSignatures};
    use greentic_types::{Flow, FlowId, FlowKind, PackId};
    use semver::Version;

    let entry = |id: &str| {
        let flow = Flow {
            schema_version: "flow-v1".to_string(),
            id: FlowId::new(id).expect("flow id"),
            kind: FlowKind::Messaging,
            entrypoints: std::collections::BTreeMap::from([(
                "default".to_string(),
                serde_json::Value::Null,
            )]),
            nodes: Default::default(),
            metadata: Default::default(),
        };
        PackFlowEntry {
            id: FlowId::new(id).expect("flow id"),
            kind: FlowKind::Messaging,
            flow,
            tags: vec![],
            entrypoints: vec!["default".to_string()],
        }
    };
    let manifest = PackManifest {
        agents: Default::default(),
        schema_version: "pack-v1".into(),
        pack_id: PackId::new(PACK).expect("pack id"),
        name: Some(PACK.into()),
        version: Version::parse("0.1.0").expect("version"),
        kind: PackKind::Application,
        publisher: "demo".into(),
        components: Vec::new(),
        flows: vec![entry("default"), entry("refund")],
        dependencies: Vec::new(),
        capabilities: Vec::new(),
        secret_requirements: Vec::new(),
        signatures: PackSignatures::default(),
        bootstrap: None,
        extensions: None,
    };
    let file = std::fs::File::create(pack_path).expect("create pack");
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("manifest.cbor", FileOptions::<()>::default())
        .expect("start manifest");
    zip.write_all(&greentic_types::encode_pack_manifest(&manifest).expect("encode"))
        .expect("write manifest");
    zip.finish().expect("finish pack");
}

/// Route one envelope and report which flows the ingress started a run of.
fn flows_run_by_ingress(root: &Path, c: &OperatorContext, session: &str) -> Vec<String> {
    let discovery = crate::discovery::discover(root).expect("discovery");
    let secrets =
        secrets_gate::resolve_secrets_manager(root, &c.tenant, c.team.as_deref()).expect("secrets");
    let runner_host = DemoRunnerHost::new(root.to_path_buf(), &discovery, None, secrets, false)
        .expect("runner host");
    // Egress fails without a provider pack; the run itself already happened.
    let _ = route_messaging_envelopes(
        root,
        &runner_host,
        "messaging-webchat",
        c,
        vec![envelope(session)],
    );
    let runs = root.join("state/runs/messaging").join(PACK);
    let mut flows: Vec<String> = std::fs::read_dir(&runs)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    flows.sort();
    flows
}

#[test]
fn the_ingress_resumes_the_owning_flow_instead_of_the_default() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("packs")).expect("packs");
    write_two_flow_pack(&root.join("packs/default.gtpack"));
    let c = ctx("demo");
    park(root, &c, PACK, "refund", "conv-1");
    flow_owner::settle(root, &c, PACK, "refund", "conv-1");

    assert_eq!(flows_run_by_ingress(root, &c, "conv-1"), vec!["refund"]);
}

#[test]
fn the_ingress_runs_the_default_flow_for_an_unowned_conversation() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("packs")).expect("packs");
    write_two_flow_pack(&root.join("packs/default.gtpack"));
    let c = ctx("demo");

    assert_eq!(flows_run_by_ingress(root, &c, "conv-1"), vec!["default"]);
    assert!(!has_record(root, &c, PACK, "conv-1"));
}
