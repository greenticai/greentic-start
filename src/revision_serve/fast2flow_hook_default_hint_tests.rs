//! Fast2Flow on the revision path: a target that only names the DEFAULT flow
//! is not an explicit selection.
//!
//! The webchat provider stores the `X-Greentic-Flow` header of
//! `POST /conversations` as the conversation's flow binding and copies it into
//! `metadata["flow_hint"]` on EVERY activity of that conversation
//! (messaging-provider-webchat `directline/http.rs` + `ops/ingest.rs`). A
//! conversation opened against the default flow therefore carries a "hint" on
//! every turn; if that counted as explicit, Fast2Flow would never run there.
#![cfg(unix)]

use std::sync::Arc;

use greentic_runner_host::WelcomeFlowHint;
use tempfile::tempdir;

use super::fast2flow_hook::*;
use super::fast2flow_hook_tests::*;
use crate::fast2flow::FAST2FLOW_CAPABILITY;
use crate::fast2flow::revision_packs::RevisionAppPack;
use crate::messaging_app::AppPackInfo;
use crate::webchat_routing::FlowIndex;

/// An app pack whose default flow is `main` (the `select_app_flow`
/// convention), as a gtbundle wizard emits it.
fn main_app(fx: &Fixture) -> Arc<RevisionAppPack> {
    Arc::new(RevisionAppPack {
        pack_id: PACK.to_string(),
        pack_path: std::path::PathBuf::from("/nonexistent.gtpack"),
        info: AppPackInfo {
            pack_id: PACK.to_string(),
            flows: vec![flow("main"), flow("pipeline_flow")],
            capabilities: vec![FAST2FLOW_CAPABILITY.to_string()],
        },
        revision_id: fx.revision_id,
    })
}

fn bundle_default(flow_id: &str) -> FlowIndex {
    let mut index = FlowIndex::default();
    index.register_bundle_default_flow(BUNDLE, PACK, flow_id);
    index
}

#[test]
fn only_a_target_naming_the_default_flow_is_demoted() {
    let fx = Fixture::new(CONTINUE);
    let app = fx.app(&[FAST2FLOW_CAPABILITY]);
    let none: Option<&WelcomeFlowHint> = None;
    // The app pack's own default flow (`default`).
    assert!(is_default_target(&default_target(), none, Some(&app)));
    // The bundle's registered default.
    let welcome = target("welcome");
    assert!(is_default_target(&welcome, Some(&welcome), None));
    // A different flow is a deliberate selection.
    assert!(!is_default_target(
        &target("pipeline_flow"),
        none,
        Some(&app)
    ));
    assert!(!is_default_target(
        &target("pipeline_flow"),
        Some(&welcome),
        Some(&app)
    ));
    // Same flow id, other pack: not the default.
    let other_pack = WelcomeFlowHint {
        pack_id: "other-pack".to_string(),
        flow_id: "default".to_string(),
    };
    assert!(!is_default_target(&other_pack, none, Some(&app)));
}

#[tokio::test]
async fn a_hint_naming_the_default_flow_is_probed_and_can_dispatch() {
    let fx = Fixture::new(DISPATCH_FLOW);
    let activation = activation_with(&fx, fx.app(&[FAST2FLOW_CAPABILITY]), FlowIndex::default());
    let turn = plan_revision_turn_with(
        &fx.cfg(),
        &activation,
        &fx.scope(),
        &envelope("show my pipeline"),
        Some(default_target()),
        None,
    )
    .await;
    assert!(
        fx.host.invoked(),
        "a default-flow hint does not skip the probe"
    );
    assert_eq!(turn.target, Some(target("pipeline_flow")));
    assert!(turn.signal.is_some());
}

#[tokio::test]
async fn a_url_named_bundle_default_flow_is_probed() {
    let fx = Fixture::new(DISPATCH_FLOW);
    let activation = activation_with(&fx, main_app(&fx), bundle_default("main"));
    let turn = plan_revision_turn_with(
        &fx.cfg(),
        &activation,
        &fx.scope(),
        &envelope("show my pipeline"),
        Some(target("main")),
        None,
    )
    .await;
    assert!(fx.host.invoked());
    assert_eq!(turn.target, Some(target("pipeline_flow")));
}

#[test]
fn a_hint_naming_another_flow_wins_and_is_logged() {
    let _env = crate::test_env_lock()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    crate::operator_log::reset_for_tests();
    let dir = tempdir().expect("log dir");
    crate::operator_log::init(dir.path().to_path_buf(), crate::operator_log::Level::Info)
        .expect("init");
    let fx = Fixture::new(DISPATCH_FLOW);
    let activation = activation_with(&fx, main_app(&fx), bundle_default("main"));
    // A runtime built here, not `#[tokio::test]`: the env lock is held for
    // the whole test and must not be held across an `.await`.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let turn = runtime.block_on(plan_revision_turn_with(
        &fx.cfg(),
        &activation,
        &fx.scope(),
        &envelope("show my pipeline"),
        Some(target("pipeline_flow")),
        None,
    ));
    let log = std::fs::read_to_string(dir.path().join("system.log")).expect("system.log");
    crate::operator_log::reset_for_tests();
    assert!(!fx.host.invoked(), "a deliberate selection is never probed");
    assert_eq!(turn.target, Some(target("pipeline_flow")));
    assert!(turn.signal.is_none());
    assert!(
        log.contains("[fast2flow:gate] skip path=revision reason=explicit_target"),
        "{log}"
    );
}

#[tokio::test]
async fn a_webchat_conversation_bound_to_the_default_flow_routes_every_turn() {
    // What the revision path receives for a conversation opened with
    // `X-Greentic-Flow: default`: the request header names the flow AND the
    // provider copies the binding into `flow_hint` on each activity.
    let fx = Fixture::new(DISPATCH_FLOW);
    let activation = activation_with(&fx, fx.app(&[FAST2FLOW_CAPABILITY]), FlowIndex::default());
    for _turn in 0..2 {
        let (explicit, fallback) =
            split_targets(Some(default_target()), Some(default_target()), true);
        let turn = plan_revision_turn_with(
            &fx.cfg(),
            &activation,
            &fx.scope(),
            &envelope("show my pipeline"),
            explicit,
            fallback,
        )
        .await;
        assert_eq!(turn.target, Some(target("pipeline_flow")));
    }
    assert!(fx.host.invoked());
}

#[tokio::test]
async fn a_pack_without_fast2flow_keeps_its_default_flow_hint() {
    let fx = Fixture::new(DISPATCH_FLOW);
    let activation = activation_with(&fx, fx.app(&[]), FlowIndex::default());
    let turn = plan_revision_turn_with(
        &fx.cfg(),
        &activation,
        &fx.scope(),
        &envelope("show my pipeline"),
        Some(default_target()),
        None,
    )
    .await;
    assert!(!fx.host.invoked());
    assert_eq!(turn.target, Some(default_target()));
    assert!(turn.signal.is_none() && turn.fixed_reply.is_none());
}
