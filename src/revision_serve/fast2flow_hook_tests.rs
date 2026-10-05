//! Fast2Flow on the revision-serve path: the hook (`fast2flow_hook`) driven
//! with a stub routing host (a shell script printing a fixed
//! `Fast2FlowHookOutV1`, the pattern of `fast2flow::tests::end_to_end`), the
//! runner's real `FlowResumeStore`, and the real `build_reply_envelopes`.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use greentic_deploy_spec::ids::{BundleId, DeploymentId, RevisionId};
use greentic_runner_host::engine::runtime::FlowResumeStore;
use greentic_runner_host::runner::engine::{ExecutionState, FlowSnapshot, FlowWait};
use greentic_runner_host::storage::{DynSessionStore, new_session_store};
use greentic_runner_host::{Activity, WelcomeFlowHint};
use greentic_types::ChannelMessageEnvelope;
use greentic_types::messaging::extensions::ext_keys;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

use super::fast2flow_hook::*;
use crate::fast2flow::gate::BundleCapabilityGate;
use crate::fast2flow::revision_packs::{RevisionAppPack, revision_index_scope};
use crate::fast2flow::turn::{MISS_REPLY_TEXT, ROUTE_METADATA_KEY};
use crate::fast2flow::{
    FAST2FLOW_CAPABILITY, FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY, Fast2FlowConfig,
};
use crate::messaging_app::{AppFlowInfo, AppPackInfo};

const TENANT: &str = "acme";
const TEAM: &str = "default";
const PACK: &str = "sales-crm";
const BUNDLE: &str = "sales-bundle";
const DISPATCH_FLOW: &str =
    r#"{"type":"dispatch","target":"sales-crm/pipeline_flow","confidence":0.9,"reason":"m"}"#;
const CONTINUE: &str = r#"{"type":"continue"}"#;

/// A routing host answering `directive`, and the file it touches when run.
struct StubHost {
    _dir: TempDir,
    bin: PathBuf,
    marker: PathBuf,
}

impl StubHost {
    fn new(directive: &str) -> Self {
        let dir = tempdir().expect("tempdir");
        let bin = dir.path().join("fake-host.sh");
        let marker = dir.path().join("invoked");
        let body = format!(r#"{{"directive":{directive}}}"#);
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\ncat > /dev/null\ntouch '{}'\nprintf '%s' '{body}'\n",
                marker.display()
            ),
        )
        .expect("write");
        let mut perms = std::fs::metadata(&bin).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&bin, perms).expect("perms");
        Self {
            _dir: dir,
            bin,
            marker,
        }
    }

    fn invoked(&self) -> bool {
        self.marker.exists()
    }
}

struct Fixture {
    host: StubHost,
    indexes: TempDir,
    revision_id: RevisionId,
    bundle_id: BundleId,
}

impl Fixture {
    fn new(directive: &str) -> Self {
        let revision_id = RevisionId::new();
        let indexes = tempdir().expect("indexes");
        // The index lives ONLY in this revision's scope, so a probe under any
        // other scope finds nothing.
        let scope = revision_index_scope(TENANT, Some(TEAM), BUNDLE, revision_id);
        std::fs::create_dir_all(indexes.path().join(&scope)).expect("scope dir");
        std::fs::write(indexes.path().join(&scope).join("index.json"), b"{}").expect("index");
        Self {
            host: StubHost::new(directive),
            indexes,
            revision_id,
            bundle_id: BundleId::new(BUNDLE),
        }
    }

    fn cfg(&self) -> Fast2FlowConfig {
        Fast2FlowConfig {
            host_bin: self.host.bin.clone(),
            registry_path: PathBuf::from("/tmp/registry"),
            indexes_path: Some(self.indexes.path().to_path_buf()),
            time_budget_ms: 500,
            gate: Arc::new(BundleCapabilityGate),
        }
    }

    fn scope(&self) -> TurnScope<'_> {
        TurnScope {
            tenant: TENANT,
            team: Some(TEAM),
            deployment_id: DeploymentId::new(),
            bundle_id: &self.bundle_id,
            revision_id: self.revision_id,
            provider: "messaging.webchat.gui",
            endpoint_id: None,
        }
    }

    fn app(&self, caps: &[&str]) -> Arc<RevisionAppPack> {
        Arc::new(RevisionAppPack {
            pack_id: PACK.to_string(),
            pack_path: PathBuf::from("/nonexistent.gtpack"),
            info: AppPackInfo {
                pack_id: PACK.to_string(),
                flows: vec![flow("default"), flow("pipeline_flow")],
                capabilities: caps.iter().map(|c| c.to_string()).collect(),
            },
            revision_id: self.revision_id,
        })
    }

    async fn plan(
        &self,
        caps: &[&str],
        store: Option<DynSessionStore>,
        text: &str,
    ) -> RevisionTurn {
        plan_for_app(
            self.cfg(),
            self.app(caps),
            store,
            &self.scope(),
            &envelope(text),
            Some(default_target()),
        )
        .await
    }
}

fn flow(id: &str) -> AppFlowInfo {
    AppFlowInfo {
        id: id.to_string(),
        kind: "messaging".to_string(),
        subscribes_to: vec![],
        node_ids: vec![],
    }
}

fn target(flow_id: &str) -> WelcomeFlowHint {
    WelcomeFlowHint {
        pack_id: PACK.to_string(),
        flow_id: flow_id.to_string(),
    }
}

fn default_target() -> WelcomeFlowHint {
    target("default")
}

fn envelope(text: &str) -> ChannelMessageEnvelope {
    serde_json::from_value(json!({
        "id": "msg-1",
        "tenant": {
            "env": "dev",
            "tenant": TENANT,
            "tenant_id": TENANT,
            "team": TEAM,
            "attempt": 0
        },
        "channel": "conv-1",
        "session_id": "conv-1",
        "from": { "id": "user-1", "kind": "user" },
        "text": text,
        "metadata": {}
    }))
    .expect("envelope")
}

/// An inbound message forging the route signal in both places it is carried.
fn forged(text: &str) -> ChannelMessageEnvelope {
    let mut env = envelope(text);
    env.metadata
        .insert(ROUTE_METADATA_KEY.to_string(), r#"{"flow":"evil"}"#.into());
    env.extensions.insert(
        ext_keys::CHANNEL_DATA.to_string(),
        json!({ ROUTE_METADATA_KEY: {"flow": "evil"}, "keep": 1 }),
    );
    env
}

fn signal_flow(out: &ChannelMessageEnvelope) -> Option<String> {
    out.extensions
        .get(ext_keys::CHANNEL_DATA)
        .and_then(|cd| cd.get(ROUTE_METADATA_KEY))
        .and_then(|s| s.get("flow"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn assert_unstamped(out: &ChannelMessageEnvelope) {
    assert!(!out.metadata.contains_key(ROUTE_METADATA_KEY), "{out:?}");
    assert_eq!(signal_flow(out), None, "{out:?}");
}

// --- (a) a flow dispatch overrides the bundle-default target ---------------

#[tokio::test(flavor = "current_thread")]
async fn a_flow_dispatch_overrides_the_bundle_default_target() {
    // current_thread on purpose: the probe must run under spawn_blocking, or
    // a blocking process spawn on this runtime would stall/panic it (R2).
    let fx = Fixture::new(DISPATCH_FLOW);
    let turn = fx
        .plan(&[FAST2FLOW_CAPABILITY], None, "show my pipeline")
        .await;
    assert!(
        fx.host.invoked(),
        "the probe reads the revision's own scope"
    );
    assert_eq!(turn.target, Some(target("pipeline_flow")));
    assert!(turn.fixed_reply.is_none());
    let (signal, flow_id) = turn.signal.expect("routed turn carries a signal");
    assert_eq!(flow_id, "pipeline_flow");
    assert_eq!(signal.confidence, Some(0.9));
}

#[tokio::test]
async fn a_pack_without_the_capability_is_never_probed() {
    let fx = Fixture::new(DISPATCH_FLOW);
    let turn = fx.plan(&[], None, "show my pipeline").await;
    assert!(!fx.host.invoked());
    assert_eq!(turn.target, Some(default_target()));
    assert!(turn.signal.is_none() && turn.fixed_reply.is_none());
}

// --- (b) explicit targets win -------------------------------------------

#[test]
fn an_explicit_target_is_never_handed_to_fast2flow() {
    let hint = Some(target("from_flow_hint"));
    let request = Some(target("from_url"));
    assert_eq!(
        split_targets(hint.clone(), request.clone(), false),
        (hint.clone(), None),
        "a validated flow_hint beats the request target"
    );
    assert_eq!(
        split_targets(None, request.clone(), true),
        (request.clone(), None),
        "a URL/header-named flow is explicit"
    );
    assert_eq!(
        split_targets(None, request.clone(), false),
        (None, request),
        "only the bundle-default fallback may be re-routed"
    );
}

#[tokio::test]
async fn plan_revision_turn_keeps_an_explicit_target_without_probing() {
    let fx = Fixture::new(DISPATCH_FLOW);
    let activation = activation_with_app(&fx, &[FAST2FLOW_CAPABILITY]);
    let turn = plan_revision_turn_with(
        &fx.cfg(),
        &activation,
        &fx.scope(),
        &envelope("show my pipeline"),
        Some(target("named_flow")),
        None,
    )
    .await;
    assert!(!fx.host.invoked(), "an explicit target skips the probe");
    assert_eq!(turn.target, Some(target("named_flow")));
    assert!(turn.signal.is_none());

    // Same activation, fallback only: now the app pack is looked up per
    // revision and the dispatch wins.
    let turn = plan_revision_turn_with(
        &fx.cfg(),
        &activation,
        &fx.scope(),
        &envelope("show my pipeline"),
        None,
        Some(default_target()),
    )
    .await;
    assert!(fx.host.invoked());
    assert_eq!(turn.target, Some(target("pipeline_flow")));
}

// --- (c) the fixed reply short-circuits the runner -------------------------

#[tokio::test]
async fn a_fixed_reply_never_calls_the_runner() {
    let fx = Fixture::new(CONTINUE);
    let turn = fx.plan(&[FAST2FLOW_CAPABILITY], None, "hello?").await;
    assert!(turn.target.is_none());
    let reply = turn.fixed_reply.clone().expect("fixed miss reply");
    assert_eq!(reply.text.as_deref(), Some(MISS_REPLY_TEXT));
    assert_ne!(reply.id, "msg-1", "the reply gets its own id");

    let calls = AtomicUsize::new(0);
    let mut turn = turn;
    // A forged key on the reply (it is a clone of the inbound) is stripped.
    turn.fixed_reply = Some({
        let mut r = forged("hello?");
        r.text = Some(MISS_REPLY_TEXT.to_string());
        r
    });
    let out = run_planned_turn(
        turn,
        |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(Vec::new()) }
        },
        |_| panic!("no runner reply to shape"),
    )
    .await
    .expect("fixed reply");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "handle_activity not called"
    );
    assert_eq!(out.len(), 1);
    assert_unstamped(&out[0]);
}

// --- (d) the on-miss opt-in keeps the default target ------------------------

#[tokio::test]
async fn the_on_miss_opt_in_keeps_the_default_target() {
    let fx = Fixture::new(CONTINUE);
    let turn = fx
        .plan(
            &[
                FAST2FLOW_CAPABILITY,
                FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY,
            ],
            None,
            "hello?",
        )
        .await;
    assert!(fx.host.invoked());
    assert_eq!(turn.target, Some(default_target()));
    assert!(turn.fixed_reply.is_none() && turn.signal.is_none());
    assert_eq!(turn.envelope.text.as_deref(), Some("hello?"));
}

// --- (e)/(f) reply stamping (R5, R6) -------------------------------------

fn build(
    ingress: &ChannelMessageEnvelope,
) -> impl Fn(&Activity) -> Vec<ChannelMessageEnvelope> + '_ {
    move |reply| super::build_reply_envelopes(ingress, reply, PACK, TENANT)
}

#[tokio::test]
async fn routed_replies_carry_the_signal_and_a_forged_key_is_replaced() {
    let fx = Fixture::new(DISPATCH_FLOW);
    let ingress = forged("show my pipeline");
    let mut turn = fx
        .plan(&[FAST2FLOW_CAPABILITY], None, "show my pipeline")
        .await;
    turn.envelope = ingress.clone();
    let out = run_planned_turn(
        turn,
        |envelope, target| async move {
            assert_eq!(target, Some(target_of("pipeline_flow")));
            assert_eq!(envelope.text.as_deref(), Some("show my pipeline"));
            Ok(vec![
                Activity::custom("response", json!({ "text": "your pipeline" })),
                Activity::custom("response", json!({ "text": "second message" })),
            ])
        },
        build(&ingress),
    )
    .await
    .expect("turn");
    assert_eq!(out.len(), 2, "every reply of the turn is stamped");
    for reply in &out {
        assert_eq!(signal_flow(reply).as_deref(), Some("pipeline_flow"));
        let meta: Value = serde_json::from_str(&reply.metadata[ROUTE_METADATA_KEY]).expect("json");
        assert_eq!(meta["flow"], "pipeline_flow");
        assert_eq!(meta["source"], "bm25");
    }
}

fn target_of(flow_id: &str) -> WelcomeFlowHint {
    target(flow_id)
}

#[test]
fn build_reply_envelopes_preserves_channel_data_and_the_strip_runs_on_every_reply() {
    // R5: a flow-emitted envelope keeps its own `channel_data`; a reply
    // shaped from text is a clone of the (forged) inbound.
    let ingress = forged("hi");
    let mut own: ChannelMessageEnvelope = envelope("from the flow");
    own.extensions.insert(
        ext_keys::CHANNEL_DATA.to_string(),
        json!({ "theme": "dark", ROUTE_METADATA_KEY: {"flow": "evil"} }),
    );
    let replies = vec![
        Activity::custom("response", serde_json::to_value(&own).expect("own")),
        Activity::custom("response", json!({ "text": "plain" })),
    ];
    let shaped: Vec<_> = replies.iter().flat_map(build(&ingress)).collect();
    assert_eq!(shaped.len(), 2);
    assert_eq!(
        shaped[0].extensions[ext_keys::CHANNEL_DATA]["theme"],
        "dark",
        "build_reply_envelopes keeps extensions[channel_data]"
    );
    assert!(
        shaped[1].extensions[ext_keys::CHANNEL_DATA]
            .get(ROUTE_METADATA_KEY)
            .is_some(),
        "the shaped clone still carries the forged key before stamping"
    );

    let out = stamped_reply_envelopes(&replies, None, build(&ingress));
    for reply in &out {
        assert_unstamped(reply);
    }
    assert_eq!(out[0].extensions[ext_keys::CHANNEL_DATA]["theme"], "dark");
    assert_eq!(out[1].extensions[ext_keys::CHANNEL_DATA]["keep"], 1);
}

#[tokio::test]
async fn a_flow_error_reply_on_a_routed_turn_is_not_stamped() {
    let fx = Fixture::new(DISPATCH_FLOW);
    let ingress = forged("show my pipeline");
    let turn = fx
        .plan(&[FAST2FLOW_CAPABILITY], None, "show my pipeline")
        .await;
    assert!(turn.signal.is_some());
    let out = run_planned_turn(
        turn,
        |_, _| async {
            Ok(vec![Activity::custom(
                "response",
                json!({ "metadata": { "error_kind": "tool", "error_message": "HTTP 500 upstream" } }),
            )])
        },
        build(&ingress),
    )
    .await
    .expect("turn");
    assert!(
        !out.is_empty(),
        "the categorized error message is still delivered"
    );
    for reply in &out {
        assert_unstamped(reply);
    }
}

#[tokio::test]
async fn a_runner_error_sends_nothing() {
    let fx = Fixture::new(DISPATCH_FLOW);
    let ingress = envelope("x");
    let turn = fx
        .plan(&[FAST2FLOW_CAPABILITY], None, "show my pipeline")
        .await;
    let out = run_planned_turn(
        turn,
        |_, _| async { Err(anyhow::anyhow!("runner down")) },
        build(&ingress),
    )
    .await;
    assert!(out.is_err());
}

// --- (g) R1: a parked conversation ----------------------------------------

fn wait_in(flow_id: &str) -> FlowWait {
    let state: ExecutionState =
        serde_json::from_value(json!({ "input": { "text": "hi" }, "nodes": {}, "egress": [] }))
            .expect("state");
    FlowWait {
        reason: Some("await-user".into()),
        snapshot: FlowSnapshot {
            pack_id: PACK.into(),
            flow_id: flow_id.into(),
            next_flow: None,
            next_node: "ask".into(),
            awaiting_submit: true,
            state,
        },
    }
}

/// Park `flow_id` exactly where the runner would for this ingress pinned to it.
async fn park(store: &DynSessionStore, fx: &Fixture, flow_id: &str) {
    let activity = super::envelope_to_activity(
        &envelope("x"),
        TENANT,
        fx.scope().endpoint_id,
        None,
        Some(target(flow_id)),
    );
    let env = resume_lookup_envelope(&activity, TENANT, PACK, flow_id);
    FlowResumeStore::new(Arc::clone(store))
        .save(&env, &wait_in(flow_id))
        .await
        .expect("park");
}

/// Evidence for R1: on this path the parked snapshot is keyed by the FLOW the
/// turn was pinned to (no channel on the activity ⇒ `canonicalize` makes the
/// flow id the conversation/reply scope). A turn pinned to another flow does
/// NOT find the snapshot, so "the snapshot wins" holds only within one flow.
#[tokio::test]
async fn a_park_is_only_found_under_the_flow_it_was_parked_in() {
    let fx = Fixture::new(DISPATCH_FLOW);
    let store = new_session_store();
    park(&store, &fx, "pipeline_flow").await;
    let activity = super::envelope_to_activity(&envelope("x"), TENANT, None, None, None);
    assert!(
        activity.channel().is_none(),
        "the revision activity carries no channel"
    );
    let resume = FlowResumeStore::new(Arc::clone(&store));
    let same = resume_lookup_envelope(&activity, TENANT, PACK, "pipeline_flow");
    let other = resume_lookup_envelope(&activity, TENANT, PACK, "default");
    assert_eq!(
        same.reply_scope.as_ref().map(|s| s.conversation.as_str()),
        Some("pipeline_flow")
    );
    assert!(resume.fetch(&same).await.expect("fetch").is_some());
    assert!(
        resume.fetch(&other).await.expect("fetch").is_none(),
        "pinning another flow would strand the parked one"
    );
}

#[tokio::test]
async fn a_parked_conversation_resumes_its_flow_and_is_never_routed() {
    // Parked in pipeline_flow; free text that would miss (CONTINUE) must
    // neither get the fixed reply nor be re-targeted to the default flow.
    let fx = Fixture::new(CONTINUE);
    let store = new_session_store();
    park(&store, &fx, "pipeline_flow").await;
    let turn = fx
        .plan(&[FAST2FLOW_CAPABILITY], Some(Arc::clone(&store)), "ACME-42")
        .await;
    assert!(!fx.host.invoked(), "a parked conversation is not probed");
    assert_eq!(turn.target, Some(target("pipeline_flow")));
    assert!(turn.fixed_reply.is_none() && turn.signal.is_none());

    // Nothing parked: the same message is probed and misses.
    let fx = Fixture::new(CONTINUE);
    let turn = fx
        .plan(
            &[FAST2FLOW_CAPABILITY],
            Some(new_session_store()),
            "ACME-42",
        )
        .await;
    assert!(fx.host.invoked());
    assert!(turn.fixed_reply.is_some());
}

// --- helpers: an Activation carrying one revision's app pack ---------------

fn activation_with_app(fx: &Fixture, caps: &[&str]) -> super::Activation {
    use crate::revision_dispatcher::{RevisionDispatcher, RevisionDispatcherConfig};
    let host = Arc::new(
        greentic_runner_host::HostBuilder::new()
            .with_config(greentic_runner_host::HostConfig::from_gtbind(
                greentic_runner_host::TenantBindings {
                    tenant: TENANT.to_string(),
                    packs: Vec::new(),
                    env_passthrough: Vec::new(),
                },
            ))
            .build()
            .expect("host"),
    );
    let app = fx.app(caps);
    let mut app_packs = crate::fast2flow::revision_packs::RevisionAppPacks::default();
    app_packs.insert_revision(
        BUNDLE,
        fx.revision_id,
        [(Path::new("/nonexistent.gtpack"), &app.info)],
    );
    super::Activation {
        host,
        routing: Arc::new(crate::deployment_routes::RevisionIngressRouting {
            dispatcher: Arc::new(RevisionDispatcher::new(RevisionDispatcherConfig::new(
                "env-f2f", [0u8; 32],
            ))),
            http_routes: crate::http_routes::HttpRouteTable::from_descriptors(Vec::new()),
            deployment_routes: crate::deployment_routes::DeploymentRouteTable::default(),
            endpoint_admit: Arc::new(crate::endpoint_admit::EndpointAdmit::default()),
            deployment_config_overrides: Arc::default(),
            static_routes: crate::static_routes::ActiveRouteTable::default(),
            bundle_index: crate::webchat_routing::BundleIndex::empty(),
            flow_index: crate::webchat_routing::FlowIndex::default(),
            app_packs,
            triggers: Default::default(),
            runtime_metered: Default::default(),
        }),
    }
}

// --- (h) the gate line is visible at info on this path ---------------------

#[test]
fn the_gate_enter_line_is_logged_at_info_on_the_revision_path() {
    let _env = crate::test_env_lock()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    crate::operator_log::reset_for_tests();
    let dir = tempdir().expect("log dir");
    crate::operator_log::init(dir.path().to_path_buf(), crate::operator_log::Level::Info)
        .expect("init");
    let fx = Fixture::new(CONTINUE);
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(fx.plan(&[FAST2FLOW_CAPABILITY], None, "hello?"));
    let log = std::fs::read_to_string(dir.path().join("system.log")).expect("system.log");
    crate::operator_log::reset_for_tests();
    assert!(
        log.contains("[fast2flow:gate] enter path=revision tenant=acme"),
        "{log}"
    );
}

// --- fix 1: a card submit navigates, never routed nor fixed-replied --------

#[tokio::test]
async fn a_card_submit_on_an_opted_in_pack_is_passed_through_unprobed() {
    for key in crate::fast2flow::turn::CARD_NAV_META_KEYS {
        for directive in [CONTINUE, DISPATCH_FLOW] {
            let fx = Fixture::new(directive);
            // A button submit carries its label as text plus the nav key.
            let mut submit = envelope("Show pipeline");
            submit
                .metadata
                .insert((*key).to_string(), "deal_card".to_string());
            let turn = plan_for_app(
                fx.cfg(),
                fx.app(&[FAST2FLOW_CAPABILITY]),
                Some(new_session_store()),
                &fx.scope(),
                &submit,
                Some(default_target()),
            )
            .await;
            assert!(!fx.host.invoked(), "{key}: a card submit is not probed");
            assert!(turn.fixed_reply.is_none(), "{key}: no fixed reply");
            assert!(turn.signal.is_none(), "{key}: not a routed turn");
            assert_eq!(turn.target, Some(default_target()), "{key}: not retargeted");
            assert_eq!(
                turn.envelope.metadata.get(*key).map(String::as_str),
                Some("deal_card"),
                "{key}: the runner still sees the nav key"
            );
        }
    }
}
