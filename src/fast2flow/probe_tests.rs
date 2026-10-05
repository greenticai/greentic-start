//! `plan_turn` outcomes against a stub routing host (a shell script that
//! prints a fixed `Fast2FlowHookOutV1`), the pattern of `mod.rs`'s
//! `tests::end_to_end`.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;
use tempfile::{TempDir, tempdir};

use super::*;
use crate::fast2flow::FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY;
use crate::fast2flow::gate::BundleCapabilityGate;
use crate::fast2flow::turn::{MISS_REPLY_TEXT, RouteSource};
use crate::messaging_app::AppFlowInfo;

const PACK: &str = "sales-crm";
const SCOPE: &str = "acme:default";

fn ctx() -> OperatorContext {
    OperatorContext {
        tenant: "acme".to_string(),
        team: None,
        correlation_id: None,
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

fn pack(capabilities: &[&str]) -> AppPackInfo {
    AppPackInfo {
        pack_id: PACK.to_string(),
        flows: vec![flow("default"), flow("pipeline_flow")],
        capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
    }
}

fn envelope(text: &str) -> ChannelMessageEnvelope {
    serde_json::from_value(json!({
        "id": "msg-1",
        "tenant": {
            "env": "dev",
            "tenant": "acme",
            "tenant_id": "acme",
            "team": "default",
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

/// A routing host that answers `directive` to any request.
fn fake_host(directive: &str) -> (TempDir, PathBuf) {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("fake-host.sh");
    let body = format!(r#"{{"directive":{directive}}}"#);
    crate::fast2flow::test_script::write_executable_script(
        &path,
        &format!("cat > /dev/null\nprintf '%s' '{body}'\n"),
    );
    (dir, path)
}

/// Indexes root with `<scope>/index.json` in place.
fn indexes(scope: &str) -> TempDir {
    let dir = tempdir().expect("indexes");
    std::fs::create_dir_all(dir.path().join(scope)).expect("scope dir");
    std::fs::write(dir.path().join(scope).join("index.json"), b"{}").expect("index");
    dir
}

fn config(host_bin: PathBuf, indexes: &TempDir) -> Fast2FlowConfig {
    Fast2FlowConfig {
        host_bin,
        registry_path: PathBuf::from("/tmp/registry"),
        indexes_path: Some(indexes.path().to_path_buf()),
        time_budget_ms: 500,
        gate: Arc::new(BundleCapabilityGate),
    }
}

fn plan(
    cfg: &Fast2FlowConfig,
    pack: &AppPackInfo,
    index_scope: Option<&str>,
    text: &str,
    owns_conversation: bool,
) -> TurnPlan {
    let ctx = ctx();
    let inputs = ProbeInputs {
        cfg,
        ctx: &ctx,
        pack,
        pack_path: Path::new("/nonexistent.gtpack"),
        index_scope,
        provider: "webchat",
        llm: None,
    };
    plan_turn(
        &inputs,
        &envelope(text),
        owns_conversation,
        OnRouterFailure::MissPolicy,
    )
}

const DISPATCH_FLOW: &str =
    r#"{"type":"dispatch","target":"sales-crm/pipeline_flow","confidence":0.9,"reason":"m"}"#;
const CONTINUE: &str = r#"{"type":"continue"}"#;

#[test]
fn a_flow_dispatch_plans_that_flow() {
    let (_h, host) = fake_host(DISPATCH_FLOW);
    let idx = indexes(SCOPE);
    let cfg = config(host, &idx);
    match plan(
        &cfg,
        &pack(&[FAST2FLOW_CAPABILITY]),
        None,
        "pipeline",
        false,
    ) {
        TurnPlan::Routed(RouteDecision::Flow {
            flow_id, signal, ..
        }) => {
            assert_eq!(flow_id, "pipeline_flow");
            assert_eq!(signal.node, None);
            assert_eq!(signal.confidence, Some(0.9));
            assert_eq!(signal.source, RouteSource::Bm25);
        }
        other => panic!("expected a flow route, got {other:?}"),
    }
}

#[test]
fn a_node_dispatch_plans_the_card_node() {
    let (_h, host) = fake_host(
        r#"{"type":"dispatch","target":"sales-crm/default/deal_card","confidence":0.8,"reason":"m"}"#,
    );
    let idx = indexes(SCOPE);
    let cfg = config(host, &idx);
    match plan(&cfg, &pack(&[FAST2FLOW_CAPABILITY]), None, "deal", false) {
        TurnPlan::Routed(RouteDecision::Node { envelope, signal }) => {
            assert_eq!(
                envelope.metadata.get("routeToCardId").map(String::as_str),
                Some("deal_card")
            );
            assert_eq!(signal.node.as_deref(), Some("deal_card"));
        }
        other => panic!("expected a node route, got {other:?}"),
    }
}

#[test]
fn a_pack_without_the_capability_runs_the_default_flow() {
    let (_h, host) = fake_host(DISPATCH_FLOW);
    let idx = indexes(SCOPE);
    let cfg = config(host, &idx);
    assert_eq!(
        plan(&cfg, &pack(&[]), None, "pipeline", false),
        TurnPlan::DefaultFlow { on_miss: false }
    );
}

#[test]
fn a_miss_gets_the_fixed_reply_unless_the_pack_opted_in() {
    let (_h, host) = fake_host(CONTINUE);
    let idx = indexes(SCOPE);
    let cfg = config(host, &idx);
    match plan(&cfg, &pack(&[FAST2FLOW_CAPABILITY]), None, "hello?", false) {
        TurnPlan::FixedReply(reply) => {
            assert_eq!(reply.text.as_deref(), Some(MISS_REPLY_TEXT));
        }
        other => panic!("expected the fixed reply, got {other:?}"),
    }
    assert_eq!(
        plan(
            &cfg,
            &pack(&[
                FAST2FLOW_CAPABILITY,
                FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY
            ]),
            None,
            "hello?",
            false
        ),
        TurnPlan::DefaultFlow { on_miss: true }
    );
}

#[test]
fn an_owned_conversation_is_never_routed() {
    let (_h, host) = fake_host(DISPATCH_FLOW);
    let idx = indexes(SCOPE);
    let cfg = config(host, &idx);
    assert_eq!(
        plan(&cfg, &pack(&[FAST2FLOW_CAPABILITY]), None, "pipeline", true),
        TurnPlan::DefaultFlow { on_miss: false }
    );
}

#[test]
fn an_index_scope_override_reads_that_scope_only() {
    let (_h, host) = fake_host(DISPATCH_FLOW);
    let idx = indexes("acme:default:bundle-a:rev-1");
    let cfg = config(host, &idx);
    let caps = [FAST2FLOW_CAPABILITY];
    assert!(matches!(
        plan(
            &cfg,
            &pack(&caps),
            Some("acme:default:bundle-a:rev-1"),
            "pipeline",
            false
        ),
        TurnPlan::Routed(RouteDecision::Flow { .. })
    ));
    // The default `<tenant>:<team>` scope has no index here, so the router is
    // not asked and the miss policy applies.
    assert!(matches!(
        plan(&cfg, &pack(&caps), None, "pipeline", false),
        TurnPlan::FixedReply(_)
    ));
}

/// A pack zip shipping `assets/intent-index.json` with no candidates: reaching
/// the index materializes it, and `try_llm_route` then abstains offline.
fn pack_with_index(dir: &Path) -> PathBuf {
    use std::io::Write as _;
    let path = dir.join("app.gtpack");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).expect("pack"));
    zip.start_file(
        "assets/intent-index.json",
        zip::write::FileOptions::<()>::default(),
    )
    .expect("entry");
    zip.write_all(b"{\"entries\":[]}").expect("write");
    zip.finish().expect("finish");
    path
}

fn llm(fast2flow: bool) -> BundleLlmConfig {
    BundleLlmConfig {
        provider: "ollama".to_string(),
        model: None,
        api_key_secret: None,
        base_url: Some("http://127.0.0.1:9".to_string()),
        fast2flow,
        fast2flow_llm_min_confidence: None,
    }
}

/// The injected-LLM fallback is consulted only past its gates, in order:
/// an `llm` instance, its `fast2flow` flag, the pack capability, non-blank
/// text. Only then does it resolve (and so materialize) the scope index — the
/// side effect this test observes. The host gate is closed (an empty
/// `AnyGate`), so the host probe never materializes the index itself.
#[test]
fn the_llm_fallback_gates_run_in_order_before_the_index_is_read() {
    let scope = "acme:llm-gates";
    let reached = |llm_cfg: Option<BundleLlmConfig>, caps: &[&str], text: &str| {
        let work = tempdir().expect("work");
        let pack_path = pack_with_index(work.path());
        let indexes = tempdir().expect("indexes");
        let cfg = Fast2FlowConfig {
            host_bin: PathBuf::from("/definitely/not/a/routing/host"),
            registry_path: PathBuf::from("/tmp/registry"),
            indexes_path: Some(indexes.path().to_path_buf()),
            time_budget_ms: 500,
            gate: Arc::new(crate::fast2flow::gate::AnyGate::new(Vec::new())),
        };
        let ctx = ctx();
        let info = pack(caps);
        let inputs = ProbeInputs {
            cfg: &cfg,
            ctx: &ctx,
            pack: &info,
            pack_path: &pack_path,
            index_scope: Some(scope),
            provider: "webchat",
            llm: llm_cfg.as_ref(),
        };
        let plan = plan_turn(&inputs, &envelope(text), false, OnRouterFailure::MissPolicy);
        let materialized = indexes.path().join(scope).join("index.json").is_file();
        (materialized, plan)
    };
    let cap = [FAST2FLOW_CAPABILITY];

    let (hit, _) = reached(None, &cap, "refund please");
    assert!(!hit, "no llm instance: the fallback is not consulted");
    let (hit, _) = reached(Some(llm(false)), &cap, "refund please");
    assert!(!hit, "fast2flow: false reserves the llm for other uses");
    let (hit, plan) = reached(Some(llm(true)), &[], "refund please");
    assert!(!hit, "a pack without the capability never asks the llm");
    assert_eq!(plan, TurnPlan::DefaultFlow { on_miss: false });
    let (hit, _) = reached(Some(llm(true)), &cap, "   ");
    assert!(!hit, "blank text is not routed");
    let (hit, plan) = reached(Some(llm(true)), &cap, "refund please");
    assert!(hit, "every gate passed: the fallback reads the scope index");
    // The llm abstained (no candidates); the host's cause stands, so the
    // miss policy applies exactly as for a host miss.
    assert!(matches!(plan, TurnPlan::FixedReply(_)), "{plan:?}");
}

/// The legacy ingress's policy is unchanged: a failed router degrades like a
/// miss; only `OnRouterFailure::DefaultFlow` (the revision path) fails open.
#[test]
fn a_failed_router_is_a_miss_unless_the_caller_fails_open() {
    let idx = indexes(SCOPE);
    let cfg = config(PathBuf::from("/definitely/not/a/routing/host"), &idx);
    let ctx = ctx();
    let info = pack(&[FAST2FLOW_CAPABILITY]);
    let inputs = ProbeInputs {
        cfg: &cfg,
        ctx: &ctx,
        pack: &info,
        pack_path: Path::new("/nonexistent.gtpack"),
        index_scope: None,
        provider: "webchat",
        llm: None,
    };
    let env = envelope("hello?");
    assert!(matches!(
        plan_turn(&inputs, &env, false, OnRouterFailure::MissPolicy),
        TurnPlan::FixedReply(_)
    ));
    assert_eq!(
        plan_turn(&inputs, &env, false, OnRouterFailure::DefaultFlow),
        TurnPlan::DefaultFlow { on_miss: false }
    );
}
