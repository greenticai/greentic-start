//! The Jev tier end to end against a loopback stand-in for the API: the real
//! HTTP client, the real index/pack handling, a fake secrets reader.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;
use tempfile::{TempDir, tempdir};

use super::mock_server::MockJev;
use super::*;
use crate::fast2flow::FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY;
use crate::fast2flow::Fast2FlowConfig;
use crate::fast2flow::gate::BundleCapabilityGate;
use crate::fast2flow::probe::{OnRouterFailure, TurnPlan, plan_turn};
use crate::fast2flow::turn::MISS_REPLY_TEXT;
use crate::inbound_verify::secrets::ChannelSecret;
use crate::messaging_app::{AppFlowInfo, AppPackInfo};
use crate::runner_host::OperatorContext;

const KEY: &str = "test-jev-key-7f3a";
const SCOPE: &str = "acme:jev";

const INDEX: &str = r#"{"version":"v2","entries":[
  {"flow_id":"refund_flow","pack_id":"router","target":"router/default/ask_support","title":"Support","utterances":["I want my money back"]},
  {"flow_id":"sales_flow","pack_id":"router","target":"router/default/ask_sales","title":"Sales","utterances":["how much does it cost"]}
]}"#;

struct FakeKeys {
    answer: Mutex<Option<SecretRead>>,
    reads: Mutex<Vec<String>>,
}

impl FakeKeys {
    fn found() -> Self {
        Self::with(SecretRead::Found(ChannelSecret::new(KEY)))
    }
    fn with(read: SecretRead) -> Self {
        Self {
            answer: Mutex::new(Some(read)),
            reads: Mutex::new(Vec::new()),
        }
    }
}

impl JevKeys for FakeKeys {
    fn read(&self, name: &str) -> SecretRead {
        self.reads.lock().unwrap().push(name.to_string());
        match self.answer.lock().unwrap().as_ref() {
            Some(SecretRead::Found(_)) => SecretRead::Found(ChannelSecret::new(KEY)),
            Some(SecretRead::Absent) => SecretRead::Absent,
            _ => SecretRead::Unavailable,
        }
    }
}

struct Fixture {
    _work: TempDir,
    _indexes: TempDir,
    pack_path: PathBuf,
    cfg: Fast2FlowConfig,
    ctx: OperatorContext,
    pack: AppPackInfo,
}

fn fixture(pack_config: Option<&str>, caps: &[&str]) -> Fixture {
    let work = tempdir().unwrap();
    let pack_path = work.path().join("router.gtpack");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&pack_path).unwrap());
    zip.start_file(
        "assets/intent-index.json",
        zip::write::FileOptions::<()>::default(),
    )
    .unwrap();
    zip.write_all(INDEX.as_bytes()).unwrap();
    if let Some(cfg) = pack_config {
        zip.start_file(
            "assets/fast2flow.json",
            zip::write::FileOptions::<()>::default(),
        )
        .unwrap();
        zip.write_all(cfg.as_bytes()).unwrap();
    }
    zip.finish().unwrap();
    let indexes = tempdir().unwrap();
    let cfg = Fast2FlowConfig {
        // No routing host: the host tier is "failed", so Jev gets every turn.
        host_bin: PathBuf::from("/definitely/not/a/routing/host"),
        registry_path: PathBuf::from("/tmp/registry"),
        indexes_path: Some(indexes.path().to_path_buf()),
        time_budget_ms: 500,
        gate: Arc::new(BundleCapabilityGate),
    };
    Fixture {
        _work: work,
        _indexes: indexes,
        pack_path,
        cfg,
        ctx: OperatorContext {
            tenant: "acme".into(),
            team: None,
            correlation_id: None,
        },
        pack: AppPackInfo {
            pack_id: "router".into(),
            flows: vec![AppFlowInfo {
                id: "default".into(),
                kind: "messaging".into(),
                subscribes_to: vec![],
                node_ids: vec![],
            }],
            capabilities: caps.iter().map(|c| c.to_string()).collect(),
            flow_meta: None,
        },
    }
}

fn envelope(text: &str) -> ChannelMessageEnvelope {
    serde_json::from_value(json!({
        "id": "m1",
        "tenant": {"env":"dev","tenant":"acme","tenant_id":"acme","team":"default","attempt":0},
        "channel": "c1", "session_id": "c1",
        "from": {"id":"u1","kind":"user"},
        "text": text, "metadata": {}
    }))
    .unwrap()
}

fn operator(endpoint: &str, extra: &str) -> JevBlock {
    serde_json::from_value(json!({"endpoint": endpoint, "timeout_ms": 500}))
        .map(|mut b: JevBlock| {
            if extra == "high_threshold" {
                b.min_confidence = Some(0.95);
            }
            b
        })
        .unwrap()
}

fn inputs<'a>(f: &'a Fixture, block: Option<&'a JevBlock>, keys: &'a FakeKeys) -> ProbeInputs<'a> {
    ProbeInputs {
        cfg: &f.cfg,
        ctx: &f.ctx,
        pack: &f.pack,
        pack_path: &f.pack_path,
        index_scope: Some(SCOPE),
        provider: "webchat",
        llm: None,
        jev: Some(JevInputs {
            operator: block,
            keys,
        }),
    }
}

const CAP: [&str; 1] = [FAST2FLOW_CAPABILITY];
const REFUND: &str = r#"{"model":"jev-1","answers":{"route":{"type":"choice","choice":"opt_1","confidence":0.91,"probabilities":{"opt_1":0.91,"none":0.09}}}}"#;

fn route_once(
    f: &Fixture,
    block: &JevBlock,
    keys: &FakeKeys,
    text: &str,
) -> (Option<RouteDecision>, WarnOnce<&'static str>) {
    let seen = WarnOnce::default();
    let got = route_reporting(&inputs(f, Some(block), keys), &envelope(text), &seen);
    (got, seen)
}

#[test]
fn a_confident_answer_routes_to_that_destination() {
    let server = MockJev::start(200, REFUND, Duration::ZERO);
    let f = fixture(None, &CAP);
    let keys = FakeKeys::found();
    let block = operator(&server.endpoint, "");
    let (got, _) = route_once(&f, &block, &keys, "I want a refund");
    match got.expect("routed") {
        RouteDecision::Node { envelope, signal } => {
            assert_eq!(
                envelope.metadata.get("routeToCardId").map(String::as_str),
                Some("ask_support")
            );
            assert_eq!(signal.source, RouteSource::Jev);
            assert_eq!(signal.confidence, Some(0.91));
        }
        other => panic!("expected a node route, got {other:?}"),
    }
    // The contract: bearer key, the single choice question, our options.
    let req = &server.requests()[0];
    assert!(req.request_line.starts_with("POST /v1/systemone"));
    assert_eq!(
        req.authorization.as_deref(),
        Some(&*format!("Bearer {KEY}"))
    );
    let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
    assert_eq!(body["state"], "I want a refund");
    assert_eq!(body["questions"]["route"]["type"], "choice");
    assert_eq!(keys.reads.lock().unwrap().as_slice(), ["jev/api_key"]);
}

#[test]
fn the_key_is_read_by_name_each_turn() {
    let server = MockJev::start(200, REFUND, Duration::ZERO);
    let f = fixture(None, &CAP);
    let keys = FakeKeys::found();
    let block = operator(&server.endpoint, "");
    route_once(&f, &block, &keys, "refund");
    route_once(&f, &block, &keys, "refund again");
    assert_eq!(keys.reads.lock().unwrap().len(), 2);
}

fn assert_falls_through(server: MockJev, f: &Fixture, keys: &FakeKeys) {
    let block = operator(&server.endpoint, "");
    let (got, _) = route_once(f, &block, keys, "I want a refund");
    assert!(got.is_none());
}

#[test]
fn server_errors_garbage_and_non_answers_all_fail_open() {
    let f = fixture(None, &CAP);
    let keys = FakeKeys::found();
    for (status, body) in [
        (500, r#"{"message":"boom"}"#),
        (503, ""),
        (429, r#"{"message":"slow down"}"#),
        (401, r#"{"message":"bad key"}"#),
        (200, "not json at all"),
        (200, r#"{"answers":{}}"#),
        (200, r#"{"answers":{"route":{"choice":"opt_1"}}}"#),
        (
            200,
            r#"{"answers":{"route":{"choice":"opt_99","confidence":0.99}}}"#,
        ),
        (
            200,
            r#"{"answers":{"route":{"choice":"none","confidence":0.99}}}"#,
        ),
        (
            200,
            r#"{"answers":{"route":{"choice":"router/default/ask_support","confidence":0.99}}}"#,
        ),
    ] {
        assert_falls_through(MockJev::start(status, body, Duration::ZERO), &f, &keys);
    }
}

#[test]
fn a_low_confidence_answer_abstains() {
    let server = MockJev::start(200, REFUND, Duration::ZERO);
    let f = fixture(None, &CAP);
    let block = operator(&server.endpoint, "high_threshold");
    let (got, _) = route_once(&f, &block, &FakeKeys::found(), "refund");
    assert!(got.is_none());
}

#[test]
fn a_slow_answer_times_out_and_the_turn_is_not_held() {
    let server = MockJev::start(200, REFUND, Duration::from_secs(3));
    let f = fixture(None, &CAP);
    let block = operator(&server.endpoint, "");
    let started = Instant::now();
    let (got, seen) = route_once(&f, &block, &FakeKeys::found(), "refund");
    assert!(got.is_none());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert!(!seen.first("timeout"), "the timeout was reported");
}

#[test]
fn an_unreachable_endpoint_fails_open() {
    let f = fixture(None, &CAP);
    let block = operator("http://127.0.0.1:9/v1/systemone", "");
    let (got, seen) = route_once(&f, &block, &FakeKeys::found(), "refund");
    assert!(got.is_none());
    assert!(!seen.first("transport"));
}

#[test]
fn a_missing_secret_fails_open_without_a_request_and_warns_once() {
    let server = MockJev::start(200, REFUND, Duration::ZERO);
    let f = fixture(None, &CAP);
    let keys = FakeKeys::with(SecretRead::Absent);
    let block = operator(&server.endpoint, "");
    let seen = WarnOnce::default();
    for _ in 0..3 {
        assert!(
            route_reporting(&inputs(&f, Some(&block), &keys), &envelope("refund"), &seen).is_none()
        );
    }
    assert!(server.requests().is_empty(), "no key, no request");
    // The class was recorded by the first turn only.
    assert!(!seen.first("secret_missing"));
    let unavailable = FakeKeys::with(SecretRead::Unavailable);
    let (got, seen) = route_once(&f, &block, &unavailable, "refund");
    assert!(got.is_none() && !seen.first("secret_unavailable"));
    assert!(server.requests().is_empty());
}

#[test]
fn nothing_runs_without_configuration_or_for_a_turn_that_would_not_route() {
    let server = MockJev::start(200, REFUND, Duration::ZERO);
    let keys = FakeKeys::found();
    let seen = WarnOnce::default();
    // No `jev` block anywhere: off, and the key is never even read.
    let f = fixture(None, &CAP);
    assert!(route_reporting(&inputs(&f, None, &keys), &envelope("refund"), &seen).is_none());
    // Pack without the Fast2Flow capability, blank text, no probe wiring.
    let block = operator(&server.endpoint, "");
    let nocap = fixture(None, &[]);
    assert!(
        route_reporting(
            &inputs(&nocap, Some(&block), &keys),
            &envelope("refund"),
            &seen
        )
        .is_none()
    );
    assert!(route_reporting(&inputs(&f, Some(&block), &keys), &envelope("   "), &seen).is_none());
    let mut bare = inputs(&f, Some(&block), &keys);
    bare.jev = None;
    assert!(route_reporting(&bare, &envelope("refund"), &seen).is_none());
    assert!(keys.reads.lock().unwrap().is_empty());
    assert!(server.requests().is_empty());
}

#[test]
fn the_operator_can_veto_and_a_pack_cannot_redirect_the_key() {
    let server = MockJev::start(200, REFUND, Duration::ZERO);
    let keys = FakeKeys::found();
    // Operator `enabled: false` beats a pack that turns the tier on.
    let f = fixture(Some(r#"{"jev":{}}"#), &CAP);
    let veto: JevBlock = serde_json::from_value(json!({"enabled": false})).unwrap();
    assert!(route_once(&f, &veto, &keys, "refund").0.is_none());
    // A pack naming its own endpoint switches the tier off (never sends there).
    let evil = fixture(
        Some(&format!(
            r#"{{"jev":{{"endpoint":"{}"}}}}"#,
            server.endpoint
        )),
        &CAP,
    );
    let on = operator(&server.endpoint, "");
    assert!(route_once(&evil, &on, &keys, "refund").0.is_none());
    // A pack asking for a secret outside `jev/` is refused the same way.
    let other = fixture(
        Some(r#"{"jev":{"api_key_secret":"slack/bot_token"}}"#),
        &CAP,
    );
    assert!(route_once(&other, &on, &keys, "refund").0.is_none());
    assert!(server.requests().is_empty());
    assert!(keys.reads.lock().unwrap().is_empty());
}

#[test]
fn a_pack_alone_can_enable_the_tier_for_a_deployed_router() {
    // No bundle.yaml block (revision serve): the pack's block is the config,
    // pointed at the loopback stand-in through the operator-only endpoint? It
    // cannot be, so the pack case uses the default endpoint and is checked at
    // the settings level; the transport is covered by the operator cases.
    let f = fixture(
        Some(r#"{"jev":{"timeout_ms":900,"min_confidence":0.3}}"#),
        &CAP,
    );
    let pack = config::read_pack_block(&f.pack_path).unwrap();
    let got = config::effective(None, pack.as_ref()).unwrap().unwrap();
    assert_eq!(got.endpoint, config::DEFAULT_ENDPOINT);
    assert_eq!(got.min_confidence, 0.3);
}

#[test]
fn jev_runs_after_the_host_router_and_before_the_miss_policy() {
    let server = MockJev::start(200, REFUND, Duration::ZERO);
    let f = fixture(None, &CAP);
    let keys = FakeKeys::found();
    let block = operator(&server.endpoint, "");
    let probe = inputs(&f, Some(&block), &keys);
    // The host router is absent (a failed tier), Jev routes the turn.
    let plan = plan_turn(
        &probe,
        &envelope("refund"),
        false,
        OnRouterFailure::MissPolicy,
    );
    assert!(
        matches!(plan, TurnPlan::Routed(RouteDecision::Node { .. })),
        "{plan:?}"
    );
}

#[test]
fn when_jev_fails_the_existing_miss_behaviour_is_unchanged() {
    let server = MockJev::start(500, "{}", Duration::ZERO);
    let keys = FakeKeys::found();
    let block = operator(&server.endpoint, "");
    // Not opted in to the default flow: the fixed reply, as before.
    let f = fixture(None, &CAP);
    let plan = plan_turn(
        &inputs(&f, Some(&block), &keys),
        &envelope("refund"),
        false,
        OnRouterFailure::MissPolicy,
    );
    match plan {
        TurnPlan::FixedReply(reply) => assert_eq!(reply.text.as_deref(), Some(MISS_REPLY_TEXT)),
        other => panic!("{other:?}"),
    }
    // Opted in: the default flow runs with the original message.
    let caps = [
        FAST2FLOW_CAPABILITY,
        FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY,
    ];
    let g = fixture(None, &caps);
    let plan = plan_turn(
        &inputs(&g, Some(&block), &keys),
        &envelope("refund"),
        false,
        OnRouterFailure::MissPolicy,
    );
    assert_eq!(plan, TurnPlan::DefaultFlow { on_miss: true });
    // The revision path fails open past a failed router.
    let plan = plan_turn(
        &inputs(&f, Some(&block), &keys),
        &envelope("refund"),
        false,
        OnRouterFailure::DefaultFlow,
    );
    assert_eq!(plan, TurnPlan::DefaultFlow { on_miss: false });
}

#[test]
fn the_key_never_appears_in_what_the_tier_can_print() {
    let secret = ChannelSecret::new(KEY);
    assert!(!format!("{secret:?}").contains(KEY));
    let block = operator("https://api.typesafe.ai/v1/systemone", "");
    assert!(!format!("{block:?}").contains(KEY));
    let settings = config::effective(Some(&block), None).unwrap().unwrap();
    assert!(!format!("{settings:?}").contains(KEY));
    let _ = Path::new("");
}

#[path = "only_tests.rs"]
mod only;
