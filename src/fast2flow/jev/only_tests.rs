//! `position: only`: Jev instead of the host router's route decision, against a
//! stub routing host and the loopback Jev double.

use super::*;
use crate::fast2flow::test_script::write_executable_script;

const BM25_SALES: &str =
    r#"{"type":"dispatch","target":"router/default/ask_sales","confidence":0.8,"reason":"m"}"#;
const DENY: &str = r#"{"type":"deny","reason":"blocked"}"#;
const ONLY_PACK: &str = r#"{"jev":{"position":"only"}}"#;

/// Point the fixture's routing host at a script that answers `directive`.
fn with_host(f: &mut Fixture, directive: &str) -> TempDir {
    let dir = tempdir().unwrap();
    let path = dir.path().join("host.sh");
    let body = format!(r#"{{"directive":{directive}}}"#);
    write_executable_script(&path, &format!("cat > /dev/null\nprintf '%s' '{body}'\n"));
    f.cfg.host_bin = path;
    dir
}

fn block_with(endpoint: &str, position: &str) -> JevBlock {
    serde_json::from_value(json!({"endpoint": endpoint, "timeout_ms": 500, "position": position}))
        .unwrap()
}

fn plan(f: &Fixture, block: Option<&JevBlock>) -> TurnPlan {
    let keys = FakeKeys::found();
    plan_turn(
        &inputs(f, block, &keys),
        &envelope("refund"),
        false,
        OnRouterFailure::MissPolicy,
    )
}

fn source_of(plan: &TurnPlan) -> RouteSource {
    match plan {
        TurnPlan::Routed(RouteDecision::Node { signal, .. })
        | TurnPlan::Routed(RouteDecision::Flow { signal, .. }) => signal.source,
        other => panic!("expected a route, got {other:?}"),
    }
}

#[test]
fn only_skips_a_bm25_match_and_jev_decides() {
    let server = MockJev::start(200, REFUND, Duration::ZERO);
    let mut f = fixture(None, &CAP);
    let _h = with_host(&mut f, BM25_SALES);
    let plan = plan(&f, Some(&block_with(&server.endpoint, "only")));
    // BM25 said sales; Jev said support, and Jev wins.
    match &plan {
        TurnPlan::Routed(RouteDecision::Node { envelope, signal }) => {
            assert_eq!(signal.source, RouteSource::Jev);
            assert_eq!(
                envelope.metadata.get("routeToCardId").map(String::as_str),
                Some("ask_support")
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn a_pack_may_select_only() {
    let server = MockJev::start(200, REFUND, Duration::ZERO);
    let mut f = fixture(Some(ONLY_PACK), &CAP);
    let _h = with_host(&mut f, BM25_SALES);
    let block: JevBlock = serde_json::from_value(json!({"endpoint": server.endpoint})).unwrap();
    assert_eq!(source_of(&plan(&f, Some(&block))), RouteSource::Jev);
}

#[test]
fn only_with_a_jev_failure_reaches_the_miss_policy_not_bm25() {
    let server = MockJev::start(500, "{}", Duration::ZERO);
    let mut f = fixture(None, &CAP);
    let _h = with_host(&mut f, BM25_SALES);
    match plan(&f, Some(&block_with(&server.endpoint, "only"))) {
        TurnPlan::FixedReply(r) => assert_eq!(r.text.as_deref(), Some(MISS_REPLY_TEXT)),
        other => panic!("{other:?}"),
    }
    // Opted in to the default flow on a miss: that runs instead.
    let caps = [
        FAST2FLOW_CAPABILITY,
        FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY,
    ];
    let mut g = fixture(None, &caps);
    let _h2 = with_host(&mut g, BM25_SALES);
    assert_eq!(
        plan(&g, Some(&block_with(&server.endpoint, "only"))),
        TurnPlan::DefaultFlow { on_miss: true }
    );
}

#[test]
fn only_still_honours_a_host_deny_without_asking_jev() {
    let server = MockJev::start(200, REFUND, Duration::ZERO);
    let mut f = fixture(None, &CAP);
    let _h = with_host(&mut f, DENY);
    match plan(&f, Some(&block_with(&server.endpoint, "only"))) {
        TurnPlan::FixedReply(_) => {}
        other => panic!("{other:?}"),
    }
    assert!(server.requests().is_empty());
}

#[test]
fn the_default_position_is_unchanged() {
    for position in [None, Some("after_router")] {
        let server = MockJev::start(200, REFUND, Duration::ZERO);
        let mut f = fixture(None, &CAP);
        let _h = with_host(&mut f, BM25_SALES);
        let block = match position {
            Some(p) => block_with(&server.endpoint, p),
            None => operator(&server.endpoint, ""),
        };
        assert_eq!(source_of(&plan(&f, Some(&block))), RouteSource::Bm25);
        assert!(server.requests().is_empty());
    }
}

#[test]
fn an_unknown_position_turns_only_the_jev_tier_off() {
    assert!(serde_json::from_str::<JevBlock>(r#"{"position":"sideways"}"#).is_err());
    assert!(serde_json::from_str::<JevBlock>(r#"{"position":"Only"}"#).is_err());
    // In a pack: the Jev tier is off, BM25 keeps routing, no Jev request.
    let server = MockJev::start(200, REFUND, Duration::ZERO);
    let mut f = fixture(Some(r#"{"jev":{"position":"sideways"}}"#), &CAP);
    let _h = with_host(&mut f, BM25_SALES);
    let block: JevBlock = serde_json::from_value(json!({"endpoint": server.endpoint})).unwrap();
    assert_eq!(source_of(&plan(&f, Some(&block))), RouteSource::Bm25);
    assert!(server.requests().is_empty());
}

#[test]
fn only_changes_nothing_when_jev_is_not_configured_or_is_vetoed() {
    let server = MockJev::start(200, REFUND, Duration::ZERO);
    // No jev block anywhere (a pack-only `only` needs a block to exist).
    let mut f = fixture(None, &CAP);
    let _h = with_host(&mut f, BM25_SALES);
    assert_eq!(source_of(&plan(&f, None)), RouteSource::Bm25);
    // The operator vetoes a pack that asks for `only`.
    let mut g = fixture(Some(ONLY_PACK), &CAP);
    let _h2 = with_host(&mut g, BM25_SALES);
    let veto: JevBlock =
        serde_json::from_value(json!({"endpoint": server.endpoint, "enabled": false})).unwrap();
    assert_eq!(source_of(&plan(&g, Some(&veto))), RouteSource::Bm25);
    assert!(server.requests().is_empty());
}
