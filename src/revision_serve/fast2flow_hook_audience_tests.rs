//! Router audience on the revision-serve path: a routed node (`ask_<unit>`)
//! restricted by `FlowMeta::node_audience` is refused for a verified caller
//! outside it, whether fast2flow dispatched to it or the client named it.
#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;

use super::fast2flow_hook::*;
use super::fast2flow_hook_tests::*;
use crate::fast2flow::FAST2FLOW_CAPABILITY;
use crate::fast2flow::revision_packs::RevisionAppPack;
use crate::flow_audience::{DENIED_REPLY_TEXT, FlowMeta};
use crate::messaging_app::AppPackInfo;
use greentic_types::ChannelMessageEnvelope;

const DISPATCH_HR: &str =
    r#"{"type":"dispatch","target":"sales-crm/default/ask_hr","confidence":0.9,"reason":"m"}"#;

fn router_app(fx: &Fixture) -> Arc<RevisionAppPack> {
    let meta = FlowMeta::parse(br#"{"version":1,"audience":[],"node_audience":{"ask_hr":["hr"]}}"#)
        .expect("meta");
    Arc::new(RevisionAppPack {
        pack_id: PACK.to_string(),
        pack_path: PathBuf::from("/nonexistent.gtpack"),
        info: AppPackInfo {
            pack_id: PACK.to_string(),
            flows: vec![flow("default")],
            capabilities: vec![FAST2FLOW_CAPABILITY.to_string()],
            flow_meta: Some(meta),
        },
        revision_id: fx.revision_id,
    })
}

fn caller(teams: Option<&[&str]>, verified: bool) -> ChannelMessageEnvelope {
    let mut env = envelope("I need leave");
    let mut block = json!({"user_verified": verified, "sub": "u"});
    if let Some(teams) = teams {
        block["teams"] = json!(teams);
    }
    env.extensions.insert("caller".to_string(), block);
    env
}

async fn plan(fx: &Fixture, env: &ChannelMessageEnvelope) -> RevisionTurn {
    plan_for_app(
        fx.cfg(),
        router_app(fx),
        None,
        &fx.scope(),
        env,
        Some(default_target()),
    )
    .await
}

fn denied_text(turn: &RevisionTurn) -> Option<&str> {
    turn.fixed_reply.as_ref().and_then(|r| r.text.as_deref())
}

#[tokio::test]
async fn a_verified_caller_outside_the_audience_is_refused_before_the_target() {
    let fx = Fixture::new(DISPATCH_HR);
    let turn = plan(&fx, &caller(Some(&["engineering"]), true)).await;
    assert_eq!(denied_text(&turn), Some(DENIED_REPLY_TEXT));
    assert!(turn.target.is_none() && turn.signal.is_none());
}

#[tokio::test]
async fn a_caller_in_the_audience_or_in_any_listed_team_is_routed() {
    for teams in [&["hr"][..], &["engineering", "hr"][..]] {
        let fx = Fixture::new(DISPATCH_HR);
        let turn = plan(&fx, &caller(Some(teams), true)).await;
        assert!(turn.fixed_reply.is_none(), "{teams:?}");
        assert!(turn.signal.is_some(), "{teams:?} is routed to the node");
    }
}

#[tokio::test]
async fn a_caller_without_verified_teams_fails_open() {
    // Anonymous, unverified block, and verified without any team claim.
    for env in [
        envelope("I need leave"),
        caller(Some(&["engineering"]), false),
        caller(None, true),
    ] {
        let fx = Fixture::new(DISPATCH_HR);
        let turn = plan(&fx, &env).await;
        assert!(turn.fixed_reply.is_none());
        assert!(turn.signal.is_some());
    }
}

#[tokio::test]
async fn a_client_named_card_navigation_cannot_jump_past_the_gate() {
    for key in ["routeToCardId", "toCardId", "nextCardId"] {
        let fx = Fixture::new(DISPATCH_HR);
        let mut env = caller(Some(&["engineering"]), true);
        env.metadata.insert(key.to_string(), "ask_hr".to_string());
        let turn = plan(&fx, &env).await;
        assert_eq!(denied_text(&turn), Some(DENIED_REPLY_TEXT), "{key}");
        assert!(!fx.host.invoked(), "{key}: refused before any probe");
    }
}

#[tokio::test]
async fn an_unrestricted_node_is_untouched() {
    let fx = Fixture::new(
        r#"{"type":"dispatch","target":"sales-crm/default/ask_open","confidence":0.9,"reason":"m"}"#,
    );
    let turn = plan(&fx, &caller(Some(&["engineering"]), true)).await;
    assert!(turn.fixed_reply.is_none());
    assert!(turn.signal.is_some());
}
