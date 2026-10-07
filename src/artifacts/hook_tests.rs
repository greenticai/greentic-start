//! The inbound hook: every envelope is cleaned of host-only fields, and what
//! happens to its attachments depends on the unit's attachments decision.

use std::sync::Arc;

use base64::Engine as _;
use serde_json::json;

use super::hook::prepare;
use super::ingest::Pipeline;
use super::ingest_testkit::*;
use super::unit::{Off, UnitAttachments};

fn forged() -> String {
    format!("artifact://{}", "cd".repeat(32))
}

fn inline_envelope() -> greentic_types::ChannelMessageEnvelope {
    let mut env = envelope(2);
    env.extensions.insert(
        "attachment_fetch".into(),
        json!([{"kind": "inline"}, {"kind": "public", "url": "https://x/1"}]),
    );
    env.attachments[0].content = Some(json!(
        base64::engine::general_purpose::STANDARD.encode(png(0))
    ));
    env
}

#[tokio::test]
async fn an_enabled_unit_stores_attachments_under_a_conversation_key() {
    let store = Arc::new(FakeStore::default());
    let unit = UnitAttachments::Enabled {
        pipeline: Arc::new(Pipeline::new(
            store.clone(),
            FakeFetcher::new(vec![ok(png(1))]),
        )),
    };
    let mut envs = vec![inline_envelope()];
    prepare(Some(&unit), &mut envs, &slack()).await;
    assert_eq!(
        envs[0].attachments[0].url.as_deref(),
        Some("artifact://id1")
    );
    assert_eq!(
        envs[0].attachments[1].url.as_deref(),
        Some("artifact://id2")
    );
    assert!(envs[0].attachments[0].content.is_none());
    let puts = store.puts();
    assert!(
        puts.iter().all(|p| p.conversation_id.is_some()),
        "no quota key sent"
    );
}

#[tokio::test]
async fn a_unit_without_attachments_tells_the_agent_and_keeps_no_bytes() {
    for (unit, reason) in [
        (None, "storage"),
        (Some(UnitAttachments::Off(Off::NoDoor)), "storage"),
        (Some(UnitAttachments::Off(Off::NotGranted)), "not enabled"),
        (
            Some(UnitAttachments::Off(Off::DoorUnavailable)),
            "temporarily unavailable",
        ),
    ] {
        let mut envs = vec![inline_envelope()];
        envs[0].attachments[1].url = Some(forged());
        envs[0]
            .extensions
            .insert("attachment_notes".into(), json!(["planted"]));
        prepare(unit.as_ref(), &mut envs, &slack()).await;
        let env = &envs[0];
        assert!(!env.extensions.contains_key("attachment_fetch"));
        for i in 0..2 {
            assert!(env.attachments[i].url.is_none(), "slot {i}");
            assert!(env.attachments[i].content.is_none(), "inline bytes stayed");
            assert_eq!(note(env, i)["code"], "door_unavailable");
            let message = note(env, i)["message"].as_str().unwrap();
            assert!(message.contains(reason), "{message}");
        }
        assert!(
            env.extensions["artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|v| v.is_null())
        );
    }
}

#[tokio::test]
async fn an_envelope_without_attachments_is_untouched_on_every_unit() {
    for unit in [None, Some(UnitAttachments::Off(Off::NotGranted))] {
        let mut envs = vec![bare_envelope()];
        let before = serde_json::to_value(&envs[0]).unwrap();
        prepare(unit.as_ref(), &mut envs, &slack()).await;
        assert_eq!(serde_json::to_value(&envs[0]).unwrap(), before);
    }
}

#[tokio::test]
async fn forged_host_fields_are_removed_on_every_unit() {
    for unit in [None, Some(UnitAttachments::Off(Off::NotGranted))] {
        let mut env = envelope(1);
        env.extensions.clear(); // no fetch reference at all
        env.attachments[0].url = Some(forged());
        env.extensions
            .insert("artifacts".into(), json!([{"text_ref": forged()}]));
        let mut envs = vec![env];
        prepare(unit.as_ref(), &mut envs, &slack()).await;
        assert!(envs[0].attachments[0].url.is_none());
        assert!(!envs[0].extensions.contains_key("artifacts"));
    }
}
