use serde_json::json;

use std::sync::Arc;

use super::ingest_testkit::{FakeStore, bare_envelope, note, ok, pipeline, png};
use super::instance_check::{configured_number, drop_foreign_numbers};

fn wa(number: &str) -> greentic_types::ChannelMessageEnvelope {
    let mut env = bare_envelope();
    env.metadata.insert("phone_number_id".into(), number.into());
    env
}

#[test]
fn a_change_naming_another_number_is_dropped_and_the_first_proceeds() {
    // `identify_instance` routed this webhook by its FIRST change (111); the
    // second change names another business number.
    let mut envs = vec![wa("111"), wa("222")];
    let dropped = drop_foreign_numbers("messaging.whatsapp", Some("111"), &mut envs);
    assert_eq!(dropped, 1);
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0].metadata["phone_number_id"], "111");
}

#[test]
fn an_envelope_without_a_number_proceeds_without_its_media_references() {
    // No number to compare: the MESSAGE is not provably foreign, so it is
    // served; its media is fetched with this instance's token, so its fetch
    // references are removed (fail closed for media only).
    let mut env = bare_envelope();
    env.attachments = vec![greentic_types::Attachment {
        mime_type: "image/jpeg".into(),
        url: Some("https://lookaside.example/media".into()),
        name: Some("p.jpg".into()),
        size_bytes: None,
        content: None,
    }];
    env.extensions.insert(
        "attachment_fetch".into(),
        json!([{ "kind": "whatsapp_media", "media_id": "m1" }]),
    );
    let mut envs = vec![env, wa("111")];
    assert_eq!(
        drop_foreign_numbers("messaging.whatsapp", Some("111"), &mut envs),
        0
    );
    assert_eq!(envs.len(), 2, "no message is dropped");
    assert_eq!(
        envs[0].extensions["attachment_fetch"],
        json!([{ "kind": "withheld" }]),
        "the reference is replaced by a marker, so the slot is still reported"
    );
    assert!(envs[0].attachments[0].url.is_none());
    assert_eq!(
        envs[0].attachments.len(),
        1,
        "the slot stays, to be reported"
    );
}

#[test]
fn other_channels_and_an_unconfigured_number_are_left_alone() {
    let mut envs = vec![wa("222")];
    assert_eq!(
        drop_foreign_numbers("messaging.slack.api", Some("111"), &mut envs),
        0
    );
    assert_eq!(
        drop_foreign_numbers("messaging.whatsapp", None, &mut envs),
        0
    );
    assert_eq!(envs.len(), 1);
}

#[test]
fn the_configured_number_comes_from_the_provider_config() {
    assert_eq!(
        configured_number(Some(&json!({"phone_number_id": " 111 "}))).as_deref(),
        Some("111")
    );
    assert_eq!(
        configured_number(Some(&json!({"phone_number_id": ""}))),
        None
    );
    assert_eq!(configured_number(Some(&json!({}))), None);
    assert_eq!(configured_number(None), None);
}

fn whatsapp_media(number: Option<&str>) -> greentic_types::ChannelMessageEnvelope {
    let mut env = bare_envelope();
    if let Some(number) = number {
        env.metadata.insert("phone_number_id".into(), number.into());
    }
    env.attachments = vec![greentic_types::Attachment {
        mime_type: "image/jpeg".into(),
        url: None,
        name: Some("p.jpg".into()),
        size_bytes: None,
        content: None,
    }];
    env.extensions.insert(
        "attachment_fetch".into(),
        json!([{ "kind": "whatsapp_media", "media_id": "m1" }]),
    );
    env
}

/// An empty or blank `phone_number_id` names no number: the message is
/// served, its media is not fetched (it is not dropped, and its references
/// are not kept either).
#[test]
fn a_blank_number_is_treated_as_no_number() {
    for blank in ["", "   "] {
        let mut envs = vec![whatsapp_media(Some(blank))];
        assert_eq!(
            drop_foreign_numbers("messaging.whatsapp", Some("111"), &mut envs),
            0,
            "{blank:?}"
        );
        assert_eq!(envs.len(), 1, "{blank:?}: the message is served");
        let refs = &envs[0].extensions["attachment_fetch"];
        assert_eq!(refs, &json!([{ "kind": "withheld" }]), "{blank:?}");
    }
}

/// A slot whose media was withheld is still REPORTED to the agent, with a
/// neutral note, after the host's own pipeline ran over it; nothing is
/// fetched for it, even on a request the host verified.
#[tokio::test]
async fn a_withheld_slot_is_reported_with_a_neutral_note_and_never_fetched() {
    let mut envs = vec![whatsapp_media(None)];
    drop_foreign_numbers("messaging.whatsapp", Some("111"), &mut envs);
    let store = Arc::new(FakeStore::default());
    let fetcher_answers = vec![ok(png(1))];
    let pipe = pipeline(fetcher_answers, Arc::clone(&store));
    let origin = super::origin::Origin::new(
        "messaging.whatsapp",
        "messaging-provider-whatsapp",
        "demo",
        None,
    )
    .verified_by_host(crate::artifacts::origin::RequestVerification::Verified);
    pipe.process(&mut envs[0], Some("c"), &origin).await;
    assert!(envs[0].attachments[0].url.is_none());
    let n = note(&envs[0], 0);
    assert_eq!(n["code"], "fetch_failed", "{n}");
    assert!(
        n["message"]
            .as_str()
            .unwrap()
            .contains("could not be retrieved"),
        "{n}"
    );
    assert!(store.puts().is_empty());
    assert!(!envs[0].extensions.contains_key("attachment_fetch"));
}

#[test]
fn a_slot_the_provider_said_not_to_fetch_is_not_turned_into_a_marker() {
    let mut env = whatsapp_media(None);
    env.attachments.push(env.attachments[0].clone());
    env.extensions.insert(
        "attachment_fetch".into(),
        json!([{ "kind": "whatsapp_media", "media_id": "m1" }, { "kind": "none" }]),
    );
    let mut envs = vec![env];
    drop_foreign_numbers("messaging.whatsapp", Some("111"), &mut envs);
    assert_eq!(
        envs[0].extensions["attachment_fetch"],
        json!([{ "kind": "withheld" }, null])
    );
}
