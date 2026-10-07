use serde_json::json;

use super::ingest_testkit::bare_envelope;
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
    assert!(!envs[0].extensions.contains_key("attachment_fetch"));
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
