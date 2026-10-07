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
fn an_envelope_without_a_number_is_dropped_too() {
    let mut envs = vec![bare_envelope(), wa("unknown")];
    assert_eq!(
        drop_foreign_numbers("messaging.whatsapp", Some("111"), &mut envs),
        2
    );
    assert!(envs.is_empty());
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
