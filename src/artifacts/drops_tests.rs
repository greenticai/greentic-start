use std::sync::Arc;

use serde_json::json;

use super::drops::{FILE_DROPPED, MESSAGE_DROPPED, append_drop_notes};
use super::ingest_testkit::*;
use super::limits::MAX_FILES;

fn with_counters(
    files: Option<&str>,
    messages: Option<&str>,
) -> greentic_types::ChannelMessageEnvelope {
    let mut env = bare_envelope();
    if let Some(v) = files {
        env.metadata.insert("attachments_dropped".into(), v.into());
    }
    if let Some(v) = messages {
        env.metadata.insert("messages_dropped".into(), v.into());
    }
    env
}

fn assert_parallel(env: &greentic_types::ChannelMessageEnvelope) {
    let n = env.attachments.len();
    assert_eq!(env.extensions["artifacts"].as_array().unwrap().len(), n);
    assert_eq!(
        env.extensions["attachment_notes"].as_array().unwrap().len(),
        n
    );
}

fn assert_drop_slot(env: &greentic_types::ChannelMessageEnvelope, i: usize, sentence: &str) {
    let a = &env.attachments[i];
    assert!(a.url.is_none() && a.content.is_none());
    assert_eq!(a.name.as_deref(), Some("file"));
    assert_eq!(a.mime_type, "application/octet-stream");
    assert_eq!(a.size_bytes, Some(0));
    assert!(env.extensions["artifacts"][i].is_null());
    assert_eq!(
        note(env, i),
        &json!({"code": "fetch_failed", "message": sentence})
    );
}

#[test]
fn no_counters_leave_the_envelope_byte_identical() {
    let mut env = envelope(2);
    let before = serde_json::to_value(&env).unwrap();
    append_drop_notes(&mut env);
    assert_eq!(serde_json::to_value(&env).unwrap(), before);
}

#[test]
fn dropped_files_become_appended_slots_with_a_fixed_note() {
    let mut env = with_counters(Some("2"), None);
    append_drop_notes(&mut env);
    assert_eq!(env.attachments.len(), 2);
    assert_parallel(&env);
    assert_drop_slot(&env, 0, FILE_DROPPED);
    assert_drop_slot(&env, 1, FILE_DROPPED);
    assert!(!env.metadata.contains_key("attachments_dropped"));
}

#[test]
fn dropped_messages_become_one_slot() {
    let mut env = with_counters(None, Some("3"));
    append_drop_notes(&mut env);
    assert_eq!(env.attachments.len(), 1);
    assert_parallel(&env);
    assert_drop_slot(&env, 0, MESSAGE_DROPPED);
    assert!(!env.metadata.contains_key("messages_dropped"));
}

#[test]
fn a_hostile_counter_cannot_grow_the_envelope() {
    let mut env = with_counters(Some("10000"), Some("10000"));
    append_drop_notes(&mut env);
    assert_eq!(env.attachments.len(), MAX_FILES);
    assert_parallel(&env);
    assert_drop_slot(&env, MAX_FILES - 1, MESSAGE_DROPPED);
}

#[test]
fn garbage_counters_append_nothing_and_are_removed() {
    for bad in ["lots", "-3", "", "1.5", "0", "99999999999999999999999"] {
        let mut env = with_counters(Some(bad), Some(bad));
        append_drop_notes(&mut env);
        assert!(env.attachments.is_empty(), "{bad:?}");
        assert!(!env.extensions.contains_key("attachment_notes"), "{bad:?}");
        assert!(!env.metadata.contains_key("attachments_dropped"), "{bad:?}");
        assert!(!env.metadata.contains_key("messages_dropped"), "{bad:?}");
    }
}

#[test]
fn drop_slots_come_after_real_attachments_and_copy_nothing_from_them() {
    let mut env = envelope(1);
    env.attachments[0].name = Some("provider-secret-name.pdf".into());
    env.attachments[0].url = Some("https://provider.example/f".into());
    env.metadata
        .insert("attachments_dropped".into(), "1".into());
    append_drop_notes(&mut env);
    assert_eq!(env.attachments.len(), 2);
    assert_eq!(
        env.attachments[0].name.as_deref(),
        Some("provider-secret-name.pdf"),
        "the real attachment keeps slot 0"
    );
    assert_parallel(&env);
    assert!(env.extensions["attachment_notes"][0].is_null());
    assert_drop_slot(&env, 1, FILE_DROPPED);
    let all = serde_json::to_string(&env.extensions["attachment_notes"]).unwrap();
    assert!(
        !all.contains("provider") && !all.contains("https://"),
        "{all}"
    );
}

#[test]
fn existing_host_arrays_are_extended_in_place() {
    let mut env = envelope(2);
    env.extensions.insert(
        "artifacts".into(),
        json!([{"sha256":"aa","kind":"image","text_ref":null}, null]),
    );
    env.extensions.insert(
        "attachment_notes".into(),
        json!([null, {"code":"too_large","message":"f1.png: not read, x"}]),
    );
    env.metadata
        .insert("attachments_dropped".into(), "1".into());
    append_drop_notes(&mut env);
    assert_parallel(&env);
    assert_eq!(env.extensions["artifacts"][0]["kind"], "image");
    assert_eq!(note(&env, 1)["code"], "too_large");
    assert_drop_slot(&env, 2, FILE_DROPPED);
}

#[tokio::test]
async fn the_pipeline_turns_counters_into_notes_even_without_attachments() {
    let store = Arc::new(FakeStore::default());
    let mut env = with_counters(Some("1"), None);
    pipeline(vec![ok(png(0))], store.clone())
        .process(&mut env, Some("c"), &slack())
        .await;
    assert_drop_slot(&env, 0, FILE_DROPPED);
    assert!(store.puts().is_empty());
}

#[tokio::test]
async fn the_pipeline_appends_after_its_own_slots() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    env.metadata
        .insert("attachments_dropped".into(), "1".into());
    pipeline(vec![ok(png(0))], store)
        .process(&mut env, Some("c"), &slack())
        .await;
    assert_eq!(env.attachments[0].url.as_deref(), Some("artifact://id1"));
    assert_parallel(&env);
    assert!(note(&env, 0).is_null());
    assert_drop_slot(&env, 1, FILE_DROPPED);
}
