use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

use super::ingest_testkit::*;

#[tokio::test]
async fn an_envelope_without_attachments_is_untouched() {
    let store = Arc::new(FakeStore::default());
    let mut env = bare_envelope();
    let before = serde_json::to_value(&env).unwrap();
    pipeline(vec![ok(png(0))], store.clone())
        .process(&mut env, Some("c"), &slack())
        .await;
    assert_eq!(serde_json::to_value(&env).unwrap(), before);
    assert!(store.puts().is_empty());
}

#[tokio::test]
async fn an_unmigrated_providers_envelope_is_untouched() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    env.extensions.clear(); // no attachment_fetch at all
    let before = serde_json::to_value(&env).unwrap();
    pipeline(vec![ok(png(0))], store.clone())
        .process(&mut env, Some("c"), &slack())
        .await;
    assert_eq!(serde_json::to_value(&env).unwrap(), before);
    assert!(store.puts().is_empty());
}

#[tokio::test]
async fn an_image_becomes_an_artifact_reference() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    pipeline(vec![ok(png(0))], store)
        .process(&mut env, Some("c"), &slack())
        .await;
    assert_eq!(env.attachments[0].url.as_deref(), Some("artifact://id1"));
    assert_eq!(env.attachments[0].mime_type, "image/png");
    assert_eq!(env.attachments[0].size_bytes, Some(13));
    let arts = env.extensions["artifacts"].as_array().unwrap();
    assert_eq!(arts[0]["kind"], "image");
    assert!(arts[0]["text_ref"].is_null());
    assert!(!env.extensions.contains_key("attachment_fetch"));
    assert!(
        !env.extensions.contains_key("attachment_notes"),
        "no failure, no notes key"
    );
}

#[tokio::test]
async fn a_document_gets_a_derived_text_artifact_in_the_same_conversation() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    env.attachments[0].mime_type = "application/pdf".into(); // the claim is ignored
    pipeline(vec![ok(b"a,b\n1,2\n3,4\n".to_vec())], store.clone())
        .process(&mut env, Some("conv-1"), &slack())
        .await;
    let arts = env.extensions["artifacts"].as_array().unwrap();
    assert_eq!(
        env.attachments[0].mime_type, "text/csv",
        "mime follows the bytes, not the claim"
    );
    assert_eq!(arts[0]["kind"], "document");
    assert_eq!(arts[0]["text_ref"], "artifact://id2");
    let puts = store.puts();
    assert_eq!(puts[1].mime, "text/plain");
    assert_eq!(puts[1].name, "f0.png.txt");
    assert_eq!(puts[1].derived_from.as_deref(), Some("artifact://id1"));
    assert!(
        puts.iter()
            .all(|p| p.conversation_id.as_deref() == Some("conv-1"))
    );
}

#[tokio::test]
async fn the_sixth_attachment_is_kept_with_a_null_url_and_a_note() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(6);
    pipeline((0..6).map(|i| ok(png(i))).collect(), store.clone())
        .process(&mut env, Some("c"), &slack())
        .await;
    assert_eq!(env.attachments.len(), 6, "nothing is removed or reordered");
    assert!(env.attachments[5].url.is_none());
    assert_eq!(env.attachments[0].url.as_deref(), Some("artifact://id1"));
    let arts = env.extensions["artifacts"].as_array().unwrap();
    assert_eq!(arts.len(), 6);
    assert!(arts[5].is_null());
    assert_eq!(note(&env, 5)["code"], "quota_exceeded");
    assert!(
        note(&env, 5)["message"]
            .as_str()
            .unwrap()
            .contains("f5.png")
    );
    assert!(note(&env, 0).is_null());
    assert_eq!(store.puts().len(), 5);
}

#[tokio::test]
async fn a_failed_download_keeps_its_slot_and_the_rest_survive() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(3);
    pipeline(vec![ok(png(0)), Answer::Denied, ok(png(2))], store)
        .process(&mut env, Some("c"), &slack())
        .await;
    assert_eq!(env.attachments.len(), 3);
    assert!(env.attachments[1].url.is_none());
    assert!(env.attachments[0].url.is_some() && env.attachments[2].url.is_some());
    assert_eq!(note(&env, 1)["code"], "fetch_failed");
    assert!(
        note(&env, 1)["message"]
            .as_str()
            .unwrap()
            .contains("f1.png")
    );
    assert!(note(&env, 0).is_null() && note(&env, 2).is_null());
    assert!(env.extensions["artifacts"][1].is_null());
    let notes = env.extensions["attachment_notes"].as_array().unwrap();
    assert_eq!(notes.len(), 3, "notes are parallel to the attachments");
}

#[tokio::test]
async fn svg_bytes_under_a_png_claim_are_rejected() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    pipeline(
        vec![ok(br#"<svg xmlns="http://www.w3.org/2000/svg"/>"#.to_vec())],
        store.clone(),
    )
    .process(&mut env, Some("c"), &slack())
    .await;
    assert!(env.attachments[0].url.is_none());
    assert!(store.puts().is_empty());
    assert_eq!(note(&env, 0)["code"], "unsupported_type");
    assert!(note(&env, 0)["message"].as_str().unwrap().contains("SVG"));
}

#[tokio::test]
async fn a_door_failure_on_one_file_keeps_the_others() {
    let store = Arc::new(FakeStore::default());
    *store.fail_on.lock().unwrap() = Some(1);
    let mut env = envelope(3);
    pipeline((0..3).map(|i| ok(png(i))).collect(), store)
        .process(&mut env, Some("c"), &slack())
        .await;
    assert!(env.attachments[1].url.is_none());
    assert_eq!(note(&env, 1)["code"], "door_unavailable");
    assert!(env.attachments[0].url.is_some() && env.attachments[2].url.is_some());
}

#[tokio::test]
async fn identical_bytes_in_one_message_cost_one_door_put() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(2);
    pipeline(vec![ok(png(7))], store.clone())
        .process(&mut env, Some("c"), &slack())
        .await;
    assert_eq!(env.attachments[0].url, env.attachments[1].url);
    assert_eq!(store.puts().len(), 1);
}

#[tokio::test]
async fn the_message_total_is_capped() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(3);
    // 13 bytes each; a 30-byte message cap admits two.
    pipeline((0..3).map(|i| ok(png(i))).collect(), store)
        .with_message_cap(30)
        .process(&mut env, Some("c"), &slack())
        .await;
    assert!(env.attachments[1].url.is_some());
    assert!(env.attachments[2].url.is_none());
    assert_eq!(note(&env, 2)["code"], "too_large");
}

#[tokio::test]
async fn an_inline_attachment_is_stored_and_its_bytes_leave_the_envelope() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    env.extensions
        .insert("attachment_fetch".into(), json!([{"kind": "inline"}]));
    env.attachments[0].content = Some(Value::String(B64.encode(png(0))));
    let fetcher = FakeFetcher::new(vec![Answer::Denied]);
    super::ingest::Pipeline::new(store.clone(), fetcher.clone())
        .process(&mut env, Some("c"), &slack())
        .await;
    assert_eq!(env.attachments[0].url.as_deref(), Some("artifact://id1"));
    assert!(
        env.attachments[0].content.is_none(),
        "bytes must not stay in the envelope"
    );
    assert_eq!(
        fetcher.calls(),
        0,
        "an inline attachment is never downloaded"
    );
    assert_eq!(store.puts()[0].bytes, png(0));
}

#[tokio::test]
async fn an_inline_attachment_accepts_the_object_form_and_rejects_garbage() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(5);
    env.extensions.insert(
        "attachment_fetch".into(),
        json!([{"kind": "inline"}, {"kind": "inline"}, {"kind": "inline"},
               {"kind": "inline"}, {"kind": "inline"}]),
    );
    env.attachments[0].content = Some(json!({"data_base64": B64.encode(png(1))}));
    env.attachments[1].content = Some(json!("%%% not base64 %%%"));
    env.attachments[2].content = Some(json!(format!(
        "data:image/png;base64,{}",
        B64.encode(png(2))
    )));
    env.attachments[3].content = Some(json!(12));
    env.attachments[4].content = None;
    pipeline(vec![Answer::Denied], store)
        .process(&mut env, Some("c"), &slack())
        .await;
    assert!(env.attachments[0].url.is_some());
    for i in 1..5 {
        assert!(env.attachments[i].url.is_none(), "slot {i}");
        assert_eq!(note(&env, i)["code"], "fetch_failed", "slot {i}");
        assert!(env.attachments[i].content.is_none(), "slot {i}");
    }
}

#[tokio::test]
async fn an_oversized_inline_payload_is_refused_before_decoding() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    env.extensions
        .insert("attachment_fetch".into(), json!([{"kind": "inline"}]));
    env.attachments[0].content = Some(Value::String("A".repeat(20 * 1024 * 1024)));
    pipeline(vec![Answer::Denied], store.clone())
        .process(&mut env, Some("c"), &slack())
        .await;
    assert_eq!(note(&env, 0)["code"], "too_large");
    assert!(store.puts().is_empty());
    assert!(env.attachments[0].content.is_none());
}

#[tokio::test]
async fn no_note_ever_contains_a_url_or_credential() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    env.extensions.insert(
        "attachment_fetch".into(),
        json!([{"kind":"bearer","url":"https://files.slack.com/x?t=secret-q","secret_key":"SLACK_BOT_TOKEN"}]),
    );
    pipeline(vec![Answer::Denied], store)
        .process(&mut env, Some("c"), &slack())
        .await;
    let text = note(&env, 0).to_string();
    for needle in ["https://", "secret-q", "SLACK_BOT_TOKEN", "401"] {
        assert!(!text.contains(needle), "{needle} in {text}");
    }
    assert!(!text.to_lowercase().contains("bearer"), "{text}");
}

#[tokio::test]
async fn the_inline_size_is_judged_from_the_base64_length_alone() {
    // Not base64 at all: only a length check made before decoding can call it
    // too large rather than unreadable.
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    env.extensions
        .insert("attachment_fetch".into(), json!([{"kind": "inline"}]));
    env.attachments[0].content = Some(Value::String("%".repeat(14 * 1024 * 1024)));
    pipeline(vec![Answer::Denied], store)
        .process(&mut env, Some("c"), &slack())
        .await;
    assert_eq!(note(&env, 0)["code"], "too_large");
}
