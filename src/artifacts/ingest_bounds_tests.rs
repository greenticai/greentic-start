//! The ingest step's bounds: time, blocking work, text size, labels, and the
//! "never fetch" references.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::json;

use super::ingest::Pipeline;
use super::ingest_testkit::*;
use super::limits::MAX_TEXT_CHARS;
use super::time_testkit::within_ceiling;

#[tokio::test]
async fn never_fetch_references_cost_no_fetch_and_stay_untouched() {
    let store = Arc::new(FakeStore::default());
    let fetcher = FakeFetcher::new(vec![ok(png(0))]);
    let mut env = envelope(4);
    // none, null, an unknown kind, and slot 3 has no entry at all.
    env.extensions.insert(
        "attachment_fetch".into(),
        json!([{"kind":"none"}, null, {"kind":"carrier_pigeon"}]),
    );
    env.attachments[3].url = Some("https://provider.example/keep".into());
    // Slot 2 needs a usable reference so the pipeline runs at all.
    env.extensions.get_mut("attachment_fetch").unwrap()[2] =
        json!({"kind":"public","url":"https://x/2"});
    Pipeline::new(store.clone(), fetcher.clone())
        .process(&mut env, Some("c"))
        .await;
    assert_eq!(fetcher.calls(), 1, "only the usable reference is fetched");
    assert_eq!(
        env.attachments[3].url.as_deref(),
        Some("https://provider.example/keep"),
        "a slot without a reference is untouched"
    );
    assert!(env.attachments[0].url.is_none() && env.attachments[1].url.is_none());
    assert!(env.extensions["artifacts"][0].is_null());
    assert!(!env.extensions.contains_key("attachment_notes"));
}

#[tokio::test]
async fn the_message_has_a_total_time_budget() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(3);
    let started = Instant::now();
    within_ceiling(
        Pipeline::new(store.clone(), FakeFetcher::new(vec![Answer::Hang]))
            .with_deadline(Duration::from_millis(200))
            .process(&mut env, Some("c")),
    )
    .await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    for i in 0..3 {
        assert!(env.attachments[i].url.is_none(), "slot {i}");
        assert_eq!(note(&env, i)["code"], "fetch_failed", "slot {i}");
    }
    assert!(store.puts().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn extraction_runs_off_the_async_runtime() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    let ticked = Arc::new(AtomicBool::new(false));
    let seen_during_extraction = Arc::new(AtomicBool::new(false));
    let ticker = {
        let ticked = ticked.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            ticked.store(true, Ordering::SeqCst);
        })
    };
    let (t, s) = (ticked.clone(), seen_during_extraction.clone());
    Pipeline::new(store, FakeFetcher::new(vec![ok(b"plain text".to_vec())]))
        .with_extractor(Arc::new(move |_: &[u8], _: &str| {
            // On the runtime thread this sleep would starve the ticker.
            std::thread::sleep(Duration::from_millis(400));
            s.store(t.load(Ordering::SeqCst), Ordering::SeqCst);
            Some("text".into())
        }))
        .process(&mut env, Some("c"))
        .await;
    ticker.await.unwrap();
    assert!(
        seen_during_extraction.load(Ordering::SeqCst),
        "the runtime kept running while text was extracted"
    );
    assert_eq!(env.extensions["artifacts"][0]["text_ref"], "artifact://id2");
}

#[tokio::test]
async fn slow_extraction_keeps_the_stored_file_and_drops_only_the_text() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    let started = Instant::now();
    Pipeline::new(
        store.clone(),
        FakeFetcher::new(vec![ok(b"plain text".to_vec())]),
    )
    .with_deadline(Duration::from_millis(200))
    .with_extractor(Arc::new(|_: &[u8], _: &str| {
        std::thread::sleep(Duration::from_secs(2));
        Some("late".into())
    }))
    .process(&mut env, Some("c"))
    .await;
    assert!(started.elapsed() < Duration::from_millis(1500));
    assert_eq!(env.attachments[0].url.as_deref(), Some("artifact://id1"));
    assert!(env.extensions["artifacts"][0]["text_ref"].is_null());
    assert_eq!(store.puts().len(), 1, "no text artifact was stored");
}

#[tokio::test]
async fn derived_text_never_exceeds_the_character_cap() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    Pipeline::new(
        store.clone(),
        FakeFetcher::new(vec![ok(b"plain text".to_vec())]),
    )
    .with_extractor(Arc::new(|_: &[u8], _: &str| {
        Some("é".repeat(MAX_TEXT_CHARS + 5000))
    }))
    .process(&mut env, Some("c"))
    .await;
    let text = String::from_utf8(store.puts()[1].bytes.clone()).unwrap();
    assert_eq!(text.chars().count(), MAX_TEXT_CHARS);
}

#[tokio::test]
async fn the_real_extractor_caps_a_long_text_file() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(1);
    let long = "word ".repeat(MAX_TEXT_CHARS);
    Pipeline::new(store.clone(), FakeFetcher::new(vec![ok(long.into_bytes())]))
        .process(&mut env, Some("c"))
        .await;
    let text = String::from_utf8(store.puts()[1].bytes.clone()).unwrap();
    assert_eq!(text.chars().count(), MAX_TEXT_CHARS);
}

#[tokio::test]
async fn a_hostile_name_is_cleaned_before_it_reaches_the_door_or_a_note() {
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(2);
    env.attachments[0].name = Some(format!("../../x/{}\u{202E}gnp.exe\n", "a".repeat(400)));
    env.attachments[1].name = Some("..".into());
    pipeline(vec![ok(png(0)), Answer::Denied], store.clone())
        .process(&mut env, Some("c"))
        .await;
    let stored = &store.puts()[0].name;
    assert!(stored.len() <= 200, "{}", stored.len());
    assert!(!stored.contains('/') && !stored.contains('\u{202E}') && !stored.contains('\n'));
    assert!(stored.starts_with("aaa"));
    let message = note(&env, 1)["message"].as_str().unwrap();
    assert!(
        message.starts_with("\"attachment 2\": not read"),
        "{message}"
    );
}

#[tokio::test]
async fn a_door_that_never_answers_is_bounded_by_the_message_budget() {
    let store = Arc::new(FakeStore::default());
    *store.hang_on.lock().unwrap() = Some(0);
    let mut env = envelope(1);
    let started = Instant::now();
    within_ceiling(
        pipeline(vec![ok(png(0))], store)
            .with_deadline(Duration::from_millis(200))
            .process(&mut env, Some("c")),
    )
    .await;
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(env.attachments[0].url.is_none());
    assert_eq!(note(&env, 0)["code"], "door_unavailable");
}

#[tokio::test]
async fn nothing_is_stored_once_the_message_budget_is_spent() {
    use base64::Engine as _;
    let store = Arc::new(FakeStore::default());
    let mut env = envelope(2);
    env.extensions.insert(
        "attachment_fetch".into(),
        json!([{"kind":"public","url":"https://x/0"}, {"kind":"inline"}]),
    );
    env.attachments[1].content = Some(json!(
        base64::engine::general_purpose::STANDARD.encode(png(1))
    ));
    within_ceiling(
        Pipeline::new(store.clone(), FakeFetcher::new(vec![Answer::Hang]))
            .with_deadline(Duration::from_millis(150))
            .process(&mut env, Some("c")),
    )
    .await;
    assert!(store.puts().is_empty(), "a late inline file is not stored");
    assert_eq!(note(&env, 1)["code"], "fetch_failed");
    assert!(env.attachments[1].content.is_none());
}
