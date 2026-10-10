//! Text extraction is blocking work: it must never fan out into more blocking
//! threads than there are extraction slots, however many documents arrive.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::ingest::{Extractor, Pipeline};
use super::ingest_testkit::*;
use super::time_testkit::within_ceiling;

/// An extractor that sleeps and records how many copies ran at once.
fn counting_extractor(sleep: Duration) -> (Extractor, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let running = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let extractor: Extractor = {
        let running = running.clone();
        let peak = peak.clone();
        Arc::new(move |_: &[u8], _: &str| {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(sleep);
            running.fetch_sub(1, Ordering::SeqCst);
            Some("text".into())
        })
    };
    (extractor, running, peak)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_documents_never_run_more_extractions_than_there_are_permits() {
    let (extractor, _, peak) = counting_extractor(Duration::from_millis(150));
    let pipeline = Arc::new(
        Pipeline::new(
            Arc::new(FakeStore::default()),
            FakeFetcher::new(vec![ok(b"a,b\n1,2\n".to_vec())]),
        )
        .with_extractor(extractor)
        .with_extraction_permits(2),
    );
    let messages = (0..8).map(|i| {
        let pipeline = pipeline.clone();
        tokio::spawn(async move {
            let mut env = envelope(1);
            pipeline
                .process(&mut env, Some(&format!("c{i}")), &slack())
                .await;
            env
        })
    });
    let envs = within_ceiling(futures_util::future::join_all(messages)).await;
    for env in envs {
        let env = env.expect("task");
        assert!(!env.extensions["artifacts"][0]["text_ref"].is_null());
    }
    assert_eq!(peak.load(Ordering::SeqCst), 2, "extractions ran at once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_timed_out_extraction_keeps_its_permit_until_the_thread_ends() {
    // The first message gives up waiting at its deadline; its blocking thread
    // keeps running. A second message must not start another extraction
    // beside it.
    let (extractor, _, peak) = counting_extractor(Duration::from_millis(800));
    let slow = Pipeline::new(
        Arc::new(FakeStore::default()),
        FakeFetcher::new(vec![ok(b"a,b\n1,2\n".to_vec())]),
    )
    .with_extractor(extractor.clone())
    .with_extraction_permits(1);
    let permits = slow.extraction_permits();
    let slow = slow.with_deadline(Duration::from_millis(100));
    let mut first = envelope(1);
    within_ceiling(slow.process(&mut first, Some("c1"), &slack())).await;
    assert!(first.extensions["artifacts"][0]["text_ref"].is_null());

    let next = Pipeline::new(
        Arc::new(FakeStore::default()),
        FakeFetcher::new(vec![ok(b"x,y\n3,4\n".to_vec())]),
    )
    .with_extractor(extractor)
    .with_shared_extraction_permits(permits);
    let mut second = envelope(1);
    within_ceiling(next.process(&mut second, Some("c2"), &slack())).await;
    // The second extraction only started after the first thread let go.
    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "two extractions ran at once"
    );
    assert!(!second.extensions["artifacts"][0]["text_ref"].is_null());
}

#[tokio::test]
async fn waiting_for_a_permit_past_the_deadline_keeps_the_file_and_drops_the_text() {
    let store = Arc::new(FakeStore::default());
    let pipeline = Pipeline::new(
        store.clone(),
        FakeFetcher::new(vec![ok(b"a,b\n1,2\n".to_vec())]),
    )
    .with_extraction_permits(1);
    let permits = pipeline.extraction_permits();
    let held = permits.clone().acquire_owned().await.expect("permit");
    let pipeline = pipeline.with_deadline(Duration::from_millis(100));
    let mut env = envelope(1);
    within_ceiling(pipeline.process(&mut env, Some("c"), &slack())).await;
    drop(held);
    assert_eq!(env.attachments[0].url.as_deref(), Some("artifact://id1"));
    assert!(env.extensions["artifacts"][0]["text_ref"].is_null());
    assert_eq!(store.puts().len(), 1);
}
