//! Integration tests for the Redis notifier backplane.
//!
//! Gated behind GREENTIC_TEST_REDIS_URL — these tests are skipped (treated as
//! pass) when the env var is unset, so default `cargo test` doesn't require
//! a running Redis.
//!
//! Run locally:
//!   docker run --rm -p 6379:6379 redis
//!   GREENTIC_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test --test notifier_redis -- --nocapture

use std::time::Duration;

use greentic_start::notifier::redis::RedisNotifier;
use greentic_start::notifier::{ActivityNotifier, NotifyEvent};

fn redis_url_or_skip() -> Option<String> {
    match std::env::var("GREENTIC_TEST_REDIS_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ => {
            eprintln!("skipping: GREENTIC_TEST_REDIS_URL not set");
            None
        }
    }
}

fn unique_channel() -> String {
    format!("greentic:test:{}", uuid::Uuid::new_v4())
}

#[tokio::test]
async fn single_notifier_local_publish_works() {
    let Some(url) = redis_url_or_skip() else {
        return;
    };
    let notifier = RedisNotifier::build(&url, Some(unique_channel()), 8)
        .await
        .unwrap();
    let mut stream = notifier.subscribe("t", "c").await.unwrap();
    notifier
        .publish(NotifyEvent {
            tenant_id: "t".into(),
            conversation_id: "c".into(),
            new_watermark: 1,
        })
        .await;
    let evt = tokio::time::timeout(
        Duration::from_secs(1),
        futures_util::StreamExt::next(&mut stream),
    )
    .await
    .expect("timeout")
    .expect("no event");
    assert_eq!(evt.new_watermark, 1);
}

#[tokio::test]
async fn two_notifiers_cross_replica_fanout() {
    let Some(url) = redis_url_or_skip() else {
        return;
    };
    let channel = unique_channel();
    let a = RedisNotifier::build(&url, Some(channel.clone()), 8)
        .await
        .unwrap();
    let b = RedisNotifier::build(&url, Some(channel.clone()), 8)
        .await
        .unwrap();

    // Subscribe on B; publish on A.
    let mut stream_b = b.subscribe("t", "c").await.unwrap();

    // Allow SUB to register on Redis side before A publishes.
    tokio::time::sleep(Duration::from_millis(50)).await;

    a.publish(NotifyEvent {
        tenant_id: "t".into(),
        conversation_id: "c".into(),
        new_watermark: 7,
    })
    .await;

    let evt = tokio::time::timeout(
        Duration::from_secs(2),
        futures_util::StreamExt::next(&mut stream_b),
    )
    .await
    .expect("timeout waiting for cross-replica fan-out")
    .expect("no event");
    assert_eq!(evt.new_watermark, 7);
}

#[tokio::test]
async fn loop_suppression_no_duplicate_on_self_publish() {
    let Some(url) = redis_url_or_skip() else {
        return;
    };
    let channel = unique_channel();
    let a = RedisNotifier::build(&url, Some(channel), 8).await.unwrap();
    let mut stream = a.subscribe("t", "c").await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    a.publish(NotifyEvent {
        tenant_id: "t".into(),
        conversation_id: "c".into(),
        new_watermark: 1,
    })
    .await;

    // Should receive exactly one event (the local fan-out).
    let _first = tokio::time::timeout(
        Duration::from_secs(1),
        futures_util::StreamExt::next(&mut stream),
    )
    .await
    .expect("timeout")
    .expect("missing first event");

    // No second event — Redis loop was suppressed by instance_id.
    let second = tokio::time::timeout(
        Duration::from_millis(300),
        futures_util::StreamExt::next(&mut stream),
    )
    .await;
    assert!(
        second.is_err(),
        "expected timeout (no second event), got {second:?}"
    );
}
