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

#[tokio::test]
async fn boot_fails_when_redis_unreachable() {
    // Use a port that is overwhelmingly likely to be closed.
    let bogus = "redis://127.0.0.1:1";
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        RedisNotifier::build(bogus, Some(unique_channel()), 8),
    )
    .await
    .expect("redis notifier boot should fail fast, not hang");
    assert!(
        result.is_err(),
        "expected build to fail against unreachable redis"
    );
}

#[tokio::test]
async fn subscribe_after_disconnect_recovers() {
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

    let mut stream_b = b.subscribe("t", "c").await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Manual disconnect simulation: push a CLIENT KILL via a side connection
    // to force B's SUB connection to drop.
    let client = redis::Client::open(url.clone()).unwrap();
    let mut admin = client.get_multiplexed_async_connection().await.unwrap();
    let _: redis::Value = redis::cmd("CLIENT")
        .arg("KILL")
        .arg("TYPE")
        .arg("pubsub")
        .query_async(&mut admin)
        .await
        .unwrap();

    // Allow B's background loop to detect + reconnect.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Publish from A; B should receive after the reconnect.
    a.publish(NotifyEvent {
        tenant_id: "t".into(),
        conversation_id: "c".into(),
        new_watermark: 99,
    })
    .await;

    let evt = tokio::time::timeout(
        Duration::from_secs(3),
        futures_util::StreamExt::next(&mut stream_b),
    )
    .await
    .expect("timeout after reconnect")
    .expect("no event after reconnect");
    assert_eq!(evt.new_watermark, 99);
}

#[tokio::test]
async fn notifier_config_yaml_end_to_end() {
    // No Redis required: this test exercises resolve_notifier_config only.
    // It writes a fake state-redis ConfigEnvelope under <root>/providers/state-redis/config.envelope.cbor
    // and asserts that resolve_notifier_config returns Redis with the literal URL.
    use greentic_start::config::OperatorConfig;
    use greentic_start::notifier::NotifierConfig;
    use greentic_start::notifier::config::{SecretResolver, resolve_notifier_config};
    use greentic_start::provider_config_envelope::{ABI_VERSION, ConfigEnvelope};
    use serde_json::json;

    struct PassthroughResolver;
    #[async_trait::async_trait]
    impl SecretResolver for PassthroughResolver {
        async fn resolve(&self, raw: &str) -> anyhow::Result<String> {
            Ok(raw.to_string())
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let providers_root = dir.path().join("providers");
    std::fs::create_dir_all(providers_root.join("state-redis")).unwrap();
    let env = ConfigEnvelope {
        config: json!({"url": "redis://envelope:6379"}),
        component_id: "state-redis".into(),
        abi_version: ABI_VERSION.to_string(),
        resolved_digest: "sha256:0".into(),
        describe_hash: "h".into(),
        schema_hash: None,
        operation_id: "configure".into(),
        updated_at: None,
    };
    let bytes = greentic_types::cbor::canonical::to_canonical_cbor(&env).unwrap();
    std::fs::write(
        providers_root
            .join("state-redis")
            .join("config.envelope.cbor"),
        bytes,
    )
    .unwrap();

    let yaml = "\
webchat:
  notifier:
    backend: redis
";
    let op: OperatorConfig = serde_yaml_bw::from_str(yaml).unwrap();
    let resolved = resolve_notifier_config(dir.path(), &op, &PassthroughResolver)
        .await
        .unwrap();
    match resolved {
        NotifierConfig::Redis { url, .. } => {
            assert_eq!(url.as_deref(), Some("redis://envelope:6379"))
        }
        _ => panic!("expected Redis variant"),
    }
}
