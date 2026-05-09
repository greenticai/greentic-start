//! Redis pub/sub backplane for the WebChat WS notifier.
//!
//! See docs/superpowers/specs/2026-05-01-webchat-ws-redis-backplane-design.md.

use anyhow::Context as _;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands as _, Client};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::notifier::{
    ActivityNotifier, EventStream, InMemoryNotifier, NotifierError, NotifyEvent,
};

const DEFAULT_CHANNEL: &str = "greentic:webchat:notify";
const BOOT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Wire payload exchanged over the global pub/sub channel.
///
/// `instance_id` is the per-process UUID used for self-echo suppression.
/// `version` allows future forward-compatible payload changes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Wire {
    pub tenant_id: String,
    pub conversation_id: String,
    pub new_watermark: u64,
    pub version: u8,
    pub instance_id: Uuid,
}

enum SubState {
    Connected,
    Reconnecting { attempt: u32 },
}

/// Redis pub/sub backplane wrapping an `InMemoryNotifier` for local fan-out.
///
/// `build` fails fast if Redis is unreachable at startup. Once running,
/// publish-to-Redis is fire-and-forget (local fan-out happens first). A
/// background SUB task handles reconnects with exponential backoff and is
/// supervised against panics.
pub struct RedisNotifier {
    inner: Arc<InMemoryNotifier>,
    self_id: Uuid,
    channel: String,
    pub_conn: ConnectionManager,
    #[allow(dead_code)]
    sub_state: Arc<RwLock<SubState>>,
    _sub_task: tokio::task::JoinHandle<()>,
}

#[async_trait::async_trait]
impl ActivityNotifier for RedisNotifier {
    async fn publish(&self, event: NotifyEvent) {
        // Local first — never block on Redis health.
        self.inner.publish(event.clone()).await;

        // Mirror to Redis fire-and-forget.
        let payload = match serde_json::to_vec(&Wire {
            tenant_id: event.tenant_id,
            conversation_id: event.conversation_id,
            new_watermark: event.new_watermark,
            version: 1,
            instance_id: self.self_id,
        }) {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!(target: "notifier_redis", ?err, "redis_encode_err");
                return;
            }
        };
        let mut pub_conn = self.pub_conn.clone();
        let channel = self.channel.clone();
        tokio::spawn(async move {
            if let Err(err) = pub_conn.publish::<_, _, ()>(&channel, payload).await {
                tracing::debug!(target: "notifier_redis", ?err, "redis_publish_dropped");
            }
        });
    }

    async fn subscribe(
        &self,
        tenant_id: &str,
        conversation_id: &str,
    ) -> Result<EventStream, NotifierError> {
        // No Redis call per subscribe — delegate to the in-memory broadcast.
        self.inner.subscribe(tenant_id, conversation_id).await
    }
}

impl RedisNotifier {
    /// Open PUB and SUB connections to Redis, verify connectivity, spawn the
    /// background SUB loop, and return a reference-counted handle.
    ///
    /// Fails immediately if the URL is invalid or either connection cannot be
    /// established (strict startup).
    pub async fn build(
        url: &str,
        channel: Option<String>,
        capacity: usize,
    ) -> anyhow::Result<Arc<Self>> {
        let channel = channel.unwrap_or_else(|| DEFAULT_CHANNEL.to_string());
        let inner = Arc::new(InMemoryNotifier::new(capacity));
        let self_id = Uuid::new_v4();

        let client = Client::open(url).with_context(|| format!("invalid redis url: {url}"))?;

        // Open the PUB connection (ConnectionManager auto-reconnects on use).
        let pub_conn =
            tokio::time::timeout(BOOT_CONNECT_TIMEOUT, ConnectionManager::new(client.clone()))
                .await
                .with_context(|| format!("timed out opening redis PUB connection to {url}"))?
                .with_context(|| format!("failed to open redis PUB connection to {url}"))?;

        // Verify SUB connectivity once at boot by opening and immediately
        // dropping a probe connection.
        {
            let probe =
                tokio::time::timeout(BOOT_CONNECT_TIMEOUT, subscribe_once(&client, &channel))
                    .await
                    .with_context(|| format!("timed out opening redis SUB connection to {url}"))?
                    .with_context(|| format!("failed to open redis SUB connection to {url}"))?;
            drop(probe);
        }

        let sub_state = Arc::new(RwLock::new(SubState::Connected));

        // Arc::new_cyclic lets the background task hold a Weak<Self> so it
        // can detect when the parent is dropped and exit cleanly.
        let notifier = Arc::new_cyclic(|weak: &std::sync::Weak<Self>| {
            let weak_clone = weak.clone();
            let inner_clone = inner.clone();
            let channel_clone = channel.clone();
            let sub_state_clone = sub_state.clone();
            let client_clone = client.clone();
            let self_id_copy = self_id;

            // Supervisor wrapper: catch panics inside the loop and restart.
            // Without this, a panic in `background_sub_loop` would silently
            // kill cross-replica delivery for the lifetime of the process.
            let task = tokio::spawn(async move {
                loop {
                    let inv = std::panic::AssertUnwindSafe(background_sub_loop(
                        weak_clone.clone(),
                        inner_clone.clone(),
                        self_id_copy,
                        client_clone.clone(),
                        channel_clone.clone(),
                        sub_state_clone.clone(),
                    ));
                    match futures_util::FutureExt::catch_unwind(inv).await {
                        Ok(()) => return, // clean exit (parent dropped)
                        Err(_panic) => {
                            tracing::error!(
                                target: "notifier_redis",
                                "background loop panicked; restarting after 500ms"
                            );
                            *sub_state_clone.write().await = SubState::Reconnecting { attempt: 0 };
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            if weak_clone.upgrade().is_none() {
                                return;
                            }
                        }
                    }
                }
            });

            Self {
                inner,
                self_id,
                channel,
                pub_conn,
                sub_state,
                _sub_task: task,
            }
        });

        Ok(notifier)
    }
}

/// Open a fresh async pub/sub connection and subscribe to `channel`.
async fn subscribe_once(client: &Client, channel: &str) -> anyhow::Result<redis::aio::PubSub> {
    let mut pubsub = client.get_async_pubsub().await?;
    pubsub.subscribe(channel).await?;
    Ok(pubsub)
}

/// Long-running background task: subscribe, drain messages, reconnect on drop.
///
/// Exits cleanly when the parent `Arc<RedisNotifier>` is dropped
/// (`notifier_weak.upgrade()` returns `None`).
async fn background_sub_loop(
    notifier_weak: std::sync::Weak<RedisNotifier>,
    inner: Arc<InMemoryNotifier>,
    self_id: Uuid,
    client: Client,
    channel: String,
    sub_state: Arc<RwLock<SubState>>,
) {
    use futures_util::StreamExt as _;

    loop {
        // (Re)subscribe with bounded backoff.
        let mut sub = loop {
            if notifier_weak.upgrade().is_none() {
                return; // parent dropped
            }
            match subscribe_once(&client, &channel).await {
                Ok(s) => {
                    *sub_state.write().await = SubState::Connected;
                    tracing::info!(target: "notifier_redis", "redis_reconnect_ok");
                    break s;
                }
                Err(err) => {
                    let attempt = match *sub_state.read().await {
                        SubState::Reconnecting { attempt } => attempt,
                        SubState::Connected => 0,
                    };
                    tracing::debug!(
                        target: "notifier_redis",
                        ?err,
                        attempt,
                        "redis_reconnect_fail"
                    );
                    *sub_state.write().await = SubState::Reconnecting {
                        attempt: attempt + 1,
                    };
                    tokio::time::sleep(backoff_with_jitter(attempt)).await;
                }
            }
        };

        // Drain messages until the connection ends.
        while let Some(msg) = sub.on_message().next().await {
            let payload: Vec<u8> = msg.get_payload().unwrap_or_default();
            process_incoming(&payload, self_id, inner.as_ref()).await;
        }

        // Stream ended = disconnect; go back to the (re)subscribe arm.
        *sub_state.write().await = SubState::Reconnecting { attempt: 0 };
        tracing::warn!(target: "notifier_redis", "redis_disconnected");
    }
}

/// Exponential backoff with ±20% jitter.
fn backoff_with_jitter(attempt: u32) -> Duration {
    use rand::RngExt as _;

    let base_ms: u64 = match attempt {
        0 => 100,
        1 => 250,
        2 => 500,
        3 => 1_000,
        4 => 2_000,
        _ => 5_000,
    };
    // rand 0.10: rand::rng() returns ThreadRng; random_range replaces gen_range.
    let jitter: f64 = rand::rng().random_range(-20i32..=20i32) as f64 / 100.0;
    let ms = (base_ms as f64) * (1.0 + jitter);
    Duration::from_millis(ms.max(1.0) as u64)
}

/// Decode a payload received over the Redis SUB stream and dispatch it
/// to the inner notifier, dropping self-echoes and unknown versions.
///
/// Extracted as a free function so unit tests can exercise it without
/// spinning up a Redis connection.
pub(crate) async fn process_incoming(payload: &[u8], self_id: Uuid, inner: &dyn ActivityNotifier) {
    let wire: Wire = match serde_json::from_slice(payload) {
        Ok(w) => w,
        Err(err) => {
            tracing::debug!(target: "notifier_redis", ?err, "redis_decode_err");
            return;
        }
    };
    if wire.instance_id == self_id {
        return; // self-echo
    }
    if wire.version != 1 {
        tracing::warn!(
            target: "notifier_redis",
            version = wire.version,
            "redis_unknown_version"
        );
        return;
    }
    inner
        .publish(NotifyEvent {
            tenant_id: wire.tenant_id,
            conversation_id: wire.conversation_id,
            new_watermark: wire.new_watermark,
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifier::{ActivityNotifier, EventStream, NotifierError, NotifyEvent};
    use async_trait::async_trait;
    use std::sync::Mutex;

    #[test]
    fn wire_payload_roundtrip() {
        let original = Wire {
            tenant_id: "tenant-a".into(),
            conversation_id: "conv-1".into(),
            new_watermark: 42,
            version: 1,
            instance_id: Uuid::new_v4(),
        };
        let bytes = serde_json::to_vec(&original).expect("encode");
        let decoded: Wire = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(original, decoded);
    }

    /// Test double that records every publish call.
    struct RecordingNotifier {
        published: Mutex<Vec<NotifyEvent>>,
    }

    impl RecordingNotifier {
        fn new() -> Self {
            Self {
                published: Mutex::new(vec![]),
            }
        }
        fn count(&self) -> usize {
            self.published.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl ActivityNotifier for RecordingNotifier {
        async fn publish(&self, event: NotifyEvent) {
            self.published.lock().unwrap().push(event);
        }
        async fn subscribe(
            &self,
            _tenant: &str,
            _conv: &str,
        ) -> Result<EventStream, NotifierError> {
            unreachable!("not used in dispatch tests")
        }
    }

    fn make_payload(instance_id: Uuid, version: u8) -> Vec<u8> {
        serde_json::to_vec(&Wire {
            tenant_id: "t".into(),
            conversation_id: "c".into(),
            new_watermark: 7,
            version,
            instance_id,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn loop_suppression_drops_self_publish() {
        let inner = RecordingNotifier::new();
        let self_id = Uuid::new_v4();
        let payload = make_payload(self_id, 1);
        process_incoming(&payload, self_id, &inner).await;
        assert_eq!(inner.count(), 0, "self-echo must be dropped");
    }

    #[tokio::test]
    async fn loop_suppression_accepts_other_replica() {
        let inner = RecordingNotifier::new();
        let self_id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let payload = make_payload(other, 1);
        process_incoming(&payload, self_id, &inner).await;
        assert_eq!(inner.count(), 1);
    }

    #[tokio::test]
    async fn dispatch_drops_unknown_version() {
        let inner = RecordingNotifier::new();
        let self_id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let payload = make_payload(other, 99);
        process_incoming(&payload, self_id, &inner).await;
        assert_eq!(inner.count(), 0);
    }

    #[tokio::test]
    async fn dispatch_drops_malformed_payload() {
        let inner = RecordingNotifier::new();
        let self_id = Uuid::new_v4();
        process_incoming(b"not-json{{", self_id, &inner).await;
        assert_eq!(inner.count(), 0);
    }
}
