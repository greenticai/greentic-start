//! Activity push notifier — informs WS sessions when a conversation has new activities.
//!
//! Two backends are supported via the `ActivityNotifier` trait. This module ships the
//! trait, types, and the in-memory backend. NATS lives in a follow-up plan.

use async_trait::async_trait;
use futures_util::Stream;
use std::pin::Pin;

pub mod config;
pub mod memory;
pub mod redis;

pub use memory::InMemoryNotifier;

/// Identifies an activity-write event for a single conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyEvent {
    pub tenant_id: String,
    pub conversation_id: String,
    pub new_watermark: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum NotifierError {
    #[error("subscribe failed: {0}")]
    Subscribe(String),
    #[error("backend disconnected: {0}")]
    Disconnected(String),
}

pub type EventStream = Pin<Box<dyn Stream<Item = NotifyEvent> + Send + 'static>>;

#[async_trait]
pub trait ActivityNotifier: Send + Sync + 'static {
    /// Fire-and-forget publish. Failures are logged but not propagated.
    async fn publish(&self, event: NotifyEvent);

    /// Subscribe to events for a specific (tenant, conversation_id). Drop the
    /// returned stream to unsubscribe.
    async fn subscribe(
        &self,
        tenant_id: &str,
        conversation_id: &str,
    ) -> Result<EventStream, NotifierError>;
}

/// Backend selector for `build_notifier`.
///
/// Deserialized from the `webchat.notifier` section of `greentic.yaml`.
/// Absent or unset → defaults to `Memory { capacity: 64 }`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum NotifierConfig {
    Memory {
        #[serde(default = "default_capacity")]
        capacity: usize,
    },
    Redis {
        /// Optional explicit URL. If `None`, resolved from the state-redis
        /// provider's `ConfigEnvelope` at boot time.
        #[serde(default)]
        url: Option<String>,
        /// Channel name override. Default: `greentic:webchat:notify`.
        #[serde(default)]
        channel: Option<String>,
        /// Local in-memory broadcast capacity (forwarded to the inner
        /// `InMemoryNotifier`).
        #[serde(default = "default_capacity")]
        capacity: usize,
    },
}

fn default_capacity() -> usize {
    64
}

impl Default for NotifierConfig {
    fn default() -> Self {
        NotifierConfig::Memory { capacity: 64 }
    }
}

pub async fn build_notifier(
    config: NotifierConfig,
) -> anyhow::Result<std::sync::Arc<dyn ActivityNotifier>> {
    match config {
        NotifierConfig::Memory { capacity } => {
            Ok(std::sync::Arc::new(InMemoryNotifier::new(capacity)))
        }
        NotifierConfig::Redis { .. } => {
            anyhow::bail!(
                "Redis notifier backend not yet implemented in this build (Phase C in progress)"
            )
        }
    }
}

#[cfg(test)]
mod build_tests {
    use super::*;

    #[tokio::test]
    async fn build_default_returns_memory_backend() {
        let notifier = build_notifier(NotifierConfig::default())
            .await
            .expect("build");
        let mut stream = notifier.subscribe("t", "c").await.unwrap();
        notifier
            .publish(NotifyEvent {
                tenant_id: "t".into(),
                conversation_id: "c".into(),
                new_watermark: 1,
            })
            .await;
        let received = futures_util::StreamExt::next(&mut stream).await.unwrap();
        assert_eq!(received.new_watermark, 1);
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn notifier_config_serde_default_yaml_empty() {
        // Empty YAML map should default to Memory { capacity: 64 }.
        let cfg: NotifierConfig = serde_yaml_bw::from_str("backend: memory").expect("parse");
        match cfg {
            NotifierConfig::Memory { capacity } => assert_eq!(capacity, 64),
            _ => panic!("expected Memory variant"),
        }
    }

    #[test]
    fn notifier_config_serde_redis_minimal() {
        let yaml = "backend: redis";
        let cfg: NotifierConfig = serde_yaml_bw::from_str(yaml).expect("parse");
        match cfg {
            NotifierConfig::Redis {
                url,
                channel,
                capacity,
            } => {
                assert!(url.is_none());
                assert!(channel.is_none());
                assert_eq!(capacity, 64);
            }
            _ => panic!("expected Redis variant"),
        }
    }

    #[test]
    fn notifier_config_serde_redis_full() {
        let yaml = "\
backend: redis
url: redis://localhost:6379
channel: greentic:webchat:notify
capacity: 128
";
        let cfg: NotifierConfig = serde_yaml_bw::from_str(yaml).expect("parse");
        match cfg {
            NotifierConfig::Redis {
                url,
                channel,
                capacity,
            } => {
                assert_eq!(url.as_deref(), Some("redis://localhost:6379"));
                assert_eq!(channel.as_deref(), Some("greentic:webchat:notify"));
                assert_eq!(capacity, 128);
            }
            _ => panic!("expected Redis variant"),
        }
    }
}
