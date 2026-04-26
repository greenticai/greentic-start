//! Activity push notifier — informs WS sessions when a conversation has new activities.
//!
//! Two backends are supported via the `ActivityNotifier` trait. This module ships the
//! trait, types, and the in-memory backend. NATS lives in a follow-up plan.

use async_trait::async_trait;
use futures_util::Stream;
use std::pin::Pin;

// NOTE: `memory` module is added in Task 2. Re-exports below are commented out
// until then so this module compiles in isolation.
// pub mod memory;
// pub use memory::InMemoryNotifier;

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
#[derive(Debug, Clone)]
pub enum NotifierConfig {
    Memory { capacity: usize },
}

impl Default for NotifierConfig {
    fn default() -> Self {
        NotifierConfig::Memory { capacity: 64 }
    }
}

pub fn build_notifier(_config: NotifierConfig) -> std::sync::Arc<dyn ActivityNotifier> {
    // Task 2 will switch on `_config` and construct the in-memory backend. Until
    // then this is unreachable — the public API is exposed for downstream tasks
    // (HttpIngressState wiring) to depend on.
    unimplemented!("InMemoryNotifier lands in Task 2")
}
