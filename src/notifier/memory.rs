use crate::notifier::{ActivityNotifier, EventStream, NotifierError, NotifyEvent};
use async_trait::async_trait;
use dashmap::DashMap;
use futures_util::StreamExt;
use std::sync::Arc;
use tokio::sync::broadcast;

pub struct InMemoryNotifier {
    channels: Arc<DashMap<(String, String), broadcast::Sender<NotifyEvent>>>,
    capacity: usize,
}

impl InMemoryNotifier {
    pub fn new(capacity: usize) -> Self {
        Self {
            channels: Arc::new(DashMap::new()),
            capacity,
        }
    }
}

#[async_trait]
impl ActivityNotifier for InMemoryNotifier {
    async fn publish(&self, event: NotifyEvent) {
        let key = (event.tenant_id.clone(), event.conversation_id.clone());
        if let Some(sender) = self.channels.get(&key) {
            // send returns Err(SendError) if no receivers — drop silently.
            let _ = sender.send(event);
        }
    }

    async fn subscribe(
        &self,
        tenant_id: &str,
        conversation_id: &str,
    ) -> Result<EventStream, NotifierError> {
        let key = (tenant_id.to_string(), conversation_id.to_string());
        let sender = self
            .channels
            .entry(key)
            .or_insert_with(|| broadcast::channel(self.capacity).0)
            .clone();
        let receiver = sender.subscribe();
        let stream = tokio_stream::wrappers::BroadcastStream::new(receiver)
            .filter_map(|res| async move { res.ok() });
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(conv: &str, wm: u64) -> NotifyEvent {
        NotifyEvent {
            tenant_id: "tenant1".into(),
            conversation_id: conv.into(),
            new_watermark: wm,
        }
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_drops_silently() {
        let notifier = InMemoryNotifier::new(8);
        notifier.publish(event("conv1", 1)).await;
        // Should not panic or error.
    }

    #[tokio::test]
    async fn subscribe_then_publish_delivers_event() {
        let notifier = InMemoryNotifier::new(8);
        let mut stream = notifier.subscribe("tenant1", "conv1").await.unwrap();

        notifier.publish(event("conv1", 5)).await;

        let received = stream.next().await.expect("expected event");
        assert_eq!(received.new_watermark, 5);
    }

    #[tokio::test]
    async fn multi_subscribers_same_conv_all_receive() {
        let notifier = InMemoryNotifier::new(8);
        let mut s1 = notifier.subscribe("tenant1", "conv1").await.unwrap();
        let mut s2 = notifier.subscribe("tenant1", "conv1").await.unwrap();

        notifier.publish(event("conv1", 7)).await;

        let r1 = s1.next().await.expect("s1 event");
        let r2 = s2.next().await.expect("s2 event");
        assert_eq!(r1.new_watermark, 7);
        assert_eq!(r2.new_watermark, 7);
    }

    #[tokio::test]
    async fn different_conversations_isolated() {
        let notifier = InMemoryNotifier::new(8);
        let mut s_a = notifier.subscribe("tenant1", "convA").await.unwrap();

        notifier.publish(event("convB", 1)).await;

        // Use a short timeout; convA subscriber must not see convB's event.
        let result = tokio::time::timeout(std::time::Duration::from_millis(50), s_a.next()).await;
        assert!(result.is_err(), "should have timed out (no event)");
    }
}
