//! Redis pub/sub backplane for the WebChat WS notifier.
//!
//! See docs/superpowers/specs/2026-05-01-webchat-ws-redis-backplane-design.md.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

use crate::notifier::{ActivityNotifier, NotifyEvent};

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
