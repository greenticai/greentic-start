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

#[cfg(test)]
mod tests {
    use super::*;

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
}
