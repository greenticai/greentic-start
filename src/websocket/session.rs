// These types are consumed by upcoming upgrade/pump modules in later tasks (Task 11+).
#![allow(dead_code)]

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Limits surfaced from `[webchat.ws]` config.
#[derive(Debug, Clone)]
pub struct WsLimits {
    pub idle_timeout_secs: u64,
    pub max_replay_size: usize,
    pub max_concurrent_per_tenant: usize,
    pub max_per_conversation: usize,
    pub max_frame_size_bytes: usize,
}

impl Default for WsLimits {
    fn default() -> Self {
        Self {
            idle_timeout_secs: 300,
            max_replay_size: 1000,
            max_concurrent_per_tenant: 1000,
            max_per_conversation: 5,
            max_frame_size_bytes: 1_048_576,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("tenant {0} reached max concurrent connections")]
    TenantLimit(String),
    #[error("conversation {0} reached max concurrent connections")]
    ConversationLimit(String),
}

#[derive(Default)]
pub struct SessionManager {
    per_tenant: DashMap<String, Arc<AtomicUsize>>,
    per_conv: DashMap<(String, String), Arc<AtomicUsize>>,
    limits: WsLimits,
}

impl SessionManager {
    pub fn new(limits: WsLimits) -> Self {
        Self {
            per_tenant: DashMap::new(),
            per_conv: DashMap::new(),
            limits,
        }
    }

    pub fn limits(&self) -> &WsLimits {
        &self.limits
    }

    /// Acquires a session slot. Returns a guard that releases on drop.
    pub fn acquire(
        &self,
        tenant_id: &str,
        conversation_id: &str,
    ) -> Result<SessionGuard, SessionError> {
        let tenant_counter = self
            .per_tenant
            .entry(tenant_id.to_string())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();
        let conv_key = (tenant_id.to_string(), conversation_id.to_string());
        let conv_counter = self
            .per_conv
            .entry(conv_key)
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();

        if tenant_counter.load(Ordering::SeqCst) >= self.limits.max_concurrent_per_tenant {
            return Err(SessionError::TenantLimit(tenant_id.to_string()));
        }
        if conv_counter.load(Ordering::SeqCst) >= self.limits.max_per_conversation {
            return Err(SessionError::ConversationLimit(conversation_id.to_string()));
        }

        tenant_counter.fetch_add(1, Ordering::SeqCst);
        conv_counter.fetch_add(1, Ordering::SeqCst);
        Ok(SessionGuard {
            tenant_counter,
            conv_counter,
        })
    }
}

#[derive(Debug)]
pub struct SessionGuard {
    tenant_counter: Arc<AtomicUsize>,
    conv_counter: Arc<AtomicUsize>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.tenant_counter.fetch_sub(1, Ordering::SeqCst);
        self.conv_counter.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(per_tenant: usize, per_conv: usize) -> WsLimits {
        WsLimits {
            max_concurrent_per_tenant: per_tenant,
            max_per_conversation: per_conv,
            ..Default::default()
        }
    }

    #[test]
    fn acquire_increments_and_drop_decrements() {
        let mgr = SessionManager::new(limits(10, 5));
        let guard = mgr.acquire("t1", "c1").unwrap();
        let counter = mgr.per_tenant.get("t1").unwrap().clone();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        drop(guard);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn tenant_limit_enforced() {
        let mgr = SessionManager::new(limits(1, 5));
        let _g1 = mgr.acquire("t1", "c1").unwrap();
        let err = mgr.acquire("t1", "c2").unwrap_err();
        assert!(matches!(err, SessionError::TenantLimit(_)));
    }

    #[test]
    fn conversation_limit_enforced() {
        let mgr = SessionManager::new(limits(10, 1));
        let _g1 = mgr.acquire("t1", "c1").unwrap();
        let err = mgr.acquire("t1", "c1").unwrap_err();
        assert!(matches!(err, SessionError::ConversationLimit(_)));
    }
}
