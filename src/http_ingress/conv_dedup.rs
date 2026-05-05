//! Idempotency cache for `POST /v3/directline/conversations`.
//!
//! Direct Line clients sometimes invoke `createDirectLine` twice in quick
//! succession (race in a React effect guard, retries from connection-status
//! observers, etc.). Without dedup, each call mints a fresh conversation —
//! the operator runs the WASM `ingest-http` op (which fires its `autoStart`
//! envelope and persists state) twice, and the SPA ends up with two
//! independent DirectLine instances both rendering a welcome card.
//!
//! Bot Framework treats `POST /conversations` as create-or-resume, so a
//! short server-side dedupe keyed on the body's `user.id` is the correct
//! place to enforce that semantic without relying on client-side idempotency.
//!
//! The cache is in-memory per operator instance. If we move to a multi-node
//! ingress fleet (Phase C alongside the Redis notifier backplane), this
//! cache should be replaced with a shared store keyed on the same identity.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::ingress_types::IngressHttpResponse;

const DEFAULT_TTL_SECS: u64 = 30;
const MAX_ENTRIES: usize = 4096;

#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub struct DedupKey {
    pub tenant: String,
    pub team: String,
    pub user_id: String,
}

#[derive(Clone)]
struct CachedEntry {
    response: IngressHttpResponse,
    cached_at: Instant,
}

pub struct ConversationDedupCache {
    inner: Mutex<HashMap<DedupKey, CachedEntry>>,
    ttl: Duration,
}

impl ConversationDedupCache {
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(DEFAULT_TTL_SECS))
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    pub fn get(&self, key: &DedupKey) -> Option<IngressHttpResponse> {
        let mut guard = self.inner.lock().ok()?;
        let entry = guard.get(key)?;
        if entry.cached_at.elapsed() > self.ttl {
            guard.remove(key);
            return None;
        }
        Some(entry.response.clone())
    }

    pub fn insert(&self, key: DedupKey, response: IngressHttpResponse) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        let now = Instant::now();
        guard.retain(|_, entry| now.duration_since(entry.cached_at) <= self.ttl);
        if guard.len() >= MAX_ENTRIES {
            return;
        }
        guard.insert(
            key,
            CachedEntry {
                response,
                cached_at: now,
            },
        );
    }
}

impl Default for ConversationDedupCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the dedup user identity from a Direct Line `POST /conversations`
/// JSON body. The Greentic webchat bootstrap stamps `user.id` to a stable
/// per-browser guest id (`greentic_guest_id` localStorage), so this is a
/// reliable client identity for short-window dedup. Returns `None` when the
/// body lacks a usable id, in which case the caller should skip dedup.
pub fn extract_user_id(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let id = value.get("user")?.get("id")?.as_str()?.trim();
    if id.is_empty() {
        return None;
    }
    Some(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tenant: &str, user: &str) -> DedupKey {
        DedupKey {
            tenant: tenant.to_string(),
            team: "default".to_string(),
            user_id: user.to_string(),
        }
    }

    fn response(body: &str) -> IngressHttpResponse {
        IngressHttpResponse {
            status: 201,
            headers: vec![],
            body: Some(body.as_bytes().to_vec()),
        }
    }

    #[test]
    fn miss_returns_none() {
        let cache = ConversationDedupCache::new();
        assert!(cache.get(&key("t", "u")).is_none());
    }

    #[test]
    fn hit_returns_cached_body() {
        let cache = ConversationDedupCache::new();
        cache.insert(key("t", "u"), response("{\"conversationId\":\"abc\"}"));
        let got = cache.get(&key("t", "u")).expect("hit");
        assert_eq!(
            got.body.as_deref(),
            Some(b"{\"conversationId\":\"abc\"}".as_ref())
        );
    }

    #[test]
    fn different_user_does_not_share_entry() {
        let cache = ConversationDedupCache::new();
        cache.insert(key("t", "u1"), response("{\"id\":1}"));
        assert!(cache.get(&key("t", "u2")).is_none());
    }

    #[test]
    fn expired_entry_is_evicted() {
        let cache = ConversationDedupCache::with_ttl(Duration::from_millis(10));
        cache.insert(key("t", "u"), response("{}"));
        std::thread::sleep(Duration::from_millis(25));
        assert!(cache.get(&key("t", "u")).is_none());
    }

    #[test]
    fn extract_user_id_from_bootstrap_body() {
        let body = br#"{"user":{"id":"guest-1234"}}"#;
        assert_eq!(extract_user_id(body), Some("guest-1234".to_string()));
    }

    #[test]
    fn extract_user_id_missing_returns_none() {
        assert!(extract_user_id(b"{}").is_none());
        assert!(extract_user_id(br#"{"user":{}}"#).is_none());
        assert!(extract_user_id(br#"{"user":{"id":""}}"#).is_none());
        assert!(extract_user_id(b"not json").is_none());
    }
}
