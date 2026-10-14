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
//! The key also carries a hash of the presented bearer: the cached response
//! holds a token bound to the new conversation, and `user.id` is chosen by
//! the client, so without it a second caller reusing someone's guest id
//! within the window received that person's conversation. The racing
//! double-create the cache exists for sends the same bearer twice.
//!
//! The cache is in-memory per operator instance. If we move to a multi-node
//! ingress fleet (Phase C alongside the Redis notifier backplane), this
//! cache should be replaced with a shared store keyed on the same identity.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use greentic_deploy_spec::DeploymentId;
use sha2::{Digest, Sha256};

use crate::ingress_types::IngressHttpResponse;

const DEFAULT_TTL_SECS: u64 = 30;
const MAX_ENTRIES: usize = 4096;

#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub struct DedupKey {
    pub deployment_id: DeploymentId,
    pub tenant: String,
    pub team: String,
    pub user_id: String,
    /// Flow discriminator for webchat multi-flow bundles. When two flow URLs
    /// target the same deployment within the TTL, they must mint distinct
    /// conversations rather than returning the cached response from the first.
    pub flow_hint: Option<String>,
    /// Domain-separated SHA-256 ([`bearer_fingerprint`]) of the bearer the
    /// CREATING request presented. The cached
    /// response carries a token bound to the new conversation, so it may go
    /// back only to the caller that created it; `user.id` alone is chosen by
    /// the client and would hand one caller's conversation to another.
    pub bearer_sha256: [u8; 32],
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

/// Domain prefix of [`bearer_fingerprint`], so the value is specific to this
/// cache and never equals a SHA-256 another component computes over the same
/// token. Changing it only empties the 30 s cache.
const BEARER_FINGERPRINT_DOMAIN: &[u8] = b"greentic-start/conv-dedup/v1\0";

/// Domain-separated SHA-256 of the raw bearer (after `Bearer `); `None`
/// without one, which
/// disables dedup for that request rather than sharing a bucket.
/// Parsed exactly as the session preflight parses it, so the two never
/// disagree about which token a request presented.
pub fn bearer_fingerprint(headers: &[(String, String)]) -> Option<[u8; 32]> {
    let token = crate::directline_session::bearer(headers)?;
    let mut hasher = Sha256::new();
    hasher.update(BEARER_FINGERPRINT_DOMAIN);
    hasher.update(token.as_bytes());
    Some(hasher.finalize().into())
}

/// The dedup key for a `POST /conversations`, or `None` when the request
/// carries no usable `user.id` or no bearer. `caller_headers` must be the
/// request's ORIGINAL headers, never the ones after
/// `directline_session::apply_authorization_rewrite`: a re-mint of an expired
/// bootstrap token would otherwise give one caller's two racing requests two
/// different keys.
pub fn create_key(
    deployment_id: DeploymentId,
    tenant: &str,
    team: &str,
    flow_hint: Option<String>,
    body: &[u8],
    caller_headers: &[(String, String)],
) -> Option<DedupKey> {
    let user_id = extract_user_id(body)?;
    let bearer_sha256 = bearer_fingerprint(caller_headers)?;
    Some(DedupKey {
        deployment_id,
        tenant: tenant.to_string(),
        team: team.to_string(),
        user_id,
        flow_hint,
        bearer_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed deployment id so the test helper produces equal keys.
    fn fixed_dep() -> DeploymentId {
        DeploymentId(ulid::Ulid::from_bytes([1; 16]))
    }

    fn key(tenant: &str, user: &str) -> DedupKey {
        DedupKey {
            deployment_id: fixed_dep(),
            tenant: tenant.to_string(),
            team: "default".to_string(),
            user_id: user.to_string(),
            flow_hint: None,
            bearer_sha256: [7; 32],
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
    fn different_deployment_does_not_share_entry() {
        let cache = ConversationDedupCache::new();
        cache.insert(key("t", "u"), response("{\"id\":1}"));
        let other = DedupKey {
            deployment_id: DeploymentId::new(),
            tenant: "t".to_string(),
            team: "default".to_string(),
            user_id: "u".to_string(),
            flow_hint: None,
            bearer_sha256: [7; 32],
        };
        assert!(cache.get(&other).is_none());
    }

    #[test]
    fn different_flow_hint_does_not_share_entry() {
        let cache = ConversationDedupCache::new();
        let mut k1 = key("t", "u");
        k1.flow_hint = Some("onboarding".to_string());
        cache.insert(k1.clone(), response("{\"id\":1}"));

        let mut k2 = key("t", "u");
        k2.flow_hint = Some("offboarding".to_string());
        assert!(
            cache.get(&k2).is_none(),
            "different flow must not share entry"
        );

        // Same flow should still hit.
        assert!(cache.get(&k1).is_some());
    }

    #[test]
    fn no_flow_hint_does_not_match_flow_hint() {
        let cache = ConversationDedupCache::new();
        let k_none = key("t", "u"); // flow_hint = None
        cache.insert(k_none.clone(), response("{\"id\":1}"));

        let mut k_some = key("t", "u");
        k_some.flow_hint = Some("onboarding".to_string());
        assert!(
            cache.get(&k_some).is_none(),
            "a flow-targeted request must not reuse a non-targeted entry"
        );
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

    fn bearer(token: &str) -> Vec<(String, String)> {
        vec![("Authorization".to_string(), format!("Bearer {token}"))]
    }

    fn create(headers: &[(String, String)]) -> Option<DedupKey> {
        create_key(
            fixed_dep(),
            "t",
            "default",
            None,
            br#"{"user":{"id":"guest-1"}}"#,
            headers,
        )
    }

    #[test]
    fn same_user_id_different_bearer_misses() {
        let cache = ConversationDedupCache::new();
        let alice = create(&bearer("token-of-alice")).expect("key");
        cache.insert(alice, response("{\"conversationId\":\"alice-conv\"}"));
        let mallory = create(&bearer("token-of-mallory")).expect("key");
        assert!(
            cache.get(&mallory).is_none(),
            "another bearer must never receive the cached conversation"
        );
    }

    #[test]
    fn same_bearer_hits() {
        let cache = ConversationDedupCache::new();
        cache.insert(
            create(&bearer("token-1")).expect("key"),
            response("{\"conversationId\":\"c\"}"),
        );
        assert!(
            cache
                .get(&create(&bearer("token-1")).expect("key"))
                .is_some()
        );
        // The scheme is case-insensitive and surrounding space is ignored, like
        // the session preflight's own bearer parse.
        let same = vec![("authorization".to_string(), "bearer  token-1 ".to_string())];
        assert!(cache.get(&create(&same).expect("key")).is_some());
    }

    #[test]
    fn no_bearer_no_key() {
        assert!(bearer_fingerprint(&[]).is_none());
        assert!(create(&[]).is_none());
        let basic = vec![("Authorization".to_string(), "Basic abc".to_string())];
        assert!(create(&basic).is_none());
        let empty = vec![("Authorization".to_string(), "Bearer ".to_string())];
        assert!(create(&empty).is_none());
    }

    #[test]
    fn the_fingerprint_is_a_domain_separated_hash_of_the_bearer() {
        let fp = bearer_fingerprint(&bearer("secret-token")).expect("fingerprint");
        let mut domain = Sha256::new();
        domain.update(b"greentic-start/conv-dedup/v1\0");
        domain.update(b"secret-token");
        assert_eq!(fp, <[u8; 32]>::from(domain.finalize()));
        // Not the bare SHA-256 of the token: a value computed for this cache
        // must not equal one any other component computes over the same token.
        assert_ne!(fp, <[u8; 32]>::from(Sha256::digest(b"secret-token")));
    }
}
