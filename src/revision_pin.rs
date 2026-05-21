//! Revision pin store (B6) — `plans/next-gen-deployment.md` §1329.
//!
//! Backs the [`RevisionDispatcher`](crate::revision_dispatcher) session pin
//! map. B1 inlined the in-memory map; B6 extracts a trait so a horizontally
//! scaled router (Phase D K8s slice) can share pins across pods via Redis.
//!
//! Two implementations:
//!
//! - [`InMemoryPinStore`] — single-process map with the same bound + eviction
//!   discipline B1 shipped (`MAX_PINS = 16_384`, soonest-expiry eviction,
//!   generation-aware drop on lookup).
//! - [`RedisPinStore`] — one key per pin under `gt:rev_pin:{env}:{deployment_id}:{tenant}:{hint}`
//!   with `SET NX EX` for race-safe create + Redis-native TTL. Matches the
//!   plan's literal key spelling and works on any Redis ≥ 2.6 (no `HEXPIRE`
//!   dependency).
//!
//! Selection between backends is a caller concern. Default
//! [`RevisionDispatcher::new`](crate::revision_dispatcher::RevisionDispatcher::new)
//! constructs an [`InMemoryPinStore`]; production deployments inject a
//! [`RedisPinStore`] via
//! [`RevisionDispatcher::with_pin_store`](crate::revision_dispatcher::RevisionDispatcher::with_pin_store).

// `RedisPinStore` is scaffolded ahead of a Phase D producer; today only the
// in-memory path has a live caller. Same shape as `revision_dispatcher`'s
// pre-B3 `#![allow(dead_code)]`.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use greentic_deploy_spec::{DeploymentId, RevisionId};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use ulid::Ulid;

/// Hard cap on the [`InMemoryPinStore`] map. Mirrors B1's `MAX_PINS` so the
/// single-process fallback keeps the same shape as the pre-extraction map.
pub const MAX_PINS: usize = 16_384;

const REDIS_KEY_PREFIX: &str = "gt:rev_pin";

/// Routing-stickiness storage for `(env, deployment_id, tenant, session_hint)`.
///
/// All four methods are infallible-by-design at the trait level for the
/// happy path: the in-memory impl never errors, and the Redis impl downgrades
/// transient connection failures to soft misses (logged via `tracing::warn!`)
/// rather than bubbling them up to the dispatch path. A hard miss is always a
/// safe answer — selection falls through to the weighted-random branch and
/// re-pins, exactly as it does after a generation bump.
#[async_trait::async_trait]
pub trait RevisionPinStore: Send + Sync {
    /// Insert a pin **only if** none exists for `(env, deployment_id, tenant, hint)`,
    /// returning the persisted entry on either branch (existing or newly inserted).
    /// Implementations MUST be race-safe — two concurrent callers with the same
    /// key see exactly one inserted value.
    #[allow(clippy::too_many_arguments)]
    async fn try_pin(
        &self,
        env_id: &str,
        deployment_id: DeploymentId,
        tenant: &str,
        hint: &str,
        revision_id: RevisionId,
        generation: u64,
        ttl: Duration,
    ) -> PinOutcome;

    /// Lookup an existing pin. Returns `None` when:
    ///
    /// - no pin exists, or
    /// - the pin's generation does not match `current_generation` (stale —
    ///   implementations MUST also evict it, matching B1's drop-on-mismatch
    ///   behavior), or
    /// - the pin has expired.
    async fn lookup(
        &self,
        env_id: &str,
        deployment_id: DeploymentId,
        tenant: &str,
        hint: &str,
        current_generation: u64,
    ) -> Option<RevisionId>;
}

/// Outcome of [`RevisionPinStore::try_pin`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinOutcome {
    /// Caller's `(revision_id, generation)` was persisted.
    Inserted { revision_id: RevisionId },
    /// A pin already existed; the value returned is what's now live.
    Existing { revision_id: RevisionId },
}

impl PinOutcome {
    pub fn revision_id(&self) -> RevisionId {
        match self {
            Self::Inserted { revision_id } => *revision_id,
            Self::Existing { revision_id } => *revision_id,
        }
    }
}

// ── In-memory backend ───────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct InMemoryEntry {
    revision_id: RevisionId,
    generation: u64,
    expires_at: SystemTime,
}

/// Single-process pin store. Matches B1's bounded-map discipline:
///
/// - hard cap at [`MAX_PINS`];
/// - at-cap inserts first sweep expired entries, then evict the soonest-to-expire;
/// - generation-mismatched entries are dropped on lookup.
#[derive(Debug, Default)]
pub struct InMemoryPinStore {
    inner: Mutex<HashMap<(DeploymentId, String, String, String), InMemoryEntry>>,
}

impl InMemoryPinStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test helper: number of live entries (post-eviction).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().expect("pin mutex poisoned").len()
    }
}

#[async_trait::async_trait]
impl RevisionPinStore for InMemoryPinStore {
    async fn try_pin(
        &self,
        env_id: &str,
        deployment_id: DeploymentId,
        tenant: &str,
        hint: &str,
        revision_id: RevisionId,
        generation: u64,
        ttl: Duration,
    ) -> PinOutcome {
        let key = (
            deployment_id,
            env_id.to_string(),
            tenant.to_string(),
            hint.to_string(),
        );
        let now = SystemTime::now();
        let mut guard = self.inner.lock().expect("pin mutex poisoned");

        // Drop stale entry first so it doesn't block insert + so we honor the
        // generation-mismatch eviction contract.
        if let Some(existing) = guard.get(&key)
            && existing.expires_at > now
            && existing.generation == generation
        {
            return PinOutcome::Existing {
                revision_id: existing.revision_id,
            };
        }
        guard.remove(&key);

        if guard.len() >= MAX_PINS {
            guard.retain(|_, e| e.expires_at > now);
            if guard.len() >= MAX_PINS
                && let Some(victim) = guard
                    .iter()
                    .min_by_key(|(_, e)| e.expires_at)
                    .map(|(k, _)| k.clone())
            {
                guard.remove(&victim);
            }
        }
        guard.insert(
            key,
            InMemoryEntry {
                revision_id,
                generation,
                expires_at: now + ttl,
            },
        );
        PinOutcome::Inserted { revision_id }
    }

    async fn lookup(
        &self,
        env_id: &str,
        deployment_id: DeploymentId,
        tenant: &str,
        hint: &str,
        current_generation: u64,
    ) -> Option<RevisionId> {
        let key = (
            deployment_id,
            env_id.to_string(),
            tenant.to_string(),
            hint.to_string(),
        );
        let now = SystemTime::now();
        let mut guard = self.inner.lock().expect("pin mutex poisoned");
        match guard.get(&key) {
            Some(entry) if entry.expires_at > now && entry.generation == current_generation => {
                Some(entry.revision_id)
            }
            Some(_) => {
                guard.remove(&key);
                None
            }
            None => None,
        }
    }
}

// ── Redis backend ───────────────────────────────────────────────────────

/// Shared `Arc<ConnectionManager>` storage for [`RedisPinStore`]. The manager
/// handles reconnect + pipelining internally so we don't need a Mutex.
pub struct RedisPinStore {
    conn: Arc<tokio::sync::Mutex<ConnectionManager>>,
}

impl std::fmt::Debug for RedisPinStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisPinStore").finish_non_exhaustive()
    }
}

impl RedisPinStore {
    /// Open a Redis client from a URL (e.g. `redis://127.0.0.1:6379/0`) and
    /// build a [`ConnectionManager`] that handles reconnection transparently.
    pub async fn from_url(url: impl AsRef<str>) -> Result<Self> {
        let client = redis::Client::open(url.as_ref())
            .with_context(|| format!("invalid redis url `{}`", url.as_ref()))?;
        let manager = ConnectionManager::new(client)
            .await
            .context("redis ConnectionManager init failed")?;
        Ok(Self {
            conn: Arc::new(tokio::sync::Mutex::new(manager)),
        })
    }
}

/// Encoded pin value: `{revision_id_ulid}|{generation}|{expires_at_unix_secs}`.
///
/// Plaintext ASCII so `redis-cli GET` is debuggable. The expires-at is
/// redundant given Redis-native TTL, but we still encode it so a stale read
/// during clock skew or replication lag returns a typed-and-checked answer
/// rather than a silently-expired pin.
fn encode_value(revision_id: RevisionId, generation: u64, expires_at: SystemTime) -> String {
    let secs = expires_at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{revision_id}|{generation}|{secs}")
}

fn decode_value(raw: &str) -> Option<(RevisionId, u64, u64)> {
    let mut parts = raw.splitn(3, '|');
    let rid_str = parts.next()?;
    let gen_str = parts.next()?;
    let exp_str = parts.next()?;
    let rid = Ulid::from_string(rid_str).ok()?;
    let generation = gen_str.parse::<u64>().ok()?;
    let expires_at = exp_str.parse::<u64>().ok()?;
    Some((RevisionId(rid), generation, expires_at))
}

fn redis_key(env_id: &str, deployment_id: DeploymentId, tenant: &str, hint: &str) -> String {
    format!("{REDIS_KEY_PREFIX}:{env_id}:{deployment_id}:{tenant}:{hint}")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[async_trait::async_trait]
impl RevisionPinStore for RedisPinStore {
    async fn try_pin(
        &self,
        env_id: &str,
        deployment_id: DeploymentId,
        tenant: &str,
        hint: &str,
        revision_id: RevisionId,
        generation: u64,
        ttl: Duration,
    ) -> PinOutcome {
        let key = redis_key(env_id, deployment_id, tenant, hint);
        let ttl_secs = ttl.as_secs().max(1);
        let value = encode_value(revision_id, generation, SystemTime::now() + ttl);

        // SET NX EX is the race-safe single-step `try_pin`. On success we
        // own the pin; on collision someone else won, so we fetch the
        // current value and return Existing. Net cost: 1 round-trip on
        // success, 2 on collision (collision = rare, by construction).
        match try_set_nx(&self.conn, &key, &value, ttl_secs).await {
            Ok(true) => PinOutcome::Inserted { revision_id },
            Ok(false) => match get_and_decode(&self.conn, &key, generation).await {
                Some(existing) => PinOutcome::Existing {
                    revision_id: existing,
                },
                None => PinOutcome::Inserted { revision_id },
            },
            Err(err) => {
                // Soft-fail: report Inserted so the dispatcher keeps routing.
                // The next request just re-runs the weighted-random branch
                // (identical behavior to a generation bump), avoiding hard
                // 5xx on transient Redis blips.
                tracing::warn!(
                    target: "greentic_start::revision_pin",
                    error = %err,
                    key = %key,
                    "redis SET NX failed; soft-falling-through to no-pin path",
                );
                PinOutcome::Inserted { revision_id }
            }
        }
    }

    async fn lookup(
        &self,
        env_id: &str,
        deployment_id: DeploymentId,
        tenant: &str,
        hint: &str,
        current_generation: u64,
    ) -> Option<RevisionId> {
        let key = redis_key(env_id, deployment_id, tenant, hint);
        let revision = get_and_decode(&self.conn, &key, current_generation).await?;
        Some(revision)
    }
}

async fn try_set_nx(
    conn: &Arc<tokio::sync::Mutex<ConnectionManager>>,
    key: &str,
    value: &str,
    ttl_secs: u64,
) -> Result<bool> {
    let mut guard = conn.lock().await;
    let opts = redis::SetOptions::default()
        .conditional_set(redis::ExistenceCheck::NX)
        .with_expiration(redis::SetExpiry::EX(ttl_secs));
    let resp: redis::Value = guard
        .set_options(key, value, opts)
        .await
        .context("redis SET NX EX failed")?;
    match resp {
        redis::Value::Okay => Ok(true),
        redis::Value::Nil => Ok(false),
        other => Err(anyhow!("unexpected redis SET response: {:?}", other)),
    }
}

async fn get_and_decode(
    conn: &Arc<tokio::sync::Mutex<ConnectionManager>>,
    key: &str,
    expected_generation: u64,
) -> Option<RevisionId> {
    let raw: Option<String> = {
        let mut guard = conn.lock().await;
        match guard.get(key).await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    target: "greentic_start::revision_pin",
                    error = %err,
                    key = %key,
                    "redis GET failed; treating as cache miss",
                );
                return None;
            }
        }
    };
    let raw = raw?;
    let (revision_id, generation, expires_at) = decode_value(&raw)?;
    if generation != expected_generation || expires_at <= now_secs() {
        // Stale (generation bumped or clock-skew-expired): delete and miss.
        let mut guard = conn.lock().await;
        let _: redis::RedisResult<()> = guard.del(key).await;
        return None;
    }
    Some(revision_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn dep() -> DeploymentId {
        DeploymentId::new()
    }
    fn rev() -> RevisionId {
        RevisionId::new()
    }

    #[tokio::test]
    async fn in_memory_inserts_then_returns_existing() {
        let store = InMemoryPinStore::new();
        let dep_id = dep();
        let r = rev();
        let out1 = store
            .try_pin("local", dep_id, "t", "h", r, 1, Duration::from_secs(60))
            .await;
        assert_eq!(out1, PinOutcome::Inserted { revision_id: r });
        let out2 = store
            .try_pin("local", dep_id, "t", "h", rev(), 1, Duration::from_secs(60))
            .await;
        // Second call observes the existing pin — returns its revision_id,
        // not the caller's.
        assert_eq!(out2, PinOutcome::Existing { revision_id: r });
    }

    #[tokio::test]
    async fn in_memory_lookup_returns_pinned_until_generation_bumps() {
        let store = InMemoryPinStore::new();
        let dep_id = dep();
        let r = rev();
        store
            .try_pin("local", dep_id, "t", "h", r, 1, Duration::from_secs(60))
            .await;
        assert_eq!(store.lookup("local", dep_id, "t", "h", 1).await, Some(r));
        // Generation bump invalidates the pin AND evicts it.
        assert_eq!(store.lookup("local", dep_id, "t", "h", 2).await, None);
        // Eviction confirmed: same-generation lookup also misses.
        assert_eq!(store.lookup("local", dep_id, "t", "h", 1).await, None);
    }

    #[tokio::test]
    async fn in_memory_lookup_drops_expired_entry() {
        let store = InMemoryPinStore::new();
        let dep_id = dep();
        let r = rev();
        store
            .try_pin("local", dep_id, "t", "h", r, 1, Duration::from_millis(10))
            .await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(store.lookup("local", dep_id, "t", "h", 1).await, None);
    }

    #[tokio::test]
    async fn in_memory_replaces_stale_generation_entry_on_try_pin() {
        let store = InMemoryPinStore::new();
        let dep_id = dep();
        let r1 = rev();
        store
            .try_pin("local", dep_id, "t", "h", r1, 1, Duration::from_secs(60))
            .await;
        let r2 = rev();
        // Same key, new generation → stale entry MUST be replaced (it would
        // never be lookup-able anyway, but the slot should be reused).
        let out = store
            .try_pin("local", dep_id, "t", "h", r2, 2, Duration::from_secs(60))
            .await;
        assert_eq!(out, PinOutcome::Inserted { revision_id: r2 });
        assert_eq!(store.lookup("local", dep_id, "t", "h", 2).await, Some(r2));
    }

    #[tokio::test]
    async fn in_memory_bounded_under_rotating_hints() {
        let store = InMemoryPinStore::new();
        let dep_id = dep();
        for i in 0..(MAX_PINS * 2) {
            let hint = format!("sess-{i}");
            store
                .try_pin(
                    "local",
                    dep_id,
                    "t",
                    &hint,
                    rev(),
                    1,
                    Duration::from_secs(60),
                )
                .await;
        }
        assert!(store.len() <= MAX_PINS);
    }

    #[tokio::test]
    async fn in_memory_distinct_keys_isolated() {
        let store = InMemoryPinStore::new();
        let dep_a = dep();
        let dep_b = dep();
        let r_a = rev();
        let r_b = rev();
        // Same env+tenant+hint, different deployments.
        store
            .try_pin("local", dep_a, "t", "h", r_a, 1, Duration::from_secs(60))
            .await;
        store
            .try_pin("local", dep_b, "t", "h", r_b, 1, Duration::from_secs(60))
            .await;
        assert_eq!(store.lookup("local", dep_a, "t", "h", 1).await, Some(r_a));
        assert_eq!(store.lookup("local", dep_b, "t", "h", 1).await, Some(r_b));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let r = RevisionId(Ulid::new());
        let exp = SystemTime::now() + Duration::from_secs(60);
        let encoded = encode_value(r, 7, exp);
        let (decoded_r, decoded_g, decoded_exp) = decode_value(&encoded).unwrap();
        assert_eq!(decoded_r, r);
        assert_eq!(decoded_g, 7);
        // Lossy in sub-second precision, but within 1s of caller's clock.
        let exp_secs = exp.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert!(decoded_exp.abs_diff(exp_secs) <= 1);
    }

    #[test]
    fn decode_rejects_malformed() {
        assert!(decode_value("").is_none());
        assert!(decode_value("not-a-ulid|1|2").is_none());
        assert!(decode_value(&format!("{}|notanum|2", Ulid::new())).is_none());
        assert!(decode_value(&format!("{}|1|notanum", Ulid::new())).is_none());
        // Missing field.
        assert!(decode_value(&format!("{}|1", Ulid::new())).is_none());
    }

    #[test]
    fn redis_key_matches_plan_format() {
        let id = DeploymentId(Ulid::from_string("01F8MECHZX3TBDSZ7XR8KZ9V8K").unwrap());
        let key = redis_key("local", id, "tenant-a", "session-x");
        assert_eq!(
            key,
            "gt:rev_pin:local:01F8MECHZX3TBDSZ7XR8KZ9V8K:tenant-a:session-x"
        );
    }

    // ── Redis integration tests ───────────────────────────────────────
    //
    // Gated by `GREENTIC_TEST_REDIS_URL` (mirrors `tests/notifier_redis.rs`).
    // Run locally:
    //   docker run --rm -p 6379:6379 redis
    //   GREENTIC_TEST_REDIS_URL=redis://127.0.0.1:6379 \
    //     cargo test -p greentic-start revision_pin -- --nocapture

    fn redis_url_or_skip() -> Option<String> {
        match std::env::var("GREENTIC_TEST_REDIS_URL") {
            Ok(url) if !url.is_empty() => Some(url),
            _ => {
                eprintln!("skipping: GREENTIC_TEST_REDIS_URL not set");
                None
            }
        }
    }

    /// Unique hint per test so concurrent test runs don't clobber each other.
    fn unique_hint(label: &str) -> String {
        format!("test-{label}-{}", Ulid::new())
    }

    #[tokio::test]
    async fn redis_inserts_then_returns_existing() {
        let Some(url) = redis_url_or_skip() else {
            return;
        };
        let store = RedisPinStore::from_url(&url).await.expect("redis open");
        let dep_id = dep();
        let hint = unique_hint("insert");
        let r = rev();

        let out1 = store
            .try_pin("local", dep_id, "t", &hint, r, 1, Duration::from_secs(60))
            .await;
        assert_eq!(out1, PinOutcome::Inserted { revision_id: r });

        let out2 = store
            .try_pin(
                "local",
                dep_id,
                "t",
                &hint,
                rev(),
                1,
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(out2, PinOutcome::Existing { revision_id: r });
    }

    #[tokio::test]
    async fn redis_lookup_drops_stale_generation() {
        let Some(url) = redis_url_or_skip() else {
            return;
        };
        let store = RedisPinStore::from_url(&url).await.expect("redis open");
        let dep_id = dep();
        let hint = unique_hint("staleness");
        let r = rev();

        store
            .try_pin("local", dep_id, "t", &hint, r, 1, Duration::from_secs(60))
            .await;
        assert_eq!(store.lookup("local", dep_id, "t", &hint, 1).await, Some(r));
        // Generation bump → eviction.
        assert_eq!(store.lookup("local", dep_id, "t", &hint, 2).await, None);
        // After eviction, same-generation lookup also misses.
        assert_eq!(store.lookup("local", dep_id, "t", &hint, 1).await, None);
    }

    #[tokio::test]
    async fn redis_ttl_expires() {
        let Some(url) = redis_url_or_skip() else {
            return;
        };
        let store = RedisPinStore::from_url(&url).await.expect("redis open");
        let dep_id = dep();
        let hint = unique_hint("ttl");
        let r = rev();
        // Redis EXpire is whole-second granularity; min TTL is 1s.
        store
            .try_pin("local", dep_id, "t", &hint, r, 1, Duration::from_secs(1))
            .await;
        // Wait past TTL.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(store.lookup("local", dep_id, "t", &hint, 1).await, None);
    }
}
