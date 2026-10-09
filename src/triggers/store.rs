//! The shared state triggers need across replicas: a "first writer wins" key
//! with a TTL, and a counter with a TTL.
//!
//! Three contract guarantees ride on it:
//!
//! - one firer per cron tick across replicas (§6.3.1) — `claim` on
//!   `fire:<…>:<tick>`;
//! - per-delivery webhook idempotency (§6.3.5) — `claim` on `seen:<…>:<key>`;
//! - the hourly firing budget (§6.6) — `incr` on `budget:<…>:<hour>`.
//!
//! **Only the Redis store meets them for more than one replica.** The in-memory
//! store is correct for a single replica and wrong for two, and the host cannot
//! tell how many it has — so boot says which one is in use, once, in terms an
//! operator can act on (see [`resolve`]).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use redis::aio::ConnectionManager;

/// Environment variable naming the trigger store's Redis. Falls back to the
/// session-pin Redis, which a multi-replica deployment already has to set for
/// sticky routing — so the common case needs no new configuration.
pub(crate) const TRIGGER_REDIS_URL_ENV: &str = "GREENTIC_TRIGGER_REDIS_URL";

const KEY_PREFIX: &str = "gt:trig";
const REDIS_OP_TIMEOUT: Duration = Duration::from_millis(250);

#[async_trait]
pub(crate) trait TriggerStore: Send + Sync + std::fmt::Debug {
    /// Set `key` if absent, expiring after `ttl`. `true` = this caller won.
    async fn claim(&self, key: &str, ttl: Duration) -> Result<bool>;
    /// Increment `key`, starting its `ttl` on first use. Returns the new value.
    async fn incr(&self, key: &str, ttl: Duration) -> Result<u64>;
}

/// Namespaced key: `gt:trig:<kind>:<env>:<deployment>:<trigger>:<part>`. The
/// free-form `part` (a delivery id, a tick) is URL-encoded so a `:` inside it
/// cannot collide with the structure.
pub(crate) fn key(kind: &str, env: &str, deployment: &str, trigger_id: &str, part: &str) -> String {
    format!(
        "{KEY_PREFIX}:{kind}:{env}:{deployment}:{trigger_id}:{}",
        urlencoding::encode(part)
    )
}

/// Resolve the store for this process. Fail open to in-memory on a bad or
/// unreachable Redis, like the session-pin store: triggers still fire, and the
/// warning names exactly which guarantee is weakened.
pub(crate) async fn resolve() -> Arc<dyn TriggerStore> {
    let url = crate::revision_pin::redis_url_from_raw(std::env::var(TRIGGER_REDIS_URL_ENV).ok())
        .or_else(|| {
            crate::revision_pin::redis_url_from_raw(
                std::env::var(crate::revision_pin::PIN_REDIS_URL_ENV).ok(),
            )
        });
    let Some(url) = url else {
        crate::operator_log::info(
            module_path!(),
            "trigger store: in-memory. Correct for ONE replica only — with more, every \
             replica fires each cron tick and webhook deduplication is per replica. Set \
             GREENTIC_TRIGGER_REDIS_URL (or GREENTIC_REVISION_PIN_REDIS_URL) to share it.",
        );
        return Arc::new(InMemoryTriggerStore::default());
    };
    match RedisTriggerStore::from_url(&url).await {
        Ok(store) => {
            crate::operator_log::info(
                module_path!(),
                "trigger store: redis (shared across replicas)",
            );
            Arc::new(store)
        }
        Err(err) => {
            crate::operator_log::warn(
                module_path!(),
                format!(
                    "trigger store Redis unavailable ({err:#}); falling back to in-memory, which \
                     is correct for one replica only"
                ),
            );
            Arc::new(InMemoryTriggerStore::default())
        }
    }
}

pub(crate) struct RedisTriggerStore {
    conn: ConnectionManager,
}

impl std::fmt::Debug for RedisTriggerStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisTriggerStore").finish_non_exhaustive()
    }
}

impl RedisTriggerStore {
    pub(crate) async fn from_url(url: &str) -> Result<Self> {
        crate::redis_tls::ensure_crypto_provider_for(url);
        let client = redis::Client::open(url).with_context(|| {
            format!(
                "invalid redis url `{}`",
                crate::revision_pin::redact_redis_url(url)
            )
        })?;
        let conn = ConnectionManager::new(client)
            .await
            .context("redis ConnectionManager init failed")?;
        Ok(Self { conn })
    }
}

#[async_trait]
impl TriggerStore for RedisTriggerStore {
    async fn claim(&self, key: &str, ttl: Duration) -> Result<bool> {
        let mut conn = self.conn.clone();
        let mut cmd = redis::cmd("SET");
        cmd.arg(key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl.as_secs().max(1));
        let reply: Option<String> =
            tokio::time::timeout(REDIS_OP_TIMEOUT, cmd.query_async(&mut conn))
                .await
                .context("redis SET NX timed out")?
                .context("redis SET NX failed")?;
        Ok(reply.is_some())
    }

    async fn incr(&self, key: &str, ttl: Duration) -> Result<u64> {
        let mut conn = self.conn.clone();
        // `SET … NX EX` then `INCR`, atomically: the window starts on the
        // first use and later increments never extend it. Written this way
        // rather than `INCR` + `EXPIRE … NX` because the `NX` flag on EXPIRE
        // needs Redis 7, and a managed Redis on 6.x would reject the pipeline
        // — silently disabling the budget, since a store error fails open.
        let mut pipe = redis::pipe();
        pipe.atomic()
            .cmd("SET")
            .arg(key)
            .arg(0)
            .arg("NX")
            .arg("EX")
            .arg(ttl.as_secs().max(1))
            .ignore()
            .cmd("INCR")
            .arg(key);
        let (value,): (u64,) = tokio::time::timeout(REDIS_OP_TIMEOUT, pipe.query_async(&mut conn))
            .await
            .context("redis INCR timed out")?
            .context("redis INCR failed")?;
        Ok(value)
    }
}

/// Single-process store. Expired entries are dropped lazily on access and
/// swept when the map grows, so a steady stream of unique delivery ids cannot
/// grow it without bound.
#[derive(Debug, Default)]
pub(crate) struct InMemoryTriggerStore {
    inner: Mutex<HashMap<String, (u64, Instant)>>,
}

const SWEEP_THRESHOLD: usize = 10_000;

impl InMemoryTriggerStore {
    fn with_live<T>(
        &self,
        f: impl FnOnce(&mut HashMap<String, (u64, Instant)>, Instant) -> T,
    ) -> T {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() > SWEEP_THRESHOLD {
            map.retain(|_, (_, exp)| *exp > now);
        }
        f(&mut map, now)
    }
}

#[async_trait]
impl TriggerStore for InMemoryTriggerStore {
    async fn claim(&self, key: &str, ttl: Duration) -> Result<bool> {
        Ok(self.with_live(|map, now| match map.get(key) {
            Some((_, exp)) if *exp > now => false,
            _ => {
                map.insert(key.to_string(), (1, now + ttl));
                true
            }
        }))
    }

    async fn incr(&self, key: &str, ttl: Duration) -> Result<u64> {
        Ok(self.with_live(|map, now| {
            let entry = map.entry(key.to_string()).or_insert((0, now + ttl));
            if entry.1 <= now {
                *entry = (0, now + ttl);
            }
            entry.0 += 1;
            entry.0
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_first_claim_wins_and_the_second_loses() {
        let store = InMemoryTriggerStore::default();
        assert!(store.claim("k", Duration::from_secs(60)).await.unwrap());
        assert!(!store.claim("k", Duration::from_secs(60)).await.unwrap());
        assert!(store.claim("other", Duration::from_secs(60)).await.unwrap());
    }

    #[tokio::test]
    async fn an_expired_claim_can_be_taken_again() {
        let store = InMemoryTriggerStore::default();
        assert!(store.claim("k", Duration::from_millis(1)).await.unwrap());
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(store.claim("k", Duration::from_secs(60)).await.unwrap());
    }

    #[tokio::test]
    async fn incr_counts_within_its_window_and_restarts_after_it() {
        let store = InMemoryTriggerStore::default();
        assert_eq!(store.incr("c", Duration::from_millis(20)).await.unwrap(), 1);
        assert_eq!(store.incr("c", Duration::from_millis(20)).await.unwrap(), 2);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(store.incr("c", Duration::from_millis(20)).await.unwrap(), 1);
    }

    #[test]
    fn a_colon_in_the_free_part_cannot_collide_with_the_key_structure() {
        let a = key("seen", "prod", "dep", "t", "a:b");
        let b = key("seen", "prod", "dep", "t:a", "b");
        assert_ne!(a, b);
        assert!(a.starts_with("gt:trig:seen:prod:dep:t:"));
    }
}
