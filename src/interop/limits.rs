//! Per-credential token bucket and a per-deployment concurrent-turn cap for
//! the interop surfaces (worker-interop contract §3, "Rate limit").
//!
//! Ported from the designer's `src/ui/mcp_server/limits.rs`, with the same
//! constants and the same two properties that make it safe:
//!
//! - **Only an authenticated caller creates a bucket.** The limiter is
//!   consulted AFTER the bearer check, keyed by the matched credential id (or,
//!   for MCP, the JWT `sub`), so an unauthenticated flood cannot grow the map.
//! - **Eviction is by idle AGE, never by an LRU cap.** An entry idle for
//!   [`IDLE_EVICTION_AFTER`] has refilled to [`BURST_CAPACITY`], so recreating
//!   it as a fresh full bucket gives its owner nothing they did not already
//!   have. `eviction_never_forgives_a_spender` pins that relationship.
//!
//! Both are per PROCESS: N Cloud Run instances multiply the ceiling by N. This
//! is a guardrail against one runaway caller, not a quota.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use greentic_deploy_spec::ids::DeploymentId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Sustained refill in tokens/second.
const REFILL_TOKENS_PER_SEC: f64 = 1.0;

/// The most tokens a bucket holds, and what a newly-seen caller starts with.
pub(crate) const BURST_CAPACITY: f64 = 120.0;

/// What a turn (`SendMessage`, an MCP `tools/call`) costs.
pub(crate) const TURN_COST: f64 = 2.0;

/// What a non-turn request (`GetTask`, `ListTasks`, …) costs.
pub(crate) const CHEAP_COST: f64 = 1.0;

/// `BURST_CAPACITY / REFILL_TOKENS_PER_SEC` seconds: the time an untouched
/// bucket takes to refill to full.
const IDLE_EVICTION_AFTER: Duration = Duration::from_secs(120);

/// Table size above which a request triggers an idle sweep. Far above what a
/// test binary reaches, so fixtures never exercise the sweep by accident.
const SWEEP_THRESHOLD: usize = 1024;

/// Concurrent turns one deployment may run through the interop surfaces
/// when `GREENTIC_INTEROP_MAX_CONCURRENT_TURNS` does not say otherwise.
pub(crate) const DEFAULT_MAX_CONCURRENT_TURNS: usize = 16;

/// The env var overriding [`DEFAULT_MAX_CONCURRENT_TURNS`].
pub(crate) const MAX_CONCURRENT_TURNS_ENV: &str = "GREENTIC_INTEROP_MAX_CONCURRENT_TURNS";

struct Bucket {
    tokens: f64,
    last_seen: Instant,
}

impl Bucket {
    fn seen_at(now: Instant) -> Self {
        Self {
            tokens: BURST_CAPACITY,
            last_seen: now,
        }
    }

    /// Refill for elapsed time, then spend `cost`. `Err(retry_after_secs)` —
    /// always >= 1 — when the bucket cannot pay.
    fn try_consume(&mut self, cost: f64, now: Instant) -> Result<(), u64> {
        let elapsed_secs = now.saturating_duration_since(self.last_seen).as_secs_f64();
        self.last_seen = now;
        self.tokens = (self.tokens + elapsed_secs * REFILL_TOKENS_PER_SEC).min(BURST_CAPACITY);
        if self.tokens >= cost {
            self.tokens -= cost;
            Ok(())
        } else {
            let deficit = cost - self.tokens;
            let secs = (deficit / REFILL_TOKENS_PER_SEC).ceil();
            // `secs` is small and positive here; the cast cannot truncate a
            // meaningful value.
            Err((secs as u64).max(1))
        }
    }
}

/// The per-credential token buckets.
#[derive(Default)]
pub(crate) struct RateLimiter {
    buckets: DashMap<String, Bucket>,
}

impl RateLimiter {
    /// Charge `cost` to `key`. `Err(retry_after_secs)` when refused.
    pub(crate) fn check(&self, key: &str, cost: f64) -> Result<(), u64> {
        self.check_at(key, cost, Instant::now())
    }

    fn check_at(&self, key: &str, cost: f64, now: Instant) -> Result<(), u64> {
        // Sweep BEFORE taking an entry: `retain` takes shard write locks and
        // would deadlock against a live entry guard from the same map.
        sweep_map(&self.buckets, now);
        self.buckets
            .entry(key.to_string())
            .or_insert_with(|| Bucket::seen_at(now))
            .try_consume(cost, now)
    }
}

fn sweep_map(buckets: &DashMap<String, Bucket>, now: Instant) {
    if buckets.len() <= SWEEP_THRESHOLD {
        return;
    }
    buckets
        .retain(|_, bucket| now.saturating_duration_since(bucket.last_seen) < IDLE_EVICTION_AFTER);
    if buckets.len() > SWEEP_THRESHOLD {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "interop: {} active rate-limit keys exceed the sweep threshold",
                buckets.len()
            ),
        );
    }
}

/// A cap on concurrent interop turns per deployment. A refused turn is a
/// `429` with `Retry-After: 1`; nothing queues, because an agent caller holds
/// its connection open for the whole turn.
pub(crate) struct TurnGate {
    max: usize,
    per_deployment: DashMap<DeploymentId, Arc<Semaphore>>,
}

impl TurnGate {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            per_deployment: DashMap::new(),
        }
    }

    /// A permit for one turn on `deployment`, or `None` when the cap is
    /// reached. The permit releases on drop.
    pub(crate) fn try_acquire(&self, deployment: DeploymentId) -> Option<OwnedSemaphorePermit> {
        let semaphore = Arc::clone(
            self.per_deployment
                .entry(deployment)
                .or_insert_with(|| Arc::new(Semaphore::new(self.max)))
                .value(),
        );
        semaphore.try_acquire_owned().ok()
    }
}

/// Parse `GREENTIC_INTEROP_MAX_CONCURRENT_TURNS`: a positive integer, else
/// the default. Defensive — a typo never removes the cap.
pub(crate) fn max_concurrent_turns(raw: Option<&str>) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_CONCURRENT_TURNS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_allowed_then_refused_with_a_retry_after() {
        let limiter = RateLimiter::default();
        let now = Instant::now();
        for _ in 0..60 {
            assert!(limiter.check_at("c1", TURN_COST, now).is_ok());
        }
        let refused = limiter.check_at("c1", TURN_COST, now);
        assert_eq!(refused, Err(2));
        // Another credential has its own bucket.
        assert!(limiter.check_at("c2", TURN_COST, now).is_ok());
    }

    #[test]
    fn the_bucket_refills_at_one_token_per_second() {
        let limiter = RateLimiter::default();
        let start = Instant::now();
        for _ in 0..120 {
            assert!(limiter.check_at("c1", CHEAP_COST, start).is_ok());
        }
        assert_eq!(limiter.check_at("c1", CHEAP_COST, start), Err(1));
        let later = start + Duration::from_secs(2);
        assert!(limiter.check_at("c1", TURN_COST, later).is_ok());
        assert!(limiter.check_at("c1", CHEAP_COST, later).is_err());
    }

    #[test]
    fn eviction_never_forgives_a_spender() {
        // An entry old enough to be swept has refilled to full anyway.
        let refill_secs = BURST_CAPACITY / REFILL_TOKENS_PER_SEC;
        assert!(IDLE_EVICTION_AFTER.as_secs_f64() >= refill_secs);

        let map: DashMap<String, Bucket> = DashMap::new();
        let start = Instant::now();
        for i in 0..=SWEEP_THRESHOLD {
            map.insert(format!("idle-{i}"), Bucket::seen_at(start));
        }
        let mut spender = Bucket::seen_at(start);
        let recent = start + IDLE_EVICTION_AFTER;
        spender.tokens = 0.0;
        spender.last_seen = recent;
        map.insert("spender".into(), spender);
        sweep_map(&map, recent + Duration::from_secs(1));
        assert_eq!(map.len(), 1, "only the recently-active entry survives");
        assert!(map.get("spender").is_some_and(|b| b.tokens == 0.0));
    }

    #[test]
    fn the_turn_gate_caps_per_deployment() {
        let gate = TurnGate::new(2);
        let a = DeploymentId::new();
        let b = DeploymentId::new();
        let first = gate.try_acquire(a);
        let second = gate.try_acquire(a);
        assert!(first.is_some() && second.is_some());
        assert!(gate.try_acquire(a).is_none());
        assert!(
            gate.try_acquire(b).is_some(),
            "another deployment is unaffected"
        );
        drop(first);
        assert!(
            gate.try_acquire(a).is_some(),
            "a released permit is reusable"
        );
    }

    #[test]
    fn the_cap_env_is_parsed_defensively() {
        assert_eq!(max_concurrent_turns(None), DEFAULT_MAX_CONCURRENT_TURNS);
        assert_eq!(
            max_concurrent_turns(Some("0")),
            DEFAULT_MAX_CONCURRENT_TURNS
        );
        assert_eq!(
            max_concurrent_turns(Some("x")),
            DEFAULT_MAX_CONCURRENT_TURNS
        );
        assert_eq!(max_concurrent_turns(Some(" 4 ")), 4);
    }
}
