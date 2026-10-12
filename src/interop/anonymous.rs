//! Limits for anonymous callers of a public unit (access-policy spec §6.2).
//!
//! An anonymous turn spends the workspace's LLM budget and nobody vouches for
//! the caller, so three things bound it, in order of how much they can be
//! trusted:
//!
//! 1. **A per-unit bucket** (`anon:<unit>`), always. It is the guarantee: it
//!    holds however many clients there are and whatever they claim to be.
//! 2. **An optional daily cap** on turns per UTC day, per unit. Per PROCESS: a
//!    cold start forgets it (documented limitation until the runtime policy
//!    door reads the admin's count).
//! 3. **A per-client bucket** (`anon:<unit>:<client>`), fairness only. The
//!    client comes from `X-Forwarded-For` when proxies are trusted, and a
//!    caller can write that header, so this bucket is NOT a guarantee: a
//!    caller who rotates it gets a fresh one each time and is still bound by
//!    (1). It exists so one client cannot take the whole unit's allowance
//!    when clients behave. The table is hard-bounded; when it is full of
//!    active entries a NEW client is simply not given a bucket, which loses
//!    fairness and nothing else.

use std::net::IpAddr;
use std::time::Instant;

use dashmap::DashMap;
use hyper::HeaderMap;

use super::config::PublicLimits;
use super::limits::{Bucket, Charge, TURN_COST};

/// Most per-client buckets held at once, across every unit.
pub(crate) const MAX_CLIENT_BUCKETS: usize = 1024;

const SECS_PER_DAY: u64 = 86_400;

/// A client's share of the unit's allowance: half the burst and half the
/// sustained rate, never less than one turn of each.
fn client_share(limits: &PublicLimits) -> (f64, f64) {
    let burst = f64::from((limits.burst / 2).max(1)) * TURN_COST;
    let per_min = f64::from((limits.rate_per_min / 2).max(1));
    (burst, per_min * TURN_COST / 60.0)
}

/// The unit's whole allowance: `burst` turns held, refilled at `rate_per_min`.
fn unit_share(limits: &PublicLimits) -> (f64, f64) {
    (
        f64::from(limits.burst) * TURN_COST,
        f64::from(limits.rate_per_min) * TURN_COST / 60.0,
    )
}

/// The anonymous half of the interop rate limiter.
#[derive(Default)]
pub(crate) struct AnonymousLimiter {
    units: DashMap<String, Bucket>,
    clients: DashMap<String, Bucket>,
    /// Per unit: `(UTC day number, turns served that day)`.
    daily: DashMap<String, (u64, u32)>,
}

impl AnonymousLimiter {
    /// Charge one anonymous request. `Err(retry_after_secs)` when refused.
    ///
    /// `deployment` names the unit and `client` the (hashed) client. The
    /// daily count is taken last and only for a turn that passed the buckets,
    /// so a refused request spends none of it.
    pub(crate) fn check(
        &self,
        deployment: &str,
        client: &str,
        limits: &PublicLimits,
        charge: Charge,
        now: Instant,
        now_ms: u64,
    ) -> Result<(), u64> {
        // A cap already reached refuses before any bucket is touched.
        if charge.turn
            && let Some(cap) = limits.daily_turn_cap
        {
            let day = now_ms / 1000 / SECS_PER_DAY;
            if self
                .daily
                .get(deployment)
                .is_some_and(|entry| entry.0 == day && entry.1 >= cap)
            {
                return Err(secs_to_midnight(now_ms));
            }
        }
        let client_key = self.charge_client(deployment, client, limits, charge.cost, now)?;
        let (capacity, refill) = unit_share(limits);
        let unit_verdict = {
            let mut bucket = self
                .units
                .entry(format!("anon:{deployment}"))
                .or_insert_with(|| Bucket::with_rate(capacity, refill, now));
            bucket.resize(capacity, refill);
            bucket.try_consume(charge.cost, now)
        };
        if let Err(retry) = unit_verdict {
            // The unit refused, so this client spent nothing: otherwise a
            // client turned away because OTHERS used the allowance would also
            // lose its own share.
            if let Some(key) = client_key
                && let Some(mut bucket) = self.clients.get_mut(&key)
            {
                bucket.refund(charge.cost);
            }
            return Err(retry);
        }
        if charge.turn
            && let Some(cap) = limits.daily_turn_cap
        {
            let day = now_ms / 1000 / SECS_PER_DAY;
            let mut entry = self.daily.entry(deployment.to_string()).or_insert((day, 0));
            if entry.0 != day {
                *entry = (day, 0);
            }
            // Re-checked under the entry lock, so two requests racing for the
            // last turn of the day cannot both take it.
            if entry.1 >= cap {
                return Err(secs_to_midnight(now_ms));
            }
            entry.1 += 1;
        }
        Ok(())
    }

    fn charge_client(
        &self,
        deployment: &str,
        client: &str,
        limits: &PublicLimits,
        cost: f64,
        now: Instant,
    ) -> Result<Option<String>, u64> {
        let key = format!("anon:{deployment}:{client}");
        let (capacity, refill) = client_share(limits);
        if !self.clients.contains_key(&key) {
            if self.clients.len() >= MAX_CLIENT_BUCKETS {
                // Sweep BEFORE taking an entry: `retain` takes shard write
                // locks. An idle, refilled bucket is dropped at no gain to
                // its owner.
                self.clients.retain(|_, bucket| !bucket.is_idle_full(now));
            }
            if self.clients.len() >= MAX_CLIENT_BUCKETS {
                warn_table_full_once();
                return Ok(None);
            }
        }
        let mut bucket = self
            .clients
            .entry(key.clone())
            .or_insert_with(|| Bucket::with_rate(capacity, refill, now));
        bucket.resize(capacity, refill);
        bucket.try_consume(cost, now).map(|()| Some(key))
    }

    #[cfg(test)]
    pub(crate) fn client_buckets(&self) -> usize {
        self.clients.len()
    }
}

fn secs_to_midnight(now_ms: u64) -> u64 {
    SECS_PER_DAY - (now_ms / 1000) % SECS_PER_DAY
}

fn warn_table_full_once() {
    static SAID: std::sync::Once = std::sync::Once::new();
    SAID.call_once(|| {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "interop: {MAX_CLIENT_BUCKETS} anonymous clients are active at once; new \
                 clients are limited by the per-unit bucket alone"
            ),
        );
    });
}

/// The label of the client behind a request: the trusted-proxy rule the
/// upload and file-link routes use (`http_ingress::client_key`), as a string.
///
/// With `trusted_hops == 0` it is the TCP peer and `X-Forwarded-For` is
/// ignored. With `N` it is the N-th entry from the right, the one the
/// outermost trusted proxy appended; a client cannot write that entry, only
/// the ones to its left. No usable address at all is the fixed label
/// `unknown`, so such requests share one fairness bucket.
pub(crate) fn client_label(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    trusted_hops: usize,
) -> String {
    use crate::http_ingress::limits::{ClientKey, client_key};
    match client_key(peer, headers, trusted_hops) {
        Some(ClientKey::Ip(ip)) => ip.to_string(),
        Some(ClientKey::Conversation(_)) | None => "unknown".to_string(),
    }
}

#[cfg(test)]
#[path = "anonymous_tests.rs"]
mod tests;
