//! Limits on the signed-link route (docs/outbound-artifacts.md).
//!
//! The admin door has no streaming and no HEAD: one read buffers the whole
//! file (up to ~14 MB of base64 in flight), so reads are bounded: at most
//! `GREENTIC_ARTIFACT_LINK_MAX_INFLIGHT` per process and ONE per unit, so a
//! single link holder cannot take every slot from the other units. On top: a
//! fixed window per link, a fixed window per client (only when the client is
//! known, see [`crate::http_ingress::limits::client_key`]), and two hourly
//! byte budgets, per unit and per link. A byte budget is RESERVED before the
//! read (the largest file the door returns) and the unused part refunded
//! after it, so concurrent reads cannot overshoot it. None of them is an
//! oracle: the per-client window applies before any lookup, the others only
//! to a link that verified.
//!
//! Every limit here lives in ONE process: a unit running on N replicas gets
//! N times each of them.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use greentic_aw_runtime::artifact_reader::MAX_ARTIFACT_BYTES;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::http_ingress::limits::ClientKey;

pub(crate) const MAX_INFLIGHT_ENV: &str = "GREENTIC_ARTIFACT_LINK_MAX_INFLIGHT";
pub(crate) const EGRESS_MB_ENV: &str = "GREENTIC_ARTIFACT_LINK_EGRESS_MB_PER_HOUR";
pub(crate) const LINK_EGRESS_MB_ENV: &str = "GREENTIC_ARTIFACT_LINK_EGRESS_MB_PER_LINK_PER_HOUR";
pub(crate) const DEFAULT_MAX_INFLIGHT: usize = 2;
pub(crate) const DEFAULT_EGRESS_MB_PER_HOUR: u64 = 2048;
pub(crate) const DEFAULT_LINK_EGRESS_MB_PER_HOUR: u64 = 64;
/// Door reads one unit may have in flight in this process.
pub(crate) const PER_UNIT_INFLIGHT: usize = 1;
/// Requests one link may answer per window.
pub(crate) const PER_LINK: u32 = 30;
/// Requests one client may make per window.
pub(crate) const PER_CLIENT: u32 = 120;
const WINDOW: Duration = Duration::from_secs(60);
/// Keys remembered per window or budget table; past it, expired keys go
/// first, then the oldest windows.
const MAX_TRACKED: usize = 10_000;
const HOUR_SECS: u64 = 3_600;
const MIB: u64 = 1024 * 1024;
/// Smallest configurable byte budget, in MiB.
const MIN_BUDGET_MB: u64 = 16;

// The smallest budget still fits one reservation of the largest file.
const _: () = assert!(MIN_BUDGET_MB * MIB >= MAX_ARTIFACT_BYTES as u64);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// A fixed 60 s window per key.
struct Windows<K> {
    limit: u32,
    map: Mutex<HashMap<K, (Instant, u32)>>,
}

impl<K: Eq + Hash + Clone> Windows<K> {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Counts one request; `false` when the key is over its limit.
    fn allow(&self, key: &K, now: Instant) -> bool {
        let mut map = lock(&self.map);
        if map.len() >= MAX_TRACKED && !map.contains_key(key) {
            map.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
            while map.len() >= MAX_TRACKED {
                let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, (start, _))| *start)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                map.remove(&oldest);
            }
        }
        let entry = map.entry(key.clone()).or_insert((now, 0));
        if now.duration_since(entry.0) >= WINDOW {
            *entry = (now, 0);
        }
        if entry.1 >= self.limit {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// Bytes served in one unix hour, plus bytes reserved by reads in flight.
#[derive(Default)]
struct Spend {
    hour: u64,
    used: u64,
    reserved: u64,
}

/// An hourly byte budget per key.
struct Budgets {
    limit: u64,
    map: Mutex<HashMap<String, Spend>>,
}

impl Budgets {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `amount` more fits in `key`'s budget for `hour`.
    fn fits(
        map: &mut HashMap<String, Spend>,
        limit: u64,
        key: &str,
        hour: u64,
        amount: u64,
    ) -> bool {
        let Some(spend) = map.get_mut(key) else {
            return amount <= limit;
        };
        if spend.hour != hour {
            spend.hour = hour;
            spend.used = 0;
        }
        spend
            .used
            .saturating_add(spend.reserved)
            .saturating_add(amount)
            <= limit
    }

    fn reserve(map: &mut HashMap<String, Spend>, key: &str, hour: u64, amount: u64) {
        if map.len() >= MAX_TRACKED && !map.contains_key(key) {
            map.retain(|_, spend| spend.reserved > 0 || spend.hour == hour);
        }
        let spend = map.entry(key.to_string()).or_insert(Spend {
            hour,
            ..Spend::default()
        });
        if spend.hour != hour {
            spend.hour = hour;
            spend.used = 0;
        }
        spend.reserved = spend.reserved.saturating_add(amount);
    }

    /// Releases `amount` and charges `charged` to `hour` (dropped when the
    /// hour has already rolled over).
    fn settle(&self, key: &str, hour: u64, amount: u64, charged: u64) {
        let mut map = lock(&self.map);
        if let Some(spend) = map.get_mut(key) {
            spend.reserved = spend.reserved.saturating_sub(amount);
            if spend.hour == hour {
                spend.used = spend.used.saturating_add(charged);
            }
        }
    }
}

/// Bytes held against a unit's and a link's budgets while one door read is
/// in flight. Dropped uncharged, it gives everything back.
pub(crate) struct Reservation<'a> {
    limits: &'a LinkLimits,
    deployment: String,
    link: String,
    hour: u64,
    amount: u64,
    charged: u64,
}

impl Reservation<'_> {
    /// Records the bytes the door actually returned.
    pub(crate) fn charge(&mut self, bytes: u64) {
        self.charged = bytes;
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        let limits = self.limits;
        limits
            .unit_bytes
            .settle(&self.deployment, self.hour, self.amount, self.charged);
        limits
            .link_bytes
            .settle(&self.link, self.hour, self.amount, self.charged);
    }
}

/// A process read slot plus the unit's own slot, both released on drop.
pub(crate) struct ReadSlot {
    _process: OwnedSemaphorePermit,
    units: Arc<Mutex<HashMap<String, usize>>>,
    deployment: String,
}

impl Drop for ReadSlot {
    fn drop(&mut self) {
        let mut units = lock(&self.units);
        if let Some(count) = units.get_mut(&self.deployment) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                units.remove(&self.deployment);
            }
        }
    }
}

pub(crate) struct LinkLimits {
    reads: Arc<Semaphore>,
    /// Reads in flight per deployment (entries exist only while in flight,
    /// so the table is bounded by the process's slots).
    unit_reads: Arc<Mutex<HashMap<String, usize>>>,
    per_link: Windows<String>,
    per_client: Windows<ClientKey>,
    unit_bytes: Budgets,
    link_bytes: Budgets,
    /// Reserved per read: the largest file the door returns.
    reserve_bytes: u64,
}

fn parse_clamped(raw: Option<&str>, default: u64, min: u64, max: u64) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(default, |v| v.clamp(min, max))
}

impl LinkLimits {
    /// `max_inflight` process slots and a unit budget; the per-link budget
    /// and the reservation are the defaults.
    #[cfg(test)]
    pub(crate) fn new(max_inflight: usize, unit_bytes_per_hour: u64) -> Self {
        Self::with_budgets(
            max_inflight,
            unit_bytes_per_hour,
            DEFAULT_LINK_EGRESS_MB_PER_HOUR * MIB,
            MAX_ARTIFACT_BYTES as u64,
        )
    }

    pub(crate) fn with_budgets(
        max_inflight: usize,
        unit_bytes_per_hour: u64,
        link_bytes_per_hour: u64,
        reserve_bytes: u64,
    ) -> Self {
        Self {
            reads: Arc::new(Semaphore::new(max_inflight)),
            unit_reads: Arc::new(Mutex::new(HashMap::new())),
            per_link: Windows::new(PER_LINK),
            per_client: Windows::new(PER_CLIENT),
            unit_bytes: Budgets::new(unit_bytes_per_hour),
            link_bytes: Budgets::new(link_bytes_per_hour),
            reserve_bytes,
        }
    }

    /// Pure: in-flight `1..=8` (default 2); unit egress `16..=65536` MiB per
    /// hour (default 2048); per-link egress `16..=65536` MiB per hour
    /// (default 64); an unparsable value is the default.
    pub(crate) fn from_values(
        max_inflight: Option<&str>,
        egress_mb: Option<&str>,
        link_egress_mb: Option<&str>,
    ) -> Self {
        let inflight = parse_clamped(max_inflight, DEFAULT_MAX_INFLIGHT as u64, 1, 8);
        let unit = parse_clamped(egress_mb, DEFAULT_EGRESS_MB_PER_HOUR, MIN_BUDGET_MB, 65_536);
        let link = parse_clamped(
            link_egress_mb,
            DEFAULT_LINK_EGRESS_MB_PER_HOUR,
            MIN_BUDGET_MB,
            65_536,
        );
        Self::with_budgets(
            inflight as usize,
            unit * MIB,
            link * MIB,
            MAX_ARTIFACT_BYTES as u64,
        )
    }

    /// The process's limits, from the environment, read once.
    pub(crate) fn global() -> &'static Self {
        static LIMITS: OnceLock<LinkLimits> = OnceLock::new();
        LIMITS.get_or_init(|| {
            Self::from_values(
                std::env::var(MAX_INFLIGHT_ENV).ok().as_deref(),
                std::env::var(EGRESS_MB_ENV).ok().as_deref(),
                std::env::var(LINK_EGRESS_MB_ENV).ok().as_deref(),
            )
        })
    }

    #[cfg(test)]
    fn max_inflight(&self) -> usize {
        self.reads.available_permits()
    }

    pub(crate) fn client_allows(&self, client: ClientKey) -> bool {
        self.per_client.allow(&client, Instant::now())
    }

    /// `link` names one file of one unit (deployment + artifact hex).
    pub(crate) fn link_allows(&self, link: &str) -> bool {
        self.per_link.allow(&link.to_string(), Instant::now())
    }

    /// Reserves one read's worth of bytes against the unit's and the link's
    /// hourly budgets, or `None` when either has no room left.
    pub(crate) fn reserve(
        &self,
        deployment: &str,
        link: &str,
        now_unix: u64,
    ) -> Option<Reservation<'_>> {
        let hour = now_unix / HOUR_SECS;
        let amount = self.reserve_bytes;
        // Both tables are locked together (unit, then link) so the check and
        // the reservation are one step.
        let mut units = lock(&self.unit_bytes.map);
        let mut links = lock(&self.link_bytes.map);
        if !Budgets::fits(&mut units, self.unit_bytes.limit, deployment, hour, amount)
            || !Budgets::fits(&mut links, self.link_bytes.limit, link, hour, amount)
        {
            return None;
        }
        Budgets::reserve(&mut units, deployment, hour, amount);
        Budgets::reserve(&mut links, link, hour, amount);
        Some(Reservation {
            limits: self,
            deployment: deployment.to_string(),
            link: link.to_string(),
            hour,
            amount,
            charged: 0,
        })
    }

    /// One door read slot for `deployment`, or `None` when the unit already
    /// has its read in flight or every process slot is in use.
    pub(crate) fn try_read_slot(&self, deployment: &str) -> Option<ReadSlot> {
        let mut units = lock(&self.unit_reads);
        let count = units.get(deployment).copied().unwrap_or(0);
        if count >= PER_UNIT_INFLIGHT {
            return None;
        }
        let permit = Arc::clone(&self.reads).try_acquire_owned().ok()?;
        units.insert(deployment.to_string(), count + 1);
        Some(ReadSlot {
            _process: permit,
            units: Arc::clone(&self.unit_reads),
            deployment: deployment.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_clamped_and_unparsable_is_default() {
        const MIB: u64 = 1024 * 1024;
        let l = LinkLimits::from_values(None, None, None);
        assert_eq!(l.max_inflight(), 2);
        assert_eq!(l.unit_bytes.limit, 2048 * MIB);
        assert_eq!(l.link_bytes.limit, 64 * MIB);
        assert_eq!(l.reserve_bytes, MAX_ARTIFACT_BYTES as u64);
        let l = LinkLimits::from_values(Some("99"), Some("1"), Some("1"));
        assert_eq!(l.max_inflight(), 8);
        assert_eq!(l.unit_bytes.limit, 16 * MIB);
        assert_eq!(l.link_bytes.limit, 16 * MIB);
        let l = LinkLimits::from_values(Some("0"), Some("999999"), Some("999999"));
        assert_eq!(l.max_inflight(), 1);
        assert_eq!(l.unit_bytes.limit, 65_536 * MIB);
        assert_eq!(l.link_bytes.limit, 65_536 * MIB);
        let l = LinkLimits::from_values(Some("x"), Some("-3"), Some("y"));
        assert_eq!(l.max_inflight(), 2);
        assert_eq!(l.unit_bytes.limit, 2048 * MIB);
        assert_eq!(l.link_bytes.limit, 64 * MIB);
    }

    #[test]
    fn a_full_window_table_still_counts_new_keys() {
        let w: Windows<u32> = Windows::new(1);
        let now = Instant::now();
        for k in 0..(MAX_TRACKED as u32 + 5) {
            assert!(w.allow(&k, now));
        }
        assert!(w.map.lock().unwrap().len() <= MAX_TRACKED);
        // A key still tracked keeps its count.
        assert!(!w.allow(&(MAX_TRACKED as u32 + 4), now));
    }
}
