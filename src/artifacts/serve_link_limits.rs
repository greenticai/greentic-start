//! Limits on the signed-link route (docs/outbound-artifacts.md).
//!
//! The admin door has no streaming and no HEAD: one read buffers the whole
//! file (up to ~34 MB in flight), so reads are bounded per process. On top:
//! a fixed window per link, a fixed window per client (only when the client
//! is known, see [`crate::http_ingress::limits::client_key`]), and an hourly
//! egress budget per unit. None of them is an oracle: the per-client window
//! applies before any lookup, the others only to a link that verified.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::http_ingress::limits::ClientKey;

pub(crate) const MAX_INFLIGHT_ENV: &str = "GREENTIC_ARTIFACT_LINK_MAX_INFLIGHT";
pub(crate) const EGRESS_MB_ENV: &str = "GREENTIC_ARTIFACT_LINK_EGRESS_MB_PER_HOUR";
pub(crate) const DEFAULT_MAX_INFLIGHT: usize = 2;
pub(crate) const DEFAULT_EGRESS_MB_PER_HOUR: u64 = 2048;
/// Requests one link may answer per window.
pub(crate) const PER_LINK: u32 = 30;
/// Requests one client may make per window.
pub(crate) const PER_CLIENT: u32 = 120;
const WINDOW: Duration = Duration::from_secs(60);
/// Keys remembered per window table; past it, expired keys go first, then
/// the oldest windows.
const MAX_TRACKED: usize = 10_000;
const HOUR_SECS: u64 = 3_600;

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
        let mut map = match self.map.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
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

pub(crate) struct LinkLimits {
    reads: Arc<Semaphore>,
    per_link: Windows<String>,
    per_client: Windows<ClientKey>,
    /// Per deployment: (unix hour, bytes served in it).
    egress: Mutex<HashMap<String, (u64, u64)>>,
    egress_bytes_per_hour: u64,
}

fn parse_clamped(raw: Option<&str>, default: u64, min: u64, max: u64) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(default, |v| v.clamp(min, max))
}

impl LinkLimits {
    pub(crate) fn new(max_inflight: usize, egress_bytes_per_hour: u64) -> Self {
        Self {
            reads: Arc::new(Semaphore::new(max_inflight)),
            per_link: Windows::new(PER_LINK),
            per_client: Windows::new(PER_CLIENT),
            egress: Mutex::new(HashMap::new()),
            egress_bytes_per_hour,
        }
    }

    /// Pure: in-flight `1..=8` (default 2), egress `16..=65536` MiB per hour
    /// (default 2048); an unparsable value is the default.
    pub(crate) fn from_values(max_inflight: Option<&str>, egress_mb: Option<&str>) -> Self {
        let inflight = parse_clamped(max_inflight, DEFAULT_MAX_INFLIGHT as u64, 1, 8);
        let mb = parse_clamped(egress_mb, DEFAULT_EGRESS_MB_PER_HOUR, 16, 65_536);
        Self::new(inflight as usize, mb * 1024 * 1024)
    }

    /// The process's limits, from the environment, read once.
    pub(crate) fn global() -> &'static Self {
        static LIMITS: OnceLock<LinkLimits> = OnceLock::new();
        LIMITS.get_or_init(|| {
            Self::from_values(
                std::env::var(MAX_INFLIGHT_ENV).ok().as_deref(),
                std::env::var(EGRESS_MB_ENV).ok().as_deref(),
            )
        })
    }

    #[cfg(test)]
    fn max_inflight(&self) -> usize {
        self.reads.available_permits()
    }

    #[cfg(test)]
    fn egress_bytes_per_hour(&self) -> u64 {
        self.egress_bytes_per_hour
    }

    pub(crate) fn client_allows(&self, client: ClientKey) -> bool {
        self.per_client.allow(&client, Instant::now())
    }

    /// `link` names one file of one unit (deployment + artifact hex).
    pub(crate) fn link_allows(&self, link: &str) -> bool {
        self.per_link.allow(&link.to_string(), Instant::now())
    }

    /// One door read slot, or `None` when every slot is in use.
    pub(crate) fn try_read_slot(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.reads).try_acquire_owned().ok()
    }

    fn egress_lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (u64, u64)>> {
        match self.egress.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// `false` once the unit has served its hourly budget.
    pub(crate) fn egress_allows(&self, deployment: &str, now_unix: u64) -> bool {
        let hour = now_unix / HOUR_SECS;
        self.egress_lock()
            .get(deployment)
            .is_none_or(|(h, used)| *h != hour || *used < self.egress_bytes_per_hour)
    }

    pub(crate) fn egress_add(&self, deployment: &str, now_unix: u64, bytes: u64) {
        let hour = now_unix / HOUR_SECS;
        let mut egress = self.egress_lock();
        if egress.len() >= MAX_TRACKED && !egress.contains_key(deployment) {
            egress.retain(|_, (h, _)| *h == hour);
        }
        let entry = egress.entry(deployment.to_string()).or_insert((hour, 0));
        if entry.0 != hour {
            *entry = (hour, 0);
        }
        entry.1 = entry.1.saturating_add(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_clamped_and_unparsable_is_default() {
        let l = LinkLimits::from_values(None, None);
        assert_eq!(l.max_inflight(), 2);
        assert_eq!(l.egress_bytes_per_hour(), 2048 * 1024 * 1024);
        let l = LinkLimits::from_values(Some("99"), Some("1"));
        assert_eq!(l.max_inflight(), 8);
        assert_eq!(l.egress_bytes_per_hour(), 16 * 1024 * 1024);
        let l = LinkLimits::from_values(Some("0"), Some("999999"));
        assert_eq!(l.max_inflight(), 1);
        assert_eq!(l.egress_bytes_per_hour(), 65_536 * 1024 * 1024);
        let l = LinkLimits::from_values(Some("x"), Some("-3"));
        assert_eq!(l.max_inflight(), 2);
        assert_eq!(l.egress_bytes_per_hour(), 2048 * 1024 * 1024);
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
