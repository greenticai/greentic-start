//! A short TTL over one unit's staged interop config, so the authenticated
//! surfaces do not read the secrets store on every request.
//!
//! Both gates — Phase 0b on the generic branch and the A2A paths — need the
//! unit's config before they can decide anything, which put one store read on
//! every non-loopback POST. On the remote lane that store is a dev-store file
//! that is BAKED INTO THE REVISION: it cannot change while this process
//! serves, because a rotation or a toggle takes effect at the next deploy.
//! So the value is immutable for the life of a revision and a TTL costs
//! nothing in freshness.
//!
//! Three properties make it safe:
//!
//! - **The key space is bounded by the environment, not by the caller.**
//!   `(tenant, bundle id)` comes from the deployment route table, which is
//!   operator-materialised; a hostile caller cannot mint entries.
//! - **A read FAILURE is never cached.** Caching it would hold a `503` for the
//!   whole TTL after the store recovered. Caching the two SUCCESSES — a
//!   parsed config, and a confirmed absence — is what removes the per-request
//!   read, and "absent" is the common case for a unit with interop off.
//! - **The TTL is short and the entry is replaced, never merged**, so a
//!   redeployed revision under the same ids converges within one window even
//!   though it cannot happen in practice (a new revision means a new process).
//!
//! It is NOT a negative cache for authentication: the credential check runs
//! against the cached config on every request, so a rotated-out token stops
//! working exactly when its `expires_at_ms` says.

use std::time::{Duration, Instant};

use dashmap::DashMap;

use super::config::InteropConfig;

/// How long a read is reused. Short enough that a redeploy converges inside
/// one window; long enough that a burst from one caller costs one read.
const TTL: Duration = Duration::from_secs(30);

/// A cached outcome. Only the two SUCCESSFUL outcomes are held — see the
/// module docs on why a failure is not.
#[derive(Clone)]
struct Entry {
    config: Option<InteropConfig>,
    stored_at: Instant,
}

/// Per-unit config cache, one per listener.
#[derive(Default)]
pub(crate) struct UnitConfigCache {
    entries: DashMap<(String, String), Entry>,
}

impl UnitConfigCache {
    /// The cached config for this unit, if one is still fresh.
    pub(crate) fn get(&self, tenant: &str, bundle_id: &str) -> Option<Option<InteropConfig>> {
        self.get_at(tenant, bundle_id, Instant::now())
    }

    fn get_at(&self, tenant: &str, bundle_id: &str, now: Instant) -> Option<Option<InteropConfig>> {
        let entry = self.entries.get(&key(tenant, bundle_id))?;
        (now.saturating_duration_since(entry.stored_at) < TTL).then(|| entry.config.clone())
    }

    /// Record a successful read (a parsed config, or a confirmed absence).
    pub(crate) fn store(&self, tenant: &str, bundle_id: &str, config: Option<InteropConfig>) {
        self.store_at(tenant, bundle_id, config, Instant::now());
    }

    fn store_at(&self, tenant: &str, bundle_id: &str, config: Option<InteropConfig>, now: Instant) {
        self.entries.insert(
            key(tenant, bundle_id),
            Entry {
                config,
                stored_at: now,
            },
        );
    }
}

fn key(tenant: &str, bundle_id: &str) -> (String, String) {
    (tenant.to_string(), bundle_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> InteropConfig {
        InteropConfig {
            a2a: true,
            ..InteropConfig::default()
        }
    }

    #[test]
    fn a_fresh_entry_is_returned_and_a_stale_one_is_not() {
        let cache = UnitConfigCache::default();
        let now = Instant::now();
        cache.store_at("t", "unit", Some(config()), now);
        assert_eq!(
            cache.get_at("t", "unit", now + Duration::from_secs(29)),
            Some(Some(config()))
        );
        assert_eq!(
            cache.get_at("t", "unit", now + Duration::from_secs(31)),
            None
        );
    }

    /// "Nothing is staged" is a successful read, and caching it is what keeps
    /// a unit with interop off from paying a store read per request.
    #[test]
    fn a_confirmed_absence_is_cached_and_is_not_a_miss() {
        let cache = UnitConfigCache::default();
        let now = Instant::now();
        cache.store_at("t", "unit", None, now);
        assert_eq!(cache.get_at("t", "unit", now), Some(None));
    }

    #[test]
    fn units_and_tenants_do_not_share_an_entry() {
        let cache = UnitConfigCache::default();
        let now = Instant::now();
        cache.store_at("t", "unit", Some(config()), now);
        assert_eq!(cache.get_at("t", "other", now), None);
        assert_eq!(cache.get_at("other", "unit", now), None);
    }

    #[test]
    fn a_later_store_replaces_the_entry() {
        let cache = UnitConfigCache::default();
        let now = Instant::now();
        cache.store_at("t", "unit", Some(config()), now);
        cache.store_at("t", "unit", None, now + Duration::from_secs(1));
        assert_eq!(
            cache.get_at("t", "unit", now + Duration::from_secs(2)),
            Some(None)
        );
    }
}
