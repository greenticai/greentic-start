//! Per-issuer signing keys, with a TTL on what is trusted and a FLOOR on how
//! often the issuer may be asked.
//!
//! The floor is the load-bearing part and it is not the TTL. Reaching a
//! lookup needs only a JWT *header* — `decode_header` runs before any
//! signature check — so an unauthenticated caller can mint
//! `{"alg":"RS256","kid":"<random>"}` with a garbage signature. Keyed on the
//! TTL alone, every one of those is a cache miss for a different `kid` and
//! therefore one outbound request to the admin, each holding a designer task
//! open for the fetch timeout.
//!
//! So there are two clocks per issuer, and they are deliberately separate:
//!
//! - `keys_fetched_at` — when the key set was last REPLACED by a successful
//!   fetch. [`POSITIVE_TTL`] measures from here, and a failed refresh does not
//!   touch it, so an admin blip cannot destroy a working key set and 503 every
//!   legitimate caller for the length of the floor.
//! - `last_attempt_at` — when a fetch was last ATTEMPTED, successful or not.
//!   [`REFRESH_FLOOR`] measures from here, so a failing admin is asked at most
//!   once per floor rather than once per request.
//!
//! `now` is a parameter rather than read inside, so both windows are testable
//! without sleeping.
//!
//! ## The map is unbounded in issuers, and that is deliberate
//!
//! [`MAX_KEYS`] bounds the keys WITHIN one issuer, because `kid` is
//! attacker-chosen. Issuer count is not bounded, because the issuer is not: it
//! is derived from `AppState::admin_endpoint`, a plain field fixed at boot
//! (not an `ArcSwap` like `state.admin`, and assigned nowhere outside tests),
//! so one process can only ever hold ONE entry here.
//!
//! An eight-entry LRU used to guard this in the designer. It could not fire in
//! production, and in its test binary it evicted entries belonging to tests
//! still running — a flake that read as a real regression. Bounding a key
//! space the product cannot express bought nothing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use jsonwebtoken::DecodingKey;

/// How long a successfully fetched key set is trusted. Signing keys rotate on
/// the order of months; ten minutes keeps a rotation propagating promptly
/// while removing the issuer from the per-request path.
pub(super) const POSITIVE_TTL: Duration = Duration::from_secs(600);

/// Minimum interval between outbound JWKS fetches for ONE issuer, whatever the
/// previous attempt's outcome.
///
/// This is what bounds an unknown-`kid` flood and a retry storm against a
/// degraded admin to one request per issuer per window. Thirty seconds matches
/// `tenant_brand::cache::NEGATIVE_TTL`, and is the ceiling on how long a
/// genuine key rotation takes to be picked up — which is why it is thirty
/// seconds and not the ten-minute positive TTL.
pub(super) const REFRESH_FLOOR: Duration = Duration::from_secs(30);

/// What a lookup decided. Three outcomes, because collapsing `Refuse` into
/// `Fetch` is exactly the bug this module exists to prevent: both mean "no key
/// for you", but only one of them may talk to the issuer.
pub(super) enum Lookup {
    /// A trusted key for this `kid`.
    Hit(Arc<DecodingKey>),
    /// No key, and the caller must NOT fetch — the issuer was asked recently.
    Refuse,
    /// No key, and the caller should fetch.
    Fetch,
}

struct Entry {
    keys: HashMap<String, Arc<DecodingKey>>,
    /// `None` when every attempt so far has failed, so nothing is trusted.
    keys_fetched_at: Option<Instant>,
    last_attempt_at: Instant,
}

#[derive(Default)]
pub(super) struct JwksCache {
    entries: DashMap<String, Entry>,
}

impl JwksCache {
    pub(super) fn lookup(&self, issuer: &str, kid: &str, now: Instant) -> Lookup {
        let Some(entry) = self.entries.get(issuer) else {
            return Lookup::Fetch;
        };
        if let Some(fetched_at) = entry.keys_fetched_at
            && now.duration_since(fetched_at) < POSITIVE_TTL
            && let Some(key) = entry.keys.get(kid)
        {
            return Lookup::Hit(Arc::clone(key));
        }
        if now.duration_since(entry.last_attempt_at) < REFRESH_FLOOR {
            return Lookup::Refuse;
        }
        Lookup::Fetch
    }

    /// Record a successful fetch, replacing whatever was held.
    pub(super) fn store_keys(
        &self,
        issuer: &str,
        keys: HashMap<String, Arc<DecodingKey>>,
        now: Instant,
    ) {
        self.entries.insert(
            issuer.to_string(),
            Entry {
                keys,
                keys_fetched_at: Some(now),
                last_attempt_at: now,
            },
        );
    }

    /// Record that a fetch was attempted and failed.
    ///
    /// Bumps `last_attempt_at` ONLY. An existing key set survives, because a
    /// transient admin failure is not evidence that the keys it served a
    /// minute ago went bad — clearing them here would turn one blip into a
    /// window in which every legitimate token is refused.
    pub(super) fn store_failed_attempt(&self, issuer: &str, now: Instant) {
        if let Some(mut entry) = self.entries.get_mut(issuer) {
            entry.last_attempt_at = now;
            return;
        }
        self.entries.insert(
            issuer.to_string(),
            Entry {
                keys: HashMap::new(),
                keys_fetched_at: None,
                last_attempt_at: now,
            },
        );
    }

    /// Test-only: drop ONE issuer's entry.
    ///
    /// Deliberately not a whole-cache `clear()`. Lib tests run in parallel
    /// threads in one process, and this cache is a `LazyLock` static shared by
    /// all of them; a global clear called by any test at any moment wipes the
    /// key set another test is mid-way through counting fetches against. Two
    /// tests here assert an EXACT upstream fetch count, so that is not a
    /// theoretical race — it is an intermittent red whose frequency rises with
    /// every new test that sets up an issuer.
    #[cfg(test)]
    pub(super) fn clear_issuer(&self, issuer: &str) {
        self.entries.remove(issuer);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Arc<DecodingKey> {
        Arc::new(
            DecodingKey::from_rsa_components(
                crate::interop::mcp::testkit::TEST_JWKS_N,
                crate::interop::mcp::testkit::TEST_JWKS_E,
            )
            .expect("test RSA components"),
        )
    }

    fn keyset(kid: &str) -> HashMap<String, Arc<DecodingKey>> {
        HashMap::from([(kid.to_string(), key())])
    }

    fn is_hit(lookup: Lookup) -> bool {
        matches!(lookup, Lookup::Hit(_))
    }

    fn is_refuse(lookup: Lookup) -> bool {
        matches!(lookup, Lookup::Refuse)
    }

    fn is_fetch(lookup: Lookup) -> bool {
        matches!(lookup, Lookup::Fetch)
    }

    #[test]
    fn an_unseen_issuer_is_a_fetch() {
        let cache = JwksCache::default();
        assert!(is_fetch(cache.lookup("iss", "k1", Instant::now())));
    }

    #[test]
    fn a_known_kid_inside_the_positive_ttl_is_a_hit() {
        let now = Instant::now();
        let cache = JwksCache::default();
        cache.store_keys("iss", keyset("k1"), now);
        assert!(is_hit(cache.lookup(
            "iss",
            "k1",
            now + Duration::from_secs(599)
        )));
    }

    /// The finding. Without the floor every one of these is an outbound
    /// request, and the `kid` is chosen by an unauthenticated caller.
    #[test]
    fn an_unknown_kid_inside_the_floor_refuses_without_fetching() {
        let now = Instant::now();
        let cache = JwksCache::default();
        cache.store_keys("iss", keyset("k1"), now);
        assert!(is_refuse(cache.lookup(
            "iss",
            "attacker-chosen",
            now + Duration::from_secs(29)
        )));
    }

    /// The floor must not become a rotation blackout: a `kid` that appeared
    /// after our last fetch has to be reachable, and thirty seconds is the
    /// whole cost of it.
    #[test]
    fn an_unknown_kid_past_the_floor_fetches_again() {
        let now = Instant::now();
        let cache = JwksCache::default();
        cache.store_keys("iss", keyset("k1"), now);
        assert!(is_fetch(cache.lookup(
            "iss",
            "rotated-in",
            now + Duration::from_secs(31)
        )));
    }

    #[test]
    fn a_known_kid_past_the_positive_ttl_is_refetched() {
        let now = Instant::now();
        let cache = JwksCache::default();
        cache.store_keys("iss", keyset("k1"), now);
        assert!(is_fetch(cache.lookup(
            "iss",
            "k1",
            now + Duration::from_secs(601)
        )));
    }

    /// A failing admin must be asked once per floor, not once per request.
    #[test]
    fn a_failed_attempt_holds_the_floor_against_a_retry_storm() {
        let now = Instant::now();
        let cache = JwksCache::default();
        cache.store_failed_attempt("iss", now);
        assert!(is_refuse(cache.lookup(
            "iss",
            "k1",
            now + Duration::from_secs(29)
        )));
        assert!(is_fetch(cache.lookup(
            "iss",
            "k1",
            now + Duration::from_secs(31)
        )));
    }

    /// A blip must not cost every legitimate caller their token. The keys
    /// stay trusted for the rest of their own TTL; only the retry rate moves.
    #[test]
    fn a_failed_attempt_does_not_discard_a_working_key_set() {
        let now = Instant::now();
        let cache = JwksCache::default();
        cache.store_keys("iss", keyset("k1"), now);
        cache.store_failed_attempt("iss", now + Duration::from_secs(60));
        assert!(is_hit(cache.lookup(
            "iss",
            "k1",
            now + Duration::from_secs(61)
        )));
    }

    /// There is deliberately NO cap on issuer count, and no eviction — this
    /// pins that a second issuer does not displace the first.
    ///
    /// A `MAX_ISSUERS = 8` cap with LRU eviction used to live here, in the
    /// designer. It was unreachable in production and actively harmful in
    /// tests, where issuers are per-test: past 8, eviction by `last_attempt_at`
    /// could drop an entry belonging to a test still running, and the tests
    /// asserting an exact upstream fetch count then saw a second fetch.
    ///
    /// If a multi-issuer deployment ever exists, the bound it needs must be
    /// designed against a real key space rather than restored from here.
    #[test]
    fn a_second_issuer_does_not_displace_the_first() {
        let now = Instant::now();
        let cache = JwksCache::default();
        for i in 0..32 {
            cache.store_keys(&format!("iss-{i}"), keyset("k1"), now);
        }
        assert_eq!(cache.len(), 32, "no issuer may be evicted");
        assert!(
            matches!(cache.lookup("iss-0", "k1", now), Lookup::Hit(_)),
            "the FIRST issuer stored must still be present — eviction was by \
             `last_attempt_at`, so this is the entry a cap would have dropped"
        );
    }
}
