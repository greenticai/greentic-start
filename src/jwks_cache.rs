//! Per-issuer (per key-space) signing keys, with a TTL on what is trusted and
//! a FLOOR on how often the issuer may be asked.
//!
//! Shared by the MCP resource server ([`crate::interop::mcp::jwks`], keys are
//! `Arc<DecodingKey>`) and the Bot Framework verifier
//! ([`crate::inbound_verify`], keys carry their channel endorsements), so the
//! two cannot drift on the floor/TTL rules. The cached value is generic and
//! the two durations are a [`CachePolicy`] chosen by each caller.
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
//!   fetch. The policy's `positive_ttl` measures from here, and a failed refresh does not
//!   touch it, so an admin blip cannot destroy a working key set and 503 every
//!   legitimate caller for the length of the floor.
//! - `last_attempt_at` — when a fetch was last ATTEMPTED, successful or not.
//!   The policy's `refresh_floor` measures from here, so a failing admin is asked at most
//!   once per floor rather than once per request.
//!
//! `now` is a parameter rather than read inside, so both windows are testable
//! without sleeping.
//!
//! ## The map is unbounded in issuers, and that is deliberate
//!
//! Each caller bounds the keys WITHIN one issuer (`MAX_KEYS`), because `kid` is
//! attacker-chosen. Issuer count is not bounded, because the issuer is not: it
//! is fixed by the caller — the MCP issuer is derived from a value fixed at
//! boot, and the Bot Framework key space is one constant metadata URL — so
//! one process holds at most one entry per caller here.
//!
//! An eight-entry LRU used to guard this in the designer. It could not fire in
//! production, and in its test binary it evicted entries belonging to tests
//! still running — a flake that read as a real regression. Bounding a key
//! space the product cannot express bought nothing.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// The two clocks a caller chooses.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CachePolicy {
    /// How long a successfully fetched key set is trusted.
    pub positive_ttl: Duration,
    /// Minimum interval between outbound fetches for ONE key space, whatever
    /// the previous attempt's outcome.
    ///
    /// This is what bounds an unknown-`kid` flood and a retry storm against a
    /// degraded issuer to one request per window, and it is the ceiling on how
    /// long a genuine key rotation takes to be picked up.
    pub refresh_floor: Duration,
    /// How long PAST `positive_ttl` an expired key set may still be read, as
    /// a fallback the caller asks for only after a refresh failed
    /// ([`JwksCache::stale_keys`]). `None` (MCP) means never: past the TTL the
    /// set is gone. Measured from `keys_fetched_at`, so it is an absolute age.
    pub stale_max_age: Option<Duration>,
}

/// What a lookup decided. Three outcomes, because collapsing `Refuse` into
/// `Fetch` is exactly the bug this module exists to prevent: both mean "no key
/// for you", but only one of them may talk to the issuer.
pub(crate) enum Lookup<V> {
    /// A trusted key for this `kid`.
    Hit(V),
    /// No key, and the caller must NOT fetch — the issuer was asked recently.
    Refuse,
    /// No key, and the caller should fetch.
    Fetch,
}

/// What an EXPIRED key set says about a `kid` ([`JwksCache::stale_keys`]).
pub(crate) enum StaleKeys<V> {
    /// The expired set carries this `kid`.
    Known(V),
    /// An expired set is held and lacks this `kid`. That proves nothing (the
    /// set may predate a rotation), so it is not a refusal.
    Lacks,
    /// No expired set usable as a fallback: none held, the set is still
    /// fresh, it is older than `stale_max_age`, or the policy keeps none.
    None,
}

struct Entry<V> {
    keys: HashMap<String, V>,
    /// `None` when every attempt so far has failed, so nothing is trusted.
    keys_fetched_at: Option<Instant>,
    last_attempt_at: Instant,
}

pub(crate) struct JwksCache<V: Clone> {
    policy: CachePolicy,
    entries: DashMap<String, Entry<V>>,
}

impl<V: Clone> JwksCache<V> {
    pub(crate) fn new(policy: CachePolicy) -> Self {
        Self {
            policy,
            entries: DashMap::new(),
        }
    }

    pub(crate) fn lookup(&self, issuer: &str, kid: &str, now: Instant) -> Lookup<V> {
        let Some(entry) = self.entries.get(issuer) else {
            return Lookup::Fetch;
        };
        if let Some(fetched_at) = entry.keys_fetched_at
            && now.duration_since(fetched_at) < self.policy.positive_ttl
            && let Some(key) = entry.keys.get(kid)
        {
            return Lookup::Hit(key.clone());
        }
        if now.duration_since(entry.last_attempt_at) < self.policy.refresh_floor {
            return Lookup::Refuse;
        }
        Lookup::Fetch
    }

    /// Whether a key set read successfully within the positive TTL is held
    /// for `issuer`. A miss against such a set PROVES the `kid` is not the
    /// issuer's; a miss with none proves nothing (the issuer may be down).
    pub(crate) fn has_trusted_keys(&self, issuer: &str, now: Instant) -> bool {
        self.entries.get(issuer).is_some_and(|entry| {
            entry
                .keys_fetched_at
                .is_some_and(|at| now.duration_since(at) < self.policy.positive_ttl)
        })
    }

    /// The fallback read of a key set past its TTL but younger than the
    /// policy's `stale_max_age`. Only for a caller whose refresh failed.
    pub(crate) fn stale_keys(&self, issuer: &str, kid: &str, now: Instant) -> StaleKeys<V> {
        let Some(max_age) = self.policy.stale_max_age else {
            return StaleKeys::None;
        };
        let Some(entry) = self.entries.get(issuer) else {
            return StaleKeys::None;
        };
        let Some(fetched_at) = entry.keys_fetched_at else {
            return StaleKeys::None;
        };
        let age = now.duration_since(fetched_at);
        if age < self.policy.positive_ttl || age >= max_age {
            return StaleKeys::None;
        }
        match entry.keys.get(kid) {
            Some(key) => StaleKeys::Known(key.clone()),
            None => StaleKeys::Lacks,
        }
    }

    /// Record a successful fetch, replacing whatever was held.
    pub(crate) fn store_keys(&self, issuer: &str, keys: HashMap<String, V>, now: Instant) {
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
    pub(crate) fn store_failed_attempt(&self, issuer: &str, now: Instant) {
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
    pub(crate) fn clear_issuer(&self, issuer: &str) {
        self.entries.remove(issuer);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::DecodingKey;
    use std::sync::Arc;

    /// The MCP policy, which these tests were written against.
    const MCP: CachePolicy = CachePolicy {
        positive_ttl: Duration::from_secs(600),
        refresh_floor: Duration::from_secs(30),
        stale_max_age: None,
    };

    fn mcp_cache() -> JwksCache<Arc<DecodingKey>> {
        JwksCache::new(MCP)
    }

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

    fn is_hit<V>(lookup: Lookup<V>) -> bool {
        matches!(lookup, Lookup::Hit(_))
    }

    fn is_refuse<V>(lookup: Lookup<V>) -> bool {
        matches!(lookup, Lookup::Refuse)
    }

    fn is_fetch<V>(lookup: Lookup<V>) -> bool {
        matches!(lookup, Lookup::Fetch)
    }

    #[test]
    fn an_unseen_issuer_is_a_fetch() {
        let cache = mcp_cache();
        assert!(is_fetch(cache.lookup("iss", "k1", Instant::now())));
    }

    #[test]
    fn a_known_kid_inside_the_positive_ttl_is_a_hit() {
        let now = Instant::now();
        let cache = mcp_cache();
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
        let cache = mcp_cache();
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
        let cache = mcp_cache();
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
        let cache = mcp_cache();
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
        let cache = mcp_cache();
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
        let cache = mcp_cache();
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
        let cache = mcp_cache();
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

    /// The MCP policy keeps NO stale fallback: past the TTL its set is gone,
    /// whatever happened to the refresh.
    #[test]
    fn the_mcp_policy_never_serves_a_stale_key_set() {
        let now = Instant::now();
        let cache = mcp_cache();
        cache.store_keys("iss", keyset("k1"), now);
        cache.store_failed_attempt("iss", now + Duration::from_secs(601));
        assert!(matches!(
            cache.stale_keys("iss", "k1", now + Duration::from_secs(602)),
            StaleKeys::None
        ));
    }

    fn stale_policy() -> CachePolicy {
        CachePolicy {
            positive_ttl: Duration::from_secs(600),
            refresh_floor: Duration::from_secs(30),
            stale_max_age: Some(Duration::from_secs(3600)),
        }
    }

    #[test]
    fn a_stale_policy_serves_an_expired_set_up_to_its_limit() {
        let now = Instant::now();
        let cache = JwksCache::new(stale_policy());
        cache.store_keys("iss", keyset("k1"), now);
        let later = now + Duration::from_secs(601);
        assert!(matches!(
            cache.stale_keys("iss", "k1", later),
            StaleKeys::Known(_)
        ));
        assert!(matches!(
            cache.stale_keys("iss", "other", later),
            StaleKeys::Lacks
        ));
        assert!(matches!(
            cache.stale_keys("iss", "k1", now + Duration::from_secs(3600)),
            StaleKeys::None
        ));
        // A FRESH set is not "stale": the caller reads it through `lookup`.
        assert!(matches!(
            cache.stale_keys("iss", "k1", now + Duration::from_secs(1)),
            StaleKeys::None
        ));
    }

    /// A longer policy (Bot Framework keeps keys for hours) trusts a key set
    /// past the MCP window while keeping the same floor.
    #[test]
    fn a_longer_policy_keeps_keys_past_the_mcp_window() {
        let now = Instant::now();
        let cache = JwksCache::new(CachePolicy {
            positive_ttl: Duration::from_secs(12 * 3600),
            refresh_floor: Duration::from_secs(30),
            stale_max_age: None,
        });
        cache.store_keys("iss", keyset("k1"), now);
        assert!(is_hit(cache.lookup(
            "iss",
            "k1",
            now + Duration::from_secs(601)
        )));
        assert!(is_refuse(cache.lookup(
            "iss",
            "other",
            now + Duration::from_secs(29)
        )));
    }
}
