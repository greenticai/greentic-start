//! Fetches and caches the authorization server's JWKS.
//!
//! Ported from greentic-designer's `src/ui/mcp_server/auth/jwks/`, whose own
//! reasoning is kept because both surfaces face the same caller.
//!
//! Two guards, both because this path is reachable by an unauthenticated
//! caller who chooses the cache key:
//!
//! - a **refresh floor** per issuer ([`cache`]), so an unknown `kid` and a
//!   failing admin each cost at most one outbound request per window rather
//!   than one per HTTP request;
//! - **in-flight coalescing**, so N concurrent cold callers issue ONE upstream
//!   fetch between them instead of N.
//!
//! Fail-closed: a fetch failure, a malformed document, or an absent `kid`
//! yields `None`, and the caller refuses the request. The failure mode being
//! guarded against is accepting a TURN on a signature this process could not
//! verify.

mod cache;

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use tokio::sync::broadcast;

use cache::{JwksCache, Lookup};

/// This fetch sits inside a request the caller is waiting on, so a slow issuer
/// must become a refusal quickly rather than holding a task open for half a
/// minute per request while a client retries.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounded so a hostile or misconfigured issuer serving an unbounded key set
/// cannot grow one cache entry without limit.
const MAX_KEYS: usize = 32;

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    kty: Option<String>,
}

static CACHE: LazyLock<JwksCache> = LazyLock::new(JwksCache::default);

/// The outbound client, built once.
///
/// `None` when it could not be built, which refuses every token rather than
/// panicking on a request path. The rustls crypto provider is installed first
/// for the reason [`crate::redis_tls::ensure_crypto_provider_for`] documents:
/// this binary carries both `ring` and `aws-lc-rs`, so rustls cannot
/// auto-select one and the builder panics without a process default.
static CLIENT: LazyLock<Option<reqwest::Client>> = LazyLock::new(|| {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    match reqwest::Client::builder().timeout(FETCH_TIMEOUT).build() {
        Ok(client) => Some(client),
        Err(err) => {
            crate::operator_log::warn(
                module_path!(),
                format!("MCP: no HTTP client for JWKS fetches ({err}); refusing OAuth tokens"),
            );
            None
        }
    }
});

/// In-flight refreshes, keyed by issuer, so concurrent callers for one cold
/// issuer issue one admin request between them rather than one each.
static IN_FLIGHT: LazyLock<DashMap<String, broadcast::Sender<()>>> = LazyLock::new(DashMap::new);

/// Removes an issuer's in-flight entry when the leader ends, however it ends.
///
/// A plain cleanup statement is skipped on panic or task cancellation, and a
/// leaked entry here is not merely a leak: later callers subscribe to a sender
/// nobody will ever send on, and since the slot never returns to vacant, no
/// caller can take over as leader either. That issuer would stop being
/// refreshable for the life of the process — which, on this path, means every
/// token refused once the current key set expires.
struct InFlightGuard(String);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        IN_FLIGHT.remove(&self.0);
    }
}

/// What a key lookup decided.
///
/// Three outcomes, not two, and this is the one place this port DIFFERS from
/// greentic-designer's: there, every failure collapses to `None` and the gate
/// answers `503`. An unknown `kid` is the commonest shape of a garbage token
/// — `decode_header` runs before any signature check, so an unauthenticated
/// caller chooses it — and reporting that as "the authorization server is
/// down" both misleads the operator and invites a client to retry. A key set
/// this issuer HAS served and that does not carry the `kid` is a fact about
/// the token, so it is a `401`.
pub(crate) enum KeyLookup {
    Found(Arc<DecodingKey>),
    /// The issuer's key set was read and carries no such `kid`.
    UnknownKid,
    /// The key set could not be read at all.
    Unavailable,
}

/// Resolve the decoding key for `kid` from `issuer`'s JWKS.
pub(crate) async fn decoding_key(issuer: &str, kid: &str) -> KeyLookup {
    match CACHE.lookup(issuer, kid, Instant::now()) {
        Lookup::Hit(key) => return KeyLookup::Found(key),
        Lookup::Refuse => {
            tracing::debug!(
                %issuer,
                %kid,
                "MCP token names a kid this issuer's cached key set does not carry; \
                 refusing without re-asking the issuer"
            );
            return KeyLookup::UnknownKid;
        }
        Lookup::Fetch => {}
    }

    let fetched = refresh_once(issuer).await;

    match CACHE.lookup(issuer, kid, Instant::now()) {
        Lookup::Hit(key) => KeyLookup::Found(key),
        // A fetch this task LED and that succeeded means the issuer's current
        // key set genuinely has no such `kid`. A follower cannot tell, and
        // takes the conservative answer.
        _ if fetched == Some(true) => KeyLookup::UnknownKid,
        _ => KeyLookup::Unavailable,
    }
}

/// Refresh `issuer`'s key set, at most once across all concurrent callers.
///
/// Returns once the cache reflects an attempt — either this task's, or the
/// leader's that this task waited on. `Some(ok)` when THIS task led the fetch
/// and whether it succeeded; `None` for a follower, which cannot know.
async fn refresh_once(issuer: &str) -> Option<bool> {
    // The shard guard the `entry` API holds is released at the end of this
    // match, BEFORE the await below. Holding one across an await is how a
    // DashMap deadlocks against its own later readers.
    let (mut receiver, leader) = match IN_FLIGHT.entry(issuer.to_string()) {
        dashmap::mapref::entry::Entry::Occupied(entry) => (entry.get().subscribe(), None),
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            let (tx, rx) = broadcast::channel(1);
            entry.insert(tx.clone());
            (rx, Some(tx))
        }
    };

    let Some(tx) = leader else {
        // A follower. Bounded by the leader's own fetch timeout plus a margin,
        // so a leader that somehow never publishes cannot park this task: the
        // wait failing simply means the cache is re-read as it stands, which
        // refuses.
        let _ = tokio::time::timeout(FETCH_TIMEOUT + Duration::from_secs(1), receiver.recv()).await;
        return None;
    };

    // Declared before the work so it drops LAST — after the cache write and
    // after the broadcast. A caller arriving in that window reads the warm
    // cache rather than taking over as leader for a fetch just completed.
    let _guard = InFlightGuard(issuer.to_string());
    let fetched = fetch(issuer).await;
    let now = Instant::now();
    let ok = match fetched {
        Some(keys) => {
            CACHE.store_keys(issuer, keys, now);
            true
        }
        // Recorded, not dropped: the floor is what stops a degraded issuer
        // being asked again by the very next request.
        None => {
            CACHE.store_failed_attempt(issuer, now);
            false
        }
    };
    let _ = tx.send(());
    Some(ok)
}

/// One outbound fetch. `None` for every failure; the key set otherwise, which
/// may legitimately be empty.
async fn fetch(issuer: &str) -> Option<HashMap<String, Arc<DecodingKey>>> {
    let url = jwks_url(issuer);
    let client = CLIENT.as_ref()?;
    let body = match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(body) => body,
            Err(err) => {
                tracing::warn!(%url, %err, "MCP JWKS body unreadable; refusing tokens from this issuer");
                return None;
            }
        },
        Ok(resp) => {
            tracing::warn!(%url, status = %resp.status(), "MCP JWKS fetch failed; refusing tokens from this issuer");
            return None;
        }
        Err(err) => {
            tracing::warn!(%url, %err, "MCP JWKS unreachable; refusing tokens from this issuer");
            return None;
        }
    };

    let Ok(set) = serde_json::from_str::<JwkSet>(&body) else {
        tracing::warn!(
            %url,
            "MCP JWKS is not a readable key set; refusing tokens from this issuer"
        );
        return None;
    };

    let mut keys = HashMap::new();
    for jwk in set.keys.into_iter().take(MAX_KEYS) {
        // RS256 only. An issuer offering a symmetric key here would let anyone
        // holding the "public" key mint tokens, and an issuer offering an
        // unrelated asymmetric family would be decoded against a validation
        // that only ever asks for RS256 anyway.
        if jwk.alg.as_deref().is_some_and(|alg| alg != "RS256") {
            continue;
        }
        if jwk.kty.as_deref().is_some_and(|kty| kty != "RSA") {
            continue;
        }
        let (Some(kid), Some(n), Some(e)) = (jwk.kid, jwk.n, jwk.e) else {
            continue;
        };
        if let Ok(key) = DecodingKey::from_rsa_components(&n, &e) {
            keys.insert(kid, Arc::new(key));
        }
    }
    Some(keys)
}

/// Where this resource server looks for `issuer`'s signing keys.
///
/// **Hardcoded, and that is a cross-repo requirement rather than a
/// derivation.** RFC 8414 has a resource server read `jwks_uri` from the
/// authorization server's own metadata document; doing that here would be a
/// second discovery hop on the cold path, and the spec's §7.1 only requires
/// the CLIENT to fetch that document. So the designer requires
/// greentic-designer-admin to serve its key set at this exact path — recorded
/// in §7.2 of `docs/superpowers/specs/2026-08-21-mcp-server-design.md`,
/// because the failure if it does not is every request answering `503` with
/// nothing naming the reason.
fn jwks_url(issuer: &str) -> String {
    format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/'))
}

/// Test-only: drop ONE issuer's cached key set and in-flight slot.
///
/// Both stores are process-global and lib tests share a process, so a test
/// must clear its own issuer before use — `MockServer` reuses ephemeral ports
/// across a binary's lifetime, so a previous test's key set can otherwise
/// answer this one's request.
///
/// Scoped to the issuer rather than clearing everything, because two tests in
/// this module assert an EXACT number of upstream fetches. A global clear
/// running concurrently drops the key set they just warmed and they count a
/// second fetch — which is what they were written to detect, so the failure
/// reads as a real regression in the refresh floor rather than as the test
/// interference it is.
#[cfg(test)]
pub(crate) fn clear_issuer_for_tests(issuer: &str) {
    CACHE.clear_issuer(issuer);
    IN_FLIGHT.remove(issuer);
}
