//! The Bot Framework signing keys, fetched from Microsoft and cached.
//!
//! This path is reachable by an unauthenticated caller who chooses the cache
//! key (a token's `kid` is read before any signature check), so it carries the
//! same two guards as the MCP key set ([`crate::jwks_cache`]): a refresh FLOOR
//! (one fetch per 30 s whatever the `kid`) and in-flight coalescing (N cold
//! callers, one fetch). Beyond that, the fetch itself is locked down, because
//! the document it reads names the next URL:
//!
//! - the client resolves names through the artifacts public-only resolver,
//!   uses no proxy, follows no redirect, speaks https only, and gives up after
//!   [`FETCH_TIMEOUT`];
//! - every body is read with a [`MAX_BODY_BYTES`] cap;
//! - the `jwks_uri` from the metadata is accepted only when it is https on
//!   exactly [`BF_KEY_HOST`] with no userinfo and no port;
//! - only RSA keys usable for RS256 are kept, at most [`MAX_KEYS`], each with
//!   its `endorsements` (the channels it may sign for).
//!
//! Public cloud only: the US Government cloud (`api.botframework.us`) and the
//! Emulator issuer are not served.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use tokio::sync::broadcast;

use crate::jwks_cache::{CachePolicy, JwksCache, Lookup, StaleKeys};

pub(crate) const BF_METADATA_URL: &str =
    "https://login.botframework.com/v1/.well-known/openidconfiguration";
pub(crate) const BF_KEY_HOST: &str = "login.botframework.com";
pub(crate) const BF_ISSUER: &str = "https://api.botframework.com";

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_KEYS: usize = 32;

/// How old a key set may be and still verify a `kid` it carries once a
/// refresh has FAILED. Without it an outage longer than the 12 h TTL turned
/// every Teams activity, forged ones included, into "admitted unverified".
/// Bot Framework signing keys rotate on the order of weeks, so a week-old set
/// still verifies genuine tokens; past this age it is not used at all.
pub(crate) const STALE_KEY_SET_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

/// Bot Framework asks for a refresh at least every 24 h; 12 h keeps inside
/// that with room, and the 30 s floor bounds unknown-`kid` traffic.
const POLICY: CachePolicy = CachePolicy {
    positive_ttl: Duration::from_secs(12 * 3600),
    refresh_floor: Duration::from_secs(30),
    stale_max_age: Some(STALE_KEY_SET_MAX_AGE),
};

/// One signing key and the channel ids it is endorsed for.
#[derive(Clone)]
pub(crate) struct BfKey {
    pub key: Arc<DecodingKey>,
    pub endorsements: Arc<[String]>,
}

pub(crate) enum BfKeyLookup {
    Found(BfKey),
    /// The key set was read and does not carry this `kid`.
    UnknownKid,
    /// The key set could not be read.
    Unavailable,
}

/// Where the keys may come from. Production: https on exactly
/// [`BF_KEY_HOST`], default port only.
struct KeyHostRule {
    host: String,
    https_only: bool,
    allow_port: bool,
}

pub(crate) struct BfKeySource {
    client: reqwest::Client,
    metadata_url: String,
    rule: KeyHostRule,
    cache: JwksCache<BfKey>,
    in_flight: DashMap<String, broadcast::Sender<()>>,
}

impl BfKeySource {
    /// The process-wide source. `None` when the client cannot be built; the
    /// caller then treats every Teams request as unverifiable.
    pub(crate) fn production() -> Option<&'static BfKeySource> {
        static SOURCE: LazyLock<Option<BfKeySource>> = LazyLock::new(|| {
            install_crypto_provider();
            let builder =
                crate::artifacts::dns::with_public_only_resolver(base_builder()).https_only(true);
            match builder.build() {
                Ok(client) => Some(BfKeySource::new(
                    client,
                    BF_METADATA_URL.to_string(),
                    KeyHostRule {
                        host: BF_KEY_HOST.to_string(),
                        https_only: true,
                        allow_port: false,
                    },
                )),
                Err(err) => {
                    crate::operator_log::error(
                        module_path!(),
                        format!(
                            "no HTTP client for the Bot Framework key set ({err}); \
                             Microsoft Teams requests cannot be verified"
                        ),
                    );
                    None
                }
            }
        });
        SOURCE.as_ref()
    }

    fn new(client: reqwest::Client, metadata_url: String, rule: KeyHostRule) -> Self {
        Self {
            client,
            metadata_url,
            rule,
            cache: JwksCache::new(POLICY),
            in_flight: DashMap::new(),
        }
    }

    /// A source over plain-http loopback stubs: the production client
    /// settings minus `https_only` and the public-only resolver, unless the
    /// test supplies its own client.
    #[cfg(test)]
    pub(crate) fn for_tests(
        metadata_url: String,
        allowed_host: String,
        client: Option<reqwest::Client>,
    ) -> Self {
        install_crypto_provider();
        let client =
            client.unwrap_or_else(|| base_builder().build().expect("test Bot Framework client"));
        Self::new(
            client,
            metadata_url,
            KeyHostRule {
                host: allowed_host,
                https_only: false,
                allow_port: true,
            },
        )
    }

    /// The production client settings, for a test to add its own resolver.
    #[cfg(test)]
    pub(crate) fn test_client_builder() -> reqwest::ClientBuilder {
        install_crypto_provider();
        base_builder()
    }

    /// A key for `kid`. `UnknownKid` only when a TRUSTED key set (read within
    /// its TTL) lacks it. With none held, a refresh that failed (or that the
    /// floor holds back after a failure) falls back to an EXPIRED set younger
    /// than [`STALE_KEY_SET_MAX_AGE`]: a `kid` it carries is `Found` and is
    /// verified against it, anything else is `Unavailable`. So an outage never
    /// refuses a genuine token, and a follower of a successful fetch never
    /// admits a forged one.
    pub(crate) async fn key(&self, kid: &str) -> BfKeyLookup {
        self.key_at(kid, Instant::now).await
    }

    /// [`Self::key`] with the clock as a parameter, so the TTL and the stale
    /// limit are testable without a host up for a week.
    pub(crate) async fn key_at(&self, kid: &str, now: impl Fn() -> Instant) -> BfKeyLookup {
        let space = self.metadata_url.as_str();
        match self.cache.lookup(space, kid, now()) {
            Lookup::Hit(key) => return BfKeyLookup::Found(key),
            Lookup::Refuse => return self.miss(space, kid, now()),
            Lookup::Fetch => {}
        }
        self.refresh_once(&now).await;
        match self.cache.lookup(space, kid, now()) {
            Lookup::Hit(key) => BfKeyLookup::Found(key),
            _ => self.miss(space, kid, now()),
        }
    }

    fn miss(&self, space: &str, kid: &str, now: Instant) -> BfKeyLookup {
        if self.cache.has_trusted_keys(space, now) {
            return BfKeyLookup::UnknownKid;
        }
        match self.cache.stale_keys(space, kid, now) {
            StaleKeys::Known(key) => BfKeyLookup::Found(key),
            StaleKeys::Lacks | StaleKeys::None => BfKeyLookup::Unavailable,
        }
    }

    /// At most one fetch across concurrent callers (same shape as the MCP
    /// key set's `refresh_once`). The outcome is read back from the cache.
    async fn refresh_once(&self, now: &impl Fn() -> Instant) {
        let space = self.metadata_url.clone();
        // The shard guard is released at the end of this match, before any
        // await.
        let (mut receiver, leader) = match self.in_flight.entry(space.clone()) {
            dashmap::mapref::entry::Entry::Occupied(entry) => (entry.get().subscribe(), None),
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                let (tx, rx) = broadcast::channel(1);
                entry.insert(tx.clone());
                (rx, Some(tx))
            }
        };
        let Some(tx) = leader else {
            let _ =
                tokio::time::timeout(2 * FETCH_TIMEOUT + Duration::from_secs(1), receiver.recv())
                    .await;
            return;
        };
        // Drops LAST, after the cache write and the broadcast, on every exit.
        let _guard = InFlightGuard {
            map: &self.in_flight,
            key: space.clone(),
        };
        let fetched = self.fetch().await;
        let now = now();
        match fetched {
            Some(keys) => self.cache.store_keys(&space, keys, now),
            None => self.cache.store_failed_attempt(&space, now),
        }
        let _ = tx.send(());
    }

    async fn fetch(&self) -> Option<HashMap<String, BfKey>> {
        let metadata: Metadata =
            serde_json::from_slice(&self.get(&self.metadata_url).await?).ok()?;
        if !metadata
            .id_token_signing_alg_values_supported
            .iter()
            .any(|alg| alg == "RS256")
        {
            warn("the Bot Framework metadata does not offer RS256");
            return None;
        }
        let jwks_uri = self.accept_jwks_uri(&metadata.jwks_uri)?;
        let set: JwkSet = serde_json::from_slice(&self.get(jwks_uri.as_str()).await?).ok()?;
        Some(keep_usable(set))
    }

    /// The `jwks_uri` only when it points where the rule allows.
    fn accept_jwks_uri(&self, raw: &str) -> Option<reqwest::Url> {
        let Ok(url) = reqwest::Url::parse(raw) else {
            warn("the Bot Framework metadata names an unreadable key URL");
            return None;
        };
        let scheme_ok =
            url.scheme() == "https" || (!self.rule.https_only && url.scheme() == "http");
        let host_ok = url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case(&self.rule.host));
        let userinfo_ok = url.username().is_empty() && url.password().is_none();
        let port_ok = self.rule.allow_port || url.port().is_none();
        if scheme_ok && host_ok && userinfo_ok && port_ok {
            return Some(url);
        }
        // The rejected HOST only — never the whole URL.
        let host = url.host_str().unwrap_or("<none>").to_string();
        warn(&format!(
            "the Bot Framework metadata names a key URL on a host this host does not \
             trust ({host}); Microsoft Teams requests are admitted unverified"
        ));
        None
    }

    /// GET with the body capped at [`MAX_BODY_BYTES`]. `None` for any
    /// failure, a non-success status (a redirect included) or an oversized
    /// body.
    async fn get(&self, url: &str) -> Option<Vec<u8>> {
        let mut response = self.client.get(url).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_BODY_BYTES as u64)
        {
            return None;
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return None;
            }
            body.extend_from_slice(&chunk);
        }
        Some(body)
    }
}

impl std::fmt::Debug for BfKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BfKeySource")
            .field("metadata_url", &self.metadata_url)
            .finish_non_exhaustive()
    }
}

struct InFlightGuard<'a> {
    map: &'a DashMap<String, broadcast::Sender<()>>,
    key: String,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

#[derive(Deserialize)]
struct Metadata {
    jwks_uri: String,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: Option<String>,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
    #[serde(default)]
    endorsements: Vec<String>,
}

fn keep_usable(set: JwkSet) -> HashMap<String, BfKey> {
    let mut keys = HashMap::new();
    for jwk in set.keys.into_iter().take(MAX_KEYS) {
        // RSA only, and RS256 when an algorithm is named: a symmetric key here
        // would let anyone holding the "public" key mint tokens.
        if jwk.kty.as_deref() != Some("RSA") {
            continue;
        }
        if jwk.alg.as_deref().is_some_and(|alg| alg != "RS256") {
            continue;
        }
        let (Some(kid), Some(n), Some(e)) = (jwk.kid, jwk.n, jwk.e) else {
            continue;
        };
        let Ok(key) = DecodingKey::from_rsa_components(&n, &e) else {
            continue;
        };
        keys.insert(
            kid,
            BfKey {
                key: Arc::new(key),
                endorsements: jwk.endorsements.into(),
            },
        );
    }
    keys
}

fn base_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .connect_timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
}

/// This binary carries both `ring` and `aws-lc-rs`, so rustls needs a process
/// default before any client is built (same as the MCP key set's client).
fn install_crypto_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn warn(line: &str) {
    crate::operator_log::warn(module_path!(), line);
}

#[cfg(test)]
#[path = "bf_keys_tests.rs"]
mod tests;
