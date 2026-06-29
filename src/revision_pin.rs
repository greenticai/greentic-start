//! Revision pin store (B6) — `plans/next-gen-deployment.md` §1329.
//!
//! Backs the [`RevisionDispatcher`](crate::revision_dispatcher) session pin
//! map. B1 inlined the in-memory map; B6 extracts a trait so a horizontally
//! scaled router (Phase D K8s slice) can share pins across pods via Redis.
//!
//! Two implementations:
//!
//! - [`InMemoryPinStore`] — single-process map with the same bound + eviction
//!   discipline B1 shipped (`MAX_PINS = 16_384`, soonest-expiry eviction,
//!   generation-aware drop on lookup).
//! - [`RedisPinStore`] — one key per pin under `gt:rev_pin:{env}:{deployment_id}:{tenant}:{hint}`
//!   inserted by a Lua script that atomically (a) returns the existing pin
//!   when one is live, (b) enforces a per-`(env, deployment, tenant)`
//!   cardinality cap, (c) writes the pin + tracks it in a TTL'd set, all in
//!   one round-trip. The Lua script collapses what would otherwise be a
//!   SET-NX-then-GET race (where a stale-generation delete + retry could
//!   silently drop the new pin) and is the only safe shape on a shared
//!   Redis. Works on any Redis ≥ 2.6.
//!
//! Selection between backends is a caller concern. Default
//! [`RevisionDispatcher::new`](crate::revision_dispatcher::RevisionDispatcher::new)
//! constructs an [`InMemoryPinStore`]; production deployments inject a
//! [`RedisPinStore`] via
//! [`RevisionDispatcher::with_pin_store`](crate::revision_dispatcher::RevisionDispatcher::with_pin_store).

// `RedisPinStore` has a live boot caller behind `PIN_REDIS_URL_ENV` (B2), but
// its tuning setters (`with_op_timeout`, `with_cardinality_cap`) are exercised
// only from tests. Same shape as `revision_dispatcher`'s pre-B3
// `#![allow(dead_code)]`.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use greentic_deploy_spec::{DeploymentId, RevisionId};
use redis::aio::ConnectionManager;
use ulid::Ulid;

/// Hard cap on the [`InMemoryPinStore`] map. This is a process-global cap
/// (not per-tenant), acceptable for single-process / `local` deployments
/// where one tenant is unlikely to exhaust the dispatcher's memory.
/// Horizontally scaled deployments use [`RedisPinStore`], which enforces
/// per-`(env, deployment, tenant)` isolation via [`MAX_PINS_PER_TENANT`].
pub(crate) const MAX_PINS: usize = 16_384;

/// Cap on the number of live pins per `(env, deployment, tenant)` on the
/// Redis backend. One tenant's rotating-hint client can't exhaust shared
/// Redis memory because the cap is scoped, not global. A rate-budget per
/// tenant is Phase D once session-aware ingress wires hints through.
pub(crate) const MAX_PINS_PER_TENANT: usize = 4_096;

/// Cap on caller-supplied scope strings (tenant, hint) at the trait
/// boundary. Defends against pathological clients that would otherwise
/// produce unbounded Redis keys.
const MAX_SCOPE_BYTES: usize = 256;

/// Default deadline for a single Redis operation in the dispatch path.
/// On timeout, the backend soft-falls through to no-pin behavior rather
/// than queueing dispatch behind a slow Redis.
const REDIS_OP_TIMEOUT: Duration = Duration::from_millis(50);

const REDIS_KEY_PREFIX: &str = "gt:rev_pin";
const REDIS_TRACKING_PREFIX: &str = "gt:rev_pin_set";

/// Identity of a pinned session: `(env, deployment, tenant, hint)`. Borrowed
/// from the caller's request data so the trait surface stays alloc-free at
/// the trait boundary; implementations own the cloning decision (in-memory
/// builds a `String` HashMap key; Redis URL-encodes into a Redis key).
#[derive(Clone, Copy, Debug)]
pub struct PinKey<'a> {
    pub env_id: &'a str,
    pub deployment_id: DeploymentId,
    pub tenant: &'a str,
    pub hint: &'a str,
}

/// Routing-stickiness storage for `(env, deployment_id, tenant, session_hint)`.
///
/// All methods are infallible-by-design at the trait level for the happy
/// path: the in-memory impl never errors, and the Redis impl downgrades
/// transient connection failures to soft misses (logged via `tracing::warn!`)
/// rather than bubbling them up to the dispatch path. A hard miss is always a
/// safe answer — selection falls through to the weighted-random branch and
/// re-pins, exactly as it does after a generation bump.
#[async_trait::async_trait]
pub trait RevisionPinStore: Send + Sync {
    /// Insert a pin **only if** the slot is free or holds a strictly-older
    /// generation. Returns the persisted entry (`Inserted` / `Existing`) or
    /// `Skipped` when the backend declined to persist (Redis timeout / cap /
    /// scope-reject).
    ///
    /// Implementations MUST be race-safe — two concurrent callers with the same
    /// key see exactly one inserted value — AND **generation-monotonic**: a
    /// stored entry whose generation is `>= generation` (same OR newer) is left
    /// intact and returned as `Existing`; only a strictly-older (or expired)
    /// entry is replaced. The store is shared across activations (B1a), so an
    /// in-flight caller from a pre-reload activation must never clobber a newer
    /// post-reload pin.
    async fn try_pin(
        &self,
        key: PinKey<'_>,
        revision_id: RevisionId,
        generation: u64,
        ttl: Duration,
    ) -> PinOutcome;

    /// Lookup an existing pin. Returns `None` when:
    ///
    /// - no pin exists, or
    /// - the pin's generation does not equal `current_generation`, or
    /// - the pin has expired.
    ///
    /// Eviction is **generation-monotonic**: when the stored generation is
    /// strictly OLDER than `current_generation` (or the entry is expired),
    /// implementations MUST evict it; when it is strictly NEWER, implementations
    /// MUST return a miss but leave it intact (a newer entry belongs to a
    /// post-reload activation sharing this store — an older in-flight caller
    /// must not delete it).
    async fn lookup(&self, key: PinKey<'_>, current_generation: u64) -> Option<RevisionId>;
}

/// Outcome of [`RevisionPinStore::try_pin`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinOutcome {
    /// Caller's `(revision_id, generation)` was persisted.
    Inserted { revision_id: RevisionId },
    /// A pin already existed; the value returned is what's now live.
    Existing { revision_id: RevisionId },
    /// The pin was NOT persisted (Redis timeout/error, cardinality cap
    /// reached, or unsafe scope strings refused). The caller's
    /// `revision_id` is still returned so dispatch can route this request,
    /// but the next request with the same hint will not find a pin.
    Skipped { revision_id: RevisionId },
}

impl PinOutcome {
    pub fn revision_id(&self) -> RevisionId {
        match self {
            Self::Inserted { revision_id }
            | Self::Existing { revision_id }
            | Self::Skipped { revision_id } => *revision_id,
        }
    }
}

// ── In-memory backend ───────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct InMemoryEntry {
    revision_id: RevisionId,
    generation: u64,
    expires_at: SystemTime,
}

/// Single-process pin store. Matches B1's bounded-map discipline:
///
/// - hard cap at [`MAX_PINS`];
/// - at-cap inserts first sweep expired entries, then evict the soonest-to-expire;
/// - strictly-older (or expired) entries are dropped on lookup; a newer entry
///   is a miss but is left intact (generation-monotonic — see the trait doc).
#[derive(Debug, Default)]
pub struct InMemoryPinStore {
    inner: Mutex<HashMap<(DeploymentId, String, String, String), InMemoryEntry>>,
}

impl InMemoryPinStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test helper: number of live entries (post-eviction).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().expect("pin mutex poisoned").len()
    }
}

/// Build the owned-String key the in-memory map uses. Centralizes the
/// `(deployment_id, env, tenant, hint)` shape so the two impl methods
/// can't drift.
fn owned_key(key: PinKey<'_>) -> (DeploymentId, String, String, String) {
    (
        key.deployment_id,
        key.env_id.to_string(),
        key.tenant.to_string(),
        key.hint.to_string(),
    )
}

#[async_trait::async_trait]
impl RevisionPinStore for InMemoryPinStore {
    async fn try_pin(
        &self,
        key: PinKey<'_>,
        revision_id: RevisionId,
        generation: u64,
        ttl: Duration,
    ) -> PinOutcome {
        let map_key = owned_key(key);
        let now = SystemTime::now();
        let mut guard = self.inner.lock().expect("pin mutex poisoned");

        // Monotonic eviction: an at-or-newer generation already owns the slot,
        // so report it and do NOT clobber. This covers same-generation (the
        // original race-loser contract) AND a *newer* entry: with the pin store
        // now shared across activations (B1a), an in-flight request from a
        // pre-reload activation can reach here at an older generation while a
        // post-reload request has already pinned the newer one — it must not
        // overwrite that. Only a strictly-stale (older) or expired entry is
        // dropped and replaced below.
        if let Some(existing) = guard.get(&map_key)
            && existing.expires_at > now
            && existing.generation >= generation
        {
            return PinOutcome::Existing {
                revision_id: existing.revision_id,
            };
        }
        guard.remove(&map_key);

        if guard.len() >= MAX_PINS {
            guard.retain(|_, e| e.expires_at > now);
            if guard.len() >= MAX_PINS
                && let Some(victim) = guard
                    .iter()
                    .min_by_key(|(_, e)| e.expires_at)
                    .map(|(k, _)| k.clone())
            {
                guard.remove(&victim);
            }
        }
        guard.insert(
            map_key,
            InMemoryEntry {
                revision_id,
                generation,
                expires_at: now + ttl,
            },
        );
        PinOutcome::Inserted { revision_id }
    }

    async fn lookup(&self, key: PinKey<'_>, current_generation: u64) -> Option<RevisionId> {
        let map_key = owned_key(key);
        let now = SystemTime::now();
        let mut guard = self.inner.lock().expect("pin mutex poisoned");
        match guard.get(&map_key) {
            Some(entry) if entry.expires_at > now && entry.generation == current_generation => {
                Some(entry.revision_id)
            }
            // Monotonic eviction: evict only what this caller may supersede —
            // an expired entry, or a strictly-older generation. A *newer* entry
            // (entry.generation > current_generation) belongs to a post-reload
            // activation sharing this store (B1a); an older in-flight caller
            // gets a miss but must leave it intact rather than delete it.
            Some(entry) if entry.expires_at <= now || entry.generation < current_generation => {
                guard.remove(&map_key);
                None
            }
            Some(_) => None,
            None => None,
        }
    }
}

// ── Redis backend ───────────────────────────────────────────────────────

/// Lua script that atomically performs the `try_pin` contract:
///
/// 1. If `KEYS[1]` already holds a pin at an AT-OR-NEWER generation
///    (`stored_gen >= ARGV[1]`), return `{1, value}` (caller gets `Existing`).
///    Monotonic: a stored newer generation belongs to a post-reload activation
///    sharing this store, so an older in-flight caller must not clobber it.
/// 2. Otherwise — a strictly-older (stale) stored generation — delete the
///    existing key, check the tracking-set cardinality, and if under cap, write
///    the new pin + add it to the tracking set + refresh the set's TTL. Return
///    `{0, value}` (caller gets `Inserted`).
/// 3. If the tracking set is at cap, return `{2}` (caller gets a no-pin
///    fallthrough that becomes `Inserted` with the caller's own
///    revision_id — see `RedisPinStore::try_pin`).
///
/// Inputs:
///   KEYS[1] = pin key
///   KEYS[2] = tracking-set key (per-(env, deployment, tenant) scope)
///   ARGV[1] = current_generation (string-encoded u64)
///   ARGV[2] = new value (`revision_id|generation|expires_at_unix_secs`)
///   ARGV[3] = ttl_secs (string-encoded u64)
///   ARGV[4] = cardinality cap (string-encoded usize)
///
/// Why Lua: SET NX EX + GET is racy across stale generations.
/// SCAN-based after-the-fact pruning is racy across cardinality.
/// One atomic script collapses both into a single round-trip.
const TRY_PIN_SCRIPT: &str = r#"
local existing = redis.call('GET', KEYS[1])
if existing then
  local _, gen = string.match(existing, '^([^|]+)|([^|]+)|')
  -- Monotonic: an at-or-newer stored generation owns the slot — report it
  -- (Existing) and leave it intact. Only a strictly-older stored generation
  -- is replaced.
  if tonumber(gen) >= tonumber(ARGV[1]) then
    return {1, existing}
  end
  redis.call('DEL', KEYS[1])
  redis.call('SREM', KEYS[2], KEYS[1])
end
local card = redis.call('SCARD', KEYS[2])
local cap = tonumber(ARGV[4])
if card >= cap then
  return {2}
end
redis.call('SET', KEYS[1], ARGV[2], 'EX', tonumber(ARGV[3]))
redis.call('SADD', KEYS[2], KEYS[1])
redis.call('EXPIRE', KEYS[2], tonumber(ARGV[3]))
return {0, ARGV[2]}
"#;

/// Pre-computed `redis::Script` for [`TRY_PIN_SCRIPT`]. Computing the SHA1
/// once per process (rather than per call) matches the sibling pattern in
/// `greentic-state/src/redis_store.rs`.
static TRY_PIN_SCRIPT_HANDLE: LazyLock<redis::Script> =
    LazyLock::new(|| redis::Script::new(TRY_PIN_SCRIPT));

/// Boot env var selecting the Redis-backed session-pin store (B2). Mirrors
/// `GREENTIC_SECRETS_BACKEND`'s connection-string-via-env convention: set it
/// to a Redis URL (`redis://[:pass@]host:port/db`) and the serve loop builds a
/// shared [`RedisPinStore`] instead of the per-process [`InMemoryPinStore`], so
/// session pins survive a pod restart and are shared across a horizontally
/// scaled fleet. Unset/empty keeps the single-process in-memory store.
pub(crate) const PIN_REDIS_URL_ENV: &str = "GREENTIC_REVISION_PIN_REDIS_URL";

/// Normalize the raw [`PIN_REDIS_URL_ENV`] value into an actionable URL:
/// `None` (unset) and a blank/whitespace-only string both mean "no Redis,
/// use in-memory". Kept pure (takes the raw value rather than reading the
/// process env) so the select decision is unit-testable without env mutation;
/// the boot site supplies `std::env::var(PIN_REDIS_URL_ENV).ok()`.
pub(crate) fn redis_url_from_raw(raw: Option<String>) -> Option<String> {
    raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Reduce a Redis URL to a safe-to-log `scheme://host[:port]`, dropping
/// everything that can carry a credential: the `user:pass@` userinfo
/// (`redis://:pass@host`), the path, AND the query string
/// (`rediss://host/0?password=…`, `…?token=…`). A Redis URL embeds its
/// password inline, and `from_url` formats the URL into its error context on
/// failure, so logging that error would otherwise leak the secret — including
/// a query credential, which an earlier userinfo-only mask left intact.
///
/// Operates on the raw string so an unparseable value is still scrubbed: no
/// `://` scheme, or an empty authority (e.g. a `redis+unix:///sock` path),
/// returns a fully-masked placeholder rather than echoing possibly-secret
/// bytes.
pub(crate) fn redact_redis_url(raw: &str) -> String {
    const REDACTED: &str = "<redacted redis url>";
    let Some((scheme, rest)) = raw.split_once("://") else {
        return REDACTED.to_string();
    };
    // Authority = everything up to the first `/` (path) or `?` (query). Both
    // can carry secrets, so neither is kept — this also means a `@` sitting in
    // a query value can't be mistaken for the userinfo delimiter below.
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    // Drop `user:pass@` userinfo. The authority has no path/query left, so the
    // last `@` (if any) is the userinfo delimiter; the host tail is safe.
    let host = match authority.rsplit_once('@') {
        Some((_userinfo, host)) => host,
        None => authority,
    };
    if host.is_empty() {
        REDACTED.to_string()
    } else {
        format!("{scheme}://{host}")
    }
}

/// Resolve the session-pin store backend for the serve loop (B2). Mirrors
/// `secrets_gate::resolve_serve_secrets_manager`: reads its selecting env var
/// ([`PIN_REDIS_URL_ENV`]) internally, connects or falls back, logs the
/// outcome, and hands back a ready `Arc`. `rt` is the activation runtime the
/// boot path already builds; the async [`RedisPinStore::from_url`] is driven on
/// it.
///
/// Fail open: an invalid or unreachable Redis logs a warning and yields the
/// in-memory store rather than aborting boot — pinning is best-effort (the
/// stickiness cookie + weighted pick still route), so a transient Redis outage
/// must not brick the worker.
pub(crate) fn resolve_pin_store(
    rt: &tokio::runtime::Runtime,
) -> std::sync::Arc<dyn RevisionPinStore> {
    use std::sync::Arc;
    let Some(url) = redis_url_from_raw(std::env::var(PIN_REDIS_URL_ENV).ok()) else {
        return Arc::new(InMemoryPinStore::new());
    };
    match rt.block_on(RedisPinStore::from_url(&url)) {
        Ok(store) => {
            crate::operator_log::info(
                module_path!(),
                "session-pin store: redis (multi-pod sticky routing)",
            );
            Arc::new(store)
        }
        Err(err) => {
            // Fail open to in-memory; name the cause (the redacted URL is
            // preserved in the error context) so a permanent misconfig is not
            // mistaken for a transient blip.
            crate::operator_log::warn(
                module_path!(),
                format!(
                    "{PIN_REDIS_URL_ENV} set but the Redis pin store is unavailable ({err:#}); \
                     falling back to in-memory (pins will not survive a restart or share across \
                     pods)"
                ),
            );
            Arc::new(InMemoryPinStore::new())
        }
    }
}

pub struct RedisPinStore {
    /// `ConnectionManager` is `Clone` and internally pipelines/multiplexes
    /// commands across a shared connection, so we hold it bare — no Mutex
    ///. Each operation gets its own clone of the cheap
    /// (`Arc<Inner>`) handle.
    conn: ConnectionManager,
    op_timeout: Duration,
    cardinality_cap: usize,
}

impl std::fmt::Debug for RedisPinStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisPinStore")
            .field("op_timeout", &self.op_timeout)
            .field("cardinality_cap", &self.cardinality_cap)
            .finish_non_exhaustive()
    }
}

impl RedisPinStore {
    /// Open a Redis client from a URL (`redis://…`, or `rediss://…` for TLS
    /// endpoints such as managed cloud Redis) and build a [`ConnectionManager`]
    /// that handles reconnection transparently.
    pub async fn from_url(url: impl AsRef<str>) -> Result<Self> {
        let url = url.as_ref();
        // A `rediss://` endpoint needs a process-default rustls crypto provider
        // in place before redis builds its TLS config; no-op for `redis://`.
        crate::redis_tls::ensure_crypto_provider_for(url);
        let client = redis::Client::open(url)
            .with_context(|| format!("invalid redis url `{}`", redact_redis_url(url)))?;
        let manager = ConnectionManager::new(client)
            .await
            .context("redis ConnectionManager init failed")?;
        Ok(Self {
            conn: manager,
            op_timeout: REDIS_OP_TIMEOUT,
            cardinality_cap: MAX_PINS_PER_TENANT,
        })
    }

    /// Override the per-op timeout. Defaults to [`REDIS_OP_TIMEOUT`] (50ms);
    /// loosened in integration tests so a cold connection-manager handshake
    /// or a Docker-on-VPN'd developer machine doesn't false-fail.
    pub fn with_op_timeout(mut self, timeout: Duration) -> Self {
        self.op_timeout = timeout;
        self
    }

    /// Override the per-`(env, deployment, tenant)` pin cap. Defaults to
    /// [`MAX_PINS_PER_TENANT`]. Phase D operators tune this when one
    /// tenant's session churn pushes against the default 4_096 ceiling.
    pub fn with_cardinality_cap(mut self, cap: usize) -> Self {
        self.cardinality_cap = cap;
        self
    }
}

/// Encoded pin value: `{revision_id_ulid}|{generation}|{expires_at_unix_secs}`.
///
/// Plaintext ASCII so `redis-cli GET` is debuggable. The expires-at is
/// redundant given Redis-native TTL, but we still encode it so a stale read
/// during clock skew or replication lag returns a typed-and-checked answer
/// rather than a silently-expired pin.
fn encode_value(revision_id: RevisionId, generation: u64, expires_at: SystemTime) -> String {
    let secs = expires_at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{revision_id}|{generation}|{secs}")
}

fn decode_value(raw: &str) -> Option<(RevisionId, u64, u64)> {
    let mut parts = raw.splitn(3, '|');
    let rid_str = parts.next()?;
    let gen_str = parts.next()?;
    let exp_str = parts.next()?;
    let rid = Ulid::from_string(rid_str).ok()?;
    let generation = gen_str.parse::<u64>().ok()?;
    let expires_at = exp_str.parse::<u64>().ok()?;
    Some((RevisionId(rid), generation, expires_at))
}

/// Tenant + hint are URL-encoded so a colon in either value cannot collide
/// with the structural delimiter. `env_id` is from a typed
/// [`greentic_deploy_spec::EnvId`] upstream (no colons allowed) and
/// `deployment_id` is a ULID, so neither needs escaping today.
fn redis_key(env_id: &str, deployment_id: DeploymentId, tenant: &str, hint: &str) -> String {
    let mut k = scope_prefix(REDIS_KEY_PREFIX, env_id, deployment_id, tenant);
    k.push(':');
    k.push_str(&urlencoding::encode(hint));
    k
}

/// Tracking-set key for cardinality enforcement: one set per
/// `(env, deployment, tenant)`. Holds the live pin keys for that scope so
/// the Lua script can `SCARD`-bound new inserts.
fn redis_tracking_key(env_id: &str, deployment_id: DeploymentId, tenant: &str) -> String {
    scope_prefix(REDIS_TRACKING_PREFIX, env_id, deployment_id, tenant)
}

/// Shared `{prefix}:{env}:{deployment}:{urlenc tenant}` builder so the two
/// key constructors can't drift in their escaping discipline.
fn scope_prefix(prefix: &str, env_id: &str, deployment_id: DeploymentId, tenant: &str) -> String {
    format!(
        "{prefix}:{env_id}:{deployment_id}:{}",
        urlencoding::encode(tenant),
    )
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Refuse caller-supplied scope strings over [`MAX_SCOPE_BYTES`]. This is
/// the Redis-side mirror of the in-memory `MAX_PINS` self-protection: long
/// values consume bandwidth + storage, and the trait's contract permits
/// soft-miss on unsafe inputs.
fn scope_within_bounds(tenant: &str, hint: &str) -> bool {
    tenant.len() <= MAX_SCOPE_BYTES && hint.len() <= MAX_SCOPE_BYTES
}

#[async_trait::async_trait]
impl RevisionPinStore for RedisPinStore {
    async fn try_pin(
        &self,
        key: PinKey<'_>,
        revision_id: RevisionId,
        generation: u64,
        ttl: Duration,
    ) -> PinOutcome {
        if !scope_within_bounds(key.tenant, key.hint) {
            tracing::warn!(
                target: "greentic_start::revision_pin",
                tenant_len = key.tenant.len(),
                hint_len = key.hint.len(),
                "rejecting pin: tenant/hint exceeds MAX_SCOPE_BYTES",
            );
            return PinOutcome::Skipped { revision_id };
        }
        let pin_key = redis_key(key.env_id, key.deployment_id, key.tenant, key.hint);
        let set_key = redis_tracking_key(key.env_id, key.deployment_id, key.tenant);
        let ttl_secs = ttl.as_secs().max(1);
        let value = encode_value(revision_id, generation, SystemTime::now() + ttl);

        let mut invocation = TRY_PIN_SCRIPT_HANDLE.prepare_invoke();
        invocation
            .key(&pin_key)
            .key(&set_key)
            .arg(generation.to_string())
            .arg(&value)
            .arg(ttl_secs.to_string())
            .arg(self.cardinality_cap.to_string());
        let mut conn = self.conn.clone();
        let fut = invocation.invoke_async::<(i64, Option<String>)>(&mut conn);

        match tokio::time::timeout(self.op_timeout, fut).await {
            Ok(Ok((0, _))) => PinOutcome::Inserted { revision_id },
            Ok(Ok((1, Some(existing)))) => match decode_value(&existing) {
                Some((existing_rev, _, _)) => PinOutcome::Existing {
                    revision_id: existing_rev,
                },
                None => PinOutcome::Skipped { revision_id },
            },
            Ok(Ok((2, _))) => {
                tracing::warn!(
                    target: "greentic_start::revision_pin",
                    cap = self.cardinality_cap,
                    pin_key = %pin_key,
                    "rejecting pin: cardinality cap reached for (env, deployment, tenant)",
                );
                PinOutcome::Skipped { revision_id }
            }
            Ok(Ok(other)) => {
                tracing::warn!(
                    target: "greentic_start::revision_pin",
                    response = ?other,
                    "redis try_pin script returned unexpected shape; soft-falling through",
                );
                PinOutcome::Skipped { revision_id }
            }
            Ok(Err(err)) => {
                tracing::warn!(
                    target: "greentic_start::revision_pin",
                    error = %err,
                    pin_key = %pin_key,
                    "redis try_pin script failed; soft-falling through to no-pin path",
                );
                PinOutcome::Skipped { revision_id }
            }
            Err(_) => {
                tracing::warn!(
                    target: "greentic_start::revision_pin",
                    timeout_ms = self.op_timeout.as_millis() as u64,
                    pin_key = %pin_key,
                    "redis try_pin timed out; soft-falling through to no-pin path",
                );
                PinOutcome::Skipped { revision_id }
            }
        }
    }

    async fn lookup(&self, key: PinKey<'_>, current_generation: u64) -> Option<RevisionId> {
        if !scope_within_bounds(key.tenant, key.hint) {
            return None;
        }
        let pin_key = redis_key(key.env_id, key.deployment_id, key.tenant, key.hint);
        let mut conn = self.conn.clone();

        let mut get_cmd = redis::cmd("GET");
        get_cmd.arg(&pin_key);
        let get_fut = get_cmd.query_async::<Option<String>>(&mut conn);
        let raw = match tokio::time::timeout(self.op_timeout, get_fut).await {
            Ok(Ok(v)) => v?,
            Ok(Err(err)) => {
                tracing::warn!(
                    target: "greentic_start::revision_pin",
                    error = %err,
                    pin_key = %pin_key,
                    "redis GET failed; treating as cache miss",
                );
                return None;
            }
            Err(_) => {
                tracing::warn!(
                    target: "greentic_start::revision_pin",
                    timeout_ms = self.op_timeout.as_millis() as u64,
                    pin_key = %pin_key,
                    "redis GET timed out; treating as cache miss",
                );
                return None;
            }
        };
        let (revision_id, generation, expires_at) = decode_value(&raw)?;
        // Generation-monotonic, mirroring `InMemoryPinStore::lookup`.
        if generation == current_generation && expires_at > now_secs() {
            Some(revision_id)
        } else if expires_at <= now_secs() || generation < current_generation {
            // Strictly-older or expired → this caller may supersede it. Drop the
            // key + its tracking-set membership best-effort. The Lua script in
            // `try_pin` covers the re-pin path; this branch handles the narrow
            // case of a lookup that's never followed by a re-pin.
            let set_key = redis_tracking_key(key.env_id, key.deployment_id, key.tenant);
            let _ = tokio::time::timeout(self.op_timeout, async {
                let mut c = self.conn.clone();
                let mut del_cmd = redis::cmd("DEL");
                del_cmd.arg(&pin_key);
                let _: redis::RedisResult<()> = del_cmd.query_async(&mut c).await;
                let mut srem_cmd = redis::cmd("SREM");
                srem_cmd.arg(&set_key).arg(&pin_key);
                let _: redis::RedisResult<()> = srem_cmd.query_async(&mut c).await;
            })
            .await;
            None
        } else {
            // Strictly-newer stored generation: a post-reload pin in the shared
            // store. Miss for this older in-flight caller, but leave it intact.
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn dep() -> DeploymentId {
        DeploymentId::new()
    }
    fn rev() -> RevisionId {
        RevisionId::new()
    }

    #[test]
    fn redis_url_from_raw_treats_unset_and_blank_as_in_memory() {
        assert_eq!(redis_url_from_raw(None), None);
        assert_eq!(redis_url_from_raw(Some(String::new())), None);
        assert_eq!(redis_url_from_raw(Some("   ".to_string())), None);
        assert_eq!(
            redis_url_from_raw(Some("  redis://127.0.0.1:6379/0  ".to_string())),
            Some("redis://127.0.0.1:6379/0".to_string()),
        );
    }

    #[test]
    fn redact_redis_url_masks_inline_credentials() {
        // Password-only and user:pass userinfo, plus path, are dropped.
        assert_eq!(
            redact_redis_url("redis://:s3cr3t@cache.internal:6379/0"),
            "redis://cache.internal:6379",
        );
        assert_eq!(
            redact_redis_url("rediss://admin:p@ss@cache:6380"),
            "rediss://cache:6380",
        );
        // No userinfo: host+port kept, path dropped.
        assert_eq!(
            redact_redis_url("redis://127.0.0.1:6379/0"),
            "redis://127.0.0.1:6379",
        );
        // Query-string credentials are dropped (the high-severity vector: no
        // `@`, so an earlier userinfo-only mask left `?password=` intact).
        assert_eq!(
            redact_redis_url("rediss://cache:6380/0?password=s3cr3t"),
            "rediss://cache:6380",
        );
        // A `@` inside a query value is not mistaken for userinfo.
        assert_eq!(
            redact_redis_url("redis://cache:6379/0?token=ab@cd"),
            "redis://cache:6379",
        );
        // Bracketed IPv6 host is preserved while creds are stripped.
        assert_eq!(
            redact_redis_url("rediss://:pw@[::1]:6380/0"),
            "rediss://[::1]:6380",
        );
        // Empty authority (unix-socket path) is fully masked, not echoed.
        assert_eq!(
            redact_redis_url("redis+unix:///var/run/redis.sock?pass=x"),
            "<redacted redis url>",
        );
        // Unparseable (no scheme) is fully masked, never echoed.
        assert_eq!(redact_redis_url(":s3cr3t@host"), "<redacted redis url>");
    }

    #[test]
    fn rediss_scheme_is_accepted_now_that_tls_is_compiled_in() {
        // Regression guard for the redis TLS features: without a TLS transport
        // linked, `Client::open` rejects the `rediss://` scheme up front. With
        // `tokio-rustls-comp` enabled it parses. The connection itself is not
        // attempted here (that needs a live TLS server) — this only proves the
        // scheme is no longer refused, i.e. the features stay enabled.
        assert!(redis::Client::open("rediss://127.0.0.1:6390/0").is_ok());
        // Plaintext stays valid too.
        assert!(redis::Client::open("redis://127.0.0.1:6379/0").is_ok());
    }

    #[tokio::test]
    async fn in_memory_inserts_then_returns_existing() {
        let store = InMemoryPinStore::new();
        let dep_id = dep();
        let r = rev();
        let out1 = store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: "h",
                },
                r,
                1,
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(out1, PinOutcome::Inserted { revision_id: r });
        let out2 = store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: "h",
                },
                rev(),
                1,
                Duration::from_secs(60),
            )
            .await;
        // Second call observes the existing pin — returns its revision_id,
        // not the caller's.
        assert_eq!(out2, PinOutcome::Existing { revision_id: r });
    }

    #[tokio::test]
    async fn in_memory_lookup_returns_pinned_until_generation_bumps() {
        let store = InMemoryPinStore::new();
        let dep_id = dep();
        let r = rev();
        store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: "h",
                },
                r,
                1,
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: "t",
                        hint: "h"
                    },
                    1
                )
                .await,
            Some(r)
        );
        // Generation bump invalidates the pin AND evicts it.
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: "t",
                        hint: "h"
                    },
                    2
                )
                .await,
            None
        );
        // Eviction confirmed: same-generation lookup also misses.
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: "t",
                        hint: "h"
                    },
                    1
                )
                .await,
            None
        );
    }

    #[tokio::test]
    async fn in_memory_lookup_drops_expired_entry() {
        let store = InMemoryPinStore::new();
        let dep_id = dep();
        let r = rev();
        store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: "h",
                },
                r,
                1,
                Duration::from_millis(10),
            )
            .await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: "t",
                        hint: "h"
                    },
                    1
                )
                .await,
            None
        );
    }

    #[tokio::test]
    async fn in_memory_replaces_stale_generation_entry_on_try_pin() {
        let store = InMemoryPinStore::new();
        let dep_id = dep();
        let r1 = rev();
        store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: "h",
                },
                r1,
                1,
                Duration::from_secs(60),
            )
            .await;
        let r2 = rev();
        // Same key, new generation → stale entry MUST be replaced (it would
        // never be lookup-able anyway, but the slot should be reused).
        let out = store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: "h",
                },
                r2,
                2,
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(out, PinOutcome::Inserted { revision_id: r2 });
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: "t",
                        hint: "h"
                    },
                    2
                )
                .await,
            Some(r2)
        );
    }

    #[tokio::test]
    async fn in_memory_older_caller_cannot_evict_or_clobber_newer_pin() {
        // B1a shares one store across activations. An in-flight request from a
        // pre-reload activation reaches the store at an OLDER generation than a
        // pin a post-reload request already wrote. It must neither evict (via
        // lookup) nor overwrite (via try_pin) that newer pin — otherwise a
        // freshly established post-reload pin is lost and the session flaps.
        let store = InMemoryPinStore::new();
        let dep_id = dep();
        let newer = rev();
        let k = || PinKey {
            env_id: "local",
            deployment_id: dep_id,
            tenant: "t",
            hint: "h",
        };
        // Post-reload pin at generation 2.
        store.try_pin(k(), newer, 2, Duration::from_secs(60)).await;

        // Old caller (generation 1) looks up: miss, but MUST NOT evict.
        assert_eq!(store.lookup(k(), 1).await, None);
        assert_eq!(
            store.lookup(k(), 2).await,
            Some(newer),
            "an older-generation lookup must not evict the newer pin"
        );

        // Old caller (generation 1) tries to pin its own pick: must report the
        // newer pin as Existing and leave it intact, not clobber it.
        let older_pick = rev();
        assert_eq!(
            store
                .try_pin(k(), older_pick, 1, Duration::from_secs(60))
                .await,
            PinOutcome::Existing { revision_id: newer },
            "an older-generation try_pin must not overwrite the newer pin"
        );
        assert_eq!(
            store.lookup(k(), 2).await,
            Some(newer),
            "the newer pin must survive an older-generation try_pin"
        );
    }

    #[tokio::test]
    async fn in_memory_bounded_under_rotating_hints() {
        let store = InMemoryPinStore::new();
        let dep_id = dep();
        for i in 0..(MAX_PINS * 2) {
            let hint = format!("sess-{i}");
            store
                .try_pin(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: "t",
                        hint: &hint,
                    },
                    rev(),
                    1,
                    Duration::from_secs(60),
                )
                .await;
        }
        assert!(store.len() <= MAX_PINS);
    }

    #[tokio::test]
    async fn in_memory_distinct_keys_isolated() {
        let store = InMemoryPinStore::new();
        let dep_a = dep();
        let dep_b = dep();
        let r_a = rev();
        let r_b = rev();
        // Same env+tenant+hint, different deployments.
        store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_a,
                    tenant: "t",
                    hint: "h",
                },
                r_a,
                1,
                Duration::from_secs(60),
            )
            .await;
        store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_b,
                    tenant: "t",
                    hint: "h",
                },
                r_b,
                1,
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_a,
                        tenant: "t",
                        hint: "h"
                    },
                    1
                )
                .await,
            Some(r_a)
        );
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_b,
                        tenant: "t",
                        hint: "h"
                    },
                    1
                )
                .await,
            Some(r_b)
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let r = RevisionId(Ulid::new());
        let exp = SystemTime::now() + Duration::from_secs(60);
        let encoded = encode_value(r, 7, exp);
        let (decoded_r, decoded_g, decoded_exp) = decode_value(&encoded).unwrap();
        assert_eq!(decoded_r, r);
        assert_eq!(decoded_g, 7);
        // Lossy in sub-second precision, but within 1s of caller's clock.
        let exp_secs = exp.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert!(decoded_exp.abs_diff(exp_secs) <= 1);
    }

    #[test]
    fn decode_rejects_malformed() {
        assert!(decode_value("").is_none());
        assert!(decode_value("not-a-ulid|1|2").is_none());
        assert!(decode_value(&format!("{}|notanum|2", Ulid::new())).is_none());
        assert!(decode_value(&format!("{}|1|notanum", Ulid::new())).is_none());
        // Missing field.
        assert!(decode_value(&format!("{}|1", Ulid::new())).is_none());
    }

    #[test]
    fn redis_key_matches_plan_format() {
        let id = DeploymentId(Ulid::from_string("01F8MECHZX3TBDSZ7XR8KZ9V8K").unwrap());
        let key = redis_key("local", id, "tenant-a", "session-x");
        assert_eq!(
            key,
            "gt:rev_pin:local:01F8MECHZX3TBDSZ7XR8KZ9V8K:tenant-a:session-x"
        );
    }

    /// Regression: `(tenant="a", hint="b:c")` and
    /// `(tenant="a:b", hint="c")` must produce distinct Redis keys. The
    /// pre-fix `format!(...)` collided across these scopes; URL-encoding
    /// the components fixes it.
    #[test]
    fn redis_key_is_injective_across_tenant_and_hint_with_colons() {
        let id = DeploymentId(Ulid::from_string("01F8MECHZX3TBDSZ7XR8KZ9V8K").unwrap());
        let k1 = redis_key("local", id, "a", "b:c");
        let k2 = redis_key("local", id, "a:b", "c");
        assert_ne!(k1, k2);
        // The literal forms are also debuggable in redis-cli.
        assert_eq!(k1, "gt:rev_pin:local:01F8MECHZX3TBDSZ7XR8KZ9V8K:a:b%3Ac");
        assert_eq!(k2, "gt:rev_pin:local:01F8MECHZX3TBDSZ7XR8KZ9V8K:a%3Ab:c");
    }

    #[test]
    fn redis_tracking_key_scopes_by_env_deployment_tenant() {
        let id = DeploymentId(Ulid::from_string("01F8MECHZX3TBDSZ7XR8KZ9V8K").unwrap());
        assert_eq!(
            redis_tracking_key("local", id, "tenant-a"),
            "gt:rev_pin_set:local:01F8MECHZX3TBDSZ7XR8KZ9V8K:tenant-a"
        );
    }

    // ── Redis integration tests ───────────────────────────────────────
    //
    // Gated by `GREENTIC_TEST_REDIS_URL` (mirrors `tests/notifier_redis.rs`).
    // Run locally:
    //   docker run --rm -p 6379:6379 redis
    //   GREENTIC_TEST_REDIS_URL=redis://127.0.0.1:6379 \
    //     cargo test -p greentic-start revision_pin -- --nocapture

    fn redis_url_or_skip() -> Option<String> {
        match std::env::var("GREENTIC_TEST_REDIS_URL") {
            Ok(url) if !url.is_empty() => Some(url),
            _ => {
                eprintln!("skipping: GREENTIC_TEST_REDIS_URL not set");
                None
            }
        }
    }

    /// Unique hint per test so concurrent test runs don't clobber each other.
    fn unique_hint(label: &str) -> String {
        format!("test-{label}-{}", Ulid::new())
    }

    #[tokio::test]
    async fn redis_inserts_then_returns_existing() {
        let Some(url) = redis_url_or_skip() else {
            return;
        };
        let store = RedisPinStore::from_url(&url).await.expect("redis open");
        let dep_id = dep();
        let hint = unique_hint("insert");
        let r = rev();

        let out1 = store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: &hint,
                },
                r,
                1,
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(out1, PinOutcome::Inserted { revision_id: r });

        let out2 = store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: &hint,
                },
                rev(),
                1,
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(out2, PinOutcome::Existing { revision_id: r });
    }

    #[tokio::test]
    async fn redis_lookup_drops_stale_generation() {
        let Some(url) = redis_url_or_skip() else {
            return;
        };
        let store = RedisPinStore::from_url(&url).await.expect("redis open");
        let dep_id = dep();
        let hint = unique_hint("staleness");
        let r = rev();

        store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: &hint,
                },
                r,
                1,
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: "t",
                        hint: &hint
                    },
                    1
                )
                .await,
            Some(r)
        );
        // Generation bump → eviction.
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: "t",
                        hint: &hint
                    },
                    2
                )
                .await,
            None
        );
        // After eviction, same-generation lookup also misses.
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: "t",
                        hint: &hint
                    },
                    1
                )
                .await,
            None
        );
    }

    #[tokio::test]
    async fn redis_ttl_expires() {
        let Some(url) = redis_url_or_skip() else {
            return;
        };
        let store = RedisPinStore::from_url(&url).await.expect("redis open");
        let dep_id = dep();
        let hint = unique_hint("ttl");
        let r = rev();
        // Redis EXpire is whole-second granularity; min TTL is 1s.
        store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: &hint,
                },
                r,
                1,
                Duration::from_secs(1),
            )
            .await;
        // Wait past TTL.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: "t",
                        hint: &hint
                    },
                    1
                )
                .await,
            None
        );
    }

    /// Regression: a stale-generation key must be REPLACED by the
    /// new pin, not silently deleted-and-reported-as-Inserted. The pre-fix
    /// path returned `Inserted` while the new pin was never written —
    /// subsequent lookups missed and the next request re-weighted.
    #[tokio::test]
    async fn redis_replaces_stale_generation_entry_on_try_pin() {
        let Some(url) = redis_url_or_skip() else {
            return;
        };
        let store = RedisPinStore::from_url(&url).await.expect("redis open");
        let dep_id = dep();
        let hint = unique_hint("stale-replace");
        let r1 = rev();
        store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: &hint,
                },
                r1,
                1,
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: "t",
                        hint: &hint
                    },
                    1
                )
                .await,
            Some(r1)
        );

        // Operator bumps generation: caller now writes gen=2 for the same
        // hint. The atomic Lua script must DEL + SET in one round-trip so
        // the new pin is persisted, not just the deletion.
        let r2 = rev();
        let out = store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: &hint,
                },
                r2,
                2,
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(out, PinOutcome::Inserted { revision_id: r2 });
        // The persistence check — without F1 fix this would be `None`
        // because the stale-handler deleted gen=1 but didn't write gen=2.
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: "t",
                        hint: &hint
                    },
                    2
                )
                .await,
            Some(r2)
        );
    }

    #[tokio::test]
    async fn redis_older_caller_cannot_evict_or_clobber_newer_pin() {
        // Redis mirror of the in-memory monotonic-eviction contract (B1a shared
        // store): an older-generation caller must neither DEL the newer pin via
        // lookup nor overwrite it via the try_pin Lua script.
        let Some(url) = redis_url_or_skip() else {
            return;
        };
        let store = RedisPinStore::from_url(&url).await.expect("redis open");
        let dep_id = dep();
        let hint = unique_hint("monotonic");
        let newer = rev();
        let k = || PinKey {
            env_id: "local",
            deployment_id: dep_id,
            tenant: "t",
            hint: &hint,
        };
        store.try_pin(k(), newer, 2, Duration::from_secs(60)).await;

        // Older-generation lookup: miss, but must not evict.
        assert_eq!(store.lookup(k(), 1).await, None);
        assert_eq!(
            store.lookup(k(), 2).await,
            Some(newer),
            "an older-generation lookup must not evict the newer pin"
        );

        // Older-generation try_pin: reports the newer pin and leaves it intact.
        let older_pick = rev();
        assert_eq!(
            store
                .try_pin(k(), older_pick, 1, Duration::from_secs(60))
                .await,
            PinOutcome::Existing { revision_id: newer },
            "an older-generation try_pin must not overwrite the newer pin"
        );
        assert_eq!(
            store.lookup(k(), 2).await,
            Some(newer),
            "the newer pin must survive an older-generation try_pin"
        );
    }

    /// Regression: concurrent re-pinners against a stale-generation
    /// key must converge on a single winner; everyone else sees `Existing`.
    /// Without the atomic script + retry, two callers could both observe
    /// the stale-delete and produce divergent `Inserted` outcomes.
    #[tokio::test]
    async fn redis_concurrent_repinners_converge_on_one_winner() {
        let Some(url) = redis_url_or_skip() else {
            return;
        };
        let store = std::sync::Arc::new(RedisPinStore::from_url(&url).await.expect("redis open"));
        let dep_id = dep();
        let hint = unique_hint("concurrent");

        let r_stale = rev();
        store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: &hint,
                },
                r_stale,
                1,
                Duration::from_secs(60),
            )
            .await;

        // 8 concurrent gen=2 writers race against the gen=1 stale entry.
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = std::sync::Arc::clone(&store);
            let hint = hint.clone();
            handles.push(tokio::spawn(async move {
                let r = rev();
                let out = store
                    .try_pin(
                        PinKey {
                            env_id: "local",
                            deployment_id: dep_id,
                            tenant: "t",
                            hint: &hint,
                        },
                        r,
                        2,
                        Duration::from_secs(60),
                    )
                    .await;
                (r, out)
            }));
        }
        let mut inserted_count = 0;
        let mut existing_revs = std::collections::HashSet::new();
        for h in handles {
            let (own_r, out) = h.await.unwrap();
            match out {
                PinOutcome::Inserted { revision_id } => {
                    assert_eq!(revision_id, own_r);
                    inserted_count += 1;
                }
                PinOutcome::Existing { revision_id } => {
                    existing_revs.insert(revision_id);
                }
                PinOutcome::Skipped { .. } => {
                    panic!("no soft-fail expected under non-overloaded Redis");
                }
            }
        }
        // Exactly one winner inserts; everyone else sees the same winner.
        assert_eq!(inserted_count, 1, "exactly one writer should insert");
        assert!(
            existing_revs.len() <= 1,
            "racing writers must observe a single winning revision, saw {existing_revs:?}",
        );
        // And the winner is durably persisted.
        let after = store
            .lookup(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: "t",
                    hint: &hint,
                },
                2,
            )
            .await;
        assert!(after.is_some(), "winner must survive the race");
    }

    /// Regression: a rotating-hint client cannot grow Redis state
    /// past [`MAX_PINS_PER_TENANT`] for a single `(env, deployment, tenant)`.
    /// Inserts past the cap are rejected (logged) — the caller still gets
    /// the no-pin fallthrough so dispatch keeps routing.
    #[tokio::test]
    async fn redis_cardinality_cap_bounds_rotating_hints() {
        let Some(url) = redis_url_or_skip() else {
            return;
        };
        let store = RedisPinStore::from_url(&url)
            .await
            .expect("redis open")
            .with_cardinality_cap(4);
        let dep_id = dep();
        let tenant = format!("tenant-card-{}", Ulid::new());

        // Pre-fill the cap with 4 distinct hints.
        for i in 0..4 {
            let hint = format!("h-{i}");
            store
                .try_pin(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: &tenant,
                        hint: &hint,
                    },
                    rev(),
                    1,
                    Duration::from_secs(60),
                )
                .await;
        }
        // A 5th distinct hint must be rejected with `Skipped` so the
        // caller (dispatcher) sees an honest "no-op, but here's your
        // revision_id for routing" signal instead of a misleading
        // `Inserted` that lies about persistence.
        let r5 = rev();
        let out = store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: &tenant,
                    hint: "h-5",
                },
                r5,
                1,
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(out, PinOutcome::Skipped { revision_id: r5 });
        // The pin must NOT actually exist in Redis (cap-rejected, not persisted).
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: &tenant,
                        hint: "h-5"
                    },
                    1
                )
                .await,
            None,
            "5th distinct hint must not be persisted past the cap",
        );
    }

    /// Regression (live): two scopes that pre-fix collided to the
    /// same Redis key (`a:b:c`) must now route to independent pins.
    #[tokio::test]
    async fn redis_tenant_and_hint_scopes_do_not_collide() {
        let Some(url) = redis_url_or_skip() else {
            return;
        };
        let store = RedisPinStore::from_url(&url).await.expect("redis open");
        let dep_id = dep();
        // Disambiguate test runs.
        let suffix = Ulid::new().to_string();
        let tenant_a = format!("a-{suffix}");
        let tenant_ab = format!("a-{suffix}:b");
        let hint_bc = "b:c";
        let hint_c = "c";

        let r1 = rev();
        let r2 = rev();
        store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: &tenant_a,
                    hint: hint_bc,
                },
                r1,
                1,
                Duration::from_secs(60),
            )
            .await;
        store
            .try_pin(
                PinKey {
                    env_id: "local",
                    deployment_id: dep_id,
                    tenant: &tenant_ab,
                    hint: hint_c,
                },
                r2,
                1,
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: &tenant_a,
                        hint: hint_bc
                    },
                    1
                )
                .await,
            Some(r1),
        );
        assert_eq!(
            store
                .lookup(
                    PinKey {
                        env_id: "local",
                        deployment_id: dep_id,
                        tenant: &tenant_ab,
                        hint: hint_c
                    },
                    1
                )
                .await,
            Some(r2),
        );
    }
}
