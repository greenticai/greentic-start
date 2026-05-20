//! Revision dispatcher (B1) — `plans/next-gen-deployment.md` §P3, §1324.
//!
//! Authoritative in-process traffic splitter. Lives between the HTTP route
//! table and the runner host on local / single-VM / K8s router. B1 ships the
//! pure state + selection module:
//!
//! - per-`deployment_id` `TrafficSplit` held in [`ArcSwap`] for atomic swaps;
//! - per-request selection order: trusted header → HMAC cookie → session pin →
//!   weighted random over basis points;
//! - HMAC-SHA256-signed cookie binding `{env_id, tenant, deployment_id,
//!   revision_id, generation, expires_at}`;
//! - in-memory session-hint pin (Redis pin is B6).
//!
//! Not in B1:
//!
//! - ingress integration (B3) — `DispatchRequest` takes a pre-resolved
//!   `deployment_id` from the caller. Route binding to `(host, path-prefix,
//!   connector) → deployment_id` belongs to the ingress, not here.
//! - `ActivePacks` / per-revision route tables (B2 + B3). The dispatcher
//!   currently stores only `(revision_id, bundle_id, weight_bps)` per entry;
//!   B2 will plug in the per-revision runtime handles when the runner grows
//!   `load_revision`.
//! - HMAC signing-key wiring to the env's secrets backend. B1 takes the key
//!   from the caller (`[u8; 32]`). Same scaffolding-ahead-of-producer pattern
//!   as B0 (the runtime-config producer lands in B4).

// B3 will remove this — the dispatcher is constructed and consumed by ingress
// once route binding lands.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use greentic_deploy_spec::{BundleId, DeploymentId, RevisionId};
use hmac::{Hmac, Mac};
use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use ulid::Ulid;

use crate::runtime_config::LoadedRuntimeConfig;

type HmacSha256 = Hmac<Sha256>;

/// Sum of basis points across a deployment's revisions. Mirrors deploy-spec §5.3.
const TOTAL_WEIGHT_BPS: u32 = 10_000;

/// Hard cap on the in-memory session-hint pin map. Mirrors the
/// `directline_session::MAX_TRACKED_CONVERSATIONS` discipline so rotating-hint
/// public traffic cannot grow the map without bound.
const MAX_PINS: usize = 16_384;

/// Cookie name prefix; full name is `_gt_rev_<deployment_id>`.
pub const COOKIE_PREFIX: &str = "_gt_rev_";

pub const DEPLOYMENT_HEADER: &str = "X-Greentic-Deployment";
pub const REVISION_HEADER: &str = "X-Greentic-Revision";

/// Cookie name a B3 ingress should look up for stickiness on a given deployment.
pub fn cookie_name(deployment_id: DeploymentId) -> String {
    format!("{COOKIE_PREFIX}{deployment_id}")
}

#[derive(Clone, Debug)]
pub struct RevisionEntry {
    pub revision_id: RevisionId,
    pub bundle_id: BundleId,
    pub weight_bps: u32,
}

#[derive(Clone, Debug)]
pub struct DeploymentEntry {
    pub bundle_id: BundleId,
    pub generation: u64,
    pub revisions: Vec<RevisionEntry>,
}

#[derive(Clone, Debug, Default)]
struct Snapshot {
    deployments: HashMap<DeploymentId, DeploymentEntry>,
}

/// Selection inputs. The caller (B3 ingress) has already resolved
/// `deployment_id` from `(host, path-prefix, connector)` and authenticated the
/// tenant; B1 does not reach into the request itself.
pub struct DispatchRequest<'a> {
    pub env_id: &'a str,
    pub tenant: &'a str,
    pub deployment_id: DeploymentId,
    pub session_hint: Option<&'a str>,
    /// `true` only for mTLS / authenticated admin / signed debug traffic. Public
    /// client traffic MUST set this to `false` — the header path is a debug
    /// affordance, not a public selector.
    pub trusted: bool,
    pub header_revision: Option<RevisionId>,
    /// Inbound cookie value (just the value, not `Name=`); B3 parses the
    /// `Cookie` header and hands the value to us.
    pub cookie: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionReason {
    Header,
    Cookie,
    Pin,
    Weighted,
}

/// Set-Cookie directive the caller (B3) wraps into a full header — attributes
/// (`Path`, `Secure`, `HttpOnly`, `SameSite=Lax`) are an ingress concern, not
/// the dispatcher's.
#[derive(Clone, Debug)]
pub struct SetCookieDirective {
    pub name: String,
    pub value: String,
    pub max_age: Duration,
}

#[derive(Clone, Debug)]
pub struct DispatchOutcome {
    pub revision_id: RevisionId,
    pub bundle_id: BundleId,
    pub reason: SelectionReason,
    pub set_cookie: Option<SetCookieDirective>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CookiePayload {
    e: String, // env_id
    t: String, // tenant
    d: String, // deployment_id (ULID display)
    r: String, // revision_id (ULID display)
    g: u64,    // generation
    x: u64,    // expires_at (seconds since UNIX_EPOCH)
}

#[derive(Clone, Debug)]
struct PinEntry {
    revision_id: RevisionId,
    /// Deployment generation at the time of pin creation. Stale pins (whose
    /// generation no longer matches the current split) are dropped on lookup,
    /// matching the cookie invalidation contract.
    generation: u64,
    expires_at: Instant,
}

pub struct RevisionDispatcherConfig {
    pub env_id: String,
    pub signing_key: [u8; 32],
    pub cookie_ttl: Duration,
    pub pin_ttl: Duration,
}

impl RevisionDispatcherConfig {
    /// Sensible defaults: 1h cookie TTL + 1h pin TTL. Tune at the call site.
    pub fn new(env_id: impl Into<String>, signing_key: [u8; 32]) -> Self {
        Self {
            env_id: env_id.into(),
            signing_key,
            cookie_ttl: Duration::from_secs(3600),
            pin_ttl: Duration::from_secs(3600),
        }
    }
}

pub struct RevisionDispatcher {
    env_id: String,
    signing_key: [u8; 32],
    cookie_ttl: Duration,
    pin_ttl: Duration,
    snapshot: ArcSwap<Snapshot>,
    pins: Mutex<HashMap<(DeploymentId, String, String), PinEntry>>,
    /// Serializes `apply_traffic_split` so the load → validate → store
    /// sequence is race-free. Reads remain lock-free through `snapshot`.
    write_lock: Mutex<()>,
}

impl std::fmt::Debug for RevisionDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevisionDispatcher")
            .field("env_id", &self.env_id)
            .field("cookie_ttl", &self.cookie_ttl)
            .field("pin_ttl", &self.pin_ttl)
            .field("deployments", &self.snapshot.load().deployments.len())
            .finish_non_exhaustive()
    }
}

impl RevisionDispatcher {
    pub fn new(cfg: RevisionDispatcherConfig) -> Self {
        Self {
            env_id: cfg.env_id,
            signing_key: cfg.signing_key,
            cookie_ttl: cfg.cookie_ttl,
            pin_ttl: cfg.pin_ttl,
            snapshot: ArcSwap::from_pointee(Snapshot::default()),
            pins: Mutex::new(HashMap::new()),
            write_lock: Mutex::new(()),
        }
    }

    /// Build a dispatcher from a runtime-config (B0 output). Parses ULID
    /// strings into typed ids and groups revisions by deployment.
    ///
    /// B0 already enforces the per-deployment invariants (one bundle, no
    /// duplicate revision id, weights sum to 10,000). We do not re-validate
    /// here — the boundary between B0 and B1 is internal. `apply_traffic_split`
    /// is the public mutation entry point and *does* re-validate.
    pub fn from_runtime_config(
        cfg: RevisionDispatcherConfig,
        rc: &LoadedRuntimeConfig,
    ) -> anyhow::Result<Self> {
        let mut deployments: HashMap<DeploymentId, DeploymentEntry> = HashMap::new();
        for block in &rc.revisions {
            let deployment_id = DeploymentId(parse_ulid(&block.deployment_id, "deployment_id")?);
            let revision_id = RevisionId(parse_ulid(&block.revision_id, "revision_id")?);
            let bundle_id = BundleId::new(&block.bundle_id);
            let entry = RevisionEntry {
                revision_id,
                bundle_id: bundle_id.clone(),
                weight_bps: block.weight_bps,
            };
            deployments
                .entry(deployment_id)
                .and_modify(|d| d.revisions.push(entry.clone()))
                .or_insert(DeploymentEntry {
                    bundle_id,
                    generation: 0,
                    revisions: vec![entry],
                });
        }
        let dispatcher = Self::new(cfg);
        dispatcher
            .snapshot
            .store(std::sync::Arc::new(Snapshot { deployments }));
        Ok(dispatcher)
    }

    pub fn deployment_count(&self) -> usize {
        self.snapshot.load().deployments.len()
    }

    /// Atomic per-deployment traffic-split swap. Enforces `expected_generation`
    /// for optimistic concurrency, that all entries belong to the deployment's
    /// bundle, that no revision id repeats, and that weights sum to 10,000.
    /// Returns the new generation.
    pub fn apply_traffic_split(
        &self,
        deployment_id: DeploymentId,
        new_revisions: Vec<RevisionEntry>,
        bundle_id: BundleId,
        expected_generation: u64,
    ) -> anyhow::Result<u64> {
        if new_revisions.is_empty() {
            bail!("traffic split for deployment `{deployment_id}` must have at least one revision");
        }
        let mut sum: u64 = 0;
        let mut seen: std::collections::HashSet<RevisionId> = std::collections::HashSet::new();
        for entry in &new_revisions {
            if entry.bundle_id != bundle_id {
                bail!(
                    "revision `{}` declares bundle `{}`, expected `{}`",
                    entry.revision_id,
                    entry.bundle_id,
                    bundle_id
                );
            }
            if !seen.insert(entry.revision_id) {
                bail!(
                    "revision `{}` appears more than once in deployment `{}`",
                    entry.revision_id,
                    deployment_id
                );
            }
            sum += entry.weight_bps as u64;
        }
        if sum != TOTAL_WEIGHT_BPS as u64 {
            bail!(
                "traffic split for deployment `{deployment_id}` weights sum to {sum} bps, expected {TOTAL_WEIGHT_BPS}"
            );
        }

        // Serialize the load → validate → store sequence: without it, two
        // concurrent callers with the same `expected_generation` both observe
        // the pre-update snapshot and the second `store` clobbers the first
        // (also losing unrelated deployment updates in the clone).
        let _w = self.write_lock.lock().expect("write lock poisoned");

        let prev = self.snapshot.load_full();
        let existing = prev.deployments.get(&deployment_id);
        let current_gen = existing.map(|d| d.generation).unwrap_or(0);
        if current_gen != expected_generation {
            bail!(
                "stale generation for deployment `{deployment_id}`: caller has {expected_generation}, current is {current_gen}"
            );
        }
        if let Some(d) = existing
            && d.bundle_id != bundle_id
        {
            bail!(
                "deployment `{deployment_id}` is bound to bundle `{}`; cannot rebind to `{bundle_id}` via apply_traffic_split",
                d.bundle_id
            );
        }

        let mut next = (*prev).clone();
        let new_generation = current_gen + 1;
        next.deployments.insert(
            deployment_id,
            DeploymentEntry {
                bundle_id,
                generation: new_generation,
                revisions: new_revisions,
            },
        );
        self.snapshot.store(std::sync::Arc::new(next));
        Ok(new_generation)
    }

    /// Pick a revision per §P3 priority order. Mutates internal pin state when a
    /// new session_hint binds to a revision. RNG is injected so tests can seed.
    pub fn dispatch<R: Rng + ?Sized>(
        &self,
        req: &DispatchRequest<'_>,
        rng: &mut R,
    ) -> anyhow::Result<DispatchOutcome> {
        let snap = self.snapshot.load_full();
        let entry = snap.deployments.get(&req.deployment_id).with_context(|| {
            format!("deployment `{}` not known to dispatcher", req.deployment_id)
        })?;
        let now = now_secs();

        if req.trusted
            && let Some(rev) = req.header_revision
            && has_revision(entry, rev)
        {
            return Ok(DispatchOutcome {
                revision_id: rev,
                bundle_id: entry.bundle_id.clone(),
                reason: SelectionReason::Header,
                set_cookie: None,
            });
        }

        if let Some(cookie) = req.cookie
            && let Some(rev) = self.verify_cookie(
                cookie,
                req.env_id,
                req.tenant,
                req.deployment_id,
                entry.generation,
                now,
            )
            && has_revision(entry, rev)
        {
            return Ok(DispatchOutcome {
                revision_id: rev,
                bundle_id: entry.bundle_id.clone(),
                reason: SelectionReason::Cookie,
                set_cookie: None,
            });
        }

        if let Some(hint) = req.session_hint {
            let pin_key = (req.deployment_id, req.tenant.to_string(), hint.to_string());
            let now_inst = Instant::now();
            let pinned = {
                let mut pins = self.pins.lock().expect("pin mutex poisoned");
                match pins.get(&pin_key) {
                    Some(p)
                        if p.expires_at > now_inst
                            && p.generation == entry.generation
                            && has_revision(entry, p.revision_id) =>
                    {
                        Some(p.revision_id)
                    }
                    Some(_) => {
                        pins.remove(&pin_key);
                        None
                    }
                    None => None,
                }
            };
            if let Some(rev) = pinned {
                return Ok(DispatchOutcome {
                    revision_id: rev,
                    bundle_id: entry.bundle_id.clone(),
                    reason: SelectionReason::Pin,
                    set_cookie: Some(self.build_set_cookie(req, entry, rev, now)),
                });
            }
        }

        let selected = weighted_pick(&entry.revisions, rng)?;
        if let Some(hint) = req.session_hint {
            let pin_key = (req.deployment_id, req.tenant.to_string(), hint.to_string());
            self.insert_pin(pin_key, selected, entry.generation);
        }
        Ok(DispatchOutcome {
            revision_id: selected,
            bundle_id: entry.bundle_id.clone(),
            reason: SelectionReason::Weighted,
            set_cookie: Some(self.build_set_cookie(req, entry, selected, now)),
        })
    }

    /// Bounded pin insert. Sweeps expired entries when at capacity, then
    /// evicts the soonest-to-expire entry if still at cap. Same eviction
    /// discipline as the DirectLine conversation cache in this crate, so a
    /// rotating-session-hint client cannot grow the map without bound.
    fn insert_pin(
        &self,
        key: (DeploymentId, String, String),
        revision_id: RevisionId,
        generation: u64,
    ) {
        let now = Instant::now();
        let mut pins = self.pins.lock().expect("pin mutex poisoned");
        if pins.len() >= MAX_PINS && !pins.contains_key(&key) {
            pins.retain(|_, e| e.expires_at > now);
            if pins.len() >= MAX_PINS
                && let Some(victim) = pins
                    .iter()
                    .min_by_key(|(_, e)| e.expires_at)
                    .map(|(k, _)| k.clone())
            {
                pins.remove(&victim);
            }
        }
        pins.insert(
            key,
            PinEntry {
                revision_id,
                generation,
                expires_at: now + self.pin_ttl,
            },
        );
    }

    fn build_set_cookie(
        &self,
        req: &DispatchRequest<'_>,
        entry: &DeploymentEntry,
        revision: RevisionId,
        now_secs: u64,
    ) -> SetCookieDirective {
        let value = self.seal_cookie(
            req.env_id,
            req.tenant,
            req.deployment_id,
            revision,
            entry.generation,
            now_secs + self.cookie_ttl.as_secs(),
        );
        SetCookieDirective {
            name: cookie_name(req.deployment_id),
            value,
            max_age: self.cookie_ttl,
        }
    }

    /// Encode + HMAC-SHA256 the cookie payload. Format: `<b64-payload>.<b64-mac>`.
    pub fn seal_cookie(
        &self,
        env_id: &str,
        tenant: &str,
        deployment_id: DeploymentId,
        revision_id: RevisionId,
        generation: u64,
        expires_at: u64,
    ) -> String {
        let payload = CookiePayload {
            e: env_id.to_string(),
            t: tenant.to_string(),
            d: deployment_id.to_string(),
            r: revision_id.to_string(),
            g: generation,
            x: expires_at,
        };
        let body = serde_json::to_vec(&payload).expect("cookie payload serializes");
        let body_b64 = URL_SAFE_NO_PAD.encode(&body);
        let mut mac =
            <HmacSha256 as hmac::KeyInit>::new_from_slice(&self.signing_key).expect("hmac key");
        mac.update(body_b64.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{body_b64}.{sig_b64}")
    }

    /// Verify a cookie value against the expected binding. Returns the bound
    /// revision id only when every field matches and the cookie is unexpired.
    pub fn verify_cookie(
        &self,
        cookie: &str,
        env_id: &str,
        tenant: &str,
        deployment_id: DeploymentId,
        expected_generation: u64,
        now_secs: u64,
    ) -> Option<RevisionId> {
        let (body_b64, sig_b64) = cookie.split_once('.')?;
        let sig = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
        let mut mac =
            <HmacSha256 as hmac::KeyInit>::new_from_slice(&self.signing_key).expect("hmac key");
        mac.update(body_b64.as_bytes());
        mac.verify_slice(&sig).ok()?; // constant-time

        let body = URL_SAFE_NO_PAD.decode(body_b64).ok()?;
        let payload: CookiePayload = serde_json::from_slice(&body).ok()?;
        if payload.e != env_id || payload.t != tenant {
            return None;
        }
        if payload.d != deployment_id.to_string() {
            return None;
        }
        if payload.g != expected_generation {
            return None;
        }
        if payload.x <= now_secs {
            return None;
        }
        let rev_ulid = Ulid::from_string(&payload.r).ok()?;
        Some(RevisionId(rev_ulid))
    }
}

fn has_revision(entry: &DeploymentEntry, revision: RevisionId) -> bool {
    entry
        .revisions
        .iter()
        .any(|r| r.revision_id == revision && r.weight_bps > 0)
}

fn weighted_pick<R: Rng + ?Sized>(
    revisions: &[RevisionEntry],
    rng: &mut R,
) -> anyhow::Result<RevisionId> {
    let total: u64 = revisions.iter().map(|r| r.weight_bps as u64).sum();
    if total == 0 {
        bail!("no non-zero-weight revisions available");
    }
    let mut pick = rng.random_range(0..total);
    for r in revisions {
        let w = r.weight_bps as u64;
        if pick < w {
            return Ok(r.revision_id);
        }
        pick -= w;
    }
    // Unreachable: pick < total and sum(w) == total.
    Ok(revisions
        .last()
        .expect("non-empty checked above")
        .revision_id)
}

fn parse_ulid(s: &str, label: &str) -> anyhow::Result<Ulid> {
    Ulid::from_string(s).with_context(|| format!("invalid {label} `{s}` (expected ULID)"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_config::{LoadedRuntimeConfig, ResolvedRevisionBlock};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use std::path::PathBuf;

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    fn cfg(env: &str) -> RevisionDispatcherConfig {
        RevisionDispatcherConfig::new(env, key())
    }

    fn dep() -> DeploymentId {
        DeploymentId::new()
    }
    fn rev() -> RevisionId {
        RevisionId::new()
    }
    fn bundle() -> BundleId {
        BundleId::new("customer.support")
    }

    fn dispatcher_with(
        deployment: DeploymentId,
        revisions: Vec<RevisionEntry>,
    ) -> RevisionDispatcher {
        let d = RevisionDispatcher::new(cfg("local"));
        let bid = revisions[0].bundle_id.clone();
        let generation = d
            .apply_traffic_split(deployment, revisions, bid, 0)
            .expect("apply_traffic_split");
        assert_eq!(generation, 1);
        d
    }

    fn entry(rev: RevisionId, w: u32) -> RevisionEntry {
        RevisionEntry {
            revision_id: rev,
            bundle_id: bundle(),
            weight_bps: w,
        }
    }

    #[test]
    fn from_runtime_config_groups_by_deployment() {
        let dep1 = Ulid::new();
        let dep2 = Ulid::new();
        let r1 = Ulid::new();
        let r2 = Ulid::new();
        let r3 = Ulid::new();
        let rc = LoadedRuntimeConfig {
            env_id: "local".into(),
            revisions: vec![
                ResolvedRevisionBlock {
                    deployment_id: dep1.to_string(),
                    revision_id: r1.to_string(),
                    bundle_id: "a".into(),
                    pack_list_refs: vec![PathBuf::new()],
                    pack_config_refs: vec![],
                    weight_bps: 6000,
                },
                ResolvedRevisionBlock {
                    deployment_id: dep1.to_string(),
                    revision_id: r2.to_string(),
                    bundle_id: "a".into(),
                    pack_list_refs: vec![PathBuf::new()],
                    pack_config_refs: vec![],
                    weight_bps: 4000,
                },
                ResolvedRevisionBlock {
                    deployment_id: dep2.to_string(),
                    revision_id: r3.to_string(),
                    bundle_id: "b".into(),
                    pack_list_refs: vec![PathBuf::new()],
                    pack_config_refs: vec![],
                    weight_bps: 10_000,
                },
            ],
        };
        let d = RevisionDispatcher::from_runtime_config(cfg("local"), &rc).unwrap();
        assert_eq!(d.deployment_count(), 2);
    }

    #[test]
    fn from_runtime_config_rejects_non_ulid_ids() {
        let rc = LoadedRuntimeConfig {
            env_id: "local".into(),
            revisions: vec![ResolvedRevisionBlock {
                deployment_id: "not-a-ulid".into(),
                revision_id: Ulid::new().to_string(),
                bundle_id: "a".into(),
                pack_list_refs: vec![],
                pack_config_refs: vec![],
                weight_bps: 10_000,
            }],
        };
        let err = RevisionDispatcher::from_runtime_config(cfg("local"), &rc).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid deployment_id"), "{msg}");
    }

    #[test]
    fn apply_traffic_split_rejects_empty() {
        let d = RevisionDispatcher::new(cfg("local"));
        let err = d
            .apply_traffic_split(dep(), vec![], bundle(), 0)
            .unwrap_err();
        assert!(format!("{err:#}").contains("at least one"));
    }

    #[test]
    fn apply_traffic_split_rejects_wrong_bundle() {
        let d = RevisionDispatcher::new(cfg("local"));
        let r = rev();
        let e = RevisionEntry {
            revision_id: r,
            bundle_id: BundleId::new("other"),
            weight_bps: 10_000,
        };
        let err = d
            .apply_traffic_split(dep(), vec![e], bundle(), 0)
            .unwrap_err();
        assert!(format!("{err:#}").contains("expected `customer.support`"));
    }

    #[test]
    fn apply_traffic_split_rejects_duplicate_revision() {
        let d = RevisionDispatcher::new(cfg("local"));
        let r = rev();
        let err = d
            .apply_traffic_split(dep(), vec![entry(r, 5000), entry(r, 5000)], bundle(), 0)
            .unwrap_err();
        assert!(format!("{err:#}").contains("appears more than once"));
    }

    #[test]
    fn apply_traffic_split_rejects_bad_sum() {
        let d = RevisionDispatcher::new(cfg("local"));
        let err = d
            .apply_traffic_split(dep(), vec![entry(rev(), 9999)], bundle(), 0)
            .unwrap_err();
        assert!(format!("{err:#}").contains("weights sum to 9999"));
    }

    #[test]
    fn apply_traffic_split_rejects_stale_generation() {
        let d = RevisionDispatcher::new(cfg("local"));
        let dep_id = dep();
        d.apply_traffic_split(dep_id, vec![entry(rev(), 10_000)], bundle(), 0)
            .unwrap();
        let err = d
            .apply_traffic_split(dep_id, vec![entry(rev(), 10_000)], bundle(), 0)
            .unwrap_err();
        assert!(format!("{err:#}").contains("stale generation"));
    }

    #[test]
    fn dispatch_unknown_deployment_errors() {
        let d = RevisionDispatcher::new(cfg("local"));
        let mut rng = StdRng::seed_from_u64(0);
        let err = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep(),
                    session_hint: None,
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .unwrap_err();
        assert!(format!("{err:#}").contains("not known to dispatcher"));
    }

    #[test]
    fn dispatch_weighted_respects_basis_points() {
        let dep_id = dep();
        let r_a = rev();
        let r_b = rev();
        let d = dispatcher_with(dep_id, vec![entry(r_a, 9000), entry(r_b, 1000)]);
        let mut rng = StdRng::seed_from_u64(42);
        let mut a = 0u32;
        let mut b = 0u32;
        for _ in 0..10_000 {
            let out = d
                .dispatch(
                    &DispatchRequest {
                        env_id: "local",
                        tenant: "t",
                        deployment_id: dep_id,
                        session_hint: None,
                        trusted: false,
                        header_revision: None,
                        cookie: None,
                    },
                    &mut rng,
                )
                .unwrap();
            if out.revision_id == r_a {
                a += 1;
            } else if out.revision_id == r_b {
                b += 1;
            }
        }
        // 90/10 split — allow ±2 percentage points of slack.
        assert!((8800..=9200).contains(&a), "a={a}");
        assert!((800..=1200).contains(&b), "b={b}");
    }

    #[test]
    fn dispatch_weighted_isolates_deployments() {
        let d = RevisionDispatcher::new(cfg("local"));
        let dep_a = dep();
        let dep_b = dep();
        let r_a = rev();
        let r_b = rev();
        d.apply_traffic_split(dep_a, vec![entry(r_a, 10_000)], bundle(), 0)
            .unwrap();
        d.apply_traffic_split(dep_b, vec![entry(r_b, 10_000)], bundle(), 0)
            .unwrap();
        let mut rng = StdRng::seed_from_u64(0);
        for _ in 0..50 {
            let out_a = d
                .dispatch(
                    &DispatchRequest {
                        env_id: "local",
                        tenant: "t",
                        deployment_id: dep_a,
                        session_hint: None,
                        trusted: false,
                        header_revision: None,
                        cookie: None,
                    },
                    &mut rng,
                )
                .unwrap();
            let out_b = d
                .dispatch(
                    &DispatchRequest {
                        env_id: "local",
                        tenant: "t",
                        deployment_id: dep_b,
                        session_hint: None,
                        trusted: false,
                        header_revision: None,
                        cookie: None,
                    },
                    &mut rng,
                )
                .unwrap();
            assert_eq!(out_a.revision_id, r_a);
            assert_eq!(out_b.revision_id, r_b);
        }
    }

    #[test]
    fn dispatch_trusted_header_overrides_when_revision_ready() {
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 9000), entry(r2, 1000)]);
        let mut rng = StdRng::seed_from_u64(0);
        let out = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: None,
                    trusted: true,
                    header_revision: Some(r2),
                    cookie: None,
                },
                &mut rng,
            )
            .unwrap();
        assert_eq!(out.revision_id, r2);
        assert_eq!(out.reason, SelectionReason::Header);
        assert!(out.set_cookie.is_none());
    }

    #[test]
    fn dispatch_header_ignored_when_untrusted() {
        let dep_id = dep();
        let r1 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 10_000)]);
        let mut rng = StdRng::seed_from_u64(0);
        let other = rev();
        let out = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: None,
                    trusted: false,
                    header_revision: Some(other),
                    cookie: None,
                },
                &mut rng,
            )
            .unwrap();
        assert_eq!(out.revision_id, r1);
        assert_eq!(out.reason, SelectionReason::Weighted);
    }

    #[test]
    fn dispatch_header_ignored_when_revision_not_in_split() {
        let dep_id = dep();
        let r1 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 10_000)]);
        let mut rng = StdRng::seed_from_u64(0);
        let ghost = rev();
        let out = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: None,
                    trusted: true,
                    header_revision: Some(ghost),
                    cookie: None,
                },
                &mut rng,
            )
            .unwrap();
        assert_eq!(out.revision_id, r1);
        assert_eq!(out.reason, SelectionReason::Weighted);
    }

    #[test]
    fn cookie_verify_roundtrip() {
        let d = RevisionDispatcher::new(cfg("local"));
        let dep_id = dep();
        let r = rev();
        let cookie = d.seal_cookie("local", "tenant-a", dep_id, r, 3, 9_999_999_999);
        let out = d
            .verify_cookie(&cookie, "local", "tenant-a", dep_id, 3, 0)
            .unwrap();
        assert_eq!(out, r);
    }

    #[test]
    fn cookie_verify_rejects_mismatches() {
        let d = RevisionDispatcher::new(cfg("local"));
        let dep_id = dep();
        let r = rev();
        let cookie = d.seal_cookie("local", "tenant-a", dep_id, r, 3, 9_999_999_999);
        // wrong env
        assert!(
            d.verify_cookie(&cookie, "prod", "tenant-a", dep_id, 3, 0)
                .is_none()
        );
        // wrong tenant
        assert!(
            d.verify_cookie(&cookie, "local", "tenant-b", dep_id, 3, 0)
                .is_none()
        );
        // wrong deployment
        assert!(
            d.verify_cookie(&cookie, "local", "tenant-a", dep(), 3, 0)
                .is_none()
        );
        // wrong generation
        assert!(
            d.verify_cookie(&cookie, "local", "tenant-a", dep_id, 4, 0)
                .is_none()
        );
        // expired
        assert!(
            d.verify_cookie(&cookie, "local", "tenant-a", dep_id, 3, 10_000_000_000)
                .is_none()
        );
        // tampered signature
        let mut tampered = cookie.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert!(
            d.verify_cookie(&tampered, "local", "tenant-a", dep_id, 3, 0)
                .is_none()
        );
        // tampered body
        let (body, sig) = cookie.split_once('.').unwrap();
        let mut body = body.to_string();
        body.pop();
        body.push('X');
        let tampered = format!("{body}.{sig}");
        assert!(
            d.verify_cookie(&tampered, "local", "tenant-a", dep_id, 3, 0)
                .is_none()
        );
        // garbage
        assert!(
            d.verify_cookie("not-a-cookie", "local", "tenant-a", dep_id, 3, 0)
                .is_none()
        );
    }

    #[test]
    fn dispatch_honors_valid_cookie() {
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        // generation is 1 after apply_traffic_split.
        let cookie = d.seal_cookie("local", "t", dep_id, r2, 1, 9_999_999_999);
        let mut rng = StdRng::seed_from_u64(0);
        let out = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: None,
                    trusted: false,
                    header_revision: None,
                    cookie: Some(&cookie),
                },
                &mut rng,
            )
            .unwrap();
        assert_eq!(out.revision_id, r2);
        assert_eq!(out.reason, SelectionReason::Cookie);
        assert!(out.set_cookie.is_none());
    }

    #[test]
    fn dispatch_ignores_cookie_after_generation_bump() {
        let d = RevisionDispatcher::new(cfg("local"));
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        d.apply_traffic_split(dep_id, vec![entry(r1, 5000), entry(r2, 5000)], bundle(), 0)
            .unwrap();
        // Cookie issued at gen=1.
        let cookie = d.seal_cookie("local", "t", dep_id, r2, 1, 9_999_999_999);
        // Operator bumps the split (gen → 2).
        d.apply_traffic_split(dep_id, vec![entry(r1, 9000), entry(r2, 1000)], bundle(), 1)
            .unwrap();
        // Stale cookie must be discarded — selection falls through to weighted.
        let mut rng = StdRng::seed_from_u64(0);
        let out = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: None,
                    trusted: false,
                    header_revision: None,
                    cookie: Some(&cookie),
                },
                &mut rng,
            )
            .unwrap();
        assert_eq!(out.reason, SelectionReason::Weighted);
        assert!(out.set_cookie.is_some());
    }

    #[test]
    fn pin_is_established_on_weighted_and_honored_next_request() {
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        let mut rng = StdRng::seed_from_u64(11);
        let first = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-A"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .unwrap();
        assert_eq!(first.reason, SelectionReason::Weighted);
        let second = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-A"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .unwrap();
        assert_eq!(second.reason, SelectionReason::Pin);
        assert_eq!(second.revision_id, first.revision_id);
    }

    #[test]
    fn pin_falls_through_to_weighted_when_revision_archived() {
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        let mut rng = StdRng::seed_from_u64(7);
        // First request pins to whichever revision wins the weighted pick.
        let first = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-X"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .unwrap();
        let pinned = first.revision_id;
        // Operator removes the pinned revision from the split (replaces it with a fresh one).
        let r_new = rev();
        let kept = if pinned == r1 { r2 } else { r1 };
        d.apply_traffic_split(
            dep_id,
            vec![entry(kept, 5000), entry(r_new, 5000)],
            bundle(),
            1,
        )
        .unwrap();
        // Same session hint now falls back to weighted + re-pins.
        let again = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-X"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .unwrap();
        assert_ne!(again.revision_id, pinned);
        assert_eq!(again.reason, SelectionReason::Weighted);
    }

    #[test]
    fn weighted_skips_zero_weight_revisions() {
        let dep_id = dep();
        let r_active = rev();
        let r_zero = rev();
        let d = dispatcher_with(dep_id, vec![entry(r_active, 10_000), entry(r_zero, 0)]);
        let mut rng = StdRng::seed_from_u64(5);
        for _ in 0..50 {
            let out = d
                .dispatch(
                    &DispatchRequest {
                        env_id: "local",
                        tenant: "t",
                        deployment_id: dep_id,
                        session_hint: None,
                        trusted: false,
                        header_revision: None,
                        cookie: None,
                    },
                    &mut rng,
                )
                .unwrap();
            assert_eq!(out.revision_id, r_active);
        }
    }

    #[test]
    fn cookie_name_uses_deployment_prefix() {
        let id = DeploymentId(Ulid::from_string("01F8MECHZX3TBDSZ7XR8KZ9V8K").unwrap());
        assert_eq!(cookie_name(id), "_gt_rev_01F8MECHZX3TBDSZ7XR8KZ9V8K");
    }

    #[test]
    fn apply_traffic_split_rejects_rebinding_bundle() {
        let d = RevisionDispatcher::new(cfg("local"));
        let dep_id = dep();
        d.apply_traffic_split(dep_id, vec![entry(rev(), 10_000)], bundle(), 0)
            .unwrap();
        let other_bundle = BundleId::new("other.app");
        let other_entry = RevisionEntry {
            revision_id: rev(),
            bundle_id: other_bundle.clone(),
            weight_bps: 10_000,
        };
        let err = d
            .apply_traffic_split(dep_id, vec![other_entry], other_bundle, 1)
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("bound to bundle"), "{msg}");
        assert!(msg.contains("cannot rebind"), "{msg}");
    }

    #[test]
    fn apply_traffic_split_is_serialized_under_concurrent_writers() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let d = Arc::new(RevisionDispatcher::new(cfg("local")));
        let dep_id = dep();
        let successes = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..16 {
            let d = Arc::clone(&d);
            let successes = Arc::clone(&successes);
            handles.push(std::thread::spawn(move || {
                // Every thread races with expected_generation = 0; without the
                // write lock several threads could TOCTOU-validate and clobber
                // each other, so we'd see > 1 success.
                let r = entry(rev(), 10_000);
                if d.apply_traffic_split(dep_id, vec![r], bundle(), 0).is_ok() {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(successes.load(Ordering::SeqCst), 1);
        let snap = d.snapshot.load();
        assert_eq!(snap.deployments[&dep_id].generation, 1);
    }

    #[test]
    fn apply_traffic_split_preserves_unrelated_deployments_across_writers() {
        use std::sync::Arc;

        // Pre-load two deployments at gen=0 → after apply they sit at gen=1.
        let d = Arc::new(RevisionDispatcher::new(cfg("local")));
        let dep_a = dep();
        let dep_b = dep();
        let r_a0 = rev();
        let r_b0 = rev();
        d.apply_traffic_split(dep_a, vec![entry(r_a0, 10_000)], bundle(), 0)
            .unwrap();
        d.apply_traffic_split(dep_b, vec![entry(r_b0, 10_000)], bundle(), 0)
            .unwrap();

        // Race: T1 updates A from gen=1; T2 updates B from gen=1. Both must
        // land (different deployments). Pre-fix, the clone-from-snapshot model
        // could drop one because the second store overwrites the first using a
        // pre-T1 clone.
        let d_a = Arc::clone(&d);
        let d_b = Arc::clone(&d);
        let r_a1 = rev();
        let r_b1 = rev();
        let t1 = std::thread::spawn(move || {
            d_a.apply_traffic_split(dep_a, vec![entry(r_a1, 10_000)], bundle(), 1)
                .unwrap();
        });
        let t2 = std::thread::spawn(move || {
            d_b.apply_traffic_split(dep_b, vec![entry(r_b1, 10_000)], bundle(), 1)
                .unwrap();
        });
        t1.join().unwrap();
        t2.join().unwrap();

        let snap = d.snapshot.load();
        assert_eq!(snap.deployments[&dep_a].generation, 2);
        assert_eq!(snap.deployments[&dep_b].generation, 2);
        assert_eq!(snap.deployments[&dep_a].revisions[0].revision_id, r_a1);
        assert_eq!(snap.deployments[&dep_b].revisions[0].revision_id, r_b1);
    }

    #[test]
    fn pin_invalidated_when_generation_bumps_even_if_revision_still_present() {
        let d = RevisionDispatcher::new(cfg("local"));
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        d.apply_traffic_split(dep_id, vec![entry(r1, 5000), entry(r2, 5000)], bundle(), 0)
            .unwrap();
        // First dispatch pins to whichever revision wins.
        let mut rng = StdRng::seed_from_u64(11);
        let first = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-K"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .unwrap();
        assert_eq!(first.reason, SelectionReason::Weighted);

        // Operator bumps the split (gen 1 → 2) keeping BOTH revisions present
        // but with different weights. Without the per-pin generation check the
        // stale pin would still hit; with the check it must be discarded.
        d.apply_traffic_split(dep_id, vec![entry(r1, 9000), entry(r2, 1000)], bundle(), 1)
            .unwrap();

        let second = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-K"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .unwrap();
        assert_eq!(second.reason, SelectionReason::Weighted);
    }

    #[test]
    fn pin_map_stays_bounded_under_rotating_session_hints() {
        let dep_id = dep();
        let d = dispatcher_with(dep_id, vec![entry(rev(), 10_000)]);
        let mut rng = StdRng::seed_from_u64(0);
        // Drive 2x the cap through unique hints. Without the bound the map
        // would hold 32_768 entries; with it, it must stay ≤ MAX_PINS.
        for i in 0..(MAX_PINS * 2) {
            let hint = format!("sess-{i}");
            d.dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some(&hint),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .unwrap();
        }
        let len = d.pins.lock().unwrap().len();
        assert!(len <= MAX_PINS, "pin map grew to {len}");
    }
}
