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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

use crate::revision_pin::{InMemoryPinStore, PinKey, PinOutcome, RevisionPinStore, now_secs};
use crate::runtime_config::LoadedRuntimeConfig;

type HmacSha256 = Hmac<Sha256>;

/// Sum of basis points across a deployment's revisions. Mirrors deploy-spec §5.3.
const TOTAL_WEIGHT_BPS: u32 = 10_000;

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
    /// Revisions flagged by [`RevisionDispatcher::mark_draining`]. Weighted
    /// selection skips them and `try_pin` is suppressed for them, but
    /// existing pin/cookie/header bindings still route through so in-flight
    /// HTTP sessions can finish during the drain window.
    pub draining: HashSet<RevisionId>,
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
    /// Session-hint pin store. Defaults to in-memory; Redis-backed
    /// implementations swap in via [`Self::with_pin_store`] so a horizontally
    /// scaled router (Phase D K8s slice) can share pins across pods.
    pin_store: Arc<dyn RevisionPinStore>,
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
        Self::with_pin_store(cfg, Arc::new(InMemoryPinStore::new()))
    }

    /// Build a dispatcher with a custom pin store. Production deployments
    /// inject a [`crate::revision_pin::RedisPinStore`] so session stickiness
    /// is shared across router pods; tests + single-process / `local` fall
    /// back to [`InMemoryPinStore`] via [`Self::new`].
    pub fn with_pin_store(
        cfg: RevisionDispatcherConfig,
        pin_store: Arc<dyn RevisionPinStore>,
    ) -> Self {
        Self {
            env_id: cfg.env_id,
            signing_key: cfg.signing_key,
            cookie_ttl: cfg.cookie_ttl,
            pin_ttl: cfg.pin_ttl,
            snapshot: ArcSwap::from_pointee(Snapshot::default()),
            pin_store,
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
    pub(crate) fn from_runtime_config(
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
                    draining: HashSet::new(),
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

    /// Env this dispatcher routes for. The ingress seam uses it to build the
    /// [`DispatchRequest`] so cookie validation binds to the right env.
    pub fn env_id(&self) -> &str {
        &self.env_id
    }

    /// Flag `revision_id` as draining under `deployment_id`. Weighted picks
    /// will skip it and `try_pin` writes against it are suppressed, but
    /// existing pin / valid cookie / trusted-header overrides still route to
    /// it so in-flight HTTP and cookie sessions can finish during the drain
    /// window. Returns `true` if the flag was newly added, `false` if it was
    /// already set or the deployment / revision is unknown — idempotent.
    pub fn mark_draining(&self, deployment_id: DeploymentId, revision_id: RevisionId) -> bool {
        self.mutate_deployment(deployment_id, |entry| {
            if !has_revision_any_weight(entry, revision_id) {
                return false;
            }
            entry.draining.insert(revision_id)
        })
    }

    /// Clear the draining flag for `(deployment_id, revision_id)`. Returns
    /// `true` if the flag was set and is now cleared, `false` otherwise.
    /// Idempotent; provided for rollback symmetry with [`mark_draining`].
    pub fn unmark_draining(&self, deployment_id: DeploymentId, revision_id: RevisionId) -> bool {
        self.mutate_deployment(deployment_id, |entry| entry.draining.remove(&revision_id))
    }

    /// Remove `revision_id` from the deployment's routing table entirely —
    /// the **post-drain** state, distinct from the soft-draining flag set by
    /// [`mark_draining`]. After eviction `has_revision` returns `false`, so
    /// every selection path (cookie, pin, weighted) skips it: a client that
    /// still holds a cookie or session pin for this revision re-dispatches to
    /// a healthy revision via the weighted fallback instead of selecting a
    /// runtime that is about to be (or already) torn down.
    ///
    /// The drain coordinator calls this **after** `drain_seconds` and
    /// **before** tearing the runtime down, closing the gap between the
    /// short drain window and the much longer cookie / pin TTL. Returns
    /// `true` if the revision was present (and is now gone) or was flagged
    /// draining, `false` if it was already absent — idempotent.
    ///
    /// **Bumps the deployment generation** when it removes a revision, exactly
    /// as [`apply_traffic_split`](Self::apply_traffic_split) does. This is
    /// load-bearing, not cosmetic: cookie validation and pin lookup are both
    /// generation-scoped, so a session pinned to the evicted revision would
    /// otherwise keep resolving to it (the pin's generation still matches),
    /// fail `has_revision`, and re-roll a *fresh* weighted pick on every
    /// request — flapping across the surviving revisions for the entire pin
    /// TTL (cookie-less hint-only clients, i.e. every messaging connector,
    /// have no cookie to re-anchor them). Bumping the generation invalidates
    /// the stale cookie/pin so the next request re-pins to one surviving
    /// revision and *stays* there. The cost — every session re-picks once —
    /// is the same one-time blip any `gtc op traffic set` already imposes,
    /// and session state lives in the shared session store, so a re-pick
    /// never loses conversation state.
    ///
    /// The surviving revisions' weights no longer sum to 10,000 bps until the
    /// operator's next `gtc op traffic set` re-materializes the split, but
    /// [`weighted_pick_healthy`] picks proportionally over whatever total
    /// remains, so routing stays correct in the interim.
    pub fn evict_revision(&self, deployment_id: DeploymentId, revision_id: RevisionId) -> bool {
        self.mutate_deployment(deployment_id, |entry| {
            let had_revision = entry.revisions.iter().any(|r| r.revision_id == revision_id);
            entry.revisions.retain(|r| r.revision_id != revision_id);
            let was_draining = entry.draining.remove(&revision_id);
            let changed = had_revision || was_draining;
            if changed {
                // Re-anchor stale generation-scoped cookies/pins (see doc).
                entry.generation += 1;
            }
            changed
        })
    }

    /// `true` if the revision is currently flagged draining under the
    /// deployment. Lock-free read off the snapshot.
    pub fn is_draining(&self, deployment_id: DeploymentId, revision_id: RevisionId) -> bool {
        self.snapshot
            .load()
            .deployments
            .get(&deployment_id)
            .map(|d| d.draining.contains(&revision_id))
            .unwrap_or(false)
    }

    /// Snapshot of all draining revisions under a deployment. Returns an
    /// empty `Vec` if the deployment is unknown or nothing is draining.
    /// The drain coordinator uses this to iterate teardown work.
    pub fn draining_revisions(&self, deployment_id: DeploymentId) -> Vec<RevisionId> {
        self.snapshot
            .load()
            .deployments
            .get(&deployment_id)
            .map(|d| d.draining.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Serialize a per-deployment entry mutation under `write_lock`. `f`
    /// returns whether a change actually occurred — we only store the new
    /// snapshot when something changed, so a no-op call doesn't churn the
    /// `ArcSwap`. The lock keeps a concurrent `apply_traffic_split` from
    /// racing with a drain mark or eviction.
    fn mutate_deployment<F>(&self, deployment_id: DeploymentId, f: F) -> bool
    where
        F: FnOnce(&mut DeploymentEntry) -> bool,
    {
        let _w = self.write_lock.lock().expect("write lock poisoned");
        let prev = self.snapshot.load_full();
        if !prev.deployments.contains_key(&deployment_id) {
            return false;
        }
        let mut next = (*prev).clone();
        let entry = next
            .deployments
            .get_mut(&deployment_id)
            .expect("checked above");
        let changed = f(entry);
        if changed {
            self.snapshot.store(std::sync::Arc::new(next));
        }
        changed
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

        // Preserve drain flags for revisions still in the new split; revisions
        // that disappear lose their flag (they're gone from the route table
        // anyway, so the flag has no observable effect). Revisions that appear
        // anew start non-draining — the sensible default.
        let preserved_draining = existing
            .map(|d| {
                let new_ids: HashSet<RevisionId> =
                    new_revisions.iter().map(|r| r.revision_id).collect();
                d.draining
                    .iter()
                    .copied()
                    .filter(|rev| new_ids.contains(rev))
                    .collect()
            })
            .unwrap_or_default();

        let mut next = (*prev).clone();
        let new_generation = current_gen + 1;
        next.deployments.insert(
            deployment_id,
            DeploymentEntry {
                bundle_id,
                generation: new_generation,
                revisions: new_revisions,
                draining: preserved_draining,
            },
        );
        self.snapshot.store(std::sync::Arc::new(next));
        Ok(new_generation)
    }

    /// Pick a revision per §P3 priority order. Mutates the pin store when a
    /// new session_hint binds to a revision. RNG is injected so tests can seed.
    ///
    /// Async because B6 backs the pin map by a trait that may resolve via
    /// Redis (`gt:rev_pin:{env}:{deployment_id}:{tenant}:{hint}`). The local
    /// [`InMemoryPinStore`] is still effectively synchronous; only Redis
    /// adds the await points.
    pub async fn dispatch<R: Rng + ?Sized>(
        &self,
        req: &DispatchRequest<'_>,
        rng: &mut R,
    ) -> anyhow::Result<DispatchOutcome> {
        let snap = self.snapshot.load();
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

        if let Some(hint) = req.session_hint
            && let Some(rev) = self
                .pin_store
                .lookup(self.pin_key(req, hint), entry.generation)
                .await
            && has_revision(entry, rev)
        {
            return Ok(DispatchOutcome {
                revision_id: rev,
                bundle_id: entry.bundle_id.clone(),
                reason: SelectionReason::Pin,
                // Suppress fresh Set-Cookie on a route to a draining
                // revision so the cookie naturally expires and the next
                // request re-picks among healthy revisions. Cookie/pin TTL
                // bounds how long a draining revision keeps holding
                // existing sessions.
                set_cookie: if entry.draining.contains(&rev) {
                    None
                } else {
                    Some(self.build_set_cookie(req, entry, rev, now))
                },
            });
        }

        let selected = weighted_pick_healthy(&entry.revisions, &entry.draining, rng)?;
        let revision_id = if let Some(hint) = req.session_hint {
            // Race-safe: if a concurrent dispatch lost the lookup race but
            // already installed a pin, honor it so two requests with the same
            // hint don't flap to different revisions. `try_pin` returns
            // either the value we just inserted (`Inserted`), the value
            // that beat us (`Existing`), or `Skipped` when the backend
            // soft-failed (timeout / cap / scope-reject) — in the last
            // case nothing is persisted but we still route this request.
            //
            // Defense in depth: `weighted_pick_healthy` already excludes
            // draining revisions, so `selected` is non-draining today and
            // this guard never fires. It's kept so that if the picker is
            // ever relaxed (e.g. draining-as-last-resort fallback), a fresh
            // session still won't be pinned to a doomed revision.
            if entry.draining.contains(&selected) {
                selected
            } else {
                match self
                    .pin_store
                    .try_pin(
                        self.pin_key(req, hint),
                        selected,
                        entry.generation,
                        self.pin_ttl,
                    )
                    .await
                {
                    PinOutcome::Inserted { revision_id } | PinOutcome::Skipped { revision_id } => {
                        revision_id
                    }
                    PinOutcome::Existing { revision_id }
                        if has_revision(entry, revision_id)
                            && !entry.draining.contains(&revision_id) =>
                    {
                        revision_id
                    }
                    PinOutcome::Existing { .. } => selected,
                }
            }
        } else {
            selected
        };
        Ok(DispatchOutcome {
            revision_id,
            bundle_id: entry.bundle_id.clone(),
            reason: SelectionReason::Weighted,
            set_cookie: if entry.draining.contains(&revision_id) {
                None
            } else {
                Some(self.build_set_cookie(req, entry, revision_id, now))
            },
        })
    }

    /// Build a borrowed [`PinKey`] from a dispatch request + the resolved
    /// session hint. Centralizes the three borrow plumbings so the lookup
    /// and try_pin sites can't drift on field order or selection.
    fn pin_key<'a>(&self, req: &'a DispatchRequest<'_>, hint: &'a str) -> PinKey<'a> {
        PinKey {
            env_id: req.env_id,
            deployment_id: req.deployment_id,
            tenant: req.tenant,
            hint,
        }
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
        if Ulid::from_string(&payload.d).ok() != Some(deployment_id.0) {
            return None;
        }
        if payload.g != expected_generation {
            return None;
        }
        if payload.x <= now_secs {
            return None;
        }
        Some(RevisionId(Ulid::from_string(&payload.r).ok()?))
    }
}

fn has_revision(entry: &DeploymentEntry, revision: RevisionId) -> bool {
    entry
        .revisions
        .iter()
        .any(|r| r.revision_id == revision && r.weight_bps > 0)
}

/// Membership check that ignores weight — used by [`RevisionDispatcher::mark_draining`]
/// so an admin can drain a revision whose weight has already been rolled to 0
/// via `gtc op traffic set`.
fn has_revision_any_weight(entry: &DeploymentEntry, revision: RevisionId) -> bool {
    entry.revisions.iter().any(|r| r.revision_id == revision)
}

/// Drain-aware weighted pick: skip any revision in `draining` so new sessions
/// never land on a revision the coordinator is about to tear down.
fn weighted_pick_healthy<R: Rng + ?Sized>(
    revisions: &[RevisionEntry],
    draining: &HashSet<RevisionId>,
    rng: &mut R,
) -> anyhow::Result<RevisionId> {
    let total: u64 = revisions
        .iter()
        .filter(|r| !draining.contains(&r.revision_id))
        .map(|r| r.weight_bps as u64)
        .sum();
    if total == 0 {
        bail!("no non-zero-weight, non-draining revisions available");
    }
    let mut pick = rng.random_range(0..total);
    for r in revisions {
        if draining.contains(&r.revision_id) {
            continue;
        }
        let w = r.weight_bps as u64;
        if pick < w {
            return Ok(r.revision_id);
        }
        pick -= w;
    }
    // Unreachable: pick < total and sum(non-draining w) == total.
    Ok(revisions
        .iter()
        .rev()
        .find(|r| !draining.contains(&r.revision_id))
        .expect("at least one non-draining checked above")
        .revision_id)
}

/// Parse a Crockford-base32 ULID string into a typed [`Ulid`], with a labelled
/// error. Shared with [`crate::revision_boot`] (the activation path parses the
/// same runtime-config id strings).
pub(crate) fn parse_ulid(s: &str, label: &str) -> anyhow::Result<Ulid> {
    Ulid::from_string(s).with_context(|| format!("invalid {label} `{s}` (expected ULID)"))
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

    #[tokio::test]
    async fn dispatch_unknown_deployment_errors() {
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
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("not known to dispatcher"));
    }

    #[tokio::test]
    async fn dispatch_weighted_respects_basis_points() {
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
                .await
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

    #[tokio::test]
    async fn dispatch_weighted_isolates_deployments() {
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
                .await
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
                .await
                .unwrap();
            assert_eq!(out_a.revision_id, r_a);
            assert_eq!(out_b.revision_id, r_b);
        }
    }

    #[tokio::test]
    async fn dispatch_trusted_header_overrides_when_revision_ready() {
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
            .await
            .unwrap();
        assert_eq!(out.revision_id, r2);
        assert_eq!(out.reason, SelectionReason::Header);
        assert!(out.set_cookie.is_none());
    }

    #[tokio::test]
    async fn dispatch_header_ignored_when_untrusted() {
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
            .await
            .unwrap();
        assert_eq!(out.revision_id, r1);
        assert_eq!(out.reason, SelectionReason::Weighted);
    }

    #[tokio::test]
    async fn dispatch_header_ignored_when_revision_not_in_split() {
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
            .await
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

    #[tokio::test]
    async fn dispatch_honors_valid_cookie() {
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
            .await
            .unwrap();
        assert_eq!(out.revision_id, r2);
        assert_eq!(out.reason, SelectionReason::Cookie);
        assert!(out.set_cookie.is_none());
    }

    #[tokio::test]
    async fn dispatch_ignores_cookie_after_generation_bump() {
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
            .await
            .unwrap();
        assert_eq!(out.reason, SelectionReason::Weighted);
        assert!(out.set_cookie.is_some());
    }

    #[tokio::test]
    async fn pin_is_established_on_weighted_and_honored_next_request() {
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
            .await
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
            .await
            .unwrap();
        assert_eq!(second.reason, SelectionReason::Pin);
        assert_eq!(second.revision_id, first.revision_id);
    }

    #[tokio::test]
    async fn pin_falls_through_to_weighted_when_revision_archived() {
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
            .await
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
            .await
            .unwrap();
        assert_ne!(again.revision_id, pinned);
        assert_eq!(again.reason, SelectionReason::Weighted);
    }

    #[tokio::test]
    async fn weighted_skips_zero_weight_revisions() {
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
                .await
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

    #[tokio::test]
    async fn pin_invalidated_when_generation_bumps_even_if_revision_still_present() {
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
            .await
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
            .await
            .unwrap();
        assert_eq!(second.reason, SelectionReason::Weighted);
    }

    // ── B7 drain semantics ────────────────────────────────────────────

    #[test]
    fn mark_draining_returns_false_for_unknown_deployment() {
        let d = RevisionDispatcher::new(cfg("local"));
        assert!(!d.mark_draining(dep(), rev()));
    }

    #[test]
    fn mark_draining_returns_false_for_unknown_revision() {
        let dep_id = dep();
        let r1 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 10_000)]);
        let ghost = rev();
        assert!(!d.mark_draining(dep_id, ghost));
        assert!(!d.is_draining(dep_id, ghost));
    }

    #[test]
    fn mark_draining_is_idempotent() {
        let dep_id = dep();
        let r1 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 10_000)]);
        assert!(d.mark_draining(dep_id, r1));
        assert!(d.is_draining(dep_id, r1));
        assert!(!d.mark_draining(dep_id, r1));
        assert!(d.is_draining(dep_id, r1));
    }

    #[test]
    fn unmark_draining_clears_the_flag() {
        let dep_id = dep();
        let r1 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 10_000)]);
        d.mark_draining(dep_id, r1);
        assert!(d.unmark_draining(dep_id, r1));
        assert!(!d.is_draining(dep_id, r1));
        assert!(!d.unmark_draining(dep_id, r1));
    }

    #[test]
    fn mark_draining_accepts_zero_weight_revision() {
        // Operator usually rolls weight to 0 first then drains. The flag
        // must apply to a present-but-zero-weight revision; `has_revision`
        // (which filters by weight > 0) would have rejected it.
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 10_000), entry(r2, 0)]);
        assert!(d.mark_draining(dep_id, r2));
        assert!(d.is_draining(dep_id, r2));
    }

    #[test]
    fn draining_revisions_lists_marked_only() {
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        d.mark_draining(dep_id, r1);
        let listed = d.draining_revisions(dep_id);
        assert_eq!(listed, vec![r1]);
    }

    #[test]
    fn draining_flag_preserved_across_apply_traffic_split() {
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 9000), entry(r2, 1000)]);
        d.mark_draining(dep_id, r2);
        // Replay with a different split that still references r2 — flag survives.
        d.apply_traffic_split(dep_id, vec![entry(r1, 9500), entry(r2, 500)], bundle(), 1)
            .expect("apply");
        assert!(d.is_draining(dep_id, r2));
    }

    #[test]
    fn draining_flag_dropped_when_revision_disappears_from_split() {
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 9000), entry(r2, 1000)]);
        d.mark_draining(dep_id, r2);
        // r2 vanishes from the new split — flag has no observable target,
        // so it's cleaned up.
        d.apply_traffic_split(dep_id, vec![entry(r1, 10_000)], bundle(), 1)
            .expect("apply");
        assert!(!d.is_draining(dep_id, r2));
    }

    #[tokio::test]
    async fn weighted_pick_skips_draining_revision() {
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        // 50/50 normally — but r2 is draining, so 100% should land on r1.
        let d = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        d.mark_draining(dep_id, r2);
        let mut rng = StdRng::seed_from_u64(0);
        for _ in 0..200 {
            let outcome = d
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
                .await
                .unwrap();
            assert_eq!(outcome.revision_id, r1);
            assert_eq!(outcome.reason, SelectionReason::Weighted);
        }
    }

    #[tokio::test]
    async fn weighted_pick_bails_when_all_revisions_draining() {
        let dep_id = dep();
        let r1 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 10_000)]);
        d.mark_draining(dep_id, r1);
        let mut rng = StdRng::seed_from_u64(0);
        let err = d
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
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("non-draining"), "{err:#}");
    }

    #[tokio::test]
    async fn cookie_still_routes_to_draining_revision_but_skips_set_cookie() {
        // "Soft drain" semantics: existing cookie sessions finish on the
        // draining revision; no fresh Set-Cookie is issued so the cookie
        // naturally expires and the next request re-picks a healthy
        // revision.
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        // Mint a fresh cookie bound to r2 (gen 1) BEFORE we mark r2 draining.
        let cookie = d.seal_cookie("local", "t", dep_id, r2, 1, now_secs() + 3600);
        d.mark_draining(dep_id, r2);
        let mut rng = StdRng::seed_from_u64(0);
        let outcome = d
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
            .await
            .unwrap();
        assert_eq!(outcome.revision_id, r2);
        assert_eq!(outcome.reason, SelectionReason::Cookie);
        assert!(
            outcome.set_cookie.is_none(),
            "no refresh cookie on a draining route",
        );
    }

    #[tokio::test]
    async fn trusted_header_still_routes_to_draining_revision() {
        // Admin override: even when a revision is draining, the trusted
        // header still routes there (useful for forced retry / debug).
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        d.mark_draining(dep_id, r2);
        let mut rng = StdRng::seed_from_u64(0);
        let outcome = d
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
            .await
            .unwrap();
        assert_eq!(outcome.revision_id, r2);
        assert_eq!(outcome.reason, SelectionReason::Header);
        // Header path never sets cookies regardless of drain state.
        assert!(outcome.set_cookie.is_none());
    }

    #[tokio::test]
    async fn weighted_pick_with_session_hint_skips_pin_write_on_draining() {
        // r2 is draining; r1 receives all new weighted traffic. The session
        // hint MUST NOT create a pin against the draining target (it'd be a
        // doomed pin), and the route MUST still succeed via r1.
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        d.mark_draining(dep_id, r2);
        let mut rng = StdRng::seed_from_u64(0);
        let first = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-drain"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .await
            .unwrap();
        assert_eq!(first.revision_id, r1, "weighted-pick must skip draining");
        // Second call with the same hint should also hit r1 — pin written for
        // r1, NOT r2 (which is draining).
        let second = d
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-drain"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .await
            .unwrap();
        assert_eq!(second.revision_id, r1);
        assert_eq!(second.reason, SelectionReason::Pin);
    }

    // ── B7 post-drain eviction ────────────────────────────────────────

    #[test]
    fn evict_revision_returns_false_for_unknown() {
        let dep_id = dep();
        let r1 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 10_000)]);
        assert!(!d.evict_revision(dep_id, rev()));
        assert!(!d.evict_revision(dep(), r1));
    }

    #[test]
    fn evict_revision_clears_draining_flag() {
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        d.mark_draining(dep_id, r2);
        assert!(d.evict_revision(dep_id, r2));
        assert!(!d.is_draining(dep_id, r2));
        // Idempotent: a second evict finds nothing left.
        assert!(!d.evict_revision(dep_id, r2));
    }

    #[tokio::test]
    async fn evicted_revision_is_skipped_by_weighted_pick() {
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        d.evict_revision(dep_id, r2);
        let mut rng = StdRng::seed_from_u64(0);
        for _ in 0..200 {
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
                .await
                .unwrap();
            assert_eq!(out.revision_id, r1);
        }
    }

    #[tokio::test]
    async fn evicted_revision_cookie_falls_through_to_weighted() {
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        let cookie = d.seal_cookie("local", "t", dep_id, r2, 1, now_secs() + 3600);
        d.evict_revision(dep_id, r2);
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
            .await
            .unwrap();
        // Cookie for the evicted revision no longer routes there.
        assert_eq!(out.revision_id, r1);
        assert_eq!(out.reason, SelectionReason::Weighted);
    }

    #[tokio::test]
    async fn evicted_revision_trusted_header_falls_through() {
        // Even the admin override can't route to an evicted (gone) revision —
        // unlike soft-draining, where the trusted header still hits it.
        let dep_id = dep();
        let r1 = rev();
        let r2 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        d.evict_revision(dep_id, r2);
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
            .await
            .unwrap();
        assert_eq!(out.revision_id, r1);
        assert_eq!(out.reason, SelectionReason::Weighted);
    }

    #[tokio::test]
    async fn evicting_last_revision_makes_dispatch_fail_closed() {
        // Draining the only revision leaves nothing healthy to fall to — a
        // dispatch error (→ B3 fails closed 500) is the correct end state.
        let dep_id = dep();
        let r1 = rev();
        let d = dispatcher_with(dep_id, vec![entry(r1, 10_000)]);
        d.evict_revision(dep_id, r1);
        let mut rng = StdRng::seed_from_u64(0);
        let err = d
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
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("non-draining"), "{err:#}");
    }
}
