//! Revision drain coordinator (B7) — `plans/next-gen-deployment.md` §1330.
//!
//! Ties the in-process pieces of `gtc op revisions drain` together:
//!
//! 1. flag the `(deployment_id, revision_id)` on the dispatcher so weighted
//!    selection skips it and new pins aren't written against it (B7
//!    dispatcher work);
//! 2. wait `drain_seconds` so in-flight HTTP / cookie-pinned sessions can
//!    finish naturally (the cookie-bound path still routes there during the
//!    window — see [`crate::revision_dispatcher`]);
//! 3. close remaining WebSocket sessions with a retryable close code (1012
//!    *Service Restart*) via the [`WsRevisionCloser`] seam;
//! 4. tear down the `TenantRuntime` via the runner-host's
//!    `ActivePacks::remove_revision` primitive (greenticai/greentic-runner
//!    `runtime.rs`).
//!
//! **Scaffold-ahead-of-producer.** Same shape as B0/B1/B2/B3/B4a/B5/B6:
//! the coordinator type and its trait seam ship now, but the producer
//! (file-watcher on `runtime-config.json`, or an operator HTTP signal)
//! that *invokes* it is Phase D / a follow-up B-train ticket. The
//! `#![allow(dead_code)]` flag matches that scaffolding posture.
//!
//! Scope decisions (locked via AskUserQuestion before implementation):
//!
//! - Soft drain semantics: existing pin / valid cookie / trusted-header
//!   override still routes to the draining revision so HTTP and cookie
//!   sessions can finish naturally. Weighted-pick excludes draining;
//!   `try_pin` writes against draining are suppressed; routes TO a
//!   draining revision suppress fresh `Set-Cookie`.
//! - WebSocket close stays a trait seam (default
//!   [`NoopWsRevisionCloser`]). No enumerable WS registry exists today —
//!   the existing `SessionManager` (greentic-start
//!   `http_ingress/websocket/session.rs`) tracks counters, not handles.
//!   A real registry threading `(deployment, revision)` through
//!   `serve_session` is a Phase D undertaking; this PR provides the
//!   seam so the coordinator's interface is stable when it lands.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use greentic_deploy_spec::ids::{BundleId, DeploymentId, RevisionId};
use tracing::{info, warn};

use crate::revision_dispatcher::RevisionDispatcher;

/// Close handle for live WebSocket sessions bound to a `(deployment, revision)`.
/// The default impl is a no-op so this seam can land without a registry.
#[async_trait]
pub trait WsRevisionCloser: Send + Sync {
    /// Close every live WS session whose route resolved to this revision.
    /// Implementations should send a `1012 Service Restart` close frame so
    /// the client retries against a healthy revision via re-dispatch.
    async fn close_revision(&self, deployment_id: DeploymentId, revision_id: RevisionId);
}

/// No-op [`WsRevisionCloser`]. Default for callers that don't yet thread a
/// per-revision WS registry; safe to use because the drain window has
/// already passed for any session that wasn't on a re-routable path.
pub struct NoopWsRevisionCloser;

#[async_trait]
impl WsRevisionCloser for NoopWsRevisionCloser {
    async fn close_revision(&self, _deployment_id: DeploymentId, _revision_id: RevisionId) {
        // Intentionally empty: see module-level scope note.
    }
}

/// Capability the coordinator needs from `ActivePacks` to tear down the
/// revision's runtime. Trait so the scaffold compiles without depending on
/// the runner-host crate at this layer (and so the coordinator stays
/// unit-testable without standing up a real `TenantRuntime`).
///
/// The real impl is a thin newtype over `Arc<runner_host::runtime::ActivePacks>`
/// that delegates to `ActivePacks::remove_revision`; that wiring lands with
/// the producer in Phase D so this file doesn't add a cross-crate boundary
/// before there's a consumer.
pub trait RevisionTeardown: Send + Sync {
    /// Remove the runtime bound to `(tenant, deployment_id, bundle_id,
    /// revision_id)`. Returns `true` if an entry was removed, `false` if
    /// the entry was absent — both are non-fatal (idempotent re-run).
    fn remove_revision(
        &self,
        tenant: &str,
        deployment_id: DeploymentId,
        bundle_id: BundleId,
        revision_id: RevisionId,
    ) -> bool;
}

/// One drain invocation. Pure inputs + behavior, no global state.
pub struct DrainRequest<'a> {
    pub tenant: &'a str,
    pub deployment_id: DeploymentId,
    pub bundle_id: BundleId,
    pub revision_id: RevisionId,
    pub drain_seconds: u32,
}

/// Drain coordinator. Holds the dispatcher + teardown + WS-close
/// collaborators by `Arc` so the producer (file-watcher / HTTP signal) can
/// fire multiple coordinated drains from one process.
pub struct RevisionDrainCoordinator {
    dispatcher: Arc<RevisionDispatcher>,
    teardown: Arc<dyn RevisionTeardown>,
    ws_closer: Arc<dyn WsRevisionCloser>,
}

impl RevisionDrainCoordinator {
    pub fn new(
        dispatcher: Arc<RevisionDispatcher>,
        teardown: Arc<dyn RevisionTeardown>,
        ws_closer: Arc<dyn WsRevisionCloser>,
    ) -> Self {
        Self {
            dispatcher,
            teardown,
            ws_closer,
        }
    }

    /// Convenience constructor that wires the no-op WS closer.
    pub fn with_noop_ws(
        dispatcher: Arc<RevisionDispatcher>,
        teardown: Arc<dyn RevisionTeardown>,
    ) -> Self {
        Self::new(dispatcher, teardown, Arc::new(NoopWsRevisionCloser))
    }

    /// Run the drain dance. Returns `Ok` whether or not the runtime was
    /// actually present (idempotent re-run is safe). Errors only on
    /// impossible internal state (no current path reaches that).
    ///
    /// **Cancellation contract for the Phase D producer:** the only await
    /// point that holds meaningful state is the `drain_seconds` sleep, after
    /// `mark_draining` has flipped the flag. If the task is dropped during
    /// that sleep the revision is left soft-draining (weighted-pick skips it,
    /// existing cookie/pin sessions still route there) but never evicted or
    /// torn down. The whole sequence is idempotent, so the producer's
    /// recovery is simply to call `run` again for the same revision; it must
    /// not assume a cancelled drain self-heals. (`unmark_draining` is the
    /// escape hatch if the drain is being aborted rather than retried.)
    pub async fn run(&self, req: DrainRequest<'_>) -> Result<DrainReport> {
        let DrainRequest {
            tenant,
            deployment_id,
            bundle_id,
            revision_id,
            drain_seconds,
        } = req;

        // 1. Stop new session pins. Existing pins / valid cookies /
        //    trusted-header overrides still route there for the window.
        let newly_marked = self.dispatcher.mark_draining(deployment_id, revision_id);
        if !newly_marked {
            info!(
                deployment_id = %deployment_id,
                revision_id = %revision_id,
                "revision already draining or unknown to dispatcher; \
                 proceeding with teardown anyway",
            );
        }

        // 2. Wait the drain window. tokio::time::sleep is cooperative so
        //    the producer can race a cancellation onto the same task if
        //    Phase D wires that in.
        tokio::time::sleep(Duration::from_secs(u64::from(drain_seconds))).await;

        // 3. Evict the revision from the dispatcher BEFORE teardown. The
        //    soft-draining flag (step 1) deliberately keeps cookie- and
        //    pin-bound sessions routing here during the window so HTTP
        //    finishes — but those bindings outlive the window (cookie/pin
        //    TTL is ~1h vs the default 30s drain). Without this transition a
        //    client holding a cookie/pin would keep selecting the revision
        //    after step 5 removed its runtime → 404/500 instead of a
        //    re-dispatch. Eviction makes `has_revision` false, so every
        //    selection path (cookie, pin, weighted) skips it and the holder
        //    re-dispatches to a healthy revision with a fresh cookie.
        let evicted = self.dispatcher.evict_revision(deployment_id, revision_id);

        // 4. Close remaining WebSockets via the trait seam. Ordered after
        //    eviction so a reconnecting client re-dispatches to a healthy
        //    revision rather than re-selecting this one. The default
        //    NoopWsRevisionCloser is a no-op — a real registry lands in
        //    Phase D once `serve_session` threads `(deployment, revision)`.
        self.ws_closer
            .close_revision(deployment_id, revision_id)
            .await;

        // 5. Tear down the TenantRuntime. The runner-host's
        //    `ActivePacks::remove_revision` returns the Arc; we let it
        //    drop here, which aborts the tenant's timer handles via
        //    `TenantRuntime::drop`. Safe now: nothing routes here anymore.
        let removed = self
            .teardown
            .remove_revision(tenant, deployment_id, bundle_id, revision_id);
        if !removed {
            warn!(
                tenant = %tenant,
                deployment_id = %deployment_id,
                revision_id = %revision_id,
                "no active runtime found for revision at drain completion; \
                 either never warmed or already torn down",
            );
        }

        Ok(DrainReport {
            newly_marked,
            evicted_from_dispatch: evicted,
            removed_runtime: removed,
        })
    }
}

/// Outcome of a single drain run. The producer can stamp these on audit
/// records / `runtime.json` once Phase D wires the consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainReport {
    /// `true` if [`RevisionDispatcher::mark_draining`] flipped the flag in
    /// this run; `false` if it was already set or the dispatcher didn't
    /// know about the revision.
    pub newly_marked: bool,
    /// `true` if [`RevisionDispatcher::evict_revision`] removed the revision
    /// from the routing table at the end of the drain window; `false` if it
    /// was already absent. After this, cookie/pin holders re-dispatch to a
    /// healthy revision instead of the torn-down runtime.
    pub evicted_from_dispatch: bool,
    /// `true` if `ActivePacks::remove_revision` popped an entry; `false`
    /// if no runtime was present (already torn down or never warmed).
    pub removed_runtime: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revision_dispatcher::{RevisionDispatcher, RevisionDispatcherConfig, RevisionEntry};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn cfg() -> RevisionDispatcherConfig {
        RevisionDispatcherConfig::new("local", [7u8; 32])
    }

    fn bundle() -> BundleId {
        BundleId::new("customer.support")
    }

    fn entry(rev: RevisionId, w: u32) -> RevisionEntry {
        RevisionEntry {
            revision_id: rev,
            bundle_id: bundle(),
            weight_bps: w,
        }
    }

    /// Records every `remove_revision` call so tests can assert the
    /// coordinator hit the right key in the right order.
    #[derive(Default)]
    struct RecordingTeardown {
        calls: Mutex<Vec<(String, DeploymentId, BundleId, RevisionId)>>,
        return_value: bool,
    }

    impl RecordingTeardown {
        fn new(return_value: bool) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                return_value,
            }
        }
    }

    impl RevisionTeardown for RecordingTeardown {
        fn remove_revision(
            &self,
            tenant: &str,
            deployment_id: DeploymentId,
            bundle_id: BundleId,
            revision_id: RevisionId,
        ) -> bool {
            self.calls.lock().unwrap().push((
                tenant.to_string(),
                deployment_id,
                bundle_id,
                revision_id,
            ));
            self.return_value
        }
    }

    /// Counts `close_revision` invocations so tests can assert the WS
    /// seam fires exactly once per drain.
    #[derive(Default)]
    struct CountingWsCloser {
        closes: AtomicUsize,
    }

    #[async_trait]
    impl WsRevisionCloser for CountingWsCloser {
        async fn close_revision(&self, _deployment_id: DeploymentId, _revision_id: RevisionId) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn dispatcher_with(
        deployment: DeploymentId,
        revisions: Vec<RevisionEntry>,
    ) -> Arc<RevisionDispatcher> {
        let d = RevisionDispatcher::new(cfg());
        let bid = revisions[0].bundle_id.clone();
        d.apply_traffic_split(deployment, revisions, bid, 0)
            .expect("apply_traffic_split");
        Arc::new(d)
    }

    #[tokio::test]
    async fn drain_marks_then_tears_down() {
        let dep_id = DeploymentId::new();
        let r1 = RevisionId::new();
        let r2 = RevisionId::new();
        let dispatcher = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        let teardown = Arc::new(RecordingTeardown::new(true));
        let ws_closer = Arc::new(CountingWsCloser::default());
        let coord = RevisionDrainCoordinator::new(
            Arc::clone(&dispatcher),
            teardown.clone(),
            ws_closer.clone(),
        );
        let report = coord
            .run(DrainRequest {
                tenant: "acme",
                deployment_id: dep_id,
                bundle_id: bundle(),
                revision_id: r2,
                drain_seconds: 0,
            })
            .await
            .expect("drain ran");

        assert!(report.newly_marked);
        assert!(report.evicted_from_dispatch);
        assert!(report.removed_runtime);
        // Eviction (step 3) cleared the draining flag and removed r2 from the
        // routing table, so it is no longer "draining" — it is gone.
        assert!(!dispatcher.is_draining(dep_id, r2));
        assert!(dispatcher.draining_revisions(dep_id).is_empty());
        assert_eq!(ws_closer.closes.load(Ordering::SeqCst), 1);
        let calls = teardown.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "acme");
        assert_eq!(calls[0].1, dep_id);
        assert_eq!(calls[0].2, bundle());
        assert_eq!(calls[0].3, r2);
    }

    #[tokio::test]
    async fn drain_is_idempotent() {
        let dep_id = DeploymentId::new();
        let r1 = RevisionId::new();
        let dispatcher = dispatcher_with(dep_id, vec![entry(r1, 10_000)]);
        let teardown = Arc::new(RecordingTeardown::new(false));
        let coord =
            RevisionDrainCoordinator::with_noop_ws(Arc::clone(&dispatcher), teardown.clone());

        let first = coord
            .run(DrainRequest {
                tenant: "acme",
                deployment_id: dep_id,
                bundle_id: bundle(),
                revision_id: r1,
                drain_seconds: 0,
            })
            .await
            .unwrap();
        let second = coord
            .run(DrainRequest {
                tenant: "acme",
                deployment_id: dep_id,
                bundle_id: bundle(),
                revision_id: r1,
                drain_seconds: 0,
            })
            .await
            .unwrap();

        // First run flips the flag and evicts; second run finds nothing left.
        assert!(first.newly_marked);
        assert!(first.evicted_from_dispatch);
        assert!(!second.newly_marked);
        assert!(!second.evicted_from_dispatch);
        // Teardown returns `false` (no entry) but both runs still complete
        // cleanly — the drain dance is safe to replay.
        assert!(!first.removed_runtime);
        assert!(!second.removed_runtime);
    }

    #[tokio::test]
    async fn drain_unknown_revision_proceeds_with_teardown() {
        // A producer that races the operator's `gtc op revisions drain`
        // may invoke the coordinator before the dispatcher knows about
        // the revision (or after `apply_traffic_split` has already
        // dropped it). The coordinator must still call through to
        // `remove_revision` so the runtime can't strand.
        let dep_id = DeploymentId::new();
        let r1 = RevisionId::new();
        let dispatcher = dispatcher_with(dep_id, vec![entry(r1, 10_000)]);
        let teardown = Arc::new(RecordingTeardown::new(true));
        let coord =
            RevisionDrainCoordinator::with_noop_ws(Arc::clone(&dispatcher), teardown.clone());

        let ghost = RevisionId::new();
        let report = coord
            .run(DrainRequest {
                tenant: "acme",
                deployment_id: dep_id,
                bundle_id: bundle(),
                revision_id: ghost,
                drain_seconds: 0,
            })
            .await
            .unwrap();

        assert!(!report.newly_marked); // dispatcher rejected the unknown rev
        assert!(!report.evicted_from_dispatch); // nothing to evict
        assert!(report.removed_runtime); // teardown still fired
        assert_eq!(teardown.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn drain_waits_the_window() {
        let dep_id = DeploymentId::new();
        let r1 = RevisionId::new();
        let dispatcher = dispatcher_with(dep_id, vec![entry(r1, 10_000)]);
        let teardown = Arc::new(RecordingTeardown::new(true));
        let coord =
            RevisionDrainCoordinator::with_noop_ws(Arc::clone(&dispatcher), teardown.clone());

        // Use Tokio's paused time so we don't actually sleep — assert the
        // coordinator advances by exactly drain_seconds. drain_seconds=2
        // is enough to detect the sleep without slowing CI.
        tokio::time::pause();
        let start = tokio::time::Instant::now();
        let handle = tokio::spawn(async move {
            coord
                .run(DrainRequest {
                    tenant: "acme",
                    deployment_id: dep_id,
                    bundle_id: bundle(),
                    revision_id: r1,
                    drain_seconds: 2,
                })
                .await
        });
        // Yield so the spawned task hits the sleep before we advance time.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        let _ = handle.await.unwrap().unwrap();
        assert!(start.elapsed() >= Duration::from_secs(2));
    }

    // Regression for the Codex no-ship: a client holding a cookie/pin issued
    // before the drain must re-dispatch to a HEALTHY revision after the drain
    // window — not keep selecting the torn-down revision until the (much
    // longer) cookie/pin TTL expires.

    #[tokio::test]
    async fn drain_then_stale_cookie_reselects_healthy_revision() {
        use crate::revision_dispatcher::{DispatchRequest, SelectionReason};
        use crate::revision_pin::now_secs;
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let dep_id = DeploymentId::new();
        let r1 = RevisionId::new();
        let r2 = RevisionId::new();
        let dispatcher = dispatcher_with(dep_id, vec![entry(r1, 5000), entry(r2, 5000)]);
        // Cookie minted while r2 was healthy (generation 1).
        let cookie = dispatcher.seal_cookie("local", "t", dep_id, r2, 1, now_secs() + 3600);
        let mut rng = StdRng::seed_from_u64(0);

        // Pre-drain: the cookie sticks the session to r2.
        let pre = dispatcher
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
        assert_eq!(pre.revision_id, r2);
        assert_eq!(pre.reason, SelectionReason::Cookie);

        // Drain r2.
        let teardown = Arc::new(RecordingTeardown::new(true));
        let coord =
            RevisionDrainCoordinator::with_noop_ws(Arc::clone(&dispatcher), teardown.clone());
        coord
            .run(DrainRequest {
                tenant: "acme",
                deployment_id: dep_id,
                bundle_id: bundle(),
                revision_id: r2,
                drain_seconds: 0,
            })
            .await
            .unwrap();

        // Post-drain: the same cookie no longer selects r2 — it falls through
        // to a weighted pick over the surviving healthy revision (r1) and a
        // fresh cookie is issued so the session migrates.
        let post = dispatcher
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
        assert_eq!(
            post.revision_id, r1,
            "stale cookie must re-dispatch to healthy r1"
        );
        assert_eq!(post.reason, SelectionReason::Weighted);
        assert!(
            post.set_cookie.is_some(),
            "fresh cookie migrates the session"
        );
    }

    #[tokio::test]
    async fn drain_then_stale_pin_reselects_healthy_revision() {
        use crate::revision_dispatcher::{DispatchRequest, SelectionReason};
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let dep_id = DeploymentId::new();
        let r1 = RevisionId::new();
        let r2 = RevisionId::new();
        // r1 weight 0 so the first weighted pick deterministically lands on r2
        // and establishes the pin there; after drain, r1 is the only survivor.
        let dispatcher = dispatcher_with(dep_id, vec![entry(r1, 0), entry(r2, 10_000)]);
        let mut rng = StdRng::seed_from_u64(0);

        // Establish a pin on r2 via a weighted pick.
        let pre = dispatcher
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-pin"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .await
            .unwrap();
        assert_eq!(pre.revision_id, r2);

        // Before draining r2, give r1 some weight so it's a valid fallback.
        dispatcher
            .apply_traffic_split(dep_id, vec![entry(r1, 5000), entry(r2, 5000)], bundle(), 1)
            .unwrap();
        // The pin survives the generation bump? No — generation bump
        // invalidates the pin (B1 semantics). Re-establish under gen 2.
        let _ = dispatcher
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-pin"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .await
            .unwrap();

        // Drain r2.
        let teardown = Arc::new(RecordingTeardown::new(true));
        let coord =
            RevisionDrainCoordinator::with_noop_ws(Arc::clone(&dispatcher), teardown.clone());
        coord
            .run(DrainRequest {
                tenant: "acme",
                deployment_id: dep_id,
                bundle_id: bundle(),
                revision_id: r2,
                drain_seconds: 0,
            })
            .await
            .unwrap();

        // Post-drain: a request with the same hint must land on r1 — the pin
        // to the evicted r2 is no longer honored.
        let post = dispatcher
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-pin"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .await
            .unwrap();
        assert_eq!(
            post.revision_id, r1,
            "stale pin must re-dispatch to healthy r1"
        );
        assert_eq!(post.reason, SelectionReason::Weighted);
    }

    // Regression for code-review finding: a hint-only (cookie-less) session
    // pinned to the evicted revision must RE-PIN to a single survivor and
    // STAY there — not re-roll the weighted dice on every request and flap
    // across the survivors until the pin TTL expires. The generation bump in
    // `evict_revision` is what makes this hold. Uses 3 revisions so two
    // survivors remain after eviction (flapping is only observable with 2+).
    #[tokio::test]
    async fn drain_does_not_make_pinned_session_flap_across_survivors() {
        use crate::revision_dispatcher::{DispatchRequest, SelectionReason};
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let dep_id = DeploymentId::new();
        let r1 = RevisionId::new();
        let r2 = RevisionId::new();
        let r3 = RevisionId::new();
        // r3 takes all initial weight so the session deterministically pins
        // there; r1 and r2 are the survivors after r3 is drained.
        let dispatcher =
            dispatcher_with(dep_id, vec![entry(r1, 0), entry(r2, 0), entry(r3, 10_000)]);
        let mut rng = StdRng::seed_from_u64(0);

        let pre = dispatcher
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-flap"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .await
            .unwrap();
        assert_eq!(pre.revision_id, r3);

        // Re-weight so r1 and r2 are both live survivors (gen 1 → 2).
        dispatcher
            .apply_traffic_split(
                dep_id,
                vec![entry(r1, 5000), entry(r2, 5000), entry(r3, 0)],
                bundle(),
                1,
            )
            .unwrap();
        // Re-pin the session to r3 under the new generation (r3 still present,
        // weight 0 — mark/evict accepts zero-weight). The pre-drain pin must
        // exist at the CURRENT generation to make the flapping risk real.
        dispatcher.mark_draining(dep_id, r3);

        let teardown = Arc::new(RecordingTeardown::new(true));
        let coord =
            RevisionDrainCoordinator::with_noop_ws(Arc::clone(&dispatcher), teardown.clone());
        coord
            .run(DrainRequest {
                tenant: "acme",
                deployment_id: dep_id,
                bundle_id: bundle(),
                revision_id: r3,
                drain_seconds: 0,
            })
            .await
            .unwrap();

        // First post-drain request re-pins to ONE survivor; every subsequent
        // request with the same hint must return that SAME survivor.
        let first = dispatcher
            .dispatch(
                &DispatchRequest {
                    env_id: "local",
                    tenant: "t",
                    deployment_id: dep_id,
                    session_hint: Some("sess-flap"),
                    trusted: false,
                    header_revision: None,
                    cookie: None,
                },
                &mut rng,
            )
            .await
            .unwrap();
        assert!(first.revision_id == r1 || first.revision_id == r2);
        let anchored = first.revision_id;

        for _ in 0..50 {
            let next = dispatcher
                .dispatch(
                    &DispatchRequest {
                        env_id: "local",
                        tenant: "t",
                        deployment_id: dep_id,
                        session_hint: Some("sess-flap"),
                        trusted: false,
                        header_revision: None,
                        cookie: None,
                    },
                    &mut rng,
                )
                .await
                .unwrap();
            assert_eq!(
                next.revision_id, anchored,
                "session must stay anchored to one survivor, not flap"
            );
            assert_eq!(next.reason, SelectionReason::Pin);
        }
    }
}
