//! Fast2Flow on the revision-serve messaging path (start WITHOUT `--bundle`).
//!
//! The legacy ingress (`http_ingress/messaging.rs`) routes every chat turn
//! through Fast2Flow; this path did not, so a deployed revision never logged
//! `[fast2flow:gate] enter`, never dispatched by intent, and never honoured
//! the on-miss opt-in. Both paths now share one implementation
//! (`crate::fast2flow::probe::plan_turn`); this module only adapts it:
//!
//! * which app pack — the one of the revision ACTUALLY serving the turn
//!   (`RevisionIngressRouting::app_packs`, keyed per revision);
//! * which index scope — `revision_index_scope(..)`, so two revisions never
//!   share (or serve each other) an intent index;
//! * precedence — an explicit target (URL/header-named flow, or the
//!   envelope's `flow_hint`) naming a NON-default flow always wins; a target
//!   naming the default flow is a fallback like no target at all, and only a
//!   fallback is replaced by Fast2Flow (see [`is_default_target`]);
//! * ownership — a conversation parked in a flow resumes that flow and is
//!   never re-routed (see [`parked_flow`]);
//! * no LLM fallback: revision mode has no `bundle.yaml` `llm:` block and no
//!   env-based source exists, so `llm` is `None` (host-only routing).
//!
//! The probe spawns a process synchronously, so it runs under
//! `spawn_blocking` (a `block_in_place` on a current-thread runtime panics).

use std::future::Future;
use std::sync::Arc;

use anyhow::Result;
use greentic_deploy_spec::ids::{BundleId, DeploymentId, RevisionId};
use greentic_runner_host::engine::runtime::{FlowResumeStore, IngressEnvelope};
use greentic_runner_host::storage::DynSessionStore;
use greentic_runner_host::{Activity, WelcomeFlowHint};
use greentic_types::ChannelMessageEnvelope;

use super::Activation;
use crate::fast2flow::Fast2FlowConfig;
use crate::fast2flow::dispatch::RouteDecision;
use crate::fast2flow::probe::{OnRouterFailure, ProbeInputs, TurnPlan, plan_turn};
use crate::fast2flow::revision_packs::{RevisionAppPack, revision_index_scope};
use crate::fast2flow::turn::{RouteSignal, card_nav_target, stamp_route};
use crate::messaging_app::select_app_flow;
use crate::operator_log;
use crate::runner_host::OperatorContext;

/// What one revision-serve turn does, decided before the runner is called.
#[derive(Debug, Clone)]
pub(super) struct RevisionTurn {
    /// The `(pack, flow)` the activity is pinned to; `None` leaves flow
    /// resolution to the runner, exactly as before.
    pub(super) target: Option<WelcomeFlowHint>,
    /// The envelope the flow receives (a node route carries `routeToCardId`
    /// and prefill metadata).
    pub(super) envelope: ChannelMessageEnvelope,
    /// Set only for a routed turn: the signal and the flow id it names.
    pub(super) signal: Option<(RouteSignal, String)>,
    /// When set, no flow runs; this reply is sent instead.
    pub(super) fixed_reply: Option<ChannelMessageEnvelope>,
}

impl RevisionTurn {
    fn passthrough(target: Option<WelcomeFlowHint>, ingress: &ChannelMessageEnvelope) -> Self {
        Self {
            target,
            envelope: ingress.clone(),
            signal: None,
            fixed_reply: None,
        }
    }
}

/// Who and where a turn runs; everything but the message.
pub(super) struct TurnScope<'a> {
    pub(super) tenant: &'a str,
    pub(super) team: Option<&'a str>,
    pub(super) deployment_id: DeploymentId,
    pub(super) bundle_id: &'a BundleId,
    pub(super) revision_id: RevisionId,
    pub(super) provider: &'a str,
    pub(super) endpoint_id: Option<&'a str>,
}

/// Split a turn's target into the EXPLICIT one (the envelope's validated
/// `flow_hint`, else a URL/header-named request target) and the bundle-default
/// FALLBACK. Only the fallback may be replaced by Fast2Flow.
pub(super) fn split_targets(
    flow_hint_target: Option<WelcomeFlowHint>,
    request_target: Option<WelcomeFlowHint>,
    request_target_explicit: bool,
) -> (Option<WelcomeFlowHint>, Option<WelcomeFlowHint>) {
    match flow_hint_target {
        Some(hint) => (Some(hint), None),
        None if request_target_explicit => (request_target, None),
        None => (None, request_target),
    }
}

/// Plan one turn on the revision that serves it.
pub(super) async fn plan_revision_turn(
    activation: &Activation,
    scope: &TurnScope<'_>,
    ingress: &ChannelMessageEnvelope,
    explicit: Option<WelcomeFlowHint>,
    fallback: Option<WelcomeFlowHint>,
) -> RevisionTurn {
    plan_revision_turn_with(
        Fast2FlowConfig::global(),
        activation,
        scope,
        ingress,
        explicit,
        fallback,
    )
    .await
}

/// [`plan_revision_turn`] with the Fast2Flow config injected (tests point it
/// at a stub routing host; production passes the process-global one).
pub(super) async fn plan_revision_turn_with(
    cfg: &Fast2FlowConfig,
    activation: &Activation,
    scope: &TurnScope<'_>,
    ingress: &ChannelMessageEnvelope,
    explicit: Option<WelcomeFlowHint>,
    fallback: Option<WelcomeFlowHint>,
) -> RevisionTurn {
    let app = activation
        .routing
        .app_packs
        .get_shared(scope.bundle_id.as_str(), scope.revision_id);
    let bundle_default = activation
        .routing
        .flow_index
        .default_flow_for_bundle(scope.bundle_id.as_str())
        .map(|(pack_id, flow_id)| WelcomeFlowHint {
            pack_id: pack_id.to_string(),
            flow_id: flow_id.to_string(),
        });
    let (explicit, fallback) =
        demote_default_target(explicit, fallback, bundle_default.as_ref(), app.as_deref());
    if let Some(turn) = explicit_passthrough(scope, explicit, ingress) {
        return turn;
    }
    let Some(app) = app else {
        log_skip(scope, SkipReason::NoAppPack);
        return RevisionTurn::passthrough(fallback, ingress);
    };
    let store = activation
        .host
        .active_packs()
        .load_revision(
            scope.tenant,
            scope.deployment_id,
            scope.bundle_id.clone(),
            scope.revision_id,
        )
        .map(|runtime| Arc::clone(runtime.session_store()));
    plan_for_app(cfg.clone(), app, store, scope, ingress, fallback).await
}

/// Why the hook did not probe a turn, for the skip log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum SkipReason {
    /// A URL/header-named flow or the envelope's `flow_hint` naming a
    /// non-default flow always wins.
    ExplicitTarget,
    /// The serving revision has no app pack (nothing to route within).
    NoAppPack,
}

impl SkipReason {
    fn token(self) -> &'static str {
        match self {
            Self::ExplicitTarget => "explicit_target",
            Self::NoAppPack => "no_app_pack",
        }
    }
}

/// Revisions/reasons already logged at info.
static SKIPS_LOGGED: std::sync::LazyLock<
    crate::fast2flow::index_refresh::WarnOnce<(String, RevisionId, SkipReason)>,
> = std::sync::LazyLock::new(Default::default);

/// `true` the first time this (bundle, revision, reason) skips a turn.
pub(super) fn first_skip(
    seen: &crate::fast2flow::index_refresh::WarnOnce<(String, RevisionId, SkipReason)>,
    scope: &TurnScope<'_>,
    reason: SkipReason,
) -> bool {
    seen.first((
        scope.bundle_id.as_str().to_string(),
        scope.revision_id,
        reason,
    ))
}

/// Log why the hook skipped a turn: at info the first time per (bundle,
/// revision, reason) — that is the line an operator checking why a deployed
/// revision does not route looks for — and at debug after that, since these
/// reasons hold for every turn of the revision.
fn log_skip(scope: &TurnScope<'_>, reason: SkipReason) {
    let line = format!(
        "[fast2flow:gate] skip path=revision reason={} bundle={} revision={}",
        reason.token(),
        scope.bundle_id.as_str(),
        scope.revision_id
    );
    if first_skip(&SKIPS_LOGGED, scope, reason) {
        operator_log::info(module_path!(), format!("{line} (logged once at info)"));
    } else {
        operator_log::debug(module_path!(), line);
    }
}

/// Whether `target` merely names the DEFAULT flow: the bundle's registered
/// default, or the app pack's own default (`select_app_flow`).
///
/// Such a target is not a deliberate selection. The webchat provider stores
/// the `X-Greentic-Flow` header a conversation was opened with and copies it
/// into `metadata["flow_hint"]` on every activity, so a conversation opened
/// against the default flow carries a "hint" on every turn; reading that as
/// explicit would switch Fast2Flow off for the whole conversation.
pub(super) fn is_default_target(
    target: &WelcomeFlowHint,
    bundle_default: Option<&WelcomeFlowHint>,
    app: Option<&RevisionAppPack>,
) -> bool {
    if bundle_default == Some(target) {
        return true;
    }
    app.is_some_and(|app| {
        target.pack_id == app.pack_id
            && select_app_flow(&app.info).is_ok_and(|flow| flow.id == target.flow_id)
    })
}

/// Demote an explicit target that only names the default flow to the
/// FALLBACK, which Fast2Flow may replace. A target naming any other flow stays
/// explicit and wins. A conversation parked in a non-default flow still
/// resumes it: the parked-flow check runs before the probe.
pub(super) fn demote_default_target(
    explicit: Option<WelcomeFlowHint>,
    fallback: Option<WelcomeFlowHint>,
    bundle_default: Option<&WelcomeFlowHint>,
    app: Option<&RevisionAppPack>,
) -> (Option<WelcomeFlowHint>, Option<WelcomeFlowHint>) {
    match explicit {
        Some(target) if is_default_target(&target, bundle_default, app) => (None, Some(target)),
        other => (other, fallback),
    }
}

/// An explicit target (URL/header-named flow, or the envelope's `flow_hint`,
/// naming a flow other than the default) is never routed: `Some(passthrough)`
/// when there is one, logged.
pub(super) fn explicit_passthrough(
    scope: &TurnScope<'_>,
    explicit: Option<WelcomeFlowHint>,
    ingress: &ChannelMessageEnvelope,
) -> Option<RevisionTurn> {
    let explicit = explicit?;
    log_skip(scope, SkipReason::ExplicitTarget);
    Some(RevisionTurn::passthrough(Some(explicit), ingress))
}

/// [`plan_revision_turn`] once the app pack and the revision's session store
/// are known. Split out so tests drive it with a stub routing host.
pub(super) async fn plan_for_app(
    cfg: Fast2FlowConfig,
    app: Arc<RevisionAppPack>,
    store: Option<DynSessionStore>,
    scope: &TurnScope<'_>,
    ingress: &ChannelMessageEnvelope,
    fallback: Option<WelcomeFlowHint>,
) -> RevisionTurn {
    let ctx = OperatorContext {
        tenant: scope.tenant.to_string(),
        team: scope.team.map(str::to_string),
        correlation_id: None,
    };
    if !cfg.gate.is_enabled(&ctx, &app.info) {
        operator_log::debug(
            module_path!(),
            format!(
                "[fast2flow:gate] skip path=revision reason=not_opted_in pack={} revision={}",
                app.pack_id, scope.revision_id
            ),
        );
        return RevisionTurn::passthrough(fallback, ingress);
    }
    // At info on this path: an operator checking that a deployed revision
    // routes looks for exactly this line.
    operator_log::info(
        module_path!(),
        format!(
            "[fast2flow:gate] enter path=revision tenant={} team={:?} pack={} bundle={} revision={} text_len={}",
            scope.tenant,
            scope.team,
            app.pack_id,
            scope.bundle_id.as_str(),
            scope.revision_id,
            ingress.text.as_deref().map(str::len).unwrap_or(0)
        ),
    );

    let default_flow = default_flow_hint(&app, fallback.as_ref());
    match store {
        Some(store) => match parked_flow(&store, scope, &app, ingress, default_flow.as_ref()).await
        {
            Ok(Some(flow_id)) => {
                operator_log::info(
                    module_path!(),
                    format!(
                        "[fast2flow] conversation parked in flow={flow_id} pack={} — resuming it, routing skipped",
                        app.pack_id
                    ),
                );
                let target = WelcomeFlowHint {
                    pack_id: app.pack_id.clone(),
                    flow_id,
                };
                return RevisionTurn::passthrough(Some(target), ingress);
            }
            Ok(None) => {}
            Err(err) => {
                // Not knowing whether a flow is parked must not re-route the
                // turn away from it: keep today's behaviour.
                operator_log::warn(
                    module_path!(),
                    format!("[fast2flow] parked-flow lookup failed; routing skipped: {err:#}"),
                );
                return RevisionTurn::passthrough(fallback, ingress);
            }
        },
        None => operator_log::debug(
            module_path!(),
            "[fast2flow] revision runtime not loaded; parked-flow check skipped",
        ),
    }

    // A card submit navigates (the runner's card_nav turns the key into an
    // entry node, or the adaptive-card component renders the card). It is
    // never routed nor answered with the miss reply — the legacy path's
    // `card_nav_target`-first rule, shared.
    if let Some(card) = card_nav_target(ingress) {
        operator_log::debug(
            module_path!(),
            format!("[fast2flow] card navigation to {card}; routing skipped"),
        );
        return RevisionTurn::passthrough(fallback, ingress);
    }

    let index_scope = revision_index_scope(
        scope.tenant,
        scope.team,
        scope.bundle_id.as_str(),
        scope.revision_id,
    );
    let provider = scope.provider.to_string();
    let probe_app = Arc::clone(&app);
    let probe_envelope = ingress.clone();
    let planned = tokio::task::spawn_blocking(move || {
        let inputs = ProbeInputs {
            cfg: &cfg,
            ctx: &ctx,
            pack: &probe_app.info,
            pack_path: &probe_app.pack_path,
            index_scope: Some(&index_scope),
            provider: &provider,
            llm: None,
        };
        plan_turn(
            &inputs,
            &probe_envelope,
            false,
            OnRouterFailure::DefaultFlow,
        )
    })
    .await;
    let plan = match planned {
        Ok(plan) => plan,
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!("[fast2flow] routing probe task failed; default target kept: {err}"),
            );
            return RevisionTurn::passthrough(fallback, ingress);
        }
    };
    match plan {
        TurnPlan::Routed(RouteDecision::Flow {
            flow_id,
            envelope,
            signal,
        }) => RevisionTurn {
            target: Some(WelcomeFlowHint {
                pack_id: app.pack_id.clone(),
                flow_id: flow_id.clone(),
            }),
            envelope,
            signal: Some((signal, flow_id)),
            fixed_reply: None,
        },
        TurnPlan::Routed(RouteDecision::Node { envelope, signal }) => {
            match fallback.or_else(|| default_flow.clone()) {
                Some(target) => {
                    let flow_id = target.flow_id.clone();
                    RevisionTurn {
                        target: Some(target),
                        envelope,
                        signal: Some((signal, flow_id)),
                        fixed_reply: None,
                    }
                }
                // No flow the node could run in: the runner resolves the
                // flow itself, and an empty flow id must not be stamped.
                None => {
                    operator_log::info(
                        module_path!(),
                        format!(
                            "[fast2flow] node route with no resolvable default flow in pack={}; no route signal",
                            app.pack_id
                        ),
                    );
                    RevisionTurn {
                        target: None,
                        envelope,
                        signal: None,
                        fixed_reply: None,
                    }
                }
            }
        }
        TurnPlan::DefaultFlow { on_miss } => {
            if on_miss {
                operator_log::info(
                    module_path!(),
                    format!(
                        "[fast2flow] miss for free text — running default flow (on_miss opt-in) pack={}",
                        app.pack_id
                    ),
                );
            }
            RevisionTurn::passthrough(fallback, ingress)
        }
        TurnPlan::FixedReply(mut reply) => {
            operator_log::info(
                module_path!(),
                format!(
                    "[fast2flow] miss for free text — emitting fixed miss reply pack={}",
                    app.pack_id
                ),
            );
            reply.id = uuid::Uuid::new_v4().to_string();
            RevisionTurn {
                target: None,
                envelope: ingress.clone(),
                signal: None,
                fixed_reply: Some(reply),
            }
        }
    }
}

/// The app pack's default flow: the request fallback when it names this pack,
/// else the pack's own default (`select_app_flow`).
fn default_flow_hint(
    app: &RevisionAppPack,
    fallback: Option<&WelcomeFlowHint>,
) -> Option<WelcomeFlowHint> {
    if let Some(hint) = fallback.filter(|h| h.pack_id == app.pack_id) {
        return Some(hint.clone());
    }
    select_app_flow(&app.info).ok().map(|flow| WelcomeFlowHint {
        pack_id: app.pack_id.clone(),
        flow_id: flow.id.clone(),
    })
}

/// The flow a conversation is parked in, if any.
///
/// The runner prefers a parked snapshot over the activity's flow ONLY when it
/// finds it, and on this path it finds it under a key that includes the
/// FLOW: the activity carries no channel, so `IngressEnvelope::canonicalize`
/// sets `channel = conversation = flow_id` and the wait is stored under that
/// reply scope. Pinning a different flow would therefore not resume the
/// parked one — it would start the new flow and strand the parked one (and a
/// card submit landing on the default flow afterwards would resume a stale
/// park). So every messaging flow of the app pack is checked, the default
/// first, through the runner's own `FlowResumeStore` over the revision's
/// session store.
pub(super) async fn parked_flow(
    store: &DynSessionStore,
    scope: &TurnScope<'_>,
    app: &RevisionAppPack,
    ingress: &ChannelMessageEnvelope,
    default_flow: Option<&WelcomeFlowHint>,
) -> Result<Option<String>> {
    let resume = FlowResumeStore::new(Arc::clone(store));
    let mut flows: Vec<&str> = Vec::new();
    if let Some(default) = default_flow {
        flows.push(default.flow_id.as_str());
    }
    for flow in &app.info.flows {
        if flow.kind.eq_ignore_ascii_case("messaging") && !flows.contains(&flow.id.as_str()) {
            flows.push(flow.id.as_str());
        }
    }
    let activity =
        super::envelope_to_activity(ingress, scope.tenant, scope.endpoint_id, None, None);
    for flow_id in flows {
        let envelope = resume_lookup_envelope(&activity, scope.tenant, &app.pack_id, flow_id);
        // greentic-runner-host 1.1.x: `fetch` is synchronous.
        if resume
            .fetch(&envelope)
            .map_err(|err| anyhow::anyhow!("{err}"))?
            .is_some()
        {
            return Ok(Some(flow_id.to_string()));
        }
    }
    Ok(None)
}

/// The envelope runner-host's `build_prepared` would build for `activity`
/// pinned to `(pack_id, flow_id)`, as far as the resume store's key reads it
/// (tenant, env, pack, flow, session, provider, endpoint, channel,
/// conversation, user). Must stay in step with runner-host
/// `host.rs::build_prepared`; a drift makes the lookup miss (fail-safe: the
/// turn is routed as if nothing were parked).
pub(super) fn resume_lookup_envelope(
    activity: &Activity,
    tenant: &str,
    pack_id: &str,
    flow_id: &str,
) -> IngressEnvelope {
    IngressEnvelope {
        tenant: tenant.to_string(),
        env: std::env::var("GREENTIC_ENV").ok(),
        pack_id: Some(pack_id.to_string()),
        flow_id: flow_id.to_string(),
        flow_type: None,
        action: None,
        session_hint: activity.session_id().map(str::to_string),
        provider: activity.provider_id().map(str::to_string),
        messaging_endpoint_id: activity.messaging_endpoint_id().map(str::to_string),
        channel: activity.channel().map(str::to_string),
        conversation: activity.conversation().map(str::to_string),
        user: activity.user().map(str::to_string),
        activity_id: None,
        timestamp: None,
        payload: serde_json::Value::Null,
        metadata: None,
        reply_scope: None,
    }
    .canonicalize()
}

/// Run a planned turn: a fixed reply short-circuits (the runner is never
/// called); otherwise `run` executes the turn and its replies are shaped by
/// `build` and stamped.
pub(super) async fn run_planned_turn<Run, Fut>(
    turn: RevisionTurn,
    run: Run,
    build: impl Fn(&Activity) -> Vec<ChannelMessageEnvelope>,
) -> Result<Vec<ChannelMessageEnvelope>>
where
    Run: FnOnce(ChannelMessageEnvelope, Option<WelcomeFlowHint>) -> Fut,
    Fut: Future<Output = Result<Vec<Activity>>>,
{
    if let Some(mut reply) = turn.fixed_reply {
        stamp_route(std::slice::from_mut(&mut reply), None, "");
        return Ok(vec![reply]);
    }
    let replies = run(turn.envelope, turn.target).await?;
    Ok(stamped_reply_envelopes(
        &replies,
        turn.signal.as_ref(),
        build,
    ))
}

/// Shape every reply and stamp the route signal on all of them — or strip a
/// forged inbound key from all of them when the turn was not routed. A routed
/// turn whose flow FAILED (the runner returned a flow-error reply) carries no
/// signal, as on the legacy path.
pub(super) fn stamped_reply_envelopes(
    replies: &[Activity],
    signal: Option<&(RouteSignal, String)>,
    build: impl Fn(&Activity) -> Vec<ChannelMessageEnvelope>,
) -> Vec<ChannelMessageEnvelope> {
    let failed = replies
        .iter()
        .any(|reply| super::flow_error_reply_text(reply.payload()).is_some());
    let signal = match signal {
        Some((_, flow_id)) if failed => {
            operator_log::info(
                module_path!(),
                format!(
                    "[fast2flow] flow={flow_id} failed on a routed turn — route signal withheld"
                ),
            );
            None
        }
        other => other,
    };
    let mut envelopes: Vec<ChannelMessageEnvelope> = replies.iter().flat_map(&build).collect();
    match signal {
        Some((signal, flow_id)) => stamp_route(&mut envelopes, Some(signal), flow_id),
        None => stamp_route(&mut envelopes, None, ""),
    }
    envelopes
}
