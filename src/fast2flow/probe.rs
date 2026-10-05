//! The one Fast2Flow entry an ingress calls per turn: ask the routing host,
//! fall back to the embedded LLM, and decide what an unrouted turn does.
//!
//! Path-neutral: everything the probe needs arrives in [`ProbeInputs`],
//! including the LLM config, which is injected rather than read from the
//! process-global so a caller without a `bundle.yaml` can supply its own (or
//! none) and so the probe is testable.
//!
//! Blocking: it may spawn the routing host and may block on the LLM. Async
//! callers must run it on a blocking thread.

use std::path::Path;

use greentic_types::ChannelMessageEnvelope;

use super::dispatch::{self, RouteDecision};
use super::turn::{self, MissAction, Unrouted};
use super::{FAST2FLOW_CAPABILITY, Fast2FlowConfig};
use crate::bundle_config::BundleLlmConfig;
use crate::messaging_app::AppPackInfo;
use crate::runner_host::OperatorContext;

/// Everything one turn's probe reads.
pub(crate) struct ProbeInputs<'a> {
    pub(crate) cfg: &'a Fast2FlowConfig,
    /// Tenant and team; the default index scope is `<tenant>:<team>`.
    pub(crate) ctx: &'a OperatorContext,
    /// The app pack the turn runs in.
    pub(crate) pack: &'a AppPackInfo,
    pub(crate) pack_path: &'a Path,
    /// Index scope override. `None` = the default `<tenant>:<team>` scope.
    pub(crate) index_scope: Option<&'a str>,
    /// The messaging provider id the ingress resolved.
    pub(crate) provider: &'a str,
    /// The `llm:` instance for the LLM fallback; `None` disables it.
    pub(crate) llm: Option<&'a BundleLlmConfig>,
}

/// What a turn does, decided before any flow runs.
///
/// Generic over the route type so the legacy ingress, which maps a
/// [`RouteDecision`] onto its own borrowed flow, shares the ONE miss policy
/// ([`plan_from`]) with the revision-serve path.
// One value per turn, moved once; boxing the reply buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TurnPlan<T = RouteDecision> {
    /// Fast2Flow or the LLM fallback routed the turn.
    Routed(T),
    /// The default flow runs with the original message. `on_miss` is set when
    /// it runs because the pack opted into
    /// [`super::FAST2FLOW_ON_MISS_DEFAULT_FLOW_CAPABILITY`] on a routing miss.
    DefaultFlow { on_miss: bool },
    /// No flow runs; this reply is sent instead.
    FixedReply(ChannelMessageEnvelope),
}

/// Ask the routing host, then the LLM fallback.
///
/// A node target synthesizes the same metadata an Adaptive Card button click
/// would produce — `routeToCardId` — so the card path renders the chosen card
/// inside the default flow. A `pack/flow` target runs that flow from its
/// entry. `Deny`/`Respond` stop routing for the turn (no LLM fallback);
/// anything else unrouted falls to the embedded LLM fallback.
pub(crate) fn probe(
    i: &ProbeInputs<'_>,
    envelope: &ChannelMessageEnvelope,
) -> Result<RouteDecision, Unrouted> {
    let host = dispatch::host_route(
        super::route_request_in_scope(
            i.cfg,
            i.ctx,
            i.pack,
            i.pack_path,
            envelope,
            i.provider,
            i.index_scope,
        ),
        i.pack,
        envelope,
    );
    turn::probe_turn(host, || llm_fallback(i, envelope))
}

/// What an unrouted turn does when the router could not be asked or failed
/// (`Unrouted::RouterNotConfigured` / `Unrouted::RouterFailed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnRouterFailure {
    /// The miss policy applies, as for a genuine no-match. The legacy
    /// ingress's behaviour; it reaches the policy through [`plan_from`].
    #[cfg_attr(not(test), allow(dead_code))]
    MissPolicy,
    /// The default flow runs (fail open). The revision-serve path: a turn that
    /// worked before Fast2Flow must not break when the routing host binary is
    /// absent, crashes, times out, or the pack ships no intent index.
    DefaultFlow,
}

/// [`probe`] plus the miss policy ([`plan_from`]).
///
/// A conversation owned by a flow is never routed: the probe is not run and
/// the plan is the default flow (the caller resumes the owning flow).
pub(crate) fn plan_turn(
    i: &ProbeInputs<'_>,
    envelope: &ChannelMessageEnvelope,
    owns_conversation: bool,
    on_router_failure: OnRouterFailure,
) -> TurnPlan {
    if owns_conversation {
        return TurnPlan::DefaultFlow { on_miss: false };
    }
    let outcome = probe(i, envelope);
    if on_router_failure == OnRouterFailure::DefaultFlow
        && let Err(cause @ (Unrouted::RouterFailed(_) | Unrouted::RouterNotConfigured(_))) =
            &outcome
    {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "[fast2flow] {} — running the default flow (fail open) pack={}",
                cause.describe(),
                i.pack.pack_id
            ),
        );
        return TurnPlan::DefaultFlow { on_miss: false };
    }
    plan_from(&i.pack.capabilities, envelope, outcome)
}

/// The miss policy ([`turn::miss_action`]) applied to a probe outcome: the
/// single place an unrouted turn becomes the default flow or the fixed reply.
pub(crate) fn plan_from<T>(
    capabilities: &[String],
    envelope: &ChannelMessageEnvelope,
    outcome: Result<T, Unrouted>,
) -> TurnPlan<T> {
    let unrouted = match outcome {
        Ok(route) => return TurnPlan::Routed(route),
        Err(unrouted) => unrouted,
    };
    match turn::miss_action(
        false,
        capabilities,
        envelope.text.as_deref(),
        Some(&unrouted),
    ) {
        MissAction::RunDefaultFlow => TurnPlan::DefaultFlow { on_miss: false },
        MissAction::DefaultFlowOnMiss => TurnPlan::DefaultFlow { on_miss: true },
        MissAction::FixedReply => TurnPlan::FixedReply(turn::miss_reply(envelope)),
    }
}

/// Embedded LLM routing fallback: when the deterministic tier yields no usable
/// dispatch for a Fast2Flow-capable pack and an `llm:` instance with
/// `fast2flow` enabled was supplied, ask [`crate::llm`] to pick a card or a
/// flow and route it exactly as a host dispatch is routed. Needs no external
/// binary, so it works embedded. `None` ⇒ fall through.
fn llm_fallback(i: &ProbeInputs<'_>, original: &ChannelMessageEnvelope) -> Option<RouteDecision> {
    let llm = i.llm?;
    if !llm.fast2flow {
        return None;
    }
    if !i
        .pack
        .capabilities
        .iter()
        .any(|c| c == FAST2FLOW_CAPABILITY)
    {
        return None;
    }
    let text = original
        .text
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())?;
    let index_path = super::resolve_index_path(i.cfg, i.ctx, i.pack_path, i.index_scope)?;
    dispatch::llm_route(
        super::try_llm_route(llm, i.ctx, &index_path, text),
        i.pack,
        original,
    )
}

#[cfg(all(test, unix))]
#[path = "probe_tests.rs"]
mod tests;
