//! Turn a router answer into a route for one turn, independent of the ingress
//! that asked.
//!
//! The result is OWNED ([`RouteDecision`] names a flow by id), so a caller that
//! does not hold the pack's `AppFlowInfo`s across the turn — the revision-serve
//! path — can use it as well as the legacy messaging ingress, which maps the
//! flow id back onto its own `&AppFlowInfo`.

use greentic_types::ChannelMessageEnvelope;

use super::RoutingOutcome;
use super::turn::{RouteSignal, RouteSource, Unrouted};
use crate::ingress::control_directive::{ControlDirective, DispatchTarget, PrefillEntity};
use crate::messaging_app::{AppFlowInfo, AppPackInfo};
use crate::operator_log;

/// What the router decided for one turn, and how it was decided.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum RouteDecision {
    /// A card node inside the default flow; the envelope carries
    /// `routeToCardId`.
    Node {
        envelope: ChannelMessageEnvelope,
        signal: RouteSignal,
    },
    /// A whole messaging flow of the app pack, run from its entry
    /// (greentic-start#590).
    Flow {
        flow_id: String,
        envelope: ChannelMessageEnvelope,
        signal: RouteSignal,
    },
}

/// Drop intent-extracted entities into `envelope.metadata` so the
/// existing `${placeholder}` substitution step can wire them into card
/// fields. The shape is intentionally generic — no per-kind code lives
/// here. Each entity contributes:
///
/// * `prefill_<kind>` — the canonical `normalized` value.
/// * `prefill_<kind>_<role>` — when the entity carries a role tag
///   (e.g. `prefill_location_from`, `prefill_location_to`).
/// * `prefill_<kind>_<format>` — for every entry in the entity's
///   `formats` map (e.g. an `iso` variant of a `YYYYMMDD` date, set
///   by the routing host so this layer stays kind-agnostic).
///
/// Card authors opt in per field via `value: "${prefill_<key>}"`. The
/// runtime never assumes which fields exist or which entities will
/// arrive — every entity surfaces under the same naming convention.
pub(crate) fn inject_prefill_metadata(
    envelope: &mut ChannelMessageEnvelope,
    entities: &[PrefillEntity],
) {
    for entity in entities {
        envelope.metadata.insert(
            format!("prefill_{}", entity.kind),
            entity.normalized.clone(),
        );
        if let Some(role) = entity.role.as_deref() {
            envelope.metadata.insert(
                format!("prefill_{}_{}", entity.kind, role),
                entity.normalized.clone(),
            );
        }
        for (format_name, value) in &entity.formats {
            envelope.metadata.insert(
                format!("prefill_{}_{}", entity.kind, format_name),
                value.clone(),
            );
        }
    }
}

/// Route an LLM router answer; every route it produces is `RouteSource::Llm`.
pub(crate) fn llm_route(
    directive: Option<ControlDirective>,
    pack_info: &AppPackInfo,
    original: &ChannelMessageEnvelope,
) -> Option<RouteDecision> {
    apply_dispatch(directive?, pack_info, original, RouteSource::Llm).ok()
}

/// Map the host router's outcome onto a route or the reason there is none.
pub(crate) fn host_route(
    outcome: RoutingOutcome,
    pack_info: &AppPackInfo,
    original: &ChannelMessageEnvelope,
) -> Result<RouteDecision, Unrouted> {
    match outcome {
        RoutingOutcome::Directive(directive) => {
            apply_dispatch(directive, pack_info, original, RouteSource::Bm25)
        }
        RoutingOutcome::NoMatch => Err(Unrouted::NoMatch),
        RoutingOutcome::NotConfigured(reason) => Err(Unrouted::RouterNotConfigured(reason)),
        RoutingOutcome::Failed(reason) => Err(Unrouted::RouterFailed(reason)),
    }
}

/// Turn a router directive into a route, or the reason there is none.
///
/// `Continue` and a `Dispatch` naming nothing this pack can run are
/// [`Unrouted::NoMatch`] (the next fallback gets the turn, as before #590).
/// `Deny` and `Respond` are [`Unrouted::Unhandled`]: routing stops for the turn.
pub(crate) fn apply_dispatch(
    directive: ControlDirective,
    pack_info: &AppPackInfo,
    original: &ChannelMessageEnvelope,
    source: RouteSource,
) -> Result<RouteDecision, Unrouted> {
    let (target, entities, confidence) = match directive {
        ControlDirective::Dispatch {
            target,
            entities,
            confidence,
        } => (target, entities, confidence),
        ControlDirective::Continue => return Err(Unrouted::NoMatch),
        ControlDirective::Deny { .. } | ControlDirective::Respond { .. } => {
            let kind = if matches!(directive, ControlDirective::Deny { .. }) {
                "deny"
            } else {
                "respond"
            };
            operator_log::warn(
                module_path!(),
                format!(
                    "[{}] {kind} directive is not handled on the messaging path yet — \
                     routing stops for this turn and the fixed reply is sent (pack={})",
                    source.log_label(),
                    pack_info.pack_id
                ),
            );
            return Err(Unrouted::Unhandled(kind));
        }
    };
    let signal = |node: Option<String>| RouteSignal {
        node,
        confidence,
        source,
    };
    let source = source.log_label();
    if let Some(node) = target.node.clone() {
        operator_log::info(
            module_path!(),
            format!(
                "[{source}] dispatch -> routeToCardId={node} entities={} (pack={} flow={:?})",
                entities.len(),
                target.pack,
                target.flow
            ),
        );
        let mut owned = original.clone();
        owned
            .metadata
            .insert("routeToCardId".to_string(), node.clone());
        inject_prefill_metadata(&mut owned, &entities);
        return Ok(RouteDecision::Node {
            envelope: owned,
            signal: signal(Some(node)),
        });
    }
    let Some(flow) = dispatch_flow(pack_info, &target) else {
        operator_log::info(
            module_path!(),
            format!(
                "[{source}] dispatch to pack={} flow={:?} names no messaging flow of app pack {}; ignored",
                target.pack, target.flow, pack_info.pack_id
            ),
        );
        return Err(Unrouted::NoMatch);
    };
    operator_log::info(
        module_path!(),
        format!(
            "[{source}] dispatch -> flow={} entities={} (pack={})",
            flow.id,
            entities.len(),
            target.pack
        ),
    );
    let mut owned = original.clone();
    inject_prefill_metadata(&mut owned, &entities);
    Ok(RouteDecision::Flow {
        flow_id: flow.id.clone(),
        envelope: owned,
        signal: signal(None),
    })
}

/// The flow a `pack/flow` target names, when it is a messaging flow of THIS
/// app pack. A node target (`pack/flow/node`) is a card route, not a flow
/// route, and a target for another pack is not ours to run.
pub(crate) fn dispatch_flow<'p>(
    pack_info: &'p AppPackInfo,
    target: &DispatchTarget,
) -> Option<&'p AppFlowInfo> {
    if target.node.is_some() || target.pack != pack_info.pack_id {
        return None;
    }
    messaging_flow(pack_info, target.flow.as_deref()?)
}

/// The messaging flow of `pack_info` with id `flow_id`. The one lookup both
/// [`dispatch_flow`] and a caller mapping [`RouteDecision::Flow`] back onto
/// the pack use, so the two cannot pick different flows.
pub(crate) fn messaging_flow<'p>(
    pack_info: &'p AppPackInfo,
    flow_id: &str,
) -> Option<&'p AppFlowInfo> {
    pack_info
        .flows
        .iter()
        .find(|f| f.id == flow_id && f.kind.eq_ignore_ascii_case("messaging"))
}
