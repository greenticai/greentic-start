//! One messaging turn: route it, run it, stamp the route, settle ownership.
//! Egress (render → encode → send) stays with the caller.
//!
//! The router probe and the flow runner are injected so the ingress wiring —
//! which branch a turn takes and what its replies carry — is testable without
//! a runner host or a routing host.

use std::path::Path;

use greentic_types::ChannelMessageEnvelope;

use super::*;
use crate::fast2flow::turn::{self as fast2flow_turn, Unrouted};

/// What running an app flow produced for one turn.
pub(super) struct FlowRun {
    pub(super) outputs: Vec<ChannelMessageEnvelope>,
    /// The flow errored and `outputs` is the error-fallback echo of its input,
    /// not the flow's answer. A failed turn never carries a route signal.
    pub(super) failed: bool,
}

impl FlowRun {
    fn ok(outputs: Vec<ChannelMessageEnvelope>) -> Self {
        Self {
            outputs,
            failed: false,
        }
    }
}

/// Runs a flow of the app pack from its entry: `(flow, envelope)`.
///
/// Backport note: greentic-runner 1.1.x has no `RunOptions::entry_node`, so a
/// card-navigation target cannot enter the flow at a node on this line; it
/// renders the card asset or runs the flow from its entry, as 1.1.41 did.
pub(super) type RunFlow<'a> = dyn FnMut(&app::AppFlowInfo, &ChannelMessageEnvelope) -> FlowRun + 'a;

#[allow(clippy::too_many_arguments)]
pub(super) fn turn_outputs<'p>(
    bundle: &Path,
    ctx: &OperatorContext,
    pack_info: &'p app::AppPackInfo,
    default_flow: &'p app::AppFlowInfo,
    app_pack_path: &Path,
    original: &ChannelMessageEnvelope,
    probe: impl FnOnce() -> Result<Routed<'p>, Unrouted>,
    run_flow: &mut RunFlow<'_>,
) -> Vec<ChannelMessageEnvelope> {
    let turn = resolve_turn(bundle, ctx, pack_info, default_flow, original, probe);
    let flow = turn.flow;
    let envelope = &turn.envelope;
    let cause = turn
        .cause
        .clone()
        .unwrap_or_else(|| "no dispatch".to_string());
    let text_len = envelope.text.as_deref().map(str::len).unwrap_or(0);

    let run = if let Some(route_to_card) = card_nav_target(envelope) {
        match read_card_from_pack(app_pack_path, route_to_card) {
            Some(card_json) => FlowRun::ok(vec![render_card_asset(
                ctx,
                pack_info,
                app_pack_path,
                envelope,
                route_to_card,
                card_json,
            )]),
            None => {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "[demo messaging] card routing: {route_to_card} -> card asset NOT found, using app flow"
                    ),
                );
                run_flow(flow, envelope)
            }
        }
    } else if let Some(reply) = turn.fixed_reply.clone() {
        // A Fast2Flow pack, free text, no route — or a Deny/Respond this path
        // does not handle yet. Surface a short reply so we don't re-echo the
        // welcome menu and confuse the user.
        operator_log::info(
            module_path!(),
            format!(
                "[fast2flow] {cause} for free text — emitting fixed miss reply pack={} text_len={text_len}",
                pack_info.pack_id
            ),
        );
        FlowRun::ok(vec![reply])
    } else {
        if turn.on_miss {
            // The pack declared the on-miss opt-in: the unrouted message goes
            // to the default flow, unchanged. A failed router degrades here
            // too, and the log says it failed rather than "no dispatch".
            operator_log::info(
                module_path!(),
                format!(
                    "[fast2flow] {cause} for free text — running default flow={} (on_miss opt-in) pack={} text_len={text_len}",
                    flow.id, pack_info.pack_id
                ),
            );
        }
        run_flow(flow, envelope)
    };

    let signal = match (&turn.route, run.failed) {
        (Some(_), true) => {
            operator_log::info(
                module_path!(),
                format!(
                    "[fast2flow] flow={} failed on a routed turn — route signal withheld",
                    flow.id
                ),
            );
            None
        }
        (route, _) => route.as_ref(),
    };
    let mut outputs = run.outputs;
    fast2flow_turn::stamp_route(&mut outputs, signal, &flow.id);

    if turn.owns_conversation {
        // Keep the conversation with this flow while it is parked on it;
        // give it back to routing once the flow has completed.
        flow_owner::settle(
            bundle,
            ctx,
            &pack_info.pack_id,
            &flow.id,
            &envelope.session_id,
        );
    }
    outputs
}

/// Render a card asset straight from the pack as the turn's reply.
fn render_card_asset(
    ctx: &OperatorContext,
    pack_info: &app::AppPackInfo,
    app_pack_path: &Path,
    envelope: &ChannelMessageEnvelope,
    route_to_card: &str,
    mut card_json: serde_json::Value,
) -> ChannelMessageEnvelope {
    operator_log::info(
        module_path!(),
        format!("[demo messaging] card routing: {route_to_card} -> card asset found"),
    );
    let from_id = envelope.from.as_ref().map(|f| f.id.as_str()).unwrap_or("?");
    crate::flow_log::log(
        "CARD",
        &format!(
            "pack={} routeToCardId={} tenant={} from={}",
            pack_info.pack_id, route_to_card, ctx.tenant, from_id
        ),
    );
    // Resolve {{i18n:KEY}} tokens from pack i18n bundle
    let locale = envelope
        .metadata
        .get("locale")
        .map(String::as_str)
        .unwrap_or("en");
    resolve_i18n_tokens(&mut card_json, app_pack_path, locale);
    // Empty-string defaults for unmatched `${prefill_*}`
    // — keeps the literal text out of the rendered card.
    let mut effective_metadata = envelope.metadata.clone();
    ensure_prefill_defaults(&card_json, &mut effective_metadata);
    resolve_placeholders(&mut card_json, &effective_metadata);
    carry_form_data_to_actions(&mut card_json, &effective_metadata);
    let mut reply = envelope.clone();
    reply.metadata.insert(
        "adaptive_card".to_string(),
        serde_json::to_string(&card_json).unwrap_or_default(),
    );
    reply.text = None;
    reply
}

#[cfg(test)]
#[path = "messaging_turn_tests.rs"]
mod tests;
