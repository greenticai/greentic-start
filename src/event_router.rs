use std::path::Path;

use anyhow::Context;
use chrono::Utc;
use serde_json::{Value as JsonValue, json};

use crate::domains::Domain;
use crate::ingress_types::{EventEnvelopeV1, EventScopeV1, EventSourceV1};
use crate::messaging_app::{self as app, AppFlowInfo, AppPackInfo};
use crate::operator_log;
use crate::runner_exec::{self, RunRequest};
use crate::runner_host::OperatorContext;

/// Maximum number of emit→route→emit hops before the router stops
/// re-dispatching, to prevent runaway event loops.
const MAX_EVENT_ROUTE_DEPTH: usize = 8;

/// Generate a fresh event identifier using UUID v4.
fn new_event_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Return the current UTC timestamp formatted as RFC 3339.
fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

/// Host-mint a full `EventEnvelopeV1` from a flow-emitted partial.
///
/// The `partial` must be a JSON object carrying at least `event_type` (a
/// non-empty string).  The optional `payload` key is extracted verbatim;
/// when absent the envelope carries an empty object.
///
/// Returns `None` — and logs nothing here (the caller logs) — when the
/// partial is malformed (missing or empty `event_type`).
fn mint_event_envelope(
    partial: &JsonValue,
    ctx: &OperatorContext,
    source_flow_id: &str,
    parent_correlation_id: Option<&str>,
) -> Option<EventEnvelopeV1> {
    let event_type = partial.get("event_type")?.as_str()?.trim().to_string();
    if event_type.is_empty() {
        return None;
    }
    let payload = partial
        .get("payload")
        .cloned()
        .unwrap_or_else(|| JsonValue::Object(Default::default()));

    // Correlation ID: prefer the partial's own, then the parent event's, then
    // the operator context's.
    let correlation_id = partial
        .get("correlation_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| parent_correlation_id.map(|s| s.to_string()))
        .or_else(|| ctx.correlation_id.clone());

    Some(EventEnvelopeV1 {
        event_id: new_event_id(),
        event_type,
        occurred_at: now_rfc3339(),
        source: EventSourceV1 {
            domain: "events".to_string(),
            provider: "flow-emit".to_string(),
            handler_id: Some(source_flow_id.to_string()),
        },
        scope: EventScopeV1 {
            tenant: ctx.tenant.clone(),
            team: ctx.team.clone(),
        },
        correlation_id,
        payload,
        http: None,
        raw: None,
    })
}

/// Returns the flows whose `subscribes_to` patterns match `event_type`.
/// An empty result means no flow explicitly subscribes; the caller should
/// fall back to the pack's default flow.
pub fn select_target_flows<'a>(info: &'a AppPackInfo, event_type: &str) -> Vec<&'a AppFlowInfo> {
    info.flows
        .iter()
        .filter(|f| {
            f.subscribes_to
                .iter()
                .any(|p| crate::topic_match::topic_matches(p, event_type))
        })
        .collect()
}

/// Topic-routed event dispatch with a default-flow fallback.
///
/// For each event in `events`:
/// - If one or more flows subscribe to the event's topic, each matching flow
///   is invoked once.
/// - If no flow subscribes, the pack's default flow is invoked (same behavior
///   as `route_events_to_default_flow`).
///
/// After each flow run, any business events it emitted are collected and
/// re-routed via a recursive call guarded by `MAX_EVENT_ROUTE_DEPTH`.
///
/// Returns the total number of flow invocations dispatched.
pub fn route_events(
    bundle: &Path,
    ctx: &OperatorContext,
    events: &[EventEnvelopeV1],
) -> anyhow::Result<usize> {
    route_events_inner(bundle, ctx, events, 0)
}

fn route_events_inner(
    bundle: &Path,
    ctx: &OperatorContext,
    events: &[EventEnvelopeV1],
    depth: usize,
) -> anyhow::Result<usize> {
    if events.is_empty() {
        return Ok(0);
    }

    let team = ctx.team.as_deref();
    let app_pack_path = app::resolve_app_pack_path(bundle, &ctx.tenant, team, None)
        .context("resolve default app pack for event routing")?;
    let pack_info = app::load_app_pack_info(&app_pack_path).context("load app pack manifest")?;

    let mut routed = 0usize;
    let mut next_wave: Vec<EventEnvelopeV1> = Vec::new();

    for event in events {
        let target_flows = select_target_flows(&pack_info, &event.event_type);
        let flows_to_run: Vec<&AppFlowInfo> = if target_flows.is_empty() {
            // No subscriber matched — fall back to the default flow.
            vec![app::select_app_flow(&pack_info).context("select app default flow")?]
        } else {
            target_flows
        };

        for flow in flows_to_run {
            let input = build_event_flow_input(event, ctx);
            let request = RunRequest {
                root: bundle.to_path_buf(),
                domain: Domain::Events,
                pack_path: app_pack_path.clone(),
                pack_label: pack_info.pack_id.clone(),
                flow_id: flow.id.clone(),
                tenant: ctx.tenant.clone(),
                team: ctx.team.clone(),
                input,
                dist_offline: true,
            };
            let output = runner_exec::run_provider_pack_flow(request)
                .with_context(|| format!("route event {} -> {}", event.event_type, flow.id))?;
            routed += 1;

            // Collect any business events this flow emitted for re-routing.
            for partial in &output.result.emitted_events {
                if let Some(env) =
                    mint_event_envelope(partial, ctx, &flow.id, event.correlation_id.as_deref())
                {
                    next_wave.push(env);
                } else {
                    operator_log::warn(
                        module_path!(),
                        format!(
                            "dropping malformed emitted event from flow {} (missing event_type)",
                            flow.id
                        ),
                    );
                }
            }
        }
    }

    // Re-route the emitted wave under the depth guard.
    if !next_wave.is_empty() {
        if depth + 1 >= MAX_EVENT_ROUTE_DEPTH {
            operator_log::warn(
                module_path!(),
                format!(
                    "event re-route depth limit {} reached; dropping {} emitted event(s)",
                    MAX_EVENT_ROUTE_DEPTH,
                    next_wave.len()
                ),
            );
        } else {
            routed += route_events_inner(bundle, ctx, &next_wave, depth + 1)?;
        }
    }

    operator_log::info(
        module_path!(),
        format!(
            "event router delivered {} flow invocation(s) for {} event(s) pack={} depth={}",
            routed,
            events.len(),
            pack_info.pack_id,
            depth
        ),
    );

    Ok(routed)
}

fn build_event_flow_input(event: &EventEnvelopeV1, ctx: &OperatorContext) -> JsonValue {
    json!({
        "event": event,
        "events": [event],
        "tenant": ctx.tenant,
        "team": ctx.team,
        "correlation_id": event.correlation_id.clone().or(ctx.correlation_id.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_EVENT_ROUTE_DEPTH, build_event_flow_input, mint_event_envelope, select_target_flows,
    };
    use crate::messaging_app::{AppFlowInfo, AppPackInfo};
    use crate::runner_host::OperatorContext;

    fn make_pack() -> AppPackInfo {
        AppPackInfo {
            pack_id: "test-pack".to_string(),
            flows: vec![
                AppFlowInfo {
                    id: "default".to_string(),
                    kind: "messaging".to_string(),
                    subscribes_to: vec![],
                },
                AppFlowInfo {
                    id: "on_order".to_string(),
                    kind: "messaging".to_string(),
                    subscribes_to: vec!["orders.*".to_string()],
                },
            ],
        }
    }

    #[test]
    fn select_target_flows_matches_subscribed_topic() {
        let info = make_pack();
        let matched = select_target_flows(&info, "orders.created");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id, "on_order");
    }

    #[test]
    fn select_target_flows_returns_empty_for_unsubscribed_topic() {
        let info = make_pack();
        let matched = select_target_flows(&info, "random");
        assert!(
            matched.is_empty(),
            "unmatched topic must yield empty vec for fallback"
        );
    }

    #[test]
    fn select_target_flows_matches_multiple_subscribers() {
        let info = AppPackInfo {
            pack_id: "multi-pack".to_string(),
            flows: vec![
                AppFlowInfo {
                    id: "orders_handler".to_string(),
                    kind: "messaging".to_string(),
                    subscribes_to: vec!["orders.*".to_string()],
                },
                AppFlowInfo {
                    id: "audit_log".to_string(),
                    kind: "messaging".to_string(),
                    subscribes_to: vec!["orders.*".to_string(), "payments.*".to_string()],
                },
                AppFlowInfo {
                    id: "payments_only".to_string(),
                    kind: "messaging".to_string(),
                    subscribes_to: vec!["payments.*".to_string()],
                },
            ],
        };
        let matched = select_target_flows(&info, "orders.shipped");
        let ids: Vec<&str> = matched.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["orders_handler", "audit_log"]);
    }

    #[test]
    fn select_target_flows_exact_match_does_not_bleed_into_other_prefixes() {
        let info = AppPackInfo {
            pack_id: "exact-pack".to_string(),
            flows: vec![AppFlowInfo {
                id: "billing_flow".to_string(),
                kind: "messaging".to_string(),
                subscribes_to: vec!["billing.*".to_string()],
            }],
        };
        // "subscription.created" must NOT match "billing.*"
        let matched = select_target_flows(&info, "subscription.created");
        assert!(matched.is_empty());
    }

    #[test]
    fn build_event_flow_input_prefers_event_correlation_id() {
        let event: crate::ingress_types::EventEnvelopeV1 =
            serde_json::from_value(serde_json::json!({
                "event_id": "evt-1",
                "event_type": "subscription.created",
                "occurred_at": "2026-04-01T00:00:00Z",
                "source": {
                    "domain": "events",
                    "provider": "events-webhook",
                    "handler_id": "default"
                },
                "scope": {
                    "tenant": "demo",
                    "team": "default"
                },
                "correlation_id": "evt-corr",
                "payload": {"id": "1"}
            }))
            .expect("event");
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            correlation_id: Some("ctx-corr".to_string()),
        };

        let input = build_event_flow_input(&event, &ctx);
        assert_eq!(input["tenant"], "demo");
        assert_eq!(input["team"], "default");
        assert_eq!(input["correlation_id"], "evt-corr");
        assert_eq!(input["events"].as_array().expect("events").len(), 1);
    }

    #[test]
    fn build_event_flow_input_falls_back_to_context_correlation_id() {
        let event: crate::ingress_types::EventEnvelopeV1 =
            serde_json::from_value(serde_json::json!({
                "event_id": "evt-2",
                "event_type": "subscription.deleted",
                "occurred_at": "2026-04-01T00:00:01Z",
                "source": {
                    "domain": "events",
                    "provider": "events-webhook"
                },
                "scope": {
                    "tenant": "demo"
                },
                "payload": {"id": "2"}
            }))
            .expect("event");
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: None,
            correlation_id: Some("ctx-corr".to_string()),
        };

        let input = build_event_flow_input(&event, &ctx);
        assert_eq!(input["correlation_id"], "ctx-corr");
        assert!(input["team"].is_null());
    }

    #[test]
    fn mint_event_envelope_builds_full_envelope_from_partial() {
        let partial = serde_json::json!({
            "event_type": "orders.created",
            "payload": { "id": "o1" }
        });
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            correlation_id: Some("root-corr".to_string()),
        };
        let env = mint_event_envelope(&partial, &ctx, "checkout_flow", Some("root-corr"))
            .expect("partial with event_type must mint");
        assert_eq!(env.event_type, "orders.created");
        assert_eq!(env.scope.tenant, "demo");
        assert_eq!(env.payload["id"], "o1");
        assert_eq!(env.correlation_id.as_deref(), Some("root-corr"));
        assert!(!env.event_id.is_empty(), "host must mint an event_id");
        assert!(!env.occurred_at.is_empty(), "host must mint occurred_at");
        assert_eq!(env.source.domain, "events");
    }

    #[test]
    fn mint_event_envelope_rejects_partial_without_event_type() {
        let partial = serde_json::json!({ "payload": {} });
        let ctx = OperatorContext {
            tenant: "demo".into(),
            team: None,
            correlation_id: None,
        };
        assert!(mint_event_envelope(&partial, &ctx, "f", None).is_none());
    }

    /// Proves the partial → mint (A5) → event_type → select_target_flows chain
    /// entirely in-process.
    ///
    /// 1. Build a partial as `RunResult.emitted_events` carries it.
    /// 2. Call `mint_event_envelope` to produce a full `EventEnvelopeV1`.
    /// 3. Assert the minted envelope carries the correct `event_type`.
    /// 4. Call `select_target_flows` with that `event_type` and assert only
    ///    the `orders.*` subscriber (`flow_b`) is returned, not the emitter
    ///    (`flow_a`, which has no subscription).
    #[test]
    fn mint_then_select_routes_emitted_partial_to_subscriber() {
        let partial = serde_json::json!({
            "event_type": "orders.created",
            "payload": { "id": "o1" }
        });
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            correlation_id: None,
        };

        // Step A5: mint a full envelope from the partial emitted by flow_a.
        let envelope = mint_event_envelope(&partial, &ctx, "flow_a", None)
            .expect("partial with event_type must mint a full envelope");
        assert_eq!(
            envelope.event_type, "orders.created",
            "minted envelope must preserve the emitted event_type"
        );

        // Selection: build a pack with flow_a (no subscription) and flow_b (orders.*).
        let pack = AppPackInfo {
            pack_id: "emit-unit-pack".to_string(),
            flows: vec![
                AppFlowInfo {
                    id: "flow_a".to_string(),
                    kind: "messaging".to_string(),
                    subscribes_to: vec![],
                },
                AppFlowInfo {
                    id: "flow_b".to_string(),
                    kind: "events".to_string(),
                    subscribes_to: vec!["orders.*".to_string()],
                },
            ],
        };

        let matched = select_target_flows(&pack, &envelope.event_type);
        let ids: Vec<&str> = matched.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["flow_b"],
            "orders.created must route to flow_b (orders.* subscriber) only; \
             flow_a (no subscription) must be excluded"
        );
    }

    #[test]
    fn route_depth_constant_is_bounded() {
        // Guard against accidental unbounded recursion via a 0 or huge constant.
        // Uses a const block so clippy::assertions_on_constants is satisfied.
        const {
            assert!(
                MAX_EVENT_ROUTE_DEPTH >= 2 && MAX_EVENT_ROUTE_DEPTH <= 32,
                "MAX_EVENT_ROUTE_DEPTH is out of the safe [2, 32] range"
            );
        }
    }
}
