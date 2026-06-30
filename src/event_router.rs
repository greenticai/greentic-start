use std::path::Path;

use anyhow::Context;
use serde_json::{Value as JsonValue, json};

use crate::domains::Domain;
use crate::ingress_types::EventEnvelopeV1;
use crate::messaging_app::{self as app, AppFlowInfo, AppPackInfo};
use crate::operator_log;
use crate::runner_exec::{self, RunRequest};
use crate::runner_host::OperatorContext;

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
/// Returns the total number of flow invocations dispatched.
pub fn route_events(
    bundle: &Path,
    ctx: &OperatorContext,
    events: &[EventEnvelopeV1],
) -> anyhow::Result<usize> {
    if events.is_empty() {
        return Ok(0);
    }
    let team = ctx.team.as_deref();
    let app_pack_path = app::resolve_app_pack_path(bundle, &ctx.tenant, team, None)
        .context("resolve default app pack for event routing")?;
    let pack_info = app::load_app_pack_info(&app_pack_path).context("load app pack manifest")?;

    let mut routed = 0usize;
    for event in events {
        let target_flows = select_target_flows(&pack_info, &event.event_type);
        if target_flows.is_empty() {
            // No subscriber matched — fall back to the default flow.
            let flow = app::select_app_flow(&pack_info).context("select app default flow")?;
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
            runner_exec::run_provider_pack_flow(request)
                .with_context(|| format!("route event {} -> {}", event.event_type, flow.id))?;
            routed += 1;
        } else {
            for flow in target_flows {
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
                runner_exec::run_provider_pack_flow(request)
                    .with_context(|| format!("route event {} -> {}", event.event_type, flow.id))?;
                routed += 1;
            }
        }
    }
    operator_log::info(
        module_path!(),
        format!(
            "event router delivered {} flow invocation(s) for {} event(s) pack={}",
            routed,
            events.len(),
            pack_info.pack_id
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
    use super::{build_event_flow_input, select_target_flows};
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
            capabilities: vec![],
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
            capabilities: vec![],
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
            capabilities: vec![],
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
}
