use std::path::Path;

use anyhow::Context;
use serde_json::{Value as JsonValue, json};

use crate::domains::Domain;
use crate::ingress_types::EventEnvelopeV1;
use crate::messaging_app as app;
use crate::operator_log;
use crate::runner_exec::{self, RunRequest};
use crate::runner_host::OperatorContext;

pub fn route_events_to_default_flow(
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
    let flow = app::select_app_flow(&pack_info).context("select app default flow")?;

    let mut routed = 0usize;
    for event in events {
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
            cross_pack_resolver: None,
        };
        runner_exec::run_provider_pack_flow(request)
            .with_context(|| format!("route event {} -> {}", event.event_type, flow.id))?;
        routed += 1;
    }
    operator_log::info(
        module_path!(),
        format!(
            "event router delivered {} event(s) to pack={} flow={}",
            routed, pack_info.pack_id, flow.id
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
    use super::build_event_flow_input;
    use crate::runner_host::OperatorContext;

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
