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
