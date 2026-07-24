#![allow(dead_code)]

//! Wall-clock trigger scheduler: fires declared `TriggerDef`s on their
//! `TriggerSchedule`, minting a business event routed to subscribing flows
//! (sink A) and durably appended to SoRX (sink C). Sibling of `timer_scheduler`.

use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use anyhow::Context;
use chrono::{DateTime, Utc};
use greentic_triggers::{TriggerDef, business_event_for_fire};

use crate::event_router::route_event_to_subscribers;
use crate::ingress_types::{EventEnvelopeV1, EventScopeV1, EventSourceV1};
use crate::operator_log;
use crate::runner_host::{DemoRunnerHost, OperatorContext};
use crate::sorx_append_client::SorxAppendClient;

pub struct WallClockSchedulerConfig {
    pub runner_host: Arc<DemoRunnerHost>,
    pub tenant: String,
    pub team: Option<String>,
    pub triggers: Vec<TriggerDef>,
    pub sorx: Option<SorxAppendClient>,
    pub state_dir: PathBuf,
    pub debug_enabled: bool,
}

pub struct WallClockScheduler {
    shutdown: Option<mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<anyhow::Result<()>>>,
}

impl WallClockScheduler {
    pub fn start(config: WallClockSchedulerConfig) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::channel::<()>();
        let handle = thread::Builder::new()
            .name("wallclock-trigger-scheduler".to_string())
            .spawn(move || run_loop(config, rx))
            .context("spawn wall-clock scheduler thread")?;
        Ok(Self {
            shutdown: Some(tx),
            handle: Some(handle),
        })
    }

    pub fn stop(mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|e| anyhow::anyhow!("wall-clock scheduler panicked: {e:?}"))??;
        }
        Ok(())
    }
}

struct Scheduled {
    def: TriggerDef,
    last_fire: Option<DateTime<Utc>>,
}

fn run_loop(config: WallClockSchedulerConfig, rx: mpsc::Receiver<()>) -> anyhow::Result<()> {
    if config.triggers.is_empty() {
        return Ok(());
    }

    // Task 10 replaces this seed with catch-up-from-state; core seeds fire-forward.
    let mut scheduled: Vec<Scheduled> = config
        .triggers
        .iter()
        .map(|def| Scheduled {
            def: def.clone(),
            last_fire: Some(Utc::now()),
        })
        .collect();

    operator_log::info(
        module_path!(),
        format!(
            "wall-clock scheduler started triggers={} tenant={} team={}",
            scheduled.len(),
            config.tenant,
            config.team.as_deref().unwrap_or("default")
        ),
    );

    loop {
        let now = Utc::now();
        let mut soonest: Option<DateTime<Utc>> = None;
        for s in &mut scheduled {
            let after = s.last_fire.unwrap_or(now);
            let Some(next) = s.def.schedule.next_fire(after) else {
                continue;
            };
            if next <= now {
                fire(&config, &s.def, next);
                s.last_fire = Some(next);
                if let Some(following) = s.def.schedule.next_fire(next) {
                    soonest = Some(soonest.map_or(following, |c| c.min(following)));
                }
            } else {
                soonest = Some(soonest.map_or(next, |c| c.min(next)));
            }
        }

        let sleep_for = soonest
            .map(|t| {
                (t - Utc::now())
                    .to_std()
                    .unwrap_or(Duration::from_millis(200))
            })
            .unwrap_or(Duration::from_secs(30))
            .clamp(Duration::from_millis(200), Duration::from_secs(60));
        if rx.recv_timeout(sleep_for).is_ok() {
            break;
        }
    }
    operator_log::info(module_path!(), "wall-clock scheduler stopped");
    Ok(())
}

fn fire(config: &WallClockSchedulerConfig, def: &TriggerDef, fire_time: DateTime<Utc>) {
    // Build the tenant context once, up front. An invalid tenant id must
    // fail the whole fire rather than silently routing events to a shared
    // "unknown" tenant scope (cross-tenant comingling risk).
    let tenant = match tenant_ctx(&config.tenant, config.team.as_deref()) {
        Ok(t) => t,
        Err(err) => {
            operator_log::error(
                module_path!(),
                format!("trigger '{}' skipped: {err}", def.id),
            );
            return;
        }
    };

    let business = match business_event_for_fire(def, fire_time, &tenant) {
        Ok(business) => business,
        Err(errs) => {
            operator_log::error(
                module_path!(),
                format!("trigger '{}' mint failed: {}", def.id, errs.join("; ")),
            );
            return;
        }
    };

    let env = match business_to_envelope(
        &business,
        def,
        fire_time,
        &config.tenant,
        config.team.as_deref(),
    ) {
        Ok(env) => env,
        Err(err) => {
            operator_log::error(
                module_path!(),
                format!("trigger '{}' mint failed: {err}", def.id),
            );
            return;
        }
    };

    let ctx = OperatorContext {
        tenant: config.tenant.clone(),
        team: config.team.clone(),
        correlation_id: None,
    };
    if let Err(err) = route_event_to_subscribers(config.runner_host.bundle_root(), &ctx, &env) {
        operator_log::error(
            module_path!(),
            format!("trigger '{}' routing failed: {err}", def.id),
        );
    }
    if let Some(sorx) = &config.sorx
        && let Err(err) = sorx.append(&config.tenant, &business)
    {
        operator_log::warn(
            module_path!(),
            format!("trigger '{}' sorx append failed: {err}", def.id),
        );
    }
}

/// Map a fired trigger to greentic-start's ingress `EventEnvelopeV1`.
pub(crate) fn envelope_for(
    def: &TriggerDef,
    fire_time: DateTime<Utc>,
    tenant: &str,
    team: Option<&str>,
) -> anyhow::Result<EventEnvelopeV1> {
    let ctx = tenant_ctx(tenant, team)?;
    let business = business_event_for_fire(def, fire_time, &ctx)
        .map_err(|errs| anyhow::anyhow!("business event build failed: {}", errs.join("; ")))?;
    business_to_envelope(&business, def, fire_time, tenant, team)
}

/// Map an already-minted business event to greentic-start's ingress
/// `EventEnvelopeV1`. Split out from `envelope_for` so `fire()` can build the
/// business event exactly once per fire and reuse it for both sink A
/// (routing) and sink C (SoRX append).
fn business_to_envelope(
    business: &greentic_types::EventEnvelope,
    def: &TriggerDef,
    fire_time: DateTime<Utc>,
    tenant: &str,
    team: Option<&str>,
) -> anyhow::Result<EventEnvelopeV1> {
    let (domain, name) = greentic_types::events::parse_business_event_type(&business.r#type)
        .map_err(|e| anyhow::anyhow!("parse emitted type: {e}"))?;
    Ok(EventEnvelopeV1 {
        event_id: business.id.to_string(),
        event_type: format!("{domain}.{name}"),
        occurred_at: fire_time.to_rfc3339(),
        source: EventSourceV1 {
            domain: "events".into(),
            provider: "trigger".into(),
            handler_id: Some(def.id.clone()),
        },
        scope: EventScopeV1 {
            tenant: tenant.to_string(),
            team: team.map(ToString::to_string),
        },
        correlation_id: None,
        payload: business.payload.clone(),
        http: None,
        raw: None,
    })
}

fn tenant_ctx(tenant: &str, team: Option<&str>) -> anyhow::Result<greentic_types::TenantCtx> {
    let env = greentic_types::EnvId::try_from("default").expect("static env id");
    let tid = greentic_types::TenantId::try_from(tenant)
        .map_err(|e| anyhow::anyhow!("invalid tenant id '{tenant}': {e}"))?;
    let ctx = greentic_types::TenantCtx::new(env, tid);
    let ctx = match team.and_then(|t| greentic_types::TeamId::try_from(t).ok()) {
        Some(team_id) => ctx.with_team(Some(team_id)),
        None => ctx,
    };
    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use greentic_triggers::{
        TriggerDef,
        schedule::{TimeOfDay, TriggerSchedule},
    };

    #[test]
    fn envelope_for_maps_business_event_to_ingress_envelope() {
        let def = TriggerDef {
            id: "daily_rent".into(),
            schedule: TriggerSchedule::Daily {
                at: TimeOfDay { hour: 6, minute: 0 },
            },
            emits: "cap://greentic/events/tenancy/rent".into(),
            payload_template: serde_json::json!({ "at": "{{fire_time}}" }),
        };
        let fire = Utc.with_ymd_and_hms(2026, 7, 24, 6, 0, 0).unwrap();
        let env = envelope_for(&def, fire, "acme", Some("core")).expect("map");
        assert_eq!(env.event_type, "tenancy.rent");
        assert_eq!(env.occurred_at, fire.to_rfc3339());
        assert_eq!(env.scope.tenant, "acme");
        assert_eq!(env.source.provider, "trigger");
        assert_eq!(env.source.handler_id.as_deref(), Some("daily_rent"));
        assert_eq!(env.payload["at"], fire.to_rfc3339());
    }

    #[test]
    fn envelope_for_rejects_invalid_tenant() {
        let def = TriggerDef {
            id: "t".into(),
            schedule: TriggerSchedule::Daily {
                at: TimeOfDay { hour: 6, minute: 0 },
            },
            emits: "cap://greentic/events/tenancy/rent".into(),
            payload_template: serde_json::json!({}),
        };
        let fire = Utc.with_ymd_and_hms(2026, 7, 24, 6, 0, 0).unwrap();
        // An empty tenant id must be rejected, not silently mapped to "unknown".
        assert!(envelope_for(&def, fire, "", Some("core")).is_err());
    }
}
