#![allow(dead_code)]

use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use zip::ZipArchive;

use crate::discovery;
use crate::domains::Domain;
use crate::event_router::route_events_to_default_flow;
use crate::ingress_types::EventEnvelopeV1;
use crate::operator_log;
use crate::runner_host::{DemoRunnerHost, OperatorContext};

#[derive(Clone, Debug)]
pub struct TimerHandlerConfig {
    pub provider: String,
    pub op_id: String,
    pub handler_id: String,
    pub interval_seconds: u64,
}

#[derive(Clone)]
pub struct TimerSchedulerConfig {
    pub runner_host: Arc<DemoRunnerHost>,
    pub tenant: String,
    pub team: Option<String>,
    pub handlers: Vec<TimerHandlerConfig>,
    pub debug_enabled: bool,
}

pub struct TimerScheduler {
    shutdown: Option<mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<anyhow::Result<()>>>,
}

impl TimerScheduler {
    pub fn start(config: TimerSchedulerConfig) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::channel::<()>();
        let handle = thread::Builder::new()
            .name("demo-events-timer".to_string())
            .spawn(move || run_scheduler_loop(config, rx))
            .context("spawn timer scheduler thread")?;
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
                .map_err(|err| anyhow::anyhow!("timer scheduler panicked: {err:?}"))??;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ScheduledTimer {
    config: TimerHandlerConfig,
    next_tick: Instant,
    last_run_rfc3339: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimerTickInputV1 {
    v: u8,
    domain: String,
    provider: String,
    handler_id: String,
    tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    team: Option<String>,
    occurred_at: String,
    interval_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_run: Option<String>,
}

fn run_scheduler_loop(config: TimerSchedulerConfig, rx: mpsc::Receiver<()>) -> anyhow::Result<()> {
    if config.handlers.is_empty() {
        return Ok(());
    }
    let mut timers = config
        .handlers
        .iter()
        .cloned()
        .map(|handler| ScheduledTimer {
            next_tick: Instant::now() + Duration::from_secs(handler.interval_seconds.max(1)),
            config: handler,
            last_run_rfc3339: None,
        })
        .collect::<Vec<_>>();

    operator_log::info(
        module_path!(),
        format!(
            "events timer scheduler started handlers={} tenant={} team={}",
            timers.len(),
            config.tenant,
            config.team.as_deref().unwrap_or("default")
        ),
    );

    loop {
        let now = Instant::now();
        for timer in &mut timers {
            if now < timer.next_tick {
                continue;
            }
            if let Err(err) = run_timer_handler(&config, timer) {
                operator_log::error(module_path!(), format!("timer handler failed: {err}"));
            }
            timer.next_tick = Instant::now() + Duration::from_secs(timer.config.interval_seconds);
        }

        let sleep_for = timers
            .iter()
            .map(|timer| timer.next_tick.saturating_duration_since(Instant::now()))
            .min()
            .unwrap_or_else(|| Duration::from_millis(200))
            .max(Duration::from_millis(50));
        if rx.recv_timeout(sleep_for).is_ok() {
            break;
        }
    }

    operator_log::info(module_path!(), "events timer scheduler stopped");
    Ok(())
}

fn run_timer_handler(
    scheduler: &TimerSchedulerConfig,
    timer: &mut ScheduledTimer,
) -> anyhow::Result<()> {
    let occurred_at = Utc::now().to_rfc3339();
    let payload = TimerTickInputV1 {
        v: 1,
        domain: "events".to_string(),
        provider: timer.config.provider.clone(),
        handler_id: timer.config.handler_id.clone(),
        tenant: scheduler.tenant.clone(),
        team: scheduler.team.clone(),
        occurred_at: occurred_at.clone(),
        interval_seconds: timer.config.interval_seconds,
        last_run: timer.last_run_rfc3339.clone(),
    };
    let bytes = greentic_types::cbor::canonical::to_canonical_cbor(&payload)
        .map_err(|err| anyhow::anyhow!("{err}"))?;
    let context = OperatorContext {
        tenant: scheduler.tenant.clone(),
        team: scheduler.team.clone(),
        correlation_id: None,
    };
    let outcome = scheduler.runner_host.invoke_provider_op(
        Domain::Events,
        &timer.config.provider,
        &timer.config.op_id,
        &bytes,
        &context,
    )?;
    if !outcome.success {
        let message = outcome
            .error
            .or(outcome.raw)
            .unwrap_or_else(|| "timer op failed".to_string());
        anyhow::bail!(
            "provider={} op={} handler={} failed: {}",
            timer.config.provider,
            timer.config.op_id,
            timer.config.handler_id,
            message
        );
    }
    if scheduler.debug_enabled {
        operator_log::debug(
            module_path!(),
            format!(
                "[demo dev] timer tick provider={} op={} handler={} tenant={} team={}",
                timer.config.provider,
                timer.config.op_id,
                timer.config.handler_id,
                scheduler.tenant,
                scheduler.team.as_deref().unwrap_or("default")
            ),
        );
    }
    let output = outcome.output.unwrap_or_else(|| json!({}));
    let events = parse_events(&output)?;
    if !events.is_empty() {
        route_events_to_default_flow(scheduler.runner_host.bundle_root(), &context, &events)?;
    }
    timer.last_run_rfc3339 = Some(occurred_at);
    Ok(())
}

fn parse_events(output: &JsonValue) -> anyhow::Result<Vec<EventEnvelopeV1>> {
    let Some(array) = output.get("events").and_then(JsonValue::as_array) else {
        return Ok(Vec::new());
    };
    let mut events = Vec::with_capacity(array.len());
    for entry in array {
        let event: EventEnvelopeV1 = serde_json::from_value(entry.clone())
            .context("invalid EventEnvelopeV1 emitted by timer op")?;
        events.push(event);
    }
    Ok(events)
}

pub fn discover_timer_handlers(
    discovery: &discovery::DiscoveryResult,
    default_interval_seconds: u64,
) -> anyhow::Result<Vec<TimerHandlerConfig>> {
    let mut handlers = Vec::new();
    for provider in &discovery.providers {
        if provider.domain != "events" {
            continue;
        }
        let file = std::fs::File::open(&provider.pack_path)?;
        let mut archive = ZipArchive::new(file)?;
        let mut manifest = archive.by_name("manifest.cbor").with_context(|| {
            format!("manifest.cbor missing in {}", provider.pack_path.display())
        })?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut manifest, &mut bytes)?;
        let manifest_json: JsonValue = serde_cbor::from_slice(&bytes)
            .with_context(|| format!("decode manifest.cbor {}", provider.pack_path.display()))?;
        let explicit = parse_explicit_timer_handlers(
            &manifest_json,
            &provider.provider_id,
            default_interval_seconds.max(1),
        )?;
        if !explicit.is_empty() {
            handlers.extend(explicit);
            continue;
        }
        // Guarded fallback for legacy packs that do not declare explicit timer metadata.
        for op in parse_provider_ops(&manifest_json, &provider.provider_id)? {
            if let Some((handler_id, interval_seconds)) =
                parse_timer_op(&op, default_interval_seconds.max(1))
            {
                handlers.push(TimerHandlerConfig {
                    provider: provider.provider_id.clone(),
                    op_id: op,
                    handler_id,
                    interval_seconds,
                });
            }
        }
    }
    Ok(handlers)
}

fn parse_explicit_timer_handlers(
    manifest_json: &JsonValue,
    default_provider: &str,
    default_interval_seconds: u64,
) -> anyhow::Result<Vec<TimerHandlerConfig>> {
    let inline = provider_extension_inline_json(manifest_json)?;
    let mut handlers = Vec::new();
    for key in ["timer_handlers", "timers"] {
        if let Some(values) = inline.get(key).and_then(JsonValue::as_array) {
            for entry in values {
                if let Some(handler) =
                    parse_timer_handler_entry(entry, default_provider, default_interval_seconds)
                {
                    handlers.push(handler);
                }
            }
        }
    }
    if !handlers.is_empty() {
        return Ok(handlers);
    }
    if let Some(providers) = inline.get("providers").and_then(JsonValue::as_array) {
        for provider in providers {
            let provider_type = provider
                .get("provider_type")
                .and_then(JsonValue::as_str)
                .unwrap_or(default_provider);
            for key in ["timer_handlers", "timers"] {
                if let Some(values) = provider.get(key).and_then(JsonValue::as_array) {
                    for entry in values {
                        if let Some(mut handler) = parse_timer_handler_entry(
                            entry,
                            default_provider,
                            default_interval_seconds,
                        ) {
                            if handler.provider == default_provider {
                                handler.provider = provider_type.to_string();
                            }
                            handlers.push(handler);
                        }
                    }
                }
            }
        }
    }
    Ok(handlers)
}

fn parse_timer_handler_entry(
    value: &JsonValue,
    default_provider: &str,
    default_interval_seconds: u64,
) -> Option<TimerHandlerConfig> {
    if let Some(op_id) = value.as_str() {
        return Some(TimerHandlerConfig {
            provider: default_provider.to_string(),
            op_id: op_id.to_string(),
            handler_id: "default".to_string(),
            interval_seconds: default_interval_seconds,
        });
    }
    let obj = value.as_object()?;
    let op_id = obj
        .get("op_id")
        .and_then(JsonValue::as_str)
        .or_else(|| obj.get("op").and_then(JsonValue::as_str))?
        .to_string();
    let handler_id = obj
        .get("handler_id")
        .and_then(JsonValue::as_str)
        .or_else(|| obj.get("handler").and_then(JsonValue::as_str))
        .unwrap_or("default")
        .to_string();
    let provider = obj
        .get("provider_type")
        .and_then(JsonValue::as_str)
        .or_else(|| obj.get("provider").and_then(JsonValue::as_str))
        .unwrap_or(default_provider)
        .to_string();
    let interval_seconds = obj
        .get("interval_seconds")
        .and_then(JsonValue::as_u64)
        .or_else(|| obj.get("interval").and_then(JsonValue::as_u64))
        .unwrap_or(default_interval_seconds)
        .max(1);
    Some(TimerHandlerConfig {
        provider,
        op_id,
        handler_id,
        interval_seconds,
    })
}

fn parse_provider_ops(manifest_json: &JsonValue, provider_id: &str) -> anyhow::Result<Vec<String>> {
    let inline = provider_extension_inline_json(manifest_json)?;
    let mut ops = Vec::new();
    if let Some(providers) = inline.get("providers").and_then(JsonValue::as_array) {
        for provider in providers {
            let provider_type = provider
                .get("provider_type")
                .and_then(JsonValue::as_str)
                .unwrap_or_default();
            if provider_type != provider_id {
                continue;
            }
            if let Some(provider_ops) = provider.get("ops").and_then(JsonValue::as_array) {
                for op in provider_ops {
                    if let Some(op_id) = op.as_str() {
                        ops.push(op_id.to_string());
                    }
                }
            }
        }
    }
    Ok(ops)
}

fn provider_extension_inline_json(manifest_json: &JsonValue) -> anyhow::Result<&JsonValue> {
    manifest_json
        .get("extensions")
        .and_then(JsonValue::as_object)
        .and_then(|extensions| extensions.get("greentic.provider-extension.v1"))
        .and_then(JsonValue::as_object)
        .and_then(|ext| ext.get("inline"))
        .ok_or_else(|| anyhow::anyhow!("provider extension inline payload missing"))
}

fn parse_timer_op(op: &str, default_interval_seconds: u64) -> Option<(String, u64)> {
    if op.eq_ignore_ascii_case("timer_tick") || op.eq_ignore_ascii_case("ingest_timer") {
        return Some(("default".to_string(), default_interval_seconds));
    }
    let prefix = "timer_";
    if !op.starts_with(prefix) {
        return None;
    }
    let tail = &op[prefix.len()..];
    if tail.is_empty() {
        return Some(("default".to_string(), default_interval_seconds));
    }
    let mut parts = tail.rsplitn(2, '_');
    let last = parts.next().unwrap_or_default();
    let rest = parts.next();
    if let Ok(interval) = last.parse::<u64>() {
        let handler = rest.unwrap_or("default");
        return Some((handler.to_string(), interval.max(1)));
    }
    Some((tail.to_string(), default_interval_seconds))
}

#[cfg(test)]
mod tests {
    use super::{
        parse_events, parse_explicit_timer_handlers, parse_provider_ops, parse_timer_handler_entry,
        parse_timer_op, provider_extension_inline_json,
    };
    use crate::ingress_types::EventEnvelopeV1;
    use serde_json::json;

    #[test]
    fn timer_op_conventions_are_detected() {
        assert_eq!(
            parse_timer_op("timer_tick", 30).expect("timer_tick"),
            ("default".to_string(), 30)
        );
        assert_eq!(
            parse_timer_op("timer_reminder", 30).expect("timer_reminder"),
            ("reminder".to_string(), 30)
        );
        assert_eq!(
            parse_timer_op("timer_reminder_10", 30).expect("timer_reminder_10"),
            ("reminder".to_string(), 10)
        );
        assert!(parse_timer_op("ingest_http", 30).is_none());
    }

    #[test]
    fn parses_explicit_timer_handlers_from_extension() {
        let manifest = json!({
            "extensions": {
                "greentic.provider-extension.v1": {
                    "inline": {
                        "timer_handlers": [
                            {"provider_type":"events-twilio","op_id":"timer_poll","handler_id":"poll","interval_seconds":15}
                        ]
                    }
                }
            }
        });
        let handlers =
            parse_explicit_timer_handlers(&manifest, "events-twilio", 60).expect("parse explicit");
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].provider, "events-twilio");
        assert_eq!(handlers[0].op_id, "timer_poll");
        assert_eq!(handlers[0].handler_id, "poll");
        assert_eq!(handlers[0].interval_seconds, 15);
    }

    #[test]
    fn parses_nested_provider_timer_handlers_and_defaults() {
        let manifest = json!({
            "extensions": {
                "greentic.provider-extension.v1": {
                    "inline": {
                        "providers": [
                            {
                                "provider_type": "events-slack",
                                "timer_handlers": [
                                    "timer_tick",
                                    {"op": "timer_cleanup_0", "handler": "cleanup", "interval": 0}
                                ]
                            }
                        ]
                    }
                }
            }
        });
        let handlers =
            parse_explicit_timer_handlers(&manifest, "events-default", 30).expect("parse");
        assert_eq!(handlers.len(), 2);
        assert_eq!(handlers[0].provider, "events-slack");
        assert_eq!(handlers[0].op_id, "timer_tick");
        assert_eq!(handlers[0].handler_id, "default");
        assert_eq!(handlers[0].interval_seconds, 30);
        assert_eq!(handlers[1].provider, "events-slack");
        assert_eq!(handlers[1].op_id, "timer_cleanup_0");
        assert_eq!(handlers[1].handler_id, "cleanup");
        assert_eq!(handlers[1].interval_seconds, 1);
    }

    #[test]
    fn parses_provider_ops_and_inline_payload_errors() {
        let manifest = json!({
            "extensions": {
                "greentic.provider-extension.v1": {
                    "inline": {
                        "providers": [
                            {"provider_type": "events-a", "ops": ["timer_poll", "ingest_http"]},
                            {"provider_type": "events-b", "ops": ["timer_tick"]}
                        ]
                    }
                }
            }
        });
        assert_eq!(
            parse_provider_ops(&manifest, "events-a").expect("provider ops"),
            vec!["timer_poll".to_string(), "ingest_http".to_string()]
        );
        let err = provider_extension_inline_json(&json!({})).expect_err("missing extension");
        assert!(
            err.to_string()
                .contains("provider extension inline payload missing")
        );
    }

    #[test]
    fn parses_timer_handler_entries_and_event_outputs() {
        let handler = parse_timer_handler_entry(
            &json!({
                "op_id": "timer_digest",
                "handler_id": "digest",
                "provider": "events-email",
                "interval_seconds": 45
            }),
            "events-default",
            30,
        )
        .expect("handler");
        assert_eq!(handler.provider, "events-email");
        assert_eq!(handler.op_id, "timer_digest");
        assert_eq!(handler.handler_id, "digest");
        assert_eq!(handler.interval_seconds, 45);

        let event: EventEnvelopeV1 = serde_json::from_value(json!({
            "event_id": "evt-1",
            "event_type": "timer.fired",
            "occurred_at": "2026-04-01T00:00:00Z",
            "source": {
                "domain": "events",
                "provider": "events-email",
                "handler_id": "digest"
            },
            "scope": {
                "tenant": "demo",
                "team": "default"
            },
            "payload": {"ok": true}
        }))
        .expect("event");
        let parsed = parse_events(&json!({"events": [event]})).expect("parse events");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].event_type, "timer.fired");

        assert!(parse_events(&json!({})).expect("missing events").is_empty());
        let err = parse_events(&json!({"events": [{"bad": true}]})).expect_err("invalid event");
        assert!(err.to_string().contains("invalid EventEnvelopeV1"));
    }

    #[test]
    fn parse_timer_handler_entry_accepts_string_and_provider_alias_fields() {
        let string_handler =
            parse_timer_handler_entry(&json!("timer_tick"), "events-default", 25).expect("string");
        assert_eq!(string_handler.provider, "events-default");
        assert_eq!(string_handler.handler_id, "default");
        assert_eq!(string_handler.interval_seconds, 25);

        let alias_handler = parse_timer_handler_entry(
            &json!({
                "op": "timer_sync",
                "provider_type": "events-sync",
                "interval": 5
            }),
            "events-default",
            30,
        )
        .expect("alias handler");
        assert_eq!(alias_handler.provider, "events-sync");
        assert_eq!(alias_handler.op_id, "timer_sync");
        assert_eq!(alias_handler.handler_id, "default");
        assert_eq!(alias_handler.interval_seconds, 5);
    }
}
