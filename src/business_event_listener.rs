//! NATS subscriber + parse/convert for the SoRX business-event bus.
//!
//! Subscribes to `greentic.events.>`, converts each raw NATS message
//! (`subject`, `body`) into an `(OperatorContext, EventEnvelopeV1)` pair, and
//! routes it to flows via `crate::event_router::route_events`. Mirrors
//! `crate::threshold_watcher`'s shape: a background thread (owning a
//! dedicated single-thread Tokio runtime, exactly like
//! `crate::threshold_watcher::watcher` owns its polling thread) that is off
//! by default and never panics or blocks the server on a connect/decode/
//! route failure. See `crate::runtime` (the `business_event_listener` wiring
//! block) for the discover -> start -> store -> stop pattern this module's
//! caller follows — gated on `GREENTIC_EVENTS_NATS_URL`, mirroring
//! `greentic-runner`'s `NatsDispatcher` gate.
//!
//! The `gtc start` path (`run_start_request -> run_start ->
//! demo_up_services`) is synchronous — there is no ambient Tokio runtime.
//! [`BusinessEventListener::start`] therefore owns its own runtime on a
//! dedicated `std::thread` (mirroring
//! `crate::threshold_watcher::ThresholdWatcher::start`'s thread ownership),
//! rather than borrowing/creating a temporary one in the caller: connecting
//! to NATS and subscribing both happen *inside* that thread's
//! `rt.block_on(...)`, so a connect failure only ever warns-and-exits the
//! background thread — it can never panic (`tokio::spawn`/`.await` with "no
//! reactor running") or crash boot.
//!
//! [`handle_message`] is generic over the `route` call purely for
//! testability: production code (the loop below, and `crate::runtime`)
//! always passes `event_router::route_events`; tests substitute a stand-in
//! to drive the message -> route path deterministically, without a running
//! NATS server or flow.

use std::path::{Path, PathBuf};
use std::thread;

use futures_util::StreamExt;
use tokio::sync::oneshot;

use crate::ingress_types::{EventEnvelopeV1, EventScopeV1, EventSourceV1};
use crate::operator_log;
use crate::runner_host::OperatorContext;

/// NATS subject wildcard business events are published on
/// (`greentic.events.<tenant>.<topic...>`; see [`topic_from_subject`]).
const BUSINESS_EVENTS_SUBJECT: &str = "greentic.events.>";

/// Default NATS queue group `greentic-start` instances subscribe under so a
/// business event is delivered to exactly one instance rather than every
/// instance in a multi-instance deployment (FIX I1).
///
/// Overridable per deployment via `GREENTIC_BE_QUEUE_GROUP` (see
/// [`resolve_queue_group`]) — distinct `greentic-start` deployments sharing
/// one NATS server must use different queue groups, or NATS may deliver one
/// deployment's event to the other (which can't route it), silently losing
/// it. Same-bundle HA replicas should keep this default so they still form a
/// single queue group.
pub const DEFAULT_BUSINESS_EVENTS_QUEUE_GROUP: &str = "greentic-start-be-listener";

/// Resolves the effective NATS queue group from an optional env value
/// (`GREENTIC_BE_QUEUE_GROUP`), falling back to
/// [`DEFAULT_BUSINESS_EVENTS_QUEUE_GROUP`] when the value is absent, empty,
/// or whitespace-only.
///
/// Takes the env value as a parameter (rather than reading
/// `std::env::var` itself) so it is deterministically testable; callers
/// (`crate::runtime`) pass `std::env::var("GREENTIC_BE_QUEUE_GROUP").ok()`.
pub fn resolve_queue_group(env_value: Option<String>) -> String {
    match env_value.as_deref().map(str::trim) {
        Some(trimmed) if !trimmed.is_empty() => trimmed.to_string(),
        _ => DEFAULT_BUSINESS_EVENTS_QUEUE_GROUP.to_string(),
    }
}

const SUBJECT_PREFIX: &str = "greentic.events.";

/// Extracts the routable topic from a `greentic.events.<tenant>.<topic...>`
/// NATS subject: everything after the tenant segment, re-joined with `.`.
///
/// `route_events`/`select_target_flows` (`crate::event_router`) match a
/// flow's `subscribes_to` patterns against `EventEnvelopeV1.event_type`.
/// Setting `event_type` to this subject-derived topic (e.g.
/// `sorla.pack.order.created`) is what makes a flow declaring
/// `subscribes_to: ["sorla.*"]` fire — see [`convert`] below.
///
/// Returns `None` if `subject` doesn't start with `greentic.events.` or has
/// no topic segment after the tenant.
pub fn topic_from_subject(subject: &str) -> Option<String> {
    let rest = subject.strip_prefix(SUBJECT_PREFIX)?;
    let mut parts = rest.splitn(2, '.');
    let _tenant = parts.next().filter(|s| !s.is_empty())?;
    let topic = parts.next().filter(|s| !s.is_empty())?;
    Some(topic.to_string())
}

/// Extracts the `<tenant>` segment from a `greentic.events.<tenant>.<topic...>`
/// NATS subject.
///
/// Returns `None` if `subject` doesn't start with `greentic.events.` or has
/// no tenant segment.
pub fn tenant_from_subject(subject: &str) -> Option<String> {
    let rest = subject.strip_prefix(SUBJECT_PREFIX)?;
    let mut parts = rest.splitn(2, '.');
    let tenant = parts.next().filter(|s| !s.is_empty())?;
    // A tenant segment with no topic after it is not a routable subject.
    parts.next().filter(|s| !s.is_empty())?;
    Some(tenant.to_string())
}

/// Decodes `body` as a `greentic_types::EventEnvelope` and converts it into
/// the `(OperatorContext, EventEnvelopeV1)` pair `route_events` expects.
///
/// `event_type` precedence (see [`topic_from_subject`] for why): the
/// subject-derived topic first, falling back to the decoded envelope's
/// `topic` (if non-empty), then its `r#type`. This keeps routing working
/// even if a caller sends a malformed subject but a well-formed envelope.
///
/// Never panics: any decode failure returns `None` (best-effort — callers
/// warn + skip the message rather than propagate an error).
pub fn convert(subject: &str, body: &[u8]) -> Option<(OperatorContext, EventEnvelopeV1)> {
    let envelope: greentic_types::EventEnvelope = serde_json::from_slice(body).ok()?;

    let event_type = topic_from_subject(subject)
        .or_else(|| Some(envelope.topic.clone()).filter(|t| !t.is_empty()))
        .unwrap_or_else(|| envelope.r#type.clone());

    let tenant = envelope.tenant.tenant_id.as_str().to_string();
    let team = envelope
        .tenant
        .team_id
        .as_ref()
        .map(|t| t.as_str().to_string());

    // Cross-check the subject's `<tenant>` segment against the decoded
    // envelope's tenant. The envelope's tenant always wins (it's the
    // authoritative, signed-off value); a mismatch only ever produces a
    // warning — it's a signal of a misconfigured publisher, never a reason
    // to drop the message.
    if let Some(subject_tenant) = tenant_from_subject(subject)
        && subject_tenant != tenant
    {
        operator_log::warn(
            module_path!(),
            format!(
                "business event subject tenant '{subject_tenant}' does not match \
                 envelope tenant '{tenant}'; routing with the envelope tenant"
            ),
        );
    }

    let ctx = OperatorContext {
        tenant: tenant.clone(),
        team: team.clone(),
        correlation_id: envelope.correlation_id.clone(),
    };

    // FIX M1: derive `source.domain` from the topic's first segment (e.g.
    // `sorla.pack.order.created` -> `sorla`) rather than hard-coding
    // `"sorla"` — a non-SoRX producer publishing on `greentic.events.>`
    // would otherwise be mislabeled. Falls back to `"events"` if the topic
    // has no non-empty first segment.
    let domain = event_type
        .split('.')
        .next()
        .filter(|segment| !segment.is_empty())
        .unwrap_or("events")
        .to_string();

    // Mirrors `threshold_watcher::watcher::build_crossing_event`'s
    // `EventEnvelopeV1` construction: `event_type` carries routing (there is
    // no dedicated `topic` field), and `source.provider` is the closest
    // analogue to a producer id.
    let event = EventEnvelopeV1 {
        event_id: envelope.id.to_string(),
        event_type,
        occurred_at: envelope.time.to_rfc3339(),
        source: EventSourceV1 {
            domain,
            provider: envelope.source.clone(),
            handler_id: None,
        },
        scope: EventScopeV1 { tenant, team },
        correlation_id: envelope.correlation_id.clone(),
        payload: envelope.payload.clone(),
        http: None,
        raw: None,
    };

    Some((ctx, event))
}

/// Decode-and-route a single business-event message.
///
/// Calls [`convert`]; on a successful decode, invokes `route` with the
/// resulting `(ctx, [event])` and warns (without propagating) on a routing
/// error. On a decode failure (malformed subject/body), the message is
/// dropped with a warning and `route` is NOT called — mirrors
/// `threshold_watcher::poll_once`'s fail-safe-skip behavior on a fetch
/// error.
///
/// Generic over `route` purely for testability — production callers (the
/// subscribe loop below) always pass `event_router::route_events`.
pub fn handle_message<R>(subject: &str, body: &[u8], bundle_root: &Path, route: R)
where
    R: FnOnce(&Path, &OperatorContext, &[EventEnvelopeV1]) -> anyhow::Result<usize>,
{
    let Some((ctx, event)) = convert(subject, body) else {
        operator_log::warn(
            module_path!(),
            format!(
                "business event listener dropped unroutable message subject={subject} (decode/subject parse failed)"
            ),
        );
        return;
    };

    if let Err(err) = route(bundle_root, &ctx, std::slice::from_ref(&event)) {
        operator_log::error(
            module_path!(),
            format!(
                "business event listener failed to route event subject={subject} event_type={}: {err:#}",
                event.event_type
            ),
        );
    }
}

/// Configuration for one running [`BusinessEventListener`]: the NATS URL to
/// connect to (connecting happens *inside* the listener's own thread/
/// runtime — see the module docs) and the bundle root `route_events`
/// dispatches against.
#[derive(Clone)]
pub struct BusinessEventListenerConfig {
    pub nats_url: String,
    pub bundle_root: PathBuf,
    /// NATS queue group to `queue_subscribe` under (see
    /// [`resolve_queue_group`]). Callers resolve this from
    /// `GREENTIC_BE_QUEUE_GROUP` before constructing the config.
    pub queue_group: String,
}

/// Handle to the background subscribe-loop thread. `start`/`stop` mirror
/// `crate::threshold_watcher::ThresholdWatcher` exactly: a dedicated
/// `std::thread` owns a Tokio runtime it builds itself, so the listener
/// never depends on (or corrupts) an ambient runtime the caller may or may
/// not have.
pub struct BusinessEventListener {
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl BusinessEventListener {
    /// Spawn the background thread that owns the listener's Tokio runtime.
    ///
    /// FIX C1: this thread builds its *own* `current_thread` runtime and
    /// does the `async_nats::connect` + `queue_subscribe` + subscribe loop
    /// entirely inside `rt.block_on(...)`. Nothing here runs on — or
    /// assumes — an ambient runtime, so calling this from the fully
    /// synchronous `gtc start` path (`run_start_request -> run_start ->
    /// demo_up_services`) is safe: a connect failure warns and the thread
    /// exits cleanly instead of panicking ("there is no reactor running")
    /// and crashing boot.
    ///
    /// If the thread itself fails to spawn (an exceptional OS-level
    /// condition), the failure is logged and a no-op handle is returned
    /// rather than panicking the caller — mirrors
    /// `ThresholdWatcher::start`.
    pub fn start(config: BusinessEventListenerConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        match thread::Builder::new()
            .name("business-event-listener".to_string())
            .spawn(move || run_listener_thread(config, shutdown_rx))
        {
            Ok(handle) => Self {
                shutdown: Some(shutdown_tx),
                handle: Some(handle),
            },
            Err(err) => {
                operator_log::error(
                    module_path!(),
                    format!("failed to spawn business event listener thread: {err}"),
                );
                Self {
                    shutdown: None,
                    handle: None,
                }
            }
        }
    }

    /// Signal the loop to stop and wait for the thread to exit. Mirrors
    /// `ThresholdWatcher::stop`: send the shutdown signal (a no-op if the
    /// thread already exited on its own, e.g. after a connect failure or a
    /// NATS disconnect), then join the thread so callers never race a
    /// still-running listener past `stop()` returning.
    pub fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take()
            && let Err(err) = handle.join()
        {
            operator_log::error(
                module_path!(),
                format!("business event listener thread panicked: {err:?}"),
            );
        }
    }
}

/// Thread entry point: build a dedicated single-thread Tokio runtime and run
/// the async subscribe loop on it via `block_on`. A runtime-build failure
/// (exceptional — e.g. OS resource exhaustion) warns and the thread exits;
/// it never propagates a panic to the caller.
fn run_listener_thread(config: BusinessEventListenerConfig, shutdown_rx: oneshot::Receiver<()>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            operator_log::error(
                module_path!(),
                format!("failed to build tokio runtime for business event listener: {err}"),
            );
            return;
        }
    };
    runtime.block_on(run_listener_loop(config, shutdown_rx));
}

/// Connect to NATS, queue-subscribe to `greentic.events.>`, and route every
/// message via [`handle_message`] until the subscription ends (NATS
/// disconnect) or `shutdown_rx` fires ([`BusinessEventListener::stop`]).
///
/// Best-effort throughout: a connect or subscribe failure warns and returns
/// without ever panicking the thread.
///
/// FIX I1: uses `queue_subscribe` under `config.queue_group` (defaults to
/// [`DEFAULT_BUSINESS_EVENTS_QUEUE_GROUP`], overridable via
/// `GREENTIC_BE_QUEUE_GROUP` — see [`resolve_queue_group`]) rather than a
/// plain fan-out `subscribe`, so multiple `greentic-start` instances sharing
/// the same NATS server form a queue group — each event is delivered to
/// exactly one instance instead of every instance double-firing the same
/// flow.
async fn run_listener_loop(
    config: BusinessEventListenerConfig,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let client = match async_nats::connect(&config.nats_url).await {
        Ok(client) => client,
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "business event listener failed to connect to {}: {err}",
                    config.nats_url
                ),
            );
            return;
        }
    };

    let queue_group = config.queue_group.clone();
    let mut subscriber = match client
        .queue_subscribe(BUSINESS_EVENTS_SUBJECT, queue_group.clone())
        .await
    {
        Ok(subscriber) => subscriber,
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "business event listener failed to subscribe to {BUSINESS_EVENTS_SUBJECT}: {err}"
                ),
            );
            return;
        }
    };

    operator_log::info(
        module_path!(),
        format!(
            "business event listener subscribed subject={BUSINESS_EVENTS_SUBJECT} queue_group={queue_group}"
        ),
    );

    loop {
        tokio::select! {
            maybe_message = subscriber.next() => {
                match maybe_message {
                    Some(message) => dispatch_message(message, &config.bundle_root),
                    None => {
                        operator_log::warn(
                            module_path!(),
                            "business event listener subscription ended (NATS connection closed)",
                        );
                        break;
                    }
                }
            }
            _ = &mut shutdown_rx => {
                operator_log::info(
                    module_path!(),
                    "business event listener stopping (shutdown signal)",
                );
                break;
            }
        }
    }
}

/// FIX I2: offloads one message's decode-and-route work
/// ([`handle_message`], which calls the synchronous, flow-executing
/// `event_router::route_events`) onto the blocking thread pool via
/// `tokio::task::spawn_blocking`, so a slow flow never stalls this loop's
/// `subscriber.next().await` (head-of-line blocking across the whole
/// subscription).
///
/// Fire-and-forget from the caller's perspective: a separate task awaits
/// the `spawn_blocking` join handle purely to log a join failure (e.g. a
/// panic inside `route_events`) — it is never propagated or re-panicked.
fn dispatch_message(message: async_nats::Message, bundle_root: &Path) {
    let subject = message.subject.to_string();
    let payload = message.payload.to_vec();
    let bundle_root = bundle_root.to_path_buf();
    let log_subject = subject.clone();

    let blocking = tokio::task::spawn_blocking(move || {
        handle_message(
            &subject,
            &payload,
            &bundle_root,
            crate::event_router::route_events,
        );
    });

    tokio::spawn(async move {
        if let Err(err) = blocking.await {
            operator_log::error(
                module_path!(),
                format!(
                    "business event listener spawn_blocking task failed subject={log_subject}: {err}"
                ),
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_types::{EnvId, EventEnvelope, EventId, TeamId, TenantCtx, TenantId};

    #[test]
    fn resolve_queue_group_uses_env_value_when_set() {
        assert_eq!(
            resolve_queue_group(Some("acme-prod".to_string())),
            "acme-prod"
        );
    }

    #[test]
    fn resolve_queue_group_trims_and_defaults_on_unset_or_blank() {
        assert_eq!(
            resolve_queue_group(None),
            DEFAULT_BUSINESS_EVENTS_QUEUE_GROUP
        );
        assert_eq!(
            resolve_queue_group(Some("   ".to_string())),
            DEFAULT_BUSINESS_EVENTS_QUEUE_GROUP
        );
        assert_eq!(
            resolve_queue_group(Some("  acme-prod  ".to_string())),
            "acme-prod"
        );
    }

    fn sample_tenant_ctx() -> TenantCtx {
        TenantCtx::new(
            EnvId::try_from("prod").expect("env"),
            TenantId::try_from("t1").expect("tenant"),
        )
        .with_team(Some(TeamId::try_from("ops").expect("team")))
    }

    fn sample_envelope() -> EventEnvelope {
        EventEnvelope {
            id: EventId::new("evt-1").expect("event id"),
            topic: "sorla.pack.order.created".to_string(),
            r#type: "cap://greentic/events/sorla/order-created".to_string(),
            source: "sorla".to_string(),
            tenant: sample_tenant_ctx(),
            subject: None,
            time: chrono::DateTime::UNIX_EPOCH,
            correlation_id: Some("corr-1".to_string()),
            payload: serde_json::json!({"order_id": "o-1"}),
            metadata: Default::default(),
        }
    }

    #[test]
    fn topic_and_tenant_parsed_from_subject() {
        assert_eq!(
            topic_from_subject("greentic.events.t1.sorla.pack.order.created").as_deref(),
            Some("sorla.pack.order.created")
        );
        assert_eq!(
            tenant_from_subject("greentic.events.t1.sorla.pack.order.created").as_deref(),
            Some("t1")
        );
        assert!(topic_from_subject("not.events").is_none());
        assert!(tenant_from_subject("not.events").is_none());
    }

    #[test]
    fn topic_from_subject_requires_tenant_and_topic_segments() {
        assert!(topic_from_subject("greentic.events.").is_none());
        assert!(topic_from_subject("greentic.events.t1").is_none());
        assert!(topic_from_subject("greentic.events.t1.").is_none());
    }

    #[test]
    fn tenant_from_subject_requires_a_topic_segment() {
        // A bare "greentic.events.t1" has a tenant-shaped segment but no
        // topic after it — not a routable subject.
        assert!(tenant_from_subject("greentic.events.t1").is_none());
    }

    #[test]
    fn convert_maps_business_event_to_routable_envelope() {
        let env = sample_envelope();
        let body = serde_json::to_vec(&env).expect("serialize envelope");

        let (ctx, ev) = convert("greentic.events.t1.sorla.pack.order.created", &body)
            .expect("convert should succeed");

        assert_eq!(ctx.tenant, "t1");
        assert_eq!(ctx.team.as_deref(), Some("ops"));
        assert_eq!(ctx.correlation_id.as_deref(), Some("corr-1"));
        // The subject topic drives subscribes_to matching, not the
        // envelope's own `topic`/`type` fields.
        assert_eq!(ev.event_type, "sorla.pack.order.created");
        assert_eq!(ev.scope.tenant, "t1");
        assert_eq!(ev.scope.team.as_deref(), Some("ops"));
        assert_eq!(ev.payload, serde_json::json!({"order_id": "o-1"}));

        let bad = convert("greentic.events.t1.x", b"{ not json");
        assert!(bad.is_none());
    }

    #[test]
    fn convert_falls_back_to_envelope_topic_when_subject_unparseable() {
        let env = sample_envelope();
        let body = serde_json::to_vec(&env).expect("serialize envelope");

        let (_, ev) = convert("not.a.greentic.subject", &body).expect("convert should succeed");
        assert_eq!(ev.event_type, "sorla.pack.order.created");
    }

    #[test]
    fn convert_falls_back_to_envelope_type_when_topic_empty() {
        let mut env = sample_envelope();
        env.topic = String::new();
        let body = serde_json::to_vec(&env).expect("serialize envelope");

        let (_, ev) = convert("not.a.greentic.subject", &body).expect("convert should succeed");
        assert_eq!(ev.event_type, "cap://greentic/events/sorla/order-created");
    }

    #[test]
    fn convert_prefers_envelope_tenant_over_mismatched_subject_tenant() {
        let env = sample_envelope();
        let body = serde_json::to_vec(&env).expect("serialize envelope");

        // Subject says "t2", envelope says "t1" — the envelope must win.
        let (ctx, ev) = convert("greentic.events.t2.sorla.pack.order.created", &body)
            .expect("convert should succeed despite the tenant mismatch");
        assert_eq!(ctx.tenant, "t1");
        assert_eq!(ev.scope.tenant, "t1");
    }

    #[test]
    fn convert_returns_none_on_malformed_body() {
        assert!(convert("greentic.events.t1.sorla.pack.order.created", b"{ not json").is_none());
        assert!(convert("greentic.events.t1.sorla.pack.order.created", b"").is_none());
    }

    #[test]
    fn handle_message_routes_valid_business_event() {
        let env = sample_envelope();
        let body = serde_json::to_vec(&env).expect("serialize envelope");

        let mut routed_event_type: Option<String> = None;
        let mut routed_tenant: Option<String> = None;
        handle_message(
            "greentic.events.t1.sorla.pack.order.created",
            &body,
            Path::new("/nonexistent-bundle"),
            |_bundle, ctx, events| {
                routed_tenant = Some(ctx.tenant.clone());
                routed_event_type = events.first().map(|e| e.event_type.clone());
                Ok(events.len())
            },
        );

        assert_eq!(
            routed_event_type.as_deref(),
            Some("sorla.pack.order.created")
        );
        assert_eq!(routed_tenant.as_deref(), Some("t1"));
    }

    #[test]
    fn handle_message_drops_malformed_body_without_calling_route() {
        let mut route_called = false;
        handle_message(
            "greentic.events.t1.sorla.pack.order.created",
            b"{ not json",
            Path::new("/nonexistent-bundle"),
            |_bundle, _ctx, _events| {
                route_called = true;
                Ok(0)
            },
        );

        assert!(!route_called, "malformed body must not call route");
    }

    #[test]
    fn handle_message_warns_but_does_not_panic_on_route_error() {
        let env = sample_envelope();
        let body = serde_json::to_vec(&env).expect("serialize envelope");

        // Must not panic even though the injected route fn returns an error.
        handle_message(
            "greentic.events.t1.sorla.pack.order.created",
            &body,
            Path::new("/nonexistent-bundle"),
            |_bundle, _ctx, _events| anyhow::bail!("simulated routing failure"),
        );
    }

    #[test]
    fn convert_derives_domain_from_topic_first_segment() {
        // FIX M1: `source.domain` must come from the routed topic's first
        // segment, not a hard-coded "sorla" — a non-SoRX producer
        // publishing on `greentic.events.>` would otherwise be mislabeled.
        let mut env = sample_envelope();
        env.topic = "billing.invoice.paid".to_string();
        let body = serde_json::to_vec(&env).expect("serialize envelope");

        let (_, ev) = convert("greentic.events.t1.billing.invoice.paid", &body)
            .expect("convert should succeed");
        assert_eq!(ev.event_type, "billing.invoice.paid");
        assert_eq!(ev.source.domain, "billing");
    }

    #[test]
    fn convert_falls_back_to_events_domain_when_topic_has_no_first_segment() {
        // A topic with an empty first segment (e.g. a leading dot) has no
        // usable domain — fall back to "events" rather than an empty string.
        let mut env = sample_envelope();
        env.topic = ".weird.topic".to_string();
        let body = serde_json::to_vec(&env).expect("serialize envelope");

        // Subject is deliberately unparseable so `convert` falls back to the
        // envelope's own (malformed) `topic` for `event_type`.
        let (_, ev) = convert("not.a.greentic.subject", &body).expect("convert should succeed");
        assert_eq!(ev.event_type, ".weird.topic");
        assert_eq!(ev.source.domain, "events");
    }

    #[test]
    fn start_and_stop_do_not_panic_in_a_synchronous_no_runtime_context() {
        // Regression test for FIX C1. The real `gtc start` boot path
        // (`run_start_request -> run_start -> demo_up_services`) is fully
        // synchronous — there is no ambient Tokio runtime. Before FIX C1,
        // `BusinessEventListener::start` called `tokio::spawn` directly,
        // which panics immediately ("there is no reactor running") when
        // there's no ambient runtime, crashing boot whenever
        // `GREENTIC_EVENTS_NATS_URL` was set. This is a plain `#[test]`
        // (deliberately NOT `#[tokio::test]`) so it reproduces that exact
        // no-ambient-runtime context; `catch_unwind` turns "did calling
        // start()/stop() panic" into a concrete assertion instead of just
        // "did the test process crash".
        let result = std::panic::catch_unwind(|| {
            let listener = BusinessEventListener::start(BusinessEventListenerConfig {
                // Deliberately unreachable: nothing listens here, so the
                // background thread's own `async_nats::connect` fails fast
                // and the thread warns + exits cleanly instead of blocking.
                nats_url: "nats://127.0.0.1:59999".to_string(),
                bundle_root: PathBuf::from("/nonexistent-bundle"),
                queue_group: DEFAULT_BUSINESS_EVENTS_QUEUE_GROUP.to_string(),
            });
            listener.stop();
        });

        assert!(
            result.is_ok(),
            "start()/stop() must not panic when called from a synchronous, \
             no-ambient-runtime context — this is exactly gtc start's real boot path"
        );
    }
}
