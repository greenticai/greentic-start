//! NATS subscriber + parse/convert for the SoRX business-event bus.
//!
//! Subscribes to `greentic.events.>`, converts each raw NATS message
//! (`subject`, `body`) into an `(OperatorContext, EventEnvelopeV1)` pair, and
//! routes it to flows via `crate::event_router::route_events`. Mirrors
//! `crate::threshold_watcher`'s shape: a background task (here, over NATS
//! rather than a poll interval) that is off by default and never panics or
//! blocks the server on a decode/route failure. See `crate::runtime` (the
//! `business_event_listener` wiring block) for the discover -> start ->
//! store -> stop pattern this module's caller follows — gated on
//! `GREENTIC_EVENTS_NATS_URL`, mirroring `greentic-runner`'s
//! `NatsDispatcher` gate.
//!
//! [`handle_message`] is generic over the `route` call purely for
//! testability: production code (the loop below, and `crate::runtime`)
//! always passes `event_router::route_events`; tests substitute a stand-in
//! to drive the message -> route path deterministically, without a running
//! NATS server or flow.

use std::path::{Path, PathBuf};

use futures_util::StreamExt;

use crate::ingress_types::{EventEnvelopeV1, EventScopeV1, EventSourceV1};
use crate::operator_log;
use crate::runner_host::OperatorContext;

/// NATS subject wildcard business events are published on
/// (`greentic.events.<tenant>.<topic...>`; see [`topic_from_subject`]).
const BUSINESS_EVENTS_SUBJECT: &str = "greentic.events.>";

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

    // Mirrors `threshold_watcher::watcher::build_crossing_event`'s
    // `EventEnvelopeV1` construction: `event_type` carries routing (there is
    // no dedicated `topic` field), and `source.provider` is the closest
    // analogue to a producer id.
    let event = EventEnvelopeV1 {
        event_id: envelope.id.to_string(),
        event_type,
        occurred_at: envelope.time.to_rfc3339(),
        source: EventSourceV1 {
            domain: "sorla".to_string(),
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

/// Configuration for one running [`BusinessEventListener`]: an already
/// connected NATS client and the bundle root `route_events` dispatches
/// against.
pub struct BusinessEventListenerConfig {
    pub client: async_nats::Client,
    pub bundle_root: PathBuf,
}

/// Handle to the background subscribe-loop task. `start`/`stop` mirror
/// `crate::threshold_watcher::ThresholdWatcher`.
pub struct BusinessEventListener {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl BusinessEventListener {
    /// Spawn the background subscribe-loop task on the current Tokio
    /// runtime. Never fails: a subscribe error surfaces as a warning inside
    /// the task rather than here (mirrors the best-effort philosophy of
    /// `crate::threshold_watcher::ThresholdWatcher::start`).
    pub fn start(config: BusinessEventListenerConfig) -> Self {
        let handle = tokio::spawn(run_listener_loop(config));
        Self {
            handle: Some(handle),
        }
    }

    /// Signal the loop to stop by aborting the background task. There is no
    /// graceful in-flight-message drain: `subscriber.next()` is the only
    /// await point, and dropping the client on abort simply ends the
    /// subscription mirrors `ThresholdWatcher::stop`'s intent (stop
    /// promptly, never block shutdown).
    pub fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Subscribe to `greentic.events.>` and route every message via
/// [`handle_message`] until the subscription ends (NATS disconnect) or the
/// task is aborted by [`BusinessEventListener::stop`].
///
/// Best-effort: a subscribe failure warns and returns without ever
/// panicking the task (and, since this always runs on a spawned task, never
/// affects the rest of the server).
async fn run_listener_loop(config: BusinessEventListenerConfig) {
    let mut subscriber = match config.client.subscribe(BUSINESS_EVENTS_SUBJECT).await {
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
        format!("business event listener subscribed subject={BUSINESS_EVENTS_SUBJECT}"),
    );

    while let Some(message) = subscriber.next().await {
        handle_message(
            message.subject.as_str(),
            &message.payload,
            &config.bundle_root,
            crate::event_router::route_events,
        );
    }

    operator_log::warn(
        module_path!(),
        "business event listener subscription ended (NATS connection closed)",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_types::{EnvId, EventEnvelope, EventId, TeamId, TenantCtx, TenantId};

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
}
