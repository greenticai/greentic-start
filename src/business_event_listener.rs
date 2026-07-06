//! Pure parse + convert for the SoRX business-event bus.
//!
//! Converts a raw NATS message (`subject`, `body`) delivered on
//! `greentic.events.>` into an `(OperatorContext, EventEnvelopeV1)` pair
//! that `crate::event_router::route_events` can dispatch to flows. This
//! module is intentionally free of any NATS/network code — Task 2 wires the
//! actual subscribe loop around these functions.
//!
//! `#![allow(dead_code)]`: Task 2 is the caller of `topic_from_subject`/
//! `tenant_from_subject`/`convert`; until it lands, nothing in the crate
//! invokes these `pub` items, which `-D warnings` would otherwise flag as
//! dead code. Mirrors the same forward-declared-code pattern used in
//! `runner_host/types.rs`.
#![allow(dead_code)]

use crate::ingress_types::{EventEnvelopeV1, EventScopeV1, EventSourceV1};
use crate::runner_host::OperatorContext;

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
    fn convert_returns_none_on_malformed_body() {
        assert!(convert("greentic.events.t1.sorla.pack.order.created", b"{ not json").is_none());
        assert!(convert("greentic.events.t1.sorla.pack.order.created", b"").is_none());
    }
}
