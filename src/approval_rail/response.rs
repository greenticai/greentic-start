//! Turning a human's click back into a `greentic.approval.response.v1` publish.
//!
//! The provider component does the channel-specific half: `messaging-provider-slack`'s
//! `ingest_http` recognises a `block_actions` payload whose `action_id` is
//! `greentic_approval_approve` / `_deny`, builds the response body, and hands it
//! out on the emitted envelope's `extensions["greentic.approval.response"]` as
//! `{subject, headers, body}`. This module is the other half: lift those off the
//! inbound envelopes so the listener can publish them.
//!
//! Two things are done here rather than in the component, because a component
//! cannot do them:
//!
//! * **The approval envelope is REMOVED from the inbound batch.** Its `text` is
//!   `[approval:approved]` — a marker, not something a human said. Left in
//!   place it would be routed to a flow (and, with fast2flow enabled, to an
//!   LLM router) as if the approver had typed it.
//! * **The `message_ts` of the message that was clicked is recorded**, which is
//!   what lets the next republish for that gate update the outstanding message
//!   instead of posting a second one. See [`super::ledger`].

use greentic_types::ChannelMessageEnvelope;
use serde_json::Value;

use super::body::RailBody;
use super::ledger::Delivery;
use super::{CORRELATION_ID_HEADER, RESPONSE_SUBJECT};

/// Envelope extension key the delivery component publishes its answer on.
/// Mirrors `messaging-provider-slack`'s `RESPONSE_EXTENSION_KEY`.
pub const RESPONSE_EXTENSION_KEY: &str = "greentic.approval.response";

/// Slack stamps this on the delivered message so a click can be tied back to
/// its gate without a server-side map. Mirrors the component's
/// `METADATA_EVENT_TYPE`.
const SLACK_METADATA_EVENT_TYPE: &str = "greentic_approval";

/// One answer, ready for the rail.
#[derive(Clone, Debug)]
pub struct ResponsePublication {
    /// Echoed back in the response's `Greentic-Correlation-Id` header — the
    /// designer routes on that header alone (contract §1).
    pub correlation_id: String,
    /// The response body verbatim, `decision_token` included and unread.
    pub body: RailBody,
}

/// Why an extension that looked like an approval response was not published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseRejection {
    /// The extension was not the `{subject, headers, body}` shape.
    Malformed,
    /// No correlation id anywhere, so the designer could not route it.
    NoCorrelationId,
    /// The extension named a subject other than the response subject. A
    /// component naming its own publish target is a privilege it does not
    /// have here.
    ForeignSubject,
}

impl ResponseRejection {
    pub fn as_str(self) -> &'static str {
        match self {
            ResponseRejection::Malformed => "malformed",
            ResponseRejection::NoCorrelationId => "no_correlation_id",
            ResponseRejection::ForeignSubject => "foreign_subject",
        }
    }
}

/// Remove every approval-response envelope from `envelopes`, returning what
/// should be published and what was refused.
///
/// An envelope carrying the extension is removed whether or not its payload
/// survives validation: it is a decision marker either way, and routing a
/// refused one to a flow is strictly worse than dropping it.
pub fn take_approval_responses(
    envelopes: &mut Vec<ChannelMessageEnvelope>,
) -> (Vec<ResponsePublication>, Vec<ResponseRejection>) {
    let mut published = Vec::new();
    let mut rejected = Vec::new();

    let mut remaining = Vec::with_capacity(envelopes.len());
    for envelope in std::mem::take(envelopes) {
        let Some(extension) = envelope.extensions.get(RESPONSE_EXTENSION_KEY) else {
            remaining.push(envelope);
            continue;
        };
        match publication_from(extension, &envelope) {
            Ok(publication) => published.push(publication),
            Err(reason) => rejected.push(reason),
        }
    }
    *envelopes = remaining;

    (published, rejected)
}

fn publication_from(
    extension: &Value,
    envelope: &ChannelMessageEnvelope,
) -> Result<ResponsePublication, ResponseRejection> {
    let object = extension.as_object().ok_or(ResponseRejection::Malformed)?;
    let body = object.get("body").ok_or(ResponseRejection::Malformed)?;
    if !body.is_object() {
        return Err(ResponseRejection::Malformed);
    }

    // The subject is validated, not trusted. A provider component is a third
    // party's WASM running in this process; letting it name the subject a host
    // NATS credential publishes on would let it reach anything that credential
    // can write to. The rail has exactly one response subject.
    let subject = object
        .get("subject")
        .and_then(Value::as_str)
        .ok_or(ResponseRejection::Malformed)?;
    if subject != RESPONSE_SUBJECT {
        return Err(ResponseRejection::ForeignSubject);
    }

    let correlation_id = object
        .get("headers")
        .and_then(|headers| headers.get(CORRELATION_ID_HEADER))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            envelope
                .correlation_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .ok_or(ResponseRejection::NoCorrelationId)?;

    Ok(ResponsePublication {
        correlation_id,
        body: RailBody::new(body.clone()),
    })
}

/// What a click told us about the message that was clicked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClickDelivery {
    pub correlation_id: String,
    pub delivery: Delivery,
}

/// Recover `(correlation_id, channel, message_ts)` from a raw Slack
/// interactivity body.
///
/// This reads the **message metadata Slack echoes back on a click**
/// (`message.metadata.event_payload.correlation_id`, stamped by the delivery
/// component for exactly this purpose) together with `container.message_ts`.
///
/// It deliberately never reads `actions[].value`. That field is where the
/// `decision_token` rides, and a host-side parser that touches it is a host-side
/// parser that can log it. The correlation id is available without it, so this
/// takes the route that cannot leak.
///
/// Host-side parsing of a Slack body is not new here:
/// [`crate::session_hint_extractor`] already demultiplexes the same four body
/// shapes off the same route, for the same reason — a routing fact the
/// component does not surface to the host. The cleaner long-term fix is for the
/// component to stamp the ts into the emitted envelope's metadata; see
/// `docs/approval-rail-bridge.md`.
pub fn slack_click_delivery(content_type: Option<&str>, body: &[u8]) -> Option<ClickDelivery> {
    let interactive = slack_interactive_payload(content_type, body)?;
    click_delivery_from_payload(&interactive)
}

fn slack_interactive_payload(content_type: Option<&str>, body: &[u8]) -> Option<Value> {
    let is_form = content_type
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
        .unwrap_or(false);

    if !is_form {
        return serde_json::from_slice(body).ok();
    }

    // Slack posts interactivity as `payload=<url-encoded json>`. `+`-as-space
    // is deliberately not decoded, matching `session_hint_extractor`: Slack
    // sends `%20`, and treating `+` as a space would corrupt base64-ish values
    // inside the payload.
    let text = std::str::from_utf8(body).ok()?;
    for pair in text.split('&') {
        let (key, value) = pair.split_once('=')?;
        if key != "payload" {
            continue;
        }
        let decoded = urlencoding::decode(value).ok()?;
        return serde_json::from_str(&decoded).ok();
    }
    None
}

fn click_delivery_from_payload(interactive: &Value) -> Option<ClickDelivery> {
    let metadata = interactive.get("message")?.get("metadata")?;
    if metadata.get("event_type").and_then(Value::as_str) != Some(SLACK_METADATA_EVENT_TYPE) {
        return None;
    }
    let correlation_id = metadata
        .get("event_payload")?
        .get("correlation_id")?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_string();

    // `container.message_ts` is the message the button lives on. `message.ts`
    // is the same value for a message action and is the fallback, not the
    // first choice: a click inside a thread reports the parent under
    // `message.ts` while `container.message_ts` stays the clicked message.
    let message_ts = interactive
        .get("container")
        .and_then(|container| container.get("message_ts"))
        .or_else(|| interactive.get("message").and_then(|m| m.get("ts")))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_string();

    let channel = interactive
        .get("channel")
        .and_then(|channel| channel.get("id"))
        .or_else(|| {
            interactive
                .get("container")
                .and_then(|container| container.get("channel_id"))
        })
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_string();

    Some(ClickDelivery {
        correlation_id,
        delivery: Delivery {
            channel,
            message_ts,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_types::{EnvId, TenantCtx, TenantId};
    use serde_json::json;

    const CONFORMANCE_RESPONSE: &str =
        include_str!("../../tests/fixtures/approval_rail/response_v2.json");

    fn envelope(extension: Option<Value>) -> ChannelMessageEnvelope {
        let env = EnvId::try_from("default").expect("env id");
        let tenant = TenantId::try_from("default").expect("tenant id");
        let mut envelope = ChannelMessageEnvelope {
            id: "slack-C123".to_string(),
            tenant: TenantCtx::new(env, tenant),
            channel: "C123".to_string(),
            session_id: "C123".to_string(),
            reply_scope: None,
            from: None,
            to: Vec::new(),
            correlation_id: None,
            text: Some("[approval:approved]".to_string()),
            attachments: Vec::new(),
            metadata: Default::default(),
            extensions: Default::default(),
        };
        if let Some(extension) = extension {
            envelope
                .extensions
                .insert(RESPONSE_EXTENSION_KEY.to_string(), extension);
        }
        envelope
    }

    fn conformance_extension() -> Value {
        let body: Value = serde_json::from_str(CONFORMANCE_RESPONSE).expect("fixture");
        json!({
            "subject": RESPONSE_SUBJECT,
            "headers": {CORRELATION_ID_HEADER: "default::run=RUN-1::node=gate"},
            "body": body["output"].clone(),
        })
    }

    #[test]
    fn a_click_is_lifted_off_the_envelope_and_the_envelope_is_removed() {
        let mut envelopes = vec![envelope(None), envelope(Some(conformance_extension()))];
        let (published, rejected) = take_approval_responses(&mut envelopes);

        assert!(rejected.is_empty(), "unexpected rejections: {rejected:?}");
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].correlation_id, "default::run=RUN-1::node=gate");
        assert_eq!(
            published[0].body.expose()["decision_token"],
            "EXAMPLE-TOKEN-NOT-A-REAL-SECRET"
        );
        assert_eq!(published[0].body.expose()["decision"], "approved");

        assert_eq!(
            envelopes.len(),
            1,
            "the approval envelope must not reach flow routing — its text is a \
             decision marker, not something a human typed"
        );
        assert!(!envelopes[0].extensions.contains_key(RESPONSE_EXTENSION_KEY));
    }

    #[test]
    fn an_unnamed_approver_is_published_as_null_never_as_an_empty_string() {
        // Slack hands a `block_actions` payload a workspace user *id*;
        // resolving it to the email the rail wants needs the app to hold
        // `users:read.email`. Without that scope the component sends
        // `resolved_by: null`, and a policy-governed gate correctly refuses the
        // vote as `no_claimed_identity` — quorum counts people (contract §3).
        //
        // This bridge must carry that null through untouched. Coercing it to
        // `""` would turn an honestly-refused vote into a vote naming a person
        // who does not exist, and `resolved_by` is already only a CLAIM (§5) —
        // manufacturing one here would be the worst possible thing to do with
        // a field nothing can verify.
        let mut extension = conformance_extension();
        extension["body"]["resolved_by"] = Value::Null;

        let (published, rejected) = take_approval_responses(&mut vec![envelope(Some(extension))]);
        assert!(rejected.is_empty());
        assert_eq!(
            published[0].body.expose()["resolved_by"],
            Value::Null,
            "an unnamed vote must stay unnamed"
        );
        assert!(
            published[0]
                .body
                .expose()
                .get("resolved_by")
                .is_some_and(Value::is_null),
            "the key must still be present and null, not dropped"
        );
    }

    #[test]
    fn ordinary_traffic_is_left_completely_alone() {
        let mut envelopes = vec![envelope(None), envelope(None)];
        let (published, rejected) = take_approval_responses(&mut envelopes);
        assert!(published.is_empty());
        assert!(rejected.is_empty());
        assert_eq!(envelopes.len(), 2);
    }

    #[test]
    fn a_component_may_not_name_its_own_publish_subject() {
        let mut extension = conformance_extension();
        extension["subject"] = json!("greentic.events.exfiltrate");
        let mut envelopes = vec![envelope(Some(extension))];

        let (published, rejected) = take_approval_responses(&mut envelopes);
        assert!(
            published.is_empty(),
            "a foreign subject must not be published"
        );
        assert_eq!(rejected, vec![ResponseRejection::ForeignSubject]);
        assert!(envelopes.is_empty(), "a refused decision is still not chat");
    }

    #[test]
    fn the_envelopes_own_correlation_id_is_the_fallback() {
        let mut extension = conformance_extension();
        extension["headers"] = json!({});
        let mut envelope = envelope(Some(extension));
        envelope.correlation_id = Some("default::run=RUN-9::node=gate".to_string());

        let (published, rejected) = take_approval_responses(&mut vec![envelope]);
        assert!(rejected.is_empty());
        assert_eq!(published[0].correlation_id, "default::run=RUN-9::node=gate");
    }

    #[test]
    fn a_response_that_names_no_gate_is_refused_rather_than_published() {
        let mut extension = conformance_extension();
        extension["headers"] = json!({});
        let (published, rejected) = take_approval_responses(&mut vec![envelope(Some(extension))]);
        assert!(published.is_empty());
        assert_eq!(rejected, vec![ResponseRejection::NoCorrelationId]);
    }

    #[test]
    fn a_malformed_extension_is_refused_rather_than_published() {
        for extension in [
            json!("not an object"),
            json!({"subject": RESPONSE_SUBJECT}),
            json!({"subject": RESPONSE_SUBJECT, "body": "not an object"}),
            json!({"body": {"decision": "approved"}}),
        ] {
            let (published, rejected) =
                take_approval_responses(&mut vec![envelope(Some(extension.clone()))]);
            assert!(published.is_empty(), "published {extension}");
            assert_eq!(
                rejected,
                vec![ResponseRejection::Malformed],
                "for {extension}"
            );
        }
    }

    fn click_payload() -> Value {
        json!({
            "type": "block_actions",
            "user": {"id": "U123"},
            "channel": {"id": "C123"},
            "container": {"type": "message", "message_ts": "1700000000.000100", "channel_id": "C123"},
            "message": {
                "ts": "1700000000.000100",
                "metadata": {
                    "event_type": "greentic_approval",
                    "event_payload": {"correlation_id": "default::run=RUN-1::node=gate"}
                }
            },
            "actions": [{
                "action_id": "greentic_approval_approve",
                "value": "{\"cid\":\"default::run=RUN-1::node=gate\",\"tok\":\"s3cr3t-token-value\"}"
            }]
        })
    }

    #[test]
    fn a_click_yields_the_outstanding_messages_ts_from_json_and_from_a_form_post() {
        let expected = ClickDelivery {
            correlation_id: "default::run=RUN-1::node=gate".to_string(),
            delivery: Delivery {
                channel: "C123".to_string(),
                message_ts: "1700000000.000100".to_string(),
            },
        };

        let raw = serde_json::to_vec(&click_payload()).expect("serialize");
        assert_eq!(
            slack_click_delivery(Some("application/json"), &raw),
            Some(expected.clone())
        );

        // The shape Slack interactivity actually posts.
        let form = format!(
            "payload={}",
            urlencoding::encode(&serde_json::to_string(&click_payload()).expect("serialize"))
        );
        assert_eq!(
            slack_click_delivery(
                Some("application/x-www-form-urlencoded; charset=utf-8"),
                form.as_bytes()
            ),
            Some(expected)
        );
    }

    #[test]
    fn the_click_reader_never_touches_the_button_value() {
        // The `decision_token` rides in `actions[].value`. A host-side parser
        // that reads it is a host-side parser that can log it, and the
        // correlation id is available from message metadata without it. Strip
        // the actions array entirely: extraction must be unaffected.
        let mut payload = click_payload();
        payload["actions"] = json!([]);
        let raw = serde_json::to_vec(&payload).expect("serialize");

        let recovered = slack_click_delivery(Some("application/json"), &raw)
            .expect("the ts must be recoverable without reading the button value");
        assert_eq!(recovered.correlation_id, "default::run=RUN-1::node=gate");
        assert_eq!(recovered.delivery.message_ts, "1700000000.000100");
    }

    #[test]
    fn a_non_approval_slack_body_yields_nothing() {
        for payload in [
            json!({"type": "block_actions", "channel": {"id": "C1"}}),
            json!({"message": {"metadata": {"event_type": "something_else"}}}),
            json!({"event": {"type": "message", "channel": "C1"}}),
        ] {
            let raw = serde_json::to_vec(&payload).expect("serialize");
            assert_eq!(slack_click_delivery(Some("application/json"), &raw), None);
        }
        assert_eq!(
            slack_click_delivery(Some("application/json"), b"{ nope"),
            None
        );
    }

    #[test]
    fn a_threaded_click_prefers_the_container_ts_over_the_parent() {
        let mut payload = click_payload();
        payload["message"]["ts"] = json!("1699999999.000000");
        let raw = serde_json::to_vec(&payload).expect("serialize");
        let recovered = slack_click_delivery(Some("application/json"), &raw).expect("hint");
        assert_eq!(recovered.delivery.message_ts, "1700000000.000100");
    }
}
