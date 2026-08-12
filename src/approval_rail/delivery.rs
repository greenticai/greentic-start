//! Handing an approval request to a messaging provider.
//!
//! Two provider ops, in the order the existing egress path already uses:
//!
//! 1. `approval_request` renders the approve/reject affordance and returns a
//!    `ProviderPayloadV1` naming the API call to make (`chat.postMessage`, or
//!    `chat.update` when a `message_ts` is supplied).
//! 2. `send_payload` executes it. This is the same step 3 of the standard
//!    `render_plan -> encode -> send_payload` chain, so an approval message
//!    leaves through exactly the path every other outbound message does — the
//!    bot token is read inside the component and never reaches this process.
//!
//! The `decision_token` is inside the request body throughout and is never read
//! here; the body travels as a [`super::body::RailBody`] until the moment it is
//! serialized into the op input.

use std::sync::Arc;

use anyhow::{Context, anyhow};
use serde_json::{Value, json};

use crate::domains::Domain;
use crate::ingress_dispatch::build_injected_config;
use crate::messaging_dto::ProviderPayloadV1;
use crate::messaging_egress::build_send_payload;
use crate::runner_host::{DemoRunnerHost, OperatorContext};

use super::ledger::Delivery;
use super::request::RailRequest;

/// The op a messaging provider must expose to carry an approval request.
pub const APPROVAL_REQUEST_OP: &str = "approval_request";

/// Delivering one approval request to a human.
///
/// A trait so the listener can be driven in tests without a bundle, a WASM
/// runtime, or a Slack workspace — mirrors how
/// [`crate::business_event_listener::handle_message`] is generic over its
/// `route` call for the same reason.
pub trait ApprovalDelivery: Send + Sync {
    /// Deliver (or update) the request.
    ///
    /// `known` is where this gate's outstanding message already lives, when
    /// this process knows; supplying it turns the delivery into an update.
    ///
    /// Returns the delivery to record, when the provider reported one. See
    /// [`RunnerHostDelivery::deliver`] for why that is `None` today.
    fn deliver(
        &self,
        request: &RailRequest,
        known: Option<&Delivery>,
    ) -> anyhow::Result<Option<Delivery>>;
}

/// Pick which installed provider delivers this request.
///
/// `candidates` are the provider ids that expose [`APPROVAL_REQUEST_OP`];
/// `preferred` is the request's `routing.channels`, which the contract (§2)
/// calls **advisory** — "the designer neither enforces nor verifies it". So it
/// orders the candidates and never filters them: a request naming a channel
/// this deployment does not have is still delivered through whatever it does
/// have, which is what an advisory preference means. Filtering would silently
/// drop a gate on a naming mismatch between two repositories' vocabularies.
pub fn select_provider(candidates: &[String], preferred: &[String]) -> Option<String> {
    for channel in preferred {
        let needle = channel.to_ascii_lowercase();
        if let Some(found) = candidates
            .iter()
            .find(|candidate| candidate.to_ascii_lowercase().contains(&needle))
        {
            return Some(found.clone());
        }
    }
    candidates.first().cloned()
}

/// Build the `approval_request` op input.
///
/// Shape per `messaging-provider-slack`'s `docs/approval-rail.md`:
/// `{correlation_id, request, channel, message_ts?}`, plus the host-injected
/// provider `config` the component's `load_config` reads.
pub fn approval_request_input(
    request: &RailRequest,
    destination: &str,
    known: Option<&Delivery>,
    config: Option<Value>,
) -> Value {
    let mut input = json!({
        "correlation_id": request.correlation_id,
        "request": request.body.expose(),
        "channel": destination,
    });
    if let Some(known) = known
        && let Some(object) = input.as_object_mut()
    {
        object.insert("message_ts".into(), json!(known.message_ts));
    }
    if let Some(config) = config
        && let Some(object) = input.as_object_mut()
    {
        object.insert("config".into(), config);
    }
    input
}

/// Delivery through the bundle's own provider packs.
pub struct RunnerHostDelivery {
    runner_host: Arc<DemoRunnerHost>,
    ctx: OperatorContext,
    destination: String,
}

impl RunnerHostDelivery {
    pub fn new(
        runner_host: Arc<DemoRunnerHost>,
        tenant: String,
        team: Option<String>,
        destination: String,
    ) -> Self {
        Self {
            runner_host,
            ctx: OperatorContext {
                tenant,
                team,
                // Deliberately not the gate's correlation id: this field is the
                // *tracing* correlation of the provider invocation, and the
                // gate id is already carried in the op input where the
                // component needs it.
                correlation_id: None,
            },
            destination,
        }
    }

    fn candidates(&self) -> Vec<String> {
        self.runner_host
            .provider_ids(Domain::Messaging)
            .into_iter()
            .filter(|provider| {
                self.runner_host
                    .supports_op(Domain::Messaging, provider, APPROVAL_REQUEST_OP)
            })
            .collect()
    }
}

impl ApprovalDelivery for RunnerHostDelivery {
    /// Always returns `Ok(None)`: the ts is not recoverable from this path.
    ///
    /// `send_payload`'s result type is `SendPayloadResultV1 { ok, message,
    /// retryable }` (greentic-types) — the provider's message id is **not** on
    /// it, and a component cannot add a field to a typed DTO it does not own.
    /// So the outstanding message's `ts` is learned from the human's click
    /// instead ([`super::response::slack_click_delivery`]), which is enough for
    /// the case the contract calls out: a quorum republish is always *caused
    /// by* a vote, and a vote is a click. The gap and its fix are written up in
    /// `docs/approval-rail-bridge.md`.
    fn deliver(
        &self,
        request: &RailRequest,
        known: Option<&Delivery>,
    ) -> anyhow::Result<Option<Delivery>> {
        let candidates = self.candidates();
        let provider = select_provider(&candidates, &request.channels).ok_or_else(|| {
            anyhow!(
                "no installed messaging provider exposes the `{APPROVAL_REQUEST_OP}` op \
                 (bundle has {} messaging provider(s))",
                self.runner_host.provider_ids(Domain::Messaging).len()
            )
        })?;

        let config = build_injected_config(
            self.runner_host.as_ref(),
            Domain::Messaging,
            &provider,
            &self.ctx,
        )
        .context("resolve provider config for approval delivery")?
        .map(crate::http_ingress::decode_injected_config_for_provider);

        let input = approval_request_input(request, &self.destination, known, config.clone());
        let input_bytes = serde_json::to_vec(&input).context("encode approval_request input")?;
        let outcome = self
            .runner_host
            .invoke_provider_op(
                Domain::Messaging,
                &provider,
                APPROVAL_REQUEST_OP,
                &input_bytes,
                &self.ctx,
            )
            .with_context(|| format!("invoke {APPROVAL_REQUEST_OP} on provider {provider}"))?;

        let payload = approval_payload(&outcome.success, outcome.output.as_ref(), &provider)?;

        let provider_type = self
            .runner_host
            .canonical_provider_type(Domain::Messaging, &provider);
        let send_input = build_send_payload(
            payload,
            &provider_type,
            &self.ctx.tenant,
            self.ctx.team.clone(),
            config,
        );
        let send_bytes = serde_json::to_vec(&send_input).context("encode send_payload input")?;
        let send_outcome = self
            .runner_host
            .invoke_provider_op(
                Domain::Messaging,
                &provider,
                "send_payload",
                &send_bytes,
                &self.ctx,
            )
            .with_context(|| format!("invoke send_payload on provider {provider}"))?;

        let sent = send_outcome.success
            && send_outcome
                .output
                .as_ref()
                .and_then(|value| value.get("ok"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
        if !sent {
            // The provider's own message is reported. It describes a Slack API
            // failure ("channel_not_found", "not_in_channel") and carries no
            // request body, so it cannot contain the token.
            let detail = send_outcome
                .output
                .as_ref()
                .and_then(|value| value.get("message"))
                .and_then(Value::as_str)
                .or(send_outcome.error.as_deref())
                .unwrap_or("provider reported failure");
            return Err(anyhow!(
                "send_payload on provider {provider} failed: {detail}"
            ));
        }

        Ok(None)
    }
}

/// Pull the `ProviderPayloadV1` out of an `approval_request` result.
///
/// Kept separate from [`RunnerHostDelivery::deliver`] so the several failure
/// shapes a component can return are testable without a WASM runtime.
fn approval_payload(
    success: &bool,
    output: Option<&Value>,
    provider: &str,
) -> anyhow::Result<ProviderPayloadV1> {
    let output = output.ok_or_else(|| {
        anyhow!("provider {provider} returned no structured output for {APPROVAL_REQUEST_OP}")
    })?;
    if !*success || output.get("ok").and_then(Value::as_bool) != Some(true) {
        // `error` is the component's own message; the input it was given is
        // never echoed into it, so no token can ride out here.
        let detail = output
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("provider reported failure");
        return Err(anyhow!(
            "{APPROVAL_REQUEST_OP} on provider {provider} failed: {detail}"
        ));
    }
    let payload = output.get("payload").ok_or_else(|| {
        anyhow!("provider {provider} returned no payload for {APPROVAL_REQUEST_OP}")
    })?;
    serde_json::from_value(payload.clone())
        .with_context(|| format!("decode {APPROVAL_REQUEST_OP} payload from provider {provider}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval_rail::body::RailBody;

    fn request(channels: &[&str]) -> RailRequest {
        RailRequest {
            correlation_id: "default::run=RUN-1::node=gate".to_string(),
            channels: channels.iter().map(|c| c.to_string()).collect(),
            body: RailBody::new(json!({
                "target": "default::run=RUN-1::node=gate",
                "operation": "request",
                "input": {"title": "Refund 1200 USD"},
                "routing": {"decision_token": "s3cr3t-token-value"},
            })),
        }
    }

    fn ids(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn the_advisory_channel_preference_orders_candidates() {
        let candidates = ids(&["messaging-teams", "messaging-slack"]);
        assert_eq!(
            select_provider(&candidates, &ids(&["slack"])).as_deref(),
            Some("messaging-slack")
        );
        assert_eq!(
            select_provider(&candidates, &ids(&["teams", "slack"])).as_deref(),
            Some("messaging-teams")
        );
    }

    #[test]
    fn an_unmatched_preference_still_delivers() {
        // §2: `channels` is advisory — "the designer neither enforces nor
        // verifies it". Filtering on it would silently drop a gate whenever the
        // designer's channel vocabulary and this bundle's pack ids disagree.
        let candidates = ids(&["messaging-slack"]);
        assert_eq!(
            select_provider(&candidates, &ids(&["telegram"])).as_deref(),
            Some("messaging-slack")
        );
        assert_eq!(
            select_provider(&candidates, &[]).as_deref(),
            Some("messaging-slack")
        );
        assert_eq!(select_provider(&[], &ids(&["slack"])), None);
    }

    #[test]
    fn the_first_delivery_posts_and_a_known_gate_updates() {
        let first = approval_request_input(&request(&["slack"]), "C123", None, None);
        assert_eq!(first["correlation_id"], "default::run=RUN-1::node=gate");
        assert_eq!(first["channel"], "C123");
        assert!(
            first.get("message_ts").is_none(),
            "a first delivery must not carry a ts — the component switches to \
             chat.update on its presence"
        );

        let known = Delivery {
            channel: "C123".to_string(),
            message_ts: "1700000000.000100".to_string(),
        };
        let repeat = approval_request_input(&request(&["slack"]), "C123", Some(&known), None);
        assert_eq!(repeat["message_ts"], "1700000000.000100");
    }

    #[test]
    fn the_request_body_reaches_the_component_verbatim() {
        let input = approval_request_input(&request(&["slack"]), "C123", None, None);
        // Including the token: this crate carries it, it does not read it.
        assert_eq!(
            input["request"]["routing"]["decision_token"],
            "s3cr3t-token-value"
        );
        assert_eq!(input["request"]["input"]["title"], "Refund 1200 USD");
    }

    #[test]
    fn host_injected_config_rides_where_the_component_looks_for_it() {
        // `load_config` reads `input["config"]` first; without it the Slack op
        // cannot resolve `api_base_url` and falls back to defaults.
        let input = approval_request_input(
            &request(&["slack"]),
            "C123",
            None,
            Some(json!({"default_channel": "C999", "enabled": true})),
        );
        assert_eq!(input["config"]["default_channel"], "C999");
    }

    #[test]
    fn a_failed_or_shapeless_approval_request_result_is_an_error_not_a_silent_skip() {
        assert!(approval_payload(&true, None, "messaging-slack").is_err());
        assert!(approval_payload(&false, Some(&json!({"ok": true})), "messaging-slack").is_err());

        let err = approval_payload(
            &true,
            Some(&json!({"ok": false, "error": "destination (to) required"})),
            "messaging-slack",
        )
        .expect_err("a component failure must surface");
        assert!(err.to_string().contains("destination (to) required"));

        assert!(approval_payload(&true, Some(&json!({"ok": true})), "messaging-slack").is_err());
    }

    #[test]
    fn a_well_formed_result_yields_the_payload_to_send() {
        let payload = approval_payload(
            &true,
            Some(&json!({
                "ok": true,
                "update": false,
                "correlation_id": "default::run=RUN-1::node=gate",
                "payload": {
                    "content_type": "application/json",
                    "body_b64": "e30=",
                    "metadata": {"url": "https://slack.example/api/chat.postMessage", "method": "POST"},
                },
            })),
            "messaging-slack",
        )
        .expect("payload");
        assert_eq!(payload.content_type, "application/json");
        assert_eq!(
            payload.metadata.as_ref().and_then(|m| m.get("method")),
            Some(&json!("POST"))
        );
    }
}
