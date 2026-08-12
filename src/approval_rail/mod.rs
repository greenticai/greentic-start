//! The bridge between the NATS approval rail and a chat channel.
//!
//! greentic-designer publishes human-in-the-loop approval requests on
//! `greentic.approval.request.v1` and reads the human's answer off
//! `greentic.approval.response.v1`. `greentic-messaging-providers` renders the
//! affordance for a channel and parses that channel's click. Neither of them
//! can touch NATS — a provider component's only host imports are `http-client`
//! and `secrets-store` — so this module is the middle: subscribe, deliver, hold
//! the state a stateless component cannot, publish the answer back.
//!
//! Contract: `greentic-designer/docs/approval-rail-contract-v2.md`. Read §4
//! (token rules), §5 (what the token does NOT do) and §6 (the operator
//! requirement) before changing anything here.
//!
//! ## Which tenant a request belongs to
//!
//! **It cannot be determined from the message, and this bridge does not try.**
//!
//! The request body carries no tenant, and `Greentic-Tenant` is explicitly not
//! usable for it (§1): it is the executor's checkpoint-partition tenant on the
//! first publish and the approval row's real tenant on a sweeper republish, so
//! the same gate arrives under two different values. Nothing else on the wire
//! identifies one.
//!
//! So the bridge stamps the tenant and team the **process** was started for —
//! `gtc start --tenant <t> --team <team>`, the same pair every other part of
//! this process scopes to (`state/runtime/<tenant>.<team>`). A `greentic-start`
//! instance serves one tenant, so this is exact rather than a guess.
//!
//! What it costs: a single instance cannot fan a shared subject out to several
//! tenants. That is not a limitation this repo can lift, and it is not one that
//! wants lifting here — §6 makes **per-tenant subject-level read authorization
//! mandatory**, which means a tenant's delivery integration gets its own NATS
//! credential and must not be able to read another tenant's requests. One
//! process, one tenant, one credential is the shape that requirement asks for.
//! A multi-tenant deployment runs one bridge per tenant.
//!
//! The contract gap worth feeding back: if a single shared subscriber ever
//! *should* serve several tenants, the request needs a routable tenant field,
//! because `Greentic-Tenant` cannot become one without breaking the republish
//! case it was documented around.
//!
//! ## Which channel a request is delivered to
//!
//! `routing.channels` is advisory and names a *channel kind*, not a
//! destination; `routing.approvers.emails` are emails, and §7 states plainly
//! that "the request carries no channel handles, only emails. An email ->
//! channel-handle mapping is greentic-designer-admin's to supply." So the rail
//! does not carry a destination and cannot be made to.
//!
//! This deployment's own outbound messaging has no answer either: every
//! `send_payload` in this crate is downstream of an inbound message and reuses
//! its `to` (`preserve_ingress_reply_route`). An approval request is
//! unsolicited — there is no inbound conversation to reply to. The one
//! remaining mechanism is the provider's own `default_channel` setup answer,
//! resolved inside the component.
//!
//! Falling through to `default_channel` is exactly what must NOT happen. That
//! is the deployment's general chat channel, and §4 is explicit that the button
//! state carrying the token "is readable by any member of the conversation" via
//! `conversations.history` — so delivery belongs in a DM or a private approver
//! channel. Inheriting a general channel would put a bearer credential in front
//! of everyone in it, silently.
//!
//! So the destination is **explicit and the bridge fails closed without one**:
//! `GREENTIC_APPROVAL_DESTINATION` names the conversation, and with it unset the
//! bridge does not start. That is the smallest mechanism that does not guess.

use std::sync::{Arc, Mutex, RwLock};

use greentic_types::ChannelMessageEnvelope;
use tokio::sync::mpsc;

use crate::operator_log;

pub mod body;
pub mod delivery;
pub mod ledger;
pub mod listener;
pub mod request;
pub mod response;

pub use listener::{ApprovalRailListener, ApprovalRailListenerConfig};

/// Subject the designer publishes approval requests on.
pub const REQUEST_SUBJECT: &str = "greentic.approval.request.v1";

/// Subject the human's answer is published on.
pub const RESPONSE_SUBJECT: &str = "greentic.approval.response.v1";

/// The header that identifies the gate, in both directions (contract §1).
pub const CORRELATION_ID_HEADER: &str = "Greentic-Correlation-Id";

/// NATS queue group every `greentic-start` instance subscribes under.
///
/// A queue group, not a fan-out subscribe, for the same reason
/// [`crate::business_event_listener`] uses one: a plain `subscribe` in a
/// multi-instance deployment would have every instance deliver the same
/// approval request, so one gate would arrive in the channel N times.
pub const REQUEST_QUEUE_GROUP: &str = "greentic-start-approval-bridge";

/// Environment variable naming the broker carrying the approval rail.
///
/// Deliberately separate from `GREENTIC_EVENTS_NATS_URL`. §6 requires
/// per-tenant subject-level read authorization on the approval subjects, which
/// in practice means a different NATS account or credential from the general
/// business-event bus; folding the two into one variable would make that
/// separation impossible to express.
pub const NATS_URL_ENV: &str = "GREENTIC_APPROVAL_NATS_URL";

/// Environment variable naming the conversation approval requests are delivered
/// to. See the module docs: there is no default, on purpose.
pub const DESTINATION_ENV: &str = "GREENTIC_APPROVAL_DESTINATION";

/// How many un-published answers may queue before one is dropped.
///
/// A dropped answer is not a lost decision: without a response the gate stays
/// PENDING (contract §3), which is what a gate is for, and the human can click
/// again. It is still logged at error level.
const RESPONSE_QUEUE_CAPACITY: usize = 256;

/// The process-wide bridge handle.
///
/// A process global rather than a field threaded through `ServeState` and
/// `HttpIngressState` because the inbound seams that need it are on two
/// unrelated ingress stacks (the revision server and the legacy one), one of
/// which is synchronous — and because, per the module docs, a process serves
/// exactly one tenant and therefore exactly one rail. Same shape as
/// `crate::post_ingress_hooks`'s offer-registry cache.
#[derive(Clone)]
struct ApprovalRailHandle {
    responses: mpsc::Sender<response::ResponsePublication>,
    ledger: Arc<Mutex<ledger::DeliveryLedger>>,
}

/// `RwLock<Option<_>>` rather than a `OnceLock`, because `gtc restart` tears
/// down `ForegroundRuntimeHandles` and calls `demo_up_services` again in the
/// SAME process. A write-once cell would refuse the second install and the
/// bridge would simply not come back after a restart — a silent loss of the
/// whole feature, with the ingress seams still calling a no-op.
static RAIL: RwLock<Option<ApprovalRailHandle>> = RwLock::new(None);

/// Intercept an inbound provider batch on its way to flow routing.
///
/// Call this with the raw request body and the envelopes a provider's
/// `ingest_http` emitted, BEFORE the envelopes are routed. Approval decisions
/// are removed from `envelopes` and published on the rail; everything else is
/// left exactly as it was.
///
/// A no-op when the bridge is not running, so both ingress paths can call it
/// unconditionally.
pub fn intercept_inbound(
    content_type: Option<&str>,
    body: &[u8],
    envelopes: &mut Vec<ChannelMessageEnvelope>,
) {
    let Some(rail) = current() else {
        return;
    };
    let rail = &rail;

    let (publications, rejections) = response::take_approval_responses(envelopes);
    for rejection in rejections {
        operator_log::warn(
            module_path!(),
            format!(
                "approval bridge refused an approval response from a provider: {}",
                rejection.as_str()
            ),
        );
    }
    if publications.is_empty() {
        return;
    }

    // Only now — this request IS an approval click — pay for parsing the raw
    // body to learn where the outstanding message lives.
    record_click_delivery(rail, content_type, body);

    for publication in publications {
        let correlation_id = publication.correlation_id.clone();
        if rail.responses.try_send(publication).is_err() {
            operator_log::error(
                module_path!(),
                format!(
                    "approval bridge dropped the answer for gate {correlation_id}: the publish \
                     queue is full or the listener has stopped. The gate stays pending; the \
                     approver can click again."
                ),
            );
        }
    }
}

fn record_click_delivery(rail: &ApprovalRailHandle, content_type: Option<&str>, body: &[u8]) {
    let Some(click) = response::slack_click_delivery(content_type, body) else {
        operator_log::warn(
            module_path!(),
            "approval bridge could not read the clicked message's id from this interaction; \
             a republish for this gate will post a new message instead of updating the \
             outstanding one",
        );
        return;
    };
    let Ok(mut ledger) = rail.ledger.lock() else {
        operator_log::error(
            module_path!(),
            "approval bridge delivery ledger is poisoned; republishes will post new messages",
        );
        return;
    };
    if let Some(evicted) = ledger.record(&click.correlation_id, click.delivery) {
        operator_log::warn(
            module_path!(),
            format!(
                "approval bridge evicted gate {evicted} from the delivery ledger (capacity \
                 reached); a republish for it will post a new message"
            ),
        );
    }
}

/// Snapshot the handle, if a bridge is running.
///
/// Cloned out from under the read lock so the (blocking, WASM-invoking) work
/// the caller then does never holds it.
fn current() -> Option<ApprovalRailHandle> {
    RAIL.read().ok()?.clone()
}

/// Install the process-wide handle, replacing any predecessor.
///
/// A replacement is expected on `gtc restart` — the previous listener has
/// already been stopped and joined by `ForegroundRuntimeHandles::stop` — but it
/// is logged, because a replacement that was NOT preceded by a stop means two
/// live bridges holding two disjoint delivery ledgers, and half the republishes
/// for a gate would post a new message instead of updating the outstanding one.
fn install(
    responses: mpsc::Sender<response::ResponsePublication>,
    ledger: Arc<Mutex<ledger::DeliveryLedger>>,
) -> bool {
    let Ok(mut slot) = RAIL.write() else {
        operator_log::error(
            module_path!(),
            "approval bridge handle is poisoned; refusing to install",
        );
        return false;
    };
    if slot.is_some() {
        operator_log::info(
            module_path!(),
            "approval bridge replacing the previously installed handle (expected on restart)",
        );
    }
    *slot = Some(ApprovalRailHandle { responses, ledger });
    true
}

/// Remove the process-wide handle, so the ingress seams stop publishing into a
/// queue nobody is draining.
fn uninstall() {
    match RAIL.write() {
        Ok(mut slot) => *slot = None,
        Err(_) => operator_log::error(
            module_path!(),
            "approval bridge handle is poisoned; could not uninstall",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_intercept_is_a_no_op_when_the_bridge_is_not_running() {
        // Every ingress path calls this unconditionally, including in
        // deployments that never configure the rail.
        let mut envelopes = Vec::new();
        intercept_inbound(Some("application/json"), b"{}", &mut envelopes);
        assert!(envelopes.is_empty());
    }
}
