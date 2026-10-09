//! Installing the runner's per-unit HTTP approval inbox (greentic-designer
//! `docs/superpowers/specs/2026-09-29-approval-rail-http-design.md` §5) from
//! the SAME staged `metering` block the worker-usage meter and the run-outcome
//! sink are built from.
//!
//! greentic-runner#816 lets an `approval.call` node that needs a human reach
//! the admin's approval inbox over plain HTTP — POST the request, poll the
//! decision, withdraw on timeout — instead of requiring a NATS bus no cloud
//! lane has. The embedding host hands it an
//! [`greentic_runner_host::runner::approval_http::ApprovalInboxTarget`] on
//! `RevisionHostOptions`; this module builds that target for a unit.
//!
//! # Rules
//!
//! - **No new secret, no new env var.** The token and tenant slug are the ones
//!   [`super::resolve_metering`] already validated. The three URLs are the
//!   metering endpoint with its LAST path segment swapped, exactly as the
//!   run-outcome door is derived ([`super::run_outcome::sibling_door`]):
//!   `…/api/v1/ingest/worker-usage` → `…/approval-request`,
//!   `…/approval-decision`, `…/approval-withdraw`. The admin accepts the same
//!   `gtm_` bearer on all of them, provided it carries the `approvals` purpose;
//!   that is the admin's to enforce, not this host's.
//! - **The endpoints are derived, never guessed.** A metering endpoint whose
//!   path does not END in `worker-usage` is refused.
//! - **The target is validated here, not only upstream.** The runner logs and
//!   skips a target that fails [`HttpApprovalDispatcher::new`]; validating it
//!   first lets this host say so in the operator log it owns, naming the unit.
//! - **A refusal never fails the boot**, and never costs the unit its meter or
//!   its run-outcome sink: each half of
//!   [`super::runtime_meter::host_options_for_unit`] is decided on its own. An
//!   approval that needs a human then fails at the node, as it did before.
//! - **No block, no inbox.** A unit that stages no `metering` block installs
//!   nothing — never an error. If `GREENTIC_EVENTS_NATS_URL` connects, the
//!   runner prefers its NATS rail and ignores the inbox.

use greentic_runner_host::runner::approval_http::{
    ApprovalInboxError, ApprovalInboxTarget, HttpApprovalDispatcher,
};

use super::MeteringConfig;
use super::run_outcome::{SiblingDoorError, WORKER_USAGE_SEGMENT, sibling_door};

/// The last path segment of the admin's approval-request door.
const REQUEST_SEGMENT: &str = "approval-request";
/// The last path segment of the admin's approval-decision door.
const DECISION_SEGMENT: &str = "approval-decision";
/// The last path segment of the admin's approval-withdraw door.
const WITHDRAW_SEGMENT: &str = "approval-withdraw";

/// Why a unit's `metering` block did not yield an approval inbox.
///
/// Every variant means the same thing to a caller — the unit runs without an
/// HTTP approval inbox — and none of them names the token.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ApprovalInboxRefusal {
    #[error("the metering endpoint `{0}` is not a URL")]
    Unparseable(String),
    #[error(
        "the metering endpoint `{0}` does not end in `/{WORKER_USAGE_SEGMENT}`, so the \
         approval doors beside it cannot be derived"
    )]
    NotWorkerUsage(String),
    #[error(transparent)]
    Inbox(#[from] ApprovalInboxError),
}

/// One approval door beside the worker-usage door.
fn door(worker_usage: &str, segment: &str) -> Result<String, ApprovalInboxRefusal> {
    sibling_door(worker_usage, segment).map_err(|err| match err {
        SiblingDoorError::Unparseable => ApprovalInboxRefusal::Unparseable(worker_usage.into()),
        SiblingDoorError::NotWorkerUsage => {
            ApprovalInboxRefusal::NotWorkerUsage(worker_usage.into())
        }
    })
}

/// The approval inbox one unit reports to, or `None` when the unit stages no
/// `metering` block. Validated with [`HttpApprovalDispatcher::new`], so a
/// target returned here is one the runner will install.
pub(crate) fn approval_inbox_target(
    metering: Option<&MeteringConfig>,
) -> Result<Option<ApprovalInboxTarget>, ApprovalInboxRefusal> {
    let Some(metering) = metering else {
        return Ok(None);
    };
    let target = ApprovalInboxTarget {
        request_url: door(&metering.endpoint, REQUEST_SEGMENT)?,
        decision_url: door(&metering.endpoint, DECISION_SEGMENT)?,
        withdraw_url: door(&metering.endpoint, WITHDRAW_SEGMENT)?,
        token: metering.token.expose().to_string(),
        // The VALIDATED slug, the same one the meter and the run-outcome sink
        // send: the admin compares it to the token's tenant.
        tenant_slug: metering.tenant_slug.clone(),
    };
    // Validation only; the runner builds its own dispatcher from the target.
    HttpApprovalDispatcher::new(target.clone())?;
    Ok(Some(target))
}

#[cfg(test)]
#[path = "approval_inbox_tests.rs"]
mod approval_inbox_tests;
