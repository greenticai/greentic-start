//! Installing the runner's per-end-user ledger (greentic-runner#832) from the
//! SAME staged `metering` block the worker-usage meter, the run-outcome sink
//! and the HTTP approval inbox are built from.
//!
//! The runner reads a verified end user's ledger before a turn and appends to
//! it after, through the admin's `…/api/v1/ingest/ledger/{read,append}` door.
//! The embedding host hands it a
//! [`greentic_aw_runtime::user_ledger::UserLedgerTarget`] on
//! `RevisionHostOptions`; this module builds that target for a unit.
//!
//! # Rules
//!
//! - **No new secret, no new env var.** The token and tenant slug are the ones
//!   [`super::resolve_metering`] already validated. The base URL is the
//!   metering endpoint with its LAST path segment swapped for `ledger`
//!   ([`super::run_outcome::sibling_door`]); the runner appends `/read` and
//!   `/append` itself. Whether the token may use the door (its `ledger`
//!   purpose) is the admin's to enforce, not this host's.
//! - **This host does not read the pack.** Which agents use the ledger, and in
//!   which mode, is decided by the runner from the pack's
//!   `assets/user-ledger.json`. A pack without one never calls the door, so
//!   installing the target for every metered unit is inert for those.
//! - **The target is validated here**, with
//!   [`HttpUserLedger::new`], so a refusal lands in the operator log naming
//!   the unit rather than only being skipped upstream.
//! - **A refusal never fails the boot** and never costs the unit its other
//!   options: [`super::runtime_meter::host_options_for_unit`] decides each
//!   part on its own.

use greentic_aw_runtime::user_ledger::{HttpUserLedger, UserLedgerTarget, UserLedgerTargetError};

use super::MeteringConfig;
use super::run_outcome::{SiblingDoorError, WORKER_USAGE_SEGMENT, sibling_door};

/// The last path segment of the admin's user-ledger door.
const LEDGER_SEGMENT: &str = "ledger";

/// Why a unit's `metering` block did not yield a user-ledger target.
///
/// Every variant means the unit runs without the ledger; none names the token.
#[derive(Debug, thiserror::Error)]
pub(crate) enum UserLedgerRefusal {
    #[error("the metering endpoint `{0}` is not a URL")]
    Unparseable(String),
    #[error(
        "the metering endpoint `{0}` does not end in `/{WORKER_USAGE_SEGMENT}`, so the \
         user-ledger door beside it cannot be derived"
    )]
    NotWorkerUsage(String),
    #[error(transparent)]
    Target(#[from] UserLedgerTargetError),
}

/// The user-ledger door one unit reads and writes, or `None` when the unit
/// stages no `metering` block. Validated with [`HttpUserLedger::new`], so a
/// target returned here is one the runner will install.
pub(crate) fn user_ledger_target(
    metering: Option<&MeteringConfig>,
) -> Result<Option<UserLedgerTarget>, UserLedgerRefusal> {
    let Some(metering) = metering else {
        return Ok(None);
    };
    let base_url = sibling_door(&metering.endpoint, LEDGER_SEGMENT).map_err(|err| match err {
        SiblingDoorError::Unparseable => UserLedgerRefusal::Unparseable(metering.endpoint.clone()),
        SiblingDoorError::NotWorkerUsage => {
            UserLedgerRefusal::NotWorkerUsage(metering.endpoint.clone())
        }
    })?;
    let target = UserLedgerTarget::new(
        base_url,
        metering.token.expose().to_string(),
        // The VALIDATED slug: the door refuses one that is not the token's.
        metering.tenant_slug.clone(),
    );
    // Validation only; the runner builds its own client from the target.
    HttpUserLedger::new(target.clone())?;
    Ok(Some(target))
}

#[cfg(test)]
#[path = "user_ledger_tests.rs"]
mod user_ledger_tests;
