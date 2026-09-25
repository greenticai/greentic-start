//! Installing the runner's per-unit run-outcome sink (the deployed run audit,
//! greentic-designer `docs/superpowers/specs/2026-09-25-deployed-run-audit-design.md`
//! §3.2) from the SAME staged `metering` block the worker-usage meter is built
//! from.
//!
//! greentic-runner#801 reports one outcome per flow turn — completed, in
//! progress, technical error, agentic — through a
//! [`greentic_runner_host::run_outcome::RunOutcomeSink`] the embedding host
//! installs on `RevisionHostOptions`. This module builds the HTTP one for a
//! revision.
//!
//! # Rules
//!
//! - **No new secret, no new env var.** The token and tenant slug are the ones
//!   [`super::resolve_metering`] already validated, and the endpoint is the
//!   metering endpoint with its LAST path segment swapped:
//!   `…/api/v1/ingest/worker-usage` → `…/api/v1/ingest/run-outcome`. The two
//!   doors are siblings on the admin, and the admin's worker-usage token is the
//!   credential both accept.
//! - **The endpoint is derived, never guessed.** A metering endpoint whose path
//!   does not END in `worker-usage` is refused rather than having a segment
//!   appended or replaced blindly: a unit staged against some other door would
//!   otherwise post its outcomes to a URL nobody chose.
//! - **A sink that cannot be built never fails the boot**, and never costs the
//!   unit its worker-usage meter: the two are decided independently, and a
//!   refusal here is one `warn` in [`super::runtime_meter::host_options_for_unit`].
//! - **No block, no sink.** A unit that stages no `metering` block installs
//!   nothing, which is exactly the behaviour before this existed.

use greentic_deploy_spec::ids::{DeploymentId, RevisionId};
use greentic_runner_host::run_outcome::{
    HttpRunOutcomeSink, RunOutcomeSinkError, RunOutcomeTarget,
};

use super::MeteringConfig;

/// The last path segment of the admin's worker-usage ingest door.
const WORKER_USAGE_SEGMENT: &str = "worker-usage";
/// The last path segment of its run-outcome sibling.
const RUN_OUTCOME_SEGMENT: &str = "run-outcome";

/// Why a unit's `metering` block did not yield a run-outcome sink.
///
/// Every variant means the same thing to a caller — the unit runs without
/// reporting run outcomes — and none of them names the token.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RunOutcomeRefusal {
    #[error("the metering endpoint `{0}` is not a URL")]
    Unparseable(String),
    #[error(
        "the metering endpoint `{0}` does not end in `/{WORKER_USAGE_SEGMENT}`, so the \
         run-outcome door beside it cannot be derived"
    )]
    NotWorkerUsage(String),
    #[error(transparent)]
    Sink(#[from] RunOutcomeSinkError),
}

/// The run-outcome ingest URL beside a worker-usage one.
///
/// Only the path's last segment changes; scheme, host, port, the rest of the
/// path and any query are kept. A single trailing slash is tolerated.
pub(crate) fn run_outcome_endpoint(worker_usage: &str) -> Result<String, RunOutcomeRefusal> {
    let mut url = reqwest::Url::parse(worker_usage)
        .map_err(|_| RunOutcomeRefusal::Unparseable(worker_usage.to_string()))?;
    let last = url
        .path_segments()
        .and_then(|mut segments| segments.rfind(|segment| !segment.is_empty()))
        .map(str::to_string);
    if last.as_deref() != Some(WORKER_USAGE_SEGMENT) {
        return Err(RunOutcomeRefusal::NotWorkerUsage(worker_usage.to_string()));
    }
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| RunOutcomeRefusal::NotWorkerUsage(worker_usage.to_string()))?;
        segments.pop_if_empty().pop().push(RUN_OUTCOME_SEGMENT);
    }
    Ok(url.to_string())
}

/// Where and as whom one revision's run outcomes are recorded, or `None` when
/// the unit stages no `metering` block.
pub(crate) fn run_outcome_target(
    metering: Option<&MeteringConfig>,
    deployment_id: DeploymentId,
    bundle_id: &str,
    revision_id: RevisionId,
) -> Result<Option<RunOutcomeTarget>, RunOutcomeRefusal> {
    let Some(metering) = metering else {
        return Ok(None);
    };
    Ok(Some(RunOutcomeTarget {
        endpoint: run_outcome_endpoint(&metering.endpoint)?,
        token: metering.token.expose().to_string(),
        // The VALIDATED slug, the same one the worker-usage meter sends: the
        // admin compares it to the token's tenant.
        tenant_slug: metering.tenant_slug.clone(),
        deployment_id: deployment_id.to_string(),
        bundle_id: bundle_id.to_string(),
        revision_id: revision_id.to_string(),
    }))
}

/// [`run_outcome_target`], built into the runner's HTTP sink.
///
/// Pure apart from constructing the sink's HTTP client: every refusal is a
/// value, so a test can assert WHICH one happened.
pub(crate) fn run_outcome_sink(
    metering: Option<&MeteringConfig>,
    deployment_id: DeploymentId,
    bundle_id: &str,
    revision_id: RevisionId,
) -> Result<Option<HttpRunOutcomeSink>, RunOutcomeRefusal> {
    match run_outcome_target(metering, deployment_id, bundle_id, revision_id)? {
        Some(target) => Ok(Some(HttpRunOutcomeSink::new(target)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
#[path = "run_outcome_tests.rs"]
mod run_outcome_tests;
