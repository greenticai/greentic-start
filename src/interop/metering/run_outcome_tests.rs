//! The run-outcome sink derived from the staged `metering` block (deployed
//! run audit §3.2).

use greentic_deploy_spec::ids::{DeploymentId, RevisionId};
use greentic_runner_host::run_outcome::RunOutcomeSinkError;

use super::super::{MeteringConfig, MeteringToken};
use super::*;

const ENDPOINT: &str = "https://admin.example/api/v1/ingest/worker-usage";
const TOKEN: &str = "gtm_staged-usage-token";
const TENANT: &str = "acme";
const BUNDLE: &str = "support-bot";

fn metering(endpoint: &str) -> MeteringConfig {
    MeteringConfig {
        endpoint: endpoint.into(),
        token: MeteringToken(TOKEN.into()),
        tenant_slug: TENANT.into(),
    }
}

#[test]
fn the_run_outcome_door_is_the_worker_usage_doors_sibling() {
    assert_eq!(
        run_outcome_endpoint(ENDPOINT).expect("derives"),
        "https://admin.example/api/v1/ingest/run-outcome"
    );
    // Port, a path prefix, a trailing slash and a query survive; only the
    // last segment moves.
    assert_eq!(
        run_outcome_endpoint("https://admin.example:8443/admin/api/v1/ingest/worker-usage/")
            .expect("derives"),
        "https://admin.example:8443/admin/api/v1/ingest/run-outcome"
    );
    assert_eq!(
        run_outcome_endpoint("http://127.0.0.1:9000/api/v1/ingest/worker-usage?x=1")
            .expect("derives"),
        "http://127.0.0.1:9000/api/v1/ingest/run-outcome?x=1"
    );
}

/// A path that does not END in `worker-usage` is refused, never rewritten:
/// the sibling door cannot be derived from it.
#[test]
fn an_endpoint_that_is_not_the_worker_usage_door_is_refused() {
    for endpoint in [
        "https://admin.example/api/v1/ingest/other",
        "https://admin.example/worker-usage/extra",
        "https://admin.example/api/v1/ingest/worker-usage-v2",
        "https://admin.example/",
        "https://admin.example",
    ] {
        assert!(
            matches!(
                run_outcome_endpoint(endpoint),
                Err(RunOutcomeRefusal::NotWorkerUsage(_))
            ),
            "{endpoint} must be refused"
        );
    }
    assert!(matches!(
        run_outcome_endpoint("not a url"),
        Err(RunOutcomeRefusal::Unparseable(_))
    ));
}

/// Every target field comes from the block and the revision being loaded —
/// nothing else — and the target's `Debug` never prints the token.
#[test]
fn the_target_is_built_from_the_block_and_the_revision() {
    let deployment_id = DeploymentId::new();
    let revision_id = RevisionId::new();
    let target = run_outcome_target(
        Some(&metering(ENDPOINT)),
        deployment_id,
        BUNDLE,
        revision_id,
    )
    .expect("derives")
    .expect("present");
    assert_eq!(
        target.endpoint,
        "https://admin.example/api/v1/ingest/run-outcome"
    );
    assert_eq!(target.token, TOKEN);
    assert_eq!(target.tenant_slug, TENANT);
    assert_eq!(target.deployment_id, deployment_id.to_string());
    assert_eq!(target.bundle_id, BUNDLE);
    assert_eq!(target.revision_id, revision_id.to_string());
    let rendered = format!("{target:?}");
    assert!(!rendered.contains(TOKEN), "the token leaked: {rendered}");
}

#[test]
fn no_block_means_no_sink() {
    assert!(
        run_outcome_target(None, DeploymentId::new(), BUNDLE, RevisionId::new())
            .expect("absence is not an error")
            .is_none()
    );
    assert!(
        run_outcome_sink(None, DeploymentId::new(), BUNDLE, RevisionId::new())
            .expect("absence is not an error")
            .is_none()
    );
}

#[test]
fn a_staged_block_builds_the_sink() {
    let sink = run_outcome_sink(
        Some(&metering(ENDPOINT)),
        DeploymentId::new(),
        BUNDLE,
        RevisionId::new(),
    )
    .expect("builds")
    .expect("present");
    let rendered = format!("{sink:?}");
    assert!(!rendered.contains(TOKEN), "the token leaked: {rendered}");
}

/// The runner's own constructor refusals surface as a value, not a panic.
#[test]
fn a_sink_the_runner_refuses_is_a_refusal() {
    let refusal = run_outcome_sink(
        Some(&metering(ENDPOINT)),
        DeploymentId::new(),
        &"b".repeat(300),
        RevisionId::new(),
    )
    .expect_err("the admin refuses an id over 256 bytes, so the sink must too");
    assert!(
        matches!(
            refusal,
            RunOutcomeRefusal::Sink(RunOutcomeSinkError::TooLong("bundle_id"))
        ),
        "{refusal:?}"
    );
    assert!(!refusal.to_string().contains(TOKEN));
}
