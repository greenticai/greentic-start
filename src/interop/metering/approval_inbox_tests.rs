//! The HTTP approval inbox derived from the staged `metering` block (approval
//! rail over HTTP §5).

use super::super::{MeteringConfig, MeteringToken};
use super::*;

const ENDPOINT: &str = "https://admin.example/api/v1/ingest/worker-usage";
const TOKEN: &str = "gtm_staged-usage-token";
const TENANT: &str = "acme";

fn metering(endpoint: &str) -> MeteringConfig {
    MeteringConfig {
        endpoint: endpoint.into(),
        token: MeteringToken(TOKEN.into()),
        tenant_slug: TENANT.into(),
    }
}

#[test]
fn the_three_doors_are_the_worker_usage_doors_siblings() {
    let target = approval_inbox_target(Some(&metering(ENDPOINT)))
        .expect("derives")
        .expect("present");
    assert_eq!(
        target.request_url,
        "https://admin.example/api/v1/ingest/approval-request"
    );
    assert_eq!(
        target.decision_url,
        "https://admin.example/api/v1/ingest/approval-decision"
    );
    assert_eq!(
        target.withdraw_url,
        "https://admin.example/api/v1/ingest/approval-withdraw"
    );
    assert_eq!(target.token, TOKEN);
    assert_eq!(target.tenant_slug, TENANT);
    let rendered = format!("{target:?}");
    assert!(!rendered.contains(TOKEN), "the token leaked: {rendered}");
}

/// Port, a path prefix and a trailing slash survive; only the last segment
/// moves — the same rule the run-outcome door follows.
#[test]
fn the_derivation_keeps_everything_but_the_last_segment() {
    let target = approval_inbox_target(Some(&metering(
        "https://admin.example:8443/admin/api/v1/ingest/worker-usage/",
    )))
    .expect("derives")
    .expect("present");
    assert_eq!(
        target.decision_url,
        "https://admin.example:8443/admin/api/v1/ingest/approval-decision"
    );
}

#[test]
fn an_absent_block_installs_no_inbox_and_is_not_an_error() {
    assert!(
        approval_inbox_target(None)
            .expect("absence is not an error")
            .is_none()
    );
}

#[test]
fn an_endpoint_that_is_not_the_worker_usage_door_is_refused() {
    for endpoint in [
        "https://admin.example/api/v1/ingest/other",
        "https://admin.example/api/v1/ingest/worker-usage-v2",
        "https://admin.example",
    ] {
        assert!(
            matches!(
                approval_inbox_target(Some(&metering(endpoint))),
                Err(ApprovalInboxRefusal::NotWorkerUsage(_))
            ),
            "{endpoint} must be refused"
        );
    }
    assert!(matches!(
        approval_inbox_target(Some(&metering("not a url"))),
        Err(ApprovalInboxRefusal::Unparseable(_))
    ));
}

/// A derivable but unsafe target — cleartext http off loopback would carry the
/// bearer in the clear — is refused here, where the operator log names the
/// unit, rather than only being skipped upstream.
#[test]
fn a_cleartext_endpoint_off_loopback_is_refused() {
    let refusal = approval_inbox_target(Some(&metering(
        "http://admin.example/api/v1/ingest/worker-usage",
    )))
    .expect_err("cleartext off loopback must be refused");
    assert!(
        matches!(
            refusal,
            ApprovalInboxRefusal::Inbox(ApprovalInboxError::UnsafeUrl(_))
        ),
        "{refusal:?}"
    );
    assert!(!refusal.to_string().contains(TOKEN));

    // Loopback http is how a local admin is reached, and is allowed.
    assert!(
        approval_inbox_target(Some(&metering(
            "http://127.0.0.1:9000/api/v1/ingest/worker-usage"
        )))
        .expect("loopback http is allowed")
        .is_some()
    );
}
