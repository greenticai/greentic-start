//! The per-end-user ledger door derived from the staged `metering` block.

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
fn the_ledger_door_is_the_worker_usage_doors_sibling() {
    let target = user_ledger_target(Some(&metering(ENDPOINT)))
        .expect("derives")
        .expect("present");
    // The runner appends `/read` and `/append` itself.
    assert_eq!(
        target.base_url,
        "https://admin.example/api/v1/ingest/ledger"
    );
    // The VALIDATED slug the meter and the other doors send.
    assert_eq!(target.tenant_slug, TENANT);
    let rendered = format!("{target:?}");
    assert!(!rendered.contains(TOKEN), "the token leaked: {rendered}");
}

/// Port, a path prefix, a trailing slash and a query survive; only the last
/// segment moves — the rule every sibling door follows.
#[test]
fn the_derivation_keeps_everything_but_the_last_segment() {
    let target = user_ledger_target(Some(&metering(
        "https://admin.example:8443/admin/api/v1/ingest/worker-usage/?region=eu",
    )))
    .expect("derives")
    .expect("present");
    assert_eq!(
        target.base_url,
        "https://admin.example:8443/admin/api/v1/ingest/ledger?region=eu"
    );
}

#[test]
fn an_absent_block_installs_no_ledger_and_is_not_an_error() {
    assert!(
        user_ledger_target(None)
            .expect("absence is not an error")
            .is_none()
    );
}

#[test]
fn an_endpoint_that_is_not_the_worker_usage_door_is_refused_without_the_token() {
    for endpoint in [
        "https://admin.example/api/v1/ingest/other",
        "https://admin.example/api/v1/ingest/worker-usage-v2",
        "https://admin.example",
    ] {
        let refusal = user_ledger_target(Some(&metering(endpoint))).expect_err("must be refused");
        assert!(
            matches!(refusal, UserLedgerRefusal::NotWorkerUsage(_)),
            "{endpoint}: {refusal:?}"
        );
        assert!(!format!("{refusal} {refusal:?}").contains(TOKEN));
    }
    assert!(matches!(
        user_ledger_target(Some(&metering("not a url"))),
        Err(UserLedgerRefusal::Unparseable(_))
    ));
}

/// Cleartext off loopback would carry the bearer in the clear: refused here,
/// where the operator log names the unit, not only skipped upstream.
#[test]
fn a_cleartext_endpoint_off_loopback_is_refused() {
    let refusal = user_ledger_target(Some(&metering(
        "http://admin.example/api/v1/ingest/worker-usage",
    )))
    .expect_err("cleartext off loopback must be refused");
    assert!(
        matches!(
            refusal,
            UserLedgerRefusal::Target(UserLedgerTargetError::UnsafeEndpoint)
        ),
        "{refusal:?}"
    );
    assert!(!format!("{refusal} {refusal:?}").contains(TOKEN));

    assert!(
        user_ledger_target(Some(&metering(
            "http://127.0.0.1:9000/api/v1/ingest/worker-usage"
        )))
        .expect("loopback http is allowed")
        .is_some()
    );
}

/// A blank tenant slug never reaches the runner: the door would refuse every
/// call, so the unit runs without the ledger and the log says why.
#[test]
fn a_blank_tenant_slug_is_refused() {
    let mut block = metering(ENDPOINT);
    block.tenant_slug = String::new();
    assert!(matches!(
        user_ledger_target(Some(&block)),
        Err(UserLedgerRefusal::Target(UserLedgerTargetError::Blank(
            "tenant_slug"
        )))
    ));
}
