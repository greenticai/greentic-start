//! The runner meter installed from the staged `metering` block, and the one
//! token source it implies for the interop reporter (Phase 2 §4.3 / §7).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use greentic_aw_runtime::billing::WorkerUsageError;
use greentic_deploy_spec::ids::{DeploymentId, RevisionId};
use serde_json::json;

use super::super::event::{Surface, TurnUsage};
use super::super::{Meter, MeteringConfig, MeteringToken, TurnMetering};
use super::*;
use crate::interop::config::InteropConfig;

const ENDPOINT: &str = "https://admin.example/api/v1/ingest/worker-usage";
const TOKEN: &str = "gtm_staged-usage-token";
const TENANT: &str = "acme";
const BUNDLE: &str = "support-bot";

fn metering() -> MeteringConfig {
    MeteringConfig {
        endpoint: ENDPOINT.into(),
        token: MeteringToken(TOKEN.into()),
        tenant_slug: TENANT.into(),
    }
}

/// Whether the options would hand the runtime a billing meter.
///
/// The field is private upstream; `RevisionHostOptions`' `Debug` names exactly
/// that bit (`billing_meter: <bool>`) and nothing else. **It only does so when
/// greentic-runner-host is built with its `agentic-worker` feature** — the
/// field and `with_billing_meter` are both `#[cfg(feature = "agentic-worker")]`
/// upstream. This crate gets that feature through runner-host's
/// `operala-in-process` (Cargo.toml), and `host_options_for_unit` would not
/// compile without it; the assertion below turns a silent loss of the feature
/// (every option reading "no meter") into a loud failure.
fn installs_a_meter(options: &RevisionHostOptions) -> bool {
    let rendered = format!("{options:?}");
    assert!(
        rendered.contains("billing_meter"),
        "RevisionHostOptions' Debug does not report the meter — greentic-runner-host \
         lost its `agentic-worker` feature, or the Debug changed upstream: {rendered}"
    );
    rendered.contains("billing_meter: true")
}

/// Whether the options would hand the runtime a run-outcome sink. Same trick
/// as [`installs_a_meter`]: the field is private upstream and its `Debug`
/// renders `run_outcome_sink: <bool>` (unconditionally — the sink is not
/// feature-gated).
fn installs_a_sink(options: &RevisionHostOptions) -> bool {
    let rendered = format!("{options:?}");
    assert!(
        rendered.contains("run_outcome_sink"),
        "RevisionHostOptions' Debug does not report the run-outcome sink — the Debug \
         changed upstream: {rendered}"
    );
    rendered.contains("run_outcome_sink: true")
}

#[test]
fn a_staged_block_installs_the_worker_usage_meter() {
    let meter = worker_usage_meter(Some(&metering()), DeploymentId::new(), BUNDLE)
        .expect("a validated block builds a meter");
    assert!(meter.is_some());

    let unit = host_options_for_unit(
        Some(&metering()),
        DeploymentId::new(),
        BUNDLE,
        RevisionId::new(),
    );
    assert!(unit.meters_usage);
    assert!(installs_a_meter(&unit.options));
    assert!(installs_a_sink(&unit.options));
}

/// The meter is built from the block's OWN endpoint, tenant slug and the
/// revision's ids — never anything else — and its `Debug` never prints the
/// token.
#[test]
fn the_meter_is_built_from_the_block_and_the_revision() {
    let deployment_id = DeploymentId::new();
    let meter = worker_usage_meter(Some(&metering()), deployment_id, BUNDLE)
        .expect("builds")
        .expect("present");
    let rendered = format!("{meter:?}");
    assert!(rendered.contains(ENDPOINT), "{rendered}");
    assert!(rendered.contains(TENANT), "{rendered}");
    assert!(rendered.contains(BUNDLE), "{rendered}");
    assert!(rendered.contains(&deployment_id.to_string()), "{rendered}");
    assert!(!rendered.contains(TOKEN), "the token leaked: {rendered}");
}

#[test]
fn an_absent_block_keeps_the_default_options() {
    assert!(
        worker_usage_meter(None, DeploymentId::new(), BUNDLE)
            .expect("absence is not an error")
            .is_none()
    );
    let unit = host_options_for_unit(None, DeploymentId::new(), BUNDLE, RevisionId::new());
    assert!(!unit.meters_usage);
    assert!(!installs_a_meter(&unit.options));
    assert!(!installs_a_sink(&unit.options));
}

/// The two halves are decided independently: a block whose endpoint is not
/// the worker-usage door still meters usage (the meter posts to it as staged)
/// but installs no run-outcome sink, because the sibling door cannot be
/// derived.
#[test]
fn an_underivable_run_outcome_door_keeps_the_meter_and_drops_only_the_sink() {
    let mut block = metering();
    block.endpoint = "https://admin.example/api/v1/ingest/other".into();
    let unit = host_options_for_unit(Some(&block), DeploymentId::new(), BUNDLE, RevisionId::new());
    assert!(unit.meters_usage);
    assert!(installs_a_meter(&unit.options));
    assert!(!installs_a_sink(&unit.options));
}

/// A constructor refusal is a value here and a warn in `host_options_for_unit`,
/// never a failed boot: the revision loads with default options.
#[test]
fn a_meter_that_cannot_be_built_leaves_the_revision_unmetered() {
    let too_long = "b".repeat(300);
    let refusal = worker_usage_meter(Some(&metering()), DeploymentId::new(), &too_long)
        .expect_err("the admin refuses an id over 256 bytes, so the meter must too");
    assert!(
        matches!(refusal, WorkerUsageError::TooLong("bundle_id")),
        "{refusal:?}"
    );

    let unit = host_options_for_unit(
        Some(&metering()),
        DeploymentId::new(),
        &too_long,
        RevisionId::new(),
    );
    assert!(!unit.meters_usage);
    assert!(!installs_a_meter(&unit.options));
    assert!(
        !installs_a_sink(&unit.options),
        "the run-outcome door refuses the same over-long id"
    );
}

#[test]
fn metered_units_answer_only_for_their_deployment_and_bundle() {
    let metered = DeploymentId::new();
    let set = RuntimeMeteredDeployments::of([(metered, BUNDLE.to_string())]);
    assert!(set.contains(metered, BUNDLE));
    assert!(
        !set.contains(metered, "another-bundle"),
        "a second bundle under one deployment id must not inherit the decision"
    );
    assert!(!set.contains(DeploymentId::new(), BUNDLE));
    assert!(!RuntimeMeteredDeployments::default().contains(metered, BUNDLE));
}

// ---- the interop reporter: one token source ---------------------------------

fn config() -> InteropConfig {
    InteropConfig {
        a2a: true,
        tenant_slug: Some(TENANT.into()),
        metering: Some(metering()),
        ..InteropConfig::default()
    }
}

fn spent() -> TurnUsage {
    TurnUsage {
        tokens_in: 120,
        tokens_out: 45,
        iterations: 3,
    }
}

/// With the runner meter installed the interop turn is still RECORDED —
/// surface, iterations, duration — but its tokens are zero, because the runner
/// meter already posted them per LLM iteration.
#[test]
fn with_the_runtime_meter_an_interop_turn_records_zero_tokens() {
    let meter = Arc::new(Meter::inspectable());
    let turn = TurnMetering::for_unit(&meter, &config(), DeploymentId::new(), BUNDLE)
        .expect("metered")
        .tokens_recorded_by_runtime(true);
    turn.record(
        Surface::Mcp,
        Some("c1"),
        spent(),
        Duration::from_millis(900),
    );

    let queued = meter.drain();
    assert_eq!(queued.len(), 1, "the turn itself is still recorded");
    let event = &queued[0].event;
    assert_eq!(event.surface, "mcp");
    assert_eq!((event.tokens_in, event.tokens_out), (0, 0));
    assert_eq!(event.iterations, 3);
    assert_eq!(event.duration_ms, 900);
    assert_eq!(event.credential_id.as_deref(), Some("c1"));
}

/// No runner meter (an older designer, or no staged block for it): the
/// reporter behaves exactly as before and carries the tokens itself.
#[test]
fn without_the_runtime_meter_an_interop_turn_carries_its_tokens() {
    for turn in [
        TurnMetering::for_unit(
            &Arc::new(Meter::inspectable()),
            &config(),
            DeploymentId::new(),
            BUNDLE,
        ),
        TurnMetering::for_unit(
            &Arc::new(Meter::inspectable()),
            &config(),
            DeploymentId::new(),
            BUNDLE,
        )
        .map(|turn| turn.tokens_recorded_by_runtime(false)),
    ] {
        let turn = turn.expect("metered");
        let meter = Arc::clone(&turn.meter);
        turn.record(Surface::A2a, None, spent(), Duration::ZERO);
        let queued = meter.drain();
        assert_eq!(queued.len(), 1);
        let event = &queued[0].event;
        assert_eq!((event.tokens_in, event.tokens_out), (120, 45));
        assert_eq!(event.iterations, 3);
    }
}

// ---- the per-unit read, once per activation ----------------------------------

struct Store {
    entries: HashMap<String, Vec<u8>>,
    fail: bool,
    reads: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl greentic_secrets_lib::SecretsManager for Store {
    async fn read(&self, path: &str) -> greentic_secrets_lib::Result<Vec<u8>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            return Err(greentic_secrets_lib::SecretError::Backend(
                "store unreachable".into(),
            ));
        }
        self.entries
            .get(path)
            .cloned()
            .ok_or_else(|| greentic_secrets_lib::SecretError::NotFound(path.to_string()))
    }

    async fn write(&self, _path: &str, _bytes: &[u8]) -> greentic_secrets_lib::Result<()> {
        Ok(())
    }

    async fn delete(&self, _path: &str) -> greentic_secrets_lib::Result<()> {
        Ok(())
    }
}

fn store(document: Option<serde_json::Value>, fail: bool) -> (Store, Arc<AtomicUsize>) {
    let reads = Arc::new(AtomicUsize::new(0));
    let mut entries = HashMap::new();
    if let Some(document) = document {
        entries.insert(
            crate::ingress_auth::ingress_secret_uri("local", TENANT, BUNDLE),
            document.to_string().into_bytes(),
        );
    }
    (
        Store {
            entries,
            fail,
            reads: Arc::clone(&reads),
        },
        reads,
    )
}

#[tokio::test]
async fn the_staged_block_is_read_once_per_unit_per_activation() {
    let (store, reads) = store(
        Some(json!({
            "v": 1,
            "tenant_slug": TENANT,
            "metering": {"endpoint": ENDPOINT, "token": TOKEN},
        })),
        false,
    );
    let mut decisions = UnitMeterDecisions::default();
    for _ in 0..3 {
        assert_eq!(
            decisions
                .metering_for(&store, "local", TENANT, BUNDLE)
                .await,
            Some(metering())
        );
    }
    assert_eq!(
        reads.load(Ordering::Relaxed),
        1,
        "two revisions of one unit must share one decision"
    );
}

#[tokio::test]
async fn a_unit_with_no_block_or_no_document_installs_nothing() {
    for document in [
        None,
        Some(json!({"v": 1, "a2a": true, "tenant_slug": TENANT})),
    ] {
        let (store, _) = store(document, false);
        let mut decisions = UnitMeterDecisions::default();
        assert_eq!(
            decisions
                .metering_for(&store, "local", TENANT, BUNDLE)
                .await,
            None
        );
    }
}

/// An unreadable store is "no meter" and a warn, never a boot failure — and
/// the outcome is memoised so every revision of the unit agrees.
#[tokio::test]
async fn an_unreadable_store_runs_the_unit_without_a_meter() {
    let (store, reads) = store(None, true);
    let mut decisions = UnitMeterDecisions::default();
    for _ in 0..2 {
        assert_eq!(
            decisions
                .metering_for(&store, "local", TENANT, BUNDLE)
                .await,
            None
        );
    }
    assert_eq!(reads.load(Ordering::Relaxed), 1);
}

// ---- the boot call: options and the metered set come from one place ----------

/// What boot does per revision: a unit whose staged document carries a block
/// loads with the runner meter AND lands in the set the interop reporter
/// reads; a unit without one loads with defaults and does not. Removing the
/// set insert, or building the set anywhere else, fails this.
#[tokio::test]
async fn boot_records_exactly_the_units_it_installed_a_meter_for() {
    let metered_doc = json!({
        "v": 1,
        "tenant_slug": TENANT,
        "metering": {"endpoint": ENDPOINT, "token": TOKEN},
    });
    let reads = Arc::new(AtomicUsize::new(0));
    let mut entries = HashMap::new();
    entries.insert(
        crate::ingress_auth::ingress_secret_uri("local", TENANT, BUNDLE),
        metered_doc.to_string().into_bytes(),
    );
    entries.insert(
        crate::ingress_auth::ingress_secret_uri("local", TENANT, "plain-bot"),
        json!({"v": 1, "a2a": true, "tenant_slug": TENANT})
            .to_string()
            .into_bytes(),
    );
    let store = Store {
        entries,
        fail: false,
        reads,
    };

    let metered = DeploymentId::new();
    let plain = DeploymentId::new();
    let mut decisions = UnitMeterDecisions::default();
    let options = decisions
        .options_for_revision(&store, "local", TENANT, metered, BUNDLE, RevisionId::new())
        .await;
    assert!(installs_a_meter(&options));
    assert!(
        installs_a_sink(&options),
        "a metered unit also reports run outcomes"
    );
    let options = decisions
        .options_for_revision(
            &store,
            "local",
            TENANT,
            plain,
            "plain-bot",
            RevisionId::new(),
        )
        .await;
    assert!(!installs_a_meter(&options));
    assert!(!installs_a_sink(&options), "no block, no run-outcome sink");

    let set = decisions.into_metered();
    assert!(set.contains(metered, BUNDLE));
    assert!(!set.contains(plain, "plain-bot"));
}
