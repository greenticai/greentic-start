//! Installing the runner's per-unit [`WorkerUsageMeter`] from the SAME staged
//! `metering` block interop turns report through (env-canvas unit usage
//! Phase 2, greentic-designer
//! `docs/superpowers/specs/2026-09-24-env-canvas-unit-monitoring-phase-2-design.md`
//! §4.3 and §7).
//!
//! The interop reporter above records one event per A2A/MCP turn. A unit's
//! OTHER turns — every channel a deployed worker answers on — recorded
//! nothing. The runner host now takes a per-revision billing meter
//! (`TenantRuntime::load_revision_with` + `RevisionHostOptions::with_billing_meter`),
//! and the agent runtime ships `WorkerUsageMeter`, which posts one event per
//! LLM iteration to the admin's per-unit ingest door with `surface: "turn"`
//! and the model id. This module builds that meter for one revision.
//!
//! # Four rules
//!
//! - **No new secret, no new env var.** The endpoint, token and tenant slug
//!   are the ones [`super::resolve_metering`] already validated. A unit that
//!   stages no block installs nothing, which is exactly the behaviour before
//!   this existed.
//! - **A meter that cannot be built never fails the boot.** A constructor
//!   refusal (an over-long bundle id, say) is one `warn` and the revision
//!   loads without a meter: losing usage rows must never cost a unit its
//!   traffic.
//! - **Tokens have ONE source.** When the runner meter is installed, it
//!   already records the LLM iterations an interop turn runs, so the interop
//!   reporter keeps posting its per-turn event (surface, iterations,
//!   duration) with `tokens_in` / `tokens_out` zeroed. The admin forwarder
//!   skips zero-quantity meters, so the interop turn stays visible as a TURN
//!   without counting its tokens twice. [`RuntimeMeteredDeployments`] is how
//!   the reporter knows. With no runner meter, the reporter is unchanged.
//! - **The decision is per UNIT, not per revision.** Every revision of one
//!   deployment reads the same staged document, so [`UnitMeterDecisions`]
//!   reads it once per `(tenant, bundle id)` per activation. Two revisions of
//!   one unit in a traffic split therefore cannot disagree about whether the
//!   interop reporter should zero its tokens. The metered set is keyed on
//!   `(deployment id, bundle id)`, the same pair the serve path resolves a
//!   request to, and the bundle id is the DEPLOYMENT's (`dep.bundle_id`, the
//!   value the route table carries), not the runtime-config block's — the two
//!   are cross-checked equal before any revision loads.
//!
//! # Two things this does NOT do
//!
//! - **It does not follow an in-place rewrite of the staged document.** The
//!   meter is built at activation and the metered set is fixed for that
//!   activation, while the serve path re-reads the document on a short TTL.
//!   A document rewritten WITHOUT a new activation (a token rotated on a lane
//!   that restages the store in place) leaves the runtime posting with the
//!   old token — which the admin refuses, and the meter then suspends — while
//!   interop turns keep sending zeroed tokens, so that unit's tokens go
//!   unrecorded until the next activation. Not reachable on Cloud Run, where
//!   the dev store is baked into the revision and any change is a new one.
//! - **It is not double billing when `GREENTIC_BILLING_*` is also set.** The
//!   runner then fans every usage event out to BOTH its env-configured
//!   cloud-commerce sink and this admin meter (and keeps the credit gate on
//!   the former). Those are two separate ledgers: the admin's
//!   `worker_usage_events` is a per-unit recording keyed on the token, not a
//!   charge. Each sink sees each LLM iteration exactly once.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use greentic_aw_runtime::billing::{WorkerUsageError, WorkerUsageMeter, WorkerUsageTarget};
use greentic_deploy_spec::ids::DeploymentId;
use greentic_runner_host::runtime::RevisionHostOptions;

use super::MeteringConfig;
use crate::operator_log;

/// Build the runner meter for one unit, or `None` when the unit stages no
/// `metering` block.
///
/// Pure apart from constructing the meter's HTTP client: every refusal is a
/// value, so a test can assert WHICH one happened, and
/// [`host_options_for_unit`] is the one place that logs it.
pub(crate) fn worker_usage_meter(
    metering: Option<&MeteringConfig>,
    deployment_id: DeploymentId,
    bundle_id: &str,
) -> Result<Option<WorkerUsageMeter>, WorkerUsageError> {
    let Some(metering) = metering else {
        return Ok(None);
    };
    WorkerUsageMeter::new(WorkerUsageTarget {
        endpoint: metering.endpoint.clone(),
        token: metering.token.expose().to_string(),
        // The VALIDATED slug, the same one every interop event carries: the
        // admin refuses a body whose slug disagrees with the token's tenant.
        tenant_slug: metering.tenant_slug.clone(),
        deployment_id: deployment_id.to_string(),
        bundle_id: bundle_id.to_string(),
    })
    .map(Some)
}

/// The host options one revision loads with, and whether they install the
/// runner meter.
pub(crate) struct UnitHostOptions {
    pub options: RevisionHostOptions,
    /// `true` exactly when [`Self::options`] carries a billing meter.
    /// [`UnitMeterDecisions::options_for_revision`] records the unit on it.
    pub meters_usage: bool,
}

/// [`worker_usage_meter`], folded into [`RevisionHostOptions`], with a
/// refusal turned into one operator line and NO meter.
///
/// An absent block yields `RevisionHostOptions::default()`, which is
/// byte-for-byte what `TenantRuntime::load_revision` did.
pub(crate) fn host_options_for_unit(
    metering: Option<&MeteringConfig>,
    deployment_id: DeploymentId,
    bundle_id: &str,
) -> UnitHostOptions {
    match worker_usage_meter(metering, deployment_id, bundle_id) {
        Ok(Some(meter)) => UnitHostOptions {
            options: RevisionHostOptions::default().with_billing_meter(Arc::new(meter)),
            meters_usage: true,
        },
        Ok(None) => UnitHostOptions {
            options: RevisionHostOptions::default(),
            meters_usage: false,
        },
        Err(err) => {
            // `WorkerUsageError`'s messages name a field or the endpoint,
            // never the token.
            operator_log::warn(
                module_path!(),
                format!(
                    "worker usage metering for unit `{bundle_id}` is off: {err}; the revision \
                     runs without recording its LLM usage"
                ),
            );
            UnitHostOptions {
                options: RevisionHostOptions::default(),
                meters_usage: false,
            }
        }
    }
}

/// The units whose loaded revisions carry the runner's worker-usage meter,
/// for the activation they were loaded in, keyed `(deployment id, bundle id)`.
///
/// Travels on [`crate::deployment_routes::RevisionIngressRouting`] because it
/// is revision-derived: a full activation rebuilds it, a routing-only reload
/// carries it over unchanged (no revision moved, so no meter did either).
/// Built only by [`UnitMeterDecisions::into_metered`], so the set and the
/// options the revisions actually loaded with cannot come from two places.
#[derive(Clone, Debug, Default)]
pub(crate) struct RuntimeMeteredDeployments(Arc<HashSet<(DeploymentId, String)>>);

impl RuntimeMeteredDeployments {
    /// Whether the runner already records this unit's LLM tokens, so the
    /// interop reporter must not record them again.
    pub(crate) fn contains(&self, deployment_id: DeploymentId, bundle_id: &str) -> bool {
        self.0.contains(&(deployment_id, bundle_id.to_string()))
    }

    #[cfg(test)]
    pub(crate) fn of(units: impl IntoIterator<Item = (DeploymentId, String)>) -> Self {
        Self(Arc::new(units.into_iter().collect()))
    }
}

/// One activation's per-unit metering decisions: the staged block read once
/// per `(tenant, bundle id)` — see the module docs on why the decision is per
/// unit — and the units that ended up with a runner meter.
#[derive(Default)]
pub(crate) struct UnitMeterDecisions {
    reads: HashMap<(String, String), Option<MeteringConfig>>,
    metered: HashSet<(DeploymentId, String)>,
}

impl UnitMeterDecisions {
    /// The host options one revision of this unit loads with, recording the
    /// unit as metered when they install the runner meter.
    ///
    /// This is the ONE boot call: reading the block, building the meter and
    /// recording the decision happen together, so an activation cannot
    /// install a meter without the interop reporter learning of it.
    pub(crate) async fn options_for_revision(
        &mut self,
        secrets: &dyn greentic_secrets_lib::SecretsManager,
        env: &str,
        tenant: &str,
        deployment_id: DeploymentId,
        bundle_id: &str,
    ) -> RevisionHostOptions {
        let metering = self.metering_for(secrets, env, tenant, bundle_id).await;
        let unit = host_options_for_unit(metering.as_ref(), deployment_id, bundle_id);
        if unit.meters_usage {
            self.metered.insert((deployment_id, bundle_id.to_string()));
        }
        unit.options
    }

    /// The units this activation installed a runner meter for.
    pub(crate) fn into_metered(self) -> RuntimeMeteredDeployments {
        RuntimeMeteredDeployments(Arc::new(self.metered))
    }

    /// The unit's resolved `metering` block, reading the staged document at
    /// most once per activation.
    ///
    /// A store that cannot answer is treated as "no block" with one `warn`,
    /// never as a boot failure — the same trade the rest of this module
    /// makes. It is also memoised, so every revision of the unit agrees.
    pub(crate) async fn metering_for(
        &mut self,
        secrets: &dyn greentic_secrets_lib::SecretsManager,
        env: &str,
        tenant: &str,
        bundle_id: &str,
    ) -> Option<MeteringConfig> {
        let key = (tenant.to_string(), bundle_id.to_string());
        if let Some(known) = self.reads.get(&key) {
            return known.clone();
        }
        let metering =
            match crate::ingress_auth::load_unit_config(secrets, env, tenant, bundle_id).await {
                Ok(config) => config.and_then(|config| config.metering),
                Err(crate::ingress_auth::ConfigUnavailable(message)) => {
                    operator_log::warn(
                        module_path!(),
                        format!(
                            "worker usage metering for unit `{bundle_id}` is off: its staged \
                             config could not be read ({message})"
                        ),
                    );
                    None
                }
            };
        self.reads.insert(key, metering.clone());
        metering
    }
}

#[cfg(test)]
#[path = "runtime_meter_tests.rs"]
mod runtime_meter_tests;
