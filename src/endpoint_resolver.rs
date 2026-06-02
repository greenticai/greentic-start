//! M1 IID.4 messaging-endpoint resolver — when an inbound request lacks the
//! `x-greentic-messaging-endpoint-id` header, ask each enabled provider
//! component to identify itself from the payload and recover a known
//! `endpoint_id`.
//!
//! The resolver is a thin coordinator over
//! [`RunnerHost::identify_messaging_endpoints_for_revision`]: it picks the
//! [`EndpointAdmit::provider_types`] set to probe, hands the host the request
//! body, and folds the per-`provider_type` outcomes against the admit table to
//! yield a [`ResolverOutcome`]. The resolver does **not** decide HTTP status
//! codes or telemetry envelopes — that policy lives at the
//! `revision_serve::serve` call site.
//!
//! Distinct conditions are surfaced as distinct outcomes (rather than
//! collapsed to `Option<String>`) because each maps to a different operator
//! intent at the call site:
//!
//! * `HeaderWins` — caller asserted an eid via the trusted (loopback)
//!   header path; the resolver never ran. Kept as an outcome so the call
//!   site can attribute every request uniformly via [`ResolverOutcome::origin`].
//! * `Hit` — exactly one declared endpoint matched the payload.
//! * `Miss` — every probed `provider_type` returned `NoMatch` (the component
//!   IS able to identify, but this payload doesn't address a known instance).
//!   Falling through is back-compat for environments with at most one
//!   endpoint per `provider_type`; the call site fails closed when ambiguity
//!   would lurk.
//! * `Ambiguous` — either multiple distinct endpoints matched in one
//!   request, OR a probe returned `NoMatch` for a `provider_type` the env
//!   declares ≥2 endpoints of. Both shapes mean "we cannot safely guess";
//!   the call site MUST 422.
//! * `NoImpl` — every probed `provider_type` returned `Unsupported`
//!   (manifest declared the world but the component never exported it, or
//!   no manifest at all). Indistinguishable from `Miss` for routing
//!   purposes, but the telemetry attribute distinguishes them so operators
//!   can see "the provider component is the wrong version" vs "the payload
//!   genuinely doesn't address a known endpoint".
//! * `Skipped` — the env declared no messaging endpoints at all, so there
//!   is nothing to resolve. Cheaper than running an empty probe; also keeps
//!   telemetry honest (we did not "miss", we never tried).

use std::sync::Arc;

use greentic_deploy_spec::{BundleId, DeploymentId, RevisionId};
use greentic_runner_host::RunnerHost;
use greentic_runner_host::pack::IdentifyOutcome;

use crate::endpoint_admit::EndpointAdmit;

/// The decision the resolver hands back to the serve pipeline.
///
/// `Hit`/`Miss`/`Ambiguous`/`NoImpl` are mutually exclusive results of a
/// real probe; `HeaderWins`/`Skipped` are the two short-circuit paths that
/// never invoked the host. The call site decides HTTP status / telemetry
/// attribution; this enum carries the *raw* decision, not its policy
/// translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolverOutcome {
    /// The caller's trusted header pinned the eid; the resolver did not run.
    /// The carried string is the validated header value, passed through.
    HeaderWins(String),
    /// Exactly one declared endpoint matched the payload across all probed
    /// `provider_type`s. The carried string is the on-wire `endpoint_id`.
    Hit(String),
    /// At least one probed `provider_type` returned `NoMatch`, and no probe
    /// returned `Identified`. The env declares ≤1 endpoint of each probed
    /// type, so falling through is safe (back-compat).
    Miss,
    /// Either a probe returned multiple distinct identified endpoints in one
    /// request, OR a probe returned `NoMatch` for a `provider_type` whose
    /// admit table holds ≥2 endpoints. Both shapes are unsafe to silently
    /// route; the call site MUST 422.
    Ambiguous,
    /// Every probed `provider_type` returned `Unsupported` — the components
    /// never exported `identify-instance` (or no manifest declared them).
    /// Routing-equivalent to `Miss`; telemetry distinguishes them so
    /// operators can see why.
    NoImpl,
    /// The env declares no messaging endpoints, so no probe was issued.
    Skipped,
}

impl ResolverOutcome {
    /// Stable string used as the `gt.endpoint_resolution` telemetry attribute
    /// at the serve call site. Kept on the type so the variants and their
    /// telemetry labels can't drift.
    pub(crate) fn origin(&self) -> &'static str {
        match self {
            ResolverOutcome::HeaderWins(_) => "header-wins",
            ResolverOutcome::Hit(_) => "hit",
            ResolverOutcome::Miss => "miss",
            ResolverOutcome::Ambiguous => "ambiguous",
            ResolverOutcome::NoImpl => "no-impl",
            ResolverOutcome::Skipped => "skipped",
        }
    }

    /// Convenience for the serve site: the resolved eid (if any) that should
    /// be threaded into the activity. `HeaderWins`/`Hit` return `Some`;
    /// `Miss`/`Ambiguous`/`NoImpl`/`Skipped` return `None`. `Ambiguous` is
    /// `None` here because the call site is expected to refuse the request
    /// before reaching the activity.
    pub(crate) fn endpoint_id(&self) -> Option<&str> {
        match self {
            ResolverOutcome::HeaderWins(eid) | ResolverOutcome::Hit(eid) => Some(eid.as_str()),
            _ => None,
        }
    }
}

/// Resolve the messaging endpoint for a dispatched request.
///
/// `header_eid` is the validated eid the caller asserted via
/// `x-greentic-messaging-endpoint-id` (only populated from loopback peers; see
/// `revision_serve::caller_identity`). When `Some`, this short-circuits to
/// [`ResolverOutcome::HeaderWins`] — the header is the operator's manual
/// override and beats the resolver.
///
/// `(deployment_id, bundle_id, revision_id)` MUST be the post-dispatch tuple
/// — the host method loads the revision's pack runtime by exactly that key.
///
/// `payload` is the raw request body bytes passed through to every probed
/// component. The body is JSON at this layer but the host accepts opaque
/// bytes (the WIT contract is `body: list<u8>`), so we don't reserialize.
///
/// Returns the [`ResolverOutcome`] for the serve site to act on. Component
/// traps / infrastructure errors bubble as `Err`; the caller distinguishes
/// "no identification" (a clean variant) from "the host couldn't even run
/// the probe" (an error).
// The argument list mirrors `RunnerHost::identify_messaging_endpoints_for_revision`
// + the admit table + the (separate-by-nature) header eid. Bundling them into
// a struct would just move the same 8 fields and force the call site (one
// caller, `revision_serve::serve`) to build a builder. The argument count is
// the right cost.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve(
    host: &Arc<RunnerHost>,
    tenant: &str,
    deployment_id: DeploymentId,
    bundle_id: &BundleId,
    revision_id: RevisionId,
    admit: &EndpointAdmit,
    header_eid: Option<&str>,
    payload: &[u8],
) -> anyhow::Result<ResolverOutcome> {
    if let Some(eid) = header_eid {
        return Ok(ResolverOutcome::HeaderWins(eid.to_string()));
    }

    let provider_types: Vec<&str> = admit.provider_types().collect();
    if provider_types.is_empty() {
        return Ok(ResolverOutcome::Skipped);
    }

    let outcomes = host
        .identify_messaging_endpoints_for_revision(
            tenant,
            deployment_id,
            bundle_id.clone(),
            revision_id,
            &provider_types,
            payload,
        )
        .await?;

    Ok(fold_outcomes(admit, &outcomes))
}

/// Pure folding step extracted for testability. Walks the per-`provider_type`
/// outcomes and decides between Hit / Miss / Ambiguous / NoImpl per the rules
/// described on [`ResolverOutcome`]. Pulled out of [`resolve`] so it can be
/// unit-tested without a running [`RunnerHost`].
fn fold_outcomes(
    admit: &EndpointAdmit,
    outcomes: &std::collections::HashMap<String, IdentifyOutcome>,
) -> ResolverOutcome {
    let mut hits: Vec<String> = Vec::new();
    // `Unsupported` is the lattice floor; any `NoMatch` or `Identified` from
    // any pack outranks it. If every type stays at `Unsupported`, the
    // components never exported the world.
    let mut any_no_match_amb = false;
    let mut any_non_unsupported = false;

    for (provider_type, outcome) in outcomes {
        match outcome {
            IdentifyOutcome::Identified(provider_id) => {
                any_non_unsupported = true;
                if let Some(eid) = admit.endpoint_id_for_provider(provider_type, provider_id) {
                    hits.push(eid.to_string());
                }
                // An `Identified` whose provider_id is NOT in the admit table
                // is an operational drift: the component thinks "this is bot
                // X" but the env never declared bot X as an endpoint. Treat
                // it as Miss for THIS provider_type — the env clearly didn't
                // intend to route it, and falling through doesn't help.
            }
            IdentifyOutcome::NoMatch => {
                any_non_unsupported = true;
                // ≥2 endpoints of this type AND the component said "none of
                // them" — we cannot disambiguate by other means, fail closed.
                if admit.endpoint_count_for_provider_type(provider_type) >= 2 {
                    any_no_match_amb = true;
                }
            }
            IdentifyOutcome::Unsupported => {
                // Stay at floor; do nothing.
            }
        }
    }

    // Multiple distinct hits → ambiguous. Dedup first: one component might
    // (incorrectly) point at one endpoint while another component happens to
    // map to the same eid via shared provider_id — that's still one hit.
    hits.sort_unstable();
    hits.dedup();

    if hits.len() > 1 {
        return ResolverOutcome::Ambiguous;
    }
    if let Some(eid) = hits.into_iter().next() {
        return ResolverOutcome::Hit(eid);
    }
    if any_no_match_amb {
        return ResolverOutcome::Ambiguous;
    }
    if any_non_unsupported {
        return ResolverOutcome::Miss;
    }
    ResolverOutcome::NoImpl
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::{
        Environment, EnvironmentHostConfig, MessagingEndpoint, MessagingEndpointId, SchemaVersion,
    };
    use greentic_types::EnvId;
    use std::collections::HashMap;

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn endpoint_typed(
        provider_type: &str,
        provider_id: &str,
        bundles: &[&str],
    ) -> MessagingEndpoint {
        let now = chrono::Utc::now();
        MessagingEndpoint {
            schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
            env_id: env_id(),
            endpoint_id: MessagingEndpointId::new(),
            provider_id: provider_id.to_string(),
            provider_type: provider_type.to_string(),
            display_name: provider_id.to_string(),
            secret_refs: Vec::new(),
            linked_bundles: bundles.iter().map(|b| BundleId::new(*b)).collect(),
            welcome_flow: None,
            generation: 1,
            created_at: now,
            updated_at: now,
            updated_by: "test".to_string(),
        }
    }

    fn admit_from(endpoints: Vec<MessagingEndpoint>) -> EndpointAdmit {
        EndpointAdmit::from_environment(&Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id(),
            name: "local".to_string(),
            host_config: EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
            },
            packs: Vec::new(),
            messaging_endpoints: endpoints,
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        })
    }

    #[test]
    fn origin_strings_are_stable() {
        // The serve site stamps these as telemetry attributes; renames would
        // break operator dashboards silently.
        assert_eq!(
            ResolverOutcome::HeaderWins("x".into()).origin(),
            "header-wins"
        );
        assert_eq!(ResolverOutcome::Hit("x".into()).origin(), "hit");
        assert_eq!(ResolverOutcome::Miss.origin(), "miss");
        assert_eq!(ResolverOutcome::Ambiguous.origin(), "ambiguous");
        assert_eq!(ResolverOutcome::NoImpl.origin(), "no-impl");
        assert_eq!(ResolverOutcome::Skipped.origin(), "skipped");
    }

    #[test]
    fn endpoint_id_threaded_only_when_resolution_succeeded() {
        assert_eq!(
            ResolverOutcome::HeaderWins("teams-legal".into()).endpoint_id(),
            Some("teams-legal")
        );
        assert_eq!(
            ResolverOutcome::Hit("teams-legal".into()).endpoint_id(),
            Some("teams-legal")
        );
        assert!(ResolverOutcome::Miss.endpoint_id().is_none());
        // Ambiguous is intentionally `None`: the serve site refuses the
        // request before threading the activity, so leaking an arbitrary
        // candidate would mask the failure.
        assert!(ResolverOutcome::Ambiguous.endpoint_id().is_none());
        assert!(ResolverOutcome::NoImpl.endpoint_id().is_none());
        assert!(ResolverOutcome::Skipped.endpoint_id().is_none());
    }

    #[test]
    fn fold_single_identified_yields_hit_with_eid() {
        let teams = endpoint_typed("teams", "28:legal-bot", &["legal-bundle"]);
        let eid = teams.endpoint_id.to_string();
        let admit = admit_from(vec![teams]);
        let outcomes = HashMap::from([(
            "teams".to_string(),
            IdentifyOutcome::Identified("28:legal-bot".to_string()),
        )]);
        assert_eq!(fold_outcomes(&admit, &outcomes), ResolverOutcome::Hit(eid));
    }

    #[test]
    fn fold_identified_unknown_provider_id_falls_through_as_miss() {
        // The component said "this is bot X" but the env doesn't know bot X
        // — that's drift, not ambiguity. Falling through is right: the env
        // didn't intend to route it.
        let admit = admit_from(vec![endpoint_typed("teams", "28:known", &["b"])]);
        let outcomes = HashMap::from([(
            "teams".to_string(),
            IdentifyOutcome::Identified("28:unknown-drift".to_string()),
        )]);
        assert_eq!(fold_outcomes(&admit, &outcomes), ResolverOutcome::Miss);
    }

    #[test]
    fn fold_no_match_with_single_endpoint_of_type_is_miss() {
        // Only one Teams endpoint declared, component said "no match" —
        // there's nothing to be ambiguous about, fall through.
        let admit = admit_from(vec![endpoint_typed("teams", "28:legal", &["b"])]);
        let outcomes = HashMap::from([("teams".to_string(), IdentifyOutcome::NoMatch)]);
        assert_eq!(fold_outcomes(&admit, &outcomes), ResolverOutcome::Miss);
    }

    #[test]
    fn fold_no_match_with_two_endpoints_of_type_is_ambiguous() {
        // Two Teams endpoints declared AND component said "no match" —
        // silently picking one would be wrong; fail closed.
        let admit = admit_from(vec![
            endpoint_typed("teams", "28:legal", &["b1"]),
            endpoint_typed("teams", "28:acct", &["b2"]),
        ]);
        let outcomes = HashMap::from([("teams".to_string(), IdentifyOutcome::NoMatch)]);
        assert_eq!(fold_outcomes(&admit, &outcomes), ResolverOutcome::Ambiguous);
    }

    #[test]
    fn fold_multiple_distinct_identified_is_ambiguous() {
        let teams_a = endpoint_typed("teams", "28:legal", &["b1"]);
        let slack_b = endpoint_typed("slack", "T0LEGAL", &["b1"]);
        let admit = admit_from(vec![teams_a, slack_b]);
        let outcomes = HashMap::from([
            (
                "teams".to_string(),
                IdentifyOutcome::Identified("28:legal".to_string()),
            ),
            (
                "slack".to_string(),
                IdentifyOutcome::Identified("T0LEGAL".to_string()),
            ),
        ]);
        assert_eq!(fold_outcomes(&admit, &outcomes), ResolverOutcome::Ambiguous);
    }

    #[test]
    fn fold_all_unsupported_is_no_impl() {
        let admit = admit_from(vec![endpoint_typed("teams", "28:legal", &["b1"])]);
        let outcomes = HashMap::from([("teams".to_string(), IdentifyOutcome::Unsupported)]);
        assert_eq!(fold_outcomes(&admit, &outcomes), ResolverOutcome::NoImpl);
    }

    #[test]
    fn fold_mixed_identified_plus_unsupported_is_hit() {
        // One pack identified, another type's component never exported the
        // world. The identified hit still wins — `Unsupported` is the floor.
        let teams = endpoint_typed("teams", "28:legal", &["b1"]);
        let slack = endpoint_typed("slack", "T0LEGAL", &["b1"]);
        let teams_eid = teams.endpoint_id.to_string();
        let admit = admit_from(vec![teams, slack]);
        let outcomes = HashMap::from([
            (
                "teams".to_string(),
                IdentifyOutcome::Identified("28:legal".to_string()),
            ),
            ("slack".to_string(), IdentifyOutcome::Unsupported),
        ]);
        assert_eq!(
            fold_outcomes(&admit, &outcomes),
            ResolverOutcome::Hit(teams_eid)
        );
    }

    #[test]
    fn fold_mixed_no_match_plus_unsupported_is_miss_when_singletons() {
        let admit = admit_from(vec![
            endpoint_typed("teams", "28:legal", &["b1"]),
            endpoint_typed("slack", "T0LEGAL", &["b1"]),
        ]);
        let outcomes = HashMap::from([
            ("teams".to_string(), IdentifyOutcome::NoMatch),
            ("slack".to_string(), IdentifyOutcome::Unsupported),
        ]);
        assert_eq!(fold_outcomes(&admit, &outcomes), ResolverOutcome::Miss);
    }
}
