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

use std::collections::HashMap;
use std::sync::Arc;

use greentic_runner_host::RunnerHost;
use greentic_runner_host::identify_hint::IdentifyInstanceHint;
use greentic_runner_host::pack::IdentifyOutcome;
use serde_json::Value;

use crate::endpoint_admit::EndpointAdmit;
use crate::http_routes::RevisionScope;

/// The decision the resolver hands back to the serve pipeline.
///
/// `Hit`/`Miss`/`Ambiguous`/`NoImpl` are mutually exclusive results of a
/// real probe; `HeaderWins`/`Skipped`/`PublicSkipped` are the three
/// short-circuit paths that never invoked the host. The call site decides
/// HTTP status / telemetry attribution; this enum carries the *raw*
/// decision, not its policy translation.
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
    /// The request arrived from a non-loopback peer without a trusted header.
    /// Running the resolver on untrusted traffic would let a forged webhook
    /// payload drive endpoint derivation (a remote caller posting a
    /// discriminator that the provider component identifies as "Teams Bot X"
    /// would get sessions/welcome-flows for that endpoint). Kept distinct
    /// from `Skipped` so operators can distinguish "env declares no
    /// endpoints" from "we refused to run the resolver on untrusted traffic".
    PublicSkipped,
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
            ResolverOutcome::PublicSkipped => "public-skipped",
        }
    }

    /// Convenience for the serve site: the resolved eid (if any) that should
    /// be threaded into the activity. `HeaderWins`/`Hit` return `Some`;
    /// `Miss`/`Ambiguous`/`NoImpl`/`Skipped`/`PublicSkipped` return `None`.
    /// `Ambiguous` is `None` here because the call site is expected to refuse
    /// the request before reaching the activity.
    pub(crate) fn endpoint_id(&self) -> Option<&str> {
        match self {
            ResolverOutcome::HeaderWins(eid) | ResolverOutcome::Hit(eid) => Some(eid.as_str()),
            _ => None,
        }
    }
}

/// Determine whether the resolver should probe provider components or
/// short-circuit. Extracted as a pure helper for testability (no
/// [`RunnerHost`] needed).
///
/// Returns `Some(outcome)` when we can decide without running the host,
/// `None` when a probe is needed.
fn should_probe(
    peer_is_loopback: bool,
    header_eid: Option<&str>,
    provider_types_count: usize,
) -> Option<ResolverOutcome> {
    if let Some(eid) = header_eid {
        return Some(ResolverOutcome::HeaderWins(eid.to_string()));
    }
    // Trust boundary: the resolver is a parallel trust-derivation mechanism
    // to `caller_identity`'s header path. A remote caller must not be able
    // to drive endpoint derivation via a forged webhook payload — only
    // loopback peers (greentic-messaging or the operator CLI) are trusted
    // originators.
    if !peer_is_loopback {
        return Some(ResolverOutcome::PublicSkipped);
    }
    if provider_types_count == 0 {
        return Some(ResolverOutcome::Skipped);
    }
    None
}

/// Preflight header scoping: if ALL probed `provider_type`s are hinted
/// (the `describe_identify_instances_for_revision` map returns `Some(hint)`
/// for every key), the caller's `headers` pass through unchanged — the
/// runner-host's per-provider scoping narrows them further at wrapper-build
/// time. If ANY type is unhinted (`None`), headers are stripped to an empty
/// list. This prevents the runner-host's back-compat pass-through
/// (`None => headers.iter().collect()` in `build_scoped_identify_payload`)
/// from leaking allowlisted headers (e.g. the Telegram secret token) to
/// sibling providers that have no use for them.
///
/// Returns the (possibly empty) header list, plus the set of unhinted
/// `provider_type` names (empty when all hinted). The caller uses the
/// unhinted set for the one-per-probe warning log.
fn scope_headers_to_hinted(
    headers: Vec<(String, String)>,
    hints: &HashMap<String, Option<IdentifyInstanceHint>>,
) -> (Vec<(String, String)>, Vec<String>) {
    let unhinted: Vec<String> = hints
        .iter()
        .filter(|(_, hint)| hint.is_none())
        .map(|(provider_type, _)| provider_type.clone())
        .collect();
    if unhinted.is_empty() {
        (headers, unhinted)
    } else {
        (Vec::new(), unhinted)
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
/// `peer_is_loopback` carries the same trust-boundary signal that
/// `revision_serve::caller_identity` uses: only loopback peers are allowed to
/// drive endpoint derivation. When the header is absent and the peer is NOT
/// loopback, the resolver short-circuits to [`ResolverOutcome::PublicSkipped`]
/// without invoking any provider component (a remote caller posting a forged
/// payload must not be able to claim an endpoint it doesn't own).
///
/// `scope` MUST be the post-dispatch revision tuple — the host method loads
/// the revision's pack runtime by exactly `(deployment_id, bundle_id,
/// revision_id)`. Reusing the `RevisionScope` the call site already built
/// for the admit gate keeps the resolver's argument list short and binds
/// the dispatched revision to the resolver call by construction.
///
/// `build_headers_body` produces the structured `(headers, body)` pair the
/// per-provider wrapper is built from inside the runner host. It is invoked
/// LAZILY — only after [`should_probe`] confirms the resolver will actually
/// run a WASM probe. Public traffic, header-pinned eid, and no-endpoint envs
/// all short-circuit before the body Value is cloned.
///
/// The runner-host `_scoped` variant builds the wrapper PER PROVIDER from
/// each component's cached `describe-identify-instance` hint: hinted
/// components receive ONLY the headers their hint declares; unhinted
/// components receive every header passed in (back-compat). To close that
/// back-compat leak at the greentic-start altitude, the resolver preflights
/// hint coverage via
/// [`RunnerHost::describe_identify_instances_for_revision`]: when ANY probed
/// provider is unhinted, headers are stripped to empty BEFORE calling the
/// scoped variant. All-hinted revisions keep their headers. This ensures
/// header-discriminated providers (Telegram via
/// `x-telegram-bot-api-secret-token`) MUST ship hints to receive headers,
/// and unhinted siblings never see them.
///
/// Returns the [`ResolverOutcome`] for the serve site to act on. Component
/// traps / infrastructure errors bubble as `Err`; the caller distinguishes
/// "no identification" (a clean variant) from "the host couldn't even run
/// the probe" (an error).
pub(crate) async fn resolve<F>(
    host: &Arc<RunnerHost>,
    tenant: &str,
    scope: &RevisionScope,
    admit: &EndpointAdmit,
    header_eid: Option<&str>,
    peer_is_loopback: bool,
    build_headers_body: F,
) -> anyhow::Result<ResolverOutcome>
where
    F: FnOnce() -> (Vec<(String, String)>, Value),
{
    let provider_types: Vec<&str> = admit.provider_types().collect();
    if let Some(outcome) = should_probe(peer_is_loopback, header_eid, provider_types.len()) {
        return Ok(outcome);
    }

    // Preflight: discover which probed provider_types have a
    // describe-identify-instance hint. Unhinted providers would receive ALL
    // passed headers via the runner-host's back-compat path — strip headers
    // to empty when any provider is unhinted so secrets don't leak across
    // sibling providers.
    let hints = host
        .describe_identify_instances_for_revision(
            tenant,
            scope.deployment_id,
            scope.bundle_id.clone(),
            scope.revision_id,
            &provider_types,
        )
        .await?;

    let (headers, body) = build_headers_body();
    let (scoped_headers, unhinted) = scope_headers_to_hinted(headers, &hints);

    if !unhinted.is_empty() {
        tracing::warn!(
            target: "greentic_start::endpoint_resolver",
            unhinted_providers = ?unhinted,
            "headers stripped for identify-instance probe: provider(s) lack a \
             describe-identify-instance hint — add a hint to receive secret-token headers"
        );
    }

    let outcomes = host
        .identify_messaging_endpoints_for_revision_scoped(
            tenant,
            scope.deployment_id,
            scope.bundle_id.clone(),
            scope.revision_id,
            &provider_types,
            &scoped_headers,
            &body,
        )
        .await?;

    Ok(fold_outcomes(admit, &outcomes))
}

/// Pure folding step extracted for testability. Walks the per-`provider_type`
/// outcomes and decides between Hit / Miss / Ambiguous / NoImpl per the rules
/// described on [`ResolverOutcome`]. Pulled out of [`resolve`] so it can be
/// unit-tested without a running [`RunnerHost`].
///
/// Tracks three signals:
/// * `hit` — `Some(eid)` after the first known-identified outcome; setting it
///   twice (two different types both identified to known eids) poisons to
///   `Ambiguous`. (Endpoint ids are env-unique, so two hits are always two
///   distinct eids — no dedup needed.)
/// * `poison` — any signal that requires `Ambiguous` regardless of other
///   outcomes: a second hit, an `Identified(unknown_provider_id)`, or a
///   `NoMatch` for a `provider_type` with ≥2 declared endpoints.
/// * `any_non_unsupported` — at least one type returned `NoMatch` or
///   `Identified`, distinguishing `Miss` from `NoImpl`.
fn fold_outcomes(
    admit: &EndpointAdmit,
    outcomes: &std::collections::HashMap<String, IdentifyOutcome>,
) -> ResolverOutcome {
    let mut hit: Option<String> = None;
    let mut poison = false;
    let mut any_non_unsupported = false;

    for (provider_type, outcome) in outcomes {
        match outcome {
            IdentifyOutcome::Identified(provider_id) => {
                any_non_unsupported = true;
                match admit.endpoint_id_for_provider(provider_type, provider_id) {
                    Some(eid) => {
                        if hit.is_some() {
                            poison = true;
                        }
                        hit = Some(eid.to_string());
                    }
                    None => {
                        // The component explicitly identified a concrete
                        // `provider_id` that the env never declared as an
                        // endpoint. Because the resolver only probes
                        // `provider_type`s where the admit table declares ≥1
                        // endpoint, this always means either operational
                        // drift (a bot the env doesn't know about) or a
                        // forged payload. Both fail closed — silently
                        // dropping to Miss would let the request run as
                        // legacy unscoped traffic, asymmetric with the
                        // header path's 401 on unknown eid.
                        poison = true;
                    }
                }
            }
            IdentifyOutcome::NoMatch => {
                any_non_unsupported = true;
                // ≥2 endpoints of this type AND the component said "none of
                // them" — we cannot disambiguate by other means, fail closed.
                if admit.endpoint_count_for_provider_type(provider_type) >= 2 {
                    poison = true;
                }
            }
            IdentifyOutcome::Unsupported => {
                // `Unsupported` is the lattice floor; any other outcome
                // outranks it. If every type stays here, the components
                // never exported the world.
            }
        }
    }

    if poison {
        return ResolverOutcome::Ambiguous;
    }
    if let Some(eid) = hit {
        return ResolverOutcome::Hit(eid);
    }
    if any_non_unsupported {
        return ResolverOutcome::Miss;
    }
    ResolverOutcome::NoImpl
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{endpoint_typed, env_with};
    use greentic_deploy_spec::MessagingEndpoint;
    use std::collections::HashMap;

    fn admit_from(endpoints: Vec<MessagingEndpoint>) -> EndpointAdmit {
        EndpointAdmit::from_environment(&env_with(endpoints))
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
        assert_eq!(ResolverOutcome::PublicSkipped.origin(), "public-skipped");
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
        assert!(ResolverOutcome::PublicSkipped.endpoint_id().is_none());
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
    fn fold_identified_unknown_provider_id_is_ambiguous() {
        // The component explicitly identified a concrete provider_id that the
        // env never declared. Because the resolver only probes provider_types
        // with >=1 declared endpoint, this always means operational drift (a
        // bot the env doesn't know about) or a forged payload. Failing closed
        // keeps the trust boundary symmetric with the header path (unknown
        // header eid -> 401).
        let admit = admit_from(vec![endpoint_typed("teams", "28:known", &["b"])]);
        let outcomes = HashMap::from([(
            "teams".to_string(),
            IdentifyOutcome::Identified("28:unknown-drift".to_string()),
        )]);
        assert_eq!(fold_outcomes(&admit, &outcomes), ResolverOutcome::Ambiguous);
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

    #[test]
    fn fold_known_hit_plus_unknown_identified_is_ambiguous() {
        // One type returns Identified(known) -> hit, another returns
        // Identified(unknown) -> the unknown one poisons the result. Even
        // though we have a clean hit from teams, the slack component
        // identifying an undeclared bot is a strong signal that the env's
        // endpoint declarations are stale or the payload is forged. Fail
        // closed.
        let teams = endpoint_typed("teams", "28:legal", &["b1"]);
        let slack = endpoint_typed("slack", "T0LEGAL", &["b1"]);
        let admit = admit_from(vec![teams, slack]);
        let outcomes = HashMap::from([
            (
                "teams".to_string(),
                IdentifyOutcome::Identified("28:legal".to_string()),
            ),
            (
                "slack".to_string(),
                IdentifyOutcome::Identified("UNDECLARED-BOT".to_string()),
            ),
        ]);
        assert_eq!(fold_outcomes(&admit, &outcomes), ResolverOutcome::Ambiguous);
    }

    #[test]
    fn should_probe_header_wins_short_circuits() {
        let outcome = should_probe(true, Some("teams-legal"), 3);
        assert_eq!(
            outcome,
            Some(ResolverOutcome::HeaderWins("teams-legal".into()))
        );
    }

    #[test]
    fn should_probe_public_peer_without_header_short_circuits() {
        // Non-loopback peer with no header must not drive the resolver —
        // a forged webhook payload must not derive an endpoint.
        let outcome = should_probe(false, None, 3);
        assert_eq!(outcome, Some(ResolverOutcome::PublicSkipped));
    }

    #[test]
    fn should_probe_loopback_with_endpoints_proceeds() {
        // Loopback peer, no header, declared endpoints -> probe needed.
        let outcome = should_probe(true, None, 2);
        assert!(outcome.is_none());
    }

    #[test]
    fn should_probe_loopback_no_endpoints_skips() {
        // Loopback peer but env declares no endpoints -> Skipped.
        let outcome = should_probe(true, None, 0);
        assert_eq!(outcome, Some(ResolverOutcome::Skipped));
    }

    #[test]
    fn should_probe_public_peer_with_header_still_wins() {
        // Even on public traffic, an asserted header wins (the header path
        // is independently gated by caller_identity — only loopback peers
        // get header_eid=Some). This test documents that should_probe
        // doesn't double-gate the header path.
        let outcome = should_probe(false, Some("teams-legal"), 3);
        assert_eq!(
            outcome,
            Some(ResolverOutcome::HeaderWins("teams-legal".into()))
        );
    }

    // -- scope_headers_to_hinted pure-helper tests --

    fn make_hint(header_names: &[&str]) -> IdentifyInstanceHint {
        use greentic_runner_host::identify_hint::HintSource;
        IdentifyInstanceHint {
            sources: header_names
                .iter()
                .map(|name| HintSource::Header {
                    name: (*name).to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn scope_headers_passes_through_when_all_provider_types_hinted() {
        let headers = vec![(
            "x-telegram-bot-api-secret-token".to_string(),
            "tok".to_string(),
        )];
        let hints = HashMap::from([
            (
                "telegram".to_string(),
                Some(make_hint(&["x-telegram-bot-api-secret-token"])),
            ),
            ("teams".to_string(), Some(make_hint(&[]))),
        ]);
        let (out, unhinted) = scope_headers_to_hinted(headers.clone(), &hints);
        assert!(unhinted.is_empty());
        assert_eq!(out, headers, "all-hinted should pass headers through");
    }

    #[test]
    fn scope_headers_drops_all_when_any_provider_type_unhinted() {
        let headers = vec![(
            "x-telegram-bot-api-secret-token".to_string(),
            "tok".to_string(),
        )];
        let hints = HashMap::from([
            (
                "telegram".to_string(),
                Some(make_hint(&["x-telegram-bot-api-secret-token"])),
            ),
            ("slack".to_string(), None), // unhinted
        ]);
        let (out, unhinted) = scope_headers_to_hinted(headers, &hints);
        assert_eq!(unhinted, vec!["slack".to_string()]);
        assert!(out.is_empty(), "any unhinted type should strip all headers");
    }

    #[test]
    fn scope_headers_drops_all_when_no_hints_at_all() {
        // Simulates an old revision where no provider ships a hint.
        let headers = vec![(
            "x-telegram-bot-api-secret-token".to_string(),
            "tok".to_string(),
        )];
        let hints = HashMap::from([
            ("telegram".to_string(), None),
            ("slack".to_string(), None),
            ("webex".to_string(), None),
        ]);
        let (out, unhinted) = scope_headers_to_hinted(headers, &hints);
        assert_eq!(unhinted.len(), 3);
        assert!(
            out.is_empty(),
            "fully unhinted env should strip all headers"
        );
    }
}
