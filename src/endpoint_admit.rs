//! M1.4c-ii admit-gate table: the projection of
//! [`Environment::messaging_endpoints`](greentic_deploy_spec::Environment) that
//! the revision ingress consults when a request carries a
//! `x-greentic-messaging-endpoint-id` header.
//!
//! M1.4c-i started receiving that header in [`crate::revision_serve`] and
//! threading it through to the runtime context, but accepted any value. This
//! module turns the header into a real authorization gate by answering one
//! question per request: *given the endpoint id the caller claims, is the
//! resolved deployment's bundle in that endpoint's `linked_bundles` ACL?*
//!
//! See `greentic-deploy-spec::messaging_endpoint` on why `linked_bundles` is
//! an ACL rather than a deployment selector — the runtime resolves the
//! concrete [`BundleDeployment`](greentic_deploy_spec::BundleDeployment) via
//! existing route binding + traffic-split routing first, and only then asks
//! this table whether that bundle is reachable through the asserted endpoint.
//!
//! The empty-table case (env declares no messaging endpoints) intentionally
//! fail-closes every header-asserted request: declaring an endpoint is the
//! one and only way to opt in.
//!
//! Composition with the rest of the serve pipeline is two-step but a *single*
//! conceptual gate:
//!
//! 1. Before dispatch we look the endpoint up — unknown endpoint ⇒ refuse the
//!    request cheaply with `UNAUTHORIZED` and don't waste a dispatch on it.
//! 2. After the dispatcher picks a revision we check membership of
//!    `outcome.bundle_id` in the ACL — outside-of-ACL ⇒ `FORBIDDEN`.
//!
//! Requests without the header take neither branch and stay on the legacy
//! single-instance path (back-compat for environments that never adopt M1).

use std::collections::{HashMap, HashSet};

use greentic_deploy_spec::{BundleId, Environment, SecretRef, WelcomeFlowRef};

/// The per-endpoint state the revision ingress needs at request time:
/// the `linked_bundles` ACL plus the M1.5 welcome-flow ref (if declared) plus
/// the optional [`webhook_secret_ref`] for IID-by-secret matching. Co-locating
/// these prevents drift between parallel maps keyed on the same endpoint id.
///
/// [`webhook_secret_ref`]: greentic_deploy_spec::MessagingEndpoint::webhook_secret_ref
#[derive(Clone, Debug)]
struct EndpointEntry {
    linked_bundles: HashSet<String>,
    /// [`MessagingEndpoint::welcome_flow`](greentic_deploy_spec::MessagingEndpoint::welcome_flow)
    /// cloned in so the lookup is one map. Read by the producer at
    /// `revision_serve::serve` to build the per-request `WelcomeFlowHint`.
    welcome_flow: Option<WelcomeFlowRef>,
    /// [`MessagingEndpoint::webhook_secret_ref`](greentic_deploy_spec::MessagingEndpoint::webhook_secret_ref)
    /// — `secret://` URI the runtime resolves through the env's secrets backend
    /// to the actual webhook secret value. `Some(_)` means this endpoint
    /// participates in webhook-secret auth (Telegram `setup_webhook` installs
    /// the resolved value as `secret_token`; the auth gate constant-time
    /// compares the inbound `x-telegram-bot-api-secret-token` header against
    /// it). `None` means the endpoint stays on the legacy posture where
    /// `provider_id` is the discriminator-and-authenticator.
    webhook_secret_ref: Option<SecretRef>,
}

/// Per-endpoint ACL projection of `Environment.messaging_endpoints` consulted
/// by the revision ingress; see the module docs.
#[derive(Clone, Debug, Default)]
pub struct EndpointAdmit {
    /// Key: the on-wire `endpoint_id` form (the same string the caller asserts
    /// in `x-greentic-messaging-endpoint-id`, which matches
    /// `MessagingEndpointId::to_string`).
    by_id: HashMap<String, EndpointEntry>,
    /// Two-level index: `provider_type → provider_id → endpoint_id`. Drives
    /// the M1 IID.4 resolver: when a request arrives without
    /// `x-greentic-messaging-endpoint-id`, the host invokes each enabled
    /// provider component's `identify-instance` export; the returned
    /// `provider_id` is paired with the resolver's known `provider_type` and
    /// looked up here to recover the matching `endpoint_id`.
    ///
    /// Nested over a flat `(String, String)` key map because:
    /// * Two-step lookup borrows on `&str` directly, no per-call allocation.
    /// * `provider_types()` is the outer map's keys.
    /// * `endpoint_count_for_provider_type(t)` is the inner map's `.len()` —
    ///   the separate count field this replaced is redundant.
    ///
    /// (`provider_type`, `provider_id`) uniqueness is an
    /// [`Environment::validate`](greentic_deploy_spec::Environment::validate)
    /// invariant, so duplicates can't reach this table.
    by_provider_type: HashMap<String, HashMap<String, String>>,
}

impl EndpointAdmit {
    /// Build an admit table from the env's declared endpoints. Each endpoint's
    /// `linked_bundles` is materialized as a `HashSet<String>` so membership
    /// checks at request time are O(1) regardless of ACL size.
    pub fn from_environment(env: &Environment) -> Self {
        let mut by_id = HashMap::with_capacity(env.messaging_endpoints.len());
        let mut by_provider_type: HashMap<String, HashMap<String, String>> = HashMap::new();
        for ep in &env.messaging_endpoints {
            let endpoint_id = ep.endpoint_id.to_string();
            by_id.insert(
                endpoint_id.clone(),
                EndpointEntry {
                    linked_bundles: ep
                        .linked_bundles
                        .iter()
                        .map(|b| b.as_str().to_string())
                        .collect(),
                    welcome_flow: ep.welcome_flow.clone(),
                    webhook_secret_ref: ep.webhook_secret_ref.clone(),
                },
            );
            by_provider_type
                .entry(ep.provider_type.clone())
                .or_default()
                .insert(ep.provider_id.clone(), endpoint_id);
        }
        Self {
            by_id,
            by_provider_type,
        }
    }

    /// Look up the on-wire `endpoint_id` for a `(provider_type, provider_id)`
    /// pair. Used by the M1 IID.4 resolver to recover an `endpoint_id` from a
    /// `provider_id` returned by a component's `identify-instance` probe.
    pub(crate) fn endpoint_id_for_provider(
        &self,
        provider_type: &str,
        provider_id: &str,
    ) -> Option<&str> {
        self.by_provider_type
            .get(provider_type)
            .and_then(|m| m.get(provider_id))
            .map(String::as_str)
    }

    /// Iterate over the distinct `provider_type` values declared in this env.
    /// The resolver uses this to pick which provider components to probe per
    /// request (one probe per type, not per endpoint).
    pub(crate) fn provider_types(&self) -> impl Iterator<Item = &str> {
        self.by_provider_type.keys().map(String::as_str)
    }

    /// Number of endpoints declared for `provider_type`. ≥2 means a missing
    /// header MUST fail closed when the resolver cannot disambiguate.
    pub(crate) fn endpoint_count_for_provider_type(&self, provider_type: &str) -> usize {
        self.by_provider_type
            .get(provider_type)
            .map(HashMap::len)
            .unwrap_or(0)
    }

    /// Look up the ACL set for `endpoint_id`. `None` means *this env has never
    /// declared that endpoint* — the caller MUST refuse the request, not fall
    /// through to the legacy path. The set itself may be empty (a declared but
    /// unwired endpoint), in which case any subsequent bundle check rejects.
    pub fn linked_bundles(&self, endpoint_id: &str) -> Option<&HashSet<String>> {
        self.by_id.get(endpoint_id).map(|e| &e.linked_bundles)
    }

    /// Iterate `(endpoint_id, provider_type, webhook_secret_ref)` for every
    /// endpoint whose [`webhook_secret_ref`] is `Some(_)`. Drives the
    /// [`dispatch_provider_route`] auth gate: callers filter by provider
    /// class via [`derive_provider_name`] (so a route descriptor
    /// `messaging.telegram.bot` matches a stored endpoint `telegram`) and
    /// then resolve each ref through the secrets manager. Endpoints without
    /// a ref are skipped — they stay on the legacy posture and do not opt
    /// into the gate.
    ///
    /// Returning `provider_type` here keeps `EndpointAdmit` a pure
    /// projection: it carries no knowledge of `derive_provider_name`'s
    /// canonicalization rules, and consumers that don't care about class
    /// (e.g. iterating all secret-bearing endpoints for a metrics export)
    /// can use the same iterator.
    ///
    /// [`webhook_secret_ref`]: MessagingEndpoint::webhook_secret_ref
    /// [`dispatch_provider_route`]: crate::revision_serve
    /// [`derive_provider_name`]: crate::http_routes::derive_provider_name
    pub(crate) fn endpoints_with_webhook_secret_ref(
        &self,
    ) -> impl Iterator<Item = (&str, &str, &SecretRef)> + '_ {
        self.by_provider_type
            .iter()
            .flat_map(|(provider_type, ids)| {
                ids.values()
                    .map(move |eid| (provider_type.as_str(), eid.as_str()))
            })
            .filter_map(|(provider_type, eid)| {
                self.by_id
                    .get(eid)
                    .and_then(|e| e.webhook_secret_ref.as_ref())
                    .map(|ref_| (eid, provider_type, ref_))
            })
    }

    /// Look up the raw M1.5 welcome-flow ref for `endpoint_id`, if the
    /// endpoint is declared AND has `welcome_flow` set. Returns `None` for
    /// both unknown endpoints and known-but-unset welcome flows — the
    /// producer cannot distinguish those at this site because
    /// [`linked_bundles`] has already classified unknowns as `UNAUTHORIZED`
    /// upstream.
    ///
    /// Most callers want [`welcome_flow_for_bundle`]; this raw lookup is
    /// kept for projection-level tests.
    ///
    /// [`linked_bundles`]: EndpointAdmit::linked_bundles
    /// [`welcome_flow_for_bundle`]: EndpointAdmit::welcome_flow_for_bundle
    pub(crate) fn welcome_flow(&self, endpoint_id: &str) -> Option<&WelcomeFlowRef> {
        self.by_id
            .get(endpoint_id)
            .and_then(|e| e.welcome_flow.as_ref())
    }

    /// Look up the welcome-flow ref for `endpoint_id` **only when the
    /// dispatched bundle matches the welcome ref's bundle**. Returns `None`
    /// when the endpoint is unknown, has no welcome ref, OR dispatched into
    /// a sibling bundle.
    ///
    /// The deploy-spec only invariant is `welcome_flow.bundle_id ∈
    /// linked_bundles`, NOT that dispatch lands on the welcome bundle.
    /// Endpoints can `linked_bundles` more than one bundle, and dispatch
    /// picks one via traffic splits / pins. Crossing bundles would target
    /// the welcome bundle's pack/flow on a sibling bundle's revision —
    /// either misroute (pack-id collision) or 500 (pack absent).
    pub(crate) fn welcome_flow_for_bundle(
        &self,
        endpoint_id: &str,
        dispatched_bundle: &BundleId,
    ) -> Option<&WelcomeFlowRef> {
        self.welcome_flow(endpoint_id)
            .filter(|ref_| &ref_.bundle_id == dispatched_bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{
        endpoint, endpoint_typed, env_with, telegram_endpoint_with_webhook_secret,
    };
    use greentic_deploy_spec::{BundleId, PackId};

    #[test]
    fn empty_env_yields_empty_table() {
        let admit = EndpointAdmit::from_environment(&env_with(Vec::new()));
        assert!(admit.linked_bundles("anything").is_none());
    }

    #[test]
    fn endpoint_lookup_keys_on_endpoint_id_string() {
        let ep = endpoint("teams-legal", &["legal-bundle", "shared-utils"]);
        let id = ep.endpoint_id.to_string();
        let admit = EndpointAdmit::from_environment(&env_with(vec![ep]));

        let bundles = admit
            .linked_bundles(&id)
            .expect("declared endpoint should resolve");
        assert!(bundles.contains("legal-bundle"));
        assert!(bundles.contains("shared-utils"));
        assert!(!bundles.contains("finance-bundle"));
    }

    #[test]
    fn endpoint_with_empty_acl_is_known_but_never_admits() {
        let ep = endpoint("teams-bare", &[]);
        let id = ep.endpoint_id.to_string();
        let admit = EndpointAdmit::from_environment(&env_with(vec![ep]));

        let bundles = admit
            .linked_bundles(&id)
            .expect("declared endpoint must resolve even with empty ACL");
        assert!(bundles.is_empty());
    }

    #[test]
    fn unknown_endpoint_id_returns_none() {
        let admit =
            EndpointAdmit::from_environment(&env_with(vec![endpoint("teams-legal", &["legal"])]));
        assert!(admit.linked_bundles("bogus-endpoint-id").is_none());
        assert!(admit.linked_bundles("").is_none());
    }

    #[test]
    fn welcome_flow_lookup_returns_ref_when_declared() {
        let mut ep = endpoint("teams-legal", &["legal-bundle"]);
        ep.welcome_flow = Some(WelcomeFlowRef {
            bundle_id: BundleId::new("legal-bundle"),
            pack_id: PackId::new("legal-pack"),
            flow_id: "welcome".to_string(),
        });
        let id = ep.endpoint_id.to_string();
        let admit = EndpointAdmit::from_environment(&env_with(vec![ep]));

        let ref_ = admit.welcome_flow(&id).expect("welcome ref present");
        assert_eq!(ref_.bundle_id.as_str(), "legal-bundle");
        assert_eq!(ref_.pack_id.as_str(), "legal-pack");
        assert_eq!(ref_.flow_id, "welcome");
    }

    #[test]
    fn welcome_flow_lookup_returns_none_when_unset() {
        // Both shapes that lack a welcome flow collapse to None at this site:
        // an unknown endpoint AND a known endpoint whose `welcome_flow` is None.
        // The unknown-vs-unset distinction belongs upstream at `linked_bundles`,
        // which has already refused the unknown case with `UNAUTHORIZED`.
        let ep = endpoint("teams-legal", &["legal-bundle"]); // welcome_flow: None
        let id = ep.endpoint_id.to_string();
        let admit = EndpointAdmit::from_environment(&env_with(vec![ep]));

        assert!(admit.welcome_flow(&id).is_none());
        assert!(admit.welcome_flow("bogus-endpoint-id").is_none());
    }

    #[test]
    fn endpoint_id_for_provider_returns_matching_endpoint() {
        let teams_legal = endpoint_typed("teams", "28:legal-bot", &["legal-bundle"]);
        let teams_accounting = endpoint_typed("teams", "28:acct-bot", &["acct-bundle"]);
        let slack = endpoint_typed("slack", "T0LEGAL", &["legal-bundle"]);
        let (legal_id, acct_id, slack_id) = (
            teams_legal.endpoint_id.to_string(),
            teams_accounting.endpoint_id.to_string(),
            slack.endpoint_id.to_string(),
        );
        let admit =
            EndpointAdmit::from_environment(&env_with(vec![teams_legal, teams_accounting, slack]));

        assert_eq!(
            admit.endpoint_id_for_provider("teams", "28:legal-bot"),
            Some(legal_id.as_str())
        );
        assert_eq!(
            admit.endpoint_id_for_provider("teams", "28:acct-bot"),
            Some(acct_id.as_str())
        );
        assert_eq!(
            admit.endpoint_id_for_provider("slack", "T0LEGAL"),
            Some(slack_id.as_str())
        );
    }

    #[test]
    fn endpoint_id_for_provider_returns_none_on_cross_type_or_unknown_id() {
        let admit = EndpointAdmit::from_environment(&env_with(vec![endpoint_typed(
            "teams",
            "28:legal-bot",
            &["legal-bundle"],
        )]));

        // Wrong type (Slack key against Teams entry).
        assert!(
            admit
                .endpoint_id_for_provider("slack", "28:legal-bot")
                .is_none()
        );
        // Right type, unknown provider_id.
        assert!(
            admit
                .endpoint_id_for_provider("teams", "28:unknown")
                .is_none()
        );
        // Empty inputs.
        assert!(admit.endpoint_id_for_provider("", "").is_none());
    }

    #[test]
    fn endpoint_counts_by_provider_type_reflect_declared_endpoints() {
        let admit = EndpointAdmit::from_environment(&env_with(vec![
            endpoint_typed("teams", "28:a", &["b1"]),
            endpoint_typed("teams", "28:b", &["b2"]),
            endpoint_typed("slack", "T0", &["b1"]),
        ]));

        assert_eq!(admit.endpoint_count_for_provider_type("teams"), 2);
        assert_eq!(admit.endpoint_count_for_provider_type("slack"), 1);
        assert_eq!(admit.endpoint_count_for_provider_type("telegram"), 0);

        let mut types: Vec<&str> = admit.provider_types().collect();
        types.sort_unstable();
        assert_eq!(types, vec!["slack", "teams"]);
    }

    #[test]
    fn endpoints_with_webhook_secret_ref_surfaces_only_endpoints_that_have_one() {
        let telegram_with = telegram_endpoint_with_webhook_secret("tg-legal", &["legal"]);
        let telegram_without = endpoint_typed("telegram", "tg-acct", &["acct"]);
        let teams_with = {
            // Distinct provider_type so the caller's `derive_provider_name`
            // filter is the source of truth for "telegram-class" — the
            // iterator itself is class-agnostic.
            let mut t = telegram_endpoint_with_webhook_secret("teams-bot", &["legal"]);
            t.provider_type = "teams".to_string();
            t
        };
        let tg_with_id = telegram_with.endpoint_id.to_string();
        let teams_with_id = teams_with.endpoint_id.to_string();
        let admit = EndpointAdmit::from_environment(&env_with(vec![
            telegram_with,
            telegram_without,
            teams_with,
        ]));

        let mut surfaced: Vec<(String, String)> = admit
            .endpoints_with_webhook_secret_ref()
            .map(|(eid, pt, _)| (eid.to_string(), pt.to_string()))
            .collect();
        surfaced.sort();
        let mut expected = vec![
            (tg_with_id, "telegram".to_string()),
            (teams_with_id, "teams".to_string()),
        ];
        expected.sort();
        assert_eq!(surfaced, expected);
    }

    #[test]
    fn welcome_flow_for_bundle_returns_ref_only_when_bundle_matches() {
        let mut ep = endpoint("teams-legal", &["bundle-a", "bundle-b"]);
        ep.welcome_flow = Some(WelcomeFlowRef {
            bundle_id: BundleId::new("bundle-b"),
            pack_id: PackId::new("legal-pack"),
            flow_id: "welcome".to_string(),
        });
        let id = ep.endpoint_id.to_string();
        let admit = EndpointAdmit::from_environment(&env_with(vec![ep]));

        // Dispatch to the welcome bundle ⇒ ref returned.
        let hit = admit
            .welcome_flow_for_bundle(&id, &BundleId::new("bundle-b"))
            .expect("ref present");
        assert_eq!(hit.bundle_id.as_str(), "bundle-b");

        // Dispatch to a sibling bundle ⇒ None (cross-bundle hint would
        // target B's pack/flow on A's revision).
        assert!(
            admit
                .welcome_flow_for_bundle(&id, &BundleId::new("bundle-a"))
                .is_none()
        );

        // Unknown endpoint ⇒ None regardless of bundle.
        assert!(
            admit
                .welcome_flow_for_bundle("bogus-endpoint-id", &BundleId::new("bundle-b"))
                .is_none()
        );
    }
}
