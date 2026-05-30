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

use greentic_deploy_spec::Environment;

/// The per-endpoint state the revision ingress needs at request time:
/// the `linked_bundles` ACL plus the M1.5 welcome-flow ref (if declared).
/// Co-locating these prevents drift between two parallel maps keyed on the
/// same endpoint id.
#[derive(Clone, Debug)]
struct EndpointEntry {
    linked_bundles: HashSet<String>,
    /// `(bundle_id, pack_id, flow_id)` from
    /// [`MessagingEndpoint::welcome_flow`](greentic_deploy_spec::MessagingEndpoint::welcome_flow),
    /// strung so the hot path doesn't rebuild typed ids. Read by the producer
    /// at `revision_serve::serve` when the M1.5 first-contact attach flips on
    /// (gated on the runner-host welcome-seen marker landing in a follow-up
    /// PR — Codex adversarial review of greentic-start#201). Until then the
    /// projection is dead at runtime; tests still exercise the lookup.
    #[allow(dead_code)]
    welcome_flow: Option<WelcomeFlowEntry>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // Read in tests; producer wiring lands in the follow-up PR (see EndpointEntry).
pub(crate) struct WelcomeFlowEntry {
    pub(crate) bundle_id: String,
    pub(crate) pack_id: String,
    pub(crate) flow_id: String,
}

/// Per-endpoint ACL projection of `Environment.messaging_endpoints` consulted
/// by the revision ingress; see the module docs.
#[derive(Clone, Debug, Default)]
pub struct EndpointAdmit {
    /// Key: the on-wire `endpoint_id` form (the same string the caller asserts
    /// in `x-greentic-messaging-endpoint-id`, which matches
    /// `MessagingEndpointId::to_string`).
    by_id: HashMap<String, EndpointEntry>,
}

impl EndpointAdmit {
    /// Build an admit table from the env's declared endpoints. Each endpoint's
    /// `linked_bundles` is materialized as a `HashSet<String>` so membership
    /// checks at request time are O(1) regardless of ACL size.
    pub fn from_environment(env: &Environment) -> Self {
        let by_id = env
            .messaging_endpoints
            .iter()
            .map(|ep| {
                let entry = EndpointEntry {
                    linked_bundles: ep
                        .linked_bundles
                        .iter()
                        .map(|b| b.as_str().to_string())
                        .collect(),
                    welcome_flow: ep.welcome_flow.as_ref().map(|w| WelcomeFlowEntry {
                        bundle_id: w.bundle_id.as_str().to_string(),
                        pack_id: w.pack_id.as_str().to_string(),
                        flow_id: w.flow_id.clone(),
                    }),
                };
                (ep.endpoint_id.to_string(), entry)
            })
            .collect();
        Self { by_id }
    }

    /// Look up the ACL set for `endpoint_id`. `None` means *this env has never
    /// declared that endpoint* — the caller MUST refuse the request, not fall
    /// through to the legacy path. The set itself may be empty (a declared but
    /// unwired endpoint), in which case any subsequent bundle check rejects.
    pub fn linked_bundles(&self, endpoint_id: &str) -> Option<&HashSet<String>> {
        self.by_id.get(endpoint_id).map(|e| &e.linked_bundles)
    }

    /// Look up the M1.5 welcome-flow ref for `endpoint_id`, if the endpoint is
    /// declared AND has `welcome_flow` set. Returns `None` for both unknown
    /// endpoints and known-but-unset welcome flows — the producer cannot
    /// distinguish those at this site because [`linked_bundles`] has already
    /// classified unknowns as `UNAUTHORIZED` upstream.
    ///
    /// Currently unused at runtime; tests exercise the lookup. Re-wired into
    /// `revision_serve::serve` once the runner-host welcome-seen marker lands
    /// (see the [`EndpointEntry::welcome_flow`] doc).
    ///
    /// [`linked_bundles`]: EndpointAdmit::linked_bundles
    #[allow(dead_code)]
    pub(crate) fn welcome_flow(&self, endpoint_id: &str) -> Option<&WelcomeFlowEntry> {
        self.by_id
            .get(endpoint_id)
            .and_then(|e| e.welcome_flow.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::{
        BundleId, EnvironmentHostConfig, MessagingEndpoint, MessagingEndpointId, PackId,
        SchemaVersion, WelcomeFlowRef,
    };
    use greentic_types::EnvId;

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn endpoint(provider_id: &str, bundles: &[&str]) -> MessagingEndpoint {
        let now = chrono::Utc::now();
        MessagingEndpoint {
            schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
            env_id: env_id(),
            endpoint_id: MessagingEndpointId::new(),
            provider_id: provider_id.to_string(),
            provider_type: "teams".to_string(),
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

    fn env_with(endpoints: Vec<MessagingEndpoint>) -> Environment {
        Environment {
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
        }
    }

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
        assert_eq!(ref_.bundle_id, "legal-bundle");
        assert_eq!(ref_.pack_id, "legal-pack");
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
}
