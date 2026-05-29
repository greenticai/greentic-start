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

/// Per-endpoint ACL projection of `Environment.messaging_endpoints` consulted
/// by the revision ingress; see the module docs.
#[derive(Clone, Debug, Default)]
pub struct EndpointAdmit {
    /// Key: the on-wire `endpoint_id` form (the same string the caller asserts
    /// in `x-greentic-messaging-endpoint-id`, which matches
    /// `MessagingEndpointId::to_string`). Value: the bundle ids the endpoint
    /// is permitted to route to, as raw strings so the dispatch outcome can be
    /// checked without rebuilding a typed id at the hot path.
    by_id: HashMap<String, HashSet<String>>,
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
                let bundles = ep
                    .linked_bundles
                    .iter()
                    .map(|b| b.as_str().to_string())
                    .collect();
                (ep.endpoint_id.to_string(), bundles)
            })
            .collect();
        Self { by_id }
    }

    /// Look up the ACL set for `endpoint_id`. `None` means *this env has never
    /// declared that endpoint* — the caller MUST refuse the request, not fall
    /// through to the legacy path. The set itself may be empty (a declared but
    /// unwired endpoint), in which case any subsequent bundle check rejects.
    pub fn linked_bundles(&self, endpoint_id: &str) -> Option<&HashSet<String>> {
        self.by_id.get(endpoint_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::{
        BundleId, EnvironmentHostConfig, MessagingEndpoint, MessagingEndpointId, SchemaVersion,
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
    fn distinct_endpoints_keep_disjoint_acls() {
        let legal = endpoint("teams-legal", &["legal-bundle"]);
        let finance = endpoint("teams-finance", &["finance-bundle"]);
        let legal_id = legal.endpoint_id.to_string();
        let finance_id = finance.endpoint_id.to_string();
        let admit = EndpointAdmit::from_environment(&env_with(vec![legal, finance]));

        assert!(
            admit
                .linked_bundles(&legal_id)
                .unwrap()
                .contains("legal-bundle")
        );
        assert!(
            !admit
                .linked_bundles(&legal_id)
                .unwrap()
                .contains("finance-bundle")
        );
        assert!(
            admit
                .linked_bundles(&finance_id)
                .unwrap()
                .contains("finance-bundle")
        );
        assert!(
            !admit
                .linked_bundles(&finance_id)
                .unwrap()
                .contains("legal-bundle")
        );
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
}
