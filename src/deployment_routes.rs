//! Request → deployment routing for the revision dispatcher (B3 producer).
//!
//! Maps an inbound `(host, path)` to the `(deployment_id, tenant)` the revision
//! dispatcher should route under, using each Active
//! [`BundleDeployment`](greentic_deploy_spec::BundleDeployment)'s
//! `route_binding`. Built from a materialized
//! [`Environment`](greentic_deploy_spec::Environment); consumed by the ingress
//! `resolve_deployment` seam in [`crate::http_ingress`].
//!
//! Public traffic cannot pick a deployment: the binding `(host, path-prefix) →
//! deployment_id` is operator-owned data on the environment, and a request that
//! matches no binding takes the legacy single-bundle path (returns `None`).

use std::collections::BTreeMap;
use std::sync::Arc;

use greentic_deploy_spec::{BundleDeploymentStatus, BundleId, DeploymentId, Environment};
use serde_json::Value as JsonValue;

use crate::http_routes::HttpRouteTable;
use crate::revision_dispatcher::RevisionDispatcher;
use crate::static_routes::ActiveRouteTable;

/// Per-deployment, per-pack non-secret config overrides projected from each
/// active `BundleDeployment.config_overrides` (D.4). Outer key is the
/// deployment id, NOT the bundle id — two deployments can bind the same
/// bundle with different per-customer overrides (multi-tenant SaaS,
/// blue/green rollouts), and keying on bundle would silently drop one set.
/// Next level is the bundle-relative pack id slug; inner map is
/// `{config_field → JSON value}`. The egress path consults this table to
/// inject overrides into `SendPayloadInV1.config` before each `send_payload`
/// invocation — see [`crate::messaging_egress::build_send_payload`] and
/// [`crate::messaging_egress::pack_config_overrides_as_json`].
///
/// Non-Active deployments are skipped to match
/// [`DeploymentRouteTable::from_environment`]: if a deployment is not
/// routable, its overrides are not reachable at egress time either.
pub type DeploymentConfigOverrides =
    BTreeMap<DeploymentId, BTreeMap<String, BTreeMap<String, JsonValue>>>;

/// Build a [`DeploymentConfigOverrides`] from an `Environment`. See the type
/// alias for the keying and Active-only filter rationale.
pub fn deployment_config_overrides_from_environment(
    env: &Environment,
) -> DeploymentConfigOverrides {
    env.bundles
        .iter()
        .filter(|dep| dep.status == BundleDeploymentStatus::Active)
        .filter(|dep| !dep.config_overrides.is_empty())
        .map(|dep| (dep.deployment_id, dep.config_overrides.clone()))
        .collect()
}

/// One Active deployment's public route binding, in matchable form.
#[derive(Clone, Debug)]
struct DeploymentRoute {
    deployment_id: DeploymentId,
    bundle_id: BundleId,
    tenant: String,
    /// Lowercased host names this deployment answers for. Empty = any host.
    hosts: Vec<String>,
    /// Normalized path prefixes (leading `/`, no trailing `/` except root).
    /// Empty = matches any path (treated as the root prefix `/`).
    path_prefixes: Vec<String>,
}

impl DeploymentRoute {
    /// Build a route from raw binding data, applying host (trim + lowercase,
    /// drop empties) and path-prefix normalization. Single normalization site
    /// shared by [`DeploymentRouteTable::from_environment`] and the test
    /// constructor, so they cannot drift.
    fn new(
        deployment_id: DeploymentId,
        bundle_id: BundleId,
        tenant: String,
        hosts: &[String],
        path_prefixes: &[String],
    ) -> Self {
        Self {
            deployment_id,
            bundle_id,
            tenant,
            hosts: hosts
                .iter()
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
            path_prefixes: path_prefixes.iter().map(|p| normalize_prefix(p)).collect(),
        }
    }

    /// `true` when this route answers for `host`. An empty `hosts` list matches
    /// any host (including a request with no `Host` header); a non-empty list
    /// requires the request to carry a host that is in the list.
    fn host_matches(&self, host: Option<&str>) -> bool {
        if self.hosts.is_empty() {
            return true;
        }
        match host {
            Some(h) => self.hosts.iter().any(|candidate| candidate == h),
            None => false,
        }
    }

    /// Specificity (matched prefix length) of the most specific path prefix that
    /// is a segment-boundary prefix of `path`, or `None` if none match. An empty
    /// `path_prefixes` list matches any path at the lowest specificity (root).
    fn path_prefix_len(&self, path: &str) -> Option<usize> {
        if self.path_prefixes.is_empty() {
            return Some(1); // root "/" — least specific.
        }
        self.path_prefixes
            .iter()
            .filter_map(|prefix| path_prefix_match_len(path, prefix))
            .max()
    }
}

/// Operator-materialized map of public routes to deployments. Built from the
/// environment's Active bundle deployments; non-Active deployments are not
/// routable and are skipped.
#[derive(Clone, Debug, Default)]
pub struct DeploymentRouteTable {
    routes: Vec<DeploymentRoute>,
}

impl DeploymentRouteTable {
    /// Build from an environment's Active bundle deployments.
    pub fn from_environment(env: &Environment) -> Self {
        let routes = env
            .bundles
            .iter()
            .filter(|dep| dep.status == BundleDeploymentStatus::Active)
            .map(|dep| {
                DeploymentRoute::new(
                    dep.deployment_id,
                    dep.bundle_id.clone(),
                    dep.route_binding.tenant_selector.tenant.clone(),
                    &dep.route_binding.hosts,
                    &dep.route_binding.path_prefixes,
                )
            })
            .collect();
        Self { routes }
    }

    /// Number of routable (Active) deployments.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Test-only: build a table directly from `(deployment_id, tenant, hosts,
    /// path_prefixes)` tuples, applying the same host/prefix normalization as
    /// [`Self::from_environment`]. Lets other modules' tests exercise routing
    /// without constructing a full `Environment`.
    #[cfg(test)]
    #[allow(clippy::type_complexity)]
    pub(crate) fn from_parts(
        parts: Vec<(DeploymentId, BundleId, String, Vec<String>, Vec<String>)>,
    ) -> Self {
        let routes = parts
            .into_iter()
            .map(|(deployment_id, bundle_id, tenant, hosts, path_prefixes)| {
                DeploymentRoute::new(deployment_id, bundle_id, tenant, &hosts, &path_prefixes)
            })
            .collect();
        Self { routes }
    }

    /// Tenant bound to `deployment_id` in this table, or `None` if no Active
    /// deployment with that id exists. Used by
    /// [`crate::revision_serve::RevisionServer::reload`] to look up the
    /// owning tenant of a revision that's about to be drained — the dispatcher
    /// itself doesn't carry tenant, since each `DispatchRequest` brings its own.
    pub(crate) fn tenant_for(&self, deployment_id: DeploymentId) -> Option<&str> {
        self.routes
            .iter()
            .find(|r| r.deployment_id == deployment_id)
            .map(|r| r.tenant.as_str())
    }

    /// Resolve `(host, path)` to `(deployment_id, tenant)`.
    ///
    /// Host match is case-insensitive; an empty `hosts` binding matches any
    /// host. Path match is a segment-boundary prefix; an empty `path_prefixes`
    /// binding matches any path. The most specific (longest) matching path
    /// prefix wins. On a tie the first deployment in environment order wins —
    /// the operator rejects ambiguous bindings at deploy time, so a tie is not
    /// expected at runtime, but the resolution stays deterministic regardless.
    pub fn resolve(&self, host: Option<&str>, path: &str) -> Option<(DeploymentId, &str)> {
        let host = host.map(|h| host_without_port(h).to_ascii_lowercase());
        let mut best: Option<(&DeploymentRoute, usize)> = None;
        for route in &self.routes {
            if !route.host_matches(host.as_deref()) {
                continue;
            }
            let Some(len) = route.path_prefix_len(path) else {
                continue;
            };
            if best.is_none_or(|(_, best_len)| len > best_len) {
                best = Some((route, len));
            }
        }
        best.map(|(route, _)| (route.deployment_id, route.tenant.as_str()))
    }

    /// Find the first Active deployment whose `(tenant, bundle_id)` matches.
    /// Returns the deployment id. Used by [`crate::webchat_routing::BundleIndex`]
    /// to resolve a bundle segment in a webchat URL to the deployment it belongs
    /// to.
    pub(crate) fn resolve_by_bundle(&self, tenant: &str, bundle_id: &str) -> Option<DeploymentId> {
        self.routes
            .iter()
            .find(|r| r.tenant == tenant && r.bundle_id.as_str() == bundle_id)
            .map(|r| r.deployment_id)
    }

    /// Resolve a deployment for a worker-invoke call, which carries a tenant but
    /// no `(host, path)` to match on.
    ///
    /// Prefers an exact tenant match against an Active deployment's
    /// `tenant_selector`. When none matches but exactly one deployment is bound,
    /// fall back to that lone deployment regardless of the caller's tenant label
    /// — the common single-app local case, where a GUI gateway's default tenant
    /// (e.g. `tenant-default`) need not be hand-aligned with the deployment's
    /// tenant for the worker contract to work out of the box. With two or more
    /// deployments and no tenant match the result is `None` (ambiguous).
    ///
    /// Returns the deployment id paired with the deployment's OWN tenant, so the
    /// caller executes under the tenant the revision was loaded with, not the
    /// (possibly mismatched) tenant the request asserted.
    pub(crate) fn resolve_worker(&self, tenant: &str) -> Option<(DeploymentId, &str)> {
        if let Some(route) = self.routes.iter().find(|r| r.tenant == tenant) {
            return Some((route.deployment_id, route.tenant.as_str()));
        }
        if self.routes.len() == 1 {
            let route = &self.routes[0];
            return Some((route.deployment_id, route.tenant.as_str()));
        }
        None
    }
}

/// The revision-routing artifacts threaded into the ingress when booting from a
/// materialized runtime-config (B3 producer wiring). A dispatcher with no route
/// tables cannot serve, so the four travel together to enforce that invariant
/// at the type level: the ingress is either fully revision-routed or fully
/// legacy, never half-wired.
pub struct RevisionIngressRouting {
    /// Per-deployment traffic-split selector built from the runtime-config.
    pub dispatcher: Arc<RevisionDispatcher>,
    /// Revision-scoped HTTP routes (`scope = Some(..)`) discovered per loaded
    /// revision, matched via [`HttpRouteTable::match_request_for_revision`].
    pub http_routes: HttpRouteTable,
    /// `(host, path) → (deployment_id, tenant)` map for the resolve step.
    pub deployment_routes: DeploymentRouteTable,
    /// M1.4c-ii admit table: per-endpoint `linked_bundles` ACL consulted when
    /// a request carries `x-greentic-messaging-endpoint-id`. Travels with the
    /// other routing artifacts so a reload swaps them as one coherent unit.
    pub endpoint_admit: Arc<crate::endpoint_admit::EndpointAdmit>,
    /// See [`DeploymentConfigOverrides`]. `Arc` so the override map outlives
    /// the routing-table swap a reload performs — the egress reads it on
    /// every reply.
    pub deployment_config_overrides: Arc<DeploymentConfigOverrides>,
    /// Revision-scoped static routes (`scope = Some(..)`) discovered per
    /// loaded revision, matched via
    /// [`ActiveRouteTable::match_request_for_revision`].
    pub static_routes: ActiveRouteTable,
    /// Webchat bundle index: tenant -> Active deployments, with pre-resolved
    /// default-bundle per tenant. Built from the same `Environment` as
    /// `deployment_routes`.
    pub(crate) bundle_index: crate::webchat_routing::BundleIndex,
    /// Webchat flow index: bundle_id -> set of flow ids. Built from pack
    /// manifests read during the activation loop.
    pub(crate) flow_index: crate::webchat_routing::FlowIndex,
}

/// Strip a trailing `:port` from a host header value. IPv6 literals are bracketed
/// (`[::1]:8080`), so only treat the last `:` as a port separator when the value
/// has no unbracketed colon ambiguity; for the common `host:port` case this is a
/// plain rsplit.
fn host_without_port(host: &str) -> &str {
    if host.starts_with('[') {
        // `[::1]:8080` → `[::1]`; `[::1]` → `[::1]`.
        return match host.split_once(']') {
            Some((addr, _rest)) => &host[..addr.len() + 1],
            None => host,
        };
    }
    match host.rsplit_once(':') {
        Some((h, _port)) => h,
        None => host,
    }
}

/// Normalize a configured path prefix: collapse leading slashes to a single
/// `/`, drop any trailing `/` (except for the root prefix itself). Collapsing
/// the leading slash matters because a request path from hyper always has a
/// single leading `/`, so a binding like `//api` would otherwise never match.
fn normalize_prefix(prefix: &str) -> String {
    let core = prefix.trim().trim_start_matches('/');
    let with_lead = format!("/{core}");
    let no_trail = with_lead.trim_end_matches('/');
    if no_trail.is_empty() {
        "/".to_string()
    } else {
        no_trail.to_string()
    }
}

/// If `prefix` is a segment-boundary prefix of `path`, return its specificity
/// (the prefix length); otherwise `None`. The root prefix `/` matches every
/// path at the lowest specificity (length 1).
fn path_prefix_match_len(path: &str, prefix: &str) -> Option<usize> {
    if prefix == "/" {
        return Some(1);
    }
    if path == prefix {
        return Some(prefix.len());
    }
    // Segment boundary: `/api` matches `/api/x` but not `/apixyz`.
    if path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/') {
        return Some(prefix.len());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::{
        BundleDeployment, BundleId, CustomerId, EnvironmentHostConfig, PartyId, RevenueShareEntry,
        RouteBinding, SchemaVersion, TenantSelector,
    };
    use greentic_types::EnvId;
    use std::path::PathBuf;

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn deployment(
        deployment_id: DeploymentId,
        tenant: &str,
        hosts: &[&str],
        prefixes: &[&str],
        status: BundleDeploymentStatus,
    ) -> BundleDeployment {
        BundleDeployment {
            schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
            deployment_id,
            env_id: env_id(),
            bundle_id: BundleId::new("fast2flow"),
            customer_id: CustomerId::new("cust"),
            status,
            current_revisions: Vec::new(),
            route_binding: RouteBinding {
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
                path_prefixes: prefixes.iter().map(|p| p.to_string()).collect(),
                tenant_selector: TenantSelector {
                    tenant: tenant.to_string(),
                    team: "default".to_string(),
                },
            },
            revenue_share: vec![RevenueShareEntry {
                party_id: PartyId::new("greentic"),
                basis_points: 10_000,
            }],
            revenue_policy_ref: PathBuf::from("revenue.json"),
            usage: None,
            created_at: chrono::Utc::now(),
            authorization_ref: PathBuf::from("auth.json"),
            config_overrides: BTreeMap::new(),
        }
    }

    fn env(bundles: Vec<BundleDeployment>) -> Environment {
        Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id(),
            name: "local".to_string(),
            host_config: EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
                default_bundle: None,
            },
            packs: Vec::new(),
            messaging_endpoints: Vec::new(),
            extensions: Vec::new(),
            credentials_ref: None,
            bundles,
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        }
    }

    #[test]
    fn skips_non_active_deployments() {
        let active = DeploymentId::new();
        let table = DeploymentRouteTable::from_environment(&env(vec![
            deployment(
                active,
                "acme",
                &[],
                &["/active"],
                BundleDeploymentStatus::Active,
            ),
            deployment(
                DeploymentId::new(),
                "paused",
                &[],
                &["/paused"],
                BundleDeploymentStatus::Paused,
            ),
        ]));
        assert_eq!(table.len(), 1);
        assert_eq!(table.resolve(None, "/active/x"), Some((active, "acme")));
        assert!(table.resolve(None, "/paused/x").is_none());
    }

    #[test]
    fn empty_binding_matches_any_host_and_path() {
        let id = DeploymentId::new();
        let table = DeploymentRouteTable::from_environment(&env(vec![deployment(
            id,
            "acme",
            &[],
            &[],
            BundleDeploymentStatus::Active,
        )]));
        assert_eq!(
            table.resolve(Some("anything.example.com"), "/anywhere"),
            Some((id, "acme"))
        );
        assert_eq!(table.resolve(None, "/"), Some((id, "acme")));
    }

    #[test]
    fn host_binding_requires_matching_host() {
        let id = DeploymentId::new();
        let table = DeploymentRouteTable::from_environment(&env(vec![deployment(
            id,
            "acme",
            &["acme.example.com"],
            &[],
            BundleDeploymentStatus::Active,
        )]));
        // Case-insensitive + port-stripped.
        assert!(table.resolve(Some("ACME.example.com:8080"), "/").is_some());
        // Wrong host.
        assert!(table.resolve(Some("other.example.com"), "/").is_none());
        // Host binding present but request carries no host → fail closed.
        assert!(table.resolve(None, "/").is_none());
    }

    #[test]
    fn longest_path_prefix_wins() {
        let root = DeploymentId::new();
        let api = DeploymentId::new();
        let table = DeploymentRouteTable::from_environment(&env(vec![
            deployment(root, "root", &[], &["/"], BundleDeploymentStatus::Active),
            deployment(
                api,
                "api",
                &[],
                &["/api/v1"],
                BundleDeploymentStatus::Active,
            ),
        ]));
        // Most specific prefix wins.
        assert_eq!(table.resolve(None, "/api/v1/things"), Some((api, "api")));
        // Falls back to root for unrelated paths.
        assert_eq!(table.resolve(None, "/other"), Some((root, "root")));
    }

    #[test]
    fn prefix_matches_on_segment_boundary_only() {
        let id = DeploymentId::new();
        let table = DeploymentRouteTable::from_environment(&env(vec![deployment(
            id,
            "acme",
            &[],
            &["/api"],
            BundleDeploymentStatus::Active,
        )]));
        assert!(table.resolve(None, "/api").is_some());
        assert!(table.resolve(None, "/api/v1").is_some());
        // `/apixyz` must NOT match the `/api` prefix.
        assert!(table.resolve(None, "/apixyz").is_none());
    }

    #[test]
    fn no_match_returns_none() {
        let table = DeploymentRouteTable::from_environment(&env(vec![deployment(
            DeploymentId::new(),
            "acme",
            &[],
            &["/app"],
            BundleDeploymentStatus::Active,
        )]));
        assert!(table.resolve(None, "/different").is_none());
    }

    #[test]
    fn resolve_worker_prefers_exact_tenant_then_falls_back_to_lone_deployment() {
        let only = DeploymentId::new();
        let single = DeploymentRouteTable::from_environment(&env(vec![deployment(
            only,
            "default",
            &[],
            &[],
            BundleDeploymentStatus::Active,
        )]));
        // Exact tenant match.
        assert_eq!(single.resolve_worker("default"), Some((only, "default")));
        // No tenant match, but a lone deployment ⇒ fall back to it, returning
        // the deployment's OWN tenant ("default"), not the asserted one.
        assert_eq!(
            single.resolve_worker("tenant-default"),
            Some((only, "default"))
        );

        // Two deployments: exact match resolves, an unknown tenant is ambiguous.
        let acme = DeploymentId::new();
        let beta = DeploymentId::new();
        let multi = DeploymentRouteTable::from_environment(&env(vec![
            deployment(
                acme,
                "acme",
                &[],
                &["/acme"],
                BundleDeploymentStatus::Active,
            ),
            deployment(
                beta,
                "beta",
                &[],
                &["/beta"],
                BundleDeploymentStatus::Active,
            ),
        ]));
        assert_eq!(multi.resolve_worker("beta"), Some((beta, "beta")));
        assert!(multi.resolve_worker("nobody").is_none());
    }

    #[test]
    fn host_without_port_handles_ipv6_and_plain() {
        assert_eq!(host_without_port("host:8080"), "host");
        assert_eq!(host_without_port("host"), "host");
        assert_eq!(host_without_port("[::1]:8080"), "[::1]");
        assert_eq!(host_without_port("[::1]"), "[::1]");
    }

    #[test]
    fn normalize_prefix_canonicalizes() {
        assert_eq!(normalize_prefix("api"), "/api");
        assert_eq!(normalize_prefix("/api/"), "/api");
        assert_eq!(normalize_prefix("/"), "/");
        assert_eq!(normalize_prefix(""), "/");
        // Collapse repeated leading slashes — a request path always has exactly
        // one, so "//api" must normalize to "/api" or it would never match.
        assert_eq!(normalize_prefix("//api"), "/api");
        assert_eq!(normalize_prefix("///"), "/");
    }

    fn deployment_with_overrides(
        id: DeploymentId,
        bundle: &str,
        status: BundleDeploymentStatus,
        overrides: BTreeMap<String, BTreeMap<String, JsonValue>>,
    ) -> BundleDeployment {
        let mut dep = deployment(id, "acme", &[], &["/"], status);
        dep.bundle_id = BundleId::new(bundle);
        dep.config_overrides = overrides;
        dep
    }

    #[test]
    fn deployment_config_overrides_project_active_only() {
        // Active deployment's per-pack map is projected; paused deployment's is dropped.
        let mut active_packs = BTreeMap::new();
        active_packs.insert(
            "telegram-pack".to_string(),
            BTreeMap::from([(
                "api_base_url".to_string(),
                JsonValue::String("https://staging.example.com".to_string()),
            )]),
        );
        let mut paused_packs = BTreeMap::new();
        paused_packs.insert(
            "slack-pack".to_string(),
            BTreeMap::from([(
                "channel".to_string(),
                JsonValue::String("#stale".to_string()),
            )]),
        );
        let live_id = DeploymentId::new();
        let frozen_id = DeploymentId::new();
        let env = env(vec![
            deployment_with_overrides(
                live_id,
                "live",
                BundleDeploymentStatus::Active,
                active_packs.clone(),
            ),
            deployment_with_overrides(
                frozen_id,
                "frozen",
                BundleDeploymentStatus::Paused,
                paused_packs,
            ),
        ]);

        let table = deployment_config_overrides_from_environment(&env);
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&live_id), Some(&active_packs));
        assert!(!table.contains_key(&frozen_id));
    }

    #[test]
    fn deployment_config_overrides_keep_distinct_overrides_for_shared_bundle() {
        // Codex adversarial finding: two active deployments of the SAME bundle
        // must keep distinct override sets. Earlier the projection keyed on
        // `BundleId` and `.collect()` dropped one side, which would have let
        // `run_reply_egress` ship deployment A's replies with deployment B's
        // egress config (multi-tenant SaaS, blue/green rollouts).
        let pack_id = "telegram-pack";
        let dep_a = DeploymentId::new();
        let dep_b = DeploymentId::new();
        let overrides_a = BTreeMap::from([(
            pack_id.to_string(),
            BTreeMap::from([(
                "api_base_url".to_string(),
                JsonValue::String("https://a.example.com".to_string()),
            )]),
        )]);
        let overrides_b = BTreeMap::from([(
            pack_id.to_string(),
            BTreeMap::from([(
                "api_base_url".to_string(),
                JsonValue::String("https://b.example.com".to_string()),
            )]),
        )]);
        let env = env(vec![
            deployment_with_overrides(
                dep_a,
                "shared-bundle",
                BundleDeploymentStatus::Active,
                overrides_a,
            ),
            deployment_with_overrides(
                dep_b,
                "shared-bundle",
                BundleDeploymentStatus::Active,
                overrides_b,
            ),
        ]);

        let table = deployment_config_overrides_from_environment(&env);
        assert_eq!(table.len(), 2, "each deployment must contribute a row");

        let config_a =
            crate::messaging_egress::pack_config_overrides_as_json(&table, dep_a, pack_id)
                .expect("deployment A must keep its own overrides");
        let config_b =
            crate::messaging_egress::pack_config_overrides_as_json(&table, dep_b, pack_id)
                .expect("deployment B must keep its own overrides");
        assert_eq!(config_a["api_base_url"], "https://a.example.com");
        assert_eq!(config_b["api_base_url"], "https://b.example.com");
    }

    #[test]
    fn deployment_config_overrides_drop_empty_maps() {
        // An Active deployment with an empty override map contributes nothing
        // to the projection — saves an allocation in the common "no overrides
        // configured" case.
        let env = env(vec![deployment_with_overrides(
            DeploymentId::new(),
            "live",
            BundleDeploymentStatus::Active,
            BTreeMap::new(),
        )]);
        let table = deployment_config_overrides_from_environment(&env);
        assert!(table.is_empty());
    }
}
