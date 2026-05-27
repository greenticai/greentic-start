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

use std::sync::Arc;

use greentic_deploy_spec::{BundleDeploymentStatus, DeploymentId, Environment};

use crate::http_routes::HttpRouteTable;
use crate::revision_dispatcher::RevisionDispatcher;

/// One Active deployment's public route binding, in matchable form.
#[derive(Clone, Debug)]
struct DeploymentRoute {
    deployment_id: DeploymentId,
    tenant: String,
    /// Lowercased host names this deployment answers for. Empty = any host.
    hosts: Vec<String>,
    /// Normalized path prefixes (leading `/`, no trailing `/` except root).
    /// Empty = matches any path (treated as the root prefix `/`).
    path_prefixes: Vec<String>,
}

impl DeploymentRoute {
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
            .map(|dep| DeploymentRoute {
                deployment_id: dep.deployment_id,
                tenant: dep.route_binding.tenant_selector.tenant.clone(),
                hosts: dep
                    .route_binding
                    .hosts
                    .iter()
                    .map(|h| h.trim().to_ascii_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect(),
                path_prefixes: dep
                    .route_binding
                    .path_prefixes
                    .iter()
                    .map(|p| normalize_prefix(p))
                    .collect(),
            })
            .collect();
        Self { routes }
    }

    /// Number of routable (Active) deployments.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Resolve `(host, path)` to `(deployment_id, tenant)`.
    ///
    /// Host match is case-insensitive; an empty `hosts` binding matches any
    /// host. Path match is a segment-boundary prefix; an empty `path_prefixes`
    /// binding matches any path. The most specific (longest) matching path
    /// prefix wins. On a tie the first deployment in environment order wins —
    /// the operator rejects ambiguous bindings at deploy time, so a tie is not
    /// expected at runtime, but the resolution stays deterministic regardless.
    pub fn resolve(&self, host: Option<&str>, path: &str) -> Option<(DeploymentId, String)> {
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
        best.map(|(route, _)| (route.deployment_id, route.tenant.clone()))
    }
}

/// The revision-routing artifacts threaded into the ingress when booting from a
/// materialized runtime-config (B3 producer wiring). A dispatcher with no route
/// tables cannot serve, so the three travel together to enforce that invariant
/// at the type level: the ingress is either fully revision-routed or fully
/// legacy, never half-wired.
#[derive(Clone)]
pub struct RevisionIngressRouting {
    /// Per-deployment traffic-split selector built from the runtime-config.
    pub dispatcher: Arc<RevisionDispatcher>,
    /// Revision-scoped HTTP routes (`scope = Some(..)`) discovered per loaded
    /// revision, matched via [`HttpRouteTable::match_request_for_revision`].
    pub http_routes: HttpRouteTable,
    /// `(host, path) → (deployment_id, tenant)` map for the resolve step.
    pub deployment_routes: DeploymentRouteTable,
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

/// Normalize a configured path prefix: ensure a single leading `/`, drop any
/// trailing `/` (except for the root prefix itself).
fn normalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim();
    let with_lead = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
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
            },
            packs: Vec::new(),
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
        assert_eq!(
            table.resolve(None, "/active/x"),
            Some((active, "acme".to_string()))
        );
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
            Some((id, "acme".to_string()))
        );
        assert_eq!(table.resolve(None, "/"), Some((id, "acme".to_string())));
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
        assert_eq!(
            table.resolve(None, "/api/v1/things"),
            Some((api, "api".to_string()))
        );
        // Falls back to root for unrelated paths.
        assert_eq!(
            table.resolve(None, "/other"),
            Some((root, "root".to_string()))
        );
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
    }
}
