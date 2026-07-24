//! Webchat bundle-scoped URL routing primitives.
//!
//! Implements the URL grammar that multiplexes multiple bundles (each
//! potentially shipping a webchat GUI) on a single tenant, and maps each
//! inbound path to the `(deployment_id, bundle_id)` that should serve it.
//!
//! The classification runs BEFORE the revision dispatcher, so it sees only the
//! raw URL path. It never opens a pack manifest or reads disk — all lookups
//! go through pre-built indices ([`BundleIndex`], [`FlowIndex`]) that are
//! rebuilt on every runtime-config hot-swap alongside the rest of
//! [`crate::deployment_routes::RevisionIngressRouting`].

use std::collections::{HashMap, HashSet};

use greentic_deploy_spec::{BundleId, DefaultBundleReason, DeploymentId, Environment};

use crate::deployment_routes::DeploymentRouteTable;

// ── reserved path segments ──────────────────────────────────────────

/// Segments that can never be a bundle id or flow id. A segment immediately
/// after `{tenant}` (or after `{bundle_id}`) that matches one of these is
/// treated as a DirectLine API path rather than a bundle/flow selector.
const RESERVED_SEGMENTS: &[&str] = &["token", "v3", "oauth"];

fn is_reserved(segment: &str) -> bool {
    RESERVED_SEGMENTS
        .iter()
        .any(|r| r.eq_ignore_ascii_case(segment))
}

// ── BundleIndex ─────────────────────────────────────────────────────

/// Pre-resolved default bundle for a tenant.
#[derive(Clone, Debug)]
struct DefaultResolution {
    deployment_id: DeploymentId,
    bundle_id: BundleId,
    reason: DefaultBundleReason,
}

/// Per-tenant index of Active bundle deployments. Built from
/// [`DeploymentRouteTable`] (which carries `bundle_id` on each route entry)
/// and [`Environment`] (for default-bundle resolution via
/// [`Environment::resolve_default_bundle`]).
///
/// Rebuilt on every runtime-config hot-swap alongside the other routing
/// artifacts in [`crate::deployment_routes::RevisionIngressRouting`].
#[derive(Clone, Debug)]
pub(crate) struct BundleIndex {
    /// Set of known bundle-id strings per tenant, for O(1) disambiguation.
    bundles: HashMap<String, HashSet<String>>,
    /// Pre-resolved default bundle per tenant, computed once at build time.
    defaults: HashMap<String, DefaultResolution>,
}

impl BundleIndex {
    /// An empty index for test harnesses that do not exercise webchat routing.
    #[allow(dead_code)] // used by test_fixtures and downstream test harnesses
    pub(crate) fn empty() -> Self {
        Self {
            bundles: HashMap::new(),
            defaults: HashMap::new(),
        }
    }

    /// Build from the route table (carries `bundle_id` per Active deployment)
    /// and the environment (for default-bundle resolution).
    pub(crate) fn from_routes_and_env(_routes: &DeploymentRouteTable, env: &Environment) -> Self {
        // Collect all distinct tenants from the route table.
        let mut bundles: HashMap<String, HashSet<String>> = HashMap::new();
        let mut tenants: HashSet<String> = HashSet::new();

        // Iterate all routes to harvest (tenant, bundle_id) pairs.
        // DeploymentRouteTable does not expose a full iterator, so we probe
        // each tenant discovered via resolve_worker or tenant_for. Instead,
        // enumerate the environment's Active deployments directly — same
        // source the route table was built from.
        for dep in &env.bundles {
            if dep.status != greentic_deploy_spec::BundleDeploymentStatus::Active {
                continue;
            }
            let tenant = &dep.route_binding.tenant_selector.tenant;
            tenants.insert(tenant.clone());
            bundles
                .entry(tenant.clone())
                .or_default()
                .insert(dep.bundle_id.as_str().to_string());
        }

        // Pre-resolve the default bundle for each tenant.
        let mut defaults = HashMap::new();
        for tenant in &tenants {
            if let Some((dep, reason)) = env.resolve_default_bundle(tenant) {
                let resolution = DefaultResolution {
                    deployment_id: dep.deployment_id,
                    bundle_id: dep.bundle_id.clone(),
                    reason,
                };
                match reason {
                    DefaultBundleReason::ExplicitConfig => {
                        tracing::info!(
                            tenant,
                            bundle_id = %dep.bundle_id,
                            "default bundle for tenant resolved via explicit config"
                        );
                    }
                    DefaultBundleReason::LoneActive => {
                        tracing::debug!(
                            tenant,
                            bundle_id = %dep.bundle_id,
                            "default bundle for tenant resolved: lone active deployment"
                        );
                    }
                    DefaultBundleReason::NewestActive => {
                        tracing::debug!(
                            tenant,
                            bundle_id = %dep.bundle_id,
                            "default bundle for tenant resolved: newest active deployment"
                        );
                    }
                    _ => {
                        tracing::debug!(
                            tenant,
                            bundle_id = %dep.bundle_id,
                            ?reason,
                            "default bundle for tenant resolved"
                        );
                    }
                }
                defaults.insert(tenant.clone(), resolution);
            }
        }

        Self { bundles, defaults }
    }

    /// Whether `segment` is a known bundle id for `tenant`.
    pub(crate) fn is_bundle(&self, tenant: &str, segment: &str) -> bool {
        self.bundles
            .get(tenant)
            .is_some_and(|set| set.contains(segment))
    }

    /// Look up the Active deployment for `(tenant, bundle_id)`.
    pub(crate) fn resolve(
        &self,
        routes: &DeploymentRouteTable,
        tenant: &str,
        bundle_id: &str,
    ) -> Option<DeploymentId> {
        routes.resolve_by_bundle(tenant, bundle_id)
    }

    /// The pre-resolved default bundle for `tenant`.
    pub(crate) fn default_for(
        &self,
        tenant: &str,
    ) -> Option<(DeploymentId, &BundleId, DefaultBundleReason)> {
        self.defaults
            .get(tenant)
            .map(|d| (d.deployment_id, &d.bundle_id, d.reason))
    }

    /// Resolve the `--open-webchat=BUNDLE_ID` URL, respecting an optional
    /// `--tenant` constraint. Returns `(tenant, ambiguous)` where `ambiguous`
    /// is `true` when multiple tenants hold the bundle and no `--tenant` was
    /// given (the caller should warn).
    pub(crate) fn resolve_open_webchat_bundle(
        &self,
        bundle_id: &str,
        tenant_filter: Option<&str>,
    ) -> Option<(&str, bool)> {
        // Collect tenants that hold this bundle, sorted for determinism.
        let mut matching_tenants: Vec<&str> = self
            .bundles
            .iter()
            .filter(|(tenant, set)| {
                let has = set.contains(bundle_id);
                match tenant_filter {
                    Some(t) => has && tenant.as_str() == t,
                    None => has,
                }
            })
            .map(|(tenant, _)| tenant.as_str())
            .collect();
        matching_tenants.sort_unstable();
        let ambiguous = matching_tenants.len() > 1 && tenant_filter.is_none();
        matching_tenants.first().map(|t| (*t, ambiguous))
    }

    /// Iterate tenants and their bundles for the boot banner. Each entry is
    /// `(tenant, bundles_sorted, default_bundle_id)` where bundles are
    /// alphabetically sorted and the default may be `None` when no resolution
    /// succeeded. Tenants are returned in alphabetical order.
    pub(crate) fn tenants_and_bundles(&self) -> Vec<(&str, Vec<&str>, Option<&str>)> {
        let mut tenants: Vec<&str> = self.bundles.keys().map(|s| s.as_str()).collect();
        tenants.sort_unstable();
        tenants
            .into_iter()
            .map(|tenant| {
                let mut bundles: Vec<&str> = self
                    .bundles
                    .get(tenant)
                    .map(|set| set.iter().map(|s| s.as_str()).collect())
                    .unwrap_or_default();
                bundles.sort_unstable();
                let default = self.defaults.get(tenant).map(|d| d.bundle_id.as_str());
                (tenant, bundles, default)
            })
            .collect()
    }
}

// ── FlowIndex ───────────────────────────────────────────────────────

/// Per-bundle index of flow ids, so recognizing a flow segment in the URL
/// never re-reads a pack manifest per request.
#[derive(Clone, Debug, Default)]
pub(crate) struct FlowIndex {
    /// `bundle_id (string)` -> set of `(flow_id, pack_id)`.
    flows: HashMap<String, Vec<FlowEntry>>,
    /// `bundle_id (string)` -> the bundle's default `(flow_id, pack_id)`, for
    /// the `/{tenant}/{bundle}` URL form that names no flow. A `None` value is
    /// a tombstone: two packs claimed a default, so the bundle has none (see
    /// [`register_bundle_default_flow`]).
    ///
    /// [`register_bundle_default_flow`]: FlowIndex::register_bundle_default_flow
    defaults: HashMap<String, Option<FlowEntry>>,
}

#[derive(Clone, Debug)]
struct FlowEntry {
    flow_id: String,
    pack_id: String,
}

impl FlowIndex {
    /// Register flows for a bundle. Deduplicates by `(flow_id, pack_id)`.
    pub(crate) fn register_bundle_flows(
        &mut self,
        bundle_id: &str,
        pack_id: &str,
        flow_ids: &[String],
    ) {
        let entries = self.flows.entry(bundle_id.to_string()).or_default();
        for flow_id in flow_ids {
            let already = entries
                .iter()
                .any(|e| e.flow_id == *flow_id && e.pack_id == pack_id);
            if !already {
                entries.push(FlowEntry {
                    flow_id: flow_id.clone(),
                    pack_id: pack_id.to_string(),
                });
            }
        }
    }

    /// Record `pack_id`'s default flow as the bundle's default.
    ///
    /// A bundle typically holds one app pack plus provider packs that ship no
    /// flows, so the pack that resolves a default owns the bundle's default.
    /// When a SECOND pack also claims one the bundle has no unambiguous
    /// default: the entry is tombstoned — permanently, so registration order
    /// cannot resurrect it — and the bare-bundle URL falls back to the
    /// runner's own flow-type resolution (which reports the ambiguity).
    pub(crate) fn register_bundle_default_flow(
        &mut self,
        bundle_id: &str,
        pack_id: &str,
        flow_id: &str,
    ) {
        match self.defaults.entry(bundle_id.to_string()) {
            std::collections::hash_map::Entry::Occupied(mut existing) => {
                if existing
                    .get()
                    .as_ref()
                    .is_some_and(|e| e.pack_id != pack_id)
                {
                    existing.insert(None);
                }
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(Some(FlowEntry {
                    flow_id: flow_id.to_string(),
                    pack_id: pack_id.to_string(),
                }));
            }
        }
    }

    /// The bundle's default `(pack_id, flow_id)`, when exactly one pack in it
    /// resolves one.
    pub(crate) fn default_flow_for_bundle(&self, bundle_id: &str) -> Option<(&str, &str)> {
        self.defaults
            .get(bundle_id)?
            .as_ref()
            .map(|e| (e.pack_id.as_str(), e.flow_id.as_str()))
    }

    /// Whether `segment` is a known flow id for `bundle_id`.
    pub(crate) fn is_flow(&self, bundle_id: &str, segment: &str) -> bool {
        self.flows
            .get(bundle_id)
            .is_some_and(|entries| entries.iter().any(|e| e.flow_id == segment))
    }

    /// Look up the pack id that owns `flow_id` within `bundle_id`.
    /// Returns `None` when the flow is unknown.
    pub(crate) fn pack_id_for_flow(&self, bundle_id: &str, flow_id: &str) -> Option<&str> {
        self.flows
            .get(bundle_id)
            .and_then(|entries| entries.iter().find(|e| e.flow_id == flow_id))
            .map(|e| e.pack_id.as_str())
    }
}

// ── WebchatTarget ───────────────────────────────────────────────────

/// How the bundle was determined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BundleSource {
    /// The bundle id appeared explicitly in the URL.
    Url,
    /// The bundle was resolved from the default-bundle ladder.
    Default(DefaultBundleReason),
}

/// A fully classified webchat request.
#[derive(Clone, Debug)]
#[allow(dead_code)] // fields consumed by the serve pipeline; some reserved for future flow routing
pub(crate) struct WebchatTarget {
    /// The tenant extracted from the URL.
    pub(crate) tenant: String,
    /// Resolved deployment id.
    pub(crate) deployment_id: DeploymentId,
    /// The bundle serving this request.
    pub(crate) bundle_id: BundleId,
    /// Whether the bundle came from the URL or the default ladder.
    pub(crate) bundle_source: BundleSource,
    /// Flow id extracted from the URL, if present.
    pub(crate) flow_id: Option<String>,
    /// The path with bundle/flow segments stripped, for static-route matching
    /// and provider path extraction. Starts with `/`.
    pub(crate) stripped_path: String,
    /// Everything up to and including the bundle segment (e.g.
    /// `/v1/web/webchat/acme/my-bundle`), used later to rewrite DirectLine
    /// `streamUrl`. For a tenant-only URL the prefix ends at the tenant
    /// segment (e.g. `/v1/web/webchat/acme`).
    pub(crate) stream_url_prefix: String,
}

impl WebchatTarget {
    /// The bundle segment the URL carried (e.g. `/my-bundle`), or `None` when
    /// the bundle came from the default ladder and the URL named no bundle.
    ///
    /// This is what the DirectLine `streamUrl` rewrite splices in: the provider
    /// builds that URL from the path it was handed, which is already
    /// tenant-scoped, so only the bundle segment is missing from it.
    pub(crate) fn url_bundle_segment(&self) -> Option<&str> {
        match self.bundle_source {
            BundleSource::Url => self
                .stream_url_prefix
                .rfind('/')
                .map(|i| &self.stream_url_prefix[i..]),
            BundleSource::Default(_) => None,
        }
    }
}

// ── classify_webchat_path ───────────────────────────────────────────

/// The webchat path prefix for `web` and `messaging` domains.
const WEBCHAT_PREFIX_WEB: &str = "/v1/web/webchat/";
const WEBCHAT_PREFIX_MSG: &str = "/v1/messaging/webchat/";

/// Classify a webchat URL path against the bundle and flow indices.
///
/// Returns `None` when the path is not a webchat path (does not start with
/// either prefix) or when no Active deployment can be resolved for the
/// tenant/bundle combination.
pub(crate) fn classify_webchat_path(
    path: &str,
    bundle_index: &BundleIndex,
    flow_index: &FlowIndex,
    routes: &DeploymentRouteTable,
) -> Option<WebchatTarget> {
    let (prefix_len, prefix_base) = if path.starts_with(WEBCHAT_PREFIX_WEB) {
        (
            WEBCHAT_PREFIX_WEB.len(),
            &path[..WEBCHAT_PREFIX_WEB.len() - 1],
        )
    } else if path.starts_with(WEBCHAT_PREFIX_MSG) {
        (
            WEBCHAT_PREFIX_MSG.len(),
            &path[..WEBCHAT_PREFIX_MSG.len() - 1],
        )
    } else {
        return None;
    };

    // Everything after the prefix is `{tenant}[/{rest}...]`.
    let after_prefix = &path[prefix_len..];
    if after_prefix.is_empty() {
        return None; // no tenant segment
    }

    // Split into segments.
    let segments: Vec<&str> = after_prefix.split('/').collect();
    if segments.is_empty() || segments[0].is_empty() {
        return None;
    }

    let tenant_raw = segments[0];
    let tenant = percent_decode(tenant_raw);
    // The prefix up to and including the tenant segment.
    let tenant_prefix = format!("{prefix_base}/{tenant_raw}");

    // Remaining segments after the tenant.
    let rest = &segments[1..];

    // No further segments: SPA index on default bundle.
    if rest.is_empty() {
        let (dep_id, bundle_id, reason) = bundle_index.default_for(&tenant)?;
        return Some(WebchatTarget {
            tenant,
            deployment_id: dep_id,
            bundle_id: bundle_id.clone(),
            bundle_source: BundleSource::Default(reason),
            flow_id: None,
            stripped_path: tenant_prefix.clone(),
            stream_url_prefix: tenant_prefix,
        });
    }

    let seg1 = rest[0];
    let seg1_decoded = percent_decode(seg1);

    // ── segment after tenant: reserved literal ──────────────────────
    if is_reserved(&seg1_decoded) {
        // DirectLine API on the default bundle.
        let (dep_id, bundle_id, reason) = bundle_index.default_for(&tenant)?;
        let stripped = format!("{tenant_prefix}{}", rebuild_path(&segments[1..]));
        return Some(WebchatTarget {
            tenant,
            deployment_id: dep_id,
            bundle_id: bundle_id.clone(),
            bundle_source: BundleSource::Default(reason),
            flow_id: None,
            stripped_path: stripped,
            stream_url_prefix: tenant_prefix,
        });
    }

    // ── segment after tenant: known bundle id ───────────────────────
    if bundle_index.is_bundle(&tenant, &seg1_decoded) {
        let dep_id = bundle_index.resolve(routes, &tenant, &seg1_decoded)?;
        let bundle_id = BundleId::new(&seg1_decoded);
        let bundle_prefix = format!("{tenant_prefix}/{seg1}");

        let after_bundle = &rest[1..];
        if after_bundle.is_empty() {
            // SPA index, bundle B, default flow.
            return Some(WebchatTarget {
                tenant,
                deployment_id: dep_id,
                bundle_id,
                bundle_source: BundleSource::Url,
                flow_id: None,
                stripped_path: tenant_prefix.clone(),
                stream_url_prefix: bundle_prefix,
            });
        }

        let seg2 = after_bundle[0];
        let seg2_decoded = percent_decode(seg2);

        // Reserved after bundle -> DirectLine API, bundle B.
        if is_reserved(&seg2_decoded) {
            let stripped = format!("{tenant_prefix}{}", rebuild_path(after_bundle));
            return Some(WebchatTarget {
                tenant,
                deployment_id: dep_id,
                bundle_id,
                bundle_source: BundleSource::Url,
                flow_id: None,
                stripped_path: stripped,
                stream_url_prefix: bundle_prefix,
            });
        }

        // Flow id after bundle.
        if flow_index.is_flow(&seg1_decoded, &seg2_decoded) {
            let after_flow = &after_bundle[1..];
            let stripped = if after_flow.is_empty() {
                tenant_prefix.clone()
            } else {
                format!("{tenant_prefix}{}", rebuild_path(after_flow))
            };
            return Some(WebchatTarget {
                tenant,
                deployment_id: dep_id,
                bundle_id,
                bundle_source: BundleSource::Url,
                flow_id: Some(seg2_decoded),
                stripped_path: stripped,
                stream_url_prefix: bundle_prefix,
            });
        }

        // Asset under bundle B (1 segment stripped = the bundle segment).
        let stripped = format!("{tenant_prefix}{}", rebuild_path(after_bundle));
        return Some(WebchatTarget {
            tenant,
            deployment_id: dep_id,
            bundle_id,
            bundle_source: BundleSource::Url,
            flow_id: None,
            stripped_path: stripped,
            stream_url_prefix: bundle_prefix,
        });
    }

    // ── fallback: asset under the default bundle ────────────────────
    // The segment is not reserved and not a known bundle id: treat it as an
    // asset path under the default bundle. This keeps existing deployments
    // working where `{tenant}/{asset...}` is the current form.
    let (dep_id, bundle_id, reason) = bundle_index.default_for(&tenant)?;
    let stripped = format!("{tenant_prefix}{}", rebuild_path(rest));
    Some(WebchatTarget {
        tenant,
        deployment_id: dep_id,
        bundle_id: bundle_id.clone(),
        bundle_source: BundleSource::Default(reason),
        flow_id: None,
        stripped_path: stripped,
        stream_url_prefix: tenant_prefix,
    })
}

// ── strip_webchat_bundle_segments ───────────────────────────────────

/// Cheap path-only stripping for the WebSocket upgrade path, which runs
/// before `serve()` and does not need default-bundle resolution.
///
/// If `path` matches the webchat grammar and the segment after the tenant is
/// a known bundle id, returns the path with the bundle (and optional flow)
/// segments removed. Otherwise returns `None` (the caller keeps the path
/// as-is).
pub(crate) fn strip_webchat_bundle_segments(
    path: &str,
    bundle_index: &BundleIndex,
    flow_index: &FlowIndex,
) -> Option<String> {
    let (prefix_len, _) = if path.starts_with(WEBCHAT_PREFIX_WEB) {
        (WEBCHAT_PREFIX_WEB.len(), WEBCHAT_PREFIX_WEB)
    } else if path.starts_with(WEBCHAT_PREFIX_MSG) {
        (WEBCHAT_PREFIX_MSG.len(), WEBCHAT_PREFIX_MSG)
    } else {
        return None;
    };

    let after_prefix = &path[prefix_len..];
    let segments: Vec<&str> = after_prefix.split('/').collect();
    if segments.len() < 2 || segments[0].is_empty() {
        return None; // no segment after tenant
    }

    let tenant = percent_decode(segments[0]);
    let seg1 = percent_decode(segments[1]);

    if !bundle_index.is_bundle(&tenant, &seg1) {
        return None;
    }

    // The prefix through the tenant stays; skip the bundle segment.
    let prefix = &path[..prefix_len + segments[0].len()];
    let after_bundle = &segments[2..];

    if !after_bundle.is_empty() {
        let seg2 = percent_decode(after_bundle[0]);
        if flow_index.is_flow(&seg1, &seg2) {
            // Skip both bundle and flow segments.
            let after_flow = &after_bundle[1..];
            if after_flow.is_empty() {
                return Some(prefix.to_string());
            }
            return Some(format!("{prefix}/{}", after_flow.join("/")));
        }
    }

    // Skip just the bundle segment.
    if after_bundle.is_empty() {
        return Some(prefix.to_string());
    }
    Some(format!("{prefix}/{}", after_bundle.join("/")))
}

// ── helpers ─────────────────────────────────────────────────────────

/// Rebuild a slash-joined path from segments, with a leading `/`.
fn rebuild_path(segments: &[&str]) -> String {
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

/// Minimal percent-decode (only `%XX`). Does not handle `+` as space — URL
/// path segments use `%20`, not `+`.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::{
        BundleDeployment, BundleDeploymentStatus, BundleId, CustomerId, DeploymentId,
        EnvironmentHostConfig, PartyId, RevenueShareEntry, RouteBinding, SchemaVersion,
        TenantSelector,
    };
    use greentic_types::EnvId;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn make_deployment(
        deployment_id: DeploymentId,
        tenant: &str,
        bundle_id: &str,
    ) -> BundleDeployment {
        BundleDeployment {
            schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
            deployment_id,
            env_id: env_id(),
            bundle_id: BundleId::new(bundle_id),
            customer_id: CustomerId::new("cust"),
            status: BundleDeploymentStatus::Active,
            current_revisions: Vec::new(),
            route_binding: RouteBinding {
                hosts: Vec::new(),
                path_prefixes: Vec::new(),
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

    fn make_env(bundles: Vec<BundleDeployment>) -> Environment {
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

    fn make_env_with_default(bundles: Vec<BundleDeployment>, default: &str) -> Environment {
        let mut env = make_env(bundles);
        env.host_config.default_bundle = Some(BundleId::new(default));
        env
    }

    /// Build a test harness: (routes, bundle_index, flow_index).
    fn harness(env: &Environment) -> (DeploymentRouteTable, BundleIndex, FlowIndex) {
        let routes = DeploymentRouteTable::from_environment(env);
        let bundle_index = BundleIndex::from_routes_and_env(&routes, env);
        let flow_index = FlowIndex::default();
        (routes, bundle_index, flow_index)
    }

    fn harness_with_flows(
        env: &Environment,
        flows: &[(&str, &str, &[&str])], // (bundle_id, pack_id, flow_ids)
    ) -> (DeploymentRouteTable, BundleIndex, FlowIndex) {
        let routes = DeploymentRouteTable::from_environment(env);
        let bundle_index = BundleIndex::from_routes_and_env(&routes, env);
        let mut flow_index = FlowIndex::default();
        for (bid, pid, fids) in flows {
            let ids: Vec<String> = fids.iter().map(|s| s.to_string()).collect();
            flow_index.register_bundle_flows(bid, pid, &ids);
        }
        (routes, bundle_index, flow_index)
    }

    // ── tenant-only paths ───────────────────────────────────────────

    #[test]
    fn tenant_only_resolves_default_bundle() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "chat")]);
        let (routes, bi, fi) = harness(&env);

        let target = classify_webchat_path("/v1/web/webchat/acme", &bi, &fi, &routes).unwrap();
        assert_eq!(target.tenant, "acme");
        assert_eq!(target.deployment_id, dep_id);
        assert_eq!(target.bundle_id.as_str(), "chat");
        assert!(matches!(target.bundle_source, BundleSource::Default(_)));
        assert!(target.flow_id.is_none());
        assert_eq!(target.stripped_path, "/v1/web/webchat/acme");
        assert_eq!(target.stream_url_prefix, "/v1/web/webchat/acme");
    }

    #[test]
    fn tenant_only_messaging_domain() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "chat")]);
        let (routes, bi, fi) = harness(&env);

        let target =
            classify_webchat_path("/v1/messaging/webchat/acme", &bi, &fi, &routes).unwrap();
        assert_eq!(target.tenant, "acme");
        assert_eq!(target.deployment_id, dep_id);
        assert_eq!(target.stream_url_prefix, "/v1/messaging/webchat/acme");
    }

    #[test]
    fn tenant_only_no_active_deployment_returns_none() {
        let env = make_env(Vec::new());
        let (routes, bi, fi) = harness(&env);

        assert!(classify_webchat_path("/v1/web/webchat/acme", &bi, &fi, &routes).is_none());
    }

    // ── reserved literal after tenant (DirectLine API) ──────────────

    #[test]
    fn reserved_token_after_tenant() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "chat")]);
        let (routes, bi, fi) = harness(&env);

        let target =
            classify_webchat_path("/v1/web/webchat/acme/token", &bi, &fi, &routes).unwrap();
        assert_eq!(target.stripped_path, "/v1/web/webchat/acme/token");
        assert!(matches!(target.bundle_source, BundleSource::Default(_)));
        assert_eq!(target.stream_url_prefix, "/v1/web/webchat/acme");
    }

    #[test]
    fn reserved_v3_conversations_after_tenant() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "chat")]);
        let (routes, bi, fi) = harness(&env);

        let target = classify_webchat_path(
            "/v1/web/webchat/acme/v3/directline/conversations",
            &bi,
            &fi,
            &routes,
        )
        .unwrap();
        assert_eq!(
            target.stripped_path,
            "/v1/web/webchat/acme/v3/directline/conversations"
        );
        assert!(matches!(target.bundle_source, BundleSource::Default(_)));
    }

    #[test]
    fn reserved_oauth_after_tenant() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "chat")]);
        let (routes, bi, fi) = harness(&env);

        let target =
            classify_webchat_path("/v1/web/webchat/acme/oauth/callback", &bi, &fi, &routes)
                .unwrap();
        assert_eq!(target.stripped_path, "/v1/web/webchat/acme/oauth/callback");
    }

    // ── bundle-scoped paths ─────────────────────────────────────────

    #[test]
    fn bundle_scoped_index() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "hr-chat")]);
        let (routes, bi, fi) = harness(&env);

        let target =
            classify_webchat_path("/v1/web/webchat/acme/hr-chat", &bi, &fi, &routes).unwrap();
        assert_eq!(target.deployment_id, dep_id);
        assert_eq!(target.bundle_id.as_str(), "hr-chat");
        assert_eq!(target.bundle_source, BundleSource::Url);
        assert!(target.flow_id.is_none());
        assert_eq!(target.stripped_path, "/v1/web/webchat/acme");
        assert_eq!(target.stream_url_prefix, "/v1/web/webchat/acme/hr-chat");
    }

    #[test]
    fn bundle_scoped_token() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "hr-chat")]);
        let (routes, bi, fi) = harness(&env);

        let target =
            classify_webchat_path("/v1/web/webchat/acme/hr-chat/token", &bi, &fi, &routes).unwrap();
        assert_eq!(target.bundle_id.as_str(), "hr-chat");
        assert_eq!(target.bundle_source, BundleSource::Url);
        assert_eq!(target.stripped_path, "/v1/web/webchat/acme/token");
        assert_eq!(target.stream_url_prefix, "/v1/web/webchat/acme/hr-chat");
    }

    #[test]
    fn bundle_scoped_v3_api() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "hr-chat")]);
        let (routes, bi, fi) = harness(&env);

        let target = classify_webchat_path(
            "/v1/web/webchat/acme/hr-chat/v3/directline/conversations",
            &bi,
            &fi,
            &routes,
        )
        .unwrap();
        assert_eq!(
            target.stripped_path,
            "/v1/web/webchat/acme/v3/directline/conversations"
        );
        assert_eq!(target.bundle_source, BundleSource::Url);
    }

    #[test]
    fn bundle_scoped_asset() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "hr-chat")]);
        let (routes, bi, fi) = harness(&env);

        let target = classify_webchat_path(
            "/v1/web/webchat/acme/hr-chat/static/main.js",
            &bi,
            &fi,
            &routes,
        )
        .unwrap();
        assert_eq!(target.stripped_path, "/v1/web/webchat/acme/static/main.js");
        assert_eq!(target.bundle_source, BundleSource::Url);
        assert!(target.flow_id.is_none());
    }

    // ── flow-scoped paths ───────────────────────────────────────────

    #[test]
    fn flow_scoped_index() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "hr-chat")]);
        let (routes, bi, fi) = harness_with_flows(
            &env,
            &[("hr-chat", "hr-pack", &["onboarding", "offboarding"])],
        );

        let target =
            classify_webchat_path("/v1/web/webchat/acme/hr-chat/onboarding", &bi, &fi, &routes)
                .unwrap();
        assert_eq!(target.bundle_id.as_str(), "hr-chat");
        assert_eq!(target.flow_id.as_deref(), Some("onboarding"));
        assert_eq!(target.stripped_path, "/v1/web/webchat/acme");
        assert_eq!(target.stream_url_prefix, "/v1/web/webchat/acme/hr-chat");
    }

    #[test]
    fn flow_scoped_asset() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "hr-chat")]);
        let (routes, bi, fi) = harness_with_flows(&env, &[("hr-chat", "hr-pack", &["onboarding"])]);

        let target = classify_webchat_path(
            "/v1/web/webchat/acme/hr-chat/onboarding/styles.css",
            &bi,
            &fi,
            &routes,
        )
        .unwrap();
        assert_eq!(target.flow_id.as_deref(), Some("onboarding"));
        assert_eq!(target.stripped_path, "/v1/web/webchat/acme/styles.css");
    }

    // ── fallback: asset under default bundle ────────────────────────

    #[test]
    fn unknown_segment_falls_back_to_asset_under_default_bundle() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "chat")]);
        let (routes, bi, fi) = harness(&env);

        // "logo.png" is neither reserved nor a known bundle id.
        let target =
            classify_webchat_path("/v1/web/webchat/acme/logo.png", &bi, &fi, &routes).unwrap();
        assert!(matches!(target.bundle_source, BundleSource::Default(_)));
        assert_eq!(target.stripped_path, "/v1/web/webchat/acme/logo.png");
        assert_eq!(target.stream_url_prefix, "/v1/web/webchat/acme");
    }

    // ── stream_url_prefix ───────────────────────────────────────────

    #[test]
    fn stream_url_prefix_tenant_only() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "chat")]);
        let (routes, bi, fi) = harness(&env);

        let target = classify_webchat_path("/v1/web/webchat/acme", &bi, &fi, &routes).unwrap();
        assert_eq!(target.stream_url_prefix, "/v1/web/webchat/acme");
    }

    #[test]
    fn stream_url_prefix_bundle_scoped() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "hr-chat")]);
        let (routes, bi, fi) = harness(&env);

        let target =
            classify_webchat_path("/v1/web/webchat/acme/hr-chat", &bi, &fi, &routes).unwrap();
        assert_eq!(target.stream_url_prefix, "/v1/web/webchat/acme/hr-chat");
    }

    // ── multi-bundle disambiguation ─────────────────────────────────

    #[test]
    fn two_bundles_same_tenant_disambiguate_by_id() {
        let dep_hr = DeploymentId::new();
        let dep_sales = DeploymentId::new();
        let env = make_env(vec![
            make_deployment(dep_hr, "acme", "hr-chat"),
            make_deployment(dep_sales, "acme", "sales-chat"),
        ]);
        let (routes, bi, fi) = harness(&env);

        let hr =
            classify_webchat_path("/v1/web/webchat/acme/hr-chat/token", &bi, &fi, &routes).unwrap();
        assert_eq!(hr.deployment_id, dep_hr);
        assert_eq!(hr.bundle_id.as_str(), "hr-chat");

        let sales =
            classify_webchat_path("/v1/web/webchat/acme/sales-chat/token", &bi, &fi, &routes)
                .unwrap();
        assert_eq!(sales.deployment_id, dep_sales);
        assert_eq!(sales.bundle_id.as_str(), "sales-chat");
    }

    // ── bundle id colliding with a flow id in a different bundle ────

    #[test]
    fn bundle_id_colliding_with_flow_id_in_different_bundle() {
        // Bundle "alpha" has a flow named "beta". Bundle "beta" also exists.
        // The URL `/acme/beta` must resolve to bundle "beta", not flow "beta"
        // of bundle "alpha" — the bundle segment takes priority.
        let dep_alpha = DeploymentId::new();
        let dep_beta = DeploymentId::new();
        let env = make_env(vec![
            make_deployment(dep_alpha, "acme", "alpha"),
            make_deployment(dep_beta, "acme", "beta"),
        ]);
        let (routes, bi, fi) = harness_with_flows(&env, &[("alpha", "pack-a", &["beta", "main"])]);

        let target = classify_webchat_path("/v1/web/webchat/acme/beta", &bi, &fi, &routes).unwrap();
        // Must resolve to bundle "beta", not flow "beta" of bundle "alpha".
        assert_eq!(target.bundle_id.as_str(), "beta");
        assert_eq!(target.deployment_id, dep_beta);
        assert_eq!(target.bundle_source, BundleSource::Url);
        assert!(target.flow_id.is_none());
    }

    // ── percent-encoded segments ────────────────────────────────────

    #[test]
    fn percent_encoded_tenant() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme corp", "chat")]);
        let (routes, bi, fi) = harness(&env);

        let target =
            classify_webchat_path("/v1/web/webchat/acme%20corp", &bi, &fi, &routes).unwrap();
        assert_eq!(target.tenant, "acme corp");
    }

    #[test]
    fn percent_encoded_bundle_id() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "my bundle")]);
        let (routes, bi, fi) = harness(&env);

        let target =
            classify_webchat_path("/v1/web/webchat/acme/my%20bundle", &bi, &fi, &routes).unwrap();
        assert_eq!(target.bundle_id.as_str(), "my bundle");
        assert_eq!(target.bundle_source, BundleSource::Url);
    }

    // ── explicit default_bundle config ──────────────────────────────

    #[test]
    fn explicit_default_bundle_config_wins() {
        let dep_hr = DeploymentId::new();
        let dep_sales = DeploymentId::new();
        let env = make_env_with_default(
            vec![
                make_deployment(dep_hr, "acme", "hr-chat"),
                make_deployment(dep_sales, "acme", "sales-chat"),
            ],
            "sales-chat",
        );
        let (routes, bi, fi) = harness(&env);

        let target = classify_webchat_path("/v1/web/webchat/acme", &bi, &fi, &routes).unwrap();
        assert_eq!(target.bundle_id.as_str(), "sales-chat");
        assert_eq!(target.deployment_id, dep_sales);
        assert!(matches!(
            target.bundle_source,
            BundleSource::Default(DefaultBundleReason::ExplicitConfig)
        ));
    }

    // ── not a webchat path ──────────────────────────────────────────

    #[test]
    fn non_webchat_path_returns_none() {
        let env = make_env(vec![make_deployment(DeploymentId::new(), "acme", "chat")]);
        let (routes, bi, fi) = harness(&env);

        assert!(classify_webchat_path("/v1/api/other", &bi, &fi, &routes).is_none());
        assert!(classify_webchat_path("/health", &bi, &fi, &routes).is_none());
    }

    #[test]
    fn empty_after_webchat_prefix_returns_none() {
        let env = make_env(vec![make_deployment(DeploymentId::new(), "acme", "chat")]);
        let (routes, bi, fi) = harness(&env);

        // The prefix alone (no tenant) is not a valid webchat path.
        assert!(classify_webchat_path("/v1/web/webchat/", &bi, &fi, &routes).is_none());
    }

    // ── strip_webchat_bundle_segments ────────────────────────────────

    #[test]
    fn strip_removes_bundle_segment() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "hr-chat")]);
        let (_, bi, fi) = harness(&env);

        let result = strip_webchat_bundle_segments(
            "/v1/web/webchat/acme/hr-chat/v3/directline/conversations",
            &bi,
            &fi,
        );
        assert_eq!(
            result.as_deref(),
            Some("/v1/web/webchat/acme/v3/directline/conversations")
        );
    }

    #[test]
    fn strip_removes_bundle_and_flow_segments() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "hr-chat")]);
        let (_, bi, fi) = harness_with_flows(&env, &[("hr-chat", "hr-pack", &["onboarding"])]);

        let result = strip_webchat_bundle_segments(
            "/v1/web/webchat/acme/hr-chat/onboarding/v3/ws",
            &bi,
            &fi,
        );
        assert_eq!(result.as_deref(), Some("/v1/web/webchat/acme/v3/ws"));
    }

    #[test]
    fn strip_returns_none_for_non_webchat_path() {
        let env = make_env(vec![make_deployment(DeploymentId::new(), "acme", "chat")]);
        let (_, bi, fi) = harness(&env);

        assert!(strip_webchat_bundle_segments("/health", &bi, &fi).is_none());
    }

    #[test]
    fn strip_returns_none_when_segment_is_not_a_bundle() {
        let env = make_env(vec![make_deployment(DeploymentId::new(), "acme", "chat")]);
        let (_, bi, fi) = harness(&env);

        // "unknown" is not a known bundle id for tenant "acme".
        assert!(
            strip_webchat_bundle_segments("/v1/web/webchat/acme/unknown/foo", &bi, &fi,).is_none()
        );
    }

    // ── FlowIndex ───────────────────────────────────────────────────

    #[test]
    fn flow_index_deduplicates() {
        let mut fi = FlowIndex::default();
        fi.register_bundle_flows("b1", "pack1", &["main".to_string(), "aux".to_string()]);
        fi.register_bundle_flows("b1", "pack1", &["main".to_string()]); // duplicate
        assert!(fi.is_flow("b1", "main"));
        assert!(fi.is_flow("b1", "aux"));
        assert!(!fi.is_flow("b1", "other"));
        assert!(!fi.is_flow("b2", "main"));
        // Only 2 entries despite the second registration.
        assert_eq!(fi.flows.get("b1").unwrap().len(), 2);
    }

    #[test]
    fn flow_index_pack_id_for_flow() {
        let mut fi = FlowIndex::default();
        fi.register_bundle_flows("b1", "pack-alpha", &["main".to_string(), "aux".to_string()]);
        assert_eq!(fi.pack_id_for_flow("b1", "main"), Some("pack-alpha"));
        assert_eq!(fi.pack_id_for_flow("b1", "aux"), Some("pack-alpha"));
        assert_eq!(fi.pack_id_for_flow("b1", "unknown"), None);
        assert_eq!(fi.pack_id_for_flow("b2", "main"), None);
    }

    #[test]
    fn flow_index_records_a_single_packs_default_flow() {
        // The typical bundle: one app pack with flows plus provider packs that
        // ship none. Re-registering the SAME pack (one call per revision of the
        // bundle) must not withdraw the default.
        let mut fi = FlowIndex::default();
        fi.register_bundle_default_flow("b1", "app-pack", "main");
        fi.register_bundle_default_flow("b1", "app-pack", "main");
        assert_eq!(fi.default_flow_for_bundle("b1"), Some(("app-pack", "main")));
        assert_eq!(fi.default_flow_for_bundle("b2"), None);
    }

    #[test]
    fn flow_index_withdraws_the_default_when_two_packs_claim_one() {
        // Two app packs each with their own entry flow: the bare-bundle URL has
        // no unambiguous target, so it must fall back to the runner's own
        // resolution rather than silently picking whichever pack loaded first.
        let mut fi = FlowIndex::default();
        fi.register_bundle_default_flow("b1", "pack-alpha", "main");
        fi.register_bundle_default_flow("b1", "pack-beta", "main");
        assert_eq!(fi.default_flow_for_bundle("b1"), None);
        // The tombstone is permanent: re-registering the first pack must not
        // resurrect a default the bundle has already been shown not to have.
        fi.register_bundle_default_flow("b1", "pack-alpha", "main");
        assert_eq!(fi.default_flow_for_bundle("b1"), None);
    }

    // ── BundleIndex ─────────────────────────────────────────────────

    #[test]
    fn bundle_index_recognises_active_bundles() {
        let env = make_env(vec![
            make_deployment(DeploymentId::new(), "acme", "alpha"),
            make_deployment(DeploymentId::new(), "acme", "beta"),
        ]);
        let routes = DeploymentRouteTable::from_environment(&env);
        let bi = BundleIndex::from_routes_and_env(&routes, &env);

        assert!(bi.is_bundle("acme", "alpha"));
        assert!(bi.is_bundle("acme", "beta"));
        assert!(!bi.is_bundle("acme", "gamma"));
        assert!(!bi.is_bundle("other-tenant", "alpha"));
    }

    #[test]
    fn bundle_index_skips_non_active_deployments() {
        let mut dep = make_deployment(DeploymentId::new(), "acme", "paused-bundle");
        dep.status = BundleDeploymentStatus::Paused;
        let env = make_env(vec![dep]);
        let routes = DeploymentRouteTable::from_environment(&env);
        let bi = BundleIndex::from_routes_and_env(&routes, &env);

        assert!(!bi.is_bundle("acme", "paused-bundle"));
    }

    #[test]
    fn bundle_index_default_for_lone_active() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "chat")]);
        let routes = DeploymentRouteTable::from_environment(&env);
        let bi = BundleIndex::from_routes_and_env(&routes, &env);

        let (id, bid, reason) = bi.default_for("acme").unwrap();
        assert_eq!(id, dep_id);
        assert_eq!(bid.as_str(), "chat");
        assert_eq!(reason, DefaultBundleReason::LoneActive);
    }

    #[test]
    fn tenants_and_bundles_returns_sorted_tenants_and_bundles() {
        let env = make_env(vec![
            make_deployment(DeploymentId::new(), "zebra", "z-bundle"),
            make_deployment(DeploymentId::new(), "acme", "beta"),
            make_deployment(DeploymentId::new(), "acme", "alpha"),
        ]);
        let routes = DeploymentRouteTable::from_environment(&env);
        let bi = BundleIndex::from_routes_and_env(&routes, &env);

        let result = bi.tenants_and_bundles();
        assert_eq!(result.len(), 2);

        let (tenant, bundles, default) = &result[0];
        assert_eq!(*tenant, "acme");
        assert_eq!(*bundles, vec!["alpha", "beta"]);
        // With two active bundles the default is the newest.
        assert!(default.is_some());

        let (tenant, bundles, default) = &result[1];
        assert_eq!(*tenant, "zebra");
        assert_eq!(*bundles, vec!["z-bundle"]);
        // Lone active -> default resolved.
        assert_eq!(*default, Some("z-bundle"));
    }

    #[test]
    fn tenants_and_bundles_empty_index() {
        let bi = BundleIndex::empty();
        assert!(bi.tenants_and_bundles().is_empty());
    }

    // ── resolve_open_webchat_bundle ───────────────────────────────────

    #[test]
    fn open_webchat_unique_bundle_resolves_without_ambiguity() {
        let env = make_env(vec![make_deployment(DeploymentId::new(), "acme", "chat")]);
        let routes = DeploymentRouteTable::from_environment(&env);
        let bi = BundleIndex::from_routes_and_env(&routes, &env);

        let (tenant, ambiguous) = bi.resolve_open_webchat_bundle("chat", None).unwrap();
        assert_eq!(tenant, "acme");
        assert!(!ambiguous);
    }

    #[test]
    fn open_webchat_with_tenant_picks_correct_tenant() {
        // Same bundle id under two tenants.
        let env = make_env(vec![
            make_deployment(DeploymentId::new(), "acme", "legal"),
            make_deployment(DeploymentId::new(), "beta", "legal"),
        ]);
        let routes = DeploymentRouteTable::from_environment(&env);
        let bi = BundleIndex::from_routes_and_env(&routes, &env);

        let (tenant, ambiguous) = bi
            .resolve_open_webchat_bundle("legal", Some("beta"))
            .unwrap();
        assert_eq!(tenant, "beta");
        assert!(
            !ambiguous,
            "a --tenant filter must suppress the ambiguity flag"
        );
    }

    #[test]
    fn open_webchat_tenant_lacking_bundle_returns_none() {
        let env = make_env(vec![make_deployment(DeploymentId::new(), "acme", "legal")]);
        let routes = DeploymentRouteTable::from_environment(&env);
        let bi = BundleIndex::from_routes_and_env(&routes, &env);

        assert!(
            bi.resolve_open_webchat_bundle("legal", Some("other"))
                .is_none(),
            "a tenant that does not hold the bundle must return None"
        );
    }

    #[test]
    fn open_webchat_ambiguous_without_tenant_flags_ambiguity() {
        let env = make_env(vec![
            make_deployment(DeploymentId::new(), "acme", "shared"),
            make_deployment(DeploymentId::new(), "beta", "shared"),
        ]);
        let routes = DeploymentRouteTable::from_environment(&env);
        let bi = BundleIndex::from_routes_and_env(&routes, &env);

        let (tenant, ambiguous) = bi.resolve_open_webchat_bundle("shared", None).unwrap();
        assert!(
            ambiguous,
            "two tenants with the same bundle must flag ambiguity"
        );
        // Deterministic: tenants_and_bundles sorts alphabetically.
        assert_eq!(tenant, "acme");
    }

    // ── reserved segment case-insensitivity ─────────────────────────

    #[test]
    fn reserved_segments_case_insensitive() {
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "chat")]);
        let (routes, bi, fi) = harness(&env);

        let target =
            classify_webchat_path("/v1/web/webchat/acme/Token", &bi, &fi, &routes).unwrap();
        assert_eq!(target.stripped_path, "/v1/web/webchat/acme/Token");
        assert!(matches!(target.bundle_source, BundleSource::Default(_)));
    }

    // ── percent_decode helper ───────────────────────────────────────

    #[test]
    fn percent_decode_handles_basic_cases() {
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("%2Fpath%2Fto"), "/path/to");
        // Invalid hex is kept verbatim.
        assert_eq!(percent_decode("%ZZ"), "%ZZ");
        // Truncated sequence at end.
        assert_eq!(percent_decode("trail%2"), "trail%2");
    }

    // ── stripped_path ↔ route-matcher integration ──────────────────
    //
    // Verifies that the stripped_path produced by classify_webchat_path
    // is compatible with StaticRouteTable and HttpRouteTable matching.
    // This is the class of bug that only surfaces when a populated
    // BundleIndex feeds the serve() pipeline; all earlier serve-level
    // tests use BundleIndex::empty() so the classified path is never
    // exercised against route templates.

    #[test]
    fn stripped_path_matches_static_route_template() {
        use crate::http_routes::RevisionScope;
        use crate::static_routes::{
            ActiveRouteTable, CacheStrategy, StaticRouteDescriptor, StaticRoutePlan,
        };

        let dep_id = DeploymentId::new();
        let bundle_id = BundleId::new("hr-chat");
        let revision_id = greentic_deploy_spec::RevisionId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "hr-chat")]);
        let (routes, bi, fi) = harness(&env);

        // Build a static route table with the webchat SPA route template,
        // scoped to the same deployment/bundle/revision that the classifier
        // resolves to.
        let scope = RevisionScope {
            deployment_id: dep_id,
            bundle_id: bundle_id.clone(),
            revision_id,
        };
        let route = StaticRouteDescriptor {
            route_id: "tenant-gui".into(),
            pack_id: "gui".into(),
            pack_path: std::path::PathBuf::from("gui.gtpack"),
            public_path: "/v1/web/webchat/{tenant}".into(),
            source_root: "assets/webchat".into(),
            index_file: Some("index.html".into()),
            spa_fallback: Some("index.html".into()),
            tenant_scoped: true,
            team_scoped: false,
            cache_strategy: CacheStrategy::None,
            route_segments: crate::static_routes::parse_route_segments("/v1/web/webchat/{tenant}")
                .expect("segments"),
            scope: Some(scope.clone()),
        };
        let table = ActiveRouteTable::from_plan(&StaticRoutePlan {
            routes: vec![route],
            warnings: Vec::new(),
            blocking_failures: Vec::new(),
        });

        // Classify a bundle-scoped asset URL. Before the fix, the stripped_path
        // was "/static/main.js" which failed to match the 4-segment route
        // template ["v1","web","webchat","{tenant}"]. After the fix it is
        // "/v1/web/webchat/acme/static/main.js" which matches.
        let target = classify_webchat_path(
            "/v1/web/webchat/acme/hr-chat/static/main.js",
            &bi,
            &fi,
            &routes,
        )
        .unwrap();

        let matched = table
            .match_request_for_revision(&target.stripped_path, &scope)
            .expect("stripped_path must match the webchat static route template");
        assert_eq!(matched.asset_path, "static/main.js");

        // Also verify a DirectLine API path through a bundle resolves correctly.
        let api_target = classify_webchat_path(
            "/v1/web/webchat/acme/hr-chat/v3/directline/conversations",
            &bi,
            &fi,
            &routes,
        )
        .unwrap();
        let api_matched = table
            .match_request_for_revision(&api_target.stripped_path, &scope)
            .expect("DirectLine API stripped_path must match the webchat route");
        assert_eq!(api_matched.asset_path, "v3/directline/conversations");
    }

    #[test]
    fn stripped_path_matches_static_route_for_default_bundle_fallback() {
        use crate::http_routes::RevisionScope;
        use crate::static_routes::{
            ActiveRouteTable, CacheStrategy, StaticRouteDescriptor, StaticRoutePlan,
        };

        let dep_id = DeploymentId::new();
        let bundle_id = BundleId::new("chat");
        let revision_id = greentic_deploy_spec::RevisionId::new();
        let env = make_env(vec![make_deployment(dep_id, "acme", "chat")]);
        let (routes, bi, fi) = harness(&env);

        let scope = RevisionScope {
            deployment_id: dep_id,
            bundle_id: bundle_id.clone(),
            revision_id,
        };
        let route = StaticRouteDescriptor {
            route_id: "tenant-gui".into(),
            pack_id: "gui".into(),
            pack_path: std::path::PathBuf::from("gui.gtpack"),
            public_path: "/v1/web/webchat/{tenant}".into(),
            source_root: "assets/webchat".into(),
            index_file: Some("index.html".into()),
            spa_fallback: Some("index.html".into()),
            tenant_scoped: true,
            team_scoped: false,
            cache_strategy: CacheStrategy::None,
            route_segments: crate::static_routes::parse_route_segments("/v1/web/webchat/{tenant}")
                .expect("segments"),
            scope: Some(scope.clone()),
        };
        let table = ActiveRouteTable::from_plan(&StaticRoutePlan {
            routes: vec![route],
            warnings: Vec::new(),
            blocking_failures: Vec::new(),
        });

        // An unknown segment after tenant falls back to the default bundle.
        // The stripped_path must still match the static route template.
        let target = classify_webchat_path(
            "/v1/web/webchat/acme/runtime-bootstrap.js",
            &bi,
            &fi,
            &routes,
        )
        .unwrap();
        assert!(matches!(target.bundle_source, BundleSource::Default(_)));

        let matched = table
            .match_request_for_revision(&target.stripped_path, &scope)
            .expect("fallback stripped_path must match the webchat route");
        assert_eq!(matched.asset_path, "runtime-bootstrap.js");
    }
}
