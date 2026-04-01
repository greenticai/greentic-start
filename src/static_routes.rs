//! Static route discovery and serving for embedded HTTP server.
//!
//! This module handles static file serving from `.gtpack` files that declare
//! the `greentic.static-routes.v1` extension. Routes are discovered at startup
//! and served directly from the HTTP ingress server without requiring NATS.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::Context;
use greentic_types::{ExtensionInline, decode_pack_manifest};
use serde::Deserialize;
use zip::ZipArchive;

use crate::domains::{self, Domain};

pub const EXT_STATIC_ROUTES_V1: &str = "greentic.static-routes.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteScopeSegment {
    Literal(String),
    Tenant,
    Team,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheStrategy {
    None,
    PublicMaxAge { max_age_seconds: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticRouteDescriptor {
    pub route_id: String,
    pub pack_id: String,
    pub pack_path: PathBuf,
    pub public_path: String,
    pub source_root: String,
    pub index_file: Option<String>,
    pub spa_fallback: Option<String>,
    pub tenant_scoped: bool,
    pub team_scoped: bool,
    pub cache_strategy: CacheStrategy,
    pub route_segments: Vec<RouteScopeSegment>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StaticRoutePlan {
    pub routes: Vec<StaticRouteDescriptor>,
    pub warnings: Vec<String>,
    pub blocking_failures: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReservedRouteSet {
    exact_paths: BTreeSet<String>,
    prefix_paths: BTreeSet<String>,
}

impl ReservedRouteSet {
    pub fn operator_defaults() -> Self {
        let mut reserved = Self::default();
        for path in [
            "/healthz",
            "/readyz",
            "/status",
            "/runtime/drain",
            "/runtime/resume",
            "/runtime/shutdown",
            "/deployments/stage",
            "/deployments/warm",
            "/deployments/activate",
            "/deployments/rollback",
            "/deployments/complete-drain",
            "/config/publish",
            "/cache/invalidate",
            "/observability/log-level",
            "/token",
        ] {
            reserved.insert_exact(path);
        }
        reserved.insert_prefix("/api/onboard");
        reserved.insert_prefix("/runtime");
        reserved.insert_prefix("/deployments");
        reserved.insert_prefix("/config");
        reserved.insert_prefix("/cache");
        reserved.insert_prefix("/observability");
        reserved.insert_prefix("/v3/directline");
        reserved.insert_prefix("/directline");
        for domain in [
            Domain::Messaging,
            Domain::Events,
            Domain::Secrets,
            Domain::OAuth,
        ] {
            let name = domains::domain_name(domain);
            reserved.insert_prefix(&format!("/v1/{name}/ingress"));
            reserved.insert_prefix(&format!("/{name}/ingress"));
        }
        reserved
    }

    pub fn insert_exact(&mut self, path: &str) {
        self.exact_paths.insert(normalize_public_path(path));
    }

    pub fn insert_prefix(&mut self, path: &str) {
        self.prefix_paths.insert(normalize_public_path(path));
    }

    pub fn conflicts_with(&self, public_path: &str) -> bool {
        let normalized = normalize_public_path(public_path);
        self.exact_paths.contains(&normalized)
            || self
                .prefix_paths
                .iter()
                .any(|prefix| path_has_prefix(&normalized, prefix))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticRouteMatch<'a> {
    pub descriptor: &'a StaticRouteDescriptor,
    pub asset_path: String,
    pub request_is_directory: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActiveRouteTable {
    routes: Vec<StaticRouteDescriptor>,
}

impl ActiveRouteTable {
    pub fn from_plan(plan: &StaticRoutePlan) -> Self {
        let mut routes = plan.routes.clone();
        routes.sort_by(|a, b| {
            b.route_segments
                .len()
                .cmp(&a.route_segments.len())
                .then_with(|| a.public_path.cmp(&b.public_path))
        });
        Self { routes }
    }

    pub fn routes(&self) -> &[StaticRouteDescriptor] {
        &self.routes
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn match_request<'a>(&'a self, request_path: &str) -> Option<StaticRouteMatch<'a>> {
        let normalized = request_path
            .trim_start_matches('/')
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        let request_is_directory = request_path.ends_with('/');
        for descriptor in &self.routes {
            if normalized.len() < descriptor.route_segments.len() {
                continue;
            }
            let mut matched = true;
            for (route_segment, request_segment) in
                descriptor.route_segments.iter().zip(normalized.iter())
            {
                match route_segment {
                    RouteScopeSegment::Literal(expected) if expected != request_segment => {
                        matched = false;
                        break;
                    }
                    RouteScopeSegment::Literal(_)
                    | RouteScopeSegment::Tenant
                    | RouteScopeSegment::Team => {}
                }
            }
            if !matched {
                continue;
            }
            let asset_path = normalized[descriptor.route_segments.len()..].join("/");
            return Some(StaticRouteMatch {
                descriptor,
                asset_path,
                request_is_directory,
            });
        }
        None
    }
}

#[derive(Debug, Deserialize)]
struct StaticRoutesExtensionV1 {
    #[serde(default = "default_schema_version")]
    schema_version: u32,
    #[serde(default)]
    routes: Vec<StaticRouteRecord>,
}

#[derive(Clone, Debug, Deserialize)]
struct StaticRouteRecord {
    #[serde(default)]
    id: Option<String>,
    public_path: String,
    source_root: String,
    #[serde(default)]
    index_file: Option<String>,
    #[serde(default)]
    spa_fallback: Option<String>,
    /// Flat tenant flag (legacy format)
    #[serde(default)]
    tenant: bool,
    /// Flat team flag (legacy format)
    #[serde(default)]
    team: bool,
    /// Nested scope object (new format from pack.yaml)
    #[serde(default)]
    scope: Option<StaticRouteScopeRecord>,
    #[serde(default)]
    cache: Option<StaticRouteCacheRecord>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct StaticRouteScopeRecord {
    #[serde(default)]
    tenant: bool,
    #[serde(default)]
    team: bool,
}

impl StaticRouteRecord {
    /// Returns the effective tenant flag, checking nested scope first
    fn effective_tenant(&self) -> bool {
        self.scope.as_ref().map_or(self.tenant, |s| s.tenant)
    }

    /// Returns the effective team flag, checking nested scope first
    fn effective_team(&self) -> bool {
        self.scope.as_ref().map_or(self.team, |s| s.team)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct StaticRouteCacheRecord {
    strategy: String,
    #[serde(default)]
    max_age_seconds: Option<u64>,
}

fn default_schema_version() -> u32 {
    1
}

pub fn discover_from_bundle(
    bundle_root: &Path,
    reserved_routes: &ReservedRouteSet,
) -> anyhow::Result<StaticRoutePlan> {
    let mut plan = StaticRoutePlan::default();
    let pack_paths = collect_runtime_pack_paths(bundle_root)?;
    for pack_path in pack_paths {
        let descriptors = match read_pack_static_routes(&pack_path) {
            Ok(Some(descriptors)) => descriptors,
            Ok(None) => continue,
            Err(err) => {
                plan.blocking_failures.push(err.to_string());
                continue;
            }
        };
        plan.routes.extend(descriptors);
    }
    validate_plan(&mut plan, reserved_routes);
    check_bundle_assets_capability(bundle_root, &mut plan);
    Ok(plan)
}

/// Checks whether the bundle has overlay asset directories on disk but does not
/// declare the `greentic.cap.bundle_assets.read.v1` capability. Emits a warning
/// into the plan so operators know to formalize the capability contract.
fn check_bundle_assets_capability(bundle_root: &Path, plan: &mut StaticRoutePlan) {
    let assets_dir = bundle_root.join("assets");
    if !assets_dir.is_dir() {
        return;
    }
    let bundle_yaml_path = bundle_root.join("bundle.yaml");
    let has_capability = bundle_yaml_path
        .exists()
        .then(|| std::fs::read_to_string(&bundle_yaml_path).ok())
        .flatten()
        .map(|content| content.contains(crate::capabilities::CAP_BUNDLE_ASSETS_READ_V1))
        .unwrap_or(false);
    if !has_capability {
        plan.warnings.push(format!(
            "Bundle has ./assets/ directory but does not declare '{}' in bundle.yaml capabilities. \
             Consider adding it so packs can formally request bundle asset access.",
            crate::capabilities::CAP_BUNDLE_ASSETS_READ_V1,
        ));
    }
}

pub fn resolve_asset_path(route_match: &StaticRouteMatch<'_>) -> Option<String> {
    if route_match.asset_path.is_empty() || route_match.request_is_directory {
        return route_match.descriptor.index_file.clone();
    }
    Some(route_match.asset_path.clone())
}

pub fn fallback_asset_path(route_match: &StaticRouteMatch<'_>) -> Option<String> {
    route_match.descriptor.spa_fallback.clone()
}

pub fn cache_control_value(strategy: &CacheStrategy) -> Option<String> {
    match strategy {
        CacheStrategy::None => None,
        CacheStrategy::PublicMaxAge { max_age_seconds } => {
            Some(format!("public, max-age={max_age_seconds}"))
        }
    }
}

fn collect_runtime_pack_paths(bundle_root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut by_path = BTreeMap::new();
    let discover = if bundle_root.join("greentic.demo.yaml").exists() {
        domains::discover_provider_packs_cbor_only
    } else {
        domains::discover_provider_packs
    };
    for domain in [
        Domain::Messaging,
        Domain::Events,
        Domain::Secrets,
        Domain::OAuth,
    ] {
        for pack in discover(bundle_root, domain)? {
            by_path.entry(pack.path.clone()).or_insert(pack.path);
        }
    }
    Ok(by_path.into_values().collect())
}

fn read_pack_static_routes(pack_path: &Path) -> anyhow::Result<Option<Vec<StaticRouteDescriptor>>> {
    let file = std::fs::File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest_entry = archive.by_name("manifest.cbor").map_err(|err| {
        anyhow::anyhow!(
            "failed to open manifest.cbor in {}: {err}",
            pack_path.display()
        )
    })?;
    let mut bytes = Vec::new();
    manifest_entry.read_to_end(&mut bytes)?;
    let manifest = decode_pack_manifest(&bytes)
        .with_context(|| format!("failed to decode pack manifest in {}", pack_path.display()))?;
    let Some(extension) = manifest
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get(EXT_STATIC_ROUTES_V1))
    else {
        return Ok(None);
    };
    let inline = extension
        .inline
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("static-routes extension inline payload missing"))?;
    let ExtensionInline::Other(value) = inline else {
        anyhow::bail!("static-routes extension inline payload has unexpected type");
    };
    let decoded: StaticRoutesExtensionV1 = serde_json::from_value(value.clone())
        .with_context(|| "failed to parse greentic.static-routes.v1 payload")?;
    if decoded.schema_version != 1 {
        anyhow::bail!(
            "unsupported static-routes extension schema_version={} in {}",
            decoded.schema_version,
            pack_path.display()
        );
    }
    let pack_id = manifest.pack_id.as_str().to_string();
    let mut routes = Vec::new();
    for (idx, route) in decoded.routes.into_iter().enumerate() {
        routes.push(normalize_route_descriptor(&pack_id, pack_path, idx, route)?);
    }
    Ok(Some(routes))
}

fn normalize_route_descriptor(
    pack_id: &str,
    pack_path: &Path,
    idx: usize,
    route: StaticRouteRecord,
) -> anyhow::Result<StaticRouteDescriptor> {
    // Use effective tenant/team which checks nested scope first, then flat fields
    let tenant_scoped = route.effective_tenant();
    let team_scoped = route.effective_team();

    if team_scoped && !tenant_scoped {
        anyhow::bail!(
            "static route {} in {} sets team=true but tenant=false",
            route.id.as_deref().unwrap_or("<unnamed>"),
            pack_path.display()
        );
    }
    let public_path = normalize_public_path(&route.public_path);
    let route_segments = parse_route_segments(&public_path)?;
    let uses_tenant = route_segments
        .iter()
        .any(|segment| matches!(segment, RouteScopeSegment::Tenant));
    let uses_team = route_segments
        .iter()
        .any(|segment| matches!(segment, RouteScopeSegment::Team));
    if tenant_scoped != uses_tenant {
        anyhow::bail!(
            "static route {} in {} has inconsistent tenant flag/public_path",
            route.id.as_deref().unwrap_or("<unnamed>"),
            pack_path.display()
        );
    }
    if team_scoped != uses_team {
        anyhow::bail!(
            "static route {} in {} has inconsistent team flag/public_path",
            route.id.as_deref().unwrap_or("<unnamed>"),
            pack_path.display()
        );
    }

    let source_root = normalize_relative_asset_path(&route.source_root).ok_or_else(|| {
        anyhow::anyhow!(
            "static route {} in {} has invalid source_root {}",
            route.id.as_deref().unwrap_or("<unnamed>"),
            pack_path.display(),
            route.source_root
        )
    })?;
    let index_file = normalize_optional_relative_asset_path(route.index_file)?;
    let spa_fallback = normalize_optional_relative_asset_path(route.spa_fallback)?;
    let cache_strategy =
        normalize_cache_strategy(route.cache.as_ref(), pack_path, route.id.as_deref())?;

    Ok(StaticRouteDescriptor {
        route_id: route.id.unwrap_or_else(|| format!("{pack_id}::{idx}")),
        pack_id: pack_id.to_string(),
        pack_path: pack_path.to_path_buf(),
        public_path,
        source_root,
        index_file,
        spa_fallback,
        tenant_scoped,
        team_scoped,
        cache_strategy,
        route_segments,
    })
}

fn normalize_cache_strategy(
    cache: Option<&StaticRouteCacheRecord>,
    pack_path: &Path,
    route_id: Option<&str>,
) -> anyhow::Result<CacheStrategy> {
    let Some(cache) = cache else {
        return Ok(CacheStrategy::None);
    };
    match cache.strategy.trim() {
        "" | "none" => Ok(CacheStrategy::None),
        "public-max-age" => Ok(CacheStrategy::PublicMaxAge {
            max_age_seconds: cache.max_age_seconds.ok_or_else(|| {
                anyhow::anyhow!(
                    "static route {} in {} uses public-max-age without max_age_seconds",
                    route_id.unwrap_or("<unnamed>"),
                    pack_path.display()
                )
            })?,
        }),
        other => anyhow::bail!(
            "static route {} in {} uses unsupported cache.strategy {}",
            route_id.unwrap_or("<unnamed>"),
            pack_path.display(),
            other
        ),
    }
}

fn normalize_optional_relative_asset_path(value: Option<String>) -> anyhow::Result<Option<String>> {
    match value {
        Some(value) => normalize_relative_asset_path(&value)
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("invalid asset path {}", value)),
        None => Ok(None),
    }
}

pub fn normalize_relative_asset_path(path: &str) -> Option<String> {
    let mut segments = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(segment) => segments.push(segment.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if segments.is_empty() {
        return None;
    }
    Some(segments.join("/"))
}

fn parse_route_segments(path: &str) -> anyhow::Result<Vec<RouteScopeSegment>> {
    let segments = path
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        anyhow::bail!("public_path must not be /");
    }
    let mut parsed = Vec::new();
    for segment in segments {
        match segment {
            "{tenant}" => parsed.push(RouteScopeSegment::Tenant),
            "{team}" => parsed.push(RouteScopeSegment::Team),
            _ if segment.contains('{') || segment.contains('}') => {
                anyhow::bail!("unsupported public_path segment {}", segment)
            }
            _ => parsed.push(RouteScopeSegment::Literal(segment.to_string())),
        }
    }
    let team_pos = parsed
        .iter()
        .position(|segment| matches!(segment, RouteScopeSegment::Team));
    let tenant_pos = parsed
        .iter()
        .position(|segment| matches!(segment, RouteScopeSegment::Tenant));
    if let Some(team_pos) = team_pos {
        let Some(tenant_pos) = tenant_pos else {
            anyhow::bail!("public_path uses {{team}} without {{tenant}}");
        };
        if team_pos <= tenant_pos {
            anyhow::bail!("public_path must place {{team}} after {{tenant}}");
        }
    }
    Ok(parsed)
}

fn validate_plan(plan: &mut StaticRoutePlan, reserved_routes: &ReservedRouteSet) {
    let mut seen_paths = BTreeMap::<String, String>::new();
    for route in &plan.routes {
        if reserved_routes.conflicts_with(&route.public_path) {
            plan.blocking_failures.push(format!(
                "static route {} conflicts with reserved operator path space at {}",
                route.route_id, route.public_path
            ));
        }
        if let Some(existing) = seen_paths.insert(route.public_path.clone(), route.route_id.clone())
        {
            plan.blocking_failures.push(format!(
                "static route {} duplicates public_path {} already claimed by {}",
                route.route_id, route.public_path, existing
            ));
        }
    }
    for i in 0..plan.routes.len() {
        for j in (i + 1)..plan.routes.len() {
            let left = &plan.routes[i];
            let right = &plan.routes[j];
            if paths_overlap(&left.public_path, &right.public_path) {
                plan.blocking_failures.push(format!(
                    "static routes {} ({}) and {} ({}) overlap ambiguously",
                    left.route_id, left.public_path, right.route_id, right.public_path
                ));
            }
        }
    }
}

fn paths_overlap(left: &str, right: &str) -> bool {
    path_has_prefix(left, right) || path_has_prefix(right, left)
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    let prefix = prefix.trim_end_matches('/');
    path.strip_prefix(prefix)
        .map(|rest| rest.starts_with('/'))
        .unwrap_or(false)
}

fn normalize_public_path(path: &str) -> String {
    let trimmed = path.trim();
    let normalized = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    if normalized.len() > 1 {
        normalized.trim_end_matches('/').to_string()
    } else {
        normalized
    }
}

/// Read asset bytes from a pack file (ZIP archive) or directory.
pub fn read_pack_asset_bytes(
    pack_path: &Path,
    asset_path: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    if pack_path.is_dir() {
        let candidate = pack_path.join(asset_path);
        return match std::fs::read(candidate) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        };
    }
    let file = std::fs::File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut entry = match archive.by_name(asset_path) {
        Ok(entry) => entry,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(err) => {
            return Err(anyhow::anyhow!(
                "failed to open asset {} in {}: {err}",
                asset_path,
                pack_path.display()
            ));
        }
    };
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

/// Determine content type based on file extension.
pub fn content_type_for_path(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("map") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn active_route_table_matches_placeholders() {
        let route = StaticRouteDescriptor {
            route_id: "tenant-gui".into(),
            pack_id: "web".into(),
            pack_path: PathBuf::from("web.gtpack"),
            public_path: "/v1/web/webchat/{tenant}".into(),
            source_root: "assets/webchat".into(),
            index_file: Some("index.html".into()),
            spa_fallback: Some("index.html".into()),
            tenant_scoped: true,
            team_scoped: false,
            cache_strategy: CacheStrategy::None,
            route_segments: parse_route_segments("/v1/web/webchat/{tenant}").expect("segments"),
        };
        let table = ActiveRouteTable::from_plan(&StaticRoutePlan {
            routes: vec![route],
            warnings: Vec::new(),
            blocking_failures: Vec::new(),
        });
        let matched = table
            .match_request("/v1/web/webchat/demo/app.js")
            .expect("route match");
        assert_eq!(matched.asset_path, "app.js");
    }

    #[test]
    fn reserved_routes_include_directline() {
        let reserved = ReservedRouteSet::operator_defaults();
        assert!(reserved.conflicts_with("/v3/directline/conversations"));
        assert!(reserved.conflicts_with("/token"));
        assert!(!reserved.conflicts_with("/v1/web/webchat/demo"));
    }

    #[test]
    fn route_helpers_handle_indexes_cache_and_fallbacks() {
        let descriptor = StaticRouteDescriptor {
            route_id: "tenant-gui".into(),
            pack_id: "web".into(),
            pack_path: PathBuf::from("web.gtpack"),
            public_path: "/v1/web/webchat/{tenant}".into(),
            source_root: "assets/webchat".into(),
            index_file: Some("index.html".into()),
            spa_fallback: Some("index.html".into()),
            tenant_scoped: true,
            team_scoped: false,
            cache_strategy: CacheStrategy::PublicMaxAge {
                max_age_seconds: 300,
            },
            route_segments: parse_route_segments("/v1/web/webchat/{tenant}").expect("segments"),
        };
        let directory_match = StaticRouteMatch {
            descriptor: &descriptor,
            asset_path: String::new(),
            request_is_directory: true,
        };
        assert_eq!(
            resolve_asset_path(&directory_match),
            Some("index.html".to_string())
        );
        assert_eq!(
            fallback_asset_path(&directory_match),
            Some("index.html".to_string())
        );
        assert_eq!(
            cache_control_value(&descriptor.cache_strategy),
            Some("public, max-age=300".to_string())
        );
    }

    #[test]
    fn normalize_relative_asset_path_rejects_parent_and_root_segments() {
        assert_eq!(
            normalize_relative_asset_path("./assets/../index.html"),
            None
        );
        assert_eq!(normalize_relative_asset_path("/etc/passwd"), None);
        assert_eq!(
            normalize_relative_asset_path("assets/./index.html"),
            Some("assets/index.html".to_string())
        );
    }

    #[test]
    fn parse_route_segments_rejects_invalid_team_placement() {
        assert!(parse_route_segments("/").is_err());
        assert!(parse_route_segments("/{team}/dashboard").is_err());
        assert!(parse_route_segments("/{team}/{tenant}").is_err());
        assert!(parse_route_segments("/v1/{tenant}/bad{segment}").is_err());
    }

    #[test]
    fn normalize_route_descriptor_rejects_inconsistent_scope_flags() {
        let err = normalize_route_descriptor(
            "web",
            Path::new("/tmp/web.gtpack"),
            0,
            StaticRouteRecord {
                id: Some("route".to_string()),
                public_path: "/web/{tenant}".to_string(),
                source_root: "assets/web".to_string(),
                index_file: None,
                spa_fallback: None,
                tenant: false,
                team: false,
                scope: Some(StaticRouteScopeRecord::default()),
                cache: None,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("inconsistent tenant flag"));
    }

    #[test]
    fn normalize_cache_strategy_validates_supported_values() {
        let none = normalize_cache_strategy(None, Path::new("/tmp/web.gtpack"), Some("route"))
            .expect("none");
        assert_eq!(none, CacheStrategy::None);

        let cache = StaticRouteCacheRecord {
            strategy: "public-max-age".to_string(),
            max_age_seconds: Some(60),
        };
        assert_eq!(
            normalize_cache_strategy(Some(&cache), Path::new("/tmp/web.gtpack"), Some("route"))
                .expect("cache"),
            CacheStrategy::PublicMaxAge {
                max_age_seconds: 60
            }
        );

        let err = normalize_cache_strategy(
            Some(&StaticRouteCacheRecord {
                strategy: "public-max-age".to_string(),
                max_age_seconds: None,
            }),
            Path::new("/tmp/web.gtpack"),
            Some("route"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("without max_age_seconds"));
    }

    #[test]
    fn validate_plan_reports_reserved_duplicate_and_overlap_paths() {
        let mut plan = StaticRoutePlan {
            routes: vec![
                StaticRouteDescriptor {
                    route_id: "a".into(),
                    pack_id: "web".into(),
                    pack_path: PathBuf::from("a.gtpack"),
                    public_path: "/runtime".into(),
                    source_root: "assets/a".into(),
                    index_file: None,
                    spa_fallback: None,
                    tenant_scoped: false,
                    team_scoped: false,
                    cache_strategy: CacheStrategy::None,
                    route_segments: parse_route_segments("/runtime").expect("segments"),
                },
                StaticRouteDescriptor {
                    route_id: "b".into(),
                    pack_id: "web".into(),
                    pack_path: PathBuf::from("b.gtpack"),
                    public_path: "/web/app".into(),
                    source_root: "assets/b".into(),
                    index_file: None,
                    spa_fallback: None,
                    tenant_scoped: false,
                    team_scoped: false,
                    cache_strategy: CacheStrategy::None,
                    route_segments: parse_route_segments("/web/app").expect("segments"),
                },
                StaticRouteDescriptor {
                    route_id: "c".into(),
                    pack_id: "web".into(),
                    pack_path: PathBuf::from("c.gtpack"),
                    public_path: "/web/app/dashboard".into(),
                    source_root: "assets/c".into(),
                    index_file: None,
                    spa_fallback: None,
                    tenant_scoped: false,
                    team_scoped: false,
                    cache_strategy: CacheStrategy::None,
                    route_segments: parse_route_segments("/web/app/dashboard").expect("segments"),
                },
            ],
            warnings: Vec::new(),
            blocking_failures: Vec::new(),
        };

        validate_plan(&mut plan, &ReservedRouteSet::operator_defaults());

        assert!(
            plan.blocking_failures
                .iter()
                .any(|value| value.contains("reserved operator path space"))
        );
        assert!(
            plan.blocking_failures
                .iter()
                .any(|value| value.contains("overlap ambiguously"))
        );
    }

    #[test]
    fn path_utilities_handle_prefixes_and_normalization() {
        assert!(paths_overlap("/web", "/web/app"));
        assert!(path_has_prefix("/web/app", "/web"));
        assert!(!path_has_prefix("/websocket", "/web"));
        assert_eq!(normalize_public_path(" web/app/ "), "/web/app");
    }

    #[test]
    fn read_pack_asset_bytes_reads_from_directory_packs() {
        let dir = tempdir().expect("tempdir");
        let asset_dir = dir.path().join("assets").join("web");
        fs::create_dir_all(&asset_dir).expect("mkdir");
        let asset_path = asset_dir.join("index.html");
        fs::write(&asset_path, "<html>ok</html>").expect("write asset");

        let bytes = read_pack_asset_bytes(dir.path(), "assets/web/index.html").expect("read asset");
        assert_eq!(bytes, Some(b"<html>ok</html>".to_vec()));
        assert_eq!(
            read_pack_asset_bytes(dir.path(), "assets/web/missing.html").expect("missing"),
            None
        );
        assert_eq!(content_type_for_path("site/app.woff2"), "font/woff2");
    }
}
