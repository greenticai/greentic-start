//! Pack-declared HTTP route discovery for the ingress server.
//!
//! Packs can declare API routes they handle via the `greentic.http-routes.v1`
//! extension in their manifest. At startup the ingress server discovers these
//! routes and dispatches matching requests to the provider's `ingest_http`
//! operation through the generic ingress pipeline.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use greentic_deploy_spec::{BundleId, DeploymentId, RevisionId};
use greentic_types::{
    ExtensionInline, PROVIDER_EXTENSION_ID, ProviderExtensionInline, decode_pack_manifest,
};
use serde::Deserialize;
use zip::ZipArchive;

use crate::domains::{self, Domain};

pub const EXT_HTTP_ROUTES_V1: &str = "greentic.http-routes.v1";

/// Op name a provider component must export to be eligible for synthesized
/// webhook ingress routes (see [`synthesize_provider_ingest_routes`]).
pub const INGEST_HTTP_OP: &str = "ingest_http";

/// Deployment provenance of a route. Present only for routes discovered from a
/// materialized runtime-config (multi-revision deployments, produced in B4).
/// Routes discovered from a single bundle have no scope (`None` = legacy),
/// matching the `Option = legacy` discipline used by `RuntimeKey`.
#[derive(Clone, Debug)]
pub struct RevisionScope {
    pub deployment_id: DeploymentId,
    pub bundle_id: BundleId,
    pub revision_id: RevisionId,
}

/// A single HTTP route declared by a pack.
#[derive(Clone, Debug)]
pub struct HttpRouteDescriptor {
    #[allow(dead_code)]
    pub route_id: String,
    pub pack_id: String,
    pub pattern: String,
    pub methods: Vec<String>,
    /// The provider operation to invoke (e.g. `ingest_http`). Used when the
    /// dispatch layer needs to call a non-default operation on the provider.
    #[allow(dead_code)]
    pub provider_op: String,
    /// The provider's `provider_type` (e.g. `messaging.telegram.bot`) when the
    /// route was synthesized from `greentic.provider-extension.v1`. The
    /// dispatch layer uses it to resolve the provider binding by type within
    /// the revision's runtime. `None` for routes discovered via the legacy
    /// `greentic.http-routes.v1` extension, which name no provider.
    #[allow(dead_code)]
    pub provider_type: Option<String>,
    pub domain: Domain,
    /// Deployment/bundle/revision this route belongs to, or `None` for a
    /// legacy single-bundle route (every route discovered today).
    pub scope: Option<RevisionScope>,
    /// Parsed segments from the pattern for matching.
    segments: Vec<RouteSegment>,
}

#[derive(Clone, Debug)]
enum RouteSegment {
    Literal(String),
    Tenant,
    Team,
    /// Wildcard: matches zero or more remaining path segments.
    Wildcard,
}

/// Ordered table of pack-declared HTTP routes, sorted by specificity.
#[derive(Default)]
pub struct HttpRouteTable {
    routes: Vec<HttpRouteDescriptor>,
}

pub struct HttpRouteMatch<'a> {
    pub descriptor: &'a HttpRouteDescriptor,
    pub tenant: String,
    pub team: String,
}

/// Test-only descriptor constructor; `segments` is private so callers in other
/// modules (e.g. the ingress dispatch tests) cannot build one directly.
#[cfg(test)]
pub(crate) fn descriptor_for_test(
    pattern: &str,
    methods: &[&str],
    domain: Domain,
    scope: Option<RevisionScope>,
) -> HttpRouteDescriptor {
    HttpRouteDescriptor {
        route_id: pattern.to_string(),
        pack_id: "test-pack".to_string(),
        pattern: pattern.to_string(),
        methods: methods.iter().map(|m| m.to_string()).collect(),
        provider_op: INGEST_HTTP_OP.to_string(),
        provider_type: None,
        domain,
        scope,
        segments: parse_route_pattern(pattern),
    }
}

impl HttpRouteTable {
    pub fn from_descriptors(mut routes: Vec<HttpRouteDescriptor>) -> Self {
        // Sort by segment count descending (most specific first).
        // Wildcard routes come after literal routes of equal prefix length.
        routes.sort_by(|a, b| {
            let a_wild = a
                .segments
                .iter()
                .any(|s| matches!(s, RouteSegment::Wildcard));
            let b_wild = b
                .segments
                .iter()
                .any(|s| matches!(s, RouteSegment::Wildcard));
            b.segments
                .len()
                .cmp(&a.segments.len())
                .then(a_wild.cmp(&b_wild))
        });
        Self { routes }
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    #[allow(dead_code)]
    pub fn routes(&self) -> &[HttpRouteDescriptor] {
        &self.routes
    }

    /// Match an incoming request against legacy (unscoped) routes only.
    /// Returns the first matching route with extracted tenant/team values.
    ///
    /// Revision-scoped routes are skipped here so the single-bundle ingress
    /// path never routes to a deployment revision; that path goes through
    /// [`Self::match_request_for_revision`] after the dispatcher resolves a
    /// revision. Today every discovered route is legacy, so this is the only
    /// live matcher.
    pub fn match_request(&self, path: &str, method: &str) -> Option<HttpRouteMatch<'_>> {
        self.match_first(path, method, |route| route.scope.is_none())
    }

    /// Match an incoming request against routes belonging to a specific
    /// resolved scope. Used by the ingress dispatcher seam once a
    /// [`crate::revision_dispatcher::RevisionDispatcher`] picks a revision.
    ///
    /// Matches on the **full** `(deployment_id, bundle_id, revision_id)`, not
    /// just the revision: a shared route table can hold entries for several
    /// deployments, and matching on revision alone could route a dispatch
    /// outcome for one deployment to a route stamped for another under id
    /// reuse or stale entries.
    pub fn match_request_for_revision(
        &self,
        path: &str,
        method: &str,
        scope: &RevisionScope,
    ) -> Option<HttpRouteMatch<'_>> {
        self.match_first(path, method, |route| {
            route.scope.as_ref().is_some_and(|s| {
                s.deployment_id == scope.deployment_id
                    && s.bundle_id == scope.bundle_id
                    && s.revision_id == scope.revision_id
            })
        })
    }

    fn match_first(
        &self,
        path: &str,
        method: &str,
        accept: impl Fn(&HttpRouteDescriptor) -> bool,
    ) -> Option<HttpRouteMatch<'_>> {
        let request_segments: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        for route in &self.routes {
            if !accept(route) {
                continue;
            }
            if !route.methods.is_empty()
                && !route.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
            {
                continue;
            }
            if let Some(m) = try_match_route(route, &request_segments) {
                return Some(m);
            }
        }
        None
    }
}

fn try_match_route<'a>(
    route: &'a HttpRouteDescriptor,
    request_segments: &[&str],
) -> Option<HttpRouteMatch<'a>> {
    let mut tenant = String::from("default");
    let mut team = String::from("default");
    let mut req_idx = 0;

    for seg in &route.segments {
        match seg {
            RouteSegment::Literal(expected) => {
                if req_idx >= request_segments.len() {
                    return None;
                }
                if !request_segments[req_idx].eq_ignore_ascii_case(expected) {
                    return None;
                }
                req_idx += 1;
            }
            RouteSegment::Tenant => {
                if req_idx >= request_segments.len() {
                    return None;
                }
                tenant = request_segments[req_idx].to_string();
                if tenant.is_empty() {
                    return None;
                }
                req_idx += 1;
            }
            RouteSegment::Team => {
                if req_idx >= request_segments.len() {
                    return None;
                }
                team = request_segments[req_idx].to_string();
                req_idx += 1;
            }
            RouteSegment::Wildcard => {
                // Wildcard matches all remaining segments
                return Some(HttpRouteMatch {
                    descriptor: route,
                    tenant,
                    team,
                });
            }
        }
    }

    // All route segments consumed; allow exact match or trailing path
    if req_idx <= request_segments.len() {
        Some(HttpRouteMatch {
            descriptor: route,
            tenant,
            team,
        })
    } else {
        None
    }
}

fn parse_route_pattern(pattern: &str) -> Vec<RouteSegment> {
    pattern
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| {
            if seg == "{tenant}" {
                RouteSegment::Tenant
            } else if seg == "{team}" {
                RouteSegment::Team
            } else if seg.ends_with("*}") || seg == "*" {
                RouteSegment::Wildcard
            } else {
                // Strip braces from unknown placeholders, treat as literal
                let cleaned = seg.trim_start_matches('{').trim_end_matches('}');
                RouteSegment::Literal(cleaned.to_string())
            }
        })
        .collect()
}

fn parse_domain(domain_str: &str) -> Option<Domain> {
    match domain_str.to_ascii_lowercase().as_str() {
        "messaging" => Some(Domain::Messaging),
        "events" => Some(Domain::Events),
        "secrets" => Some(Domain::Secrets),
        "oauth" => Some(Domain::OAuth),
        _ => None,
    }
}

// ── Extension schema ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct HttpRoutesExtensionV1 {
    #[serde(default = "default_schema_version")]
    schema_version: u32,
    #[serde(default)]
    routes: Vec<HttpRouteRecord>,
}

fn default_schema_version() -> u32 {
    1
}

#[derive(Deserialize)]
struct HttpRouteRecord {
    #[serde(default)]
    id: Option<String>,
    pattern: String,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default = "default_provider_op")]
    provider_op: String,
    #[serde(default = "default_domain")]
    domain: String,
}

fn default_provider_op() -> String {
    "ingest_http".to_string()
}

fn default_domain() -> String {
    "messaging".to_string()
}

// ── Discovery ───────────────────────────────────────────────────────────────

/// Discover HTTP routes declared by packs in the bundle.
pub fn discover_http_routes_from_bundle(
    bundle_root: &Path,
) -> anyhow::Result<Vec<HttpRouteDescriptor>> {
    let pack_paths = collect_runtime_pack_paths(bundle_root)?;
    Ok(discover_routes_from_packs(&pack_paths, None))
}

/// Discover HTTP routes from a revision's pinned pack files, stamping each with
/// the revision's [`RevisionScope`].
///
/// A revision is a set of pinned `.gtpack` files (not a bundle directory), so
/// this takes explicit pack paths and reuses the same per-pack manifest reader
/// as [`discover_http_routes_from_bundle`]. The scope makes the resulting
/// descriptors matchable via [`HttpRouteTable::match_request_for_revision`].
pub fn discover_revision_http_routes(
    pack_paths: &[PathBuf],
    scope: &RevisionScope,
) -> Vec<HttpRouteDescriptor> {
    discover_routes_from_packs(pack_paths, Some(scope))
}

/// Read pack-declared HTTP routes from each pack path, optionally stamping every
/// route with `scope` (`Some` = revision-scoped discovery, `None` = legacy
/// single-bundle). A pack that declares no routes — or fails to read — is
/// skipped with a warning so one malformed pack can't abort discovery of the
/// rest.
fn discover_routes_from_packs(
    pack_paths: &[PathBuf],
    scope: Option<&RevisionScope>,
) -> Vec<HttpRouteDescriptor> {
    let mut routes = Vec::new();
    for pack_path in pack_paths {
        match read_pack_http_routes(pack_path) {
            Ok(Some(mut pack_routes)) => {
                if let Some(scope) = scope {
                    for route in &mut pack_routes {
                        route.scope = Some(scope.clone());
                    }
                }
                routes.extend(pack_routes);
            }
            Ok(None) => continue,
            Err(err) => {
                crate::operator_log::warn(
                    module_path!(),
                    format!(
                        "failed to read http-routes from {}: {err:#}",
                        pack_path.display()
                    ),
                );
            }
        }
    }
    routes
}

fn read_pack_http_routes(pack_path: &Path) -> anyhow::Result<Option<Vec<HttpRouteDescriptor>>> {
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
    let extensions = match manifest.extensions.as_ref() {
        Some(ext) => ext,
        None => return Ok(None),
    };

    if let Some(extension) = extensions.get(EXT_HTTP_ROUTES_V1) {
        return parse_http_routes_v1(extension, manifest.pack_id.as_str(), pack_path);
    }
    Ok(None)
}

fn parse_http_routes_v1(
    extension: &greentic_types::pack_manifest::ExtensionRef,
    pack_id: &str,
    pack_path: &Path,
) -> anyhow::Result<Option<Vec<HttpRouteDescriptor>>> {
    let inline = extension
        .inline
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("http-routes extension inline payload missing"))?;
    let ExtensionInline::Other(value) = inline else {
        anyhow::bail!("http-routes extension inline payload has unexpected type");
    };
    let decoded: HttpRoutesExtensionV1 = serde_json::from_value(value.clone())
        .with_context(|| "failed to parse greentic.http-routes.v1 payload")?;
    if decoded.schema_version != 1 {
        anyhow::bail!(
            "unsupported http-routes extension schema_version={} in {}",
            decoded.schema_version,
            pack_path.display()
        );
    }
    let mut routes = Vec::new();
    for (idx, record) in decoded.routes.into_iter().enumerate() {
        let route_id = record
            .id
            .unwrap_or_else(|| format!("{pack_id}:http-route-{idx}"));
        let domain = parse_domain(&record.domain).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown domain '{}' in http-route {route_id}",
                record.domain
            )
        })?;
        let segments = parse_route_pattern(&record.pattern);
        routes.push(HttpRouteDescriptor {
            route_id,
            pack_id: pack_id.to_string(),
            pattern: record.pattern,
            methods: record.methods,
            provider_op: record.provider_op,
            provider_type: None,
            domain,
            // Single-bundle discovery: no deployment provenance. B4's
            // runtime-config-backed discovery stamps `Some(..)`.
            scope: None,
            segments,
        });
    }
    Ok(Some(routes))
}

fn collect_runtime_pack_paths(bundle_root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut seen = std::collections::BTreeMap::new();
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
            seen.entry(pack.path.clone()).or_insert(pack.path);
        }
    }
    Ok(seen.into_values().collect())
}

// ── Provider-ingress synthesis ──────────────────────────────────────────────
//
// Packs declaring `greentic.provider-extension.v1` providers whose `ops`
// include `ingest_http` get a webhook route synthesized for them — one per
// `(provider, deployment-prefix)` pair. The URL convention is
// `<prefix>/webhook/<provider-name>` (POST), where `<provider-name>` is
// derived from `provider_type` by stripping a leading `messaging.` and any
// trailing kind suffix (`.bot`, `.graph`, `.client`, …) → `telegram`, `teams`,
// `slack`, etc.
//
// This is intentionally separate from the `greentic.http-routes.v1` reader:
// the two extensions coexist, the http-routes reader skips packs that only
// declare a provider, and vice versa.

/// Synthesize webhook ingress routes for any provider in the given packs whose
/// `greentic.provider-extension.v1` declaration includes the `ingest_http` op.
///
/// One descriptor is emitted per (`ingest_http` provider, `path_prefix`) pair.
/// Each descriptor is stamped with `scope` so it matches only inside the
/// owning deployment via [`HttpRouteTable::match_request_for_revision`].
///
/// Packs that don't declare a provider extension, or whose providers don't
/// expose `ingest_http`, are skipped silently. Unreadable packs emit a
/// warning and are skipped (same posture as
/// [`discover_revision_http_routes`]).
///
/// An empty `path_prefixes` slice yields no routes for this revision: the
/// deployment hasn't claimed any URL space yet, so there is nowhere safe to
/// mount a webhook. (`DeploymentRouteTable` treats empty as "match any path",
/// but synthesizing a root-prefix `/webhook/<name>` for a deployment that
/// declared no prefixes would steal that URL from any other deployment that
/// later binds at `/`.)
pub fn synthesize_provider_ingest_routes(
    pack_paths: &[PathBuf],
    scope: &RevisionScope,
    path_prefixes: &[String],
) -> Vec<HttpRouteDescriptor> {
    if path_prefixes.is_empty() {
        return Vec::new();
    }
    let mut routes = Vec::new();
    for pack_path in pack_paths {
        let (pack_id, inline) = match read_pack_provider_extension(pack_path) {
            Ok(Some(pair)) => pair,
            Ok(None) => continue,
            Err(err) => {
                crate::operator_log::warn(
                    module_path!(),
                    format!(
                        "failed to read provider extension from {}: {err:#}",
                        pack_path.display()
                    ),
                );
                continue;
            }
        };

        for provider in &inline.providers {
            if !provider.ops.iter().any(|op| op == INGEST_HTTP_OP) {
                continue;
            }
            let Some(name) = derive_provider_name(&provider.provider_type) else {
                crate::operator_log::warn(
                    module_path!(),
                    format!(
                        "skipping ingest_http route synthesis for {}: cannot derive a \
                         provider-name from provider_type `{}`",
                        pack_path.display(),
                        provider.provider_type,
                    ),
                );
                continue;
            };
            for prefix in path_prefixes {
                let pattern = build_webhook_pattern(prefix, &name);
                let segments = parse_route_pattern(&pattern);
                routes.push(HttpRouteDescriptor {
                    route_id: format!("{pack_id}:provider-webhook:{name}@{prefix}"),
                    pack_id: pack_id.clone(),
                    pattern,
                    methods: vec!["POST".to_string()],
                    provider_op: INGEST_HTTP_OP.to_string(),
                    provider_type: Some(provider.provider_type.clone()),
                    domain: Domain::Messaging,
                    scope: Some(scope.clone()),
                    segments,
                });
            }
        }
    }
    routes
}

fn read_pack_provider_extension(
    pack_path: &Path,
) -> anyhow::Result<Option<(String, ProviderExtensionInline)>> {
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
    let extensions = match manifest.extensions.as_ref() {
        Some(ext) => ext,
        None => return Ok(None),
    };
    let Some(extension) = extensions.get(PROVIDER_EXTENSION_ID) else {
        return Ok(None);
    };
    let Some(inline) = extension.inline.as_ref() else {
        return Ok(None);
    };
    let ExtensionInline::Provider(provider_inline) = inline else {
        return Ok(None);
    };
    Ok(Some((
        manifest.pack_id.as_str().to_string(),
        provider_inline.clone(),
    )))
}

/// Derive a URL-safe provider-name from a `provider_type` like
/// `messaging.telegram.bot` → `telegram`. The leading `messaging.` is stripped
/// when present, then the trailing kind suffix (`bot`, `graph`, `client`,
/// `gui`, `webhook`) is dropped if there is more than one segment remaining.
/// Returns `None` for unrecognizable shapes (empty, no dots after stripping).
fn derive_provider_name(provider_type: &str) -> Option<String> {
    let trimmed = provider_type
        .strip_prefix("messaging.")
        .unwrap_or(provider_type);
    let mut parts: Vec<&str> = trimmed.split('.').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    if parts.len() > 1 {
        let last = *parts.last().unwrap();
        if matches!(last, "bot" | "graph" | "client" | "gui" | "webhook") {
            parts.pop();
        }
    }
    let name = parts.join("-").to_ascii_lowercase();
    if name.is_empty() { None } else { Some(name) }
}

fn build_webhook_pattern(prefix: &str, name: &str) -> String {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        format!("/webhook/{name}")
    } else {
        format!("/{trimmed}/webhook/{name}")
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_route(pattern: &str, methods: &[&str], domain: Domain) -> HttpRouteDescriptor {
        make_scoped_route(pattern, methods, domain, None)
    }

    fn make_scoped_route(
        pattern: &str,
        methods: &[&str],
        domain: Domain,
        scope: Option<RevisionScope>,
    ) -> HttpRouteDescriptor {
        super::descriptor_for_test(pattern, methods, domain, scope)
    }

    #[test]
    fn matches_exact_literal_route() {
        let table = HttpRouteTable::from_descriptors(vec![make_route(
            "/v1/messaging/webchat/{tenant}/token",
            &["GET"],
            Domain::Messaging,
        )]);

        let m = table
            .match_request("/v1/messaging/webchat/demo/token", "GET")
            .expect("should match");
        assert_eq!(m.tenant, "demo");
        assert_eq!(m.descriptor.pack_id, "test-pack");

        // Wrong method
        assert!(
            table
                .match_request("/v1/messaging/webchat/demo/token", "DELETE")
                .is_none()
        );

        // Wrong path
        assert!(
            table
                .match_request("/v1/messaging/webchat/demo/other", "GET")
                .is_none()
        );
    }

    #[test]
    fn matches_wildcard_route() {
        let table = HttpRouteTable::from_descriptors(vec![make_route(
            "/v1/messaging/webchat/{tenant}/v3/directline/{path*}",
            &["GET", "POST"],
            Domain::Messaging,
        )]);

        let m = table
            .match_request(
                "/v1/messaging/webchat/acme/v3/directline/conversations/123/activities",
                "POST",
            )
            .expect("should match wildcard");
        assert_eq!(m.tenant, "acme");

        let m = table
            .match_request(
                "/v1/messaging/webchat/demo/v3/directline/conversations",
                "GET",
            )
            .expect("should match wildcard");
        assert_eq!(m.tenant, "demo");
    }

    #[test]
    fn empty_methods_matches_any_method() {
        let table = HttpRouteTable::from_descriptors(vec![make_route(
            "/v1/messaging/webchat/{tenant}/auth/config",
            &[],
            Domain::Messaging,
        )]);

        assert!(
            table
                .match_request("/v1/messaging/webchat/demo/auth/config", "GET")
                .is_some()
        );
        assert!(
            table
                .match_request("/v1/messaging/webchat/demo/auth/config", "POST")
                .is_some()
        );
    }

    #[test]
    fn specific_routes_take_priority_over_wildcards() {
        let table = HttpRouteTable::from_descriptors(vec![
            make_route(
                "/v1/messaging/webchat/{tenant}/v3/directline/{path*}",
                &[],
                Domain::Messaging,
            ),
            make_route(
                "/v1/messaging/webchat/{tenant}/token",
                &["GET"],
                Domain::Messaging,
            ),
        ]);

        let m = table
            .match_request("/v1/messaging/webchat/demo/token", "GET")
            .expect("should match specific route");
        assert!(m.descriptor.pattern.contains("token"));
    }

    #[test]
    fn no_match_returns_none() {
        let table = HttpRouteTable::from_descriptors(vec![make_route(
            "/v1/messaging/webchat/{tenant}/token",
            &["GET"],
            Domain::Messaging,
        )]);

        assert!(table.match_request("/healthz", "GET").is_none());
        assert!(
            table
                .match_request("/v1/events/ingress/p/t", "GET")
                .is_none()
        );
    }

    #[test]
    fn tenant_and_team_extraction() {
        let table = HttpRouteTable::from_descriptors(vec![make_route(
            "/v1/messaging/ingress/{tenant}/{team}/handler",
            &[],
            Domain::Messaging,
        )]);

        let m = table
            .match_request("/v1/messaging/ingress/acme/support/handler", "POST")
            .expect("should match");
        assert_eq!(m.tenant, "acme");
        assert_eq!(m.team, "support");
    }

    fn scope_for(deployment_id: DeploymentId, revision_id: RevisionId) -> RevisionScope {
        RevisionScope {
            deployment_id,
            bundle_id: BundleId::new("acme-bundle"),
            revision_id,
        }
    }

    #[test]
    fn match_request_skips_revision_scoped_routes() {
        let rev = RevisionId::new();
        let table = HttpRouteTable::from_descriptors(vec![make_scoped_route(
            "/v1/messaging/webchat/{tenant}/token",
            &["GET"],
            Domain::Messaging,
            Some(scope_for(DeploymentId::new(), rev)),
        )]);

        // Legacy matcher ignores scoped routes.
        assert!(
            table
                .match_request("/v1/messaging/webchat/demo/token", "GET")
                .is_none()
        );
    }

    #[test]
    fn match_request_for_revision_only_matches_that_revision() {
        let deployment = DeploymentId::new();
        let scope_a = scope_for(deployment, RevisionId::new());
        let scope_b = scope_for(deployment, RevisionId::new());
        let table = HttpRouteTable::from_descriptors(vec![
            make_scoped_route(
                "/v1/messaging/webchat/{tenant}/token",
                &["GET"],
                Domain::Messaging,
                Some(scope_a.clone()),
            ),
            make_scoped_route(
                "/v1/messaging/webchat/{tenant}/token",
                &["GET"],
                Domain::Messaging,
                Some(scope_b.clone()),
            ),
        ]);

        let m = table
            .match_request_for_revision("/v1/messaging/webchat/demo/token", "GET", &scope_a)
            .expect("should match revision A's route");
        assert_eq!(
            m.descriptor.scope.as_ref().unwrap().revision_id,
            scope_a.revision_id
        );

        // No legacy route exists, so the unscoped matcher finds nothing.
        assert!(
            table
                .match_request("/v1/messaging/webchat/demo/token", "GET")
                .is_none()
        );

        // A scope for a revision with no routes matches nothing.
        let unknown = scope_for(deployment, RevisionId::new());
        assert!(
            table
                .match_request_for_revision("/v1/messaging/webchat/demo/token", "GET", &unknown)
                .is_none()
        );
    }

    #[test]
    fn match_request_for_revision_distinguishes_deployments() {
        // Same revision id stamped under two different deployments. Matching on
        // the full scope must not route one deployment's request to the other's
        // route (regression for revision-only matching).
        let revision = RevisionId::new();
        let scope_a = scope_for(DeploymentId::new(), revision);
        let scope_b = scope_for(DeploymentId::new(), revision);
        let table = HttpRouteTable::from_descriptors(vec![make_scoped_route(
            "/v1/messaging/webchat/{tenant}/token",
            &["GET"],
            Domain::Messaging,
            Some(scope_a.clone()),
        )]);

        assert!(
            table
                .match_request_for_revision("/v1/messaging/webchat/demo/token", "GET", &scope_a)
                .is_some(),
            "deployment A's scope matches its own route"
        );
        assert!(
            table
                .match_request_for_revision("/v1/messaging/webchat/demo/token", "GET", &scope_b)
                .is_none(),
            "deployment B's scope must not match deployment A's route despite equal revision id"
        );
    }

    #[test]
    fn match_request_for_revision_skips_legacy_routes() {
        let table = HttpRouteTable::from_descriptors(vec![make_route(
            "/v1/messaging/webchat/{tenant}/token",
            &["GET"],
            Domain::Messaging,
        )]);

        let scope = scope_for(DeploymentId::new(), RevisionId::new());
        assert!(
            table
                .match_request_for_revision("/v1/messaging/webchat/demo/token", "GET", &scope)
                .is_none()
        );
    }

    #[test]
    fn parse_route_pattern_handles_variants() {
        let segs = parse_route_pattern("/v1/{tenant}/v3/directline/{path*}");
        assert!(matches!(segs[0], RouteSegment::Literal(ref s) if s == "v1"));
        assert!(matches!(segs[1], RouteSegment::Tenant));
        assert!(matches!(segs[2], RouteSegment::Literal(ref s) if s == "v3"));
        assert!(matches!(segs[3], RouteSegment::Literal(ref s) if s == "directline"));
        assert!(matches!(segs[4], RouteSegment::Wildcard));
    }

    /// Write a minimal `.gtpack` whose manifest declares a single
    /// `greentic.http-routes.v1` route, mirroring the real on-disk shape. The
    /// manifest is built via plain serde then re-encoded with the symbol-table
    /// CBOR codec [`decode_pack_manifest`] expects.
    fn write_http_routes_pack(path: &Path, pack_id: &str, pattern: &str) {
        use std::io::Write as _;
        use zip::write::FileOptions;

        let manifest_json = serde_json::json!({
            "schema_version": "1.0.0",
            "pack_id": pack_id,
            "version": "1.0.0",
            "kind": "provider",
            "publisher": "tests",
            "extensions": {
                EXT_HTTP_ROUTES_V1: {
                    "kind": EXT_HTTP_ROUTES_V1,
                    "version": "1.0.0",
                    "inline": {
                        "schema_version": 1,
                        "routes": [{
                            "pattern": pattern,
                            "methods": ["GET"],
                            "domain": "messaging"
                        }]
                    }
                }
            }
        });
        let manifest: greentic_types::PackManifest =
            serde_json::from_value(manifest_json).expect("manifest deserializes");
        let bytes = greentic_types::encode_pack_manifest(&manifest).expect("manifest encodes");
        let file = std::fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())
            .unwrap();
        zip.write_all(&bytes).unwrap();
        zip.finish().unwrap();
    }

    #[test]
    fn discover_revision_http_routes_stamps_scope() {
        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("alpha.gtpack");
        let pattern = "/v1/messaging/webchat/{tenant}/token";
        write_http_routes_pack(&pack, "alpha", pattern);

        let scope = RevisionScope {
            deployment_id: DeploymentId::new(),
            bundle_id: BundleId::new("acme-bundle"),
            revision_id: RevisionId::new(),
        };
        let routes = discover_revision_http_routes(&[pack], &scope);
        assert_eq!(routes.len(), 1, "one route discovered");
        assert_eq!(routes[0].pattern, pattern);
        let stamped = routes[0].scope.as_ref().expect("scope stamped");
        assert_eq!(stamped.deployment_id, scope.deployment_id);
        assert_eq!(stamped.bundle_id, scope.bundle_id);
        assert_eq!(stamped.revision_id, scope.revision_id);

        // The stamped route is matchable for its scope, invisible to the legacy
        // matcher.
        let table = HttpRouteTable::from_descriptors(routes);
        assert!(
            table
                .match_request_for_revision("/v1/messaging/webchat/demo/token", "GET", &scope)
                .is_some()
        );
        assert!(
            table
                .match_request("/v1/messaging/webchat/demo/token", "GET")
                .is_none()
        );
    }

    #[test]
    fn discover_revision_http_routes_skips_unreadable_pack() {
        let dir = tempfile::tempdir().unwrap();
        // Not a zip — discovery must skip it (with a warning) and not abort.
        let bad = dir.path().join("garbage.gtpack");
        std::fs::write(&bad, b"not a zip archive").unwrap();
        let missing = dir.path().join("does-not-exist.gtpack");

        let scope = RevisionScope {
            deployment_id: DeploymentId::new(),
            bundle_id: BundleId::new("acme-bundle"),
            revision_id: RevisionId::new(),
        };
        let routes = discover_revision_http_routes(&[bad, missing], &scope);
        assert!(routes.is_empty(), "unreadable packs yield no routes");
    }

    // ── Provider-ingress synthesis tests ───────────────────────────────────

    #[test]
    fn derive_provider_name_strips_messaging_prefix_and_kind_suffix() {
        assert_eq!(
            derive_provider_name("messaging.telegram.bot").as_deref(),
            Some("telegram")
        );
        assert_eq!(
            derive_provider_name("messaging.teams.graph").as_deref(),
            Some("teams")
        );
        assert_eq!(
            derive_provider_name("messaging.slack.client").as_deref(),
            Some("slack")
        );
        assert_eq!(
            derive_provider_name("messaging.webchat.gui").as_deref(),
            Some("webchat")
        );
    }

    #[test]
    fn derive_provider_name_preserves_unknown_shapes() {
        // No `messaging.` prefix, no kind suffix → use the whole thing.
        assert_eq!(
            derive_provider_name("events.timer").as_deref(),
            Some("events-timer")
        );
        // Only one segment after stripping → keep it, even if it's a kind name.
        assert_eq!(
            derive_provider_name("messaging.bot").as_deref(),
            Some("bot")
        );
        // Empty + degenerate inputs.
        assert!(derive_provider_name("").is_none());
        assert!(derive_provider_name(".").is_none());
        assert!(derive_provider_name("messaging.").is_none());
    }

    #[test]
    fn build_webhook_pattern_handles_prefix_variants() {
        assert_eq!(
            build_webhook_pattern("/bot", "telegram"),
            "/bot/webhook/telegram"
        );
        assert_eq!(
            build_webhook_pattern("bot", "telegram"),
            "/bot/webhook/telegram"
        );
        assert_eq!(
            build_webhook_pattern("/bot/", "telegram"),
            "/bot/webhook/telegram"
        );
        assert_eq!(build_webhook_pattern("/", "telegram"), "/webhook/telegram");
        assert_eq!(build_webhook_pattern("", "telegram"), "/webhook/telegram");
        assert_eq!(
            build_webhook_pattern("/api/v1", "teams"),
            "/api/v1/webhook/teams"
        );
    }

    /// Write a minimal `.gtpack` whose manifest declares a single provider via
    /// `greentic.provider-extension.v1`. `ops` controls whether the provider
    /// exposes `ingest_http` (and is therefore eligible for webhook
    /// synthesis).
    fn write_provider_pack(path: &Path, pack_id: &str, provider_type: &str, ops: &[&str]) {
        use std::io::Write as _;
        use zip::write::FileOptions;

        let manifest_json = serde_json::json!({
            "schema_version": "1.0.0",
            "pack_id": pack_id,
            "version": "1.0.0",
            "kind": "provider",
            "publisher": "tests",
            "extensions": {
                PROVIDER_EXTENSION_ID: {
                    "kind": PROVIDER_EXTENSION_ID,
                    "version": "1.0.0",
                    "inline": {
                        "providers": [{
                            "provider_type": provider_type,
                            "capabilities": [],
                            "ops": ops,
                            "config_schema_ref": "config.schema.json",
                            "runtime": {
                                "component_ref": format!("{pack_id}-component"),
                                "export": "schema-core-api",
                                "world": "greentic:provider/schema-core@1.0.0"
                            }
                        }]
                    }
                }
            }
        });
        let manifest: greentic_types::PackManifest =
            serde_json::from_value(manifest_json).expect("manifest deserializes");
        let bytes = greentic_types::encode_pack_manifest(&manifest).expect("manifest encodes");
        let file = std::fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())
            .unwrap();
        zip.write_all(&bytes).unwrap();
        zip.finish().unwrap();
    }

    #[test]
    fn synthesize_provider_routes_for_ingest_http_provider() {
        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("telegram.gtpack");
        write_provider_pack(
            &pack,
            "telegram-pack",
            "messaging.telegram.bot",
            &["ingest_http"],
        );

        let scope = RevisionScope {
            deployment_id: DeploymentId::new(),
            bundle_id: BundleId::new("acme-bundle"),
            revision_id: RevisionId::new(),
        };
        let routes = synthesize_provider_ingest_routes(&[pack], &scope, &["/bot".to_string()]);
        assert_eq!(
            routes.len(),
            1,
            "one prefix × one ingest_http provider = one route"
        );
        let route = &routes[0];
        assert_eq!(route.pattern, "/bot/webhook/telegram");
        assert_eq!(route.methods, vec!["POST".to_string()]);
        assert_eq!(route.provider_op, INGEST_HTTP_OP);
        assert_eq!(
            route.provider_type.as_deref(),
            Some("messaging.telegram.bot")
        );
        let stamped = route.scope.as_ref().expect("scope stamped");
        assert_eq!(stamped.deployment_id, scope.deployment_id);
        assert_eq!(stamped.revision_id, scope.revision_id);
    }

    #[test]
    fn synthesize_provider_routes_skips_providers_without_ingest_http() {
        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("egress-only.gtpack");
        write_provider_pack(&pack, "egress-only", "messaging.email.smtp", &["send"]);

        let scope = RevisionScope {
            deployment_id: DeploymentId::new(),
            bundle_id: BundleId::new("acme-bundle"),
            revision_id: RevisionId::new(),
        };
        let routes = synthesize_provider_ingest_routes(&[pack], &scope, &["/bot".to_string()]);
        assert!(routes.is_empty());
    }

    #[test]
    fn synthesize_provider_routes_emits_one_per_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("telegram.gtpack");
        write_provider_pack(
            &pack,
            "telegram-pack",
            "messaging.telegram.bot",
            &["ingest_http"],
        );

        let scope = RevisionScope {
            deployment_id: DeploymentId::new(),
            bundle_id: BundleId::new("acme-bundle"),
            revision_id: RevisionId::new(),
        };
        let routes = synthesize_provider_ingest_routes(
            &[pack],
            &scope,
            &["/bot".to_string(), "/api/bot".to_string()],
        );
        let patterns: Vec<&str> = routes.iter().map(|r| r.pattern.as_str()).collect();
        assert_eq!(
            patterns,
            vec!["/bot/webhook/telegram", "/api/bot/webhook/telegram"]
        );
    }

    #[test]
    fn synthesize_provider_routes_no_prefixes_yields_none() {
        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("telegram.gtpack");
        write_provider_pack(
            &pack,
            "telegram-pack",
            "messaging.telegram.bot",
            &["ingest_http"],
        );

        let scope = RevisionScope {
            deployment_id: DeploymentId::new(),
            bundle_id: BundleId::new("acme-bundle"),
            revision_id: RevisionId::new(),
        };
        let routes = synthesize_provider_ingest_routes(&[pack], &scope, &[]);
        assert!(
            routes.is_empty(),
            "deployment with no prefixes mounts no webhook (would steal `/` from other deployments)"
        );
    }

    #[test]
    fn synthesize_provider_routes_skips_unreadable_pack() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("garbage.gtpack");
        std::fs::write(&bad, b"not a zip").unwrap();
        let missing = dir.path().join("absent.gtpack");

        let scope = RevisionScope {
            deployment_id: DeploymentId::new(),
            bundle_id: BundleId::new("acme-bundle"),
            revision_id: RevisionId::new(),
        };
        let routes =
            synthesize_provider_ingest_routes(&[bad, missing], &scope, &["/bot".to_string()]);
        assert!(routes.is_empty());
    }

    #[test]
    fn synthesized_route_matches_only_inside_its_scope() {
        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("telegram.gtpack");
        write_provider_pack(
            &pack,
            "telegram-pack",
            "messaging.telegram.bot",
            &["ingest_http"],
        );

        let scope_a = RevisionScope {
            deployment_id: DeploymentId::new(),
            bundle_id: BundleId::new("a"),
            revision_id: RevisionId::new(),
        };
        let scope_b = RevisionScope {
            deployment_id: DeploymentId::new(),
            bundle_id: BundleId::new("b"),
            revision_id: RevisionId::new(),
        };
        let routes = synthesize_provider_ingest_routes(&[pack], &scope_a, &["/bot".to_string()]);
        let table = HttpRouteTable::from_descriptors(routes);
        assert!(
            table
                .match_request_for_revision("/bot/webhook/telegram", "POST", &scope_a)
                .is_some()
        );
        assert!(
            table
                .match_request_for_revision("/bot/webhook/telegram", "POST", &scope_b)
                .is_none()
        );
        // Legacy (unscoped) matcher must never see a synthesized route.
        assert!(
            table
                .match_request("/bot/webhook/telegram", "POST")
                .is_none()
        );
    }
}
