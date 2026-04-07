//! Pack-declared HTTP route discovery for the ingress server.
//!
//! Packs can declare API routes they handle via the `greentic.http-routes.v1`
//! extension in their manifest. At startup the ingress server discovers these
//! routes and dispatches matching requests to the provider's `ingest_http`
//! operation through the generic ingress pipeline.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use greentic_types::{ExtensionInline, decode_pack_manifest};
use serde::Deserialize;
use zip::ZipArchive;

use crate::domains::{self, Domain};

pub const EXT_HTTP_ROUTES_V1: &str = "greentic.http-routes.v1";

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
    pub domain: Domain,
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

    /// Match an incoming request path against declared routes.
    /// Returns the first matching route with extracted tenant/team values.
    pub fn match_request(&self, path: &str, method: &str) -> Option<HttpRouteMatch<'_>> {
        let request_segments: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        for route in &self.routes {
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
    let mut all_routes = Vec::new();
    for pack_path in pack_paths {
        match read_pack_http_routes(&pack_path) {
            Ok(Some(routes)) => all_routes.extend(routes),
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
    Ok(all_routes)
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
            domain,
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

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_route(pattern: &str, methods: &[&str], domain: Domain) -> HttpRouteDescriptor {
        let segments = parse_route_pattern(pattern);
        HttpRouteDescriptor {
            route_id: pattern.to_string(),
            pack_id: "test-pack".to_string(),
            pattern: pattern.to_string(),
            methods: methods.iter().map(|m| m.to_string()).collect(),
            provider_op: "ingest_http".to_string(),
            domain,
            segments,
        }
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

    #[test]
    fn parse_route_pattern_handles_variants() {
        let segs = parse_route_pattern("/v1/{tenant}/v3/directline/{path*}");
        assert!(matches!(segs[0], RouteSegment::Literal(ref s) if s == "v1"));
        assert!(matches!(segs[1], RouteSegment::Tenant));
        assert!(matches!(segs[2], RouteSegment::Literal(ref s) if s == "v3"));
        assert!(matches!(segs[3], RouteSegment::Literal(ref s) if s == "directline"));
        assert!(matches!(segs[4], RouteSegment::Wildcard));
    }
}
