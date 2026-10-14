//! Provider "setup surfaces": the pages and wizard API a pack declares through
//! its `greentic.setup.web-component.v1` descriptor.
//!
//! A messaging pack (e.g. `messaging-teams`) ships a setup web component. Its
//! descriptor — the manifest extension of that name and/or
//! `assets/setup.routes.json` — names
//!
//! * `static_route.public_path` / `asset_base_path`: where the page and its
//!   script are served, and
//! * `api.*`: the wizard's backend paths. These are served by the provider
//!   component itself (`ingest_http`), and some of them START A REAL ACTION —
//!   an anonymous `POST …/next` begins a device-code login and returns the
//!   device code.
//!
//! Neither half is a webhook: nothing on this surface is signed by a platform,
//! so nothing authenticates the caller except us. The surface is therefore
//! gated exactly like the generic JSON ingress (worker-interop contract D7):
//! a non-loopback peer must present the dispatched unit's bearer. The gate
//! itself is [`crate::ingress_auth::decide_generic`]; this module only answers
//! "is this path a setup surface".
//!
//! The surface is identified GENERICALLY from the descriptor — no provider is
//! named anywhere here. Ordinary webhook ingress paths are never declared by a
//! setup descriptor, so they are untouched.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::Value;
use zip::ZipArchive;

use crate::http_routes::RevisionScope;
use crate::operator_log;

/// Manifest extension key and `schema_id` of the descriptor.
pub(crate) const EXT_SETUP_WEB_COMPONENT_V1: &str = "greentic.setup.web-component.v1";

/// The descriptor file inside a pack.
const SETUP_ROUTES_ASSET: &str = "assets/setup.routes.json";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Segment {
    Literal(String),
    /// A `{placeholder}` (`{tenant}`, `{kind}`, …): any single segment.
    Placeholder(String),
}

/// One declared path, as segments. Matches the path itself and everything
/// beneath it: a wizard that declares `…/{tenant}` also serves `…/{tenant}/x`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SetupSurface {
    scope: Option<RevisionScope>,
    segments: Vec<Segment>,
}

/// The setup surfaces of the loaded packs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetupSurfaceTable {
    surfaces: Vec<SetupSurface>,
}

/// A request that landed on a setup surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SetupMatch {
    /// The `{tenant}` segment of the declared path, when it has one.
    pub tenant: Option<String>,
}

impl SetupSurfaceTable {
    pub fn is_empty(&self) -> bool {
        self.surfaces.is_empty()
    }

    pub(crate) fn extend(&mut self, other: Self) {
        self.surfaces.extend(other.surfaces);
    }

    /// Does `request_path` fall on a surface declared by `scope`'s packs
    /// (`None` = the legacy single-bundle boot)?
    pub(crate) fn match_request(
        &self,
        request_path: &str,
        scope: Option<&RevisionScope>,
    ) -> Option<SetupMatch> {
        let request: Vec<&str> = request_path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        self.surfaces
            .iter()
            .filter(|surface| scope_matches(surface.scope.as_ref(), scope))
            .find_map(|surface| surface.matches(&request))
    }

    #[cfg(test)]
    pub(crate) fn for_tests(paths: &[&str], scope: Option<RevisionScope>) -> Self {
        Self {
            surfaces: paths
                .iter()
                .filter_map(|path| SetupSurface::parse(path, scope.clone()))
                .collect(),
        }
    }
}

fn scope_matches(declared: Option<&RevisionScope>, requested: Option<&RevisionScope>) -> bool {
    match (declared, requested) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.deployment_id == b.deployment_id
                && a.bundle_id == b.bundle_id
                && a.revision_id == b.revision_id
        }
        _ => false,
    }
}

impl SetupSurface {
    /// `None` for a path with no segments (`/`), which would gate everything.
    fn parse(path: &str, scope: Option<RevisionScope>) -> Option<Self> {
        let path = path.split(['?', '#']).next().unwrap_or_default();
        let segments: Vec<Segment> = path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .map(|segment| {
                if segment.starts_with('{') && segment.ends_with('}') {
                    Segment::Placeholder(segment[1..segment.len() - 1].trim_end_matches('*').into())
                } else {
                    Segment::Literal(segment.to_string())
                }
            })
            .collect();
        if segments.is_empty() {
            return None;
        }
        Some(Self { scope, segments })
    }

    fn matches(&self, request: &[&str]) -> Option<SetupMatch> {
        if request.len() < self.segments.len() {
            return None;
        }
        let mut tenant = None;
        for (declared, actual) in self.segments.iter().zip(request) {
            match declared {
                Segment::Literal(expected) if expected != actual => return None,
                Segment::Literal(_) => {}
                Segment::Placeholder(name) => {
                    if name == "tenant" {
                        tenant = Some((*actual).to_string());
                    }
                }
            }
        }
        Some(SetupMatch { tenant })
    }
}

/// Every path a descriptor value exposes: `static_route.public_path`,
/// `asset_base_path` and each string under `api`.
fn paths_in_descriptor(descriptor: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    let mut push = |value: Option<&Value>| {
        if let Some(path) = value.and_then(Value::as_str)
            && path.starts_with('/')
        {
            paths.push(path.to_string());
        }
    };
    push(descriptor.pointer("/static_route/public_path"));
    push(descriptor.get("asset_base_path"));
    if let Some(api) = descriptor.get("api").and_then(Value::as_object) {
        for value in api.values() {
            push(Some(value));
        }
    }
    paths
}

/// Surfaces declared by one pack: its manifest extension plus
/// `assets/setup.routes.json`. Unreadable declarations log and contribute
/// nothing (the descriptor is the only source of the paths, so there is
/// nothing to gate without it).
fn surfaces_of_pack(pack_path: &Path, scope: Option<&RevisionScope>) -> Vec<SetupSurface> {
    let mut descriptors: Vec<Value> = Vec::new();

    match crate::static_routes::read_pack_manifest(pack_path) {
        Ok(manifest) => {
            if let Some(greentic_types::ExtensionInline::Other(value)) = manifest
                .extensions
                .as_ref()
                .and_then(|extensions| extensions.get(EXT_SETUP_WEB_COMPONENT_V1))
                .and_then(|extension| extension.inline.as_ref())
            {
                descriptors.push(value.clone());
            }
        }
        Err(err) => operator_log::warn(
            module_path!(),
            format!(
                "setup surface: cannot read manifest of {}: {err:#}",
                pack_path.display()
            ),
        ),
    }

    match read_setup_routes_asset(pack_path) {
        Ok(Some(value)) => descriptors.push(value),
        Ok(None) => {}
        Err(err) => operator_log::warn(
            module_path!(),
            format!(
                "setup surface: cannot read {SETUP_ROUTES_ASSET} of {}: {err:#}",
                pack_path.display()
            ),
        ),
    }

    descriptors
        .iter()
        .flat_map(paths_in_descriptor)
        .filter_map(|path| SetupSurface::parse(&path, scope.cloned()))
        .collect()
}

fn read_setup_routes_asset(pack_path: &Path) -> anyhow::Result<Option<Value>> {
    let bytes = if pack_path.is_dir() {
        match std::fs::read(pack_path.join(SETUP_ROUTES_ASSET)) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        }
    } else {
        let mut archive = ZipArchive::new(std::fs::File::open(pack_path)?)?;
        let mut entry = match archive.by_name(SETUP_ROUTES_ASSET) {
            Ok(entry) => entry,
            Err(zip::result::ZipError::FileNotFound) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        bytes
    };
    Ok(Some(serde_json::from_slice(&bytes)?))
}

/// Surfaces declared by a revision's pinned packs, stamped with its scope.
pub fn discover_revision_setup_surfaces(
    pack_paths: &[PathBuf],
    scope: &RevisionScope,
) -> SetupSurfaceTable {
    SetupSurfaceTable {
        surfaces: pack_paths
            .iter()
            .flat_map(|path| surfaces_of_pack(path, Some(scope)))
            .collect(),
    }
}

/// Surfaces declared by a legacy `--bundle` boot's packs (no scope).
pub fn discover_bundle_setup_surfaces(bundle_root: &Path) -> SetupSurfaceTable {
    let packs = match crate::static_routes::collect_runtime_pack_paths(bundle_root) {
        Ok(packs) => packs,
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!("setup surface: cannot enumerate packs: {err:#}"),
            );
            return SetupSurfaceTable::default();
        }
    };
    SetupSurfaceTable {
        surfaces: packs
            .iter()
            .flat_map(|path| surfaces_of_pack(path, None))
            .collect(),
    }
}

/// Anti-framing headers for a setup response. The designer proxies the surface
/// from its server, so a browser never has a reason to frame it directly; the
/// wizard page carries a live login flow and must not be clickjackable.
pub(crate) fn harden_response(
    mut response: hyper::Response<http_body_util::Full<hyper::body::Bytes>>,
) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    use hyper::header;
    let headers = response.headers_mut();
    headers.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static("frame-ancestors 'none'"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scope() -> RevisionScope {
        use greentic_deploy_spec::ids::{BundleId, DeploymentId, RevisionId};
        RevisionScope {
            deployment_id: DeploymentId::new(),
            bundle_id: BundleId::new("unit"),
            revision_id: RevisionId::new(),
        }
    }

    fn table() -> SetupSurfaceTable {
        SetupSurfaceTable::for_tests(
            &[
                "/v1/web/p/setup/{tenant}",
                "/v1/messaging/setup/p/{tenant}",
                "/v1/messaging/setup/p/{tenant}/oauth/{kind}/start",
            ],
            None,
        )
    }

    #[test]
    fn declared_paths_and_their_subpaths_match_and_capture_the_tenant() {
        let t = table();
        for path in [
            "/v1/web/p/setup/demo",
            "/v1/web/p/setup/demo/app.js",
            "/v1/messaging/setup/p/demo",
            "/v1/messaging/setup/p/demo/next",
            "/v1/messaging/setup/p/demo/oauth/device/start",
        ] {
            let m = t
                .match_request(path, None)
                .unwrap_or_else(|| panic!("{path}"));
            assert_eq!(m.tenant.as_deref(), Some("demo"), "{path}");
        }
    }

    #[test]
    fn undeclared_paths_do_not_match() {
        let t = table();
        for path in [
            "/",
            "/v1/messaging/ingress/p/demo/default",
            "/v1/web/webchat/demo/",
            "/v1/messaging/setup/other/demo",
            "/v1/messaging/setup/p",
        ] {
            assert!(t.match_request(path, None).is_none(), "{path}");
        }
    }

    #[test]
    fn a_legacy_surface_does_not_match_a_scoped_request() {
        assert!(
            table()
                .match_request("/v1/messaging/setup/p/demo", Some(&scope()))
                .is_none()
        );
    }

    #[test]
    fn descriptor_paths_come_from_static_route_asset_base_and_api() {
        let paths = paths_in_descriptor(&json!({
            "static_route": {"public_path": "/a/{tenant}", "source_root": "assets/x"},
            "asset_base_path": "/a/{tenant}",
            "module_url": "/a/{tenant}/m.js?v=1",
            "api": {"state": "/b/{tenant}", "next": "/b/{tenant}/next", "bad": 3},
            "attributes": {"state-path": "/c"}
        }));
        // The api map's iteration order depends on serde_json's `preserve_order`
        // feature, which is enabled by other crates in the graph; compare the set.
        let mut paths = paths;
        paths.sort();
        assert_eq!(
            paths,
            [
                "/a/{tenant}",
                "/a/{tenant}",
                "/b/{tenant}",
                "/b/{tenant}/next"
            ]
        );
    }

    #[test]
    fn a_root_path_never_becomes_a_surface() {
        assert!(SetupSurface::parse("/", None).is_none());
    }

    /// Manual check against a real pack: `GS_REAL_PACK=<.gtpack> cargo test
    /// real_pack -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn real_pack_surfaces() {
        let pack = std::env::var("GS_REAL_PACK").expect("GS_REAL_PACK");
        let surfaces = surfaces_of_pack(Path::new(&pack), None);
        let table = SetupSurfaceTable { surfaces };
        for path in [
            "/v1/web/messaging-teams/setup/demo/",
            "/v1/messaging/setup/messaging-teams/demo",
            "/v1/messaging/setup/messaging-teams/demo/next",
            "/v1/messaging/setup/messaging-teams/demo/oauth/device/start",
        ] {
            assert!(table.match_request(path, None).is_some(), "{path}");
        }
        for path in [
            "/v1/messaging/ingress/messaging-teams/demo/default",
            "/v1/web/webchat/demo/",
        ] {
            assert!(table.match_request(path, None).is_none(), "{path}");
        }
    }
}
