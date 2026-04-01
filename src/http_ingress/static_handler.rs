use std::path::Path;

use http_body_util::Full;
use hyper::{
    Response, StatusCode,
    body::Bytes,
    header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE},
};

use crate::operator_log;
use crate::static_routes::{
    StaticRouteDescriptor, StaticRouteMatch, cache_control_value, content_type_for_path,
    fallback_asset_path, normalize_relative_asset_path, read_pack_asset_bytes, resolve_asset_path,
};

use super::helpers::error_response;

pub(super) fn serve_static_route(
    route_match: &StaticRouteMatch<'_>,
    bundle_root: &Path,
    request_path: &str,
) -> Response<Full<Bytes>> {
    // Redirect to trailing-slash when the matched route is a directory (no asset path)
    // and the request doesn't end with '/'. Without this, relative paths in index.html
    // (e.g. ./runtime-bootstrap.js) resolve against the wrong parent directory.
    if route_match.asset_path.is_empty() && !route_match.request_is_directory {
        let redirect_path = format!("{}/", request_path.trim_end_matches('/'));
        operator_log::info(
            module_path!(),
            format!("[static] redirect {request_path} -> {redirect_path}"),
        );
        return Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header("Location", &redirect_path)
            .header("Content-Length", "0")
            .body(Full::from(Bytes::new()))
            .unwrap_or_else(|_| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "redirect failed")
            });
    }
    if let Some(asset_path) = resolve_asset_path(route_match) {
        match serve_static_asset(route_match.descriptor, &asset_path, bundle_root) {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(err) => {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
            }
        }
    }
    if let Some(asset_path) = fallback_asset_path(route_match) {
        match serve_static_asset(route_match.descriptor, &asset_path, bundle_root) {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(err) => {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
            }
        }
    }
    error_response(StatusCode::NOT_FOUND, "file not found")
}

fn serve_static_asset(
    descriptor: &StaticRouteDescriptor,
    asset_path: &str,
    bundle_root: &Path,
) -> anyhow::Result<Option<Response<Full<Bytes>>>> {
    let Some(asset_path) = normalize_relative_asset_path(asset_path) else {
        return Ok(None);
    };
    let full_path = format!("{}/{}", descriptor.source_root, asset_path);

    // Check bundle overlay first: bundle_root/<source_root>/<asset_path>
    // This allows users to place custom assets (e.g. skins) directly in the
    // bundle directory without extracting or rebuilding the pack.
    let overlay_candidate = bundle_root.join(&full_path);
    let body = if overlay_candidate.is_file() {
        std::fs::read(&overlay_candidate)?
    } else {
        match read_pack_asset_bytes(&descriptor.pack_path, &full_path)? {
            Some(bytes) => bytes,
            None => {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "[static] asset not found: {} in {}",
                        full_path,
                        descriptor.pack_path.display()
                    ),
                );
                return Ok(None);
            }
        }
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type_for_path(&full_path))
        .header(CONTENT_LENGTH, body.len().to_string());
    if let Some(cache_control) = cache_control_value(&descriptor.cache_strategy) {
        builder = builder.header(CACHE_CONTROL, cache_control);
    }
    let response = builder
        .body(Full::from(Bytes::from(body)))
        .map_err(|err| anyhow::anyhow!("build static response: {err}"))?;
    Ok(Some(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_routes::{
        CacheStrategy, RouteScopeSegment, StaticRouteDescriptor, StaticRouteMatch,
    };
    use http_body_util::BodyExt;
    use tempfile::tempdir;

    fn descriptor(pack_path: &Path) -> StaticRouteDescriptor {
        StaticRouteDescriptor {
            route_id: "web".to_string(),
            pack_id: "web".to_string(),
            pack_path: pack_path.to_path_buf(),
            public_path: "/web".to_string(),
            source_root: "site".to_string(),
            index_file: Some("index.html".to_string()),
            spa_fallback: Some("index.html".to_string()),
            tenant_scoped: false,
            team_scoped: false,
            cache_strategy: CacheStrategy::PublicMaxAge {
                max_age_seconds: 60,
            },
            route_segments: vec![RouteScopeSegment::Literal("web".to_string())],
        }
    }

    #[test]
    fn serve_static_route_redirects_directory_requests_without_trailing_slash() {
        let dir = tempdir().expect("tempdir");
        let descriptor = descriptor(dir.path());
        let route_match = StaticRouteMatch {
            descriptor: &descriptor,
            asset_path: String::new(),
            request_is_directory: false,
        };

        let response = serve_static_route(&route_match, dir.path(), "/web");
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(response.headers()["Location"], "/web/");
    }

    #[test]
    fn serve_static_route_prefers_bundle_overlay_assets() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let bundle = tempdir().expect("tempdir");
        let pack = tempdir().expect("tempdir");
        std::fs::create_dir_all(bundle.path().join("site")).expect("mkdir");
        std::fs::create_dir_all(pack.path().join("site")).expect("mkdir");
        std::fs::write(bundle.path().join("site").join("app.js"), "overlay").expect("overlay");
        std::fs::write(pack.path().join("site").join("app.js"), "pack").expect("pack");

        let descriptor = descriptor(pack.path());
        let route_match = StaticRouteMatch {
            descriptor: &descriptor,
            asset_path: "app.js".to_string(),
            request_is_directory: false,
        };

        let response = serve_static_route(&route_match, bundle.path(), "/web/app.js");
        let body = runtime.block_on(async {
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
        });
        assert_eq!(body, Bytes::from_static(b"overlay"));
    }

    #[test]
    fn serve_static_route_uses_spa_fallback_when_asset_missing() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let dir = tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("site")).expect("mkdir");
        std::fs::write(
            dir.path().join("site").join("index.html"),
            "<html>ok</html>",
        )
        .expect("index");

        let descriptor = descriptor(dir.path());
        let route_match = StaticRouteMatch {
            descriptor: &descriptor,
            asset_path: "missing/path".to_string(),
            request_is_directory: false,
        };

        let response = serve_static_route(&route_match, dir.path(), "/web/missing/path");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(response.headers()[CACHE_CONTROL], "public, max-age=60");
        let body = runtime.block_on(async {
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
        });
        assert!(String::from_utf8_lossy(&body).contains("<html>ok</html>"));
    }

    #[test]
    fn serve_static_route_rejects_missing_assets() {
        let dir = tempdir().expect("tempdir");
        let descriptor = descriptor(dir.path());
        let route_match = StaticRouteMatch {
            descriptor: &descriptor,
            asset_path: "missing.js".to_string(),
            request_is_directory: false,
        };

        let response = serve_static_route(&route_match, dir.path(), "/web/missing.js");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
