use std::path::Path;

use http_body_util::Full;
use hyper::{
    Response, StatusCode,
    body::Bytes,
    header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE},
};
use serde_json::Value as JsonValue;

use crate::operator_log;
use crate::provider_config_envelope::read_provider_config_envelope;
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
    // The webchat-gui locale picker fetches `<route-prefix>/i18n/_manifest.json`
    // to learn which translations are available. Single source of truth is the
    // active app pack's `assets/i18n/*.json` set, so we synthesize the response
    // from the pack contents instead of asking authors to maintain a parallel
    // file in the webchat-gui pack.
    if let Some(response) = try_serve_i18n_manifest(request_path, bundle_root) {
        return response;
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
    // Synthesize per-tenant webchat client config from the provider envelope when
    // neither the bundle overlay nor the pack ships an explicit
    // `config/tenants/<tenant>.json`. Without this branch the request would fall
    // through to `spa_fallback` and serve `index.html`, returning HTML where the
    // client expects JSON — silently downgrading the active skin to the built-in
    // fallback even when wizard answers asked for something else.
    if let Some(response) = try_serve_synthesized_tenant_config(route_match, bundle_root) {
        return response;
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

/// Synthesize the locale picker manifest from the active app pack's `assets/i18n/`
/// when the request targets `/v1/web/webchat/{tenant}/i18n/_manifest.json`.
///
/// Returns `None` for every other path so the regular static-file path runs.
fn try_serve_i18n_manifest(
    request_path: &str,
    bundle_root: &Path,
) -> Option<Response<Full<Bytes>>> {
    let tenant = extract_webchat_tenant_for_manifest(request_path)?;
    let pack_path =
        crate::messaging_app::resolve_app_pack_path(bundle_root, &tenant, None, None).ok()?;
    let codes = enumerate_pack_locale_codes(&pack_path);
    let body = serde_json::to_vec(&codes).ok()?;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body.len().to_string())
        .header(CACHE_CONTROL, "no-cache")
        .body(Full::from(Bytes::from(body)))
        .ok()
}

/// Match `/v1/web/webchat/{tenant}/i18n/_manifest.json` and return `tenant`.
fn extract_webchat_tenant_for_manifest(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/v1/web/webchat/")?;
    let (tenant, tail) = rest.split_once('/')?;
    if tenant.is_empty() || tail != "i18n/_manifest.json" {
        return None;
    }
    Some(tenant.to_string())
}

/// Enumerate locale codes from a `.gtpack`'s `assets/i18n/*.json` entries.
/// Returns a sorted, deduplicated list. Unreadable packs yield an empty list
/// so the picker degrades gracefully (English-only).
fn enumerate_pack_locale_codes(pack_path: &Path) -> Vec<String> {
    let Ok(file) = std::fs::File::open(pack_path) else {
        return Vec::new();
    };
    let Ok(mut archive) = zip::ZipArchive::new(file) else {
        return Vec::new();
    };
    let mut codes = std::collections::BTreeSet::new();
    for index in 0..archive.len() {
        let Ok(entry) = archive.by_index(index) else {
            continue;
        };
        let name = entry.name();
        let Some(stripped) = name.strip_prefix("assets/i18n/") else {
            continue;
        };
        if stripped.contains('/') {
            continue;
        }
        let Some(code) = stripped.strip_suffix(".json") else {
            continue;
        };
        if code.is_empty() || code == "glossary" || code == "_manifest" {
            continue;
        }
        codes.insert(code.to_string());
    }
    codes.into_iter().collect()
}

/// Synthesize a per-tenant webchat client config (`config/tenants/<tenant>.json`)
/// from provider setup config when no overlay or pack file ships one for that
/// tenant. The pack-shipped `default.json` is loaded as a base template and the
/// provider config object overlays tenant-specific fields (`tenant_id`, `skin`,
/// `nav_links`, OAuth provider enable flags) so wizard answers reach the browser
/// without forcing authors to commit a JSON file per tenant.
///
/// Returns `None` when the request does not match the tenant-config URL shape,
/// when the pack has no `default.json` template, or when no provider setup config
/// exists in `.providers/<pack_id>/config.envelope.cbor` or
/// `state/config/<pack_id>/setup-answers.json`. The caller then proceeds to its
/// existing fallbacks.
fn try_serve_synthesized_tenant_config(
    route_match: &StaticRouteMatch<'_>,
    bundle_root: &Path,
) -> Option<Response<Full<Bytes>>> {
    let tenant_id = match_tenant_config_asset_path(&route_match.asset_path)?;

    // The pack ships `default.json` as a literal template — defer to the file
    // path serve so the byte-identical version is returned when requested.
    if tenant_id == "default" {
        return None;
    }

    let template_asset_path = format!(
        "{}/config/tenants/default.json",
        route_match.descriptor.source_root
    );
    let template_bytes =
        read_pack_asset_bytes(&route_match.descriptor.pack_path, &template_asset_path).ok()??;
    let mut template: JsonValue = serde_json::from_slice(&template_bytes).ok()?;

    let providers_root = bundle_root.join(".providers");
    let provider_config =
        read_provider_config_envelope(&providers_root, &route_match.descriptor.pack_id)
            .ok()
            .flatten()
            .map(|envelope| envelope.config)
            .or_else(|| {
                read_provider_setup_answers(bundle_root, &route_match.descriptor.pack_id)
            })?;

    apply_envelope_tenant_overrides(&mut template, tenant_id, &provider_config);

    let body = serde_json::to_vec(&template).ok()?;
    operator_log::info(
        module_path!(),
        format!(
            "[static] synthesized tenant config tenant={tenant_id} pack={}",
            route_match.descriptor.pack_id
        ),
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body.len().to_string())
        .header(CACHE_CONTROL, "no-cache")
        .body(Full::from(Bytes::from(body)))
        .ok()
}

fn read_provider_setup_answers(bundle_root: &Path, provider_id: &str) -> Option<JsonValue> {
    let path = bundle_root
        .join("state")
        .join("config")
        .join(provider_id)
        .join("setup-answers.json");
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Match an asset path of the exact shape `config/tenants/<id>.json` and return
/// `<id>`. Returns `None` for nested directories under `config/tenants/` and for
/// any other extension so synthesis stays scoped to the canonical client URL.
fn match_tenant_config_asset_path(asset_path: &str) -> Option<&str> {
    let rest = asset_path.strip_prefix("config/tenants/")?;
    let id = rest.strip_suffix(".json")?;
    if id.is_empty() || id.contains('/') {
        return None;
    }
    Some(id)
}

/// Overlay envelope fields onto the `default.json` template in place. Missing
/// envelope fields leave the template value untouched so the pack-author's
/// defaults remain authoritative for anything the wizard did not configure.
fn apply_envelope_tenant_overrides(
    template: &mut JsonValue,
    tenant_id: &str,
    envelope_config: &JsonValue,
) {
    template["tenant_id"] = JsonValue::String(tenant_id.to_string());

    if let Some(skin) = envelope_config.get("skin").and_then(|v| v.as_str())
        && !skin.is_empty()
    {
        template["skin"] = JsonValue::String(skin.to_string());
    }
    if let Some(nav_links) = envelope_config.get("nav_links")
        && !nav_links.is_null()
    {
        template["nav_links"] = nav_links.clone();
    }

    // Map `oauth_enable_<id>` envelope booleans onto each declared provider's
    // `enabled` flag. Providers absent from the envelope keep the template
    // value (typically the pack-author's safe default of `false`).
    if let Some(providers) = template
        .pointer_mut("/auth/providers")
        .and_then(|v| v.as_array_mut())
    {
        for provider in providers.iter_mut() {
            let Some(provider_id) = provider
                .get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
            else {
                continue;
            };
            let key = format!("oauth_enable_{provider_id}");
            if let Some(enabled) = envelope_config.get(&key).and_then(|v| v.as_bool()) {
                provider["enabled"] = JsonValue::Bool(enabled);
            }
        }
    }
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

    #[test]
    fn extract_webchat_tenant_for_manifest_matches_canonical_url() {
        assert_eq!(
            extract_webchat_tenant_for_manifest("/v1/web/webchat/demo/i18n/_manifest.json"),
            Some("demo".to_string())
        );
    }

    #[test]
    fn extract_webchat_tenant_for_manifest_rejects_other_paths() {
        assert!(extract_webchat_tenant_for_manifest("/v1/web/webchat/demo/index.html").is_none());
        assert!(
            extract_webchat_tenant_for_manifest("/v1/web/webchat//i18n/_manifest.json").is_none()
        );
        assert!(extract_webchat_tenant_for_manifest("/some/other/path").is_none());
        assert!(extract_webchat_tenant_for_manifest("/v1/web/webchat/demo/i18n/en.json").is_none());
    }

    fn write_pack_with_i18n(path: &Path, locale_codes: &[&str]) {
        use std::io::Write;
        let file = std::fs::File::create(path).expect("create pack");
        let mut writer = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        // Manifest the loader expects (kept minimal — only needed for realism).
        writer
            .start_file("pack.manifest.json", opts)
            .expect("start manifest");
        writer
            .write_all(br#"{"pack_id":"deep-research-demo","version":"0.0.0"}"#)
            .expect("write manifest");
        for code in locale_codes {
            let entry = format!("assets/i18n/{code}.json");
            writer.start_file(&entry, opts).expect("start i18n entry");
            writer.write_all(b"{}").expect("write i18n entry");
        }
        // Noise that must be ignored by the enumerator.
        writer
            .start_file("assets/i18n/glossary.json", opts)
            .expect("start glossary");
        writer.write_all(b"{}").expect("write glossary");
        writer
            .start_file("assets/i18n/README.md", opts)
            .expect("start readme");
        writer.write_all(b"docs").expect("write readme");
        writer
            .start_file("assets/i18n/nested/dir.json", opts)
            .expect("start nested");
        writer.write_all(b"{}").expect("write nested");
        writer.finish().expect("finish pack");
    }

    #[test]
    fn enumerate_pack_locale_codes_returns_only_top_level_locales_sorted() {
        let dir = tempdir().expect("tempdir");
        let pack = dir.path().join("app.gtpack");
        write_pack_with_i18n(&pack, &["en", "id", "fr", "ja"]);

        let codes = enumerate_pack_locale_codes(&pack);
        assert_eq!(codes, vec!["en", "fr", "id", "ja"]);
    }

    #[test]
    fn enumerate_pack_locale_codes_returns_empty_for_unreadable_pack() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("missing.gtpack");
        assert!(enumerate_pack_locale_codes(&missing).is_empty());
    }

    #[test]
    fn try_serve_i18n_manifest_returns_pack_locale_array() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let bundle = tempdir().expect("tempdir");
        let packs_dir = bundle.path().join("packs");
        std::fs::create_dir_all(&packs_dir).expect("mkdir packs");
        let pack_path = packs_dir.join("default.gtpack");
        write_pack_with_i18n(&pack_path, &["en", "id", "ja"]);

        let response =
            try_serve_i18n_manifest("/v1/web/webchat/demo/i18n/_manifest.json", bundle.path())
                .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");

        let body = runtime.block_on(async {
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
        });
        let parsed: Vec<String> = serde_json::from_slice(&body).expect("parse json");
        assert_eq!(parsed, vec!["en", "id", "ja"]);
    }

    #[test]
    fn try_serve_i18n_manifest_skips_non_manifest_paths() {
        let bundle = tempdir().expect("tempdir");
        assert!(
            try_serve_i18n_manifest("/v1/web/webchat/demo/index.html", bundle.path()).is_none()
        );
    }

    // ── Synthesized tenant config ─────────────────────────────────────────────

    use crate::provider_config_envelope::{ABI_VERSION, ConfigEnvelope};
    use greentic_types::cbor::canonical;
    use serde_json::json;

    /// Default `assets/webchat-gui/config/tenants/default.json` shipped by the
    /// real `messaging-webchat-gui` pack (truncated to fields the synth touches).
    const PACK_DEFAULT_TENANT_TEMPLATE: &str = r##"{
        "tenant_id": "default",
        "legacy_skin": "_template",
        "branding": {
            "company_name": "AI Assistant",
            "logo": "/skins/_template/assets/logo.svg"
        },
        "webchat": {
            "directline": {},
            "style_options": {"accent": "#059669"},
            "adaptive_cards_host_config": {"fontFamily": "Poppins"},
            "locale": "en-US"
        },
        "auth": {
            "providers": [
                {"id": "guest", "label": "Continue as Guest", "type": "dummy", "enabled": true},
                {"id": "google", "label": "Sign in with Google", "type": "oidc", "enabled": false},
                {"id": "microsoft", "label": "Sign in with Microsoft", "type": "oidc", "enabled": false}
            ]
        }
    }"##;

    fn write_webchat_pack_with_default_tenant(path: &Path) {
        use std::io::Write;
        let file = std::fs::File::create(path).expect("create pack");
        let mut writer = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer
            .start_file("assets/webchat-gui/config/tenants/default.json", opts)
            .expect("start default.json");
        writer
            .write_all(PACK_DEFAULT_TENANT_TEMPLATE.as_bytes())
            .expect("write default.json");
        writer.finish().expect("finish pack");
    }

    fn write_test_envelope(providers_root: &Path, provider_id: &str, config: JsonValue) {
        let provider_dir = providers_root.join(provider_id);
        std::fs::create_dir_all(&provider_dir).expect("create provider dir");
        let envelope = ConfigEnvelope {
            config,
            component_id: provider_id.to_string(),
            abi_version: ABI_VERSION.to_string(),
            resolved_digest: "test-digest".to_string(),
            describe_hash: "test-describe".to_string(),
            schema_hash: None,
            operation_id: "setup-input".to_string(),
            updated_at: None,
        };
        let bytes = canonical::to_canonical_cbor(&envelope).expect("encode envelope");
        std::fs::write(provider_dir.join("config.envelope.cbor"), bytes).expect("write envelope");
    }

    fn webchat_descriptor(pack_path: &Path) -> StaticRouteDescriptor {
        StaticRouteDescriptor {
            route_id: "webchat-gui".to_string(),
            pack_id: "messaging-webchat-gui".to_string(),
            pack_path: pack_path.to_path_buf(),
            public_path: "/v1/web/webchat/{tenant}".to_string(),
            source_root: "assets/webchat-gui".to_string(),
            index_file: Some("index.html".to_string()),
            spa_fallback: Some("index.html".to_string()),
            tenant_scoped: true,
            team_scoped: false,
            cache_strategy: CacheStrategy::None,
            route_segments: vec![
                RouteScopeSegment::Literal("v1".into()),
                RouteScopeSegment::Literal("web".into()),
                RouteScopeSegment::Literal("webchat".into()),
                RouteScopeSegment::Tenant,
            ],
        }
    }

    #[test]
    fn match_tenant_config_extracts_id() {
        assert_eq!(
            match_tenant_config_asset_path("config/tenants/demo.json"),
            Some("demo")
        );
        assert_eq!(
            match_tenant_config_asset_path("config/tenants/3aigent.json"),
            Some("3aigent")
        );
    }

    #[test]
    fn match_tenant_config_rejects_other_paths() {
        assert!(match_tenant_config_asset_path("index.html").is_none());
        assert!(match_tenant_config_asset_path("config/tenants/").is_none());
        assert!(match_tenant_config_asset_path("config/tenants/.json").is_none());
        assert!(match_tenant_config_asset_path("config/tenants/nested/x.json").is_none());
        assert!(match_tenant_config_asset_path("skins/3aigent/skin.json").is_none());
    }

    #[test]
    fn synthesize_overlays_skin_nav_links_and_oauth() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let bundle = tempdir().expect("tempdir");
        let pack_path = bundle.path().join("messaging-webchat-gui.gtpack");
        write_webchat_pack_with_default_tenant(&pack_path);
        write_test_envelope(
            &bundle.path().join(".providers"),
            "messaging-webchat-gui",
            json!({
                "skin": "3aigent",
                "nav_links": [
                    {"num": "M1", "label": "Playground", "url": "https://example.test"}
                ],
                "oauth_enabled": false,
                "oauth_enable_google": true,
                "oauth_enable_microsoft": false,
            }),
        );

        let descriptor = webchat_descriptor(&pack_path);
        let route_match = StaticRouteMatch {
            descriptor: &descriptor,
            asset_path: "config/tenants/demo.json".to_string(),
            request_is_directory: false,
        };

        let response = serve_static_route(
            &route_match,
            bundle.path(),
            "/v1/web/webchat/demo/config/tenants/demo.json",
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        let body = runtime.block_on(async {
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
        });
        let parsed: JsonValue = serde_json::from_slice(&body).expect("parse json");

        assert_eq!(parsed["tenant_id"], json!("demo"));
        assert_eq!(parsed["skin"], json!("3aigent"));
        assert_eq!(parsed["legacy_skin"], json!("_template"));
        assert_eq!(parsed["nav_links"][0]["num"], json!("M1"));

        let providers = parsed["auth"]["providers"]
            .as_array()
            .expect("providers array");
        let google = providers
            .iter()
            .find(|p| p["id"] == "google")
            .expect("google");
        assert_eq!(google["enabled"], json!(true));
        let microsoft = providers
            .iter()
            .find(|p| p["id"] == "microsoft")
            .expect("microsoft");
        assert_eq!(microsoft["enabled"], json!(false));
    }

    #[test]
    fn synthesize_uses_setup_answers_when_envelope_missing() {
        use std::io::Write;
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let bundle = tempdir().expect("tempdir");
        let pack_path = bundle.path().join("messaging-webchat-gui.gtpack");
        let file = std::fs::File::create(&pack_path).expect("create pack");
        let mut writer = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer
            .start_file("assets/webchat-gui/config/tenants/default.json", opts)
            .unwrap();
        writer
            .write_all(PACK_DEFAULT_TENANT_TEMPLATE.as_bytes())
            .unwrap();
        writer
            .start_file("assets/webchat-gui/index.html", opts)
            .unwrap();
        writer.write_all(b"<html>spa</html>").unwrap();
        writer.finish().unwrap();

        let setup_answers_dir = bundle
            .path()
            .join("state")
            .join("config")
            .join("messaging-webchat-gui");
        std::fs::create_dir_all(&setup_answers_dir).expect("create setup answers dir");
        std::fs::write(
            setup_answers_dir.join("setup-answers.json"),
            serde_json::to_vec(&json!({
                "skin": "3aigent",
                "nav_links": [
                    {"num": "M1", "label": "Playground", "url": "https://example.test"}
                ]
            }))
            .expect("encode setup answers"),
        )
        .expect("write setup answers");

        let descriptor = webchat_descriptor(&pack_path);
        let route_match = StaticRouteMatch {
            descriptor: &descriptor,
            asset_path: "config/tenants/demo.json".to_string(),
            request_is_directory: false,
        };

        let response = serve_static_route(
            &route_match,
            bundle.path(),
            "/v1/web/webchat/demo/config/tenants/demo.json",
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        let body = runtime.block_on(async {
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
        });
        let parsed: JsonValue = serde_json::from_slice(&body).expect("parse json");
        assert_eq!(parsed["tenant_id"], json!("demo"));
        assert_eq!(parsed["skin"], json!("3aigent"));
        assert_eq!(
            parsed["nav_links"],
            json!([
                {"num": "M1", "label": "Playground", "url": "https://example.test"}
            ])
        );
    }

    #[test]
    fn synthesize_skips_default_tenant_so_pack_file_serves_directly() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let bundle = tempdir().expect("tempdir");
        let pack_path = bundle.path().join("messaging-webchat-gui.gtpack");
        write_webchat_pack_with_default_tenant(&pack_path);
        write_test_envelope(
            &bundle.path().join(".providers"),
            "messaging-webchat-gui",
            json!({"skin": "3aigent"}),
        );

        let descriptor = webchat_descriptor(&pack_path);
        let route_match = StaticRouteMatch {
            descriptor: &descriptor,
            asset_path: "config/tenants/default.json".to_string(),
            request_is_directory: false,
        };

        let response = serve_static_route(
            &route_match,
            bundle.path(),
            "/v1/web/webchat/demo/config/tenants/default.json",
        );
        assert_eq!(response.status(), StatusCode::OK);
        let body = runtime.block_on(async {
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
        });
        let parsed: JsonValue = serde_json::from_slice(&body).expect("parse json");
        // Pack file served verbatim — synth would have set tenant_id="default" and
        // overridden skin to "3aigent"; the pack file has tenant_id "default" and
        // no `skin` field at all.
        assert_eq!(parsed["tenant_id"], json!("default"));
        assert!(parsed.get("skin").is_none());
    }

    #[test]
    fn synthesize_preserves_overlay_when_present() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let bundle = tempdir().expect("tempdir");
        let pack_path = bundle.path().join("messaging-webchat-gui.gtpack");
        write_webchat_pack_with_default_tenant(&pack_path);
        write_test_envelope(
            &bundle.path().join(".providers"),
            "messaging-webchat-gui",
            json!({"skin": "3aigent"}),
        );
        // Workspace overlay supplies an explicit demo.json — synth must NOT shadow
        // it (overlay is the author's deliberate override).
        let overlay_dir = bundle.path().join("assets/webchat-gui/config/tenants");
        std::fs::create_dir_all(&overlay_dir).unwrap();
        std::fs::write(
            overlay_dir.join("demo.json"),
            r#"{"tenant_id":"demo","skin":"overlay-wins"}"#,
        )
        .unwrap();

        let descriptor = webchat_descriptor(&pack_path);
        let route_match = StaticRouteMatch {
            descriptor: &descriptor,
            asset_path: "config/tenants/demo.json".to_string(),
            request_is_directory: false,
        };

        let response = serve_static_route(
            &route_match,
            bundle.path(),
            "/v1/web/webchat/demo/config/tenants/demo.json",
        );
        assert_eq!(response.status(), StatusCode::OK);
        let body = runtime.block_on(async {
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
        });
        let parsed: JsonValue = serde_json::from_slice(&body).expect("parse json");
        assert_eq!(parsed["skin"], json!("overlay-wins"));
    }
}
