use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use greentic_types::decode_pack_manifest;
use hyper::http::Uri;
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::domains;

pub const EXT_STATIC_ROUTES_V1: &str = "greentic.static-routes.v1";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BundleStaticRoutesInspection {
    pub pack_paths: Vec<PathBuf>,
}

impl BundleStaticRoutesInspection {
    pub fn bundle_has_static_routes(&self) -> bool {
        !self.pack_paths.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupContractInput {
    pub bundle_has_static_routes: bool,
    pub http_listener_enabled: bool,
    pub asset_serving_enabled: bool,
    pub public_base_url: Option<String>,
    pub runtime_config: Option<RuntimeConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<RuntimePublicBaseUrl>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePublicBaseUrl {
    pub value: String,
    pub source: RuntimePublicBaseUrlSource,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePublicBaseUrlSource {
    Configured,
    EnvStore,
    StaticRoutes,
    Tunnel,
    Derived,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StartupContract {
    pub bundle_has_static_routes: bool,
    pub public_http_enabled: bool,
    pub static_routes_enabled: bool,
    pub asset_serving_enabled: bool,
    pub public_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_config: Option<RuntimeConfig>,
}

impl StartupContract {
    pub fn apply_env(&self, env: &mut BTreeMap<String, String>) {
        env.insert(
            "PUBLIC_HTTP_ENABLED".to_string(),
            bool_str(self.public_http_enabled).to_string(),
        );
        env.insert(
            "STATIC_ROUTES_ENABLED".to_string(),
            bool_str(self.static_routes_enabled).to_string(),
        );
        env.insert(
            "ASSET_SERVING_ENABLED".to_string(),
            bool_str(self.asset_serving_enabled).to_string(),
        );
        env.insert(
            "BUNDLE_HAS_STATIC_ROUTES".to_string(),
            bool_str(self.bundle_has_static_routes).to_string(),
        );
        if let Some(url) = self.public_base_url.as_ref() {
            env.insert("PUBLIC_BASE_URL".to_string(), url.clone());
        }
    }
}

pub fn inspect_bundle(root: &Path) -> anyhow::Result<BundleStaticRoutesInspection> {
    let mut pack_paths = Vec::new();
    for pack_path in collect_bundle_packs(root)? {
        if pack_declares_static_routes(&pack_path)? {
            pack_paths.push(pack_path);
        }
    }
    pack_paths.sort();
    Ok(BundleStaticRoutesInspection { pack_paths })
}

pub fn resolve(input: StartupContractInput) -> anyhow::Result<StartupContract> {
    let runtime_config = input.runtime_config.or_else(|| {
        input.public_base_url.clone().map(|value| RuntimeConfig {
            public_base_url: Some(RuntimePublicBaseUrl {
                value,
                source: RuntimePublicBaseUrlSource::Configured,
            }),
        })
    });
    let effective_public_base_url = runtime_config
        .as_ref()
        .and_then(|config| config.public_base_url.as_ref())
        .map(|public_base_url| public_base_url.value.clone())
        .or(input.public_base_url);

    if input.bundle_has_static_routes {
        if !input.http_listener_enabled {
            anyhow::bail!(
                "bundle declares static routes but this launch mode does not expose public HTTP"
            );
        }
        if !input.asset_serving_enabled {
            anyhow::bail!(
                "bundle declares static routes but asset serving is not supported in this launch mode"
            );
        }
    }

    let public_http_enabled = input.http_listener_enabled;
    let static_routes_enabled = input.bundle_has_static_routes
        && input.asset_serving_enabled
        && input.http_listener_enabled;

    Ok(StartupContract {
        bundle_has_static_routes: input.bundle_has_static_routes,
        public_http_enabled,
        static_routes_enabled,
        asset_serving_enabled: input.asset_serving_enabled,
        public_base_url: effective_public_base_url,
        runtime_config,
    })
}

pub fn configured_public_base_url_from_env() -> anyhow::Result<Option<String>> {
    let Ok(raw) = std::env::var("PUBLIC_BASE_URL") else {
        return Ok(None);
    };
    normalize_public_base_url(&raw).map(Some)
}

/// Reads a `public_base_url` that setup persisted into
/// `state/config/platform/static-routes.json` — the URL an operator supplied at
/// setup time (e.g. the "no tunnel / manual public URL" path), so it is honored
/// at runtime without needing a managed tunnel or the `PUBLIC_BASE_URL` env var.
///
/// This sits BELOW `PUBLIC_BASE_URL` in the precedence chain, so the env var can
/// always override a setup-provided value. Returns `Ok(None)` when the file is
/// absent, carries no `public_base_url`, or the value fails `http(s)://`
/// validation — a malformed artifact must never block startup.
pub fn configured_public_base_url_from_static_routes(
    config_dir: &Path,
) -> anyhow::Result<Option<String>> {
    let path = config_dir
        .join("state")
        .join("config")
        .join("platform")
        .join("static-routes.json");
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let doc: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    let Some(raw_url) = doc
        .get("public_base_url")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    // Lenient: a bad persisted URL is ignored, not fatal to startup.
    Ok(normalize_public_base_url(raw_url).ok())
}

/// Reads the local port `greentic-setup` recorded when it started a
/// speculative tunnel during setup (`tunnel-handoff.json`, written by
/// `greentic-setup::platform_setup::persist_tunnel_handoff_artifact`).
///
/// Binding the gateway to this same port lets the boot sequence's shared
/// tunnel record (`tunnel_state.rs`, protocol-compatible with `greentic-setup`'s
/// own copy) recognise and adopt the tunnel setup already established,
/// instead of picking its own default/fallback port and minting a second,
/// disconnected tunnel — which would leave whatever URL was registered with
/// providers like Slack (Event Subscriptions, etc.) pointing at a tunnel
/// nothing is listening behind anymore.
///
/// Returns `Ok(None)` when the file is absent or carries no usable port — a
/// missing or malformed handoff must never block startup; the gateway just
/// falls back to its configured/default port as before.
pub fn configured_gateway_port_from_handoff(config_dir: &Path) -> anyhow::Result<Option<u16>> {
    let path = config_dir
        .join("state")
        .join("config")
        .join("platform")
        .join("tunnel-handoff.json");
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let doc: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    Ok(doc
        .get("local_port")
        .and_then(serde_json::Value::as_u64)
        .and_then(|port| u16::try_from(port).ok()))
}

/// Reads the persisted `public_base_url` from the deployer-managed env store.
///
/// Returns `Ok(None)` when the env directory is missing (cold start before
/// `gtc op env init`), the environment has no persisted URL, or the home dir
/// cannot be resolved (headless CI). Returns `Err` when an env directory
/// exists but is malformed (`environment.json` unreadable or corrupt).
///
/// The deploy-spec validator (`validate_public_base_url`) already gates
/// writes, so no second normalization is needed here.
pub fn configured_public_base_url_from_env_store(env_id: &str) -> anyhow::Result<Option<String>> {
    use greentic_deployer::environment::{EnvironmentStore, LocalFsStore};
    use greentic_types::EnvId;

    let Some(root) = LocalFsStore::default_root() else {
        return Ok(None);
    };
    if !root.join(env_id).is_dir() {
        return Ok(None);
    }
    let env_typed =
        EnvId::new(env_id).with_context(|| format!("invalid environment id `{env_id}`"))?;
    let store = LocalFsStore::new(root);
    let environment = EnvironmentStore::load(&store, &env_typed)
        .with_context(|| format!("loading environment `{env_id}` for public_base_url"))?;
    Ok(environment.host_config.public_base_url)
}

/// Single point of truth for the env-derived precedence:
/// `host_config.public_base_url > PUBLIC_BASE_URL env var`.
///
/// Returns `Err` only when the env var is set but malformed; the caller picks
/// the error policy. The boot-time bundle-less path propagates with `?`; the
/// reload hook in `revision_webhook_register` discards with `.ok().flatten()`
/// because the watcher is intentionally fail-soft.
pub fn resolve_public_base_url(
    env: &greentic_deploy_spec::Environment,
) -> anyhow::Result<Option<String>> {
    if let Some(url) = env.host_config.public_base_url.as_deref() {
        return Ok(Some(url.to_string()));
    }
    configured_public_base_url_from_env()
}

fn collect_bundle_packs(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut packs = Vec::new();
    for dir in [root.join("providers"), root.join("packs")] {
        if !dir.exists() {
            continue;
        }
        collect_gtpacks(&dir, &mut packs)?;
    }
    packs.retain(|path| domains::supports_runtime_pack_loading(path));
    packs.sort();
    packs.dedup();
    Ok(packs)
}

fn collect_gtpacks(root: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) == Some("gtpack") {
                out.push(path);
            }
        }
    }
    Ok(())
}

fn pack_declares_static_routes(path: &Path) -> anyhow::Result<bool> {
    let file = std::fs::File::open(path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest_entry = archive.by_name("manifest.cbor").map_err(|err| {
        anyhow::anyhow!("failed to open manifest.cbor in {}: {err}", path.display())
    })?;
    let mut bytes = Vec::new();
    manifest_entry.read_to_end(&mut bytes)?;
    let manifest = decode_pack_manifest(&bytes)
        .with_context(|| format!("failed to decode pack manifest in {}", path.display()))?;
    Ok(manifest
        .extensions
        .as_ref()
        .is_some_and(|extensions| extensions.contains_key(EXT_STATIC_ROUTES_V1)))
}

pub(crate) fn normalize_public_base_url(value: &str) -> anyhow::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("PUBLIC_BASE_URL cannot be empty");
    }
    if trimmed.contains(char::is_whitespace) {
        anyhow::bail!("PUBLIC_BASE_URL must not contain whitespace");
    }
    let uri: Uri = trimmed
        .parse()
        .with_context(|| format!("PUBLIC_BASE_URL is not a valid URI: {trimmed}"))?;
    match uri.scheme_str() {
        Some("http") | Some("https") => {}
        _ => anyhow::bail!("PUBLIC_BASE_URL must start with http:// or https://"),
    }
    if uri.authority().is_none() {
        anyhow::bail!("PUBLIC_BASE_URL must include a host");
    }
    if let Some(path_and_query) = uri.path_and_query() {
        if path_and_query.query().is_some() {
            anyhow::bail!("PUBLIC_BASE_URL must not include a query string");
        }
        let path = path_and_query.path();
        if path != "/" && !path.is_empty() {
            anyhow::bail!("PUBLIC_BASE_URL must be an origin without a path");
        }
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

const fn bool_str(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// Returns `true` when the process is running on Cloud Run. Cloud Run always
/// sets `K_SERVICE` to the service name.
///
/// This checks only the boot-arming condition (cheap). Per-request trust is
/// enforced separately by [`derive_public_base_url`], which requires
/// `X-Cloud-Trace-Context` (set by the GFE on every external request) plus
/// HTTPS scheme and a public DNS host.
pub(crate) fn running_on_cloud_run() -> bool {
    std::env::var_os("K_SERVICE").is_some()
}

/// Derive the runtime's own public base URL from the headers of an inbound
/// request, gated on Cloud Run's Google Front End (GFE) trust signals AND
/// pinned to THIS service's own auto-assigned URL.
///
/// Returns `Some("https://<host>")` only when ALL of:
///   1. `X-Cloud-Trace-Context` header is present (GFE sets this on every
///      external request; Knative ingress controllers do not).
///   2. `X-Forwarded-Proto` is `https` (defaulting to `https` when absent,
///      since Cloud Run terminates TLS at the GFE).
///   3. The `Host` header is THIS service's own Cloud Run URL —
///      `<expected_service>-*.run.app` (see [`is_own_cloud_run_host`]).
///
/// The service-name pin (3) is the load-bearing anti-hijack control. Cloud Run
/// GFE routes by TLS SNI and forwards the client-supplied `Host`, so a `Host`
/// header is attacker-controllable on its own; pinning the captured URL to the
/// running service's own name means a forged `Host` (`evil.com`, a custom
/// domain, or another service's URL) can never be captured. The worst case is
/// no auto-registration — never a wrong one.
///
/// **Fail-safe:** any check failure returns `None` — the system falls back to
/// the unchanged manual/`public_base_url` path; it never registers a wrong URL.
///
/// NOTE: Cloud Run Host-forwarding is observed GFE behaviour, not a documented
/// contract. The live acceptance test (plan section 7) confirms it empirically.
/// A deployment behind a custom domain is intentionally NOT auto-captured (the
/// pin rejects it) and must set `public_base_url` explicitly.
pub(crate) fn derive_public_base_url(
    headers: &hyper::HeaderMap,
    expected_service: &str,
) -> Option<String> {
    // Gate: require X-Cloud-Trace-Context as proof the request traversed the GFE.
    if !headers.contains_key("x-cloud-trace-context") {
        return None;
    }

    // Scheme: default to https (Cloud Run terminates TLS at GFE); reject http.
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    if scheme != "https" {
        return None;
    }

    // Host: must be present AND this service's own Cloud Run URL.
    let host = headers.get(hyper::header::HOST)?.to_str().ok()?;
    if !is_own_cloud_run_host(host, expected_service) {
        return None;
    }

    // Validate via the shared normalizer for consistency with the rest of the
    // codebase (rejects paths, query strings, non-http schemes, etc.).
    normalize_public_base_url(&format!("https://{host}")).ok()
}

/// Returns `true` when `host` is THIS service's own auto-assigned Cloud Run
/// URL: it ends in `.run.app` and starts with `<expected_service>-`. Both URL
/// formats begin with the service name — legacy `<service>-<hash>-<region>.a.run.app`
/// and current `<service>-<projnum>.<region>.run.app`. Case-insensitive; strips
/// an optional `:port`.
///
/// Pinning to the service name is the anti-hijack control: a forged or
/// attacker-supplied `Host` (`evil.com`, a custom domain, or a different
/// service's URL) can never match, so it can never be captured. A custom domain
/// fronting this service also does not match and must set `public_base_url`
/// explicitly.
fn is_own_cloud_run_host(host: &str, expected_service: &str) -> bool {
    if expected_service.is_empty() {
        return false;
    }
    // Strip optional port, lowercase for a case-insensitive compare.
    let name = host.rsplit_once(':').map(|(h, _port)| h).unwrap_or(host);
    let name = name.to_ascii_lowercase();
    let prefix = format!("{}-", expected_service.to_ascii_lowercase());
    name.ends_with(".run.app") && name.starts_with(&prefix)
}

/// Choose the WebSocket scheme (`ws` / `wss`) for a DirectLine `streamUrl`
/// advertised to the browser, based on the forwarded protocol of the inbound
/// request.
///
/// A browser on an HTTPS page can only open a `wss://` socket —
/// `new WebSocket("ws://…")` throws `SecurityError` synchronously, so the
/// BotFramework SDK never connects and stalls for several seconds before
/// falling back. Behind a TLS-terminating proxy (Cloud Run's GFE, a K8s
/// ingress) the container itself sees plain HTTP, so the external scheme has
/// to be read from `X-Forwarded-Proto`, which such proxies set to `https`.
///
/// When multiple proxies chain the header (`"https, http"`) the first,
/// client-facing value governs. Absent the header entirely — local
/// plain-HTTP development with no proxy — fall back to `ws`, matching the
/// page's own `http://` origin.
pub(crate) fn forwarded_ws_scheme(headers: &[(String, String)]) -> &'static str {
    let is_https = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-proto"))
        .and_then(|(_, v)| v.split(',').next())
        .is_some_and(|proto| proto.trim().eq_ignore_ascii_case("https"));
    if is_https { "wss" } else { "ws" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_types::{
        ExtensionInline, ExtensionRef, PackId, PackKind, PackManifest, PackSignatures,
    };
    use semver::Version;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::ZipWriter;
    use zip::write::FileOptions;

    fn hdr(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn forwarded_ws_scheme_defaults_to_ws_when_header_absent() {
        // Local plain-HTTP dev: no X-Forwarded-Proto, page is http:// -> ws.
        assert_eq!(
            forwarded_ws_scheme(&hdr(&[("host", "localhost:8080")])),
            "ws"
        );
    }

    #[test]
    fn forwarded_ws_scheme_upgrades_to_wss_for_forwarded_https() {
        // Cloud Run / TLS-terminating proxy sets X-Forwarded-Proto: https.
        assert_eq!(
            forwarded_ws_scheme(&hdr(&[("x-forwarded-proto", "https")])),
            "wss"
        );
    }

    #[test]
    fn forwarded_ws_scheme_stays_ws_for_forwarded_http() {
        assert_eq!(
            forwarded_ws_scheme(&hdr(&[("x-forwarded-proto", "http")])),
            "ws"
        );
    }

    #[test]
    fn forwarded_ws_scheme_is_case_insensitive_on_name_and_value() {
        assert_eq!(
            forwarded_ws_scheme(&hdr(&[("X-Forwarded-Proto", "HTTPS")])),
            "wss"
        );
    }

    #[test]
    fn forwarded_ws_scheme_uses_first_value_when_chained() {
        // Proxy chains append; the first (client-facing) value governs.
        assert_eq!(
            forwarded_ws_scheme(&hdr(&[("x-forwarded-proto", "https, http")])),
            "wss"
        );
    }

    #[test]
    fn inspect_bundle_detects_static_route_extension() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let pack_path = dir.path().join("packs").join("default.gtpack");
        write_pack(&pack_path, true)?;
        let inspection = inspect_bundle(dir.path())?;
        assert!(inspection.bundle_has_static_routes());
        assert_eq!(inspection.pack_paths, vec![pack_path]);
        Ok(())
    }

    #[test]
    fn configured_gateway_port_from_handoff_reads_setup_written_port() -> anyhow::Result<()> {
        let dir = tempdir()?;
        assert_eq!(configured_gateway_port_from_handoff(dir.path())?, None);

        let platform_dir = dir.path().join("state").join("config").join("platform");
        std::fs::create_dir_all(&platform_dir)?;
        std::fs::write(
            platform_dir.join("tunnel-handoff.json"),
            r#"{"service":"cloudflared","local_port":8080,"public_base_url":"https://example.trycloudflare.com"}"#,
        )?;

        assert_eq!(
            configured_gateway_port_from_handoff(dir.path())?,
            Some(8080)
        );
        Ok(())
    }

    #[test]
    fn configured_gateway_port_from_handoff_ignores_malformed_file() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let platform_dir = dir.path().join("state").join("config").join("platform");
        std::fs::create_dir_all(&platform_dir)?;
        std::fs::write(platform_dir.join("tunnel-handoff.json"), "not json")?;

        assert!(configured_gateway_port_from_handoff(dir.path()).is_err());
        Ok(())
    }

    #[test]
    fn inspect_bundle_ignores_non_runtime_packs() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let pack_path = dir.path().join("packs").join("default.gtpack");
        write_pack(&pack_path, true)?;
        std::fs::write(
            dir.path().join("packs").join("terraform.gtpack"),
            b"not-a-zip",
        )?;
        let inspection = inspect_bundle(dir.path())?;
        assert!(inspection.bundle_has_static_routes());
        assert_eq!(inspection.pack_paths, vec![pack_path]);
        Ok(())
    }

    fn write_static_routes(config_dir: &Path, body: &serde_json::Value) -> anyhow::Result<()> {
        let dir = config_dir.join("state").join("config").join("platform");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("static-routes.json"), body.to_string())?;
        Ok(())
    }

    #[test]
    fn static_routes_public_base_url_absent_file_is_none() -> anyhow::Result<()> {
        let dir = tempdir()?;
        assert_eq!(
            configured_public_base_url_from_static_routes(dir.path())?,
            None
        );
        Ok(())
    }

    #[test]
    fn static_routes_public_base_url_reads_persisted_https() -> anyhow::Result<()> {
        let dir = tempdir()?;
        write_static_routes(
            dir.path(),
            &json!({ "version": 1, "public_base_url": "https://stable.example.com" }),
        )?;
        assert_eq!(
            configured_public_base_url_from_static_routes(dir.path())?,
            Some("https://stable.example.com".to_string())
        );
        Ok(())
    }

    #[test]
    fn static_routes_public_base_url_null_or_missing_is_none() -> anyhow::Result<()> {
        let dir = tempdir()?;
        write_static_routes(
            dir.path(),
            &json!({ "version": 1, "public_base_url": null }),
        )?;
        assert_eq!(
            configured_public_base_url_from_static_routes(dir.path())?,
            None
        );
        write_static_routes(dir.path(), &json!({ "version": 1 }))?;
        assert_eq!(
            configured_public_base_url_from_static_routes(dir.path())?,
            None
        );
        Ok(())
    }

    #[test]
    fn static_routes_public_base_url_invalid_is_lenient_none() -> anyhow::Result<()> {
        let dir = tempdir()?;
        // Bare host without scheme fails http(s):// validation → ignored, not fatal.
        write_static_routes(
            dir.path(),
            &json!({ "version": 1, "public_base_url": "stable.example.com" }),
        )?;
        assert_eq!(
            configured_public_base_url_from_static_routes(dir.path())?,
            None
        );
        Ok(())
    }

    #[test]
    fn resolve_rejects_missing_public_http() {
        let err = resolve(StartupContractInput {
            bundle_has_static_routes: true,
            http_listener_enabled: false,
            asset_serving_enabled: true,
            public_base_url: Some("https://example.com".to_string()),
            runtime_config: None,
        })
        .expect_err("expected launch gating failure");
        assert!(err.to_string().contains("does not expose public HTTP"));
    }

    #[test]
    fn resolve_allows_missing_public_base_url_when_http_and_assets_are_available() {
        let contract = resolve(StartupContractInput {
            bundle_has_static_routes: true,
            http_listener_enabled: true,
            asset_serving_enabled: true,
            public_base_url: None,
            runtime_config: None,
        })
        .expect("expected static routes startup contract");
        assert!(contract.public_http_enabled);
        assert!(contract.static_routes_enabled);
        assert!(contract.public_base_url.is_none());
    }

    #[test]
    fn resolve_enables_static_routes_when_requirements_are_met() -> anyhow::Result<()> {
        let contract = resolve(StartupContractInput {
            bundle_has_static_routes: true,
            http_listener_enabled: true,
            asset_serving_enabled: true,
            public_base_url: Some("https://example.com".to_string()),
            runtime_config: None,
        })?;
        assert!(contract.public_http_enabled);
        assert!(contract.static_routes_enabled);
        Ok(())
    }

    #[test]
    fn resolve_prefers_runtime_config_public_base_url() -> anyhow::Result<()> {
        let contract = resolve(StartupContractInput {
            bundle_has_static_routes: true,
            http_listener_enabled: true,
            asset_serving_enabled: true,
            public_base_url: Some("https://configured.example.com".to_string()),
            runtime_config: Some(RuntimeConfig {
                public_base_url: Some(RuntimePublicBaseUrl {
                    value: "https://tunnel.example.com".to_string(),
                    source: RuntimePublicBaseUrlSource::Tunnel,
                }),
            }),
        })?;
        assert_eq!(
            contract.public_base_url.as_deref(),
            Some("https://tunnel.example.com")
        );
        assert_eq!(
            contract
                .runtime_config
                .as_ref()
                .and_then(|config| config.public_base_url.as_ref())
                .map(|entry| entry.source),
            Some(RuntimePublicBaseUrlSource::Tunnel)
        );
        Ok(())
    }

    #[test]
    fn normalize_public_base_url_rejects_paths() {
        let err = normalize_public_base_url("https://example.com/path")
            .expect_err("expected invalid path");
        assert!(err.to_string().contains("without a path"));
    }

    /// Round-trips an EnvStore-source URL through `resolve` so the new enum
    /// variant survives serde + the same precedence-preserving identity that
    /// `Tunnel` already has. Pure runtime-config flow — no disk I/O.
    #[test]
    fn resolve_surfaces_env_store_source_from_runtime_config() -> anyhow::Result<()> {
        let contract = resolve(StartupContractInput {
            bundle_has_static_routes: true,
            http_listener_enabled: true,
            asset_serving_enabled: true,
            public_base_url: Some("https://from-env-var.example.com".to_string()),
            runtime_config: Some(RuntimeConfig {
                public_base_url: Some(RuntimePublicBaseUrl {
                    value: "https://persisted.example.com".to_string(),
                    source: RuntimePublicBaseUrlSource::EnvStore,
                }),
            }),
        })?;
        assert_eq!(
            contract.public_base_url.as_deref(),
            Some("https://persisted.example.com")
        );
        assert_eq!(
            contract
                .runtime_config
                .as_ref()
                .and_then(|config| config.public_base_url.as_ref())
                .map(|entry| entry.source),
            Some(RuntimePublicBaseUrlSource::EnvStore)
        );
        let json = serde_json::to_string(&contract)?;
        assert!(
            json.contains("\"env_store\""),
            "expected snake_case env_store in: {json}"
        );
        Ok(())
    }

    /// Cold-start guard: with no env directory on disk, the reader returns
    /// `Ok(None)` rather than failing. Mirrors the helper's contract for the
    /// pre-init case (no `gtc op env init` yet, no `~/.greentic/environments/`).
    #[test]
    fn env_store_reader_returns_none_for_missing_env_dir() -> anyhow::Result<()> {
        let dir = tempdir()?;
        // Point HOME at an empty temp dir so `LocalFsStore::default_root` resolves
        // to a real path but no env subdirectory exists. `set_var` is `unsafe` on
        // Rust 2024; safe here because the test does not spawn child threads
        // that read HOME concurrently.
        let prev = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", dir.path());
        }
        let result = configured_public_base_url_from_env_store("local");
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        assert_eq!(result?, None);
        Ok(())
    }

    fn write_pack(path: &Path, with_static_routes: bool) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut extensions = BTreeMap::new();
        if with_static_routes {
            extensions.insert(
                EXT_STATIC_ROUTES_V1.to_string(),
                ExtensionRef {
                    kind: EXT_STATIC_ROUTES_V1.to_string(),
                    version: "1.0.0".to_string(),
                    digest: None,
                    location: None,
                    inline: Some(ExtensionInline::Other(json!({
                        "schema_version": 1,
                        "routes": [{"path": "/"}]
                    }))),
                },
            );
        }
        let manifest = PackManifest {
            agents: Default::default(),
            schema_version: "pack-v1".to_string(),
            pack_id: PackId::new("demo.static").expect("pack id"),
            name: None,
            version: Version::parse("0.1.0").expect("version"),
            kind: PackKind::Provider,
            publisher: "demo".to_string(),
            components: Vec::new(),
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            secret_requirements: Vec::new(),
            signatures: PackSignatures::default(),
            bootstrap: None,
            extensions: if extensions.is_empty() {
                None
            } else {
                Some(extensions)
            },
        };
        let bytes = greentic_types::encode_pack_manifest(&manifest)?;
        let file = File::create(path)?;
        let mut zip = ZipWriter::new(file);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())?;
        zip.write_all(&bytes)?;
        zip.finish()?;
        Ok(())
    }

    // --- derive_public_base_url / running_on_cloud_run / is_own_cloud_run_host ---

    fn cloud_run_headers(host: &str, proto: Option<&str>, trace: bool) -> hyper::HeaderMap {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(hyper::header::HOST, host.parse().unwrap());
        if let Some(p) = proto {
            headers.insert("x-forwarded-proto", p.parse().unwrap());
        }
        if trace {
            headers.insert("x-cloud-trace-context", "abc123/456;o=1".parse().unwrap());
        }
        headers
    }

    #[test]
    fn derive_public_base_url_accepts_own_service_legacy_url() {
        // Legacy format: <service>-<hash>-<region>.a.run.app
        let headers = cloud_run_headers("gtc-svc-abc123-uc.a.run.app", Some("https"), true);
        assert_eq!(
            derive_public_base_url(&headers, "gtc-svc-abc123"),
            Some("https://gtc-svc-abc123-uc.a.run.app".to_string()),
        );
    }

    #[test]
    fn derive_public_base_url_accepts_own_service_new_url() {
        // Current format: <service>-<projnum>.<region>.run.app
        let headers = cloud_run_headers("mysvc-123456.us-central1.run.app", Some("https"), true);
        assert_eq!(
            derive_public_base_url(&headers, "mysvc"),
            Some("https://mysvc-123456.us-central1.run.app".to_string()),
        );
    }

    #[test]
    fn derive_public_base_url_defaults_scheme_to_https_when_absent() {
        // No x-forwarded-proto header — should default to https.
        let headers = cloud_run_headers("example-xyz.a.run.app", None, true);
        assert_eq!(
            derive_public_base_url(&headers, "example"),
            Some("https://example-xyz.a.run.app".to_string()),
        );
    }

    #[test]
    fn derive_public_base_url_rejects_http_scheme() {
        let headers = cloud_run_headers("gtc-svc-xyz.a.run.app", Some("http"), true);
        assert_eq!(derive_public_base_url(&headers, "gtc-svc"), None);
    }

    #[test]
    fn derive_public_base_url_rejects_missing_host() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-cloud-trace-context", "abc/1;o=1".parse().unwrap());
        assert_eq!(derive_public_base_url(&headers, "example"), None);
    }

    #[test]
    fn derive_public_base_url_rejects_ip_host() {
        let headers = cloud_run_headers("192.168.1.1", Some("https"), true);
        assert_eq!(derive_public_base_url(&headers, "example"), None);
    }

    #[test]
    fn derive_public_base_url_rejects_localhost() {
        let headers = cloud_run_headers("localhost", Some("https"), true);
        assert_eq!(derive_public_base_url(&headers, "example"), None);
    }

    #[test]
    fn derive_public_base_url_rejects_missing_trace_context() {
        // No X-Cloud-Trace-Context → not a GFE-fronted request.
        let headers = cloud_run_headers("example-xyz.a.run.app", Some("https"), false);
        assert_eq!(derive_public_base_url(&headers, "example"), None);
    }

    #[test]
    fn derive_public_base_url_rejects_foreign_host_hijack() {
        // Attacker-supplied Host that passes the GFE trust signals but is NOT
        // this service's own run.app URL — must never be captured (webhook
        // hijack). Covers both a bare domain and a custom domain.
        for host in ["evil.attacker.com", "bot.example.com"] {
            let headers = cloud_run_headers(host, Some("https"), true);
            assert_eq!(
                derive_public_base_url(&headers, "mysvc"),
                None,
                "must reject foreign host {host}",
            );
        }
    }

    #[test]
    fn derive_public_base_url_rejects_other_services_run_app_url() {
        // Another Cloud Run service's URL: right suffix, wrong service prefix.
        let headers = cloud_run_headers("othersvc-abc-uc.a.run.app", Some("https"), true);
        assert_eq!(derive_public_base_url(&headers, "mysvc"), None);
    }

    /// `running_on_cloud_run` reads K_SERVICE. Both the set and unset checks
    /// live in one test to avoid a race with another env-mutating test
    /// (`set_var` is not thread-safe).
    #[test]
    fn running_on_cloud_run_reads_k_service() {
        let prev = std::env::var_os("K_SERVICE");
        // Phase 1: set → should return true.
        unsafe {
            std::env::set_var("K_SERVICE", "my-svc");
        }
        let when_set = running_on_cloud_run();
        // Phase 2: remove → should return false.
        unsafe {
            std::env::remove_var("K_SERVICE");
        }
        let when_unset = running_on_cloud_run();
        // Restore.
        unsafe {
            if let Some(v) = prev {
                std::env::set_var("K_SERVICE", v);
            }
        }
        assert!(when_set, "must return true when K_SERVICE is set");
        assert!(!when_unset, "must return false when K_SERVICE is absent");
    }

    #[test]
    fn is_own_cloud_run_host_matches_own_service() {
        assert!(is_own_cloud_run_host(
            "gtc-svc-abc-uc.a.run.app",
            "gtc-svc-abc"
        ));
        assert!(is_own_cloud_run_host(
            "mysvc-123456.us-central1.run.app",
            "mysvc"
        ));
        // Case-insensitive; strips an optional :port.
        assert!(is_own_cloud_run_host("MYSVC-1.A.RUN.APP", "mysvc"));
        assert!(is_own_cloud_run_host("mysvc-1.a.run.app:443", "mysvc"));
    }

    #[test]
    fn is_own_cloud_run_host_rejects_mismatches() {
        // Foreign / custom domains.
        assert!(!is_own_cloud_run_host("evil.com", "mysvc"));
        assert!(!is_own_cloud_run_host("bot.example.com", "mysvc"));
        // Right suffix, wrong service.
        assert!(!is_own_cloud_run_host("othersvc-1.a.run.app", "mysvc"));
        // Right service, wrong suffix (custom domain that starts with the name).
        assert!(!is_own_cloud_run_host("mysvc-1.example.com", "mysvc"));
        // IP / localhost.
        assert!(!is_own_cloud_run_host("192.168.1.1", "mysvc"));
        assert!(!is_own_cloud_run_host("localhost", "mysvc"));
        // Empty service never matches (fail-safe).
        assert!(!is_own_cloud_run_host("mysvc-1.a.run.app", ""));
    }
}
