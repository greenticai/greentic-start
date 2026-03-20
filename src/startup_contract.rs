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
        if effective_public_base_url.is_none() {
            anyhow::bail!("bundle declares static routes but no PUBLIC_BASE_URL could be resolved");
        }
    }

    let public_http_enabled = input.http_listener_enabled && effective_public_base_url.is_some();
    let static_routes_enabled =
        input.bundle_has_static_routes && input.asset_serving_enabled && public_http_enabled;

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

fn normalize_public_base_url(value: &str) -> anyhow::Result<String> {
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
    fn resolve_rejects_missing_public_base_url() {
        let err = resolve(StartupContractInput {
            bundle_has_static_routes: true,
            http_listener_enabled: true,
            asset_serving_enabled: true,
            public_base_url: None,
            runtime_config: None,
        })
        .expect_err("expected launch gating failure");
        assert!(err.to_string().contains("no PUBLIC_BASE_URL"));
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
}
