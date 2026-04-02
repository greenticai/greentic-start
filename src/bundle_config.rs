use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use serde::Deserialize;

use crate::StartRequest;
use crate::bundle_ref;
use crate::config;

#[derive(Clone, Debug)]
pub(crate) struct DemoPaths {
    pub(crate) config_path: PathBuf,
    pub(crate) root_dir: PathBuf,
    pub(crate) state_dir: PathBuf,
    pub(crate) config_source: DemoConfigSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DemoConfigSource {
    LegacyFile,
    NormalizedBundle,
}

pub(crate) fn resolve_demo_paths(
    explicit: Option<PathBuf>,
    bundle: Option<&str>,
) -> anyhow::Result<DemoPaths> {
    if let Some(path) = explicit {
        let root_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        let config_source = resolve_runtime_config_source(&root_dir, &path)?;
        return Ok(DemoPaths {
            state_dir: root_dir.join("state"),
            root_dir,
            config_path: path,
            config_source,
        });
    }
    if let Some(bundle_ref) = bundle {
        let resolved = bundle_ref::resolve_bundle_ref(bundle_ref)?;
        let root_dir = resolved.bundle_dir;
        let (config_path, config_source) = resolve_bundle_config_path(&root_dir)?;
        return Ok(DemoPaths {
            state_dir: root_dir.join("state"),
            root_dir,
            config_path,
            config_source,
        });
    }
    let cwd = std::env::current_dir()?;
    let demo_path = cwd.join("demo").join("demo.yaml");
    if demo_path.exists() {
        let root_dir = demo_path.parent().unwrap_or(Path::new(".")).to_path_buf();
        return Ok(DemoPaths {
            state_dir: root_dir.join("state"),
            root_dir,
            config_path: demo_path,
            config_source: DemoConfigSource::LegacyFile,
        });
    }
    let fallback = cwd.join("greentic.operator.yaml");
    if fallback.exists() {
        return Ok(DemoPaths {
            state_dir: cwd.join("state"),
            root_dir: cwd,
            config_path: fallback,
            config_source: DemoConfigSource::LegacyFile,
        });
    }
    Err(anyhow!(
        "no demo config found; pass --config, --bundle, or create ./demo/demo.yaml"
    ))
}

fn resolve_bundle_config_path(root_dir: &Path) -> anyhow::Result<(PathBuf, DemoConfigSource)> {
    let demo = root_dir.join("greentic.demo.yaml");
    if demo.exists() {
        return Ok((demo, DemoConfigSource::LegacyFile));
    }
    let fallback = root_dir.join("greentic.operator.yaml");
    if fallback.exists() {
        return Ok((fallback, DemoConfigSource::LegacyFile));
    }
    let nested_demo = root_dir.join("demo").join("demo.yaml");
    if nested_demo.exists() {
        return Ok((nested_demo, DemoConfigSource::LegacyFile));
    }
    let normalized = root_dir.join("bundle.yaml");
    if normalized.exists() && normalized_bundle_has_runtime_payload(root_dir) {
        return Ok((normalized, DemoConfigSource::NormalizedBundle));
    }
    Err(anyhow!(
        "bundle config not found under {}; expected greentic.demo.yaml, greentic.operator.yaml, demo/demo.yaml, or a normalized bundle rooted on bundle.yaml",
        root_dir.display()
    ))
}

fn resolve_runtime_config_source(root_dir: &Path, path: &Path) -> anyhow::Result<DemoConfigSource> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if matches!(
        name,
        "greentic.demo.yaml" | "greentic.operator.yaml" | "demo.yaml"
    ) {
        return Ok(DemoConfigSource::LegacyFile);
    }
    if name == "bundle.yaml" && normalized_bundle_has_runtime_payload(root_dir) {
        return Ok(DemoConfigSource::NormalizedBundle);
    }
    Err(anyhow!(
        "unsupported startup config {}; expected greentic.demo.yaml, greentic.operator.yaml, demo/demo.yaml, or bundle.yaml for a normalized bundle",
        path.display()
    ))
}

fn normalized_bundle_has_runtime_payload(root_dir: &Path) -> bool {
    root_dir.join("bundle-manifest.json").exists() || root_dir.join("resolved").is_dir()
}

/// Extended bundle.yaml structure with optional demo config fields
#[derive(Debug, Deserialize)]
struct ExtendedBundleYaml {
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    providers: Option<std::collections::BTreeMap<String, config::DemoProviderConfig>>,
}

/// Result of loading extended bundle.yaml
struct ExtendedBundleResult {
    tenant: Option<String>,
    team: Option<String>,
    providers: Option<std::collections::BTreeMap<String, config::DemoProviderConfig>>,
}

/// Load extended config from bundle.yaml if present (tenant, team, providers)
fn load_extended_bundle_config(
    bundle_path: &Path,
    root_dir: &Path,
) -> anyhow::Result<Option<ExtendedBundleResult>> {
    if !bundle_path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(bundle_path)
        .with_context(|| format!("read {}", bundle_path.display()))?;

    let parsed: ExtendedBundleYaml = serde_yaml_bw::from_str(&raw)
        .with_context(|| format!("parse extended config from {}", bundle_path.display()))?;

    let mut providers = parsed.providers;

    // Resolve relative pack paths to absolute paths
    if let Some(ref mut provider_map) = providers {
        for (_name, cfg) in provider_map.iter_mut() {
            if let Some(pack) = cfg.pack.as_mut() {
                let pack_path = Path::new(pack);
                if !pack_path.is_absolute() {
                    let resolved = root_dir.join(pack_path);
                    *pack = resolved.to_string_lossy().to_string();
                }
            }
        }
    }

    Ok(Some(ExtendedBundleResult {
        tenant: parsed.tenant,
        team: parsed.team,
        providers,
    }))
}

pub(crate) fn load_runtime_demo_config(
    demo_paths: &DemoPaths,
    request: &StartRequest,
) -> anyhow::Result<config::DemoConfig> {
    let mut demo_config = match demo_paths.config_source {
        DemoConfigSource::LegacyFile => config::load_demo_config(&demo_paths.config_path)?,
        DemoConfigSource::NormalizedBundle => {
            let mut config = config::DemoConfig::default();
            let mut tenant_from_bundle = false;
            let mut team_from_bundle = false;

            // Try to load extended config from bundle.yaml (tenant, team, providers)
            if let Some(extended) =
                load_extended_bundle_config(&demo_paths.config_path, &demo_paths.root_dir)?
            {
                // Use tenant/team from bundle.yaml if present
                if let Some(tenant) = extended.tenant {
                    config.tenant = tenant;
                    tenant_from_bundle = true;
                }
                if let Some(team) = extended.team {
                    config.team = team;
                    team_from_bundle = true;
                }
                // Load providers
                if extended.providers.is_some() {
                    config.providers = extended.providers;
                }
            }

            // Fallback to inferred target from resolved/ directory if tenant/team not set in bundle.yaml
            if !tenant_from_bundle
                && let Some(target) = infer_normalized_bundle_target(&demo_paths.root_dir)?
            {
                config.tenant = target.tenant;
                if !team_from_bundle && let Some(team) = target.team {
                    config.team = team;
                }
            }

            config
        }
    };
    apply_target_overrides(&mut demo_config, request);
    Ok(demo_config)
}

fn apply_target_overrides(config: &mut config::DemoConfig, request: &StartRequest) {
    if let Some(tenant) = request.tenant.as_ref() {
        config.tenant = tenant.clone();
    }
    if let Some(team) = request.team.as_ref() {
        config.team = team.clone();
    }
    if let Ok(listen_addr) = std::env::var("GREENTIC_GATEWAY_LISTEN_ADDR") {
        let trimmed = listen_addr.trim();
        if !trimmed.is_empty() {
            config.services.gateway.listen_addr = trimmed.to_string();
        }
    }
    if let Ok(port) = std::env::var("GREENTIC_GATEWAY_PORT") {
        let trimmed = port.trim();
        if !trimmed.is_empty()
            && let Ok(parsed) = trimmed.parse::<u16>()
        {
            config.services.gateway.port = parsed;
        }
    }
}

#[derive(Debug, Deserialize)]
struct BundleManifestSummary {
    #[serde(default)]
    resolved_targets: Vec<ResolvedTargetSummary>,
}

#[derive(Debug, Deserialize)]
struct ResolvedTargetSummary {
    tenant: String,
    #[serde(default)]
    team: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResolvedManifestSummary {
    tenant: String,
    #[serde(default)]
    team: Option<String>,
}

fn infer_normalized_bundle_target(
    root_dir: &Path,
) -> anyhow::Result<Option<ResolvedTargetSummary>> {
    let manifest_path = root_dir.join("bundle-manifest.json");
    if manifest_path.exists() {
        let raw = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?;
        let parsed: BundleManifestSummary = serde_json::from_str(&raw)
            .with_context(|| format!("parse {}", manifest_path.display()))?;
        if let Some(target) = parsed.resolved_targets.into_iter().next() {
            return Ok(Some(target));
        }
    }

    let resolved_dir = root_dir.join("resolved");
    if !resolved_dir.is_dir() {
        return Ok(None);
    }

    let mut entries = std::fs::read_dir(&resolved_dir)?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("read {}", resolved_dir.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("yaml") {
            continue;
        }
        if let Some(target) = infer_target_from_resolved_file(&path)? {
            return Ok(Some(target));
        }
    }

    Ok(None)
}

fn infer_target_from_resolved_file(path: &Path) -> anyhow::Result<Option<ResolvedTargetSummary>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if let Ok(parsed) = serde_yaml_bw::from_str::<ResolvedManifestSummary>(&raw) {
        return Ok(Some(ResolvedTargetSummary {
            tenant: parsed.tenant,
            team: parsed.team,
        }));
    }

    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if stem.is_empty() {
        return Ok(None);
    }
    if let Some((tenant, team)) = stem.split_once('.') {
        return Ok(Some(ResolvedTargetSummary {
            tenant: tenant.to_string(),
            team: Some(team.to_string()),
        }));
    }
    Ok(Some(ResolvedTargetSummary {
        tenant: stem.to_string(),
        team: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CloudflaredModeArg, DEMO_DEFAULT_TEAM, NatsModeArg, NgrokModeArg};

    fn make_test_request(bundle: Option<&str>) -> StartRequest {
        StartRequest {
            bundle: bundle.map(|s| s.to_string()),
            tenant: None,
            team: None,
            no_nats: false,
            nats: NatsModeArg::Off,
            nats_url: None,
            config: None,
            cloudflared: CloudflaredModeArg::Off,
            cloudflared_binary: None,
            ngrok: NgrokModeArg::Off,
            ngrok_binary: None,
            runner_binary: None,
            restart: Vec::new(),
            log_dir: None,
            verbose: false,
            quiet: false,
            admin: false,
            admin_port: 9443,
            admin_certs_dir: None,
            admin_allowed_clients: Vec::new(),
            tunnel_explicit: true,
        }
    }

    #[test]
    fn resolve_demo_paths_prefers_bundle_greentic_demo_yaml() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        std::fs::write(
            bundle.join("greentic.demo.yaml"),
            "version: \"1\"\nproject_root: \"./\"\n",
        )
        .expect("write config");

        let paths =
            resolve_demo_paths(None, Some(bundle.to_string_lossy().as_ref())).expect("paths");
        assert_eq!(paths.root_dir, bundle);
        assert_eq!(paths.config_path, bundle.join("greentic.demo.yaml"));
        assert_eq!(paths.state_dir, bundle.join("state"));
        assert_eq!(paths.config_source, DemoConfigSource::LegacyFile);
    }

    #[test]
    fn resolve_demo_paths_accepts_file_bundle_ref() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        std::fs::write(
            bundle.join("greentic.demo.yaml"),
            "version: \"1\"\nproject_root: \"./\"\n",
        )
        .expect("write config");
        let file_ref = format!("file://{}", bundle.display());

        let paths = resolve_demo_paths(None, Some(&file_ref)).expect("paths");
        assert_eq!(paths.config_path, bundle.join("greentic.demo.yaml"));
    }

    #[test]
    fn resolve_demo_paths_accepts_normalized_bundle_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        std::fs::write(bundle.join("bundle.yaml"), "bundle_id: demo-bundle\n").expect("bundle");
        std::fs::create_dir_all(bundle.join("resolved")).expect("resolved dir");
        std::fs::write(bundle.join("resolved/default.yaml"), "tenant: default\n")
            .expect("resolved output");

        let paths =
            resolve_demo_paths(None, Some(bundle.to_string_lossy().as_ref())).expect("paths");
        assert_eq!(paths.config_path, bundle.join("bundle.yaml"));
        assert_eq!(paths.config_source, DemoConfigSource::NormalizedBundle);
    }

    #[test]
    fn load_runtime_demo_config_infers_normalized_bundle_target() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        std::fs::write(bundle.join("bundle.yaml"), "bundle_id: demo-bundle\n").expect("bundle");
        std::fs::write(
            bundle.join("bundle-manifest.json"),
            r#"{"resolved_targets":[{"tenant":"default","team":null}]}"#,
        )
        .expect("manifest");
        let request = make_test_request(Some(&bundle.display().to_string()));
        let paths = DemoPaths {
            config_path: bundle.join("bundle.yaml"),
            root_dir: bundle.to_path_buf(),
            state_dir: bundle.join("state"),
            config_source: DemoConfigSource::NormalizedBundle,
        };

        let config = load_runtime_demo_config(&paths, &request).expect("config");
        assert_eq!(config.tenant, "default");
        assert_eq!(config.team, DEMO_DEFAULT_TEAM);
    }

    #[test]
    fn load_runtime_demo_config_applies_cli_target_overrides() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        std::fs::write(bundle.join("bundle.yaml"), "bundle_id: demo-bundle\n").expect("bundle");
        std::fs::create_dir_all(bundle.join("resolved")).expect("resolved dir");
        std::fs::write(
            bundle.join("resolved/default.platform.yaml"),
            "tenant: default\nteam: platform\n",
        )
        .expect("resolved output");
        let mut request = make_test_request(Some(&bundle.display().to_string()));
        request.tenant = Some("tenant-a".to_string());
        request.team = Some("team-b".to_string());
        let paths = DemoPaths {
            config_path: bundle.join("bundle.yaml"),
            root_dir: bundle.to_path_buf(),
            state_dir: bundle.join("state"),
            config_source: DemoConfigSource::NormalizedBundle,
        };

        let config = load_runtime_demo_config(&paths, &request).expect("config");
        assert_eq!(config.tenant, "tenant-a");
        assert_eq!(config.team, "team-b");
    }

    #[test]
    fn load_runtime_demo_config_applies_gateway_env_overrides() {
        let _lock = crate::test_env_lock().lock().unwrap();
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        std::fs::write(bundle.join("bundle.yaml"), "bundle_id: demo-bundle\n").expect("bundle");
        let request = make_test_request(Some(&bundle.display().to_string()));
        let paths = DemoPaths {
            config_path: bundle.join("bundle.yaml"),
            root_dir: bundle.to_path_buf(),
            state_dir: bundle.join("state"),
            config_source: DemoConfigSource::NormalizedBundle,
        };

        unsafe {
            std::env::set_var("GREENTIC_GATEWAY_LISTEN_ADDR", "0.0.0.0");
            std::env::set_var("GREENTIC_GATEWAY_PORT", "18080");
        }
        let config = load_runtime_demo_config(&paths, &request).expect("config");
        unsafe {
            std::env::remove_var("GREENTIC_GATEWAY_LISTEN_ADDR");
            std::env::remove_var("GREENTIC_GATEWAY_PORT");
        }

        assert_eq!(config.services.gateway.listen_addr, "0.0.0.0");
        assert_eq!(config.services.gateway.port, 18080);
    }
}
