use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_cbor::Value as CborValue;
use zip::result::ZipError;

use crate::domains::{self, Domain};
use crate::runtime_state::write_json;

#[derive(Clone, Debug, Serialize)]
pub struct DiscoveryResult {
    pub domains: DetectedDomains,
    pub providers: Vec<DetectedProvider>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DetectedDomains {
    pub messaging: bool,
    pub events: bool,
    pub oauth: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct DetectedProvider {
    pub provider_id: String,
    pub domain: String,
    pub pack_path: PathBuf,
    pub id_source: ProviderIdSource,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderIdSource {
    Manifest,
    Filename,
}

#[derive(Default)]
pub struct DiscoveryOptions {
    pub cbor_only: bool,
}

pub fn discover(root: &Path) -> anyhow::Result<DiscoveryResult> {
    discover_with_options(root, DiscoveryOptions::default())
}

pub fn discover_with_options(
    root: &Path,
    options: DiscoveryOptions,
) -> anyhow::Result<DiscoveryResult> {
    let mut providers = Vec::new();
    for domain in [Domain::Messaging, Domain::Events, Domain::OAuth] {
        let cfg = domains::config(domain);
        let providers_dir = root.join(cfg.providers_dir);
        if !providers_dir.exists() {
            continue;
        }
        for entry in std::fs::read_dir(&providers_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("gtpack") {
                continue;
            }
            let (provider_id, id_source) = match if options.cbor_only {
                read_pack_id_from_manifest_cbor_only(&path)?
            } else {
                read_pack_id_from_manifest(&path)?
            } {
                Some(pack_id) => (pack_id, ProviderIdSource::Manifest),
                None => {
                    let stem = path
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .unwrap_or_default()
                        .to_string();
                    (stem, ProviderIdSource::Filename)
                }
            };
            providers.push(DetectedProvider {
                provider_id,
                domain: domains::domain_name(domain).to_string(),
                pack_path: path,
                id_source,
            });
        }
    }
    providers.sort_by(|a, b| a.pack_path.cmp(&b.pack_path));
    let domains = DetectedDomains {
        messaging: providers
            .iter()
            .any(|provider| provider.domain == "messaging"),
        events: providers.iter().any(|provider| provider.domain == "events"),
        oauth: providers.iter().any(|provider| provider.domain == "oauth"),
    };
    Ok(DiscoveryResult { domains, providers })
}

pub fn persist(root: &Path, tenant: &str, discovery: &DiscoveryResult) -> anyhow::Result<()> {
    let runtime_root = root.join("state").join("runtime").join(tenant);
    let domains_path = runtime_root.join("detected_domains.json");
    let providers_path = runtime_root.join("detected_providers.json");
    write_json(&domains_path, &discovery.domains)?;
    write_json(&providers_path, &discovery.providers)?;
    Ok(())
}

fn read_pack_id_from_manifest(path: &Path) -> anyhow::Result<Option<String>> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    if let Some(parsed) = read_manifest_cbor_for_discovery(&mut archive).map_err(|err| {
        anyhow::anyhow!(
            "failed to decode manifest.cbor in {}: {err}",
            path.display()
        )
    })? {
        return extract_pack_id(parsed);
    }
    if let Some(parsed) = read_manifest_json_for_discovery(&mut archive, "pack.manifest.json")
        .map_err(|err| {
            anyhow::anyhow!(
                "failed to decode pack.manifest.json in {}: {err}",
                path.display()
            )
        })?
    {
        return extract_pack_id(parsed);
    }
    Ok(None)
}

fn read_pack_id_from_manifest_cbor_only(path: &Path) -> anyhow::Result<Option<String>> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    if let Some(parsed) = read_manifest_cbor_for_discovery(&mut archive).map_err(|err| {
        anyhow::anyhow!(
            "failed to decode manifest.cbor in {}: {err}",
            path.display()
        )
    })? {
        return extract_pack_id(parsed);
    }
    Err(missing_cbor_error(path))
}

fn extract_pack_id(parsed: domains::PackManifestForDiscovery) -> anyhow::Result<Option<String>> {
    if let Some(meta) = parsed.meta {
        return Ok(Some(meta.pack_id));
    }
    if let Some(pack_id) = parsed.pack_id {
        return Ok(Some(pack_id));
    }
    Ok(None)
}

fn read_manifest_cbor_for_discovery(
    archive: &mut zip::ZipArchive<std::fs::File>,
) -> anyhow::Result<Option<domains::PackManifestForDiscovery>> {
    let mut file = match archive.by_name("manifest.cbor") {
        Ok(file) => file,
        Err(ZipError::FileNotFound) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)?;
    let value: CborValue = serde_cbor::from_slice(&bytes)?;
    if let Some(pack_id) = extract_pack_id_from_value(&value)? {
        return Ok(Some(domains::PackManifestForDiscovery {
            meta: None,
            pack_id: Some(pack_id),
        }));
    }
    Ok(None)
}

fn read_manifest_json_for_discovery(
    archive: &mut zip::ZipArchive<std::fs::File>,
    name: &str,
) -> anyhow::Result<Option<domains::PackManifestForDiscovery>> {
    let mut file = match archive.by_name(name) {
        Ok(file) => file,
        Err(ZipError::FileNotFound) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut file, &mut contents)?;
    let parsed: domains::PackManifestForDiscovery = serde_json::from_str(&contents)?;
    Ok(Some(parsed))
}

fn extract_pack_id_from_value(value: &CborValue) -> anyhow::Result<Option<String>> {
    let CborValue::Map(map) = value else {
        return Ok(None);
    };
    let symbols = match map_get(map, "symbols") {
        Some(CborValue::Map(map)) => Some(map),
        _ => None,
    };

    if let Some(pack_id) = map_get(map, "pack_id")
        && let Some(value) = resolve_string_symbol(pack_id, symbols, "pack_ids")?
    {
        return Ok(Some(value));
    }

    if let Some(CborValue::Map(meta)) = map_get(map, "meta")
        && let Some(pack_id) = map_get(meta, "pack_id")
        && let Some(value) = resolve_string_symbol(pack_id, symbols, "pack_ids")?
    {
        return Ok(Some(value));
    }

    Ok(None)
}

fn resolve_string_symbol(
    value: &CborValue,
    symbols: Option<&std::collections::BTreeMap<CborValue, CborValue>>,
    symbol_key: &str,
) -> anyhow::Result<Option<String>> {
    match value {
        CborValue::Text(text) => Ok(Some(text.clone())),
        CborValue::Integer(idx) => {
            let Some(symbols) = symbols else {
                return Ok(Some(idx.to_string()));
            };
            let Some(CborValue::Array(values)) = map_get(symbols, symbol_key)
                .or_else(|| map_get(symbols, symbol_key.strip_suffix('s').unwrap_or(symbol_key)))
            else {
                return Ok(Some(idx.to_string()));
            };
            let idx = usize::try_from(*idx).unwrap_or(usize::MAX);
            match values.get(idx) {
                Some(CborValue::Text(text)) => Ok(Some(text.clone())),
                _ => Ok(Some(idx.to_string())),
            }
        }
        _ => Ok(None),
    }
}

fn map_get<'a>(
    map: &'a std::collections::BTreeMap<CborValue, CborValue>,
    key: &str,
) -> Option<&'a CborValue> {
    map.iter().find_map(|(k, v)| match k {
        CborValue::Text(text) if text == key => Some(v),
        _ => None,
    })
}

fn missing_cbor_error(path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "ERROR: demo packs must be CBOR-only (.gtpack must contain manifest.cbor). Rebuild the pack with greentic-pack build (do not use --dev). Missing in {}",
        path.display()
    )
}
