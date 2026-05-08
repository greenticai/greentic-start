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
    let providers_root = root.join("providers");
    let discovered_paths = if providers_root.exists() {
        collect_gtpacks(&providers_root)?
    } else {
        Vec::new()
    };
    for domain in [Domain::Messaging, Domain::Events, Domain::OAuth] {
        for path in &discovered_paths {
            if !domains::provider_pack_matches_domain(
                root,
                path,
                &read_provider_id_hint(path),
                domain,
            ) {
                continue;
            }
            let (provider_id, id_source) = match if options.cbor_only {
                read_pack_id_from_manifest_cbor_only(path)?
            } else {
                read_pack_id_from_manifest(path)?
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
            if !domains::provider_pack_matches_domain(root, path, &provider_id, domain) {
                continue;
            }
            providers.push(DetectedProvider {
                provider_id,
                domain: domains::domain_name(domain).to_string(),
                pack_path: path.clone(),
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

fn collect_gtpacks(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut packs = Vec::new();
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
                packs.push(path);
            }
        }
    }
    Ok(packs)
}

fn read_provider_id_hint(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string()
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
    let symbols = symbols_map(map);

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

fn symbols_map(
    map: &std::collections::BTreeMap<CborValue, CborValue>,
) -> Option<&std::collections::BTreeMap<CborValue, CborValue>> {
    match map_get(map, "symbols") {
        Some(CborValue::Map(map)) => Some(map),
        _ => None,
    }
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
            let Some(values) = symbol_array(symbols, symbol_key) else {
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

fn symbol_array<'a>(
    symbols: &'a std::collections::BTreeMap<CborValue, CborValue>,
    key: &'a str,
) -> Option<&'a Vec<CborValue>> {
    if let Some(CborValue::Array(values)) = map_get(symbols, key) {
        return Some(values);
    }
    if let Some(stripped) = key.strip_suffix('s')
        && let Some(CborValue::Array(values)) = map_get(symbols, stripped)
    {
        return Some(values);
    }
    None
}

fn map_get<'a>(
    map: &'a std::collections::BTreeMap<CborValue, CborValue>,
    key: &str,
) -> Option<&'a CborValue> {
    map.get(&CborValue::Text(key.to_string()))
}

fn missing_cbor_error(path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "ERROR: demo packs must be CBOR-only (.gtpack must contain manifest.cbor). Rebuild the pack with greentic-pack build (do not use --dev). Missing in {}",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use tempfile::tempdir;
    use zip::write::FileOptions;

    fn write_pack(path: &Path, entries: &[(&str, Vec<u8>)]) {
        let file = std::fs::File::create(path).expect("create pack");
        let mut zip = zip::ZipWriter::new(file);
        for (name, bytes) in entries {
            zip.start_file(*name, FileOptions::<()>::default())
                .expect("start file");
            zip.write_all(bytes).expect("write file");
        }
        zip.finish().expect("finish pack");
    }

    #[test]
    fn discover_falls_back_to_filename_and_persists_results() {
        let dir = tempdir().expect("tempdir");
        let messaging_dir = dir.path().join("providers").join("messaging");
        let oauth_dir = dir.path().join("providers").join("oauth");
        std::fs::create_dir_all(&messaging_dir).expect("messaging dir");
        std::fs::create_dir_all(&oauth_dir).expect("oauth dir");

        write_pack(
            &messaging_dir.join("alpha.gtpack"),
            &[(
                "manifest.cbor",
                serde_cbor::to_vec(&CborValue::Map(std::collections::BTreeMap::from([(
                    CborValue::Text("pack_id".to_string()),
                    CborValue::Text("messaging-alpha".to_string()),
                )])))
                .expect("manifest"),
            )],
        );
        write_pack(
            &oauth_dir.join("fallback.gtpack"),
            &[(
                "pack.manifest.json",
                serde_json::to_vec(&serde_json::json!({})).expect("json"),
            )],
        );

        let discovered = discover(dir.path()).expect("discover");
        assert!(discovered.domains.messaging);
        assert!(discovered.domains.oauth);
        assert!(!discovered.domains.events);
        assert_eq!(discovered.providers.len(), 2);
        assert_eq!(discovered.providers[0].provider_id, "messaging-alpha");
        assert_eq!(
            discovered.providers[0].id_source,
            ProviderIdSource::Manifest
        );
        assert_eq!(discovered.providers[1].provider_id, "fallback");
        assert_eq!(
            discovered.providers[1].id_source,
            ProviderIdSource::Filename
        );

        persist(dir.path(), "tenant-a", &discovered).expect("persist");
        assert!(
            dir.path()
                .join("state")
                .join("runtime")
                .join("tenant-a")
                .join("detected_domains.json")
                .exists()
        );
        assert!(
            dir.path()
                .join("state")
                .join("runtime")
                .join("tenant-a")
                .join("detected_providers.json")
                .exists()
        );
    }

    #[test]
    fn discover_cbor_only_requires_manifest_cbor() {
        let dir = tempdir().expect("tempdir");
        let messaging_dir = dir.path().join("providers").join("messaging");
        std::fs::create_dir_all(&messaging_dir).expect("messaging dir");
        write_pack(
            &messaging_dir.join("json-only.gtpack"),
            &[(
                "pack.manifest.json",
                serde_json::to_vec(&serde_json::json!({"pack_id":"json-only"})).expect("json"),
            )],
        );

        let err = discover_with_options(dir.path(), DiscoveryOptions { cbor_only: true })
            .expect_err("cbor-only should fail");
        assert!(err.to_string().contains("CBOR-only"));
    }

    #[test]
    fn discover_supports_provider_id_directories() {
        let dir = tempdir().expect("tempdir");
        let provider_dir = dir.path().join("providers").join("messaging-webchat-gui");
        std::fs::create_dir_all(&provider_dir).expect("provider dir");
        write_pack(
            &provider_dir.join("messaging-webchat-gui.gtpack"),
            &[(
                "manifest.cbor",
                serde_cbor::to_vec(&CborValue::Map(std::collections::BTreeMap::from([(
                    CborValue::Text("pack_id".to_string()),
                    CborValue::Text("messaging-webchat-gui".to_string()),
                )])))
                .expect("manifest"),
            )],
        );

        let discovered = discover(dir.path()).expect("discover");
        assert!(discovered.domains.messaging);
        assert_eq!(discovered.providers.len(), 1);
        assert_eq!(discovered.providers[0].provider_id, "messaging-webchat-gui");
        assert_eq!(discovered.providers[0].domain, "messaging");
    }

    #[test]
    fn extract_pack_id_from_value_supports_symbol_tables_and_meta_fallback() {
        let value = CborValue::Map(std::collections::BTreeMap::from([
            (
                CborValue::Text("symbols".to_string()),
                CborValue::Map(std::collections::BTreeMap::from([(
                    CborValue::Text("pack_ids".to_string()),
                    CborValue::Array(vec![CborValue::Text("events-hook".to_string())]),
                )])),
            ),
            (
                CborValue::Text("meta".to_string()),
                CborValue::Map(std::collections::BTreeMap::from([(
                    CborValue::Text("pack_id".to_string()),
                    CborValue::Integer(0),
                )])),
            ),
        ]));
        assert_eq!(
            extract_pack_id_from_value(&value).expect("extract"),
            Some("events-hook".to_string())
        );
        assert_eq!(
            resolve_string_symbol(&CborValue::Integer(3), None, "pack_ids").expect("fallback"),
            Some("3".to_string())
        );
    }
}
