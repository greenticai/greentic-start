#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use zip::result::ZipError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum Domain {
    Messaging,
    Events,
    Llm,
    Secrets,
    OAuth,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainAction {
    Setup,
    Diagnostics,
    Verify,
}

#[derive(Clone, Debug)]
pub struct DomainConfig {
    pub providers_dir: &'static str,
    pub setup_flow: &'static str,
    pub diagnostics_flow: &'static str,
    pub verify_flows: &'static [&'static str],
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderPack {
    pub pack_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub file_name: String,
    pub path: PathBuf,
    pub entry_flows: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PlannedRun {
    pub pack: ProviderPack,
    pub flow_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PackMetaCacheDocument {
    version: u32,
    entries: BTreeMap<String, PackMetaCacheEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PackMetaCacheEntry {
    len: u64,
    modified_epoch_s: u64,
    format: PackManifestFormat,
    pack_id: String,
    display_name: Option<String>,
    description: Option<String>,
    tags: Vec<String>,
    entry_flows: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PackManifestFormat {
    Cbor,
    Json,
}

pub fn config(domain: Domain) -> DomainConfig {
    match domain {
        Domain::Messaging => DomainConfig {
            providers_dir: "providers/messaging",
            setup_flow: "setup_default",
            diagnostics_flow: "diagnostics",
            verify_flows: &["verify_webhooks"],
        },
        Domain::Events => DomainConfig {
            providers_dir: "providers/events",
            setup_flow: "setup_default",
            diagnostics_flow: "diagnostics",
            verify_flows: &["verify_subscriptions"],
        },
        Domain::Llm => DomainConfig {
            providers_dir: "providers/llm",
            setup_flow: "setup_default",
            diagnostics_flow: "diagnostics",
            verify_flows: &[],
        },
        Domain::Secrets => DomainConfig {
            providers_dir: "providers/secrets",
            setup_flow: "setup_default",
            diagnostics_flow: "diagnostics",
            verify_flows: &[],
        },
        Domain::OAuth => DomainConfig {
            providers_dir: "providers/oauth",
            setup_flow: "setup_default",
            diagnostics_flow: "diagnostics",
            verify_flows: &[],
        },
    }
}

pub fn validator_pack_path(root: &Path, domain: Domain) -> Option<PathBuf> {
    let name = match domain {
        Domain::Messaging => "validators-messaging.gtpack",
        Domain::Events => "validators-events.gtpack",
        Domain::Llm => "validators-llm.gtpack",
        Domain::Secrets => "validators-secrets.gtpack",
        Domain::OAuth => "validators-oauth.gtpack",
    };
    let path = root.join("validators").join(domain_name(domain)).join(name);
    if path.exists() { Some(path) } else { None }
}

pub fn ensure_cbor_packs(root: &Path) -> anyhow::Result<()> {
    let mut roots = Vec::new();
    let providers = root.join("providers");
    if providers.exists() {
        roots.push(providers);
    }
    let packs = root.join("packs");
    if packs.exists() {
        roots.push(packs);
    }
    for root in roots {
        for pack in collect_gtpacks(&root)? {
            if !supports_runtime_pack_loading(&pack) {
                continue;
            }
            let file = std::fs::File::open(&pack)?;
            let mut archive = zip::ZipArchive::new(file)?;
            let manifest = read_manifest_cbor(&mut archive, &pack).map_err(|err| {
                anyhow::anyhow!(
                    "failed to decode manifest.cbor in {}: {err}",
                    pack.display()
                )
            })?;
            if manifest.is_none() {
                return Err(missing_cbor_error(&pack));
            }
        }
    }
    Ok(())
}

pub fn manifest_cbor_issue_detail(path: &Path) -> anyhow::Result<Option<String>> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut manifest = match archive.by_name("manifest.cbor") {
        Ok(file) => file,
        Err(ZipError::FileNotFound) => {
            return Ok(Some("manifest.cbor missing from archive".to_string()));
        }
        Err(err) => return Err(err.into()),
    };
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut manifest, &mut bytes)?;
    let value = match serde_cbor::from_slice::<CborValue>(&bytes) {
        Ok(value) => value,
        Err(err) => return Ok(Some(err.to_string())),
    };
    if let Some(path) = find_manifest_string_type_mismatch(&value) {
        return Ok(Some(format!("invalid type at {path} (expected string)")));
    }
    Ok(None)
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

pub(crate) fn supports_runtime_pack_loading(path: &Path) -> bool {
    if path.is_dir() {
        return true;
    }
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    zip::ZipArchive::new(file).is_ok()
}

fn append_packs_from_root(
    bundle_root: &Path,
    packs: &mut Vec<ProviderPack>,
    seen: &mut BTreeSet<PathBuf>,
    root: &Path,
    cbor_only: bool,
    cache: &mut PackMetaCacheDocument,
) -> anyhow::Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for path in collect_gtpacks(root)? {
        append_pack(bundle_root, packs, seen, path, cbor_only, cache)?;
    }
    Ok(())
}

fn append_pack(
    bundle_root: &Path,
    packs: &mut Vec<ProviderPack>,
    seen: &mut BTreeSet<PathBuf>,
    path: PathBuf,
    cbor_only: bool,
    cache: &mut PackMetaCacheDocument,
) -> anyhow::Result<()> {
    if !seen.insert(path.clone()) {
        return Ok(());
    }
    if path.starts_with(bundle_root.join("packs")) && !supports_runtime_pack_loading(&path) {
        return Ok(());
    }
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid pack file name: {}", path.display()))?
        .to_string();
    let meta = read_pack_meta_cached(bundle_root, &path, cbor_only, cache)?;
    packs.push(ProviderPack {
        pack_id: meta.pack_id,
        display_name: meta.display_name,
        description: meta.description,
        tags: meta.tags,
        file_name,
        path,
        entry_flows: meta.entry_flows,
    });
    Ok(())
}

pub fn discover_provider_packs(root: &Path, domain: Domain) -> anyhow::Result<Vec<ProviderPack>> {
    let cfg = config(domain);
    let providers_dir = root.join(cfg.providers_dir);
    let packs_dir = root.join("packs");
    let mut packs = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cache = load_pack_meta_cache(root);
    append_packs_from_root(
        root,
        &mut packs,
        &mut seen,
        &providers_dir,
        false,
        &mut cache,
    )?;
    append_packs_from_root(root, &mut packs, &mut seen, &packs_dir, false, &mut cache)?;
    packs.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    persist_pack_meta_cache(root, &cache)?;
    Ok(packs)
}

pub fn discover_provider_packs_cbor_only(
    root: &Path,
    domain: Domain,
) -> anyhow::Result<Vec<ProviderPack>> {
    let cfg = config(domain);
    let providers_dir = root.join(cfg.providers_dir);
    let packs_dir = root.join("packs");
    let mut packs = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cache = load_pack_meta_cache(root);
    append_packs_from_root(
        root,
        &mut packs,
        &mut seen,
        &providers_dir,
        true,
        &mut cache,
    )?;
    append_packs_from_root(root, &mut packs, &mut seen, &packs_dir, true, &mut cache)?;
    packs.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    persist_pack_meta_cache(root, &cache)?;
    Ok(packs)
}

pub fn plan_runs(
    domain: Domain,
    action: DomainAction,
    packs: &[ProviderPack],
    provider_filter: Option<&str>,
    allow_missing_setup: bool,
) -> anyhow::Result<Vec<PlannedRun>> {
    let cfg = config(domain);
    let flows: Vec<&str> = match action {
        DomainAction::Setup => vec![cfg.setup_flow],
        DomainAction::Diagnostics => vec![cfg.diagnostics_flow],
        DomainAction::Verify => cfg.verify_flows.to_vec(),
    };

    let mut plan = Vec::new();
    for pack in packs {
        if let Some(filter) = provider_filter {
            let file_stem = pack
                .file_name
                .strip_suffix(".gtpack")
                .unwrap_or(&pack.file_name);
            let matches = pack.pack_id == filter
                || pack.file_name == filter
                || file_stem == filter
                || pack.pack_id.contains(filter)
                || pack.file_name.contains(filter)
                || file_stem.contains(filter);
            if !matches {
                continue;
            }
        }

        for flow in &flows {
            let has_flow = pack.entry_flows.iter().any(|entry| entry == flow);
            if !has_flow {
                if action == DomainAction::Setup && !allow_missing_setup {
                    return Err(anyhow::anyhow!(
                        "Missing required flow '{}' in provider pack {}",
                        flow,
                        pack.file_name
                    ));
                }
                eprintln!(
                    "Warning: provider pack {} missing flow {}; skipping.",
                    pack.file_name, flow
                );
                continue;
            }
            plan.push(PlannedRun {
                pack: pack.clone(),
                flow_id: (*flow).to_string(),
            });
        }
    }
    Ok(plan)
}

#[derive(Debug, Deserialize)]
pub(crate) struct PackManifestForDiscovery {
    #[serde(default)]
    pub meta: Option<PackMeta>,
    #[serde(default)]
    pub pack_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PackManifest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    meta: Option<PackMeta>,
    #[serde(default)]
    pack_id: Option<String>,
    #[serde(default)]
    flows: Vec<PackFlow>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PackMeta {
    pub pack_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub entry_flows: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PackFlow {
    id: String,
    #[serde(default)]
    entrypoints: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
}

fn read_pack_manifest(path: &Path) -> anyhow::Result<PackManifest> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let manifest = read_pack_manifest_data(&mut archive, path)
        .with_context(|| format!("failed to read pack manifest from {}", path.display()))?;
    let meta = build_pack_meta(&manifest, path);
    Ok(PackManifest {
        name: manifest.name,
        description: manifest.description,
        meta: Some(meta),
        pack_id: None,
        flows: Vec::new(),
    })
}

pub(crate) fn read_pack_meta(path: &Path) -> anyhow::Result<PackMeta> {
    let manifest = if path.is_dir() {
        read_pack_manifest_from_dir(path)
    } else {
        read_pack_manifest(path)
    }?;
    manifest
        .meta
        .ok_or_else(|| anyhow::anyhow!("pack manifest missing meta in {}", path.display()))
}

fn read_pack_meta_cached(
    bundle_root: &Path,
    path: &Path,
    cbor_only: bool,
    cache: &mut PackMetaCacheDocument,
) -> anyhow::Result<PackMeta> {
    let key = cache_key(bundle_root, path);
    let fingerprint = file_fingerprint(path)?;
    if let Some(entry) = cache.entries.get(&key)
        && entry.len == fingerprint.0
        && entry.modified_epoch_s == fingerprint.1
        && (!cbor_only || entry.format == PackManifestFormat::Cbor)
    {
        return Ok(PackMeta {
            pack_id: entry.pack_id.clone(),
            display_name: entry.display_name.clone(),
            description: entry.description.clone(),
            tags: entry.tags.clone(),
            entry_flows: entry.entry_flows.clone(),
        });
    }

    let (meta, format) = read_pack_meta_with_format(path, cbor_only)?;
    cache.entries.insert(
        key,
        PackMetaCacheEntry {
            len: fingerprint.0,
            modified_epoch_s: fingerprint.1,
            format,
            pack_id: meta.pack_id.clone(),
            display_name: meta.display_name.clone(),
            description: meta.description.clone(),
            tags: meta.tags.clone(),
            entry_flows: meta.entry_flows.clone(),
        },
    );
    Ok(meta)
}

fn read_pack_meta_with_format(
    path: &Path,
    cbor_only: bool,
) -> anyhow::Result<(PackMeta, PackManifestFormat)> {
    let manifest = if cbor_only {
        read_pack_manifest_cbor_only(path)?
    } else {
        read_pack_manifest(path)?
    };
    let format = detect_manifest_format(path, cbor_only)?;
    let meta = manifest
        .meta
        .ok_or_else(|| anyhow::anyhow!("pack manifest missing meta in {}", path.display()))?;
    Ok((meta, format))
}

fn detect_manifest_format(path: &Path, cbor_only: bool) -> anyhow::Result<PackManifestFormat> {
    if path.is_dir() || cbor_only {
        return Ok(PackManifestFormat::Cbor);
    }
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    if archive.by_name("manifest.cbor").is_ok() {
        return Ok(PackManifestFormat::Cbor);
    }
    Ok(PackManifestFormat::Json)
}

fn pack_meta_cache_path(bundle_root: &Path) -> PathBuf {
    bundle_root
        .join("state")
        .join("cache")
        .join("pack-meta-v1.json")
}

fn load_pack_meta_cache(bundle_root: &Path) -> PackMetaCacheDocument {
    let path = pack_meta_cache_path(bundle_root);
    let Ok(raw) = fs::read_to_string(&path) else {
        return PackMetaCacheDocument {
            version: 1,
            entries: BTreeMap::new(),
        };
    };
    serde_json::from_str(&raw).unwrap_or(PackMetaCacheDocument {
        version: 1,
        entries: BTreeMap::new(),
    })
}

fn persist_pack_meta_cache(
    bundle_root: &Path,
    cache: &PackMetaCacheDocument,
) -> anyhow::Result<()> {
    let path = pack_meta_cache_path(bundle_root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, serde_json::to_vec_pretty(cache)?)?;
    Ok(())
}

fn cache_key(bundle_root: &Path, path: &Path) -> String {
    path.strip_prefix(bundle_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn file_fingerprint(path: &Path) -> anyhow::Result<(u64, u64)> {
    let metadata = fs::metadata(path)?;
    let modified_epoch_s = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_secs())
        .unwrap_or(0);
    Ok((metadata.len(), modified_epoch_s))
}

fn read_pack_manifest_cbor_only(path: &Path) -> anyhow::Result<PackManifest> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let manifest = match read_manifest_cbor(&mut archive, path).map_err(|err| {
        anyhow::anyhow!(
            "failed to decode manifest.cbor in {}: {err}",
            path.display()
        )
    })? {
        Some(manifest) => manifest,
        None => return Err(missing_cbor_error(path)),
    };
    let meta = build_pack_meta(&manifest, path);
    Ok(PackManifest {
        name: manifest.name,
        description: manifest.description,
        meta: Some(meta),
        pack_id: None,
        flows: Vec::new(),
    })
}

fn read_pack_manifest_data(
    archive: &mut zip::ZipArchive<std::fs::File>,
    path: &Path,
) -> anyhow::Result<PackManifest> {
    match read_manifest_cbor(archive, path) {
        Ok(Some(manifest)) => return Ok(manifest),
        Ok(None) => {}
        Err(err) => {
            return Err(anyhow::anyhow!(
                "failed to decode manifest.cbor in {}: {err}",
                path.display()
            ));
        }
    }
    match read_manifest_json(archive, "pack.manifest.json") {
        Ok(Some(manifest)) => return Ok(manifest),
        Ok(None) => {}
        Err(err) => {
            return Err(anyhow::anyhow!(
                "failed to decode pack.manifest.json in {}: {err}",
                path.display()
            ));
        }
    }
    Err(anyhow::anyhow!(
        "pack manifest not found in archive {} (expected manifest.cbor or pack.manifest.json)",
        path.display()
    ))
}

fn read_manifest_cbor(
    archive: &mut zip::ZipArchive<std::fs::File>,
    _path: &Path,
) -> anyhow::Result<Option<PackManifest>> {
    let mut file = match archive.by_name("manifest.cbor") {
        Ok(file) => file,
        Err(ZipError::FileNotFound) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)?;
    let manifest = parse_manifest_cbor_bytes(&bytes)?;
    Ok(Some(manifest))
}

fn read_pack_manifest_from_dir(path: &Path) -> anyhow::Result<PackManifest> {
    let manifest_path = path.join("manifest.cbor");
    if !manifest_path.exists() {
        return Err(anyhow::anyhow!(
            "pack manifest missing manifest.cbor in {}",
            path.display()
        ));
    }
    let bytes = fs::read(&manifest_path)?;
    parse_manifest_cbor_bytes(&bytes)
}

fn parse_manifest_cbor_bytes(bytes: &[u8]) -> anyhow::Result<PackManifest> {
    let value: CborValue = serde_cbor::from_slice(bytes)?;
    match decode_manifest_lenient(&value) {
        Ok(manifest) => Ok(manifest),
        Err(decode_err) => {
            if let Some(err_path) = find_manifest_string_type_mismatch(&value) {
                return Err(anyhow::anyhow!(
                    "invalid type at {} (expected string)",
                    err_path
                ));
            }
            Err(anyhow::anyhow!(
                "manifest.cbor uses symbol table encoding but could not be decoded: {decode_err}"
            ))
        }
    }
}

fn build_pack_meta(manifest: &PackManifest, path: &Path) -> PackMeta {
    let pack_id = manifest
        .meta
        .as_ref()
        .map(|meta| meta.pack_id.clone())
        .or_else(|| manifest.pack_id.clone())
        .unwrap_or_else(|| {
            let fallback = path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("pack")
                .to_string();
            eprintln!(
                "Warning: pack manifest missing pack id; using filename '{}' for {}",
                fallback,
                path.display()
            );
            fallback
        });
    let mut entry_flows = manifest
        .meta
        .as_ref()
        .map(|meta| meta.entry_flows.clone())
        .unwrap_or_default();
    if entry_flows.is_empty() {
        for flow in &manifest.flows {
            entry_flows.push(flow.id.clone());
            entry_flows.extend(flow.entrypoints.iter().cloned());
        }
    }
    if entry_flows.is_empty() {
        entry_flows.push(pack_id.clone());
    }
    let display_name = manifest
        .name
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| manifest.pack_id.clone())
        .or_else(|| manifest.meta.as_ref().map(|meta| meta.pack_id.clone()))
        .or_else(|| Some(pack_id.clone()));
    let description = manifest
        .description
        .clone()
        .filter(|value| !value.trim().is_empty());
    let mut tags = BTreeSet::new();
    for flow in &manifest.flows {
        for tag in &flow.tags {
            if !tag.trim().is_empty() {
                tags.insert(tag.clone());
            }
        }
    }
    PackMeta {
        pack_id,
        display_name,
        description,
        tags: tags.into_iter().collect(),
        entry_flows,
    }
}

fn read_manifest_json(
    archive: &mut zip::ZipArchive<std::fs::File>,
    name: &str,
) -> anyhow::Result<Option<PackManifest>> {
    let mut file = match archive.by_name(name) {
        Ok(file) => file,
        Err(ZipError::FileNotFound) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut file, &mut contents)?;
    let manifest: PackManifest = serde_json::from_str(&contents)?;
    Ok(Some(manifest))
}

fn find_manifest_string_type_mismatch(value: &CborValue) -> Option<String> {
    let CborValue::Map(map) = value else {
        return None;
    };
    let symbols = symbols_map(map);

    if let Some(pack_id) = map_get(map, "pack_id")
        && !value_is_string_or_symbol(pack_id, symbols, "pack_ids")
    {
        return Some("pack_id".to_string());
    }

    if let Some(meta) = map_get(map, "meta") {
        let CborValue::Map(meta_map) = meta else {
            return Some("meta".to_string());
        };
        if let Some(pack_id) = map_get(meta_map, "pack_id")
            && !value_is_string_or_symbol(pack_id, symbols, "pack_ids")
        {
            return Some("meta.pack_id".to_string());
        }
        if let Some(entry_flows) = map_get(meta_map, "entry_flows") {
            let CborValue::Array(values) = entry_flows else {
                return Some("meta.entry_flows".to_string());
            };
            for (idx, value) in values.iter().enumerate() {
                if !value_is_string_or_symbol(value, symbols, "flow_ids") {
                    return Some(format!("meta.entry_flows[{idx}]"));
                }
            }
        }
    }

    if let Some(flows) = map_get(map, "flows") {
        let CborValue::Array(values) = flows else {
            return Some("flows".to_string());
        };
        for (idx, value) in values.iter().enumerate() {
            let CborValue::Map(flow) = value else {
                return Some(format!("flows[{idx}]"));
            };
            if let Some(id) = map_get(flow, "id")
                && !value_is_string_or_symbol(id, symbols, "flow_ids")
            {
                return Some(format!("flows[{idx}].id"));
            }
            if let Some(entrypoints) = map_get(flow, "entrypoints") {
                let CborValue::Array(values) = entrypoints else {
                    return Some(format!("flows[{idx}].entrypoints"));
                };
                for (jdx, value) in values.iter().enumerate() {
                    if !value_is_string_or_symbol(value, symbols, "entrypoints") {
                        return Some(format!("flows[{idx}].entrypoints[{jdx}]"));
                    }
                }
            }
        }
    }

    None
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

fn symbols_map(
    map: &std::collections::BTreeMap<CborValue, CborValue>,
) -> Option<&std::collections::BTreeMap<CborValue, CborValue>> {
    let symbols = map_get(map, "symbols")?;
    match symbols {
        CborValue::Map(map) => Some(map),
        _ => None,
    }
}

fn value_is_string_or_symbol(
    value: &CborValue,
    symbols: Option<&std::collections::BTreeMap<CborValue, CborValue>>,
    symbol_key: &str,
) -> bool {
    if matches!(value, CborValue::Text(_)) {
        return true;
    }
    let CborValue::Integer(idx) = value else {
        return false;
    };
    let symbols = match symbols {
        Some(symbols) => symbols,
        None => return true,
    };
    let Some(CborValue::Array(values)) = map_get(symbols, symbol_key)
        .or_else(|| map_get(symbols, symbol_key.strip_suffix('s').unwrap_or(symbol_key)))
    else {
        return true;
    };
    let idx = match usize::try_from(*idx) {
        Ok(idx) => idx,
        Err(_) => return true,
    };
    matches!(values.get(idx), Some(CborValue::Text(_)))
}

fn decode_manifest_lenient(value: &CborValue) -> anyhow::Result<PackManifest> {
    let CborValue::Map(map) = value else {
        return Err(anyhow::anyhow!("manifest is not a map"));
    };
    let symbols = symbols_map(map);
    let name = resolve_string_symbol(map_get(map, "name"), symbols, "names")?;
    let description = resolve_string_symbol(map_get(map, "description"), symbols, "descriptions")?;

    let (meta_pack_id, meta_entry_flows) = if let Some(meta) = map_get(map, "meta") {
        let CborValue::Map(meta_map) = meta else {
            return Err(anyhow::anyhow!("meta is not a map"));
        };
        let pack_id = resolve_string_symbol(map_get(meta_map, "pack_id"), symbols, "pack_ids")?;
        let entry_flows = resolve_string_array(
            map_get(meta_map, "entry_flows"),
            symbols,
            "flow_ids",
            Some("entrypoints"),
        )?;
        (pack_id, entry_flows)
    } else {
        (None, Vec::new())
    };

    let pack_id = resolve_string_symbol(map_get(map, "pack_id"), symbols, "pack_ids")?
        .or(meta_pack_id)
        .ok_or_else(|| anyhow::anyhow!("pack_id missing"))?;

    let mut flows = Vec::new();
    if let Some(flows_value) = map_get(map, "flows") {
        let CborValue::Array(values) = flows_value else {
            return Err(anyhow::anyhow!("flows is not an array"));
        };
        for (idx, value) in values.iter().enumerate() {
            let CborValue::Map(flow) = value else {
                return Err(anyhow::anyhow!("flows[{idx}] is not a map"));
            };
            let id = resolve_string_symbol(map_get(flow, "id"), symbols, "flow_ids")?
                .ok_or_else(|| anyhow::anyhow!("flows[{idx}].id missing"))?;
            let entrypoints =
                resolve_string_array(map_get(flow, "entrypoints"), symbols, "entrypoints", None)?;
            let tags = resolve_string_array(map_get(flow, "tags"), symbols, "tags", None)?;
            flows.push(PackFlow {
                id,
                entrypoints,
                tags,
            });
        }
    }

    Ok(PackManifest {
        name,
        description,
        meta: Some(PackMeta {
            pack_id,
            display_name: None,
            description: None,
            tags: Vec::new(),
            entry_flows: meta_entry_flows,
        }),
        pack_id: None,
        flows,
    })
}

fn resolve_string_symbol(
    value: Option<&CborValue>,
    symbols: Option<&std::collections::BTreeMap<CborValue, CborValue>>,
    symbol_key: &str,
) -> anyhow::Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
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
        _ => Err(anyhow::anyhow!("expected string or symbol index")),
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

fn resolve_string_array(
    value: Option<&CborValue>,
    symbols: Option<&std::collections::BTreeMap<CborValue, CborValue>>,
    symbol_key: &str,
    fallback_key: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let CborValue::Array(values) = value else {
        return Err(anyhow::anyhow!("expected array"));
    };
    let mut out = Vec::new();
    for (idx, value) in values.iter().enumerate() {
        match resolve_string_symbol(Some(value), symbols, symbol_key) {
            Ok(Some(value)) => out.push(value),
            Ok(None) => {}
            Err(err) => {
                if let Some(fallback_key) = fallback_key
                    && let Ok(Some(value)) =
                        resolve_string_symbol(Some(value), symbols, fallback_key)
                {
                    out.push(value);
                    continue;
                }
                return Err(anyhow::anyhow!("{err} at index {idx}"));
            }
        }
    }
    Ok(out)
}

fn missing_cbor_error(path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "ERROR: demo packs must be CBOR-only (.gtpack must contain manifest.cbor). Rebuild the pack with greentic-pack build (do not use --dev). Missing in {}",
        path.display()
    )
}

pub(crate) fn domain_name(domain: Domain) -> &'static str {
    match domain {
        Domain::Messaging => "messaging",
        Domain::Events => "events",
        Domain::Llm => "llm",
        Domain::Secrets => "secrets",
        Domain::OAuth => "oauth",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::ZipWriter;
    use zip::write::FileOptions;

    #[test]
    fn discover_provider_packs_persists_manifest_cache() {
        let temp = tempdir().expect("tempdir");
        let providers_dir = temp.path().join("providers").join("messaging");
        fs::create_dir_all(&providers_dir).expect("providers dir");
        let pack_path = providers_dir.join("messaging-webchat.gtpack");
        write_test_gtpack(&pack_path, "messaging-webchat", &["setup_default"]);

        let packs = discover_provider_packs(temp.path(), Domain::Messaging).expect("discover");
        assert_eq!(packs.len(), 1);
        assert_eq!(packs[0].pack_id, "messaging-webchat");
        assert_eq!(packs[0].display_name.as_deref(), Some("messaging-webchat"));
        assert_eq!(packs[0].description.as_deref(), Some("fixture description"));
        assert_eq!(packs[0].tags, vec!["default".to_string()]);

        let cache_raw =
            fs::read_to_string(temp.path().join("state/cache/pack-meta-v1.json")).expect("cache");
        assert!(cache_raw.contains("messaging-webchat.gtpack"));
        assert!(cache_raw.contains("\"pack_id\": \"messaging-webchat\""));
        assert!(cache_raw.contains("\"display_name\": \"messaging-webchat\""));
        assert!(cache_raw.contains("\"description\": \"fixture description\""));
        assert!(cache_raw.contains("\"default\""));
    }

    #[test]
    fn discover_provider_packs_skips_non_runtime_packs_in_bundle_packs_dir() {
        let temp = tempdir().expect("tempdir");
        let providers_dir = temp.path().join("providers").join("messaging");
        let packs_dir = temp.path().join("packs");
        fs::create_dir_all(&providers_dir).expect("providers dir");
        fs::create_dir_all(&packs_dir).expect("packs dir");
        let pack_path = providers_dir.join("messaging-webchat.gtpack");
        write_test_gtpack(&pack_path, "messaging-webchat", &["setup_default"]);
        fs::write(packs_dir.join("terraform.gtpack"), b"not-a-zip").expect("fake deployer pack");

        let packs = discover_provider_packs(temp.path(), Domain::Messaging).expect("discover");
        assert_eq!(packs.len(), 1);
        assert_eq!(packs[0].pack_id, "messaging-webchat");
    }

    #[test]
    fn validator_pack_path_matches_domain_layout() {
        let temp = tempdir().expect("tempdir");
        let validator = temp
            .path()
            .join("validators")
            .join("messaging")
            .join("validators-messaging.gtpack");
        fs::create_dir_all(validator.parent().expect("parent")).expect("mkdir");
        fs::write(&validator, "").expect("write validator");

        assert_eq!(
            validator_pack_path(temp.path(), Domain::Messaging),
            Some(validator)
        );
        assert_eq!(validator_pack_path(temp.path(), Domain::OAuth), None);
    }

    #[test]
    fn plan_runs_matches_provider_filter_and_verify_flows() {
        let pack = ProviderPack {
            pack_id: "messaging-webchat".to_string(),
            display_name: Some("Messaging Webchat".to_string()),
            description: None,
            tags: vec![],
            file_name: "messaging-webchat.gtpack".to_string(),
            path: PathBuf::from("/tmp/messaging-webchat.gtpack"),
            entry_flows: vec!["verify_webhooks".to_string(), "setup_default".to_string()],
        };

        let plan = plan_runs(
            Domain::Messaging,
            DomainAction::Verify,
            &[pack],
            Some("webchat"),
            false,
        )
        .expect("plan");

        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].flow_id, "verify_webhooks");
        assert_eq!(plan[0].pack.pack_id, "messaging-webchat");
    }

    #[test]
    fn setup_plan_requires_missing_flow_unless_explicitly_allowed() {
        let pack = ProviderPack {
            pack_id: "messaging-webchat".to_string(),
            display_name: None,
            description: None,
            tags: vec![],
            file_name: "messaging-webchat.gtpack".to_string(),
            path: PathBuf::from("/tmp/messaging-webchat.gtpack"),
            entry_flows: vec!["diagnostics".to_string()],
        };

        let err = plan_runs(
            Domain::Messaging,
            DomainAction::Setup,
            std::slice::from_ref(&pack),
            None,
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("Missing required flow 'setup_default'")
        );

        let plan = plan_runs(Domain::Messaging, DomainAction::Setup, &[pack], None, true)
            .expect("allowed missing setup");
        assert!(plan.is_empty());
    }

    #[test]
    fn build_pack_meta_falls_back_to_flow_and_filename_information() {
        let manifest = PackManifest {
            name: Some("".to_string()),
            description: Some("  ".to_string()),
            meta: None,
            pack_id: None,
            flows: vec![PackFlow {
                id: "setup_default".to_string(),
                entrypoints: vec!["verify_webhooks".to_string()],
                tags: vec!["default".to_string(), "".to_string()],
            }],
        };

        let meta = build_pack_meta(&manifest, Path::new("/tmp/messaging-webchat.gtpack"));
        assert_eq!(meta.pack_id, "messaging-webchat");
        assert_eq!(meta.display_name.as_deref(), Some("messaging-webchat"));
        assert_eq!(meta.entry_flows, vec!["setup_default", "verify_webhooks"]);
        assert_eq!(meta.tags, vec!["default"]);
        assert_eq!(meta.description, None);
    }

    #[test]
    fn manifest_string_type_mismatch_reports_precise_path() {
        let value = CborValue::Map(
            [(
                CborValue::Text("meta".to_string()),
                CborValue::Map(
                    [(
                        CborValue::Text("entry_flows".to_string()),
                        CborValue::Array(vec![CborValue::Bool(true)]),
                    )]
                    .into_iter()
                    .collect(),
                ),
            )]
            .into_iter()
            .collect(),
        );

        assert_eq!(
            find_manifest_string_type_mismatch(&value).as_deref(),
            Some("meta.entry_flows[0]")
        );
    }

    fn write_test_gtpack(path: &Path, pack_id: &str, entry_flows: &[&str]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        let file = fs::File::create(path).expect("create gtpack");
        let mut zip = ZipWriter::new(file);
        let manifest = serde_cbor::to_vec(&CborValue::Map(
            [
                (
                    CborValue::Text("name".to_string()),
                    CborValue::Text(pack_id.to_string()),
                ),
                (
                    CborValue::Text("description".to_string()),
                    CborValue::Text("fixture description".to_string()),
                ),
                (
                    CborValue::Text("pack_id".to_string()),
                    CborValue::Text(pack_id.to_string()),
                ),
                (
                    CborValue::Text("flows".to_string()),
                    CborValue::Array(vec![CborValue::Map(
                        [
                            (
                                CborValue::Text("id".to_string()),
                                CborValue::Text(entry_flows[0].to_string()),
                            ),
                            (
                                CborValue::Text("entrypoints".to_string()),
                                CborValue::Array(
                                    entry_flows
                                        .iter()
                                        .map(|value| CborValue::Text((*value).to_string()))
                                        .collect(),
                                ),
                            ),
                            (
                                CborValue::Text("tags".to_string()),
                                CborValue::Array(vec![CborValue::Text("default".to_string())]),
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    )]),
                ),
            ]
            .into_iter()
            .collect(),
        ))
        .expect("manifest");
        zip.start_file("manifest.cbor", FileOptions::<()>::default())
            .expect("start manifest");
        zip.write_all(&manifest).expect("write manifest");
        zip.finish().expect("finish");
    }
}
