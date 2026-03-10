use std::{collections::BTreeMap, fs::File, io::Read, path::Path};

use anyhow::{Result, anyhow};
use serde::Deserialize;
use serde_cbor::value::Value as CborValue;
use serde_json;
use zip::{ZipArchive, result::ZipError};

type CborMap = BTreeMap<CborValue, CborValue>;

pub fn load_secret_keys_from_pack(pack_path: &Path) -> Result<Vec<String>> {
    let keys = load_keys_from_assets(pack_path)?;
    if !keys.is_empty() {
        return Ok(keys);
    }
    load_keys_from_manifest(pack_path)
}

fn load_keys_from_assets(pack_path: &Path) -> Result<Vec<String>> {
    let file = File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    const ASSET_PATHS: &[&str] = &[
        "assets/secret-requirements.json",
        "assets/secret_requirements.json",
        "secret-requirements.json",
        "secret_requirements.json",
    ];
    for asset in ASSET_PATHS {
        if let Ok(mut entry) = archive.by_name(asset) {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            let requirements: Vec<AssetSecretRequirement> = serde_json::from_str(&contents)?;
            return Ok(requirements
                .into_iter()
                .filter(|req| req.required.unwrap_or(true))
                .filter_map(|req| req.key)
                .map(|key| key.to_lowercase())
                .collect());
        }
    }
    Ok(Vec::new())
}

fn load_keys_from_manifest(pack_path: &Path) -> Result<Vec<String>> {
    let file = File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest = match archive.by_name("manifest.cbor") {
        Ok(file) => file,
        Err(ZipError::FileNotFound) => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut bytes = Vec::new();
    manifest.read_to_end(&mut bytes)?;
    let value: CborValue = serde_cbor::from_slice(&bytes)?;
    if let CborValue::Map(map) = &value {
        return extract_keys_from_manifest_map(map);
    }
    Ok(Vec::new())
}

fn extract_keys_from_manifest_map(map: &CborMap) -> Result<Vec<String>> {
    let symbols = symbols_map(map);
    let mut keys = Vec::new();
    if let Some(CborValue::Array(entries)) = map_get(map, "secret_requirements") {
        for entry in entries {
            if let CborValue::Map(entry_map) = entry {
                if !is_required(entry_map) {
                    continue;
                }
                if let Some(key_value) = map_get(entry_map, "key")
                    && let Some(key) =
                        resolve_string_symbol(Some(key_value), symbols, "secret_requirements")?
                {
                    keys.push(key.to_lowercase());
                }
            }
        }
    }
    Ok(keys)
}

fn is_required(entry: &CborMap) -> bool {
    match map_get(entry, "required") {
        Some(CborValue::Bool(value)) => *value,
        _ => true,
    }
}

fn map_get<'a>(map: &'a CborMap, key: &str) -> Option<&'a CborValue> {
    map.iter().find_map(|(k, v)| match k {
        CborValue::Text(text) if text == key => Some(v),
        _ => None,
    })
}

fn symbols_map(map: &CborMap) -> Option<&CborMap> {
    let symbols = map_get(map, "symbols")?;
    match symbols {
        CborValue::Map(map) => Some(map),
        _ => None,
    }
}

fn resolve_string_symbol(
    value: Option<&CborValue>,
    symbols: Option<&CborMap>,
    symbol_key: &str,
) -> Result<Option<String>> {
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
        _ => Err(anyhow!("expected string or symbol index")),
    }
}

fn symbol_array<'a>(symbols: &'a CborMap, key: &'a str) -> Option<&'a Vec<CborValue>> {
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

#[derive(Deserialize)]
struct AssetSecretRequirement {
    key: Option<String>,
    #[serde(default)]
    required: Option<bool>,
}
