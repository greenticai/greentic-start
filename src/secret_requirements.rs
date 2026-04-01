use std::{collections::BTreeMap, fs::File, io::Read, path::Path};

use anyhow::{Result, anyhow};
use serde::Deserialize;
use serde_cbor::value::Value as CborValue;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use tempfile::tempdir;
    use zip::write::FileOptions;

    fn write_pack(path: &Path, entries: &[(&str, Vec<u8>)]) {
        let file = File::create(path).expect("create pack");
        let mut zip = zip::ZipWriter::new(file);
        for (name, bytes) in entries {
            zip.start_file(*name, FileOptions::<()>::default())
                .expect("start file");
            zip.write_all(bytes).expect("write file");
        }
        zip.finish().expect("finish pack");
    }

    #[test]
    fn load_secret_keys_prefers_asset_file_and_filters_optional_entries() {
        let dir = tempdir().expect("tempdir");
        let pack = dir.path().join("pack.gtpack");
        write_pack(
            &pack,
            &[(
                "assets/secret-requirements.json",
                serde_json::to_vec(&serde_json::json!([
                    {"key": "API_TOKEN", "required": true},
                    {"key": "OPTIONAL_TOKEN", "required": false},
                    {"required": true}
                ]))
                .expect("asset json"),
            )],
        );

        assert_eq!(
            load_secret_keys_from_pack(&pack).expect("load keys"),
            vec!["api_token".to_string()]
        );
    }

    #[test]
    fn load_secret_keys_falls_back_to_manifest_symbol_resolution() {
        let dir = tempdir().expect("tempdir");
        let pack = dir.path().join("pack.gtpack");
        let manifest = CborValue::Map(BTreeMap::from([
            (
                CborValue::Text("symbols".to_string()),
                CborValue::Map(BTreeMap::from([(
                    CborValue::Text("secret_requirements".to_string()),
                    CborValue::Array(vec![CborValue::Text("jwt_signing_key".to_string())]),
                )])),
            ),
            (
                CborValue::Text("secret_requirements".to_string()),
                CborValue::Array(vec![
                    CborValue::Map(BTreeMap::from([
                        (CborValue::Text("key".to_string()), CborValue::Integer(0)),
                        (
                            CborValue::Text("required".to_string()),
                            CborValue::Bool(true),
                        ),
                    ])),
                    CborValue::Map(BTreeMap::from([
                        (
                            CborValue::Text("key".to_string()),
                            CborValue::Text("ignored".to_string()),
                        ),
                        (
                            CborValue::Text("required".to_string()),
                            CborValue::Bool(false),
                        ),
                    ])),
                ]),
            ),
        ]));
        write_pack(
            &pack,
            &[(
                "manifest.cbor",
                serde_cbor::to_vec(&manifest).expect("manifest cbor"),
            )],
        );

        assert_eq!(
            load_secret_keys_from_pack(&pack).expect("load keys"),
            vec!["jwt_signing_key".to_string()]
        );
    }

    #[test]
    fn resolve_string_symbol_handles_text_indices_and_invalid_types() {
        let symbols = BTreeMap::from([(
            CborValue::Text("secret_requirement".to_string()),
            CborValue::Array(vec![CborValue::Text("token".to_string())]),
        )]);

        assert_eq!(
            resolve_string_symbol(
                Some(&CborValue::Text("direct".to_string())),
                Some(&symbols),
                "secret_requirements",
            )
            .expect("text"),
            Some("direct".to_string())
        );
        assert_eq!(
            resolve_string_symbol(
                Some(&CborValue::Integer(0)),
                Some(&symbols),
                "secret_requirements",
            )
            .expect("symbol"),
            Some("token".to_string())
        );
        assert_eq!(
            resolve_string_symbol(Some(&CborValue::Integer(3)), None, "secret_requirements")
                .expect("fallback index"),
            Some("3".to_string())
        );
        assert!(
            resolve_string_symbol(
                Some(&CborValue::Bool(true)),
                Some(&symbols),
                "secret_requirements",
            )
            .is_err()
        );
    }
}
