use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
};

use anyhow::{Result, anyhow};
use greentic_types::{ExtensionInline, decode_pack_manifest};
use serde::Deserialize;
use serde_cbor::value::Value as CborValue;
use zip::{ZipArchive, result::ZipError};

type CborMap = BTreeMap<CborValue, CborValue>;
const EXT_GENERATED_SECRETS_V1: &str = "greentic.generated-secrets.v1";

/// Derive the set of secret-marked answer keys for a pack using the SAME
/// source the B12a producer (greentic-setup) redacts from: `pack_to_form_spec`
/// unions `setup.yaml` / `qa/*.json` questions flagged `secret: true` AND
/// `assets/secret-requirements.json` entries (required and optional). Keys are
/// canonicalized via `canonical_secret_name` so reader-side lookups line up
/// with the producer's redaction and the dev-store URIs.
///
/// `load_secret_keys_from_pack` (below) is intentionally NOT used for B12a
/// reader paths: it reads only the requirements asset, filtered to
/// required-only, and lowercases (keeping `-`/`.`). That set is narrower than
/// and normalized differently from the producer's, so a form-declared-only or
/// optional secret would be stripped from disk yet never re-fetched. This
/// helper closes that gap by reusing the producer's exact derivation.
pub fn secret_answer_keys_for_pack(pack_path: &Path, provider_id: &str) -> BTreeSet<String> {
    let Some(form) = greentic_setup::setup_to_formspec::pack_to_form_spec(pack_path, provider_id)
    else {
        return BTreeSet::new();
    };
    form.questions
        .iter()
        .filter(|q| q.secret)
        .map(|q| greentic_setup::secret_name::canonical_secret_name(&q.id))
        .collect()
}

/// True if `answer_key` is a secret per `secret_keys` (canonical set from
/// [`secret_answer_keys_for_pack`]). Mirrors the producer's
/// `is_secret_answer_key` exactly — canonical equality or a forward suffix
/// match (secret key ends with the answer key, e.g. `webex_bot_token`
/// satisfied by `bot_token`) — so the reader's defense-in-depth skip lines up
/// with what the producer redacts and the dev store seeds.
pub fn answer_key_is_secret(answer_key: &str, secret_keys: &BTreeSet<String>) -> bool {
    let norm = greentic_setup::secret_name::canonical_secret_name(answer_key);
    secret_keys
        .iter()
        .any(|secret| secret == &norm || secret.ends_with(&norm))
}

pub fn load_secret_keys_from_pack(pack_path: &Path) -> Result<Vec<String>> {
    Ok(load_secret_requirements_from_pack(pack_path)?
        .into_iter()
        .map(|req| req.key.to_lowercase())
        .collect())
}

pub fn load_secret_requirements_from_pack(pack_path: &Path) -> Result<Vec<SecretRequirement>> {
    let mut requirements = load_generated_requirements_from_extensions(pack_path)?;
    let asset_requirements = load_requirements_from_assets(pack_path)?;
    if !asset_requirements.is_empty() {
        merge_requirements(&mut requirements, asset_requirements);
        return Ok(requirements);
    }
    if !requirements.is_empty() {
        return Ok(requirements);
    }
    let requirements = load_requirements_from_manifest(pack_path)?;
    if !requirements.is_empty() {
        return Ok(requirements);
    }
    load_requirements_from_component_manifests(pack_path)
}

fn merge_requirements(
    requirements: &mut Vec<SecretRequirement>,
    additional: Vec<SecretRequirement>,
) {
    for mut next in additional {
        if let Some(existing) = requirements
            .iter_mut()
            .find(|requirement| requirement.key == next.key)
        {
            if existing.aliases.is_empty() {
                existing.aliases = next.aliases;
            }
            if existing.generated.is_none() {
                existing.generated = next.generated.take();
            }
        } else {
            requirements.push(next);
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SecretRequirement {
    pub key: String,
    pub aliases: Vec<String>,
    pub generated: Option<GeneratedSecretRequirement>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GeneratedSecretRequirement {
    pub policy: String,
    pub length: usize,
    pub encoding: String,
    pub scope: GeneratedSecretScope,
    pub regenerate_if_present: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GeneratedSecretScope {
    pub level: String,
    pub team: Option<String>,
}

#[allow(dead_code)]
pub fn load_secret_keys_from_pack_legacy(pack_path: &Path) -> Result<Vec<String>> {
    let keys = load_keys_from_assets(pack_path)?;
    if !keys.is_empty() {
        return Ok(keys);
    }
    let keys = load_keys_from_manifest(pack_path)?;
    if !keys.is_empty() {
        return Ok(keys);
    }
    load_keys_from_component_manifests(pack_path)
}

fn load_generated_requirements_from_extensions(pack_path: &Path) -> Result<Vec<SecretRequirement>> {
    if let Some(requirements) = load_generated_requirements_from_manifest_cbor(pack_path)? {
        return Ok(requirements);
    }
    load_generated_requirements_from_manifest_json(pack_path)
}

fn load_generated_requirements_from_manifest_cbor(
    pack_path: &Path,
) -> Result<Option<Vec<SecretRequirement>>> {
    let file = File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest = match archive.by_name("manifest.cbor") {
        Ok(file) => file,
        Err(ZipError::FileNotFound) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut bytes = Vec::new();
    manifest.read_to_end(&mut bytes)?;
    let manifest = match decode_pack_manifest(&bytes) {
        Ok(manifest) => manifest,
        Err(_) => return Ok(None),
    };
    let Some(extension) = manifest
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get(EXT_GENERATED_SECRETS_V1))
    else {
        return Ok(None);
    };
    let Some(ExtensionInline::Other(value)) = extension.inline.as_ref() else {
        return Ok(Some(Vec::new()));
    };
    parse_generated_secrets_extension(value.clone()).map(Some)
}

fn load_generated_requirements_from_manifest_json(
    pack_path: &Path,
) -> Result<Vec<SecretRequirement>> {
    let file = File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest = match archive.by_name("pack.manifest.json") {
        Ok(file) => file,
        Err(ZipError::FileNotFound) => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut contents = String::new();
    manifest.read_to_string(&mut contents)?;
    let manifest: serde_json::Value = serde_json::from_str(&contents)?;
    let Some(value) = manifest
        .get("extensions")
        .and_then(|extensions| extensions.get(EXT_GENERATED_SECRETS_V1))
        .and_then(|extension| extension.get("inline"))
    else {
        return Ok(Vec::new());
    };
    parse_generated_secrets_extension(value.clone())
}

fn parse_generated_secrets_extension(value: serde_json::Value) -> Result<Vec<SecretRequirement>> {
    let extension: GeneratedSecretsExtension = serde_json::from_value(value)?;
    Ok(extension
        .secrets
        .into_iter()
        .filter(|secret| secret.required.unwrap_or(true))
        .map(|secret| SecretRequirement {
            key: secret.key.to_lowercase(),
            aliases: secret.aliases,
            generated: Some(GeneratedSecretRequirement {
                policy: secret.policy.unwrap_or_else(|| "random".to_string()),
                length: secret.length.unwrap_or(20),
                encoding: secret.encoding.unwrap_or_else(|| "raw_text".to_string()),
                scope: GeneratedSecretScope {
                    level: secret
                        .scope
                        .as_ref()
                        .and_then(|scope| scope.level.clone())
                        .unwrap_or_else(|| "tenant".to_string()),
                    team: secret.scope.and_then(|scope| scope.team),
                },
                regenerate_if_present: secret.regenerate_if_present.unwrap_or(false),
            }),
        })
        .collect())
}

fn load_requirements_from_assets(pack_path: &Path) -> Result<Vec<SecretRequirement>> {
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
                .filter_map(asset_requirement_to_requirement)
                .collect());
        }
    }
    Ok(Vec::new())
}

fn asset_requirement_to_requirement(req: AssetSecretRequirement) -> Option<SecretRequirement> {
    let key = req.key.or(req.name)?;
    Some(SecretRequirement {
        key: key.to_lowercase(),
        aliases: req.aliases,
        generated: req.generated.map(|generated| GeneratedSecretRequirement {
            policy: generated.policy.unwrap_or_else(|| "random".to_string()),
            length: generated.length.unwrap_or(32),
            encoding: generated
                .encoding
                .unwrap_or_else(|| "base64url".to_string()),
            scope: GeneratedSecretScope {
                level: generated
                    .scope
                    .as_ref()
                    .and_then(|scope| scope.level.clone())
                    .unwrap_or_else(|| "team".to_string()),
                team: generated.scope.and_then(|scope| scope.team),
            },
            regenerate_if_present: generated.regenerate_if_present.unwrap_or(false),
        }),
    })
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

fn load_requirements_from_manifest(pack_path: &Path) -> Result<Vec<SecretRequirement>> {
    let keys = load_keys_from_manifest(pack_path)?;
    Ok(keys
        .into_iter()
        .map(|key| SecretRequirement {
            key,
            aliases: Vec::new(),
            generated: None,
        })
        .collect())
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

fn load_requirements_from_component_manifests(pack_path: &Path) -> Result<Vec<SecretRequirement>> {
    let keys = load_keys_from_component_manifests(pack_path)?;
    Ok(keys
        .into_iter()
        .map(|key| SecretRequirement {
            key,
            aliases: Vec::new(),
            generated: None,
        })
        .collect())
}

fn load_keys_from_component_manifests(pack_path: &Path) -> Result<Vec<String>> {
    let file = File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut keys = BTreeSet::new();

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name().to_string();
        if !name.ends_with("component.manifest.json") {
            continue;
        }

        let mut contents = String::new();
        entry.read_to_string(&mut contents)?;
        let manifest: ComponentManifest = serde_json::from_str(&contents)?;
        for requirement in manifest.secret_requirements {
            if requirement.required.unwrap_or(true)
                && let Some(key) = requirement.key
            {
                keys.insert(key.to_lowercase());
            }
        }
    }

    Ok(keys.into_iter().collect())
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
    name: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    required: Option<bool>,
    #[serde(default)]
    generated: Option<AssetGeneratedSecret>,
}

#[derive(Deserialize)]
struct AssetGeneratedSecret {
    policy: Option<String>,
    length: Option<usize>,
    encoding: Option<String>,
    scope: Option<AssetGeneratedSecretScope>,
    #[serde(default)]
    regenerate_if_present: Option<bool>,
}

#[derive(Deserialize)]
struct AssetGeneratedSecretScope {
    level: Option<String>,
    team: Option<String>,
}

#[derive(Deserialize)]
struct GeneratedSecretsExtension {
    #[serde(default)]
    secrets: Vec<GeneratedSecretEntry>,
}

#[derive(Deserialize)]
struct GeneratedSecretEntry {
    key: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    required: Option<bool>,
    policy: Option<String>,
    length: Option<usize>,
    encoding: Option<String>,
    scope: Option<AssetGeneratedSecretScope>,
    #[serde(default)]
    regenerate_if_present: Option<bool>,
}

#[derive(Deserialize)]
struct ComponentManifest {
    #[serde(default)]
    secret_requirements: Vec<AssetSecretRequirement>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use greentic_types::{
        ExtensionInline, ExtensionRef, PackId, PackKind, PackManifest, PackSignatures,
        encode_pack_manifest,
    };
    use semver::Version;
    use serde_json::json;
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
    fn load_secret_requirements_reads_generated_metadata_from_assets() {
        let dir = tempdir().expect("tempdir");
        let pack = dir.path().join("pack.gtpack");
        write_pack(
            &pack,
            &[(
                "assets/secret-requirements.json",
                serde_json::to_vec(&serde_json::json!([
                    {
                        "key": "jwt_signing_key",
                        "required": true,
                        "generated": {
                            "policy": "random",
                            "length": 20,
                            "encoding": "raw_text",
                            "scope": {
                                "level": "tenant",
                                "team": "_"
                            },
                            "regenerate_if_present": false
                        }
                    }
                ]))
                .expect("asset json"),
            )],
        );

        let requirements = load_secret_requirements_from_pack(&pack).expect("requirements");
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].key, "jwt_signing_key");
        let generated = requirements[0].generated.as_ref().expect("generated");
        assert_eq!(generated.policy, "random");
        assert_eq!(generated.length, 20);
        assert_eq!(generated.encoding, "raw_text");
        assert_eq!(generated.scope.level, "tenant");
        assert_eq!(generated.scope.team.as_deref(), Some("_"));
        assert!(!generated.regenerate_if_present);
    }

    #[test]
    fn load_secret_requirements_reads_generated_metadata_from_cbor_extension() {
        let dir = tempdir().expect("tempdir");
        let pack = dir.path().join("pack.gtpack");
        let mut extensions = BTreeMap::new();
        extensions.insert(
            EXT_GENERATED_SECRETS_V1.to_string(),
            ExtensionRef {
                kind: EXT_GENERATED_SECRETS_V1.to_string(),
                version: "1".to_string(),
                digest: None,
                location: None,
                inline: Some(ExtensionInline::Other(json!({
                    "secrets": [{
                        "key": "slack_signing_secret",
                        "aliases": ["SLACK_SIGNING_SECRET"],
                        "required": true,
                        "policy": "random",
                        "length": 20,
                        "encoding": "raw_text",
                        "scope": {
                            "level": "tenant",
                            "team": "_"
                        },
                        "regenerate_if_present": false
                    }]
                }))),
            },
        );
        let manifest = PackManifest {
            schema_version: "1".to_string(),
            pack_id: PackId::new("messaging-slack").expect("pack id"),
            name: None,
            version: Version::parse("0.0.0").expect("version"),
            kind: PackKind::Provider,
            publisher: "test".to_string(),
            components: Vec::new(),
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            secret_requirements: Vec::new(),
            signatures: PackSignatures::default(),
            bootstrap: None,
            extensions: Some(extensions),
        };
        write_pack(
            &pack,
            &[(
                "manifest.cbor",
                encode_pack_manifest(&manifest).expect("manifest cbor"),
            )],
        );

        let requirements = load_secret_requirements_from_pack(&pack).expect("requirements");
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].key, "slack_signing_secret");
        assert_eq!(requirements[0].aliases, vec!["SLACK_SIGNING_SECRET"]);
        let generated = requirements[0].generated.as_ref().expect("generated");
        assert_eq!(generated.length, 20);
        assert_eq!(generated.scope.level, "tenant");
        assert_eq!(generated.scope.team.as_deref(), Some("_"));
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
    fn load_secret_keys_falls_back_to_component_manifests() {
        let dir = tempdir().expect("tempdir");
        let pack = dir.path().join("pack.gtpack");
        write_pack(
            &pack,
            &[
                (
                    "assets/secret-requirements.json",
                    serde_json::to_vec(&serde_json::json!([])).expect("asset json"),
                ),
                (
                    "components/provider/component.manifest.json",
                    serde_json::to_vec(&serde_json::json!({
                        "secret_requirements": [
                            {"key": "JWT_SIGNING_KEY", "required": true},
                            {"key": "OPTIONAL_TOKEN", "required": false}
                        ]
                    }))
                    .expect("component json"),
                ),
            ],
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
