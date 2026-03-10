#![allow(dead_code)]

use std::fs::File;

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use chrono::Utc;
use greentic_types::cbor::canonical;
use greentic_types::decode_pack_manifest;
use greentic_types::schemas::common::schema_ir::SchemaIr;
use greentic_types::schemas::component::v0_6_0::ComponentDescribe;
use greentic_types::schemas::component::v0_6_0::{
    ComponentOperation, ComponentRunInput, ComponentRunOutput,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use zip::ZipArchive;

use crate::runtime_state::atomic_write;

const ABI_VERSION: &str = "greentic:component@0.6.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigEnvelope {
    pub config: JsonValue,
    pub component_id: String,
    pub abi_version: String,
    pub resolved_digest: String,
    pub describe_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_hash: Option<String>,
    pub operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCacheEntry {
    pub component_id: String,
    pub abi_version: String,
    pub resolved_digest: String,
    pub describe_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_schema: Option<JsonValue>,
}

struct PackProvenance {
    component_id: String,
    resolved_digest: String,
    describe_hash: String,
    schema_hash: Option<String>,
    config_schema: Option<JsonValue>,
}

pub fn write_provider_config_envelope(
    providers_root: &Path,
    provider_id: &str,
    operation_id: &str,
    config: &JsonValue,
    pack_path: &Path,
    backup: bool,
) -> anyhow::Result<PathBuf> {
    let provenance = read_pack_provenance(pack_path, provider_id)?;
    let _ = write_contract_cache_entry(providers_root, &provenance);
    let envelope = ConfigEnvelope {
        config: config.clone(),
        component_id: provenance.component_id,
        abi_version: ABI_VERSION.to_string(),
        resolved_digest: provenance.resolved_digest,
        describe_hash: provenance.describe_hash,
        schema_hash: provenance.schema_hash,
        operation_id: operation_id.to_string(),
        // Useful for audit/debug; exclude from deterministic comparisons.
        updated_at: Some(Utc::now().to_rfc3339()),
    };
    let bytes = canonical::to_canonical_cbor(&envelope).map_err(|err| anyhow!("{err}"))?;
    let path = providers_root
        .join(provider_id)
        .join("config.envelope.cbor");
    if backup && path.exists() {
        let backup_path = path.with_extension("cbor.bak");
        if let Some(parent) = backup_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&path, &backup_path)?;
    }
    atomic_write(&path, &bytes)?;
    Ok(path)
}

pub fn read_provider_config_envelope(
    providers_root: &Path,
    provider_id: &str,
) -> anyhow::Result<Option<ConfigEnvelope>> {
    let path = providers_root
        .join(provider_id)
        .join("config.envelope.cbor");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)?;
    let envelope: ConfigEnvelope = serde_cbor::from_slice(&bytes)?;
    Ok(Some(envelope))
}

pub fn resolved_describe_hash(
    pack_path: &Path,
    fallback_component_id: &str,
) -> anyhow::Result<String> {
    Ok(read_pack_provenance(pack_path, fallback_component_id)?.describe_hash)
}

pub fn ensure_contract_compatible(
    providers_root: &Path,
    provider_id: &str,
    flow_id: &str,
    pack_path: &Path,
    allow_contract_change: bool,
) -> anyhow::Result<()> {
    let Some(stored) = read_provider_config_envelope(providers_root, provider_id)? else {
        return Ok(());
    };
    let resolved = resolved_describe_hash(pack_path, provider_id)?;
    if stored.describe_hash != resolved && !allow_contract_change {
        return Err(anyhow!(
            "OP_CONTRACT_DRIFT: provider={} flow={} stored_describe_hash={} resolved_describe_hash={} (pass --allow-contract-change to override)",
            provider_id,
            flow_id,
            stored.describe_hash,
            resolved
        ));
    }
    Ok(())
}

fn write_contract_cache_entry(
    providers_root: &Path,
    provenance: &PackProvenance,
) -> anyhow::Result<PathBuf> {
    let cache_dir = providers_root.join("_contracts");
    let path = cache_dir.join(format!("{}.contract.cbor", provenance.resolved_digest));
    let entry = ContractCacheEntry {
        component_id: provenance.component_id.clone(),
        abi_version: ABI_VERSION.to_string(),
        resolved_digest: provenance.resolved_digest.clone(),
        describe_hash: provenance.describe_hash.clone(),
        schema_hash: provenance.schema_hash.clone(),
        config_schema: provenance.config_schema.clone(),
    };
    let bytes = canonical::to_canonical_cbor(&entry).map_err(|err| anyhow!("{err}"))?;
    atomic_write(&path, &bytes)?;
    Ok(path)
}

fn read_pack_provenance(
    pack_path: &Path,
    fallback_component_id: &str,
) -> anyhow::Result<PackProvenance> {
    let pack_bytes = std::fs::read(pack_path).unwrap_or_default();
    let resolved_digest = digest_hex(&pack_bytes);
    let manifest_bytes = read_manifest_cbor_bytes(pack_path).ok();
    let manifest = manifest_bytes
        .as_ref()
        .and_then(|bytes| decode_pack_manifest(bytes).ok());

    let Some(manifest) = manifest else {
        return Ok(PackProvenance {
            component_id: fallback_component_id.to_string(),
            resolved_digest,
            describe_hash: digest_hex(fallback_component_id.as_bytes()),
            schema_hash: None,
            config_schema: None,
        });
    };

    let component = manifest.components.first();
    let component_id = component
        .map(|value| value.id.to_string())
        .unwrap_or_else(|| fallback_component_id.to_string());

    let describe = ComponentDescribe {
        info: greentic_types::schemas::component::v0_6_0::ComponentInfo {
            id: component_id.clone(),
            version: component
                .map(|value| value.version.to_string())
                .unwrap_or_else(|| "0.0.0".to_string()),
            role: "provider".to_string(),
            display_name: None,
        },
        provided_capabilities: Vec::new(),
        required_capabilities: Vec::new(),
        metadata: Default::default(),
        operations: component
            .map(|value| {
                value
                    .operations
                    .iter()
                    .map(|op| ComponentOperation {
                        id: op.name.clone(),
                        display_name: None,
                        input: ComponentRunInput {
                            schema: SchemaIr::Null,
                        },
                        output: ComponentRunOutput {
                            schema: SchemaIr::Null,
                        },
                        defaults: Default::default(),
                        redactions: Vec::new(),
                        constraints: Default::default(),
                        schema_hash: digest_hex(op.name.as_bytes()),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        config_schema: SchemaIr::Null,
    };
    let describe_hash = hash_canonical(&describe)?;

    let schema_hash = component
        .map(|value| {
            let schema_payload = json!({
                "input": JsonValue::Null,
                "output": JsonValue::Null,
                "config": value.config_schema.clone().unwrap_or(JsonValue::Null),
            });
            hash_canonical(&schema_payload)
        })
        .transpose()?;

    Ok(PackProvenance {
        component_id,
        resolved_digest,
        describe_hash,
        schema_hash,
        config_schema: component.and_then(|value| value.config_schema.clone()),
    })
}

fn hash_canonical<T: Serialize>(value: &T) -> anyhow::Result<String> {
    let cbor = canonical::to_canonical_cbor(value).map_err(|err| anyhow!("{err}"))?;
    Ok(digest_hex(&cbor))
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = canonical::blake3_128(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '0',
    }
}

fn read_manifest_cbor_bytes(pack_path: &Path) -> anyhow::Result<Vec<u8>> {
    let file = File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest = archive
        .by_name("manifest.cbor")
        .with_context(|| format!("manifest.cbor missing in {}", pack_path.display()))?;
    let mut bytes = Vec::new();
    manifest.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::write::FileOptions;

    #[test]
    fn writes_cbor_envelope() {
        let temp = tempdir().unwrap();
        let pack = temp.path().join("provider.gtpack");
        write_test_pack(&pack).unwrap();

        let providers_root = temp
            .path()
            .join("state")
            .join("runtime")
            .join("demo")
            .join("providers");
        let path = write_provider_config_envelope(
            &providers_root,
            "messaging-telegram",
            "setup_default",
            &json!({"token":"abc"}),
            &pack,
            false,
        )
        .unwrap();

        assert!(path.ends_with("messaging-telegram/config.envelope.cbor"));
        let bytes = std::fs::read(path).unwrap();
        let decoded: ConfigEnvelope = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(decoded.component_id, "messaging-telegram");
        assert_eq!(decoded.operation_id, "setup_default");
        assert_eq!(decoded.abi_version, ABI_VERSION);
        assert!(decoded.updated_at.is_some());
        assert_eq!(decoded.config, json!({"token":"abc"}));
        assert!(!decoded.describe_hash.is_empty());
        assert!(!decoded.resolved_digest.is_empty());
        let contracts = providers_root.join("_contracts");
        assert!(contracts.exists());
    }

    #[test]
    fn reports_contract_drift_without_override() {
        let temp = tempdir().unwrap();
        let pack = temp.path().join("provider.gtpack");
        write_test_pack(&pack).unwrap();
        let providers_root = temp
            .path()
            .join("state")
            .join("runtime")
            .join("demo")
            .join("providers");
        let provider_id = "messaging-telegram";
        let provider_dir = providers_root.join(provider_id);
        std::fs::create_dir_all(&provider_dir).unwrap();
        let envelope = ConfigEnvelope {
            config: json!({"token":"abc"}),
            component_id: provider_id.to_string(),
            abi_version: ABI_VERSION.to_string(),
            resolved_digest: "digest".to_string(),
            describe_hash: "different".to_string(),
            schema_hash: None,
            operation_id: "setup_default".to_string(),
            updated_at: None,
        };
        let bytes = canonical::to_canonical_cbor(&envelope).unwrap();
        std::fs::write(provider_dir.join("config.envelope.cbor"), bytes).unwrap();

        let err =
            ensure_contract_compatible(&providers_root, provider_id, "setup_default", &pack, false)
                .unwrap_err();
        assert!(err.to_string().contains("OP_CONTRACT_DRIFT"));
    }

    fn write_test_pack(path: &Path) -> anyhow::Result<()> {
        let file = File::create(path)?;
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())?;
        let manifest = json!({
            "schema_version": "1.0.0",
            "pack_id": "messaging-telegram",
            "name": "messaging-telegram",
            "version": "1.0.0",
            "kind": "provider",
            "publisher": "tests",
            "components": [{
                "id": "messaging-telegram",
                "version": "1.0.0",
                "supports": ["provider"],
                "world": "greentic:component/component-v0-v6-v0@0.6.0",
                "profiles": {},
                "capabilities": { "provides": ["messaging"], "requires": [] },
                "configurators": null,
                "operations": [],
                "config_schema": {"type":"object"},
                "resources": {},
                "dev_flows": {}
            }],
            "flows": [],
            "dependencies": [],
            "capabilities": [],
            "secret_requirements": [],
            "signatures": [],
            "extensions": {}
        });
        let bytes = greentic_types::cbor::canonical::to_canonical_cbor(&manifest)
            .map_err(|err| anyhow!("{err}"))?;
        zip.write_all(&bytes)?;
        zip.finish()?;
        Ok(())
    }
}
