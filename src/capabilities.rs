#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use greentic_types::{ExtensionInline, decode_pack_manifest};
use serde::Deserialize;
use zip::ZipArchive;

use crate::domains::Domain;

pub const EXT_CAPABILITIES_V1: &str = "greentic.ext.capabilities.v1";
pub const CAP_OP_HOOK_PRE: &str = "greentic.cap.op_hook.pre";
pub const CAP_OP_HOOK_POST: &str = "greentic.cap.op_hook.post";
pub const CAP_OAUTH_BROKER_V1: &str = "greentic.cap.oauth.broker.v1";
pub const CAP_OAUTH_CARD_V1: &str = "greentic.cap.oauth.card.v1";
pub const CAP_OAUTH_TOKEN_VALIDATION_V1: &str = "greentic.cap.oauth.token_validation.v1";
pub const OAUTH_OP_INITIATE_AUTH: &str = "oauth.initiate_auth";
pub const OAUTH_OP_AWAIT_RESULT: &str = "oauth.await_result";
pub const OAUTH_OP_GET_ACCESS_TOKEN: &str = "oauth.get_access_token";
pub const OAUTH_OP_REQUEST_RESOURCE_TOKEN: &str = "oauth.request_resource_token";

/// Bundle-level capability: packs can request read-only access to bundle `./assets/`.
pub const CAP_BUNDLE_ASSETS_READ_V1: &str = "greentic.cap.bundle_assets.read.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookStage {
    Pre,
    Post,
}

impl HookStage {
    fn cap_id(&self) -> &'static str {
        match self {
            HookStage::Pre => CAP_OP_HOOK_PRE,
            HookStage::Post => CAP_OP_HOOK_POST,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolveScope {
    pub env: Option<String>,
    pub tenant: Option<String>,
    pub team: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityPackRecord {
    pub pack_id: String,
    pub domain: Domain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityBinding {
    pub cap_id: String,
    pub stable_id: String,
    pub pack_id: String,
    pub domain: Domain,
    pub pack_path: PathBuf,
    pub provider_component_ref: String,
    pub provider_op: String,
    pub version: String,
    pub requires_setup: bool,
    pub setup_qa_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityOfferRecord {
    pub stable_id: String,
    pub pack_id: String,
    pub domain: Domain,
    pub pack_path: PathBuf,
    pub cap_id: String,
    pub version: String,
    pub provider_component_ref: String,
    pub provider_op: String,
    pub priority: i32,
    pub requires_setup: bool,
    pub setup_qa_ref: Option<String>,
    scope: CapabilityScopeV1,
    pub applies_to_ops: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CapabilityRegistry {
    by_cap_id: BTreeMap<String, Vec<CapabilityOfferRecord>>,
}

impl CapabilityRegistry {
    pub fn build_from_pack_index(
        pack_index: &BTreeMap<PathBuf, CapabilityPackRecord>,
    ) -> anyhow::Result<Self> {
        let mut by_cap_id: BTreeMap<String, Vec<CapabilityOfferRecord>> = BTreeMap::new();

        for (pack_path, pack_record) in pack_index {
            let Some(ext) = read_capabilities_extension(pack_path)? else {
                continue;
            };

            for (idx, offer) in ext.offers.into_iter().enumerate() {
                let stable_id = match offer.offer_id {
                    Some(id) if !id.trim().is_empty() => id,
                    _ => format!(
                        "{}::{}::{}::{}::{}",
                        pack_record.pack_id,
                        offer.cap_id,
                        offer.provider.component_ref,
                        offer.provider.op,
                        idx
                    ),
                };
                let applies_to_ops = offer
                    .applies_to
                    .map(|value| value.op_names)
                    .unwrap_or_default();
                let setup_qa_ref = offer.setup.map(|value| value.qa_ref);
                by_cap_id
                    .entry(offer.cap_id.clone())
                    .or_default()
                    .push(CapabilityOfferRecord {
                        stable_id,
                        pack_id: pack_record.pack_id.clone(),
                        domain: pack_record.domain,
                        pack_path: pack_path.clone(),
                        cap_id: offer.cap_id,
                        version: offer.version,
                        provider_component_ref: offer.provider.component_ref,
                        provider_op: offer.provider.op,
                        priority: offer.priority,
                        requires_setup: offer.requires_setup,
                        setup_qa_ref,
                        scope: offer.scope.unwrap_or_default(),
                        applies_to_ops,
                    });
            }
        }

        for offers in by_cap_id.values_mut() {
            offers.sort_by(|a, b| {
                a.priority
                    .cmp(&b.priority)
                    .then_with(|| a.stable_id.cmp(&b.stable_id))
            });
        }

        Ok(Self { by_cap_id })
    }

    pub fn offers_for_capability(&self, cap_id: &str) -> &[CapabilityOfferRecord] {
        self.by_cap_id
            .get(cap_id)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn resolve(
        &self,
        cap_id: &str,
        min_version: Option<&str>,
        scope: &ResolveScope,
    ) -> Option<CapabilityBinding> {
        self.resolve_for_op(cap_id, min_version, scope, None)
    }

    pub fn resolve_for_op(
        &self,
        cap_id: &str,
        min_version: Option<&str>,
        scope: &ResolveScope,
        requested_op: Option<&str>,
    ) -> Option<CapabilityBinding> {
        let offers = self.by_cap_id.get(cap_id)?;
        let selected = offers.iter().find(|offer| {
            version_matches(&offer.version, min_version)
                && scope_matches(&offer.scope, scope)
                && op_matches(offer, requested_op)
        })?;
        Some(CapabilityBinding {
            cap_id: selected.cap_id.clone(),
            stable_id: selected.stable_id.clone(),
            pack_id: selected.pack_id.clone(),
            domain: selected.domain,
            pack_path: selected.pack_path.clone(),
            provider_component_ref: selected.provider_component_ref.clone(),
            provider_op: selected.provider_op.clone(),
            version: selected.version.clone(),
            requires_setup: selected.requires_setup,
            setup_qa_ref: selected.setup_qa_ref.clone(),
        })
    }

    pub fn resolve_hook_chain(&self, stage: HookStage, op_name: &str) -> Vec<CapabilityBinding> {
        self.by_cap_id
            .get(stage.cap_id())
            .map(|offers| {
                offers
                    .iter()
                    .filter(|offer| {
                        offer.applies_to_ops.is_empty()
                            || offer.applies_to_ops.iter().any(|entry| entry == op_name)
                    })
                    .map(|selected| CapabilityBinding {
                        cap_id: selected.cap_id.clone(),
                        stable_id: selected.stable_id.clone(),
                        pack_id: selected.pack_id.clone(),
                        domain: selected.domain,
                        pack_path: selected.pack_path.clone(),
                        provider_component_ref: selected.provider_component_ref.clone(),
                        provider_op: selected.provider_op.clone(),
                        version: selected.version.clone(),
                        requires_setup: selected.requires_setup,
                        setup_qa_ref: selected.setup_qa_ref.clone(),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    pub fn offers_requiring_setup(&self, scope: &ResolveScope) -> Vec<CapabilityOfferRecord> {
        let mut selected = Vec::new();
        for offers in self.by_cap_id.values() {
            for offer in offers {
                if !offer.requires_setup {
                    continue;
                }
                if !scope_matches(&offer.scope, scope) {
                    continue;
                }
                selected.push(offer.clone());
            }
        }
        selected.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.stable_id.cmp(&b.stable_id))
        });
        selected
    }
}

pub fn is_oauth_broker_operation(op_name: &str) -> bool {
    matches!(
        op_name,
        OAUTH_OP_INITIATE_AUTH
            | OAUTH_OP_AWAIT_RESULT
            | OAUTH_OP_GET_ACCESS_TOKEN
            | OAUTH_OP_REQUEST_RESOURCE_TOKEN
    )
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct CapabilityInstallRecord {
    pub cap_id: String,
    pub stable_id: String,
    pub pack_id: String,
    pub status: String,
    pub config_state_keys: Vec<String>,
    pub timestamp_unix_sec: u64,
}

impl CapabilityInstallRecord {
    pub fn ready(cap_id: &str, stable_id: &str, pack_id: &str) -> Self {
        Self {
            cap_id: cap_id.to_string(),
            stable_id: stable_id.to_string(),
            pack_id: pack_id.to_string(),
            status: "ready".to_string(),
            config_state_keys: Vec::new(),
            timestamp_unix_sec: now_unix_sec(),
        }
    }

    pub fn failed(cap_id: &str, stable_id: &str, pack_id: &str, key: &str) -> Self {
        Self {
            cap_id: cap_id.to_string(),
            stable_id: stable_id.to_string(),
            pack_id: pack_id.to_string(),
            status: "failed".to_string(),
            config_state_keys: vec![key.to_string()],
            timestamp_unix_sec: now_unix_sec(),
        }
    }
}

pub fn install_record_path(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
    stable_id: &str,
) -> PathBuf {
    let team = team.unwrap_or("default");
    bundle_root
        .join("state")
        .join("runtime")
        .join(tenant)
        .join(team)
        .join("capabilities")
        .join(format!("{stable_id}.install.json"))
}

pub fn write_install_record(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
    record: &CapabilityInstallRecord,
) -> anyhow::Result<PathBuf> {
    let path = install_record_path(bundle_root, tenant, team, &record.stable_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(record)?;
    std::fs::write(&path, bytes)?;
    Ok(path)
}

pub fn read_install_record(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
    stable_id: &str,
) -> anyhow::Result<Option<CapabilityInstallRecord>> {
    let path = install_record_path(bundle_root, tenant, team, stable_id);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    let record: CapabilityInstallRecord = serde_json::from_slice(&bytes)?;
    Ok(Some(record))
}

pub fn is_binding_ready(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
    binding: &CapabilityBinding,
) -> anyhow::Result<bool> {
    if !binding.requires_setup {
        return Ok(true);
    }
    let Some(record) = read_install_record(bundle_root, tenant, team, &binding.stable_id)? else {
        return Ok(false);
    };
    Ok(record.status.eq_ignore_ascii_case("ready"))
}

fn read_capabilities_extension(path: &Path) -> anyhow::Result<Option<CapabilitiesExtensionV1>> {
    let file = std::fs::File::open(path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest_entry = archive.by_name("manifest.cbor").map_err(|err| {
        anyhow::anyhow!("failed to open manifest.cbor in {}: {err}", path.display())
    })?;
    let mut bytes = Vec::new();
    manifest_entry.read_to_end(&mut bytes)?;
    let manifest = decode_pack_manifest(&bytes)
        .with_context(|| format!("failed to decode pack manifest in {}", path.display()))?;
    let Some(extension) = manifest
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get(EXT_CAPABILITIES_V1))
    else {
        return Ok(None);
    };
    let inline = extension
        .inline
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("capabilities extension inline payload missing"))?;
    let ExtensionInline::Other(value) = inline else {
        anyhow::bail!("capabilities extension inline payload has unexpected type");
    };
    let decoded: CapabilitiesExtensionV1 = serde_json::from_value(value.clone())
        .with_context(|| "failed to parse greentic.ext.capabilities.v1 payload")?;
    if decoded.schema_version != 1 {
        anyhow::bail!(
            "unsupported capabilities extension schema_version={}",
            decoded.schema_version
        );
    }
    Ok(Some(decoded))
}

fn version_matches(version: &str, min_version: Option<&str>) -> bool {
    match min_version {
        None => true,
        Some(requested) => version == requested,
    }
}

fn scope_matches(offer_scope: &CapabilityScopeV1, scope: &ResolveScope) -> bool {
    value_matches(&offer_scope.envs, scope.env.as_deref())
        && value_matches(&offer_scope.tenants, scope.tenant.as_deref())
        && value_matches(&offer_scope.teams, scope.team.as_deref())
}

fn op_matches(offer: &CapabilityOfferRecord, requested_op: Option<&str>) -> bool {
    let Some(requested_op) = requested_op else {
        return true;
    };
    if offer.applies_to_ops.is_empty() {
        return true;
    }
    offer
        .applies_to_ops
        .iter()
        .any(|entry| entry == requested_op)
}

fn value_matches(values: &[String], current: Option<&str>) -> bool {
    if values.is_empty() {
        return true;
    }
    let Some(current) = current else {
        return false;
    };
    values.iter().any(|value| value == current)
}

#[derive(Debug, Deserialize)]
struct CapabilitiesExtensionV1 {
    #[serde(default = "default_schema_version")]
    schema_version: u32,
    #[serde(default)]
    offers: Vec<CapabilityOfferV1>,
}

#[derive(Debug, Deserialize)]
struct CapabilityOfferV1 {
    #[serde(default)]
    offer_id: Option<String>,
    cap_id: String,
    version: String,
    provider: CapabilityProviderRefV1,
    #[serde(default)]
    scope: Option<CapabilityScopeV1>,
    #[serde(default)]
    priority: i32,
    #[serde(default)]
    requires_setup: bool,
    #[serde(default)]
    setup: Option<CapabilitySetupV1>,
    #[serde(default)]
    applies_to: Option<HookAppliesToV1>,
}

#[derive(Debug, Deserialize)]
struct CapabilityProviderRefV1 {
    component_ref: String,
    op: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
struct CapabilityScopeV1 {
    #[serde(default)]
    envs: Vec<String>,
    #[serde(default)]
    tenants: Vec<String>,
    #[serde(default)]
    teams: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CapabilitySetupV1 {
    qa_ref: String,
}

#[derive(Debug, Deserialize)]
struct HookAppliesToV1 {
    #[serde(default)]
    op_names: Vec<String>,
}

const fn default_schema_version() -> u32 {
    1
}

fn now_unix_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_types::{ExtensionRef, PackId, PackKind, PackManifest, PackSignatures};
    use semver::Version;
    use serde_json::json;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;
    use zip::ZipWriter;
    use zip::write::FileOptions;

    #[test]
    fn scope_matching_accepts_unrestricted_scope() {
        let offer_scope = CapabilityScopeV1::default();
        let scope = ResolveScope::default();
        assert!(scope_matches(&offer_scope, &scope));
    }

    #[test]
    fn scope_matching_rejects_missing_restricted_value() {
        let offer_scope = CapabilityScopeV1 {
            envs: vec!["prod".to_string()],
            tenants: Vec::new(),
            teams: Vec::new(),
        };
        let scope = ResolveScope::default();
        assert!(!scope_matches(&offer_scope, &scope));
    }

    #[test]
    fn value_matching_handles_lists() {
        assert!(value_matches(&[], None));
        assert!(value_matches(&["demo".to_string()], Some("demo")));
        assert!(!value_matches(&["demo".to_string()], Some("prod")));
    }

    #[test]
    fn install_record_roundtrip() {
        let tmp = tempdir().expect("tempdir");
        let record =
            CapabilityInstallRecord::ready("greentic.cap.test", "offer.test.01", "pack-test");
        let path = write_install_record(tmp.path(), "tenant-a", Some("team-b"), &record)
            .expect("write install record");
        assert!(path.exists());
        let loaded = read_install_record(tmp.path(), "tenant-a", Some("team-b"), "offer.test.01")
            .expect("read install record")
            .expect("record should exist");
        assert_eq!(loaded.cap_id, record.cap_id);
        assert_eq!(loaded.status, "ready");
    }

    #[test]
    fn setup_required_binding_reports_not_ready_without_record() {
        let tmp = tempdir().expect("tempdir");
        let binding = CapabilityBinding {
            cap_id: "greentic.cap.test".to_string(),
            stable_id: "offer.setup.01".to_string(),
            pack_id: "pack-test".to_string(),
            domain: Domain::Messaging,
            pack_path: tmp.path().join("dummy.gtpack"),
            provider_component_ref: "component".to_string(),
            provider_op: "invoke".to_string(),
            version: "v1".to_string(),
            requires_setup: true,
            setup_qa_ref: Some("qa/setup.cbor".to_string()),
        };
        let ready = is_binding_ready(tmp.path(), "tenant-a", Some("team-b"), &binding)
            .expect("ready check");
        assert!(!ready);
    }

    #[test]
    fn resolve_for_op_prefers_offer_with_matching_applies_to() {
        let mut by_cap_id = BTreeMap::new();
        by_cap_id.insert(
            CAP_OAUTH_BROKER_V1.to_string(),
            vec![
                CapabilityOfferRecord {
                    stable_id: "offer.a".to_string(),
                    pack_id: "pack".to_string(),
                    domain: Domain::Messaging,
                    pack_path: PathBuf::from("/tmp/a.gtpack"),
                    cap_id: CAP_OAUTH_BROKER_V1.to_string(),
                    version: "v1".to_string(),
                    provider_component_ref: "oauth".to_string(),
                    provider_op: "provider.dispatch".to_string(),
                    priority: 0,
                    requires_setup: false,
                    setup_qa_ref: None,
                    scope: CapabilityScopeV1::default(),
                    applies_to_ops: vec![OAUTH_OP_INITIATE_AUTH.to_string()],
                },
                CapabilityOfferRecord {
                    stable_id: "offer.b".to_string(),
                    pack_id: "pack".to_string(),
                    domain: Domain::Messaging,
                    pack_path: PathBuf::from("/tmp/b.gtpack"),
                    cap_id: CAP_OAUTH_BROKER_V1.to_string(),
                    version: "v1".to_string(),
                    provider_component_ref: "oauth".to_string(),
                    provider_op: "provider.await".to_string(),
                    priority: 1,
                    requires_setup: false,
                    setup_qa_ref: None,
                    scope: CapabilityScopeV1::default(),
                    applies_to_ops: vec![OAUTH_OP_AWAIT_RESULT.to_string()],
                },
            ],
        );
        let registry = CapabilityRegistry { by_cap_id };
        let scope = ResolveScope::default();
        let resolved = registry
            .resolve_for_op(
                CAP_OAUTH_BROKER_V1,
                None,
                &scope,
                Some(OAUTH_OP_AWAIT_RESULT),
            )
            .expect("should resolve");
        assert_eq!(resolved.provider_op, "provider.await");
    }

    #[test]
    fn oauth_broker_operation_whitelist_is_enforced() {
        assert!(is_oauth_broker_operation(OAUTH_OP_INITIATE_AUTH));
        assert!(is_oauth_broker_operation(OAUTH_OP_AWAIT_RESULT));
        assert!(is_oauth_broker_operation(OAUTH_OP_GET_ACCESS_TOKEN));
        assert!(is_oauth_broker_operation(OAUTH_OP_REQUEST_RESOURCE_TOKEN));
        assert!(!is_oauth_broker_operation("oauth.unknown"));
    }

    #[test]
    fn oauth_capability_offers_load_into_registry() {
        let tmp = tempdir().expect("tempdir");
        let pack_path = tmp.path().join("oauth-provider.gtpack");
        write_gtpack_with_oauth_capabilities(&pack_path).expect("write pack");

        let mut pack_index = BTreeMap::new();
        pack_index.insert(
            pack_path.clone(),
            CapabilityPackRecord {
                pack_id: "oauth.provider".to_string(),
                domain: Domain::Messaging,
            },
        );
        let registry = CapabilityRegistry::build_from_pack_index(&pack_index).expect("registry");

        assert_eq!(
            registry.offers_for_capability(CAP_OAUTH_BROKER_V1).len(),
            1,
            "oauth broker capability offer missing from registry"
        );
        assert_eq!(
            registry
                .offers_for_capability("greentic.cap.oauth.card.v1")
                .len(),
            1,
            "oauth card capability offer missing from registry"
        );
        assert_eq!(
            registry
                .offers_for_capability("greentic.cap.oauth.token_validation.v1")
                .len(),
            1,
            "oauth token_validation capability offer missing from registry"
        );
        assert_eq!(
            registry
                .offers_for_capability("greentic.cap.oauth.discovery.v1")
                .len(),
            1,
            "oauth discovery capability offer missing from registry"
        );
    }

    fn write_gtpack_with_oauth_capabilities(path: &Path) -> anyhow::Result<()> {
        let mut extensions = BTreeMap::new();
        extensions.insert(
            EXT_CAPABILITIES_V1.to_string(),
            ExtensionRef {
                kind: EXT_CAPABILITIES_V1.to_string(),
                version: "1.0.0".to_string(),
                digest: None,
                location: None,
                inline: Some(greentic_types::ExtensionInline::Other(json!({
                    "schema_version": 1,
                    "offers": [
                        {
                            "offer_id": "oauth.broker.v1",
                            "cap_id": CAP_OAUTH_BROKER_V1,
                            "version": "v1",
                            "provider": {"component_ref": "oauth.component", "op": "oauth.broker.dispatch"},
                            "priority": 10,
                            "requires_setup": true,
                            "setup": {"qa_ref": "qa/oauth_broker.setup.json"}
                        },
                        {
                            "offer_id": "oauth.card.v1",
                            "cap_id": "greentic.cap.oauth.card.v1",
                            "version": "v1",
                            "provider": {"component_ref": "oauth.component", "op": "oauth.card.dispatch"},
                            "priority": 20,
                            "requires_setup": true,
                            "setup": {"qa_ref": "qa/oauth_card.setup.json"}
                        },
                        {
                            "offer_id": "oauth.token_validation.v1",
                            "cap_id": "greentic.cap.oauth.token_validation.v1",
                            "version": "v1",
                            "provider": {"component_ref": "oauth.component", "op": "oauth.token_validation.dispatch"},
                            "priority": 30,
                            "requires_setup": true,
                            "setup": {"qa_ref": "qa/oauth_token_validation.setup.json"}
                        },
                        {
                            "offer_id": "oauth.discovery.v1",
                            "cap_id": "greentic.cap.oauth.discovery.v1",
                            "version": "v1",
                            "provider": {"component_ref": "oauth.component", "op": "oauth.discovery.dispatch"},
                            "priority": 40,
                            "requires_setup": true,
                            "setup": {"qa_ref": "qa/oauth_discovery.setup.json"}
                        }
                    ]
                }))),
            },
        );

        let manifest = PackManifest {
            schema_version: "pack-v1".to_string(),
            pack_id: PackId::new("oauth.provider").expect("pack id"),
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
            extensions: Some(extensions),
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
