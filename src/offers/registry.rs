use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde_json::Value as JsonValue;
use zip::ZipArchive;
use zip::result::ZipError;

pub const HOOK_STAGE_POST_INGRESS: &str = "post_ingress";
pub const HOOK_CONTRACT_CONTROL_V1: &str = "greentic.hook.control.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OfferKind {
    Hook,
    Subs,
    Capability,
}

impl OfferKind {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "hook" => Some(Self::Hook),
            "subs" => Some(Self::Subs),
            "capability" => Some(Self::Capability),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hook => "hook",
            Self::Subs => "subs",
            Self::Capability => "capability",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub offer_key: String,
    pub pack_id: String,
    pub pack_ref: PathBuf,
    pub id: String,
    pub kind: OfferKind,
    pub priority: i32,
    pub provider_op: String,
    pub stage: Option<String>,
    pub contract: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PackOffers {
    pub pack_id: String,
    pub pack_ref: PathBuf,
    pub offers: Vec<PackOffer>,
}

#[derive(Clone, Debug)]
pub struct PackOffer {
    pub id: String,
    pub kind: OfferKind,
    pub priority: i32,
    pub provider_op: String,
    pub stage: Option<String>,
    pub contract: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct OfferRegistry {
    by_key: BTreeMap<String, Offer>,
    pack_refs: BTreeMap<String, PathBuf>,
}

impl OfferRegistry {
    pub fn from_pack_refs(pack_refs: &[PathBuf]) -> anyhow::Result<Self> {
        let mut registry = Self::default();
        for pack_ref in pack_refs {
            let parsed = load_pack_offers(pack_ref)?;
            registry.register_pack(parsed)?;
        }
        Ok(registry)
    }

    pub fn register_pack(&mut self, pack: PackOffers) -> anyhow::Result<()> {
        if let Some(existing_ref) = self.pack_refs.get(&pack.pack_id)
            && existing_ref != &pack.pack_ref
        {
            anyhow::bail!(
                "duplicate pack_id {} across packs: {} and {}",
                pack.pack_id,
                existing_ref.display(),
                pack.pack_ref.display()
            );
        }
        self.pack_refs
            .entry(pack.pack_id.clone())
            .or_insert_with(|| pack.pack_ref.clone());

        for offer in pack.offers {
            let offer_key = offer_key(&pack.pack_id, &offer.id);
            let record = Offer {
                offer_key: offer_key.clone(),
                pack_id: pack.pack_id.clone(),
                pack_ref: pack.pack_ref.clone(),
                id: offer.id,
                kind: offer.kind,
                priority: offer.priority,
                provider_op: offer.provider_op,
                stage: offer.stage,
                contract: offer.contract,
            };
            self.by_key.insert(offer_key, record);
        }
        Ok(())
    }

    pub fn offers_total(&self) -> usize {
        self.by_key.len()
    }

    pub fn packs_total(&self) -> usize {
        self.pack_refs.len()
    }

    pub fn kind_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for offer in self.by_key.values() {
            *counts.entry(offer.kind.as_str()).or_insert(0) += 1;
        }
        counts
    }

    pub fn hook_counts_by_stage_contract(&self) -> Vec<(String, String, usize)> {
        let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
        for offer in self.by_key.values() {
            if offer.kind != OfferKind::Hook {
                continue;
            }
            let Some(stage) = offer.stage.clone() else {
                continue;
            };
            let Some(contract) = offer.contract.clone() else {
                continue;
            };
            *counts.entry((stage, contract)).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .map(|((stage, contract), count)| (stage, contract, count))
            .collect()
    }

    pub fn subs_counts_by_contract(&self) -> Vec<(String, usize)> {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for offer in self.by_key.values() {
            if offer.kind != OfferKind::Subs {
                continue;
            }
            let contract = offer
                .contract
                .clone()
                .unwrap_or_else(|| "<none>".to_string());
            *counts.entry(contract).or_insert(0) += 1;
        }
        counts.into_iter().collect()
    }

    pub fn select_hooks(&self, stage: &str, contract: &str) -> Vec<&Offer> {
        let mut selected = self
            .by_key
            .values()
            .filter(|offer| {
                offer.kind == OfferKind::Hook
                    && offer.stage.as_deref() == Some(stage)
                    && offer.contract.as_deref() == Some(contract)
            })
            .collect::<Vec<_>>();
        selected.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.offer_key.cmp(&b.offer_key))
        });
        selected
    }

    #[allow(dead_code)]
    pub fn select_subs(&self, contract: Option<&str>) -> Vec<&Offer> {
        let mut selected = self
            .by_key
            .values()
            .filter(|offer| {
                offer.kind == OfferKind::Subs
                    && contract
                        .map(|expected| offer.contract.as_deref() == Some(expected))
                        .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        selected.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.offer_key.cmp(&b.offer_key))
        });
        selected
    }
}

pub fn offer_key(pack_id: &str, offer_id: &str) -> String {
    format!("{pack_id}::{offer_id}")
}

pub fn discover_gtpacks(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
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
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

pub fn load_pack_offers(pack_ref: &Path) -> anyhow::Result<PackOffers> {
    let file = std::fs::File::open(pack_ref)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest_entry = archive.by_name("manifest.cbor").map_err(|err| match err {
        ZipError::FileNotFound => {
            anyhow::anyhow!("manifest.cbor missing in {}", pack_ref.display())
        }
        other => anyhow::anyhow!(
            "failed to read manifest.cbor in {}: {other}",
            pack_ref.display()
        ),
    })?;
    let mut bytes = Vec::new();
    manifest_entry.read_to_end(&mut bytes)?;
    let manifest: JsonValue = serde_cbor::from_slice(&bytes)
        .with_context(|| format!("decode manifest.cbor {}", pack_ref.display()))?;

    let pack_id = manifest_pack_id(&manifest).ok_or_else(|| {
        anyhow::anyhow!("pack manifest missing pack id in {}", pack_ref.display())
    })?;
    let offers = parse_pack_offers(&manifest, pack_ref)?;
    Ok(PackOffers {
        pack_id,
        pack_ref: pack_ref.to_path_buf(),
        offers,
    })
}

fn parse_pack_offers(manifest: &JsonValue, pack_ref: &Path) -> anyhow::Result<Vec<PackOffer>> {
    let mut offers_raw: Vec<&JsonValue> = Vec::new();
    if let Some(array) = manifest.get("offers").and_then(JsonValue::as_array) {
        offers_raw.extend(array);
    }
    if let Some(extensions) = manifest.get("extensions").and_then(JsonValue::as_object) {
        for ext in extensions.values() {
            if let Some(array) = ext.get("offers").and_then(JsonValue::as_array) {
                offers_raw.extend(array);
            }
            if let Some(array) = ext
                .get("inline")
                .and_then(|value| value.get("offers"))
                .and_then(JsonValue::as_array)
            {
                offers_raw.extend(array);
            }
        }
    }

    let mut parsed = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for raw in offers_raw {
        let Some(raw_obj) = raw.as_object() else {
            continue;
        };
        let candidate = raw_obj.contains_key("id")
            || raw_obj.contains_key("offer_id")
            || raw_obj.contains_key("kind")
            || raw_obj.contains_key("cap_id");
        if !candidate {
            continue;
        }

        let id = raw_obj
            .get("id")
            .or_else(|| raw_obj.get("offer_id"))
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("offer id missing in {}", pack_ref.display()))?
            .to_string();
        if !seen_ids.insert(id.clone()) {
            anyhow::bail!("duplicate offer id {} in {}", id, pack_ref.display());
        }

        let kind = raw_obj
            .get("kind")
            .and_then(JsonValue::as_str)
            .and_then(OfferKind::parse)
            .or_else(|| {
                if raw_obj.contains_key("cap_id") {
                    Some(OfferKind::Capability)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "offer kind missing/invalid for {} in {}",
                    id,
                    pack_ref.display()
                )
            })?;

        let provider_op = raw_obj
            .get("provider")
            .and_then(|value| value.get("op"))
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "provider.op missing for offer {} in {}",
                    id,
                    pack_ref.display()
                )
            })?
            .to_string();

        let priority = raw_obj
            .get("priority")
            .and_then(JsonValue::as_i64)
            .map(|value| value as i32)
            .unwrap_or(100);

        let stage = raw_obj
            .get("stage")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        let contract = raw_obj
            .get("contract")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);

        parsed.push(PackOffer {
            id,
            kind,
            priority,
            provider_op,
            stage,
            contract,
        });
    }

    Ok(parsed)
}

fn manifest_pack_id(manifest: &JsonValue) -> Option<String> {
    manifest
        .get("meta")
        .and_then(|value| value.get("pack_id"))
        .and_then(JsonValue::as_str)
        .or_else(|| manifest.get("pack_id").and_then(JsonValue::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| resolve_symbol_pack_id(manifest))
}

/// Resolve pack_id when stored as a symbol index (integer) referencing the
/// symbols.pack_ids array in the manifest.
fn resolve_symbol_pack_id(manifest: &JsonValue) -> Option<String> {
    let idx = manifest
        .get("meta")
        .and_then(|m| m.get("pack_id"))
        .or_else(|| manifest.get("pack_id"))
        .and_then(JsonValue::as_u64)? as usize;
    manifest
        .get("symbols")
        .and_then(|s| s.get("pack_ids"))
        .and_then(JsonValue::as_array)
        .and_then(|arr| arr.get(idx))
        .and_then(JsonValue::as_str)
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde_json::json;
    use tempfile::tempdir;
    use zip::write::FileOptions;

    use super::*;

    #[test]
    fn duplicate_offer_ids_within_pack_fail() {
        let tmp = tempdir().expect("tempdir");
        let pack_path = tmp.path().join("dup.gtpack");
        write_manifest_pack(
            &pack_path,
            &json!({
                "meta": { "pack_id": "pack-a" },
                "extensions": {
                    "greentic.ext.offers.v1": {
                        "inline": {
                            "offers": [
                                { "id": "x", "kind": "hook", "provider": { "op": "hook_a" } },
                                { "id": "x", "kind": "hook", "provider": { "op": "hook_b" } }
                            ]
                        }
                    }
                }
            }),
        );

        let err = load_pack_offers(&pack_path).unwrap_err().to_string();
        assert!(err.contains("duplicate offer id"));
    }

    #[test]
    fn duplicate_pack_id_across_packs_fail() {
        let tmp = tempdir().expect("tempdir");
        let pack_a = tmp.path().join("a.gtpack");
        let pack_b = tmp.path().join("b.gtpack");
        write_manifest_pack(
            &pack_a,
            &json!({
                "meta": { "pack_id": "pack-a" },
                "offers": [
                    { "id": "one", "kind": "capability", "provider": { "op": "op_a" } }
                ]
            }),
        );
        write_manifest_pack(
            &pack_b,
            &json!({
                "meta": { "pack_id": "pack-a" },
                "offers": [
                    { "id": "two", "kind": "capability", "provider": { "op": "op_b" } }
                ]
            }),
        );

        let err = OfferRegistry::from_pack_refs(&[pack_a, pack_b])
            .unwrap_err()
            .to_string();
        assert!(err.contains("duplicate pack_id"));
    }

    #[test]
    fn hook_selection_is_priority_then_offer_key() {
        let mut registry = OfferRegistry::default();
        registry
            .register_pack(PackOffers {
                pack_id: "pack-b".to_string(),
                pack_ref: PathBuf::from("/tmp/pack-b.gtpack"),
                offers: vec![PackOffer {
                    id: "offer-b".to_string(),
                    kind: OfferKind::Hook,
                    priority: 100,
                    provider_op: "hook_b".to_string(),
                    stage: Some(HOOK_STAGE_POST_INGRESS.to_string()),
                    contract: Some(HOOK_CONTRACT_CONTROL_V1.to_string()),
                }],
            })
            .expect("register b");
        registry
            .register_pack(PackOffers {
                pack_id: "pack-a".to_string(),
                pack_ref: PathBuf::from("/tmp/pack-a.gtpack"),
                offers: vec![
                    PackOffer {
                        id: "offer-a".to_string(),
                        kind: OfferKind::Hook,
                        priority: 100,
                        provider_op: "hook_a".to_string(),
                        stage: Some(HOOK_STAGE_POST_INGRESS.to_string()),
                        contract: Some(HOOK_CONTRACT_CONTROL_V1.to_string()),
                    },
                    PackOffer {
                        id: "offer-c".to_string(),
                        kind: OfferKind::Hook,
                        priority: 10,
                        provider_op: "hook_c".to_string(),
                        stage: Some(HOOK_STAGE_POST_INGRESS.to_string()),
                        contract: Some(HOOK_CONTRACT_CONTROL_V1.to_string()),
                    },
                ],
            })
            .expect("register a");

        let selected = registry.select_hooks(HOOK_STAGE_POST_INGRESS, HOOK_CONTRACT_CONTROL_V1);
        let keys = selected
            .iter()
            .map(|offer| offer.offer_key.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            vec![
                "pack-a::offer-c".to_string(),
                "pack-a::offer-a".to_string(),
                "pack-b::offer-b".to_string()
            ]
        );
    }

    #[test]
    fn subs_selection_filters_and_sorts() {
        let mut registry = OfferRegistry::default();
        registry
            .register_pack(PackOffers {
                pack_id: "pack-s".to_string(),
                pack_ref: PathBuf::from("/tmp/pack-s.gtpack"),
                offers: vec![
                    PackOffer {
                        id: "subs-a".to_string(),
                        kind: OfferKind::Subs,
                        priority: 100,
                        provider_op: "subs_a".to_string(),
                        stage: Some("post_ingress".to_string()),
                        contract: Some("contract-a".to_string()),
                    },
                    PackOffer {
                        id: "subs-b".to_string(),
                        kind: OfferKind::Subs,
                        priority: 10,
                        provider_op: "subs_b".to_string(),
                        stage: Some("post_ingress".to_string()),
                        contract: Some("contract-b".to_string()),
                    },
                ],
            })
            .expect("register subs");

        let filtered = registry.select_subs(Some("contract-a"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].offer_key, "pack-s::subs-a");

        let all = registry.select_subs(None);
        let keys = all
            .iter()
            .map(|offer| offer.offer_key.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            vec!["pack-s::subs-b".to_string(), "pack-s::subs-a".to_string()]
        );
    }

    fn write_manifest_pack(path: &Path, manifest: &JsonValue) {
        let file = std::fs::File::create(path).expect("create gtpack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())
            .expect("start manifest");
        let bytes = serde_cbor::to_vec(manifest).expect("manifest cbor");
        zip.write_all(&bytes).expect("write manifest");
        zip.finish().expect("finish zip");
    }
}
