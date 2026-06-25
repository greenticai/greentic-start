//! Derive agentic-worker `AgentConfig`s from `DwApplication` packs in a bundle.
//!
//! `gtc start` builds a synthetic `HostConfig`; this module sources its agents
//! from the bundle's DwApplication app-packs (manifest.json), so a hand-authored
//! `GREENTIC_AW_AGENTS_FILE` is no longer required. Fail-soft: any unreadable /
//! non-DwApplication / unparseable pack is logged and skipped.
use std::io::Read;
use std::path::{Path, PathBuf};

use greentic_aw_runtime::config::AgentConfig;
use greentic_aw_runtime::dw::{DwApplicationManifest, agent_config_from_dw_manifest};

/// Discover DwApplication packs under the bundle and convert each to an
/// `(agent_id, AgentConfig)`. Never errors: problems are logged and skipped.
pub(crate) fn dw_agents_from_bundle(
    bundle_root: &Path,
    tenant: &str,
) -> Vec<(String, AgentConfig)> {
    let mut out = Vec::new();
    for pack in candidate_packs(bundle_root, tenant) {
        match agent_from_pack(&pack) {
            Ok(Some(cfg)) => out.push((cfg.agent_id.clone(), cfg)),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(pack = %pack.display(), error = %error, "skipping DwApplication pack");
            }
        }
    }
    out
}

/// `.gtpack` files under `tenants/<tenant>/packs/` and `packs/`.
fn candidate_packs(bundle_root: &Path, tenant: &str) -> Vec<PathBuf> {
    let dirs = [
        bundle_root.join("tenants").join(tenant).join("packs"),
        bundle_root.join("packs"),
    ];
    let mut packs = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "gtpack") {
                packs.push(path);
            }
        }
    }
    packs
}

/// Returns `Some(cfg)` for a DwApplication pack, `None` for any other kind.
fn agent_from_pack(pack: &Path) -> anyhow::Result<Option<AgentConfig>> {
    let file = std::fs::File::open(pack)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let metadata: serde_json::Value = read_json(&mut archive, "metadata.json")?;
    if metadata.get("kind").and_then(serde_json::Value::as_str) != Some("DwApplication") {
        return Ok(None);
    }

    let manifest: DwApplicationManifest =
        serde_json::from_value(read_json(&mut archive, "manifest.json")?)?;
    Ok(Some(agent_config_from_dw_manifest(&manifest)))
}

fn read_json(
    archive: &mut zip::ZipArchive<std::fs::File>,
    name: &str,
) -> anyhow::Result<serde_json::Value> {
    let mut entry = archive.by_name(name)?;
    let mut buf = String::new();
    entry.read_to_string(&mut buf)?;
    Ok(serde_json::from_str(&buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_dw_pack(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        zip.start_file("metadata.json", opts).unwrap();
        zip.write_all(br#"{"kind":"DwApplication"}"#).unwrap();
        zip.start_file("manifest.json", opts).unwrap();
        zip.write_all(br#"{"manifest_id":"onboarding-companion","manifest":{"capability_plan":{"default_provider_ids":{"cap://llm/chat":"provider.llm.deepseek.chat"}},"defaults":{"values":{"system_prompt":"hi","provider.llm.deepseek.chat::model":"deepseek-chat"}}}}"#).unwrap();
        zip.finish().unwrap();
        path
    }

    /// Writes a non-DwApplication pack (different `kind`) — must be skipped by the kind-gate.
    fn write_non_dw_pack(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        zip.start_file("metadata.json", opts).unwrap();
        zip.write_all(br#"{"kind":"FlowPack"}"#).unwrap();
        zip.finish().unwrap();
        path
    }

    #[test]
    fn discovers_and_converts_dw_pack() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = tmp.path().join("tenants").join("greentic").join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        write_dw_pack(&packs, "onboarding.gtpack");

        let agents = dw_agents_from_bundle(tmp.path(), "greentic");
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].0, "onboarding-companion");
        assert_eq!(agents[0].1.llm.model, "deepseek-chat");
    }

    #[test]
    fn skips_non_dwapplication_and_empty_bundles() {
        let tmp = tempfile::tempdir().unwrap();
        // no packs dir at all → empty, no panic
        assert!(dw_agents_from_bundle(tmp.path(), "greentic").is_empty());
    }

    #[test]
    fn dw_pack_wins_alongside_non_dw_pack() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = tmp.path().join("tenants").join("greentic").join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        write_dw_pack(&packs, "onboarding.gtpack");
        write_non_dw_pack(&packs, "some-flow.gtpack");

        let agents = dw_agents_from_bundle(tmp.path(), "greentic");
        assert_eq!(
            agents.len(),
            1,
            "exactly one agent — the DwApplication pack; the non-DW pack must be skipped"
        );
        assert_eq!(agents[0].0, "onboarding-companion");
    }
}
