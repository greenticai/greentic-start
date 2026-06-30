//! Derive agentic-worker `AgentConfig`s from agent packs in a bundle.
//!
//! `gtc start` builds a synthetic `HostConfig`; this module sources its agents
//! from the bundle's agent packs so a hand-authored `GREENTIC_AW_AGENTS_FILE`
//! is no longer required. Two pack formats are supported:
//!
//! - **Legacy DwApplication** (`metadata.json` kind == `"DwApplication"` +
//!   `manifest.json`): emitted by the old aw-runtime pack tooling.
//! - **packc sidecar** (`dw-agents.json` bare JSON object
//!   `{ agent_id → AgentConfig-blob }`): emitted by `greentic-pack` (packc).
//!   A packc pack may expose multiple agents per archive.
//!
//! Fail-soft: any unreadable, non-agent, or malformed pack is logged and
//! skipped; it never aborts the bundle start.
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use greentic_aw_runtime::config::AgentConfig;
use greentic_aw_runtime::dw::{DwApplicationManifest, agent_config_from_dw_manifest};

/// Discover agent packs under the bundle and convert each to an
/// `(agent_id, AgentConfig)`. Never errors: problems are logged and skipped.
pub(crate) fn dw_agents_from_bundle(
    bundle_root: &Path,
    tenant: &str,
) -> Vec<(String, AgentConfig)> {
    let mut out: Vec<(String, AgentConfig)> = Vec::new();
    for pack in candidate_packs(bundle_root, tenant) {
        match agents_from_pack(&pack) {
            Ok(cfgs) => {
                for cfg in cfgs {
                    if out.iter().any(|(id, _)| id == &cfg.agent_id) {
                        tracing::warn!(
                            agent = %cfg.agent_id,
                            pack = %pack.display(),
                            "duplicate agent_id across bundle packs; later pack wins"
                        );
                    }
                    out.push((cfg.agent_id.clone(), cfg));
                }
            }
            Err(error) => {
                tracing::warn!(pack = %pack.display(), error = %error, "skipping agent pack");
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
            if path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("gtpack"))
            {
                packs.push(path);
            }
        }
    }
    packs
}

/// Returns the agents declared by a single `.gtpack` archive.
///
/// Supports two formats (additive — the legacy path remains unchanged):
///
/// 1. **Legacy DwApplication**: `metadata.json` with `kind == "DwApplication"` +
///    `manifest.json` as `DwApplicationManifest`. Returns a single agent.
/// 2. **packc sidecar**: `dw-agents.json` bare object
///    `{ "<agent_id>": <AgentConfig-blob> }`. The sidecar key is the
///    `agent_id`; if the deserialized `AgentConfig.agent_id` is empty the
///    key is used as the fallback. May return multiple agents.
///
/// Returns `Ok(vec![])` for packs that carry neither format.
/// Fail-soft on a malformed sidecar (logs warn, contributes none).
fn agents_from_pack(pack: &Path) -> anyhow::Result<Vec<AgentConfig>> {
    let file = std::fs::File::open(pack)?;
    let mut archive = zip::ZipArchive::new(file)?;

    // --- Legacy path ---
    // If metadata.json is absent (FileNotFound) we fall through to the packc
    // path. Any other I/O error is surfaced to the caller. When kind is any
    // value other than "DwApplication" (including absent metadata.json) we also
    // fall through to the packc sidecar check.
    if let Some(metadata) = read_json_optional(&mut archive, "metadata.json")?
        && metadata.get("kind").and_then(serde_json::Value::as_str) == Some("DwApplication")
    {
        let manifest: DwApplicationManifest =
            serde_json::from_value(read_json(&mut archive, "manifest.json")?)?;
        return Ok(vec![agent_config_from_dw_manifest(&manifest)]);
    }

    // --- packc sidecar path ---
    let sidecar_value = match read_json_optional(&mut archive, "dw-agents.json")? {
        Some(v) => v,
        None => return Ok(vec![]), // Not an agent pack.
    };

    let blobs: BTreeMap<String, serde_json::Value> = match serde_json::from_value(sidecar_value) {
        Ok(map) => map,
        Err(error) => {
            tracing::warn!(
                pack = %pack.display(),
                error = %error,
                "ignoring malformed dw-agents.json sidecar"
            );
            return Ok(vec![]);
        }
    };

    let mut agents = Vec::with_capacity(blobs.len());
    for (sidecar_key, blob) in blobs {
        match serde_json::from_value::<AgentConfig>(blob) {
            Ok(mut cfg) => {
                if cfg.agent_id.is_empty() {
                    cfg.agent_id = sidecar_key;
                }
                agents.push(cfg);
            }
            Err(error) => {
                tracing::warn!(
                    pack = %pack.display(),
                    agent = %sidecar_key,
                    error = %error,
                    "skipping malformed entry in dw-agents.json sidecar"
                );
            }
        }
    }
    Ok(agents)
}

/// Reads a JSON entry from an archive, returning `None` when the entry is
/// absent (`FileNotFound`). Propagates any other error to the caller.
fn read_json_optional(
    archive: &mut zip::ZipArchive<std::fs::File>,
    name: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let mut entry = match archive.by_name(name) {
        Ok(e) => e,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(other) => return Err(anyhow::Error::from(other)),
    };
    let mut buf = String::new();
    entry.read_to_string(&mut buf)?;
    Ok(Some(serde_json::from_str(&buf)?))
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

    #[test]
    fn discovers_uppercase_extension() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = tmp.path().join("tenants").join("greentic").join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        write_dw_pack(&packs, "onboarding.GTPACK");

        let agents = dw_agents_from_bundle(tmp.path(), "greentic");
        assert_eq!(
            agents.len(),
            1,
            "the `.gtpack` extension match must be case-insensitive"
        );
        assert_eq!(agents[0].0, "onboarding-companion");
    }

    #[test]
    fn duplicate_agent_id_keeps_both_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = tmp.path().join("tenants").join("greentic").join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        // Both packs declare manifest_id "onboarding-companion".
        write_dw_pack(&packs, "a.gtpack");
        write_dw_pack(&packs, "b.gtpack");

        let agents = dw_agents_from_bundle(tmp.path(), "greentic");
        assert_eq!(
            agents.len(),
            2,
            "both duplicate-id entries are returned (warn emitted); HashMap insertion resolves last-wins"
        );
        assert!(agents.iter().all(|(id, _)| id == "onboarding-companion"));
    }

    /// Minimal valid `AgentConfig` JSON for use in packc sidecar tests.
    fn minimal_agent_config_json(agent_id: &str) -> String {
        format!(
            r#"{{"agent_id":"{agent_id}","system_prompt":"You are a research assistant.","tools":[],"llm":{{"provider":"openai","model":"gpt-4o-mini"}}}}"#
        )
    }

    /// Writes a packc-format `.gtpack` zip: contains a `dw-agents.json` sidecar
    /// with a single agent entry, NO `metadata.json`.
    fn write_packc_dw_pack(dir: &Path, name: &str, agent_id: &str) -> PathBuf {
        let path = dir.join(name);
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        zip.start_file("dw-agents.json", opts).unwrap();
        let sidecar = format!(
            r#"{{"{agent_id}":{}}}"#,
            minimal_agent_config_json(agent_id)
        );
        zip.write_all(sidecar.as_bytes()).unwrap();
        // Also add a manifest.cbor placeholder so it looks like a real packc pack.
        zip.start_file("manifest.cbor", opts).unwrap();
        zip.write_all(b"").unwrap();
        zip.finish().unwrap();
        path
    }

    /// Writes a packc-format `.gtpack` zip with multiple agents in the sidecar.
    fn write_packc_multi_agent_pack(dir: &Path, name: &str, agent_ids: &[&str]) -> PathBuf {
        let path = dir.join(name);
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        zip.start_file("dw-agents.json", opts).unwrap();
        let entries: Vec<String> = agent_ids
            .iter()
            .map(|id| format!(r#""{id}":{}"#, minimal_agent_config_json(id)))
            .collect();
        let sidecar = format!("{{{}}}", entries.join(","));
        zip.write_all(sidecar.as_bytes()).unwrap();
        zip.start_file("manifest.cbor", opts).unwrap();
        zip.write_all(b"").unwrap();
        zip.finish().unwrap();
        path
    }

    #[test]
    fn packc_single_agent_sidecar_is_discovered() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = tmp.path().join("tenants").join("greentic").join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        write_packc_dw_pack(&packs, "researcher.gtpack", "tavily_researcher");

        let agents = dw_agents_from_bundle(tmp.path(), "greentic");
        assert_eq!(agents.len(), 1, "packc sidecar agent must be discovered");
        assert_eq!(agents[0].0, "tavily_researcher");
        assert_eq!(agents[0].1.agent_id, "tavily_researcher");
    }

    #[test]
    fn packc_multi_agent_sidecar_yields_all_agents() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = tmp.path().join("tenants").join("greentic").join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        write_packc_multi_agent_pack(
            &packs,
            "crew.gtpack",
            &["tavily_researcher", "email_writer"],
        );

        let mut agents = dw_agents_from_bundle(tmp.path(), "greentic");
        agents.sort_by(|(a, _), (b, _)| a.cmp(b));
        assert_eq!(agents.len(), 2, "both sidecar agents must be discovered");
        assert_eq!(agents[0].0, "email_writer");
        assert_eq!(agents[1].0, "tavily_researcher");
    }

    #[test]
    fn packc_malformed_sidecar_is_skipped_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = tmp.path().join("tenants").join("greentic").join("packs");
        std::fs::create_dir_all(&packs).unwrap();

        // Write a pack with a broken JSON sidecar — must not panic or abort.
        let path = packs.join("broken.gtpack");
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        zip.start_file("dw-agents.json", opts).unwrap();
        zip.write_all(b"not valid json {{{").unwrap();
        zip.finish().unwrap();

        // Must return empty without panicking.
        let agents = dw_agents_from_bundle(tmp.path(), "greentic");
        assert!(agents.is_empty(), "malformed sidecar must be skipped");
    }
}
