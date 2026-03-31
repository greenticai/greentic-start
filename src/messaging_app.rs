use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use greentic_types::ChannelMessageEnvelope;
use serde_cbor::Value as CborValue;
use serde_json::{Value as JsonValue, json};
use zip::ZipArchive;

use crate::runner_exec::{self, RunRequest};
use crate::runner_host::OperatorContext;

#[derive(Clone, Debug)]
pub struct AppPackInfo {
    pub pack_id: String,
    pub flows: Vec<AppFlowInfo>,
}

#[derive(Clone, Debug)]
pub struct AppFlowInfo {
    pub id: String,
    pub kind: String,
}

pub fn resolve_app_pack_path(
    bundle: &Path,
    tenant: &str,
    team: Option<&str>,
    override_path: Option<&str>,
) -> Result<PathBuf> {
    if let Some(override_value) = override_path {
        let candidate = PathBuf::from(override_value);
        if candidate.exists() {
            return Ok(candidate);
        }
        bail!("APP_PACK_NOT_FOUND override path {override_value} does not exist");
    }

    let packs_root = bundle.join("packs");
    let mut tried = Vec::new();

    // 1. Try app_packs from bundle.yaml (highest priority)
    if let Some(pack_path) = resolve_from_bundle_yaml(bundle, &packs_root) {
        return Ok(pack_path);
    }

    // 2. Try tenant/team-scoped default.gtpack
    if let Some(team_id) = team {
        let candidate = packs_root.join(tenant).join(team_id).join("default.gtpack");
        tried.push(candidate.clone());
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    let candidate = packs_root.join(tenant).join("default.gtpack");
    tried.push(candidate.clone());
    if candidate.exists() {
        return Ok(candidate);
    }

    // 3. Fallback to packs/default.gtpack
    let candidate = packs_root.join("default.gtpack");
    tried.push(candidate.clone());
    if candidate.exists() {
        return Ok(candidate);
    }

    let paths = tried
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    bail!("APP_PACK_NOT_FOUND; tried {paths}");
}

/// Read bundle.yaml app_packs and try to find a matching .gtpack in the packs directory.
/// Handles both local references (packs/name.pack) and HTTPS URLs (extracts filename).
fn resolve_from_bundle_yaml(bundle: &Path, packs_root: &Path) -> Option<PathBuf> {
    let yaml_path = bundle.join("bundle.yaml");
    let content = std::fs::read_to_string(&yaml_path).ok()?;

    let mut in_app_packs = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "app_packs:" {
            in_app_packs = true;
            continue;
        }
        if in_app_packs {
            if !trimmed.starts_with("- ") {
                break;
            }
            let reference = trimmed.trim_start_matches("- ").trim();

            // Extract the pack name from the reference (local path or HTTPS URL)
            let pack_name = if reference.starts_with("http://") || reference.starts_with("https://")
            {
                // URL like https://.../hr-onboarding.gtpack → "hr-onboarding"
                reference
                    .rsplit('/')
                    .next()
                    .unwrap_or(reference)
                    .trim_end_matches(".gtpack")
            } else {
                // Local path like packs/hr-onboarding.pack → "hr-onboarding"
                reference
                    .rsplit('/')
                    .next()
                    .unwrap_or(reference)
                    .trim_end_matches(".pack")
                    .trim_end_matches(".gtpack")
            };

            // Try: packs/<name>.gtpack
            let candidate = packs_root.join(format!("{pack_name}.gtpack"));
            if candidate.exists() {
                return Some(candidate);
            }

            // Try: packs/<name>.pack/dist/<name>.pack.gtpack
            let pack_dir = packs_root.join(format!("{pack_name}.pack"));
            if pack_dir.is_dir()
                && let Ok(entries) = std::fs::read_dir(pack_dir.join("dist"))
            {
                for entry in entries.flatten() {
                    if entry.path().extension().is_some_and(|ext| ext == "gtpack") {
                        return Some(entry.path());
                    }
                }
            }

            // Try as direct file reference
            let candidate = packs_root.join(reference);
            if candidate.exists() && candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    // Fallback: find any non-default .gtpack in packs/
    if let Ok(entries) = std::fs::read_dir(packs_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "gtpack")
                && path.file_stem().is_some_and(|name| name != "default")
            {
                return Some(path);
            }
        }
    }
    None
}

pub fn load_app_pack_info(pack_path: &Path) -> Result<AppPackInfo> {
    let file = File::open(pack_path).with_context(|| format!("unable to open {pack_path:?}"))?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest = archive
        .by_name("manifest.cbor")
        .with_context(|| format!("pack {pack_path:?} missing manifest.cbor"))?;
    let mut buf = Vec::new();
    manifest.read_to_end(&mut buf)?;
    let value: CborValue = serde_cbor::from_slice(&buf)?;
    let pack_id = extract_text_or_symbol(&value, "pack_id", "pack_ids")
        .ok_or_else(|| anyhow::anyhow!("pack manifest missing pack id in {pack_path:?}"))?;
    let flows = extract_flows(&value);
    Ok(AppPackInfo { pack_id, flows })
}

pub fn select_app_flow(info: &AppPackInfo) -> Result<&AppFlowInfo> {
    if let Some(flow) = info.flows.iter().find(|flow| flow.id == "default") {
        return Ok(flow);
    }
    let messaging_flows: Vec<_> = info
        .flows
        .iter()
        .filter(|flow| flow.kind.eq_ignore_ascii_case("messaging"))
        .collect();
    if messaging_flows.len() == 1 {
        return Ok(messaging_flows[0]);
    }
    let available = info
        .flows
        .iter()
        .map(|flow| flow.id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    bail!("APP_FLOW_NOT_RESOLVED; available flows: {available}");
}

pub fn run_app_flow(
    bundle: &Path,
    ctx: &OperatorContext,
    pack_path: &Path,
    pack_id: &str,
    flow_id: &str,
    envelope: &ChannelMessageEnvelope,
) -> Result<Vec<ChannelMessageEnvelope>> {
    let request = RunRequest {
        root: bundle.to_path_buf(),
        domain: crate::domains::Domain::Messaging,
        pack_path: pack_path.to_path_buf(),
        pack_label: pack_id.to_string(),
        flow_id: flow_id.to_string(),
        tenant: ctx.tenant.clone(),
        team: ctx.team.clone(),
        input: json!({
            "input": envelope,
            "tenant": ctx.tenant,
            "team": ctx.team,
            "correlation_id": ctx.correlation_id,
        }),
        dist_offline: true,
    };

    let output = runner_exec::run_provider_pack_flow(request)?;
    let target_node = envelope
        .metadata
        .get("routeToCardId")
        .or_else(|| envelope.metadata.get("toCardId"));
    let value = collect_transcript_outputs(&output.run_dir, target_node.map(|s| s.as_str()))?
        .ok_or_else(|| anyhow::anyhow!("app flow produced no outputs"))?;
    parse_envelopes(&value, envelope)
}

fn extract_text_or_symbol(value: &CborValue, key: &str, symbol_table: &str) -> Option<String> {
    let map = match value {
        CborValue::Map(map) => map,
        _ => return None,
    };
    let cbor_key = CborValue::Text(key.to_string());
    match map.get(&cbor_key)? {
        CborValue::Text(text) => Some(text.clone()),
        CborValue::Integer(idx) => {
            let idx = *idx as usize;
            let symbols_key = CborValue::Text("symbols".to_string());
            let table_key = CborValue::Text(symbol_table.to_string());
            let symbols = map.get(&symbols_key)?;
            if let CborValue::Map(sym_map) = symbols
                && let Some(CborValue::Array(entries)) = sym_map.get(&table_key)
                && let Some(CborValue::Text(resolved)) = entries.get(idx)
            {
                return Some(resolved.clone());
            }
            None
        }
        _ => None,
    }
}

fn extract_flows(value: &CborValue) -> Vec<AppFlowInfo> {
    let mut flows = Vec::new();
    if let CborValue::Map(map) = value {
        let flows_key = CborValue::Text("flows".to_string());
        if let Some(CborValue::Array(entries)) = map.get(&flows_key) {
            for entry in entries {
                if let Some(flow) = parse_flow_entry(entry) {
                    flows.push(flow);
                }
            }
        }
    }
    flows
}

fn parse_flow_entry(value: &CborValue) -> Option<AppFlowInfo> {
    let map = match value {
        CborValue::Map(map) => map,
        _ => return None,
    };
    let id = extract_text_from_map(map, "id")?;
    let kind = if let Some(flow_map) =
        map.get(&CborValue::Text("flow".to_string()))
            .and_then(|v| match v {
                CborValue::Map(flow_map) => Some(flow_map),
                _ => None,
            }) {
        extract_text_from_map(flow_map, "kind")
    } else {
        extract_text_from_map(map, "kind")
    };
    Some(AppFlowInfo {
        id,
        kind: kind.unwrap_or_else(|| "messaging".to_string()),
    })
}

fn extract_text_from_map(map: &BTreeMap<CborValue, CborValue>, key: &str) -> Option<String> {
    map.get(&CborValue::Text(key.to_string()))
        .and_then(|value| match value {
            CborValue::Text(text) => Some(text.clone()),
            _ => None,
        })
}

fn collect_transcript_outputs(
    run_dir: &Path,
    target_node_id: Option<&str>,
) -> Result<Option<JsonValue>> {
    let path = run_dir.join("transcript.jsonl");
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(path)?;
    let mut first = None;
    let mut targeted = None;
    for line in contents.lines() {
        if let Ok(value) = serde_json::from_str::<JsonValue>(line)
            && let Some(outputs) = value.get("outputs")
            && !outputs.is_null()
        {
            if first.is_none() {
                first = Some(outputs.clone());
            }
            if let Some(target) = target_node_id
                && let Some(node_id) = value.get("node_id").and_then(|n| n.as_str())
                && node_id == target
            {
                targeted = Some(outputs.clone());
            }
        }
    }
    Ok(targeted.or(first))
}

fn parse_envelopes(
    value: &JsonValue,
    ingress_envelope: &ChannelMessageEnvelope,
) -> Result<Vec<ChannelMessageEnvelope>> {
    if let Some(v) = value.as_array() {
        return parse_envelope_array(v);
    }
    if let Some(events) = value.get("events").and_then(|v| v.as_array()) {
        return parse_envelope_array(events);
    }
    if let Some(envelope) = value.get("message") {
        let envelope: ChannelMessageEnvelope = serde_json::from_value(envelope.clone())
            .context("app flow message payload is not a ChannelMessageEnvelope")?;
        return Ok(vec![envelope]);
    }
    if let Some(rendered_card) = value.get("renderedCard")
        && !rendered_card.is_null()
    {
        let mut reply = ingress_envelope.clone();
        let title = rendered_card
            .get("body")
            .and_then(|b| b.as_array())
            .and_then(|arr| arr.first())
            .and_then(|e| e.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("Adaptive Card");
        reply.text = Some(title.to_string());
        if let Ok(ac_json) = serde_json::to_string(rendered_card) {
            reply.metadata.insert("adaptive_card".to_string(), ac_json);
        }
        return Ok(vec![reply]);
    }
    if let Some(text) = value
        .get("payload")
        .and_then(|p| p.get("text"))
        .and_then(JsonValue::as_str)
        .or_else(|| value.get("text").and_then(JsonValue::as_str))
        .or_else(|| value.as_str())
    {
        let mut reply = ingress_envelope.clone();
        reply.text = Some(text.to_string());
        return Ok(vec![reply]);
    }
    Err(anyhow::anyhow!(
        "app flow output did not produce envelope(s)"
    ))
}

fn parse_envelope_array(array: &[JsonValue]) -> Result<Vec<ChannelMessageEnvelope>> {
    let mut envelopes = Vec::new();
    for element in array {
        let envelope: ChannelMessageEnvelope = serde_json::from_value(element.clone())
            .context("app flow output array contains invalid channel envelope")?;
        envelopes.push(envelope);
    }
    Ok(envelopes)
}
