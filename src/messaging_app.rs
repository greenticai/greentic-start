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
    if let Ok(content) = std::fs::read_to_string(&yaml_path) {
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
                let pack_name =
                    if reference.starts_with("http://") || reference.starts_with("https://") {
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
    let mut last = None;
    let mut targeted = None;
    for line in contents.lines() {
        if let Ok(value) = serde_json::from_str::<JsonValue>(line)
            && let Some(outputs) = value.get("outputs")
            && !outputs.is_null()
        {
            last = Some(outputs.clone());
            if let Some(target) = target_node_id
                && let Some(node_id) = value.get("node_id").and_then(|n| n.as_str())
                && node_id == target
            {
                targeted = Some(outputs.clone());
            }
        }
    }
    Ok(targeted.or(last))
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
        // Don't set text when adaptive card is present — the card renders
        // natively on TierA channels (Teams, WebChat) and the redundant text
        // bubble is distracting.  TierD providers already get a downsampled
        // text summary via the render_plan pipeline.
        reply.text = None;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use tempfile::tempdir;

    fn envelope() -> ChannelMessageEnvelope {
        serde_json::from_value(json!({
            "id": "msg-1",
            "tenant": {
                "env": "dev",
                "tenant": "demo",
                "tenant_id": "demo",
                "team": "default",
                "attempt": 0
            },
            "channel": "conv-1",
            "session_id": "conv-1",
            "from": {
                "id": "user-1",
                "kind": "user"
            },
            "text": "hello",
            "metadata": {}
        }))
        .expect("envelope")
    }

    fn cbor_text(key: &str, value: &str) -> (CborValue, CborValue) {
        (
            CborValue::Text(key.to_string()),
            CborValue::Text(value.to_string()),
        )
    }

    #[test]
    fn resolve_from_bundle_yaml_prefers_direct_gtpack_reference() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path();
        let packs_root = bundle.join("packs");
        std::fs::create_dir_all(&packs_root).expect("packs root");
        let pack_path = packs_root.join("sales-assist.gtpack");
        std::fs::write(&pack_path, b"pack").expect("write pack");
        std::fs::write(
            bundle.join("bundle.yaml"),
            "app_packs:\n  - https://cdn.example.com/sales-assist.gtpack\n",
        )
        .expect("write bundle");

        assert_eq!(
            resolve_from_bundle_yaml(bundle, &packs_root),
            Some(pack_path)
        );
    }

    #[test]
    fn resolve_from_bundle_yaml_falls_back_to_dist_gtpack_and_non_default_scan() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path();
        let packs_root = bundle.join("packs");
        let dist_dir = packs_root.join("support.pack").join("dist");
        std::fs::create_dir_all(&dist_dir).expect("dist dir");
        let dist_pack = dist_dir.join("support.pack.gtpack");
        std::fs::write(&dist_pack, b"pack").expect("write dist pack");
        std::fs::write(
            bundle.join("bundle.yaml"),
            "app_packs:\n  - packs/support.pack\n",
        )
        .expect("write bundle");

        assert_eq!(
            resolve_from_bundle_yaml(bundle, &packs_root),
            Some(dist_pack.clone())
        );

        std::fs::remove_file(bundle.join("bundle.yaml")).expect("remove bundle");
        std::fs::remove_file(&dist_pack).expect("remove dist pack");
        let fallback = packs_root.join("assistant.gtpack");
        std::fs::write(&fallback, b"fallback").expect("write fallback");

        assert_eq!(
            resolve_from_bundle_yaml(bundle, &packs_root),
            Some(fallback)
        );
    }

    #[test]
    fn select_app_flow_prefers_default_and_single_messaging_flow() {
        let info = AppPackInfo {
            pack_id: "pack".to_string(),
            flows: vec![
                AppFlowInfo {
                    id: "alternate".to_string(),
                    kind: "messaging".to_string(),
                },
                AppFlowInfo {
                    id: "default".to_string(),
                    kind: "workflow".to_string(),
                },
            ],
        };
        assert_eq!(select_app_flow(&info).expect("default flow").id, "default");

        let single_messaging = AppPackInfo {
            pack_id: "pack".to_string(),
            flows: vec![
                AppFlowInfo {
                    id: "notify".to_string(),
                    kind: "messaging".to_string(),
                },
                AppFlowInfo {
                    id: "wizard".to_string(),
                    kind: "setup".to_string(),
                },
            ],
        };
        assert_eq!(
            select_app_flow(&single_messaging)
                .expect("single messaging flow")
                .id,
            "notify"
        );
    }

    #[test]
    fn select_app_flow_errors_when_choice_is_ambiguous() {
        let info = AppPackInfo {
            pack_id: "pack".to_string(),
            flows: vec![
                AppFlowInfo {
                    id: "one".to_string(),
                    kind: "messaging".to_string(),
                },
                AppFlowInfo {
                    id: "two".to_string(),
                    kind: "messaging".to_string(),
                },
            ],
        };

        let err = select_app_flow(&info).expect_err("ambiguous flow should fail");
        assert!(err.to_string().contains("one, two"));
    }

    #[test]
    fn extract_text_or_symbol_and_parse_flow_entry_support_symbol_tables_and_defaults() {
        let value = CborValue::Map(BTreeMap::from([
            (
                CborValue::Text("pack_id".to_string()),
                CborValue::Integer(1),
            ),
            (
                CborValue::Text("symbols".to_string()),
                CborValue::Map(BTreeMap::from([(
                    CborValue::Text("pack_ids".to_string()),
                    CborValue::Array(vec![
                        CborValue::Text("ignored".to_string()),
                        CborValue::Text("demo-pack".to_string()),
                    ]),
                )])),
            ),
        ]));
        assert_eq!(
            extract_text_or_symbol(&value, "pack_id", "pack_ids"),
            Some("demo-pack".to_string())
        );

        let nested_flow = CborValue::Map(BTreeMap::from([
            cbor_text("id", "route-card"),
            (
                CborValue::Text("flow".to_string()),
                CborValue::Map(BTreeMap::from([cbor_text("kind", "workflow")])),
            ),
        ]));
        let parsed = parse_flow_entry(&nested_flow).expect("flow entry");
        assert_eq!(parsed.id, "route-card");
        assert_eq!(parsed.kind, "workflow");

        let default_kind_flow = CborValue::Map(BTreeMap::from([cbor_text("id", "default")]));
        assert_eq!(
            parse_flow_entry(&default_kind_flow)
                .expect("default kind flow")
                .kind,
            "messaging"
        );
    }

    #[test]
    fn collect_transcript_outputs_prefers_targeted_node_then_last_output() {
        let dir = tempdir().expect("tempdir");
        let transcript = dir.path().join("transcript.jsonl");
        std::fs::write(
            &transcript,
            concat!(
                "{\"node_id\":\"first\",\"outputs\":null}\n",
                "{\"node_id\":\"other\",\"outputs\":{\"text\":\"middle\"}}\n",
                "{\"node_id\":\"target\",\"outputs\":{\"text\":\"targeted\"}}\n"
            ),
        )
        .expect("write transcript");

        // Targeted node takes priority
        let targeted = collect_transcript_outputs(dir.path(), Some("target"))
            .expect("collect outputs")
            .expect("targeted output");
        assert_eq!(targeted["text"], "targeted");

        // When target not found, fall back to LAST non-null output
        let fallback = collect_transcript_outputs(dir.path(), Some("missing"))
            .expect("collect fallback")
            .expect("fallback output");
        assert_eq!(fallback["text"], "targeted");

        let missing = collect_transcript_outputs(&dir.path().join("no-run"), None)
            .expect("missing transcript");
        assert!(missing.is_none());
    }

    #[test]
    fn parse_envelopes_supports_message_events_cards_and_text_payloads() {
        let ingress = envelope();

        let message_output = parse_envelopes(
            &json!({
                "message": {
                    "id": "msg-2",
                    "tenant": ingress.tenant,
                    "channel": "conv-2",
                    "session_id": "conv-2",
                    "from": {
                        "id": "bot-1",
                        "kind": "bot"
                    },
                    "text": "reply",
                    "metadata": {}
                }
            }),
            &ingress,
        )
        .expect("message output");
        assert_eq!(message_output[0].text.as_deref(), Some("reply"));

        let events_output = parse_envelopes(
            &json!({
                "events": [
                    {
                        "id": "msg-3",
                        "tenant": ingress.tenant,
                        "channel": "conv-3",
                        "session_id": "conv-3",
                        "from": {
                            "id": "bot-1",
                            "kind": "bot"
                        },
                        "text": "event reply",
                        "metadata": {}
                    }
                ]
            }),
            &ingress,
        )
        .expect("events output");
        assert_eq!(events_output[0].text.as_deref(), Some("event reply"));

        let card_output = parse_envelopes(
            &json!({
                "renderedCard": {
                    "body": [
                        {"text": "Welcome card"}
                    ]
                }
            }),
            &ingress,
        )
        .expect("card output");
        assert_eq!(card_output[0].text, None);
        assert!(card_output[0].metadata.contains_key("adaptive_card"));

        let text_output = parse_envelopes(&json!({"payload": {"text": "payload text"}}), &ingress)
            .expect("text output");
        assert_eq!(text_output[0].text.as_deref(), Some("payload text"));
    }

    #[test]
    fn parse_envelopes_reports_invalid_arrays_and_unrecognized_payloads() {
        let ingress = envelope();

        let invalid_array = parse_envelopes(&json!([{"not": "an envelope"}]), &ingress)
            .expect_err("invalid array should fail");
        assert!(
            invalid_array
                .to_string()
                .contains("invalid channel envelope")
        );

        let unknown = parse_envelopes(&json!({"payload": {"unknown": true}}), &ingress)
            .expect_err("unknown payload should fail");
        assert!(unknown.to_string().contains("did not produce envelope"));
    }

    #[test]
    fn load_app_pack_info_reads_manifest_pack_id_and_flows() {
        let dir = tempdir().expect("tempdir");
        let pack_path = dir.path().join("app.gtpack");
        let file = File::create(&pack_path).expect("create pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", zip::write::FileOptions::<()>::default())
            .expect("start manifest");
        let manifest = CborValue::Map(BTreeMap::from([
            cbor_text("pack_id", "demo-pack"),
            (
                CborValue::Text("flows".to_string()),
                CborValue::Array(vec![
                    CborValue::Map(BTreeMap::from([
                        cbor_text("id", "default"),
                        cbor_text("kind", "messaging"),
                    ])),
                    CborValue::Map(BTreeMap::from([
                        cbor_text("id", "setup"),
                        (
                            CborValue::Text("flow".to_string()),
                            CborValue::Map(BTreeMap::from([cbor_text("kind", "workflow")])),
                        ),
                    ])),
                ]),
            ),
        ]));
        let bytes = serde_cbor::to_vec(&manifest).expect("encode manifest");
        zip.write_all(&bytes).expect("write manifest");
        zip.finish().expect("finish zip");

        let info = load_app_pack_info(&pack_path).expect("load pack info");
        assert_eq!(info.pack_id, "demo-pack");
        assert_eq!(info.flows.len(), 2);
        assert_eq!(info.flows[0].id, "default");
        assert_eq!(info.flows[1].kind, "workflow");
    }
}
