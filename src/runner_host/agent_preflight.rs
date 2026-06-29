//! Pre-flight guard: abort `gtc start` before serving when a bundle flow
//! references a `dw.agent` (agentic worker) whose `agent_id` is not present in
//! the tenant's assembled agent map.
//!
//! Today an unprovided agent only surfaces at conversation time — and is even
//! swallowed into a generic "Something went wrong" reply — so the bundle starts,
//! serves, and silently fails every turn that hits the missing worker. This
//! module makes that condition fail **closed** at startup with an actionable
//! error listing every missing reference and the flow/node that names it.
//!
//! ## What is "referenced"
//!
//! A `dw.agent` node in a compiled flow (the flow IR carried in a pack's
//! `manifest.cbor`). In the IR, a node's `component.id` is a *symbol index* into
//! `symbols.component_ids`; the node is a `dw.agent` node when that resolves to
//! the literal component id `"dw.agent"`. The referenced agent id is the node's
//! `component.operation` (e.g. `tavily_researcher`). The human-readable node id
//! is `symbols.node_ids[node.id]`.
//!
//! ## What is "provided"
//!
//! On the `research` lane the runtime assembles every agentic worker into the
//! synthetic [`HostConfig::agents`] map: first from `DwApplication` packs in the
//! bundle (`dw_agents_from_bundle`), then overlaid by the optional
//! `GREENTIC_AW_AGENTS_FILE` (`apply_demo_agents`). The provided set is the
//! **keys of that assembled map** — so an agent supplied only via the env-file
//! overlay is correctly counted as provided and is never false-flagged. This is
//! the key difference from a filesystem-only pack rescan: the guard honours the
//! real runtime source of agents.
//!
//! The guard is a pure set-difference of referenced-vs-provided agent ids,
//! evaluated within a single tenant scope (the assembled map and the referenced
//! flows both come from that tenant's bundle).

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, bail};
use serde_cbor::Value as CborValue;

use crate::operator_log;
use crate::runner_host::helpers::build_demo_host_config;

/// Component id that marks an agentic-worker node in a compiled flow.
const DW_AGENT_COMPONENT_ID: &str = "dw.agent";

// Intention-revealing aliases for the (flow, node, agent) triple the guard
// reasons about. They are all `String`; the aliases document the role.
type FlowId = String;
type NodeId = String;
type AgentId = String;

/// A `dw.agent` node reference whose agent id is not present in the assembled
/// agent map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MissingAgentRef {
    pub flow_id: FlowId,
    pub node_id: NodeId,
    pub agent_id: AgentId,
}

impl MissingAgentRef {
    /// One actionable line naming the missing worker and where it is referenced.
    fn render(&self) -> String {
        format!(
            "agentic worker \"{}\" referenced by flow \"{}\" (node \"{}\") is not provided by this \
             bundle — include the DwApplication pack that exports it (or define it in \
             GREENTIC_AW_AGENTS_FILE), or remove the dw.agent node",
            self.agent_id, self.flow_id, self.node_id
        )
    }
}

/// Pure set-difference: every referenced agent whose id is absent from
/// `provided`. Returns `Ok(())` when every referenced agent is provided (or when
/// nothing is referenced); otherwise `Err` lists every missing reference, in the
/// order they were discovered.
///
/// Pure and dependency-free so it can be unit-tested in isolation; the bundle
/// I/O that assembles `referenced` and `provided` lives in
/// [`check_bundle_dw_agents`].
pub(crate) fn check_dw_agent_references(
    referenced: &[(FlowId, NodeId, AgentId)],
    provided: &HashSet<AgentId>,
) -> Result<(), Vec<MissingAgentRef>> {
    let missing: Vec<MissingAgentRef> = referenced
        .iter()
        .filter(|(_, _, agent_id)| !provided.contains(agent_id))
        .map(|(flow_id, node_id, agent_id)| MissingAgentRef {
            flow_id: flow_id.clone(),
            node_id: node_id.clone(),
            agent_id: agent_id.clone(),
        })
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}

/// Run the guard for one tenant's bundle, aborting (`Err`) before the server
/// serves when any `dw.agent` reference has no entry in the assembled agent map.
///
/// The provided set is sourced from the **assembled** agent map keys
/// ([`build_demo_host_config`], which folds bundle `DwApplication` packs and the
/// `GREENTIC_AW_AGENTS_FILE` overlay), so an env-file agent is honoured.
///
/// Fail-soft on everything *except* a genuine missing-agent difference: if the
/// app pack cannot be resolved or read (e.g. a bundle with no app pack at all),
/// there is nothing to check and the guard is a no-op. Only an actual unprovided
/// `dw.agent` reference is fatal.
pub(crate) fn check_bundle_dw_agents(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
) -> anyhow::Result<()> {
    let provided = assembled_agent_ids(bundle_root, tenant);
    check_bundle_dw_agents_against(bundle_root, tenant, team, &provided)
}

/// Inner seam: identical to [`check_bundle_dw_agents`] but accepts the provided
/// set explicitly, so tests can drive the assembled-map path (or any provided
/// set) without re-reading process env.
pub(crate) fn check_bundle_dw_agents_against(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
    provided: &HashSet<AgentId>,
) -> anyhow::Result<()> {
    // Resolve the app pack the same way the messaging route does. A bundle with
    // no resolvable app pack has no flows to inspect — no-op rather than abort.
    let Ok(app_pack_path) =
        crate::messaging_app::resolve_app_pack_path(bundle_root, tenant, team, None)
    else {
        return Ok(());
    };

    let referenced = match referenced_dw_agents_from_pack(&app_pack_path) {
        Ok(refs) => refs,
        Err(error) => {
            // An unreadable manifest is already reported (and fails) by the
            // messaging app-route validation that runs alongside this guard; do
            // not double-abort here on the same condition.
            operator_log::warn(
                module_path!(),
                format!(
                    "dw.agent pre-flight skipped: cannot read flows from {}: {error:#}",
                    app_pack_path.display()
                ),
            );
            return Ok(());
        }
    };

    if referenced.is_empty() {
        return Ok(());
    }

    match check_dw_agent_references(&referenced, provided) {
        Ok(()) => {
            operator_log::info(
                module_path!(),
                format!(
                    "dw.agent pre-flight passed: {} referenced agent(s) all provided",
                    referenced.len()
                ),
            );
            Ok(())
        }
        Err(missing) => {
            let detail = missing
                .iter()
                .map(MissingAgentRef::render)
                .collect::<Vec<_>>()
                .join("\n");
            bail!(
                "DW_AGENT_NOT_PROVIDED: gtc start refuses to serve because {} dw.agent reference(s) \
                 in this bundle have no provider:\n{detail}",
                missing.len()
            );
        }
    }
}

/// The keys of the tenant's assembled agent map: bundle `DwApplication` packs
/// plus the `GREENTIC_AW_AGENTS_FILE` overlay. This is the **runtime** source of
/// agents — exactly what the agentic-worker node resolves against — so the guard
/// never false-flags an env-file-only agent.
fn assembled_agent_ids(bundle_root: &Path, tenant: &str) -> HashSet<AgentId> {
    build_demo_host_config(tenant, bundle_root)
        .agents
        .keys()
        .cloned()
        .collect()
}

/// Collect every `dw.agent` reference across all compiled flows in `pack_path`'s
/// `manifest.cbor`, as `(flow_id, node_id, agent_id)`.
fn referenced_dw_agents_from_pack(
    pack_path: &Path,
) -> anyhow::Result<Vec<(FlowId, NodeId, AgentId)>> {
    let bytes = read_zip_entry(pack_path, "manifest.cbor")
        .with_context(|| format!("reading manifest.cbor from {}", pack_path.display()))?;
    let manifest: CborValue =
        serde_cbor::from_slice(&bytes).context("decoding pack manifest.cbor")?;
    Ok(referenced_dw_agents_from_manifest(&manifest))
}

/// Pure extraction of `dw.agent` references from a decoded `manifest.cbor`.
///
/// The IR interns component and node ids: `node.component.id` indexes
/// `symbols.component_ids` and `node.id` indexes `symbols.node_ids`. A node is a
/// `dw.agent` reference when its resolved component id equals `"dw.agent"`; the
/// agent id is the node's `component.operation`. Nodes with an empty operation
/// are skipped (no real agent is named).
fn referenced_dw_agents_from_manifest(manifest: &CborValue) -> Vec<(FlowId, NodeId, AgentId)> {
    let mut refs = Vec::new();
    let CborValue::Map(_) = manifest else {
        return refs;
    };

    let component_ids = symbol_table(manifest, "component_ids");
    let node_ids = symbol_table(manifest, "node_ids");

    let Some(CborValue::Array(flows)) = map_get(manifest, "flows") else {
        return refs;
    };

    for flow_entry in flows {
        // `flows[i].id` is the human flow id (plain string in the IR).
        let flow_id = map_get(flow_entry, "id")
            .and_then(as_text)
            .unwrap_or_else(|| "<unknown-flow>".to_string());
        // The node graph lives under the inner `flow` object.
        let Some(inner) = map_get(flow_entry, "flow") else {
            continue;
        };
        let Some(CborValue::Array(nodes)) = map_get(inner, "nodes") else {
            continue;
        };
        for node in nodes {
            let Some(component) = map_get(node, "component") else {
                continue;
            };
            let Some(component_id) = resolve_component_id(component, &component_ids) else {
                continue;
            };
            if component_id != DW_AGENT_COMPONENT_ID {
                continue;
            }
            let Some(agent_id) = map_get(component, "operation").and_then(as_text) else {
                continue;
            };
            if agent_id.is_empty() {
                continue;
            }
            let node_id = resolve_node_id(node, &node_ids);
            refs.push((flow_id.clone(), node_id, agent_id));
        }
    }
    refs
}

// ---------------------------------------------------------------------------
// CBOR helpers (self-contained so the guard does not couple to messaging_app).
// ---------------------------------------------------------------------------

fn read_zip_entry(pack_path: &Path, name: &str) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::File::open(pack_path)
        .with_context(|| format!("opening {}", pack_path.display()))?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut entry = archive
        .by_name(name)
        .with_context(|| format!("pack {} missing {name}", pack_path.display()))?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Read `manifest[key]` for a string key.
fn map_get<'a>(value: &'a CborValue, key: &str) -> Option<&'a CborValue> {
    let CborValue::Map(map) = value else {
        return None;
    };
    map.get(&CborValue::Text(key.to_string()))
}

fn as_text(value: &CborValue) -> Option<String> {
    match value {
        CborValue::Text(text) => Some(text.clone()),
        _ => None,
    }
}

fn as_index(value: &CborValue) -> Option<usize> {
    match value {
        CborValue::Integer(int) if *int >= 0 => usize::try_from(*int).ok(),
        _ => None,
    }
}

/// Read `manifest.symbols.<name>` as a vector of interned strings.
fn symbol_table(manifest: &CborValue, name: &str) -> Vec<String> {
    let Some(symbols) = map_get(manifest, "symbols") else {
        return Vec::new();
    };
    let Some(CborValue::Array(items)) = map_get(symbols, name) else {
        return Vec::new();
    };
    items.iter().filter_map(as_text).collect()
}

/// Resolve a node's component id, whether it is a symbol index (the usual
/// compiled form) or an inline string (defensive).
fn resolve_component_id(component: &CborValue, component_ids: &[String]) -> Option<String> {
    let id = map_get(component, "id")?;
    if let Some(text) = as_text(id) {
        return Some(text);
    }
    let index = as_index(id)?;
    component_ids.get(index).cloned()
}

/// Resolve a node's human-readable id, falling back to the raw index when the
/// symbol table cannot resolve it.
fn resolve_node_id(node: &CborValue, node_ids: &[String]) -> NodeId {
    match map_get(node, "id") {
        Some(value) => {
            if let Some(text) = as_text(value) {
                return text;
            }
            if let Some(index) = as_index(value) {
                if let Some(name) = node_ids.get(index) {
                    return name.clone();
                }
                return format!("#{index}");
            }
            "<unknown-node>".to_string()
        }
        None => "<unknown-node>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn provided_set(ids: &[&str]) -> HashSet<AgentId> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    fn refs(items: &[(&str, &str, &str)]) -> Vec<(FlowId, NodeId, AgentId)> {
        items
            .iter()
            .map(|(flow, node, agent)| (flow.to_string(), node.to_string(), agent.to_string()))
            .collect()
    }

    // --- pure set-difference -------------------------------------------------

    #[test]
    fn missing_reference_is_reported_with_flow_and_node() {
        let provided = provided_set(&["a"]);
        let referenced = refs(&[("flowY", "node1", "demo_assistant")]);

        let error = check_dw_agent_references(&referenced, &provided)
            .expect_err("demo_assistant is not provided");

        assert_eq!(error.len(), 1);
        assert_eq!(error[0].agent_id, "demo_assistant");
        assert_eq!(error[0].flow_id, "flowY");
        assert_eq!(error[0].node_id, "node1");
        let rendered = error[0].render();
        assert!(rendered.contains("demo_assistant"));
        assert!(rendered.contains("flowY"));
        assert!(rendered.contains("node1"));
    }

    #[test]
    fn all_referenced_agents_provided_is_ok() {
        let provided = provided_set(&["a", "demo_assistant"]);
        let referenced = refs(&[
            ("flowY", "node1", "demo_assistant"),
            ("flowZ", "node2", "a"),
        ]);
        assert!(check_dw_agent_references(&referenced, &provided).is_ok());
    }

    #[test]
    fn no_references_is_ok_even_with_no_providers() {
        let provided = provided_set(&[]);
        let referenced = refs(&[]);
        assert!(check_dw_agent_references(&referenced, &provided).is_ok());
    }

    #[test]
    fn every_missing_reference_is_listed() {
        let provided = provided_set(&["present"]);
        let referenced = refs(&[
            ("flowA", "n1", "missing_one"),
            ("flowB", "n2", "present"),
            ("flowC", "n3", "missing_two"),
        ]);
        let error = check_dw_agent_references(&referenced, &provided).expect_err("two missing");
        let agents: Vec<&str> = error.iter().map(|m| m.agent_id.as_str()).collect();
        assert_eq!(agents, vec!["missing_one", "missing_two"]);
    }

    // --- manifest extraction -------------------------------------------------

    fn cbor_map(pairs: Vec<(&str, CborValue)>) -> CborValue {
        CborValue::Map(
            pairs
                .into_iter()
                .map(|(key, value)| (CborValue::Text(key.to_string()), value))
                .collect(),
        )
    }

    fn cbor_array(items: Vec<CborValue>) -> CborValue {
        CborValue::Array(items)
    }

    fn text(value: &str) -> CborValue {
        CborValue::Text(value.to_string())
    }

    fn int(value: i64) -> CborValue {
        CborValue::Integer(value as i128)
    }

    /// A manifest with `component_ids = [card, dw.agent]`, `node_ids = [reply,
    /// research]` and one flow whose `research` node is a `dw.agent` referencing
    /// `tavily_researcher`.
    fn manifest_with_dw_agent() -> CborValue {
        // component_ids[1] == "dw.agent"; node_ids[1] == "research".
        let symbols = cbor_map(vec![
            (
                "component_ids",
                cbor_array(vec![
                    text("ai.greentic.component-adaptive-card"),
                    text("dw.agent"),
                ]),
            ),
            (
                "node_ids",
                cbor_array(vec![text("reply"), text("research")]),
            ),
        ]);
        let research_node = cbor_map(vec![
            ("id", int(1)),
            (
                "component",
                cbor_map(vec![
                    ("id", int(1)),
                    ("operation", text("tavily_researcher")),
                ]),
            ),
        ]);
        let reply_node = cbor_map(vec![
            ("id", int(0)),
            (
                "component",
                cbor_map(vec![("id", int(0)), ("operation", text("card"))]),
            ),
        ]);
        let flow_entry = cbor_map(vec![
            ("id", text("on_message")),
            (
                "flow",
                cbor_map(vec![("nodes", cbor_array(vec![research_node, reply_node]))]),
            ),
        ]);
        cbor_map(vec![
            ("symbols", symbols),
            ("flows", cbor_array(vec![flow_entry])),
        ])
    }

    #[test]
    fn extracts_dw_agent_reference_from_manifest() {
        let manifest = manifest_with_dw_agent();
        let found = referenced_dw_agents_from_manifest(&manifest);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0],
            (
                "on_message".to_string(),
                "research".to_string(),
                "tavily_researcher".to_string()
            )
        );
    }

    #[test]
    fn manifest_without_dw_agent_nodes_yields_no_references() {
        let symbols = cbor_map(vec![
            (
                "component_ids",
                cbor_array(vec![text("ai.greentic.component-adaptive-card")]),
            ),
            ("node_ids", cbor_array(vec![text("welcome")])),
        ]);
        let flow_entry = cbor_map(vec![
            ("id", text("on_message")),
            (
                "flow",
                cbor_map(vec![(
                    "nodes",
                    cbor_array(vec![cbor_map(vec![
                        ("id", int(0)),
                        (
                            "component",
                            cbor_map(vec![("id", int(0)), ("operation", text("card"))]),
                        ),
                    ])]),
                )]),
            ),
        ]);
        let manifest = cbor_map(vec![
            ("symbols", symbols),
            ("flows", cbor_array(vec![flow_entry])),
        ]);
        assert!(referenced_dw_agents_from_manifest(&manifest).is_empty());
    }

    #[test]
    fn dw_agent_node_with_empty_operation_is_skipped() {
        let symbols = cbor_map(vec![
            ("component_ids", cbor_array(vec![text("dw.agent")])),
            ("node_ids", cbor_array(vec![text("research")])),
        ]);
        let flow_entry = cbor_map(vec![
            ("id", text("on_message")),
            (
                "flow",
                cbor_map(vec![(
                    "nodes",
                    cbor_array(vec![cbor_map(vec![
                        ("id", int(0)),
                        (
                            "component",
                            cbor_map(vec![("id", int(0)), ("operation", text(""))]),
                        ),
                    ])]),
                )]),
            ),
        ]);
        let manifest = cbor_map(vec![
            ("symbols", symbols),
            ("flows", cbor_array(vec![flow_entry])),
        ]);
        assert!(referenced_dw_agents_from_manifest(&manifest).is_empty());
    }

    // --- bundle integration (assembled-map path) -----------------------------

    fn write_pack(dir: &Path, name: &str, manifest: &CborValue) -> PathBuf {
        let path = dir.join(name);
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        zip.start_file("manifest.cbor", opts).unwrap();
        zip.write_all(&serde_cbor::to_vec(manifest).unwrap())
            .unwrap();
        zip.finish().unwrap();
        path
    }

    fn application_manifest_referencing(agent_id: &str) -> CborValue {
        let symbols = cbor_map(vec![
            ("component_ids", cbor_array(vec![text("dw.agent")])),
            ("node_ids", cbor_array(vec![text("research")])),
        ]);
        let flow_entry = cbor_map(vec![
            ("id", text("on_message")),
            (
                "flow",
                cbor_map(vec![(
                    "nodes",
                    cbor_array(vec![cbor_map(vec![
                        ("id", int(0)),
                        (
                            "component",
                            cbor_map(vec![("id", int(0)), ("operation", text(agent_id))]),
                        ),
                    ])]),
                )]),
            ),
        ]);
        cbor_map(vec![
            ("kind", text("application")),
            ("pack_id", text("quickstart-demo")),
            ("symbols", symbols),
            ("flows", cbor_array(vec![flow_entry])),
        ])
    }

    #[test]
    fn bundle_with_referenced_but_unprovided_agent_aborts() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = tmp.path().join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        // App pack references `tavily_researcher`; nothing provides it.
        write_pack(
            &packs,
            "default.gtpack",
            &application_manifest_referencing("tavily_researcher"),
        );

        let provided = provided_set(&[]);
        let error = check_bundle_dw_agents_against(tmp.path(), "greentic", None, &provided)
            .expect_err("missing agent must abort start");
        let message = format!("{error:#}");
        assert!(message.contains("DW_AGENT_NOT_PROVIDED"), "got: {message}");
        assert!(message.contains("tavily_researcher"), "got: {message}");
        assert!(message.contains("on_message"), "got: {message}");
    }

    #[test]
    fn bundle_with_provided_agent_passes() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = tmp.path().join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        write_pack(
            &packs,
            "default.gtpack",
            &application_manifest_referencing("tavily_researcher"),
        );

        // The assembled map already contains the agent (as it would when a
        // DwApplication pack — or the env overlay — supplies it).
        let provided = provided_set(&["tavily_researcher"]);
        assert!(check_bundle_dw_agents_against(tmp.path(), "greentic", None, &provided).is_ok());
    }

    /// RESEARCH-SPECIFIC: an agent provided ONLY through the assembled agent map
    /// (e.g. via the `GREENTIC_AW_AGENTS_FILE` overlay) — with NO DwApplication
    /// pack on disk — must be treated as PROVIDED and never flagged. This is the
    /// reason the guard sources `provided` from the assembled-map keys rather
    /// than a filesystem pack rescan.
    #[test]
    fn agent_provided_only_via_assembled_map_overlay_is_not_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = tmp.path().join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        // Only a plain application pack referencing the agent; NO DwApplication
        // pack provides it on disk.
        write_pack(
            &packs,
            "default.gtpack",
            &application_manifest_referencing("env_overlay_agent"),
        );

        // Provided set models the assembled map AFTER the GREENTIC_AW_AGENTS_FILE
        // overlay folded in `env_overlay_agent` — even though no pack exports it.
        let provided = provided_set(&["env_overlay_agent"]);
        assert!(
            check_bundle_dw_agents_against(tmp.path(), "greentic", None, &provided).is_ok(),
            "an agent present in the assembled map (env-file overlay) must not be flagged"
        );
    }

    #[test]
    fn bundle_without_dw_agent_references_is_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = tmp.path().join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        // An application pack whose only node is a card — no dw.agent reference.
        let symbols = cbor_map(vec![
            (
                "component_ids",
                cbor_array(vec![text("ai.greentic.component-adaptive-card")]),
            ),
            ("node_ids", cbor_array(vec![text("welcome")])),
        ]);
        let flow_entry = cbor_map(vec![
            ("id", text("on_message")),
            (
                "flow",
                cbor_map(vec![(
                    "nodes",
                    cbor_array(vec![cbor_map(vec![
                        ("id", int(0)),
                        (
                            "component",
                            cbor_map(vec![("id", int(0)), ("operation", text("card"))]),
                        ),
                    ])]),
                )]),
            ),
        ]);
        let manifest = cbor_map(vec![
            ("kind", text("application")),
            ("pack_id", text("quickstart-demo")),
            ("symbols", symbols),
            ("flows", cbor_array(vec![flow_entry])),
        ]);
        write_pack(&packs, "default.gtpack", &manifest);

        // Empty provided set, but there are no references → still a no-op.
        let provided = provided_set(&[]);
        assert!(check_bundle_dw_agents_against(tmp.path(), "greentic", None, &provided).is_ok());
    }

    #[test]
    fn bundle_without_app_pack_is_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        // No packs directory at all → no app pack resolves → guard is a no-op.
        let provided = provided_set(&[]);
        assert!(check_bundle_dw_agents_against(tmp.path(), "greentic", None, &provided).is_ok());
    }
}
