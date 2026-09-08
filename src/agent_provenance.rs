//! Reply provenance derived from a `dw.agent` node's audit trail.
//!
//! A Designer-authored agentic worker answers a turn with the
//! `greentic-runner-host` `dw.agent` node output contract
//! `{"reply", "trail", "terminated_by"}`.
//! [`crate::messaging_app::parse_envelopes`] turns `reply` into the outbound
//! text bubble; this module turns `trail` into a small, portable provenance
//! object carried on the reply's DirectLine `channelData`, so a chat GUI can
//! render "where did this answer come from" without the operator writing a
//! per-deployment shim.
//!
//! # What the trail actually is
//!
//! `trail` is `Vec<greentic_aw_runtime::AgentStep>`, serialised with
//! `#[serde(tag = "kind", rename_all = "snake_case")]`, so every entry is one
//! of exactly four shapes:
//!
//! ```json
//! {"kind": "tool_call",         "name": "…", "call_id": "…", "result": <any json>}
//! {"kind": "tool_call_reused",  "name": "…", "call_id": "…"}
//! {"kind": "tool_call_blocked", "name": "…", "reason": "…"}
//! {"kind": "reply",             "text": "…"}
//! ```
//!
//! Everything this module emits is read out of those entries. Three
//! consequences are worth stating, because each one is a field a partner has
//! asked for and we cannot honestly produce:
//!
//! - **There is no model name.** The node output carries `reply` / `trail` /
//!   `terminated_by` and nothing else; the model lives in the agent's
//!   `AgentConfig`, which never reaches the flow output. Emitting one would
//!   mean inventing it.
//! - **There is no confidence.** A top-level confidence would have to be
//!   derived (e.g. the best citation score), and a derived number presented
//!   beside real ones reads as a measurement.
//! - **The built-in knowledge/RAG seam produces no trail entries at all.** The
//!   agent loop injects retrieved chunks into the system prompt
//!   (`greentic_aw_runtime::knowledge::augment_system_prompt`) rather than
//!   dispatching a tool, so citations exist here only when the worker calls a
//!   *retrieval tool*, whose result lands verbatim in `AgentStep::ToolCall`.
//!
//! # Why the citation reader has an alias set, and why it is closed
//!
//! `AgentStep::ToolCall.result` is whatever the tool returned — MCP hands back
//! the server's `structuredContent`, a component hands back its own JSON. The
//! platform defines no citation schema, so recognising one means naming field
//! names. The alias set below is deliberately **not** open-ended: it is exactly
//! the union of the two retrieval vocabularies we have actually observed —
//! `greentic_aw_runtime::knowledge::RetrievedChunk` (`text` / `score` /
//! `doc_id` / `metadata`) and the shape 3Point's `rag_search` tool returns
//! (`doc` / `source_file` / `section` / `page` / `excerpt` / `relevance_score`)
//! — plus the camelCase twin of each snake_case name, since a JS-authored MCP
//! server routinely emits the camelCase one. A tool returning something else
//! contributes its NAME to `tools` and no citations, which is the honest
//! answer rather than a guess.
//!
//! # What is deliberately absent
//!
//! - `withheld` (how many documents the caller was not allowed to see) — useful
//!   transparency in some tenants, a disclosure in others. Not a decision to
//!   make globally in v1; it can arrive later behind a per-tenant setting.
//! - `scoped_to` (the caller's own identity) — the browser already knows who it
//!   signed in as.
//! - Blocked tools (`tool_call_blocked`). A blocked tool did not run, and
//!   listing what the agent tried and was denied is the same disclosure
//!   question as `withheld`.
//! - A hardcoded `"type": "rag"`. The trail describes whichever tools ran; a
//!   worker with no retrieval tool still produces a coherent payload.
//!
//! Every field is additive-only from here: a GUI will be reading these names,
//! so adding one later is cheap and removing one is breaking.

use greentic_types::ChannelMessageEnvelope;
use greentic_types::messaging::extensions::ext_keys;
use serde_json::{Map as JsonMap, Value as JsonValue, json};

/// Key this payload occupies inside the reply's DirectLine `channelData`.
///
/// Namespaced rather than written at the `channelData` root so a runner value
/// that already carries `channelData` keeps every key it had.
pub(crate) const CHANNEL_DATA_KEY: &str = "greenticProvenance";

/// Shape version of the payload under [`CHANNEL_DATA_KEY`]. Bump only for a
/// breaking change; new fields are additive and do not move it.
pub(crate) const PROVENANCE_VERSION: u64 = 1;

/// What produced the payload. Constant today (only the `dw.agent` reply arm
/// calls this), but carried explicitly so a second producer cannot be mistaken
/// for this one by a GUI.
const PROVENANCE_SOURCE: &str = "dw.agent";

/// Upper bound on citations carried on one reply. A retrieval tool is free to
/// return hundreds of hits and this payload rides on every outbound activity;
/// the cap keeps a chat transport from carrying a corpus. Ordering is the
/// tool's own (retrieval backends rank by relevance descending), so the cap
/// keeps the best hits.
const MAX_CITATIONS: usize = 20;

/// Result keys whose array value is read as a list of retrieval hits. Kept
/// narrow on purpose: these three name retrieval specifically, whereas a
/// generic `results` array would sweep in every non-retrieval tool's output.
const HIT_ARRAY_KEYS: &[&str] = &["citations", "sources", "chunks"];

/// Document identity. `doc_id` is `RetrievedChunk`'s; `doc` / `title` are the
/// partner shape's.
const DOC_KEYS: &[&str] = &["doc", "doc_id", "docId", "title"];
/// Where the document lives.
const SOURCE_FILE_KEYS: &[&str] = &["source_file", "sourceFile"];
/// Location within the document.
const SECTION_KEYS: &[&str] = &["section"];
/// Page number within the document; read only when it is a number.
const PAGE_KEYS: &[&str] = &["page", "page_number", "pageNumber"];
/// The quoted text. `text` is `RetrievedChunk`'s field name.
const EXCERPT_KEYS: &[&str] = &["excerpt", "text"];
/// Relevance, read only when it is a number. `score` is `RetrievedChunk`'s.
const SCORE_KEYS: &[&str] = &["score", "relevance_score", "relevanceScore"];

/// Attach reply provenance to `envelope` when `output`'s `trail` carries tool
/// activity.
///
/// Call AFTER [`crate::messaging_app::copy_directline_passthrough`], so a
/// runner-supplied `channelData` is already on the envelope and this merges
/// into it rather than being overwritten by it.
///
/// A no-op when the trail is absent, empty, or records no tool that ran — an
/// empty provenance object is worse than none, because a GUI cannot tell "this
/// answer had no sources" from "we lost them".
pub(crate) fn attach_provenance(output: &JsonValue, envelope: &mut ChannelMessageEnvelope) {
    let Some(provenance) = provenance_from_trail(output.get("trail")) else {
        return;
    };

    match envelope.extensions.get_mut(ext_keys::CHANNEL_DATA) {
        // No channelData yet: this reply gets one carrying only our key.
        None => {
            envelope.extensions.insert(
                ext_keys::CHANNEL_DATA.to_string(),
                json!({ CHANNEL_DATA_KEY: provenance }),
            );
        }
        // channelData exists and is an object: merge, never clobber. A runner
        // value that already set this key wins — it knows something we do not.
        Some(JsonValue::Object(existing)) => {
            existing
                .entry(CHANNEL_DATA_KEY.to_string())
                .or_insert(provenance);
        }
        // channelData exists and is not an object. Nothing can be merged into
        // a string or an array without destroying it, and the passthrough
        // value is the runner's, so it stays as-is and provenance is dropped.
        Some(_) => {}
    }
}

/// Build the provenance payload from a `dw.agent` node output's `trail`.
///
/// `None` when the trail is missing, is not an array, or records no
/// `tool_call` / `tool_call_reused` step — i.e. whenever there is no tool
/// activity to describe.
fn provenance_from_trail(trail: Option<&JsonValue>) -> Option<JsonValue> {
    let steps = trail?.as_array()?;

    let mut tools: Vec<String> = Vec::new();
    let mut citations: Vec<JsonValue> = Vec::new();

    for step in steps {
        // `tool_call_blocked` and `reply` are deliberately not read here: a
        // blocked tool did not run, and the reply text is already the bubble.
        // A step with no `kind` at all is skipped, not fatal — the trail is
        // another process's JSON and one unreadable entry must not discard the
        // rest of it.
        let Some(kind) = step.get("kind").and_then(JsonValue::as_str) else {
            continue;
        };
        if kind != "tool_call" && kind != "tool_call_reused" {
            continue;
        }
        let Some(name) = step
            .get("name")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        if !tools.iter().any(|seen| seen == name) {
            tools.push(name.to_string());
        }
        // Only `tool_call` carries a result — `tool_call_reused` records that
        // the ledger replayed one and does not repeat its value.
        if kind == "tool_call"
            && let Some(result) = step.get("result")
        {
            collect_citations(name, result, &mut citations);
        }
    }

    if tools.is_empty() {
        return None;
    }

    let mut payload = JsonMap::new();
    payload.insert("version".to_string(), json!(PROVENANCE_VERSION));
    payload.insert("source".to_string(), json!(PROVENANCE_SOURCE));
    payload.insert("tools".to_string(), json!(tools));
    if !citations.is_empty() {
        payload.insert("citations".to_string(), json!(citations));
    }
    Some(JsonValue::Object(payload))
}

/// Append every recognisable citation in one tool `result` to `into`, stopping
/// at [`MAX_CITATIONS`].
fn collect_citations(tool: &str, result: &JsonValue, into: &mut Vec<JsonValue>) {
    let Some(hits) = hit_array(result) else {
        return;
    };
    for hit in hits {
        if into.len() >= MAX_CITATIONS {
            return;
        }
        if let Some(citation) = citation_from_hit(tool, hit) {
            into.push(citation);
        }
    }
}

/// The array of retrieval hits inside a tool result, if there is one: either
/// the result IS the array, or it holds one under a [`HIT_ARRAY_KEYS`] name.
fn hit_array(result: &JsonValue) -> Option<&Vec<JsonValue>> {
    if let Some(array) = result.as_array() {
        return Some(array);
    }
    HIT_ARRAY_KEYS
        .iter()
        .find_map(|key| result.get(*key).and_then(JsonValue::as_array))
}

/// Map one hit onto a citation, keeping only fields the hit really carries.
///
/// `None` for a hit with no document identity, no file and no excerpt: an
/// entry carrying nothing but a score names no source, and rendering it would
/// show the reader a citation to nowhere.
fn citation_from_hit(tool: &str, hit: &JsonValue) -> Option<JsonValue> {
    let hit = hit.as_object()?;

    let mut citation = JsonMap::new();
    citation.insert("tool".to_string(), json!(tool));

    for (field, aliases) in [
        ("doc", DOC_KEYS),
        ("sourceFile", SOURCE_FILE_KEYS),
        ("section", SECTION_KEYS),
        ("excerpt", EXCERPT_KEYS),
    ] {
        if let Some(text) = first_string(hit, aliases) {
            citation.insert(field.to_string(), json!(text));
        }
    }
    if let Some(page) = first_number(hit, PAGE_KEYS).and_then(|page| page.as_u64()) {
        citation.insert("page".to_string(), json!(page));
    }
    if let Some(score) = first_number(hit, SCORE_KEYS) {
        citation.insert("score".to_string(), score);
    }

    let names_a_source = ["doc", "sourceFile", "excerpt"]
        .iter()
        .any(|field| citation.contains_key(*field));
    names_a_source.then(|| JsonValue::Object(citation))
}

/// First non-empty string under any of `aliases`, looked up on the hit itself
/// and then inside its `metadata` object.
///
/// The `metadata` fallback is what makes the platform's own retrieval shape
/// work: `RetrievedChunk` carries `text` and `score` at the top level and puts
/// everything identifying the document — path, page, section — in `metadata`.
fn first_string(hit: &JsonMap<String, JsonValue>, aliases: &[&str]) -> Option<String> {
    first_field(hit, aliases, |value| {
        value
            .as_str()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    })
}

/// First numeric value under any of `aliases`, with the same `metadata`
/// fallback as [`first_string`]. A score or page arriving as a string is
/// ignored rather than parsed — a tool that types it that way may not mean a
/// number by it.
fn first_number(hit: &JsonMap<String, JsonValue>, aliases: &[&str]) -> Option<JsonValue> {
    first_field(hit, aliases, |value| {
        value.is_number().then(|| value.clone())
    })
}

fn first_field<T>(
    hit: &JsonMap<String, JsonValue>,
    aliases: &[&str],
    accept: impl Fn(&JsonValue) -> Option<T>,
) -> Option<T> {
    let metadata = hit.get("metadata").and_then(JsonValue::as_object);
    for alias in aliases {
        if let Some(found) = hit.get(*alias).and_then(&accept) {
            return Some(found);
        }
        if let Some(found) = metadata.and_then(|meta| meta.get(*alias)).and_then(&accept) {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `dw.agent` node output whose `trail` is exactly what
    /// `greentic_aw_runtime::AgentStep` serialises to.
    fn agent_output(trail: JsonValue) -> JsonValue {
        json!({
            "reply": "The refund window is 30 days.",
            "trail": trail,
            "terminated_by": "final_reply",
        })
    }

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
            "from": { "id": "user-1", "kind": "user" },
            "to": [{ "id": "room-1", "kind": "room" }],
            "text": "hello",
            "metadata": {}
        }))
        .expect("envelope")
    }

    fn provenance_of(envelope: &ChannelMessageEnvelope) -> Option<&JsonValue> {
        envelope
            .extensions
            .get(ext_keys::CHANNEL_DATA)?
            .get(CHANNEL_DATA_KEY)
    }

    #[test]
    fn a_tool_call_with_citations_produces_the_payload() {
        let output = agent_output(json!([
            {
                "kind": "tool_call",
                "name": "rag_search",
                "call_id": "call_1",
                "result": {
                    "citations": [
                        {
                            "doc": "Refund policy",
                            "source_file": "policies/refunds.pdf",
                            "section": "Eligibility",
                            "page": 4,
                            "excerpt": "Refunds are accepted within 30 days.",
                            "relevance_score": 0.96
                        }
                    ]
                }
            },
            { "kind": "reply", "text": "The refund window is 30 days." }
        ]));

        let mut reply = envelope();
        attach_provenance(&output, &mut reply);

        let provenance = provenance_of(&reply).expect("provenance attached");
        assert_eq!(provenance["version"], json!(PROVENANCE_VERSION));
        assert_eq!(provenance["source"], json!("dw.agent"));
        assert_eq!(provenance["tools"], json!(["rag_search"]));
        assert_eq!(
            provenance["citations"],
            json!([{
                "tool": "rag_search",
                "doc": "Refund policy",
                "sourceFile": "policies/refunds.pdf",
                "section": "Eligibility",
                "page": 4,
                "excerpt": "Refunds are accepted within 30 days.",
                "score": 0.96
            }])
        );
    }

    /// The platform's own retrieval shape: `RetrievedChunk` keeps `text` and
    /// `score` at the top level and the document identity in `metadata`.
    #[test]
    fn a_retrieved_chunk_shape_maps_through_metadata() {
        let output = agent_output(json!([{
            "kind": "tool_call",
            "name": "knowledge_search",
            "call_id": "call_1",
            "result": [{
                "text": "Support hours are 09:00-17:00 UTC.",
                "score": 0.71,
                "doc_id": "handbook",
                "chunk_index": 3,
                "metadata": { "source_file": "handbook.md", "page": 12 }
            }]
        }]));

        let mut reply = envelope();
        attach_provenance(&output, &mut reply);

        let provenance = provenance_of(&reply).expect("provenance attached");
        assert_eq!(
            provenance["citations"],
            json!([{
                "tool": "knowledge_search",
                "doc": "handbook",
                "sourceFile": "handbook.md",
                "page": 12,
                "excerpt": "Support hours are 09:00-17:00 UTC.",
                "score": 0.71
            }])
        );
    }

    /// A tool ran but returned nothing citation-shaped: the payload still names
    /// the tool, and carries no `citations` key at all rather than an empty
    /// array a GUI would render as a sources panel with nothing in it.
    #[test]
    fn a_tool_call_without_citations_still_names_the_tool() {
        let output = agent_output(json!([{
            "kind": "tool_call",
            "name": "get_order_status",
            "call_id": "call_1",
            "result": { "status": "shipped" }
        }]));

        let mut reply = envelope();
        attach_provenance(&output, &mut reply);

        let provenance = provenance_of(&reply).expect("provenance attached");
        assert_eq!(provenance["tools"], json!(["get_order_status"]));
        assert!(provenance.get("citations").is_none());
    }

    #[test]
    fn a_trail_with_no_tool_activity_attaches_nothing() {
        for trail in [
            json!([]),
            json!([{ "kind": "reply", "text": "hello" }]),
            // Blocked tools did not run, so they are not tool activity.
            json!([{ "kind": "tool_call_blocked", "name": "delete_user", "reason": "not in allow-list" }]),
            // The agent-graph node's trail shape: node visits, not tool calls.
            json!([{ "node": "agent_1", "kind": "agent", "attempt": 1, "replayed": false }]),
        ] {
            let mut reply = envelope();
            attach_provenance(&agent_output(trail.clone()), &mut reply);
            assert!(
                !reply.extensions.contains_key(ext_keys::CHANNEL_DATA),
                "expected no channelData for trail {trail}"
            );
        }
    }

    #[test]
    fn an_absent_or_malformed_trail_attaches_nothing() {
        for output in [
            json!({ "reply": "hi", "terminated_by": "final_reply" }),
            json!({ "reply": "hi", "trail": null, "terminated_by": "final_reply" }),
            json!({ "reply": "hi", "trail": "not an array" }),
        ] {
            let mut reply = envelope();
            attach_provenance(&output, &mut reply);
            assert!(
                !reply.extensions.contains_key(ext_keys::CHANNEL_DATA),
                "expected no channelData for output {output}"
            );
        }
    }

    /// A reused tool call is real activity (the turn used the tool's result),
    /// so it names the tool — but it carries no result and so no citations.
    #[test]
    fn a_reused_tool_call_names_the_tool_and_repeats_no_citations() {
        let output = agent_output(json!([
            { "kind": "tool_call_reused", "name": "rag_search", "call_id": "call_1" }
        ]));

        let mut reply = envelope();
        attach_provenance(&output, &mut reply);

        let provenance = provenance_of(&reply).expect("provenance attached");
        assert_eq!(provenance["tools"], json!(["rag_search"]));
        assert!(provenance.get("citations").is_none());
    }

    #[test]
    fn tool_names_are_deduped_and_keep_first_call_order() {
        let output = agent_output(json!([
            { "kind": "tool_call", "name": "rag_search", "call_id": "c1", "result": {} },
            { "kind": "tool_call", "name": "get_order", "call_id": "c2", "result": {} },
            { "kind": "tool_call", "name": "rag_search", "call_id": "c3", "result": {} }
        ]));

        let mut reply = envelope();
        attach_provenance(&output, &mut reply);

        let provenance = provenance_of(&reply).expect("provenance attached");
        assert_eq!(provenance["tools"], json!(["rag_search", "get_order"]));
    }

    /// A hit with a score and nothing identifying is a citation to nowhere.
    #[test]
    fn a_hit_naming_no_source_is_not_a_citation() {
        let output = agent_output(json!([{
            "kind": "tool_call",
            "name": "rag_search",
            "call_id": "c1",
            "result": { "sources": [{ "relevance_score": 0.9 }, { "doc": "Handbook" }] }
        }]));

        let mut reply = envelope();
        attach_provenance(&output, &mut reply);

        let provenance = provenance_of(&reply).expect("provenance attached");
        assert_eq!(
            provenance["citations"],
            json!([{ "tool": "rag_search", "doc": "Handbook" }])
        );
    }

    #[test]
    fn citations_are_capped() {
        let hits: Vec<JsonValue> = (0..(MAX_CITATIONS + 5))
            .map(|i| json!({ "doc": format!("doc-{i}") }))
            .collect();
        let output = agent_output(json!([{
            "kind": "tool_call",
            "name": "rag_search",
            "call_id": "c1",
            "result": { "chunks": hits }
        }]));

        let mut reply = envelope();
        attach_provenance(&output, &mut reply);

        let provenance = provenance_of(&reply).expect("provenance attached");
        assert_eq!(
            provenance["citations"].as_array().map(Vec::len),
            Some(MAX_CITATIONS)
        );
    }

    /// A runner-supplied `channelData` keeps every key it had.
    #[test]
    fn an_existing_channel_data_object_is_merged_not_replaced() {
        let output = agent_output(json!([{
            "kind": "tool_call", "name": "rag_search", "call_id": "c1", "result": {}
        }]));

        let mut reply = envelope();
        reply.extensions.insert(
            ext_keys::CHANNEL_DATA.to_string(),
            json!({ "clientActivityID": "abc" }),
        );
        attach_provenance(&output, &mut reply);

        let channel_data = reply
            .extensions
            .get(ext_keys::CHANNEL_DATA)
            .expect("channelData preserved");
        assert_eq!(channel_data["clientActivityID"], json!("abc"));
        assert_eq!(
            channel_data[CHANNEL_DATA_KEY]["tools"],
            json!(["rag_search"])
        );
    }

    /// A runner that already spoke about provenance is authoritative.
    #[test]
    fn an_existing_provenance_key_is_not_overwritten() {
        let output = agent_output(json!([{
            "kind": "tool_call", "name": "rag_search", "call_id": "c1", "result": {}
        }]));

        let mut reply = envelope();
        reply.extensions.insert(
            ext_keys::CHANNEL_DATA.to_string(),
            json!({ CHANNEL_DATA_KEY: { "version": 99 } }),
        );
        attach_provenance(&output, &mut reply);

        assert_eq!(
            provenance_of(&reply).expect("provenance kept")["version"],
            json!(99)
        );
    }

    /// A non-object `channelData` cannot be merged into without destroying it.
    #[test]
    fn a_non_object_channel_data_is_left_alone() {
        let output = agent_output(json!([{
            "kind": "tool_call", "name": "rag_search", "call_id": "c1", "result": {}
        }]));

        let mut reply = envelope();
        reply.extensions.insert(
            ext_keys::CHANNEL_DATA.to_string(),
            json!("opaque runner string"),
        );
        attach_provenance(&output, &mut reply);

        assert_eq!(
            reply.extensions.get(ext_keys::CHANNEL_DATA),
            Some(&json!("opaque runner string"))
        );
    }
}
