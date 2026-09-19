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
//! `#[serde(tag = "kind", rename_all = "snake_case")]`. The entries this
//! module reads are:
//!
//! ```json
//! {"kind": "tool_call",           "name": "…", "call_id": "…", "result": <any json>}
//! {"kind": "tool_call_reused",    "name": "…", "call_id": "…"}
//! {"kind": "knowledge_retrieval", "chunks": [{"text", "score", "doc_id"?, "chunk_index"?, "metadata"}]}
//! ```
//!
//! Every other kind (`tool_call_blocked`, `reply`, `llm_call`, and any kind a
//! newer runtime adds) is skipped, never fatal — the trail is another
//! process's JSON.
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
//!
//! # Built-in knowledge, and why its excerpts are opt-in
//!
//! A worker's BUILT-IN knowledge base (`KnowledgeSettings`) is not a tool: the
//! agent loop retrieves chunks and injects them into the system prompt. Until
//! greentic-runner#770 that left no trail entry, so a knowledge-grounded answer
//! arrived with no citations. The runtime now records the retrieval as
//! `AgentStep::KnowledgeRetrieval`, faithfully and with full chunk text — the
//! trail is server-side data.
//!
//! What reaches the end user's BROWSER is decided here, and the two sources
//! are treated differently on purpose:
//!
//! - A **retrieval tool's** result is something the tool's author chose to
//!   return, and its excerpts have always travelled; that default is kept
//!   (only length-capped, see below).
//! - A **built-in knowledge** chunk is a passage from a document a tenant may
//!   expect the model to USE and not QUOTE. So by default its citation carries
//!   identifying fields only — `doc`, `title`, `sourceFile`, `section`, `page`,
//!   `chunkIndex`, `score` — and **no excerpt text**. Excerpts are included only
//!   when the deployment sets [`KNOWLEDGE_EXCERPTS_ENV`] to a truthy value.
//!
//! That switch is per DEPLOYMENT (one greentic-start process serves one
//! bundle), not per tenant: this reply arm has no per-tenant settings seam to
//! read, and the analogous `withheld` question below is likewise unresolved.
//! A knowledge citation carries `"origin": "knowledge"` and no `tool`.
//!
//! # Size caps
//!
//! This object rides on every reply and is written TWICE (under
//! [`CHANNEL_DATA_KEY`] and [`CHANNEL_DATA_RAG_KEY`]), and the webchat
//! provider stores `channelData` verbatim on every activity. So, for every
//! citation from either source: an excerpt is cut to [`MAX_EXCERPT_CHARS`]
//! characters (marked `"excerptTruncated": true`), at most [`MAX_CITATIONS`]
//! citations are kept, and the serialised object is held under
//! [`MAX_PROVENANCE_BYTES`] by dropping the lowest-ranked citations (marked
//! `"citationsTruncated": true`).
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

/// Second key the SAME payload is written under, for GUIs that read the
/// platform's `rag` name rather than this module's.
///
/// ## Why two names and not a rename
///
/// `greenticProvenance` is what has shipped since this module landed, and a
/// GUI reading it must keep working — renaming a key a partner already parses
/// is the one change that breaks silently on their side. `rag` is the name
/// `greentic_types`' `ext_keys::RAG` already reserves for "RAG component
/// citations/context payload", and the name a 3Point-style chat GUI looks for.
/// Writing both costs a clone of a small object per reply and ends a class of
/// bug worth more than that: a payload arriving correctly under a name nobody
/// is reading looks exactly like no payload at all. That is precisely what
/// happened — provenance shipped on 2026-09-08 and was reported as "the reply
/// arm delivers text only" four days later, because the panel was looking at
/// `channelData.rag`.
///
/// ## What this deliberately does NOT do
///
/// It does not reshape the payload to any external schema. The object is
/// byte-identical under both keys, so nothing here can drift between them. In
/// particular there is still **no `confidence`** and no per-citation
/// `source_type`: the first would have to be derived (see the module doc on
/// why a derived number beside real ones reads as a measurement) and the
/// second names a vocabulary this module does not own. If a consumer's schema
/// requires either, that is a decision to take explicitly — not something to
/// approximate here and hope it renders.
pub(crate) const CHANNEL_DATA_RAG_KEY: &str = "rag";

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

/// Longest excerpt, in characters, carried on one citation. Applies to
/// retrieval-tool excerpts and (when enabled) knowledge excerpts alike: enough
/// to show the reader the passage, never a whole chunk of a corpus.
pub(crate) const MAX_EXCERPT_CHARS: usize = 500;

/// Upper bound on the serialised size of the provenance object. It is written
/// under two keys, so the reply carries at most twice this — well inside the
/// 64 KiB the webchat provider allows a client-posted `channelData`.
pub(crate) const MAX_PROVENANCE_BYTES: usize = 16 * 1024;

/// Deployment switch that lets built-in knowledge citations carry excerpt
/// text. Off unless set to `1` / `true` / `yes` / `on`: a knowledge base may
/// hold documents a tenant expects the model to use and not quote, so quoting
/// them to the browser has to be a decision somebody took.
pub(crate) const KNOWLEDGE_EXCERPTS_ENV: &str = "GREENTIC_PROVENANCE_KNOWLEDGE_EXCERPTS";

/// `origin` value on a citation that came from the built-in knowledge base.
const KNOWLEDGE_ORIGIN: &str = "knowledge";

/// What this reply's provenance may disclose. Read from the environment by
/// [`attach_provenance`]; passed explicitly everywhere else so tests do not
/// depend on process state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DisclosurePolicy {
    /// Include (capped) excerpt text on built-in knowledge citations.
    pub(crate) knowledge_excerpts: bool,
}

impl DisclosurePolicy {
    pub(crate) fn from_env() -> Self {
        Self::from_env_value(std::env::var(KNOWLEDGE_EXCERPTS_ENV).ok().as_deref())
    }

    fn from_env_value(value: Option<&str>) -> Self {
        let knowledge_excerpts = value.is_some_and(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        });
        Self { knowledge_excerpts }
    }
}

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
/// A human-readable document name, read for built-in knowledge chunks (whose
/// `doc_id` is often an opaque id). Looked up in the chunk's `metadata`.
const TITLE_KEYS: &[&str] = &["title", "name", "filename", "file_name", "fileName"];
/// Position of the chunk within its document; read only when it is a number.
const CHUNK_INDEX_KEYS: &[&str] = &["chunk_index", "chunkIndex"];

/// Attach reply provenance to `envelope` when `output`'s `trail` carries tool
/// activity.
///
/// Call AFTER [`crate::messaging_app::copy_directline_passthrough`], so a
/// runner-supplied `channelData` is already on the envelope and this merges
/// into it rather than being overwritten by it.
///
/// A no-op when the trail is absent, empty, or records neither a tool that ran
/// nor a citable knowledge retrieval — an
/// empty provenance object is worse than none, because a GUI cannot tell "this
/// answer had no sources" from "we lost them".
pub(crate) fn attach_provenance(output: &JsonValue, envelope: &mut ChannelMessageEnvelope) {
    attach_provenance_with(output, envelope, DisclosurePolicy::from_env());
}

fn attach_provenance_with(
    output: &JsonValue,
    envelope: &mut ChannelMessageEnvelope,
    policy: DisclosurePolicy,
) {
    let Some(provenance) = provenance_from_trail(output.get("trail"), policy) else {
        return;
    };

    match envelope.extensions.get_mut(ext_keys::CHANNEL_DATA) {
        // No channelData yet: this reply gets one carrying only our keys.
        None => {
            envelope.extensions.insert(
                ext_keys::CHANNEL_DATA.to_string(),
                json!({
                    CHANNEL_DATA_KEY: provenance,
                    CHANNEL_DATA_RAG_KEY: provenance,
                }),
            );
        }
        // channelData exists and is an object: merge, never clobber. A runner
        // value that already set either key wins — it knows something we do
        // not, and that is decided per key: a reply carrying its own `rag`
        // still gets `greenticProvenance`, and the reverse.
        Some(JsonValue::Object(existing)) => {
            existing
                .entry(CHANNEL_DATA_RAG_KEY.to_string())
                .or_insert_with(|| provenance.clone());
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
/// `None` when the trail is missing, is not an array, or records neither a
/// `tool_call` / `tool_call_reused` step nor a knowledge retrieval that yields
/// a citation — i.e. whenever there is nothing to describe.
fn provenance_from_trail(trail: Option<&JsonValue>, policy: DisclosurePolicy) -> Option<JsonValue> {
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
        if kind == "knowledge_retrieval" {
            collect_knowledge_citations(step.get("chunks"), policy, &mut citations);
            continue;
        }
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

    if tools.is_empty() && citations.is_empty() {
        return None;
    }

    let mut payload = JsonMap::new();
    payload.insert("version".to_string(), json!(PROVENANCE_VERSION));
    payload.insert("source".to_string(), json!(PROVENANCE_SOURCE));
    payload.insert("tools".to_string(), json!(tools));
    if !citations.is_empty() {
        payload.insert("citations".to_string(), json!(citations));
    }
    enforce_size_cap(&mut payload);
    Some(JsonValue::Object(payload))
}

/// Hold the serialised payload under [`MAX_PROVENANCE_BYTES`] by dropping
/// citations from the end — the lowest-ranked, since every source orders by
/// relevance — and flag that it happened, so a GUI does not present a partial
/// list as complete. Excerpts are already capped, so this only bites on many
/// long identifiers; it is a backstop, not the main control.
fn enforce_size_cap(payload: &mut JsonMap<String, JsonValue>) {
    let serialised_len =
        |payload: &JsonMap<String, JsonValue>| serde_json::to_vec(payload).map_or(0, |b| b.len());
    if serialised_len(payload) <= MAX_PROVENANCE_BYTES {
        return;
    }
    payload.insert("citationsTruncated".to_string(), json!(true));
    loop {
        let Some(JsonValue::Array(citations)) = payload.get_mut("citations") else {
            return;
        };
        if citations.pop().is_none() {
            payload.remove("citations");
            return;
        }
        if citations.is_empty() {
            payload.remove("citations");
        }
        if serialised_len(payload) <= MAX_PROVENANCE_BYTES {
            return;
        }
    }
}

/// Append a citation for every recognisable chunk of one
/// `knowledge_retrieval` step, stopping at [`MAX_CITATIONS`].
fn collect_knowledge_citations(
    chunks: Option<&JsonValue>,
    policy: DisclosurePolicy,
    into: &mut Vec<JsonValue>,
) {
    let Some(chunks) = chunks.and_then(JsonValue::as_array) else {
        return;
    };
    for chunk in chunks {
        if into.len() >= MAX_CITATIONS {
            return;
        }
        if let Some(citation) = citation_from_knowledge_chunk(chunk, policy) {
            into.push(citation);
        }
    }
}

/// Map one built-in knowledge chunk onto a citation.
///
/// Identifying fields only, unless `policy.knowledge_excerpts` is on — see the
/// module doc. `None` for a chunk that names no document (no `doc`, `title` or
/// `sourceFile`, and no permitted excerpt): a bare score cites nothing.
fn citation_from_knowledge_chunk(chunk: &JsonValue, policy: DisclosurePolicy) -> Option<JsonValue> {
    let chunk = chunk.as_object()?;

    let mut citation = JsonMap::new();
    citation.insert("origin".to_string(), json!(KNOWLEDGE_ORIGIN));

    for (field, aliases) in [
        ("doc", DOC_KEYS),
        ("title", TITLE_KEYS),
        ("sourceFile", SOURCE_FILE_KEYS),
        ("section", SECTION_KEYS),
    ] {
        if let Some(text) = first_string(chunk, aliases) {
            citation.insert(field.to_string(), json!(text));
        }
    }
    // `title` falls back through the same `title` alias `doc` reads, so a chunk
    // with no `doc_id` would otherwise carry its title twice.
    if citation.get("title") == citation.get("doc") {
        citation.remove("title");
    }
    if let Some(page) = first_number(chunk, PAGE_KEYS).and_then(|page| page.as_u64()) {
        citation.insert("page".to_string(), json!(page));
    }
    if let Some(index) = first_number(chunk, CHUNK_INDEX_KEYS).and_then(|index| index.as_u64()) {
        citation.insert("chunkIndex".to_string(), json!(index));
    }
    if let Some(score) = first_number(chunk, SCORE_KEYS) {
        citation.insert("score".to_string(), score);
    }
    if policy.knowledge_excerpts
        && let Some(text) = first_string(chunk, EXCERPT_KEYS)
    {
        insert_capped_excerpt(&mut citation, &text);
    }

    let names_a_source = ["doc", "title", "sourceFile", "excerpt"]
        .iter()
        .any(|field| citation.contains_key(*field));
    names_a_source.then(|| JsonValue::Object(citation))
}

/// Insert `text` as the citation's `excerpt`, cut to [`MAX_EXCERPT_CHARS`]
/// characters (on a char boundary) and flagged when it was cut.
fn insert_capped_excerpt(citation: &mut JsonMap<String, JsonValue>, text: &str) {
    let mut chars = text.char_indices();
    match chars.nth(MAX_EXCERPT_CHARS) {
        None => {
            citation.insert("excerpt".to_string(), json!(text));
        }
        Some((cut, _)) => {
            citation.insert("excerpt".to_string(), json!(text[..cut].trim_end()));
            citation.insert("excerptTruncated".to_string(), json!(true));
        }
    }
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
    ] {
        if let Some(text) = first_string(hit, aliases) {
            citation.insert(field.to_string(), json!(text));
        }
    }
    if let Some(text) = first_string(hit, EXCERPT_KEYS) {
        insert_capped_excerpt(&mut citation, &text);
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
mod runtime_contract_tests;

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

    /// The same object under both names — and byte-identical, so nothing can
    /// drift between them.
    #[test]
    fn the_payload_is_written_under_both_keys() {
        let output = agent_output(json!([{
            "kind": "tool_call", "name": "rag_search", "call_id": "c1",
            "result": { "citations": [{ "doc": "handbook", "excerpt": "x", "score": 0.9 }] }
        }]));

        let mut reply = envelope();
        attach_provenance(&output, &mut reply);

        let cd = reply
            .extensions
            .get(ext_keys::CHANNEL_DATA)
            .expect("channelData");
        let under_provenance = &cd[CHANNEL_DATA_KEY];
        let under_rag = &cd[CHANNEL_DATA_RAG_KEY];

        assert!(!under_rag.is_null(), "a GUI reading `rag` must find it");
        assert_eq!(
            under_provenance, under_rag,
            "the two names must carry the same object, not two shapes"
        );
        assert_eq!(under_rag["tools"], json!(["rag_search"]));
    }

    /// Each key is decided on its own. A reply that already carries its own
    /// `rag` keeps it AND still gets `greenticProvenance` — collapsing the two
    /// into one decision would drop a payload because of an unrelated key.
    #[test]
    fn an_existing_rag_key_is_kept_without_costing_the_other() {
        let output = agent_output(json!([{
            "kind": "tool_call", "name": "rag_search", "call_id": "c1", "result": {}
        }]));

        let mut reply = envelope();
        reply.extensions.insert(
            ext_keys::CHANNEL_DATA.to_string(),
            json!({ CHANNEL_DATA_RAG_KEY: { "mine": true } }),
        );
        attach_provenance(&output, &mut reply);

        let cd = reply.extensions.get(ext_keys::CHANNEL_DATA).expect("cd");
        assert_eq!(cd[CHANNEL_DATA_RAG_KEY]["mine"], json!(true), "runner wins");
        assert_eq!(
            cd[CHANNEL_DATA_KEY]["tools"],
            json!(["rag_search"]),
            "the other key must still be populated"
        );
    }

    /// Nothing is invented to satisfy an external schema. Both are absent on
    /// purpose — see `CHANNEL_DATA_RAG_KEY`'s doc comment.
    #[test]
    fn no_confidence_and_no_source_type_are_invented() {
        let output = agent_output(json!([{
            "kind": "tool_call", "name": "rag_search", "call_id": "c1",
            "result": { "citations": [{ "doc": "d", "excerpt": "e", "score": 0.4 }] }
        }]));

        let mut reply = envelope();
        attach_provenance(&output, &mut reply);
        let rag = &reply.extensions[ext_keys::CHANNEL_DATA][CHANNEL_DATA_RAG_KEY];

        assert!(rag.get("confidence").is_none());
        assert!(rag["citations"][0].get("source_type").is_none());
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

    // ---- greentic-runner#770: built-in knowledge retrieval ----

    fn knowledge_trail() -> JsonValue {
        agent_output(json!([
            {
                "kind": "knowledge_retrieval",
                "chunks": [
                    {
                        "text": "Refunds are accepted within 30 days of purchase.",
                        "score": 0.91,
                        "doc_id": "kb/refunds",
                        "chunk_index": 3,
                        "metadata": { "title": "Refund policy", "page": 2 }
                    }
                ]
            },
            { "kind": "llm_call", "content": "", "tokens_in": 10, "tokens_out": 5 },
            { "kind": "reply", "text": "The refund window is 30 days." }
        ]))
    }

    #[test]
    fn a_knowledge_retrieval_cites_identifying_fields_and_no_excerpt_by_default() {
        let mut reply = envelope();
        attach_provenance_with(&knowledge_trail(), &mut reply, DisclosurePolicy::default());

        let provenance = provenance_of(&reply).expect("knowledge alone produces provenance");
        assert_eq!(provenance["tools"], json!([]), "a retrieval is not a tool");
        assert_eq!(
            provenance["citations"],
            json!([{
                "origin": "knowledge",
                "doc": "kb/refunds",
                "title": "Refund policy",
                "page": 2,
                "chunkIndex": 3,
                "score": 0.91
            }])
        );
        let wire = serde_json::to_string(provenance).expect("serialise");
        assert!(
            !wire.contains("Refunds are accepted"),
            "chunk text must not reach the browser by default: {wire}"
        );
    }

    #[test]
    fn knowledge_excerpts_are_included_when_the_deployment_enables_them() {
        let mut reply = envelope();
        attach_provenance_with(
            &knowledge_trail(),
            &mut reply,
            DisclosurePolicy {
                knowledge_excerpts: true,
            },
        );
        let citation = &provenance_of(&reply).expect("provenance")["citations"][0];
        assert_eq!(
            citation["excerpt"],
            "Refunds are accepted within 30 days of purchase."
        );
        assert!(
            !citation
                .as_object()
                .expect("object")
                .contains_key("excerptTruncated")
        );
    }

    #[test]
    fn an_enabled_knowledge_excerpt_is_capped() {
        let long = "é".repeat(MAX_EXCERPT_CHARS + 40);
        let output = agent_output(json!([
            {
                "kind": "knowledge_retrieval",
                "chunks": [{ "text": long, "score": 0.5, "doc_id": "kb/long", "metadata": {} }]
            }
        ]));
        let mut reply = envelope();
        attach_provenance_with(
            &output,
            &mut reply,
            DisclosurePolicy {
                knowledge_excerpts: true,
            },
        );
        let citation = &provenance_of(&reply).expect("provenance")["citations"][0];
        let excerpt = citation["excerpt"].as_str().expect("excerpt");
        assert_eq!(excerpt.chars().count(), MAX_EXCERPT_CHARS);
        assert_eq!(citation["excerptTruncated"], true);
    }

    #[test]
    fn a_retrieval_tool_excerpt_is_capped_but_still_included_by_default() {
        let long = "x".repeat(MAX_EXCERPT_CHARS * 3);
        let output = agent_output(json!([
            {
                "kind": "tool_call",
                "name": "rag_search",
                "call_id": "c1",
                "result": { "citations": [{ "doc": "Big doc", "excerpt": long }] }
            }
        ]));
        let mut reply = envelope();
        attach_provenance_with(&output, &mut reply, DisclosurePolicy::default());
        let citation = &provenance_of(&reply).expect("provenance")["citations"][0];
        assert_eq!(citation["tool"], "rag_search");
        assert_eq!(
            citation["excerpt"].as_str().expect("excerpt").len(),
            MAX_EXCERPT_CHARS
        );
        assert_eq!(citation["excerptTruncated"], true);
        assert!(
            citation.get("origin").is_none(),
            "tool citations are unchanged"
        );
    }

    #[test]
    fn tool_and_knowledge_citations_travel_together() {
        let output = agent_output(json!([
            {
                "kind": "knowledge_retrieval",
                "chunks": [{ "text": "t", "score": 0.4, "doc_id": "kb/a", "metadata": {} }]
            },
            {
                "kind": "tool_call",
                "name": "rag_search",
                "call_id": "c1",
                "result": { "citations": [{ "doc": "Tool doc", "excerpt": "quoted" }] }
            }
        ]));
        let mut reply = envelope();
        attach_provenance_with(&output, &mut reply, DisclosurePolicy::default());
        let provenance = provenance_of(&reply).expect("provenance");
        assert_eq!(provenance["tools"], json!(["rag_search"]));
        let citations = provenance["citations"].as_array().expect("citations");
        assert_eq!(citations.len(), 2);
        assert_eq!(citations[0]["origin"], "knowledge");
        assert_eq!(citations[1]["excerpt"], "quoted");
    }

    #[test]
    fn a_knowledge_chunk_naming_no_document_is_not_a_citation() {
        let output = agent_output(json!([
            { "kind": "knowledge_retrieval", "chunks": [{ "text": "t", "score": 0.4, "metadata": {} }] }
        ]));
        let mut reply = envelope();
        attach_provenance_with(&output, &mut reply, DisclosurePolicy::default());
        assert!(
            !reply.extensions.contains_key(ext_keys::CHANNEL_DATA),
            "an unattributable chunk with its text withheld cites nothing"
        );
    }

    #[test]
    fn the_whole_object_is_held_under_the_size_cap() {
        let hits: Vec<JsonValue> = (0..MAX_CITATIONS)
            .map(|i| {
                json!({
                    "doc": format!("{i}-{}", "d".repeat(MAX_EXCERPT_CHARS)),
                    "source_file": "s".repeat(MAX_EXCERPT_CHARS),
                    "section": "x".repeat(MAX_EXCERPT_CHARS),
                    "excerpt": "e".repeat(MAX_EXCERPT_CHARS * 2)
                })
            })
            .collect();
        let output = agent_output(json!([
            { "kind": "tool_call", "name": "rag_search", "call_id": "c1", "result": { "citations": hits } }
        ]));
        let mut reply = envelope();
        attach_provenance_with(&output, &mut reply, DisclosurePolicy::default());
        let provenance = provenance_of(&reply).expect("provenance");
        let size = serde_json::to_vec(provenance).expect("serialise").len();
        assert!(size <= MAX_PROVENANCE_BYTES, "{size} bytes");
        assert_eq!(provenance["citationsTruncated"], true);
        let kept = provenance["citations"].as_array().expect("citations");
        assert!(!kept.is_empty() && kept.len() < MAX_CITATIONS);
        assert!(
            kept[0]["doc"].as_str().expect("doc").starts_with("0-"),
            "best hits kept"
        );
    }

    #[test]
    fn the_knowledge_excerpt_switch_is_off_unless_explicitly_truthy() {
        assert!(!DisclosurePolicy::from_env_value(None).knowledge_excerpts);
        for off in ["", "0", "false", "no", "off", "maybe"] {
            assert!(
                !DisclosurePolicy::from_env_value(Some(off)).knowledge_excerpts,
                "{off}"
            );
        }
        for on in ["1", "true", "YES", " on "] {
            assert!(
                DisclosurePolicy::from_env_value(Some(on)).knowledge_excerpts,
                "{on}"
            );
        }
    }

    #[test]
    fn an_unknown_trail_kind_is_skipped() {
        let output = agent_output(json!([
            { "kind": "some_future_kind", "payload": 1 },
            { "kind": "tool_call", "name": "lookup", "call_id": "c", "result": {} }
        ]));
        let mut reply = envelope();
        attach_provenance_with(&output, &mut reply, DisclosurePolicy::default());
        assert_eq!(
            provenance_of(&reply).expect("provenance")["tools"],
            json!(["lookup"])
        );
    }
}
