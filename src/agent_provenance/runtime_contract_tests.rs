//! The provenance contract, checked against the REAL agent runtime.
//!
//! Every other test in this module feeds a hand-written `trail`. That proves
//! the reader, not the contract: nothing there fails if the runtime this binary
//! is built against never records a retrieval at all — which is exactly what
//! shipped until greentic-start#595 moved this binary onto the greentic-runner
//! that carries #773 (`AgentStep::KnowledgeRetrieval`).
//!
//! Here the trail comes from `greentic_aw_runtime::AgentRuntime::step` — the
//! crate resolved into this binary's own graph — driven by a stub LLM and a
//! stub knowledge backend that returns chunks, and it is wrapped exactly the
//! way greentic-runner-host's `dw.agent` node wraps an `AgentOutput`
//! (`{"reply", "trail", "terminated_by", "usage"}`). If the runtime stops
//! emitting the step, or its serialised shape drifts from what this module
//! reads, this test fails.

use std::sync::Arc;

use greentic_aw_runtime::config::KnowledgeSettings;
use greentic_aw_runtime::knowledge::RetrievedChunk;
use greentic_aw_runtime::mock::{
    MockAgentStateStore, MockConfigProvider, MockKnowledge, MockLlmBackend, MockTelemetry,
    NoopToolLedger,
};
use greentic_aw_runtime::{
    AgentConfig, AgentInput, AgentLimits, AgentRuntime, LlmProviderRef, LlmResponse,
    MemoryProviderRef, MockTokenMeter, TenantContext,
};
use greentic_ext_runtime::ExtensionRuntime;
use serde_json::{Value as JsonValue, json};

use greentic_types::ChannelMessageEnvelope;
use greentic_types::messaging::extensions::ext_keys;

use super::{CHANNEL_DATA_KEY, CHANNEL_DATA_RAG_KEY, DisclosurePolicy, attach_provenance_with};

const AGENT: &str = "support-agent";
const CHUNK_TEXT: &str = "Refunds are processed within 5 business days.";

fn agent_config() -> AgentConfig {
    AgentConfig {
        agent_id: AGENT.into(),
        system_prompt: "You answer refund questions.".into(),
        tools: vec![],
        guardrails: vec![],
        llm: LlmProviderRef {
            provider: "openai".into(),
            model: "stub".into(),
            credential_ref: None,
        },
        limits: AgentLimits::default(),
        memory: None,
        knowledge: Some(KnowledgeSettings {
            knowledge: Some(MemoryProviderRef {
                provider: "provider.knowledge.chronicle".into(),
                capability: "cap://dw.knowledge".into(),
                params: serde_json::Map::new(),
                credential_ref: None,
            }),
            embedding: None,
            top_k: 3,
        }),
        conversational: false,
        opening_message: None,
    }
}

/// Run one real agent turn whose knowledge backend returns `chunks`, and
/// return the `dw.agent` node output greentic-runner-host builds from it.
async fn dw_agent_node_output(chunks: Vec<RetrievedChunk>) -> JsonValue {
    let tenant = TenantContext::new("acme", "prod");
    let configs = MockConfigProvider::new();
    configs.insert(&tenant, AGENT, agent_config());

    let llm = Arc::new(MockLlmBackend::new(vec![Ok(LlmResponse {
        content: Some("Refunds take up to 5 business days.".into()),
        tool_calls: vec![],
        tokens_in: 1,
        tokens_out: 1,
    })]));
    let ext = Arc::new(ExtensionRuntime::for_test().expect("test extension runtime"));

    let runtime = AgentRuntime::new(
        Arc::new(configs),
        Arc::new(MockAgentStateStore::new()),
        ext,
        llm,
        Arc::new(MockTelemetry::new()),
        Arc::new(MockTokenMeter::new(0)),
        Arc::new(NoopToolLedger),
        None,
    )
    .with_knowledge(Arc::new(MockKnowledge::new(chunks)));

    let output = runtime
        .step(
            tenant,
            "sess-595",
            AGENT,
            AgentInput {
                text: "How long do refunds take?".into(),
                ..Default::default()
            },
        )
        .await
        .expect("agent turn");

    // Byte-for-byte the object greentic-runner-host's `dw.agent` handler
    // returns for a successful turn (runner/agent_node.rs).
    json!({
        "reply": output.reply,
        "trail": output.trail,
        "terminated_by": output.terminated_by,
        "usage": output.usage,
    })
}

fn reply_envelope() -> ChannelMessageEnvelope {
    serde_json::from_value(json!({
        "id": "msg-595",
        "tenant": {
            "env": "prod",
            "tenant": "acme",
            "tenant_id": "acme",
            "team": "default",
            "attempt": 0
        },
        "channel": "conv-595",
        "session_id": "conv-595",
        "from": { "id": "bot", "kind": "agent" },
        "to": [{ "id": "user-1", "kind": "user" }],
        "text": "Refunds take up to 5 business days.",
        "metadata": {}
    }))
    .expect("envelope")
}

fn refund_chunk() -> RetrievedChunk {
    let mut metadata = serde_json::Map::new();
    metadata.insert("title".into(), json!("Refund policy"));
    metadata.insert("page".into(), json!(2));
    RetrievedChunk {
        text: CHUNK_TEXT.into(),
        score: 0.9,
        doc_id: Some("kb/refunds".into()),
        chunk_index: Some(3),
        metadata,
    }
}

#[tokio::test]
async fn a_real_knowledge_retrieval_reaches_channel_data_rag_as_a_knowledge_citation() {
    let output = dw_agent_node_output(vec![refund_chunk()]).await;

    // The runtime really recorded the retrieval, as the kind this module reads.
    let kinds: Vec<&str> = output["trail"]
        .as_array()
        .expect("trail is an array")
        .iter()
        .filter_map(|step| step["kind"].as_str())
        .collect();
    assert!(
        kinds.contains(&"knowledge_retrieval"),
        "runtime trail has no knowledge_retrieval step: {kinds:?}"
    );

    let mut reply = reply_envelope();
    attach_provenance_with(&output, &mut reply, DisclosurePolicy::default());

    let channel_data = reply
        .extensions
        .get(ext_keys::CHANNEL_DATA)
        .expect("channelData attached");
    let rag = &channel_data[CHANNEL_DATA_RAG_KEY];
    assert_eq!(rag["tools"], json!([]), "a retrieval is not a tool: {rag}");
    assert_eq!(
        rag["citations"],
        json!([{
            "origin": "knowledge",
            "doc": "kb/refunds",
            "title": "Refund policy",
            "page": 2,
            "chunkIndex": 3,
            "score": 0.9
        }]),
        "unexpected rag citations: {rag}"
    );
    assert_eq!(
        channel_data[CHANNEL_DATA_KEY], *rag,
        "greenticProvenance and rag carry the same object"
    );

    // Default disclosure: identifying fields only, never the chunk text.
    let wire = serde_json::to_string(channel_data).expect("serialise");
    assert!(
        !wire.contains(CHUNK_TEXT),
        "chunk text must not reach the browser by default: {wire}"
    );
}

#[tokio::test]
async fn an_empty_real_retrieval_attaches_no_provenance() {
    let output = dw_agent_node_output(Vec::new()).await;

    let mut reply = reply_envelope();
    attach_provenance_with(&output, &mut reply, DisclosurePolicy::default());

    assert!(
        !reply.extensions.contains_key(ext_keys::CHANNEL_DATA),
        "nothing retrieved and no tool ran, so there is nothing to cite: {:?}",
        reply.extensions
    );
}
