//! Embedded LLM routing fallback.
//!
//! When the deterministic tier doesn't resolve a free-text message (the host
//! returned `Continue`, or no host is deployed), this picks the best
//! destination flow/card by asking an LLM — via greentic-start's own reusable
//! [`crate::llm`] capability — to choose from the pack's routing catalog.
//!
//! The catalog is the pack's `assets/intent-index.json` (the same file the
//! deterministic tier uses), so the LLM and the matcher point at the same set
//! of targets. The LLM is constrained to pick an *exact* candidate target or
//! abstain; a hallucinated target is rejected. On any error/abstain we return
//! `None` and the caller degrades to its "I'm not sure" reply.

use std::path::Path;

use serde::Deserialize;

use crate::bundle_config::BundleLlmConfig;
use crate::ingress::control_directive::ControlDirective;
use crate::llm;
use crate::operator_log;
use crate::runner_host::OperatorContext;

use super::contracts::RoutingDirective;
use super::mapper::map_directive_to_control;

/// Default accept threshold when the bundle doesn't set
/// `fast2flow_llm_min_confidence`.
const DEFAULT_LLM_MIN_CONFIDENCE: f32 = 0.5;
/// Cap candidates shown to the model to keep the prompt bounded.
const MAX_CANDIDATES: usize = 40;

/// A routable destination derived from one index entry.
#[derive(Debug, Clone, PartialEq)]
struct Candidate {
    /// `pack/flow/node` (or fewer segments) — what the model must echo back.
    target: String,
    title: String,
    /// Example utterances / tags shown to the model as matching hints.
    hints: Vec<String>,
}

/// The model's structured choice.
#[derive(Debug, Deserialize)]
struct LlmDecision {
    #[serde(default)]
    target: String,
    #[serde(default)]
    confidence: f32,
    #[serde(default)]
    reason: String,
}

// --- Local, tolerant mirror of the fast2flow index manifest (v1 + v2). ---
#[derive(Debug, Deserialize)]
struct IndexManifest {
    #[serde(default)]
    entries: Vec<IndexEntry>,
}

#[derive(Debug, Deserialize)]
struct IndexEntry {
    #[serde(default)]
    target: String,
    #[serde(default)]
    title: String,
    /// v1 carried `titles: Vec<String>`; v2 uses singular `title`.
    #[serde(default)]
    titles: Vec<String>,
    #[serde(default)]
    node_ids: Vec<String>,
    #[serde(default)]
    utterances: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
}

/// Entry point used by the messaging fallback. Reads the index, asks the LLM,
/// and maps a confident choice to a `ControlDirective::Dispatch`. Returns
/// `None` on any miss so the caller falls through to its default reply.
pub fn try_llm_route(
    cfg: &BundleLlmConfig,
    ctx: &OperatorContext,
    index_path: &Path,
    text: &str,
) -> Option<ControlDirective> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    let bytes = std::fs::read(index_path).ok()?;
    let candidates = candidates_from_index(&bytes);
    if candidates.is_empty() {
        operator_log::info(
            module_path!(),
            format!(
                "[fast2flow:llm] no candidates in index {} — skipping",
                index_path.display()
            ),
        );
        return None;
    }

    let provider = cfg.provider.trim();
    let model = resolve_model(cfg);
    let backend =
        match llm::build_backend(provider, &model, resolve_api_key(cfg), cfg.base_url.clone()) {
            Ok(b) => b,
            Err(err) => {
                operator_log::warn(
                    module_path!(),
                    format!("[fast2flow:llm] backend build failed ({provider}/{model}): {err:#}"),
                );
                return None;
            }
        };

    let threshold = cfg
        .fast2flow_llm_min_confidence
        .unwrap_or(DEFAULT_LLM_MIN_CONFIDENCE);
    let decision = decide(&backend, &candidates, text)?;

    if decision.confidence < threshold {
        operator_log::info(
            module_path!(),
            format!(
                "[fast2flow:llm] abstain confidence={:.3} < threshold={:.3} text_len={}",
                decision.confidence,
                threshold,
                text.len()
            ),
        );
        return None;
    }

    // Reject hallucinated targets: the choice must be an exact candidate.
    if !candidates.iter().any(|c| c.target == decision.target) {
        operator_log::warn(
            module_path!(),
            format!(
                "[fast2flow:llm] rejected off-catalog target {:?}",
                decision.target
            ),
        );
        return None;
    }

    operator_log::info(
        module_path!(),
        format!(
            "[fast2flow] dispatch target={} confidence={:.3} reason={:?}",
            decision.target,
            decision.confidence,
            format!("llm:{}", decision.reason)
        ),
    );
    tracing::info!(
        target: "greentic.fast2flow",
        tenant = %ctx.tenant,
        route_target = %decision.target,
        confidence = decision.confidence,
        reason = %format!("llm:{}", decision.reason),
        "fast2flow llm dispatch"
    );

    match map_directive_to_control(
        RoutingDirective::Dispatch {
            target: decision.target,
            confidence: decision.confidence,
            reason: format!("llm:{}", decision.reason),
            entities: Vec::new(),
        },
        ctx,
    ) {
        ControlDirective::Continue => None,
        actionable => Some(actionable),
    }
}

/// Run the LLM and return its decision. Split out so unit tests can drive it
/// with `greentic_llm::mock::TestLlmProvider`.
fn decide(
    provider: &dyn greentic_llm::LlmProvider,
    candidates: &[Candidate],
    text: &str,
) -> Option<LlmDecision> {
    let (system, user) = build_prompt(candidates, text);
    match llm::block_on(llm::chat_json::<LlmDecision>(
        provider,
        &system,
        &user,
        Some(256),
    )) {
        Ok(Ok(decision)) => Some(decision),
        Ok(Err(err)) => {
            operator_log::warn(module_path!(), format!("[fast2flow:llm] {err:#}"));
            None
        }
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!("[fast2flow:llm] runtime bridge failed: {err:#}"),
            );
            None
        }
    }
}

/// Build the (system, user) prompt instructing the model to pick one candidate
/// target or abstain, returning strict JSON.
fn build_prompt(candidates: &[Candidate], text: &str) -> (String, String) {
    let system = "You are a routing assistant for a chat app. Choose the single best \
destination for the user's message from the provided options, or abstain when none fit. \
Respond with ONLY a JSON object and nothing else: \
{\"target\": \"<exact target string, or empty to abstain>\", \"confidence\": <number 0..1>, \"reason\": \"<short>\"}. \
The target MUST be copied verbatim from one of the options. If nothing is a good match, set target to \"\" and confidence to 0."
        .to_string();

    let mut user = String::new();
    user.push_str("User message:\n");
    user.push_str(text);
    user.push_str("\n\nOptions:\n");
    for c in candidates {
        user.push_str("- target: ");
        user.push_str(&c.target);
        user.push('\n');
        if !c.title.is_empty() {
            user.push_str("  title: ");
            user.push_str(&c.title);
            user.push('\n');
        }
        if !c.hints.is_empty() {
            user.push_str("  examples: ");
            user.push_str(&c.hints.join("; "));
            user.push('\n');
        }
    }
    (system, user)
}

/// Parse the index JSON and build the routable candidate list.
fn candidates_from_index(bytes: &[u8]) -> Vec<Candidate> {
    let manifest: IndexManifest = match serde_json::from_slice(bytes) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    manifest
        .entries
        .into_iter()
        .filter_map(|e| {
            let target = routable_target(&e)?;
            let title = if e.title.is_empty() {
                e.titles.into_iter().next().unwrap_or_default()
            } else {
                e.title
            };
            let mut hints = e.utterances;
            hints.extend(e.tags);
            Some(Candidate {
                target,
                title,
                hints,
            })
        })
        .take(MAX_CANDIDATES)
        .collect()
}

/// Compose a routable `pack/flow/node` target. When the entry's `target` has
/// fewer than 3 segments and a node id is available, append the first node so
/// the dispatch resolves to a card.
fn routable_target(e: &IndexEntry) -> Option<String> {
    let base = e.target.trim().trim_matches('/');
    if base.is_empty() {
        return None;
    }
    let segments = base.split('/').filter(|s| !s.trim().is_empty()).count();
    if segments >= 3 {
        return Some(base.to_string());
    }
    match e.node_ids.iter().find(|n| !n.trim().is_empty()) {
        Some(node) => Some(format!("{base}/{}", node.trim())),
        None => Some(base.to_string()),
    }
}

fn resolve_model(cfg: &BundleLlmConfig) -> String {
    if let Some(model) = cfg
        .model
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
    {
        return model.to_string();
    }
    // Per-provider defaults so a provider-only `llm:` block works. Pin a model
    // for production.
    match cfg.provider.trim().to_ascii_lowercase().as_str() {
        "openai" => "gpt-4o-mini",
        "anthropic" => "claude-haiku-4-5",
        "gemini" => "gemini-1.5-flash",
        "groq" => "llama-3.1-8b-instant",
        "deepseek" => "deepseek-chat",
        "ollama" => "llama3.1",
        _ => "",
    }
    .to_string()
}

/// API key for the call: the startup-resolved credential (see
/// [`crate::llm::resolve_credential`]), else a direct env-var lookup for tests.
/// Empty is fine for keyless Ollama.
fn resolve_api_key(cfg: &BundleLlmConfig) -> String {
    if let Some(key) = crate::llm::resolved_api_key().filter(|k| !k.is_empty()) {
        return key.to_string();
    }
    if let Some(name) = cfg
        .api_key_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && let Ok(value) = std::env::var(name)
        && !value.trim().is_empty()
    {
        return value;
    }
    std::env::var("GREENTIC_LLM_API_KEY").unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_llm::mock::TestLlmProviderBuilder;
    use greentic_llm::{ChatResponse, FinishReason};

    const INDEX_V2: &[u8] = br#"{
        "version": "v2",
        "scope": "acme:default",
        "generated_at_ms": 0,
        "entries": [
            {"flow_id":"pipeline_flow","pack_id":"sales-crm","target":"sales-crm/pipeline_flow","title":"View pipeline","node_ids":["pipeline_card"],"utterances":["show my deals"]},
            {"flow_id":"refund_flow","pack_id":"support","target":"support/refund_flow/confirm","title":"Refund"}
        ]
    }"#;

    fn candidates() -> Vec<Candidate> {
        candidates_from_index(INDEX_V2)
    }

    #[test]
    fn candidates_build_routable_three_segment_targets() {
        let c = candidates();
        assert_eq!(c.len(), 2);
        // 2-seg target + node_id → appended to a 3-seg routable target.
        assert_eq!(c[0].target, "sales-crm/pipeline_flow/pipeline_card");
        assert_eq!(c[0].title, "View pipeline");
        assert_eq!(c[0].hints, vec!["show my deals".to_string()]);
        // already 3-seg → unchanged.
        assert_eq!(c[1].target, "support/refund_flow/confirm");
    }

    #[test]
    fn decide_returns_model_choice() {
        let provider = TestLlmProviderBuilder::new()
            .script_response(ChatResponse {
                content: r#"{"target":"sales-crm/pipeline_flow/pipeline_card","confidence":0.82,"reason":"deals"}"#.into(),
                tool_calls: vec![],
                finish_reason: FinishReason::Stop,
            })
            .build();
        let d = decide(&provider, &candidates(), "show my deals").expect("decision");
        assert_eq!(d.target, "sales-crm/pipeline_flow/pipeline_card");
        assert!((d.confidence - 0.82).abs() < 1e-6);
    }

    #[test]
    fn prompt_lists_targets_and_user_text() {
        let (system, user) = build_prompt(&candidates(), "show my deals");
        assert!(system.contains("JSON object"));
        assert!(user.contains("show my deals"));
        assert!(user.contains("sales-crm/pipeline_flow/pipeline_card"));
        assert!(user.contains("support/refund_flow/confirm"));
    }

    #[test]
    fn empty_index_yields_no_candidates() {
        assert!(candidates_from_index(b"{\"entries\":[]}").is_empty());
        assert!(candidates_from_index(b"not json").is_empty());
    }

    #[test]
    fn candidates_use_legacy_titles_tags_and_trimmed_targets() {
        let bytes = br#"{
            "entries": [
                {
                    "target": "/legacy/flow/",
                    "titles": ["Legacy title"],
                    "node_ids": [" first_card "],
                    "utterances": ["open legacy"],
                    "tags": ["legacy", "sales"]
                },
                {"target": "   ", "title": "ignored"}
            ]
        }"#;

        let c = candidates_from_index(bytes);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].target, "legacy/flow/first_card");
        assert_eq!(c[0].title, "Legacy title");
        assert_eq!(
            c[0].hints,
            vec![
                "open legacy".to_string(),
                "legacy".to_string(),
                "sales".to_string()
            ]
        );
    }

    #[test]
    fn candidates_are_capped_to_prompt_limit() {
        let entries = (0..(MAX_CANDIDATES + 5))
            .map(|idx| {
                format!(
                    r#"{{"target":"pack/flow_{idx}","node_ids":["card"],"title":"Flow {idx}"}}"#
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let manifest = format!(r#"{{"entries":[{entries}]}}"#);

        let c = candidates_from_index(manifest.as_bytes());
        assert_eq!(c.len(), MAX_CANDIDATES);
        assert_eq!(
            c.last().map(|candidate| candidate.target.as_str()),
            Some("pack/flow_39/card")
        );
    }

    #[test]
    fn decide_returns_none_when_response_has_no_json() {
        let provider = TestLlmProviderBuilder::new()
            .script_response(ChatResponse {
                content: "I would route to sales".into(),
                tool_calls: vec![],
                finish_reason: FinishReason::Stop,
            })
            .build();

        assert!(decide(&provider, &candidates(), "show my deals").is_none());
    }

    #[test]
    fn resolve_model_uses_provider_defaults_and_explicit_override() {
        let cfg = BundleLlmConfig {
            provider: "openai".to_string(),
            ..Default::default()
        };
        assert_eq!(resolve_model(&cfg), "gpt-4o-mini");

        let cfg = BundleLlmConfig {
            provider: "ollama".to_string(),
            model: Some(" custom-model ".to_string()),
            ..Default::default()
        };
        assert_eq!(resolve_model(&cfg), "custom-model");

        let cfg = BundleLlmConfig {
            provider: "unknown".to_string(),
            ..Default::default()
        };
        assert_eq!(resolve_model(&cfg), "");
    }
}
