//! Reusable LLM access wrapping `greentic-llm` (rig-core, 9 providers).
//! Routing-agnostic; any feature can reuse it: [`build_backend`], [`chat_json`]
//! (structured output via JSON prompting — `RigBackend` has no tool calling),
//! and [`block_on`] (sync→async bridge).

use std::path::Path;
use std::str::FromStr;
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};
use greentic_llm::{
    ChatMessage, ChatRequest, Credential, LlmProvider, MessageRole, ProviderKind, RigBackend,
};
use serde::de::DeserializeOwned;

use crate::bundle_config::BundleLlmConfig;
use crate::operator_log;

/// The bundle's `llm:` instance, peeked once at startup. Shared by every LLM
/// consumer. `None` ⇒ no LLM declared.
static LLM_CONFIG: OnceLock<Option<BundleLlmConfig>> = OnceLock::new();

/// Credential resolved once at startup. `None` ⇒ keyless (Ollama).
static RESOLVED_API_KEY: OnceLock<Option<String>> = OnceLock::new();

/// Store the peeked `llm:` block. Call once, early in startup.
pub fn set_config(cfg: Option<BundleLlmConfig>) {
    let _ = LLM_CONFIG.set(cfg);
}

/// The configured `llm:` instance, if the bundle declared one.
pub fn config() -> Option<&'static BundleLlmConfig> {
    LLM_CONFIG.get().and_then(|o| o.as_ref())
}

/// Cache the credential resolved at startup. Call once, after [`set_config`].
pub fn set_resolved_api_key(key: Option<String>) {
    let _ = RESOLVED_API_KEY.set(key);
}

/// The credential resolved at startup, if any.
pub fn resolved_api_key() -> Option<&'static str> {
    RESOLVED_API_KEY.get().and_then(|o| o.as_deref())
}

/// Resolve the credential from `cfg.api_key_secret`: a `secrets://…` ref reads
/// the dev-store, otherwise it's an env-var name. Falls back to
/// `GREENTIC_LLM_API_KEY`. `None` is fine for keyless Ollama.
pub fn resolve_credential(cfg: &BundleLlmConfig, bundle_root: &Path) -> Option<String> {
    if let Some(reference) = cfg
        .api_key_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if reference.starts_with("secret://") || reference.starts_with("secrets://") {
            match read_store_secret(bundle_root, reference) {
                Some(value) => return Some(value),
                None => operator_log::warn(
                    module_path!(),
                    format!(
                        "[llm] secret reference {reference:?} not found in the dev store — \
                         the LLM will have no credential"
                    ),
                ),
            }
        } else if let Ok(value) = std::env::var(reference) {
            let value = value.trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    std::env::var("GREENTIC_LLM_API_KEY")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Read a `secrets://…` reference from the bundle's dev-store.
fn read_store_secret(bundle_root: &Path, uri: &str) -> Option<String> {
    use greentic_secrets_lib::SecretsManager as _;
    let client = crate::secrets_client::SecretsClient::open(bundle_root).ok()?;
    let uri = uri.to_string();
    let bytes = block_on(async move { client.read(&uri).await })
        .ok()?
        .ok()?;
    let value = String::from_utf8(bytes).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// Build a `greentic-llm` backend for `provider`. `api_key` may be empty for
/// keyless providers (Ollama); `base_url` overrides the default endpoint.
pub fn build_backend(
    provider: &str,
    model: &str,
    api_key: String,
    base_url: Option<String>,
) -> Result<RigBackend> {
    let kind = ProviderKind::from_str(provider)
        .map_err(|e| anyhow!("unsupported llm provider {provider:?}: {e}"))?;
    let cred = Credential {
        api_key,
        base_url,
        expires_at: None,
    };
    RigBackend::new(kind, model, &cred)
        .map_err(|e| anyhow!("build {provider} llm backend (model={model}): {e}"))
}

/// One-shot completion expecting a JSON object back, deserialized into `T`.
/// Two-turn chat at temperature 0; extracts the first balanced JSON object from
/// the reply (tolerating code fences and prose).
pub async fn chat_json<T: DeserializeOwned>(
    provider: &dyn LlmProvider,
    system: &str,
    user: &str,
    max_tokens: Option<u32>,
) -> Result<T> {
    let mut messages = Vec::with_capacity(2);
    if !system.trim().is_empty() {
        messages.push(ChatMessage {
            role: MessageRole::System,
            content: system.to_string(),
            images: Vec::new(),
        });
    }
    messages.push(ChatMessage {
        role: MessageRole::User,
        content: user.to_string(),
        images: Vec::new(),
    });

    let req = ChatRequest {
        messages,
        tools: Vec::new(),
        tool_choice: None,
        max_tokens,
        temperature: Some(0.0),
    };
    let resp = provider
        .chat(req)
        .await
        .map_err(|e| anyhow!("llm chat failed: {e}"))?;
    let json = extract_json_object(&resp.content)
        .ok_or_else(|| anyhow!("no JSON object in llm response: {:?}", resp.content))?;
    serde_json::from_str::<T>(json).with_context(|| format!("decode llm json response: {json:?}"))
}

/// Extract the first balanced `{...}` JSON object from free text. Tracks string
/// literals and escapes so braces inside strings don't unbalance the scan.
/// Returns `None` when no balanced object is present.
pub fn extract_json_object(content: &str) -> Option<&str> {
    let bytes = content.as_bytes();
    let start = content.find('{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, &b) in bytes[start..].iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&content[start..=start + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Drive an async future from sync code (mirrors [`crate::runtime`]): hop off
/// the worker when inside a runtime, else spin a temporary one.
pub fn block_on<F>(fut: F) -> Result<F::Output>
where
    F: std::future::Future,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => Ok(tokio::task::block_in_place(|| handle.block_on(fut))),
        Err(_) => Ok(tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build temporary tokio runtime for llm call")?
            .block_on(fut)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bare_object() {
        let s = r#"{"target":"a/b/c","confidence":0.9}"#;
        assert_eq!(extract_json_object(s), Some(s));
    }

    #[test]
    fn extracts_object_from_fenced_and_prose() {
        let s = "Here you go:\n```json\n{\"target\":\"a/b\",\"reason\":\"x\"}\n```\nthanks";
        assert_eq!(
            extract_json_object(s),
            Some("{\"target\":\"a/b\",\"reason\":\"x\"}")
        );
    }

    #[test]
    fn ignores_braces_inside_strings() {
        let s = r#"{"reason":"use {curly} braces","target":"a/b"}"#;
        assert_eq!(extract_json_object(s), Some(s));
    }

    #[test]
    fn none_when_unbalanced_or_absent() {
        assert_eq!(extract_json_object("no json here"), None);
        assert_eq!(extract_json_object("{\"a\":1"), None);
    }
}
