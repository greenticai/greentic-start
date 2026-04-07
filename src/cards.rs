use anyhow::{Result, anyhow};
use serde_json::{Map, Value};

use crate::capabilities::CAP_OAUTH_CARD_V1;

/// Lightweight renderer that delegates OAuth card resolution to
/// `greentic.cap.oauth.card.v1` capability (provided by greentic-oauth).
#[derive(Clone, Default)]
pub struct CardRenderer;

/// Outcome from attempting to render a provider card.
pub struct RenderOutcome {
    pub bytes: Vec<u8>,
}

impl CardRenderer {
    /// Create a no-op renderer.
    pub fn new() -> Self {
        Self
    }

    /// Resolve OAuth card placeholders via `greentic.cap.oauth.card.v1/oauth.card.resolve`
    /// when present; otherwise return the original payload unchanged.
    pub fn render_if_needed<F>(
        &self,
        provider_type: &str,
        payload_bytes: &[u8],
        mut resolve_capability: F,
    ) -> Result<RenderOutcome>
    where
        F: FnMut(&str, &str, &[u8]) -> Result<Value>,
    {
        let mut payload_json: Value = match serde_json::from_slice(payload_bytes) {
            Ok(value) => value,
            Err(_) => {
                return Ok(RenderOutcome {
                    bytes: payload_bytes.to_vec(),
                });
            }
        };
        let Some(_) = payload_json.as_object() else {
            return Ok(RenderOutcome {
                bytes: payload_bytes.to_vec(),
            });
        };
        let Some(adaptive_card_raw) = payload_json
            .pointer("/metadata/adaptive_card")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            return Ok(RenderOutcome {
                bytes: payload_bytes.to_vec(),
            });
        };
        // Lightweight pre-flight: skip capability call if no OAuth markers present.
        let has_placeholder = adaptive_card_raw.contains("{{oauth.start_url}}")
            || adaptive_card_raw.contains("{{oauth.teams.connectionName}}")
            || adaptive_card_raw.contains("oauth://start");
        let request_seed = payload_json
            .pointer("/metadata/oauth_card_request")
            .and_then(Value::as_object)
            .cloned();
        if !has_placeholder && request_seed.is_none() {
            return Ok(RenderOutcome {
                bytes: payload_bytes.to_vec(),
            });
        }
        let mut request_payload =
            build_card_resolve_request(request_seed, &payload_json, provider_type);
        // Pass the raw card to the capability so it can do the rewriting.
        if let Some(obj) = request_payload.as_object_mut() {
            obj.insert(
                "adaptive_card".to_string(),
                Value::String(adaptive_card_raw),
            );
        }
        let resolve_result = resolve_capability(
            CAP_OAUTH_CARD_V1,
            "oauth.card.resolve",
            &serde_json::to_vec(&request_payload)?,
        )?;
        // The capability returns the fully resolved card — just swap it in.
        let resolved_card = resolve_result
            .get("resolved_card")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("oauth.card.resolve output missing resolved_card"))?;
        if let Some(metadata) = payload_json
            .pointer_mut("/metadata")
            .and_then(Value::as_object_mut)
        {
            metadata.insert(
                "adaptive_card".to_string(),
                Value::String(resolved_card.to_string()),
            );
            // Store resolve audit without the card (already in adaptive_card).
            let mut audit = resolve_result.clone();
            if let Some(obj) = audit.as_object_mut() {
                obj.remove("resolved_card");
            }
            metadata.insert("oauth_card_resolved".to_string(), audit);
            if let Some(downgrade) = resolve_result.get("downgrade").filter(|v| !v.is_null()) {
                metadata.insert("oauth_card_downgrade".to_string(), downgrade.clone());
            }
        }
        let rendered = serde_json::to_vec(&payload_json)?;
        Ok(RenderOutcome { bytes: rendered })
    }
}

fn build_card_resolve_request(
    seed: Option<Map<String, Value>>,
    payload: &Value,
    provider_type: &str,
) -> Value {
    let mut request = seed.unwrap_or_default();
    if !request.contains_key("provider_type") {
        request.insert(
            "provider_type".to_string(),
            Value::String(provider_type.to_string()),
        );
    }
    if !request.contains_key("tenant")
        && let Some(tenant) = payload
            .pointer("/tenant/tenant_id")
            .or_else(|| payload.pointer("/tenant/tenant"))
            .and_then(Value::as_str)
    {
        request.insert("tenant".to_string(), Value::String(tenant.to_string()));
    }
    if !request.contains_key("team")
        && let Some(team) = payload
            .pointer("/tenant/team_id")
            .or_else(|| payload.pointer("/tenant/team"))
            .and_then(Value::as_str)
    {
        request.insert("team".to_string(), Value::String(team.to_string()));
    }
    if !request.contains_key("provider_id")
        && let Some(provider_id) = payload
            .pointer("/metadata/oauth_provider_id")
            .or_else(|| payload.pointer("/metadata/provider_id"))
            .and_then(Value::as_str)
    {
        request.insert(
            "provider_id".to_string(),
            Value::String(provider_id.to_string()),
        );
    }
    Value::Object(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn oauth_card_resolve_swaps_resolved_card() {
        let renderer = CardRenderer::new();
        let payload = json!({
            "tenant": { "tenant_id": "demo", "team_id": "default" },
            "metadata": {
                "adaptive_card": "{\"type\":\"AdaptiveCard\",\"actions\":[{\"type\":\"Action.OpenUrl\",\"title\":\"Connect\",\"url\":\"oauth://start\"}],\"connectionName\":\"{{oauth.teams.connectionName}}\"}",
                "oauth_provider_id": "google"
            }
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let output = renderer
            .render_if_needed("messaging.teams", &bytes, |cap_id, op, _input| {
                assert_eq!(cap_id, CAP_OAUTH_CARD_V1);
                assert_eq!(op, "oauth.card.resolve");
                Ok(json!({
                    "ok": true,
                    "resolved_card": "{\"type\":\"AdaptiveCard\",\"actions\":[{\"type\":\"Action.OpenUrl\",\"title\":\"Connect\",\"url\":\"https://oauth.example/start/session\"}],\"connectionName\":\"greentic-oauth\"}",
                    "start_url": "https://oauth.example/start/session",
                    "native_oauth_card": true,
                    "teams": { "connectionName": "greentic-oauth" },
                    "downgrade": null
                }))
            })
            .expect("render");
        let rendered: Value = serde_json::from_slice(&output.bytes).expect("json");
        let card_raw = rendered
            .pointer("/metadata/adaptive_card")
            .and_then(Value::as_str)
            .expect("adaptive_card");
        let card_json: Value = serde_json::from_str(card_raw).expect("card json");
        assert_eq!(
            card_json.pointer("/actions/0/url").and_then(Value::as_str),
            Some("https://oauth.example/start/session")
        );
        assert_eq!(
            card_json.get("connectionName").and_then(Value::as_str),
            Some("greentic-oauth")
        );
        assert_eq!(
            rendered
                .pointer("/metadata/oauth_card_resolved/start_url")
                .and_then(Value::as_str),
            Some("https://oauth.example/start/session")
        );
        // resolved_card should be stripped from audit metadata (already in adaptive_card).
        assert!(
            rendered
                .pointer("/metadata/oauth_card_resolved/resolved_card")
                .is_none(),
            "resolved_card should not be duplicated in audit metadata"
        );
    }

    #[test]
    fn oauth_card_downgrade_propagated_from_capability() {
        let renderer = CardRenderer::new();
        let payload = json!({
            "tenant": { "tenant_id": "demo", "team_id": "default" },
            "metadata": {
                "adaptive_card": "{\"type\":\"AdaptiveCard\",\"actions\":[{\"type\":\"Action.OpenUrl\",\"title\":\"Connect\",\"url\":\"oauth://start\"}],\"connectionName\":\"{{oauth.teams.connectionName}}\"}",
                "oauth_provider_id": "google"
            }
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let output = renderer
            .render_if_needed("messaging.telegram", &bytes, |_cap_id, _op, _input| {
                Ok(json!({
                    "ok": true,
                    "resolved_card": "{\"type\":\"AdaptiveCard\",\"actions\":[{\"type\":\"Action.OpenUrl\",\"title\":\"Connect\",\"url\":\"https://oauth.example/start/session\"}]}",
                    "start_url": "https://oauth.example/start/session",
                    "native_oauth_card": false,
                    "teams": { "connectionName": null },
                    "downgrade": {
                        "mode": "non_native_fallback",
                        "reason": "teams_connection_name_unavailable"
                    }
                }))
            })
            .expect("render");
        let rendered: Value = serde_json::from_slice(&output.bytes).expect("json");
        let card_raw = rendered
            .pointer("/metadata/adaptive_card")
            .and_then(Value::as_str)
            .expect("adaptive_card");
        let card_json: Value = serde_json::from_str(card_raw).expect("card json");
        assert_eq!(
            card_json.pointer("/actions/0/url").and_then(Value::as_str),
            Some("https://oauth.example/start/session")
        );
        assert!(
            card_json.get("connectionName").is_none(),
            "non-teams provider should not have connectionName"
        );
        assert_eq!(
            rendered
                .pointer("/metadata/oauth_card_downgrade/mode")
                .and_then(Value::as_str),
            Some("non_native_fallback")
        );
    }
}
