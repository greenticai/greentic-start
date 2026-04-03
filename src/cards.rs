use anyhow::{Context, Result, anyhow};
use serde_json::{Map, Value};

use crate::capabilities::CAP_OAUTH_CARD_V1;

/// Lightweight renderer that used to downgrade message_card payloads.
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
        let mut adaptive_card: Value = serde_json::from_str(&adaptive_card_raw)
            .with_context(|| "invalid metadata.adaptive_card JSON")?;
        let had_teams_placeholder = adaptive_card_raw.contains("{{oauth.teams.connectionName}}");
        let has_placeholder = adaptive_card_raw.contains("{{oauth.start_url}}")
            || adaptive_card_raw.contains("{{oauth.teams.connectionName}}")
            || contains_oauth_start_marker(&adaptive_card);
        let request_seed = payload_json
            .pointer("/metadata/oauth_card_request")
            .and_then(Value::as_object)
            .cloned();
        if !has_placeholder && request_seed.is_none() {
            return Ok(RenderOutcome {
                bytes: payload_bytes.to_vec(),
            });
        }
        let request_payload =
            build_card_resolve_request(request_seed, &payload_json, provider_type);
        let resolve_result = resolve_capability(
            CAP_OAUTH_CARD_V1,
            "oauth.card.resolve",
            &serde_json::to_vec(&request_payload)?,
        )?;
        let start_url = resolve_result
            .get("start_url")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("oauth.card.resolve output missing start_url"))?;
        let teams_connection_name = resolve_result
            .pointer("/teams/connectionName")
            .or_else(|| resolve_result.pointer("/teams/connection_name"))
            .and_then(Value::as_str)
            .map(str::to_string);
        // Determine native OAuth card support from the capability response rather
        // than checking the provider name. Providers that support native OAuth
        // connection cards return `native_oauth_card: true` in their resolve output.
        let supports_native_oauth_card = resolve_result
            .get("native_oauth_card")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        rewrite_oauth_fields(
            &mut adaptive_card,
            start_url,
            teams_connection_name.as_deref(),
            supports_native_oauth_card,
        );
        if let Some(metadata) = payload_json
            .pointer_mut("/metadata")
            .and_then(Value::as_object_mut)
        {
            metadata.insert(
                "adaptive_card".to_string(),
                Value::String(serde_json::to_string(&adaptive_card)?),
            );
            metadata.insert("oauth_card_resolved".to_string(), resolve_result);
            if had_teams_placeholder
                && (!supports_native_oauth_card || teams_connection_name.is_none())
            {
                metadata.insert(
                    "oauth_card_downgrade".to_string(),
                    Value::Object(Map::from_iter([
                        (
                            "mode".to_string(),
                            Value::String("non_native_fallback".to_string()),
                        ),
                        (
                            "reason".to_string(),
                            Value::String("teams_connection_name_unavailable".to_string()),
                        ),
                    ])),
                );
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

fn contains_oauth_start_marker(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            let is_open_url = map
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("Action.OpenUrl"));
            if is_open_url
                && map
                    .get("url")
                    .and_then(Value::as_str)
                    .is_some_and(|url| url == "oauth://start")
            {
                return true;
            }
            map.values().any(contains_oauth_start_marker)
        }
        Value::Array(values) => values.iter().any(contains_oauth_start_marker),
        _ => false,
    }
}

fn rewrite_oauth_fields(
    value: &mut Value,
    start_url: &str,
    teams_connection_name: Option<&str>,
    teams_native_platform: bool,
) {
    match value {
        Value::Object(map) => {
            let is_open_url = map
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("Action.OpenUrl"));
            let has_oauth_url_marker =
                map.get("url").and_then(Value::as_str) == Some("oauth://start");
            if is_open_url && has_oauth_url_marker {
                map.insert("url".to_string(), Value::String(start_url.to_string()));
            }
            if map.get("connectionName").and_then(Value::as_str)
                == Some("{{oauth.teams.connectionName}}")
            {
                if teams_native_platform && let Some(name) = teams_connection_name {
                    map.insert(
                        "connectionName".to_string(),
                        Value::String(name.to_string()),
                    );
                } else {
                    map.remove("connectionName");
                }
            }
            for entry in map.values_mut() {
                rewrite_oauth_fields(
                    entry,
                    start_url,
                    teams_connection_name,
                    teams_native_platform,
                );
            }
        }
        Value::Array(values) => {
            for entry in values {
                rewrite_oauth_fields(
                    entry,
                    start_url,
                    teams_connection_name,
                    teams_native_platform,
                );
            }
        }
        Value::String(text) => {
            *text = text.replace("{{oauth.start_url}}", start_url);
            if teams_native_platform {
                if let Some(name) = teams_connection_name {
                    *text = text.replace("{{oauth.teams.connectionName}}", name);
                } else {
                    *text = text.replace("{{oauth.teams.connectionName}}", "");
                }
            } else {
                *text = text.replace("{{oauth.teams.connectionName}}", "");
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn oauth_card_resolve_rewrites_adaptive_card() {
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
                    "start_url": "https://oauth.example/start/session",
                    "native_oauth_card": true,
                    "teams": { "connectionName": "greentic-oauth" }
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
    }

    #[test]
    fn oauth_card_non_teams_downgrades_connection_name() {
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
                    "start_url": "https://oauth.example/start/session",
                    "teams": { "connectionName": "greentic-oauth" }
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
            "non-teams provider should drop teams-only placeholder"
        );
        assert_eq!(
            rendered
                .pointer("/metadata/oauth_card_downgrade/mode")
                .and_then(Value::as_str),
            Some("non_native_fallback")
        );
    }
}
