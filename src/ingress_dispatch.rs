#![allow(dead_code)]

use anyhow::Context;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use greentic_types::ChannelMessageEnvelope;
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use std::fs;
use std::path::Path;

use crate::domains::Domain;
use crate::ingress_types::{
    EventEnvelopeV1, IngressDispatchResult, IngressHttpResponse, IngressRequestV1,
};
use crate::messaging_dto::HttpInV1;
use crate::operator_log;
use crate::post_ingress_hooks::apply_post_ingress_hooks_dispatch;
use crate::provider_config_envelope::read_provider_config_envelope;
use crate::runner_host::{DemoRunnerHost, OperatorContext};
use crate::secret_requirements::load_secret_keys_from_pack;

pub fn dispatch_http_ingress(
    runner_host: &DemoRunnerHost,
    domain: Domain,
    request: &IngressRequestV1,
    ctx: &OperatorContext,
) -> anyhow::Result<IngressDispatchResult> {
    dispatch_http_ingress_with_op(runner_host, domain, request, ctx, "ingest_http")
}

pub fn dispatch_http_ingress_with_op(
    runner_host: &DemoRunnerHost,
    domain: Domain,
    request: &IngressRequestV1,
    ctx: &OperatorContext,
    op_name: &str,
) -> anyhow::Result<IngressDispatchResult> {
    // Inject secrets into config for providers running in provider_core_only mode.
    // Fall back to a minimal config for events providers that require a non-null
    // config object even when no secrets or setup have been configured yet.
    let config = build_injected_config(runner_host, domain, &request.provider, ctx).or_else(|| {
        if matches!(domain, Domain::Events) {
            Some(json!({
                "target_url": "http://0.0.0.0:0/events/noop",
                "timeout_ms": 1
            }))
        } else {
            None
        }
    });

    let http_in = build_ingress_request(
        &request.provider,
        request.handler.clone(),
        &request.method,
        &request.path,
        request.headers.clone(),
        request.query.clone(),
        &request.body,
        None,
        Some(request.tenant.clone()),
        request.team.clone(),
        config,
    );
    let payload_json = serde_json::to_vec(&http_in)?;
    let outcome =
        runner_host.invoke_provider_op(domain, &request.provider, op_name, &payload_json, ctx)?;
    if !outcome.success {
        let message = outcome
            .error
            .or(outcome.raw)
            .unwrap_or_else(|| "provider ingest_http failed".to_string());
        anyhow::bail!("{message}");
    }
    if let Some(output) = outcome.output.as_ref()
        && output
            .get("ok")
            .and_then(JsonValue::as_bool)
            .is_some_and(|ok| !ok)
    {
        let message = output
            .get("error")
            .and_then(JsonValue::as_str)
            .or_else(|| output.get("message").and_then(JsonValue::as_str))
            .unwrap_or("provider ingest_http reported ok=false");
        anyhow::bail!("{message}");
    }

    let value = outcome.output.unwrap_or_else(|| json!({}));
    let mut decoded = parse_dispatch_result(&value).with_context(|| "decode ingest_http output")?;

    // When the events-webhook provider emits events with null payload,
    // inject the original HTTP request body so flow nodes can access the data.
    if !decoded.events.is_empty()
        && !request.body.is_empty()
        && let Ok(body) = serde_json::from_slice::<JsonValue>(&request.body)
    {
        for event in &mut decoded.events {
            if event.payload.is_null() {
                event.payload = body.clone();
            }
        }
    }
    apply_post_ingress_hooks_dispatch(
        runner_host.bundle_root(),
        runner_host,
        domain,
        request,
        &mut decoded,
        ctx,
    )?;
    Ok(decoded)
}

/// Build injected config with pre-fetched secrets for providers running in provider_core_only mode.
/// This allows the host to inject secrets instead of the component calling secrets_store directly.
///
/// The function reads secret requirements from the provider's pack and fetches all required
/// secrets, injecting them into the config as base64-encoded values with `_b64` suffix.
pub(crate) fn build_injected_config(
    runner_host: &DemoRunnerHost,
    domain: Domain,
    provider: &str,
    ctx: &OperatorContext,
) -> Option<JsonValue> {
    // Get the pack path for this provider
    let pack_path = runner_host.get_provider_pack_path(domain, provider)?;

    let mut config_map = serde_json::Map::new();

    // Prefer already-materialized runtime config over live secret-store reads.
    // This keeps hot ingress paths off the dev-store for cloud targets like AWS.
    if let Some(envelope_config) =
        load_provider_config_from_envelope(runner_host.bundle_root(), provider)
    {
        inject_config_values(&mut config_map, &envelope_config);
    }
    if let Some(setup_answers) = load_provider_setup_answers(runner_host.bundle_root(), provider) {
        inject_config_values(&mut config_map, &setup_answers);
    }
    inject_runtime_env_config(&mut config_map, provider);

    // Load secret requirements from the pack
    let secret_keys = match load_secret_keys_from_pack(pack_path) {
        Ok(keys) => keys,
        Err(err) => {
            operator_log::debug(
                module_path!(),
                format!(
                    "failed to load secret requirements for {provider}: {err}, skipping injection"
                ),
            );
            return if config_map.is_empty() {
                None
            } else {
                Some(JsonValue::Object(config_map))
            };
        }
    };

    for key in &secret_keys {
        let key_b64 = format!("{key}_b64");
        if config_map.contains_key(&key_b64) {
            continue;
        }
        match runner_host.get_secret(provider, key, ctx) {
            Ok(Some(bytes)) => {
                // Store as base64-encoded value with _b64 suffix
                config_map.insert(key_b64, JsonValue::String(STANDARD.encode(&bytes)));
            }
            Ok(None) => {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "secret {key} not found for provider {provider}, component will try secrets_store"
                    ),
                );
            }
            Err(err) => {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "failed to fetch secret {key} for provider {provider}: {err}, component will try secrets_store"
                    ),
                );
            }
        }
    }

    if !config_map.is_empty() {
        Some(JsonValue::Object(config_map))
    } else {
        None
    }
}

fn inject_runtime_env_config(config_map: &mut JsonMap<String, JsonValue>, provider: &str) {
    match provider {
        "messaging-webchat" | "messaging-webchat-gui" => {
            inject_env_string(config_map, "public_base_url", "PUBLIC_BASE_URL", true);
            inject_env_string(config_map, "mode", "GREENTIC_WEBCHAT_MODE", true);
            inject_env_string(config_map, "route", "GREENTIC_WEBCHAT_ROUTE", true);
            inject_env_string(
                config_map,
                "tenant_channel_id",
                "GREENTIC_WEBCHAT_TENANT_CHANNEL_ID",
                true,
            );
            inject_env_string(config_map, "base_url", "GREENTIC_WEBCHAT_BASE_URL", true);
        }
        "state-redis" => {
            inject_env_string(config_map, "redis_url", "REDIS_URL", true);
        }
        _ => {}
    }
}

fn inject_env_string(
    config_map: &mut JsonMap<String, JsonValue>,
    key: &str,
    env_key: &str,
    overwrite: bool,
) {
    let target_key = format!("{key}_b64");
    if !overwrite && config_map.contains_key(&target_key) {
        return;
    }
    let Ok(value) = std::env::var(env_key) else {
        return;
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    config_map.insert(
        target_key,
        JsonValue::String(STANDARD.encode(trimmed.as_bytes())),
    );
}

fn load_provider_config_from_envelope(bundle_root: &Path, provider: &str) -> Option<JsonValue> {
    let providers_root = bundle_root.join(".providers");
    read_provider_config_envelope(&providers_root, provider)
        .ok()
        .flatten()
        .map(|envelope| envelope.config)
}

fn load_provider_setup_answers(bundle_root: &Path, provider: &str) -> Option<JsonValue> {
    let path = bundle_root
        .join("state")
        .join("config")
        .join(provider)
        .join("setup-answers.json");
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn inject_config_values(config_map: &mut JsonMap<String, JsonValue>, value: &JsonValue) {
    let Some(obj) = value.as_object() else {
        return;
    };

    for (key, value) in obj {
        if value.is_null() {
            continue;
        }
        let encoded = match value {
            JsonValue::String(text) if !text.is_empty() => STANDARD.encode(text.as_bytes()),
            JsonValue::Bool(flag) => STANDARD.encode(flag.to_string().as_bytes()),
            JsonValue::Number(number) => STANDARD.encode(number.to_string().as_bytes()),
            JsonValue::Array(_) | JsonValue::Object(_) => {
                let json = serde_json::to_vec(value).unwrap_or_default();
                if json.is_empty() {
                    continue;
                }
                STANDARD.encode(json)
            }
            JsonValue::String(_) => continue,
            JsonValue::Null => continue,
        };
        config_map.insert(format!("{key}_b64"), JsonValue::String(encoded));
    }
}

#[allow(clippy::too_many_arguments)]
fn build_ingress_request(
    provider: &str,
    route: Option<String>,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    query: Vec<(String, String)>,
    body: &[u8],
    binding_id: Option<String>,
    tenant_hint: Option<String>,
    team_hint: Option<String>,
    config: Option<JsonValue>,
) -> HttpInV1 {
    HttpInV1 {
        v: 1,
        provider: provider.to_string(),
        route,
        binding_id,
        tenant_hint,
        team_hint,
        method: method.to_string(),
        path: path.to_string(),
        query,
        headers,
        body_b64: STANDARD.encode(body),
        config,
    }
}

fn parse_dispatch_result(value: &JsonValue) -> anyhow::Result<IngressDispatchResult> {
    // Some provider WASM components return the WIT ABI envelope {"ok": {...}, "error": ...}
    // instead of the flat dispatch format. Unwrap "ok" when top-level looks like a WIT envelope.
    let value = if value.get("ok").is_some()
        && value.get("events").is_none()
        && value.get("status").is_none()
    {
        value.get("ok").unwrap_or(value)
    } else {
        value
    };

    if value.get("http").is_none() && value.get("response").is_none() {
        if let Some(error) = value.get("error").and_then(JsonValue::as_str)
            && !error.trim().is_empty()
        {
            anyhow::bail!("{error}");
        }
        if value
            .get("ok")
            .and_then(JsonValue::as_bool)
            .is_some_and(|ok| !ok)
        {
            anyhow::bail!("provider returned ok=false without http response");
        }
    }

    let http_value = value
        .get("http")
        .or_else(|| value.get("response"))
        .unwrap_or(value);
    let response = parse_http_response(http_value)?;
    // Provider components may return events under "events" or "emitted_events".
    let events_value = value.get("events").or_else(|| value.get("emitted_events"));
    let events = parse_events(events_value)?;
    let messaging_envelopes = parse_messaging_envelopes(events_value);

    operator_log::info(
        module_path!(),
        format!(
            "[DEBUG] parsed events={}, messaging_envelopes={}",
            events.len(),
            messaging_envelopes.len()
        ),
    );

    Ok(IngressDispatchResult {
        response,
        events,
        messaging_envelopes,
    })
}

fn parse_http_response(value: &JsonValue) -> anyhow::Result<IngressHttpResponse> {
    let status = value
        .get("status")
        .and_then(JsonValue::as_u64)
        .unwrap_or(200) as u16;
    let headers = parse_headers(value.get("headers"));
    let body = parse_body_bytes(value)?;
    Ok(IngressHttpResponse {
        status,
        headers,
        body,
    })
}

fn parse_headers(value: Option<&JsonValue>) -> Vec<(String, String)> {
    let Some(value) = value else {
        return Vec::new();
    };
    if let Some(map) = value.as_object() {
        return map
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    v.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string()),
                )
            })
            .collect();
    }
    if let Some(array) = value.as_array() {
        let mut headers = Vec::new();
        for entry in array {
            if let Some(pair) = entry.as_array()
                && pair.len() >= 2
                && let (Some(name), Some(value)) = (pair[0].as_str(), pair[1].as_str())
            {
                headers.push((name.to_string(), value.to_string()));
                continue;
            }
            if let Some(obj) = entry.as_object()
                && let (Some(name), Some(value)) = (
                    obj.get("name").and_then(JsonValue::as_str),
                    obj.get("value").and_then(JsonValue::as_str),
                )
            {
                headers.push((name.to_string(), value.to_string()));
            }
        }
        return headers;
    }
    Vec::new()
}

fn parse_body_bytes(value: &JsonValue) -> anyhow::Result<Option<Vec<u8>>> {
    if let Some(body_b64) = value.get("body_b64").and_then(JsonValue::as_str) {
        let decoded = STANDARD
            .decode(body_b64)
            .with_context(|| "body_b64 is not valid base64")?;
        return Ok(Some(decoded));
    }
    if let Some(body_text) = value.get("body").and_then(JsonValue::as_str) {
        return Ok(Some(body_text.as_bytes().to_vec()));
    }
    if let Some(body_json) = value.get("body_json") {
        let encoded = serde_json::to_vec(body_json)?;
        return Ok(Some(encoded));
    }
    Ok(None)
}

fn parse_events(value: Option<&JsonValue>) -> anyhow::Result<Vec<EventEnvelopeV1>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(array) = value.as_array() else {
        return Ok(Vec::new());
    };

    let mut events = Vec::new();
    for entry in array {
        match serde_json::from_value::<EventEnvelopeV1>(entry.clone()) {
            Ok(event) => events.push(event),
            Err(_) => continue,
        }
    }
    Ok(events)
}

fn parse_messaging_envelopes(value: Option<&JsonValue>) -> Vec<ChannelMessageEnvelope> {
    let Some(value) = value else {
        return Vec::new();
    };
    let Some(array) = value.as_array() else {
        return Vec::new();
    };
    let mut envelopes = Vec::new();
    for (i, entry) in array.iter().enumerate() {
        match serde_json::from_value::<ChannelMessageEnvelope>(entry.clone()) {
            Ok(envelope) => {
                envelopes.push(envelope);
            }
            Err(err) => {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "[DEBUG] parse_messaging_envelopes: failed to parse envelope {}: {} entry={}",
                        i,
                        err,
                        serde_json::to_string(entry).unwrap_or_default()
                    ),
                );
            }
        }
    }
    envelopes
}

pub fn events_debug_json(events: &[EventEnvelopeV1]) -> JsonValue {
    let mut items = Vec::new();
    for event in events {
        let mut item = JsonMap::new();
        item.insert(
            "event_id".to_string(),
            JsonValue::String(event.event_id.clone()),
        );
        item.insert(
            "event_type".to_string(),
            JsonValue::String(event.event_type.clone()),
        );
        item.insert(
            "provider".to_string(),
            JsonValue::String(event.source.provider.clone()),
        );
        item.insert(
            "tenant".to_string(),
            JsonValue::String(event.scope.tenant.clone()),
        );
        items.push(JsonValue::Object(item));
    }
    JsonValue::Array(items)
}

pub fn log_invalid_event_warning(err: &anyhow::Error) {
    operator_log::warn(
        module_path!(),
        format!("ingress events decode warning: {err}"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn messaging_envelope() -> JsonValue {
        json!({
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
        })
    }

    fn event() -> JsonValue {
        json!({
            "event_id": "evt-1",
            "event_type": "subscription.created",
            "occurred_at": "2026-04-01T00:00:00Z",
            "source": {
                "domain": "events",
                "provider": "events-webhook"
            },
            "scope": {
                "tenant": "demo",
                "team": "default"
            },
            "payload": {"id": "1"}
        })
    }

    #[test]
    fn build_ingress_request_and_parse_headers_cover_supported_shapes() {
        let request = build_ingress_request(
            "provider-a",
            Some("hook".to_string()),
            "POST",
            "/v1/events",
            vec![("x-test".to_string(), "1".to_string())],
            vec![("q".to_string(), "v".to_string())],
            b"body",
            Some("binding-1".to_string()),
            Some("demo".to_string()),
            Some("ops".to_string()),
            Some(json!({"token_b64": "e30="})),
        );
        assert_eq!(request.provider, "provider-a");
        assert_eq!(request.route.as_deref(), Some("hook"));
        assert_eq!(request.method, "POST");
        assert_eq!(request.binding_id.as_deref(), Some("binding-1"));
        assert_eq!(request.tenant_hint.as_deref(), Some("demo"));
        assert_eq!(request.team_hint.as_deref(), Some("ops"));
        assert_eq!(request.body_b64, STANDARD.encode(b"body"));

        assert_eq!(
            parse_headers(Some(&json!({"x-a": "1", "x-b": 2}))),
            vec![
                ("x-a".to_string(), "1".to_string()),
                ("x-b".to_string(), "2".to_string())
            ]
        );
        assert_eq!(
            parse_headers(Some(&json!([
                ["x-a", "1"],
                {"name": "x-b", "value": "2"},
                ["ignored"]
            ]))),
            vec![
                ("x-a".to_string(), "1".to_string()),
                ("x-b".to_string(), "2".to_string())
            ]
        );
    }

    #[test]
    fn body_event_and_messaging_parsers_handle_multiple_shapes() {
        assert_eq!(
            parse_body_bytes(&json!({"body_b64": STANDARD.encode(b"hello")})).expect("b64"),
            Some(b"hello".to_vec())
        );
        assert_eq!(
            parse_body_bytes(&json!({"body": "hello"})).expect("text"),
            Some(b"hello".to_vec())
        );
        assert_eq!(
            parse_body_bytes(&json!({"body_json": {"ok": true}})).expect("json"),
            Some(br#"{"ok":true}"#.to_vec())
        );
        assert_eq!(parse_body_bytes(&json!({})).expect("missing"), None);

        let events = parse_events(Some(&json!([event(), {"bad": true}]))).expect("events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-1");

        let envelopes =
            parse_messaging_envelopes(Some(&json!([messaging_envelope(), {"bad": true}])));
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].id, "msg-1");
    }

    #[test]
    fn parse_dispatch_result_supports_wit_envelopes_and_debug_helpers() {
        let result = parse_dispatch_result(&json!({
            "ok": {
                "response": {
                    "status": 202,
                    "headers": [{"name": "content-type", "value": "application/json"}],
                    "body_json": {"ok": true}
                },
                "events": [event(), messaging_envelope()]
            }
        }))
        .expect("dispatch result");

        assert_eq!(result.response.status, 202);
        assert_eq!(
            result.response.headers,
            vec![("content-type".to_string(), "application/json".to_string())]
        );
        assert_eq!(result.response.body, Some(br#"{"ok":true}"#.to_vec()));
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.messaging_envelopes.len(), 1);

        let debug = events_debug_json(&result.events);
        assert_eq!(debug.as_array().expect("array").len(), 1);
        assert_eq!(debug[0]["provider"], "events-webhook");

        log_invalid_event_warning(&anyhow::anyhow!("bad event"));
    }

    #[test]
    fn inject_runtime_env_config_populates_webchat_and_redis_from_env() {
        let mut webchat = JsonMap::new();
        unsafe {
            std::env::set_var("PUBLIC_BASE_URL", "https://example.com");
            std::env::set_var("GREENTIC_WEBCHAT_MODE", "websocket");
            std::env::set_var("GREENTIC_WEBCHAT_ROUTE", "webchat");
            std::env::set_var("GREENTIC_WEBCHAT_TENANT_CHANNEL_ID", "demo:webchat");
            std::env::set_var("GREENTIC_WEBCHAT_BASE_URL", "https://example.com");
            std::env::set_var("REDIS_URL", "redis://shared.example.com:6379/0");
        }

        inject_runtime_env_config(&mut webchat, "messaging-webchat-gui");
        assert_eq!(
            webchat.get("public_base_url_b64"),
            Some(&JsonValue::String(STANDARD.encode("https://example.com")))
        );
        assert_eq!(
            webchat.get("mode_b64"),
            Some(&JsonValue::String(STANDARD.encode("websocket")))
        );
        assert_eq!(
            webchat.get("tenant_channel_id_b64"),
            Some(&JsonValue::String(STANDARD.encode("demo:webchat")))
        );

        let mut redis = JsonMap::new();
        inject_runtime_env_config(&mut redis, "state-redis");
        assert_eq!(
            redis.get("redis_url_b64"),
            Some(&JsonValue::String(
                STANDARD.encode("redis://shared.example.com:6379/0")
            ))
        );

        unsafe {
            std::env::remove_var("PUBLIC_BASE_URL");
            std::env::remove_var("GREENTIC_WEBCHAT_MODE");
            std::env::remove_var("GREENTIC_WEBCHAT_ROUTE");
            std::env::remove_var("GREENTIC_WEBCHAT_TENANT_CHANNEL_ID");
            std::env::remove_var("GREENTIC_WEBCHAT_BASE_URL");
            std::env::remove_var("REDIS_URL");
        }
    }
}
