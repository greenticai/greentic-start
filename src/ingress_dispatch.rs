#![allow(dead_code)]

use anyhow::Context;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use greentic_types::ChannelMessageEnvelope;
use serde_json::{Map as JsonMap, Value as JsonValue, json};

use crate::domains::Domain;
use crate::ingress_types::{
    EventEnvelopeV1, IngressDispatchResult, IngressHttpResponse, IngressRequestV1,
};
use crate::messaging_dto::HttpInV1;
use crate::operator_log;
use crate::post_ingress_hooks::apply_post_ingress_hooks_dispatch;
use crate::runner_host::{DemoRunnerHost, OperatorContext};
use crate::secret_requirements::load_secret_keys_from_pack;

pub fn dispatch_http_ingress(
    runner_host: &DemoRunnerHost,
    domain: Domain,
    request: &IngressRequestV1,
    ctx: &OperatorContext,
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
    let outcome = runner_host.invoke_provider_op(
        domain,
        &request.provider,
        "ingest_http",
        &payload_json,
        ctx,
    )?;
    if !outcome.success {
        let message = outcome
            .error
            .or(outcome.raw)
            .unwrap_or_else(|| "provider ingest_http failed".to_string());
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
fn build_injected_config(
    runner_host: &DemoRunnerHost,
    domain: Domain,
    provider: &str,
    ctx: &OperatorContext,
) -> Option<JsonValue> {
    // Get the pack path for this provider
    let pack_path = runner_host.get_provider_pack_path(domain, provider)?;

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
            return None;
        }
    };

    if secret_keys.is_empty() {
        return None;
    }

    // Fetch all required secrets and build the config
    let mut config_map = serde_json::Map::new();
    let mut any_found = false;

    for key in &secret_keys {
        match runner_host.get_secret(provider, key, ctx) {
            Ok(Some(bytes)) => {
                // Store as base64-encoded value with _b64 suffix
                let key_b64 = format!("{}_b64", key);
                config_map.insert(key_b64, JsonValue::String(STANDARD.encode(&bytes)));
                any_found = true;
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

    if any_found {
        Some(JsonValue::Object(config_map))
    } else {
        None
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
