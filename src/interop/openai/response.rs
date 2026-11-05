//! The bodies the OpenAI-compatible surface answers with.
//!
//! Errors use OpenAI's envelope, `{"error": {"message", "type", "param",
//! "code"}}`, because that is what an SDK parses. The messages are fixed
//! sentences: never a provider body, a path or a credential.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode, header};
use serde_json::{Value, json};

use super::CONVERSATION_HEADER;

/// The OpenAI error `type` for a status.
fn error_type(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "authentication_error",
        StatusCode::TOO_MANY_REQUESTS => "rate_limit_error",
        s if s.is_client_error() => "invalid_request_error",
        _ => "server_error",
    }
}

/// A JSON response. The builder cannot refuse these inputs; the fallback only
/// keeps this path free of a panic.
fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// An OpenAI-shaped error.
pub(crate) fn error(
    status: StatusCode,
    code: &str,
    message: &str,
    param: Option<&str>,
) -> Response<Full<Bytes>> {
    json_response(
        status,
        &json!({
            "error": {
                "message": message,
                "type": error_type(status),
                "param": param,
                "code": code,
            }
        }),
    )
}

/// `401`, with a bare Bearer challenge (there is no discovery document for
/// this surface to point at).
pub(crate) fn unauthorized() -> Response<Full<Bytes>> {
    let mut response = error(
        StatusCode::UNAUTHORIZED,
        "invalid_api_key",
        "A valid access token is required. Send it as `Authorization: Bearer <token>`.",
        None,
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}

/// `429` with `Retry-After`.
pub(crate) fn rate_limited(
    retry_after_secs: u64,
    code: &str,
    message: &str,
) -> Response<Full<Bytes>> {
    let mut response = error(StatusCode::TOO_MANY_REQUESTS, code, message, None);
    if let Ok(value) = header::HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// `GET /v1/models`: exactly one entry.
pub(crate) fn models(model: &str, created: u64) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::OK,
        &json!({
            "object": "list",
            "data": [{
                "id": model,
                "object": "model",
                "created": created,
                "owned_by": "greentic",
            }]
        }),
    )
}

/// What the runtime measured for a turn, when it measured anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MeasuredUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

/// A finished (non-streaming) completion. `awaiting_input` adds the
/// `x_greentic` extension object so a caller can tell a question from an
/// answer.
pub(crate) fn completion(
    model: &str,
    created: u64,
    conversation_id: &str,
    content: &str,
    usage: Option<MeasuredUsage>,
    awaiting_input: bool,
) -> Response<Full<Bytes>> {
    let mut body = json!({
        "id": format!("chatcmpl-{}", ulid::Ulid::new().to_string().to_ascii_lowercase()),
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": content },
            "finish_reason": "stop",
        }],
    });
    if let Value::Object(map) = &mut body {
        // Omitted, never estimated, when the runtime did not measure it.
        if let Some(usage) = usage {
            map.insert(
                "usage".to_string(),
                json!({
                    "prompt_tokens": usage.prompt_tokens,
                    "completion_tokens": usage.completion_tokens,
                    "total_tokens": usage.prompt_tokens.saturating_add(usage.completion_tokens),
                }),
            );
        }
        if awaiting_input {
            map.insert(
                "x_greentic".to_string(),
                json!({ "status": "input_required" }),
            );
        }
    }
    let mut response = json_response(StatusCode::OK, &body);
    with_conversation(&mut response, conversation_id);
    response
}

/// Carry the conversation id back, so a caller can continue it.
pub(crate) fn with_conversation(response: &mut Response<Full<Bytes>>, conversation_id: &str) {
    if let Ok(value) = header::HeaderValue::from_str(conversation_id) {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static(CONVERSATION_HEADER), value);
    }
}
