//! Derive a stable, per-conversation session hint from raw webhook bodies.
//!
//! The hint only needs to be stable per conversation and chat/channel granular;
//! it need NOT equal the session_id the provider component later derives.
//! Returns `None` for unknown providers or unparseable input.

use serde_json::Value;

/// Extract a chat/channel-level session hint from a raw webhook body.
///
/// `provider` is the canonical short name returned by
/// [`crate::http_routes::derive_provider_name`] (e.g. `"telegram"`, `"slack"`).
/// `content_type` is the request's `Content-Type` header value, if present.
pub(crate) fn extract_session_hint(
    provider: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> Option<String> {
    match provider {
        "telegram" => telegram_hint(body),
        "slack" => slack_hint(content_type, body),
        _ => None,
    }
}

// ── Telegram ────────────────────────────────────────────────────────────────

/// Telegram update types that carry `.chat.id` at a known path.
const TELEGRAM_CHAT_KEYS: &[&str] = &[
    "message",
    "edited_message",
    "channel_post",
    "edited_channel_post",
    "my_chat_member",
    "chat_member",
    "chat_join_request",
];

/// Telegram update types where the user anchor lives at `.from.id` (no chat).
const TELEGRAM_FROM_KEYS: &[&str] = &[
    "inline_query",
    "chosen_inline_result",
    "shipping_query",
    "pre_checkout_query",
];

fn telegram_hint(body: &[u8]) -> Option<String> {
    let root: Value = serde_json::from_slice(body).ok()?;

    // 1. Top-level keys whose `.chat.id` is the stable anchor.
    for key in TELEGRAM_CHAT_KEYS {
        if let Some(id) = root.get(key).and_then(|v| v.get("chat")).and_then(chat_id) {
            return Some(format!("telegram:{id}"));
        }
    }

    // 2. callback_query: prefer `.message.chat.id`, fall back to `.from.id`.
    if let Some(cb) = root.get("callback_query") {
        if let Some(id) = cb
            .get("message")
            .and_then(|m| m.get("chat"))
            .and_then(chat_id)
        {
            return Some(format!("telegram:{id}"));
        }
        if let Some(id) = cb.get("from").and_then(user_id) {
            return Some(format!("telegram:{id}"));
        }
    }

    // 3. Chat-less update types anchored on `.from.id`.
    for key in TELEGRAM_FROM_KEYS {
        if let Some(id) = root.get(key).and_then(|v| v.get("from")).and_then(user_id) {
            return Some(format!("telegram:{id}"));
        }
    }

    // 4. poll_answer uses `.user.id`.
    if let Some(id) = root
        .get("poll_answer")
        .and_then(|v| v.get("user"))
        .and_then(user_id)
    {
        return Some(format!("telegram:{id}"));
    }

    None
}

/// Extract an integer id from a chat-like object (`{"id": 12345}`).
fn chat_id(chat: &Value) -> Option<i64> {
    chat.get("id").and_then(Value::as_i64)
}

/// Extract an integer id from a user-like object (`{"id": 67890}`).
fn user_id(user: &Value) -> Option<i64> {
    user.get("id").and_then(Value::as_i64)
}

// ── Slack ───────────────────────────────────────────────────────────────────

fn slack_hint(content_type: Option<&str>, body: &[u8]) -> Option<String> {
    let is_form = content_type
        .map(|ct| {
            ct.to_ascii_lowercase()
                .contains("application/x-www-form-urlencoded")
        })
        .unwrap_or(false);

    if is_form {
        slack_hint_form(body)
    } else {
        slack_hint_json(body)
    }
}

/// JSON bodies: Events API `event_callback` (`.event.channel`) or interactive
/// messages sent as JSON (`.channel.id`). `url_verification` challenges have
/// no channel and correctly return `None`.
fn slack_hint_json(body: &[u8]) -> Option<String> {
    let root: Value = serde_json::from_slice(body).ok()?;

    // Events API: { "event": { "channel": "C0123" } }
    if let Some(ch) = root
        .get("event")
        .and_then(|e| e.get("channel"))
        .and_then(Value::as_str)
    {
        return Some(format!("slack:{ch}"));
    }

    // Interactive messages (JSON variant): { "channel": { "id": "C0123" } }
    if let Some(ch) = root
        .get("channel")
        .and_then(|c| c.get("id"))
        .and_then(Value::as_str)
    {
        return Some(format!("slack:{ch}"));
    }

    None
}

/// Form-urlencoded bodies: slash commands (`channel_id=C0123&...`) and
/// interactive messages (`payload=<percent-encoded JSON>`).
///
/// The `url` crate is not a dependency, so we do minimal manual key=value
/// splitting with percent-decoding via the `urlencoding` crate (already a dep).
/// The `payload` field's JSON is percent-decoded then parsed for `.channel.id`.
fn slack_hint_form(body: &[u8]) -> Option<String> {
    let body_str = std::str::from_utf8(body).ok()?;
    for pair in body_str.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        match key {
            "channel_id" => {
                let Ok(decoded) = urlencoding::decode(value) else {
                    continue;
                };
                if !decoded.is_empty() {
                    return Some(format!("slack:{decoded}"));
                }
            }
            "payload" => {
                let Ok(decoded) = urlencoding::decode(value) else {
                    continue;
                };
                let parsed: Value = serde_json::from_str(&decoded).ok()?;
                if let Some(ch) = parsed
                    .get("channel")
                    .and_then(|c| c.get("id"))
                    .and_then(Value::as_str)
                {
                    return Some(format!("slack:{ch}"));
                }
            }
            _ => {}
        }
    }
    None
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Telegram ────────────────────────────────────────────────────────────

    #[test]
    fn telegram_message_hint() {
        let body = serde_json::json!({
            "update_id": 1,
            "message": { "message_id": 10, "chat": { "id": 42 }, "text": "hi" }
        });
        assert_eq!(
            extract_session_hint("telegram", None, body.to_string().as_bytes()),
            Some("telegram:42".to_string()),
        );
    }

    #[test]
    fn telegram_edited_message_same_chat() {
        let body = serde_json::json!({
            "update_id": 2,
            "edited_message": { "message_id": 10, "chat": { "id": 42 }, "text": "fixed" }
        });
        assert_eq!(
            extract_session_hint("telegram", None, body.to_string().as_bytes()),
            Some("telegram:42".to_string()),
        );
    }

    #[test]
    fn telegram_callback_query_with_message() {
        let body = serde_json::json!({
            "update_id": 3,
            "callback_query": {
                "id": "abc",
                "from": { "id": 99 },
                "message": { "message_id": 10, "chat": { "id": 42 } },
                "data": "btn1"
            }
        });
        // Must resolve to chat.id (42), same as message/edited_message.
        assert_eq!(
            extract_session_hint("telegram", None, body.to_string().as_bytes()),
            Some("telegram:42".to_string()),
        );
    }

    #[test]
    fn telegram_callback_query_without_message_falls_to_from() {
        let body = serde_json::json!({
            "update_id": 4,
            "callback_query": {
                "id": "abc",
                "from": { "id": 99 },
                "data": "btn1"
            }
        });
        assert_eq!(
            extract_session_hint("telegram", None, body.to_string().as_bytes()),
            Some("telegram:99".to_string()),
        );
    }

    #[test]
    fn telegram_channel_post() {
        let body = serde_json::json!({
            "update_id": 5,
            "channel_post": { "message_id": 20, "chat": { "id": -100123 } }
        });
        assert_eq!(
            extract_session_hint("telegram", None, body.to_string().as_bytes()),
            Some("telegram:-100123".to_string()),
        );
    }

    #[test]
    fn telegram_inline_query_uses_from() {
        let body = serde_json::json!({
            "update_id": 6,
            "inline_query": { "id": "iq1", "from": { "id": 77 }, "query": "search" }
        });
        assert_eq!(
            extract_session_hint("telegram", None, body.to_string().as_bytes()),
            Some("telegram:77".to_string()),
        );
    }

    #[test]
    fn telegram_poll_answer_uses_user() {
        let body = serde_json::json!({
            "update_id": 7,
            "poll_answer": { "poll_id": "p1", "user": { "id": 55 }, "option_ids": [0] }
        });
        assert_eq!(
            extract_session_hint("telegram", None, body.to_string().as_bytes()),
            Some("telegram:55".to_string()),
        );
    }

    #[test]
    fn telegram_malformed_body() {
        assert_eq!(
            extract_session_hint("telegram", None, b"not json at all"),
            None,
        );
    }

    #[test]
    fn telegram_message_and_edited_and_callback_same_chat_produce_identical_hint() {
        let msg = serde_json::json!({
            "update_id": 1,
            "message": { "message_id": 10, "chat": { "id": 42 }, "text": "hi" }
        });
        let edited = serde_json::json!({
            "update_id": 2,
            "edited_message": { "message_id": 10, "chat": { "id": 42 }, "text": "fixed" }
        });
        let callback = serde_json::json!({
            "update_id": 3,
            "callback_query": {
                "id": "abc",
                "from": { "id": 99 },
                "message": { "message_id": 10, "chat": { "id": 42 } },
                "data": "btn1"
            }
        });
        let hint_msg = extract_session_hint("telegram", None, msg.to_string().as_bytes()).unwrap();
        let hint_edited =
            extract_session_hint("telegram", None, edited.to_string().as_bytes()).unwrap();
        let hint_cb =
            extract_session_hint("telegram", None, callback.to_string().as_bytes()).unwrap();
        assert_eq!(hint_msg, hint_edited);
        assert_eq!(hint_msg, hint_cb);
    }

    // ── Slack ───────────────────────────────────────────────────────────────

    #[test]
    fn slack_event_callback() {
        let body = serde_json::json!({
            "type": "event_callback",
            "event": { "type": "message", "channel": "C0123", "text": "hello" }
        });
        assert_eq!(
            extract_session_hint(
                "slack",
                Some("application/json"),
                body.to_string().as_bytes()
            ),
            Some("slack:C0123".to_string()),
        );
    }

    #[test]
    fn slack_interactive_json() {
        let body = serde_json::json!({
            "type": "block_actions",
            "channel": { "id": "C0456" },
            "actions": []
        });
        assert_eq!(
            extract_session_hint(
                "slack",
                Some("application/json"),
                body.to_string().as_bytes()
            ),
            Some("slack:C0456".to_string()),
        );
    }

    #[test]
    fn slack_url_verification_returns_none() {
        let body = serde_json::json!({
            "type": "url_verification",
            "challenge": "abc123"
        });
        assert_eq!(
            extract_session_hint(
                "slack",
                Some("application/json"),
                body.to_string().as_bytes()
            ),
            None,
        );
    }

    #[test]
    fn slack_slash_command_urlencoded() {
        let body = b"command=%2Ftest&channel_id=C0789&text=hello";
        assert_eq!(
            extract_session_hint("slack", Some("application/x-www-form-urlencoded"), body,),
            Some("slack:C0789".to_string()),
        );
    }

    #[test]
    fn slack_interactive_payload_urlencoded() {
        let payload_json = serde_json::json!({
            "type": "block_actions",
            "channel": { "id": "C0999" },
            "actions": []
        });
        let payload_str = payload_json.to_string();
        let encoded_payload = urlencoding::encode(&payload_str);
        let body = format!("payload={encoded_payload}");
        assert_eq!(
            extract_session_hint(
                "slack",
                Some("application/x-www-form-urlencoded"),
                body.as_bytes(),
            ),
            Some("slack:C0999".to_string()),
        );
    }

    #[test]
    fn slack_malformed_body() {
        assert_eq!(
            extract_session_hint("slack", Some("application/json"), b"{{bad json"),
            None,
        );
    }

    // ── Unknown provider ────────────────────────────────────────────────────

    #[test]
    fn unknown_provider_returns_none() {
        let body = serde_json::json!({"foo": "bar"});
        assert_eq!(
            extract_session_hint("unknown", None, body.to_string().as_bytes()),
            None,
        );
    }
}
