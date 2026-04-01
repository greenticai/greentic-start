#![allow(dead_code)]

use serde_json::Value as JsonValue;

use super::types::TokenValidationDecision;

pub(super) fn extract_token_validation_request(payload_bytes: &[u8]) -> Option<JsonValue> {
    let payload: JsonValue = serde_json::from_slice(payload_bytes).ok()?;
    let token = extract_bearer_token(&payload)?;
    let mut request = serde_json::Map::new();
    request.insert("token".to_string(), JsonValue::String(token));
    if let Some(issuer) = first_string_at_paths(
        &payload,
        &["/token_validation/issuer", "/auth/issuer", "/issuer"],
    ) {
        request.insert("issuer".to_string(), JsonValue::String(issuer));
    }
    if let Some(audience) = first_value_at_paths(
        &payload,
        &["/token_validation/audience", "/auth/audience", "/audience"],
    ) {
        request.insert("audience".to_string(), normalize_string_or_array(audience));
    }
    if let Some(scopes) = first_value_at_paths(
        &payload,
        &[
            "/token_validation/scopes",
            "/token_validation/required_scopes",
            "/auth/scopes",
            "/auth/required_scopes",
            "/scopes",
        ],
    ) {
        request.insert("scopes".to_string(), normalize_string_or_array(scopes));
    }
    Some(JsonValue::Object(request))
}

fn extract_bearer_token(payload: &JsonValue) -> Option<String> {
    if let Some(value) = first_string_at_paths(
        payload,
        &[
            "/token_validation/token",
            "/auth/token",
            "/bearer_token",
            "/token",
            "/access_token",
        ],
    ) && let Some(token) = parse_token_value(&value)
    {
        return Some(token);
    }

    if let Some(value) = payload
        .pointer("/authorization")
        .and_then(JsonValue::as_str)
        && let Some(token) = parse_authorization_value(value)
    {
        return Some(token);
    }

    if let Some(headers) = payload.get("headers")
        && let Some(token) = extract_bearer_from_headers(headers)
    {
        return Some(token);
    }

    if let Some(value) = payload
        .pointer("/metadata/authorization")
        .and_then(JsonValue::as_str)
        && let Some(token) = parse_authorization_value(value)
    {
        return Some(token);
    }

    None
}

fn extract_bearer_from_headers(headers: &JsonValue) -> Option<String> {
    match headers {
        JsonValue::Object(map) => {
            for key in ["authorization", "Authorization"] {
                if let Some(value) = map.get(key).and_then(JsonValue::as_str)
                    && let Some(token) = parse_authorization_value(value)
                {
                    return Some(token);
                }
            }
            None
        }
        JsonValue::Array(values) => values.iter().find_map(|entry| {
            let name = entry
                .get("name")
                .or_else(|| entry.get("key"))
                .and_then(JsonValue::as_str)?;
            if !name.eq_ignore_ascii_case("authorization") {
                return None;
            }
            let value = entry.get("value").and_then(JsonValue::as_str)?;
            parse_authorization_value(value)
        }),
        _ => None,
    }
}

fn parse_token_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_authorization_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let mut parts = trimmed.split_whitespace();
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = parts.next()?;
    if token.trim().is_empty() || parts.next().is_some() {
        return None;
    }
    Some(token.to_string())
}

fn first_string_at_paths(payload: &JsonValue, paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| payload.pointer(path).and_then(JsonValue::as_str))
        .map(str::to_string)
}

fn first_value_at_paths<'a>(payload: &'a JsonValue, paths: &[&str]) -> Option<&'a JsonValue> {
    paths.iter().find_map(|path| payload.pointer(path))
}

fn normalize_string_or_array(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::String(raw) => {
            let values = raw
                .split_whitespace()
                .filter(|entry| !entry.trim().is_empty())
                .map(|entry| JsonValue::String(entry.to_string()))
                .collect::<Vec<_>>();
            JsonValue::Array(values)
        }
        JsonValue::Array(items) => JsonValue::Array(
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(|item| JsonValue::String(item.to_string()))
                .collect(),
        ),
        _ => JsonValue::Array(Vec::new()),
    }
}

pub(super) fn evaluate_token_validation_output(output: &JsonValue) -> TokenValidationDecision {
    let valid = output
        .get("valid")
        .and_then(JsonValue::as_bool)
        .or_else(|| output.get("ok").and_then(JsonValue::as_bool))
        .unwrap_or(false);
    if !valid {
        let reason = output
            .get("reason")
            .and_then(JsonValue::as_str)
            .or_else(|| output.get("error").and_then(JsonValue::as_str))
            .unwrap_or("invalid bearer token");
        return TokenValidationDecision::Deny(reason.to_string());
    }
    let claims = output
        .get("claims")
        .filter(|value| value.is_object())
        .cloned()
        .or_else(|| {
            output
                .as_object()
                .is_some_and(|map| map.contains_key("sub"))
                .then(|| output.clone())
        });
    TokenValidationDecision::Allow(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn token_validation_request_extracts_bearer_and_requirements() {
        let payload = json!({
            "headers": {
                "Authorization": "Bearer token-123"
            },
            "token_validation": {
                "issuer": "https://issuer.example",
                "audience": ["api://svc"],
                "required_scopes": "read write"
            }
        });
        let request =
            extract_token_validation_request(&serde_json::to_vec(&payload).expect("payload bytes"))
                .expect("request");
        assert_eq!(
            request.pointer("/token").and_then(JsonValue::as_str),
            Some("token-123")
        );
        assert_eq!(
            request.pointer("/issuer").and_then(JsonValue::as_str),
            Some("https://issuer.example")
        );
        assert_eq!(
            request.pointer("/audience/0").and_then(JsonValue::as_str),
            Some("api://svc")
        );
        assert_eq!(
            request.pointer("/scopes/0").and_then(JsonValue::as_str),
            Some("read")
        );
        assert_eq!(
            request.pointer("/scopes/1").and_then(JsonValue::as_str),
            Some("write")
        );
    }

    #[test]
    fn token_validation_request_accepts_case_insensitive_bearer_authorization() {
        let payload = json!({
            "headers": {
                "authorization": "bearer token-123"
            }
        });
        let request =
            extract_token_validation_request(&serde_json::to_vec(&payload).expect("payload bytes"))
                .expect("request");
        assert_eq!(
            request.pointer("/token").and_then(JsonValue::as_str),
            Some("token-123")
        );
    }

    #[test]
    fn token_validation_request_rejects_non_bearer_authorization_headers() {
        let payload = json!({
            "headers": {
                "Authorization": "Basic Zm9vOmJhcg=="
            }
        });
        assert!(
            extract_token_validation_request(&serde_json::to_vec(&payload).expect("payload bytes"))
                .is_none()
        );
    }

    #[test]
    fn token_validation_request_accepts_explicit_token_fields_without_bearer_prefix() {
        let payload = json!({
            "token": " token-123 "
        });
        let request =
            extract_token_validation_request(&serde_json::to_vec(&payload).expect("payload bytes"))
                .expect("request");
        assert_eq!(
            request.pointer("/token").and_then(JsonValue::as_str),
            Some("token-123")
        );
    }

    #[test]
    fn token_validation_output_deny_when_invalid() {
        let output = json!({
            "valid": false,
            "reason": "issuer mismatch"
        });
        match evaluate_token_validation_output(&output) {
            TokenValidationDecision::Deny(reason) => {
                assert_eq!(reason, "issuer mismatch");
            }
            TokenValidationDecision::Allow(_) => panic!("expected deny"),
        }
    }

    #[test]
    fn token_validation_output_uses_error_fallback_reason() {
        let output = json!({
            "ok": false,
            "error": "token expired"
        });
        match evaluate_token_validation_output(&output) {
            TokenValidationDecision::Deny(reason) => {
                assert_eq!(reason, "token expired");
            }
            TokenValidationDecision::Allow(_) => panic!("expected deny"),
        }
    }

    #[test]
    fn token_validation_output_allows_and_returns_claims() {
        let output = json!({
            "valid": true,
            "claims": {
                "sub": "user-1",
                "scope": "read write",
                "aud": ["api://svc"]
            }
        });
        match evaluate_token_validation_output(&output) {
            TokenValidationDecision::Allow(Some(claims)) => {
                assert_eq!(
                    claims.pointer("/sub").and_then(JsonValue::as_str),
                    Some("user-1")
                );
            }
            TokenValidationDecision::Allow(None) => panic!("expected claims"),
            TokenValidationDecision::Deny(reason) => panic!("unexpected deny: {reason}"),
        }
    }

    #[test]
    fn token_validation_output_uses_root_object_as_claims_when_sub_present() {
        let output = json!({
            "ok": true,
            "sub": "user-1",
            "scope": "read"
        });
        match evaluate_token_validation_output(&output) {
            TokenValidationDecision::Allow(Some(claims)) => {
                assert_eq!(
                    claims.pointer("/sub").and_then(JsonValue::as_str),
                    Some("user-1")
                );
            }
            TokenValidationDecision::Allow(None) => panic!("expected claims"),
            TokenValidationDecision::Deny(reason) => panic!("unexpected deny: {reason}"),
        }
    }
}
