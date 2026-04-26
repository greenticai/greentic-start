//! WebSocket upgrade handler — authenticates and hands off to the session task.

// Consumed by the http_ingress dispatch in Task 11.
#![allow(dead_code)]

use crate::http_ingress::helpers::{
    DirectLineTokenClaims, TokenVerifyError, verify_directline_token,
};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};

#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error("missing token")]
    MissingToken,
    #[error("token verification failed: {0}")]
    Token(#[from] TokenVerifyError),
    #[error("not a websocket request")]
    NotWebSocket,
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("upgrade failed: {0}")]
    UpgradeFailed(String),
}

#[derive(Debug)]
pub struct UpgradeContext {
    pub claims: DirectLineTokenClaims,
    pub initial_watermark: u64,
}

/// Extract the bearer-style token from query param `t` or `Sec-WebSocket-Protocol`.
pub fn extract_token(uri: &hyper::Uri, headers: &hyper::HeaderMap) -> Option<String> {
    if let Some(query) = uri.query() {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("t=") {
                return Some(urlencoding::decode(value).ok()?.into_owned());
            }
        }
    }
    headers
        .get(hyper::header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
}

/// Extract the `?watermark=N` query param. Returns 0 on absent / invalid.
pub fn extract_watermark(uri: &hyper::Uri) -> u64 {
    uri.query()
        .and_then(|q| {
            q.split('&').find_map(|pair| {
                pair.strip_prefix("watermark=")
                    .and_then(|v| urlencoding::decode(v).ok())
                    .and_then(|s| s.parse::<u64>().ok())
            })
        })
        .unwrap_or(0)
}

fn is_websocket_request(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Pre-upgrade validation. Returns the parsed context on success.
pub fn validate_request_parts(
    uri: &hyper::Uri,
    headers: &hyper::HeaderMap,
    expected_conv_id: &str,
    expected_tenant: &str,
    signing_key: &[u8],
) -> Result<UpgradeContext, UpgradeError> {
    if !is_websocket_request(headers) {
        return Err(UpgradeError::NotWebSocket);
    }
    let token = extract_token(uri, headers).ok_or(UpgradeError::MissingToken)?;
    let claims = verify_directline_token(&token, expected_conv_id, expected_tenant, signing_key)?;
    Ok(UpgradeContext {
        claims,
        initial_watermark: extract_watermark(uri),
    })
}

/// Build a 401/403/4xx response without doing the upgrade.
pub fn refusal_response(err: &UpgradeError) -> Response<Full<Bytes>> {
    let status = match err {
        UpgradeError::MissingToken
        | UpgradeError::Token(TokenVerifyError::Expired)
        | UpgradeError::Token(TokenVerifyError::InvalidSignature)
        | UpgradeError::Token(TokenVerifyError::Malformed)
        | UpgradeError::Token(TokenVerifyError::MissingKey) => StatusCode::UNAUTHORIZED,
        UpgradeError::Token(TokenVerifyError::ConversationMismatch)
        | UpgradeError::Token(TokenVerifyError::TenantMismatch) => StatusCode::FORBIDDEN,
        UpgradeError::LimitExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
        UpgradeError::NotWebSocket => StatusCode::BAD_REQUEST,
        UpgradeError::UpgradeFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(err.to_string())))
        .expect("static response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_token_from_query() {
        let uri: hyper::Uri = "/v3/directline/conversations/c1/stream?t=abc123&watermark=5"
            .parse()
            .unwrap();
        let headers = hyper::HeaderMap::new();
        assert_eq!(extract_token(&uri, &headers), Some("abc123".into()));
    }

    #[test]
    fn extract_token_from_protocol_header() {
        let uri: hyper::Uri = "/foo".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::SEC_WEBSOCKET_PROTOCOL,
            hyper::header::HeaderValue::from_static("hdr-token"),
        );
        assert_eq!(extract_token(&uri, &headers), Some("hdr-token".into()));
    }

    #[test]
    fn missing_token_returns_none() {
        let uri: hyper::Uri = "/foo".parse().unwrap();
        let headers = hyper::HeaderMap::new();
        assert_eq!(extract_token(&uri, &headers), None);
    }

    #[test]
    fn extract_watermark_parses_query() {
        let uri: hyper::Uri = "/foo?t=x&watermark=42".parse().unwrap();
        assert_eq!(extract_watermark(&uri), 42);
    }

    #[test]
    fn extract_watermark_defaults_to_zero() {
        let uri: hyper::Uri = "/foo".parse().unwrap();
        assert_eq!(extract_watermark(&uri), 0);
    }
}
