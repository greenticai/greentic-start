//! Activity-driven DirectLine session-token renewal (greentic-start side).
//!
//! greentic-start proxies DirectLine traffic (`/v3/directline/...`) to the
//! `messaging-webchat` / `messaging-webchat-gui` WASM provider. That provider
//! mints session JWTs with a fixed TTL (1800 s by default) and validates them
//! with a strict `exp` check — so a chat surface left open longer than the TTL
//! gets `401 {"error":"unauthorized","message":"invalid token: Expired"}` on its
//! next `POST /v3/directline/conversations/<id>/activities`, even mid-conversation.
//!
//! This module keeps an in-memory, bounded, per-process sliding window of active
//! conversations (`conversation_id -> expires_at` only — never tokens, never the
//! signing key). On every accepted activity (or reconnect, or `/tokens/refresh`)
//! the conversation's lifetime is extended to `now + ttl`, and a fresh-TTL JWT
//! carrying the same `conv`/`ctx` is re-minted: it is swapped into the upstream
//! `Authorization` header (so the provider's strict `exp` check is always
//! satisfied) and, when the caller's own token is getting old, surfaced back in
//! the response body as `_directline.renewed_token`. Idle conversations are
//! never `touch`ed, so they still lapse after `ttl` — this is a sliding window,
//! not an infinite session.
//!
//! The base TTL is the `GREENTIC_DIRECTLINE_TOKEN_TTL_SECS` env var (clamped to
//! `[60, 604800]`, default 1800). See `docs/directline-token-renewal.md`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::HeaderValue;
use hyper::{Method, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::ingress_types::IngressHttpResponse;

/// Env var that overrides the base DirectLine token TTL (seconds). Documented in
/// `docs/coding-agents.md`.
pub const TTL_ENV: &str = "GREENTIC_DIRECTLINE_TOKEN_TTL_SECS";
const DEFAULT_TTL_SECS: u64 = 1800;
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 604_800;
/// Hard cap on tracked conversations so a flood of conversation creates cannot
/// grow the window map without bound (matches the `conversation_dedup` cache's
/// `MAX_ENTRIES` discipline).
const MAX_TRACKED_CONVERSATIONS: usize = 16_384;

/// Resolve the base DirectLine token TTL in seconds from
/// `GREENTIC_DIRECTLINE_TOKEN_TTL_SECS`, clamped to `[60, 604800]`. Defaults to
/// 1800 (the value the WASM provider has historically used).
pub fn token_ttl_secs() -> u64 {
    std::env::var(TTL_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|secs| secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS))
        .unwrap_or(DEFAULT_TTL_SECS)
}

// ---------------------------------------------------------------------------
// Sliding-window store
// ---------------------------------------------------------------------------

/// In-memory, bounded, per-process registry of active DirectLine conversations.
///
/// Holds only `conversation_id -> expires_at`; never tokens or signing keys, so
/// it is no more sensitive than the (also-ephemeral) conversation records it
/// shadows in the state-memory provider. Entries are lazily evicted once expired
/// and the map is capped. Per-instance — a multi-node ingress fleet would need
/// to back this with the shared notifier/Redis backplane instead, same as
/// `conversation_dedup`.
pub struct DirectLineSessions {
    inner: Mutex<HashMap<String, Instant>>,
    ttl: Duration,
}

impl DirectLineSessions {
    /// Build a store whose base TTL comes from the environment.
    pub fn from_env() -> Self {
        Self::with_ttl_secs(token_ttl_secs())
    }

    pub fn with_ttl_secs(secs: u64) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS)),
        }
    }

    /// Base token TTL in seconds (used both for the sliding window and for the
    /// `expires_in` reported to clients).
    pub fn ttl_secs(&self) -> u64 {
        self.ttl.as_secs()
    }

    /// Record activity on `conversation_id`: (re)sets its expiry to `now + ttl`.
    /// No-op for an empty id. Lazily evicts expired entries and respects the
    /// entry cap (without ever dropping an already-tracked conversation).
    pub fn touch(&self, conversation_id: &str) {
        if conversation_id.is_empty() {
            return;
        }
        let Ok(mut map) = self.inner.lock() else {
            return;
        };
        let now = Instant::now();
        map.retain(|_, expires_at| *expires_at > now);
        if !map.contains_key(conversation_id) && map.len() >= MAX_TRACKED_CONVERSATIONS {
            return;
        }
        map.insert(conversation_id.to_string(), now + self.ttl);
    }

    /// True while `conversation_id` has a not-yet-expired window record.
    pub fn is_alive(&self, conversation_id: &str) -> bool {
        if conversation_id.is_empty() {
            return false;
        }
        let Ok(map) = self.inner.lock() else {
            return false;
        };
        map.get(conversation_id)
            .map(|expires_at| *expires_at > Instant::now())
            .unwrap_or(false)
    }

    #[cfg(test)]
    pub fn forget(&self, conversation_id: &str) {
        if let Ok(mut map) = self.inner.lock() {
            map.remove(conversation_id);
        }
    }

    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }
}

impl Default for DirectLineSessions {
    fn default() -> Self {
        Self::from_env()
    }
}

// ---------------------------------------------------------------------------
// DirectLine JWT — mirror of messaging_provider_webchat::directline::jwt::TokenClaims
// ---------------------------------------------------------------------------

/// Issuer / audience the webchat provider stamps on every DirectLine JWT.
/// Re-minted tokens must carry these so the provider keeps treating them as its
/// own (it re-hashes the literal header+payload, so only the claim *shape* and
/// the signing key matter).
const TOKEN_ISS: &str = "greentic.webchat";
const TOKEN_AUD: &str = "directline";
/// Static JOSE header — `verify_token` re-hashes whatever header bytes we send,
/// so the exact value only needs to be a well-formed `HS256` header.
const JOSE_HEADER: &[u8] = br#"{"alg":"HS256","typ":"JWT"}"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DlContext {
    #[serde(default = "default_env")]
    env: String,
    tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    team: Option<String>,
}

fn default_env() -> String {
    "default".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DlClaims {
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    ctx: DlContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    conv: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenError {
    /// Not three base64url segments, or the payload is not the expected shape.
    Malformed,
    /// HMAC-SHA256 signature does not verify against the signing key.
    BadSignature,
}

fn hs256(signing_input: &str, key: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(signing_input.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn parse_token(token: &str, key: &[u8]) -> Result<DlClaims, TokenError> {
    let mut parts = token.trim().split('.');
    let header = parts.next().ok_or(TokenError::Malformed)?;
    let payload = parts.next().ok_or(TokenError::Malformed)?;
    let signature = parts.next().ok_or(TokenError::Malformed)?;
    if parts.next().is_some() {
        return Err(TokenError::Malformed);
    }
    let expected = hs256(&format!("{header}.{payload}"), key);
    let actual = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| TokenError::Malformed)?;
    if expected != actual {
        return Err(TokenError::BadSignature);
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| TokenError::Malformed)?;
    serde_json::from_slice::<DlClaims>(&payload_bytes).map_err(|_| TokenError::Malformed)
}

/// Mint a fresh DirectLine JWT carrying the same `sub`/`ctx`/`conv` as
/// `template`, with `iat = nbf = now` and `exp = now + ttl_secs`, signed with
/// `key`. The provider validates it like any token it issued itself.
fn mint_token(template: &DlClaims, key: &[u8], ttl_secs: u64) -> String {
    let now = now_secs();
    let claims = DlClaims {
        iss: TOKEN_ISS.to_string(),
        aud: TOKEN_AUD.to_string(),
        sub: template.sub.clone(),
        iat: now,
        nbf: now,
        exp: now + ttl_secs as i64,
        ctx: template.ctx.clone(),
        conv: template.conv.clone(),
    };
    let header_enc = URL_SAFE_NO_PAD.encode(JOSE_HEADER);
    let payload_enc =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims serialize"));
    let signing_input = format!("{header_enc}.{payload_enc}");
    let signature_enc = URL_SAFE_NO_PAD.encode(hs256(&signing_input, key));
    format!("{signing_input}.{signature_enc}")
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn is_expired(claims: &DlClaims) -> bool {
    now_secs() >= claims.exp
}

/// True when the caller's token is past 50 % of its lifetime (or already
/// expired) — the point at which it's worth handing back a renewed token.
fn token_is_stale(claims: &DlClaims) -> bool {
    let now = now_secs();
    if now >= claims.exp {
        return true;
    }
    let lifetime = claims.exp - claims.iat;
    let remaining = claims.exp - now;
    lifetime <= 0 || remaining.saturating_mul(2) <= lifetime
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

/// What the dispatcher should do with a DirectLine request when it forwards it
/// upstream. `Default` = forward unchanged.
#[derive(Debug, Default)]
pub struct ForwardPlan {
    /// Replace the request's `Authorization` header value with this (a freshly
    /// minted, full-TTL `Bearer …`) before forwarding.
    pub rewrite_authorization: Option<String>,
    /// On a 2xx JSON-object response, inject `_directline.renewed_token` (= this)
    /// and `_directline.expires_in` (= the base TTL) into the body.
    pub inject_renewed_token: Option<String>,
    /// On a 2xx response, parse `conversationId` from the body and `touch` the
    /// sliding window for it (used for `POST /v3/directline/conversations`).
    pub seed_from_response: bool,
}

/// Outcome of screening a DirectLine request before it reaches the provider.
pub enum Preflight {
    /// Forward upstream (possibly after rewriting auth / with response
    /// post-processing per the plan).
    Forward(ForwardPlan),
    /// Do not contact the provider; return this response to the client. Covers
    /// auth failures (with a machine-readable `code`) and locally-served
    /// endpoints (`/tokens/refresh`).
    Respond(Response<Full<Bytes>>),
}

/// Screen a normalized DirectLine request (`provider_path` is post
/// [`normalize_directline_dispatch`], e.g. `/v3/directline/conversations/<id>/activities`).
///
/// Side effect: accepted activity / reconnect / refresh requests `touch` the
/// sliding-window store for their conversation. `signing_key` is the
/// `jwt_signing_key` secret for the target provider; when absent the request is
/// forwarded unchanged (the provider performs its own auth) except for
/// `/tokens/refresh`, which cannot work without it.
pub fn preflight(
    method: &Method,
    provider_path: &str,
    headers: &[(String, String)],
    signing_key: Option<&[u8]>,
    sessions: &DirectLineSessions,
) -> Preflight {
    let signing_key = signing_key.filter(|key| !key.is_empty());
    let segments: Vec<&str> = provider_path.trim_start_matches('/').split('/').collect();
    match segments.as_slice() {
        ["v3", "directline", "tokens", "refresh"] if method == Method::POST => {
            handle_refresh(headers, signing_key, sessions)
        }
        ["v3", "directline", "conversations"] if method == Method::POST => {
            handle_conversations_create(headers, signing_key, sessions)
        }
        ["v3", "directline", "conversations", conv_id, "activities"]
            if method == Method::POST || method == Method::GET =>
        {
            handle_activities(method, conv_id, headers, signing_key, sessions)
        }
        ["v3", "directline", "conversations", conv_id] if method == Method::GET => {
            handle_reconnect(conv_id, headers, signing_key, sessions)
        }
        _ => Preflight::Forward(ForwardPlan::default()),
    }
}

/// Replace (or append) the `Authorization` header value in a `collect_headers`
/// vector.
pub fn apply_authorization_rewrite(headers: &mut Vec<(String, String)>, authorization_value: &str) {
    let mut replaced = false;
    for (name, value) in headers.iter_mut() {
        if name.eq_ignore_ascii_case("authorization") {
            *value = authorization_value.to_string();
            replaced = true;
        }
    }
    if !replaced {
        headers.push(("Authorization".to_string(), authorization_value.to_string()));
    }
}

/// Inject `_directline: { renewed_token, expires_in }` into a 2xx JSON-object
/// response body. No-op for non-2xx responses or non-object bodies.
pub fn inject_renewed_token(response: &mut IngressHttpResponse, renewed: &str, ttl_secs: u64) {
    if !(200..300).contains(&response.status) {
        return;
    }
    let Some(body) = response.body.as_ref() else {
        return;
    };
    let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
        return;
    };
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    obj.insert(
        "_directline".to_string(),
        json!({ "renewed_token": renewed, "expires_in": ttl_secs }),
    );
    if let Ok(bytes) = serde_json::to_vec(&value) {
        response.body = Some(bytes);
    }
}

/// Extract `conversationId` from a 2xx JSON-object response body.
pub fn conversation_id_from_response(response: &IngressHttpResponse) -> Option<String> {
    if !(200..300).contains(&response.status) {
        return None;
    }
    let body = response.body.as_ref()?;
    let value: Value = serde_json::from_slice(body).ok()?;
    value
        .get("conversationId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Per-endpoint handlers
// ---------------------------------------------------------------------------

fn handle_activities(
    method: &Method,
    conv_id: &str,
    headers: &[(String, String)],
    signing_key: Option<&[u8]>,
    sessions: &DirectLineSessions,
) -> Preflight {
    let Some(key) = signing_key else {
        return Preflight::Forward(ForwardPlan::default());
    };
    let token = match bearer(headers) {
        Some(token) => token,
        None => return unauthorized("Unauthorized", "missing Authorization header"),
    };
    let claims = match parse_token(&token, key) {
        Ok(claims) => claims,
        Err(TokenError::BadSignature) => {
            return unauthorized("InvalidToken", "invalid token signature");
        }
        Err(TokenError::Malformed) => return unauthorized("InvalidToken", "malformed token"),
    };
    if claims.conv.as_deref() != Some(conv_id) {
        return forbidden(
            "WrongConversation",
            "token bound to a different conversation",
        );
    }
    if is_expired(&claims) && !sessions.is_alive(conv_id) {
        return unauthorized("TokenExpired", "invalid token: Expired");
    }
    // Accepted — extend the conversation's lifetime and re-mint a full-TTL
    // bearer so the provider's strict `exp` check is satisfied even when the
    // caller is still presenting an older (or just-expired) token.
    sessions.touch(conv_id);
    let renewed = mint_token(&claims, key, sessions.ttl_secs());
    // POST = a user-typed message (low frequency) — always echo the renewed
    // token so the client can adopt it; GET polling (high frequency) only when
    // the caller's own token is already getting old, to avoid bloating every
    // poll response.
    let echo_renewed = token_is_stale(&claims) || method == Method::POST;
    Preflight::Forward(ForwardPlan {
        rewrite_authorization: Some(format!("Bearer {renewed}")),
        inject_renewed_token: echo_renewed.then_some(renewed),
        seed_from_response: false,
    })
}

fn handle_reconnect(
    conv_id: &str,
    headers: &[(String, String)],
    signing_key: Option<&[u8]>,
    sessions: &DirectLineSessions,
) -> Preflight {
    let Some(key) = signing_key else {
        return Preflight::Forward(ForwardPlan::default());
    };
    let token = match bearer(headers) {
        Some(token) => token,
        None => return unauthorized("Unauthorized", "missing Authorization header"),
    };
    let mut claims = match parse_token(&token, key) {
        Ok(claims) => claims,
        Err(TokenError::BadSignature) => {
            return unauthorized("InvalidToken", "invalid token signature");
        }
        Err(TokenError::Malformed) => return unauthorized("InvalidToken", "malformed token"),
    };
    match claims.conv.as_deref() {
        None => {}
        Some(bound) if bound == conv_id => {}
        Some(_) => {
            return forbidden(
                "WrongConversation",
                "token bound to a different conversation",
            );
        }
    }
    if is_expired(&claims) && !sessions.is_alive(conv_id) {
        return unauthorized("TokenExpired", "invalid token: Expired");
    }
    sessions.touch(conv_id);
    // Forward a fresh conv-bound bearer so the provider's reconnect handler
    // accepts it; its response already carries a freshly issued token.
    claims.conv = Some(conv_id.to_string());
    let renewed = mint_token(&claims, key, sessions.ttl_secs());
    Preflight::Forward(ForwardPlan {
        rewrite_authorization: Some(format!("Bearer {renewed}")),
        inject_renewed_token: None,
        seed_from_response: false,
    })
}

fn handle_conversations_create(
    headers: &[(String, String)],
    signing_key: Option<&[u8]>,
    sessions: &DirectLineSessions,
) -> Preflight {
    let Some(key) = signing_key else {
        return Preflight::Forward(ForwardPlan {
            seed_from_response: true,
            ..ForwardPlan::default()
        });
    };
    let token = match bearer(headers) {
        Some(token) => token,
        None => return unauthorized("Unauthorized", "missing Authorization header"),
    };
    let claims = match parse_token(&token, key) {
        Ok(claims) => claims,
        Err(TokenError::BadSignature) => {
            return unauthorized("InvalidToken", "invalid token signature");
        }
        Err(TokenError::Malformed) => return unauthorized("InvalidToken", "malformed token"),
    };
    if claims.conv.is_some() {
        return forbidden("WrongConversation", "token already bound to a conversation");
    }
    // A signed-but-expired bootstrap token: re-mint a fresh unbound one so the
    // create still succeeds (the signature proves it came from us). This does
    // not start a long-lived session — the new conversation gets its own window
    // seeded from the create response.
    let rewrite_authorization = is_expired(&claims)
        .then(|| format!("Bearer {}", mint_token(&claims, key, sessions.ttl_secs())));
    Preflight::Forward(ForwardPlan {
        rewrite_authorization,
        inject_renewed_token: None,
        seed_from_response: true,
    })
}

fn handle_refresh(
    headers: &[(String, String)],
    signing_key: Option<&[u8]>,
    sessions: &DirectLineSessions,
) -> Preflight {
    let Some(key) = signing_key else {
        return Preflight::Respond(coded_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "ServerError",
            "directline signing key unavailable",
        ));
    };
    let token = match bearer(headers) {
        Some(token) => token,
        None => {
            return Preflight::Respond(coded_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Unauthorized",
                "missing Authorization header",
            ));
        }
    };
    let claims = match parse_token(&token, key) {
        Ok(claims) => claims,
        Err(_) => {
            return Preflight::Respond(coded_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "InvalidToken",
                "invalid token signature",
            ));
        }
    };
    let conv = claims.conv.clone();
    let alive = conv
        .as_deref()
        .map(|c| sessions.is_alive(c))
        .unwrap_or(false);
    if is_expired(&claims) && !alive {
        return Preflight::Respond(coded_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "TokenExpired",
            "invalid token: Expired",
        ));
    }
    if let Some(ref c) = conv {
        sessions.touch(c);
    }
    let fresh = mint_token(&claims, key, sessions.ttl_secs());
    let mut body = json!({ "token": fresh, "expires_in": sessions.ttl_secs() });
    if let Some(c) = conv {
        body["conversationId"] = json!(c);
    }
    Preflight::Respond(json_response(StatusCode::OK, body))
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn bearer(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .and_then(|(_, value)| {
            let value = value.trim();
            let mut parts = value.splitn(2, ' ');
            let scheme = parts.next()?;
            if scheme.eq_ignore_ascii_case("bearer") {
                let token = parts.next().unwrap_or("").trim();
                (!token.is_empty()).then(|| token.to_string())
            } else {
                None
            }
        })
}

fn unauthorized(code: &str, message: &str) -> Preflight {
    Preflight::Respond(coded_error(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        code,
        message,
    ))
}

fn forbidden(code: &str, message: &str) -> Preflight {
    Preflight::Respond(coded_error(
        StatusCode::FORBIDDEN,
        "forbidden",
        code,
        message,
    ))
}

fn coded_error(
    status: StatusCode,
    error: &str,
    code: &str,
    message: &str,
) -> Response<Full<Bytes>> {
    let mut response = json_response(
        status,
        json!({ "error": error, "code": code, "message": message }),
    );
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            "Link",
            HeaderValue::from_static("</v3/directline/tokens/refresh>; rel=\"related\""),
        );
    }
    response
}

fn json_response(status: StatusCode, value: Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::from(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::from(Bytes::from_static(b"{}"))))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    const KEY: &[u8] = b"test-signing-key";

    fn auth(token: &str) -> Vec<(String, String)> {
        vec![("Authorization".to_string(), format!("Bearer {token}"))]
    }

    /// Build a token directly (so we can choose `iat`/`exp`/`conv`).
    fn make_token(sub: &str, conv: Option<&str>, iat: i64, exp: i64, key: &[u8]) -> String {
        let claims = DlClaims {
            iss: TOKEN_ISS.to_string(),
            aud: TOKEN_AUD.to_string(),
            sub: sub.to_string(),
            iat,
            nbf: iat,
            exp,
            ctx: DlContext {
                env: "default".to_string(),
                tenant: "demo".to_string(),
                team: None,
            },
            conv: conv.map(str::to_string),
        };
        let header_enc = URL_SAFE_NO_PAD.encode(JOSE_HEADER);
        let payload_enc = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_enc}.{payload_enc}");
        let sig = URL_SAFE_NO_PAD.encode(hs256(&signing_input, key));
        format!("{signing_input}.{sig}")
    }

    fn body_of(resp: Response<Full<Bytes>>) -> (StatusCode, Value) {
        let status = resp.status();
        let bytes = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async { resp.into_body().collect().await.unwrap().to_bytes() });
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[test]
    fn ttl_env_clamps_and_defaults() {
        // No reliable way to mutate process env safely in parallel tests, so just
        // assert the bounds logic via `with_ttl_secs`.
        assert_eq!(
            DirectLineSessions::with_ttl_secs(10).ttl_secs(),
            MIN_TTL_SECS
        );
        assert_eq!(
            DirectLineSessions::with_ttl_secs(10_000_000).ttl_secs(),
            MAX_TTL_SECS
        );
        assert_eq!(DirectLineSessions::with_ttl_secs(3600).ttl_secs(), 3600);
    }

    #[test]
    fn sliding_window_touch_and_expiry() {
        let sessions = DirectLineSessions::with_ttl_secs(60);
        assert!(!sessions.is_alive("c1"));
        sessions.touch("c1");
        assert!(sessions.is_alive("c1"));
        sessions.forget("c1");
        assert!(!sessions.is_alive("c1"));
        sessions.touch("");
        assert_eq!(sessions.tracked(), 0);
    }

    #[test]
    fn mint_round_trips_through_parse() {
        let original = make_token("alice", Some("conv-1"), 100, 200, KEY);
        let claims = parse_token(&original, KEY).unwrap();
        let minted = mint_token(&claims, KEY, 1800);
        let reparsed = parse_token(&minted, KEY).unwrap();
        assert_eq!(reparsed.sub, "alice");
        assert_eq!(reparsed.conv.as_deref(), Some("conv-1"));
        assert_eq!(reparsed.iss, TOKEN_ISS);
        assert_eq!(reparsed.aud, TOKEN_AUD);
        assert!(reparsed.exp > now_secs());
        // Tampering with the payload breaks the signature.
        let mut chars: Vec<char> = minted.chars().collect();
        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(matches!(
            parse_token(&tampered, KEY),
            Err(TokenError::BadSignature) | Err(TokenError::Malformed)
        ));
        assert!(matches!(
            parse_token("not-a-jwt", KEY),
            Err(TokenError::Malformed)
        ));
    }

    #[test]
    fn activities_active_token_renews_and_keeps_window_alive() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        let now = now_secs();
        let token = make_token("alice", Some("conv-1"), now, now + 1800, KEY);
        let outcome = preflight(
            &Method::POST,
            "/v3/directline/conversations/conv-1/activities",
            &auth(&token),
            Some(KEY),
            &sessions,
        );
        match outcome {
            Preflight::Forward(plan) => {
                assert!(plan.rewrite_authorization.is_some());
                assert!(plan.inject_renewed_token.is_some());
                assert!(!plan.seed_from_response);
            }
            Preflight::Respond(_) => panic!("expected forward"),
        }
        assert!(sessions.is_alive("conv-1"));
    }

    #[test]
    fn activities_expired_token_with_live_window_is_accepted() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        sessions.touch("conv-1");
        let now = now_secs();
        // Token expired an hour ago, but the conversation has been kept alive.
        let token = make_token("alice", Some("conv-1"), now - 5000, now - 3600, KEY);
        let outcome = preflight(
            &Method::POST,
            "/v3/directline/conversations/conv-1/activities",
            &auth(&token),
            Some(KEY),
            &sessions,
        );
        assert!(
            matches!(outcome, Preflight::Forward(plan) if plan.rewrite_authorization.is_some())
        );
    }

    #[test]
    fn activities_expired_token_idle_conversation_is_rejected_with_code() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        let now = now_secs();
        let token = make_token("alice", Some("conv-1"), now - 5000, now - 3600, KEY);
        let outcome = preflight(
            &Method::POST,
            "/v3/directline/conversations/conv-1/activities",
            &auth(&token),
            Some(KEY),
            &sessions,
        );
        let Preflight::Respond(resp) = outcome else {
            panic!("expected reject");
        };
        let link = resp
            .headers()
            .get("Link")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let (status, body) = body_of(resp);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "TokenExpired");
        assert!(link.contains("/v3/directline/tokens/refresh"));
    }

    #[test]
    fn activities_wrong_conversation_is_403_with_code() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        let now = now_secs();
        let token = make_token("alice", Some("conv-OTHER"), now, now + 1800, KEY);
        let outcome = preflight(
            &Method::POST,
            "/v3/directline/conversations/conv-1/activities",
            &auth(&token),
            Some(KEY),
            &sessions,
        );
        let Preflight::Respond(resp) = outcome else {
            panic!("expected reject");
        };
        let (status, body) = body_of(resp);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "WrongConversation");
    }

    #[test]
    fn activities_tampered_token_is_401_with_code() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        let now = now_secs();
        let token = make_token("alice", Some("conv-1"), now, now + 1800, b"some-other-key");
        let outcome = preflight(
            &Method::POST,
            "/v3/directline/conversations/conv-1/activities",
            &auth(&token),
            Some(KEY),
            &sessions,
        );
        let Preflight::Respond(resp) = outcome else {
            panic!("expected reject");
        };
        let (status, body) = body_of(resp);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "InvalidToken");
    }

    #[test]
    fn refresh_returns_fresh_token_and_same_conversation_id() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        let now = now_secs();
        let token = make_token("alice", Some("conv-1"), now, now + 1800, KEY);
        let Preflight::Respond(resp) = preflight(
            &Method::POST,
            "/v3/directline/tokens/refresh",
            &auth(&token),
            Some(KEY),
            &sessions,
        ) else {
            panic!("expected respond");
        };
        let (status, body) = body_of(resp);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["conversationId"], "conv-1");
        assert_eq!(body["expires_in"], 1800);
        let fresh = body["token"].as_str().unwrap();
        let claims = parse_token(fresh, KEY).unwrap();
        assert_eq!(claims.conv.as_deref(), Some("conv-1"));
        assert!(claims.exp > now_secs());
        assert!(sessions.is_alive("conv-1"));
    }

    #[test]
    fn conversations_create_seeds_window_from_response() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        let now = now_secs();
        let bootstrap = make_token("alice", None, now, now + 1800, KEY);
        let Preflight::Forward(plan) = preflight(
            &Method::POST,
            "/v3/directline/conversations",
            &auth(&bootstrap),
            Some(KEY),
            &sessions,
        ) else {
            panic!("expected forward");
        };
        assert!(plan.seed_from_response);
        assert!(plan.rewrite_authorization.is_none());

        let mut response = IngressHttpResponse {
            status: 201,
            headers: vec![],
            body: Some(serde_json::to_vec(&json!({ "conversationId": "conv-xyz" })).unwrap()),
        };
        let conv = conversation_id_from_response(&response).unwrap();
        sessions.touch(&conv);
        assert!(sessions.is_alive("conv-xyz"));

        inject_renewed_token(&mut response, "tok", 1800);
        let value: Value = serde_json::from_slice(response.body.as_ref().unwrap()).unwrap();
        assert_eq!(value["_directline"]["renewed_token"], "tok");
        assert_eq!(value["_directline"]["expires_in"], 1800);
    }

    #[test]
    fn conversations_create_rejects_bound_token() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        let now = now_secs();
        let bound = make_token("alice", Some("conv-1"), now, now + 1800, KEY);
        let Preflight::Respond(resp) = preflight(
            &Method::POST,
            "/v3/directline/conversations",
            &auth(&bound),
            Some(KEY),
            &sessions,
        ) else {
            panic!("expected reject");
        };
        let (status, body) = body_of(resp);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "WrongConversation");
    }

    #[test]
    fn unrelated_paths_pass_through() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        assert!(matches!(
            preflight(
                &Method::POST,
                "/v3/directline/tokens/generate",
                &[],
                Some(KEY),
                &sessions
            ),
            Preflight::Forward(plan) if plan.rewrite_authorization.is_none()
                && plan.inject_renewed_token.is_none()
                && !plan.seed_from_response
        ));
        assert!(matches!(
            preflight(&Method::GET, "/v3/directline", &[], Some(KEY), &sessions),
            Preflight::Forward(_)
        ));
    }

    #[test]
    fn missing_signing_key_passes_through_but_breaks_refresh() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        assert!(matches!(
            preflight(
                &Method::POST,
                "/v3/directline/conversations/conv-1/activities",
                &auth("whatever"),
                None,
                &sessions
            ),
            Preflight::Forward(_)
        ));
        let Preflight::Respond(resp) = preflight(
            &Method::POST,
            "/v3/directline/tokens/refresh",
            &auth("whatever"),
            None,
            &sessions,
        ) else {
            panic!("expected respond");
        };
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn apply_authorization_rewrite_replaces_or_appends() {
        let mut headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("authorization".to_string(), "Bearer old".to_string()),
        ];
        apply_authorization_rewrite(&mut headers, "Bearer new");
        assert_eq!(headers[1].1, "Bearer new");

        let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        apply_authorization_rewrite(&mut headers, "Bearer new");
        assert!(
            headers
                .iter()
                .any(|(n, v)| n == "Authorization" && v == "Bearer new")
        );
    }
}
