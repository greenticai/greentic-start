//! Activity-driven DirectLine session-token renewal (greentic-start side).
//!
//! greentic-start proxies DirectLine traffic (`/v3/directline/...`) to the
//! `messaging-webchat` / `messaging-webchat-gui` WASM provider. That provider
//! mints session JWTs with a fixed lifetime and validates them with a strict
//! `exp` check, and never extends that lifetime while a conversation is active —
//! so a chat surface left open longer than the token's lifetime gets
//! `401 {"error":"unauthorized","message":"invalid token: Expired"}` on its next
//! `POST /v3/directline/conversations/<id>/activities`, even mid-conversation.
//!
//! This module keeps an in-memory, bounded, per-process sliding window of active
//! conversations (`conversation_id -> expires_at` only — never tokens, never the
//! signing key). On every accepted activity (or reconnect, or `/tokens/refresh`)
//! the conversation's lifetime is extended to `now + ttl`, and a fresh JWT
//! carrying the same `conv`/`ctx` is re-minted: it is swapped into the upstream
//! `Authorization` header (so the provider's strict `exp` check is always
//! satisfied) and, when the caller's own token is getting old, surfaced back in
//! the response body as `_directline.renewed_token`. Idle conversations are
//! never `touch`ed, so they still lapse after `ttl` — this is a sliding window,
//! not an infinite session.
//!
//! The base `ttl` greentic-start uses (both the lifetime it stamps on re-minted
//! tokens and the sliding-window length) comes from
//! `GREENTIC_DIRECTLINE_TOKEN_TTL_SECS`, clamped to `[60, 604800]`, with a
//! built-in fallback when unset. The provider's own token lifetime is
//! configurable on its side, so this code never assumes a particular value —
//! every re-mint hands the provider a fresh, full-lifetime token, which is what
//! makes the window work regardless of how the provider is tuned. See
//! `docs/directline-token-renewal.md`.
//!
//! Conversation ownership: only a token whose signed `conv` names the
//! conversation is renewed, touched or allowed to pin. start never binds a
//! conversation-less token to the conversation in the URL. On a conversation
//! route it refuses an anonymous conversation-less token itself
//! (`403 ConversationOwnerRequired`, the provider's own answer) and forwards a
//! signed-in one unchanged for the provider to decide — see
//! `screen_conversation_less` and `docs/directline-conversation-ownership.md`.

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

/// Env var that overrides the base DirectLine token lifetime (seconds).
/// Documented in `docs/coding-agents.md`.
pub const TTL_ENV: &str = "GREENTIC_DIRECTLINE_TOKEN_TTL_SECS";
/// Base lifetime used when `GREENTIC_DIRECTLINE_TOKEN_TTL_SECS` is unset. This
/// is only a fallback for re-minted tokens and the sliding window — the webchat
/// provider's own token lifetime is configured separately and is not assumed
/// here.
const DEFAULT_TTL_SECS: u64 = 1800;
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 604_800;
/// Hard cap on tracked conversations so a flood of conversation creates cannot
/// grow the window map without bound (matches the `conversation_dedup` cache's
/// `MAX_ENTRIES` discipline).
const MAX_TRACKED_CONVERSATIONS: usize = 16_384;

/// Resolve the base DirectLine token lifetime in seconds — the lifetime
/// greentic-start stamps on re-minted tokens and uses for the conversation
/// sliding window. From `GREENTIC_DIRECTLINE_TOKEN_TTL_SECS`, clamped to
/// `[60, 604800]`; falls back to [`DEFAULT_TTL_SECS`] when unset.
///
/// The webchat provider has its own, separately-configurable token lifetime; we
/// don't depend on it — each re-minted token gets a fresh full lifetime, so
/// renewal works whatever the provider is tuned to (we just account for "it can
/// differ / change" by always re-issuing rather than reusing the caller's `exp`).
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
    /// Every other claim on the token — `groups`, `role`, `teams`, `email`,
    /// `name`, whatever the issuer put there.
    ///
    /// Without this the re-mint below dropped all of them, so an identity
    /// provider's roles and groups never reached the provider's second look at
    /// the token (greentic-start#584). They are only ever read out of a token
    /// whose HMAC signature has ALREADY verified against the provider's own
    /// signing key ([`parse_token`]), so they are exactly as trustworthy as
    /// `sub` — never request input.
    ///
    /// On deserialize, serde routes the named fields above into their own
    /// slots, so a reserved name can only appear here when a value is built by
    /// hand; [`carried_extra_claims`] strips those anyway before signing.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    extra: serde_json::Map<String, Value>,
}

/// Claims whose meaning greentic-start or the provider owns. They are never
/// copied from [`DlClaims::extra`]: the named fields are re-stamped by
/// [`mint_token`], and letting an extra with the same name through would
/// serialize a duplicate key — which parsers resolve differently — or, for
/// `jti`, replay a single-use id onto a new token.
const RESERVED_CLAIMS: &[&str] = &[
    "iss", "aud", "sub", "iat", "nbf", "exp", "jti", "ctx", "conv",
];

/// Upper bound on the serialized size of the carried extra claims. The token
/// travels in an `Authorization` header on every poll, and common proxies
/// refuse headers past ~8 KiB; an issuer that stuffs hundreds of groups into
/// its token must not turn every Direct Line request into a 431.
const MAX_EXTRA_CLAIMS_BYTES: usize = 4096;

/// The extra claims a re-minted token carries: reserved names removed, and the
/// whole set dropped (with a warning) when it exceeds
/// [`MAX_EXTRA_CLAIMS_BYTES`].
///
/// Over the cap it drops ALL of them rather than truncating. A truncated
/// `groups` array, or `role` kept while `groups` is lost, would hand a
/// downstream authorisation check a partial identity that looks complete;
/// an absent claim is an answer every consumer already has to handle.
fn carried_extra_claims(extra: &serde_json::Map<String, Value>) -> serde_json::Map<String, Value> {
    let carried: serde_json::Map<String, Value> = extra
        .iter()
        .filter(|(name, _)| !RESERVED_CLAIMS.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    let size = serde_json::to_vec(&carried)
        .map(|b| b.len())
        .unwrap_or(usize::MAX);
    if size > MAX_EXTRA_CLAIMS_BYTES {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "directline re-mint: dropping {} extra claim(s) ({size} bytes > {MAX_EXTRA_CLAIMS_BYTES} byte cap); the renewed token carries only sub/ctx/conv",
                carried.len()
            ),
        );
        return serde_json::Map::new();
    }
    carried
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
    let actual = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| TokenError::Malformed)?;
    // Constant-time comparison (`verify_slice`), as `directline_token` does:
    // a byte-by-byte `!=` leaks how much of a forged tag matched.
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| TokenError::BadSignature)?;
    mac.update(format!("{header}.{payload}").as_bytes());
    mac.verify_slice(&actual)
        .map_err(|_| TokenError::BadSignature)?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| TokenError::Malformed)?;
    serde_json::from_slice::<DlClaims>(&payload_bytes).map_err(|_| TokenError::Malformed)
}

/// Mint a fresh DirectLine JWT carrying the same `sub`/`ctx`/`conv` — and the
/// same non-reserved extra claims (see [`carried_extra_claims`]) — as
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
        extra: carried_extra_claims(&template.extra),
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
    /// The caller's token was already bound to the conversation in the URL
    /// (`conv` claim equal to the path id), not a conversation-less bootstrap
    /// token. Only such a request may (re-)establish the conversation's revision
    /// pin after the provider accepts it.
    pub token_bound_to_conversation: bool,
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

/// What the caller found when it looked for this provider's signing key.
///
/// The three states must stay distinct. A provider that never had a key has
/// DirectLine auth switched off and has always been forwarded; a read that
/// FAILED is a degraded secrets backend, and forwarding there turns a
/// transient error into an authentication bypass. Collapsing them into one
/// `Option` is what this type replaces — see the classification in
/// `read_provider_signing_key` (`revision_serve.rs`), and the visibility fix
/// that preceded it (`git log --grep "report an unreadable signing key"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningKey<'a> {
    /// A key was read and requests are verified against it.
    Present(&'a [u8]),
    /// No key is configured for this provider. Auth is off, deliberately.
    NotConfigured,
    /// A key may exist but could not be read. Refuse rather than guess.
    Unavailable,
}

/// Screen a normalized DirectLine request (`provider_path` is post
/// [`normalize_directline_dispatch`], e.g. `/v3/directline/conversations/<id>/activities`).
///
/// Side effect: accepted activity / reconnect / refresh requests `touch` the
/// sliding-window store for their conversation. `signing_key` is the
/// `jwt_signing_key` secret for the target provider; when [`SigningKey::NotConfigured`]
/// the request is forwarded unchanged (the provider performs its own auth)
/// except for `/tokens/refresh`, which cannot work without it. When
/// [`SigningKey::Unavailable`] the request is refused rather than forwarded
/// unverified.
pub fn preflight(
    method: &Method,
    provider_path: &str,
    headers: &[(String, String)],
    signing_key: SigningKey<'_>,
    sessions: &DirectLineSessions,
) -> Preflight {
    // An empty key cannot verify anything. Treat it as a broken configuration
    // (`Unavailable`), never as "no key" (`NotConfigured`) — the latter would
    // silently reopen the fail-open this type exists to close.
    let signing_key = match signing_key {
        SigningKey::Present([]) => SigningKey::Unavailable,
        other => other,
    };
    // Methods are case-insensitive on every router in front of and behind
    // this function (start's route table, the provider's router), so a
    // case-sensitive match here would let `get .../conversations/{id}` skip
    // every check below and still be answered as a `GET` (G2 review).
    let method = &canonical_method(method);
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

/// `method` in its canonical upper-case spelling (`get` → `GET`). Every
/// Direct Line method comparison must go through this, here and in the two
/// `normalize_directline_dispatch` copies that also forward the method.
pub(crate) fn canonical_method(method: &Method) -> Method {
    Method::from_bytes(method.as_str().to_ascii_uppercase().as_bytes())
        .unwrap_or_else(|_| method.clone())
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
    signing_key: SigningKey<'_>,
    sessions: &DirectLineSessions,
) -> Preflight {
    let key = match signing_key {
        SigningKey::Present(key) => key,
        SigningKey::NotConfigured => {
            return Preflight::Forward(ForwardPlan::default());
        }
        SigningKey::Unavailable => {
            return signing_key_unavailable();
        }
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
    // Conversation-less tokens are accepted ONLY for a signed-in visitor, and
    // are forwarded untouched: the provider decides whether that identity owns
    // this conversation. start never binds a token to a conversation on the
    // caller's behalf — doing so handed any conversation to anyone who knew
    // its id (G2). See `screen_conversation_less`.
    match claims.conv.as_deref() {
        None => return screen_conversation_less(&claims),
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
    // Accepted bound token — extend the conversation's lifetime and re-mint a
    // full-TTL bearer with the SAME `conv` so the provider's strict `exp` check
    // passes.
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
        token_bound_to_conversation: true,
    })
}

fn handle_reconnect(
    conv_id: &str,
    headers: &[(String, String)],
    signing_key: SigningKey<'_>,
    sessions: &DirectLineSessions,
) -> Preflight {
    let key = match signing_key {
        SigningKey::Present(key) => key,
        SigningKey::NotConfigured => {
            return Preflight::Forward(ForwardPlan::default());
        }
        SigningKey::Unavailable => {
            return signing_key_unavailable();
        }
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
    match claims.conv.as_deref() {
        None => return screen_conversation_less(&claims),
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
    // Forward a fresh bearer for the SAME conversation so the provider's
    // strict `exp` check passes; its response already carries a freshly
    // issued token.
    let renewed = mint_token(&claims, key, sessions.ttl_secs());
    Preflight::Forward(ForwardPlan {
        rewrite_authorization: Some(format!("Bearer {renewed}")),
        inject_renewed_token: None,
        seed_from_response: false,
        token_bound_to_conversation: true,
    })
}

/// A verified, signature-checked token WITHOUT a `conv` claim, presented on a
/// conversation route (reconnect, `/activities`).
///
/// - anonymous (no `verified: true`): refused here with
///   `403 ConversationOwnerRequired` — an anonymous `sub` is client-chosen,
///   so only a token bound to the conversation proves ownership. Needs no
///   state, so it closes the hole even in bundles that still carry an old
///   provider pack. There is no switch to relax it: forwarding would not
///   rescue an embed (a new provider pack refuses the token anyway, and an
///   old one can no longer post with it, since start does not bind it) and
///   would only reopen the reconnect hijack on old packs.
/// - expired: `401 TokenExpired`. The sliding window rescues bound tokens
///   only; for a conversation-less token it would let any old signed token
///   reach any live conversation.
/// - otherwise forwarded UNCHANGED — no rewrite, no renewed token, no window
///   touch, no pin. The provider decides whether this signed-in identity owns
///   the conversation.
///
/// The answer never depends on whether the conversation exists (start holds
/// no conversation state), so a refusal is not an existence oracle.
fn screen_conversation_less(claims: &DlClaims) -> Preflight {
    if !token_is_verified(claims) {
        return owner_required();
    }
    if is_expired(claims) {
        return unauthorized("TokenExpired", "invalid token: Expired");
    }
    Preflight::Forward(ForwardPlan::default())
}

/// `verified` is not a named field on [`DlClaims`] (it rides in `extra`); only
/// an explicit JSON `true` counts.
fn token_is_verified(claims: &DlClaims) -> bool {
    claims.extra.get("verified").and_then(Value::as_bool) == Some(true)
}

/// Same status and body as the provider's `owner::Refusal::OwnerRequired`.
fn owner_required() -> Preflight {
    forbidden(
        "ConversationOwnerRequired",
        "this conversation belongs to another session; start a new conversation",
    )
}

fn handle_conversations_create(
    headers: &[(String, String)],
    signing_key: SigningKey<'_>,
    sessions: &DirectLineSessions,
) -> Preflight {
    let key = match signing_key {
        SigningKey::Present(key) => key,
        SigningKey::NotConfigured => {
            return Preflight::Forward(ForwardPlan {
                seed_from_response: true,
                ..ForwardPlan::default()
            });
        }
        SigningKey::Unavailable => {
            return signing_key_unavailable();
        }
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
        ..ForwardPlan::default()
    })
}

fn handle_refresh(
    headers: &[(String, String)],
    signing_key: SigningKey<'_>,
    sessions: &DirectLineSessions,
) -> Preflight {
    let key = match signing_key {
        SigningKey::Present(key) => key,
        SigningKey::NotConfigured | SigningKey::Unavailable => {
            return signing_key_unavailable();
        }
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

/// The token after `Bearer ` (scheme case-insensitive, whitespace trimmed),
/// or `None`. Shared with the create-dedup key (`conv_dedup`).
pub(crate) fn bearer(headers: &[(String, String)]) -> Option<String> {
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

/// The refusal every handler returns for [`SigningKey::Unavailable`] (and,
/// in `handle_refresh`, for [`SigningKey::NotConfigured`] too — that handler
/// has no "auth off" posture, see its own match). One function so a future
/// fifth handler cannot spell this refusal subtly differently from the other
/// four.
fn signing_key_unavailable() -> Preflight {
    Preflight::Respond(coded_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "ServerError",
        "directline signing key unavailable",
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
#[path = "directline_session_tests.rs"]
mod tests;

/// Token helpers shared by this file's two test modules (a pure move out of
/// `mod tests`, so `owner_tests` can build the same tokens).
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) const KEY: &[u8] = b"test-signing-key";

    pub(crate) fn auth(token: &str) -> Vec<(String, String)> {
        vec![("Authorization".to_string(), format!("Bearer {token}"))]
    }

    /// Build a token directly (so we can choose `iat`/`exp`/`conv`).
    pub(crate) fn make_token(
        sub: &str,
        conv: Option<&str>,
        iat: i64,
        exp: i64,
        key: &[u8],
    ) -> String {
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
            extra: serde_json::Map::new(),
        };
        let header_enc = URL_SAFE_NO_PAD.encode(JOSE_HEADER);
        let payload_enc = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_enc}.{payload_enc}");
        let sig = URL_SAFE_NO_PAD.encode(hs256(&signing_input, key));
        format!("{signing_input}.{sig}")
    }
}

#[cfg(test)]
#[path = "directline_session_owner_tests.rs"]
mod owner_tests;

#[cfg(test)]
#[path = "directline_session_method_tests.rs"]
mod method_tests;

#[cfg(test)]
#[path = "directline_session_embed_flow_tests.rs"]
mod embed_flow_tests;
