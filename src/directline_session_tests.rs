//! Unit tests for `directline_session` (moved out of the module file
//! unchanged).

use super::test_support::*;
use super::*;
use http_body_util::BodyExt;

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

/// Sign an arbitrary JSON payload, so a test can put claims on a token that
/// `DlClaims` would not produce itself (duplicates, `jti`, IdP claims).
fn sign_raw(payload: &Value, key: &[u8]) -> String {
    let header_enc = URL_SAFE_NO_PAD.encode(JOSE_HEADER);
    let payload_enc = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
    let signing_input = format!("{header_enc}.{payload_enc}");
    let sig = URL_SAFE_NO_PAD.encode(hs256(&signing_input, key));
    format!("{signing_input}.{sig}")
}

fn payload_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn idp_token(extra: Value, key: &[u8]) -> String {
    let now = now_secs();
    let mut payload = json!({
        "iss": TOKEN_ISS, "aud": TOKEN_AUD, "sub": "alice",
        "iat": now, "nbf": now, "exp": now + 1800,
        "ctx": { "env": "default", "tenant": "demo", "team": "sales" },
        "conv": "conv-1",
    });
    for (name, value) in extra.as_object().unwrap() {
        payload[name] = value.clone();
    }
    sign_raw(&payload, key)
}

#[test]
fn re_mint_carries_the_identity_providers_extra_claims() {
    let token = idp_token(
        json!({
            "groups": ["engineering", "admins"],
            "role": "owner",
            "teams": ["sales"],
            "email": "alice@example.com",
            "name": "Alice",
        }),
        KEY,
    );
    let claims = parse_token(&token, KEY).unwrap();
    let minted = mint_token(&claims, KEY, 1800);
    let reparsed = parse_token(&minted, KEY).unwrap();

    assert_eq!(reparsed.sub, "alice");
    assert_eq!(reparsed.ctx.team.as_deref(), Some("sales"));
    assert_eq!(reparsed.extra["groups"], json!(["engineering", "admins"]));
    assert_eq!(reparsed.extra["role"], json!("owner"));
    assert_eq!(reparsed.extra["teams"], json!(["sales"]));
    assert_eq!(reparsed.extra["email"], json!("alice@example.com"));
    assert_eq!(reparsed.extra["name"], json!("Alice"));

    // And the renewed token the preflight hands upstream carries them too.
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let Preflight::Forward(plan) = preflight(
        &Method::POST,
        "/v3/directline/conversations/conv-1/activities",
        &auth(&token),
        SigningKey::Present(KEY),
        &sessions,
    ) else {
        panic!("expected forward");
    };
    let rewritten = plan.rewrite_authorization.unwrap();
    let forwarded = payload_of(rewritten.strip_prefix("Bearer ").unwrap());
    assert_eq!(forwarded["groups"], json!(["engineering", "admins"]));
    assert_eq!(forwarded["role"], json!("owner"));
}

#[test]
fn reserved_claims_cannot_be_spoofed_through_extras() {
    // A template built by hand whose extras shadow every reserved name.
    let token = make_token("alice", Some("conv-1"), 100, 200, KEY);
    let mut claims = parse_token(&token, KEY).unwrap();
    for name in RESERVED_CLAIMS {
        claims.extra.insert((*name).to_string(), json!("forged"));
    }
    claims.extra.insert("role".to_string(), json!("owner"));

    let minted = mint_token(&claims, KEY, 1800);
    let payload = payload_of(&minted);
    let raw = String::from_utf8(
        URL_SAFE_NO_PAD
            .decode(minted.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(payload["sub"], json!("alice"));
    assert_eq!(payload["iss"], json!(TOKEN_ISS));
    assert_eq!(payload["aud"], json!(TOKEN_AUD));
    assert_eq!(payload["conv"], json!("conv-1"));
    assert_eq!(payload["ctx"]["tenant"], json!("demo"));
    assert!(payload["exp"].as_i64().unwrap() > now_secs());
    assert!(payload.get("jti").is_none(), "jti must not be replayed");
    assert_eq!(payload["role"], json!("owner"));
    // No duplicate keys in the signed bytes.
    for name in ["\"sub\"", "\"iss\"", "\"exp\"", "\"conv\"", "\"ctx\""] {
        assert_eq!(raw.matches(name).count(), 1, "duplicate {name} in {raw}");
    }
}

#[test]
fn an_inbound_jti_is_not_copied_onto_the_renewed_token() {
    let token = idp_token(json!({ "jti": "once-only", "role": "owner" }), KEY);
    let claims = parse_token(&token, KEY).unwrap();
    let payload = payload_of(&mint_token(&claims, KEY, 1800));
    assert!(payload.get("jti").is_none());
    assert_eq!(payload["role"], json!("owner"));
}

#[test]
fn oversized_extra_claims_are_dropped_whole_not_truncated() {
    let groups: Vec<String> = (0..500).map(|i| format!("group-number-{i}")).collect();
    let token = idp_token(json!({ "groups": groups, "role": "owner" }), KEY);
    let claims = parse_token(&token, KEY).unwrap();
    let payload = payload_of(&mint_token(&claims, KEY, 1800));
    assert!(payload.get("groups").is_none());
    assert!(payload.get("role").is_none());
    assert_eq!(payload["sub"], json!("alice"));
    assert_eq!(payload["conv"], json!("conv-1"));
}

#[test]
fn extra_claims_on_a_token_with_a_bad_signature_are_never_read() {
    let token = idp_token(json!({ "role": "owner" }), b"someone-elses-key");
    assert!(matches!(
        parse_token(&token, KEY),
        Err(TokenError::BadSignature)
    ));
}

#[test]
fn a_signature_of_the_wrong_length_is_bad_not_a_panic() {
    let token = make_token("alice", Some("conv-1"), 100, 200, KEY);
    let (signing_input, signature) = token.rsplit_once('.').unwrap();
    let full = URL_SAFE_NO_PAD.decode(signature).unwrap();
    let mut longer = full.clone();
    longer.push(0);
    for tag in [
        Vec::new(),
        vec![0u8],
        full[..full.len() - 1].to_vec(),
        longer,
    ] {
        let forged = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(&tag));
        assert!(
            matches!(parse_token(&forged, KEY), Err(TokenError::BadSignature)),
            "a {}-byte tag must be a bad signature",
            tag.len()
        );
    }
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
        SigningKey::Present(KEY),
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
        SigningKey::Present(KEY),
        &sessions,
    );
    assert!(matches!(outcome, Preflight::Forward(plan) if plan.rewrite_authorization.is_some()));
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
        SigningKey::Present(KEY),
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
        SigningKey::Present(KEY),
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
        SigningKey::Present(KEY),
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
        SigningKey::Present(KEY),
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
        SigningKey::Present(KEY),
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
        SigningKey::Present(KEY),
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
            SigningKey::Present(KEY),
            &sessions
        ),
        Preflight::Forward(plan) if plan.rewrite_authorization.is_none()
            && plan.inject_renewed_token.is_none()
            && !plan.seed_from_response
    ));
    assert!(matches!(
        preflight(
            &Method::GET,
            "/v3/directline",
            &[],
            SigningKey::Present(KEY),
            &sessions
        ),
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
            SigningKey::NotConfigured,
            &sessions
        ),
        Preflight::Forward(_)
    ));
    let Preflight::Respond(resp) = preflight(
        &Method::POST,
        "/v3/directline/tokens/refresh",
        &auth("whatever"),
        SigningKey::NotConfigured,
        &sessions,
    ) else {
        panic!("expected respond");
    };
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn an_unreadable_signing_key_refuses_activities_instead_of_forwarding() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let now = now_secs();
    let token = make_token("alice", Some("conv-1"), now, now + 1800, KEY);
    let outcome = preflight(
        &Method::POST,
        "/v3/directline/conversations/conv-1/activities",
        &auth(&token),
        SigningKey::Unavailable,
        &sessions,
    );
    let Preflight::Respond(resp) = outcome else {
        panic!("an unreadable signing key must never forward an unverified request");
    };
    let (status, body) = body_of(resp);
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["code"], "ServerError");
}

#[test]
fn an_unreadable_signing_key_refuses_reconnect_and_conversation_create() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    for (method, path) in [
        (Method::GET, "/v3/directline/conversations/conv-1"),
        (Method::POST, "/v3/directline/conversations"),
    ] {
        let outcome = preflight(&method, path, &[], SigningKey::Unavailable, &sessions);
        let Preflight::Respond(resp) = outcome else {
            panic!("{path} forwarded an unverified request on an unreadable key");
        };
        let (status, _) = body_of(resp);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{path}");
    }
}

#[test]
fn an_empty_signing_key_is_refused_rather_than_treated_as_absent() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let outcome = preflight(
        &Method::POST,
        "/v3/directline/conversations/conv-1/activities",
        &[],
        SigningKey::Present(b""),
        &sessions,
    );
    let Preflight::Respond(resp) = outcome else {
        panic!("an empty key cannot verify anything and must not forward");
    };
    let (status, _) = body_of(resp);
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn a_tenant_with_no_key_configured_is_still_served() {
    // Auth was never switched on for this provider. That is a deliberate
    // posture, not a degraded one, and it must keep working exactly as it
    // did before this change — otherwise the fix takes a live tenant down.
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let outcome = preflight(
        &Method::POST,
        "/v3/directline/conversations/conv-1/activities",
        &[],
        SigningKey::NotConfigured,
        &sessions,
    );
    assert!(matches!(outcome, Preflight::Forward(_)));
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

/// Headline scenario: a conversation that posts an activity every minute for
/// well over the token's lifetime. We can't actually wait half an hour, so we
/// model "time has moved on" by handing in tokens whose `iat`/`exp` are in the
/// past while the in-process sliding window — `touch`ed on every accepted post
/// — stays alive. This mirrors the `repro-slow.sh --activity-heartbeat` flow:
/// before the fix the post at t ≈ 1801 s 401s; after it, every post is renewed
/// and forwarded with a fresh, non-expired bearer.
#[test]
fn renewal_keeps_a_busy_conversation_alive_past_the_original_ttl() {
    let ttl: i64 = 1800;
    let sessions = DirectLineSessions::with_ttl_secs(ttl as u64);
    let conv = "conv-busy";
    let path = format!("/v3/directline/conversations/{conv}/activities");

    // t = 0: conversation created -> window seeded.
    sessions.touch(conv);

    // The client keeps presenting the *same* bearer it was issued at t = 0
    // (i.e. it never adopts the renewed token), so by minute 31 it is
    // wall-clock-expired. Each accepted post must still succeed.
    for minute in 1..=35_i64 {
        let elapsed = minute * 60;
        let now = now_secs();
        // Modelled as "the t = 0 bearer, observed `elapsed` seconds later".
        let original = make_token("alice", Some(conv), now - elapsed, now - elapsed + ttl, KEY);
        match preflight(
            &Method::POST,
            &path,
            &auth(&original),
            SigningKey::Present(KEY),
            &sessions,
        ) {
            Preflight::Forward(plan) => {
                let renewed = plan
                    .rewrite_authorization
                    .as_deref()
                    .and_then(|h| h.strip_prefix("Bearer "))
                    .expect("renewed bearer forwarded upstream");
                let claims = parse_token(renewed, KEY).expect("renewed token verifies");
                assert_eq!(claims.conv.as_deref(), Some(conv));
                assert!(
                    claims.exp > now_secs(),
                    "minute {minute}: forwarded bearer must be in the future, got exp={} now={}",
                    claims.exp,
                    now_secs()
                );
                // POST always echoes the renewed token to the client.
                assert!(plan.inject_renewed_token.is_some());
            }
            Preflight::Respond(resp) => panic!(
                "minute {minute}: post should be accepted, got status {}",
                resp.status()
            ),
        }
        assert!(
            sessions.is_alive(conv),
            "minute {minute}: window must stay alive"
        );
    }

    // Sanity: an unrelated, untouched conversation with the same expired
    // token *is* rejected — the window is what keeps the busy one alive.
    let stale = make_token(
        "alice",
        Some("conv-idle"),
        now_secs() - 5000,
        now_secs() - 3600,
        KEY,
    );
    assert!(matches!(
        preflight(
            &Method::POST,
            "/v3/directline/conversations/conv-idle/activities",
            &auth(&stale),
            SigningKey::Present(KEY),
            &sessions,
        ),
        Preflight::Respond(_)
    ));
}

#[test]
fn get_poll_with_fresh_token_renews_upstream_but_does_not_bloat_response() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    sessions.touch("conv-1");
    let now = now_secs();
    let fresh = make_token("alice", Some("conv-1"), now, now + 1800, KEY);
    let Preflight::Forward(plan) = preflight(
        &Method::GET,
        "/v3/directline/conversations/conv-1/activities",
        &auth(&fresh),
        SigningKey::Present(KEY),
        &sessions,
    ) else {
        panic!("expected forward");
    };
    assert!(plan.rewrite_authorization.is_some());
    assert!(plan.inject_renewed_token.is_none());
    assert!(sessions.is_alive("conv-1"));
}

#[test]
fn get_poll_with_stale_token_echoes_renewed_token() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    sessions.touch("conv-1");
    let now = now_secs();
    // Token is past 50 % of its life (remaining 800 of 1800).
    let stale = make_token("alice", Some("conv-1"), now - 1000, now + 800, KEY);
    let Preflight::Forward(plan) = preflight(
        &Method::GET,
        "/v3/directline/conversations/conv-1/activities",
        &auth(&stale),
        SigningKey::Present(KEY),
        &sessions,
    ) else {
        panic!("expected forward");
    };
    assert!(plan.rewrite_authorization.is_some());
    assert!(plan.inject_renewed_token.is_some());
}

/// Was `reconnect_accepts_unbound_token_and_keeps_window_alive`: start used
/// to bind the conversation-less token to the conversation in the URL,
/// which granted it to anyone who knew the id (G2). A signed-in visitor's
/// conversation-less token is now forwarded as presented, for the provider
/// to decide; an anonymous one is refused (see `owner_tests`).
#[test]
fn reconnect_forwards_a_verified_unbound_token_without_binding_it() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let now = now_secs();
    let unbound = verified_unbound("alice", now, now + 1800);
    let Preflight::Forward(plan) = preflight(
        &Method::GET,
        "/v3/directline/conversations/conv-7",
        &auth(&unbound),
        SigningKey::Present(KEY),
        &sessions,
    ) else {
        panic!("expected forward");
    };
    assert_eq!(plan.rewrite_authorization, None);
    assert!(!plan.token_bound_to_conversation);
    assert!(!sessions.is_alive("conv-7"));
}

/// A conversation-less token carrying `verified: true` (a signed-in visitor).
fn verified_unbound(sub: &str, iat: i64, exp: i64) -> String {
    sign_raw(
        &json!({
            "iss": TOKEN_ISS, "aud": TOKEN_AUD, "sub": sub,
            "iat": iat, "nbf": iat, "exp": exp,
            "ctx": { "env": "default", "tenant": "demo" },
            "verified": true,
        }),
        KEY,
    )
}

fn forward_plan(method: Method, path: &str, token: &str) -> ForwardPlan {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    match preflight(
        &method,
        path,
        &auth(token),
        SigningKey::Present(KEY),
        &sessions,
    ) {
        Preflight::Forward(plan) => plan,
        Preflight::Respond(_) => panic!("expected forward"),
    }
}

#[test]
fn only_a_token_already_bound_to_the_conversation_may_repin() {
    let now = now_secs();
    let bound = make_token("alice", Some("conv-7"), now, now + 1800, KEY);
    // An anonymous conversation-less token no longer reaches the provider
    // at all; a signed-in one is forwarded and still must not re-pin.
    let unbound = verified_unbound("alice", now, now + 1800);
    for (method, path) in [
        (Method::GET, "/v3/directline/conversations/conv-7"),
        (
            Method::POST,
            "/v3/directline/conversations/conv-7/activities",
        ),
        (
            Method::GET,
            "/v3/directline/conversations/conv-7/activities",
        ),
    ] {
        assert!(
            forward_plan(method.clone(), path, &bound).token_bound_to_conversation,
            "a bound token may re-pin {method} {path}"
        );
        assert!(
            !forward_plan(method.clone(), path, &unbound).token_bound_to_conversation,
            "a conversation-less token must not re-pin {method} {path}"
        );
    }
}

#[test]
fn a_token_bound_to_another_conversation_is_refused_so_it_cannot_pin() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let now = now_secs();
    let other = make_token("alice", Some("conv-OTHER"), now, now + 1800, KEY);
    for (method, path) in [
        (Method::GET, "/v3/directline/conversations/conv-7"),
        (
            Method::POST,
            "/v3/directline/conversations/conv-7/activities",
        ),
    ] {
        assert!(
            matches!(
                preflight(
                    &method,
                    path,
                    &auth(&other),
                    SigningKey::Present(KEY),
                    &sessions
                ),
                Preflight::Respond(_)
            ),
            "{method} {path} must be refused before it can reach the provider"
        );
    }
}

#[test]
fn activities_missing_authorization_is_401() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let Preflight::Respond(resp) = preflight(
        &Method::POST,
        "/v3/directline/conversations/conv-1/activities",
        &[],
        SigningKey::Present(KEY),
        &sessions,
    ) else {
        panic!("expected reject");
    };
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let (_, body) = body_of(resp);
    assert_eq!(body["code"], "Unauthorized");
}

#[test]
fn response_helpers_ignore_non_2xx() {
    let mut not_found = IngressHttpResponse {
        status: 404,
        headers: vec![],
        body: Some(serde_json::to_vec(&json!({ "conversationId": "c" })).unwrap()),
    };
    let before = not_found.body.clone();
    inject_renewed_token(&mut not_found, "tok", 1800);
    assert_eq!(not_found.body, before, "must not touch a 404 body");
    assert_eq!(conversation_id_from_response(&not_found), None);

    let mut server_error = IngressHttpResponse {
        status: 500,
        headers: vec![],
        body: Some(b"not json".to_vec()),
    };
    inject_renewed_token(&mut server_error, "tok", 1800);
    assert_eq!(server_error.body.as_deref(), Some(b"not json".as_ref()));
}
