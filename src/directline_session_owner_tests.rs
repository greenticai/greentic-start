//! Conversation ownership on the start side (G2, reconnect-token hardening).
//!
//! greentic-start never binds a token to a conversation on the caller's
//! behalf: a conversation-less token is either refused here (anonymous) or
//! forwarded untouched for the provider to decide (signed in). See
//! `docs/directline-conversation-ownership.md`.

use super::test_support::{KEY, auth, make_token};
use super::*;
use http_body_util::BodyExt;

const OWNER_REQUIRED_BODY: &str = r#"{"code":"ConversationOwnerRequired","error":"forbidden","message":"this conversation belongs to another session; start a new conversation"}"#;

/// The three conversation-scoped routes start screens.
const CONVERSATION_ROUTES: [(Method, &str); 3] = [
    (Method::GET, "/v3/directline/conversations/conv-7"),
    (
        Method::POST,
        "/v3/directline/conversations/conv-7/activities",
    ),
    (
        Method::GET,
        "/v3/directline/conversations/conv-7/activities",
    ),
];

/// A token carrying an arbitrary `verified` value (absent when `None`).
fn token_with_verified(
    sub: &str,
    conv: Option<&str>,
    iat: i64,
    exp: i64,
    verified: Option<Value>,
) -> String {
    let mut extra = serde_json::Map::new();
    if let Some(value) = verified {
        extra.insert("verified".to_string(), value);
    }
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
        extra,
    };
    let header_enc = URL_SAFE_NO_PAD.encode(JOSE_HEADER);
    let payload_enc = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_enc}.{payload_enc}");
    let sig = URL_SAFE_NO_PAD.encode(hs256(&signing_input, KEY));
    format!("{signing_input}.{sig}")
}

fn verified_token(conv: Option<&str>, iat: i64, exp: i64) -> String {
    token_with_verified("acme:users:7", conv, iat, exp, Some(json!(true)))
}

fn run(method: &Method, path: &str, token: &str, sessions: &DirectLineSessions) -> Preflight {
    preflight(
        method,
        path,
        &auth(token),
        SigningKey::Present(KEY),
        sessions,
    )
}

/// Status, headers and raw body bytes of a locally served answer.
fn raw_of(resp: Response<Full<Bytes>>) -> (StatusCode, Vec<(String, String)>, Vec<u8>) {
    let status = resp.status();
    let headers = resp
        .headers()
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let bytes = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async { resp.into_body().collect().await.unwrap().to_bytes() });
    (status, headers, bytes.to_vec())
}

fn respond(outcome: Preflight) -> (StatusCode, Vec<(String, String)>, Vec<u8>) {
    match outcome {
        Preflight::Respond(resp) => raw_of(resp),
        Preflight::Forward(plan) => panic!("expected a local answer, got forward {plan:?}"),
    }
}

fn forward(outcome: Preflight) -> ForwardPlan {
    match outcome {
        Preflight::Forward(plan) => plan,
        Preflight::Respond(resp) => {
            let (status, _, body) = raw_of(resp);
            panic!(
                "expected forward, got {status} {}",
                String::from_utf8_lossy(&body)
            )
        }
    }
}

fn assert_owner_required(outcome: Preflight, what: &str) {
    let (status, _, body) = respond(outcome);
    assert_eq!(status, StatusCode::FORBIDDEN, "{what}");
    let got: Value = serde_json::from_slice(&body).unwrap();
    let want: Value = serde_json::from_str(OWNER_REQUIRED_BODY).unwrap();
    assert_eq!(got, want, "{what}: the body must match the provider's");
}

#[test]
fn anonymous_conversation_less_token_is_refused_on_reconnect_and_activities() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let now = now_secs();
    let anonymous = make_token("guest-1", None, now, now + 1800, KEY);
    for (method, path) in CONVERSATION_ROUTES {
        assert_owner_required(
            run(&method, path, &anonymous, &sessions),
            &format!("{method} {path}"),
        );
    }
    assert!(!sessions.is_alive("conv-7"), "a refusal must not touch");
}

#[test]
fn only_an_explicit_json_true_counts_as_verified() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let now = now_secs();
    for verified in [
        None,
        Some(json!(false)),
        Some(json!("true")),
        Some(json!(1)),
        Some(Value::Null),
    ] {
        let token = token_with_verified("acme:users:7", None, now, now + 1800, verified.clone());
        for (method, path) in CONVERSATION_ROUTES {
            assert_owner_required(
                run(&method, path, &token, &sessions),
                &format!("verified={verified:?} {method} {path}"),
            );
        }
    }
}

#[test]
fn the_refusal_does_not_reveal_whether_the_conversation_exists() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    sessions.touch("conv-7");
    let now = now_secs();
    let anonymous = make_token("guest-1", None, now, now + 1800, KEY);
    for (method, path) in CONVERSATION_ROUTES {
        let live = respond(run(&method, path, &anonymous, &sessions));
        let unknown_path = path.replace("conv-7", "9b0d6f2e-unknown");
        let unknown = respond(run(&method, &unknown_path, &anonymous, &sessions));
        assert_eq!(
            live, unknown,
            "{method} {path}: live vs unknown conversation"
        );
    }
}

#[test]
fn verified_conversation_less_token_is_forwarded_unchanged() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let now = now_secs();
    let token = verified_token(None, now, now + 1800);
    for (method, path) in CONVERSATION_ROUTES {
        let plan = forward(run(&method, path, &token, &sessions));
        assert_eq!(
            plan.rewrite_authorization, None,
            "{method} {path}: forwarded as presented"
        );
        assert_eq!(plan.inject_renewed_token, None, "{method} {path}");
        assert!(!plan.token_bound_to_conversation, "{method} {path}");
        assert!(!plan.seed_from_response, "{method} {path}");
    }
    assert!(
        !sessions.is_alive("conv-7"),
        "only a bound request extends the conversation's window"
    );
    assert_eq!(sessions.tracked(), 0);
}

#[test]
fn expired_verified_conversation_less_token_is_rejected_even_with_a_live_window() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    sessions.touch("conv-7");
    let now = now_secs();
    let expired = verified_token(None, now - 3600, now - 1800);
    for (method, path) in CONVERSATION_ROUTES {
        let (status, _, body) = respond(run(&method, path, &expired, &sessions));
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], json!("TokenExpired"), "{method} {path}");
    }
}

#[test]
fn an_expired_anonymous_conversation_less_token_is_refused_as_owner_required() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    sessions.touch("conv-7");
    let now = now_secs();
    let expired = make_token("guest-1", None, now - 3600, now - 1800, KEY);
    for (method, path) in CONVERSATION_ROUTES {
        assert_owner_required(
            run(&method, path, &expired, &sessions),
            &format!("{method} {path}"),
        );
    }
}

#[test]
fn a_bound_token_is_re_minted_with_its_own_conversation_only() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let now = now_secs();
    let bound = make_token("guest-1", Some("conv-7"), now, now + 1800, KEY);
    for (method, path) in CONVERSATION_ROUTES {
        let plan = forward(run(&method, path, &bound, &sessions));
        assert!(plan.token_bound_to_conversation, "{method} {path}");
        let renewed = plan
            .rewrite_authorization
            .as_deref()
            .and_then(|h| h.strip_prefix("Bearer "))
            .expect("a bound token is renewed upstream");
        assert_eq!(
            parse_token(renewed, KEY).unwrap().conv.as_deref(),
            Some("conv-7")
        );
    }
    assert!(sessions.is_alive("conv-7"));
}

/// Every token start emits — rewritten upstream, echoed to the client, or
/// served locally — carries exactly the `conv` it was handed. If this ever
/// fails, start has started granting conversations again.
#[test]
fn start_never_mints_a_conv_it_did_not_receive() {
    let now = now_secs();
    let tokens: Vec<(&str, String)> = vec![
        (
            "anonymous unbound",
            make_token("guest-1", None, now, now + 1800, KEY),
        ),
        (
            "anonymous unbound, expired",
            make_token("guest-1", None, now - 3600, now - 1800, KEY),
        ),
        ("verified unbound", verified_token(None, now, now + 1800)),
        (
            "verified unbound, stale",
            verified_token(None, now - 1700, now + 100),
        ),
        (
            "anonymous bound",
            make_token("guest-1", Some("conv-7"), now, now + 1800, KEY),
        ),
        (
            "verified bound, stale",
            verified_token(Some("conv-7"), now - 1700, now + 100),
        ),
        (
            "bound elsewhere",
            make_token("guest-1", Some("conv-OTHER"), now, now + 1800, KEY),
        ),
    ];
    let routes: Vec<(Method, &str)> = vec![
        (Method::POST, "/v3/directline/conversations"),
        (Method::POST, "/v3/directline/tokens/refresh"),
        (Method::GET, "/v3/directline/conversations/conv-7"),
        (
            Method::POST,
            "/v3/directline/conversations/conv-7/activities",
        ),
        (
            Method::GET,
            "/v3/directline/conversations/conv-7/activities",
        ),
    ];
    for policy in [
        AnonymousUnboundPolicy::Refuse,
        AnonymousUnboundPolicy::WarnOnly,
    ] {
        for (label, token) in &tokens {
            let input_conv = parse_token(token, KEY).unwrap().conv;
            for (method, path) in &routes {
                let sessions =
                    DirectLineSessions::with_ttl_secs(1800).with_anonymous_unbound_policy(policy);
                // A live window so the expired cases reach their deepest branch.
                sessions.touch("conv-7");
                let emitted: Vec<String> = match run(method, path, token, &sessions) {
                    Preflight::Forward(plan) => plan
                        .rewrite_authorization
                        .iter()
                        .filter_map(|h| h.strip_prefix("Bearer ").map(str::to_string))
                        .chain(plan.inject_renewed_token.clone())
                        .collect(),
                    Preflight::Respond(resp) => {
                        let (_, _, body) = raw_of(resp);
                        serde_json::from_slice::<Value>(&body)
                            .ok()
                            .and_then(|v| {
                                v.get("token").and_then(Value::as_str).map(str::to_string)
                            })
                            .into_iter()
                            .collect()
                    }
                };
                for minted in emitted {
                    let conv = parse_token(&minted, KEY).unwrap().conv;
                    assert_eq!(
                        conv, input_conv,
                        "{policy:?} {label} {method} {path}: emitted a token for another conversation"
                    );
                }
            }
        }
    }
}

#[test]
fn warn_only_forwards_an_anonymous_conversation_less_token_without_binding_it() {
    let sessions = DirectLineSessions::with_ttl_secs(1800)
        .with_anonymous_unbound_policy(AnonymousUnboundPolicy::WarnOnly);
    let now = now_secs();
    let anonymous = make_token("guest-1", None, now, now + 1800, KEY);
    for (method, path) in CONVERSATION_ROUTES {
        let plan = forward(run(&method, path, &anonymous, &sessions));
        assert_eq!(plan.rewrite_authorization, None, "{method} {path}");
        assert_eq!(plan.inject_renewed_token, None, "{method} {path}");
        assert!(!plan.token_bound_to_conversation, "{method} {path}");
    }
    assert!(!sessions.is_alive("conv-7"));
    // Expired still fails: the warn-only mode relaxes the ownership refusal,
    // not expiry.
    let expired = make_token("guest-1", None, now - 3600, now - 1800, KEY);
    let (status, _, _) = respond(run(
        &Method::GET,
        "/v3/directline/conversations/conv-7",
        &expired,
        &sessions,
    ));
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[test]
fn warn_only_warns_once_per_conversation() {
    let sessions = DirectLineSessions::with_ttl_secs(1800)
        .with_anonymous_unbound_policy(AnonymousUnboundPolicy::WarnOnly);
    assert!(sessions.first_anonymous_unbound_use("conv-7"));
    assert!(!sessions.first_anonymous_unbound_use("conv-7"));
    assert!(sessions.first_anonymous_unbound_use("conv-8"));
}

#[test]
fn the_policy_defaults_to_refuse_and_only_an_explicit_off_relaxes_it() {
    assert_eq!(
        anonymous_unbound_policy_from(None),
        AnonymousUnboundPolicy::Refuse
    );
    for off in ["0", "false", "no", "off", " OFF ", "False"] {
        assert_eq!(
            anonymous_unbound_policy_from(Some(off)),
            AnonymousUnboundPolicy::WarnOnly,
            "{off:?}"
        );
    }
    for on in ["1", "true", "yes", "on", "", "garbage"] {
        assert_eq!(
            anonymous_unbound_policy_from(Some(on)),
            AnonymousUnboundPolicy::Refuse,
            "{on:?} must fail closed"
        );
    }
}
