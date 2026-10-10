//! An HTTP method is case-insensitive on every layer that routes a Direct
//! Line request (start's route table, the provider's router). The session
//! preflight must agree, or `get /v3/directline/conversations/{id}` skips
//! every check below and reaches a provider that answers it as a `GET`.

use super::test_support::{KEY, auth, make_token};
use super::*;

fn method(raw: &str) -> Method {
    Method::from_bytes(raw.as_bytes()).expect("a valid method token")
}

const GET_SPELLINGS: [&str; 4] = ["GET", "get", "Get", "gEt"];
const POST_SPELLINGS: [&str; 4] = ["POST", "post", "Post", "pOsT"];

fn run(method_raw: &str, path: &str, token: &str, sessions: &DirectLineSessions) -> Preflight {
    preflight(
        &method(method_raw),
        path,
        &auth(token),
        SigningKey::Present(KEY),
        sessions,
    )
}

fn status_and_code(outcome: Preflight) -> Option<(StatusCode, String)> {
    match outcome {
        Preflight::Forward(_) => None,
        Preflight::Respond(resp) => {
            let status = resp.status();
            let bytes = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(async {
                    http_body_util::BodyExt::collect(resp.into_body())
                        .await
                        .unwrap()
                        .to_bytes()
                });
            let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let code = body
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            Some((status, code))
        }
    }
}

fn verified_unbound(now: i64) -> String {
    let claims = DlClaims {
        iss: TOKEN_ISS.to_string(),
        aud: TOKEN_AUD.to_string(),
        sub: "acme:users:7".to_string(),
        iat: now,
        nbf: now,
        exp: now + 1800,
        ctx: DlContext {
            env: "default".to_string(),
            tenant: "demo".to_string(),
            team: None,
        },
        conv: None,
        extra: serde_json::Map::from_iter([("verified".to_string(), json!(true))]),
    };
    mint_token(&claims, KEY, 1800)
}

/// Each conversation-scoped route, with every spelling of its method.
fn conversation_routes() -> Vec<(&'static str, &'static str)> {
    let mut routes = Vec::new();
    for m in GET_SPELLINGS {
        routes.push((m, "/v3/directline/conversations/conv-7"));
        routes.push((m, "/v3/directline/conversations/conv-7/activities"));
    }
    for m in POST_SPELLINGS {
        routes.push((m, "/v3/directline/conversations/conv-7/activities"));
    }
    routes
}

#[test]
fn an_anonymous_conversation_less_token_is_refused_whatever_the_method_case() {
    let now = now_secs();
    let anonymous = make_token("guest-1", None, now, now + 1800, KEY);
    for (m, path) in conversation_routes() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        assert_eq!(
            status_and_code(run(m, path, &anonymous, &sessions)),
            Some((
                StatusCode::FORBIDDEN,
                "ConversationOwnerRequired".to_string()
            )),
            "{m} {path}"
        );
    }
}

#[test]
fn a_verified_conversation_less_token_is_forwarded_unchanged_whatever_the_method_case() {
    let now = now_secs();
    let verified = verified_unbound(now);
    for (m, path) in conversation_routes() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        match run(m, path, &verified, &sessions) {
            Preflight::Forward(plan) => {
                assert!(plan.rewrite_authorization.is_none(), "{m} {path}");
                assert!(plan.inject_renewed_token.is_none(), "{m} {path}");
                assert!(!plan.token_bound_to_conversation, "{m} {path}");
            }
            Preflight::Respond(resp) => panic!("{m} {path}: answered {}", resp.status()),
        }
        assert!(!sessions.is_alive("conv-7"), "{m} {path}: touched");
    }
}

#[test]
fn a_bound_token_is_screened_and_renewed_whatever_the_method_case() {
    let now = now_secs();
    let bound = make_token("guest-1", Some("conv-7"), now, now + 1800, KEY);
    let elsewhere = make_token("guest-1", Some("conv-OTHER"), now, now + 1800, KEY);
    for (m, path) in conversation_routes() {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        let Preflight::Forward(plan) = run(m, path, &bound, &sessions) else {
            panic!("{m} {path}: a bound token must be forwarded");
        };
        assert!(plan.rewrite_authorization.is_some(), "{m} {path}");
        assert!(plan.token_bound_to_conversation, "{m} {path}");
        // A POST on /activities always echoes the renewed token.
        if m.eq_ignore_ascii_case("POST") {
            assert!(plan.inject_renewed_token.is_some(), "{m} {path}");
        }
        assert_eq!(
            status_and_code(run(m, path, &elsewhere, &sessions)),
            Some((StatusCode::FORBIDDEN, "WrongConversation".to_string())),
            "{m} {path}"
        );
    }
}

#[test]
fn conversation_create_is_screened_whatever_the_method_case() {
    let now = now_secs();
    let unbound = make_token("guest-1", None, now, now + 1800, KEY);
    let bound = make_token("guest-1", Some("conv-7"), now, now + 1800, KEY);
    for m in POST_SPELLINGS {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        let Preflight::Forward(plan) = run(m, "/v3/directline/conversations", &unbound, &sessions)
        else {
            panic!("{m}: an unbound token creates a conversation");
        };
        assert!(plan.seed_from_response, "{m}: the create is recognised");
        assert_eq!(
            status_and_code(run(m, "/v3/directline/conversations", &bound, &sessions)),
            Some((StatusCode::FORBIDDEN, "WrongConversation".to_string())),
            "{m}"
        );
    }
}

#[test]
fn token_refresh_is_served_locally_whatever_the_method_case() {
    let now = now_secs();
    let bound = make_token("guest-1", Some("conv-7"), now, now + 1800, KEY);
    for m in POST_SPELLINGS {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        let outcome = run(m, "/v3/directline/tokens/refresh", &bound, &sessions);
        assert!(
            matches!(outcome, Preflight::Respond(ref r) if r.status() == StatusCode::OK),
            "{m}: refresh is answered by start"
        );
    }
}

/// `/stream` is not screened by start in any spelling (the provider checks
/// the stream's own token); a lower-case spelling must not change that.
#[test]
fn the_stream_route_is_treated_the_same_in_every_method_case() {
    let now = now_secs();
    let anonymous = make_token("guest-1", None, now, now + 1800, KEY);
    for m in GET_SPELLINGS {
        let sessions = DirectLineSessions::with_ttl_secs(1800);
        let Preflight::Forward(plan) = run(
            m,
            "/v3/directline/conversations/conv-7/stream",
            &anonymous,
            &sessions,
        ) else {
            panic!("{m}: /stream is forwarded");
        };
        assert!(plan.rewrite_authorization.is_none(), "{m}");
        assert!(plan.inject_renewed_token.is_none(), "{m}");
    }
}
