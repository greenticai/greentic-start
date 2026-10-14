//! The anonymous embed flow that MUST keep working once start refuses a
//! conversation-less anonymous token on a conversation route:
//!
//! `/token` (conversation-less) → `POST /conversations` → adopt the bound
//! token from the create response → `/activities`, reconnect, refresh.
//!
//! The provider is a stub that answers like the webchat provider does (the
//! create response carries a token bound to the new conversation, every
//! conversation route insists on a token bound to it). The request is run
//! through start's real `preflight`, `apply_authorization_rewrite`,
//! `conversation_id_from_response` and `inject_renewed_token`, in the order
//! both ingress paths use them. A full ingress test would need a WASM
//! webchat provider; this is the closest layer that exercises every start
//! decision on the way.

use super::test_support::{KEY, auth, make_token};
use super::*;

const CONV: &str = "conv-embed-1";
const GUEST: &str = "guest-embed";

/// What the stub provider saw and answered.
struct Exchange {
    forwarded_bearer: Option<String>,
    response: IngressHttpResponse,
}

/// Runs one request through start the way the ingress does and, when start
/// forwards it, through the stub provider. `Err` = start answered itself.
fn send(
    method: &str,
    path: &str,
    token: &str,
    sessions: &DirectLineSessions,
) -> Result<Exchange, StatusCode> {
    let method = Method::from_bytes(method.as_bytes()).expect("method");
    let mut headers = auth(token);
    let plan = match preflight(&method, path, &headers, SigningKey::Present(KEY), sessions) {
        Preflight::Respond(resp) => return Err(resp.status()),
        Preflight::Forward(plan) => plan,
    };
    if let Some(rewrite) = plan.rewrite_authorization.as_deref() {
        apply_authorization_rewrite(&mut headers, rewrite);
    }
    let forwarded_bearer = bearer(&headers);
    let mut response = stub_provider(&method, path, forwarded_bearer.as_deref());
    if plan.seed_from_response
        && let Some(conv) = conversation_id_from_response(&response)
    {
        sessions.touch(&conv);
    }
    if let Some(renewed) = plan.inject_renewed_token.as_deref() {
        inject_renewed_token(&mut response, renewed, sessions.ttl_secs());
    }
    Ok(Exchange {
        forwarded_bearer,
        response,
    })
}

/// The webchat provider, reduced to the two rules that matter here.
fn stub_provider(method: &Method, path: &str, bearer: Option<&str>) -> IngressHttpResponse {
    let claims = bearer.and_then(|t| parse_token(t, KEY).ok());
    let json_response = |status: u16, body: Value| IngressHttpResponse {
        status,
        headers: Vec::new(),
        body: Some(serde_json::to_vec(&body).unwrap()),
    };
    let Some(claims) = claims else {
        return json_response(401, json!({ "error": "unauthorized" }));
    };
    if *method == Method::POST && path == "/v3/directline/conversations" {
        assert!(
            claims.conv.is_none(),
            "create needs a conversation-less token"
        );
        let now = now_secs();
        let bound = make_token(&claims.sub, Some(CONV), now, now + 1800, KEY);
        return json_response(
            201,
            json!({ "conversationId": CONV, "token": bound, "expires_in": 1800 }),
        );
    }
    if claims.conv.as_deref() != Some(CONV) {
        return json_response(403, json!({ "error": "forbidden" }));
    }
    json_response(200, json!({ "id": "activity-1", "conversationId": CONV }))
}

fn body_json(response: &IngressHttpResponse) -> Value {
    serde_json::from_slice(response.body.as_deref().unwrap_or(b"{}")).unwrap()
}

fn conv_of(token: &str) -> Option<String> {
    parse_token(token, KEY).unwrap().conv
}

#[test]
fn an_anonymous_embed_creates_adopts_the_bound_token_and_talks() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let now = now_secs();
    // 1. `/token`: conversation-less, anonymous.
    let bootstrap = make_token(GUEST, None, now, now + 1800, KEY);

    // 2. Create: forwarded untouched, the window is seeded from the response.
    let created = send(
        "POST",
        "/v3/directline/conversations",
        &bootstrap,
        &sessions,
    )
    .expect("start forwards the create");
    assert_eq!(created.response.status, 201);
    assert_eq!(
        created.forwarded_bearer.as_deref(),
        Some(bootstrap.as_str())
    );
    assert!(sessions.is_alive(CONV), "the create seeds the window");

    // 3. The client adopts the token from the create response.
    let mut token = body_json(&created.response)["token"]
        .as_str()
        .expect("the create response carries a token")
        .to_string();
    assert_eq!(conv_of(&token).as_deref(), Some(CONV));

    // 4. Post, poll, reconnect: each reaches the provider with a token bound
    //    to THIS conversation, and a POST hands back a renewed one.
    let activities = format!("/v3/directline/conversations/{CONV}/activities");
    let posted = send("POST", &activities, &token, &sessions).expect("post is forwarded");
    assert_eq!(posted.response.status, 200, "the provider accepted it");
    assert_eq!(
        conv_of(posted.forwarded_bearer.as_deref().unwrap()).as_deref(),
        Some(CONV)
    );
    let renewed = body_json(&posted.response)["_directline"]["renewed_token"]
        .as_str()
        .expect("a POST echoes the renewed token")
        .to_string();
    assert_eq!(conv_of(&renewed).as_deref(), Some(CONV));
    token = renewed;

    let reconnect = format!("/v3/directline/conversations/{CONV}");
    for (m, path) in [("GET", activities.as_str()), ("GET", reconnect.as_str())] {
        let exchange = send(m, path, &token, &sessions).expect("forwarded");
        assert_eq!(exchange.response.status, 200, "{m} {path}");
    }

    // 5. Refresh keeps the conversation.
    let refreshed = match preflight(
        &Method::POST,
        "/v3/directline/tokens/refresh",
        &auth(&token),
        SigningKey::Present(KEY),
        &sessions,
    ) {
        Preflight::Respond(resp) => {
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(async {
                    http_body_util::BodyExt::collect(resp.into_body())
                        .await
                        .unwrap()
                        .to_bytes()
                });
            serde_json::from_slice::<Value>(&bytes).unwrap()
        }
        Preflight::Forward(_) => panic!("refresh is served by start"),
    };
    assert_eq!(refreshed["conversationId"], json!(CONV));
    let refreshed = refreshed["token"].as_str().unwrap();
    assert_eq!(conv_of(refreshed).as_deref(), Some(CONV));
    let after_refresh = send("POST", &activities, refreshed, &sessions).expect("forwarded");
    assert_eq!(after_refresh.response.status, 200);
}

/// A `tokenUrl` embed that keeps sending a `/token` bearer on the existing
/// conversation is refused by start before the provider is asked, in every
/// method spelling and even with a freshly fetched `/token` token.
#[test]
fn a_token_url_bearer_on_the_existing_conversation_is_refused_by_start() {
    let sessions = DirectLineSessions::with_ttl_secs(1800);
    let now = now_secs();
    let bootstrap = make_token(GUEST, None, now, now + 1800, KEY);
    send(
        "POST",
        "/v3/directline/conversations",
        &bootstrap,
        &sessions,
    )
    .expect("create");
    let refetched = make_token(GUEST, None, now, now + 1800, KEY);

    let activities = format!("/v3/directline/conversations/{CONV}/activities");
    let reconnect = format!("/v3/directline/conversations/{CONV}");
    for token in [&bootstrap, &refetched] {
        for (m, path) in [
            ("POST", activities.as_str()),
            ("post", activities.as_str()),
            ("GET", activities.as_str()),
            ("GET", reconnect.as_str()),
            ("get", reconnect.as_str()),
        ] {
            assert_eq!(
                send(m, path, token, &sessions).err(),
                Some(StatusCode::FORBIDDEN),
                "{m} {path}: start must refuse a conversation-less anonymous token"
            );
        }
    }
}
