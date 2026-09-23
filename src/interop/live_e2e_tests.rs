//! End-to-end checks against a REAL running `greentic-start`, over HTTP.
//!
//! Every other test of the worker-interop surface drives the listener
//! in-process. That leaves one whole class of failure uncovered: the staged
//! config and the runtime disagreeing about WHERE the config lives. When they
//! do, nothing is red — the deploy succeeds, the process boots, `/livez`
//! answers, and every interop call returns `401` (or the paths quietly stop
//! being reserved at all). An actual request against an actual process is the
//! only thing that catches it.
//!
//! These are `#[ignore]`d because they need an operator-provisioned `op` store
//! and a running server. Point them at one with two env vars:
//!
//! ```text
//! GREENTIC_INTEROP_E2E_BASE   the listener's base URL, e.g. http://127.0.0.1:8899
//! GREENTIC_INTEROP_E2E_TOKEN  a plaintext gtw_ token whose sha256 is staged
//! ```
//!
//! ```bash
//! GREENTIC_INTEROP_E2E_BASE=http://127.0.0.1:8899 \
//! GREENTIC_INTEROP_E2E_TOKEN=gtw_… \
//!   cargo test -p greentic-start --lib interop::live_e2e -- --ignored --nocapture
//! ```
//!
//! # Standing one up
//!
//! The recipe below is the one this suite was written against. Every step uses
//! the real tooling on purpose — staging the secret with `greentic-deployer op
//! secrets put` rather than writing the dev-store file by hand is half of what
//! is being proven, because the deployer is what a deploy actually runs.
//!
//! ```bash
//! # An isolated HOME. This is NOT optional: `dev_store_path::find_existing`
//! # resolves the dev store from `LocalFsStore::default_root()` — i.e. from
//! # $HOME — BEFORE it looks under the env dir that `--store-root` names. A
//! # store staged outside $HOME is staged somewhere the runtime will not read.
//! export FHOME=/tmp/interop-e2e-home
//! export STORE=$FHOME/.greentic/environments
//! mkdir -p "$STORE"
//! D() { env HOME="$FHOME" greentic-deployer op --store-root "$STORE" "$@"; }
//!
//! D env create --answers <(echo '{"environment_id":"local","name":"e2e",
//!     "public_base_url":"http://127.0.0.1:8899"}')
//! D trust-root bootstrap local
//! D env-packs add --answers <(echo '{"environment_id":"local","slot":"secrets",
//!     "kind":"greentic.secrets.dev-store@0.1.7",
//!     "pack_ref":"builtin://greentic.secrets.dev-store"}')
//! # Any .gtbundle whose pack carries a `manifest.cbor` flow. A card-only flow
//! # needs no LLM key.
//! D deploy --answers <(echo '{"environment_id":"local","bundle_id":"Support-Bot.v2",
//!     "bundle_path":"/path/to/bundle.gtbundle"}')
//!
//! # The interop config. The NAME is the bundle id through
//! # `ingress_secret_uri`'s canonicalisation — `Support-Bot.v2` becomes
//! # `support_bot_v2`. `op secrets put` REFUSES a non-canonical name rather
//! # than transforming one, which is what keeps the two sides in step.
//! D secrets put --answers <(echo '{"environment_id":"local",
//!     "path":"default/_/ingress/support_bot_v2",
//!     "value":"{\"v\":1,\"a2a\":true,\"mcp\":true,\"credentials\":[{\"id\":\"c_e2e\",
//!              \"sha256\":\"<sha256 of the gtw_ token>\"}],\"tenant_slug\":\"acme\",
//!              \"issuer\":\"http://127.0.0.1:8901\"}"}')
//!
//! env -i PATH=/usr/bin:/bin HOME="$FHOME" PORT=8899 \
//!     PUBLIC_BASE_URL=http://127.0.0.1:8899 GREENTIC_ENV=local \
//!   greentic-start start --store-root "$STORE" --env local --no-browser
//! ```
//!
//! # What is deliberately NOT here
//!
//! The Phase 0b generic-ingress gate needs a NON-loopback peer
//! ([`crate::revision_serve::peer_is_loopback_trusted`] reads the real socket
//! address and no header), so it cannot be exercised from a suite talking to
//! `127.0.0.1`. Bind the listener to a host-only non-loopback address
//! (`GREENTIC_GATEWAY_LISTEN_ADDR=172.17.0.1:8899`, the docker bridge) and
//! point `GREENTIC_INTEROP_E2E_BASE` at it to cover that half too;
//! [`the_generic_ingress_refuses_a_remote_caller_without_a_bearer`] then stops
//! skipping.

use serde_json::{Value, json};

const BASE_ENV: &str = "GREENTIC_INTEROP_E2E_BASE";
const TOKEN_ENV: &str = "GREENTIC_INTEROP_E2E_TOKEN";

/// The live server's base URL and a token staged for it.
///
/// Panics with the recipe rather than silently passing: an `#[ignore]`d test
/// that is RUN and then skips itself reports green for work it did not do.
fn target() -> (String, String) {
    let base = std::env::var(BASE_ENV).unwrap_or_else(|_| {
        panic!("{BASE_ENV} is unset; see this module's docs for how to stand a server up")
    });
    let token = std::env::var(TOKEN_ENV)
        .unwrap_or_else(|_| panic!("{TOKEN_ENV} is unset; it is the plaintext gtw_ token"));
    (base.trim_end_matches('/').to_string(), token)
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("client")
}

/// One `SendMessage` over the JSON-RPC binding, returning the `Message`.
fn a2a_send(base: &str, token: &str, context_id: Option<&str>, parts: Value) -> Value {
    let mut message = json!({"messageId": ulid::Ulid::new().to_string(),
                             "role": "ROLE_USER", "parts": parts});
    if let (Some(id), Some(map)) = (context_id, message.as_object_mut()) {
        map.insert("contextId".into(), json!(id));
    }
    let body = json!({"jsonrpc":"2.0","id":1,"method":"SendMessage",
                      "params":{"message": message}});
    let response = client()
        .post(format!("{base}/a2a"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .expect("send");
    assert_eq!(response.status().as_u16(), 200, "SendMessage should answer");
    let value: Value = response.json().expect("json");
    assert!(value.get("error").is_none(), "unexpected error: {value}");
    value["result"]["message"].clone()
}

/// Every text part of a reply, joined — what a human would read.
fn reply_text(message: &Value) -> String {
    message["parts"]
        .as_array()
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// A2A
// ---------------------------------------------------------------------------

/// The card is the one explicit MUST in A2A §8.2, and the two shapes asserted
/// here are the ones a strict client rejects silently:
///
/// - `securityRequirements[].schemes` is `map<string, StringList>`, so proto
///   JSON renders the value as `{"list": []}` and NEVER as a bare array;
/// - declaring a scheme is not requiring it — a card with an empty
///   `securityRequirements` reads as "no authentication" while every call is
///   refused.
#[test]
#[ignore = "needs a live greentic-start; see the module docs"]
fn the_agent_card_is_a2a_v1_conformant() {
    let (base, _) = target();
    let response = client()
        .get(format!("{base}/.well-known/agent-card.json"))
        .send()
        .expect("send");
    assert_eq!(response.status().as_u16(), 200, "the card is public");
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .map(|v| v.to_str().unwrap_or_default().to_string());
    let card: Value = response.json().expect("json");

    for field in [
        "name",
        "description",
        "supportedInterfaces",
        "version",
        "capabilities",
        "defaultInputModes",
        "defaultOutputModes",
        "skills",
    ] {
        assert!(card.get(field).is_some(), "card is missing `{field}`");
    }
    let interface = &card["supportedInterfaces"][0];
    assert_eq!(interface["protocolBinding"], "JSONRPC");
    assert_eq!(interface["protocolVersion"], "1.0");
    assert!(
        interface["url"]
            .as_str()
            .is_some_and(|url| url.ends_with("/a2a")),
        "the preferred interface must be the JSON-RPC endpoint: {interface}"
    );
    assert_eq!(card["capabilities"]["streaming"], json!(false));
    assert_eq!(card["capabilities"]["pushNotifications"], json!(false));
    assert!(
        !card["skills"].as_array().expect("skills").is_empty(),
        "a card always carries at least the fallback `converse` skill"
    );

    let scheme = &card["securitySchemes"]["bearer"]["httpAuthSecurityScheme"];
    assert_eq!(scheme["scheme"], "bearer", "card: {card}");
    assert_eq!(scheme["bearerFormat"], "gtw");
    assert_eq!(
        card["securityRequirements"][0]["schemes"]["bearer"],
        json!({"list": []}),
        "the requirement value is a StringList message, not a bare array"
    );

    // A2A §8.6 asks for a cacheable card. The ETag is also what makes a
    // conditional request cheap, so it must actually match.
    let etag = etag.expect("the card carries a strong ETag");
    let conditional = client()
        .get(format!("{base}/.well-known/agent-card.json"))
        .header(reqwest::header::IF_NONE_MATCH, &etag)
        .send()
        .expect("send");
    assert_eq!(
        conditional.status().as_u16(),
        304,
        "etag {etag} should match"
    );
}

/// A turn runs, and a second turn carrying the returned `contextId` reaches
/// the SAME session rather than starting a new one.
///
/// The continuity half is asserted generically: the id is echoed back and the
/// second turn answers. For a proof that the session state actually carried
/// over, see [`a_parked_card_flow_advances_across_turns`], which needs a
/// specific pack.
#[test]
#[ignore = "needs a live greentic-start; see the module docs"]
fn a2a_send_message_answers_and_the_conversation_continues() {
    let (base, token) = target();
    let first = a2a_send(&base, &token, None, json!([{"text": "hello"}]));
    assert_eq!(first["role"], "ROLE_AGENT");
    let context = first["contextId"]
        .as_str()
        .expect("the server mints a contextId when the caller sends none")
        .to_string();
    assert!(!context.is_empty());
    assert!(
        !first["parts"].as_array().expect("parts").is_empty(),
        "a turn must answer with at least one part"
    );

    let second = a2a_send(&base, &token, Some(&context), json!([{"text": "hello"}]));
    assert_eq!(
        second["contextId"].as_str(),
        Some(context.as_str()),
        "the caller's contextId must be echoed, not replaced"
    );
}

/// The decisive continuity check, and the reason it needs a named pack: it
/// sends actions that route only from the node the session is PARKED at, so
/// the same payload against a fresh conversation cannot produce the same
/// answer.
///
/// Requires a card flow shaped like the designer's `new-flow` starter
/// (`greeting` → `answer_billing` → `resolution` → `thank_you`, routed on
/// `response.action`). `nextCardId` is deliberately OMITTED from every submit:
/// with it present the payload routes on its own and proves nothing.
#[test]
#[ignore = "needs a live greentic-start serving the new-flow card starter"]
fn a_parked_card_flow_advances_across_turns() {
    let (base, token) = target();
    let context = format!("live-e2e-{}", ulid::Ulid::new());

    let greeting = a2a_send(&base, &token, Some(&context), json!([{"text": "hello"}]));
    let greeting_text = reply_text(&greeting);

    let billing = a2a_send(
        &base,
        &token,
        Some(&context),
        json!([{"data": {"action": "pick_billing"}}]),
    );
    assert_ne!(
        reply_text(&billing),
        greeting_text,
        "a submit must advance the flow off the entry card"
    );

    // `resolve` routes to `resolution` ONLY from an answer card. Against a
    // fresh conversation the flow is at `greeting`, where it matches nothing.
    let resolved = a2a_send(
        &base,
        &token,
        Some(&context),
        json!([{"data": {"action": "resolve"}}]),
    );
    let resolved_text = reply_text(&resolved);
    assert_ne!(resolved_text, reply_text(&billing));

    let fresh = a2a_send(
        &base,
        &token,
        Some(&format!("live-e2e-fresh-{}", ulid::Ulid::new())),
        json!([{"data": {"action": "resolve"}}]),
    );
    assert_eq!(
        reply_text(&fresh),
        greeting_text,
        "the identical payload on a FRESH conversation must land on the entry card — \
         if it does not, this assertion proves nothing about session continuity"
    );
}

/// Both bindings, and every way of not presenting the staged credential.
#[test]
#[ignore = "needs a live greentic-start; see the module docs"]
fn a2a_refuses_a_missing_or_wrong_bearer() {
    let (base, token) = target();
    let body = json!({"jsonrpc":"2.0","id":1,"method":"SendMessage",
                      "params":{"message":{"messageId":"n","role":"ROLE_USER",
                                           "parts":[{"text":"hello"}]}}});
    let wrong = format!("{token}-not-the-token");
    for path in ["/a2a", "/a2a/message:send"] {
        for (label, header) in [
            ("no Authorization", None),
            ("wrong token", Some(format!("Bearer {wrong}"))),
            ("empty bearer", Some("Bearer ".to_string())),
            ("wrong scheme", Some(format!("Basic {token}"))),
        ] {
            let mut request = client().post(format!("{base}{path}")).json(&body);
            if let Some(value) = header {
                request = request.header(reqwest::header::AUTHORIZATION, value);
            }
            let status = request.send().expect("send").status().as_u16();
            assert_eq!(status, 401, "{path} with {label} must be refused");
        }
    }
}

/// Contract D4: stateless MVP. These are not "unimplemented" — they are the
/// conformant answers for a server that keeps no task store, and a client that
/// polls must be able to tell that apart from a broken endpoint.
#[test]
#[ignore = "needs a live greentic-start; see the module docs"]
fn a2a_task_methods_answer_the_stateless_shape() {
    let (base, token) = target();
    let post = |body: Value| -> Value {
        client()
            .post(format!("{base}/a2a"))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .expect("send")
            .json()
            .expect("json")
    };
    let get = post(json!({"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"t"}}));
    assert_eq!(get["error"]["code"], json!(-32001), "{get}");
    let cancel = post(json!({"jsonrpc":"2.0","id":2,"method":"CancelTask","params":{"id":"t"}}));
    assert_eq!(cancel["error"]["code"], json!(-32001), "{cancel}");
    let list = post(json!({"jsonrpc":"2.0","id":3,"method":"ListTasks","params":{}}));
    assert_eq!(list["result"]["tasks"], json!([]), "{list}");
    let unknown = post(json!({"jsonrpc":"2.0","id":4,"method":"Nope","params":{}}));
    assert_eq!(unknown["error"]["code"], json!(-32601), "{unknown}");
}

// ---------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------

fn mcp_post(
    base: &str,
    token: Option<&str>,
    method: &str,
    body: Value,
) -> reqwest::blocking::Response {
    let mut request = client()
        .post(format!("{base}/mcp"))
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header(super::mcp::MCP_METHOD_HEADER, method)
        .json(&body);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request.send().expect("send")
}

/// One tool, `ask`, and a `tools/call` that really runs a turn.
///
/// The tool count is asserted exactly: the worker's OWN bound tools must never
/// appear here (research §6.3) — exposing them would let a caller invoke a
/// tool the worker's instructions and guardrails never chose to run.
#[test]
#[ignore = "needs a live greentic-start; see the module docs"]
fn mcp_exposes_exactly_the_ask_tool_and_runs_a_turn() {
    let (base, token) = target();

    let init: Value = mcp_post(
        &base,
        Some(&token),
        "initialize",
        json!({"jsonrpc":"2.0","id":1,"method":"initialize",
               "params":{"protocolVersion":"2026-07-28","capabilities":{},
                         "clientInfo":{"name":"live-e2e","version":"1"}}}),
    )
    .json()
    .expect("json");
    assert!(
        init["result"]["capabilities"]["tools"].is_object(),
        "{init}"
    );

    let list: Value = mcp_post(
        &base,
        Some(&token),
        "tools/list",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    )
    .json()
    .expect("json");
    let tools = list["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 1, "exactly one tool is exposed: {list}");
    assert_eq!(tools[0]["name"], "ask");
    let properties = &tools[0]["inputSchema"]["properties"];
    assert!(properties["message"].is_object(), "{list}");
    assert!(properties["conversation_id"].is_object(), "{list}");

    let call: Value = mcp_post(
        &base,
        Some(&token),
        "tools/call",
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
               "params":{"name":"ask","arguments":{"message":"hello"}}}),
    )
    .json()
    .expect("json");
    let result = &call["result"];
    assert!(
        result["content"]
            .as_array()
            .is_some_and(|c| c.iter().any(|item| item["type"] == "text")),
        "a turn answers with text content: {call}"
    );
    let conversation = result["structuredContent"]["conversation_id"]
        .as_str()
        .expect("structuredContent carries the conversation id")
        .to_string();

    let again: Value = mcp_post(
        &base,
        Some(&token),
        "tools/call",
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
               "params":{"name":"ask","arguments":{"message":"hello",
                                                   "conversation_id": conversation}}}),
    )
    .json()
    .expect("json");
    assert_eq!(
        again["result"]["structuredContent"]["conversation_id"].as_str(),
        Some(conversation.as_str()),
        "the caller's conversation id must be echoed, not replaced"
    );
}

/// The `401` has to carry `resource_metadata`, or a client that discovered no
/// issuer has nowhere to go and abandons authentication rather than starting
/// it.
#[test]
#[ignore = "needs a live greentic-start; see the module docs"]
fn mcp_refuses_an_anonymous_caller_and_points_it_at_its_issuer() {
    let (base, token) = target();
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                      "params":{"name":"ask","arguments":{"message":"hello"}}});
    for (label, presented) in [
        ("no token", None),
        ("wrong token", Some(format!("{token}-not-the-token"))),
    ] {
        let response = mcp_post(&base, presented.as_deref(), "tools/call", body.clone());
        assert_eq!(response.status().as_u16(), 401, "{label} must be refused");
        let challenge = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            challenge.contains("resource_metadata=")
                && challenge.contains("/.well-known/oauth-protected-resource"),
            "{label}: WWW-Authenticate must name the metadata document, got {challenge:?}"
        );
    }
}

/// `/mcp` is POST-only. A `GET` that returned a stream would be the SSE
/// transport this server does not implement, and a client would hang on it.
#[test]
#[ignore = "needs a live greentic-start; see the module docs"]
fn mcp_rejects_every_method_but_post() {
    let (base, token) = target();
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let status = client()
            .request(method.clone(), format!("{base}/mcp"))
            .bearer_auth(&token)
            .send()
            .expect("send")
            .status()
            .as_u16();
        assert_eq!(status, 405, "{method} /mcp");
    }
}

/// RFC 9728, both spellings. Clients differ over which they probe, and one
/// probing the unserved form sees a 404 and abandons discovery.
#[test]
#[ignore = "needs a live greentic-start; see the module docs"]
fn the_protected_resource_metadata_is_served_at_both_paths() {
    let (base, _) = target();
    let mut documents = Vec::new();
    for path in [
        super::mcp::PROTECTED_RESOURCE_PATH,
        super::mcp::PROTECTED_RESOURCE_MCP_PATH,
    ] {
        let response = client().get(format!("{base}{path}")).send().expect("send");
        assert_eq!(response.status().as_u16(), 200, "{path} is public");
        let document: Value = response.json().expect("json");
        assert!(
            document["resource"]
                .as_str()
                .is_some_and(|r| r.ends_with("/mcp")),
            "{path}: `resource` is the MCP URL, and it is the audience every \
             OAuth token is checked against: {document}"
        );
        assert!(
            !document["authorization_servers"]
                .as_array()
                .expect("authorization_servers")
                .is_empty(),
            "{path}: the document must name the staged issuer: {document}"
        );
        documents.push(document);
    }
    assert_eq!(
        documents[0], documents[1],
        "the two spellings describe one resource and must not drift"
    );
}

// ---------------------------------------------------------------------------
// Phase 0b
// ---------------------------------------------------------------------------

/// The generic JSON ingress refuses a remote caller with no bearer.
///
/// Skips when the target is loopback, because loopback peers are trusted by
/// design and the gate is keyed on the real socket address — no header can
/// stand in for one. See the module docs for how to point this at a
/// host-only non-loopback address.
#[test]
#[ignore = "needs a live greentic-start reachable on a NON-loopback address"]
fn the_generic_ingress_refuses_a_remote_caller_without_a_bearer() {
    let (base, token) = target();
    let host = base
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(':')
        .next()
        .unwrap_or_default()
        .to_string();
    if host
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
        || host == "localhost"
    {
        eprintln!(
            "skipping: {BASE_ENV} points at a loopback address, which the Phase 0b gate \
             trusts by design — see the module docs"
        );
        return;
    }
    let body = json!({"text": "hello"});
    let anonymous = client()
        .post(format!("{base}/"))
        .json(&body)
        .send()
        .expect("send");
    assert_eq!(
        anonymous.status().as_u16(),
        401,
        "the generic ingress runs a flow turn; a remote caller must present the unit's bearer"
    );
    let authenticated = client()
        .post(format!("{base}/"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .expect("send");
    assert_eq!(
        authenticated.status().as_u16(),
        200,
        "the same request with the staged bearer runs the turn"
    );
}
