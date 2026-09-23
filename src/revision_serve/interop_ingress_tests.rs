//! Listener-level tests for the worker-interop surfaces: a real TCP socket,
//! the real `spawn_revision_connection` → `handle_connection` → `serve`
//! pipeline, an in-memory secrets manager holding the staged unit config, and
//! a turn override standing in for a loaded WASM revision.
//!
//! Wiring is what these cover. The decisions themselves are unit-tested in
//! `crate::ingress_auth` and `crate::interop`; a test that calls those
//! directly stays green if `serve` never consults them.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use greentic_deploy_spec::ids::{BundleId, DeploymentId, RevisionId};
use greentic_runner_host::Activity;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::revision_dispatcher::{RevisionDispatcher, RevisionDispatcherConfig, RevisionEntry};

const TENANT: &str = "default";
const BUNDLE: &str = "support-bot";
const TOKEN: &str = "gtw_test-token";

/// An in-memory secrets manager that can also fail the way a broken backend
/// does — the distinction the gate turns into 401 vs 503.
struct TestSecrets {
    entries: HashMap<String, Vec<u8>>,
    fail: bool,
    /// Every `read` counted, so a test can assert the config cache actually
    /// removed the per-request store read.
    reads: Arc<std::sync::atomic::AtomicUsize>,
}

impl TestSecrets {
    fn with(entries: HashMap<String, Vec<u8>>, reads: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        Self {
            entries,
            fail: false,
            reads,
        }
    }

    fn failing(reads: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        Self {
            entries: HashMap::new(),
            fail: true,
            reads,
        }
    }
}

#[async_trait::async_trait]
impl greentic_secrets_lib::SecretsManager for TestSecrets {
    async fn read(&self, path: &str) -> greentic_secrets_lib::Result<Vec<u8>> {
        self.reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.fail {
            return Err(greentic_secrets_lib::SecretError::Backend(
                "store unreachable".into(),
            ));
        }
        self.entries
            .get(path)
            .cloned()
            .ok_or_else(|| greentic_secrets_lib::SecretError::NotFound(path.to_string()))
    }

    async fn write(&self, _path: &str, _bytes: &[u8]) -> greentic_secrets_lib::Result<()> {
        Ok(())
    }

    async fn delete(&self, _path: &str) -> greentic_secrets_lib::Result<()> {
        Ok(())
    }
}

/// The staged config document for this unit.
fn staged_config(a2a: bool) -> Vec<u8> {
    staged_interop_config(a2a, false, None)
}

/// The same document with both toggles and the OAuth issuer under the test's
/// control.
fn staged_interop_config(a2a: bool, mcp: bool, issuer: Option<&str>) -> Vec<u8> {
    staged_interop_config_with(a2a, mcp, issuer, Some("https://w.example/mcp"))
}

/// …and with the staged `mcp_resource` under the test's control too, so the
/// "this deployment can name no resource identifier" case is reachable.
fn staged_interop_config_with(
    a2a: bool,
    mcp: bool,
    issuer: Option<&str>,
    mcp_resource: Option<&str>,
) -> Vec<u8> {
    let mut doc = json!({
        "v": 1,
        "a2a": a2a,
        "mcp": mcp,
        "credentials": [{
            "id": "c1",
            "sha256": Sha256::digest(TOKEN.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        }],
        "tenant_slug": "acme",
        "agent": {"name": "Support Bot", "description": "Answers support questions."}
    });
    if let (Some(issuer), Value::Object(map)) = (issuer, &mut doc) {
        map.insert("issuer".to_string(), json!(issuer));
    }
    if let (Some(resource), Value::Object(map)) = (mcp_resource, &mut doc) {
        map.insert("mcp_resource".to_string(), json!(resource));
    }
    doc.to_string().into_bytes()
}

fn config_uri() -> String {
    crate::ingress_auth::ingress_secret_uri(&crate::resolve_env(None), TENANT, BUNDLE)
}

/// What the unit's secrets store holds for this test.
enum Store {
    /// The staged config, with A2A enabled or not and MCP off.
    Config(bool),
    /// The staged config with MCP on (and A2A off), naming this issuer.
    Mcp(Option<String>),
    /// MCP on, with NO issuer and NO staged `mcp_resource` — a unit whose
    /// only credential is the staged bearer.
    McpBare,
    /// Nothing staged.
    Empty,
    /// The backend cannot answer.
    Down,
}

fn activation_with(store: Store) -> (Activation, DeploymentId) {
    let (activation, deployment_id, _reads) = activation_counting(store);
    (activation, deployment_id)
}

/// The same activation, plus the counter of store reads its secrets manager
/// has served.
fn activation_counting(
    store: Store,
) -> (
    Activation,
    DeploymentId,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let secrets: greentic_runner_host::secrets::DynSecretsManager = match store {
        Store::Config(a2a) => {
            let mut entries = HashMap::new();
            entries.insert(config_uri(), staged_config(a2a));
            Arc::new(TestSecrets::with(entries, Arc::clone(&reads)))
        }
        Store::McpBare => {
            let mut entries = HashMap::new();
            entries.insert(
                config_uri(),
                staged_interop_config_with(false, true, None, None),
            );
            Arc::new(TestSecrets::with(entries, Arc::clone(&reads)))
        }
        Store::Mcp(issuer) => {
            let mut entries = HashMap::new();
            entries.insert(
                config_uri(),
                staged_interop_config(false, true, issuer.as_deref()),
            );
            Arc::new(TestSecrets::with(entries, Arc::clone(&reads)))
        }
        Store::Empty => Arc::new(TestSecrets::with(HashMap::new(), Arc::clone(&reads))),
        Store::Down => Arc::new(TestSecrets::failing(Arc::clone(&reads))),
    };
    let host = Arc::new(
        greentic_runner_host::HostBuilder::new()
            .with_config(greentic_runner_host::HostConfig::from_gtbind(
                greentic_runner_host::TenantBindings {
                    tenant: TENANT.to_string(),
                    packs: Vec::new(),
                    env_passthrough: Vec::new(),
                },
            ))
            .with_secrets_manager(secrets)
            .build()
            .expect("build test host"),
    );

    let deployment_id = DeploymentId::new();
    let bundle_id = BundleId::new(BUNDLE);
    let dispatcher = RevisionDispatcher::new(RevisionDispatcherConfig::new("interop", [0u8; 32]));
    dispatcher
        .apply_traffic_split(
            deployment_id,
            vec![RevisionEntry {
                revision_id: RevisionId::new(),
                bundle_id: bundle_id.clone(),
                weight_bps: 10_000,
            }],
            bundle_id.clone(),
            0,
        )
        .expect("apply_traffic_split");

    let activation = Activation {
        host,
        routing: Arc::new(RevisionIngressRouting {
            dispatcher: Arc::new(dispatcher),
            http_routes: HttpRouteTable::from_descriptors(Vec::new()),
            deployment_routes: crate::deployment_routes::DeploymentRouteTable::from_parts(vec![(
                deployment_id,
                bundle_id,
                TENANT.to_string(),
                Vec::new(),
                Vec::new(),
            )]),
            endpoint_admit: Arc::new(crate::endpoint_admit::EndpointAdmit::default()),
            deployment_config_overrides: Arc::default(),
            static_routes: crate::static_routes::ActiveRouteTable::default(),
            bundle_index: crate::webchat_routing::BundleIndex::empty(),
            flow_index: crate::webchat_routing::FlowIndex::default(),
            triggers: Default::default(),
        }),
    };
    (activation, deployment_id, reads)
}

/// A `ServeState` over `activation`, answering every turn with `replies`.
fn state_with(activation: Activation, interop: crate::interop::InteropState) -> Arc<ServeState> {
    let bound: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    Arc::new(ServeState {
        slot: ArcSwap::new(Arc::new(activation)),
        bound_addr: bound,
        gui_enabled: false,
        restart_required: AtomicBool::new(false),
        updates_enabled: false,
        auto_restart_pending: AtomicBool::new(false),
        auto_restart_enabled: false,
        exe_path: None,
        directline_sessions: Arc::new(
            crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
        ),
        conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
        session_manager: Arc::new(crate::websocket::SessionManager::new(
            crate::websocket::WsLimits::default(),
        )),
        notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
        public_url_capture: None,
        interop,
        activity_source_override: None,
    })
}

/// An interop state that answers every turn with `replies`.
fn interop_replying(replies: Vec<Activity>) -> crate::interop::InteropState {
    crate::interop::InteropState {
        turn_override: Some(Arc::new(move |_activity: &Activity| replies.clone())),
        ..crate::interop::InteropState::default()
    }
}

/// One raw HTTP exchange against a listener serving `state`.
struct Exchange {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Exchange {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

/// Serve `state` on a fresh loopback listener and send one request.
async fn exchange(state: &Arc<ServeState>, trust_loopback_peers: bool, request: &str) -> Exchange {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let accept_state = Arc::clone(state);
    let accept = tokio::spawn(async move {
        let accepted = listener.accept().await;
        spawn_revision_connection(accepted, &accept_state, trust_loopback_peers);
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    // A write error is tolerated: a server that refuses before reading the
    // whole body (an unauthenticated oversized POST, say) legitimately closes
    // the connection mid-write, and the RESPONSE is what this asserts on.
    let _ = stream.write_all(request.as_bytes()).await;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");
    accept.await.expect("accept loop");

    let raw = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in: {raw:?}"));
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Exchange {
        status,
        headers,
        body: body.to_string(),
    }
}

/// A `POST /` carrying a JSON body, with optional extra headers.
fn post(path: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    request
}

fn get(path: &str, headers: &[(&str, &str)]) -> String {
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request
}

const AUTH: (&str, &str) = ("Authorization", "Bearer gtw_test-token");

// ---------------------------------------------------------------------------
// Phase 0b: the generic JSON ingress
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_remote_generic_post_without_a_token_is_refused() {
    let (activation, _) = activation_with(Store::Config(false));
    let state = state_with(activation, interop_replying(vec![Activity::text("hi")]));
    let response = exchange(&state, false, &post("/", &[], r#"{"text":"hello"}"#)).await;
    assert_eq!(response.status, 401);
    assert_eq!(response.header("www-authenticate"), Some("Bearer"));
}

#[tokio::test]
async fn a_remote_generic_post_with_the_staged_token_runs_the_turn() {
    let (activation, _) = activation_with(Store::Config(false));
    let state = state_with(activation, interop_replying(vec![Activity::text("hi")]));
    let response = exchange(&state, false, &post("/", &[AUTH], r#"{"text":"hello"}"#)).await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert_eq!(response.json()[0]["payload"]["text"], "hi");
}

#[tokio::test]
async fn a_unit_with_no_staged_config_refuses_every_remote_caller() {
    let (activation, _) = activation_with(Store::Empty);
    let state = state_with(activation, interop_replying(vec![Activity::text("hi")]));
    let response = exchange(&state, false, &post("/", &[AUTH], r#"{"text":"hello"}"#)).await;
    assert_eq!(response.status, 401);
}

#[tokio::test]
async fn an_unreadable_secrets_backend_is_503_not_401_and_never_an_allow() {
    let (activation, _) = activation_with(Store::Down);
    let state = state_with(activation, interop_replying(vec![Activity::text("hi")]));
    let response = exchange(&state, false, &post("/", &[AUTH], r#"{"text":"hello"}"#)).await;
    assert_eq!(response.status, 503);
}

#[tokio::test]
async fn a_loopback_trusted_peer_keeps_running_turns_unauthenticated() {
    // Nothing is staged at all, which is the harshest case for the gate.
    let (activation, _) = activation_with(Store::Empty);
    let state = state_with(activation, interop_replying(vec![Activity::text("hi")]));
    let response = exchange(&state, true, &post("/", &[], r#"{"text":"hello"}"#)).await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert_eq!(response.json()[0]["payload"]["text"], "hi");
}

#[tokio::test]
async fn the_host_local_escape_hatch_reopens_the_generic_branch() {
    let (activation, _) = activation_with(Store::Empty);
    let state = state_with(
        activation,
        crate::interop::InteropState {
            generic_auth_enabled: false,
            ..interop_replying(vec![Activity::text("hi")])
        },
    );
    let response = exchange(&state, false, &post("/", &[], r#"{"text":"hello"}"#)).await;
    assert_eq!(response.status, 200, "body: {}", response.body);
}

/// A GET is a 405 either way; the gate must not turn it into a 401 that hides
/// what is actually wrong (and must not run a turn for it).
#[tokio::test]
async fn a_remote_get_still_reports_method_not_allowed() {
    let (activation, _) = activation_with(Store::Config(false));
    let state = state_with(activation, interop_replying(vec![Activity::text("hi")]));
    let response = exchange(&state, false, &get("/", &[])).await;
    assert_eq!(response.status, 405);
}

// ---------------------------------------------------------------------------
// A2A: the public agent card
// ---------------------------------------------------------------------------

/// The card needs an absolute URL, and the listener knows one only from the
/// boot-resolved `public_base_url` or the Cloud Run capture.
fn interop_with_base_url(replies: Vec<Activity>) -> crate::interop::InteropState {
    crate::interop::InteropState {
        public_base_url: Some("https://gtc-svc.example.run.app/".to_string()),
        ..interop_replying(replies)
    }
}

#[tokio::test]
async fn the_agent_card_is_served_without_authentication() {
    let (activation, _) = activation_with(Store::Config(true));
    let state = state_with(activation, interop_with_base_url(Vec::new()));
    let response = exchange(&state, false, &get("/.well-known/agent-card.json", &[])).await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let card = response.json();
    assert_eq!(card["name"], "Support Bot");
    assert_eq!(
        card["supportedInterfaces"][0]["url"], "https://gtc-svc.example.run.app/a2a",
        "the trailing slash of the base URL must not double"
    );
    assert_eq!(
        card["securitySchemes"]["bearer"]["httpAuthSecurityScheme"]["scheme"],
        "bearer"
    );
    assert!(
        response
            .header("cache-control")
            .is_some_and(|value| value.contains("max-age"))
    );
    let etag = response.header("etag").expect("an ETag").to_string();

    let conditional = exchange(
        &state,
        false,
        &get("/.well-known/agent-card.json", &[("If-None-Match", &etag)]),
    )
    .await;
    assert_eq!(conditional.status, 304);
}

#[tokio::test]
async fn the_interop_paths_fall_through_when_a2a_is_off() {
    // `a2a: false` in the staged config: the card path is NOT reserved, so it
    // reaches normal routing — where a GET is a 405, not a card.
    let (activation, _) = activation_with(Store::Config(false));
    let state = state_with(activation, interop_with_base_url(Vec::new()));
    let card = exchange(&state, false, &get("/.well-known/agent-card.json", &[])).await;
    assert_eq!(card.status, 405);

    // Nothing staged at all: same answer, by a different route through the
    // same decision.
    let (activation, _) = activation_with(Store::Empty);
    let state = state_with(activation, interop_with_base_url(Vec::new()));
    let card = exchange(&state, false, &get("/.well-known/agent-card.json", &[])).await;
    assert_eq!(card.status, 405);
}

#[tokio::test]
async fn an_unreadable_store_refuses_an_interop_path_rather_than_falling_through() {
    let (activation, _) = activation_with(Store::Down);
    let state = state_with(activation, interop_with_base_url(Vec::new()));
    let response = exchange(&state, false, &get("/.well-known/agent-card.json", &[])).await;
    assert_eq!(response.status, 503);
}

#[tokio::test]
async fn the_card_is_refused_when_no_public_base_url_is_known() {
    let (activation, _) = activation_with(Store::Config(true));
    let state = state_with(activation, interop_replying(Vec::new()));
    let response = exchange(&state, false, &get("/.well-known/agent-card.json", &[])).await;
    assert_eq!(
        response.status, 503,
        "a card with no absolute URL is not a card"
    );
}

#[tokio::test]
async fn a_post_to_the_card_path_is_method_not_allowed() {
    let (activation, _) = activation_with(Store::Config(true));
    let state = state_with(activation, interop_with_base_url(Vec::new()));
    let response = exchange(
        &state,
        false,
        &post("/.well-known/agent-card.json", &[AUTH], "{}"),
    )
    .await;
    assert_eq!(response.status, 405);
}

// ---------------------------------------------------------------------------
// A2A: the request bindings
// ---------------------------------------------------------------------------

fn send_message_body(context_id: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "SendMessage",
        "params": {"message": {
            "messageId": "m-in",
            "contextId": context_id,
            "role": "ROLE_USER",
            "parts": [{"text": "how do I reset my password?"}]
        }}
    })
    .to_string()
}

#[tokio::test]
async fn a_send_message_round_trip_returns_the_turns_reply() {
    let (activation, _) = activation_with(Store::Config(true));
    let state = state_with(
        activation,
        interop_with_base_url(vec![Activity::custom(
            "response",
            json!({"reply": "Use the reset link."}),
        )]),
    );
    let response = exchange(
        &state,
        false,
        &post("/a2a", &[AUTH], &send_message_body("ctx-1")),
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let value = response.json();
    assert_eq!(value["id"], 7);
    assert_eq!(value["result"]["message"]["role"], "ROLE_AGENT");
    assert_eq!(value["result"]["message"]["contextId"], "ctx-1");
    assert_eq!(
        value["result"]["message"]["parts"],
        json!([{"text": "Use the reset link."}])
    );
    assert_eq!(response.header("a2a-version"), Some("1.0"));
    assert!(
        response.header("access-control-allow-origin").is_none(),
        "/a2a must never be CORS-enabled"
    );
}

#[tokio::test]
async fn the_rest_binding_runs_the_same_turn() {
    let (activation, _) = activation_with(Store::Config(true));
    let state = state_with(
        activation,
        interop_with_base_url(vec![Activity::text("hello there")]),
    );
    let body = json!({"message": {
        "messageId": "m-in", "contextId": "ctx-2", "role": "ROLE_USER",
        "parts": [{"text": "hi"}]
    }})
    .to_string();
    let response = exchange(&state, false, &post("/a2a/message:send", &[AUTH], &body)).await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert_eq!(
        response.json()["message"]["parts"],
        json!([{"text": "hello there"}])
    );
}

#[tokio::test]
async fn a_send_message_without_a_bearer_is_refused_and_runs_nothing() {
    let (activation, _) = activation_with(Store::Config(true));
    let state = state_with(
        activation,
        interop_with_base_url(vec![Activity::text("never sent")]),
    );
    let response = exchange(&state, false, &post("/a2a", &[], &send_message_body("c"))).await;
    assert_eq!(response.status, 401);
    assert!(!response.body.contains("never sent"));
}

/// Loopback trust is a property of the GENERIC ingress, not of A2A: the
/// session namespace is derived from the credential, so an anonymous caller
/// has no conversation to be in.
#[tokio::test]
async fn a2a_requires_a_bearer_even_from_a_loopback_peer() {
    let (activation, _) = activation_with(Store::Config(true));
    let state = state_with(
        activation,
        interop_with_base_url(vec![Activity::text("never sent")]),
    );
    let response = exchange(&state, true, &post("/a2a", &[], &send_message_body("c"))).await;
    assert_eq!(response.status, 401);
}

#[tokio::test]
async fn the_a2a_paths_fall_through_when_a2a_is_off() {
    let (activation, _) = activation_with(Store::Config(false));
    let state = state_with(activation, interop_with_base_url(vec![Activity::text("x")]));
    // Falls through to the generic branch, which answers the JSON-RPC body as
    // an ordinary turn once the Phase 0b bearer check passes.
    let response = exchange(
        &state,
        false,
        &post("/a2a", &[AUTH], &send_message_body("c")),
    )
    .await;
    assert_eq!(response.status, 200);
    assert!(
        response.json().get("result").is_none(),
        "a JSON-RPC result means the A2A binding answered a unit that has it off"
    );
}

#[tokio::test]
async fn a_get_on_the_json_rpc_path_is_method_not_allowed() {
    let (activation, _) = activation_with(Store::Config(true));
    let state = state_with(activation, interop_with_base_url(Vec::new()));
    let response = exchange(&state, false, &get("/a2a", &[AUTH])).await;
    assert_eq!(response.status, 405);
}

// ---------------------------------------------------------------------------
// The staged-config cache
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_units_config_is_read_once_for_a_burst_of_requests() {
    let (activation, _, reads) = activation_counting(Store::Config(true));
    let state = state_with(
        activation,
        interop_with_base_url(vec![Activity::text("hi")]),
    );
    for _ in 0..3 {
        let response = exchange(&state, false, &post("/", &[AUTH], r#"{"text":"hello"}"#)).await;
        assert_eq!(response.status, 200, "body: {}", response.body);
    }
    // …and a different surface on the same unit shares the entry.
    let card = exchange(&state, false, &get("/.well-known/agent-card.json", &[])).await;
    assert_eq!(card.status, 200);
    assert_eq!(
        reads.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the staged config must be read from the store once, not per request"
    );
}

/// A read FAILURE is never cached: holding a 503 for the TTL after the store
/// recovered would turn one blip into a window of refusals.
#[tokio::test]
async fn an_unreadable_store_is_retried_on_the_next_request() {
    let (activation, _, reads) = activation_counting(Store::Down);
    let state = state_with(
        activation,
        interop_with_base_url(vec![Activity::text("hi")]),
    );
    for _ in 0..2 {
        let response = exchange(&state, false, &post("/", &[AUTH], r#"{"text":"hello"}"#)).await;
        assert_eq!(response.status, 503);
    }
    assert_eq!(reads.load(std::sync::atomic::Ordering::Relaxed), 2);
}

// ---------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------

/// A JSON-RPC `tools/call` for the one tool this surface exposes.
fn tools_call(message: &str, conversation_id: Option<&str>) -> String {
    let mut arguments = json!({ "message": message });
    if let (Some(id), Value::Object(map)) = (conversation_id, &mut arguments) {
        map.insert("conversation_id".to_string(), json!(id));
    }
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "ask", "arguments": arguments}
    })
    .to_string()
}

/// The headers an MCP client sends: the bearer, the content negotiation rmcp
/// requires, and the `Mcp-Method` the limiter meters on.
fn mcp_headers(method: &str) -> Vec<(&str, &str)> {
    vec![
        AUTH,
        ("Accept", "application/json, text/event-stream"),
        ("Mcp-Method", method),
    ]
}

#[tokio::test]
async fn a_tools_call_runs_a_turn_and_returns_the_reply() {
    let (activation, _) = activation_with(Store::Mcp(None));
    let state = state_with(
        activation,
        interop_with_base_url(vec![Activity::custom(
            "response",
            json!({"reply": "Reset it from the profile page."}),
        )]),
    );
    let response = exchange(
        &state,
        false,
        &post(
            "/mcp",
            &mcp_headers("tools/call"),
            &tools_call("how?", Some("c-1")),
        ),
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let value = response.json();
    let result = &value["result"];
    assert_eq!(
        result["content"][0]["text"], "Reset it from the profile page.",
        "body: {}",
        response.body
    );
    assert_eq!(result["structuredContent"]["conversation_id"], "c-1");
    assert_ne!(result["isError"], json!(true));
    assert!(
        response.header("access-control-allow-origin").is_none(),
        "/mcp must never be CORS-enabled"
    );
}

#[tokio::test]
async fn tools_list_offers_the_ask_tool_and_nothing_else() {
    let (activation, _) = activation_with(Store::Mcp(None));
    let state = state_with(activation, interop_with_base_url(Vec::new()));
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).to_string();
    let response = exchange(
        &state,
        false,
        &post("/mcp", &mcp_headers("tools/list"), &body),
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let tools = response.json()["result"]["tools"].clone();
    let names: Vec<String> = tools
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|tool| tool["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(names, vec!["ask".to_string()], "body: {}", response.body);
}

#[tokio::test]
async fn an_mcp_call_without_a_token_is_401_with_the_discovery_url() {
    let (activation, _) = activation_with(Store::Mcp(None));
    let state = state_with(
        activation,
        interop_with_base_url(vec![Activity::text("never sent")]),
    );
    let response = exchange(
        &state,
        false,
        &post(
            "/mcp",
            &[("Accept", "application/json, text/event-stream")],
            &tools_call("hi", None),
        ),
    )
    .await;
    assert_eq!(response.status, 401);
    assert_eq!(
        response.header("www-authenticate"),
        Some(
            "Bearer resource_metadata=\"https://gtc-svc.example.run.app/.well-known/oauth-protected-resource/mcp\""
        )
    );
    assert!(!response.body.contains("never sent"));
}

/// rmcp answers GET and DELETE itself in stateless mode: with
/// `legacy_session_mode = false` and no event store its `handle` allows POST
/// alone. The token is presented so this cannot pass for a 401.
#[tokio::test]
async fn a_get_or_delete_on_the_mcp_endpoint_is_405() {
    let (activation, _) = activation_with(Store::Mcp(None));
    let state = state_with(activation, interop_with_base_url(Vec::new()));
    let get_response = exchange(&state, false, &get("/mcp", &mcp_headers("ping"))).await;
    assert_eq!(get_response.status, 405);
    assert_eq!(get_response.header("allow"), Some("POST"));

    let delete_request = format!(
        "DELETE /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\n\
         Accept: application/json, text/event-stream\r\nConnection: close\r\n\r\n",
        AUTH.1
    );
    let delete_response = exchange(&state, false, &delete_request).await;
    assert_eq!(delete_response.status, 405);
}

#[tokio::test]
async fn the_protected_resource_metadata_is_served_at_both_paths() {
    let (activation, _) = activation_with(Store::Mcp(Some("https://admin.example/".to_string())));
    let state = state_with(activation, interop_with_base_url(Vec::new()));
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let response = exchange(&state, false, &get(path, &[])).await;
        assert_eq!(response.status, 200, "{path}: {}", response.body);
        assert_eq!(
            response.json(),
            json!({
                "resource": "https://w.example/mcp",
                "authorization_servers": ["https://admin.example"],
                "bearer_methods_supported": ["header"],
            }),
            "{path}"
        );
    }
}

#[tokio::test]
async fn a_unit_with_no_issuer_publishes_no_metadata_document() {
    let (activation, _) = activation_with(Store::Mcp(None));
    let state = state_with(activation, interop_with_base_url(Vec::new()));
    let response = exchange(
        &state,
        false,
        &get("/.well-known/oauth-protected-resource", &[]),
    )
    .await;
    assert_eq!(response.status, 503);
}

#[tokio::test]
async fn the_mcp_paths_fall_through_when_mcp_is_off() {
    // `a2a: true, mcp: false`: the A2A paths are reserved and the MCP ones are
    // not, on the same unit.
    let (activation, _) = activation_with(Store::Config(true));
    let state = state_with(activation, interop_with_base_url(vec![Activity::text("x")]));
    let metadata = exchange(
        &state,
        false,
        &get("/.well-known/oauth-protected-resource", &[]),
    )
    .await;
    assert_eq!(
        metadata.status, 405,
        "a GET falls through to the generic ingress"
    );

    let endpoint = exchange(
        &state,
        false,
        &post("/mcp", &mcp_headers("tools/call"), &tools_call("hi", None)),
    )
    .await;
    assert_eq!(endpoint.status, 200);
    assert!(
        endpoint.json().get("result").is_none(),
        "a JSON-RPC result means the MCP binding answered a unit that has it off"
    );
}

/// A turn costs a turn however the request ANNOUNCES itself.
///
/// The transport prices a request from the caller's own `Mcp-Method` header,
/// so a `tools/call` body may arrive labelled `tools/list` — the cheap tier.
/// The `ask` tool settles the remainder, so the honest and the lying client
/// get the same number of turns out of one bucket. Without that settle-up a
/// lying client gets twice as many, which is a rate limit the caller sets for
/// itself.
#[tokio::test]
async fn a_lying_mcp_method_header_still_pays_for_its_turn() {
    let (activation, _) = activation_with(Store::Mcp(None));
    let state = state_with(
        activation,
        interop_with_base_url(vec![Activity::text("ok")]),
    );
    let mut turns = 0;
    for _ in 0..80 {
        let response = exchange(
            &state,
            false,
            // The body is a `tools/call`; the header says `tools/list`.
            &post(
                "/mcp",
                &mcp_headers("tools/list"),
                &tools_call("hi", Some("c")),
            ),
        )
        .await;
        if response.status == 429 {
            break;
        }
        let value = response.json();
        if value["result"]["isError"] == json!(true) {
            assert!(
                value["result"]["content"][0]["text"]
                    .as_str()
                    .is_some_and(|text| text.contains("too many turns")),
                "the only tool-level failure here is the rate limit: {}",
                response.body
            );
            break;
        }
        turns += 1;
    }
    // Burst 120 at 2 per turn is 60 turns; the pre-filter charged 1 of each
    // pair, the tool settled the other.
    assert_eq!(
        turns, 60,
        "a cheap-labelled turn must cost the same as an honest one"
    );
}

/// The limiter keys on the caller and meters on `Mcp-Method`: a `tools/call`
/// costs two, so a full burst is 60 of them.
#[tokio::test]
async fn the_mcp_rate_limit_refuses_with_a_retry_after() {
    let (activation, _) = activation_with(Store::Mcp(None));
    let state = state_with(
        activation,
        interop_with_base_url(vec![Activity::text("ok")]),
    );
    let mut refused = None;
    for _ in 0..61 {
        let response = exchange(
            &state,
            false,
            &post(
                "/mcp",
                &mcp_headers("tools/call"),
                &tools_call("hi", Some("c")),
            ),
        )
        .await;
        if response.status == 429 {
            refused = Some(response);
            break;
        }
    }
    let refused = refused.expect("the 61st turn must be refused");
    assert!(refused.header("retry-after").is_some());
}

/// A unit with no staged `mcp_resource` and no public base URL can name no
/// resource identifier — which only the OAuth path needs. The staged bearer
/// must still work, so authentication has to run BEFORE that refusal.
#[tokio::test]
async fn a_bearer_caller_needs_no_resource_identifier() {
    let (activation, _) = activation_with(Store::McpBare);
    // No `public_base_url` either, so nothing can derive one.
    let state = state_with(activation, interop_replying(vec![Activity::text("served")]));
    let response = exchange(
        &state,
        false,
        &post(
            "/mcp",
            &mcp_headers("tools/call"),
            &tools_call("hi", Some("c")),
        ),
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert_eq!(response.json()["result"]["content"][0]["text"], "served");
}

/// …and an anonymous caller on that same unit is still refused, with a BARE
/// challenge: there is no discovery document to point at, and naming one that
/// would 503 sends a client in a circle.
#[tokio::test]
async fn an_anonymous_caller_with_no_resource_identifier_gets_a_bare_challenge() {
    let (activation, _) = activation_with(Store::McpBare);
    let state = state_with(activation, interop_replying(vec![Activity::text("x")]));
    let response = exchange(
        &state,
        false,
        &post(
            "/mcp",
            &[("Accept", "application/json, text/event-stream")],
            &tools_call("hi", None),
        ),
    )
    .await;
    assert_eq!(response.status, 401);
    assert_eq!(response.header("www-authenticate"), Some("Bearer"));
}

/// The discovery document is the one thing that genuinely needs the resource
/// identifier, so it still refuses.
#[tokio::test]
async fn the_metadata_document_still_needs_a_resource_identifier() {
    let (activation, _) = activation_with(Store::McpBare);
    let state = state_with(activation, interop_replying(Vec::new()));
    let response = exchange(
        &state,
        false,
        &get("/.well-known/oauth-protected-resource", &[]),
    )
    .await;
    assert_eq!(response.status, 503);
}

/// Authentication runs BEFORE the body is read.
///
/// Asserted by the status an oversized POST gets: a body past the 1 MiB cap
/// answers `413` only once the reader has been asked to buffer it, so an
/// unauthenticated peer seeing `401` proves this process never read one. With
/// the two steps the other way round — the shape this path shipped with — an
/// anonymous caller could make every request buffer a megabyte first.
#[tokio::test]
async fn an_unauthenticated_a2a_post_is_refused_before_its_body_is_read() {
    let (activation, _) = activation_with(Store::Config(true));
    let state = state_with(activation, interop_with_base_url(vec![Activity::text("x")]));
    let oversized = "x".repeat((1 << 20) + 1);
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "SendMessage",
        "params": {"message": {"messageId": "m", "role": "ROLE_USER",
                   "parts": [{"text": oversized}]}}
    })
    .to_string();

    let anonymous = exchange(&state, false, &post("/a2a", &[], &body)).await;
    assert_eq!(
        anonymous.status, 401,
        "an anonymous caller must be refused before the body is buffered"
    );

    // …and the cap still applies to a caller that IS authenticated, so the
    // reorder did not remove the limit.
    let authenticated = exchange(&state, false, &post("/a2a", &[AUTH], &body)).await;
    assert_eq!(authenticated.status, 413);
}
