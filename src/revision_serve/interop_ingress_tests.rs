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
}

impl TestSecrets {
    fn with(entries: HashMap<String, Vec<u8>>) -> Self {
        Self {
            entries,
            fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            entries: HashMap::new(),
            fail: true,
        }
    }
}

#[async_trait::async_trait]
impl greentic_secrets_lib::SecretsManager for TestSecrets {
    async fn read(&self, path: &str) -> greentic_secrets_lib::Result<Vec<u8>> {
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
    json!({
        "v": 1,
        "a2a": a2a,
        "mcp": false,
        "credentials": [{
            "id": "c1",
            "sha256": Sha256::digest(TOKEN.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        }],
        "tenant_slug": "acme",
        "agent": {"name": "Support Bot", "description": "Answers support questions."}
    })
    .to_string()
    .into_bytes()
}

fn config_uri() -> String {
    crate::ingress_auth::ingress_secret_uri(&crate::resolve_env(None), TENANT, BUNDLE)
}

/// What the unit's secrets store holds for this test.
enum Store {
    /// The staged config, with A2A enabled or not.
    Config(bool),
    /// Nothing staged.
    Empty,
    /// The backend cannot answer.
    Down,
}

fn activation_with(store: Store) -> (Activation, DeploymentId) {
    let secrets: greentic_runner_host::secrets::DynSecretsManager = match store {
        Store::Config(a2a) => {
            let mut entries = HashMap::new();
            entries.insert(config_uri(), staged_config(a2a));
            Arc::new(TestSecrets::with(entries))
        }
        Store::Empty => Arc::new(TestSecrets::with(HashMap::new())),
        Store::Down => Arc::new(TestSecrets::failing()),
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
    (activation, deployment_id)
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
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
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
