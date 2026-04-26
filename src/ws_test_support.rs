//! Public test support for the WebSocket streaming endpoint.
//!
//! This module is `#[doc(hidden)]` and only intended for use by integration
//! tests in `tests/` (notably `tests/webchat_websocket.rs`). It exposes a
//! self-contained Hyper server that wires the same WS upgrade -> session ->
//! pump pipeline used in production, but with stub-friendly seams so tests
//! don't need a fully-loaded `HttpIngressState`.
//!
//! What is *not* exercised here:
//! * `HttpIngressState` / `DemoRunnerHost` — those require a real bundle.
//! * The route-matching logic in `http_ingress::handle_request_inner` — the
//!   test server accepts any URL and runs the upgrade handshake directly.
//!
//! What *is* exercised end-to-end:
//! * Real Hyper HTTP/1 server bound to a random TCP port.
//! * `hyper_tungstenite::upgrade` handshake.
//! * `validate_request_parts` (token check, watermark parsing).
//! * `serve_session` -> `Pump` -> `InMemoryNotifier` push pipeline.
//! * Tungstenite-over-Hyper framing back to a `tokio_tungstenite` client.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::tokio::TokioIo;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

pub use crate::http_ingress::websocket::{
    ActivitySource, SessionManager, WsLimits, refusal_response, serve_session,
    validate_request_parts,
};
pub use crate::notifier::{ActivityNotifier, InMemoryNotifier, NotifyEvent};

/// In-memory bag of activities, shared between the test driver and the stub
/// `ActivitySource`. Tests append entries via [`TestActivities::append`] and
/// the source returns those whose `channelData.watermark` is `>= since`.
#[derive(Default)]
pub struct TestActivities {
    entries: Mutex<Vec<Value>>,
    next_watermark: Mutex<u64>,
}

impl TestActivities {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a message activity and return the watermark it was assigned.
    pub fn append(&self, text: &str) -> u64 {
        let mut wm = self.next_watermark.lock().unwrap();
        let watermark = *wm;
        *wm += 1;
        self.entries.lock().unwrap().push(serde_json::json!({
            "type": "message",
            "text": text,
            "channelData": {"watermark": watermark},
        }));
        watermark
    }

    /// Number of activities currently stored.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// `ActivitySource` adapter over [`TestActivities`].
pub struct InMemoryActivitySource {
    pub activities: Arc<TestActivities>,
}

#[async_trait]
impl ActivitySource for InMemoryActivitySource {
    async fn fetch_since(
        &self,
        _tenant_id: &str,
        _conversation_id: &str,
        since_watermark: u64,
    ) -> Result<(Vec<Value>, u64), String> {
        let entries = self.activities.entries.lock().unwrap();
        let next = *self.activities.next_watermark.lock().unwrap();
        let filtered: Vec<Value> = entries
            .iter()
            .filter(|activity| {
                activity
                    .get("channelData")
                    .and_then(|cd| cd.get("watermark"))
                    .and_then(|w| w.as_u64())
                    .map(|w| w >= since_watermark)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        Ok((filtered, next))
    }
}

/// Configuration for [`spawn_test_server`].
pub struct TestServerConfig {
    pub signing_key: Vec<u8>,
    pub expected_tenant: String,
    pub limits: WsLimits,
}

impl Default for TestServerConfig {
    fn default() -> Self {
        Self {
            signing_key: b"test-key".to_vec(),
            expected_tenant: "tenant1".to_string(),
            limits: WsLimits::default(),
        }
    }
}

/// Handle returned by [`spawn_test_server`] — exposes the bound address,
/// the notifier (so tests can publish events), and the activity store
/// (so tests can populate replay/live data).
pub struct TestServer {
    pub addr: SocketAddr,
    pub notifier: Arc<dyn ActivityNotifier>,
    pub activities: Arc<TestActivities>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl TestServer {
    /// Trigger graceful shutdown of the test server.
    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Spawn an in-process Hyper server that:
/// * binds to `127.0.0.1:0` (random free port),
/// * accepts any path,
/// * authenticates incoming WS upgrades against `config.signing_key`,
/// * fans the WS session into `serve_session` with an in-memory
///   notifier and an [`InMemoryActivitySource`].
pub async fn spawn_test_server(config: TestServerConfig) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind random port");
    let addr = listener.local_addr().expect("local addr");

    let notifier: Arc<dyn ActivityNotifier> = Arc::new(InMemoryNotifier::new(64));
    let activities = Arc::new(TestActivities::new());
    let session_manager = Arc::new(SessionManager::new(config.limits.clone()));

    let shared = Arc::new(SharedState {
        notifier: notifier.clone(),
        activities: activities.clone(),
        session_manager,
        signing_key: config.signing_key,
        expected_tenant: config.expected_tenant,
        limits: config.limits,
    });

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accept = listener.accept() => match accept {
                    Ok((stream, _peer)) => {
                        let shared = shared.clone();
                        tokio::spawn(async move {
                            let service = service_fn(move |req| {
                                handle_request(req, shared.clone())
                            });
                            let stream = TokioIo::new(stream);
                            let _ = Http1Builder::new()
                                .serve_connection(stream, service)
                                .with_upgrades()
                                .await;
                        });
                    }
                    Err(_) => break,
                },
            }
        }
    });

    TestServer {
        addr,
        notifier,
        activities,
        shutdown: Some(shutdown_tx),
    }
}

struct SharedState {
    notifier: Arc<dyn ActivityNotifier>,
    activities: Arc<TestActivities>,
    session_manager: Arc<SessionManager>,
    signing_key: Vec<u8>,
    expected_tenant: String,
    limits: WsLimits,
}

async fn handle_request(
    mut req: Request<hyper::body::Incoming>,
    shared: Arc<SharedState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Conversation id is the last path segment before `/stream`. We don't
    // re-parse the full webchat route here — the test driver always points
    // at `/.../conversations/<id>/stream`.
    let path = req.uri().path().to_string();
    let conv_id = match conversation_id_from_stream_path(&path) {
        Some(id) => id,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("not a stream path")))
                .expect("static response"));
        }
    };

    let ctx = match validate_request_parts(
        req.uri(),
        req.headers(),
        &conv_id,
        &shared.expected_tenant,
        &shared.signing_key,
    ) {
        Ok(ctx) => ctx,
        Err(err) => return Ok(refusal_response(&err)),
    };

    let guard = match shared
        .session_manager
        .acquire(&shared.expected_tenant, &conv_id)
    {
        Ok(g) => g,
        Err(err) => {
            return Ok(refusal_response(
                &crate::http_ingress::websocket::UpgradeError::LimitExceeded(err.to_string()),
            ));
        }
    };

    let (response, websocket) = match hyper_tungstenite::upgrade(&mut req, None) {
        Ok(pair) => pair,
        Err(err) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(format!("upgrade failed: {err}"))))
                .expect("static response"));
        }
    };

    let source: Arc<dyn ActivitySource> = Arc::new(InMemoryActivitySource {
        activities: shared.activities.clone(),
    });
    let notifier = shared.notifier.clone();
    let tenant = shared.expected_tenant.clone();
    let limits = shared.limits.clone();

    tokio::spawn(serve_session(
        websocket,
        notifier,
        source,
        tenant,
        conv_id,
        ctx.initial_watermark,
        limits,
        guard,
    ));

    // Hyper's response carries a `BoxBody` (`http_body_util::combinators::BoxBody`),
    // but our handler signature uses `Full<Bytes>`. Repackage the upgrade
    // response into the same body type.
    let (parts, _body) = response.into_parts();
    Ok(Response::from_parts(parts, Full::new(Bytes::new())))
}

/// Extract `<id>` from `.../conversations/<id>/stream`.
fn conversation_id_from_stream_path(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let stream_idx = segments.iter().position(|s| *s == "stream")?;
    if stream_idx < 2 {
        return None;
    }
    if segments[stream_idx - 2] != "conversations" {
        return None;
    }
    Some(segments[stream_idx - 1].to_string())
}

/// Issue an HS256 JWT matching the production `verify_directline_token`
/// expectations (`{ sub: conv, tenant, exp }` claims).
pub fn issue_test_token(conversation_id: &str, tenant: &str, signing_key: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let exp = chrono::Utc::now().timestamp() + 60;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = format!(r#"{{"sub":"{conversation_id}","tenant":"{tenant}","exp":{exp}}}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
    let signing_input = format!("{header}.{payload}");
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(signing_key).expect("hmac accepts any key");
    mac.update(signing_input.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{sig}")
}
