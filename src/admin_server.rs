//! mTLS admin API server for runtime bundle lifecycle management.
//!
//! Runs on a separate port (default 8443) alongside the main HTTP ingress.
//! Uses rustls for mutual TLS authentication.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::tokio::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value as JsonValue, json};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::{RwLock, oneshot};
use tokio_rustls::TlsAcceptor;

use greentic_setup::admin::AdminTlsConfig;
use greentic_setup::admin::routes::{
    AdminResponse, BundleDeployRequest, BundleRemoveRequest, BundleStatus, BundleStatusResponse,
};
use greentic_setup::card_setup::CardSetupSession;
use greentic_setup::discovery;
use greentic_setup::engine::{SetupConfig, SetupRequest};
use greentic_setup::plan::TenantSelection;
use greentic_setup::qa::persist::persist_qa_results;
use greentic_setup::qa::wizard::{
    compute_visibility, render_qa_card, validate_answers_against_form_spec,
};
use greentic_setup::setup_to_formspec;
use greentic_setup::{SetupEngine, SetupMode};

use crate::operator_log;

pub struct AdminServerConfig {
    pub tls_config: AdminTlsConfig,
    pub bundle_root: PathBuf,
}

pub struct AdminServer {
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<thread::JoinHandle<Result<()>>>,
}

/// Default session TTL: 30 minutes.
const SESSION_TTL_SECS: u64 = 1800;

#[derive(Clone)]
struct AdminState {
    bundle_root: PathBuf,
    allowed_clients: Vec<String>,
    sessions: Arc<RwLock<HashMap<String, CardSetupSession>>>,
}

impl AdminServer {
    pub fn start(config: AdminServerConfig) -> Result<Self> {
        let tls_config = config.tls_config;
        tls_config.validate()?;

        let tls_server_config = build_tls_config(
            &tls_config.server_cert,
            &tls_config.server_key,
            &tls_config.client_ca,
        )?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_server_config));

        let bind_addr: SocketAddr = format!("127.0.0.1:{}", tls_config.port).parse()?;
        let state = Arc::new(AdminState {
            bundle_root: config.bundle_root,
            allowed_clients: tls_config.allowed_clients.clone(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        });

        let (tx, rx) = oneshot::channel();
        let (startup_tx, startup_rx) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("admin-server".to_string())
            .spawn(move || -> Result<()> {
                let runtime = match Runtime::new().context("failed to create admin runtime") {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        let _ = startup_tx.send(Err(err.to_string()));
                        return Err(err);
                    }
                };
                runtime.block_on(async move {
                    let listener = match TcpListener::bind(bind_addr)
                        .await
                        .context("failed to bind admin listener")
                    {
                        Ok(listener) => listener,
                        Err(err) => {
                            let _ = startup_tx.send(Err(err.to_string()));
                            return Err(err);
                        }
                    };
                    let _ = startup_tx.send(Ok(()));
                    operator_log::info(
                        module_path!(),
                        format!("admin API listening on https://{} (mTLS)", bind_addr),
                    );
                    let mut shutdown = rx;
                    loop {
                        tokio::select! {
                            _ = &mut shutdown => break,
                            accept = listener.accept() => match accept {
                                Ok((stream, peer)) => {
                                    let tls = acceptor.clone();
                                    let conn_state = state.clone();
                                    tokio::spawn(async move {
                                        let tls_stream = match tls.accept(stream).await {
                                            Ok(s) => s,
                                            Err(err) => {
                                                operator_log::warn(
                                                    module_path!(),
                                                    format!("admin TLS handshake failed from {}: {}", peer, err),
                                                );
                                                return;
                                            }
                                        };

                                        // Extract client CN from peer certs
                                        let client_cn = extract_client_cn(tls_stream.get_ref().1);
                                        if !check_client_allowed(&conn_state.allowed_clients, client_cn.as_deref()) {
                                            operator_log::warn(
                                                module_path!(),
                                                format!("admin: rejected client CN={:?} from {}", client_cn, peer),
                                            );
                                            return;
                                        }

                                        let service = service_fn(move |req| {
                                            handle_admin_request(req, conn_state.clone())
                                        });
                                        let http = Http1Builder::new();
                                        let io = TokioIo::new(tls_stream);
                                        if let Err(err) = http.serve_connection(io, service).await {
                                            operator_log::error(
                                                module_path!(),
                                                format!("admin connection error from {}: {}", peer, err),
                                            );
                                        }
                                    });
                                }
                                Err(err) => {
                                    operator_log::error(
                                        module_path!(),
                                        format!("admin accept error: {}", err),
                                    );
                                }
                            },
                        }
                    }
                    Ok(())
                })
            })?;

        match startup_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                return Err(anyhow::anyhow!("failed to start admin server: {err}"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(anyhow::anyhow!(
                    "failed to start admin server: startup timed out"
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(anyhow::anyhow!(
                    "failed to start admin server: startup thread disconnected"
                ));
            }
        }

        Ok(Self {
            shutdown: Some(tx),
            handle: Some(handle),
        })
    }

    pub fn stop(mut self) -> Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let joined = handle
                .join()
                .map_err(|err| anyhow::anyhow!("admin server panicked: {err:?}"))?;
            joined?;
        }
        Ok(())
    }
}

fn build_tls_config(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> Result<rustls::ServerConfig> {
    // Load server certs
    let cert_file = File::open(cert_path)
        .with_context(|| format!("open server cert: {}", cert_path.display()))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .context("parse server certs")?;

    // Load server key
    let key_file =
        File::open(key_path).with_context(|| format!("open server key: {}", key_path.display()))?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .context("parse server key")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    // Load client CA
    let ca_file =
        File::open(ca_path).with_context(|| format!("open client CA: {}", ca_path.display()))?;
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(ca_file))
            .collect::<Result<Vec<_>, _>>()
            .context("parse client CA certs")?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).context("add CA cert to root store")?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(root_store),
        provider.clone(),
    )
    .build()
    .context("build client cert verifier")?;

    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("set TLS protocol versions")?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("with_single_cert failed: {e}"))?;

    Ok(config)
}

fn extract_client_cn(server_conn: &rustls::ServerConnection) -> Option<String> {
    let certs = server_conn.peer_certificates()?;
    let cert = certs.first()?;
    // Parse the DER certificate to extract CN
    // Simple approach: look for CN in the subject
    extract_cn_from_der(cert.as_ref())
}

fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    // Minimal ASN.1 CN extraction — looks for the OID 2.5.4.3 (CN) in DER.
    // In X.509 DER encoding, Issuer appears before Subject, so we take the
    // *last* CN match to get the Subject CN rather than the Issuer CN.
    // OID bytes: 55 04 03
    let cn_oid = [0x55, 0x04, 0x03];
    let mut last_cn: Option<String> = None;
    for window_start in 0..der.len().saturating_sub(cn_oid.len()) {
        if der[window_start..window_start + cn_oid.len()] == cn_oid {
            // After OID, expect: tag(0x0C or 0x13) + length + value
            let value_start = window_start + cn_oid.len();
            if value_start + 2 > der.len() {
                continue;
            }
            let tag = der[value_start];
            if tag != 0x0C && tag != 0x13 {
                continue;
            }
            let len = der[value_start + 1] as usize;
            let data_start = value_start + 2;
            if data_start + len > der.len() {
                continue;
            }
            if let Ok(cn) = std::str::from_utf8(&der[data_start..data_start + len]) {
                last_cn = Some(cn.to_string());
            }
        }
    }
    last_cn
}

fn check_client_allowed(allowed: &[String], cn: Option<&str>) -> bool {
    if allowed.is_empty() {
        return true; // No allowlist = allow any valid client cert
    }
    let Some(cn) = cn else {
        return false;
    };
    allowed
        .iter()
        .any(|pattern| pattern == cn || pattern == &format!("CN={cn}") || pattern == "*")
}

// ── Request Handling ────────────────────────────────────────────────────────

async fn handle_admin_request(
    req: Request<Incoming>,
    state: Arc<AdminState>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let response = match route_admin_request(method, &path, req, &state).await {
        Ok(resp) => resp,
        Err(resp) => resp,
    };
    Ok(response)
}

async fn route_admin_request(
    method: Method,
    path: &str,
    req: Request<Incoming>,
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    match (method.clone(), path) {
        (Method::GET, "/admin/v1/health") => Ok(json_response(
            StatusCode::OK,
            json!(AdminResponse::ok("healthy")),
        )),

        (Method::GET, "/admin/v1/status") => handle_status(state),

        (Method::POST, "/admin/v1/deploy") => {
            let body = read_json_body(req).await?;
            handle_deploy(state, body).await
        }

        (Method::POST, "/admin/v1/remove") => {
            let body = read_json_body(req).await?;
            handle_remove(state, body).await
        }

        (Method::POST, "/admin/v1/setup") => {
            let body = read_json_body(req).await?;
            handle_setup(state, body).await
        }

        // ── QA Adaptive Card endpoints ──────────────────────────────────
        (Method::POST, "/admin/v1/qa/card") => {
            let body = read_json_body(req).await?;
            handle_qa_card(state, body).await
        }

        (Method::POST, "/admin/v1/qa/submit") => {
            let body = read_json_body(req).await?;
            handle_qa_submit(state, body).await
        }

        (Method::POST, "/admin/v1/qa/validate") => {
            let body = read_json_body(req).await?;
            handle_qa_validate(state, body)
        }

        _ => {
            // Dynamic path: GET /admin/v1/qa/session/:id
            if method == Method::GET && path.starts_with("/admin/v1/qa/session/") {
                let session_id = &path["/admin/v1/qa/session/".len()..];
                return handle_qa_session_get(state, session_id).await;
            }
            Err(json_response(
                StatusCode::NOT_FOUND,
                json!(AdminResponse::<()>::err(format!(
                    "unknown endpoint: {path}"
                ))),
            ))
        }
    }
}

fn handle_status(state: &AdminState) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let bundle = &state.bundle_root;

    let provider_count = match discovery::discover(bundle) {
        Ok(result) => result.providers.len(),
        Err(_) => 0,
    };
    let pack_count = count_bundle_packs(bundle).unwrap_or(0);

    let tenants_dir = bundle.join("tenants");
    let tenant_count = std::fs::read_dir(&tenants_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .count()
        })
        .unwrap_or(0);

    let resp = BundleStatusResponse {
        bundle_path: bundle.clone(),
        status: BundleStatus::Active,
        pack_count,
        tenant_count,
        provider_count,
    };

    Ok(json_response(
        StatusCode::OK,
        json!(AdminResponse::ok(resp)),
    ))
}

async fn handle_deploy(
    _state: &AdminState,
    body: JsonValue,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    tokio::task::spawn_blocking(move || {
        let req: BundleDeployRequest = serde_json::from_value(body).map_err(|err| {
            json_response(
                StatusCode::BAD_REQUEST,
                json!(AdminResponse::<()>::err(err.to_string())),
            )
        })?;

        let config = SetupConfig {
            tenant: req
                .tenants
                .first()
                .map(|t| t.tenant.clone())
                .unwrap_or_else(|| "demo".into()),
            team: req.tenants.first().and_then(|t| t.team.clone()),
            env: greentic_setup::resolve_env(None),
            offline: false,
            verbose: true,
        };
        let engine = SetupEngine::new(config);

        let setup_answers = if let Some(obj) = req.answers.as_object() {
            obj.clone()
        } else {
            serde_json::Map::new()
        };

        let setup_request = SetupRequest {
            bundle: req.bundle_path.clone(),
            pack_refs: req.pack_refs,
            tenants: req.tenants,
            setup_answers,
            ..Default::default()
        };

        let plan = engine
            .plan(SetupMode::Create, &setup_request, req.dry_run)
            .map_err(|err| {
                json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!(AdminResponse::<()>::err(err.to_string())),
                )
            })?;

        if req.dry_run {
            let steps: Vec<String> = plan.steps.iter().map(|s| s.description.clone()).collect();
            return Ok(json_response(
                StatusCode::OK,
                json!(AdminResponse::ok(json!({
                    "dry_run": true,
                    "steps": steps,
                }))),
            ));
        }

        let report = engine.execute(&plan).map_err(|err| {
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!(AdminResponse::<()>::err(err.to_string())),
            )
        })?;

        Ok(json_response(
            StatusCode::OK,
            json!(AdminResponse::ok(json!({
                "deployed": true,
                "resolved_packs": report.resolved_packs.len(),
            }))),
        ))
    })
    .await
    .map_err(|err| {
        json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!(AdminResponse::<()>::err(format!(
                "deploy task failed: {err}"
            ))),
        )
    })?
}

async fn handle_remove(
    _state: &AdminState,
    body: JsonValue,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    tokio::task::spawn_blocking(move || {
        let req: BundleRemoveRequest = serde_json::from_value(body).map_err(|err| {
            json_response(
                StatusCode::BAD_REQUEST,
                json!(AdminResponse::<()>::err(err.to_string())),
            )
        })?;

        let config = SetupConfig {
            tenant: req
                .tenants
                .first()
                .map(|t| t.tenant.clone())
                .unwrap_or_else(|| "demo".into()),
            team: req.tenants.first().and_then(|t| t.team.clone()),
            env: greentic_setup::resolve_env(None),
            offline: false,
            verbose: true,
        };
        let engine = SetupEngine::new(config);

        let setup_request = SetupRequest {
            bundle: req.bundle_path.clone(),
            providers_remove: req.providers,
            tenants: req.tenants,
            ..Default::default()
        };

        let plan = engine
            .plan(SetupMode::Remove, &setup_request, req.dry_run)
            .map_err(|err| {
                json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!(AdminResponse::<()>::err(err.to_string())),
                )
            })?;

        if req.dry_run {
            let steps: Vec<String> = plan.steps.iter().map(|s| s.description.clone()).collect();
            return Ok(json_response(
                StatusCode::OK,
                json!(AdminResponse::ok(json!({
                    "dry_run": true,
                    "steps": steps,
                }))),
            ));
        }

        engine.execute(&plan).map_err(|err| {
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!(AdminResponse::<()>::err(err.to_string())),
            )
        })?;

        Ok(json_response(
            StatusCode::OK,
            json!(AdminResponse::ok(json!({
                "removed": true,
            }))),
        ))
    })
    .await
    .map_err(|err| {
        json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!(AdminResponse::<()>::err(format!(
                "remove task failed: {err}"
            ))),
        )
    })?
}

async fn handle_setup(
    state: &AdminState,
    body: JsonValue,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let bundle_root = state.bundle_root.clone();
    tokio::task::spawn_blocking(move || {
        // Accept: { "tenant": "demo", "team": "default", "answers": { "provider-id": { ... } } }
        let tenant = body
            .get("tenant")
            .and_then(|v| v.as_str())
            .unwrap_or("demo");
        let team = body.get("team").and_then(|v| v.as_str());
        let dry_run = body
            .get("dry_run")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let config = SetupConfig {
            tenant: tenant.to_string(),
            team: team.map(|t| t.to_string()),
            env: greentic_setup::resolve_env(None),
            offline: false,
            verbose: true,
        };
        let engine = SetupEngine::new(config);

        let setup_answers = body
            .get("answers")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        let setup_request = SetupRequest {
            bundle: bundle_root,
            tenants: vec![TenantSelection {
                tenant: tenant.to_string(),
                team: team.map(|t| t.to_string()),
                allow_paths: Vec::new(),
            }],
            setup_answers,
            ..Default::default()
        };

        let plan = engine
            .plan(SetupMode::Create, &setup_request, dry_run)
            .map_err(|err| {
                json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!(AdminResponse::<()>::err(err.to_string())),
                )
            })?;

        if dry_run {
            let steps: Vec<String> = plan.steps.iter().map(|s| s.description.clone()).collect();
            return Ok(json_response(
                StatusCode::OK,
                json!(AdminResponse::ok(json!({
                    "dry_run": true,
                    "steps": steps,
                }))),
            ));
        }

        engine.execute(&plan).map_err(|err| {
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!(AdminResponse::<()>::err(err.to_string())),
            )
        })?;

        Ok(json_response(
            StatusCode::OK,
            json!(AdminResponse::ok(json!({
                "setup": true,
            }))),
        ))
    })
    .await
    .map_err(|err| {
        json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!(AdminResponse::<()>::err(format!(
                "setup task failed: {err}"
            ))),
        )
    })?
}

// ── QA Adaptive Card Handlers ───────────────────────────────────────────────

/// POST /admin/v1/qa/card
///
/// Start a new card session or continue an existing one. Returns an Adaptive
/// Card v1.3 JSON for the next unanswered question.
///
/// Request:
/// ```json
/// {
///   "provider_id": "state-redis",
///   "tenant": "demo",
///   "team": null,
///   "session_id": null,
///   "answers": {}
/// }
/// ```
async fn handle_qa_card(
    state: &AdminState,
    body: JsonValue,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let provider_id = body
        .get("provider_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request("missing provider_id"))?;
    let tenant = body
        .get("tenant")
        .and_then(|v| v.as_str())
        .unwrap_or("demo");
    let team = body.get("team").and_then(|v| v.as_str());

    let pack_path = find_provider_pack(&state.bundle_root, provider_id)?;
    let form_spec = setup_to_formspec::pack_to_form_spec(&pack_path, provider_id)
        .ok_or_else(|| bad_request(format!("no QA spec found for {provider_id}")))?;

    // Look up or create session
    let session_id = body.get("session_id").and_then(|v| v.as_str());
    let new_answers = body.get("answers").cloned().unwrap_or(json!({}));

    let session_id = if let Some(sid) = session_id {
        // Continue existing session
        let mut sessions = state.sessions.write().await;
        let session = sessions.get_mut(sid).ok_or_else(|| {
            json_response(
                StatusCode::NOT_FOUND,
                json!(AdminResponse::<()>::err(format!("session {sid} not found"))),
            )
        })?;
        if session.is_expired() {
            sessions.remove(sid);
            return Err(json_response(
                StatusCode::GONE,
                json!(AdminResponse::<()>::err("session expired")),
            ));
        }
        session.merge_answers(&new_answers);
        sid.to_string()
    } else {
        // Create new session
        let mut session = CardSetupSession::new(
            state.bundle_root.clone(),
            provider_id.to_string(),
            tenant.to_string(),
            team.map(|t| t.to_string()),
            Duration::from_secs(SESSION_TTL_SECS),
        );
        session.merge_answers(&new_answers);
        let sid = session.session_id.clone();
        state.sessions.write().await.insert(sid.clone(), session);
        sid
    };

    // Render the adaptive card
    let current_answers = {
        let sessions = state.sessions.read().await;
        sessions
            .get(&session_id)
            .map(|s| s.answers_as_value())
            .unwrap_or(json!({}))
    };
    let (card, next_question_id) = render_qa_card(&form_spec, &current_answers);
    let complete = next_question_id.is_none();

    Ok(json_response(
        StatusCode::OK,
        json!(AdminResponse::ok(json!({
            "session_id": session_id,
            "card": card,
            "complete": complete,
            "next_question_id": next_question_id,
        }))),
    ))
}

/// POST /admin/v1/qa/submit
///
/// Submit answers for a card session. If all questions are answered, persists
/// secrets and marks the session complete. Otherwise returns the next card.
///
/// Request:
/// ```json
/// {
///   "session_id": "setup-abc123",
///   "answers": { "redis_url": "redis://localhost:6379", ... }
/// }
/// ```
async fn handle_qa_submit(
    state: &AdminState,
    body: JsonValue,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let session_id = body
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request("missing session_id"))?;
    let new_answers = body.get("answers").cloned().unwrap_or(json!({}));

    // Update session answers
    let (provider_id, tenant, team, all_answers) = {
        let mut sessions = state.sessions.write().await;
        let session = sessions.get_mut(session_id).ok_or_else(|| {
            json_response(
                StatusCode::NOT_FOUND,
                json!(AdminResponse::<()>::err(format!(
                    "session {session_id} not found"
                ))),
            )
        })?;
        if session.is_expired() {
            let sid = session_id.to_string();
            sessions.remove(&sid);
            return Err(json_response(
                StatusCode::GONE,
                json!(AdminResponse::<()>::err("session expired")),
            ));
        }
        if session.completed {
            return Err(bad_request("session already completed"));
        }
        session.merge_answers(&new_answers);
        (
            session.provider_id.clone(),
            session.tenant.clone(),
            session.team.clone(),
            session.answers_as_value(),
        )
    };

    // Load FormSpec
    let pack_path = find_provider_pack(&state.bundle_root, &provider_id)?;
    let form_spec = setup_to_formspec::pack_to_form_spec(&pack_path, &provider_id)
        .ok_or_else(|| bad_request(format!("no QA spec found for {provider_id}")))?;

    // Validate
    if let Err(err) = validate_answers_against_form_spec(&form_spec, &all_answers) {
        // Validation failed — return next card with the error
        let (card, next_question_id) = render_qa_card(&form_spec, &all_answers);
        return Ok(json_response(
            StatusCode::OK,
            json!(AdminResponse::ok(json!({
                "session_id": session_id,
                "complete": false,
                "validation_error": err.to_string(),
                "card": card,
                "next_question_id": next_question_id,
            }))),
        ));
    }

    // Check if all questions are answered
    let (card, next_question_id) = render_qa_card(&form_spec, &all_answers);
    if next_question_id.is_some() {
        // Still more questions — return next card
        return Ok(json_response(
            StatusCode::OK,
            json!(AdminResponse::ok(json!({
                "session_id": session_id,
                "complete": false,
                "card": card,
                "next_question_id": next_question_id,
            }))),
        ));
    }

    // All questions answered — persist secrets
    let persisted_keys = persist_qa_results(
        &state.bundle_root,
        &tenant,
        team.as_deref(),
        &provider_id,
        &all_answers,
        &form_spec,
    )
    .await
    .map_err(|err| {
        json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!(AdminResponse::<()>::err(format!("persist failed: {err}"))),
        )
    })?;

    // Mark session complete
    {
        let mut sessions = state.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.completed = true;
        }
    }

    Ok(json_response(
        StatusCode::OK,
        json!(AdminResponse::ok(json!({
            "session_id": session_id,
            "complete": true,
            "persisted_keys": persisted_keys,
        }))),
    ))
}

/// POST /admin/v1/qa/validate
///
/// Stateless validation of answers against a provider's FormSpec.
/// Returns validity, errors, and the current visibility map.
///
/// Request:
/// ```json
/// {
///   "provider_id": "state-redis",
///   "answers": { "redis_url": "redis://localhost:6379" }
/// }
/// ```
fn handle_qa_validate(
    state: &AdminState,
    body: JsonValue,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let provider_id = body
        .get("provider_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request("missing provider_id"))?;
    let answers = body.get("answers").cloned().unwrap_or(json!({}));

    let pack_path = find_provider_pack(&state.bundle_root, provider_id)?;
    let form_spec = setup_to_formspec::pack_to_form_spec(&pack_path, provider_id)
        .ok_or_else(|| bad_request(format!("no QA spec found for {provider_id}")))?;

    let validation_error = validate_answers_against_form_spec(&form_spec, &answers)
        .err()
        .map(|e| e.to_string());

    let visibility = compute_visibility(&form_spec, &answers);

    Ok(json_response(
        StatusCode::OK,
        json!(AdminResponse::ok(json!({
            "valid": validation_error.is_none(),
            "error": validation_error,
            "visibility": visibility,
        }))),
    ))
}

/// GET /admin/v1/qa/session/:id
///
/// Get the current state of a card setup session.
async fn handle_qa_session_get(
    state: &AdminState,
    session_id: &str,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let sessions = state.sessions.read().await;
    let session = sessions.get(session_id).ok_or_else(|| {
        json_response(
            StatusCode::NOT_FOUND,
            json!(AdminResponse::<()>::err(format!(
                "session {session_id} not found"
            ))),
        )
    })?;

    if session.is_expired() {
        return Err(json_response(
            StatusCode::GONE,
            json!(AdminResponse::<()>::err("session expired")),
        ));
    }

    Ok(json_response(
        StatusCode::OK,
        json!(AdminResponse::ok(json!({
            "session_id": session.session_id,
            "provider_id": session.provider_id,
            "tenant": session.tenant,
            "team": session.team,
            "current_step": session.current_step,
            "completed": session.completed,
            "expires_at": session.expires_at,
            "answer_count": session.answers.len(),
        }))),
    ))
}

/// Resolve a provider ID to its pack path via bundle discovery.
fn find_provider_pack(
    bundle_root: &Path,
    provider_id: &str,
) -> Result<PathBuf, Response<Full<Bytes>>> {
    let result = discovery::discover(bundle_root).map_err(|err| {
        json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!(AdminResponse::<()>::err(format!("discovery failed: {err}"))),
        )
    })?;
    result
        .providers
        .iter()
        .find(|p| p.provider_id == provider_id)
        .map(|p| p.pack_path.clone())
        .ok_or_else(|| {
            json_response(
                StatusCode::NOT_FOUND,
                json!(AdminResponse::<()>::err(format!(
                    "provider {provider_id} not found in bundle"
                ))),
            )
        })
}

/// Shorthand for a 400 Bad Request response.
fn bad_request(msg: impl Into<String>) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::BAD_REQUEST,
        json!(AdminResponse::<()>::err(msg.into())),
    )
}

fn count_bundle_packs(bundle_root: &Path) -> anyhow::Result<usize> {
    let packs_dir = bundle_root.join("packs");
    if !packs_dir.exists() {
        return Ok(0);
    }
    let mut count = 0usize;
    let mut stack = vec![packs_dir];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("gtpack") {
                count += 1;
            }
        }
    }
    Ok(count)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async fn read_json_body(req: Request<Incoming>) -> Result<JsonValue, Response<Full<Bytes>>> {
    let bytes = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|err| {
            json_response(
                StatusCode::BAD_REQUEST,
                json!(AdminResponse::<()>::err(format!(
                    "failed to read body: {err}"
                ))),
            )
        })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        json_response(
            StatusCode::BAD_REQUEST,
            json!(AdminResponse::<()>::err(format!("invalid JSON: {err}"))),
        )
    })
}

fn json_response(status: StatusCode, value: JsonValue) -> Response<Full<Bytes>> {
    let body = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::from(Bytes::from(body)))
        .unwrap_or_else(|err| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::from(Bytes::from(format!(
                    "response build error: {err}"
                ))))
                .unwrap()
        })
}
