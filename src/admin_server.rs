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
use hyper::body::{Body, Bytes, Incoming};
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
    AdminClientAddRequest, AdminClientEntry, AdminClientListResponse, AdminClientRemoveRequest,
    AdminResponse, BundleDeployRequest, BundleListResponse, BundleRemoveRequest,
    BundleStartRequest, BundleStatus, BundleStatusResponse, BundleStopRequest, BundleUpdateRequest,
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
use crate::runtime_state::{self, RuntimePaths, StopRequest};

type AdminHttpResponse = Response<Full<Bytes>>;
type AdminHttpError = Box<AdminHttpResponse>;
type AdminHttpResult<T = AdminHttpResponse> = Result<T, AdminHttpError>;

pub struct AdminServerConfig {
    pub tls_config: AdminTlsConfig,
    pub bundle_root: PathBuf,
    pub runtime_paths: RuntimePaths,
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
    runtime_paths: RuntimePaths,
    allowed_clients: Arc<RwLock<Vec<String>>>,
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
            runtime_paths: config.runtime_paths,
            allowed_clients: Arc::new(RwLock::new(tls_config.allowed_clients.clone())),
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
                                        let allowed_clients = conn_state.allowed_clients.read().await.clone();
                                        if !check_client_allowed(&allowed_clients, client_cn.as_deref()) {
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
) -> Result<AdminHttpResponse, std::convert::Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let response = match route_admin_request(method, &path, req, &state).await {
        Ok(resp) => resp,
        Err(resp) => *resp,
    };
    Ok(response)
}

async fn route_admin_request<B>(
    method: Method,
    path: &str,
    req: Request<B>,
    state: &AdminState,
) -> AdminHttpResult
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    match (method.clone(), path) {
        (Method::GET, "/admin/v1/health") => Ok(json_response(
            StatusCode::OK,
            json!(AdminResponse::ok("healthy")),
        )),

        (Method::GET, "/admin/v1/status") => handle_status(state),
        (Method::GET, "/admin/v1/list") => handle_list(state),
        (Method::GET, "/admin/v1/admins") => handle_admin_clients(state).await,

        (Method::POST, "/admin/v1/deploy") => {
            let body = read_json_body(req).await?;
            handle_deploy(state, body).await
        }

        (Method::POST, "/admin/v1/update") => {
            let body = read_json_body(req).await?;
            handle_update(state, body).await
        }

        (Method::POST, "/admin/v1/remove") => {
            let body = read_json_body(req).await?;
            handle_remove(state, body).await
        }

        (Method::POST, "/admin/v1/start") => {
            let body = read_json_body(req).await?;
            handle_start(state, body)
        }

        (Method::POST, "/admin/v1/stop") => {
            let body = read_json_body(req).await?;
            handle_stop(state, body)
        }

        (Method::POST, "/admin/v1/admins/add") => {
            let body = read_json_body(req).await?;
            handle_add_admin_client(state, body).await
        }

        (Method::POST, "/admin/v1/admins/remove") => {
            let body = read_json_body(req).await?;
            handle_remove_admin_client(state, body).await
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
            Err(Box::new(json_response(
                StatusCode::NOT_FOUND,
                json!(AdminResponse::<()>::err(format!(
                    "unknown endpoint: {path}"
                ))),
            )))
        }
    }
}

fn handle_status(state: &AdminState) -> AdminHttpResult {
    let bundle = &state.bundle_root;
    let bundle_exists = bundle.exists();

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
        status: current_bundle_status(state, bundle_exists),
        pack_count,
        tenant_count,
        provider_count,
    };

    Ok(json_response(
        StatusCode::OK,
        json!(AdminResponse::ok(resp)),
    ))
}

fn handle_list(state: &AdminState) -> AdminHttpResult {
    let bundle = &state.bundle_root;
    let status = BundleStatusResponse {
        bundle_path: bundle.clone(),
        status: current_bundle_status(state, bundle.exists()),
        pack_count: count_bundle_packs(bundle).unwrap_or(0),
        tenant_count: std::fs::read_dir(bundle.join("tenants"))
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.path().is_dir())
                    .count()
            })
            .unwrap_or(0),
        provider_count: discovery::discover(bundle)
            .map(|result| result.providers.len())
            .unwrap_or(0),
    };
    Ok(json_response(
        StatusCode::OK,
        json!(AdminResponse::ok(BundleListResponse {
            bundles: vec![status],
        })),
    ))
}

async fn handle_deploy(_state: &AdminState, body: JsonValue) -> AdminHttpResult {
    tokio::task::spawn_blocking(move || {
        let req: BundleDeployRequest = serde_json::from_value(body).map_err(|err| {
            Box::new(json_response(
                StatusCode::BAD_REQUEST,
                json!(AdminResponse::<()>::err(err.to_string())),
            ))
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
                Box::new(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!(AdminResponse::<()>::err(err.to_string())),
                ))
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
            Box::new(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!(AdminResponse::<()>::err(err.to_string())),
            ))
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
        Box::new(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!(AdminResponse::<()>::err(format!(
                "deploy task failed: {err}"
            ))),
        ))
    })?
}

async fn handle_update(_state: &AdminState, body: JsonValue) -> AdminHttpResult {
    tokio::task::spawn_blocking(move || {
        let req: BundleUpdateRequest = serde_json::from_value(body).map_err(|err| {
            Box::new(json_response(
                StatusCode::BAD_REQUEST,
                json!(AdminResponse::<()>::err(err.to_string())),
            ))
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
            .plan(SetupMode::Update, &setup_request, req.dry_run)
            .map_err(|err| {
                Box::new(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!(AdminResponse::<()>::err(err.to_string())),
                ))
            })?;

        if req.dry_run {
            let steps: Vec<String> = plan.steps.iter().map(|s| s.description.clone()).collect();
            return Ok(json_response(
                StatusCode::OK,
                json!(AdminResponse::ok(json!({
                    "dry_run": true,
                    "steps": steps,
                    "mode": "update",
                }))),
            ));
        }

        let report = engine.execute(&plan).map_err(|err| {
            Box::new(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!(AdminResponse::<()>::err(err.to_string())),
            ))
        })?;

        Ok(json_response(
            StatusCode::OK,
            json!(AdminResponse::ok(json!({
                "updated": true,
                "resolved_packs": report.resolved_packs.len(),
            }))),
        ))
    })
    .await
    .map_err(|err| {
        Box::new(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!(AdminResponse::<()>::err(format!(
                "update task failed: {err}"
            ))),
        ))
    })?
}

async fn handle_remove(_state: &AdminState, body: JsonValue) -> AdminHttpResult {
    tokio::task::spawn_blocking(move || {
        let req: BundleRemoveRequest = serde_json::from_value(body).map_err(|err| {
            Box::new(json_response(
                StatusCode::BAD_REQUEST,
                json!(AdminResponse::<()>::err(err.to_string())),
            ))
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
                Box::new(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!(AdminResponse::<()>::err(err.to_string())),
                ))
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
            Box::new(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!(AdminResponse::<()>::err(err.to_string())),
            ))
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
        Box::new(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!(AdminResponse::<()>::err(format!(
                "remove task failed: {err}"
            ))),
        ))
    })?
}

async fn handle_admin_clients(state: &AdminState) -> AdminHttpResult {
    let admins = state
        .allowed_clients
        .read()
        .await
        .iter()
        .cloned()
        .map(|client_cn| AdminClientEntry { client_cn })
        .collect::<Vec<_>>();
    Ok(json_response(
        StatusCode::OK,
        json!(AdminResponse::ok(AdminClientListResponse { admins })),
    ))
}

fn handle_start(state: &AdminState, body: JsonValue) -> AdminHttpResult {
    let req: BundleStartRequest = serde_json::from_value(body).map_err(|err| {
        Box::new(json_response(
            StatusCode::BAD_REQUEST,
            json!(AdminResponse::<()>::err(err.to_string())),
        ))
    })?;
    ensure_bundle_matches(state, &req.bundle_path)?;

    if !state.bundle_root.exists() {
        return Err(Box::new(json_response(
            StatusCode::CONFLICT,
            json!(AdminResponse::<()>::err(
                "runtime is inactive; remote start requires an external greentic-start launcher or cloud supervisor"
            )),
        )));
    }

    if runtime_state::read_stop_request(&state.runtime_paths)
        .map_err(internal_server_error)?
        .is_some()
    {
        return Err(Box::new(json_response(
            StatusCode::CONFLICT,
            json!(AdminResponse::<()>::err("runtime is already stopping")),
        )));
    }

    Ok(json_response(
        StatusCode::OK,
        json!(AdminResponse::ok(json!({
            "started": false,
            "status": "active",
            "message": "runtime is already active"
        }))),
    ))
}

fn handle_stop(state: &AdminState, body: JsonValue) -> AdminHttpResult {
    let req: BundleStopRequest = serde_json::from_value(body).map_err(|err| {
        Box::new(json_response(
            StatusCode::BAD_REQUEST,
            json!(AdminResponse::<()>::err(err.to_string())),
        ))
    })?;
    ensure_bundle_matches(state, &req.bundle_path)?;

    let stop_request = StopRequest {
        requested_by: "admin-api".into(),
        reason: Some("remote stop requested".into()),
    };
    runtime_state::write_stop_request(&state.runtime_paths, &stop_request)
        .map_err(internal_server_error)?;

    Ok(json_response(
        StatusCode::ACCEPTED,
        json!(AdminResponse::ok(json!({
            "stopping": true,
            "status": "stopping"
        }))),
    ))
}

async fn handle_add_admin_client(state: &AdminState, body: JsonValue) -> AdminHttpResult {
    let req: AdminClientAddRequest = serde_json::from_value(body).map_err(|err| {
        Box::new(json_response(
            StatusCode::BAD_REQUEST,
            json!(AdminResponse::<()>::err(err.to_string())),
        ))
    })?;
    ensure_bundle_matches(state, &req.bundle_path)?;

    let client_cn = req.client_cn.trim();
    if client_cn.is_empty() {
        return Err(bad_request_err("client_cn cannot be empty"));
    }

    let path = admin_registry_path(&state.bundle_root);
    let mut doc = read_admin_registry(&path).map_err(internal_server_error)?;
    if !doc.admins.iter().any(|entry| entry.client_cn == client_cn) {
        doc.admins.push(AdminRegistryEntry {
            client_cn: client_cn.to_string(),
        });
        doc.admins
            .sort_by(|left, right| left.client_cn.cmp(&right.client_cn));
        write_admin_registry(&path, &doc).map_err(internal_server_error)?;
    }

    {
        let mut allowed = state.allowed_clients.write().await;
        if !allowed.iter().any(|value| value == client_cn) {
            allowed.push(client_cn.to_string());
            allowed.sort();
            allowed.dedup();
        }
    }

    handle_admin_clients(state).await
}

async fn handle_remove_admin_client(state: &AdminState, body: JsonValue) -> AdminHttpResult {
    let req: AdminClientRemoveRequest = serde_json::from_value(body).map_err(|err| {
        Box::new(json_response(
            StatusCode::BAD_REQUEST,
            json!(AdminResponse::<()>::err(err.to_string())),
        ))
    })?;
    ensure_bundle_matches(state, &req.bundle_path)?;

    let client_cn = req.client_cn.trim();
    if client_cn.is_empty() {
        return Err(bad_request_err("client_cn cannot be empty"));
    }

    let path = admin_registry_path(&state.bundle_root);
    let mut doc = read_admin_registry(&path).map_err(internal_server_error)?;
    doc.admins.retain(|entry| entry.client_cn != client_cn);
    write_admin_registry(&path, &doc).map_err(internal_server_error)?;

    {
        let mut allowed = state.allowed_clients.write().await;
        allowed.retain(|value| value != client_cn);
    }

    handle_admin_clients(state).await
}

async fn handle_setup(state: &AdminState, body: JsonValue) -> AdminHttpResult {
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
                Box::new(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!(AdminResponse::<()>::err(err.to_string())),
                ))
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
            Box::new(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!(AdminResponse::<()>::err(err.to_string())),
            ))
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
        Box::new(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!(AdminResponse::<()>::err(format!(
                "setup task failed: {err}"
            ))),
        ))
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
async fn handle_qa_card(state: &AdminState, body: JsonValue) -> AdminHttpResult {
    let provider_id = body
        .get("provider_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request_err("missing provider_id"))?;
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
            Box::new(json_response(
                StatusCode::NOT_FOUND,
                json!(AdminResponse::<()>::err(format!("session {sid} not found"))),
            ))
        })?;
        if session.is_expired() {
            sessions.remove(sid);
            return Err(Box::new(json_response(
                StatusCode::GONE,
                json!(AdminResponse::<()>::err("session expired")),
            )));
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
async fn handle_qa_submit(state: &AdminState, body: JsonValue) -> AdminHttpResult {
    let session_id = body
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request_err("missing session_id"))?;
    let new_answers = body.get("answers").cloned().unwrap_or(json!({}));

    // Update session answers
    let (provider_id, tenant, team, all_answers) = {
        let mut sessions = state.sessions.write().await;
        let session = sessions.get_mut(session_id).ok_or_else(|| {
            Box::new(json_response(
                StatusCode::NOT_FOUND,
                json!(AdminResponse::<()>::err(format!(
                    "session {session_id} not found"
                ))),
            ))
        })?;
        if session.is_expired() {
            let sid = session_id.to_string();
            sessions.remove(&sid);
            return Err(Box::new(json_response(
                StatusCode::GONE,
                json!(AdminResponse::<()>::err("session expired")),
            )));
        }
        if session.completed {
            return Err(bad_request_err("session already completed"));
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
        Box::new(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!(AdminResponse::<()>::err(format!("persist failed: {err}"))),
        ))
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
fn handle_qa_validate(state: &AdminState, body: JsonValue) -> AdminHttpResult {
    let provider_id = body
        .get("provider_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request_err("missing provider_id"))?;
    let answers = body.get("answers").cloned().unwrap_or(json!({}));

    let pack_path = find_provider_pack(&state.bundle_root, provider_id)?;
    let form_spec = setup_to_formspec::pack_to_form_spec(&pack_path, provider_id)
        .ok_or_else(|| bad_request_err(format!("no QA spec found for {provider_id}")))?;

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
async fn handle_qa_session_get(state: &AdminState, session_id: &str) -> AdminHttpResult {
    let sessions = state.sessions.read().await;
    let session = sessions.get(session_id).ok_or_else(|| {
        Box::new(json_response(
            StatusCode::NOT_FOUND,
            json!(AdminResponse::<()>::err(format!(
                "session {session_id} not found"
            ))),
        ))
    })?;

    if session.is_expired() {
        return Err(Box::new(json_response(
            StatusCode::GONE,
            json!(AdminResponse::<()>::err("session expired")),
        )));
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
fn find_provider_pack(bundle_root: &Path, provider_id: &str) -> AdminHttpResult<PathBuf> {
    let result = discovery::discover(bundle_root).map_err(|err| {
        Box::new(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!(AdminResponse::<()>::err(format!("discovery failed: {err}"))),
        ))
    })?;
    result
        .providers
        .iter()
        .find(|p| p.provider_id == provider_id)
        .map(|p| p.pack_path.clone())
        .ok_or_else(|| {
            Box::new(json_response(
                StatusCode::NOT_FOUND,
                json!(AdminResponse::<()>::err(format!(
                    "provider {provider_id} not found in bundle"
                ))),
            ))
        })
}

/// Shorthand for a 400 Bad Request response.
fn bad_request(msg: impl Into<String>) -> AdminHttpResponse {
    json_response(
        StatusCode::BAD_REQUEST,
        json!(AdminResponse::<()>::err(msg.into())),
    )
}

fn bad_request_err(msg: impl Into<String>) -> AdminHttpError {
    Box::new(bad_request(msg))
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct AdminRegistryDocument {
    #[serde(default)]
    admins: Vec<AdminRegistryEntry>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AdminRegistryEntry {
    client_cn: String,
}

fn admin_registry_path(bundle_root: &Path) -> PathBuf {
    bundle_root
        .join(".greentic")
        .join("admin")
        .join("admins.json")
}

fn read_admin_registry(path: &Path) -> anyhow::Result<AdminRegistryDocument> {
    if !path.exists() {
        return Ok(AdminRegistryDocument::default());
    }
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw).unwrap_or_default())
}

fn write_admin_registry(path: &Path, doc: &AdminRegistryDocument) -> anyhow::Result<()> {
    runtime_state::write_json(path, doc)
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

async fn read_json_body<B>(req: Request<B>) -> AdminHttpResult<JsonValue>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let bytes = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|err| {
            Box::new(json_response(
                StatusCode::BAD_REQUEST,
                json!(AdminResponse::<()>::err(format!(
                    "failed to read body: {err}"
                ))),
            ))
        })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        Box::new(json_response(
            StatusCode::BAD_REQUEST,
            json!(AdminResponse::<()>::err(format!("invalid JSON: {err}"))),
        ))
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

fn current_bundle_status(state: &AdminState, bundle_exists: bool) -> BundleStatus {
    if runtime_state::read_stop_request(&state.runtime_paths)
        .ok()
        .flatten()
        .is_some()
    {
        BundleStatus::Stopping
    } else if bundle_exists {
        BundleStatus::Active
    } else {
        BundleStatus::Inactive
    }
}

fn ensure_bundle_matches(state: &AdminState, bundle_path: &Path) -> AdminHttpResult<()> {
    if bundle_path == state.bundle_root {
        Ok(())
    } else {
        Err(Box::new(json_response(
            StatusCode::BAD_REQUEST,
            json!(AdminResponse::<()>::err(format!(
                "bundle_path {} does not match managed bundle {}",
                bundle_path.display(),
                state.bundle_root.display()
            ))),
        )))
    }
}

fn internal_server_error(err: anyhow::Error) -> AdminHttpError {
    Box::new(json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!(AdminResponse::<()>::err(err.to_string())),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_state::{RuntimePaths, StopRequest};
    use http_body_util::{BodyExt, Full};
    use hyper::Request;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;
    use tokio::runtime::Runtime;

    fn test_admin_state(root: &Path) -> AdminState {
        AdminState {
            bundle_root: root.to_path_buf(),
            runtime_paths: RuntimePaths::new(root.join("state"), "demo", "default"),
            allowed_clients: Arc::new(RwLock::new(Vec::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[test]
    fn extract_cn_from_der_uses_last_cn_match() {
        let der = [
            0x55, 0x04, 0x03, 0x0C, 0x06, b'i', b's', b's', b'u', b'e', b'r', 0x55, 0x04, 0x03,
            0x0C, 0x07, b'c', b'l', b'i', b'e', b'n', b't', b'1',
        ];
        assert_eq!(extract_cn_from_der(&der).as_deref(), Some("client1"));
    }

    #[test]
    fn check_client_allowed_honors_exact_prefixed_and_wildcard_matches() {
        assert!(check_client_allowed(&[], Some("client1")));
        assert!(check_client_allowed(
            &["client1".to_string()],
            Some("client1")
        ));
        assert!(check_client_allowed(
            &["CN=client1".to_string()],
            Some("client1")
        ));
        assert!(check_client_allowed(&["*".to_string()], Some("client1")));
        assert!(!check_client_allowed(
            &["client1".to_string()],
            Some("client2")
        ));
        assert!(!check_client_allowed(&["client1".to_string()], None));
    }

    #[test]
    fn admin_registry_path_uses_greentic_admin_location() {
        let root = PathBuf::from("/tmp/bundle");
        assert_eq!(
            admin_registry_path(&root),
            root.join(".greentic").join("admin").join("admins.json")
        );
    }

    #[test]
    fn count_bundle_packs_counts_nested_gtpack_files_only() {
        let dir = tempdir().unwrap();
        let packs = dir.path().join("packs");
        fs::create_dir_all(packs.join("nested")).unwrap();
        fs::write(packs.join("root.gtpack"), "").unwrap();
        fs::write(packs.join("nested").join("child.gtpack"), "").unwrap();
        fs::write(packs.join("nested").join("ignore.txt"), "").unwrap();

        assert_eq!(count_bundle_packs(dir.path()).unwrap(), 2);
    }

    #[test]
    fn current_bundle_status_prefers_stop_request_over_bundle_presence() {
        let dir = tempdir().unwrap();
        let state = test_admin_state(dir.path());
        runtime_state::write_stop_request(
            &state.runtime_paths,
            &StopRequest {
                requested_by: "test".to_string(),
                reason: Some("stop".to_string()),
            },
        )
        .unwrap();

        assert_eq!(current_bundle_status(&state, true), BundleStatus::Stopping);
        runtime_state::clear_stop_request(&state.runtime_paths).unwrap();
        assert_eq!(current_bundle_status(&state, true), BundleStatus::Active);
        assert_eq!(current_bundle_status(&state, false), BundleStatus::Inactive);
    }

    #[test]
    fn ensure_bundle_matches_rejects_unmanaged_paths() {
        let dir = tempdir().unwrap();
        let state = test_admin_state(dir.path());
        assert!(ensure_bundle_matches(&state, dir.path()).is_ok());
        assert!(ensure_bundle_matches(&state, &dir.path().join("other")).is_err());
    }

    #[test]
    fn bad_request_helpers_and_internal_server_error_use_expected_statuses() {
        let response = bad_request("nope");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let err = bad_request_err("still nope");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);

        let internal = internal_server_error(anyhow::anyhow!("boom"));
        assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn read_and_write_admin_registry_roundtrip_and_tolerate_invalid_json() {
        let dir = tempdir().unwrap();
        let path = admin_registry_path(dir.path());
        let doc = AdminRegistryDocument {
            admins: vec![AdminRegistryEntry {
                client_cn: "client-1".to_string(),
            }],
        };

        write_admin_registry(&path, &doc).unwrap();
        let loaded = read_admin_registry(&path).unwrap();
        assert_eq!(loaded.admins.len(), 1);
        assert_eq!(loaded.admins[0].client_cn, "client-1");

        fs::write(&path, "{not-json").unwrap();
        let loaded = read_admin_registry(&path).unwrap();
        assert!(loaded.admins.is_empty());
    }

    #[test]
    fn build_tls_config_reports_missing_input_files() {
        let dir = tempdir().unwrap();
        let err = build_tls_config(
            &dir.path().join("server.crt"),
            &dir.path().join("server.key"),
            &dir.path().join("ca.crt"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("open server cert"));
    }

    fn empty_request(method: Method, path: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Full::from(Bytes::new()))
            .unwrap()
    }

    fn json_request(method: Method, path: &str, body: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Full::from(Bytes::from(body.to_owned())))
            .unwrap()
    }

    async fn response_json(response: AdminHttpResponse) -> JsonValue {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn write_setup_pack(root: &Path, provider_id: &str, setup_yaml: &str) -> PathBuf {
        let pack_path = root
            .join("providers")
            .join("messaging")
            .join(format!("{provider_id}.gtpack"));
        fs::create_dir_all(pack_path.parent().expect("parent")).unwrap();
        let file = fs::File::create(&pack_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "assets/setup.yaml",
            zip::write::FileOptions::<()>::default(),
        )
        .unwrap();
        zip.write_all(setup_yaml.as_bytes()).unwrap();
        zip.finish().unwrap();
        pack_path
    }

    #[test]
    fn read_json_body_accepts_valid_json() {
        let runtime = Runtime::new().unwrap();
        let value = runtime
            .block_on(read_json_body(json_request(
                Method::POST,
                "/admin/v1/test",
                r#"{"ok":true,"count":2}"#,
            )))
            .unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["count"], 2);
    }

    #[test]
    fn handle_status_and_list_report_bundle_counts() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("packs/nested")).unwrap();
        fs::create_dir_all(dir.path().join("tenants/acme")).unwrap();
        fs::create_dir_all(dir.path().join("tenants/umbrella")).unwrap();
        fs::write(dir.path().join("packs/root.gtpack"), b"pack").unwrap();
        fs::write(dir.path().join("packs/nested/child.gtpack"), b"pack").unwrap();
        let state = test_admin_state(dir.path());

        let status = handle_status(&state).unwrap();
        let status_body = runtime.block_on(response_json(status));
        assert_eq!(status_body["data"]["pack_count"], 2);
        assert_eq!(status_body["data"]["tenant_count"], 2);
        assert_eq!(status_body["data"]["status"], "active");

        let list = handle_list(&state).unwrap();
        let list_body = runtime.block_on(response_json(list));
        assert_eq!(list_body["data"]["bundles"][0]["pack_count"], 2);
        assert_eq!(list_body["data"]["bundles"][0]["tenant_count"], 2);
    }

    #[test]
    fn extract_cn_from_der_ignores_invalid_tags_and_truncated_values() {
        let der = [
            0x55, 0x04, 0x03, 0x05, 0x03, b'b', b'a', b'd', 0x55, 0x04, 0x03, 0x0C, 0x05, b's',
            b'o', b'l', b'i',
        ];
        assert_eq!(extract_cn_from_der(&der), None);
    }

    #[test]
    fn handle_start_reports_inactive_and_stopping_conflicts() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let missing_bundle = dir.path().join("managed-bundle");
        let state = test_admin_state(&missing_bundle);
        let start_body = json!({ "bundle_path": missing_bundle });

        let inactive = handle_start(&state, start_body.clone()).unwrap_err();
        assert_eq!(inactive.status(), StatusCode::CONFLICT);

        fs::create_dir_all(&state.bundle_root).unwrap();
        runtime_state::write_stop_request(
            &state.runtime_paths,
            &StopRequest {
                requested_by: "test".into(),
                reason: Some("already stopping".into()),
            },
        )
        .unwrap();

        let stopping = handle_start(&state, start_body).unwrap_err();
        assert_eq!(stopping.status(), StatusCode::CONFLICT);

        let body = runtime.block_on(response_json(*stopping));
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("already stopping")
        );
    }

    #[test]
    fn handle_start_reports_active_when_runtime_is_already_running() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path()).unwrap();
        let state = test_admin_state(dir.path());

        let response = handle_start(&state, json!({ "bundle_path": dir.path() })).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = runtime.block_on(response_json(response));
        assert_eq!(body["data"]["started"], false);
        assert_eq!(body["data"]["status"], "active");
    }

    #[test]
    fn handle_stop_persists_stop_request() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path()).unwrap();
        let state = test_admin_state(dir.path());

        let response = handle_stop(&state, json!({ "bundle_path": dir.path() })).unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let stop_request = runtime_state::read_stop_request(&state.runtime_paths)
            .unwrap()
            .expect("stop request");
        assert_eq!(stop_request.requested_by, "admin-api");
        assert_eq!(
            stop_request.reason.as_deref(),
            Some("remote stop requested")
        );

        let body = runtime.block_on(response_json(response));
        assert_eq!(body["data"]["status"], "stopping");
    }

    #[test]
    fn find_provider_pack_returns_not_found_for_unknown_provider() {
        let dir = tempdir().unwrap();
        let err = find_provider_pack(dir.path(), "missing-provider").unwrap_err();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn route_admin_request_handles_health_unknown_and_invalid_json() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let state = test_admin_state(dir.path());

        let health = runtime
            .block_on(route_admin_request(
                Method::GET,
                "/admin/v1/health",
                empty_request(Method::GET, "/admin/v1/health"),
                &state,
            ))
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let unknown = runtime
            .block_on(route_admin_request(
                Method::GET,
                "/admin/v1/nope",
                empty_request(Method::GET, "/admin/v1/nope"),
                &state,
            ))
            .unwrap_err();
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

        let invalid_json = runtime
            .block_on(route_admin_request(
                Method::POST,
                "/admin/v1/start",
                json_request(Method::POST, "/admin/v1/start", "{not-json"),
                &state,
            ))
            .unwrap_err();
        assert_eq!(invalid_json.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn handle_add_and_remove_admin_client_updates_registry_and_allowlist() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path()).unwrap();
        let state = test_admin_state(dir.path());

        let added = runtime
            .block_on(handle_add_admin_client(
                &state,
                json!({
                    "bundle_path": dir.path(),
                    "client_cn": "client-b"
                }),
            ))
            .unwrap();
        assert_eq!(added.status(), StatusCode::OK);

        runtime
            .block_on(handle_add_admin_client(
                &state,
                json!({
                    "bundle_path": dir.path(),
                    "client_cn": "client-a"
                }),
            ))
            .unwrap();

        runtime
            .block_on(handle_add_admin_client(
                &state,
                json!({
                    "bundle_path": dir.path(),
                    "client_cn": "client-a"
                }),
            ))
            .unwrap();

        let registry = read_admin_registry(&admin_registry_path(dir.path())).unwrap();
        let clients = registry
            .admins
            .into_iter()
            .map(|entry| entry.client_cn)
            .collect::<Vec<_>>();
        assert_eq!(
            clients,
            vec!["client-a".to_string(), "client-b".to_string()]
        );

        let allowed = runtime.block_on(async { state.allowed_clients.read().await.clone() });
        assert_eq!(
            allowed,
            vec!["client-a".to_string(), "client-b".to_string()]
        );

        let removed = runtime
            .block_on(handle_remove_admin_client(
                &state,
                json!({
                    "bundle_path": dir.path(),
                    "client_cn": "client-a"
                }),
            ))
            .unwrap();
        assert_eq!(removed.status(), StatusCode::OK);

        let allowed = runtime.block_on(async { state.allowed_clients.read().await.clone() });
        assert_eq!(allowed, vec!["client-b".to_string()]);
    }

    #[test]
    fn remove_admin_client_is_idempotent_for_missing_entries() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path()).unwrap();
        let state = test_admin_state(dir.path());

        let response = runtime
            .block_on(handle_remove_admin_client(
                &state,
                json!({
                    "bundle_path": dir.path(),
                    "client_cn": "missing-client"
                }),
            ))
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = runtime.block_on(response_json(response));
        assert_eq!(body["data"]["admins"], json!([]));
    }

    #[test]
    fn deploy_update_and_remove_reject_invalid_request_bodies() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let state = test_admin_state(dir.path());

        for result in [
            runtime.block_on(handle_deploy(&state, json!({}))),
            runtime.block_on(handle_update(&state, json!({}))),
            runtime.block_on(handle_remove(&state, json!({}))),
        ] {
            let err = result.unwrap_err();
            assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn deploy_update_remove_and_setup_support_dry_run_requests() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path()).unwrap();
        let state = test_admin_state(dir.path());
        let tenant = json!([{ "tenant": "demo", "team": "default", "allow_paths": [] }]);

        let deploy = runtime
            .block_on(handle_deploy(
                &state,
                json!({
                    "bundle_path": dir.path(),
                    "tenants": tenant,
                    "answers": {},
                    "dry_run": true
                }),
            ))
            .unwrap();
        let deploy_body = runtime.block_on(response_json(deploy));
        assert_eq!(deploy_body["data"]["dry_run"], true);
        assert!(deploy_body["data"]["steps"].is_array());

        let update = runtime
            .block_on(handle_update(
                &state,
                json!({
                    "bundle_path": dir.path(),
                    "tenants": tenant,
                    "answers": {},
                    "dry_run": true
                }),
            ))
            .unwrap();
        let update_body = runtime.block_on(response_json(update));
        assert_eq!(update_body["data"]["dry_run"], true);
        assert_eq!(update_body["data"]["mode"], "update");
        assert!(update_body["data"]["steps"].is_array());

        let remove = runtime
            .block_on(handle_remove(
                &state,
                json!({
                    "bundle_path": dir.path(),
                    "tenants": tenant,
                    "providers": ["missing-provider"],
                    "dry_run": true
                }),
            ))
            .unwrap();
        let remove_body = runtime.block_on(response_json(remove));
        assert_eq!(remove_body["data"]["dry_run"], true);
        assert!(remove_body["data"]["steps"].is_array());

        let setup = runtime
            .block_on(handle_setup(
                &state,
                json!({
                    "tenant": "demo",
                    "team": "default",
                    "answers": {},
                    "dry_run": true
                }),
            ))
            .unwrap();
        let setup_body = runtime.block_on(response_json(setup));
        assert_eq!(setup_body["data"]["dry_run"], true);
        assert!(setup_body["data"]["steps"].is_array());
    }

    #[test]
    fn add_admin_client_rejects_empty_client_names() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let state = test_admin_state(dir.path());

        let err = runtime
            .block_on(handle_add_admin_client(
                &state,
                json!({
                    "bundle_path": dir.path(),
                    "client_cn": "   "
                }),
            ))
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn qa_session_get_and_submit_handle_missing_expired_and_completed_sessions() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let state = test_admin_state(dir.path());

        let missing = runtime
            .block_on(handle_qa_session_get(&state, "missing"))
            .unwrap_err();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let mut expired = CardSetupSession::new(
            dir.path().to_path_buf(),
            "provider-a".to_string(),
            "demo".to_string(),
            Some("default".to_string()),
            Duration::from_secs(60),
        );
        expired.expires_at = 0;
        let expired_id = expired.session_id.clone();
        runtime.block_on(async {
            state
                .sessions
                .write()
                .await
                .insert(expired_id.clone(), expired);
        });

        let expired_resp = runtime
            .block_on(handle_qa_session_get(&state, &expired_id))
            .unwrap_err();
        assert_eq!(expired_resp.status(), StatusCode::GONE);

        let submit_expired = runtime
            .block_on(handle_qa_submit(
                &state,
                json!({
                    "session_id": expired_id,
                    "answers": {"foo": "bar"}
                }),
            ))
            .unwrap_err();
        assert_eq!(submit_expired.status(), StatusCode::GONE);

        let mut completed = CardSetupSession::new(
            dir.path().to_path_buf(),
            "provider-a".to_string(),
            "demo".to_string(),
            Some("default".to_string()),
            Duration::from_secs(60),
        );
        completed.completed = true;
        let completed_id = completed.session_id.clone();
        runtime.block_on(async {
            state
                .sessions
                .write()
                .await
                .insert(completed_id.clone(), completed);
        });

        let submit_completed = runtime
            .block_on(handle_qa_submit(
                &state,
                json!({
                    "session_id": completed_id,
                    "answers": {"foo": "bar"}
                }),
            ))
            .unwrap_err();
        assert_eq!(submit_completed.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn qa_card_and_validate_require_provider_id() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let state = test_admin_state(dir.path());

        let card = runtime
            .block_on(handle_qa_card(&state, json!({})))
            .unwrap_err();
        assert_eq!(card.status(), StatusCode::BAD_REQUEST);

        let validate = handle_qa_validate(&state, json!({})).unwrap_err();
        assert_eq!(validate.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn handle_admin_clients_and_session_get_return_current_state() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let state = test_admin_state(dir.path());

        runtime.block_on(async {
            *state.allowed_clients.write().await =
                vec!["client-a".to_string(), "client-b".to_string()];
        });

        let admins = runtime.block_on(handle_admin_clients(&state)).unwrap();
        assert_eq!(admins.status(), StatusCode::OK);
        let admins_body = runtime.block_on(response_json(admins));
        assert_eq!(
            admins_body["data"]["admins"]
                .as_array()
                .map(std::vec::Vec::len),
            Some(2)
        );

        let mut session = CardSetupSession::new(
            dir.path().to_path_buf(),
            "provider-a".to_string(),
            "demo".to_string(),
            Some("default".to_string()),
            Duration::from_secs(60),
        );
        session.merge_answers(&json!({"alpha": "beta"}));
        let session_id = session.session_id.clone();
        runtime.block_on(async {
            state
                .sessions
                .write()
                .await
                .insert(session_id.clone(), session);
        });

        let session_response = runtime
            .block_on(handle_qa_session_get(&state, &session_id))
            .unwrap();
        assert_eq!(session_response.status(), StatusCode::OK);
        let session_body = runtime.block_on(response_json(session_response));
        assert_eq!(session_body["data"]["provider_id"], "provider-a");
        assert_eq!(session_body["data"]["answer_count"], 1);
    }

    #[test]
    fn qa_validate_reports_validity_and_qa_card_creates_and_continues_sessions() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        write_setup_pack(
            dir.path(),
            "messaging-telegram",
            r#"
title: Telegram Setup
questions:
  - name: bot_token
    kind: string
    required: true
"#,
        );
        let state = test_admin_state(dir.path());

        let invalid = handle_qa_validate(
            &state,
            json!({
                "provider_id": "messaging-telegram",
                "answers": {}
            }),
        )
        .unwrap();
        let invalid_body = runtime.block_on(response_json(invalid));
        assert_eq!(invalid_body["data"]["valid"], false);
        assert!(
            invalid_body["data"]["error"]
                .as_str()
                .unwrap_or_default()
                .contains("bot_token")
        );

        let valid = handle_qa_validate(
            &state,
            json!({
                "provider_id": "messaging-telegram",
                "answers": {"bot_token": "secret123"}
            }),
        )
        .unwrap();
        let valid_body = runtime.block_on(response_json(valid));
        assert_eq!(valid_body["data"]["valid"], true);

        let created = runtime
            .block_on(handle_qa_card(
                &state,
                json!({
                    "provider_id": "messaging-telegram",
                    "tenant": "demo",
                    "team": "default",
                    "answers": {}
                }),
            ))
            .unwrap();
        let created_body = runtime.block_on(response_json(created));
        let session_id = created_body["data"]["session_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(created_body["data"]["complete"], false);
        assert_eq!(created_body["data"]["next_question_id"], "bot_token");

        let continued = runtime
            .block_on(handle_qa_card(
                &state,
                json!({
                    "provider_id": "messaging-telegram",
                    "session_id": session_id,
                    "answers": {"bot_token": "secret123"}
                }),
            ))
            .unwrap();
        let continued_body = runtime.block_on(response_json(continued));
        assert_eq!(continued_body["data"]["complete"], true);
        assert!(continued_body["data"]["next_question_id"].is_null());
    }

    #[test]
    fn qa_card_reports_not_found_and_completed_session_states() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        write_setup_pack(
            dir.path(),
            "provider-a",
            r#"
title: Provider A Setup
questions:
  - name: api_key
    kind: string
    required: true
"#,
        );
        let state = test_admin_state(dir.path());

        let missing_provider = runtime
            .block_on(handle_qa_card(
                &state,
                json!({
                    "provider_id": "missing-provider",
                    "answers": {}
                }),
            ))
            .unwrap_err();
        assert_eq!(missing_provider.status(), StatusCode::NOT_FOUND);

        let mut completed = CardSetupSession::new(
            dir.path().to_path_buf(),
            "provider-a".to_string(),
            "demo".to_string(),
            Some("default".to_string()),
            Duration::from_secs(60),
        );
        completed.merge_answers(&json!({"api_key": "secret"}));
        completed.completed = true;
        let session_id = completed.session_id.clone();
        runtime.block_on(async {
            state
                .sessions
                .write()
                .await
                .insert(session_id.clone(), completed);
        });

        let completed_response = runtime
            .block_on(handle_qa_card(
                &state,
                json!({
                    "provider_id": "provider-a",
                    "session_id": session_id,
                    "answers": {"foo": "bar"}
                }),
            ))
            .unwrap();
        let body = runtime.block_on(response_json(completed_response));
        assert_eq!(body["data"]["complete"], true);
        assert!(body["data"]["card"].is_object());
        assert!(body["data"]["next_question_id"].is_null());
    }

    #[test]
    fn qa_submit_returns_validation_errors_and_completes_sessions() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        write_setup_pack(
            dir.path(),
            "messaging-telegram",
            r#"
title: Telegram Setup
questions:
  - name: bot_token
    kind: string
    required: true
"#,
        );
        let state = test_admin_state(dir.path());

        let created = runtime
            .block_on(handle_qa_card(
                &state,
                json!({
                    "provider_id": "messaging-telegram",
                    "tenant": "demo",
                    "team": "default"
                }),
            ))
            .unwrap();
        let created_body = runtime.block_on(response_json(created));
        let session_id = created_body["data"]["session_id"]
            .as_str()
            .unwrap()
            .to_string();

        let invalid = runtime
            .block_on(handle_qa_submit(
                &state,
                json!({
                    "session_id": session_id,
                    "answers": {}
                }),
            ))
            .unwrap();
        let invalid_body = runtime.block_on(response_json(invalid));
        assert_eq!(invalid_body["data"]["complete"], false);
        assert!(
            invalid_body["data"]["validation_error"]
                .as_str()
                .unwrap_or_default()
                .contains("bot_token")
        );

        let completed = runtime
            .block_on(handle_qa_submit(
                &state,
                json!({
                    "session_id": created_body["data"]["session_id"],
                    "answers": {"bot_token": "secret123"}
                }),
            ))
            .unwrap();
        let completed_body = runtime.block_on(response_json(completed));
        assert_eq!(completed_body["data"]["complete"], true);
        assert!(completed_body["data"]["persisted_keys"].is_array());
    }

    #[test]
    fn remove_admin_client_rejects_empty_client_names() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let state = test_admin_state(dir.path());

        let err = runtime
            .block_on(handle_remove_admin_client(
                &state,
                json!({
                    "bundle_path": dir.path(),
                    "client_cn": "   "
                }),
            ))
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }
}
