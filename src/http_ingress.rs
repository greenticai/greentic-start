use std::{convert::Infallible, net::SocketAddr, path::Path, sync::Arc, thread};

use anyhow::{Context, Result};
use base64::Engine as _;
use greentic_types::ChannelMessageEnvelope;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue},
    server::conn::http1::Builder as Http1Builder,
    service::service_fn,
};
use hyper_util::rt::tokio::TokioIo;
use serde_json::json;
use tokio::{net::TcpListener, runtime::Runtime, sync::oneshot};

use crate::domains::Domain;
use crate::ingress_dispatch::dispatch_http_ingress;
use crate::ingress_types::{IngressHttpResponse, IngressRequestV1};
use crate::messaging_app as app;
use crate::messaging_dto::ProviderPayloadV1;
use crate::messaging_egress as egress;
use crate::onboard::api;
use crate::operator_log;
use crate::runner_host::{DemoRunnerHost, OperatorContext};
use crate::static_routes::{
    ActiveRouteTable, ReservedRouteSet, StaticRouteDescriptor, StaticRouteMatch,
    cache_control_value, content_type_for_path, discover_from_bundle, fallback_asset_path,
    normalize_relative_asset_path, read_pack_asset_bytes, resolve_asset_path,
};

#[derive(Clone)]
pub struct HttpIngressConfig {
    pub bind_addr: SocketAddr,
    pub domains: Vec<Domain>,
    pub runner_host: Arc<DemoRunnerHost>,
    pub enable_static_routes: bool,
}

pub struct HttpIngressServer {
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<thread::JoinHandle<Result<()>>>,
}

impl HttpIngressServer {
    pub fn start(config: HttpIngressConfig) -> Result<Self> {
        let debug_enabled = config.runner_host.debug_enabled();
        let domains = config.domains;
        let runner_host = config.runner_host;

        // Discover static routes if enabled
        let active_route_table = if config.enable_static_routes {
            let static_route_plan = discover_from_bundle(
                runner_host.bundle_root(),
                &ReservedRouteSet::operator_defaults(),
            )
            .context("discover static routes from active bundle")?;
            if !static_route_plan.blocking_failures.is_empty() {
                anyhow::bail!(
                    "static route validation failed: {}",
                    static_route_plan.blocking_failures.join("; ")
                );
            }
            for warning in &static_route_plan.warnings {
                operator_log::warn(module_path!(), format!("static route warning: {warning}"));
            }
            let table = ActiveRouteTable::from_plan(&static_route_plan);
            if !table.is_empty() {
                operator_log::info(
                    module_path!(),
                    format!(
                        "discovered {} static route(s): {}",
                        table.routes().len(),
                        table
                            .routes()
                            .iter()
                            .map(|r| r.public_path.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );
            }
            table
        } else {
            ActiveRouteTable::default()
        };

        let state = Arc::new(HttpIngressState {
            runner_host,
            domains,
            active_route_table,
        });
        let (tx, rx) = oneshot::channel();
        let addr = config.bind_addr;
        let handle = thread::Builder::new()
            .name("demo-ingress".to_string())
            .spawn(move || -> Result<()> {
                let runtime = Runtime::new().context("failed to create ingress runtime")?;
                runtime.block_on(async move {
                    let listener = TcpListener::bind(addr)
                        .await
                        .context("failed to bind ingress listener")?;
                    operator_log::info(
                        module_path!(),
                        format!("demo ingress listening on http://{}", addr),
                    );
                    if debug_enabled {
                        let domain_list = state
                            .domains
                            .iter()
                            .map(|domain| domain_name(*domain))
                            .collect::<Vec<_>>()
                            .join(",");
                        operator_log::debug(
                            module_path!(),
                            format!(
                                "[demo dev] ingress server bound={} domains={}",
                                addr, domain_list
                            ),
                        );
                    }
                    let mut shutdown = rx;
                    loop {
                        tokio::select! {
                            _ = &mut shutdown => break,
                            accept = listener.accept() => match accept {
                                Ok((stream, _peer)) => {
                                    let connection_state = state.clone();
                                    tokio::spawn(async move {
                                        let service = service_fn(move |req| {
                                            handle_request(req, connection_state.clone())
                                        });
                                        let http = Http1Builder::new();
                                        let stream = TokioIo::new(stream);
                                        if let Err(err) = http
                                            .serve_connection(stream, service)
                                            .await
                                        {
                                            operator_log::error(
                                                module_path!(),
                                                format!(
                                                    "demo ingress connection error: {err}"
                                                ),
                                            );
                                        }
                                    });
                                }
                                Err(err) => {
                                    operator_log::error(
                                        module_path!(),
                                        format!("demo ingress accept error: {err}"),
                                    );
                                }
                            },
                        }
                    }
                    Ok(())
                })
            })?;
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
                .map_err(|err| anyhow::anyhow!("ingress server panicked: {err:?}"))?;
            joined?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct HttpIngressState {
    runner_host: Arc<DemoRunnerHost>,
    domains: Vec<Domain>,
    active_route_table: ActiveRouteTable,
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<HttpIngressState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = match handle_request_inner(req, state).await {
        Ok(response) => with_cors(response),
        Err(response) => with_cors(response),
    };
    Ok(response)
}

async fn handle_request_inner(
    req: Request<Incoming>,
    state: Arc<HttpIngressState>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    if req.method() == Method::OPTIONS {
        return Ok(cors_preflight_response());
    }
    if req.method() != Method::POST && req.method() != Method::GET {
        return Err(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "only GET/POST/OPTIONS allowed",
        ));
    }

    let path = req.uri().path().to_string();

    if path.starts_with("/api/onboard") {
        return api::handle_onboard_request(req, &path, &state.runner_host)
            .await
            .map_err(|err| *err);
    }

    // Legacy Direct Line routes (root level)
    if path == "/token" || path.starts_with("/v3/directline") || path.starts_with("/directline") {
        return handle_directline_request(req, &path, None, state).await;
    }

    // WebChat Direct Line routes: /v1/messaging/webchat/{tenant}/token or /v1/messaging/webchat/{tenant}/v3/directline/*
    if let Some((tenant, dl_path)) = parse_webchat_directline_route(&path) {
        return handle_directline_request(req, &dl_path, Some(tenant), state).await;
    }

    // Static route handling - serve assets from .gtpack files
    if let Some(route_match) = state.active_route_table.match_request(&path) {
        return Ok(serve_static_route(&route_match));
    }

    let method = req.method().clone();
    let parsed = match parse_route_segments(req.uri().path()) {
        Some(value) => value,
        None => {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "expected /v1/{domain}/ingress/{provider}/{tenant}/{team?}/{handler?}",
            ));
        }
    };
    let domain = parsed.domain;
    if !state.domains.contains(&domain) {
        return Err(error_response(StatusCode::NOT_FOUND, "domain disabled"));
    }
    if !state
        .runner_host
        .supports_op(domain, &parsed.provider, "ingest_http")
    {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "no ingest_http handler available",
        ));
    }

    let correlation_id = req
        .headers()
        .get("x-correlation-id")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let headers = collect_headers(req.headers());
    let queries = collect_queries(req.uri().query());
    let payload_bytes = req
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();

    let context = OperatorContext {
        tenant: parsed.tenant.clone(),
        team: Some(parsed.team.clone()),
        correlation_id: correlation_id.clone(),
    };
    let debug_enabled = state.runner_host.debug_enabled();
    if debug_enabled {
        operator_log::debug(
            module_path!(),
            format!(
                "[demo dev] ingress request method={} path={} domain={} provider={} tenant={} team={} corr_id={:?} payload_len={}",
                method,
                path,
                domain_name(domain),
                parsed.provider,
                context.tenant,
                context.team.as_deref().unwrap_or("default"),
                context.correlation_id.as_deref().unwrap_or("none"),
                payload_bytes.len(),
            ),
        );
    }

    let ingress_request = IngressRequestV1 {
        v: 1,
        domain: domain_name(domain).to_string(),
        provider: parsed.provider.clone(),
        handler: parsed.handler.clone(),
        tenant: parsed.tenant.clone(),
        team: Some(parsed.team.clone()),
        method: method.as_str().to_string(),
        path: path.clone(),
        query: queries,
        headers,
        body: payload_bytes.to_vec(),
        correlation_id: correlation_id.clone(),
        remote_addr: None,
    };

    let result = dispatch_http_ingress(
        state.runner_host.as_ref(),
        domain,
        &ingress_request,
        &context,
    )
    .map_err(|err| error_response(StatusCode::BAD_GATEWAY, err.to_string()))?;
    if !result.events.is_empty() {
        operator_log::info(
            module_path!(),
            format!(
                "[demo ingress] parsed {} event(s) from provider={} tenant={} team={}",
                result.events.len(),
                parsed.provider,
                parsed.tenant,
                parsed.team
            ),
        );
    }
    if domain == Domain::Events && !result.events.is_empty() {
        crate::event_router::route_events_to_default_flow(
            state.runner_host.bundle_root(),
            &crate::runner_host::OperatorContext {
                tenant: context.tenant.clone(),
                team: context.team.clone(),
                correlation_id: context.correlation_id.clone(),
            },
            &result
                .events
                .iter()
                .filter_map(|event| serde_json::to_value(event).ok())
                .filter_map(|value| serde_json::from_value(value).ok())
                .collect::<Vec<_>>(),
        )
        .map_err(|err| error_response(StatusCode::BAD_GATEWAY, err.to_string()))?;
    }
    if domain == Domain::Messaging && !result.messaging_envelopes.is_empty() {
        let envelopes: Vec<_> = result
            .messaging_envelopes
            .iter()
            .filter(|env| {
                let dominated_by_bot = env
                    .from
                    .as_ref()
                    .map(|f| f.id.ends_with(".bot") || f.id.ends_with("@webex.bot"))
                    .unwrap_or(false);
                if dominated_by_bot {
                    operator_log::debug(
                        module_path!(),
                        format!(
                            "[demo ingress] skipping bot self-message from={:?} id={}",
                            env.from, env.id
                        ),
                    );
                }
                !dominated_by_bot
            })
            .cloned()
            .collect();
        if envelopes.is_empty() {
            return build_http_response(&result.response)
                .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err));
        }
        let provider = parsed.provider.clone();
        let bundle = state.runner_host.bundle_root().to_path_buf();
        let ctx = context.clone();
        let runner_host = state.runner_host.clone();
        std::thread::spawn(move || {
            if let Err(err) =
                route_messaging_envelopes(&bundle, &runner_host, &provider, &ctx, envelopes)
            {
                operator_log::error(
                    module_path!(),
                    format!(
                        "[demo ingress] messaging pipeline failed provider={} err={err}",
                        provider
                    ),
                );
            }
        });
    }

    if debug_enabled {
        operator_log::debug(
            module_path!(),
            format!(
                "[demo dev] ingress outcome domain={} provider={} tenant={} team={} corr_id={:?} events={}",
                domain_name(domain),
                parsed.provider,
                context.tenant,
                context.team.as_deref().unwrap_or("default"),
                correlation_id.as_deref().unwrap_or("none"),
                result.events.len(),
            ),
        );
    }

    build_http_response(&result.response)
        .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))
}

fn route_messaging_envelopes(
    bundle: &Path,
    runner_host: &DemoRunnerHost,
    provider: &str,
    ctx: &OperatorContext,
    envelopes: Vec<ChannelMessageEnvelope>,
) -> anyhow::Result<()> {
    let team = ctx.team.as_deref();
    let app_pack_path = app::resolve_app_pack_path(bundle, &ctx.tenant, team, None)
        .context("resolve app pack for messaging pipeline")?;
    let pack_info = app::load_app_pack_info(&app_pack_path).context("load app pack manifest")?;
    let flow = app::select_app_flow(&pack_info).context("select app default flow")?;

    operator_log::info(
        module_path!(),
        format!(
            "[demo messaging] routing {} envelope(s) through app flow={} pack={}",
            envelopes.len(),
            flow.id,
            pack_info.pack_id
        ),
    );

    for envelope in &envelopes {
        let outputs = if let Some(route_to_card) = envelope.metadata.get("routeToCardId") {
            match read_card_from_pack(&app_pack_path, route_to_card) {
                Some(card_json) => {
                    operator_log::info(
                        module_path!(),
                        format!(
                            "[demo messaging] card routing: {} -> card asset found",
                            route_to_card
                        ),
                    );
                    let mut reply = envelope.clone();
                    reply.metadata.insert(
                        "adaptive_card".to_string(),
                        serde_json::to_string(&card_json).unwrap_or_default(),
                    );
                    let summary = card_json
                        .get("body")
                        .and_then(|b| b.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|item| item.get("text"))
                        .and_then(|t| t.as_str())
                        .unwrap_or(route_to_card)
                        .to_string();
                    reply.text = Some(summary);
                    vec![reply]
                }
                None => {
                    operator_log::warn(
                        module_path!(),
                        format!(
                            "[demo messaging] card routing: {} -> card asset NOT found, using app flow",
                            route_to_card
                        ),
                    );
                    run_app_flow_safe(bundle, ctx, &app_pack_path, &pack_info, flow, envelope)
                }
            }
        } else {
            run_app_flow_safe(bundle, ctx, &app_pack_path, &pack_info, flow, envelope)
        };

        for out_envelope in outputs {
            let message_value = serde_json::to_value(&out_envelope)?;

            let plan = match egress::render_plan(runner_host, ctx, provider, message_value.clone())
            {
                Ok(plan) => plan,
                Err(err) => {
                    operator_log::warn(
                        module_path!(),
                        format!("[demo messaging] render_plan failed: {err}; using empty plan"),
                    );
                    json!({})
                }
            };

            let payload = match egress::encode_payload(
                runner_host,
                ctx,
                provider,
                message_value.clone(),
                plan,
            ) {
                Ok(payload) => payload,
                Err(err) => {
                    operator_log::warn(
                        module_path!(),
                        format!("[demo messaging] encode failed: {err}; using fallback payload"),
                    );
                    let body_bytes = serde_json::to_vec(&message_value)?;
                    ProviderPayloadV1 {
                        content_type: "application/json".to_string(),
                        body_b64: base64::engine::general_purpose::STANDARD.encode(&body_bytes),
                        metadata_json: Some(serde_json::to_string(&message_value)?),
                        metadata: None,
                    }
                }
            };

            let provider_type = runner_host.canonical_provider_type(Domain::Messaging, provider);
            let send_input =
                egress::build_send_payload(payload, &provider_type, &ctx.tenant, ctx.team.clone());
            let send_bytes = serde_json::to_vec(&send_input)?;
            let outcome = runner_host.invoke_provider_op(
                Domain::Messaging,
                provider,
                "send_payload",
                &send_bytes,
                ctx,
            )?;

            let provider_ok = outcome
                .output
                .as_ref()
                .and_then(|v| v.get("ok"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if outcome.success && provider_ok {
                operator_log::info(
                    module_path!(),
                    format!(
                        "[demo messaging] send succeeded provider={} envelope_id={}",
                        provider, out_envelope.id
                    ),
                );
            } else {
                let provider_msg = outcome
                    .output
                    .as_ref()
                    .and_then(|v| v.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let err_msg = outcome
                    .error
                    .clone()
                    .unwrap_or_else(|| provider_msg.to_string());
                operator_log::error(
                    module_path!(),
                    format!(
                        "[demo messaging] send failed provider={} provider_ok={} err={}",
                        provider, provider_ok, err_msg
                    ),
                );
            }
        }
    }
    Ok(())
}

fn read_card_from_pack(pack_path: &Path, card_key: &str) -> Option<serde_json::Value> {
    let file = std::fs::File::open(pack_path).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;
    let asset_path = format!("assets/cards/{card_key}.json");
    let mut entry = archive.by_name(&asset_path).ok()?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

fn run_app_flow_safe(
    bundle: &Path,
    ctx: &OperatorContext,
    app_pack_path: &Path,
    pack_info: &app::AppPackInfo,
    flow: &app::AppFlowInfo,
    envelope: &ChannelMessageEnvelope,
) -> Vec<ChannelMessageEnvelope> {
    match app::run_app_flow(
        bundle,
        ctx,
        app_pack_path,
        &pack_info.pack_id,
        &flow.id,
        envelope,
    ) {
        Ok(outputs) => outputs,
        Err(err) => {
            operator_log::error(
                module_path!(),
                format!("[demo messaging] app flow failed: {err}"),
            );
            vec![envelope.clone()]
        }
    }
}

/// Parse WebChat Direct Line routes: /v1/messaging/webchat/{tenant}/token or /v1/messaging/webchat/{tenant}/v3/directline/*
/// Returns (tenant, directline_path) if matched
fn parse_webchat_directline_route(path: &str) -> Option<(String, String)> {
    // Pattern: /v1/messaging/webchat/{tenant}/token
    // Pattern: /v1/messaging/webchat/{tenant}/v3/directline/{*path}
    let prefix = "/v1/messaging/webchat/";
    if !path.starts_with(prefix) {
        return None;
    }
    let rest = &path[prefix.len()..];
    let mut parts = rest.splitn(2, '/');
    let tenant = parts.next()?;
    if tenant.is_empty() {
        return None;
    }
    let remainder = parts.next().unwrap_or("");

    // Check if it's a Direct Line route
    if remainder == "token" {
        Some((tenant.to_string(), "/token".to_string()))
    } else if remainder.starts_with("v3/directline") {
        Some((tenant.to_string(), format!("/{}", remainder)))
    } else {
        None
    }
}

async fn handle_directline_request(
    req: Request<Incoming>,
    path: &str,
    explicit_tenant: Option<String>,
    state: Arc<HttpIngressState>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let method = req.method().clone();
    let queries = collect_queries(req.uri().query());

    // Use webchat-gui provider for tenant-scoped routes, webchat for legacy
    let is_tenant_scoped = explicit_tenant.is_some();
    let provider = if is_tenant_scoped {
        "messaging-webchat-gui".to_string()
    } else {
        "messaging-webchat".to_string()
    };

    // Use explicit tenant from URL path, or fall back to query param
    let tenant = explicit_tenant.unwrap_or_else(|| {
        queries
            .iter()
            .find(|(k, _)| k == "tenant")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "default".to_string())
    });
    if !state.domains.contains(&Domain::Messaging) {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "messaging domain disabled",
        ));
    }

    let dl_path = if path == "/token" {
        "/v3/directline/tokens/generate".to_string()
    } else {
        path.to_string()
    };

    let headers = collect_headers(req.headers());
    let payload_bytes = req
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();

    let context = OperatorContext {
        tenant: tenant.clone(),
        team: Some("default".to_string()),
        correlation_id: None,
    };

    let ingress_request = IngressRequestV1 {
        v: 1,
        domain: "messaging".to_string(),
        provider: provider.clone(),
        handler: None,
        tenant: tenant.clone(),
        team: Some("default".to_string()),
        method: method.as_str().to_string(),
        path: dl_path,
        query: queries,
        headers,
        body: payload_bytes.to_vec(),
        correlation_id: None,
        remote_addr: None,
    };

    let result = dispatch_http_ingress(
        state.runner_host.as_ref(),
        Domain::Messaging,
        &ingress_request,
        &context,
    )
    .map_err(|err| error_response(StatusCode::BAD_GATEWAY, err.to_string()))?;

    if !result.messaging_envelopes.is_empty() {
        let envelopes = result.messaging_envelopes.clone();
        let bundle = state.runner_host.bundle_root().to_path_buf();
        let ctx = context.clone();
        let runner_host = state.runner_host.clone();
        std::thread::spawn(move || {
            if let Err(err) =
                route_messaging_envelopes(&bundle, &runner_host, &provider, &ctx, envelopes)
            {
                operator_log::error(
                    module_path!(),
                    format!("[demo ingress] webchat messaging pipeline failed err={err}"),
                );
            }
        });
    }

    build_http_response(&result.response)
        .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))
}

fn cors_preflight_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Requested-With, x-ms-bot-agent",
        )
        .header("Access-Control-Max-Age", "86400")
        .body(Full::from(Bytes::new()))
        .unwrap()
}

fn with_cors(mut response: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
    let headers = response.headers_mut();
    headers.insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
    headers.insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        HeaderValue::from_static("Content-Type, Authorization, X-Requested-With, x-ms-bot-agent"),
    );
    response
}

fn build_http_response(response: &IngressHttpResponse) -> Result<Response<Full<Bytes>>, String> {
    let mut builder = Response::builder().status(response.status);
    let mut has_content_type = false;
    for (name, value) in &response.headers {
        if let (Ok(header_name), Ok(header_value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            if header_name == CONTENT_TYPE {
                has_content_type = true;
            }
            builder = builder.header(header_name, header_value);
        }
    }
    if !has_content_type {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    let body = response.body.clone().unwrap_or_default();
    builder
        .body(Full::from(Bytes::from(body)))
        .map_err(|err| err.to_string())
}

fn collect_headers(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect()
}

fn collect_queries(query: Option<&str>) -> Vec<(String, String)> {
    query
        .map(|value| {
            value
                .split('&')
                .filter_map(|pair| {
                    let mut pieces = pair.splitn(2, '=');
                    let key = pieces.next()?.trim();
                    if key.is_empty() {
                        return None;
                    }
                    let value = pieces.next().unwrap_or("").trim();
                    Some((key.to_string(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_domain(value: &str) -> Option<Domain> {
    match value.to_lowercase().as_str() {
        "messaging" => Some(Domain::Messaging),
        "events" => Some(Domain::Events),
        "secrets" => Some(Domain::Secrets),
        "oauth" => Some(Domain::OAuth),
        _ => None,
    }
}

fn domain_name(domain: Domain) -> &'static str {
    match domain {
        Domain::Messaging => "messaging",
        Domain::Events => "events",
        Domain::Secrets => "secrets",
        Domain::OAuth => "oauth",
    }
}

#[derive(Clone, Debug)]
struct ParsedIngressRoute {
    domain: Domain,
    provider: String,
    tenant: String,
    team: String,
    handler: Option<String>,
}

fn parse_route_segments(path: &str) -> Option<ParsedIngressRoute> {
    let segments = path
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return None;
    }
    if segments[0].eq_ignore_ascii_case("v1") {
        return parse_v1_route(&segments);
    }
    parse_legacy_route(&segments)
}

fn parse_v1_route(segments: &[&str]) -> Option<ParsedIngressRoute> {
    if segments.len() < 5 || !segments[2].eq_ignore_ascii_case("ingress") {
        return None;
    }
    let domain = parse_domain(segments[1])?;
    let provider = segments[3].to_string();
    let tenant = segments[4].to_string();
    let team = segments.get(5).copied().unwrap_or("default").to_string();
    let handler = segments.get(6).map(|value| (*value).to_string());
    Some(ParsedIngressRoute {
        domain,
        provider,
        tenant,
        team,
        handler,
    })
}

fn parse_legacy_route(segments: &[&str]) -> Option<ParsedIngressRoute> {
    if segments.len() < 4 || !segments[1].eq_ignore_ascii_case("ingress") {
        return None;
    }
    let domain = parse_domain(segments[0])?;
    let provider = segments[2].to_string();
    let tenant = segments[3].to_string();
    let team = segments.get(4).copied().unwrap_or("default").to_string();
    let handler = segments.get(5).map(|value| (*value).to_string());
    Some(ParsedIngressRoute {
        domain,
        provider,
        tenant,
        team,
        handler,
    })
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response<Full<Bytes>> {
    let body = json!({
        "success": false,
        "message": message.into()
    });
    json_response(status, body)
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::from(Bytes::from(body)))
        .unwrap_or_else(|err| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::from(Bytes::from(format!(
                    "failed to build response: {err}"
                ))))
                .unwrap()
        })
}

// ============================================================================
// Static route serving
// ============================================================================

fn serve_static_route(route_match: &StaticRouteMatch<'_>) -> Response<Full<Bytes>> {
    if let Some(asset_path) = resolve_asset_path(route_match) {
        match serve_static_asset(route_match.descriptor, &asset_path) {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(err) => {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
            }
        }
    }
    if let Some(asset_path) = fallback_asset_path(route_match) {
        match serve_static_asset(route_match.descriptor, &asset_path) {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(err) => {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
            }
        }
    }
    error_response(StatusCode::NOT_FOUND, "file not found")
}

fn serve_static_asset(
    descriptor: &StaticRouteDescriptor,
    asset_path: &str,
) -> anyhow::Result<Option<Response<Full<Bytes>>>> {
    let Some(asset_path) = normalize_relative_asset_path(asset_path) else {
        return Ok(None);
    };
    let full_path = format!("{}/{}", descriptor.source_root, asset_path);
    let body = match read_pack_asset_bytes(&descriptor.pack_path, &full_path)? {
        Some(bytes) => bytes,
        None => return Ok(None),
    };
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type_for_path(&full_path))
        .header(CONTENT_LENGTH, body.len().to_string());
    if let Some(cache_control) = cache_control_value(&descriptor.cache_strategy) {
        builder = builder.header(CACHE_CONTROL, cache_control);
    }
    let response = builder
        .body(Full::from(Bytes::from(body)))
        .map_err(|err| anyhow::anyhow!("build static response: {err}"))?;
    Ok(Some(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v1_route_with_optional_segments() {
        let parsed = parse_route_segments("/v1/events/ingress/provider-a/tenant-x/team-y/h1")
            .expect("route should parse");
        assert_eq!(parsed.domain, Domain::Events);
        assert_eq!(parsed.provider, "provider-a");
        assert_eq!(parsed.tenant, "tenant-x");
        assert_eq!(parsed.team, "team-y");
        assert_eq!(parsed.handler.as_deref(), Some("h1"));
    }

    #[test]
    fn parses_legacy_route_for_compatibility() {
        let parsed = parse_route_segments("/messaging/ingress/provider-a/tenant-x")
            .expect("route should parse");
        assert_eq!(parsed.domain, Domain::Messaging);
        assert_eq!(parsed.team, "default");
    }
}
