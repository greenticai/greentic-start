mod helpers;
mod legacy_directline;
mod legacy_directline_handler;
mod messaging;
mod static_handler;

use std::{convert::Infallible, net::SocketAddr, sync::Arc, thread};

use anyhow::{Context, Result};
use base64::Engine as _;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Bytes},
    server::conn::http1::Builder as Http1Builder,
    service::service_fn,
};
use hyper_util::rt::tokio::TokioIo;
use tokio::{net::TcpListener, runtime::Runtime, sync::oneshot};

use crate::domains::Domain;
use crate::ingress_dispatch::dispatch_http_ingress;
use crate::ingress_types::{IngressHttpResponse, IngressRequestV1};
use crate::messaging_dto::HttpInV1;
use crate::operator_log;
use crate::runner_host::{DemoRunnerHost, OperatorContext};
use crate::static_routes::{
    ActiveRouteTable, ReservedRouteSet, RouteScopeSegment, StaticRouteMatch, discover_from_bundle,
};

use helpers::{
    build_http_response, collect_headers, collect_queries, cors_preflight_response, domain_name,
    error_response, handle_builtin_health_request, handle_oauth_token_exchange, parse_domain,
    parse_route_segments, with_cors,
};
use legacy_directline_handler::handle_legacy_directline_request;
use messaging::route_messaging_envelopes;
use static_handler::serve_static_route;

const LEGACY_DIRECTLINE_COMPAT_ENV: &str = "GREENTIC_START_ENABLE_LEGACY_DIRECTLINE";

#[derive(Clone)]
pub struct HttpIngressConfig {
    pub bind_addr: SocketAddr,
    pub domains: Vec<Domain>,
    pub runner_host: Arc<DemoRunnerHost>,
    pub enable_static_routes: bool,
    pub tenant: String,
}

pub struct HttpIngressServer {
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<thread::JoinHandle<Result<()>>>,
    /// Public URLs discovered from static routes during startup.
    pub static_route_urls: Vec<String>,
}

impl HttpIngressServer {
    pub fn start(config: HttpIngressConfig) -> Result<Self> {
        let debug_enabled = config.runner_host.debug_enabled();
        let domains = config.domains;
        let runner_host = config.runner_host;

        // Discover static routes if enabled
        let mut static_route_urls = Vec::new();
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
                for route in table.routes() {
                    let url_path = route.public_path.replace("{tenant}", &config.tenant);
                    let route_url = format!(
                        "http://{}/{}/",
                        config.bind_addr,
                        url_path.trim_start_matches('/')
                    );
                    operator_log::info(module_path!(), format!("Static route: {route_url}"));
                    static_route_urls.push(route_url);
                }
            }
            table
        } else {
            ActiveRouteTable::default()
        };

        let state = Arc::new(HttpIngressState {
            runner_host,
            domains,
            active_route_table,
            legacy_directline: legacy_directline::LegacyDirectLineCompat::new(),
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
            static_route_urls,
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
    legacy_directline: legacy_directline::LegacyDirectLineCompat,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StaticRouteIngressTarget {
    domain: Domain,
    provider: String,
    tenant: String,
    team: Option<String>,
    handler: Option<String>,
}

type StaticRouteDirectlineTarget = (
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);

struct ProviderDirectlineHttpRequest<'a> {
    method: &'a Method,
    path: &'a str,
    route: Option<&'a str>,
    tenant: &'a str,
    team: &'a str,
    provider: &'a str,
    queries: &'a [(String, String)],
}

impl HttpIngressState {
    fn legacy_directline_compat(&self) -> &legacy_directline::LegacyDirectLineCompat {
        &self.legacy_directline
    }
}

async fn handle_request<B>(
    req: Request<B>,
    state: Arc<HttpIngressState>,
) -> Result<Response<Full<Bytes>>, Infallible>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let response = match handle_request_inner(req, state).await {
        Ok(response) => with_cors(response),
        Err(response) => with_cors(response),
    };
    Ok(response)
}

async fn handle_request_inner<B>(
    req: Request<B>,
    state: Arc<HttpIngressState>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
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

    if let Some(response) = handle_builtin_health_request(req.method(), &path) {
        return Ok(response);
    }

    if path.starts_with("/api/onboard") {
        return crate::onboard::api::handle_onboard_request(req, &path, &state.runner_host)
            .await
            .map_err(|err| *err);
    }

    if is_oauth_token_exchange_path(&path) && req.method() == Method::POST {
        return handle_oauth_token_exchange(req).await;
    }

    // WebChat Direct Line routes: /v1/messaging/webchat/{tenant}/token or /v1/messaging/webchat/{tenant}/v3/directline/*
    if let Some((tenant, dl_path)) = parse_webchat_directline_route(&path) {
        let provider = state
            .active_route_table
            .match_request(&path)
            .map(|route_match| route_match.descriptor.pack_id.clone())
            .or_else(|| {
                state
                    .active_route_table
                    .routes()
                    .iter()
                    .find(|route| route.pack_id == "messaging-webchat-gui")
                    .map(|route| route.pack_id.clone())
            })
            .or_else(|| {
                state
                    .active_route_table
                    .routes()
                    .iter()
                    .find(|route| route.pack_id == "messaging-webchat")
                    .map(|route| route.pack_id.clone())
            })
            .or_else(|| {
                // /v1/messaging/webchat/* endpoints are API routes and do not necessarily share
                // the same URL prefix as static web assets (/v1/web/webchat/*). When there is no
                // direct static-route match, prefer the GUI provider if present.
                if state
                    .runner_host
                    .get_provider_pack_path(Domain::Messaging, "messaging-webchat-gui")
                    .is_some()
                {
                    Some("messaging-webchat-gui".to_string())
                } else if state
                    .runner_host
                    .get_provider_pack_path(Domain::Messaging, "messaging-webchat")
                    .is_some()
                {
                    Some("messaging-webchat".to_string())
                } else {
                    None
                }
            });
        return handle_directline_request(req, &dl_path, Some(tenant), provider, state).await;
    }

    // Static route handling - serve assets from .gtpack files
    if let Some(route_match) = state.active_route_table.match_request(&path) {
        let ingress_target =
            infer_static_route_ingress_target(&path, &route_match).filter(|target| {
                state
                    .runner_host
                    .supports_op(target.domain, &target.provider, "ingest_http")
            });
        let directline_target =
            resolve_static_route_directline_request_from_match(&path, &route_match);
        let static_response =
            serve_static_route(&route_match, state.runner_host.bundle_root(), &path);
        if static_response.status() != StatusCode::NOT_FOUND {
            return Ok(static_response);
        }
        if let Some(target) = ingress_target {
            if let Some(response) =
                dispatch_static_route_ingress(req, &path, &state, target).await?
            {
                return Ok(response);
            }
            return Ok(static_response);
        } else if let Some((tenant, team, route, dl_path, provider)) = directline_target {
            if let Some(provider) = provider.as_deref()
                && state
                    .runner_host
                    .supports_op(Domain::Messaging, provider, "directline_http")
            {
                let method = req.method().clone();
                let queries = collect_queries(req.uri().query());
                return dispatch_provider_directline_http(
                    req,
                    ProviderDirectlineHttpRequest {
                        method: &method,
                        path: &dl_path,
                        route: route.as_deref(),
                        tenant: &tenant,
                        team: team.as_deref().unwrap_or("default"),
                        provider,
                        queries: &queries,
                    },
                    &state,
                )
                .await;
            }
            return handle_legacy_directline_request(
                req,
                &dl_path,
                Some(tenant),
                team,
                provider,
                state,
            )
            .await;
        }
        return Ok(static_response);
    }

    // Legacy root-level Direct Line routes remain only as an explicit
    // compatibility path. Pack-owned static routes should take precedence.
    if is_legacy_directline_path(&path) {
        if !legacy_directline_compat_enabled() {
            return Err(error_response(
                StatusCode::NOT_FOUND,
                "legacy directline compatibility is disabled; declare the route in a pack",
            ));
        }
        operator_log::warn(
            module_path!(),
            format!(
                "using legacy directline compatibility path for {}; prefer pack-owned routes or directline_http providers",
                path
            ),
        );
        let queries = collect_queries(req.uri().query());
        let provider = queries
            .iter()
            .find(|(name, _)| name == "provider")
            .map(|(_, value)| value.as_str());
        if provider.is_none() {
            return Err(error_response(
                StatusCode::NOT_FOUND,
                "directline routes must be declared by a pack or supply provider query",
            ));
        }
        let tenant = queries
            .iter()
            .find(|(name, _)| name == "tenant")
            .map(|(_, value)| value.as_str())
            .unwrap_or("default");
        let team = queries
            .iter()
            .find(|(name, _)| name == "team")
            .map(|(_, value)| value.as_str())
            .unwrap_or("default");
        if let Some(provider) = provider
            && state
                .runner_host
                .supports_op(Domain::Messaging, provider, "directline_http")
        {
            let method = req.method().clone();
            return dispatch_provider_directline_http(
                req,
                ProviderDirectlineHttpRequest {
                    method: &method,
                    path: &path,
                    route: None,
                    tenant,
                    team,
                    provider,
                    queries: &queries,
                },
                &state,
            )
            .await;
        }
        return handle_legacy_directline_request(req, &path, None, None, None, state).await;
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
        let bundle = state.runner_host.bundle_root().to_path_buf();
        let ctx = crate::runner_host::OperatorContext {
            tenant: context.tenant.clone(),
            team: context.team.clone(),
            correlation_id: context.correlation_id.clone(),
        };
        let events: Vec<crate::ingress_types::EventEnvelopeV1> = result
            .events
            .iter()
            .filter_map(|event| serde_json::to_value(event).ok())
            .filter_map(|value| serde_json::from_value(value).ok())
            .collect();
        std::thread::spawn(move || {
            if let Err(err) =
                crate::event_router::route_events_to_default_flow(&bundle, &ctx, &events)
            {
                crate::operator_log::warn(module_path!(), format!("event routing failed: {err:#}"));
            }
        });
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
                route_messaging_envelopes(&bundle, &runner_host, &provider, &ctx, envelopes, None)
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

fn resolve_static_route_directline_request_from_match(
    path: &str,
    route_match: &StaticRouteMatch<'_>,
) -> Option<StaticRouteDirectlineTarget> {
    let directline_path = match route_match.asset_path.as_str() {
        "token" => "/token".to_string(),
        "auth/config" => "/auth/config".to_string(),
        asset_path if asset_path.starts_with("v3/directline") => format!("/{asset_path}"),
        _ => return None,
    };
    let (tenant, team) = extract_scope_from_route_match(path, route_match)?;
    let route = Some(route_match.descriptor.route_id.clone());
    let provider = Some(route_match.descriptor.pack_id.clone());
    Some((tenant, team, route, directline_path, provider))
}

async fn dispatch_provider_directline_http<B>(
    req: Request<B>,
    request: ProviderDirectlineHttpRequest<'_>,
    state: &Arc<HttpIngressState>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let headers = collect_headers(req.headers());
    let body = req
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();
    let payload = HttpInV1 {
        v: 1,
        provider: request.provider.to_string(),
        route: request.route.map(str::to_string),
        binding_id: None,
        tenant_hint: Some(request.tenant.to_string()),
        team_hint: Some(request.team.to_string()),
        method: request.method.as_str().to_string(),
        path: request.path.to_string(),
        query: request.queries.to_vec(),
        headers,
        body_b64: base64::engine::general_purpose::STANDARD.encode(&body),
        config: None,
    };
    let ctx = OperatorContext {
        tenant: request.tenant.to_string(),
        team: Some(request.team.to_string()),
        correlation_id: None,
    };
    let payload_bytes = serde_json::to_vec(&payload).map_err(|err| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize directline_http payload: {err}"),
        )
    })?;
    let outcome = state
        .runner_host
        .invoke_provider_op(
            Domain::Messaging,
            request.provider,
            "directline_http",
            &payload_bytes,
            &ctx,
        )
        .map_err(|err| error_response(StatusCode::BAD_GATEWAY, err.to_string()))?;
    if !outcome.success {
        let message = outcome
            .error
            .or(outcome.raw)
            .unwrap_or_else(|| "provider directline_http failed".to_string());
        return Err(error_response(StatusCode::BAD_GATEWAY, message));
    }
    let value = outcome.output.unwrap_or_else(|| serde_json::json!({}));
    let response = parse_provider_directline_http_response(&value).map_err(|err| {
        error_response(
            StatusCode::BAD_GATEWAY,
            format!("invalid directline_http response: {err}"),
        )
    })?;
    build_http_response(&response)
        .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))
}

async fn dispatch_static_route_ingress<B>(
    req: Request<B>,
    path: &str,
    state: &Arc<HttpIngressState>,
    target: StaticRouteIngressTarget,
) -> Result<Option<Response<Full<Bytes>>>, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let method = req.method().clone();
    let headers = collect_headers(req.headers());
    let query = collect_queries(req.uri().query());
    let body = req
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes().to_vec())
        .map_err(|err| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("failed to read request body: {err}"),
            )
        })?;
    let ctx = OperatorContext {
        tenant: target.tenant.clone(),
        team: target.team.clone(),
        correlation_id: None,
    };
    let request = IngressRequestV1 {
        v: 1,
        domain: domain_name(target.domain).to_string(),
        provider: target.provider.clone(),
        handler: target.handler.clone(),
        tenant: target.tenant.clone(),
        team: target.team.clone(),
        method: method.as_str().to_string(),
        path: path.to_string(),
        query,
        headers,
        body,
        correlation_id: None,
        remote_addr: None,
    };
    let result = dispatch_http_ingress(&state.runner_host, target.domain, &request, &ctx)
        .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let response = build_http_response(&result.response)
        .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))?;
    Ok(Some(with_cors(response)))
}

fn parse_provider_directline_http_response(
    value: &serde_json::Value,
) -> anyhow::Result<IngressHttpResponse> {
    let value = value
        .get("http")
        .or_else(|| value.get("response"))
        .unwrap_or(value);
    let status = value
        .get("status")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(200) as u16;
    let headers = value
        .get("headers")
        .and_then(serde_json::Value::as_object)
        .map(|headers| {
            headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.to_string(),
                        value
                            .as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| value.to_string()),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let body = if let Some(body_b64) = value.get("body_b64").and_then(serde_json::Value::as_str) {
        Some(base64::engine::general_purpose::STANDARD.decode(body_b64)?)
    } else if let Some(body) = value.get("body").and_then(serde_json::Value::as_str) {
        Some(body.as_bytes().to_vec())
    } else if let Some(body_json) = value.get("body_json") {
        Some(serde_json::to_vec(body_json)?)
    } else {
        None
    };
    Ok(IngressHttpResponse {
        status,
        headers,
        body,
    })
}

fn infer_static_route_ingress_target(
    request_path: &str,
    route_match: &StaticRouteMatch<'_>,
) -> Option<StaticRouteIngressTarget> {
    let normalized = request_path
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let segments = &route_match.descriptor.route_segments;
    let domain = match (segments.first(), segments.get(1)) {
        (Some(RouteScopeSegment::Literal(prefix)), Some(RouteScopeSegment::Literal(domain)))
            if prefix.eq_ignore_ascii_case("v1") =>
        {
            parse_domain(domain)?
        }
        (Some(RouteScopeSegment::Literal(domain)), _) => parse_domain(domain)?,
        _ => return None,
    };
    let mut tenant = None;
    let mut team = None;
    for (value, segment) in normalized.iter().zip(segments.iter()) {
        match segment {
            RouteScopeSegment::Tenant => tenant = Some((*value).to_string()),
            RouteScopeSegment::Team => team = Some((*value).to_string()),
            RouteScopeSegment::Literal(_) => {}
        }
    }
    Some(StaticRouteIngressTarget {
        domain,
        provider: route_match.descriptor.pack_id.clone(),
        tenant: tenant?,
        team,
        handler: Some(route_match.descriptor.route_id.clone()),
    })
}

fn is_oauth_token_exchange_path(path: &str) -> bool {
    path.trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>()
        .ends_with(&["oauth", "token-exchange"])
}

fn is_legacy_directline_path(path: &str) -> bool {
    path == "/token" || path.starts_with("/v3/directline") || path.starts_with("/directline")
}

fn legacy_directline_compat_enabled() -> bool {
    std::env::var_os(LEGACY_DIRECTLINE_COMPAT_ENV)
        .and_then(|value| value.into_string().ok())
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

fn extract_scope_from_route_match(
    request_path: &str,
    route_match: &StaticRouteMatch<'_>,
) -> Option<(String, Option<String>)> {
    let mut tenant = None;
    let mut team = None;
    request_path
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .zip(route_match.descriptor.route_segments.iter())
        .for_each(|(value, segment)| match segment {
            RouteScopeSegment::Tenant => tenant = Some(value.to_string()),
            RouteScopeSegment::Team => team = Some(value.to_string()),
            RouteScopeSegment::Literal(_) => {}
        });
    Some((tenant?, team))
}

#[cfg(test)]
mod tests {
    use super::helpers::{handle_builtin_health_request, parse_route_segments};
    use super::*;
    use crate::domains::Domain;
    use crate::secrets_gate;
    use crate::static_routes::{
        ActiveRouteTable, CacheStrategy, RouteScopeSegment, StaticRouteDescriptor, StaticRoutePlan,
    };
    use http_body_util::{BodyExt, Full};
    use hyper::{Method, Request, StatusCode, body::Bytes};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::runtime::Runtime;

    fn test_state(domains: Vec<Domain>) -> Arc<HttpIngressState> {
        let dir = tempdir().unwrap();
        let discovery = crate::discovery::discover(dir.path()).unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default")).unwrap();
        let runner_host = Arc::new(
            DemoRunnerHost::new(
                dir.path().to_path_buf(),
                &discovery,
                None,
                secrets_handle,
                false,
            )
            .unwrap(),
        );
        Arc::new(HttpIngressState {
            runner_host,
            domains,
            active_route_table: ActiveRouteTable::default(),
            legacy_directline: legacy_directline::LegacyDirectLineCompat::new(),
        })
    }

    fn empty_request(method: Method, path: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Full::from(Bytes::new()))
            .unwrap()
    }

    fn body_request(method: Method, path: &str, body: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Full::from(Bytes::from(body.to_string())))
            .unwrap()
    }

    async fn response_json(response: Response<Full<Bytes>>) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

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

    #[test]
    fn builtin_health_routes_return_ok() {
        for path in ["/healthz", "/readyz", "/status"] {
            let response =
                handle_builtin_health_request(&Method::GET, path).expect("builtin response");
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[test]
    fn handle_request_inner_rejects_options_and_invalid_methods() {
        let runtime = Runtime::new().unwrap();
        let state = test_state(vec![Domain::Events]);

        let options = runtime
            .block_on(handle_request_inner(
                empty_request(Method::OPTIONS, "/v1/events/ingress/p/demo"),
                state.clone(),
            ))
            .unwrap();
        assert_eq!(options.status(), StatusCode::NO_CONTENT);

        let invalid_method = runtime
            .block_on(handle_request_inner(
                empty_request(Method::PUT, "/v1/events/ingress/p/demo"),
                state,
            ))
            .unwrap_err();
        assert_eq!(invalid_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn handle_request_inner_covers_bad_route_disabled_domain_and_missing_handler() {
        let runtime = Runtime::new().unwrap();

        let bad_route = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/v1/events/not-ingress"),
                test_state(vec![Domain::Events]),
            ))
            .unwrap_err();
        assert_eq!(bad_route.status(), StatusCode::BAD_REQUEST);

        let domain_disabled = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/v1/events/ingress/provider-a/demo"),
                test_state(vec![Domain::Messaging]),
            ))
            .unwrap_err();
        assert_eq!(domain_disabled.status(), StatusCode::NOT_FOUND);

        let no_handler = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/v1/events/ingress/provider-a/demo"),
                test_state(vec![Domain::Events]),
            ))
            .unwrap_err();
        assert_eq!(no_handler.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn handle_request_inner_routes_onboard_oauth_and_directline_paths() {
        let runtime = Runtime::new().unwrap();

        let onboard = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/api/onboard/unknown"),
                test_state(vec![Domain::Messaging]),
            ))
            .unwrap_err();
        assert_eq!(onboard.status(), StatusCode::NOT_FOUND);

        let oauth_invalid_json = runtime
            .block_on(handle_request_inner(
                body_request(
                    Method::POST,
                    "/v1/messaging/webchat/demo/oauth/token-exchange",
                    "{not-json",
                ),
                test_state(vec![Domain::Messaging]),
            ))
            .unwrap_err();
        assert_eq!(oauth_invalid_json.status(), StatusCode::BAD_REQUEST);

        let oauth_missing_url = runtime
            .block_on(handle_request_inner(
                body_request(
                    Method::POST,
                    "/v1/messaging/webchat/demo/oauth/token-exchange",
                    "{}",
                ),
                test_state(vec![Domain::Messaging]),
            ))
            .unwrap_err();
        assert_eq!(oauth_missing_url.status(), StatusCode::BAD_REQUEST);

        let legacy_directline = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/token"),
                test_state(vec![]),
            ))
            .unwrap_err();
        assert_eq!(legacy_directline.status(), StatusCode::NOT_FOUND);
        let legacy_directline_body = runtime.block_on(response_json(legacy_directline));
        let legacy_directline_message = legacy_directline_body["message"]
            .as_str()
            .unwrap_or_default();
        assert!(
            legacy_directline_message.contains("legacy directline compatibility is disabled")
                || legacy_directline_message.contains("messaging domain disabled")
                || legacy_directline_message.contains(
                    "directline routes must be declared by a pack or supply provider query"
                )
        );

        let webchat_directline = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/v1/messaging/webchat/demo/token"),
                test_state(vec![]),
            ))
            .unwrap_err();
        assert_eq!(webchat_directline.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn legacy_directline_root_routes_require_explicit_provider_query() {
        let runtime = Runtime::new().unwrap();
        let env_guard = crate::test_env_lock().lock().unwrap();

        let missing_provider = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/v3/directline/conversations"),
                test_state(vec![Domain::Messaging]),
            ))
            .unwrap_err();
        assert_eq!(missing_provider.status(), StatusCode::NOT_FOUND);

        unsafe {
            std::env::set_var(LEGACY_DIRECTLINE_COMPAT_ENV, "1");
        }
        let explicit_provider = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/token?tenant=demo&provider=messaging-webchat"),
                test_state(vec![Domain::Messaging]),
            ))
            .unwrap_err();
        assert_eq!(
            explicit_provider.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        unsafe {
            std::env::remove_var(LEGACY_DIRECTLINE_COMPAT_ENV);
        }
        drop(env_guard);
    }

    #[test]
    fn handle_request_wraps_errors_with_cors_headers() {
        let runtime = Runtime::new().unwrap();
        let response = runtime
            .block_on(handle_request(
                empty_request(Method::PUT, "/v1/events/ingress/provider-a/demo"),
                test_state(vec![Domain::Events]),
            ))
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body = runtime.block_on(response_json(response));
        assert_eq!(body["success"], false);
    }

    #[test]
    fn handle_request_wraps_success_with_cors_headers() {
        let runtime = Runtime::new().unwrap();
        let response = runtime
            .block_on(handle_request(
                empty_request(Method::GET, "/healthz"),
                test_state(vec![Domain::Events]),
            ))
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }

    #[test]
    fn handle_request_inner_short_circuits_builtin_health_routes() {
        let runtime = Runtime::new().unwrap();
        let response = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/readyz"),
                test_state(vec![]),
            ))
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = runtime.block_on(response_json(response));
        assert_eq!(body["status"], "ready");
    }

    #[test]
    fn http_ingress_server_starts_and_stops_without_static_routes() {
        let dir = tempdir().unwrap();
        let discovery = crate::discovery::discover(dir.path()).unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default")).unwrap();
        let runner_host = Arc::new(
            DemoRunnerHost::new(
                dir.path().to_path_buf(),
                &discovery,
                None,
                secrets_handle,
                false,
            )
            .unwrap(),
        );

        let server = HttpIngressServer::start(HttpIngressConfig {
            bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            domains: vec![Domain::Messaging],
            runner_host,
            enable_static_routes: false,
            tenant: "demo".to_string(),
        })
        .expect("start ingress server");

        assert!(server.static_route_urls.is_empty());
        server.stop().expect("stop ingress server");
    }

    #[test]
    fn handle_request_inner_serves_static_routes_before_ingress_dispatch() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let discovery = crate::discovery::discover(dir.path()).unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default")).unwrap();
        let runner_host = Arc::new(
            DemoRunnerHost::new(
                dir.path().to_path_buf(),
                &discovery,
                None,
                secrets_handle,
                false,
            )
            .unwrap(),
        );

        std::fs::create_dir_all(dir.path().join("site")).unwrap();
        std::fs::write(
            dir.path().join("site").join("index.html"),
            "<html>ok</html>",
        )
        .unwrap();
        let route = StaticRouteDescriptor {
            route_id: "web".to_string(),
            pack_id: "web".to_string(),
            pack_path: dir.path().to_path_buf(),
            public_path: "/web".to_string(),
            source_root: "site".to_string(),
            index_file: Some("index.html".to_string()),
            spa_fallback: Some("index.html".to_string()),
            tenant_scoped: false,
            team_scoped: false,
            cache_strategy: CacheStrategy::None,
            route_segments: vec![RouteScopeSegment::Literal("web".to_string())],
        };
        let state = Arc::new(HttpIngressState {
            runner_host,
            domains: vec![],
            active_route_table: ActiveRouteTable::from_plan(&StaticRoutePlan {
                routes: vec![route],
                warnings: vec![],
                blocking_failures: vec![],
            }),
            legacy_directline: legacy_directline::LegacyDirectLineCompat::new(),
        });

        let response = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/web/"),
                state,
            ))
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body =
            runtime.block_on(async { response.into_body().collect().await.unwrap().to_bytes() });
        assert!(String::from_utf8_lossy(&body).contains("<html>ok</html>"));
    }

    #[test]
    fn tenant_scoped_directline_uses_provider_from_matching_static_route_pack_id() {
        use crate::secrets_gate::canonical_secret_uri;
        use std::fs::File;
        use std::io::Write;
        use zip::write::FileOptions;

        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let env_guard = crate::test_env_lock().lock().unwrap();

        let pack_path = dir.path().join("env-backend.gtpack");
        let file = File::create(&pack_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("assets/secrets_backend.json", FileOptions::<()>::default())
            .unwrap();
        zip.write_all(br#"{"backend":"env"}"#).unwrap();
        zip.finish().unwrap();
        unsafe {
            std::env::set_var("GREENTIC_SECRETS_MANAGER_PACK", &pack_path);
        }

        let discovery = crate::discovery::discover(dir.path()).unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default")).unwrap();
        let runner_host = Arc::new(
            DemoRunnerHost::new(
                dir.path().to_path_buf(),
                &discovery,
                None,
                secrets_handle,
                false,
            )
            .unwrap(),
        );

        let route = StaticRouteDescriptor {
            route_id: "webchat-gui".to_string(),
            pack_id: "messaging-webchat-gui".to_string(),
            pack_path: dir.path().to_path_buf(),
            public_path: "/v1/web/webchat/{tenant}".to_string(),
            source_root: "site".to_string(),
            index_file: Some("index.html".to_string()),
            spa_fallback: Some("index.html".to_string()),
            tenant_scoped: true,
            team_scoped: false,
            cache_strategy: CacheStrategy::None,
            route_segments: vec![
                RouteScopeSegment::Literal("v1".to_string()),
                RouteScopeSegment::Literal("web".to_string()),
                RouteScopeSegment::Literal("webchat".to_string()),
                RouteScopeSegment::Tenant,
            ],
        };
        let state = Arc::new(HttpIngressState {
            runner_host,
            domains: vec![Domain::Messaging],
            active_route_table: ActiveRouteTable::from_plan(&StaticRoutePlan {
                routes: vec![route],
                warnings: vec![],
                blocking_failures: vec![],
            }),
            legacy_directline: legacy_directline::LegacyDirectLineCompat::new(),
        });

        let gui_secret_uri = canonical_secret_uri(
            "dev",
            "demo",
            Some("default"),
            "messaging-webchat-gui",
            "jwt_signing_key",
        );
        unsafe {
            std::env::set_var(&gui_secret_uri, "gui-signing-key");
        }

        let response = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/v1/messaging/webchat/demo/token"),
                state,
            ))
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        unsafe {
            std::env::remove_var(&gui_secret_uri);
            std::env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
        }
        drop(env_guard);
    }

    #[test]
    fn oauth_token_exchange_path_detection_is_generic() {
        assert!(is_oauth_token_exchange_path(
            "/v1/messaging/webchat/demo/oauth/token-exchange"
        ));
        assert!(is_oauth_token_exchange_path(
            "/custom/prefix/oauth/token-exchange"
        ));
        assert!(!is_oauth_token_exchange_path("/custom/prefix/oauth/token"));
    }

    #[test]
    fn infer_static_route_ingress_target_reads_domain_provider_and_scope() {
        let descriptor = StaticRouteDescriptor {
            route_id: "gui".to_string(),
            pack_id: "messaging-webchat-gui".to_string(),
            pack_path: std::path::PathBuf::from("/tmp/pack.gtpack"),
            public_path: "/v1/messaging/webchat/{tenant}/{team}".to_string(),
            source_root: "assets".to_string(),
            index_file: Some("index.html".to_string()),
            spa_fallback: Some("index.html".to_string()),
            tenant_scoped: true,
            team_scoped: true,
            cache_strategy: CacheStrategy::None,
            route_segments: vec![
                RouteScopeSegment::Literal("v1".to_string()),
                RouteScopeSegment::Literal("messaging".to_string()),
                RouteScopeSegment::Literal("webchat".to_string()),
                RouteScopeSegment::Tenant,
                RouteScopeSegment::Team,
            ],
        };
        let route_match = StaticRouteMatch {
            descriptor: &descriptor,
            asset_path: "token".to_string(),
            request_is_directory: false,
        };
        let target = infer_static_route_ingress_target(
            "/v1/messaging/webchat/demo/default/token",
            &route_match,
        )
        .expect("target");
        assert_eq!(target.domain, Domain::Messaging);
        assert_eq!(target.provider, "messaging-webchat-gui");
        assert_eq!(target.tenant, "demo");
        assert_eq!(target.team.as_deref(), Some("default"));
        assert_eq!(target.handler.as_deref(), Some("gui"));
    }

    #[test]
    fn resolve_static_route_directline_request_preserves_team_scope() {
        let descriptor = StaticRouteDescriptor {
            route_id: "gui".to_string(),
            pack_id: "messaging-webchat-gui".to_string(),
            pack_path: std::path::PathBuf::from("/tmp/pack.gtpack"),
            public_path: "/v1/messaging/webchat/{tenant}/{team}".to_string(),
            source_root: "assets".to_string(),
            index_file: Some("index.html".to_string()),
            spa_fallback: Some("index.html".to_string()),
            tenant_scoped: true,
            team_scoped: true,
            cache_strategy: CacheStrategy::None,
            route_segments: vec![
                RouteScopeSegment::Literal("v1".to_string()),
                RouteScopeSegment::Literal("messaging".to_string()),
                RouteScopeSegment::Literal("webchat".to_string()),
                RouteScopeSegment::Tenant,
                RouteScopeSegment::Team,
            ],
        };
        let route_match = StaticRouteMatch {
            descriptor: &descriptor,
            asset_path: "v3/directline/conversations".to_string(),
            request_is_directory: false,
        };
        let target = resolve_static_route_directline_request_from_match(
            "/v1/messaging/webchat/demo/default/v3/directline/conversations",
            &route_match,
        )
        .expect("target");
        assert_eq!(target.0, "demo");
        assert_eq!(target.1.as_deref(), Some("default"));
        assert_eq!(target.2.as_deref(), Some("gui"));
        assert_eq!(target.3, "/v3/directline/conversations");
        assert_eq!(target.4.as_deref(), Some("messaging-webchat-gui"));
    }
}
