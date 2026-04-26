mod admin_relay;
mod helpers;
mod messaging;
mod static_handler;
pub mod websocket;

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, mpsc},
    thread,
};

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
use crate::http_routes::{HttpRouteTable, discover_http_routes_from_bundle};
use crate::ingress_dispatch::{dispatch_http_ingress, dispatch_http_ingress_with_op};
use crate::ingress_types::{IngressHttpResponse, IngressRequestV1};
use crate::operator_log;
use crate::runner_host::{DemoRunnerHost, OperatorContext};
use crate::static_routes::{
    ActiveRouteTable, ReservedRouteSet, RouteScopeSegment, StaticRouteMatch, discover_from_bundle,
};

use admin_relay::{
    AdminRelayConfig, handle_admin_relay, load_admin_relay_config_from_env, relay_target_path,
};
use helpers::{
    build_http_response, collect_headers, collect_queries, cors_preflight_response, domain_name,
    error_response, handle_builtin_health_request, handle_oauth_token_exchange, parse_domain,
    parse_route_segments, with_cors,
};
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
    /// When set, UI URLs use this base instead of the local bind address.
    pub public_base_url: Option<String>,
}

pub struct HttpIngressServer {
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<thread::JoinHandle<Result<()>>>,
    /// WebChat GUI URLs discovered from static routes during startup.
    pub ui_urls: Vec<String>,
    /// The port the server actually bound to (may differ from requested port
    /// when port cycling is active).
    pub actual_port: u16,
}

impl HttpIngressServer {
    pub fn start(config: HttpIngressConfig) -> Result<Self> {
        let debug_enabled = config.runner_host.debug_enabled();
        let domains = config.domains;
        let runner_host = config.runner_host;

        // Discover static routes if enabled
        let mut ui_urls = Vec::new();
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
                // Discover user-facing UI URLs from tenant-scoped static routes.
                // When a public base URL is available (tunnel), use it so users
                // get the externally-reachable address.
                for route in table.routes() {
                    if route.tenant_scoped && route.spa_fallback.is_some() {
                        let url_path = route.public_path.replace("{tenant}", &config.tenant);
                        let ui_url = if let Some(ref base) = config.public_base_url {
                            format!(
                                "{}/{}/",
                                base.trim_end_matches('/'),
                                url_path.trim_start_matches('/')
                            )
                        } else {
                            format!(
                                "http://{}/{}/",
                                config.bind_addr,
                                url_path.trim_start_matches('/')
                            )
                        };
                        operator_log::info(module_path!(), format!("UI: {ui_url}"));
                        ui_urls.push(ui_url);
                    }
                }
            }
            table
        } else {
            ActiveRouteTable::default()
        };

        // Discover pack-declared HTTP API routes (greentic.http-routes.v1)
        let http_route_table = if config.enable_static_routes {
            match discover_http_routes_from_bundle(runner_host.bundle_root()) {
                Ok(routes) => {
                    if !routes.is_empty() {
                        operator_log::info(
                            module_path!(),
                            format!(
                                "discovered {} HTTP route(s): {}",
                                routes.len(),
                                routes
                                    .iter()
                                    .map(|r| r.pattern.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                        );
                    }
                    HttpRouteTable::from_descriptors(routes)
                }
                Err(err) => {
                    operator_log::warn(
                        module_path!(),
                        format!("http route discovery failed: {err:#}"),
                    );
                    HttpRouteTable::default()
                }
            }
        } else {
            HttpRouteTable::default()
        };

        let admin_relay = load_admin_relay_config_from_env()?;
        let state = Arc::new(HttpIngressState {
            runner_host,
            domains,
            active_route_table,
            http_route_table,
            admin_relay,
            notifier: crate::notifier::build_notifier(crate::notifier::NotifierConfig::default()),
            session_manager: Arc::new(websocket::SessionManager::new(
                websocket::WsLimits::default(),
            )),
            webchat_provider: "messaging-webchat".to_string(),
        });

        // Resolve an available port before spawning the server thread.
        let requested_port = config.bind_addr.port();
        let listen_addr_str = config.bind_addr.ip().to_string();
        let actual_port =
            crate::port_utils::find_available_port(&listen_addr_str, requested_port, 10)
                .context("failed to find available port for HTTP ingress")?;
        if actual_port != requested_port {
            operator_log::warn(
                module_path!(),
                format!(
                    "requested port {requested_port} is in use; using port {actual_port} instead"
                ),
            );
        }
        let addr = SocketAddr::new(config.bind_addr.ip(), actual_port);

        let (tx, rx) = oneshot::channel();
        let (startup_tx, startup_rx) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("demo-ingress".to_string())
            .spawn(move || -> Result<()> {
                let runtime = match Runtime::new().context("failed to create ingress runtime") {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        let _ = startup_tx.send(Err(anyhow::anyhow!("{err:#}")));
                        return Err(err);
                    }
                };
                runtime.block_on(async move {
                    let listener = match TcpListener::bind(addr)
                        .await
                        .context("failed to bind ingress listener")
                    {
                        Ok(listener) => listener,
                        Err(err) => {
                            let _ = startup_tx.send(Err(anyhow::anyhow!("{err:#}")));
                            return Err(err);
                        }
                    };
                    let _ = startup_tx.send(Ok(()));
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
        startup_rx
            .recv()
            .context("failed to receive ingress startup result")??;

        Ok(Self {
            shutdown: Some(tx),
            handle: Some(handle),
            ui_urls,
            actual_port,
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

struct HttpIngressState {
    runner_host: Arc<DemoRunnerHost>,
    domains: Vec<Domain>,
    active_route_table: ActiveRouteTable,
    http_route_table: HttpRouteTable,
    admin_relay: Option<Arc<AdminRelayConfig>>,
    // Used by WebSocket session handlers (Task 11+) to subscribe to activity events.
    pub notifier: std::sync::Arc<dyn crate::notifier::ActivityNotifier>,
    /// Bookkeeping for active WebSocket sessions (concurrency limits + per-conv guards).
    pub session_manager: Arc<websocket::SessionManager>,
    /// Provider id used to fan WS reads through the existing webchat provider WASM.
    pub webchat_provider: String,
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

    if let Some(target_path) = relay_target_path(&path) {
        let Some(config) = state.admin_relay.clone() else {
            return Err(error_response(
                StatusCode::NOT_FOUND,
                "admin relay is not enabled for this runtime",
            ));
        };
        return handle_admin_relay(req, target_path, config).await;
    }

    if path.starts_with("/api/onboard") {
        return crate::onboard::api::handle_onboard_request(req, &path, &state.runner_host)
            .await
            .map_err(|err| *err);
    }

    // OAuth token exchange proxy: /v1/messaging/webchat/{tenant}/oauth/token-exchange
    if is_oauth_token_exchange_path(&path) && req.method() == Method::POST {
        return handle_oauth_token_exchange(req).await;
    }

    // WebChat Direct Line routes:
    // - /v1/messaging/webchat/{tenant}/token
    // - /v1/messaging/webchat/{tenant}/v3/directline/*
    // - /v1/web/webchat/{tenant}/token
    // - /v1/web/webchat/{tenant}/v3/directline/*
    if let Some((tenant, dl_path)) = parse_webchat_directline_route(&path) {
        let provider = state
            .active_route_table
            .match_request(&path)
            .map(|route_match| route_match.descriptor.pack_id.clone())
            .or_else(|| {
                // /v1/messaging/webchat/* endpoints are API routes and do not necessarily share
                // the same URL prefix as static web assets (/v1/web/webchat/*). When there is no
                // direct static-route match, prefer the backend webchat provider if present.
                if state
                    .runner_host
                    .get_provider_pack_path(Domain::Messaging, "messaging-webchat")
                    .is_some()
                {
                    Some("messaging-webchat".to_string())
                } else if state
                    .runner_host
                    .get_provider_pack_path(Domain::Messaging, "messaging-webchat-gui")
                    .is_some()
                {
                    Some("messaging-webchat-gui".to_string())
                } else {
                    None
                }
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
                state
                    .active_route_table
                    .routes()
                    .iter()
                    .find(|route| route.pack_id == "messaging-webchat-gui")
                    .map(|route| route.pack_id.clone())
            });
        if provider.is_none() {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "provider must be supplied by the route or query",
            ));
        }
        if is_webchat_directline_stream_path(&path) {
            return handle_websocket_upgrade(req, &path, &tenant, state).await;
        }
        return handle_legacy_directline_request(
            req,
            &dl_path,
            Some(tenant),
            None,
            provider,
            state,
        )
        .await;
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
        if let Some((tenant, team, route, dl_path, provider)) = directline_target {
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

    // Resolve path to a parsed ingress route.
    // Tries: (1) pack-declared HTTP routes, (2) static routes, (3) standard ingress.
    let method = req.method().clone();
    let parsed = 'resolve: {
        // Pack-declared HTTP routes (greentic.http-routes.v1): provider packs declare
        // which URL patterns they handle, and the ingress server dispatches to them
        // via the generic `dispatch_http_ingress` pipeline.
        if let Some(route_match) = state.http_route_table.match_request(&path, method.as_str()) {
            break 'resolve helpers::ParsedIngressRoute {
                domain: route_match.descriptor.domain,
                provider: route_match.descriptor.pack_id.clone(),
                tenant: route_match.tenant,
                team: route_match.team,
                handler: None,
            };
        }

        // Static route handling — serve assets from .gtpack files
        if let Some(route_match) = state.active_route_table.match_request(&path) {
            return Ok(serve_static_route(
                &route_match,
                state.runner_host.bundle_root(),
                &path,
            ));
        }

        // Standard ingress route: /v1/{domain}/ingress/{provider}/{tenant}/{team?}/{handler?}
        match parse_route_segments(req.uri().path()) {
            Some(value) => value,
            None => {
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    "expected /v1/{domain}/ingress/{provider}/{tenant}/{team?}/{handler?}",
                ));
            }
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
                // Providers set `is_bot_message=true` in envelope metadata to
                // signal bot self-messages that should not be routed back through
                // the app flow.
                let is_bot = env
                    .metadata
                    .get("is_bot_message")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                if is_bot {
                    operator_log::debug(
                        module_path!(),
                        format!(
                            "[demo ingress] skipping bot self-message from={:?} id={}",
                            env.from, env.id
                        ),
                    );
                }
                !is_bot
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

async fn handle_legacy_directline_request<B>(
    req: Request<B>,
    path: &str,
    explicit_tenant: Option<String>,
    explicit_team: Option<String>,
    explicit_provider: Option<String>,
    state: Arc<HttpIngressState>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let queries = collect_queries(req.uri().query());
    let provider = explicit_provider.or_else(|| {
        queries
            .iter()
            .find(|(name, _)| name == "provider")
            .map(|(_, value)| value.clone())
    });
    let tenant = explicit_tenant.unwrap_or_else(|| {
        queries
            .iter()
            .find(|(name, _)| name == "tenant")
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| "default".to_string())
    });
    let team = explicit_team.unwrap_or_else(|| {
        queries
            .iter()
            .find(|(name, _)| name == "team")
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| "default".to_string())
    });

    let provider = provider.ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "provider must be supplied by the route or query",
        )
    })?;
    let has_directline =
        state
            .runner_host
            .supports_op(Domain::Messaging, &provider, "directline_http");
    let has_ingest = state
        .runner_host
        .supports_op(Domain::Messaging, &provider, "ingest_http")
        || state
            .runner_host
            .supports_op(Domain::Messaging, &provider, "ingest-http");

    if !(state.domains.contains(&Domain::Messaging) || has_directline || has_ingest) {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "messaging domain disabled",
        ));
    }

    let method = req.method().clone();
    if has_directline {
        return dispatch_provider_directline_http(
            req,
            ProviderDirectlineHttpRequest {
                method: &method,
                path,
                route: None,
                tenant: &tenant,
                team: &team,
                provider: &provider,
                queries: &queries,
            },
            &state,
        )
        .await;
    }
    if has_ingest {
        return dispatch_provider_directline_via_ingest_http(
            req,
            ProviderDirectlineHttpRequest {
                method: &method,
                path,
                route: None,
                tenant: &tenant,
                team: &team,
                provider: &provider,
                queries: &queries,
            },
            &state,
        )
        .await;
    }
    Err(error_response(
        StatusCode::NOT_FOUND,
        "provider does not implement directline_http or ingest_http",
    ))
}

async fn handle_websocket_upgrade<B>(
    mut req: Request<B>,
    path: &str,
    tenant: &str,
    state: Arc<HttpIngressState>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    use crate::runner_host::OperatorContext;
    use crate::secrets_gate::canonical_secret_uri;
    use crate::secrets_setup::resolve_env;
    use websocket::{
        ActivitySource, RunnerHostActivitySource, RunnerHostHandle, UpgradeError, refusal_response,
        serve_session, validate_request_parts,
    };

    let conv_id = match extract_stream_conversation_id(path) {
        Some(c) => c,
        None => return Err(error_response(StatusCode::NOT_FOUND, "invalid stream path")),
    };

    // Read JWT signing key from the same secrets URI the WASM provider uses
    // when issuing tokens. The webchat provider id is configurable on the
    // ingress state so deployments that override the default still work.
    let secret_ctx = OperatorContext {
        tenant: tenant.to_string(),
        team: Some("default".to_string()),
        correlation_id: None,
    };
    let signing_key =
        match state
            .runner_host
            .get_secret(&state.webchat_provider, "jwt_signing_key", &secret_ctx)
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                // Fall back: try reading by canonical URI directly so we surface a
                // helpful 500 instead of a silent unauthorized response.
                let env = resolve_env(None);
                let uri = canonical_secret_uri(
                    &env,
                    tenant,
                    Some("default"),
                    &state.webchat_provider,
                    "jwt_signing_key",
                );
                return Err(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("missing jwt signing key (looked up {uri})"),
                ));
            }
            Err(err) => {
                return Err(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to read jwt signing key: {err}"),
                ));
            }
        };

    let ctx = match validate_request_parts(req.uri(), req.headers(), &conv_id, tenant, &signing_key)
    {
        Ok(c) => c,
        Err(err) => return Ok(refusal_response(&err)),
    };

    let manager = state.session_manager.clone();
    let guard = match manager.acquire(tenant, &conv_id) {
        Ok(g) => g,
        Err(err) => {
            return Ok(refusal_response(&UpgradeError::LimitExceeded(
                err.to_string(),
            )));
        }
    };

    let (response, websocket) = match hyper_tungstenite::upgrade(&mut req, None) {
        Ok(pair) => pair,
        Err(err) => {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                format!("websocket upgrade failed: {err}"),
            ));
        }
    };

    let notifier = state.notifier.clone();
    let runner_host: Arc<dyn RunnerHostHandle> = state.runner_host.clone();
    let source: Arc<dyn ActivitySource> = Arc::new(RunnerHostActivitySource {
        runner_host,
        provider: state.webchat_provider.clone(),
        team: "default".to_string(),
    });
    let limits = manager.limits().clone();
    tokio::spawn(serve_session(
        websocket,
        notifier,
        source,
        tenant.to_string(),
        conv_id,
        ctx.initial_watermark,
        limits,
        guard,
    ));

    Ok(response)
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
    let (provider_method, provider_path) =
        normalize_directline_dispatch(request.method, request.path);
    let provider_queries =
        augment_directline_queries(request.queries, request.tenant, Some(request.team));
    let provider_query_string = encode_directline_query_string(&provider_queries);
    let headers = collect_headers(req.headers());
    let body = req
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();
    let payload = serde_json::json!({
        "v": 1,
        "provider": request.provider,
        "route": request.route,
        "binding_id": serde_json::Value::Null,
        "tenant_hint": request.tenant,
        "team_hint": request.team,
        "method": provider_method.as_str(),
        "path": provider_path,
        "query": provider_query_string,
        "headers": headers,
        "body_b64": base64::engine::general_purpose::STANDARD.encode(&body),
        "config": serde_json::Value::Null,
    });
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

fn normalize_directline_dispatch(method: &Method, path: &str) -> (Method, String) {
    if path == "/token" {
        return (Method::POST, "/v3/directline/tokens/generate".to_string());
    }
    if path == "/directline" {
        return (method.clone(), "/v3/directline".to_string());
    }
    if let Some(rest) = path.strip_prefix("/directline/") {
        return (method.clone(), format!("/v3/directline/{rest}"));
    }
    (method.clone(), path.to_string())
}

fn augment_directline_queries(
    queries: &[(String, String)],
    tenant: &str,
    team: Option<&str>,
) -> Vec<(String, String)> {
    let mut augmented = queries.to_vec();
    if !augmented.iter().any(|(name, _)| name == "tenant") {
        augmented.push(("tenant".to_string(), tenant.to_string()));
    }
    if let Some(team) = team.filter(|value| !value.is_empty())
        && !augmented.iter().any(|(name, _)| name == "team")
    {
        augmented.push(("team".to_string(), team.to_string()));
    }
    augmented
}

fn encode_directline_query_string(queries: &[(String, String)]) -> Option<String> {
    if queries.is_empty() {
        return None;
    }
    Some(
        queries
            .iter()
            .map(|(name, value)| {
                format!(
                    "{}={}",
                    percent_encode_query_component(name),
                    percent_encode_query_component(value)
                )
            })
            .collect::<Vec<_>>()
            .join("&"),
    )
}

fn percent_encode_query_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b' ' => encoded.push_str("%20"),
            _ => encoded.push_str(&format!("%{:02X}", byte)),
        }
    }
    encoded
}

async fn dispatch_provider_directline_via_ingest_http<B>(
    req: Request<B>,
    request: ProviderDirectlineHttpRequest<'_>,
    state: &Arc<HttpIngressState>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let (provider_method, provider_path) =
        normalize_directline_dispatch(request.method, request.path);
    let provider_queries =
        augment_directline_queries(request.queries, request.tenant, Some(request.team));
    let headers = collect_headers(req.headers());
    let body = req
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes().to_vec())
        .unwrap_or_default();
    let ctx = OperatorContext {
        tenant: request.tenant.to_string(),
        team: Some(request.team.to_string()),
        correlation_id: None,
    };
    let ingress_request = IngressRequestV1 {
        v: 1,
        domain: domain_name(Domain::Messaging).to_string(),
        provider: request.provider.to_string(),
        handler: None,
        tenant: request.tenant.to_string(),
        team: Some(request.team.to_string()),
        method: provider_method.as_str().to_string(),
        path: provider_path,
        query: provider_queries,
        headers,
        body,
        correlation_id: None,
        remote_addr: None,
    };

    let result = match dispatch_http_ingress_with_op(
        &state.runner_host,
        Domain::Messaging,
        &ingress_request,
        &ctx,
        "ingest-http",
    ) {
        Ok(result) => result,
        Err(primary_err) => dispatch_http_ingress(
            &state.runner_host,
            Domain::Messaging,
            &ingress_request,
            &ctx,
        )
        .map_err(|_secondary_err| {
            error_response(StatusCode::BAD_GATEWAY, primary_err.to_string())
        })?,
    };
    if request.path == "/token" && (200..300).contains(&result.response.status) {
        let body = result.response.body.as_deref().unwrap_or_default();
        let token_ok = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|value| {
                value
                    .get("token")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
            .is_some_and(|token| !token.trim().is_empty());
        if !token_ok {
            return Err(error_response(
                StatusCode::BAD_GATEWAY,
                "invalid directline token response: expected JSON body with non-empty token",
            ));
        }
    }
    if !result.messaging_envelopes.is_empty() {
        let envelopes: Vec<_> = result
            .messaging_envelopes
            .iter()
            .filter(|env| {
                env.metadata
                    .get("is_bot_message")
                    .map(|v| v != "true")
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if !envelopes.is_empty() {
            let bundle = state.runner_host.bundle_root().to_path_buf();
            let provider = request.provider.to_string();
            let ctx_for_worker = ctx.clone();
            let runner_host = state.runner_host.clone();
            std::thread::spawn(move || {
                if let Err(err) = route_messaging_envelopes(
                    &bundle,
                    &runner_host,
                    &provider,
                    &ctx_for_worker,
                    envelopes,
                ) {
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
    }

    build_http_response(&result.response)
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

fn parse_webchat_directline_route(path: &str) -> Option<(String, String)> {
    let segments = path
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 5
        || segments[0] != "v1"
        || (segments[1] != "messaging" && segments[1] != "web")
        || segments[2] != "webchat"
    {
        return None;
    }
    let tenant = segments[3].to_string();
    if segments[4] == "token" && segments.len() == 5 {
        return Some((tenant, "/token".to_string()));
    }
    if segments[4] == "v3" && segments.get(5).is_some_and(|value| *value == "directline") {
        return Some((tenant, format!("/{}", segments[4..].join("/"))));
    }
    None
}

/// True if the path is a webchat DirectLine stream endpoint:
/// `/v1/{messaging,web}/webchat/{tenant}/v3/directline/conversations/{id}/stream`.
fn is_webchat_directline_stream_path(path: &str) -> bool {
    if let Some((_, dl_path)) = parse_webchat_directline_route(path) {
        let segments: Vec<&str> = dl_path.trim_start_matches('/').split('/').collect();
        return matches!(
            segments.as_slice(),
            ["v3", "directline", "conversations", _, "stream"]
        );
    }
    false
}

fn extract_stream_conversation_id(path: &str) -> Option<String> {
    let (_, dl_path) = parse_webchat_directline_route(path)?;
    let segments: Vec<&str> = dl_path.trim_start_matches('/').split('/').collect();
    match segments.as_slice() {
        ["v3", "directline", "conversations", conv_id, "stream"] => Some((*conv_id).to_string()),
        _ => None,
    }
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
            http_route_table: HttpRouteTable::default(),
            admin_relay: None,
            notifier: crate::notifier::build_notifier(crate::notifier::NotifierConfig::default()),
            session_manager: Arc::new(websocket::SessionManager::new(
                websocket::WsLimits::default(),
            )),
            webchat_provider: "messaging-webchat".to_string(),
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

        // Legacy directline paths no longer have a transitional rewriter;
        // they fall through to the standard ingress parser which rejects them.
        let legacy_directline = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/token"),
                test_state(vec![]),
            ))
            .unwrap_err();
        assert_eq!(legacy_directline.status(), StatusCode::NOT_FOUND);

        let webchat_directline = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/v1/messaging/webchat/demo/token"),
                test_state(vec![]),
            ))
            .unwrap_err();
        assert_eq!(webchat_directline.status(), StatusCode::BAD_REQUEST);

        let webchat_directline_web_route = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/v1/web/webchat/demo/token"),
                test_state(vec![]),
            ))
            .unwrap_err();
        assert_eq!(
            webchat_directline_web_route.status(),
            StatusCode::BAD_REQUEST
        );
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
            public_base_url: None,
        })
        .expect("start ingress server");

        assert!(server.ui_urls.is_empty());
        if let Err(err) = server.stop() {
            let message = err.to_string();
            assert!(
                message.contains("failed to bind ingress listener")
                    || message.contains("Operation not permitted"),
                "stop ingress server: {message}"
            );
        }
    }

    #[test]
    fn http_ingress_server_fails_fast_when_all_ports_occupied() {
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

        // Occupy a contiguous block of ports so port cycling exhausts the range.
        let base = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let base_port = base.local_addr().unwrap().port();
        let mut _holders = vec![base];
        for offset in 1..=10u16 {
            if let Ok(listener) =
                std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, base_port + offset))
            {
                _holders.push(listener);
            }
        }

        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, base_port));

        let err = match HttpIngressServer::start(HttpIngressConfig {
            bind_addr: addr,
            domains: vec![Domain::Messaging],
            runner_host,
            enable_static_routes: false,
            tenant: "demo".to_string(),
            public_base_url: None,
        }) {
            Ok(_) => panic!("occupied port range should fail ingress startup"),
            Err(err) => err,
        };

        let message = err.to_string();
        assert!(
            message.contains("no available port found")
                || message.contains("failed to find available port"),
            "unexpected error: {message}"
        );
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
            http_route_table: HttpRouteTable::default(),
            admin_relay: None,
            notifier: crate::notifier::build_notifier(crate::notifier::NotifierConfig::default()),
            session_manager: Arc::new(websocket::SessionManager::new(
                websocket::WsLimits::default(),
            )),
            webchat_provider: "messaging-webchat".to_string(),
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
            http_route_table: HttpRouteTable::default(),
            admin_relay: None,
            notifier: crate::notifier::build_notifier(crate::notifier::NotifierConfig::default()),
            session_manager: Arc::new(websocket::SessionManager::new(
                websocket::WsLimits::default(),
            )),
            webchat_provider: "messaging-webchat".to_string(),
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
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

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

    #[test]
    fn parse_webchat_directline_route_accepts_messaging_and_web_prefixes() {
        let token_messaging = parse_webchat_directline_route("/v1/messaging/webchat/demo/token");
        assert_eq!(
            token_messaging,
            Some(("demo".to_string(), "/token".to_string()))
        );

        let token_web = parse_webchat_directline_route("/v1/web/webchat/demo/token");
        assert_eq!(token_web, Some(("demo".to_string(), "/token".to_string())));

        let dl_web =
            parse_webchat_directline_route("/v1/web/webchat/demo/v3/directline/conversations");
        assert_eq!(
            dl_web,
            Some((
                "demo".to_string(),
                "/v3/directline/conversations".to_string()
            ))
        );
    }

    #[test]
    fn normalize_directline_dispatch_maps_token_alias_to_canonical_endpoint() {
        let (method, path) = normalize_directline_dispatch(&Method::GET, "/token");
        assert_eq!(method, Method::POST);
        assert_eq!(path, "/v3/directline/tokens/generate");

        let (method, path) =
            normalize_directline_dispatch(&Method::POST, "/directline/conversations");
        assert_eq!(method, Method::POST);
        assert_eq!(path, "/v3/directline/conversations");
    }

    #[test]
    fn augment_directline_queries_injects_tenant_and_team_when_missing() {
        let augmented = augment_directline_queries(
            &[("env".into(), "default".into())],
            "demo",
            Some("default"),
        );
        assert!(
            augmented
                .iter()
                .any(|(name, value)| name == "env" && value == "default")
        );
        assert!(
            augmented
                .iter()
                .any(|(name, value)| name == "tenant" && value == "demo")
        );
        assert!(
            augmented
                .iter()
                .any(|(name, value)| name == "team" && value == "default")
        );

        let preserved = augment_directline_queries(
            &[
                ("tenant".into(), "custom".into()),
                ("team".into(), "ops".into()),
            ],
            "demo",
            Some("default"),
        );
        assert!(
            preserved
                .iter()
                .any(|(name, value)| name == "tenant" && value == "custom")
        );
        assert!(
            preserved
                .iter()
                .any(|(name, value)| name == "team" && value == "ops")
        );
        assert_eq!(
            preserved
                .iter()
                .filter(|(name, _)| name == "tenant")
                .count(),
            1
        );
        assert_eq!(
            preserved.iter().filter(|(name, _)| name == "team").count(),
            1
        );
    }

    #[test]
    fn encode_directline_query_string_serializes_pairs() {
        assert_eq!(encode_directline_query_string(&[]), None);
        assert_eq!(
            encode_directline_query_string(&[
                ("env".into(), "default".into()),
                ("tenant".into(), "demo space".into()),
                ("team".into(), "blue/ops".into()),
            ]),
            Some("env=default&tenant=demo%20space&team=blue%2Fops".to_string())
        );
        assert_eq!(
            percent_encode_query_component("a+b&c=d"),
            "a%2Bb%26c%3Dd".to_string()
        );
    }
}
