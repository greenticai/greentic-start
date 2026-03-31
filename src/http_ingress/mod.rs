mod directline_handler;
mod helpers;
mod messaging;
mod static_handler;

use std::{convert::Infallible, net::SocketAddr, sync::Arc, thread};

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    server::conn::http1::Builder as Http1Builder,
    service::service_fn,
};
use hyper_util::rt::tokio::TokioIo;
use tokio::{net::TcpListener, runtime::Runtime, sync::oneshot};

use crate::domains::Domain;
use crate::ingress_dispatch::dispatch_http_ingress;
use crate::ingress_types::IngressRequestV1;
use crate::operator_log;
use crate::runner_host::{DemoRunnerHost, OperatorContext};
use crate::static_routes::{ActiveRouteTable, ReservedRouteSet, discover_from_bundle};

use directline_handler::{handle_directline_request, parse_webchat_directline_route};
use helpers::{
    build_http_response, collect_headers, collect_queries, cors_preflight_response, domain_name,
    error_response, handle_builtin_health_request, handle_oauth_token_exchange,
    parse_route_segments, with_cors,
};
use messaging::route_messaging_envelopes;
use static_handler::serve_static_route;

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
                for route in table.routes() {
                    if route.public_path.contains("webchat") {
                        let url_path = route.public_path.replace("{tenant}", &config.tenant);
                        let webchat_url = format!(
                            "WebChat GUI: http://{}/{}/",
                            config.bind_addr,
                            url_path.trim_start_matches('/')
                        );
                        eprintln!("{webchat_url}");
                        operator_log::info(module_path!(), &webchat_url);
                    }
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
            dl_state: crate::directline::DirectLineState::new(),
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
    dl_state: crate::directline::DirectLineState,
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

    if let Some(response) = handle_builtin_health_request(req.method(), &path) {
        return Ok(response);
    }

    if path.starts_with("/api/onboard") {
        return crate::onboard::api::handle_onboard_request(req, &path, &state.runner_host)
            .await
            .map_err(|err| *err);
    }

    // Legacy Direct Line routes (root level)
    if path == "/token" || path.starts_with("/v3/directline") || path.starts_with("/directline") {
        return handle_directline_request(req, &path, None, state).await;
    }

    // OAuth token exchange proxy: /v1/messaging/webchat/{tenant}/oauth/token-exchange
    if path.contains("/oauth/token-exchange") && req.method() == Method::POST {
        return handle_oauth_token_exchange(req).await;
    }

    // WebChat Direct Line routes: /v1/messaging/webchat/{tenant}/token or /v1/messaging/webchat/{tenant}/v3/directline/*
    if let Some((tenant, dl_path)) = parse_webchat_directline_route(&path) {
        return handle_directline_request(req, &dl_path, Some(tenant), state).await;
    }

    // Static route handling - serve assets from .gtpack files
    if let Some(route_match) = state.active_route_table.match_request(&path) {
        return Ok(serve_static_route(
            &route_match,
            state.runner_host.bundle_root(),
            &path,
        ));
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

#[cfg(test)]
mod tests {
    use super::helpers::{handle_builtin_health_request, parse_route_segments};
    use crate::domains::Domain;
    use hyper::{Method, StatusCode};

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
}
