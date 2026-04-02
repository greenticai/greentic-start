mod directline_handler;
mod helpers;
mod messaging;
mod static_handler;

use std::{convert::Infallible, net::SocketAddr, sync::Arc, thread};

use anyhow::{Context, Result};
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
    /// WebChat GUI URLs discovered from static routes during startup.
    pub webchat_urls: Vec<String>,
}

impl HttpIngressServer {
    pub fn start(config: HttpIngressConfig) -> Result<Self> {
        let debug_enabled = config.runner_host.debug_enabled();
        let domains = config.domains;
        let runner_host = config.runner_host;

        // Discover static routes if enabled
        let mut webchat_urls = Vec::new();
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
                            "http://{}/{}/",
                            config.bind_addr,
                            url_path.trim_start_matches('/')
                        );
                        operator_log::info(module_path!(), format!("WebChat GUI: {webchat_url}"));
                        webchat_urls.push(webchat_url);
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
            webchat_urls,
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

    // Legacy Direct Line routes (root level)
    if path == "/token" || path.starts_with("/v3/directline") || path.starts_with("/directline") {
        return handle_directline_request(req, &path, None, None, state).await;
    }

    // OAuth token exchange proxy: /v1/messaging/webchat/{tenant}/oauth/token-exchange
    if path.contains("/oauth/token-exchange") && req.method() == Method::POST {
        return handle_oauth_token_exchange(req).await;
    }

    // WebChat Direct Line routes: /v1/messaging/webchat/{tenant}/token or /v1/messaging/webchat/{tenant}/v3/directline/*
    if let Some((tenant, dl_path)) = parse_webchat_directline_route(&path) {
        let provider = state
            .active_route_table
            .match_request(&path)
            .map(|route_match| route_match.descriptor.pack_id.clone());
        return handle_directline_request(req, &dl_path, Some(tenant), provider, state).await;
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
            dl_state: crate::directline::DirectLineState::new(),
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

        let webchat_directline = runtime
            .block_on(handle_request_inner(
                empty_request(Method::GET, "/v1/messaging/webchat/demo/token"),
                test_state(vec![]),
            ))
            .unwrap_err();
        assert_eq!(webchat_directline.status(), StatusCode::NOT_FOUND);
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

        assert!(server.webchat_urls.is_empty());
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
            dl_state: crate::directline::DirectLineState::new(),
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
            public_path: "/v1/messaging/webchat/{tenant}".to_string(),
            source_root: "site".to_string(),
            index_file: Some("index.html".to_string()),
            spa_fallback: Some("index.html".to_string()),
            tenant_scoped: true,
            team_scoped: false,
            cache_strategy: CacheStrategy::None,
            route_segments: vec![
                RouteScopeSegment::Literal("v1".to_string()),
                RouteScopeSegment::Literal("messaging".to_string()),
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
            dl_state: crate::directline::DirectLineState::new(),
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
}
