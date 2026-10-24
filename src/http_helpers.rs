//! Pure HTTP helper functions shared by both the legacy `http_ingress` server
//! and the revision-path `revision_serve` runtime.
//!
//! Hoisted from `http_ingress/helpers.rs` (A.1) so both runtimes can reuse
//! CORS, response building, header/query collection, health endpoints, and
//! route parsing without pulling in any `DemoRunnerHost`-coupled code.

use http_body_util::Full;
use hyper::{
    Method, Response, StatusCode,
    body::Bytes,
    header::{CONTENT_TYPE, HeaderName, HeaderValue},
};
use serde_json::json;

use crate::ingress_types::IngressHttpResponse;

const CORS_ALLOW_METHODS: &str = "GET, POST, OPTIONS";
const CORS_ALLOW_HEADERS: &str =
    "Content-Type, Authorization, X-Requested-With, x-ms-bot-agent, X-Greentic-Locale";

pub(crate) fn cors_preflight_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", CORS_ALLOW_METHODS)
        .header("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)
        .header("Access-Control-Max-Age", "86400")
        .body(Full::from(Bytes::new()))
        .unwrap_or_else(|_| {
            let mut response = Response::new(Full::from(Bytes::new()));
            *response.status_mut() = StatusCode::NO_CONTENT;
            response
        })
}

pub(crate) fn with_cors(mut response: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
    let headers = response.headers_mut();
    headers.insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
    headers.insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static(CORS_ALLOW_METHODS),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        HeaderValue::from_static(CORS_ALLOW_HEADERS),
    );
    response
}

pub(crate) fn build_http_response(
    response: &IngressHttpResponse,
) -> Result<Response<Full<Bytes>>, String> {
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

pub(crate) fn collect_headers(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
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

pub(crate) fn collect_queries(query: Option<&str>) -> Vec<(String, String)> {
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

pub(crate) fn error_response(
    status: StatusCode,
    message: impl Into<String>,
) -> Response<Full<Bytes>> {
    let body = json!({
        "success": false,
        "message": message.into()
    });
    json_response(status, body)
}

pub(crate) fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::from(Bytes::from(body)))
        .unwrap_or_else(|err| {
            let mut response = Response::new(Full::from(Bytes::from(format!(
                "failed to build response: {err}"
            ))));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        })
}

pub(crate) fn handle_builtin_health_request(
    method: &Method,
    path: &str,
) -> Option<Response<Full<Bytes>>> {
    if method != Method::GET {
        return None;
    }
    match path {
        "/healthz" => Some(json_response(
            StatusCode::OK,
            json!({ "status": "healthy" }),
        )),
        "/readyz" => Some(json_response(StatusCode::OK, json!({ "status": "ready" }))),
        "/status" => Some(json_response(
            StatusCode::OK,
            json!({
                "status": "running",
                "telemetry": crate::otlp_status::snapshot_json(),
            }),
        )),
        _ => None,
    }
}

use http_body_util::BodyExt;
use hyper::{Request, body::Body};

/// Proxy OAuth token exchange to external provider (avoids browser CORS).
/// Frontend POSTs JSON: { token_url, code, redirect_uri, client_id, code_verifier }
/// Server forwards as form-urlencoded POST to token_url, returns the response.
pub(crate) async fn handle_oauth_token_exchange<B>(
    req: Request<B>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let body_bytes = read_body_capped(req.into_body(), OAUTH_EXCHANGE_MAX_BODY_BYTES).await?;

    let body: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, format!("invalid json: {e}")))?;

    let token_url = body["token_url"]
        .as_str()
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "missing token_url"))?;
    let code = body["code"].as_str().unwrap_or("");
    let redirect_uri = body["redirect_uri"].as_str().unwrap_or("");
    let client_id = body["client_id"].as_str().unwrap_or("");
    let client_secret = body["client_secret"].as_str().unwrap_or("");
    let code_verifier = body["code_verifier"].as_str().unwrap_or("");

    // The caller names the endpoint, so it must not reach internal services.
    if !token_url_is_allowed(token_url) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "token_url must be an https URL on a public host",
        ));
    }

    // Close the DNS-rebinding gap the syntactic check leaves: every address the
    // host resolves to must be public.
    if !token_host_resolves_public(token_url).await {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "token_url must be an https URL on a public host",
        ));
    }

    fn encode(s: &str) -> String {
        // Percent-encode per UTF-8 byte; casting a `char` to `u8` would
        // truncate every non-ASCII code point.
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    char::from(b).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }
    let mut form_body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        encode(code),
        encode(redirect_uri),
        encode(client_id),
        encode(code_verifier),
    );
    if !client_secret.is_empty() {
        form_body.push_str(&format!("&client_secret={}", encode(client_secret)));
    }

    let token_url_owned = token_url.to_string();
    let result = tokio::task::spawn_blocking(move || {
        // No redirects: a public endpoint must not bounce the request to an
        // internal address after the host check above.
        let agent = ureq::Agent::config_builder()
            .max_redirects(0)
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build()
            .new_agent();
        agent
            .post(&token_url_owned)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .send(form_body.as_bytes())
    })
    .await;

    match result {
        Ok(Ok(mut response)) => {
            let status = response.status().as_u16();
            let response_body = response
                .body_mut()
                .read_to_string()
                .unwrap_or_else(|_| "{}".to_string());
            let http_status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            Ok(with_cors(
                Response::builder()
                    .status(http_status)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(response_body)))
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))),
            ))
        }
        Ok(Err(err)) => {
            let error_body = serde_json::json!({
                "error": "token_exchange_failed",
                "error_description": err.to_string()
            });
            Ok(with_cors(
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(error_body.to_string())))
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))),
            ))
        }
        Err(err) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("proxy error: {err}"),
        )),
    }
}

/// Cap on the JSON body accepted by the OAuth token-exchange proxy.
const OAUTH_EXCHANGE_MAX_BODY_BYTES: usize = 64 * 1024;

/// Read a request body up to `cap` bytes. Over the cap is `413`; a body that
/// breaks off mid-read is `400` (never silently treated as empty).
pub(crate) async fn read_body_capped<B>(
    mut body: B,
    cap: usize,
) -> Result<Bytes, Response<Full<Bytes>>>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| {
            error_response(
                StatusCode::BAD_REQUEST,
                "the request body could not be read",
            )
        })?;
        if let Ok(data) = frame.into_data() {
            if buf.len().saturating_add(data.len()) > cap {
                return Err(error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds the size limit",
                ));
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(buf))
}

/// True when `raw` is an `https` URL whose host is not loopback, private,
/// link-local or a local-only name. A hostname is not resolved here (see
/// `token_host_resolves_public` for that).
fn token_url_is_allowed(raw: &str) -> bool {
    let Ok(uri) = raw.parse::<hyper::Uri>() else {
        return false;
    };
    if uri.scheme_str() != Some("https") {
        return false;
    }
    let Some(host) = uri.host() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return crate::artifacts::dns::is_public_ip(ip);
    }
    let lower = host.trim_end_matches('.').to_ascii_lowercase();
    // The system resolver accepts inet_aton shorthands (`127.1`, `0x7f.1`,
    // `017.0.0.1`) that `IpAddr` refuses to parse; a real TLD is never numeric.
    let last_label = lower.rsplit('.').next().unwrap_or("");
    let numeric_tail = !last_label.is_empty()
        && (last_label.bytes().all(|b| b.is_ascii_digit())
            || last_label
                .strip_prefix("0x")
                .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit())));
    if numeric_tail {
        return false;
    }
    !(lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || !lower.contains('.'))
}

/// Resolve the host of an (already syntactically vetted) URL and require ALL
/// addresses to be public. IP literals were judged by `token_url_is_allowed`.
/// A residual race remains between this lookup and the HTTP client's own.
async fn token_host_resolves_public(raw: &str) -> bool {
    use crate::artifacts::dns::{Lookup, SystemLookup};
    let Some(host) = raw
        .parse::<hyper::Uri>()
        .ok()
        .and_then(|uri| uri.host().map(str::to_string))
    else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    match SystemLookup.lookup(host).await {
        Ok(addrs) => {
            !addrs.is_empty()
                && addrs
                    .iter()
                    .all(|a| crate::artifacts::dns::is_public_ip(a.ip()))
        }
        Err(_) => false,
    }
}

use crate::domains::Domain;

pub(crate) fn parse_domain(value: &str) -> Option<Domain> {
    match value.to_lowercase().as_str() {
        "messaging" => Some(Domain::Messaging),
        "events" => Some(Domain::Events),
        "secrets" => Some(Domain::Secrets),
        "oauth" => Some(Domain::OAuth),
        _ => None,
    }
}

pub(crate) fn domain_name(domain: Domain) -> &'static str {
    match domain {
        Domain::Messaging => "messaging",
        Domain::Events => "events",
        Domain::Secrets => "secrets",
        Domain::OAuth => "oauth",
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedIngressRoute {
    pub domain: Domain,
    pub provider: String,
    pub tenant: String,
    pub team: String,
    pub handler: Option<String>,
}

impl From<crate::http_routes::HttpRouteMatch<'_>> for ParsedIngressRoute {
    fn from(m: crate::http_routes::HttpRouteMatch<'_>) -> Self {
        Self {
            domain: m.descriptor.domain,
            provider: m.descriptor.pack_id.clone(),
            tenant: m.tenant,
            team: m.team,
            handler: None,
        }
    }
}

pub(crate) fn parse_route_segments(path: &str) -> Option<ParsedIngressRoute> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use hyper::header::{CONTENT_TYPE, HeaderValue};

    #[test]
    fn cors_helpers_attach_expected_headers() {
        let preflight = cors_preflight_response();
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            preflight.headers()["Access-Control-Allow-Origin"],
            HeaderValue::from_static("*")
        );

        let response = with_cors(Response::new(Full::from(Bytes::from("ok"))));
        assert_eq!(
            response.headers()["Access-Control-Allow-Methods"],
            HeaderValue::from_static("GET, POST, OPTIONS")
        );
    }

    #[test]
    fn build_http_response_defaults_content_type_and_skips_invalid_headers() {
        let response = build_http_response(&IngressHttpResponse {
            status: 201,
            headers: vec![
                ("x-test".to_string(), "yes".to_string()),
                ("bad header".to_string(), "ignored".to_string()),
            ],
            body: Some(b"{\"ok\":true}".to_vec()),
        })
        .expect("response");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            HeaderValue::from_static("application/json")
        );
        assert_eq!(
            response.headers()["x-test"],
            HeaderValue::from_static("yes")
        );
        assert!(response.headers().get("bad header").is_none());
    }

    #[test]
    fn collect_helpers_preserve_only_valid_values() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-tenant", HeaderValue::from_static("demo"));
        let collected = collect_headers(&headers);
        assert_eq!(
            collected,
            vec![("x-tenant".to_string(), "demo".to_string())]
        );

        let queries = collect_queries(Some("tenant=demo&&empty=&team=blue%20sky&novalue"));
        assert_eq!(
            queries,
            vec![
                ("tenant".to_string(), "demo".to_string()),
                ("empty".to_string(), "".to_string()),
                ("team".to_string(), "blue%20sky".to_string()),
                ("novalue".to_string(), "".to_string()),
            ]
        );
    }

    #[test]
    fn token_url_allowlist_rejects_internal_targets() {
        assert!(token_url_is_allowed("https://oauth2.googleapis.com/token"));
        assert!(!token_url_is_allowed("http://oauth2.googleapis.com/token"));
        assert!(!token_url_is_allowed("https://127.0.0.1/token"));
        assert!(!token_url_is_allowed("https://169.254.169.254/latest"));
        assert!(!token_url_is_allowed("https://[::1]/token"));
        assert!(!token_url_is_allowed("https://localhost/token"));
        assert!(!token_url_is_allowed("https://metadata.internal/token"));
        assert!(!token_url_is_allowed("https://intranet/token"));
        assert!(!token_url_is_allowed("https://127.1/token"));
        assert!(!token_url_is_allowed("https://0x7f.0x1/token"));
        assert!(!token_url_is_allowed("https://10.0.1/token"));
        assert!(!token_url_is_allowed("not a url"));
    }

    #[test]
    fn token_url_allowlist_rejects_private_ranges_and_local_names() {
        assert!(!token_url_is_allowed("https://10.0.0.5/token"));
        assert!(!token_url_is_allowed("https://192.168.1.1/token"));
        assert!(!token_url_is_allowed("https://localhost./token"));
        assert!(!token_url_is_allowed("https://api.localhost/token"));
        assert!(!token_url_is_allowed("https://printer.local/token"));
        assert!(!token_url_is_allowed("/relative/token"));
        assert!(token_url_is_allowed(
            "https://login.microsoftonline.com/x/oauth2/v2.0/token"
        ));
    }

    #[test]
    fn read_body_capped_refuses_oversize_bodies() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let ok = runtime
            .block_on(read_body_capped(Full::new(Bytes::from_static(b"abcd")), 4))
            .expect("within cap");
        assert_eq!(ok.as_ref(), b"abcd");
        let err = runtime
            .block_on(read_body_capped(Full::new(Bytes::from_static(b"abcde")), 4))
            .expect_err("over cap");
        assert_eq!(err.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn builtin_health_and_domain_parsing_cover_known_routes() {
        assert!(handle_builtin_health_request(&Method::POST, "/healthz").is_none());
        assert!(handle_builtin_health_request(&Method::GET, "/unknown").is_none());
        assert_eq!(parse_domain("Messaging"), Some(Domain::Messaging));
        assert_eq!(domain_name(Domain::OAuth), "oauth");
    }

    #[test]
    fn route_parsing_supports_v1_and_legacy_variants() {
        let v1 = parse_route_segments("/v1/messaging/ingress/provider/demo/team-a/hook")
            .expect("v1 route");
        assert_eq!(v1.team, "team-a");
        assert_eq!(v1.handler.as_deref(), Some("hook"));

        let legacy = parse_route_segments("/events/ingress/provider/demo").expect("legacy route");
        assert_eq!(legacy.team, "default");
        assert_eq!(legacy.handler, None);

        assert!(parse_route_segments("/v1/events/provider/demo").is_none());
        assert!(parse_route_segments("/unknown/ingress/provider/demo").is_none());
    }

    #[test]
    fn error_and_json_responses_emit_json_bodies() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let error = error_response(StatusCode::BAD_REQUEST, "bad request");
        let json = json_response(StatusCode::OK, json!({"status": "ok"}));

        let error_body =
            runtime.block_on(async { error.into_body().collect().await.expect("body").to_bytes() });
        let json_body =
            runtime.block_on(async { json.into_body().collect().await.expect("body").to_bytes() });

        assert!(String::from_utf8_lossy(&error_body).contains("\"bad request\""));
        assert!(String::from_utf8_lossy(&json_body).contains("\"status\":\"ok\""));
    }
}
