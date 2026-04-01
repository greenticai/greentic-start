use http_body_util::Full;
use hyper::{
    Method, Response, StatusCode,
    body::Bytes,
    header::{CONTENT_TYPE, HeaderName, HeaderValue},
};
use serde_json::json;

use crate::ingress_types::IngressHttpResponse;

pub(super) fn cors_preflight_response() -> Response<Full<Bytes>> {
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

pub(super) fn with_cors(mut response: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
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

pub(super) fn build_http_response(
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

pub(super) fn collect_headers(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
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

pub(super) fn collect_queries(query: Option<&str>) -> Vec<(String, String)> {
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

pub(super) fn error_response(
    status: StatusCode,
    message: impl Into<String>,
) -> Response<Full<Bytes>> {
    let body = json!({
        "success": false,
        "message": message.into()
    });
    json_response(status, body)
}

pub(super) fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Full<Bytes>> {
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

pub(super) fn handle_builtin_health_request(
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
            json!({ "status": "running" }),
        )),
        _ => None,
    }
}

use http_body_util::BodyExt;
use hyper::{Request, body::Body};

/// Proxy OAuth token exchange to external provider (avoids browser CORS).
/// Frontend POSTs JSON: { token_url, code, redirect_uri, client_id, code_verifier }
/// Server forwards as form-urlencoded POST to token_url, returns the response.
pub(super) async fn handle_oauth_token_exchange<B>(
    req: Request<B>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();

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

    fn encode(s: &str) -> String {
        s.chars()
            .map(|c| match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
                _ => format!("%{:02X}", c as u8),
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
        ureq::post(&token_url_owned)
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

use crate::domains::Domain;

pub(super) fn parse_domain(value: &str) -> Option<Domain> {
    match value.to_lowercase().as_str() {
        "messaging" => Some(Domain::Messaging),
        "events" => Some(Domain::Events),
        "secrets" => Some(Domain::Secrets),
        "oauth" => Some(Domain::OAuth),
        _ => None,
    }
}

pub(super) fn domain_name(domain: Domain) -> &'static str {
    match domain {
        Domain::Messaging => "messaging",
        Domain::Events => "events",
        Domain::Secrets => "secrets",
        Domain::OAuth => "oauth",
    }
}

#[derive(Clone, Debug)]
pub(super) struct ParsedIngressRoute {
    pub domain: Domain,
    pub provider: String,
    pub tenant: String,
    pub team: String,
    pub handler: Option<String>,
}

pub(super) fn parse_route_segments(path: &str) -> Option<ParsedIngressRoute> {
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
