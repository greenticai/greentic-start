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
use hyper::{Request, body::Incoming};

/// Proxy OAuth token exchange to external provider (avoids browser CORS).
/// Frontend POSTs JSON: { token_url, code, redirect_uri, client_id, code_verifier }
/// Server forwards as form-urlencoded POST to token_url, returns the response.
pub(super) async fn handle_oauth_token_exchange(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
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
