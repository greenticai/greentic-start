use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Bytes},
    header::CONTENT_TYPE,
};
use serde_json::{Value, json};

use crate::runner_host::DemoRunnerHost;

use super::providers;
use super::wizard;

/// Shared state for onboard API handlers.
pub struct OnboardState {
    pub runner_host: Arc<DemoRunnerHost>,
}

pub type OnboardResponse = Response<Full<Bytes>>;
pub type OnboardError = Box<OnboardResponse>;
pub type OnboardResult<T = OnboardResponse> = Result<T, OnboardError>;

pub fn into_error(response: OnboardResponse) -> OnboardError {
    Box::new(response)
}

/// Dispatch onboard API requests.
///
/// Routes:
///   GET  /api/onboard/providers   → list available provider packs
///   GET  /api/onboard/tenants     → list tenants
///   GET  /api/onboard/status      → deployment status
///   POST /api/onboard/qa/spec     → get FormSpec for a provider
///   POST /api/onboard/qa/validate → validate partial answers
///   POST /api/onboard/qa/submit   → submit answers → deploy
pub async fn handle_onboard_request<B>(
    req: Request<B>,
    path: &str,
    runner_host: &Arc<DemoRunnerHost>,
) -> OnboardResult
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let state = OnboardState {
        runner_host: runner_host.clone(),
    };

    let method = req.method().clone();
    let sub_path = path
        .strip_prefix("/api/onboard")
        .unwrap_or("")
        .trim_end_matches('/');

    match (method, sub_path) {
        (Method::GET, "/providers") => providers::list_providers(&state),
        (Method::GET, "/tenants") => providers::list_tenants(&state),
        (Method::GET, "/status") => providers::deployment_status(&state),
        (Method::POST, "/qa/spec") => {
            let body = read_json_body(req).await?;
            wizard::get_form_spec(&state, &body)
        }
        (Method::POST, "/qa/validate") => {
            let body = read_json_body(req).await?;
            wizard::validate_answers(&state, &body)
        }
        (Method::POST, "/qa/submit") => {
            let body = read_json_body(req).await?;
            // Run on a dedicated thread to avoid nested Tokio runtime panics.
            // submit_answers → invoke_provider_op → run_pack_with_options
            // all create their own Runtime::new(), which panics on a Tokio worker.
            std::thread::scope(|s| {
                s.spawn(|| wizard::submit_answers(&state, &body))
                    .join()
                    .expect("submit thread panicked")
            })
        }
        (Method::POST, "/tenants/create") => {
            let body = read_json_body(req).await?;
            providers::create_tenant(&state, &body)
        }
        (Method::POST, "/tenants/teams/create") => {
            let body = read_json_body(req).await?;
            providers::create_team(&state, &body)
        }
        _ => Err(into_error(error_response(
            StatusCode::NOT_FOUND,
            format!("unknown onboard endpoint: {sub_path}"),
        ))),
    }
}

/// Read and parse a JSON body from the request.
async fn read_json_body<B>(req: Request<B>) -> OnboardResult<Value>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let payload_bytes = req
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|err| {
            into_error(error_response(
                StatusCode::BAD_REQUEST,
                format!("read body: {err}"),
            ))
        })?;

    if payload_bytes.is_empty() {
        return Ok(json!({}));
    }

    serde_json::from_slice(&payload_bytes).map_err(|err| {
        into_error(error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid JSON: {err}"),
        ))
    })
}

pub fn json_ok(value: Value) -> OnboardResult {
    Ok(json_response(StatusCode::OK, value))
}

pub fn json_response(status: StatusCode, value: Value) -> OnboardResponse {
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

pub fn error_response(status: StatusCode, message: impl Into<String>) -> OnboardResponse {
    json_response(
        status,
        json!({
            "success": false,
            "message": message.into()
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery;
    use crate::runner_host::DemoRunnerHost;
    use crate::secrets_gate;
    use http_body_util::BodyExt;
    use tempfile::tempdir;
    use tokio::runtime::Runtime;

    fn test_runner_host(root: &std::path::Path) -> Arc<DemoRunnerHost> {
        let discovery = discovery::discover(root).unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(root, "demo", Some("default")).unwrap();
        Arc::new(
            DemoRunnerHost::new(root.to_path_buf(), &discovery, None, secrets_handle, false)
                .unwrap(),
        )
    }

    fn request(method: Method, path: &str, body: Option<&str>) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Full::from(Bytes::from(
                body.unwrap_or_default().to_string(),
            )))
            .unwrap()
    }

    fn response_json(response: OnboardResponse) -> Value {
        let bytes = Runtime::new()
            .unwrap()
            .block_on(response.into_body().collect())
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn error_json(err: OnboardResponse) -> Value {
        response_json(err)
    }

    #[test]
    fn read_json_body_accepts_empty_and_rejects_invalid_json() {
        let runtime = Runtime::new().unwrap();

        let empty = runtime
            .block_on(read_json_body(request(
                Method::POST,
                "/api/onboard/qa/spec",
                None,
            )))
            .unwrap();
        assert_eq!(empty, json!({}));

        let invalid = runtime
            .block_on(read_json_body(request(
                Method::POST,
                "/api/onboard/qa/spec",
                Some("{not-json"),
            )))
            .unwrap_err();
        assert_eq!(
            error_json(*invalid)["message"],
            "invalid JSON: key must be a string at line 1 column 2"
        );
    }

    #[test]
    fn response_helpers_emit_json_status_and_messages() {
        let ok = json_ok(json!({"status": "ok"})).unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(ok.headers().get(CONTENT_TYPE).unwrap(), "application/json");
        assert_eq!(response_json(ok)["status"], "ok");

        let err = error_response(StatusCode::BAD_REQUEST, "boom");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(err)["message"], "boom");
    }

    #[test]
    fn handle_onboard_request_routes_unknown_and_tenant_endpoints() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let runner_host = test_runner_host(dir.path());

        let unknown = runtime
            .block_on(handle_onboard_request(
                request(Method::GET, "/api/onboard/nope", None),
                "/api/onboard/nope",
                &runner_host,
            ))
            .unwrap_err();
        assert_eq!(
            error_json(*unknown)["message"],
            "unknown onboard endpoint: /nope"
        );

        let tenants = runtime
            .block_on(handle_onboard_request(
                request(Method::GET, "/api/onboard/tenants", None),
                "/api/onboard/tenants",
                &runner_host,
            ))
            .unwrap();
        assert_eq!(tenants.status(), StatusCode::OK);
        assert!(
            response_json(tenants)["tenants"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["tenant"] == "default")
        );

        let create_tenant = runtime
            .block_on(handle_onboard_request(
                request(
                    Method::POST,
                    "/api/onboard/tenants/create",
                    Some(r#"{"tenant":"north"}"#),
                ),
                "/api/onboard/tenants/create",
                &runner_host,
            ))
            .unwrap();
        assert!(
            response_json(create_tenant)["tenants"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["tenant"] == "north")
        );

        let create_team = runtime
            .block_on(handle_onboard_request(
                request(
                    Method::POST,
                    "/api/onboard/tenants/teams/create",
                    Some(r#"{"tenant":"north","team":"ops"}"#),
                ),
                "/api/onboard/tenants/teams/create",
                &runner_host,
            ))
            .unwrap();
        let north = response_json(create_team)["tenants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["tenant"] == "north")
            .unwrap()
            .clone();
        assert!(
            north["teams"]
                .as_array()
                .unwrap()
                .iter()
                .any(|team| team == "ops")
        );
    }

    #[test]
    fn handle_onboard_request_rejects_invalid_json_for_post_routes() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let runner_host = test_runner_host(dir.path());

        let err = runtime
            .block_on(handle_onboard_request(
                request(Method::POST, "/api/onboard/tenants/create", Some("{bad")),
                "/api/onboard/tenants/create",
                &runner_host,
            ))
            .unwrap_err();
        assert_eq!(
            error_json(*err)["message"],
            "invalid JSON: key must be a string at line 1 column 2"
        );
    }
}
