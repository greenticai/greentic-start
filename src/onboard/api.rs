use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
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
pub async fn handle_onboard_request(
    req: Request<Incoming>,
    path: &str,
    runner_host: &Arc<DemoRunnerHost>,
) -> OnboardResult {
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
async fn read_json_body(req: Request<Incoming>) -> OnboardResult<Value> {
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
