//! DirectLine WebSocket streaming endpoint.

pub mod protocol;
pub mod pump;
pub mod session;
pub mod upgrade;

#[allow(unused_imports)]
pub use pump::{ActivitySource, Pump, PumpError, PumpFrame};
#[allow(unused_imports)]
pub use session::{SessionError, SessionGuard, SessionManager, WsLimits};
#[allow(unused_imports)]
pub use upgrade::{UpgradeContext, UpgradeError, refusal_response, validate_request_parts};

use crate::domains::Domain;
use crate::notifier::ActivityNotifier;
use crate::runner_host::{DemoRunnerHost, OperatorContext};
use async_trait::async_trait;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use hyper_tungstenite::tungstenite::Message;
use protocol::{ActivitySet, ErrorFrame};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Minimal trait surface the source needs from the runtime host.
///
/// This is implemented for [`DemoRunnerHost`] in `greentic-start`. Tests in the
/// websocket module substitute their own implementation to avoid pulling in
/// the full demo host.
pub trait RunnerHostHandle: Send + Sync + 'static {
    /// Synchronously invoke `directline_http` GET on the named provider and
    /// return the parsed JSON body.
    fn invoke_directline_get_activities(
        &self,
        tenant: &str,
        team: &str,
        provider: &str,
        conversation_id: &str,
        watermark: u64,
    ) -> Result<Value, String>;
}

impl RunnerHostHandle for DemoRunnerHost {
    fn invoke_directline_get_activities(
        &self,
        tenant: &str,
        team: &str,
        provider: &str,
        conversation_id: &str,
        watermark: u64,
    ) -> Result<Value, String> {
        let payload = serde_json::json!({
            "v": 1,
            "provider": provider,
            "route": serde_json::Value::Null,
            "binding_id": serde_json::Value::Null,
            "tenant_hint": tenant,
            "team_hint": team,
            "method": "GET",
            "path": format!("/v3/directline/conversations/{conversation_id}/activities"),
            "query": format!("watermark={watermark}&tenant={tenant}&team={team}"),
            "headers": [],
            "body_b64": "",
            "config": serde_json::Value::Null,
        });
        let payload_bytes = serde_json::to_vec(&payload).map_err(|err| err.to_string())?;
        let ctx = OperatorContext {
            tenant: tenant.to_string(),
            team: Some(team.to_string()),
            correlation_id: None,
        };
        let outcome = self
            .invoke_provider_op(
                Domain::Messaging,
                provider,
                "directline_http",
                &payload_bytes,
                &ctx,
            )
            .map_err(|err| err.to_string())?;
        if !outcome.success {
            return Err(outcome
                .error
                .or(outcome.raw)
                .unwrap_or_else(|| "provider directline_http failed".to_string()));
        }
        let value = outcome
            .output
            .ok_or_else(|| "directline_http returned no output".to_string())?;
        let body_b64 = value
            .get("body_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing body_b64 in directline_http response".to_string())?;
        let body_bytes = base64::engine::general_purpose::STANDARD
            .decode(body_b64.as_bytes())
            .map_err(|err| format!("invalid base64 body_b64: {err}"))?;
        // Empty body -> empty object so callers can keep consistent shape.
        if body_bytes.is_empty() {
            return Ok(serde_json::json!({"activities": [], "watermark": watermark.to_string()}));
        }
        serde_json::from_slice::<Value>(&body_bytes)
            .map_err(|err| format!("invalid directline_http body json: {err}"))
    }
}

/// `ActivitySource` that calls `RunnerHostHandle::invoke_directline_get_activities`
/// to read activities from the conversation state via the existing GET polling
/// code path in the WASM webchat provider.
pub struct RunnerHostActivitySource {
    pub runner_host: Arc<dyn RunnerHostHandle>,
    pub provider: String,
    pub team: String,
}

#[async_trait]
impl pump::ActivitySource for RunnerHostActivitySource {
    async fn fetch_since(
        &self,
        tenant_id: &str,
        conversation_id: &str,
        since_watermark: u64,
    ) -> Result<(Vec<Value>, u64), String> {
        let host = self.runner_host.clone();
        let team = self.team.clone();
        let provider = self.provider.clone();
        let tenant = tenant_id.to_string();
        let conv = conversation_id.to_string();
        let value = tokio::task::spawn_blocking(move || {
            host.invoke_directline_get_activities(&tenant, &team, &provider, &conv, since_watermark)
        })
        .await
        .map_err(|err| format!("join error: {err}"))??;

        let activities = value
            .get("activities")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let next_watermark = value
            .get("watermark")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(since_watermark);
        Ok((activities, next_watermark))
    }
}

/// Serve a single WebSocket session: complete the upgrade, then bridge the
/// `Pump` output frames into the WS sink and watch the WS stream for client
/// disconnects.
///
/// The `_guard` parameter is held only to keep the session counter elevated
/// for the lifetime of the connection.
#[allow(clippy::too_many_arguments)]
pub async fn serve_session(
    websocket: hyper_tungstenite::HyperWebsocket,
    notifier: Arc<dyn ActivityNotifier>,
    source: Arc<dyn pump::ActivitySource>,
    tenant_id: String,
    conversation_id: String,
    initial_watermark: u64,
    limits: WsLimits,
    _guard: SessionGuard,
) {
    let mut ws = match websocket.await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(?err, "websocket handshake failed");
            return;
        }
    };

    let (frame_tx, mut frame_rx) = mpsc::channel::<PumpFrame>(16);
    let pump = Pump::new(source, notifier, limits.max_replay_size);

    let pump_handle = tokio::spawn(async move {
        pump.run(tenant_id, conversation_id, initial_watermark, frame_tx)
            .await
    });

    let idle = Duration::from_secs(limits.idle_timeout_secs);
    loop {
        tokio::select! {
            maybe_frame = frame_rx.recv() => {
                match maybe_frame {
                    Some(PumpFrame::Activities { activities, next_watermark }) => {
                        let payload = ActivitySet::new(&activities, next_watermark)
                            .to_json()
                            .unwrap_or_default();
                        if ws.send(Message::Text(payload.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(PumpFrame::Error(msg)) => {
                        let _ = ws
                            .send(Message::Text(
                                ErrorFrame::new(&msg).to_json().unwrap_or_default().into(),
                            ))
                            .await;
                    }
                    None => break,
                }
            }
            incoming = tokio::time::timeout(idle, ws.next()) => {
                match incoming {
                    // Idle timeout hit, or stream ended, or close received -> stop.
                    Err(_) | Ok(None) | Ok(Some(Ok(Message::Close(_)))) => break,
                    Ok(Some(Ok(_))) => continue,
                    Ok(Some(Err(_))) => break,
                }
            }
        }
    }

    let _ = ws.close(None).await;
    pump_handle.abort();
    let _ = pump_handle.await;
}
