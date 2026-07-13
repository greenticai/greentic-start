//! DirectLine WebSocket streaming endpoint.
//!
//! Hoisted from `http_ingress/websocket/` (A.1) so both the legacy ingress
//! and the revision-path runtime can share the session pump, protocol types,
//! upgrade logic, and session management.
//!
//! The `RunnerHostHandle` trait is defined here; the `impl` for
//! `DemoRunnerHost` lives in `http_ingress` (legacy-coupled). The revision
//! path will supply its own implementation in a later PR.

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

use crate::notifier::ActivityNotifier;
use crate::operator_log;
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use hyper_tungstenite::tungstenite::Message;
use protocol::{ActivitySet, ErrorFrame};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Minimal trait surface the source needs from the runtime host.
///
/// This is implemented for [`crate::runner_host::DemoRunnerHost`] in
/// `http_ingress` (legacy path). Tests in the websocket module substitute
/// their own implementation to avoid pulling in the full demo host. The
/// revision path will add its own impl in a later PR.
pub trait RunnerHostHandle: Send + Sync + 'static {
    /// Synchronously invoke `directline_http` GET on the named provider and
    /// return the parsed JSON body. `auth_token` is forwarded as the
    /// `Authorization: Bearer <token>` header so the WASM provider's JWT
    /// guard accepts the call.
    fn invoke_directline_get_activities(
        &self,
        tenant: &str,
        team: &str,
        provider: &str,
        conversation_id: &str,
        watermark: u64,
        auth_token: Option<&str>,
    ) -> Result<Value, String>;
}

/// `ActivitySource` that calls `RunnerHostHandle::invoke_directline_get_activities`
/// to read activities from the conversation state via the existing GET polling
/// code path in the WASM webchat provider.
pub struct RunnerHostActivitySource {
    pub runner_host: Arc<dyn RunnerHostHandle>,
    pub provider: String,
    pub team: String,
    /// Bearer token captured at WS upgrade time. Forwarded as the
    /// `Authorization` header on every `fetch_since` so the WASM provider's
    /// JWT guard accepts internal pump calls.
    pub auth_token: Option<String>,
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
        let auth_token = self.auth_token.clone();
        let value = tokio::task::spawn_blocking(move || {
            host.invoke_directline_get_activities(
                &tenant,
                &team,
                &provider,
                &conv,
                since_watermark,
                auth_token.as_deref(),
            )
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

/// Decrements `greentic.conversations.active` when dropped. Created after a
/// successful WS handshake so the gauge mirrors live connections regardless
/// of how the session ends.
struct SessionMetricGuard {
    tenant: String,
}

impl Drop for SessionMetricGuard {
    fn drop(&mut self) {
        crate::metrics::record_session_end(&self.tenant, "webchat");
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
    operator_log::debug(
        module_path!(),
        format!(
            "[ws serve_session] entered tenant={} conv={} initial_watermark={}",
            tenant_id, conversation_id, initial_watermark,
        ),
    );
    crate::metrics::record_session_start(&tenant_id, "webchat");
    let _session_metric = SessionMetricGuard {
        tenant: tenant_id.clone(),
    };
    let mut ws = match websocket.await {
        Ok(stream) => {
            operator_log::debug(
                module_path!(),
                format!(
                    "[ws serve_session] handshake completed tenant={} conv={}",
                    tenant_id, conversation_id,
                ),
            );
            stream
        }
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "[ws serve_session] handshake FAILED tenant={} conv={} err={}",
                    tenant_id, conversation_id, err,
                ),
            );
            return;
        }
    };

    let (frame_tx, mut frame_rx) = mpsc::channel::<PumpFrame>(16);
    let pump = Pump::new(source, notifier, limits.max_replay_size);

    let pump_tenant = tenant_id.clone();
    let pump_conv = conversation_id.clone();
    let pump_handle = tokio::spawn(async move {
        let result = pump
            .run(tenant_id, conversation_id, initial_watermark, frame_tx)
            .await;
        if let Err(ref err) = result {
            operator_log::warn(
                module_path!(),
                format!(
                    "[ws pump] run errored tenant={} conv={} err={:?}",
                    pump_tenant, pump_conv, err,
                ),
            );
        } else {
            operator_log::debug(
                module_path!(),
                format!(
                    "[ws pump] run ended Ok tenant={} conv={}",
                    pump_tenant, pump_conv,
                ),
            );
        }
        result
    });

    let idle = Duration::from_secs(limits.idle_timeout_secs);
    // Send a WebSocket ping at half the idle window (clamped to a sane
    // minimum) so a chat session that's idle waiting for a bot reply
    // doesn't get reaped after `idle_timeout_secs`. The peer's pong
    // arrives on the receive arm and resets the timeout naturally;
    // if the peer is genuinely dead, no pong arrives and the receive
    // arm's `idle` timeout still fires, breaking the loop.
    let ping_period = Duration::from_secs((limits.idle_timeout_secs / 2).max(30));
    let mut ping_ticker = tokio::time::interval(ping_period);
    ping_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // First tick fires immediately by default; consume it so we don't
    // ping at t=0 before the client has finished its handshake setup.
    ping_ticker.tick().await;
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
            _ = ping_ticker.tick() => {
                if ws.send(Message::Ping(Default::default())).await.is_err() {
                    break;
                }
            }
        }
    }

    let _ = ws.close(None).await;
    pump_handle.abort();
    let _ = pump_handle.await;
}
