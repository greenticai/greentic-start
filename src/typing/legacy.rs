//! Legacy (demo / single-bundle) half: the blocking `send_typing` sender over
//! `DemoRunnerHost::invoke_provider_op`, and the per-batch / per-envelope wiring
//! `route_messaging_envelopes` calls.

use std::sync::Arc;

use greentic_types::ChannelMessageEnvelope;
use serde_json::Value;

use super::{BlockingTypingSender, SendTypingInV1, SendTypingOutV1, TYPING_OP};
use crate::domains::Domain;
use crate::runner_host::{DemoRunnerHost, OperatorContext};

/// Owns its handles because the blocking driver runs it on a DETACHED thread (so a
/// hung provider call can be abandoned after `STOP_GRACE`).
pub(crate) struct DemoTypingSender {
    pub host: Arc<DemoRunnerHost>,
    /// Catalog lookup key, as egress passes it to `invoke_provider_op`.
    pub provider: String,
    pub ctx: OperatorContext,
}

impl BlockingTypingSender for DemoTypingSender {
    fn send_typing(&self, input: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1> {
        let bytes = serde_json::to_vec(input)?;
        // Provider-invoke seam only: not a flow run, no run outcome, no metering. The
        // host's post-op callback forwards a webchat `_greentic` block to the WS pump.
        let outcome = self.host.invoke_provider_op(
            Domain::Messaging,
            &self.provider,
            TYPING_OP,
            &bytes,
            &self.ctx,
        )?;
        if !outcome.success {
            anyhow::bail!(
                outcome
                    .error
                    .unwrap_or_else(|| "send_typing failed".to_string())
            );
        }
        Ok(serde_json::from_value(outcome.output.unwrap_or_default())?)
    }
}

pub(crate) fn legacy_typing_enabled(host_supports: bool, kill_switch_on: bool) -> bool {
    host_supports && kill_switch_on
}

/// Per-batch typing context for the legacy path. `None` from [`Self::prepare`] means
/// "no typing for this batch".
pub(crate) struct LegacyTyping {
    sender: Arc<dyn BlockingTypingSender>,
    provider_type: String,
    tenant: String,
    team: Option<String>,
    config: Option<Value>,
}

impl LegacyTyping {
    /// Decided ONCE per batch from the provider's declared ops (`supports_op` reads the
    /// pack manifest; it never invokes). `config` / `team` mirror what egress hands
    /// `send_payload` on this path.
    pub(crate) fn prepare(
        runner_host: &Arc<DemoRunnerHost>,
        provider: &str,
        ctx: &OperatorContext,
        config: impl FnOnce() -> anyhow::Result<Option<Value>>,
    ) -> Option<Self> {
        if !legacy_typing_enabled(
            runner_host.supports_op(Domain::Messaging, provider, TYPING_OP),
            super::enabled(),
        ) {
            return None;
        }
        let config = match config() {
            Ok(config) => config,
            Err(err) => {
                crate::operator_log::warn(
                    module_path!(),
                    format!(
                        "send_typing disabled for this batch provider={provider}: \
                         injected config unavailable: {err:#}"
                    ),
                );
                return None;
            }
        };
        Some(Self {
            sender: Arc::new(DemoTypingSender {
                host: Arc::clone(runner_host),
                provider: provider.to_string(),
                ctx: ctx.clone(),
            }),
            provider_type: runner_host.canonical_provider_type(Domain::Messaging, provider),
            tenant: ctx.tenant.clone(),
            team: ctx.team.clone(),
            config,
        })
    }

    /// Runs `turn` with the typing signal raised for `inbound`, returning the turn's
    /// output untouched. Returns only after typing has stopped (bounded by
    /// `STOP_GRACE`), so the caller's egress never races a refresh.
    pub(crate) fn around<R>(
        &self,
        inbound: &ChannelMessageEnvelope,
        turn: impl FnOnce() -> R,
    ) -> R {
        if super::is_bot_self_message(inbound) {
            return turn();
        }
        let input = match SendTypingInV1::for_inbound(
            self.provider_type.clone(),
            self.tenant.clone(),
            self.team.clone(),
            inbound,
            self.config.clone(),
        ) {
            Ok(input) => input,
            Err(err) => {
                tracing::debug!("send_typing input not built: {err:#}");
                return turn();
            }
        };
        super::keep_typing_blocking(Arc::clone(&self.sender), input, turn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    #[test]
    fn legacy_gate_needs_both_support_and_the_kill_switch() {
        assert!(legacy_typing_enabled(true, true));
        assert!(!legacy_typing_enabled(true, false));
        assert!(!legacy_typing_enabled(false, true));
        assert!(!legacy_typing_enabled(false, false));
    }

    struct Recorder(Arc<Mutex<Vec<String>>>);
    impl BlockingTypingSender for Recorder {
        fn send_typing(&self, input: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1> {
            std::thread::sleep(std::time::Duration::from_millis(150));
            self.0.lock().unwrap().push(format!(
                "typing:{}:{}",
                input.tenant_id,
                input.tenant.team.as_deref().unwrap_or("-")
            ));
            Ok(SendTypingOutV1 {
                v: 1,
                ok: true,
                error: None,
                refresh_after_ms: Some(4000),
            })
        }
    }

    fn typing(log: &Arc<Mutex<Vec<String>>>) -> LegacyTyping {
        LegacyTyping {
            sender: Arc::new(Recorder(log.clone())),
            provider_type: "messaging.webchat-gui".into(),
            tenant: "demo".into(),
            team: Some("default".into()),
            config: None,
        }
    }

    fn inbound() -> ChannelMessageEnvelope {
        serde_json::from_value(json!({
            "id": "m1",
            "tenant": {"env": "dev", "tenant": "demo", "tenant_id": "demo", "attempt": 0},
            "channel": "webchat",
            "session_id": "conv-1",
            "from": {"id": "user-1", "kind": "user"},
            "text": "hi",
            "metadata": {}
        }))
        .unwrap()
    }

    #[test]
    fn typing_is_raised_during_the_turn_and_never_after_egress_starts() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let turn_log = log.clone();
        let out = typing(&log).around(&inbound(), || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            turn_log.lock().unwrap().push("turn".to_string());
            "reply"
        });
        log.lock().unwrap().push("send_payload".to_string());
        assert_eq!(out, "reply");
        let log = log.lock().unwrap().clone();
        assert_eq!(log, vec!["turn", "typing:demo:default", "send_payload"]);
    }

    #[test]
    fn bot_self_messages_raise_no_typing() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut env = inbound();
        env.metadata
            .insert("is_bot_message".to_string(), "true".to_string());
        assert_eq!(typing(&log).around(&env, || 5), 5);
        assert!(log.lock().unwrap().is_empty());
    }
}
