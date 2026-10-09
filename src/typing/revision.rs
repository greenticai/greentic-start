//! Deployed (revision-serve) half: the `send_typing` sender over
//! `RunnerHost::invoke_provider_for_revision` and the per-envelope decision.

use std::sync::Arc;

use async_trait::async_trait;
use greentic_deploy_spec::ids::{BundleId, DeploymentId, RevisionId};
use greentic_runner_host::RunnerHost;
use greentic_types::ChannelMessageEnvelope;
use serde_json::Value;

use super::{SendTypingInV1, SendTypingOutV1, TYPING_OP, TypingSender};

pub(crate) struct RevisionTypingSender {
    pub host: Arc<RunnerHost>,
    pub tenant: String,
    pub deployment_id: DeploymentId,
    pub bundle_id: BundleId,
    pub revision_id: RevisionId,
    pub provider_type: String,
    pub notifier: Arc<dyn crate::notifier::ActivityNotifier>,
}

#[async_trait]
impl TypingSender for RevisionTypingSender {
    async fn send_typing(&self, input: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1> {
        let bytes = serde_json::to_vec(input)?;
        // Goes through the provider-invoke seam only: never through
        // `handle_activity_for_revision`, so a typing call is not a turn, creates no
        // run outcome and is not metered.
        let out = self
            .host
            .invoke_provider_for_revision(
                &self.tenant,
                self.deployment_id,
                self.bundle_id.clone(),
                self.revision_id,
                &self.provider_type,
                TYPING_OP,
                bytes,
                None,
                None,
            )
            .await?;
        // Webchat raises typing through an ephemeral slot and reports the
        // conversation's watermark in `_greentic`; the WS pump only wakes on a
        // published NotifyEvent, exactly like send_payload.
        crate::revision_serve::try_notify_webchat_activity(self.notifier.as_ref(), &out).await;
        Ok(serde_json::from_value(out)?)
    }
}

/// Providers mark their own echoes with `is_bot_message=true`; the bot never
/// "types" at itself. Same rule the legacy ingress filters on.
pub(crate) fn is_bot_self_message(envelope: &ChannelMessageEnvelope) -> bool {
    envelope
        .metadata
        .get("is_bot_message")
        .is_some_and(|v| v == "true")
}

/// The per-envelope decision on the deployed path: `None` means "do not send typing
/// for this turn". The deployed `send_payload` passes `team: None` and the per-pack
/// config overrides; typing matches it.
pub(crate) fn typing_input_for(
    supports_typing: bool,
    kill_switch_on: bool,
    provider_type: &str,
    tenant: &str,
    ingress: &ChannelMessageEnvelope,
    config: Option<Value>,
) -> Option<SendTypingInV1> {
    if !supports_typing || !kill_switch_on || is_bot_self_message(ingress) {
        return None;
    }
    match SendTypingInV1::for_inbound(provider_type, tenant, None, ingress, config) {
        Ok(input) => Some(input),
        Err(err) => {
            tracing::debug!(provider_type, "send_typing input not built: {err:#}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifier::{ActivityNotifier, EventStream, NotifierError, NotifyEvent};
    use serde_json::json;
    use std::sync::Mutex;

    fn telegram_ingress() -> ChannelMessageEnvelope {
        serde_json::from_value(json!({
            "id": "msg-in-1",
            "tenant": {"env": "dev", "tenant": "acme", "tenant_id": "acme", "attempt": 0},
            "channel": "telegram",
            "session_id": "chat-42",
            "to": [{"id": "room-1", "kind": "room"}],
            "from": {"id": "user-1", "kind": "user"},
            "text": "hi",
            "metadata": {"route": "/webhook/telegram"}
        }))
        .expect("ingress envelope")
    }

    #[test]
    fn typing_input_is_none_without_support_or_with_the_kill_switch() {
        let ingress = telegram_ingress();
        let pt = "messaging.telegram.bot";
        assert!(typing_input_for(false, true, pt, "acme", &ingress, None).is_none());
        assert!(typing_input_for(true, false, pt, "acme", &ingress, None).is_none());
        let input = typing_input_for(true, true, pt, "acme", &ingress, None).unwrap();
        assert_eq!(input.message["session_id"], "chat-42");
        assert_eq!(input.tenant_id, "acme");
        assert!(
            input.tenant.team.is_none(),
            "deployed send_payload passes team None; typing matches"
        );
    }

    #[test]
    fn typing_input_skips_bot_self_messages() {
        let mut ingress = telegram_ingress();
        ingress
            .metadata
            .insert("is_bot_message".into(), "true".into());
        assert!(typing_input_for(true, true, "p", "acme", &ingress, None).is_none());
    }

    #[derive(Default)]
    struct RecordingNotifier(Mutex<Vec<NotifyEvent>>);

    #[async_trait]
    impl ActivityNotifier for RecordingNotifier {
        async fn publish(&self, event: NotifyEvent) {
            self.0.lock().unwrap().push(event);
        }
        async fn subscribe(&self, _: &str, _: &str) -> Result<EventStream, NotifierError> {
            unimplemented!("publish-only test notifier")
        }
    }

    #[tokio::test]
    async fn typing_output_publishes_a_ws_notify() {
        let notifier = RecordingNotifier::default();
        let out = json!({"v": 1, "ok": true, "refresh_after_ms": 4000,
            "_greentic": {"tenant": "acme", "conversation_id": "c1", "watermark_bumped": 7}});
        crate::revision_serve::try_notify_webchat_activity(&notifier, &out).await;
        let events = notifier.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            (events[0].conversation_id.as_str(), events[0].new_watermark),
            ("c1", 7)
        );
    }
}
