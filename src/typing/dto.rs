//! Wire types for the `send_typing` provider op (contract §5.1).

use anyhow::Context;
use greentic_types::ChannelMessageEnvelope;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::messaging_dto::TenantHint;

/// Input to `send_typing`. `message` is the INBOUND envelope the turn answers — the
/// provider derives its target from it exactly as it does for a reply.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct SendTypingInV1 {
    pub v: u32,
    pub provider_type: String,
    /// The tenant slug, top-level (= `tenant.tenant`). Providers parse this key and
    /// ignore unknown fields, so both are carried.
    pub tenant_id: String,
    pub tenant: TenantHint,
    pub message: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
}

/// Output of `send_typing`. `ok: false` is a failed attempt, never a failed turn.
/// `refresh_after_ms` absent (or 0) means "do not refresh".
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(crate) struct SendTypingOutV1 {
    #[serde(default = "one")]
    pub v: u32,
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub refresh_after_ms: Option<u64>,
}

fn one() -> u32 {
    1
}

impl SendTypingInV1 {
    /// Built per path so `tenant.team` and `config` match what THAT path hands
    /// `send_payload` (deployed: team None + per-pack config overrides;
    /// legacy: `ctx.team` + the injected provider config).
    pub(crate) fn for_inbound(
        provider_type: impl Into<String>,
        tenant: impl Into<String>,
        team: Option<String>,
        inbound: &ChannelMessageEnvelope,
        config: Option<Value>,
    ) -> anyhow::Result<Self> {
        let tenant = tenant.into();
        Ok(Self {
            v: 1,
            provider_type: provider_type.into(),
            tenant_id: tenant.clone(),
            tenant: TenantHint {
                tenant,
                team,
                user: None,
                correlation_id: None,
            },
            message: serde_json::to_value(inbound).context("serialize inbound envelope")?,
            config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inbound() -> ChannelMessageEnvelope {
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
        .expect("inbound envelope")
    }

    #[test]
    fn for_inbound_carries_the_inbound_envelope_and_tenant_hint() {
        let input = SendTypingInV1::for_inbound(
            "messaging.telegram.bot",
            "acme",
            Some("ops".to_string()),
            &inbound(),
            Some(json!({"api_base_url": "https://x"})),
        )
        .unwrap();
        let v = serde_json::to_value(&input).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["provider_type"], "messaging.telegram.bot");
        assert_eq!(
            v["tenant_id"], "acme",
            "providers read the top-level tenant_id"
        );
        assert_eq!(v["tenant"], json!({"tenant": "acme", "team": "ops"}));
        assert_eq!(v["message"]["session_id"], "chat-42");
        assert_eq!(v["message"]["from"]["id"], "user-1");
        assert_eq!(v["config"]["api_base_url"], "https://x");
    }

    #[test]
    fn config_and_team_are_omitted_when_absent() {
        let input = SendTypingInV1::for_inbound("p", "acme", None, &inbound(), None).unwrap();
        let v = serde_json::to_value(&input).unwrap();
        assert!(v.get("config").is_none());
        assert!(v["tenant"].get("team").is_none());
    }

    #[test]
    fn out_v1_parses_absent_refresh_and_error() {
        let ok: SendTypingOutV1 =
            serde_json::from_value(json!({"v": 1, "ok": true, "refresh_after_ms": 4000})).unwrap();
        assert_eq!(ok.refresh_after_ms, Some(4000));
        let no_refresh: SendTypingOutV1 = serde_json::from_value(json!({"ok": true})).unwrap();
        assert_eq!((no_refresh.v, no_refresh.refresh_after_ms), (1, None));
        let failed: SendTypingOutV1 =
            serde_json::from_value(json!({"v": 1, "ok": false, "error": "429"})).unwrap();
        assert_eq!(failed.error.as_deref(), Some("429"));
    }
}
