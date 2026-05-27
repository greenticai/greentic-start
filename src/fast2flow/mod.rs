//! Fast2Flow routing-host integration: per-envelope hook before the default
//! `select_app_flow` fallback. Fails open — any failure path falls through.

use std::time::{SystemTime, UNIX_EPOCH};

use greentic_types::ChannelMessageEnvelope;

use crate::ingress::control_directive::ControlDirective;
use crate::messaging_app::AppPackInfo;
use crate::operator_log;
use crate::runner_host::OperatorContext;

pub mod config;
pub mod contracts;
pub mod gate;
pub mod host_process;
pub mod mapper;

pub use config::Fast2FlowConfig;
pub use contracts::{Fast2FlowHookInV1, MessageEnvelope};
pub use gate::Fast2FlowGate;
pub use host_process::invoke_routing_host;
pub use mapper::map_directive_to_control;

/// Scope key for the Fast2Flow index. Env partitioning lives at the
/// `indexes_path` mount, so identity is just `<tenant>:<team>`.
pub fn scope_for(ctx: &OperatorContext) -> String {
    let team = ctx.team.as_deref().unwrap_or("default");
    format!("{}:{}", ctx.tenant, team)
}

/// Eligibility + invoke + map. Returns `Some` only for actionable
/// directives; `None` means skip (ineligible, Continue, or error).
pub fn try_for_request(
    cfg: &Fast2FlowConfig,
    ctx: &OperatorContext,
    pack: &AppPackInfo,
    envelope: &ChannelMessageEnvelope,
    provider: &str,
) -> Option<ControlDirective> {
    if !cfg.has_deploy_intent() || !cfg.gate.is_enabled(ctx, pack) {
        return None;
    }
    let indexes_path = cfg.indexes_path.as_ref()?;
    let scope = scope_for(ctx);
    if !indexes_path.join(&scope).join("index.json").is_file() {
        return None;
    }

    let text = envelope.text.clone().unwrap_or_default();
    let locale = envelope
        .metadata
        .get("locale")
        .cloned()
        .unwrap_or_else(|| "en".to_string());
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let input = Fast2FlowHookInV1 {
        scope,
        envelope: MessageEnvelope {
            text,
            // FIXME(channel): derive from envelope metadata when available.
            channel: None,
            provider: Some(provider.to_string()),
        },
        // FIXME(session-active): thread runtime session state.
        session_active: true,
        input_locale: locale,
        time_budget_ms: cfg.time_budget_ms,
        registry_path: cfg.registry_path.to_string_lossy().into_owned(),
        indexes_path: indexes_path.to_string_lossy().into_owned(),
        now_unix_ms,
    };

    let out = invoke_routing_host(&cfg.host_bin, &input)?;
    let directive = map_directive_to_control(out.directive, ctx);
    operator_log::info(
        module_path!(),
        format!("[fast2flow] directive={directive:?}"),
    );

    match directive {
        ControlDirective::Continue => None,
        actionable => Some(actionable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_uses_default_team_when_absent() {
        let ctx = OperatorContext {
            tenant: "acme".to_string(),
            team: None,
            correlation_id: None,
        };
        assert_eq!(scope_for(&ctx), "acme:default");
    }

    #[test]
    fn scope_uses_supplied_team() {
        let ctx = OperatorContext {
            tenant: "acme".to_string(),
            team: Some("legal".to_string()),
            correlation_id: None,
        };
        assert_eq!(scope_for(&ctx), "acme:legal");
    }
}
