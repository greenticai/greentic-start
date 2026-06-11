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
pub mod llm_router;
pub mod mapper;

pub use config::Fast2FlowConfig;
pub use contracts::{Fast2FlowHookInV1, MessageEnvelope};
pub use gate::{FAST2FLOW_CAPABILITY, Fast2FlowGate};
pub use host_process::invoke_routing_host;
pub use llm_router::try_llm_route;
pub use mapper::map_directive_to_control;

/// Scope key for the Fast2Flow index. Env partitioning lives at the
/// `indexes_path` mount, so identity is just `<tenant>:<team>`.
pub fn scope_for(ctx: &OperatorContext) -> String {
    let team = ctx.team.as_deref().unwrap_or("default");
    format!("{}:{}", ctx.tenant, team)
}

/// Resolve `<indexes_path>/<scope>/index.json`, materializing it from the
/// pack's `assets/intent-index.json` when absent. Returns the index file path
/// when present (or just materialized), else `None`. Shared by the host probe
/// and the embedded LLM fallback so both route against the same catalog.
pub fn resolve_index_path(
    cfg: &Fast2FlowConfig,
    ctx: &OperatorContext,
    pack_path: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let indexes_path = cfg.indexes_path.as_ref()?;
    let scope = scope_for(ctx);
    let index_path = indexes_path.join(&scope).join("index.json");
    let mut exists = index_path.is_file();
    if !exists && materialize_index_from_pack(pack_path, &index_path) {
        exists = true;
        operator_log::info(
            module_path!(),
            format!(
                "[fast2flow:gate] materialized index from pack -> {}",
                index_path.display()
            ),
        );
    }
    operator_log::info(
        module_path!(),
        format!(
            "[fast2flow:gate] index_check path={} exists={exists}",
            index_path.display()
        ),
    );
    exists.then_some(index_path)
}

/// Eligibility + invoke + map. Returns `Some` only for actionable
/// directives; `None` means skip (ineligible, Continue, or error).
pub fn try_for_request(
    cfg: &Fast2FlowConfig,
    ctx: &OperatorContext,
    pack: &AppPackInfo,
    pack_path: &std::path::Path,
    envelope: &ChannelMessageEnvelope,
    provider: &str,
) -> Option<ControlDirective> {
    let deploy_intent = cfg.has_deploy_intent();
    let gate_enabled = cfg.gate.is_enabled(ctx, pack);
    operator_log::info(
        module_path!(),
        format!(
            "[fast2flow:gate] enter tenant={} team={:?} pack={} caps={:?} deploy_intent={} gate_enabled={} text_len={}",
            ctx.tenant,
            ctx.team,
            pack.pack_id,
            pack.capabilities,
            deploy_intent,
            gate_enabled,
            envelope.text.as_deref().map(str::len).unwrap_or(0)
        ),
    );
    if !deploy_intent || !gate_enabled {
        operator_log::info(
            module_path!(),
            format!(
                "[fast2flow:gate] skip reason=gate deploy_intent={deploy_intent} gate_enabled={gate_enabled}"
            ),
        );
        return None;
    }
    let indexes_path = match cfg.indexes_path.as_ref() {
        Some(p) => p,
        None => {
            operator_log::info(
                module_path!(),
                "[fast2flow:gate] skip reason=no_indexes_path",
            );
            return None;
        }
    };
    let scope = scope_for(ctx);
    // Resolve (and materialize) the scope index; short-circuit before spawning
    // the host when it's absent. Shared with the embedded LLM fallback.
    resolve_index_path(cfg, ctx, pack_path)?;

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
        // FIXME(session-active): thread the runtime's real session state.
        // Defaulting to `false` so Fast2Flow's hook filter actually runs the
        // matcher; `true` causes it to short-circuit to Continue (the
        // "in-progress flow keeps priority" semantics) and silently masked
        // every dispatch in early testing.
        session_active: false,
        input_locale: locale,
        time_budget_ms: cfg.time_budget_ms,
        registry_path: cfg.registry_path.to_string_lossy().into_owned(),
        indexes_path: indexes_path.to_string_lossy().into_owned(),
        now_unix_ms,
    };

    let out = invoke_routing_host(&cfg.host_bin, &input)?;
    let routing = out.directive;
    // Observability: surface the matcher's decision (target + confidence + reason)
    // before `map_directive_to_control` collapses it. Emitted via `tracing` so it
    // reaches OTLP (and Loki/whatever the collector fans out to), and via
    // operator_log for the local operator.log.
    if let contracts::RoutingDirective::Dispatch {
        target,
        confidence,
        reason,
        ..
    } = &routing
    {
        tracing::info!(
            target: "greentic.fast2flow",
            tenant = %ctx.tenant,
            route_target = %target,
            confidence = *confidence,
            reason = %reason,
            "fast2flow dispatch"
        );
        operator_log::info(
            module_path!(),
            format_dispatch_log(target, *confidence, reason),
        );
    }
    let directive = map_directive_to_control(routing, ctx);
    operator_log::info(
        module_path!(),
        format!("[fast2flow] directive={directive:?}"),
    );

    match directive {
        ControlDirective::Continue => None,
        actionable => Some(actionable),
    }
}

/// Human-readable operator.log line for a fast2flow dispatch decision. Kept as a
/// pure helper so the exact wire format (which downstream log scrapers / e2e
/// tests grep for) is pinned by a unit test.
fn format_dispatch_log(target: &str, confidence: f32, reason: &str) -> String {
    format!("[fast2flow] dispatch target={target} confidence={confidence:.3} reason={reason:?}")
}

/// Copy `assets/intent-index.json` out of the pack zip into `target_index`.
fn materialize_index_from_pack(
    pack_path: &std::path::Path,
    target_index: &std::path::Path,
) -> bool {
    let Ok(file) = std::fs::File::open(pack_path) else {
        return false;
    };
    let Ok(mut archive) = zip::ZipArchive::new(file) else {
        return false;
    };
    let mut buf = Vec::new();
    {
        let Ok(mut entry) = archive.by_name("assets/intent-index.json") else {
            return false;
        };
        if std::io::Read::read_to_end(&mut entry, &mut buf).is_err() {
            return false;
        }
    }
    if let Some(parent) = target_index.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return false;
    }
    if std::fs::write(target_index, &buf).is_err() {
        return false;
    }
    if let Some(parent) = target_index.parent() {
        let _ = std::fs::write(parent.join("latest"), "index.json\n");
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_log_pins_target_confidence_reason() {
        let line = format_dispatch_log(
            "greentic.pet-daycare.demo/default/attendance_card",
            0.5,
            "bm25",
        );
        assert_eq!(
            line,
            "[fast2flow] dispatch target=greentic.pet-daycare.demo/default/attendance_card confidence=0.500 reason=\"bm25\""
        );
    }

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

    // End-to-end smoke covering the two-level gate, host invocation, and
    // directive mapping. Cf. docs/fast2flow-prototype-bundle.md "Test plan".
    #[cfg(unix)]
    mod end_to_end {
        use super::*;
        use crate::fast2flow::gate::{BundleCapabilityGate, FAST2FLOW_CAPABILITY};
        use crate::ingress::control_directive::ControlDirective;
        use crate::messaging_app::{AppFlowInfo, AppPackInfo};
        use serde_json::json;
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;
        use std::sync::Arc;
        use tempfile::{TempDir, tempdir};

        fn pack_with_fast2flow_cap() -> AppPackInfo {
            AppPackInfo {
                pack_id: "sales-crm".to_string(),
                flows: alloc_messaging_default(),
                capabilities: vec![FAST2FLOW_CAPABILITY.to_string()],
            }
        }

        fn alloc_messaging_default() -> Vec<AppFlowInfo> {
            vec![AppFlowInfo {
                id: "welcome".to_string(),
                kind: "messaging".to_string(),
            }]
        }

        fn ctx() -> OperatorContext {
            OperatorContext {
                tenant: "acme".to_string(),
                team: None,
                correlation_id: None,
            }
        }

        fn envelope(text: &str) -> ChannelMessageEnvelope {
            serde_json::from_value(json!({
                "id": "msg-1",
                "tenant": {
                    "env": "dev",
                    "tenant": "acme",
                    "tenant_id": "acme",
                    "team": "default",
                    "attempt": 0
                },
                "channel": "conv-1",
                "session_id": "conv-1",
                "from": { "id": "user-1", "kind": "user" },
                "text": text,
                "metadata": {}
            }))
            .expect("envelope")
        }

        fn fake_host(body: &str) -> (TempDir, PathBuf) {
            let dir = tempdir().expect("tempdir");
            let path = dir.path().join("fake-host.sh");
            let script = format!("#!/bin/sh\ncat > /dev/null\nprintf '%s' '{body}'\n");
            std::fs::write(&path, script).expect("write");
            let mut perms = std::fs::metadata(&path).expect("meta").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).expect("perms");
            (dir, path)
        }

        fn config_with(host_bin: PathBuf, indexes_path: Option<PathBuf>) -> Fast2FlowConfig {
            Fast2FlowConfig {
                host_bin,
                registry_path: PathBuf::from("/tmp/registry"),
                indexes_path,
                time_budget_ms: 500,
                gate: Arc::new(BundleCapabilityGate),
            }
        }

        /// Materializes `<indexes_path>/<scope>/index.json` so the
        /// file-existence gate clears.
        fn place_index(indexes_path: &std::path::Path, scope: &str) {
            let scope_dir = indexes_path.join(scope);
            std::fs::create_dir_all(&scope_dir).expect("scope dir");
            std::fs::write(scope_dir.join("index.json"), b"{}").expect("index");
        }

        #[test]
        fn returns_dispatch_when_capability_index_and_host_all_align() {
            let (_dir, host) = fake_host(
                r#"{"directive":{"type":"dispatch","target":"sales-crm/pipeline_flow","confidence":0.92,"reason":"matched pipeline"}}"#,
            );
            let indexes = tempdir().expect("indexes dir");
            place_index(indexes.path(), "acme:default");
            let cfg = config_with(host, Some(indexes.path().to_path_buf()));

            let result = try_for_request(
                &cfg,
                &ctx(),
                &pack_with_fast2flow_cap(),
                std::path::Path::new("/nonexistent.gtpack"),
                &envelope("show me my pipeline"),
                "webchat",
            );
            match result {
                Some(ControlDirective::Dispatch { target, .. }) => {
                    assert_eq!(target.tenant, "acme");
                    assert_eq!(target.team, None);
                    assert_eq!(target.pack, "sales-crm");
                    assert_eq!(target.flow.as_deref(), Some("pipeline_flow"));
                    assert!(target.node.is_none());
                }
                other => panic!("expected Dispatch, got {other:?}"),
            }
        }

        #[test]
        fn returns_none_when_pack_does_not_declare_capability() {
            let (_dir, host) = fake_host(r#"{"directive":{"type":"continue"}}"#);
            let indexes = tempdir().expect("indexes dir");
            place_index(indexes.path(), "acme:default");
            let cfg = config_with(host, Some(indexes.path().to_path_buf()));

            let pack_without_cap = AppPackInfo {
                pack_id: "no-fast2flow".to_string(),
                flows: alloc_messaging_default(),
                capabilities: Vec::new(),
            };
            let result = try_for_request(
                &cfg,
                &ctx(),
                &pack_without_cap,
                std::path::Path::new("/nonexistent.gtpack"),
                &envelope("show pipeline"),
                "webchat",
            );
            assert!(result.is_none(), "gate must veto undeclared packs");
        }

        #[test]
        fn returns_none_when_scope_index_file_missing() {
            let (_dir, host) = fake_host(
                r#"{"directive":{"type":"dispatch","target":"sales-crm/pipeline_flow","confidence":1.0,"reason":""}}"#,
            );
            // Indexes dir exists but no <scope>/index.json placed.
            let indexes = tempdir().expect("indexes dir");
            let cfg = config_with(host, Some(indexes.path().to_path_buf()));

            let result = try_for_request(
                &cfg,
                &ctx(),
                &pack_with_fast2flow_cap(),
                std::path::Path::new("/nonexistent.gtpack"),
                &envelope("show pipeline"),
                "webchat",
            );
            assert!(
                result.is_none(),
                "missing index file must short-circuit before host spawn"
            );
        }

        #[test]
        fn returns_none_when_host_returns_continue() {
            let (_dir, host) = fake_host(r#"{"directive":{"type":"continue"}}"#);
            let indexes = tempdir().expect("indexes dir");
            place_index(indexes.path(), "acme:default");
            let cfg = config_with(host, Some(indexes.path().to_path_buf()));

            let result = try_for_request(
                &cfg,
                &ctx(),
                &pack_with_fast2flow_cap(),
                std::path::Path::new("/nonexistent.gtpack"),
                &envelope("hi"),
                "webchat",
            );
            assert!(
                result.is_none(),
                "Continue directive maps to None so caller falls through"
            );
        }
    }
}
