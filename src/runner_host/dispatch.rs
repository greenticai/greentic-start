#![allow(dead_code)]

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose};
use greentic_runner_desktop::RunStatus;
use greentic_runner_host::RunnerWasiPolicy;
use greentic_runner_host::component_api::node::{
    ExecCtx as ComponentExecCtx, TenantCtx as ComponentTenantCtx,
};
use greentic_runner_host::pack::{ComponentResolution, PackRuntime};
use greentic_runner_host::storage::DynSessionStore;
use serde_json::{Value as JsonValue, json};

use crate::domains::{Domain, ProviderPack};
use crate::operator_log;
use crate::runner_exec;
use crate::runner_integration::RunFlowOptions;
use crate::runner_integration::RunnerFlavor;
use crate::runner_integration::run_flow_with_options;
use crate::state_layout;

use super::DemoRunnerHost;
use super::helpers::{
    build_demo_host_config, domain_name, make_runtime_or_thread_scope, needs_secret_context,
    payload_preview, primary_provider_type, read_transcript_outputs, secret_error_context,
};
use super::hooks::json_to_canonical_cbor;
use super::types::{
    FlowOutcome, HookChainOutcome, OperationEnvelope, OperationStatus, OperatorContext,
    RunnerExecutionMode, RunnerMode,
};

impl DemoRunnerHost {
    pub fn invoke_provider_op(
        &self,
        domain: Domain,
        provider_type: &str,
        op_id: &str,
        payload_bytes: &[u8],
        ctx: &OperatorContext,
    ) -> anyhow::Result<FlowOutcome> {
        let mut envelope = OperationEnvelope::new(op_id, payload_bytes, ctx);
        let token_validation_outcome =
            self.evaluate_token_validation_pre_hook(&mut envelope, payload_bytes, ctx)?;
        if let HookChainOutcome::Denied(reason) = token_validation_outcome {
            envelope.status = OperationStatus::Denied;
            self.emit_pre_sub(&envelope);
            self.emit_post_sub(&envelope);
            return Ok(FlowOutcome {
                success: false,
                output: None,
                raw: None,
                error: Some(format!("operation denied by pre-hook: {reason}")),
                mode: RunnerExecutionMode::Exec,
            });
        }
        let pre_chain = self.resolve_hook_chain(crate::capabilities::HookStage::Pre, op_id);
        let pre_hook_outcome = self.evaluate_hook_chain(
            &pre_chain,
            crate::capabilities::HookStage::Pre,
            &mut envelope,
        )?;
        self.emit_pre_sub(&envelope);
        if let HookChainOutcome::Denied(reason) = pre_hook_outcome {
            envelope.status = OperationStatus::Denied;
            self.emit_post_sub(&envelope);
            return Ok(FlowOutcome {
                success: false,
                output: Some(serde_json::to_value(&envelope).unwrap_or_else(|_| json!({}))),
                raw: None,
                error: Some(format!("operation denied by pre-hook: {reason}")),
                mode: RunnerExecutionMode::Exec,
            });
        }

        let outcome =
            self.invoke_provider_op_inner(domain, provider_type, op_id, payload_bytes, ctx)?;
        envelope.status = if outcome.success {
            OperationStatus::Ok
        } else {
            OperationStatus::Err
        };
        envelope.result_cbor = outcome.output.as_ref().and_then(json_to_canonical_cbor);

        let post_chain = self.resolve_hook_chain(crate::capabilities::HookStage::Post, op_id);
        let _ = self.evaluate_hook_chain(
            &post_chain,
            crate::capabilities::HookStage::Post,
            &mut envelope,
        )?;
        self.emit_post_sub(&envelope);

        // Fire post-op callback (e.g. WebSocket activity notifier) only on
        // successful invocations that produced structured output. The callback
        // is held under an `Arc<RwLock<_>>`; snapshot it first so the callback
        // body is not run while holding the lock.
        if let Some(callback) = self.post_op_callback_snapshot()
            && outcome.success
            && let Some(output) = outcome.output.as_ref()
        {
            callback(domain_name(domain), provider_type, op_id, output);
        }

        Ok(outcome)
    }

    fn invoke_provider_op_inner(
        &self,
        domain: Domain,
        provider_type: &str,
        op_id: &str,
        payload_bytes: &[u8],
        ctx: &OperatorContext,
    ) -> anyhow::Result<FlowOutcome> {
        let pack = self
            .catalog
            .get(&(domain, provider_type.to_string()))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "provider {} not found for domain {}",
                    provider_type,
                    domain_name(domain)
                )
            })?;

        if pack.entry_flows.iter().any(|flow| flow == op_id) {
            let flow_id = op_id;

            // Log flow execution start to flow.log
            crate::flow_log::flow_start(
                provider_type,
                flow_id,
                &ctx.tenant,
                ctx.team.as_deref().unwrap_or("default"),
            );

            if self.debug_enabled {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "[demo dev] invoking provider domain={} provider={} flow={} tenant={} team={} payload_len={} preview={}",
                        domain_name(domain),
                        provider_type,
                        flow_id,
                        ctx.tenant,
                        ctx.team.as_deref().unwrap_or("default"),
                        payload_bytes.len(),
                        payload_preview(payload_bytes),
                    ),
                );
            }
            let run_dir = state_layout::run_dir(&self.bundle_root, domain, &pack.pack_id, flow_id)?;
            std::fs::create_dir_all(&run_dir)?;

            let render_outcome = self.card_renderer.render_if_needed(
                provider_type,
                payload_bytes,
                |cap_id, op, input| {
                    let outcome = self.invoke_capability(cap_id, op, input, ctx)?;
                    if !outcome.success {
                        let reason = outcome
                            .error
                            .clone()
                            .or(outcome.raw.clone())
                            .unwrap_or_else(|| "capability invocation failed".to_string());
                        return Err(anyhow!(
                            "card capability {}:{} failed: {}",
                            cap_id,
                            op,
                            reason
                        ));
                    }
                    outcome.output.ok_or_else(|| {
                        anyhow!(
                            "card capability {}:{} returned no structured output",
                            cap_id,
                            op
                        )
                    })
                },
            )?;
            let payload = serde_json::from_slice(&render_outcome.bytes).unwrap_or_else(|_| {
                json!({
                    "payload": general_purpose::STANDARD.encode(&render_outcome.bytes)
                })
            });

            let outcome = match &self.runner_mode {
                RunnerMode::Exec => {
                    self.execute_with_runner_exec(domain, pack, flow_id, &payload, ctx, &run_dir)?
                }
                RunnerMode::Integration { binary, flavor } => self
                    .execute_with_runner_integration(
                        domain, pack, flow_id, &payload, ctx, &run_dir, binary, *flavor,
                    )?,
            };

            // Log flow execution result to flow.log
            crate::flow_log::flow_end(
                provider_type,
                flow_id,
                &ctx.tenant,
                ctx.team.as_deref().unwrap_or("default"),
                outcome.success,
                outcome.error.as_deref(),
            );

            if self.debug_enabled {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "[demo dev] provider={} flow={} tenant={} team={} success={} mode={:?} error={:?} corr_id={}",
                        provider_type,
                        flow_id,
                        ctx.tenant,
                        ctx.team.as_deref().unwrap_or("default"),
                        outcome.success,
                        outcome.mode,
                        outcome.error,
                        ctx.correlation_id.as_deref().unwrap_or("none"),
                    ),
                );
            }
            operator_log::info(
                module_path!(),
                format!(
                    "invoke domain={} provider={} op={} mode={:?} corr={}",
                    domain_name(domain),
                    provider_type,
                    flow_id,
                    outcome.mode,
                    ctx.correlation_id.as_deref().unwrap_or("none")
                ),
            );

            return Ok(outcome);
        }

        self.invoke_provider_component_op(domain, pack, provider_type, op_id, payload_bytes, ctx)
    }

    fn execute_with_runner_exec(
        &self,
        domain: Domain,
        pack: &ProviderPack,
        flow_id: &str,
        payload: &JsonValue,
        ctx: &OperatorContext,
        _run_dir: &Path,
    ) -> anyhow::Result<FlowOutcome> {
        let request = runner_exec::RunRequest {
            root: self.bundle_root.clone(),
            domain,
            pack_path: pack.path.clone(),
            pack_label: pack.pack_id.clone(),
            flow_id: flow_id.to_string(),
            tenant: ctx.tenant.clone(),
            team: ctx.team.clone(),
            input: payload.clone(),
            dist_offline: true,
        };
        let run_output = runner_exec::run_provider_pack_flow(request)?;
        let parsed = read_transcript_outputs(&run_output.run_dir)?;
        Ok(FlowOutcome {
            success: run_output.result.status == RunStatus::Success,
            output: parsed,
            raw: None,
            error: run_output.result.error.clone(),
            mode: RunnerExecutionMode::Exec,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_with_runner_integration(
        &self,
        _domain: Domain,
        pack: &ProviderPack,
        flow_id: &str,
        payload: &JsonValue,
        ctx: &OperatorContext,
        run_dir: &Path,
        runner_binary: &Path,
        flavor: RunnerFlavor,
    ) -> anyhow::Result<FlowOutcome> {
        let output = run_flow_with_options(
            runner_binary,
            &pack.path,
            flow_id,
            payload,
            RunFlowOptions {
                dist_offline: true,
                tenant: Some(&ctx.tenant),
                team: ctx.team.as_deref(),
                artifacts_dir: Some(run_dir),
                runner_flavor: flavor,
            },
        )?;
        let mut parsed = output.parsed.clone();
        if parsed.is_none() {
            parsed = read_transcript_outputs(run_dir)?;
        }
        let raw = if output.stdout.trim().is_empty() {
            None
        } else {
            Some(output.stdout.clone())
        };
        Ok(FlowOutcome {
            success: output.status.success(),
            output: parsed,
            raw,
            error: if output.status.success() {
                None
            } else {
                Some(output.stderr.clone())
            },
            mode: RunnerExecutionMode::Integration,
        })
    }

    pub fn invoke_provider_component_op_direct(
        &self,
        domain: Domain,
        pack: &ProviderPack,
        provider_id: &str,
        op_id: &str,
        payload_bytes: &[u8],
        ctx: &OperatorContext,
    ) -> anyhow::Result<FlowOutcome> {
        self.invoke_provider_component_op(domain, pack, provider_id, op_id, payload_bytes, ctx)
    }

    pub(super) fn invoke_provider_component_op(
        &self,
        domain: Domain,
        pack: &ProviderPack,
        provider_id: &str,
        op_id: &str,
        payload_bytes: &[u8],
        ctx: &OperatorContext,
    ) -> anyhow::Result<FlowOutcome> {
        if let RunnerMode::Integration { binary, flavor } = &self.runner_mode {
            let payload_value: JsonValue =
                serde_json::from_slice(payload_bytes).unwrap_or_else(|_| json!({}));
            let run_dir = state_layout::run_dir(&self.bundle_root, domain, &pack.pack_id, op_id)?;
            std::fs::create_dir_all(&run_dir)?;
            return self.execute_with_runner_integration(
                domain,
                pack,
                op_id,
                &payload_value,
                ctx,
                &run_dir,
                binary,
                *flavor,
            );
        }

        let payload = payload_bytes.to_vec();
        let result = make_runtime_or_thread_scope(|runtime| {
            runtime.block_on(async {
                let host_config = Arc::new(build_demo_host_config(&ctx.tenant));
                // Reuse the cached secrets handle — the CachingSecretsManager
                // layer handles TTL expiry and write-through invalidation, so
                // newly-written secrets are picked up after cache expiry.
                let pack_runtime = PackRuntime::load(
                    &pack.path,
                    host_config.clone(),
                    None,
                    Some(&pack.path),
                    None::<DynSessionStore>,
                    Some(self.state_store.clone()),
                    Arc::new(RunnerWasiPolicy::default()),
                    self.secrets_handle.runtime_manager(Some(&pack.pack_id)),
                    None,
                    false,
                    ComponentResolution::default(),
                )
                .await?;
                let provider_type = primary_provider_type(&pack.path)
                    .context("failed to determine provider type for direct invocation")?;
                let binding = pack_runtime.resolve_provider(None, Some(&provider_type))?;
                let exec_ctx = ComponentExecCtx {
                    tenant: ComponentTenantCtx {
                        tenant: ctx.tenant.clone(),
                        team: ctx.team.clone(),
                        i18n_id: None,
                        user: None,
                        trace_id: None,
                        correlation_id: ctx.correlation_id.clone(),
                        deadline_unix_ms: None,
                        attempt: 1,
                        idempotency_key: None,
                    },
                    i18n_id: None,
                    flow_id: op_id.to_string(),
                    node_id: Some(op_id.to_string()),
                };
                pack_runtime
                    .invoke_provider(&binding, exec_ctx, op_id, payload)
                    .await
            })
        });

        match result {
            Ok(value) => {
                let value_str = serde_json::to_string(&value).unwrap_or_default();
                operator_log::info(
                    module_path!(),
                    format!(
                        "[wasm-output] op={} provider={} value_preview={}",
                        op_id,
                        provider_id,
                        value_str.chars().take(500).collect::<String>()
                    ),
                );
                Ok(FlowOutcome {
                    success: true,
                    output: Some(value),
                    raw: None,
                    error: None,
                    mode: RunnerExecutionMode::Exec,
                })
            }
            Err(err) => {
                let err_message = err.to_string();
                let needs_context = needs_secret_context(&err_message);
                let enriched_err = if needs_context {
                    err.context(secret_error_context(ctx, provider_id, op_id, pack))
                } else {
                    err
                };
                let error_text = if needs_context {
                    enriched_err.to_string()
                } else {
                    err_message
                };
                Ok(FlowOutcome {
                    success: false,
                    output: None,
                    raw: None,
                    error: Some(error_text),
                    mode: RunnerExecutionMode::Exec,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery;
    use crate::secrets_gate;
    use tempfile::tempdir;

    fn empty_host() -> DemoRunnerHost {
        let dir = tempdir().unwrap();
        let discovery = discovery::discover(dir.path()).unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default")).unwrap();
        DemoRunnerHost::new(dir.keep(), &discovery, None, secrets_handle, false).unwrap()
    }

    #[test]
    fn invoke_provider_op_errors_when_provider_is_missing() {
        let host = empty_host();
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            correlation_id: None,
        };

        let err = match host.invoke_provider_op(
            Domain::Messaging,
            "missing-provider",
            "ingest_http",
            br#"{}"#,
            &ctx,
        ) {
            Ok(_) => panic!("expected missing provider to fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("provider missing-provider not found")
        );
    }

    #[cfg(unix)]
    fn integration_host(script_body: &str) -> (DemoRunnerHost, crate::domains::ProviderPack) {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let root = dir.keep();
        let runner = root.join("greentic-runner-cli");
        fs::write(&runner, script_body).expect("runner script");
        let mut perms = fs::metadata(&runner).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&runner, perms).expect("chmod");

        let discovery = discovery::discover(&root).unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(&root, "demo", Some("default")).unwrap();
        let host = DemoRunnerHost::new(
            root.clone(),
            &discovery,
            Some(runner),
            secrets_handle,
            false,
        )
        .unwrap();
        let pack_path = root.join("messaging-webchat.gtpack");
        fs::write(&pack_path, b"fixture-pack").expect("pack");
        let pack = crate::domains::ProviderPack {
            pack_id: "messaging-webchat".to_string(),
            display_name: None,
            description: None,
            tags: Vec::new(),
            file_name: "messaging-webchat.gtpack".to_string(),
            path: pack_path,
            entry_flows: vec!["ingest_http".to_string()],
        };
        (host, pack)
    }

    #[cfg(unix)]
    #[test]
    fn integration_runner_executes_component_ops() {
        let (host, pack) = integration_host("#!/bin/sh\nprintf '{\"integration\":true}'\n");
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            correlation_id: Some("corr-1".to_string()),
        };

        let component = host
            .invoke_provider_component_op_direct(
                Domain::Messaging,
                &pack,
                "messaging-webchat",
                "custom-op",
                br#"{"hello":"world"}"#,
                &ctx,
            )
            .unwrap();
        assert!(component.success);
        assert_eq!(component.mode, RunnerExecutionMode::Integration);
        assert_eq!(
            component.output,
            Some(serde_json::json!({"integration": true}))
        );
    }

    #[cfg(unix)]
    #[test]
    fn integration_runner_propagates_stderr_on_failure() {
        let (host, pack) = integration_host("#!/bin/sh\necho 'runner failed' 1>&2\nexit 7\n");
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            correlation_id: None,
        };

        let outcome = host
            .invoke_provider_component_op_direct(
                Domain::Messaging,
                &pack,
                "messaging-webchat",
                "custom-op",
                br#"{}"#,
                &ctx,
            )
            .unwrap();
        assert!(!outcome.success);
        assert_eq!(outcome.mode, RunnerExecutionMode::Integration);
        assert_eq!(outcome.raw, None);
        assert!(outcome.error.unwrap_or_default().contains("runner failed"));
    }

    #[cfg(unix)]
    #[test]
    fn integration_runner_preserves_non_json_stdout_as_raw_output() {
        let (host, pack) = integration_host("#!/bin/sh\nprintf 'plain stdout'\n");
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            correlation_id: None,
        };

        let outcome = host
            .invoke_provider_component_op_direct(
                Domain::Messaging,
                &pack,
                "messaging-webchat",
                "custom-op",
                br#"{}"#,
                &ctx,
            )
            .unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.mode, RunnerExecutionMode::Integration);
        assert_eq!(outcome.output, None);
        assert_eq!(outcome.raw.as_deref(), Some("plain stdout"));
    }
}
