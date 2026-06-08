#![allow(dead_code)]

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose};
use greentic_runner_desktop::RunStatus;
use greentic_runner_host::RunnerWasiPolicy;
use greentic_runner_host::component_api::node::{
    ExecCtx as ComponentExecCtx, TenantCtx as ComponentTenantCtx,
};
use greentic_runner_host::pack::{
    ComponentResolution, ComponentState, HostState, PackRuntime, register_all,
};
use greentic_runner_host::runtime_wasmtime::{Component, Engine, Linker, Store};
use greentic_runner_host::storage::DynSessionStore;
use greentic_types::{
    ArtifactLocationV1, EXT_COMPONENT_SOURCES_V1, ExtensionInline, decode_pack_manifest,
};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use wasmtime::component::TypedFunc;
use zip::ZipArchive;

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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn invoke_pack_component_op_direct(
        &self,
        domain: Domain,
        pack: &ProviderPack,
        component_ref: &str,
        op_id: &str,
        config: &JsonValue,
        input: &JsonValue,
        ctx: &OperatorContext,
    ) -> anyhow::Result<FlowOutcome> {
        self.invoke_pack_component_op(domain, pack, component_ref, op_id, config, input, ctx)
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
                let level = if is_startup_diagnostic_op(op_id) {
                    operator_log::Level::Info
                } else {
                    operator_log::Level::Debug
                };
                operator_log::log(
                    level,
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn invoke_pack_component_op(
        &self,
        _domain: Domain,
        pack: &ProviderPack,
        component_ref: &str,
        op_id: &str,
        config: &JsonValue,
        input: &JsonValue,
        ctx: &OperatorContext,
    ) -> anyhow::Result<FlowOutcome> {
        if let RunnerMode::Integration { .. } = &self.runner_mode {
            return Ok(FlowOutcome {
                success: false,
                output: None,
                raw: None,
                error: Some(
                    "direct component extension invocation is not supported by integration runner"
                        .to_string(),
                ),
                mode: RunnerExecutionMode::Integration,
            });
        }

        let config_json = serde_json::to_string(config)?;
        let input_json = serde_json::to_string(input)?;
        let result = make_runtime_or_thread_scope(|runtime| {
            runtime.block_on(async {
                let host_config = Arc::new(build_demo_host_config(&ctx.tenant));
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
                    .invoke_component(
                        component_ref,
                        exec_ctx,
                        op_id,
                        Some(config_json),
                        input_json,
                    )
                    .await
            })
        });

        match result {
            Ok(value) => Ok(FlowOutcome {
                success: true,
                output: Some(value),
                raw: None,
                error: None,
                mode: RunnerExecutionMode::Exec,
            }),
            Err(err)
                if operation_is_provider_common_subscription(op_id)
                    && err.to_string().contains(
                        "component exports neither node@0.5/0.4 nor component-runtime@0.6",
                    ) =>
            {
                self.invoke_provider_common_subscription_component(
                    pack,
                    component_ref,
                    config,
                    input,
                    ctx,
                )
            }
            Err(err) => Ok(FlowOutcome {
                success: false,
                output: None,
                raw: None,
                error: Some(err.to_string()),
                mode: RunnerExecutionMode::Exec,
            }),
        }
    }

    fn invoke_provider_common_subscription_component(
        &self,
        pack: &ProviderPack,
        component_ref: &str,
        config: &JsonValue,
        input: &JsonValue,
        ctx: &OperatorContext,
    ) -> anyhow::Result<FlowOutcome> {
        let component_bytes = read_pack_component_wasm(&pack.path, component_ref)?;
        let config_json = serde_json::to_string(config)?;
        let input_json = serde_json::to_string(input)?;
        let tenant = ctx.tenant.clone();
        let team = ctx.team.clone();
        let correlation_id = ctx.correlation_id.clone();
        let secrets_manager = self.secrets_handle.runtime_manager(Some(&pack.pack_id));
        let state_store = self.state_store.clone();
        let pack_id = pack.pack_id.clone();
        let component_ref = component_ref.to_string();
        let result = make_runtime_or_thread_scope(|_| {
            let exec_ctx = ComponentExecCtx {
                tenant: ComponentTenantCtx {
                    tenant: tenant.clone(),
                    team: team.clone(),
                    i18n_id: None,
                    user: None,
                    trace_id: None,
                    correlation_id: correlation_id.clone(),
                    deadline_unix_ms: None,
                    attempt: 1,
                    idempotency_key: None,
                },
                i18n_id: None,
                flow_id: "sync-subscriptions".to_string(),
                node_id: Some("sync-subscriptions".to_string()),
            };
            let http_client = Arc::new(reqwest::blocking::Client::new());
            let host_config = Arc::new(build_demo_host_config(&tenant));
            let engine = Engine::default();
            let component = Component::from_binary(&engine, &component_bytes)?;
            let mut linker = Linker::new(&engine);
            register_all(&mut linker, true)?;
            let host_state = HostState::new(
                pack_id,
                host_config,
                http_client,
                None,
                None::<DynSessionStore>,
                Some(state_store),
                secrets_manager,
                None,
                Some(exec_ctx),
                Some(component_ref),
                true,
                None,
            )?;
            let store_state =
                ComponentState::new(host_state, Arc::new(RunnerWasiPolicy::default()))?;
            let mut store = Store::new(&engine, store_state);
            let instance = linker.instantiate(&mut store, &component)?;
            let subs_index = instance
                .get_export_index(&mut store, None, "provider:common/subscriptions@0.0.2")
                .context("get provider-common subscriptions export")?;
            let sync_index = instance
                .get_export_index(&mut store, Some(&subs_index), "sync-subscriptions")
                .context("get sync-subscriptions export")?;
            let sync: TypedFunc<(String, String), (Result<String, String>,)> = instance
                .get_typed_func(&mut store, sync_index)
                .map_err(|err| anyhow!("get typed sync-subscriptions function: {err}"))?;
            let (result,) = sync
                .call(&mut store, (config_json, input_json))
                .map_err(|err| anyhow!("call provider-common sync-subscriptions: {err}"))?;
            let output = result.map_err(anyhow::Error::msg)?;
            let value = serde_json::from_str(&output).unwrap_or(JsonValue::String(output));
            anyhow::Ok(value)
        });

        match result {
            Ok(value) => Ok(FlowOutcome {
                success: true,
                output: Some(value),
                raw: None,
                error: None,
                mode: RunnerExecutionMode::Exec,
            }),
            Err(err) => Ok(FlowOutcome {
                success: false,
                output: None,
                raw: None,
                error: Some(err.to_string()),
                mode: RunnerExecutionMode::Exec,
            }),
        }
    }

    pub(crate) fn invoke_provider_ingress_extension(
        &self,
        domain: Domain,
        provider_id: &str,
        headers_json: String,
        body_json: String,
        ctx: &OperatorContext,
    ) -> anyhow::Result<Option<FlowOutcome>> {
        let Some(pack) = self.catalog.get(&(domain, provider_id.to_string())) else {
            return Ok(None);
        };
        let Some(extension) = read_provider_ingress_extension(&pack.path)? else {
            return Ok(None);
        };
        let component_bytes = read_pack_component_wasm(&pack.path, &extension.component_ref)?;
        let tenant = ctx.tenant.clone();
        let team = ctx.team.clone();
        let correlation_id = ctx.correlation_id.clone();
        let secrets_manager = self.secrets_handle.runtime_manager(Some(&pack.pack_id));
        let state_store = self.state_store.clone();
        let pack_id = pack.pack_id.clone();
        let result = make_runtime_or_thread_scope(|_| {
            let exec_ctx = ComponentExecCtx {
                tenant: ComponentTenantCtx {
                    tenant: tenant.clone(),
                    team: team.clone(),
                    i18n_id: None,
                    user: None,
                    trace_id: None,
                    correlation_id: correlation_id.clone(),
                    deadline_unix_ms: None,
                    attempt: 1,
                    idempotency_key: None,
                },
                i18n_id: None,
                flow_id: extension.export_name.clone(),
                node_id: Some(extension.export_name.clone()),
            };
            let http_client = Arc::new(reqwest::blocking::Client::new());
            let host_config = Arc::new(build_demo_host_config(&tenant));
            let engine = Engine::default();
            let component = Component::from_binary(&engine, &component_bytes)?;
            let mut linker = Linker::new(&engine);
            register_all(&mut linker, true)?;
            let host_state = HostState::new(
                pack_id,
                host_config,
                http_client,
                None,
                None::<DynSessionStore>,
                Some(state_store),
                secrets_manager,
                None,
                Some(exec_ctx),
                Some(extension.component_ref.clone()),
                true,
                None,
            )?;
            let store_state =
                ComponentState::new(host_state, Arc::new(RunnerWasiPolicy::default()))?;
            let mut store = Store::new(&engine, store_state);
            let instance = linker.instantiate(&mut store, &component)?;
            let ingress_index = instance
                .get_export_index(&mut store, None, "provider:common/ingress@0.0.2")
                .context("get provider-common ingress export")?;
            let handle_index = instance
                .get_export_index(&mut store, Some(&ingress_index), &extension.export_name)
                .with_context(|| format!("get {} export", extension.export_name))?;
            let handle: TypedFunc<(String, String), (Result<String, String>,)> = instance
                .get_typed_func(&mut store, handle_index)
                .map_err(|err| anyhow!("get typed handle-webhook function: {err}"))?;
            let (result,) = handle
                .call(&mut store, (headers_json, body_json))
                .map_err(|err| anyhow!("call provider-common handle-webhook: {err}"))?;
            let output = result.map_err(anyhow::Error::msg)?;
            let value = serde_json::from_str(&output).unwrap_or(JsonValue::String(output));
            anyhow::Ok(value)
        });

        let outcome = match result {
            Ok(value) => FlowOutcome {
                success: true,
                output: Some(value),
                raw: None,
                error: None,
                mode: RunnerExecutionMode::Exec,
            },
            Err(err) => FlowOutcome {
                success: false,
                output: None,
                raw: None,
                error: Some(err.to_string()),
                mode: RunnerExecutionMode::Exec,
            },
        };
        Ok(Some(outcome))
    }
}

fn operation_is_provider_common_subscription(op_id: &str) -> bool {
    op_id == "sync-subscriptions"
}

fn is_startup_diagnostic_op(op_id: &str) -> bool {
    matches!(
        op_id,
        "setup_webhook"
            | "verify_webhooks"
            | "sync-subscriptions"
            | "sync_subscriptions"
            | "subscription_ensure"
            | "subscription_renew"
            | "subscription_delete"
    )
}

fn read_pack_component_wasm(pack_path: &Path, component_ref: &str) -> anyhow::Result<Vec<u8>> {
    let wasm = find_component_wasm_path(pack_path, component_ref)?
        .ok_or_else(|| anyhow::anyhow!("component '{component_ref}' not found in pack manifest"))?;
    if pack_path.is_dir() {
        let wasm_path = pack_path.join(wasm);
        return std::fs::read(&wasm_path)
            .with_context(|| format!("read component wasm {}", wasm_path.display()));
    }
    let file =
        File::open(pack_path).with_context(|| format!("open pack {}", pack_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("read pack archive {}", pack_path.display()))?;
    let mut entry = archive
        .by_name(&wasm)
        .with_context(|| format!("read component wasm {wasm} from {}", pack_path.display()))?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn find_component_wasm_path(
    pack_path: &Path,
    component_ref: &str,
) -> anyhow::Result<Option<String>> {
    if let Some(manifest) = read_pack_manifest_json(pack_path)?
        && let Some(wasm) = manifest
            .components
            .iter()
            .find(|component| component.id == component_ref)
            .and_then(|component| component.wasm.clone())
    {
        return Ok(Some(wasm));
    }

    if let Some(bytes) = read_pack_manifest_cbor_bytes(pack_path)? {
        let manifest = decode_pack_manifest(&bytes)
            .with_context(|| format!("parse manifest.cbor from {}", pack_path.display()))?;
        if manifest
            .components
            .iter()
            .any(|component| component.id.as_str() == component_ref)
        {
            if let Some(wasm) = manifest
                .extensions
                .as_ref()
                .and_then(|extensions| extensions.get(EXT_COMPONENT_SOURCES_V1))
                .and_then(|extension| extension.inline.as_ref())
                .and_then(|inline| component_source_wasm_path(inline, component_ref))
            {
                return Ok(Some(wasm));
            }
            return Ok(Some(format!("components/{component_ref}.wasm")));
        }
    }

    Ok(None)
}

fn component_source_wasm_path(inline: &ExtensionInline, component_ref: &str) -> Option<String> {
    let ExtensionInline::Other(value) = inline else {
        return None;
    };
    let sources =
        serde_json::from_value::<greentic_types::ComponentSourcesV1>(value.clone()).ok()?;
    sources
        .components
        .into_iter()
        .find(|entry| {
            entry.name == component_ref
                || entry
                    .component_id
                    .as_ref()
                    .is_some_and(|id| id.as_str() == component_ref)
        })
        .and_then(|entry| match entry.artifact {
            ArtifactLocationV1::Inline { wasm_path, .. } => Some(wasm_path),
            ArtifactLocationV1::Remote => None,
        })
}

fn read_provider_ingress_extension(
    pack_path: &Path,
) -> anyhow::Result<Option<ProviderIngressExtension>> {
    if let Some(bytes) = read_pack_manifest_cbor_bytes(pack_path)? {
        let manifest = decode_pack_manifest(&bytes)
            .with_context(|| format!("parse manifest.cbor from {}", pack_path.display()))?;
        if let Some(inline) = manifest
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.get("messaging.provider_ingress.v1"))
            .and_then(|extension| extension.inline.as_ref())
            && let ExtensionInline::Other(value) = inline
        {
            return serde_json::from_value::<ProviderIngressExtension>(value.clone())
                .map(Some)
                .with_context(|| {
                    format!(
                        "parse messaging.provider_ingress.v1 from {}",
                        pack_path.display()
                    )
                });
        }
    }

    if let Some(manifest) = read_pack_manifest_json(pack_path)?
        && let Some(value) = manifest
            .extensions
            .get("messaging.provider_ingress.v1")
            .and_then(|extension| extension.get("inline"))
    {
        return serde_json::from_value::<ProviderIngressExtension>(value.clone())
            .map(Some)
            .with_context(|| {
                format!(
                    "parse messaging.provider_ingress.v1 from {}",
                    pack_path.display()
                )
            });
    }

    Ok(None)
}

#[derive(Clone, Debug, Deserialize)]
struct ProviderIngressExtension {
    component_ref: String,
    #[serde(rename = "export")]
    export_name: String,
}

fn read_pack_manifest_cbor_bytes(pack_path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    if pack_path.is_dir() {
        let path = pack_path.join("manifest.cbor");
        if !path.exists() {
            return Ok(None);
        }
        return std::fs::read(&path)
            .map(Some)
            .with_context(|| format!("read {}", path.display()));
    }
    let file =
        File::open(pack_path).with_context(|| format!("open pack {}", pack_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("read pack archive {}", pack_path.display()))?;
    let mut entry = match archive.by_name("manifest.cbor") {
        Ok(file) => file,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn read_pack_manifest_json(pack_path: &Path) -> anyhow::Result<Option<PackManifestJson>> {
    let bytes = if pack_path.is_dir() {
        let path = pack_path.join("pack.manifest.json");
        if !path.exists() {
            return Ok(None);
        }
        std::fs::read(&path).with_context(|| format!("read {}", path.display()))?
    } else {
        let file =
            File::open(pack_path).with_context(|| format!("open pack {}", pack_path.display()))?;
        let mut archive = ZipArchive::new(file)
            .with_context(|| format!("read pack archive {}", pack_path.display()))?;
        let mut entry = match archive.by_name("pack.manifest.json") {
            Ok(file) => file,
            Err(zip::result::ZipError::FileNotFound) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        bytes
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .with_context(|| format!("parse pack.manifest.json from {}", pack_path.display()))
}

#[derive(Debug, Deserialize)]
struct PackManifestJson {
    #[serde(default)]
    components: Vec<PackComponentJson>,
    #[serde(default)]
    extensions: serde_json::Map<String, JsonValue>,
}

#[derive(Debug, Deserialize)]
struct PackComponentJson {
    id: String,
    #[serde(default)]
    wasm: Option<String>,
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

    #[test]
    fn provider_ingress_extension_can_be_read_from_json_manifest() {
        let dir = tempdir().unwrap();
        let manifest = serde_json::json!({
            "components": [],
            "extensions": {
                "messaging.provider_ingress.v1": {
                    "inline": {
                        "component_ref": "messaging-ingress-teams",
                        "export": "handle-webhook"
                    }
                }
            }
        });
        std::fs::write(
            dir.path().join("pack.manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let extension = read_provider_ingress_extension(dir.path())
            .unwrap()
            .expect("provider ingress extension");
        assert_eq!(extension.component_ref, "messaging-ingress-teams");
        assert_eq!(extension.export_name, "handle-webhook");
    }
}
