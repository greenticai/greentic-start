#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose};
use greentic_runner_desktop::RunStatus;
use greentic_runner_host::{
    RunnerWasiPolicy,
    component_api::node::{ExecCtx as ComponentExecCtx, TenantCtx as ComponentTenantCtx},
    config::{
        FlowRetryConfig, HostConfig, OperatorPolicy, RateLimits, SecretsPolicy, StateStorePolicy,
        WebhookPolicy,
    },
    pack::{ComponentResolution, PackRuntime},
    storage::{DynSessionStore, DynStateStore, new_state_store},
    trace::TraceConfig,
    validate::ValidationConfig,
};
use greentic_types::cbor::canonical;
use greentic_types::decode_pack_manifest;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use tokio::runtime::Runtime as TokioRuntime;
use zip::ZipArchive;

/// Create a Tokio runtime for blocking async operations.
/// When called from within an existing runtime (e.g., HTTP ingress handler),
/// spawns a dedicated thread to avoid "Cannot start a runtime from within a
/// runtime" panics.
fn make_runtime_or_thread_scope<F, T>(f: F) -> T
where
    F: FnOnce(&TokioRuntime) -> T + Send,
    T: Send,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::scope(|s| {
            s.spawn(|| {
                let rt = TokioRuntime::new().expect("failed to create tokio runtime");
                f(&rt)
            })
            .join()
            .expect("provider invocation thread panicked")
        })
    } else {
        let rt = TokioRuntime::new().expect("failed to create tokio runtime");
        f(&rt)
    }
}

use crate::capabilities::{
    CAP_OAUTH_BROKER_V1, CAP_OAUTH_TOKEN_VALIDATION_V1, CapabilityBinding, CapabilityInstallRecord,
    CapabilityPackRecord, CapabilityRegistry, HookStage, OAUTH_OP_AWAIT_RESULT,
    OAUTH_OP_GET_ACCESS_TOKEN, OAUTH_OP_INITIATE_AUTH, OAUTH_OP_REQUEST_RESOURCE_TOKEN,
    ResolveScope, is_binding_ready, is_oauth_broker_operation, write_install_record,
};
use crate::cards::CardRenderer;
use crate::discovery;
use crate::domains::{self, Domain, ProviderPack};
use crate::operator_log;
use crate::runner_exec;
use crate::runner_integration;
use crate::runner_integration::RunFlowOptions;
use crate::runner_integration::RunnerFlavor;
use crate::runner_integration::run_flow_with_options;
use crate::secrets_gate::{self, DynSecretsManager, SecretsManagerHandle};
use crate::secrets_manager;
use crate::state_layout;

#[derive(Clone)]
pub struct OperatorContext {
    pub tenant: String,
    pub team: Option<String>,
    pub correlation_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerExecutionMode {
    Exec,
    Integration,
}

#[derive(Clone)]
pub struct FlowOutcome {
    pub success: bool,
    pub output: Option<JsonValue>,
    pub raw: Option<String>,
    pub error: Option<String>,
    pub mode: RunnerExecutionMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OperationStatus {
    Pending,
    Denied,
    Ok,
    Err,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OperationEnvelopeContext {
    tenant: String,
    team: Option<String>,
    correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_claims: Option<JsonValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OperationEnvelope {
    op_id: String,
    op_name: String,
    ctx: OperationEnvelopeContext,
    payload_cbor: Vec<u8>,
    meta_cbor: Option<Vec<u8>>,
    status: OperationStatus,
    result_cbor: Option<Vec<u8>>,
}

impl OperationEnvelope {
    fn new(op_name: &str, payload: &[u8], ctx: &OperatorContext) -> Self {
        Self {
            op_id: uuid::Uuid::new_v4().to_string(),
            op_name: op_name.to_string(),
            ctx: OperationEnvelopeContext {
                tenant: ctx.tenant.clone(),
                team: ctx.team.clone(),
                correlation_id: ctx.correlation_id.clone(),
                auth_claims: None,
            },
            payload_cbor: payload.to_vec(),
            meta_cbor: None,
            status: OperationStatus::Pending,
            result_cbor: None,
        }
    }
}

#[derive(Debug, Serialize)]
struct HookEvalRequest {
    stage: String,
    op_name: String,
    envelope: OperationEnvelope,
}

#[derive(Debug, Deserialize)]
struct HookEvalResponse {
    decision: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    envelope: Option<OperationEnvelope>,
}

#[derive(Debug)]
enum HookChainOutcome {
    Continue,
    Denied(String),
}

#[derive(Clone, Debug)]
enum RunnerMode {
    Exec,
    Integration {
        binary: PathBuf,
        flavor: RunnerFlavor,
    },
}

#[derive(Clone)]
pub struct DemoRunnerHost {
    bundle_root: PathBuf,
    runner_mode: RunnerMode,
    catalog: HashMap<(Domain, String), ProviderPack>,
    packs_by_path: BTreeMap<PathBuf, ProviderPack>,
    capability_registry: CapabilityRegistry,
    secrets_handle: SecretsManagerHandle,
    card_renderer: CardRenderer,
    state_store: DynStateStore,
    debug_enabled: bool,
}

impl DemoRunnerHost {
    pub fn bundle_root(&self) -> &Path {
        &self.bundle_root
    }

    pub fn secrets_manager(&self) -> DynSecretsManager {
        self.secrets_handle.manager()
    }

    pub fn secrets_handle(&self) -> &SecretsManagerHandle {
        &self.secrets_handle
    }

    pub fn new(
        bundle_root: PathBuf,
        discovery: &discovery::DiscoveryResult,
        runner_binary: Option<PathBuf>,
        secrets_handle: SecretsManagerHandle,
        debug_enabled: bool,
    ) -> anyhow::Result<Self> {
        let runner_binary = runner_binary.and_then(validate_runner_binary);
        let mode = if let Some(ref binary) = runner_binary {
            let flavor = runner_integration::detect_runner_flavor(binary);
            RunnerMode::Integration {
                binary: binary.clone(),
                flavor,
            }
        } else {
            RunnerMode::Exec
        };
        let mut catalog = HashMap::new();
        let mut packs_by_path = BTreeMap::new();
        let mut pack_index: BTreeMap<PathBuf, CapabilityPackRecord> = BTreeMap::new();
        let provider_map = discovery
            .providers
            .iter()
            .map(|provider| (provider.pack_path.clone(), provider.provider_id.clone()))
            .collect::<HashMap<_, _>>();
        for domain in [
            Domain::Messaging,
            Domain::Events,
            Domain::Secrets,
            Domain::OAuth,
        ] {
            let is_demo_bundle = bundle_root.join("greentic.demo.yaml").exists();
            let packs = if is_demo_bundle {
                domains::discover_provider_packs_cbor_only(&bundle_root, domain)?
            } else {
                domains::discover_provider_packs(&bundle_root, domain)?
            };
            for pack in packs {
                packs_by_path.insert(pack.path.clone(), pack.clone());
                pack_index.insert(
                    pack.path.clone(),
                    CapabilityPackRecord {
                        pack_id: pack.pack_id.clone(),
                        domain,
                    },
                );
                let provider_type = provider_map
                    .get(&pack.path)
                    .cloned()
                    .unwrap_or_else(|| pack.pack_id.clone());
                catalog.insert((domain, provider_type.clone()), pack.clone());
                if provider_type != pack.pack_id {
                    catalog.insert((domain, pack.pack_id.clone()), pack.clone());
                }
                // Add short aliases for packs with long pack_ids (e.g., "greentic.events.webhook" → "webhook")
                let aliases = extract_provider_short_aliases(&pack.pack_id, domain);
                for alias in aliases {
                    if alias != provider_type && alias != pack.pack_id {
                        catalog.entry((domain, alias)).or_insert_with(|| pack.clone());
                    }
                }
            }
        }
        let capability_registry = CapabilityRegistry::build_from_pack_index(&pack_index)?;
        Ok(Self {
            bundle_root,
            runner_mode: mode,
            catalog,
            packs_by_path,
            capability_registry,
            secrets_handle,
            card_renderer: CardRenderer::new(),
            state_store: new_state_store(),
            debug_enabled,
        })
    }

    pub fn debug_enabled(&self) -> bool {
        self.debug_enabled
    }

    /// Return the canonical `provider_type` stored inside a provider pack manifest
    /// (e.g. `"messaging.webex.bot"`).  Falls back to the lookup key when the pack
    /// is not found or the manifest cannot be read.
    pub fn canonical_provider_type(&self, domain: Domain, lookup_key: &str) -> String {
        if let Some(pack) = self.catalog.get(&(domain, lookup_key.to_string())) {
            primary_provider_type(&pack.path).unwrap_or_else(|_| lookup_key.to_string())
        } else {
            lookup_key.to_string()
        }
    }

    pub fn resolve_capability(
        &self,
        cap_id: &str,
        min_version: Option<&str>,
        scope: ResolveScope,
    ) -> Option<CapabilityBinding> {
        self.capability_registry
            .resolve(cap_id, min_version, &scope)
    }

    pub fn resolve_hook_chain(&self, stage: HookStage, op_name: &str) -> Vec<CapabilityBinding> {
        self.capability_registry.resolve_hook_chain(stage, op_name)
    }

    pub fn has_provider_packs_for_domain(&self, domain: Domain) -> bool {
        self.catalog
            .keys()
            .any(|(entry_domain, _)| *entry_domain == domain)
    }

    pub fn capability_setup_plan(&self, ctx: &OperatorContext) -> Vec<CapabilityBinding> {
        let scope = ResolveScope {
            env: env::var("GREENTIC_ENV").ok(),
            tenant: Some(ctx.tenant.clone()),
            team: ctx.team.clone(),
        };
        self.capability_registry
            .offers_requiring_setup(&scope)
            .into_iter()
            .map(|offer| CapabilityBinding {
                cap_id: offer.cap_id,
                stable_id: offer.stable_id,
                pack_id: offer.pack_id,
                domain: offer.domain,
                pack_path: offer.pack_path,
                provider_component_ref: offer.provider_component_ref,
                provider_op: offer.provider_op,
                version: offer.version,
                requires_setup: offer.requires_setup,
                setup_qa_ref: offer.setup_qa_ref,
            })
            .collect()
    }

    pub fn mark_capability_ready(
        &self,
        ctx: &OperatorContext,
        binding: &CapabilityBinding,
    ) -> anyhow::Result<PathBuf> {
        let record =
            CapabilityInstallRecord::ready(&binding.cap_id, &binding.stable_id, &binding.pack_id);
        write_install_record(&self.bundle_root, &ctx.tenant, ctx.team.as_deref(), &record)
    }

    pub fn mark_capability_failed(
        &self,
        ctx: &OperatorContext,
        binding: &CapabilityBinding,
        failure_key: &str,
    ) -> anyhow::Result<PathBuf> {
        let record = CapabilityInstallRecord::failed(
            &binding.cap_id,
            &binding.stable_id,
            &binding.pack_id,
            failure_key,
        );
        write_install_record(&self.bundle_root, &ctx.tenant, ctx.team.as_deref(), &record)
    }

    pub fn invoke_capability(
        &self,
        cap_id: &str,
        op: &str,
        payload_bytes: &[u8],
        ctx: &OperatorContext,
    ) -> anyhow::Result<FlowOutcome> {
        let requested_op = op.trim();
        if cap_id == CAP_OAUTH_BROKER_V1 {
            if requested_op.is_empty() {
                return Ok(capability_route_error_outcome(
                    cap_id,
                    "<missing-op>",
                    format!(
                        "oauth broker capability requires an explicit op (supported: {}, {}, {}, {})",
                        OAUTH_OP_INITIATE_AUTH,
                        OAUTH_OP_AWAIT_RESULT,
                        OAUTH_OP_GET_ACCESS_TOKEN,
                        OAUTH_OP_REQUEST_RESOURCE_TOKEN
                    ),
                ));
            }
            if !is_oauth_broker_operation(requested_op) {
                return Ok(capability_route_error_outcome(
                    cap_id,
                    requested_op,
                    format!(
                        "unsupported oauth broker op `{requested_op}` (supported: {}, {}, {}, {})",
                        OAUTH_OP_INITIATE_AUTH,
                        OAUTH_OP_AWAIT_RESULT,
                        OAUTH_OP_GET_ACCESS_TOKEN,
                        OAUTH_OP_REQUEST_RESOURCE_TOKEN
                    ),
                ));
            }
        }
        let scope = ResolveScope {
            env: env::var("GREENTIC_ENV").ok(),
            tenant: Some(ctx.tenant.clone()),
            team: ctx.team.clone(),
        };
        let binding = if requested_op.is_empty() {
            self.resolve_capability(cap_id, None, scope)
        } else {
            self.capability_registry
                .resolve_for_op(cap_id, None, &scope, Some(requested_op))
        };
        let Some(binding) = binding else {
            return Ok(missing_capability_outcome(cap_id, op, None));
        };
        if !is_binding_ready(
            &self.bundle_root,
            &ctx.tenant,
            ctx.team.as_deref(),
            &binding,
        )? {
            return Ok(capability_not_installed_outcome(
                cap_id,
                op,
                &binding.stable_id,
            ));
        }

        let Some(pack) = self.packs_by_path.get(&binding.pack_path) else {
            return Ok(capability_route_error_outcome(
                cap_id,
                op,
                format!("resolved pack not found at {}", binding.pack_path.display()),
            ));
        };

        let target_op = if cap_id == CAP_OAUTH_BROKER_V1 || requested_op.is_empty() {
            // OAuth broker cap.invoke always routes through the selected provider op.
            binding.provider_op.as_str()
        } else {
            requested_op
        };

        // Capability invocations go through the same operator pipeline.
        let mut envelope =
            OperationEnvelope::new(&format!("cap.invoke:{cap_id}"), payload_bytes, ctx);
        let token_validation_outcome =
            self.evaluate_token_validation_pre_hook(&mut envelope, payload_bytes, ctx)?;
        if let HookChainOutcome::Denied(reason) = token_validation_outcome {
            envelope.status = OperationStatus::Denied;
            self.emit_post_sub(&envelope);
            return Ok(capability_route_error_outcome(
                cap_id,
                target_op,
                format!("operation denied by pre-hook: {reason}"),
            ));
        }
        let pre_chain = self.resolve_hook_chain(HookStage::Pre, &envelope.op_name);
        let pre_hook_outcome =
            self.evaluate_hook_chain(&pre_chain, HookStage::Pre, &mut envelope)?;
        self.emit_pre_sub(&envelope);
        if let HookChainOutcome::Denied(reason) = pre_hook_outcome {
            envelope.status = OperationStatus::Denied;
            self.emit_post_sub(&envelope);
            return Ok(capability_route_error_outcome(
                cap_id,
                target_op,
                format!("operation denied by pre-hook: {reason}"),
            ));
        }

        let outcome = self.invoke_provider_component_op(
            binding.domain,
            pack,
            &binding.pack_id,
            target_op,
            payload_bytes,
            ctx,
        )?;

        envelope.status = if outcome.success {
            OperationStatus::Ok
        } else {
            OperationStatus::Err
        };
        envelope.result_cbor = outcome.output.as_ref().and_then(json_to_canonical_cbor);
        let post_chain = self.resolve_hook_chain(HookStage::Post, &envelope.op_name);
        let _ = self.evaluate_hook_chain(&post_chain, HookStage::Post, &mut envelope)?;
        self.emit_post_sub(&envelope);
        Ok(outcome)
    }

    pub fn supports_op(&self, domain: Domain, provider_type: &str, op_id: &str) -> bool {
        self.catalog
            .get(&(domain, provider_type.to_string()))
            .map(|pack| {
                pack.entry_flows.iter().any(|flow| flow == op_id)
                    || pack_supports_provider_op(&pack.path, op_id).unwrap_or(false)
            })
            .unwrap_or(false)
    }

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
        let pre_chain = self.resolve_hook_chain(HookStage::Pre, op_id);
        let pre_hook_outcome =
            self.evaluate_hook_chain(&pre_chain, HookStage::Pre, &mut envelope)?;
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

        let post_chain = self.resolve_hook_chain(HookStage::Post, op_id);
        let _ = self.evaluate_hook_chain(&post_chain, HookStage::Post, &mut envelope)?;
        self.emit_post_sub(&envelope);
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

    fn evaluate_hook_chain(
        &self,
        chain: &[CapabilityBinding],
        stage: HookStage,
        envelope: &mut OperationEnvelope,
    ) -> anyhow::Result<HookChainOutcome> {
        for binding in chain {
            let Some(pack) = self.packs_by_path.get(&binding.pack_path) else {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "hook binding skipped; pack not found stable_id={} path={}",
                        binding.stable_id,
                        binding.pack_path.display()
                    ),
                );
                continue;
            };

            let payload = canonical::to_canonical_cbor(&HookEvalRequest {
                stage: match stage {
                    HookStage::Pre => "pre",
                    HookStage::Post => "post",
                }
                .to_string(),
                op_name: envelope.op_name.clone(),
                envelope: envelope.clone(),
            })
            .map_err(|err| anyhow!("failed to encode hook request as cbor: {err}"))?;
            let ctx = OperatorContext {
                tenant: envelope.ctx.tenant.clone(),
                team: envelope.ctx.team.clone(),
                correlation_id: envelope.ctx.correlation_id.clone(),
            };
            let outcome = self.invoke_provider_component_op(
                binding.domain,
                pack,
                &binding.pack_id,
                &binding.provider_op,
                &payload,
                &ctx,
            )?;
            if !outcome.success {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "hook invocation failed stage={:?} binding={} err={}",
                        stage,
                        binding.stable_id,
                        outcome.error.unwrap_or_else(|| "unknown error".to_string())
                    ),
                );
                continue;
            }
            let Some(output) = outcome.output else {
                continue;
            };
            let parsed: HookEvalResponse = match decode_hook_response(&output) {
                Ok(value) => value,
                Err(err) => {
                    operator_log::warn(
                        module_path!(),
                        format!(
                            "hook response decode failed stage={:?} binding={} err={} (expected cbor, with legacy json fallback)",
                            stage, binding.stable_id, err
                        ),
                    );
                    continue;
                }
            };
            if let Some(updated) = parsed.envelope {
                *envelope = updated;
            }
            if parsed.decision.eq_ignore_ascii_case("deny") && matches!(stage, HookStage::Pre) {
                let reason = parsed
                    .reason
                    .unwrap_or_else(|| "hook denied operation".to_string());
                return Ok(HookChainOutcome::Denied(reason));
            }
        }
        Ok(HookChainOutcome::Continue)
    }

    fn evaluate_token_validation_pre_hook(
        &self,
        envelope: &mut OperationEnvelope,
        payload_bytes: &[u8],
        ctx: &OperatorContext,
    ) -> anyhow::Result<HookChainOutcome> {
        if envelope
            .op_name
            .starts_with(&format!("cap.invoke:{CAP_OAUTH_TOKEN_VALIDATION_V1}"))
        {
            return Ok(HookChainOutcome::Continue);
        }
        let Some(validation_request) = extract_token_validation_request(payload_bytes) else {
            return Ok(HookChainOutcome::Continue);
        };
        let scope = ResolveScope {
            env: env::var("GREENTIC_ENV").ok(),
            tenant: Some(ctx.tenant.clone()),
            team: ctx.team.clone(),
        };
        let Some(binding) = self.resolve_capability(CAP_OAUTH_TOKEN_VALIDATION_V1, None, scope)
        else {
            return Ok(HookChainOutcome::Continue);
        };
        if !is_binding_ready(
            &self.bundle_root,
            &ctx.tenant,
            ctx.team.as_deref(),
            &binding,
        )? {
            return Ok(HookChainOutcome::Denied(format!(
                "token validation capability is not installed (stable_id={})",
                binding.stable_id
            )));
        }
        let Some(pack) = self.packs_by_path.get(&binding.pack_path) else {
            return Ok(HookChainOutcome::Denied(format!(
                "token validation pack not found at {}",
                binding.pack_path.display()
            )));
        };
        let request_bytes = serde_json::to_vec(&validation_request)
            .map_err(|err| anyhow!("failed to encode token validation payload: {err}"))?;
        let outcome = self.invoke_provider_component_op(
            binding.domain,
            pack,
            &binding.pack_id,
            &binding.provider_op,
            &request_bytes,
            ctx,
        )?;
        if !outcome.success {
            let reason = outcome
                .error
                .unwrap_or_else(|| "token validation capability invocation failed".to_string());
            return Ok(HookChainOutcome::Denied(reason));
        }
        let Some(output) = outcome.output else {
            return Ok(HookChainOutcome::Denied(
                "token validation returned no output".to_string(),
            ));
        };
        match evaluate_token_validation_output(&output) {
            TokenValidationDecision::Allow(claims) => {
                envelope.ctx.auth_claims = claims;
                Ok(HookChainOutcome::Continue)
            }
            TokenValidationDecision::Deny(reason) => Ok(HookChainOutcome::Denied(reason)),
        }
    }

    fn emit_pre_sub(&self, envelope: &OperationEnvelope) {
        operator_log::info(
            module_path!(),
            format!(
                "sub.pre op={} status={:?} tenant={} team={}",
                envelope.op_name,
                envelope.status,
                envelope.ctx.tenant,
                envelope.ctx.team.as_deref().unwrap_or("default")
            ),
        );
    }

    fn emit_post_sub(&self, envelope: &OperationEnvelope) {
        operator_log::info(
            module_path!(),
            format!(
                "sub.post op={} status={:?} tenant={} team={}",
                envelope.op_name,
                envelope.status,
                envelope.ctx.tenant,
                envelope.ctx.team.as_deref().unwrap_or("default")
            ),
        );
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

    fn invoke_provider_component_op(
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
            // Re-open the dev store on each invocation so newly-written secrets
            // (e.g. from QA wizard submit) are visible without restarting the demo.
            let fresh_secrets = secrets_gate::resolve_secrets_manager(
                &self.bundle_root,
                &ctx.tenant,
                ctx.team.as_deref(),
            )
            .unwrap_or_else(|_| self.secrets_handle.clone());
            let dev_store_display = fresh_secrets
                .dev_store_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<default>".to_string());
            operator_log::info(
                module_path!(),
                format!(
                    "secrets backend for wasm: using_env_fallback={} dev_store={}",
                    fresh_secrets.using_env_fallback, dev_store_display,
                ),
            );
            operator_log::info(
                module_path!(),
                format!(
                    "exec secrets: dev_store={} env_fallback={}",
                    dev_store_display, fresh_secrets.using_env_fallback,
                ),
            );
            let pack_runtime = PackRuntime::load(
                &pack.path,
                host_config.clone(),
                None,
                Some(&pack.path),
                None::<DynSessionStore>,
                Some(self.state_store.clone()),
                Arc::new(RunnerWasiPolicy::default()),
                fresh_secrets.runtime_manager(Some(&pack.pack_id)),
                None,
                false,
                ComponentResolution::default(),
            )
            .await?;
            let provider_type = primary_provider_type(&pack.path)
                .context("failed to determine provider type for direct invocation")?;
            let env_value = env::var("GREENTIC_ENV").unwrap_or_else(|_| "<unset>".to_string());
            let canonical_team = secrets_manager::canonical_team(ctx.team.as_deref()).into_owned();
            let runner_dev_store_desc = self
                .secrets_handle
                .dev_store_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string());
            eprintln!(
                "secrets runner ctx: env={} tenant={} canonical_team={} provider_id={} pack_id={} dev_store_path={} using_env_fallback={}",
                env_value,
                ctx.tenant,
                canonical_team,
                provider_type,
                pack.pack_id,
                runner_dev_store_desc,
                self.secrets_handle.using_env_fallback,
            );
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
            Ok(value) => Ok(FlowOutcome {
                success: true,
                output: Some(value),
                raw: None,
                error: None,
                mode: RunnerExecutionMode::Exec,
            }),
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

pub fn primary_provider_type(pack_path: &Path) -> anyhow::Result<String> {
    let file = std::fs::File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest_entry = archive.by_name("manifest.cbor").map_err(|err| {
        anyhow!(
            "failed to open manifest.cbor in {}: {err}",
            pack_path.display()
        )
    })?;
    let mut bytes = Vec::new();
    manifest_entry.read_to_end(&mut bytes)?;
    let manifest = decode_pack_manifest(&bytes)
        .context("failed to decode pack manifest for provider introspection")?;
    let inline = manifest.provider_extension_inline().ok_or_else(|| {
        anyhow!(
            "pack {} provider extension missing or not inline",
            pack_path.display()
        )
    })?;
    let provider = inline.providers.first().ok_or_else(|| {
        anyhow!(
            "pack {} provider extension contains no providers",
            pack_path.display()
        )
    })?;
    Ok(provider.provider_type.clone())
}

fn needs_secret_context(message: &str) -> bool {
    let lower = message.to_lowercase();
    lower.contains("secret store error") || message.contains("SecretsError")
}

fn secret_error_context(
    ctx: &OperatorContext,
    provider_id: &str,
    op_id: &str,
    pack: &ProviderPack,
) -> String {
    let env = env::var("GREENTIC_ENV").unwrap_or_else(|_| "local".to_string());
    let team = secrets_manager::canonical_team(ctx.team.as_deref()).into_owned();
    format!(
        "secret lookup context env={} tenant={} team={} provider={} flow={} pack_id={} pack_path={}",
        env,
        ctx.tenant,
        team,
        provider_id,
        op_id,
        pack.pack_id,
        pack.path.display()
    )
}

fn json_to_canonical_cbor(value: &JsonValue) -> Option<Vec<u8>> {
    canonical::to_canonical_cbor_allow_floats(value).ok()
}

fn decode_hook_response(value: &JsonValue) -> anyhow::Result<HookEvalResponse> {
    if let Some(cbor) = extract_cbor_blob(value)
        && let Ok(parsed) = serde_cbor::from_slice::<HookEvalResponse>(&cbor)
    {
        return Ok(parsed);
    }
    serde_json::from_value(value.clone())
        .map_err(|err| anyhow!("hook response is not valid cbor or legacy json: {err}"))
}

fn extract_cbor_blob(value: &JsonValue) -> Option<Vec<u8>> {
    match value {
        JsonValue::Array(items) => items
            .iter()
            .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect::<Option<Vec<u8>>>(),
        JsonValue::String(s) => general_purpose::STANDARD.decode(s).ok(),
        JsonValue::Object(map) => {
            for key in ["hook_decision_cbor_b64", "cbor_b64", "hook_decision_cbor"] {
                let Some(raw) = map.get(key) else {
                    continue;
                };
                if let JsonValue::String(s) = raw
                    && let Ok(bytes) = general_purpose::STANDARD.decode(s)
                {
                    return Some(bytes);
                }
                if let Some(bytes) = extract_cbor_blob(raw) {
                    return Some(bytes);
                }
            }
            None
        }
        _ => None,
    }
}

fn missing_capability_outcome(
    cap_id: &str,
    op_name: &str,
    component_id: Option<&str>,
) -> FlowOutcome {
    FlowOutcome {
        success: false,
        output: Some(json!({
            "code": "missing_capability",
            "error": {
                "type": "MissingCapability",
                "cap_id": cap_id,
                "op_name": op_name,
                "component_id": component_id,
            }
        })),
        raw: None,
        error: Some(format!(
            "MissingCapability(cap_id={cap_id}, op_name={op_name}, component_id={})",
            component_id.unwrap_or("<unknown>")
        )),
        mode: RunnerExecutionMode::Exec,
    }
}

fn capability_not_installed_outcome(cap_id: &str, op_name: &str, stable_id: &str) -> FlowOutcome {
    FlowOutcome {
        success: false,
        output: Some(json!({
            "code": "capability_not_installed",
            "error": {
                "type": "CapabilityNotInstalled",
                "cap_id": cap_id,
                "op_name": op_name,
                "stable_id": stable_id,
            }
        })),
        raw: None,
        error: Some(format!(
            "CapabilityNotInstalled(cap_id={cap_id}, op_name={op_name}, stable_id={stable_id})"
        )),
        mode: RunnerExecutionMode::Exec,
    }
}

fn capability_route_error_outcome(cap_id: &str, op_name: &str, reason: String) -> FlowOutcome {
    FlowOutcome {
        success: false,
        output: Some(json!({
            "code": "capability_route_error",
            "error": {
                "type": "CapabilityRouteError",
                "cap_id": cap_id,
                "op_name": op_name,
                "reason": reason,
            }
        })),
        raw: None,
        error: Some(reason),
        mode: RunnerExecutionMode::Exec,
    }
}

fn read_transcript_outputs(run_dir: &Path) -> anyhow::Result<Option<JsonValue>> {
    let path = run_dir.join("transcript.jsonl");
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(path)?;
    let mut last = None;
    for line in contents.lines() {
        let Ok(value) = serde_json::from_str::<JsonValue>(line) else {
            continue;
        };
        let Some(outputs) = value.get("outputs") else {
            continue;
        };
        if !outputs.is_null() {
            last = Some(outputs.clone());
        }
    }
    Ok(last)
}

fn build_demo_host_config(tenant: &str) -> HostConfig {
    HostConfig {
        tenant: tenant.to_string(),
        bindings_path: PathBuf::from("<demo-provider>"),
        flow_type_bindings: HashMap::new(),
        rate_limits: RateLimits::default(),
        retry: FlowRetryConfig::default(),
        http_enabled: true,
        secrets_policy: SecretsPolicy::allow_all(),
        state_store_policy: StateStorePolicy::default(),
        webhook_policy: WebhookPolicy::default(),
        timers: Vec::new(),
        oauth: None,
        mocks: None,
        pack_bindings: Vec::new(),
        env_passthrough: Vec::new(),
        trace: TraceConfig::from_env(),
        validation: ValidationConfig::from_env(),
        operator_policy: OperatorPolicy::allow_all(),
    }
}

fn validate_runner_binary(path: PathBuf) -> Option<PathBuf> {
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() && runner_binary_is_executable(&metadata) => Some(path),
        Ok(metadata) => {
            let reason = if !metadata.is_file() {
                "not a regular file"
            } else {
                "not executable"
            };
            operator_log::warn(
                module_path!(),
                format!(
                    "runner binary '{}' is not usable ({})",
                    path.display(),
                    reason
                ),
            );
            None
        }
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "runner binary '{}' cannot be accessed: {}",
                    path.display(),
                    err
                ),
            );
            None
        }
    }
}

fn domain_name(domain: Domain) -> &'static str {
    match domain {
        Domain::Messaging => "messaging",
        Domain::Events => "events",
        Domain::Secrets => "secrets",
        Domain::OAuth => "oauth",
    }
}

fn pack_supports_provider_op(pack_path: &Path, op_id: &str) -> anyhow::Result<bool> {
    let file = std::fs::File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest_entry = archive.by_name("manifest.cbor").map_err(|err| {
        anyhow!(
            "failed to open manifest.cbor in {}: {err}",
            pack_path.display()
        )
    })?;
    let mut bytes = Vec::new();
    manifest_entry.read_to_end(&mut bytes)?;
    let manifest = decode_pack_manifest(&bytes)
        .context("failed to decode pack manifest for op support introspection")?;
    let Some(provider_ext) = manifest.provider_extension_inline() else {
        return Ok(false);
    };
    Ok(provider_ext
        .providers
        .iter()
        .any(|provider| provider.ops.iter().any(|op| op == op_id)))
}

/// Extract short aliases from a pack_id for catalog registration.
///
/// Automatically generates progressive aliases by splitting on dots and hyphens:
/// - "greentic.events.email.sendgrid" → ["sendgrid", "email.sendgrid", "events.email.sendgrid"]
/// - "greentic.events.webhook" → ["webhook", "events.webhook"]
/// - "messaging-telegram" → ["telegram"]
/// - "state-memory" → ["memory"]
fn extract_provider_short_aliases(pack_id: &str, _domain: Domain) -> Vec<String> {
    let mut aliases = Vec::new();

    // Handle dot-separated pack_ids (e.g., "greentic.events.email.sendgrid")
    // Generate progressive aliases from right to left
    let parts: Vec<&str> = pack_id.split('.').collect();
    if parts.len() > 1 {
        for i in (1..parts.len()).rev() {
            let alias = parts[i..].join(".");
            if !alias.is_empty() && alias != pack_id && !aliases.contains(&alias) {
                aliases.push(alias);
            }
        }
    }

    // Handle hyphenated pack_ids (e.g., "messaging-telegram", "state-memory")
    // Extract everything after the first hyphen
    if let Some(pos) = pack_id.find('-') {
        let after_hyphen = &pack_id[pos + 1..];
        if !after_hyphen.is_empty() && !aliases.contains(&after_hyphen.to_string()) {
            aliases.push(after_hyphen.to_string());
        }
    }

    aliases
}

#[cfg(unix)]
fn runner_binary_is_executable(metadata: &fs::Metadata) -> bool {
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn runner_binary_is_executable(_: &fs::Metadata) -> bool {
    true
}

fn payload_preview(bytes: &[u8]) -> String {
    const MAX_PREVIEW: usize = 256;
    if bytes.is_empty() {
        return "<empty>".to_string();
    }
    let preview_len = bytes.len().min(MAX_PREVIEW);
    if let Ok(text) = std::str::from_utf8(&bytes[..preview_len]) {
        if bytes.len() <= MAX_PREVIEW {
            text.to_string()
        } else {
            format!("{text}...")
        }
    } else {
        let encoded = general_purpose::STANDARD.encode(&bytes[..preview_len]);
        if bytes.len() <= MAX_PREVIEW {
            encoded
        } else {
            format!("{encoded}...")
        }
    }
}

fn extract_token_validation_request(payload_bytes: &[u8]) -> Option<JsonValue> {
    let payload: JsonValue = serde_json::from_slice(payload_bytes).ok()?;
    let token = extract_bearer_token(&payload)?;
    let mut request = serde_json::Map::new();
    request.insert("token".to_string(), JsonValue::String(token));
    if let Some(issuer) = first_string_at_paths(
        &payload,
        &["/token_validation/issuer", "/auth/issuer", "/issuer"],
    ) {
        request.insert("issuer".to_string(), JsonValue::String(issuer));
    }
    if let Some(audience) = first_value_at_paths(
        &payload,
        &["/token_validation/audience", "/auth/audience", "/audience"],
    ) {
        request.insert("audience".to_string(), normalize_string_or_array(audience));
    }
    if let Some(scopes) = first_value_at_paths(
        &payload,
        &[
            "/token_validation/scopes",
            "/token_validation/required_scopes",
            "/auth/scopes",
            "/auth/required_scopes",
            "/scopes",
        ],
    ) {
        request.insert("scopes".to_string(), normalize_string_or_array(scopes));
    }
    Some(JsonValue::Object(request))
}

fn extract_bearer_token(payload: &JsonValue) -> Option<String> {
    if let Some(value) = first_string_at_paths(
        payload,
        &[
            "/token_validation/token",
            "/auth/token",
            "/bearer_token",
            "/token",
            "/access_token",
            "/authorization",
        ],
    ) && let Some(token) = parse_bearer_value(&value)
    {
        return Some(token);
    }

    if let Some(headers) = payload.get("headers")
        && let Some(token) = extract_bearer_from_headers(headers)
    {
        return Some(token);
    }

    if let Some(value) = payload
        .pointer("/metadata/authorization")
        .and_then(JsonValue::as_str)
        && let Some(token) = parse_bearer_value(value)
    {
        return Some(token);
    }

    None
}

fn extract_bearer_from_headers(headers: &JsonValue) -> Option<String> {
    match headers {
        JsonValue::Object(map) => {
            for key in ["authorization", "Authorization"] {
                if let Some(value) = map.get(key).and_then(JsonValue::as_str)
                    && let Some(token) = parse_bearer_value(value)
                {
                    return Some(token);
                }
            }
            None
        }
        JsonValue::Array(values) => values.iter().find_map(|entry| {
            let name = entry
                .get("name")
                .or_else(|| entry.get("key"))
                .and_then(JsonValue::as_str)?;
            if !name.eq_ignore_ascii_case("authorization") {
                return None;
            }
            let value = entry.get("value").and_then(JsonValue::as_str)?;
            parse_bearer_value(value)
        }),
        _ => None,
    }
}

fn parse_bearer_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("Bearer ") {
        let token = rest.trim();
        if token.is_empty() {
            None
        } else {
            Some(token.to_string())
        }
    } else {
        Some(trimmed.to_string())
    }
}

fn first_string_at_paths(payload: &JsonValue, paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| payload.pointer(path).and_then(JsonValue::as_str))
        .map(str::to_string)
}

fn first_value_at_paths<'a>(payload: &'a JsonValue, paths: &[&str]) -> Option<&'a JsonValue> {
    paths.iter().find_map(|path| payload.pointer(path))
}

fn normalize_string_or_array(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::String(raw) => {
            let values = raw
                .split_whitespace()
                .filter(|entry| !entry.trim().is_empty())
                .map(|entry| JsonValue::String(entry.to_string()))
                .collect::<Vec<_>>();
            JsonValue::Array(values)
        }
        JsonValue::Array(items) => JsonValue::Array(
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(|item| JsonValue::String(item.to_string()))
                .collect(),
        ),
        _ => JsonValue::Array(Vec::new()),
    }
}

enum TokenValidationDecision {
    Allow(Option<JsonValue>),
    Deny(String),
}

fn evaluate_token_validation_output(output: &JsonValue) -> TokenValidationDecision {
    let valid = output
        .get("valid")
        .and_then(JsonValue::as_bool)
        .or_else(|| output.get("ok").and_then(JsonValue::as_bool))
        .unwrap_or(false);
    if !valid {
        let reason = output
            .get("reason")
            .and_then(JsonValue::as_str)
            .or_else(|| output.get("error").and_then(JsonValue::as_str))
            .unwrap_or("invalid bearer token");
        return TokenValidationDecision::Deny(reason.to_string());
    }
    let claims = output
        .get("claims")
        .filter(|value| value.is_object())
        .cloned()
        .or_else(|| {
            output
                .as_object()
                .is_some_and(|map| map.contains_key("sub"))
                .then(|| output.clone())
        });
    TokenValidationDecision::Allow(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn token_validation_request_extracts_bearer_and_requirements() {
        let payload = json!({
            "headers": {
                "Authorization": "Bearer token-123"
            },
            "token_validation": {
                "issuer": "https://issuer.example",
                "audience": ["api://svc"],
                "required_scopes": "read write"
            }
        });
        let request =
            extract_token_validation_request(&serde_json::to_vec(&payload).expect("payload bytes"))
                .expect("request");
        assert_eq!(
            request.pointer("/token").and_then(JsonValue::as_str),
            Some("token-123")
        );
        assert_eq!(
            request.pointer("/issuer").and_then(JsonValue::as_str),
            Some("https://issuer.example")
        );
        assert_eq!(
            request.pointer("/audience/0").and_then(JsonValue::as_str),
            Some("api://svc")
        );
        assert_eq!(
            request.pointer("/scopes/0").and_then(JsonValue::as_str),
            Some("read")
        );
        assert_eq!(
            request.pointer("/scopes/1").and_then(JsonValue::as_str),
            Some("write")
        );
    }

    #[test]
    fn token_validation_output_deny_when_invalid() {
        let output = json!({
            "valid": false,
            "reason": "issuer mismatch"
        });
        match evaluate_token_validation_output(&output) {
            TokenValidationDecision::Deny(reason) => {
                assert_eq!(reason, "issuer mismatch");
            }
            TokenValidationDecision::Allow(_) => panic!("expected deny"),
        }
    }

    #[test]
    fn token_validation_output_allows_and_returns_claims() {
        let output = json!({
            "valid": true,
            "claims": {
                "sub": "user-1",
                "scope": "read write",
                "aud": ["api://svc"]
            }
        });
        match evaluate_token_validation_output(&output) {
            TokenValidationDecision::Allow(Some(claims)) => {
                assert_eq!(
                    claims.pointer("/sub").and_then(JsonValue::as_str),
                    Some("user-1")
                );
            }
            TokenValidationDecision::Allow(None) => panic!("expected claims"),
            TokenValidationDecision::Deny(reason) => panic!("unexpected deny: {reason}"),
        }
    }
}
