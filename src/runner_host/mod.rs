#![allow(dead_code)]

mod dispatch;
mod helpers;
mod hooks;
mod token_validation;
mod types;

pub use helpers::primary_provider_type;
// RunnerExecutionMode is re-exported because it is a public field of FlowOutcome.
#[allow(unused_imports)]
pub use types::{FlowOutcome, OperatorContext, RunnerExecutionMode};

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::path::{Path, PathBuf};

use greentic_runner_host::storage::{DynStateStore, new_state_store};

use crate::capabilities::{
    CAP_OAUTH_BROKER_V1, CapabilityBinding, CapabilityInstallRecord, CapabilityPackRecord,
    CapabilityRegistry, HookStage, OAUTH_OP_AWAIT_RESULT, OAUTH_OP_GET_ACCESS_TOKEN,
    OAUTH_OP_INITIATE_AUTH, OAUTH_OP_REQUEST_RESOURCE_TOKEN, ResolveScope, is_binding_ready,
    is_oauth_broker_operation, write_install_record,
};
use crate::cards::CardRenderer;
use crate::discovery;
use crate::domains::{self, Domain, ProviderPack};
use crate::runner_integration;
use crate::secrets_gate::{DynSecretsManager, SecretsManagerHandle};

use helpers::{
    capability_not_installed_outcome, capability_route_error_outcome,
    extract_provider_short_aliases, make_runtime_or_thread_scope, missing_capability_outcome,
    pack_supports_provider_op, validate_runner_binary,
};
use hooks::json_to_canonical_cbor;
use types::{HookChainOutcome, OperationEnvelope, OperationStatus, RunnerMode};

pub struct DemoRunnerHost {
    bundle_root: PathBuf,
    runner_mode: RunnerMode,
    catalog: HashMap<(Domain, String), ProviderPack>,
    packs_by_path: BTreeMap<PathBuf, ProviderPack>,
    pub(crate) capability_registry: CapabilityRegistry,
    secrets_handle: SecretsManagerHandle,
    pub(crate) card_renderer: CardRenderer,
    state_store: DynStateStore,
    debug_enabled: bool,
    pub(crate) cross_pack_resolver: std::sync::RwLock<Option<std::sync::Arc<dyn greentic_runner_host::runner::engine::CrossPackResolver>>>,
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

    /// Get the pack path for a provider in the given domain.
    /// Returns None if the provider is not found in the catalog.
    pub fn get_provider_pack_path(&self, domain: Domain, provider: &str) -> Option<&Path> {
        self.catalog
            .get(&(domain, provider.to_string()))
            .map(|pack| pack.path.as_path())
    }

    /// Read a secret synchronously from the secrets manager.
    /// The secret key is resolved using the canonical URI format:
    /// `secrets://{env}/{tenant}/{team}/{provider}/{key}`
    pub fn get_secret(
        &self,
        provider: &str,
        key: &str,
        ctx: &OperatorContext,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.get_secret_with_handle(&self.secrets_handle, provider, key, ctx)
    }

    /// Read a secret using a fresh secrets handle (re-reads from disk).
    /// Use this for values that may have been updated at runtime (e.g., public_base_url).
    pub fn get_secret_fresh(
        &self,
        provider: &str,
        key: &str,
        ctx: &OperatorContext,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let fresh = crate::secrets_gate::resolve_secrets_manager(
            &self.bundle_root,
            &ctx.tenant,
            ctx.team.as_deref(),
        )
        .unwrap_or_else(|_| self.secrets_handle.clone());
        self.get_secret_with_handle(&fresh, provider, key, ctx)
    }

    fn get_secret_with_handle(
        &self,
        handle: &SecretsManagerHandle,
        provider: &str,
        key: &str,
        ctx: &OperatorContext,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        use crate::secrets_gate::canonical_secret_uri;
        use crate::secrets_setup::resolve_env;

        let env = resolve_env(None);
        let uri = canonical_secret_uri(&env, &ctx.tenant, ctx.team.as_deref(), provider, key);

        make_runtime_or_thread_scope(|rt| {
            rt.block_on(async {
                match handle.manager().read(&uri).await {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(err) => {
                        let err_str = err.to_string();
                        if err_str.contains("not found") || err_str.contains("NotFound") {
                            Ok(None)
                        } else {
                            Err(anyhow::anyhow!("secret read failed: {}", err))
                        }
                    }
                }
            })
        })
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
                // Add short aliases for packs with long pack_ids (e.g., "greentic.events.webhook" -> "webhook")
                let aliases = extract_provider_short_aliases(&pack.pack_id, domain);
                for alias in aliases {
                    if alias != provider_type && alias != pack.pack_id {
                        catalog
                            .entry((domain, alias))
                            .or_insert_with(|| pack.clone());
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
            cross_pack_resolver: std::sync::RwLock::new(None),
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
            env: Some(env::var("GREENTIC_ENV").unwrap_or_else(|_| "dev".to_string())),
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
            env: Some(env::var("GREENTIC_ENV").unwrap_or_else(|_| "dev".to_string())),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery;
    use crate::secrets_gate;
    use tempfile::tempdir;

    pub(super) fn empty_host_for_tests() -> DemoRunnerHost {
        let dir = tempdir().unwrap();
        let discovery = discovery::discover(dir.path()).unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default")).unwrap();
        DemoRunnerHost::new(dir.keep(), &discovery, None, secrets_handle, false).unwrap()
    }

    #[test]
    fn empty_catalog_helpers_return_safe_defaults() {
        let host = empty_host_for_tests();

        assert_eq!(
            host.get_provider_pack_path(Domain::Messaging, "missing"),
            None
        );
        assert_eq!(
            host.canonical_provider_type(Domain::Messaging, "missing"),
            "missing"
        );
        assert!(!host.has_provider_packs_for_domain(Domain::Messaging));
        assert!(!host.supports_op(Domain::Messaging, "missing", "ingest_http"));
    }

    #[test]
    fn invoke_capability_returns_missing_outcome_when_registry_is_empty() {
        let host = empty_host_for_tests();
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            correlation_id: None,
        };
        let outcome = host
            .invoke_capability("greentic.cap.missing", "op", br#"{}"#, &ctx)
            .unwrap();
        assert!(!outcome.success);
        assert!(
            outcome
                .error
                .unwrap_or_default()
                .contains("MissingCapability")
        );
    }

    #[test]
    fn empty_host_reports_no_secret_or_capability_setup_plan() {
        let host = empty_host_for_tests();
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            correlation_id: Some("corr-1".to_string()),
        };

        assert_eq!(
            host.capability_setup_plan(&ctx),
            Vec::<CapabilityBinding>::new()
        );
        assert_eq!(
            host.get_secret("missing-provider", "missing-key", &ctx)
                .unwrap(),
            None
        );
    }

    #[test]
    fn oauth_capability_requires_supported_explicit_ops() {
        let host = empty_host_for_tests();
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            correlation_id: None,
        };

        let missing_op = host
            .invoke_capability(CAP_OAUTH_BROKER_V1, "", br#"{}"#, &ctx)
            .unwrap();
        assert!(!missing_op.success);
        assert!(
            missing_op
                .error
                .unwrap_or_default()
                .contains("requires an explicit op")
        );

        let unsupported = host
            .invoke_capability(CAP_OAUTH_BROKER_V1, "oauth.nope", br#"{}"#, &ctx)
            .unwrap();
        assert!(!unsupported.success);
        assert!(
            unsupported
                .error
                .unwrap_or_default()
                .contains("unsupported oauth broker op")
        );
    }
}
