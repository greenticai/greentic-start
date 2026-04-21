#![allow(dead_code)]

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose};
use greentic_runner_host::config::{
    FlowRetryConfig, HostConfig, OperatorPolicy, RateLimits, SecretsPolicy, StateStorePolicy,
    WebhookPolicy,
};
use greentic_runner_host::trace::TraceConfig;
use greentic_runner_host::validate::ValidationConfig;
use greentic_types::decode_pack_manifest;
use serde_json::{Value as JsonValue, json};
use tokio::runtime::Runtime as TokioRuntime;
use zip::ZipArchive;

use crate::domains::{Domain, ProviderPack};
use crate::operator_log;
use crate::secrets_manager;

use super::types::{FlowOutcome, OperatorContext, RunnerExecutionMode};

/// Create a Tokio runtime for blocking async operations.
/// When called from within an existing runtime (e.g., HTTP ingress handler),
/// spawns a dedicated thread to avoid "Cannot start a runtime from within a
/// runtime" panics.
pub(super) fn make_runtime_or_thread_scope<F, T>(f: F) -> T
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

pub(super) fn domain_name(domain: Domain) -> &'static str {
    match domain {
        Domain::Messaging => "messaging",
        Domain::Events => "events",
        Domain::Llm => "llm",
        Domain::Secrets => "secrets",
        Domain::OAuth => "oauth",
    }
}

pub(super) fn pack_supports_provider_op(pack_path: &Path, op_id: &str) -> anyhow::Result<bool> {
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

    // Check explicit ops list in provider extension
    if let Some(provider_ext) = manifest.provider_extension_inline()
        && provider_ext
            .providers
            .iter()
            .any(|provider| provider.ops.iter().any(|op| op == op_id))
    {
        return Ok(true);
    }

    // For ingest_http, also check if messaging.provider_ingress.v1 extension exists
    // This extension declares HTTP ingress capability even if not in ops list
    if op_id == "ingest_http"
        && let Some(extensions) = &manifest.extensions
        && extensions.contains_key("messaging.provider_ingress.v1")
    {
        return Ok(true);
    }

    Ok(false)
}

/// Extract short aliases from a pack_id for catalog registration.
///
/// Automatically generates progressive aliases by splitting on dots and hyphens:
/// - "greentic.events.email.sendgrid" -> ["sendgrid", "email.sendgrid", "events.email.sendgrid"]
/// - "greentic.events.webhook" -> ["webhook", "events.webhook"]
/// - "messaging-telegram" -> ["telegram"]
/// - "state-memory" -> ["memory"]
pub(super) fn extract_provider_short_aliases(pack_id: &str, _domain: Domain) -> Vec<String> {
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

pub(super) fn validate_runner_binary(path: PathBuf) -> Option<PathBuf> {
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

#[cfg(unix)]
fn runner_binary_is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn runner_binary_is_executable(_: &fs::Metadata) -> bool {
    true
}

pub(super) fn payload_preview(bytes: &[u8]) -> String {
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

pub(super) fn read_transcript_outputs(run_dir: &Path) -> anyhow::Result<Option<JsonValue>> {
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

pub(super) fn build_demo_host_config(tenant: &str) -> HostConfig {
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

pub(super) fn needs_secret_context(message: &str) -> bool {
    let lower = message.to_lowercase();
    lower.contains("secret store error") || message.contains("SecretsError")
}

pub(super) fn secret_error_context(
    ctx: &OperatorContext,
    provider_id: &str,
    op_id: &str,
    pack: &ProviderPack,
) -> String {
    let env = env::var("GREENTIC_ENV").unwrap_or_else(|_| "dev".to_string());
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

pub(super) fn missing_capability_outcome(
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

pub(super) fn capability_not_installed_outcome(
    cap_id: &str,
    op_name: &str,
    stable_id: &str,
) -> FlowOutcome {
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

pub(super) fn capability_route_error_outcome(
    cap_id: &str,
    op_name: &str,
    reason: String,
) -> FlowOutcome {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn helper_functions_cover_domains_aliases_and_secret_detection() {
        assert_eq!(domain_name(Domain::Messaging), "messaging");
        assert_eq!(domain_name(Domain::Events), "events");
        assert_eq!(domain_name(Domain::Secrets), "secrets");
        assert_eq!(domain_name(Domain::OAuth), "oauth");

        assert_eq!(
            extract_provider_short_aliases("greentic.events.email.sendgrid", Domain::Events),
            vec![
                "sendgrid".to_string(),
                "email.sendgrid".to_string(),
                "events.email.sendgrid".to_string()
            ]
        );
        assert_eq!(
            extract_provider_short_aliases("messaging-telegram", Domain::Messaging),
            vec!["telegram".to_string()]
        );

        assert!(needs_secret_context("SecretsError: failed"));
        assert!(needs_secret_context(
            "secret store error while fetching key"
        ));
        assert!(!needs_secret_context("ordinary validation failure"));
    }

    #[test]
    fn payload_preview_and_transcript_outputs_handle_text_binary_and_missing_files() {
        assert_eq!(payload_preview(b""), "<empty>");
        assert_eq!(payload_preview(b"hello"), "hello");
        assert_eq!(payload_preview(&[0xff, 0x00]), "/wA=");

        let long = vec![b'a'; 300];
        assert!(payload_preview(&long).ends_with("..."));

        let dir = tempdir().expect("tempdir");
        assert!(
            read_transcript_outputs(dir.path())
                .expect("missing transcript")
                .is_none()
        );

        std::fs::write(
            dir.path().join("transcript.jsonl"),
            concat!(
                "{\"outputs\":null}\n",
                "{\"outputs\":{\"text\":\"first\"}}\n",
                "not-json\n",
                "{\"outputs\":{\"text\":\"last\"}}\n"
            ),
        )
        .expect("write transcript");
        let outputs = read_transcript_outputs(dir.path())
            .expect("transcript")
            .expect("outputs");
        assert_eq!(outputs["text"], "last");
    }

    #[test]
    fn secret_and_capability_outcomes_include_expected_context() {
        let pack = ProviderPack {
            pack_id: "messaging-webchat".to_string(),
            display_name: None,
            description: None,
            tags: vec![],
            file_name: "messaging-webchat.gtpack".to_string(),
            path: PathBuf::from("/tmp/messaging-webchat.gtpack"),
            entry_flows: vec![],
        };
        let ctx = OperatorContext {
            tenant: "demo".to_string(),
            team: Some("ops".to_string()),
            correlation_id: Some("corr-1".to_string()),
        };

        unsafe {
            env::set_var("GREENTIC_ENV", "test");
        }
        let secret_context = secret_error_context(&ctx, "provider-a", "lookup", &pack);
        assert!(secret_context.contains("env=test"));
        assert!(secret_context.contains("tenant=demo"));
        assert!(secret_context.contains("team=ops"));
        assert!(secret_context.contains("provider=provider-a"));
        unsafe {
            env::remove_var("GREENTIC_ENV");
        }

        let missing = missing_capability_outcome("cap-x", "op-y", Some("cmp-z"));
        assert!(!missing.success);
        assert_eq!(missing.mode, RunnerExecutionMode::Exec);
        assert_eq!(
            missing.output.as_ref().expect("output")["code"],
            "missing_capability"
        );

        let not_installed = capability_not_installed_outcome("cap-x", "op-y", "stable-z");
        assert_eq!(
            not_installed.output.as_ref().expect("output")["code"],
            "capability_not_installed"
        );

        let route_error =
            capability_route_error_outcome("cap-x", "op-y", "route missing".to_string());
        assert_eq!(
            route_error.output.as_ref().expect("output")["code"],
            "capability_route_error"
        );
        assert_eq!(route_error.error.as_deref(), Some("route missing"));
    }
}
