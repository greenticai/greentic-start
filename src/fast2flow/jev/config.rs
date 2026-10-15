//! Settings for the Jev routing tier.
//!
//! Two sources, one shape ([`JevSettings`]):
//!
//! * the bundle's top-level `jev:` block in `bundle.yaml` (the operator's, read
//!   once at startup, [`set_operator`]);
//! * a `jev` object in the pack's own `assets/fast2flow.json` (the router
//!   pack's, so a deployed router unit carries its tier with it).
//!
//! ```yaml
//! jev:
//!   endpoint: https://api.typesafe.ai/v1/systemone   # operator only
//!   api_key_secret: jev/api_key                      # a secret NAME
//!   timeout_ms: 2000
//!   min_confidence: 0.5
//!   model: jev-latest
//! ```
//!
//! Rules that keep a hostile or careless pack from turning this into a leak:
//!
//! * **Absent means off.** No block anywhere: the tier is never consulted.
//! * **There is no field for a key.** `api_key_secret` is a NAME resolved at
//!   call time; `deny_unknown_fields` makes a pasted literal (`api_key: ...`) a
//!   parse error instead of a silently ignored line.
//! * **A pack cannot choose where the key goes.** `endpoint` is honoured from
//!   the operator's block only, and a pack's secret name must live under
//!   `jev/`, so a pack cannot make this host send some other secret (or any
//!   secret anywhere else) to a third party.
//! * **The operator can veto.** `enabled: false` in `bundle.yaml` turns the
//!   tier off whatever a pack says.

use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use serde::Deserialize;

use crate::operator_log;

/// The pack entry shared with [`crate::fast2flow::pack_config`].
const PACK_CONFIG_ENTRY: &str = "assets/fast2flow.json";
const PACK_SCHEMA: &str = "greentic.fast2flow-config.v1";

pub(crate) const DEFAULT_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
pub(crate) const DEFAULT_SECRET_NAME: &str = "jev/api_key";
/// The prefix a PACK-supplied secret name must live under.
pub(crate) const PACK_SECRET_PREFIX: &str = "jev/";
const DEFAULT_TIMEOUT_MS: u64 = 2_000;
const MIN_TIMEOUT_MS: u64 = 100;
const MAX_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_MIN_CONFIDENCE: f32 = 0.5;

/// One `jev` block as written (either source). Every field is optional so a
/// pack block can override single values of the operator's.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct JevBlock {
    pub enabled: Option<bool>,
    pub endpoint: Option<String>,
    pub api_key_secret: Option<String>,
    pub timeout_ms: Option<u64>,
    pub min_confidence: Option<f64>,
    pub model: Option<String>,
}

/// The settings a turn runs with.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct JevSettings {
    pub endpoint: String,
    pub secret_name: String,
    pub timeout: Duration,
    pub min_confidence: f32,
    pub model: Option<String>,
}

static OPERATOR: OnceLock<Option<JevBlock>> = OnceLock::new();

/// Store the bundle's `jev:` block. Call once, early in startup.
pub(crate) fn set_operator(block: Option<JevBlock>) {
    let _ = OPERATOR.set(block);
}

/// The bundle's `jev:` block, when it declared one.
pub(crate) fn operator() -> Option<&'static JevBlock> {
    OPERATOR.get().and_then(|o| o.as_ref())
}

/// Parse the operator's block. An unusable block is reported and ignored: the
/// tier stays off rather than half-configured.
pub(crate) fn parse_operator_block(raw: serde_yaml_bw::Value) -> Option<JevBlock> {
    match serde_yaml_bw::from_value::<JevBlock>(raw) {
        Ok(block) => Some(block),
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "[fast2flow:jev] bundle.yaml `jev:` block is unusable ({err}); the Jev tier stays off"
                ),
            );
            None
        }
    }
}

/// Read the pack's `jev` object. `Ok(None)`: the pack declares none (every pack
/// that never shipped one). `Err`: it exists and cannot be used.
pub(crate) fn read_pack_block(pack_path: &Path) -> Result<Option<JevBlock>, String> {
    let Ok(file) = std::fs::File::open(pack_path) else {
        return Ok(None);
    };
    let Ok(mut archive) = zip::ZipArchive::new(file) else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    match archive.by_name(PACK_CONFIG_ENTRY) {
        Ok(mut entry) => std::io::Read::read_to_end(&mut entry, &mut bytes)
            .map_err(|e| format!("read {PACK_CONFIG_ENTRY}: {e}"))?,
        Err(_) => return Ok(None),
    };
    parse_pack_block(&bytes)
}

fn parse_pack_block(bytes: &[u8]) -> Result<Option<JevBlock>, String> {
    let doc: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| format!("{PACK_CONFIG_ENTRY} is not valid JSON: {e}"))?;
    if let Some(schema) = doc.get("schema").and_then(|s| s.as_str())
        && schema != PACK_SCHEMA
    {
        return Err(format!(
            "{PACK_CONFIG_ENTRY} declares schema `{schema}`, expected `{PACK_SCHEMA}`"
        ));
    }
    let Some(block) = doc.get("jev") else {
        return Ok(None);
    };
    serde_json::from_value::<JevBlock>(block.clone())
        .map(Some)
        .map_err(|e| format!("{PACK_CONFIG_ENTRY} `jev` block is unusable: {e}"))
}

/// Combine the operator's block with the pack's into the settings a turn uses.
///
/// `None` means the tier is off: no block at all, an operator veto, or a block
/// that breaks a rule above (reported by the caller via the `Err`).
pub(crate) fn effective(
    operator: Option<&JevBlock>,
    pack: Option<&JevBlock>,
) -> Result<Option<JevSettings>, String> {
    if operator.is_none() && pack.is_none() {
        return Ok(None);
    }
    if operator.and_then(|o| o.enabled) == Some(false) {
        return Ok(None);
    }
    if pack.and_then(|p| p.enabled) == Some(false) {
        return Ok(None);
    }
    if pack.is_some_and(|p| p.endpoint.is_some()) {
        return Err(
            "a pack cannot set the Jev endpoint (only bundle.yaml can); the tier stays off"
                .to_string(),
        );
    }
    let pick = |f: fn(&JevBlock) -> Option<&String>| {
        pack.and_then(f)
            .or_else(|| operator.and_then(f))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let secret_from_pack = pack
        .and_then(|p| p.api_key_secret.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(name) = secret_from_pack
        && !name.starts_with(PACK_SECRET_PREFIX)
    {
        return Err(format!(
            "a pack's Jev secret name must start with `{PACK_SECRET_PREFIX}`; the tier stays off"
        ));
    }
    let endpoint = operator
        .and_then(|o| o.endpoint.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_ENDPOINT)
        .to_string();
    check_endpoint(&endpoint)?;
    let min_confidence = match pack
        .and_then(|p| p.min_confidence)
        .or_else(|| operator.and_then(|o| o.min_confidence))
    {
        None => DEFAULT_MIN_CONFIDENCE,
        Some(v) if v.is_finite() && (0.0..=1.0).contains(&v) => v as f32,
        Some(v) => return Err(format!("min_confidence {v} is outside 0..=1")),
    };
    let timeout_ms = pack
        .and_then(|p| p.timeout_ms)
        .or_else(|| operator.and_then(|o| o.timeout_ms))
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
    Ok(Some(JevSettings {
        endpoint,
        secret_name: pick(|b| b.api_key_secret.as_ref())
            .unwrap_or_else(|| DEFAULT_SECRET_NAME.to_string()),
        timeout: Duration::from_millis(timeout_ms),
        min_confidence,
        model: pick(|b| b.model.as_ref()),
    }))
}

/// The key travels as a bearer token, so the endpoint must be TLS — or a
/// loopback address, which only a local test double or sidecar can be.
fn check_endpoint(endpoint: &str) -> Result<(), String> {
    if endpoint.starts_with("https://") {
        return Ok(());
    }
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return Err("the Jev endpoint must be an https:// URL".to_string());
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let name = host.rsplit_once(':').map_or(host, |(h, _)| h);
    if matches!(name, "127.0.0.1" | "localhost" | "[::1]") {
        Ok(())
    } else {
        Err("a plain http:// Jev endpoint is only allowed on loopback".to_string())
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
