#![allow(dead_code)]

//! Persist config and secrets from QA apply-answers output.
//!
//! After a provider's `apply-answers` op returns a config object, this module:
//! - Writes every visible answer to the dev secrets store under
//!   `secrets://<env>/<tenant>/<team>/<provider>/<key>` (legacy universal
//!   write — WASM components have historically read both secret and
//!   non-secret config values through the secrets API).
//! - Emits a sibling `pack-config-input.v1` file via
//!   [`emit_pack_config_input`] when the wizard scope is known. This is the
//!   C7 producer for the `pack-config.v1.non_secret` channel: the
//!   greentic-deployer picks up the file at revision-create, stamps the
//!   active `revision_id`, and writes the final `pack-config.v1` consumed by
//!   the runtime (C4). The universal DevStore write stays alive for one
//!   release as the C4.2 compatibility shim.
//! - Writes remaining (non-secret) fields to the provider config envelope.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use greentic_secrets_lib::{
    ApplyOptions, DevStore, SecretFormat, SeedDoc, SeedEntry, SeedValue, apply_seed,
};
use qa_spec::{FormSpec, VisibilityMode, resolve_visibility};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};

use crate::secret_name::canonical_secret_name;
use crate::secrets_gate::canonical_secret_uri;
use crate::secrets_setup::resolve_env;

/// Extract secret fields from the QA config output and write them to the dev store.
///
/// Returns a list of secret keys that were persisted.
pub async fn persist_qa_secrets(
    store: &DevStore,
    env: &str,
    tenant: &str,
    team: Option<&str>,
    provider_id: &str,
    config: &Value,
    form_spec: &FormSpec,
) -> Result<Vec<String>> {
    // Collect visible question IDs — WASM components read both secret and
    // non-secret config values via the secrets API, so we must persist
    // everything that is currently visible (skip conditionally-invisible
    // questions to avoid leaking stale answers).
    let visibility = resolve_visibility(form_spec, config, VisibilityMode::Visible);
    let visible_question_ids: Vec<&str> = form_spec
        .questions
        .iter()
        .filter(|q| visibility.get(&q.id).copied().unwrap_or(true))
        .map(|q| q.id.as_str())
        .collect();

    if visible_question_ids.is_empty() {
        return Ok(vec![]);
    }

    let Some(config_map) = config.as_object() else {
        return Ok(vec![]);
    };

    let mut entries = Vec::new();
    let mut saved_keys = Vec::new();

    for &key in &visible_question_ids {
        if let Some(value) = config_map.get(key) {
            let text = match value {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if text.is_empty() || text == "null" {
                continue;
            }
            let uri = canonical_secret_uri(env, tenant, team, provider_id, key);
            entries.push(SeedEntry {
                uri,
                format: SecretFormat::Text,
                value: SeedValue::Text { text },
                description: Some(format!("from QA setup for {provider_id}")),
            });
            saved_keys.push(key.to_string());
        }
    }

    if entries.is_empty() {
        return Ok(vec![]);
    }

    let report = apply_seed(store, &SeedDoc { entries }, ApplyOptions::default()).await;

    if !report.failed.is_empty() {
        return Err(anyhow::anyhow!(
            "failed to persist {} secret(s): {:?}",
            report.failed.len(),
            report.failed
        ));
    }

    Ok(saved_keys)
}

/// Write non-secret config fields to the provider config envelope.
///
/// Filters out secret fields (identified by the FormSpec) before writing.
pub fn persist_qa_config(
    providers_root: &Path,
    provider_id: &str,
    config: &Value,
    pack_path: &Path,
    form_spec: &FormSpec,
    backup: bool,
) -> Result<()> {
    let secret_ids: Vec<&str> = form_spec
        .questions
        .iter()
        .filter(|q| q.secret)
        .map(|q| q.id.as_str())
        .collect();

    let filtered_config = if secret_ids.is_empty() {
        config.clone()
    } else {
        filter_secrets(config, &secret_ids)
    };

    crate::provider_config_envelope::write_provider_config_envelope(
        providers_root,
        provider_id,
        "qa-setup",
        &filtered_config,
        pack_path,
        backup,
    )?;

    Ok(())
}

/// Remove secret fields from a config object.
fn filter_secrets(config: &Value, secret_ids: &[&str]) -> Value {
    let Some(map) = config.as_object() else {
        return config.clone();
    };
    let filtered: JsonMap<String, Value> = map
        .iter()
        .filter(|(key, _)| !secret_ids.contains(&key.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Value::Object(filtered)
}

/// Convenience function to persist both secrets and config from QA results.
///
/// Creates a `DevStore` from the bundle root and persists both.
/// Also seeds secret-requirement aliases so WASM components can find secrets
/// by their canonical requirement key.
#[allow(clippy::too_many_arguments)]
pub async fn persist_qa_results(
    bundle_root: &Path,
    providers_root: &Path,
    tenant: &str,
    team: Option<&str>,
    provider_id: &str,
    config: &Value,
    pack_path: &Path,
    form_spec: &FormSpec,
    backup: bool,
) -> Result<(Vec<String>, bool)> {
    let env = resolve_env(None);
    let store_path = crate::dev_store_path::ensure_path(bundle_root)?;
    let store = DevStore::with_path(&store_path).map_err(|err| {
        anyhow::anyhow!(
            "failed to open dev secrets store {}: {err}",
            store_path.display()
        )
    })?;

    let saved_secrets =
        persist_qa_secrets(&store, &env, tenant, team, provider_id, config, form_spec).await?;

    // Seed aliases from secret-requirements.json so WASM components can find
    // secrets by their canonical requirement key when provider metadata declares
    // a longer runtime key than the setup answer key.
    if let Some(config_map) = config.as_object() {
        let alias_count = seed_secret_requirement_aliases(
            &store,
            config_map,
            &env,
            tenant,
            team,
            provider_id,
            pack_path,
        )
        .await
        .unwrap_or(0);
        if alias_count > 0 {
            tracing::debug!(
                "seeded {} secret alias(es) for provider {}",
                alias_count,
                provider_id
            );
        }
    }

    let config_written = if config.as_object().is_some_and(|m| !m.is_empty()) {
        persist_qa_config(
            providers_root,
            provider_id,
            config,
            pack_path,
            form_spec,
            backup,
        )?;
        true
    } else {
        false
    };

    // C7: emit `pack-config-input.v1` so the deployer can populate the
    // `pack-config.v1.non_secret` channel at revision-create. Runs AFTER
    // persist_qa_config so a config-write failure aborts before any C7
    // artifact lands on disk. Emit failures soft-fail with a warn — the
    // C4.2 compat shim still serves these keys from DevStore (already
    // populated above), so a wizard run does not regress on emit failure.
    let bundle_id = infer_bundle_id(bundle_root);
    if let Err(err) = emit_pack_config_input(
        bundle_root,
        &env,
        &bundle_id,
        provider_id,
        config,
        form_spec,
    ) {
        tracing::warn!(
            provider_id,
            env = %env,
            bundle_id = %bundle_id,
            bundle_root = %bundle_root.display(),
            error = %err,
            "pack-config-input emission failed; runtime falls back to legacy DevStore reads via C4.2 compat shim",
        );
    }

    Ok((saved_secrets, config_written))
}

/// OAuth authorization stub.
///
/// Prints the authorization URL and returns `None`. This is a placeholder for
/// future integration with `greentic-oauth` for providers that require OAuth
/// (e.g., Teams, Slack with OAuth scopes).
pub fn oauth_authorize_stub(provider_id: &str, auth_url: Option<&str>) -> Option<String> {
    if let Some(url) = auth_url {
        println!("[oauth] Authorize {provider_id} at: {url}");
        println!("[oauth] After authorizing, re-run setup to complete configuration.");
    } else {
        println!("[oauth] Provider {provider_id} requires OAuth authorization.");
        println!("[oauth] OAuth integration is not yet implemented.");
    }
    None
}

// ── Alias seeding ───────────────────────────────────────────────────────────

/// Read `assets/secret-requirements.json` from a pack and seed alias entries
/// for any requirement key that differs from the answers key after
/// canonicalization.
///
/// This allows WASM components to find secrets by their canonical requirement
/// key even when the answers file uses a shorter key.
pub async fn seed_secret_requirement_aliases(
    store: &DevStore,
    config_map: &JsonMap<String, Value>,
    env: &str,
    tenant: &str,
    team: Option<&str>,
    provider_id: &str,
    pack_path: &Path,
) -> Result<usize> {
    let reqs = match read_secret_requirements(pack_path) {
        Ok(r) => r,
        Err(_) => return Ok(0),
    };

    // Collect existing keys (already stored by persist_qa_secrets)
    let existing_keys: std::collections::HashSet<String> = config_map
        .keys()
        .map(|k| canonical_secret_name(k))
        .collect();

    let mut entries = Vec::new();

    for req in &reqs {
        let canonical_req_key = canonical_secret_name(&req.key);
        // Skip if already stored with this exact key
        if existing_keys.contains(&canonical_req_key) {
            continue;
        }

        // Find a config value where the canonical requirement key ends with the
        // canonical config key.
        let matched_value = config_map.iter().find_map(|(cfg_key, cfg_val)| {
            let norm_cfg = canonical_secret_name(cfg_key);
            if canonical_req_key.ends_with(&norm_cfg) {
                let text = value_to_text(cfg_val);
                if text.is_empty() || text == "null" {
                    None
                } else {
                    Some(text)
                }
            } else {
                None
            }
        });

        if let Some(text) = matched_value {
            let uri = canonical_secret_uri(env, tenant, team, provider_id, &canonical_req_key);
            entries.push(SeedEntry {
                uri,
                format: SecretFormat::Text,
                value: SeedValue::Text { text },
                description: Some(format!("alias from {} for {provider_id}", req.key)),
            });
        }
    }

    if entries.is_empty() {
        return Ok(0);
    }

    let count = entries.len();
    let report = apply_seed(store, &SeedDoc { entries }, ApplyOptions::default()).await;

    if !report.failed.is_empty() {
        tracing::warn!(
            "failed to seed {} secret alias(es) for {}: {:?}",
            report.failed.len(),
            provider_id,
            report.failed
        );
    }

    Ok(count)
}

#[derive(serde::Deserialize)]
struct SecretRequirement {
    key: String,
}

fn read_secret_requirements(pack_path: &Path) -> Result<Vec<SecretRequirement>> {
    let file = std::fs::File::open(pack_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let entry = archive.by_name("assets/secret-requirements.json")?;
    let reqs: Vec<SecretRequirement> = serde_json::from_reader(entry)?;
    Ok(reqs)
}

fn value_to_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ── pack-config-input.v1 emitter (C7) ──────────────────────────────────────

/// Schema tag for the wizard-emitted intermediate file consumed by the
/// greentic-deployer at revision-create.
pub const PACK_CONFIG_INPUT_SCHEMA: &str = "greentic.pack-config-input.v1";

/// Directory under `bundle_root` where wizard-emitted pack-config inputs land.
/// The deployer joins on `<bundle_root>/<PACK_CONFIG_INPUT_DIR>/<pack_id>.json`
/// at revision-create.
pub const PACK_CONFIG_INPUT_DIR: &str = "state/pack-configs";

/// Wizard-emitted intermediate file the deployer picks up at revision-create
/// (C7). The deployer stamps the active `revision_id` and writes the final
/// `pack-config.v1` referenced by `pack_config_refs` in `runtime-config.v1`.
/// We keep `revision_id` OUT of this shape on purpose: revisions are minted
/// by the deployer, not the wizard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackConfigInput {
    pub schema: String,
    pub pack_id: String,
    pub env_id: String,
    pub bundle_id: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub non_secret: BTreeMap<String, Value>,
    /// `secret://<env>/<bundle>/<pack>/<question>` URIs (kept as plain
    /// strings here — `greentic-deploy-spec::SecretRef` validates at the
    /// deployer side when it materializes the final `pack-config.v1`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secret_refs: BTreeMap<String, String>,
}

/// Emit a `pack-config-input.v1` file at
/// `<bundle_root>/state/pack-configs/<pack_id>.json` carrying the FormSpec-
/// split of one provider's QA answers (C7). Idempotent: overwrites in place
/// so re-running the wizard produces the same on-disk shape.
///
/// Secret-marked answers are recorded as `secret://<env>/<bundle>/<pack>/<key>`
/// URI references (no plaintext); non-secret answers stay inline. Empty
/// `config` is a no-op (no file written).
pub fn emit_pack_config_input(
    bundle_root: &Path,
    env_id: &str,
    bundle_id: &str,
    pack_id: &str,
    config: &Value,
    form_spec: &FormSpec,
) -> Result<Option<std::path::PathBuf>> {
    validate_segment("env_id", env_id)?;
    validate_segment("bundle_id", bundle_id)?;
    validate_segment("pack_id", pack_id)?;

    // Pre-compute the on-disk path so every Ok(None) early-return path can
    // tombstone any stale file left behind by an earlier wizard run that
    // had visible/non-empty answers. Without this, clearing answers (or
    // hiding them via `visible_if`) would leave the previous file for the
    // deployer to consume on the next revision-create.
    let dir = bundle_root.join(PACK_CONFIG_INPUT_DIR);
    let path = dir.join(format!("{pack_id}.json"));

    let Some(config_map) = config.as_object() else {
        remove_stale_pack_config_input(&path)?;
        return Ok(None);
    };
    if config_map.is_empty() {
        remove_stale_pack_config_input(&path)?;
        return Ok(None);
    }

    // Apply the same visibility filter that `persist_qa_secrets` uses so
    // that conditionally-invisible answers do not leak into the
    // pack-config-input file (and from there into runtime config).
    let visibility = resolve_visibility(form_spec, config, VisibilityMode::Visible);

    let secret_ids: std::collections::HashSet<&str> = form_spec
        .questions
        .iter()
        .filter(|q| q.secret)
        .map(|q| q.id.as_str())
        .collect();

    let visible_ids: std::collections::HashSet<&str> = form_spec
        .questions
        .iter()
        .filter(|q| visibility.get(&q.id).copied().unwrap_or(true))
        .map(|q| q.id.as_str())
        .collect();

    let mut non_secret = BTreeMap::new();
    let mut secret_refs = BTreeMap::new();
    for (key, value) in config_map {
        if !visible_ids.contains(key.as_str()) {
            continue;
        }
        let text = value_to_text(value);
        if text.is_empty() || text == "null" {
            continue;
        }
        if secret_ids.contains(key.as_str()) {
            validate_segment("question.id", key)?;
            let uri = format!("secret://{env_id}/{bundle_id}/{pack_id}/{key}");
            secret_refs.insert(key.clone(), uri);
        } else {
            non_secret.insert(key.clone(), value.clone());
        }
    }

    if non_secret.is_empty() && secret_refs.is_empty() {
        remove_stale_pack_config_input(&path)?;
        return Ok(None);
    }

    let input = PackConfigInput {
        schema: PACK_CONFIG_INPUT_SCHEMA.to_string(),
        pack_id: pack_id.to_string(),
        env_id: env_id.to_string(),
        bundle_id: bundle_id.to_string(),
        non_secret,
        secret_refs,
    };

    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create pack-config-input dir {}", dir.display()))?;
    let body = serde_json::to_string_pretty(&input).context("serialize pack-config-input.v1")?;
    std::fs::write(&path, format!("{body}\n"))
        .with_context(|| format!("write pack-config-input {}", path.display()))?;

    tracing::debug!(
        pack_id,
        env_id,
        bundle_id,
        non_secret_count = input.non_secret.len(),
        secret_ref_count = input.secret_refs.len(),
        path = %path.display(),
        "wizard emitted pack-config-input.v1 (C7) for deployer pickup",
    );
    Ok(Some(path))
}

/// Remove a stale pack-config-input file when the current wizard state has
/// no visible/non-empty entries. Returns `Ok(())` if the file is already
/// gone (NotFound). Any other I/O error propagates so the caller sees the
/// staleness risk instead of silently emitting an inconsistent revision.
fn remove_stale_pack_config_input(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            tracing::debug!(
                path = %path.display(),
                "removed stale pack-config-input.v1 (current answers produced no entries)"
            );
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(anyhow::Error::from(err))
            .with_context(|| format!("remove stale pack-config-input {}", path.display())),
    }
}

/// Reject empty, `/`-bearing, or relative-component (`.`, `..`) identifiers —
/// these would silently corrupt the `secret://<env>/<bundle>/<pack>/<question>`
/// path structure or the `<dir>/<pack_id>.json` file path.
fn validate_segment(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        anyhow::bail!("{label} must not be empty for pack-config-input emission");
    }
    if value.contains('/') {
        anyhow::bail!(
            "{label} `{value}` contains '/' which would corrupt the pack-config-input layout"
        );
    }
    if value == "." || value == ".." {
        anyhow::bail!(
            "{label} `{value}` is a relative path component and would corrupt the pack-config-input layout"
        );
    }
    Ok(())
}

/// Derive a stable bundle id from the bundle root path, with a `"bundle"`
/// fallback when the directory name is missing or empty.
pub(crate) fn infer_bundle_id(root: &Path) -> String {
    root.file_name()
        .and_then(|value| value.to_str())
        .map(ToOwned::to_owned)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "bundle".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_lib::{
        ApplyOptions, DevStore, SecretsStore, SeedDoc, SeedEntry, SeedValue, apply_seed,
    };
    use qa_spec::{QuestionSpec, QuestionType};
    use serde_json::json;
    use std::fs;
    use std::io::Write;
    use tokio::runtime::Runtime;

    fn make_form_spec(questions: Vec<QuestionSpec>) -> FormSpec {
        FormSpec {
            id: "test".into(),
            title: "Test".into(),
            version: "1.0.0".into(),
            description: None,
            presentation: None,
            progress_policy: None,
            secrets_policy: None,
            store: vec![],
            validations: vec![],
            includes: vec![],
            questions,
        }
    }

    fn question(id: &str, secret: bool) -> QuestionSpec {
        QuestionSpec {
            id: id.into(),
            kind: QuestionType::String,
            title: id.into(),
            title_i18n: None,
            description: None,
            description_i18n: None,
            required: false,
            choices: None,
            default_value: None,
            secret,
            visible_if: None,
            constraint: None,
            list: None,
            computed: None,
            policy: Default::default(),
            computed_overridable: false,
        }
    }

    #[test]
    fn filters_out_secret_fields() {
        let config = json!({
            "enabled": true,
            "bot_token": "secret123",
            "public_url": "https://example.com"
        });
        let secret_ids = vec!["bot_token"];
        let filtered = filter_secrets(&config, &secret_ids);
        assert!(filtered.get("enabled").is_some());
        assert!(filtered.get("public_url").is_some());
        assert!(filtered.get("bot_token").is_none());
    }

    #[test]
    fn no_secrets_returns_full_config() {
        let config = json!({"enabled": true, "url": "https://example.com"});
        let filtered = filter_secrets(&config, &[]);
        assert_eq!(filtered, config);
    }

    #[test]
    fn identifies_secret_questions() {
        let spec = make_form_spec(vec![
            question("enabled", false),
            question("bot_token", true),
            question("api_secret", true),
            question("url", false),
        ]);
        let secret_ids: Vec<&str> = spec
            .questions
            .iter()
            .filter(|q| q.secret)
            .map(|q| q.id.as_str())
            .collect();
        assert_eq!(secret_ids, vec!["bot_token", "api_secret"]);
    }

    #[test]
    fn value_to_text_handles_strings_and_json_values() {
        assert_eq!(value_to_text(&json!("token")), "token");
        assert_eq!(value_to_text(&json!(true)), "true");
        assert_eq!(value_to_text(&json!({"a": 1})), r#"{"a":1}"#);
    }

    #[test]
    fn oauth_stub_is_noop_with_and_without_url() {
        assert!(oauth_authorize_stub("provider-a", Some("https://auth.example.com")).is_none());
        assert!(oauth_authorize_stub("provider-a", None).is_none());
    }

    #[test]
    fn filter_secrets_leaves_non_object_values_unchanged() {
        let value = json!(true);
        assert_eq!(filter_secrets(&value, &["token"]), value);
    }

    #[test]
    fn read_secret_requirements_reads_asset_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pack = dir.path().join("pack.gtpack");
        let file = std::fs::File::create(&pack).expect("pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "assets/secret-requirements.json",
            zip::write::FileOptions::<()>::default(),
        )
        .expect("start file");
        zip.write_all(br#"[{"key":"SLACK_BOT_TOKEN"},{"key":"API_KEY"}]"#)
            .expect("write");
        zip.finish().expect("finish");

        let reqs = read_secret_requirements(&pack).expect("requirements");
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].key, "SLACK_BOT_TOKEN");
        assert_eq!(reqs[1].key, "API_KEY");
    }

    #[test]
    fn persist_qa_config_filters_secret_fields_before_writing_envelope() {
        let dir = tempfile::tempdir().expect("tempdir");
        let providers_root = dir.path().join(".providers");
        fs::create_dir_all(&providers_root).expect("providers");

        let pack = dir.path().join("provider.gtpack");
        fs::write(&pack, b"fixture").expect("pack");

        let spec = make_form_spec(vec![
            question("bot_token", true),
            question("public_url", false),
        ]);
        persist_qa_config(
            &providers_root,
            "messaging-slack",
            &json!({
                "bot_token": "secret123",
                "public_url": "https://example.com"
            }),
            &pack,
            &spec,
            false,
        )
        .expect("persist config");

        let envelope = crate::provider_config_envelope::read_provider_config_envelope(
            &providers_root,
            "messaging-slack",
        )
        .expect("read envelope")
        .expect("envelope");
        assert_eq!(envelope.config["public_url"], "https://example.com");
        assert!(envelope.config.get("bot_token").is_none());
    }

    #[test]
    fn persist_qa_secrets_saves_non_empty_answers_and_skips_nulls() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DevStore::with_path(dir.path().join("secrets.env")).expect("store");
        let spec = make_form_spec(vec![
            question("bot_token", true),
            question("retries", false),
            question("empty", true),
        ]);
        let runtime = Runtime::new().expect("runtime");
        let saved = runtime
            .block_on(persist_qa_secrets(
                &store,
                "dev",
                "demo",
                Some("default"),
                "messaging-slack",
                &json!({
                    "bot_token": "secret123",
                    "retries": 3,
                    "empty": ""
                }),
                &spec,
            ))
            .expect("persist secrets");

        assert_eq!(saved, vec!["bot_token".to_string(), "retries".to_string()]);
        let bot_uri = canonical_secret_uri(
            "dev",
            "demo",
            Some("default"),
            "messaging-slack",
            "bot_token",
        );
        let retries_uri =
            canonical_secret_uri("dev", "demo", Some("default"), "messaging-slack", "retries");
        let bot = runtime
            .block_on(store.get(&bot_uri))
            .expect("read bot token");
        let retries = runtime
            .block_on(store.get(&retries_uri))
            .expect("read retries");
        assert_eq!(bot, b"secret123".to_vec());
        assert_eq!(retries, b"3".to_vec());
    }

    #[test]
    fn seed_secret_requirement_aliases_creates_alias_entries_for_suffix_matches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DevStore::with_path(dir.path().join("secrets.env")).expect("store");
        let runtime = Runtime::new().expect("runtime");
        let existing = SeedDoc {
            entries: vec![SeedEntry {
                uri: canonical_secret_uri(
                    "dev",
                    "demo",
                    Some("default"),
                    "messaging-slack",
                    "bot_token",
                ),
                format: greentic_secrets_lib::SecretFormat::Text,
                value: SeedValue::Text {
                    text: "secret123".to_string(),
                },
                description: None,
            }],
        };
        let report = runtime
            .block_on(async { apply_seed(&store, &existing, ApplyOptions::default()).await });
        assert_eq!(report.ok, 1);

        let pack = dir.path().join("pack.gtpack");
        let file = std::fs::File::create(&pack).expect("pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "assets/secret-requirements.json",
            zip::write::FileOptions::<()>::default(),
        )
        .expect("start file");
        zip.write_all(br#"[{"key":"SLACK_BOT_TOKEN"}]"#)
            .expect("write");
        zip.finish().expect("finish");

        let count = runtime
            .block_on(seed_secret_requirement_aliases(
                &store,
                json!({"bot_token": "secret123"}).as_object().unwrap(),
                "dev",
                "demo",
                Some("default"),
                "messaging-slack",
                &pack,
            ))
            .expect("seed aliases");
        assert_eq!(count, 1);

        let alias_uri = canonical_secret_uri(
            "dev",
            "demo",
            Some("default"),
            "messaging-slack",
            "slack_bot_token",
        );
        let alias = runtime.block_on(store.get(&alias_uri)).expect("alias");
        assert_eq!(alias, b"secret123".to_vec());
    }

    // ── C7: pack-config-input.v1 emitter ──────────────────────────────────

    /// Secrets land as `secret://` URI refs (no plaintext); non-secrets stay
    /// inline. Empty config → no file written.
    #[test]
    fn emit_pack_config_input_splits_secret_vs_non_secret() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let root = tmp.path();
        let form = make_form_spec(vec![
            question("enabled", false),
            question("bot_token", true),
            question("public_url", false),
        ]);
        let config = json!({
            "enabled": true,
            "bot_token": "shhh",
            "public_url": "https://example.com",
        });
        let path =
            emit_pack_config_input(root, "local", "test-bundle", "provider-a", &config, &form)
                .expect("emit")
                .expect("path");
        assert!(path.exists());
        let bytes = fs::read(&path).expect("read");
        let parsed: PackConfigInput = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(parsed.schema, PACK_CONFIG_INPUT_SCHEMA);
        assert_eq!(parsed.pack_id, "provider-a");
        assert_eq!(parsed.env_id, "local");
        assert_eq!(parsed.bundle_id, "test-bundle");
        assert_eq!(parsed.non_secret.get("enabled"), Some(&Value::Bool(true)));
        assert_eq!(
            parsed.non_secret.get("public_url"),
            Some(&Value::String("https://example.com".into())),
        );
        assert!(
            !parsed.non_secret.contains_key("bot_token"),
            "secret must not be in non_secret"
        );
        assert_eq!(
            parsed.secret_refs.get("bot_token").map(String::as_str),
            Some("secret://local/test-bundle/provider-a/bot_token"),
            "secret recorded as URI ref"
        );
        let body = String::from_utf8(bytes).expect("utf8");
        assert!(
            !body.contains("shhh"),
            "plaintext secret leaked into pack-config-input: {body}"
        );
    }

    /// Same answers + different env_id → different secret_refs.
    #[test]
    fn emit_pack_config_input_secret_refs_discriminate_on_env_id() {
        let tmp_a = tempfile::TempDir::new().expect("tempdir-a");
        let tmp_b = tempfile::TempDir::new().expect("tempdir-b");
        let form = make_form_spec(vec![question("api_token", true)]);
        let cfg = json!({"api_token": "x"});
        let pa = emit_pack_config_input(tmp_a.path(), "local", "b", "p", &cfg, &form)
            .expect("emit-a")
            .expect("path-a");
        let pb = emit_pack_config_input(tmp_b.path(), "staging", "b", "p", &cfg, &form)
            .expect("emit-b")
            .expect("path-b");
        let parsed_a: PackConfigInput = serde_json::from_slice(&fs::read(&pa).unwrap()).unwrap();
        let parsed_b: PackConfigInput = serde_json::from_slice(&fs::read(&pb).unwrap()).unwrap();
        assert_eq!(
            parsed_a.secret_refs.get("api_token").map(String::as_str),
            Some("secret://local/b/p/api_token")
        );
        assert_eq!(
            parsed_b.secret_refs.get("api_token").map(String::as_str),
            Some("secret://staging/b/p/api_token")
        );
    }

    /// Empty config → no file written.
    #[test]
    fn emit_pack_config_input_skips_empty_config() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let root = tmp.path();
        let form = make_form_spec(vec![question("enabled", false)]);
        let empty = json!({});
        assert!(
            emit_pack_config_input(root, "local", "b", "p", &empty, &form)
                .expect("emit")
                .is_none()
        );
        assert!(!root.join(PACK_CONFIG_INPUT_DIR).exists());
    }

    /// Reject invalid path segments — `/`-bearing, empty, or `.`/`..`.
    #[test]
    fn emit_pack_config_input_rejects_invalid_segments() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let root = tmp.path();
        let form = make_form_spec(vec![question("k", false)]);
        let cfg = json!({"k": "v"});
        assert!(emit_pack_config_input(root, "", "b", "p", &cfg, &form).is_err());
        assert!(emit_pack_config_input(root, "local", "b", "../p", &cfg, &form).is_err());
        assert!(emit_pack_config_input(root, "local", "b/c", "p", &cfg, &form).is_err());
        assert!(emit_pack_config_input(root, "local", "b", "..", &cfg, &form).is_err());
        assert!(emit_pack_config_input(root, ".", "b", "p", &cfg, &form).is_err());
    }

    /// Conditionally-invisible questions must not leak into the file.
    #[test]
    fn emit_pack_config_input_respects_visibility() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let root = tmp.path();
        let form = make_form_spec(vec![question("mode", false), {
            let mut q = question("advanced_url", false);
            q.visible_if = Some(qa_spec::Expr::Eq {
                left: Box::new(qa_spec::Expr::Answer {
                    path: "mode".into(),
                }),
                right: Box::new(qa_spec::Expr::Literal {
                    value: Value::String("advanced".into()),
                }),
            });
            q
        }]);
        let config = json!({
            "mode": "basic",
            "advanced_url": "https://should-be-hidden.example.com",
        });
        let path = emit_pack_config_input(root, "local", "b", "p", &config, &form)
            .expect("emit")
            .expect("path");
        let parsed: PackConfigInput = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(
            !parsed.non_secret.contains_key("advanced_url"),
            "invisible question should not appear in non_secret: {parsed:?}"
        );
        assert_eq!(
            parsed.non_secret.get("mode"),
            Some(&Value::String("basic".into())),
        );
    }

    /// `infer_bundle_id` returns the directory name, with `"bundle"`
    /// fallback when the root has no usable file name.
    #[test]
    fn infer_bundle_id_uses_dir_name_with_bundle_fallback() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("my-bundle");
        fs::create_dir_all(&nested).expect("nested");
        assert_eq!(infer_bundle_id(&nested), "my-bundle");
        assert_eq!(infer_bundle_id(Path::new("/")), "bundle");
    }

    /// Stale-file cleanup: when an earlier wizard run wrote a
    /// pack-config-input.v1 file and a subsequent run produces no visible /
    /// non-empty entries, the existing file must be removed so the deployer
    /// does not pick up stale answers on the next revision-create.
    #[test]
    fn emit_pack_config_input_removes_stale_file_when_answers_clear() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let root = tmp.path();
        let form = make_form_spec(vec![question("enabled", false)]);

        // First run: produces a file.
        let path =
            emit_pack_config_input(root, "local", "b", "p", &json!({"enabled": true}), &form)
                .expect("emit-first")
                .expect("path");
        assert!(path.exists(), "first run must write the file");

        // Second run: empty config → file must be removed.
        let empty = json!({});
        assert!(
            emit_pack_config_input(root, "local", "b", "p", &empty, &form)
                .expect("emit-empty")
                .is_none()
        );
        assert!(
            !path.exists(),
            "stale pack-config-input survived after empty re-run: {}",
            path.display()
        );

        // Third run: rewrite, then a run where every value is empty/null →
        // file must again be removed (post-filter Ok(None) path).
        emit_pack_config_input(root, "local", "b", "p", &json!({"enabled": true}), &form)
            .expect("emit-third")
            .expect("path-third");
        assert!(path.exists());
        assert!(
            emit_pack_config_input(root, "local", "b", "p", &json!({"enabled": ""}), &form)
                .expect("emit-blank")
                .is_none()
        );
        assert!(
            !path.exists(),
            "stale pack-config-input survived after all-empty re-run: {}",
            path.display()
        );
    }

    /// Visibility-driven empty result also tombstones any stale file.
    #[test]
    fn emit_pack_config_input_removes_stale_file_when_visibility_clears_all() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let root = tmp.path();
        let form = make_form_spec(vec![question("mode", false), {
            let mut q = question("token", true);
            q.visible_if = Some(qa_spec::Expr::Eq {
                left: Box::new(qa_spec::Expr::Answer {
                    path: "mode".into(),
                }),
                right: Box::new(qa_spec::Expr::Literal {
                    value: Value::String("advanced".into()),
                }),
            });
            q
        }]);

        // First run: mode=advanced → token visible → file written.
        let path = emit_pack_config_input(
            root,
            "local",
            "b",
            "p",
            &json!({"mode": "advanced", "token": "shhh"}),
            &form,
        )
        .expect("emit-first")
        .expect("path");
        assert!(path.exists());

        // Second run: every visible answer absent → file must be removed.
        let absent = json!({});
        assert!(
            emit_pack_config_input(root, "local", "b", "p", &absent, &form)
                .expect("emit-absent")
                .is_none()
        );
        assert!(
            !path.exists(),
            "stale pack-config-input survived after visibility-empty re-run: {}",
            path.display()
        );
    }
}
