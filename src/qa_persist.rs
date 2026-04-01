#![allow(dead_code)]

//! Persist config and secrets from QA apply-answers output.
//!
//! After a provider's `apply-answers` op returns a config object, this module:
//! - Extracts secret fields (identified by `FormSpec.questions[].secret == true`)
//!   and writes them to the dev secrets store.
//! - Writes remaining (non-secret) fields to the provider config envelope.

use std::path::Path;

use anyhow::Result;
use greentic_secrets_lib::{
    ApplyOptions, DevStore, SecretFormat, SeedDoc, SeedEntry, SeedValue, apply_seed,
};
use qa_spec::FormSpec;
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
    // Collect all question IDs — WASM components read both secret and non-secret
    // config values via the secrets API, so we must persist everything.
    let all_question_ids: Vec<&str> = form_spec.questions.iter().map(|q| q.id.as_str()).collect();

    if all_question_ids.is_empty() {
        return Ok(vec![]);
    }

    let Some(config_map) = config.as_object() else {
        return Ok(vec![]);
    };

    let mut entries = Vec::new();
    let mut saved_keys = Vec::new();

    for &key in &all_question_ids {
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
    // secrets by their canonical requirement key (e.g. SLACK_BOT_TOKEN →
    // slack_bot_token) even when the answers file uses a shorter key (bot_token).
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
/// key (e.g. `SLACK_BOT_TOKEN` → `slack_bot_token`) even when the answers file
/// uses a shorter key (e.g. `bot_token`).
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
        // canonical config key. E.g., "slack_bot_token" ends with "bot_token".
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
}
