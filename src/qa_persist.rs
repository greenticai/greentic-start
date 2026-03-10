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

#[cfg(test)]
mod tests {
    use super::*;
    use qa_spec::{QuestionSpec, QuestionType};
    use serde_json::json;

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
}
