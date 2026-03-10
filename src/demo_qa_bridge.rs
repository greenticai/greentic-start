#![allow(dead_code)]

//! Bridge between provider QA specs and greentic-qa's FormSpec engine.
//!
//! Providers return a simple list of `(id, i18n_key, required)` questions.
//! This module converts that into a full `qa_spec::FormSpec` so the operator
//! can drive wizard flows using greentic-qa's engine (visibility, progress,
//! validation, rendering).

use std::collections::{BTreeMap, HashMap};

use qa_spec::{
    FormSpec, I18nText, QuestionSpec, QuestionType, ResolvedI18nMap,
    spec::{FormPresentation, ProgressPolicy},
};
use serde_json::Value;

/// Convert provider QA spec JSON output + i18n translations into a `FormSpec`.
///
/// The provider's `qa-spec` output looks like:
/// ```json
/// {
///   "mode": "setup",
///   "title": {"key": "telegram.qa.setup.title"},
///   "questions": [
///     {"id": "enabled", "label": {"key": "telegram.qa.setup.enabled"}, "required": true},
///     ...
///   ]
/// }
/// ```
pub fn provider_qa_to_form_spec(
    qa_output: &Value,
    i18n: &HashMap<String, String>,
    provider: &str,
) -> FormSpec {
    let mode = qa_output
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("setup");

    // Resolve form title from i18n
    let title_key = qa_output
        .get("title")
        .and_then(|t| t.get("key").and_then(Value::as_str))
        .unwrap_or("");
    let title = i18n
        .get(title_key)
        .cloned()
        .unwrap_or_else(|| format!("{} setup", provider));

    // Parse questions
    let questions = qa_output
        .get("questions")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|q| convert_question(q, i18n, provider))
                .collect()
        })
        .unwrap_or_default();

    // Derive display name for intro
    let display_name = provider.strip_prefix("messaging-").unwrap_or(provider);
    let display_name = capitalize(display_name);

    FormSpec {
        id: format!("{provider}-{mode}"),
        title,
        version: "1.0.0".to_string(),
        description: Some(format!("{display_name} provider configuration")),
        presentation: Some(FormPresentation {
            intro: Some(format!(
                "Configure {display_name} provider settings.\n\
                 Fields marked with * are required."
            )),
            theme: None,
            default_locale: Some("en".to_string()),
        }),
        progress_policy: Some(ProgressPolicy {
            skip_answered: false,
            autofill_defaults: false,
            treat_default_as_answered: false,
        }),
        secrets_policy: None,
        store: vec![],
        validations: vec![],
        includes: vec![],
        questions,
    }
}

/// Convert a single provider question JSON to a `QuestionSpec`.
fn convert_question(
    q: &Value,
    i18n: &HashMap<String, String>,
    provider: &str,
) -> Option<QuestionSpec> {
    let id = q.get("id").and_then(Value::as_str)?.to_string();

    // Extract i18n key from label (can be string or {key: "..."})
    let label_key = q
        .get("label")
        .and_then(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| v.get("key").and_then(Value::as_str).map(String::from))
        })
        .unwrap_or_else(|| id.clone());

    // Resolve title from i18n
    let title = i18n.get(&label_key).cloned().unwrap_or_else(|| id.clone());

    // Resolve description from i18n (convention: {prefix}.schema.config.{id}.description)
    let description =
        description_key_for(&label_key, &id).and_then(|desc_key| i18n.get(&desc_key).cloned());

    let required = q.get("required").and_then(Value::as_bool).unwrap_or(false);

    // Infer type and properties from question id
    let (kind, secret, constraint) = infer_question_properties(&id);

    // Use explicit default from provider QaSpec, fall back to inferred default
    let default_value = q
        .get("default")
        .and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Bool(b) => Some(b.to_string()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
        .or_else(|| infer_default(&kind));

    Some(QuestionSpec {
        id,
        kind,
        title: title.clone(),
        title_i18n: Some(I18nText {
            key: label_key,
            args: None,
        }),
        description: description.clone(),
        description_i18n: description_key_for_raw(provider, q)
            .map(|key| I18nText { key, args: None }),
        required,
        choices: None,
        default_value,
        secret,
        visible_if: None,
        constraint,
        list: None,
        computed: None,
        policy: Default::default(),
        computed_overridable: false,
    })
}

/// Infer QuestionType, secret flag, and optional constraint from a question id.
pub fn infer_question_properties(
    id: &str,
) -> (QuestionType, bool, Option<qa_spec::spec::Constraint>) {
    match id {
        "enabled" => (QuestionType::Boolean, false, None),
        id if id.ends_with("_url") || id == "public_base_url" || id == "api_base_url" => (
            QuestionType::String,
            false,
            Some(qa_spec::spec::Constraint {
                pattern: Some(r"^https?://\S+".to_string()),
                min: None,
                max: None,
                min_len: None,
                max_len: None,
            }),
        ),
        id if id.ends_with("_token") || id.contains("secret") || id.contains("password") => {
            (QuestionType::String, true, None)
        }
        _ => (QuestionType::String, false, None),
    }
}

/// Return a sensible default for boolean questions.
fn infer_default(kind: &QuestionType) -> Option<String> {
    match kind {
        QuestionType::Boolean => Some("true".to_string()),
        _ => None,
    }
}

/// Derive the i18n description key from a label key and question id.
///
/// `telegram.qa.setup.enabled` + `enabled` → `telegram.schema.config.enabled.description`
fn description_key_for(label_key: &str, question_id: &str) -> Option<String> {
    let prefix = label_key.split(".qa.").next()?;
    Some(format!("{prefix}.schema.config.{question_id}.description"))
}

/// Try to build the description i18n key from raw question data.
fn description_key_for_raw(_provider: &str, q: &Value) -> Option<String> {
    let id = q.get("id").and_then(Value::as_str)?;
    let label_key = q
        .get("label")
        .and_then(|v| v.as_str().or_else(|| v.get("key").and_then(Value::as_str)))?;
    description_key_for(label_key, id)
}

/// Build a `ResolvedI18nMap` from the provider's i18n bundle.
///
/// greentic-qa expects keys like `"key"` or `"en:key"`.
/// We insert both forms for maximum compatibility.
pub fn build_resolved_i18n(i18n: &HashMap<String, String>) -> ResolvedI18nMap {
    let mut resolved = BTreeMap::new();
    for (key, value) in i18n {
        resolved.insert(key.clone(), value.clone());
        resolved.insert(format!("en:{key}"), value.clone());
    }
    resolved
}

/// Normalize a user's answer based on the question type.
///
/// For boolean questions, converts natural language (yes/no/y/n) to "true"/"false".
pub fn normalize_answer(answer: &str, kind: QuestionType) -> String {
    match kind {
        QuestionType::Boolean => match answer.to_ascii_lowercase().as_str() {
            "yes" | "y" | "true" | "1" | "on" => "true".to_string(),
            "no" | "n" | "false" | "0" | "off" => "false".to_string(),
            _ => answer.to_string(),
        },
        _ => answer.to_string(),
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => format!("{}{}", c.to_ascii_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_qa_output() -> Value {
        json!({
            "mode": "setup",
            "title": {"key": "telegram.qa.setup.title"},
            "questions": [
                {"id": "enabled", "label": {"key": "telegram.qa.setup.enabled"}, "required": true},
                {"id": "public_base_url", "label": {"key": "telegram.qa.setup.public_base_url"}, "required": true},
                {"id": "default_chat_id", "label": {"key": "telegram.qa.setup.default_chat_id"}, "required": false},
                {"id": "api_base_url", "label": {"key": "telegram.qa.setup.api_base_url"}, "required": true},
                {"id": "bot_token", "label": {"key": "telegram.qa.setup.bot_token"}, "required": false},
            ]
        })
    }

    fn sample_i18n() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("telegram.qa.setup.title".into(), "Setup".into());
        m.insert("telegram.qa.setup.enabled".into(), "Enable provider".into());
        m.insert(
            "telegram.qa.setup.public_base_url".into(),
            "Public base URL".into(),
        );
        m.insert(
            "telegram.qa.setup.default_chat_id".into(),
            "Default chat ID".into(),
        );
        m.insert(
            "telegram.qa.setup.api_base_url".into(),
            "API base URL".into(),
        );
        m.insert("telegram.qa.setup.bot_token".into(), "Bot token".into());
        m.insert(
            "telegram.schema.config.enabled.description".into(),
            "Enable this provider".into(),
        );
        m.insert(
            "telegram.schema.config.public_base_url.description".into(),
            "Public URL for webhook callbacks".into(),
        );
        m.insert(
            "telegram.schema.config.bot_token.description".into(),
            "Bot token for Telegram API calls".into(),
        );
        m
    }

    #[test]
    fn converts_provider_qa_to_form_spec() {
        let form =
            provider_qa_to_form_spec(&sample_qa_output(), &sample_i18n(), "messaging-telegram");
        assert_eq!(form.id, "messaging-telegram-setup");
        assert_eq!(form.title, "Setup");
        assert_eq!(form.questions.len(), 5);
    }

    #[test]
    fn infers_question_types() {
        let form =
            provider_qa_to_form_spec(&sample_qa_output(), &sample_i18n(), "messaging-telegram");
        assert_eq!(form.questions[0].kind, QuestionType::Boolean); // enabled
        assert_eq!(form.questions[1].kind, QuestionType::String); // public_base_url
        assert!(form.questions[1].constraint.is_some()); // URL constraint
        assert!(form.questions[4].secret); // bot_token
    }

    #[test]
    fn resolves_titles_from_i18n() {
        let form =
            provider_qa_to_form_spec(&sample_qa_output(), &sample_i18n(), "messaging-telegram");
        assert_eq!(form.questions[0].title, "Enable provider");
        assert_eq!(form.questions[4].title, "Bot token");
    }

    #[test]
    fn resolves_descriptions_from_i18n() {
        let form =
            provider_qa_to_form_spec(&sample_qa_output(), &sample_i18n(), "messaging-telegram");
        assert_eq!(
            form.questions[0].description.as_deref(),
            Some("Enable this provider")
        );
        assert_eq!(
            form.questions[4].description.as_deref(),
            Some("Bot token for Telegram API calls")
        );
    }

    #[test]
    fn normalizes_boolean_answers() {
        assert_eq!(normalize_answer("yes", QuestionType::Boolean), "true");
        assert_eq!(normalize_answer("No", QuestionType::Boolean), "false");
        assert_eq!(normalize_answer("y", QuestionType::Boolean), "true");
        assert_eq!(normalize_answer("hello", QuestionType::String), "hello");
    }

    #[test]
    fn builds_resolved_i18n_map() {
        let i18n = sample_i18n();
        let resolved = build_resolved_i18n(&i18n);
        assert_eq!(
            resolved
                .get("telegram.qa.setup.enabled")
                .map(String::as_str),
            Some("Enable provider")
        );
        assert_eq!(
            resolved
                .get("en:telegram.qa.setup.enabled")
                .map(String::as_str),
            Some("Enable provider")
        );
    }
}
