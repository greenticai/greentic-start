//! Converts legacy `setup.yaml` (`SetupSpec`) into a `qa_spec::FormSpec`.
//!
//! This allows the operator to drive provider configuration through a single
//! FormSpec-based wizard regardless of whether the provider ships a WASM
//! `qa-spec` op or a static `setup.yaml` file.

use std::path::Path;

use qa_spec::spec::{Constraint, FormPresentation, ProgressPolicy};
use qa_spec::{FormSpec, QuestionSpec, QuestionType};

use crate::setup_input::{SetupQuestion, SetupSpec, load_setup_spec};

/// Convert a legacy `SetupSpec` (from `assets/setup.yaml`) into a `FormSpec`.
pub fn setup_spec_to_form_spec(spec: &SetupSpec, provider_id: &str) -> FormSpec {
    let display_name = provider_id
        .strip_prefix("messaging-")
        .or_else(|| provider_id.strip_prefix("events-"))
        .unwrap_or(provider_id);
    let display_name = capitalize(display_name);

    let title = spec
        .title
        .clone()
        .unwrap_or_else(|| format!("{display_name} setup"));

    let questions: Vec<QuestionSpec> = spec.questions.iter().map(convert_setup_question).collect();

    FormSpec {
        id: format!("{provider_id}-setup"),
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

/// Convert a single `SetupQuestion` to a `QuestionSpec`.
fn convert_setup_question(q: &SetupQuestion) -> QuestionSpec {
    let kind = match q.kind.as_str() {
        "boolean" => QuestionType::Boolean,
        "number" => QuestionType::Number,
        "choice" | "enum" => QuestionType::Enum,
        _ => QuestionType::String,
    };

    // Infer type, secret flag, and constraint from naming conventions
    let (inferred_kind, inferred_secret, inferred_constraint) = infer_question_properties(&q.name);

    // Explicit kind from setup.yaml takes priority unless it's the default "string"
    let final_kind = if q.kind == "string" {
        inferred_kind
    } else {
        kind
    };

    // Explicit secret flag from setup.yaml takes priority
    let secret = q.secret || inferred_secret;

    // Use inferred constraint if none would be derived from the explicit kind
    let constraint = if final_kind == QuestionType::String {
        inferred_constraint
    } else {
        None
    };

    let choices = if q.choices.is_empty() {
        None
    } else {
        Some(q.choices.clone())
    };

    let default_value = q.default.as_ref().map(|v| match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    });

    QuestionSpec {
        id: q.name.clone(),
        kind: final_kind,
        title: q.title.clone().unwrap_or_else(|| q.name.clone()),
        title_i18n: None,
        description: q.help.clone(),
        description_i18n: None,
        required: q.required,
        choices,
        default_value,
        secret,
        visible_if: None,
        constraint,
        list: None,
        computed: None,
        policy: Default::default(),
        computed_overridable: false,
    }
}

/// Load a `FormSpec` from a pack's `setup.yaml`, if present.
pub fn pack_to_form_spec(pack_path: &Path, provider_id: &str) -> Option<FormSpec> {
    let spec = load_setup_spec(pack_path).ok()??;
    Some(setup_spec_to_form_spec(&spec, provider_id))
}

/// Infer QuestionType, secret flag, and optional constraint from a question id.
///
/// Shared logic with `qa_bridge::infer_question_properties` — kept here to
/// avoid circular dependency issues when qa_bridge is not yet activated.
pub fn infer_question_properties(id: &str) -> (QuestionType, bool, Option<Constraint>) {
    match id {
        "enabled" => (QuestionType::Boolean, false, None),
        id if id.ends_with("_url") || id == "public_base_url" || id == "api_base_url" => (
            QuestionType::String,
            false,
            Some(Constraint {
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

    fn sample_setup_spec() -> SetupSpec {
        SetupSpec {
            title: Some("Telegram Setup".to_string()),
            questions: vec![
                SetupQuestion {
                    name: "enabled".to_string(),
                    kind: "boolean".to_string(),
                    required: true,
                    help: Some("Enable this provider".to_string()),
                    choices: vec![],
                    default: Some(json!(true)),
                    secret: false,
                    title: Some("Enable provider".to_string()),
                },
                SetupQuestion {
                    name: "public_base_url".to_string(),
                    kind: "string".to_string(),
                    required: true,
                    help: Some("Public URL for webhook callbacks".to_string()),
                    choices: vec![],
                    default: None,
                    secret: false,
                    title: None,
                },
                SetupQuestion {
                    name: "bot_token".to_string(),
                    kind: "string".to_string(),
                    required: true,
                    help: Some("Telegram bot token".to_string()),
                    choices: vec![],
                    default: None,
                    secret: true,
                    title: Some("Bot Token".to_string()),
                },
                SetupQuestion {
                    name: "log_level".to_string(),
                    kind: "choice".to_string(),
                    required: false,
                    help: None,
                    choices: vec!["debug".into(), "info".into(), "warn".into()],
                    default: Some(json!("info")),
                    secret: false,
                    title: Some("Log Level".to_string()),
                },
            ],
        }
    }

    #[test]
    fn converts_setup_spec_to_form_spec() {
        let form = setup_spec_to_form_spec(&sample_setup_spec(), "messaging-telegram");
        assert_eq!(form.id, "messaging-telegram-setup");
        assert_eq!(form.title, "Telegram Setup");
        assert_eq!(form.questions.len(), 4);
    }

    #[test]
    fn maps_question_types_correctly() {
        let form = setup_spec_to_form_spec(&sample_setup_spec(), "messaging-telegram");
        assert_eq!(form.questions[0].kind, QuestionType::Boolean); // enabled
        assert_eq!(form.questions[1].kind, QuestionType::String); // public_base_url
        assert_eq!(form.questions[3].kind, QuestionType::Enum); // log_level (choice)
    }

    #[test]
    fn detects_url_constraint() {
        let form = setup_spec_to_form_spec(&sample_setup_spec(), "messaging-telegram");
        let url_q = &form.questions[1]; // public_base_url
        assert!(url_q.constraint.is_some());
        let c = url_q.constraint.as_ref().unwrap();
        assert!(c.pattern.as_ref().unwrap().contains("https?"));
    }

    #[test]
    fn detects_secret_fields() {
        let form = setup_spec_to_form_spec(&sample_setup_spec(), "messaging-telegram");
        assert!(form.questions[2].secret); // bot_token — explicit
        assert!(!form.questions[0].secret); // enabled
    }

    #[test]
    fn preserves_choices_and_defaults() {
        let form = setup_spec_to_form_spec(&sample_setup_spec(), "messaging-telegram");
        let log_q = &form.questions[3];
        assert_eq!(log_q.choices.as_ref().unwrap(), &["debug", "info", "warn"]);
        assert_eq!(log_q.default_value.as_deref(), Some("info"));
    }

    #[test]
    fn preserves_descriptions() {
        let form = setup_spec_to_form_spec(&sample_setup_spec(), "messaging-telegram");
        assert_eq!(
            form.questions[0].description.as_deref(),
            Some("Enable this provider")
        );
        assert_eq!(
            form.questions[2].description.as_deref(),
            Some("Telegram bot token")
        );
    }

    #[test]
    fn handles_empty_spec() {
        let spec = SetupSpec {
            title: None,
            questions: vec![],
        };
        let form = setup_spec_to_form_spec(&spec, "messaging-dummy");
        assert_eq!(form.id, "messaging-dummy-setup");
        assert_eq!(form.title, "Dummy setup");
        assert!(form.questions.is_empty());
    }
}
