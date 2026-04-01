#![allow(dead_code)]

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
    str::FromStr,
};

use anyhow::{Context, anyhow};
use rpassword::prompt_password;
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value};
use zip::{ZipArchive, result::ZipError};

/// Answers loaded from a user-provided `--setup-input` file.
#[derive(Clone)]
pub struct SetupInputAnswers {
    raw: Value,
    provider_keys: BTreeSet<String>,
}

impl SetupInputAnswers {
    /// Creates a new helper with the raw file data and the set of known provider ids.
    pub fn new(raw: Value, provider_keys: BTreeSet<String>) -> anyhow::Result<Self> {
        Ok(Self { raw, provider_keys })
    }

    /// Returns the answers that correspond to a provider/pack.
    pub fn answers_for_provider(&self, provider: &str) -> Option<&Value> {
        if let Some(map) = self.raw.as_object() {
            if let Some(value) = map.get(provider) {
                return Some(value);
            }
            if !self.provider_keys.is_empty()
                && map.keys().all(|key| self.provider_keys.contains(key))
            {
                return None;
            }
        }
        Some(&self.raw)
    }
}

/// Reads a JSON/YAML answers file (mirrors the fixtures shipped with the packs).
pub fn load_setup_input(path: &Path) -> anyhow::Result<Value> {
    let raw = fs::read_to_string(path)?;
    serde_json::from_str(&raw)
        .or_else(|_| serde_yaml_bw::from_str(&raw))
        .with_context(|| format!("parse setup input {}", path.display()))
}

/// Represents a provider setup spec extracted from `assets/setup.yaml`.
#[derive(Debug, Deserialize)]
pub struct SetupSpec {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub questions: Vec<SetupQuestion>,
}

#[derive(Debug, Deserialize)]
pub struct SetupQuestion {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub help: Option<String>,
    #[serde(default)]
    pub choices: Vec<String>,
    #[serde(default)]
    pub default: Option<Value>,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub title: Option<String>,
}

fn default_kind() -> String {
    "string".to_string()
}

pub fn load_setup_spec(pack_path: &Path) -> anyhow::Result<Option<SetupSpec>> {
    let file = File::open(pack_path)?;
    let mut archive = match ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(ZipError::InvalidArchive(_)) | Err(ZipError::UnsupportedArchive(_)) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let contents = match read_setup_yaml(&mut archive)? {
        Some(value) => value,
        None => return Ok(None),
    };
    let spec: SetupSpec =
        serde_yaml_bw::from_str(&contents).context("parse provider setup spec")?;
    Ok(Some(spec))
}

fn read_setup_yaml(archive: &mut ZipArchive<File>) -> anyhow::Result<Option<String>> {
    for entry in ["assets/setup.yaml", "setup.yaml"] {
        match archive.by_name(entry) {
            Ok(mut file) => {
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                return Ok(Some(contents));
            }
            Err(ZipError::FileNotFound) => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(None)
}

pub fn collect_setup_answers(
    pack_path: &Path,
    provider_id: &str,
    setup_input: Option<&SetupInputAnswers>,
    interactive: bool,
) -> anyhow::Result<Value> {
    let spec = load_setup_spec(pack_path)?;
    if let Some(input) = setup_input {
        if let Some(value) = input.answers_for_provider(provider_id) {
            let answers = ensure_object(value.clone())?;
            ensure_required_answers(spec.as_ref(), &answers)?;
            return Ok(answers);
        }
        if has_required_questions(spec.as_ref()) {
            return Err(anyhow!("setup input missing answers for {provider_id}"));
        }
        return Ok(Value::Object(JsonMap::new()));
    }
    if let Some(spec) = spec {
        if spec.questions.is_empty() {
            return Ok(Value::Object(JsonMap::new()));
        }
        if !has_required_questions(Some(&spec)) && !interactive {
            return Ok(Value::Object(JsonMap::new()));
        }
        if interactive {
            let answers = prompt_setup_answers(&spec, provider_id)?;
            ensure_required_answers(Some(&spec), &answers)?;
            return Ok(answers);
        }
        return Err(anyhow!(
            "setup answers required for {provider_id} but run is non-interactive"
        ));
    }
    Ok(Value::Object(JsonMap::new()))
}

fn has_required_questions(spec: Option<&SetupSpec>) -> bool {
    spec.map(|spec| spec.questions.iter().any(|question| question.required))
        .unwrap_or(false)
}

fn ensure_required_answers(spec: Option<&SetupSpec>, answers: &Value) -> anyhow::Result<()> {
    let map = answers
        .as_object()
        .ok_or_else(|| anyhow!("setup answers must be an object"))?;
    if let Some(spec) = spec {
        for question in spec.questions.iter().filter(|question| question.required) {
            match map.get(&question.name) {
                Some(value) if !value.is_null() => continue,
                _ => {
                    return Err(anyhow!(
                        "missing required setup answer for {}",
                        question.name
                    ));
                }
            }
        }
    }
    Ok(())
}

fn ensure_object(value: Value) -> anyhow::Result<Value> {
    match value {
        Value::Object(_) => Ok(value),
        other => Err(anyhow!(
            "setup answers must be a JSON object, got {}",
            other
        )),
    }
}

fn prompt_setup_answers(spec: &SetupSpec, provider: &str) -> anyhow::Result<Value> {
    if spec.questions.is_empty() {
        return Ok(Value::Object(JsonMap::new()));
    }
    let title = spec.title.as_deref().unwrap_or(provider).to_string();
    println!("\nConfiguring {provider}: {title}");
    let mut answers = JsonMap::new();
    for question in &spec.questions {
        if question.name.trim().is_empty() {
            continue;
        }
        if let Some(value) = ask_setup_question(question)? {
            answers.insert(question.name.clone(), value);
        }
    }
    Ok(Value::Object(answers))
}

fn ask_setup_question(question: &SetupQuestion) -> anyhow::Result<Option<Value>> {
    if let Some(help) = question.help.as_ref()
        && !help.trim().is_empty()
    {
        println!("  {help}");
    }
    if !question.choices.is_empty() {
        println!("  Choices:");
        for (idx, choice) in question.choices.iter().enumerate() {
            println!("    {}) {}", idx + 1, choice);
        }
    }
    loop {
        let prompt = build_question_prompt(question);
        let input = read_question_input(&prompt, question.secret)?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            if let Some(default) = question.default.clone() {
                return Ok(Some(default));
            }
            if question.required {
                println!("  This field is required.");
                continue;
            }
            return Ok(None);
        }
        match parse_question_value(question, trimmed) {
            Ok(value) => return Ok(Some(value)),
            Err(err) => {
                println!("  {err}");
                continue;
            }
        }
    }
}

fn build_question_prompt(question: &SetupQuestion) -> String {
    let mut prompt = question
        .title
        .as_deref()
        .unwrap_or(&question.name)
        .to_string();
    if question.kind != "string" {
        prompt = format!("{prompt} [{}]", question.kind);
    }
    if let Some(default) = &question.default {
        prompt = format!("{prompt} [default: {}]", display_value(default));
    }
    prompt.push_str(": ");
    prompt
}

fn read_question_input(prompt: &str, secret: bool) -> anyhow::Result<String> {
    if secret {
        prompt_password(prompt).map_err(|err| anyhow!("read secret: {err}"))
    } else {
        print!("{prompt}");
        io::stdout().flush()?;
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer)?;
        Ok(buffer)
    }
}

fn parse_question_value(question: &SetupQuestion, input: &str) -> anyhow::Result<Value> {
    let kind = question.kind.to_lowercase();
    match kind.as_str() {
        "number" => serde_json::Number::from_str(input)
            .map(Value::Number)
            .map_err(|err| anyhow!("invalid number: {err}")),
        "choice" => {
            if question.choices.is_empty() {
                return Ok(Value::String(input.to_string()));
            }
            if let Ok(index) = input.parse::<usize>()
                && let Some(choice) = question.choices.get(index - 1)
            {
                return Ok(Value::String(choice.clone()));
            }
            for choice in &question.choices {
                if choice == input {
                    return Ok(Value::String(choice.clone()));
                }
            }
            Err(anyhow!("invalid choice '{input}'"))
        }
        "boolean" => match input.to_lowercase().as_str() {
            "true" | "t" | "yes" | "y" => Ok(Value::Bool(true)),
            "false" | "f" | "no" | "n" => Ok(Value::Bool(false)),
            _ => Err(anyhow!("invalid boolean value")),
        },
        _ => Ok(Value::String(input.to_string())),
    }
}

fn display_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use zip::write::{FileOptions, ZipWriter};

    fn create_test_pack(yaml: &str) -> Result<(TempDir, PathBuf)> {
        let temp_dir = tempfile::tempdir()?;
        let pack_path = temp_dir.path().join("messaging-test.gtpack");
        let file = File::create(&pack_path)?;
        let mut writer = ZipWriter::new(file);
        let options: FileOptions<'_, ()> =
            FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer.start_file("assets/setup.yaml", options)?;
        writer.write_all(yaml.as_bytes())?;
        writer.finish()?;
        Ok((temp_dir, pack_path))
    }

    #[test]
    fn parse_setup_yaml_questions() -> Result<()> {
        let yaml = r#"
provider_id: dummy
questions:
  - name: public_base_url
    required: true
"#;
        let (_dir, pack_path) = create_test_pack(yaml)?;
        let spec = load_setup_spec(&pack_path)?.expect("expected spec");
        assert_eq!(spec.questions.len(), 1);
        assert_eq!(spec.questions[0].name, "public_base_url");
        assert!(spec.questions[0].required);
        Ok(())
    }

    #[test]
    fn collect_setup_answers_uses_input() -> Result<()> {
        let yaml = r#"
provider_id: telegram
questions:
  - name: public_base_url
    required: true
"#;
        let (_dir, pack_path) = create_test_pack(yaml)?;
        let provider_keys = BTreeSet::from(["messaging-telegram".to_string()]);
        let raw = json!({
            "messaging-telegram": {
                "public_base_url": "https://example.com"
            }
        });
        let answers = SetupInputAnswers::new(raw, provider_keys)?;
        let collected =
            collect_setup_answers(&pack_path, "messaging-telegram", Some(&answers), false)?;
        assert_eq!(
            collected.get("public_base_url"),
            Some(&Value::String("https://example.com".to_string()))
        );
        Ok(())
    }

    #[test]
    fn collect_setup_answers_missing_required_errors() -> Result<()> {
        let yaml = r#"
provider_id: slack
questions:
  - name: slack_bot_token
    required: true
"#;
        let (_dir, pack_path) = create_test_pack(yaml)?;
        let provider_keys = BTreeSet::from(["messaging-slack".to_string()]);
        let raw = json!({
            "messaging-slack": {}
        });
        let answers = SetupInputAnswers::new(raw, provider_keys)?;
        let error = collect_setup_answers(&pack_path, "messaging-slack", Some(&answers), false)
            .unwrap_err();
        assert!(error.to_string().contains("missing required setup answer"));
        Ok(())
    }

    #[test]
    fn answers_for_provider_falls_back_to_raw_object_when_not_provider_keyed() -> Result<()> {
        let answers = SetupInputAnswers::new(
            json!({"public_base_url": "https://example.com"}),
            BTreeSet::from(["messaging-slack".to_string()]),
        )?;
        assert_eq!(
            answers
                .answers_for_provider("messaging-slack")
                .and_then(|value| value.get("public_base_url")),
            Some(&Value::String("https://example.com".to_string()))
        );
        Ok(())
    }

    #[test]
    fn non_interactive_setup_without_required_questions_returns_empty_object() -> Result<()> {
        let yaml = r#"
questions:
  - name: optional_value
    required: false
"#;
        let (_dir, pack_path) = create_test_pack(yaml)?;
        let collected = collect_setup_answers(&pack_path, "messaging-test", None, false)?;
        assert_eq!(collected, Value::Object(JsonMap::new()));
        Ok(())
    }

    #[test]
    fn parse_question_value_handles_choice_boolean_and_number_inputs() -> Result<()> {
        let choice = SetupQuestion {
            name: "mode".to_string(),
            kind: "choice".to_string(),
            required: false,
            help: None,
            choices: vec!["alpha".to_string(), "beta".to_string()],
            default: None,
            secret: false,
            title: None,
        };
        assert_eq!(
            parse_question_value(&choice, "2")?,
            Value::String("beta".to_string())
        );
        assert!(parse_question_value(&choice, "3").is_err());

        let boolean = SetupQuestion {
            name: "enabled".to_string(),
            kind: "boolean".to_string(),
            required: false,
            help: None,
            choices: vec![],
            default: None,
            secret: false,
            title: None,
        };
        assert_eq!(parse_question_value(&boolean, "y")?, Value::Bool(true));
        assert_eq!(parse_question_value(&boolean, "no")?, Value::Bool(false));

        let number = SetupQuestion {
            name: "count".to_string(),
            kind: "number".to_string(),
            required: false,
            help: None,
            choices: vec![],
            default: None,
            secret: false,
            title: None,
        };
        assert_eq!(parse_question_value(&number, "42")?, json!(42));
        Ok(())
    }
}
