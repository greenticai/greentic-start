use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use serde_json::{Value as JsonValue, json};

use crate::discovery::{self, DiscoveryOptions};
use crate::domains::{Domain, ProviderPack};
use crate::runner_host::{DemoRunnerHost, OperatorContext};
use crate::secrets_gate;
use greentic_types::cbor::canonical;
use greentic_types::decode_pack_manifest;
use greentic_types::schemas::component::v0_6_0::ComponentQaSpec;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum QaMode {
    Default,
    Setup,
    Upgrade,
    Remove,
}

impl QaMode {
    pub fn as_str(self) -> &'static str {
        match self {
            QaMode::Default => "default",
            QaMode::Setup => "setup",
            QaMode::Upgrade => "upgrade",
            QaMode::Remove => "remove",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum QaDiagnosticCode {
    QaSpecFailed,
    QaSpecInvalid,
    I18nExportMissing,
    I18nKeyMissing,
    ApplyAnswersFailed,
    ConfigSchemaMismatch,
}

impl QaDiagnosticCode {
    pub fn as_str(self) -> &'static str {
        match self {
            QaDiagnosticCode::QaSpecFailed => "OP_QA_SPEC_FAILED",
            QaDiagnosticCode::QaSpecInvalid => "OP_QA_SPEC_INVALID",
            QaDiagnosticCode::I18nExportMissing => "OP_I18N_EXPORT_MISSING",
            QaDiagnosticCode::I18nKeyMissing => "OP_I18N_KEY_MISSING",
            QaDiagnosticCode::ApplyAnswersFailed => "OP_APPLY_ANSWERS_FAILED",
            QaDiagnosticCode::ConfigSchemaMismatch => "OP_CONFIG_SCHEMA_MISMATCH",
        }
    }
}

#[derive(Debug, Clone)]
pub struct QaDiagnostic {
    pub code: QaDiagnosticCode,
    pub message: String,
}

impl std::fmt::Display for QaDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for QaDiagnostic {}

#[allow(dead_code)]
pub fn qa_mode_for_flow(flow_id: &str) -> Option<QaMode> {
    let normalized = flow_id.to_ascii_lowercase();
    if normalized.contains("remove") {
        Some(QaMode::Remove)
    } else if normalized.contains("upgrade") {
        Some(QaMode::Upgrade)
    } else if normalized.contains("default") {
        Some(QaMode::Default)
    } else if normalized.contains("setup") {
        Some(QaMode::Setup)
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
pub fn apply_answers_via_component_qa(
    root: &Path,
    domain: Domain,
    tenant: &str,
    team: Option<&str>,
    pack: &ProviderPack,
    provider_id: &str,
    mode: QaMode,
    current_config: Option<&JsonValue>,
    answers: &JsonValue,
) -> Result<Option<JsonValue>, QaDiagnostic> {
    if !supports_component_qa_contract(&pack.path).map_err(|err| {
        diagnostic(
            QaDiagnosticCode::QaSpecFailed,
            format!("inspect qa contract support: {err}"),
        )
    })? {
        return Ok(None);
    }

    let cbor_only = root.join("greentic.demo.yaml").exists();
    let discovery = discovery::discover_with_options(root, DiscoveryOptions { cbor_only })
        .map_err(|err| {
            diagnostic(
                QaDiagnosticCode::QaSpecFailed,
                format!("discover providers: {err}"),
            )
        })?;
    let secrets_handle =
        secrets_gate::resolve_secrets_manager(root, tenant, team).map_err(|err| {
            diagnostic(
                QaDiagnosticCode::QaSpecFailed,
                format!("resolve secrets manager: {err}"),
            )
        })?;
    let host = DemoRunnerHost::new(root.to_path_buf(), &discovery, None, secrets_handle, false)
        .map_err(|err| {
            diagnostic(
                QaDiagnosticCode::QaSpecFailed,
                format!("build runner host: {err}"),
            )
        })?;
    let ctx = OperatorContext {
        tenant: tenant.to_string(),
        team: team.map(|value| value.to_string()),
        correlation_id: None,
    };

    let qa_payload = serde_json::to_vec(&json!({"mode": mode.as_str()})).map_err(|err| {
        diagnostic(
            QaDiagnosticCode::QaSpecFailed,
            format!("encode qa-spec payload: {err}"),
        )
    })?;
    let qa_out = host
        .invoke_provider_component_op_direct(
            domain,
            pack,
            provider_id,
            "qa-spec",
            &qa_payload,
            &ctx,
        )
        .map_err(|err| {
            diagnostic(
                QaDiagnosticCode::QaSpecFailed,
                format!("invoke qa-spec: {err}"),
            )
        })?;
    if !qa_out.success {
        let message = qa_out.error.unwrap_or_else(|| "unknown error".to_string());
        if is_missing_op(&message) {
            return Ok(None);
        }
        return Err(diagnostic(QaDiagnosticCode::QaSpecFailed, message));
    }
    let qa_json = qa_out.output.ok_or_else(|| {
        diagnostic(
            QaDiagnosticCode::QaSpecFailed,
            "missing qa-spec output payload".to_string(),
        )
    })?;
    let qa_spec: ComponentQaSpec = serde_json::from_value(qa_json).map_err(|err| {
        diagnostic(
            QaDiagnosticCode::QaSpecInvalid,
            format!("decode qa-spec payload: {err}"),
        )
    })?;

    let i18n_payload = serde_json::to_vec(&json!({})).map_err(|err| {
        diagnostic(
            QaDiagnosticCode::I18nExportMissing,
            format!("encode i18n-keys payload: {err}"),
        )
    })?;
    let i18n_out = host
        .invoke_provider_component_op_direct(
            domain,
            pack,
            provider_id,
            "i18n-keys",
            &i18n_payload,
            &ctx,
        )
        .map_err(|err| {
            diagnostic(
                QaDiagnosticCode::I18nExportMissing,
                format!("invoke i18n-keys: {err}"),
            )
        })?;
    if !i18n_out.success {
        let message = i18n_out
            .error
            .unwrap_or_else(|| "unknown error".to_string());
        return Err(diagnostic(QaDiagnosticCode::I18nExportMissing, message));
    }
    let i18n_json = i18n_out.output.ok_or_else(|| {
        diagnostic(
            QaDiagnosticCode::I18nExportMissing,
            "missing i18n-keys payload".to_string(),
        )
    })?;
    let known_keys: Vec<String> = serde_json::from_value(i18n_json).map_err(|err| {
        diagnostic(
            QaDiagnosticCode::I18nExportMissing,
            format!("i18n-keys payload is not a string array: {err}"),
        )
    })?;
    validate_i18n_contract(&qa_spec, &known_keys)?;

    let apply_payload = serde_json::to_vec(&json!({
        "mode": mode.as_str(),
        "current_config": current_config.cloned().unwrap_or_else(|| json!({})),
        "answers": answers,
    }))
    .map_err(|err| {
        diagnostic(
            QaDiagnosticCode::ApplyAnswersFailed,
            format!("encode apply-answers payload: {err}"),
        )
    })?;
    let apply_out = host
        .invoke_provider_component_op_direct(
            domain,
            pack,
            provider_id,
            "apply-answers",
            &apply_payload,
            &ctx,
        )
        .map_err(|err| {
            diagnostic(
                QaDiagnosticCode::ApplyAnswersFailed,
                format!("invoke apply-answers: {err}"),
            )
        })?;
    if !apply_out.success {
        let message = apply_out
            .error
            .unwrap_or_else(|| "unknown error".to_string());
        return Err(diagnostic(QaDiagnosticCode::ApplyAnswersFailed, message));
    }
    let apply_json = apply_out.output.ok_or_else(|| {
        diagnostic(
            QaDiagnosticCode::ApplyAnswersFailed,
            "missing apply-answers payload".to_string(),
        )
    })?;
    let config = extract_config_from_apply_output(apply_json);

    if let Some(schema) = read_pack_config_schema(&pack.path).map_err(|err| {
        diagnostic(
            QaDiagnosticCode::ConfigSchemaMismatch,
            format!("read config schema: {err}"),
        )
    })? && let Some(reason) = validate_config_strict(&config, &schema)
    {
        return Err(diagnostic(QaDiagnosticCode::ConfigSchemaMismatch, reason));
    }

    Ok(Some(config))
}

pub fn persist_answers_artifacts(
    providers_root: &Path,
    provider_id: &str,
    mode: QaMode,
    answers: &JsonValue,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    let answers_dir = providers_root.join(provider_id).join("answers");
    std::fs::create_dir_all(&answers_dir)?;
    let json_path = answers_dir.join(format!("{}.answers.json", mode.as_str()));
    let cbor_path = answers_dir.join(format!("{}.answers.cbor", mode.as_str()));
    let json_bytes = serde_json::to_vec_pretty(answers)?;
    let cbor_bytes =
        canonical::to_canonical_cbor(answers).map_err(|err| anyhow::anyhow!("{err}"))?;
    std::fs::write(&json_path, json_bytes)?;
    std::fs::write(&cbor_path, cbor_bytes)?;
    Ok((json_path, cbor_path))
}

fn validate_i18n_contract(
    qa_spec: &ComponentQaSpec,
    known_keys: &[String],
) -> Result<(), QaDiagnostic> {
    let known_key_set = known_keys
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let missing = qa_spec
        .i18n_keys()
        .into_iter()
        .filter(|key| !known_key_set.contains(key))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(diagnostic(
            QaDiagnosticCode::I18nKeyMissing,
            format!("unknown keys referenced by qa-spec: {}", missing.join(", ")),
        ));
    }
    Ok(())
}

fn extract_config_from_apply_output(apply_json: JsonValue) -> JsonValue {
    if let Some(value) = apply_json.get("config") {
        value.clone()
    } else {
        apply_json
    }
}

fn supports_component_qa_contract(pack_path: &Path) -> anyhow::Result<bool> {
    let bytes = match read_manifest_cbor_bytes(pack_path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false),
    };
    let decoded = match decode_pack_manifest(&bytes) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let Some(provider_ext) = decoded.provider_extension_inline() else {
        return Ok(false);
    };
    let supports = provider_ext.providers.iter().any(|provider| {
        provider.ops.iter().any(|op| op == "qa-spec")
            && provider.ops.iter().any(|op| op == "apply-answers")
            && provider.ops.iter().any(|op| op == "i18n-keys")
    });
    Ok(supports)
}

fn read_pack_config_schema(pack_path: &Path) -> anyhow::Result<Option<JsonValue>> {
    let bytes = read_manifest_cbor_bytes(pack_path)?;
    let decoded = decode_pack_manifest(&bytes)
        .with_context(|| format!("decode manifest.cbor {}", pack_path.display()))?;
    let schema = decoded
        .components
        .first()
        .and_then(|component| component.config_schema.clone());
    Ok(schema)
}

fn read_manifest_cbor_bytes(pack_path: &Path) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::File::open(pack_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut manifest = archive
        .by_name("manifest.cbor")
        .with_context(|| format!("manifest.cbor missing in {}", pack_path.display()))?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut manifest, &mut bytes)?;
    Ok(bytes)
}

fn validate_config_strict(config: &JsonValue, schema: &JsonValue) -> Option<String> {
    if schema.is_object()
        && let Err(err) = jsonschema::validate(schema, config)
    {
        return Some(err.to_string());
    }
    validate_config_shallow(config, schema)
}

fn validate_config_shallow(config: &JsonValue, schema: &JsonValue) -> Option<String> {
    let schema_obj = schema.as_object()?;

    if let Some(expected) = schema_obj.get("type").and_then(JsonValue::as_str)
        && !matches_json_type(config, expected)
    {
        return Some(format!(
            "config type mismatch: expected `{expected}`, got `{}`",
            json_type_name(config)
        ));
    }

    if let Some(required) = schema_obj.get("required").and_then(JsonValue::as_array)
        && let Some(map) = config.as_object()
    {
        for key in required.iter().filter_map(JsonValue::as_str) {
            if !map.contains_key(key) {
                return Some(format!("missing required config key `{key}`"));
            }
        }
    }

    if let (Some(properties), Some(map)) = (
        schema_obj.get("properties").and_then(JsonValue::as_object),
        config.as_object(),
    ) {
        for (key, value) in map {
            if let Some(prop_schema) = properties.get(key)
                && let Some(expected) = prop_schema.get("type").and_then(JsonValue::as_str)
                && !matches_json_type(value, expected)
            {
                return Some(format!(
                    "config key `{key}` type mismatch: expected `{expected}`, got `{}`",
                    json_type_name(value)
                ));
            }
        }
        if schema_obj
            .get("additionalProperties")
            .is_some_and(|value| value == &JsonValue::Bool(false))
        {
            for key in map.keys() {
                if !properties.contains_key(key) {
                    return Some(format!("unknown config key `{key}`"));
                }
            }
        }
    }

    None
}

fn matches_json_type(value: &JsonValue, expected: &str) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "number" => value.is_number(),
        "integer" => {
            value.as_i64().is_some()
                || value.as_u64().is_some()
                || value.as_f64().is_some_and(|number| number.fract() == 0.0)
        }
        "null" => value.is_null(),
        _ => true,
    }
}

fn json_type_name(value: &JsonValue) -> &'static str {
    if value.is_object() {
        "object"
    } else if value.is_array() {
        "array"
    } else if value.is_string() {
        "string"
    } else if value.is_boolean() {
        "boolean"
    } else if value.is_number() {
        "number"
    } else {
        "null"
    }
}

fn is_missing_op(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("not found") || lower.contains("opnotfound") || lower.contains("op not found")
}

fn diagnostic(code: QaDiagnosticCode, message: String) -> QaDiagnostic {
    QaDiagnostic { code, message }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_types::i18n_text::I18nText;
    use greentic_types::schemas::component::v0_6_0::{
        ComponentQaSpec, QaMode as SpecQaMode, Question, QuestionKind,
    };
    use std::collections::BTreeMap;

    #[test]
    fn shallow_schema_type_mismatch_is_reported() {
        let config = json!({"enabled":"yes"});
        let schema = json!({
            "type": "object",
            "properties": {
                "enabled": {"type":"boolean"}
            },
            "required": ["enabled"]
        });
        let message = validate_config_shallow(&config, &schema).unwrap();
        assert!(message.contains("enabled"));
        assert!(message.contains("boolean"));
    }

    #[test]
    fn strict_schema_reports_missing_required_property() {
        let config = json!({});
        let schema = json!({
            "type": "object",
            "properties": {
                "token": {"type":"string"}
            },
            "required": ["token"]
        });
        let message = validate_config_strict(&config, &schema).unwrap();
        assert!(message.to_ascii_lowercase().contains("token"));
    }

    #[test]
    fn shallow_schema_accepts_valid_object() {
        let config = json!({"enabled": true, "name": "demo"});
        let schema = json!({
            "type": "object",
            "properties": {
                "enabled": {"type":"boolean"},
                "name": {"type":"string"}
            },
            "required": ["enabled", "name"]
        });
        assert!(validate_config_shallow(&config, &schema).is_none());
    }

    #[test]
    fn missing_op_detection_matches_common_messages() {
        assert!(is_missing_op("op not found"));
        assert!(is_missing_op("OperatorErrorCode::OpNotFound"));
        assert!(!is_missing_op("invalid input"));
    }

    #[test]
    fn qa_mode_infers_from_flow_names() {
        assert_eq!(qa_mode_for_flow("setup_default"), Some(QaMode::Default));
        assert_eq!(qa_mode_for_flow("setup_upgrade"), Some(QaMode::Upgrade));
        assert_eq!(qa_mode_for_flow("setup_remove"), Some(QaMode::Remove));
        assert_eq!(qa_mode_for_flow("setup"), Some(QaMode::Setup));
        assert_eq!(qa_mode_for_flow("verify_webhooks"), None);
    }

    #[test]
    fn qa_contract_success_path_validates_i18n() {
        let qa_spec = sample_qa_spec();
        let known_keys = vec![
            "qa.title".to_string(),
            "qa.question.label".to_string(),
            "qa.question.help".to_string(),
            "qa.question.error".to_string(),
        ];
        assert!(validate_i18n_contract(&qa_spec, &known_keys).is_ok());
    }

    #[test]
    fn qa_contract_reports_missing_i18n_keys() {
        let qa_spec = sample_qa_spec();
        let known_keys = vec!["qa.title".to_string()];
        let err = validate_i18n_contract(&qa_spec, &known_keys).unwrap_err();
        assert_eq!(err.code, QaDiagnosticCode::I18nKeyMissing);
        assert!(err.message.contains("unknown keys"));
    }

    #[test]
    fn extract_apply_output_prefers_config_field() {
        let config = extract_config_from_apply_output(json!({"config": {"token":"x"}}));
        assert_eq!(config, json!({"token":"x"}));
    }

    fn sample_qa_spec() -> ComponentQaSpec {
        ComponentQaSpec {
            mode: SpecQaMode::Setup,
            title: I18nText {
                key: "qa.title".to_string(),
                fallback: None,
            },
            description: None,
            questions: vec![Question {
                id: "token".to_string(),
                label: I18nText {
                    key: "qa.question.label".to_string(),
                    fallback: None,
                },
                help: Some(I18nText {
                    key: "qa.question.help".to_string(),
                    fallback: None,
                }),
                error: Some(I18nText {
                    key: "qa.question.error".to_string(),
                    fallback: None,
                }),
                kind: QuestionKind::Text,
                required: true,
                default: None,
            }],
            defaults: BTreeMap::new(),
        }
    }
}
