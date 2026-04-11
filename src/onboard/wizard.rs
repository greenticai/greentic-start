use crate::component_qa_ops::{self, QaMode};
use hyper::StatusCode;
use serde_json::{Value, json};

use crate::demo_qa_bridge;
use crate::domains::{self, Domain, ProviderPack};
use crate::gmap;
use crate::operator_log;
use crate::provider_config_envelope;
use crate::qa_persist;
use crate::setup_to_formspec;

use qa_spec::{build_render_payload, render_json_ui};

use super::api::{OnboardResult, OnboardState, error_response, into_error, json_ok};
use super::webhook_setup;

// ── Request parsing (shared across all 3 endpoints) ─────────────────────────

struct RequestParams {
    provider_id: String,
    domain: Domain,
    tenant: String,
    team: Option<String>,
    answers: Value,
    locale: String,
    mode: QaMode,
}

impl RequestParams {
    fn tenant(&self) -> &str {
        &self.tenant
    }
    fn team(&self) -> Option<&str> {
        self.team.as_deref()
    }
}

fn parse_request(body: &Value) -> OnboardResult<RequestParams> {
    let provider_id = body["provider_id"]
        .as_str()
        .ok_or_else(|| {
            into_error(error_response(
                StatusCode::BAD_REQUEST,
                "missing provider_id",
            ))
        })?
        .to_string();
    let domain = parse_domain(body)?;
    let answers = body.get("answers").cloned().unwrap_or_else(|| json!({}));
    // Read tenant/team from top-level body, then fallback to _scope_* in answers
    let tenant = body["tenant"]
        .as_str()
        .or_else(|| answers.get("_scope_tenant").and_then(Value::as_str))
        .unwrap_or("default")
        .to_ascii_lowercase();
    let team = body["team"]
        .as_str()
        .or_else(|| answers.get("_scope_team").and_then(Value::as_str))
        .map(|s| s.to_ascii_lowercase());
    let locale = body["locale"].as_str().unwrap_or("en").to_string();
    let mode = parse_mode(body);

    Ok(RequestParams {
        provider_id,
        domain,
        tenant,
        team,
        answers,
        locale,
        mode,
    })
}

// ── FormSpec loading with WASM → setup.yaml fallback ────────────────────────

fn load_form_spec_with_fallback(
    bundle_root: &std::path::Path,
    domain: Domain,
    pack: &ProviderPack,
    params: &RequestParams,
) -> Option<qa_spec::FormSpec> {
    match get_form_spec_from_pack(
        bundle_root,
        domain,
        pack,
        &params.provider_id,
        params.tenant(),
        params.team(),
        &params.locale,
        params.mode,
    ) {
        Some(spec) => {
            operator_log::info(
                module_path!(),
                format!(
                    "[onboard] qa/spec path=wasm provider={} questions={}",
                    params.provider_id,
                    spec.questions.len()
                ),
            );
            Some(spec)
        }
        None => {
            operator_log::info(
                module_path!(),
                format!(
                    "[onboard] qa/spec path=fallback provider={} pack={}",
                    params.provider_id,
                    pack.path.display()
                ),
            );
            let mut spec = setup_to_formspec::pack_to_form_spec(&pack.path, &params.provider_id)?;
            apply_i18n_to_form_spec(
                &mut spec,
                bundle_root,
                &params.provider_id,
                &params.locale,
                params.mode.as_str(),
            );
            Some(spec)
        }
    }
}

// ── Provider alias injection (Telegram + Slack secret dedup) ────────────────

/// Static table of secret aliases per provider.
///
/// Each entry: `(setup.yaml field, WASM runtime key, is_secret)`.
/// The wizard saves config under setup.yaml field names, but the WASM component
/// reads secrets via its own constant (e.g. `SLACK_BOT_TOKEN` → `slack_bot_token`).
/// This table bridges that gap by copying the value to the runtime key name.
type ProviderSecretAlias = (&'static str, &'static str, bool);
type ProviderSecretAliasEntry = (&'static str, &'static [ProviderSecretAlias]);

const PROVIDER_SECRET_ALIASES: &[ProviderSecretAliasEntry] = &[
    (
        "messaging-telegram",
        &[("bot_token", "telegram_bot_token", true)],
    ),
    ("messaging-slack", &[("bot_token", "slack_bot_token", true)]),
    ("messaging-webex", &[("bot_token", "webex_bot_token", true)]),
    (
        "messaging-whatsapp",
        &[("access_token", "whatsapp_token", true)],
    ),
];

fn inject_provider_aliases(
    provider_id: &str,
    config: &mut Value,
    form_spec: &mut qa_spec::FormSpec,
    answers: &Value,
) {
    // Apply static alias table (setup.yaml field → WASM runtime key)
    if let Some(&(_, aliases)) = PROVIDER_SECRET_ALIASES
        .iter()
        .find(|&&(id, _)| id == provider_id)
    {
        for &(src_key, dst_key, is_secret) in aliases {
            if let Some(val) = config
                .get(src_key)
                .and_then(Value::as_str)
                .map(String::from)
                && !val.is_empty()
            {
                if let Some(map) = config.as_object_mut() {
                    map.entry(dst_key.to_string())
                        .or_insert_with(|| Value::String(val));
                }
                push_synthetic_question(form_spec, dst_key, is_secret);
            }
        }
    }

    // Slack-specific: forward extra fields from answers
    if provider_id == "messaging-slack" {
        for (key, is_secret) in [("slack_app_id", false), ("slack_configuration_token", true)] {
            if let Some(val) = answers.get(key).and_then(Value::as_str).map(String::from)
                && !val.is_empty()
            {
                if let Some(map) = config.as_object_mut() {
                    map.entry(key.to_string())
                        .or_insert_with(|| Value::String(val));
                }
                push_synthetic_question(form_spec, key, is_secret);
            }
        }
    }
}

fn push_synthetic_question(form_spec: &mut qa_spec::FormSpec, key: &str, secret: bool) {
    if form_spec.questions.iter().any(|q| q.id == key) {
        return;
    }
    form_spec.questions.push(qa_spec::QuestionSpec {
        id: key.to_string(),
        kind: qa_spec::QuestionType::String,
        title: key.to_string(),
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
    });
}

// ── Provider flow invocation (dedup setup_default + verify_webhooks) ────────

fn run_provider_flow(
    state: &OnboardState,
    domain: Domain,
    provider_id: &str,
    flow_name: &str,
    payload_bytes: &[u8],
    ctx: &crate::runner_host::OperatorContext,
) -> Value {
    operator_log::info(
        module_path!(),
        format!("[onboard] running {} flow for {}", flow_name, provider_id),
    );

    match state
        .runner_host
        .invoke_provider_op(domain, provider_id, flow_name, payload_bytes, ctx)
    {
        Ok(outcome) => {
            operator_log::info(
                module_path!(),
                format!(
                    "[onboard] {} flow complete provider={} success={} error={:?}",
                    flow_name, provider_id, outcome.success, outcome.error
                ),
            );
            json!({
                "flow": flow_name,
                "success": outcome.success,
                "error": outcome.error,
                "output": outcome.output,
            })
        }
        Err(err) => {
            operator_log::error(
                module_path!(),
                format!(
                    "[onboard] {} flow failed for {}: {err}",
                    flow_name, provider_id
                ),
            );
            json!({
                "flow": flow_name,
                "success": false,
                "error": err.to_string(),
            })
        }
    }
}

fn applicable_verify_flows(domain: Domain, pack: &ProviderPack) -> Vec<String> {
    domains::config(domain)
        .verify_flows
        .iter()
        .filter(|flow| pack.entry_flows.iter().any(|entry| entry == **flow))
        .map(|flow| (*flow).to_string())
        .collect()
}

// ── Public URL meta injection ───────────────────────────────────────────────

fn inject_public_url_meta(
    response: &mut Value,
    bundle_root: &std::path::Path,
    tenant: &str,
    team: Option<&str>,
) {
    if let Some(url) = read_runtime_public_url(bundle_root, tenant, team) {
        response["meta"] = json!({ "public_url": url });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API handlers
// ═══════════════════════════════════════════════════════════════════════════

/// POST /api/onboard/qa/spec
///
/// Returns the FormSpec JSON UI for a provider.
///
/// Request body: `{ "provider_id": "messaging-telegram", "domain": "messaging",
///                  "tenant": "default", "team": null, "mode": "setup",
///                  "answers": {} }`
pub fn get_form_spec(state: &OnboardState, body: &Value) -> OnboardResult {
    let params = parse_request(body)?;
    let bundle_root = state.runner_host.bundle_root();
    let pack = find_provider_pack(bundle_root, params.domain, &params.provider_id)?;

    let form_spec = load_form_spec_with_fallback(bundle_root, params.domain, &pack, &params)
        .ok_or_else(|| {
            into_error(error_response(
                StatusCode::NOT_FOUND,
                format!("no qa-spec or setup.yaml found in {}", pack.file_name),
            ))
        })?;

    // For upgrade mode: pre-fill answers with existing config values
    let answers = if params.mode == QaMode::Upgrade {
        merge_existing_config(bundle_root, &params.provider_id, &params.answers)
    } else {
        params.answers.clone()
    };

    let ctx = json!({ "tenant": params.tenant(), "team": params.team() });
    let payload = build_render_payload(&form_spec, &ctx, &answers);
    let rendered = render_json_ui(&payload);

    operator_log::info(
        module_path!(),
        format!(
            "[onboard] qa/spec provider={} status={}",
            params.provider_id,
            payload.status.as_str()
        ),
    );

    let mut response = rendered;
    inject_public_url_meta(&mut response, bundle_root, params.tenant(), params.team());

    json_ok(response)
}

/// POST /api/onboard/qa/validate
///
/// Validates partial answers and returns updated progress.
///
/// Request body: `{ "provider_id": "messaging-telegram", "domain": "messaging",
///                  "tenant": "default", "answers": { ... } }`
pub fn validate_answers(state: &OnboardState, body: &Value) -> OnboardResult {
    let params = parse_request(body)?;
    let bundle_root = state.runner_host.bundle_root();
    let pack = find_provider_pack(bundle_root, params.domain, &params.provider_id)?;

    let form_spec = load_form_spec_with_fallback(bundle_root, params.domain, &pack, &params)
        .ok_or_else(|| {
            into_error(error_response(
                StatusCode::NOT_FOUND,
                format!("no qa-spec found for {}", params.provider_id),
            ))
        })?;

    let ctx = json!({ "tenant": params.tenant(), "team": params.team() });
    let payload = build_render_payload(&form_spec, &ctx, &params.answers);
    let rendered = render_json_ui(&payload);

    let mut response = rendered;
    inject_public_url_meta(&mut response, bundle_root, params.tenant(), params.team());

    json_ok(response)
}

/// POST /api/onboard/qa/submit
///
/// Submits answers, persists secrets + config, and updates gmap.
///
/// Request body: `{ "provider_id": "messaging-telegram", "domain": "messaging",
///                  "tenant": "default", "team": null, "answers": { ... } }`
pub fn submit_answers(state: &OnboardState, body: &Value) -> OnboardResult {
    let params = parse_request(body)?;
    let bundle_root = state.runner_host.bundle_root();
    let pack = find_provider_pack(bundle_root, params.domain, &params.provider_id)?;

    operator_log::info(
        module_path!(),
        format!(
            "[onboard] qa/submit provider={} tenant={} team={:?}",
            params.provider_id,
            params.tenant(),
            params.team()
        ),
    );

    // 1. Run apply-answers via component QA
    let current_config = if params.mode == QaMode::Upgrade || params.mode == QaMode::Remove {
        provider_config_envelope::read_provider_config_envelope(
            &bundle_root.join(".providers"),
            &params.provider_id,
        )
        .ok()
        .flatten()
        .map(|envelope| envelope.config)
    } else {
        None
    };
    let config = component_qa_ops::apply_answers_via_component_qa(
        bundle_root,
        params.domain,
        params.tenant(),
        params.team(),
        &pack,
        &params.provider_id,
        params.mode,
        current_config.as_ref(),
        &params.answers,
    )
    .map_err(|err| {
        operator_log::error(
            module_path!(),
            format!("[onboard] apply-answers failed: {err}"),
        );
        into_error(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("apply-answers failed: {err}"),
        ))
    })?;

    let mut config = match config {
        Some(config) => config,
        None => params.answers.clone(),
    };

    // Re-inject UI-level fields that WASM may have stripped
    if let Some(map) = config.as_object_mut() {
        if let Some(label) = params.answers.get("instance_label").and_then(Value::as_str)
            && !label.is_empty()
        {
            map.insert(
                "instance_label".to_string(),
                Value::String(label.to_string()),
            );
        }
        map.insert(
            "_scope_tenant".to_string(),
            Value::String(params.tenant().to_string()),
        );
        if let Some(t) = params.team() {
            map.insert("_scope_team".to_string(), Value::String(t.to_string()));
        }
    }

    // 2. Get FormSpec (for secret field identification — locale not needed here)
    let mut form_spec = match get_form_spec_from_pack(
        bundle_root,
        params.domain,
        &pack,
        &params.provider_id,
        params.tenant(),
        params.team(),
        "en",
        params.mode,
    ) {
        Some(spec) => spec,
        None => setup_to_formspec::pack_to_form_spec(&pack.path, &params.provider_id)
            .unwrap_or_else(|| make_minimal_form_spec(&params.provider_id, &config)),
    };

    // 3. Inject secret aliases into config + FormSpec (single batch to avoid DEK cache bug)
    inject_provider_aliases(
        &params.provider_id,
        &mut config,
        &mut form_spec,
        &params.answers,
    );

    // Persist secrets + config (single DevStore instance writes all secrets in one batch)
    let providers_root = bundle_root.join(".providers");
    let rt = tokio::runtime::Runtime::new().expect("persist runtime");
    let persist_result = rt
        .block_on(qa_persist::persist_qa_results(
            bundle_root,
            &providers_root,
            params.tenant(),
            params.team(),
            &params.provider_id,
            &config,
            &pack.path,
            &form_spec,
            true,
        ))
        .map_err(|err| {
            operator_log::error(module_path!(), format!("[onboard] persist failed: {err}"));
            into_error(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("persist failed: {err}"),
            ))
        })?;
    let (secrets_saved, config_written) = persist_result;

    // 4. Update gmap policy
    let gmap_path = resolve_gmap_path(bundle_root, params.tenant(), params.team());
    let rule_path = params.provider_id.to_string();
    if let Err(err) = gmap::upsert_policy(&gmap_path, &rule_path, gmap::Policy::Public) {
        operator_log::error(
            module_path!(),
            format!("[onboard] gmap upsert failed: {err}"),
        );
        return Err(into_error(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("gmap update failed: {err}"),
        )));
    }

    if params.mode == QaMode::Remove {
        let provider_dir = bundle_root.join(".providers").join(&params.provider_id);
        if provider_dir.exists() {
            let _ = std::fs::remove_dir_all(&provider_dir);
        }
        if let Err(err) = gmap::upsert_policy(&gmap_path, &rule_path, gmap::Policy::Forbidden) {
            operator_log::error(
                module_path!(),
                format!("[onboard] gmap revoke failed: {err}"),
            );
        }
    }

    // 5. Run setup flows from pack (skip for remove mode)
    let mut setup_flow_result: Option<Value> = None;
    let mut verify_flow_results: Vec<Value> = Vec::new();
    let webhook_result;

    // Inject runtime-detected public URL into config if not already set
    let runtime_url = read_runtime_public_url(bundle_root, params.tenant(), params.team());
    if let Some(ref url) = runtime_url
        && let Some(map) = config.as_object_mut()
    {
        map.entry("public_base_url".to_string())
            .or_insert_with(|| Value::String(url.clone()));
    }

    if params.mode != QaMode::Remove {
        let has_setup_flow = pack.entry_flows.iter().any(|f| f == "setup_default");

        if has_setup_flow {
            let public_base_url = config.get("public_base_url").and_then(Value::as_str);
            let flow_input = build_setup_flow_input(
                &params.provider_id,
                params.tenant(),
                params.team(),
                public_base_url,
                &config,
            );
            let payload_bytes = serde_json::to_vec(&flow_input).unwrap_or_default();

            let ctx = crate::runner_host::OperatorContext {
                tenant: params.tenant().to_string(),
                team: params.team().map(|t| t.to_string()),
                correlation_id: None,
            };

            setup_flow_result = Some(run_provider_flow(
                state,
                params.domain,
                &params.provider_id,
                "setup_default",
                &payload_bytes,
                &ctx,
            ));

            for verify_flow in applicable_verify_flows(params.domain, &pack) {
                verify_flow_results.push(run_provider_flow(
                    state,
                    params.domain,
                    &params.provider_id,
                    &verify_flow,
                    &payload_bytes,
                    &ctx,
                ));
            }

            webhook_result = setup_flow_result
                .as_ref()
                .and_then(|result| result.get("output"))
                .and_then(|output| webhook_setup::webhook_result_from_flow_output(Some(output)));
        } else {
            webhook_result = None;
        }
    } else {
        webhook_result = None;
    }

    if let Some(ref result) = webhook_result {
        operator_log::info(
            module_path!(),
            format!(
                "[onboard] setup_webhook provider={} result={}",
                params.provider_id, result
            ),
        );
    }

    operator_log::info(
        module_path!(),
        format!(
            "[onboard] qa/submit complete provider={} secrets={} config={}",
            params.provider_id,
            secrets_saved.len(),
            config_written
        ),
    );

    json_ok(json!({
        "status": "ok",
        "provider_id": params.provider_id,
        "mode": params.mode.as_str(),
        "secrets_saved": secrets_saved,
        "config_written": config_written,
        "gmap_updated": true,
        "webhook_setup": webhook_result,
        "setup_flow": setup_flow_result,
        "verify_flow": verify_flow_results.first().cloned(),
        "verify_flows": verify_flow_results,
    }))
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal helpers (unchanged logic, just reorganized)
// ═══════════════════════════════════════════════════════════════════════════

/// Try to get a FormSpec from the WASM qa-spec op.
#[allow(clippy::too_many_arguments)]
fn get_form_spec_from_pack(
    bundle_root: &std::path::Path,
    domain: Domain,
    pack: &ProviderPack,
    provider_id: &str,
    tenant: &str,
    team: Option<&str>,
    locale: &str,
    mode: QaMode,
) -> Option<qa_spec::FormSpec> {
    use super::provider_i18n;
    use crate::discovery::{self, DiscoveryOptions};
    use crate::runner_host::{DemoRunnerHost, OperatorContext};
    use crate::secrets_gate;

    let cbor_only = bundle_root.join("greentic.demo.yaml").exists();
    let discovery =
        discovery::discover_with_options(bundle_root, DiscoveryOptions { cbor_only }).ok()?;
    let secrets_handle = secrets_gate::resolve_secrets_manager(bundle_root, tenant, team).ok()?;
    let host = DemoRunnerHost::new(
        bundle_root.to_path_buf(),
        &discovery,
        None,
        secrets_handle,
        false,
        0,
    )
    .ok()?;

    let ctx = OperatorContext {
        tenant: tenant.to_string(),
        team: team.map(|t| t.to_string()),
        correlation_id: None,
    };

    let qa_payload = serde_json::to_vec(&json!({"mode": mode.as_str()})).ok()?;
    let qa_out = match host.invoke_provider_component_op_direct(
        domain,
        pack,
        provider_id,
        "qa-spec",
        &qa_payload,
        &ctx,
    ) {
        Ok(out) => out,
        Err(err) => {
            operator_log::info(
                module_path!(),
                format!(
                    "[onboard] qa-spec invoke failed for {}: {}",
                    provider_id, err
                ),
            );
            return None;
        }
    };

    if !qa_out.success {
        operator_log::info(
            module_path!(),
            format!(
                "[onboard] qa-spec not successful for {}: {:?}",
                provider_id, qa_out.error
            ),
        );
        return None;
    }
    let qa_json = match qa_out.output {
        Some(json) => json,
        None => {
            operator_log::info(
                module_path!(),
                format!("[onboard] qa-spec output is None for {}", provider_id),
            );
            return None;
        }
    };

    let wasm_english: std::collections::BTreeMap<String, String> =
        fetch_i18n_bundle(&host, domain, pack, provider_id, &ctx)
            .into_iter()
            .collect();

    let i18n_dir = provider_i18n::resolve_i18n_dir(bundle_root);
    operator_log::info(
        module_path!(),
        format!(
            "[onboard] i18n: bundle_root={} locale={} dir={:?} wasm_keys={}",
            bundle_root.display(),
            locale,
            i18n_dir,
            wasm_english.len(),
        ),
    );
    let merged = provider_i18n::load_and_merge(&wasm_english, locale, i18n_dir.as_deref());
    operator_log::info(
        module_path!(),
        format!("[onboard] i18n: merged_keys={}", merged.len()),
    );

    let i18n_map: std::collections::HashMap<String, String> = merged.into_iter().collect();
    let form_spec = demo_qa_bridge::provider_qa_to_form_spec(&qa_json, &i18n_map, provider_id);

    Some(form_spec)
}

fn fetch_i18n_bundle(
    host: &crate::runner_host::DemoRunnerHost,
    domain: Domain,
    pack: &ProviderPack,
    provider_id: &str,
    ctx: &crate::runner_host::OperatorContext,
) -> std::collections::HashMap<String, String> {
    let locale_payload = serde_json::to_vec(&json!("en")).unwrap_or_default();
    let bundle_out = match host.invoke_provider_component_op_direct(
        domain,
        pack,
        provider_id,
        "i18n-bundle",
        &locale_payload,
        ctx,
    ) {
        Ok(out) if out.success => out,
        Ok(out) => {
            operator_log::info(
                module_path!(),
                format!(
                    "[onboard] i18n-bundle failed for {}: {:?}",
                    provider_id, out.error
                ),
            );
            return std::collections::HashMap::new();
        }
        Err(err) => {
            operator_log::info(
                module_path!(),
                format!("[onboard] i18n-bundle error for {}: {}", provider_id, err),
            );
            return std::collections::HashMap::new();
        }
    };

    let Some(bundle_json) = bundle_out.output else {
        return std::collections::HashMap::new();
    };

    bundle_json
        .get("messages")
        .and_then(Value::as_object)
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn make_minimal_form_spec(provider_id: &str, config: &Value) -> qa_spec::FormSpec {
    use qa_spec::{FormSpec, QuestionSpec};

    let questions = config
        .as_object()
        .map(|map| {
            map.keys()
                .map(|key| {
                    let (kind, secret, _) = setup_to_formspec::infer_question_properties(key);
                    QuestionSpec {
                        id: key.clone(),
                        kind,
                        title: key.clone(),
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
                })
                .collect()
        })
        .unwrap_or_default();

    FormSpec {
        id: format!("{provider_id}-setup"),
        title: format!("{provider_id} setup"),
        version: "1.0.0".to_string(),
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

fn apply_i18n_to_form_spec(
    form_spec: &mut qa_spec::FormSpec,
    bundle_root: &std::path::Path,
    provider_id: &str,
    locale: &str,
    mode: &str,
) {
    use super::provider_i18n;

    let i18n_dir = provider_i18n::resolve_i18n_dir(bundle_root);
    let empty = std::collections::BTreeMap::new();
    let i18n = provider_i18n::load_and_merge(&empty, locale, i18n_dir.as_deref());

    if i18n.is_empty() {
        return;
    }

    let prefix = provider_id
        .strip_prefix("messaging-")
        .or_else(|| provider_id.strip_prefix("events-"))
        .unwrap_or(provider_id);

    let title_key = format!("{prefix}.qa.{mode}.title");
    if let Some(title) = i18n.get(&title_key) {
        form_spec.title = title.clone();
    }

    for q in &mut form_spec.questions {
        let q_title_key = format!("{prefix}.qa.{mode}.{}", q.id);
        if let Some(title) = i18n.get(&q_title_key) {
            q.title = title.clone();
        }

        let desc_key = format!("{prefix}.schema.config.{}.description", q.id);
        if let Some(desc) = i18n.get(&desc_key) {
            q.description = Some(desc.clone());
        }
    }

    operator_log::info(
        module_path!(),
        format!(
            "[onboard] i18n fallback: provider={} locale={} keys={}",
            provider_id,
            locale,
            i18n.len()
        ),
    );
}

fn find_provider_pack(
    bundle_root: &std::path::Path,
    domain: Domain,
    provider_id: &str,
) -> OnboardResult<ProviderPack> {
    let packs = domains::discover_provider_packs(bundle_root, domain).map_err(|err| {
        into_error(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("discover packs: {err}"),
        ))
    })?;

    packs
        .into_iter()
        .find(|pack| {
            pack.pack_id == provider_id
                || pack
                    .file_name
                    .strip_suffix(".gtpack")
                    .unwrap_or(&pack.file_name)
                    == provider_id
        })
        .ok_or_else(|| {
            into_error(error_response(
                StatusCode::NOT_FOUND,
                format!("provider pack not found: {provider_id}"),
            ))
        })
}

fn parse_domain(body: &Value) -> OnboardResult<Domain> {
    let domain_str = body["domain"].as_str().unwrap_or("messaging");
    match domain_str {
        "messaging" => Ok(Domain::Messaging),
        "events" => Ok(Domain::Events),
        "secrets" => Ok(Domain::Secrets),
        _ => Err(into_error(error_response(
            StatusCode::BAD_REQUEST,
            format!("unknown domain: {domain_str}"),
        ))),
    }
}

fn parse_mode(body: &Value) -> QaMode {
    match body["mode"].as_str().unwrap_or("setup") {
        "upgrade" => QaMode::Upgrade,
        "remove" => QaMode::Remove,
        "default" => QaMode::Default,
        _ => QaMode::Setup,
    }
}

fn merge_existing_config(
    bundle_root: &std::path::Path,
    provider_id: &str,
    answers: &Value,
) -> Value {
    let providers_root = bundle_root.join(".providers");
    let existing =
        match provider_config_envelope::read_provider_config_envelope(&providers_root, provider_id)
        {
            Ok(Some(envelope)) => envelope.config,
            _ => return answers.clone(),
        };

    let Some(existing_map) = existing.as_object() else {
        return answers.clone();
    };

    let answers_map = answers.as_object().cloned().unwrap_or_default();

    let mut merged = existing_map.clone();
    for (key, value) in &answers_map {
        merged.insert(key.clone(), value.clone());
    }

    Value::Object(merged)
}

fn read_runtime_public_url(
    bundle_root: &std::path::Path,
    _tenant: &str,
    _team: Option<&str>,
) -> Option<String> {
    let runtime_dir = bundle_root.join("state").join("runtime");
    let entries = std::fs::read_dir(&runtime_dir).ok()?;

    let mut best: Option<(std::time::SystemTime, String)> = None;

    for entry in entries.flatten() {
        let url_path = entry.path().join("public_base_url.txt");
        let Ok(meta) = std::fs::metadata(&url_path) else {
            continue;
        };
        let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        let Ok(contents) = std::fs::read_to_string(&url_path) else {
            continue;
        };
        let trimmed = contents.trim();
        let url = if trimmed.starts_with("https://") {
            trimmed.to_string()
        } else if let Some(parsed) = crate::ngrok::parse_public_url(&contents) {
            parsed
        } else {
            continue;
        };

        if best.as_ref().is_none_or(|(t, _)| modified > *t) {
            best = Some((modified, url));
        }
    }

    best.map(|(_, url)| url)
}

fn build_setup_flow_input(
    pack_id: &str,
    tenant: &str,
    team: Option<&str>,
    public_base_url: Option<&str>,
    config: &Value,
) -> Value {
    let team_str = team.unwrap_or("_");
    let mut payload = json!({
        "id": pack_id,
        "tenant": tenant,
        "team": team_str,
        "env": "dev",
    });
    let mut cfg = config.clone();
    if let Some(url) = public_base_url {
        payload["public_base_url"] = Value::String(url.to_string());
        if let Some(map) = cfg.as_object_mut() {
            map.entry("public_base_url".to_string())
                .or_insert_with(|| Value::String(url.to_string()));
        }
    }
    if let Some(map) = cfg.as_object_mut() {
        map.entry("id".to_string())
            .or_insert_with(|| Value::String(pack_id.to_string()));
    }
    payload["config"] = cfg;
    payload["msg"] = json!({
        "channel": "setup",
        "id": format!("{pack_id}.setup"),
        "message": {
            "id": format!("{pack_id}.setup_default__collect"),
            "text": "Collect inputs for setup_default."
        },
        "metadata": {},
        "reply_scope": "",
        "session_id": "setup",
        "tenant_id": tenant,
        "text": "Collect inputs for setup_default.",
        "user_id": "operator"
    });
    payload["payload"] = json!({
        "id": format!("{pack_id}-setup_default"),
        "spec_ref": "assets/setup.yaml"
    });
    payload["setup_answers"] = config.clone();
    if let Ok(answers_str) = serde_json::to_string(config) {
        payload["answers_json"] = Value::String(answers_str);
    }
    payload
}

fn resolve_gmap_path(
    bundle_root: &std::path::Path,
    tenant: &str,
    team: Option<&str>,
) -> std::path::PathBuf {
    match team {
        Some(team) if team != "_" => bundle_root
            .join("tenants")
            .join(tenant)
            .join("teams")
            .join(team)
            .join("team.gmap"),
        _ => bundle_root.join("tenants").join(tenant).join("tenant.gmap"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_config_envelope;
    use qa_spec::QuestionType;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::tempdir;
    use zip::write::FileOptions;

    fn pack_with_flows(flows: &[&str]) -> ProviderPack {
        ProviderPack {
            pack_id: "fixture-pack".to_string(),
            display_name: None,
            description: None,
            tags: Vec::new(),
            file_name: "fixture.gtpack".to_string(),
            path: PathBuf::from("/tmp/fixture.gtpack"),
            entry_flows: flows.iter().map(|value| (*value).to_string()).collect(),
        }
    }

    #[test]
    fn applicable_verify_flows_uses_domain_verify_flows_for_messaging() {
        let pack = pack_with_flows(&["setup_default", "verify_webhooks", "verify_subscriptions"]);
        let flows = applicable_verify_flows(Domain::Messaging, &pack);
        assert_eq!(flows, vec!["verify_webhooks".to_string()]);
    }

    #[test]
    fn applicable_verify_flows_uses_domain_verify_flows_for_events() {
        let pack = pack_with_flows(&["setup_default", "verify_webhooks", "verify_subscriptions"]);
        let flows = applicable_verify_flows(Domain::Events, &pack);
        assert_eq!(flows, vec!["verify_subscriptions".to_string()]);
    }

    #[test]
    fn parse_request_uses_scope_fallbacks_and_normalizes_case() {
        let params = parse_request(&json!({
            "provider_id": "messaging-slack",
            "domain": "messaging",
            "answers": {
                "_scope_tenant": "Demo",
                "_scope_team": "Blue"
            },
            "locale": "nl"
        }))
        .expect("request params");

        assert_eq!(params.provider_id, "messaging-slack");
        assert_eq!(params.domain, Domain::Messaging);
        assert_eq!(params.tenant, "demo");
        assert_eq!(params.team.as_deref(), Some("blue"));
        assert_eq!(params.locale, "nl");
        assert_eq!(params.mode, QaMode::Setup);
    }

    #[test]
    fn parse_request_rejects_missing_provider_and_invalid_domain() {
        assert!(parse_request(&json!({"domain": "messaging"})).is_err());
        assert!(
            parse_request(&json!({
                "provider_id": "messaging-slack",
                "domain": "invalid"
            }))
            .is_err()
        );
    }

    #[test]
    fn inject_provider_aliases_adds_runtime_secret_aliases_once() {
        let mut config = json!({
            "bot_token": "secret-value"
        });
        let mut form_spec = make_minimal_form_spec("messaging-slack", &config);
        let original_question_count = form_spec.questions.len();

        inject_provider_aliases(
            "messaging-slack",
            &mut config,
            &mut form_spec,
            &json!({
                "bot_token": "secret-value",
                "slack_app_id": "A123",
                "slack_configuration_token": "cfg-secret"
            }),
        );
        inject_provider_aliases(
            "messaging-slack",
            &mut config,
            &mut form_spec,
            &json!({
                "bot_token": "secret-value",
                "slack_app_id": "A123",
                "slack_configuration_token": "cfg-secret"
            }),
        );

        assert_eq!(config["slack_bot_token"], "secret-value");
        assert_eq!(config["slack_app_id"], "A123");
        assert_eq!(config["slack_configuration_token"], "cfg-secret");
        assert!(
            form_spec
                .questions
                .iter()
                .any(|q| q.id == "slack_bot_token" && q.secret)
        );
        assert!(
            form_spec
                .questions
                .iter()
                .any(|q| q.id == "slack_configuration_token" && q.secret)
        );
        assert!(
            form_spec
                .questions
                .iter()
                .any(|q| q.id == "slack_app_id" && !q.secret)
        );
        assert!(form_spec.questions.len() >= original_question_count + 3);
    }

    #[test]
    fn push_synthetic_question_deduplicates_existing_entries() {
        let mut form_spec = make_minimal_form_spec("provider-a", &json!({"token": "x"}));
        let initial = form_spec.questions.len();
        push_synthetic_question(&mut form_spec, "token", true);
        push_synthetic_question(&mut form_spec, "token", true);
        assert_eq!(form_spec.questions.len(), initial);
    }

    #[test]
    fn helper_functions_cover_mode_gmap_and_setup_input_shapes() {
        assert_eq!(parse_mode(&json!({})), QaMode::Setup);
        assert_eq!(parse_mode(&json!({"mode": "upgrade"})), QaMode::Upgrade);
        assert_eq!(parse_mode(&json!({"mode": "remove"})), QaMode::Remove);

        let spec = make_minimal_form_spec(
            "provider-a",
            &json!({
                "secret_token": "s3cr3t",
                "enabled": true
            }),
        );
        assert_eq!(spec.id, "provider-a-setup");
        assert!(
            spec.questions
                .iter()
                .any(|q| q.id == "secret_token" && q.secret && q.kind == QuestionType::String)
        );
        assert!(
            spec.questions
                .iter()
                .any(|q| q.id == "enabled" && !q.secret)
        );

        let gmap = resolve_gmap_path(std::path::Path::new("/bundle"), "tenant-a", Some("team-b"));
        assert_eq!(
            gmap,
            std::path::Path::new("/bundle/tenants/tenant-a/teams/team-b/team.gmap")
        );

        let payload = build_setup_flow_input(
            "provider-a",
            "tenant-a",
            Some("team-b"),
            Some("https://demo.example"),
            &json!({"alpha": 1}),
        );
        assert_eq!(payload["payload"]["id"], "provider-a-setup_default");
        assert_eq!(payload["msg"]["id"], "provider-a.setup");
        assert_eq!(payload["tenant"], "tenant-a");
        assert_eq!(payload["team"], "team-b");
        assert_eq!(payload["public_base_url"], "https://demo.example");
        assert_eq!(payload["config"]["alpha"], 1);
    }

    #[test]
    fn merge_existing_config_overlays_answers_on_saved_envelope() {
        let dir = tempdir().unwrap();
        let providers_root = dir.path().join(".providers");
        let pack_path = dir.path().join("provider.gtpack");
        std::fs::write(&pack_path, b"not-a-zip-but-good-enough").unwrap();

        provider_config_envelope::write_provider_config_envelope(
            &providers_root,
            "messaging-slack",
            "setup_default",
            &json!({
                "bot_token": "stored-token",
                "workspace": "stored-workspace"
            }),
            &pack_path,
            false,
        )
        .unwrap();

        let merged = merge_existing_config(
            dir.path(),
            "messaging-slack",
            &json!({
                "workspace": "fresh-workspace",
                "channel": "alerts"
            }),
        );

        assert_eq!(merged["bot_token"], "stored-token");
        assert_eq!(merged["workspace"], "fresh-workspace");
        assert_eq!(merged["channel"], "alerts");
    }

    #[test]
    fn apply_i18n_and_runtime_url_helpers_populate_response_metadata() {
        let dir = tempdir().unwrap();
        let i18n_dir = dir.path().join("i18n").join("providers");
        std::fs::create_dir_all(&i18n_dir).unwrap();
        std::fs::write(
            i18n_dir.join("en.json"),
            serde_json::to_vec(&json!({
                "slack.qa.setup.title": "Slack setup",
                "slack.qa.setup.bot_token": "Bot token",
                "slack.schema.config.bot_token.description": "Needed for webhook calls"
            }))
            .unwrap(),
        )
        .unwrap();

        let runtime_a = dir.path().join("state").join("runtime").join("a");
        let runtime_b = dir.path().join("state").join("runtime").join("b");
        std::fs::create_dir_all(&runtime_a).unwrap();
        std::fs::create_dir_all(&runtime_b).unwrap();
        std::fs::write(
            runtime_a.join("public_base_url.txt"),
            "https://older.example",
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(
            runtime_b.join("public_base_url.txt"),
            "time=2025-01-01T00:00:00Z level=info msg=tunnel url=https://newer.example",
        )
        .unwrap();

        let mut form_spec = make_minimal_form_spec("messaging-slack", &json!({"bot_token": ""}));
        apply_i18n_to_form_spec(&mut form_spec, dir.path(), "messaging-slack", "en", "setup");
        assert_eq!(form_spec.title, "Slack setup");
        assert_eq!(form_spec.questions[0].title, "Bot token");
        assert_eq!(
            form_spec.questions[0].description.as_deref(),
            Some("Needed for webhook calls")
        );

        assert_eq!(
            read_runtime_public_url(dir.path(), "demo", Some("default")).as_deref(),
            Some("https://newer.example")
        );

        let mut response = json!({});
        inject_public_url_meta(&mut response, dir.path(), "demo", Some("default"));
        assert_eq!(response["meta"]["public_url"], "https://newer.example");
    }

    #[test]
    fn load_form_spec_with_fallback_uses_setup_yaml_when_component_qa_is_unavailable() {
        let dir = tempdir().unwrap();
        let i18n_dir = dir.path().join("i18n").join("providers");
        std::fs::create_dir_all(&i18n_dir).unwrap();
        std::fs::write(
            i18n_dir.join("en.json"),
            serde_json::to_vec(&json!({
                "telegram.qa.setup.title": "Localized Telegram setup",
                "telegram.qa.setup.bot_token": "Localized Bot Token"
            }))
            .unwrap(),
        )
        .unwrap();

        let pack_path = dir.path().join("messaging-telegram.gtpack");
        let file = std::fs::File::create(&pack_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("assets/setup.yaml", FileOptions::<()>::default())
            .unwrap();
        zip.write_all(
            br#"
title: Telegram Setup
questions:
  - name: bot_token
    kind: string
    required: true
"#,
        )
        .unwrap();
        zip.finish().unwrap();

        let pack = ProviderPack {
            pack_id: "messaging-telegram".to_string(),
            display_name: None,
            description: None,
            tags: Vec::new(),
            file_name: "messaging-telegram.gtpack".to_string(),
            path: pack_path,
            entry_flows: vec![],
        };
        let params = RequestParams {
            provider_id: "messaging-telegram".to_string(),
            domain: Domain::Messaging,
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            answers: json!({}),
            locale: "en".to_string(),
            mode: QaMode::Setup,
        };

        let spec = load_form_spec_with_fallback(dir.path(), Domain::Messaging, &pack, &params)
            .expect("fallback form spec");
        assert_eq!(spec.title, "Localized Telegram setup");
        assert!(spec.questions.iter().any(|q| q.id == "bot_token"));
        assert!(
            spec.questions
                .iter()
                .any(|q| q.title == "Localized Bot Token")
        );
    }

    #[test]
    fn parse_domain_defaults_to_messaging_and_accepts_known_domains() {
        assert_eq!(parse_domain(&json!({})).unwrap(), Domain::Messaging);
        assert_eq!(
            parse_domain(&json!({"domain": "events"})).unwrap(),
            Domain::Events
        );
        assert_eq!(
            parse_domain(&json!({"domain": "secrets"})).unwrap(),
            Domain::Secrets
        );
    }

    #[test]
    fn build_setup_flow_input_uses_default_team_and_injects_pack_id_without_public_url() {
        let payload =
            build_setup_flow_input("provider-a", "tenant-a", None, None, &json!({"alpha": 1}));

        assert_eq!(payload["team"], "_");
        assert_eq!(payload["config"]["id"], "provider-a");
        assert!(payload.get("public_base_url").is_none());
        assert_eq!(payload["setup_answers"]["alpha"], 1);
    }
}
