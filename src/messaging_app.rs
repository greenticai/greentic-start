use std::{
    collections::BTreeMap,
    collections::BTreeSet,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use greentic_types::ChannelMessageEnvelope;
use greentic_types::messaging::extensions::ext_keys;
use serde_cbor::Value as CborValue;
use serde_json::{Value as JsonValue, json};
use zip::ZipArchive;

use crate::operator_log;
use crate::runner_exec::{self, RunRequest};
use crate::runner_host::OperatorContext;

#[derive(Clone, Debug)]
pub struct AppPackInfo {
    pub pack_id: String,
    pub flows: Vec<AppFlowInfo>,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct AppFlowInfo {
    pub id: String,
    pub kind: String,
}

pub fn resolve_app_pack_path(
    bundle: &Path,
    tenant: &str,
    team: Option<&str>,
    override_path: Option<&str>,
) -> Result<PathBuf> {
    if let Some(override_value) = override_path {
        let candidate = PathBuf::from(override_value);
        if candidate.exists() {
            return Ok(candidate);
        }
        bail!("APP_PACK_NOT_FOUND override path {override_value} does not exist");
    }

    let packs_root = bundle.join("packs");
    let mut tried = Vec::new();

    // 1. Try app_packs from bundle.yaml (highest priority)
    if let Some(pack_path) = resolve_from_bundle_yaml(bundle, &packs_root) {
        return Ok(pack_path);
    }

    // 2. Try tenant/team-scoped default.gtpack
    if let Some(team_id) = team {
        let candidate = packs_root.join(tenant).join(team_id).join("default.gtpack");
        tried.push(candidate.clone());
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    let candidate = packs_root.join(tenant).join("default.gtpack");
    tried.push(candidate.clone());
    if candidate.exists() {
        return Ok(candidate);
    }

    // 3. Fallback to packs/default.gtpack
    let candidate = packs_root.join("default.gtpack");
    tried.push(candidate.clone());
    if candidate.exists() {
        return Ok(candidate);
    }

    let paths = tried
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    bail!("APP_PACK_NOT_FOUND; tried {paths}");
}

/// Read bundle.yaml app_packs and try to find a matching .gtpack in the packs directory.
/// Handles both local references (packs/name.pack) and HTTPS URLs (extracts filename).
fn resolve_from_bundle_yaml(bundle: &Path, packs_root: &Path) -> Option<PathBuf> {
    let yaml_path = bundle.join("bundle.yaml");
    if let Ok(content) = std::fs::read_to_string(&yaml_path) {
        let mut in_app_packs = false;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed == "app_packs:" {
                in_app_packs = true;
                continue;
            }
            if in_app_packs {
                if !trimmed.starts_with("- ") {
                    break;
                }
                let reference = trimmed.trim_start_matches("- ").trim();

                // Extract the pack name from the reference (local path or HTTPS URL)
                let pack_name =
                    if reference.starts_with("http://") || reference.starts_with("https://") {
                        // URL like https://.../hr-onboarding.gtpack → "hr-onboarding"
                        reference
                            .rsplit('/')
                            .next()
                            .unwrap_or(reference)
                            .trim_end_matches(".gtpack")
                    } else {
                        // Local path like packs/hr-onboarding.pack → "hr-onboarding"
                        reference
                            .rsplit('/')
                            .next()
                            .unwrap_or(reference)
                            .trim_end_matches(".pack")
                            .trim_end_matches(".gtpack")
                    };

                // Try: packs/<name>.gtpack
                let candidate = packs_root.join(format!("{pack_name}.gtpack"));
                if candidate.exists() {
                    return Some(candidate);
                }

                // Try: packs/<name>.pack/dist/<name>.pack.gtpack
                let pack_dir = packs_root.join(format!("{pack_name}.pack"));
                if pack_dir.is_dir()
                    && let Ok(entries) = std::fs::read_dir(pack_dir.join("dist"))
                {
                    for entry in entries.flatten() {
                        if entry.path().extension().is_some_and(|ext| ext == "gtpack") {
                            return Some(entry.path());
                        }
                    }
                }

                // Try as direct file reference
                let candidate = packs_root.join(reference);
                if candidate.exists() && candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }

    // Fallback: find any non-default .gtpack in packs/
    if let Ok(entries) = std::fs::read_dir(packs_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "gtpack")
                && path.file_stem().is_some_and(|name| name != "default")
            {
                return Some(path);
            }
        }
    }
    None
}

pub fn load_app_pack_info(pack_path: &Path) -> Result<AppPackInfo> {
    let file = File::open(pack_path).with_context(|| format!("unable to open {pack_path:?}"))?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest = archive
        .by_name("manifest.cbor")
        .with_context(|| format!("pack {pack_path:?} missing manifest.cbor"))?;
    let mut buf = Vec::new();
    manifest.read_to_end(&mut buf)?;
    let value: CborValue = serde_cbor::from_slice(&buf)?;
    let pack_id = extract_text_or_symbol(&value, "pack_id", "pack_ids")
        .ok_or_else(|| anyhow::anyhow!("pack manifest missing pack id in {pack_path:?}"))?;
    let flows = extract_flows(&value);
    let capabilities = extract_capabilities(&value);
    Ok(AppPackInfo {
        pack_id,
        flows,
        capabilities,
    })
}

pub fn select_app_flow(info: &AppPackInfo) -> Result<&AppFlowInfo> {
    if let Some(flow) = info.flows.iter().find(|flow| flow.id == "default") {
        return Ok(flow);
    }
    let messaging_flows: Vec<_> = info
        .flows
        .iter()
        .filter(|flow| flow.kind.eq_ignore_ascii_case("messaging"))
        .collect();
    if messaging_flows.len() == 1 {
        return Ok(messaging_flows[0]);
    }
    bail!("{}", app_flow_resolution_error(info));
}

pub fn app_flow_resolution_error(info: &AppPackInfo) -> String {
    let messaging_count = info
        .flows
        .iter()
        .filter(|flow| flow.kind.eq_ignore_ascii_case("messaging"))
        .count();
    let available = if info.flows.is_empty() {
        "<none>".to_string()
    } else {
        info.flows
            .iter()
            .map(|flow| format!("{} (kind={})", flow.id, flow.kind))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "APP_FLOW_NOT_RESOLVED: greentic-start cannot choose which flow to invoke for app pack `{}`. \
Expected either a flow with id `default`, or exactly one flow with kind `messaging`. \
Found {} flow(s), {} messaging flow(s): {}. \
Fix the pack manifest by marking one flow as id `default`, or by making exactly one flow kind `messaging`.",
        info.pack_id,
        info.flows.len(),
        messaging_count,
        available
    )
}

pub fn run_app_flow(
    bundle: &Path,
    ctx: &OperatorContext,
    pack_path: &Path,
    pack_id: &str,
    flow_id: &str,
    envelope: &ChannelMessageEnvelope,
) -> Result<Vec<ChannelMessageEnvelope>> {
    let mut envelope_for_flow = envelope.clone();
    inject_pack_setup_answers(bundle, pack_id, &mut envelope_for_flow.metadata);

    let request = RunRequest {
        root: bundle.to_path_buf(),
        domain: crate::domains::Domain::Messaging,
        pack_path: pack_path.to_path_buf(),
        pack_label: pack_id.to_string(),
        flow_id: flow_id.to_string(),
        tenant: ctx.tenant.clone(),
        team: ctx.team.clone(),
        input: json!({
            "input": &envelope_for_flow,
            "tenant": ctx.tenant,
            "team": ctx.team,
            "correlation_id": ctx.correlation_id,
        }),
        dist_offline: true,
    };

    let output = runner_exec::run_provider_pack_flow(request)?;
    let target_node = envelope_for_flow
        .metadata
        .get("routeToCardId")
        .or_else(|| envelope_for_flow.metadata.get("toCardId"))
        .or_else(|| envelope_for_flow.metadata.get("nextCardId"));
    operator_log::info(
        module_path!(),
        format!(
            "[messaging_app] run_app_flow completed run_dir={} target_node={} status={:?} failures={}",
            output.run_dir.display(),
            target_node.map(String::as_str).unwrap_or("<none>"),
            output.result.status,
            output.result.failures.len(),
        ),
    );

    // Flow-failure short-circuit: when a node failed, the transcript.jsonl
    // contains only the last *successful* node's output (since failed nodes
    // never write a transcript entry). Reading transcript here would return
    // a stale envelope from an earlier node (e.g. the menu card), causing
    // the chat to "loop" instead of surfacing the error. Build a metadata-only
    // value from result.failures so parse_envelopes routes through the
    // flow_error categorization branch instead.
    //
    // Skip the synthetic `_runtime` failure that the desktop runner injects
    // when a Waiting status (e.g. "awaiting user submit at node ...") is
    // converted into an Err. That isn't a real failure: the flow rendered
    // the welcome card and is paused for the next inbound activity. Reading
    // transcript in that case correctly returns the welcome card.
    let real_failure = output
        .result
        .failures
        .iter()
        .find(|(node_id, _)| node_id.as_str() != "_runtime");
    if !matches!(
        output.result.status,
        greentic_runner_desktop::RunStatus::Success
    ) && let Some((failed_node_id, failure)) = real_failure
    {
        let error_value = json!({
            "metadata": {
                "error_kind": "flow_node_failed",
                "error_message": failure.message,
                "node_id": failed_node_id,
            }
        });
        return parse_envelopes(&error_value, envelope);
    }

    let mut value = collect_transcript_outputs_with_retry(
        &output.run_dir,
        target_node.map(|s| s.as_str()),
        envelope,
    )?
    .ok_or_else(|| anyhow::anyhow!("app flow produced no outputs"))?;
    // OAuth bake-in: the adapter's Connect card carries a `scheme|provider` state;
    // mint a signed state token (host knows pack/tenant/team) so /oauth/callback
    // can resolve pack-scoped creds + persist the token.
    augment_oauth_connect_state(
        &mut value,
        pack_id,
        &ctx.tenant,
        ctx.team.as_deref().unwrap_or("default"),
    );
    parse_envelopes(&value, envelope)
}

/// Replace the adapter's `state=scheme|provider` in a Connect card's authorize URL
/// with a host-signed `crate::oauth_state` token carrying the full context.
///
/// `renderedCard` can be nested anywhere in the node output, so we walk the whole
/// value and rewrite the `state` of any `oauth/authorize` URL we find.
fn augment_oauth_connect_state(value: &mut JsonValue, pack_id: &str, tenant: &str, team: &str) {
    match value {
        JsonValue::Object(map) => {
            if let Some(url) = map.get("url").and_then(|u| u.as_str()).map(String::from)
                && let Some(new_url) = sign_authorize_url_state(&url, pack_id, tenant, team)
            {
                map.insert("url".to_string(), JsonValue::String(new_url));
            }
            for (_, v) in map.iter_mut() {
                augment_oauth_connect_state(v, pack_id, tenant, team);
            }
        }
        JsonValue::Array(arr) => {
            for v in arr.iter_mut() {
                augment_oauth_connect_state(v, pack_id, tenant, team);
            }
        }
        _ => {}
    }
}

/// If `url` is an OAuth `authorize` URL carrying a `state=scheme|provider`, return
/// the same URL with `state` replaced by a signed `crate::oauth_state` token; else
/// `None`.
fn sign_authorize_url_state(url: &str, pack_id: &str, tenant: &str, team: &str) -> Option<String> {
    // Trigger on the adapter's raw `state=<scheme>|<provider>` marker rather than a
    // provider-specific authorize path: GitHub uses `.../oauth/authorize` but Google
    // uses `.../oauth2/v2/auth`, so a path check skips Google entirely (no signed
    // state, no PKCE, no redirect_uri). The `scheme|provider` split below is the real
    // gate — only the adapter's OAuth card emits it, and an already-signed JWT state
    // (no `|`) returns None here, so we never double-augment.
    let raw_state = url_query_value(url, "state")?;
    let (scheme, provider) = raw_state.split_once('|')?;
    if scheme.is_empty() || provider.is_empty() {
        return None;
    }
    let jti = uuid::Uuid::new_v4().to_string();
    let signed = crate::oauth_state::mint(&crate::oauth_state::OAuthStateContext {
        pack: pack_id.to_string(),
        scheme: scheme.to_string(),
        provider: provider.to_string(),
        tenant: tenant.to_string(),
        team: team.to_string(),
        subject: "user".to_string(),
        jti: jti.clone(),
        // Threaded from the messaging ingress in a follow-up so /oauth/callback can
        // push a resume into the originating webchat conversation (auto-advance).
        conv: None,
        exp: chrono::Utc::now().timestamp() + 600,
    });
    let mut new_url = replace_query_value(url, "state", &signed);
    // Layer on the provider profile: PKCE challenge (verifier stashed server-side,
    // keyed by jti) + provider-specific authorize params (e.g. Google offline).
    if let Some(profile) = crate::oauth_engine::provider_profile(provider) {
        if profile.uses_pkce {
            let pkce = crate::oauth_engine::pkce();
            crate::oauth_engine::store_verifier(&jti, &pkce.verifier);
            new_url.push_str(&format!(
                "&code_challenge={}&code_challenge_method=S256",
                crate::oauth_engine::enc(&pkce.challenge)
            ));
        }
        for (k, v) in profile.authorize_extra {
            new_url.push_str(&format!(
                "&{}={}",
                crate::oauth_engine::enc(k),
                crate::oauth_engine::enc(v)
            ));
        }
        if profile.redirect_uri_required {
            new_url.push_str(&format!(
                "&redirect_uri={}",
                crate::oauth_engine::enc(&crate::oauth_engine::callback_redirect_uri(provider))
            ));
        }
    }
    Some(new_url)
}

/// Minimal `%XX`/`+` decode for a query value.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(v) => {
                    out.push(v);
                    i += 3;
                }
                Err(_) => {
                    out.push(b[i]);
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn url_query_value(url: &str, key: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    q.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| pct_decode(v))
    })
}

/// Replace `key=<old>` with `key=<new>` (new is URL-safe; written verbatim).
fn replace_query_value(url: &str, key: &str, new: &str) -> String {
    let Some((base, q)) = url.split_once('?') else {
        return url.to_string();
    };
    let rebuilt: Vec<String> = q
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((k, _)) if k == key => format!("{key}={new}"),
            _ => pair.to_string(),
        })
        .collect();
    format!("{base}?{}", rebuilt.join("&"))
}

/// Merge top-level keys from `<bundle>/state/config/<pack_id>/setup-answers.json`
/// into `metadata` so flow templates can reference pack-level config (LLM url,
/// model, api_key_secret, etc.) via `entry.input.metadata.*`. Existing keys
/// from the inbound envelope take precedence — user-supplied form data is
/// never overwritten by pack defaults.
fn inject_pack_setup_answers(
    bundle: &Path,
    pack_id: &str,
    metadata: &mut BTreeMap<String, String>,
) {
    let path = bundle
        .join("state")
        .join("config")
        .join(pack_id)
        .join("setup-answers.json");
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    let Ok(JsonValue::Object(answers)) = serde_json::from_slice::<JsonValue>(&bytes) else {
        return;
    };
    let mut injected: Vec<&str> = Vec::new();
    for (key, value) in &answers {
        if metadata.contains_key(key) {
            continue;
        }
        let coerced = match value {
            JsonValue::String(text) => text.clone(),
            JsonValue::Bool(flag) => flag.to_string(),
            JsonValue::Number(num) => num.to_string(),
            JsonValue::Null => continue,
            JsonValue::Array(_) | JsonValue::Object(_) => match serde_json::to_string(value) {
                Ok(s) => s,
                Err(_) => continue,
            },
        };
        metadata.insert(key.clone(), coerced);
        injected.push(key.as_str());
    }
    if !injected.is_empty() {
        operator_log::info(
            module_path!(),
            format!(
                "[messaging_app] injected pack setup-answers pack_id={pack_id} keys=[{}]",
                injected.join(",")
            ),
        );
    }
}

fn extract_text_or_symbol(value: &CborValue, key: &str, symbol_table: &str) -> Option<String> {
    let map = match value {
        CborValue::Map(map) => map,
        _ => return None,
    };
    let cbor_key = CborValue::Text(key.to_string());
    match map.get(&cbor_key)? {
        CborValue::Text(text) => Some(text.clone()),
        CborValue::Integer(idx) => {
            let idx = *idx as usize;
            let symbols_key = CborValue::Text("symbols".to_string());
            let table_key = CborValue::Text(symbol_table.to_string());
            let symbols = map.get(&symbols_key)?;
            if let CborValue::Map(sym_map) = symbols
                && let Some(CborValue::Array(entries)) = sym_map.get(&table_key)
                && let Some(CborValue::Text(resolved)) = entries.get(idx)
            {
                return Some(resolved.clone());
            }
            None
        }
        _ => None,
    }
}

fn extract_flows(value: &CborValue) -> Vec<AppFlowInfo> {
    let mut flows = Vec::new();
    if let CborValue::Map(map) = value {
        let flows_key = CborValue::Text("flows".to_string());
        if let Some(CborValue::Array(entries)) = map.get(&flows_key) {
            for entry in entries {
                if let Some(flow) = parse_flow_entry(entry) {
                    flows.push(flow);
                }
            }
        }
    }
    flows
}

/// Reads the pack manifest's `capabilities: Vec<ComponentCapability>` and
/// returns each entry's `name`. The canonical encoder symbol-indexes the
/// name as a `u32` into `symbols.capability_names`, so we resolve through
/// that table when the inline value is an integer; an inline text name is
/// also accepted for non-canonical encodings.
fn extract_capabilities(value: &CborValue) -> Vec<String> {
    let mut caps = Vec::new();
    let CborValue::Map(map) = value else {
        return caps;
    };
    let entries = match map.get(&CborValue::Text("capabilities".to_string())) {
        Some(CborValue::Array(entries)) => entries,
        _ => return caps,
    };
    let cap_names_table = symbol_table_array(map, "capability_names");
    for entry in entries {
        if let CborValue::Map(entry_map) = entry
            && let Some(name) = resolve_capability_name(entry_map, cap_names_table)
        {
            caps.push(name);
        }
    }
    caps
}

fn resolve_capability_name(
    entry_map: &BTreeMap<CborValue, CborValue>,
    cap_names_table: Option<&Vec<CborValue>>,
) -> Option<String> {
    match entry_map.get(&CborValue::Text("name".to_string()))? {
        CborValue::Text(text) => Some(text.clone()),
        CborValue::Integer(idx) => match cap_names_table?.get(*idx as usize)? {
            CborValue::Text(resolved) => Some(resolved.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn symbol_table_array<'a>(
    manifest_map: &'a BTreeMap<CborValue, CborValue>,
    table: &str,
) -> Option<&'a Vec<CborValue>> {
    let symbols = manifest_map.get(&CborValue::Text("symbols".to_string()))?;
    let CborValue::Map(sym_map) = symbols else {
        return None;
    };
    match sym_map.get(&CborValue::Text(table.to_string())) {
        Some(CborValue::Array(arr)) => Some(arr),
        _ => None,
    }
}

fn parse_flow_entry(value: &CborValue) -> Option<AppFlowInfo> {
    let map = match value {
        CborValue::Map(map) => map,
        _ => return None,
    };
    let id = extract_text_from_map(map, "id")?;
    let kind = if let Some(flow_map) =
        map.get(&CborValue::Text("flow".to_string()))
            .and_then(|v| match v {
                CborValue::Map(flow_map) => Some(flow_map),
                _ => None,
            }) {
        extract_text_from_map(flow_map, "kind")
    } else {
        extract_text_from_map(map, "kind")
    };
    Some(AppFlowInfo {
        id,
        kind: kind.unwrap_or_else(|| "messaging".to_string()),
    })
}

fn extract_text_from_map(map: &BTreeMap<CborValue, CborValue>, key: &str) -> Option<String> {
    map.get(&CborValue::Text(key.to_string()))
        .and_then(|value| match value {
            CborValue::Text(text) => Some(text.clone()),
            _ => None,
        })
}

const TRANSCRIPT_OUTPUT_RETRIES: usize = 6;
const TRANSCRIPT_OUTPUT_RETRY_DELAY: Duration = Duration::from_millis(40);

fn collect_transcript_outputs_with_retry(
    run_dir: &Path,
    target_node_id: Option<&str>,
    ingress_envelope: &ChannelMessageEnvelope,
) -> Result<Option<JsonValue>> {
    let mut fallback = None;
    for attempt in 0..TRANSCRIPT_OUTPUT_RETRIES {
        if let Some(value) = collect_transcript_outputs(run_dir, target_node_id)? {
            let envelope_like = looks_like_envelope_output(&value);
            operator_log::info(
                module_path!(),
                format!(
                    "[messaging_app] transcript attempt={}/{} target_node={} envelope_like={} shape={}",
                    attempt + 1,
                    TRANSCRIPT_OUTPUT_RETRIES,
                    target_node_id.unwrap_or("<none>"),
                    envelope_like,
                    summarize_output_shape(&value)
                ),
            );
            if envelope_like {
                return Ok(Some(value));
            }
            fallback = Some(value);
        } else {
            operator_log::debug(
                module_path!(),
                format!(
                    "[messaging_app] transcript attempt={}/{} target_node={} no_output",
                    attempt + 1,
                    TRANSCRIPT_OUTPUT_RETRIES,
                    target_node_id.unwrap_or("<none>")
                ),
            );
        }

        if attempt + 1 < TRANSCRIPT_OUTPUT_RETRIES {
            std::thread::sleep(TRANSCRIPT_OUTPUT_RETRY_DELAY);
        }
    }

    if let Some(value) = fallback.as_ref()
        && parse_envelopes(value, ingress_envelope).is_ok()
    {
        operator_log::warn(
            module_path!(),
            format!(
                "[messaging_app] transcript retry exhausted; using parseable non-envelope output shape={}",
                summarize_output_shape(value)
            ),
        );
        return Ok(fallback);
    }
    if let Some(value) = fallback.as_ref() {
        operator_log::warn(
            module_path!(),
            format!(
                "[messaging_app] transcript retry exhausted; fallback not parseable shape={}",
                summarize_output_shape(value)
            ),
        );
    } else {
        operator_log::warn(
            module_path!(),
            "[messaging_app] transcript retry exhausted; no outputs found",
        );
    }
    Ok(fallback)
}

fn collect_transcript_outputs(
    run_dir: &Path,
    target_node_id: Option<&str>,
) -> Result<Option<JsonValue>> {
    let path = run_dir.join("transcript.jsonl");
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(path)?;
    let mut first = None;
    let mut preferred = None;
    let mut last = None;
    let mut targeted = None;
    for line in contents.lines() {
        if let Ok(value) = serde_json::from_str::<JsonValue>(line)
            && let Some(outputs) = value.get("outputs")
            && !outputs.is_null()
        {
            if first.is_none() {
                first = Some(outputs.clone());
            }
            if looks_like_envelope_output(outputs) {
                preferred = Some(outputs.clone());
            }
            last = Some(outputs.clone());
            if let Some(target) = target_node_id
                && let Some(node_id) = value.get("node_id").and_then(|n| n.as_str())
                && node_id == target
            {
                targeted = Some(outputs.clone());
            }
        }
    }
    let selected = if target_node_id.is_some() {
        // Preserve historical routing behavior when the caller asked for a specific node:
        // prefer explicit target match, then the latest output.
        targeted.or(last.clone()).or(preferred).or(first)
    } else {
        // Non-targeted flows: prefer an envelope-compatible output (e.g. the
        // rendered welcome card) over a trailing non-envelope record. autoStart
        // can run downstream nodes whose outputs are diagnostic objects like
        // `{error: AC_BINDING_EVAL_ERROR}` — those would otherwise displace the
        // envelope-shaped reply the user actually needs to see.
        targeted.or(preferred).or(last.clone()).or(first)
    };
    Ok(selected)
}

fn looks_like_envelope_output(value: &JsonValue) -> bool {
    value.is_array()
        || value.get("events").and_then(|v| v.as_array()).is_some()
        || value
            .get("messages")
            .and_then(|v| v.as_array())
            .is_some_and(|messages| !messages.is_empty())
        || value.get("message").is_some()
        || value.get("renderedCard").is_some_and(|v| !v.is_null())
        || value
            .get("payload")
            .and_then(|p| p.get("text"))
            .and_then(JsonValue::as_str)
            .is_some()
        || value.get("text").and_then(JsonValue::as_str).is_some()
        || value.as_str().is_some()
}

fn summarize_output_shape(value: &JsonValue) -> String {
    let kind = if value.is_object() {
        "object"
    } else if value.is_array() {
        "array"
    } else if value.is_string() {
        "string"
    } else if value.is_number() {
        "number"
    } else if value.is_boolean() {
        "bool"
    } else if value.is_null() {
        "null"
    } else {
        "unknown"
    };

    let keys = value
        .as_object()
        .map(|obj| {
            let mut keys = obj.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            keys.into_iter().take(8).collect::<Vec<_>>().join(",")
        })
        .unwrap_or_default();

    let messages_len = value
        .get("messages")
        .and_then(|m| m.as_array())
        .map(|m| m.len())
        .unwrap_or(0);
    let events_len = value
        .get("events")
        .and_then(|e| e.as_array())
        .map(|e| e.len())
        .unwrap_or(0);
    let has_rendered_card = value.get("renderedCard").is_some_and(|v| !v.is_null());
    let has_message = value.get("message").is_some();
    let has_payload_text = value
        .get("payload")
        .and_then(|p| p.get("text"))
        .and_then(JsonValue::as_str)
        .is_some();
    let has_text = value.get("text").and_then(JsonValue::as_str).is_some();
    let has_result_content = value
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(JsonValue::as_array)
        .is_some();
    let has_structured = value
        .get("result")
        .and_then(|r| r.get("structured_content"))
        .is_some();

    format!(
        "kind={kind} keys=[{keys}] has_renderedCard={} has_message={} messages_len={} events_len={} has_payload_text={} has_text={} has_result_content={} has_structured_content={}",
        has_rendered_card,
        has_message,
        messages_len,
        events_len,
        has_payload_text,
        has_text,
        has_result_content,
        has_structured
    )
}

/// Forward DirectLine / Bot Framework passthrough fields from the component
/// output JSON into `envelope.extensions` so TierA providers (WebChat, Teams)
/// can render them natively.
///
/// Each extension key is written at most once — existing values are preserved
/// so that earlier pipeline stages (e.g. the `renderedCard` branch) remain
/// authoritative when they have already populated a key.
///
/// Additionally, if the component emitted `attachments[]` with an adaptive
/// card entry (`contentType == "application/vnd.microsoft.card.adaptive"`),
/// its `content` is lifted into `extensions[ADAPTIVE_CARD]` so the render
/// planner can classify the reply as TierA.
fn copy_directline_passthrough(output: &JsonValue, envelope: &mut ChannelMessageEnvelope) {
    // (ext_key, [json_aliases])
    const PASSTHROUGH: &[(&str, &[&str])] = &[
        (ext_keys::ATTACHMENTS, &["attachments"]),
        (ext_keys::CHANNEL_DATA, &["channelData", "channel_data"]),
        (ext_keys::ENTITIES, &["entities"]),
        (
            ext_keys::SUGGESTED_ACTIONS,
            &["suggestedActions", "suggested_actions"],
        ),
        (ext_keys::SPEAK, &["speak"]),
        (ext_keys::INPUT_HINT, &["inputHint", "input_hint"]),
        (ext_keys::RAG, &["rag"]),
    ];

    for (ext_key, aliases) in PASSTHROUGH {
        if envelope.extensions.contains_key(*ext_key) {
            continue;
        }
        for alias in *aliases {
            if let Some(value) = output.get(*alias)
                && !value.is_null()
            {
                envelope
                    .extensions
                    .insert(ext_key.to_string(), value.clone());
                break;
            }
        }
    }

    // Lift an inline adaptive card from attachments[] into
    // extensions[ADAPTIVE_CARD] only when the attachments array itself is NOT
    // being forwarded (i.e. the card lives inline without a DirectLine-shape
    // wrapper). When `extensions[ATTACHMENTS]` is already set, the provider's
    // send-payload path reads the card from there and lifting would cause the
    // card to surface twice on the outbound DirectLine activity.
    if !envelope.extensions.contains_key(ext_keys::ADAPTIVE_CARD)
        && !envelope.extensions.contains_key(ext_keys::ATTACHMENTS)
        && let Some(attachments) = output.get("attachments").and_then(JsonValue::as_array)
    {
        for attachment in attachments {
            let is_adaptive_card = attachment
                .get("contentType")
                .and_then(JsonValue::as_str)
                .is_some_and(|ct| ct == "application/vnd.microsoft.card.adaptive");
            if is_adaptive_card
                && let Some(content) = attachment.get("content")
                && !content.is_null()
            {
                envelope
                    .extensions
                    .insert(ext_keys::ADAPTIVE_CARD.to_string(), content.clone());
                break;
            }
        }
    }
}

fn parse_envelopes(
    value: &JsonValue,
    ingress_envelope: &ChannelMessageEnvelope,
) -> Result<Vec<ChannelMessageEnvelope>> {
    if let Some(message_type) = value.get("type").and_then(JsonValue::as_str) {
        if message_type == "adaptive_card"
            && let Some(card) = value.get("card").filter(|card| !card.is_null())
        {
            let mut reply = ingress_envelope.clone();
            reply.text = None;
            if let Ok(ac_json) = serde_json::to_string(card) {
                reply.metadata.insert("adaptive_card".to_string(), ac_json);
            }
            reply
                .extensions
                .insert(ext_keys::ADAPTIVE_CARD.to_string(), card.clone());
            copy_directline_passthrough(value, &mut reply);
            operator_log::info(
                module_path!(),
                format!(
                    "[messaging_app] parse_envelopes path=typed_adaptive_card shape={}",
                    summarize_output_shape(value)
                ),
            );
            return Ok(vec![reply]);
        }

        if message_type == "text"
            && let Some(text) = value.get("text").and_then(JsonValue::as_str)
        {
            let mut reply = ingress_envelope.clone();
            reply.text = Some(text.to_string());
            copy_directline_passthrough(value, &mut reply);
            operator_log::info(
                module_path!(),
                format!(
                    "[messaging_app] parse_envelopes path=typed_text text_len={} shape={}",
                    text.len(),
                    summarize_output_shape(value)
                ),
            );
            return Ok(vec![reply]);
        }
    }

    if let Some(v) = value.as_array() {
        operator_log::info(
            module_path!(),
            format!(
                "[messaging_app] parse_envelopes path=array len={} shape={}",
                v.len(),
                summarize_output_shape(value)
            ),
        );
        return parse_envelope_array(v, ingress_envelope);
    }
    if let Some(messages) = value.get("messages").and_then(|v| v.as_array()) {
        operator_log::info(
            module_path!(),
            format!(
                "[messaging_app] parse_envelopes path=messages len={} shape={}",
                messages.len(),
                summarize_output_shape(value)
            ),
        );
        return parse_envelope_array(messages, ingress_envelope);
    }
    if let Some(events) = value.get("events").and_then(|v| v.as_array()) {
        operator_log::info(
            module_path!(),
            format!(
                "[messaging_app] parse_envelopes path=events len={} shape={}",
                events.len(),
                summarize_output_shape(value)
            ),
        );
        return parse_envelope_array(events, ingress_envelope);
    }
    if let Some(envelope) = value.get("message") {
        operator_log::info(
            module_path!(),
            format!(
                "[messaging_app] parse_envelopes path=message shape={}",
                summarize_output_shape(value)
            ),
        );
        let mut envelope: ChannelMessageEnvelope = serde_json::from_value(envelope.clone())
            .context("app flow message payload is not a ChannelMessageEnvelope")?;
        preserve_ingress_reply_route(&mut envelope, ingress_envelope);
        return Ok(vec![envelope]);
    }
    if let Some(rendered_card) = value.get("renderedCard")
        && !rendered_card.is_null()
    {
        let mut reply = base_reply_envelope(ingress_envelope);
        // Don't set text when adaptive card is present — the card renders
        // natively on TierA channels (Teams, WebChat) and the redundant text
        // bubble is distracting.  TierD providers already get a downsampled
        // text summary via the render_plan pipeline.
        reply.text = None;
        if let Ok(ac_json) = serde_json::to_string(rendered_card) {
            reply.metadata.insert("adaptive_card".to_string(), ac_json);
        }
        // Expose the adaptive card via extensions so consumers on the new
        // extensions-based pipeline can read it without parsing metadata.
        reply
            .extensions
            .insert(ext_keys::ADAPTIVE_CARD.to_string(), rendered_card.clone());
        copy_directline_passthrough(value, &mut reply);
        operator_log::info(
            module_path!(),
            format!(
                "[messaging_app] parse_envelopes path=renderedCard title={} shape={}",
                reply.text.as_deref().unwrap_or("Adaptive Card"),
                summarize_output_shape(value)
            ),
        );
        return Ok(vec![reply]);
    }
    let messages_text = value
        .get("messages")
        .and_then(|messages| messages.as_array())
        .and_then(|messages| {
            messages
                .iter()
                .find_map(|entry| entry.get("text").and_then(JsonValue::as_str))
        });
    let result_content_text = value
        .get("result")
        .and_then(|result| result.get("content"))
        .and_then(JsonValue::as_array)
        .and_then(|content| {
            content
                .iter()
                .find_map(|entry| entry.get("text").and_then(JsonValue::as_str))
        });
    let structured_text = value
        .get("result")
        .and_then(|result| result.get("structured_content"))
        .map(|structured| structured.to_string())
        .filter(|text| !text.is_empty());
    let payload_text = value
        .get("payload")
        .and_then(|p| p.get("text"))
        .and_then(JsonValue::as_str);

    if let Some(text) = messages_text
        .or(result_content_text)
        .or(structured_text.as_deref())
        .or(payload_text)
        .or_else(|| value.get("text").and_then(JsonValue::as_str))
        .or_else(|| value.as_str())
    {
        let mut reply = base_reply_envelope(ingress_envelope);
        reply.text = Some(text.to_string());
        copy_directline_passthrough(value, &mut reply);
        operator_log::info(
            module_path!(),
            format!(
                "[messaging_app] parse_envelopes path=text_fallback text_len={} shape={}",
                text.len(),
                summarize_output_shape(value)
            ),
        );
        return Ok(vec![reply]);
    }

    // Attachments/channelData/entities-only payloads have no text to classify
    // against but still carry TierA-renderable native DirectLine fields. Build
    // an empty-text reply and forward the passthrough so the webchat provider
    // receives the attachments instead of silently dropping them.
    let has_directline_only = value.get("attachments").is_some()
        || value.get("channelData").is_some()
        || value.get("channel_data").is_some()
        || value.get("entities").is_some();
    if has_directline_only {
        let mut reply = base_reply_envelope(ingress_envelope);
        reply.text = None;
        copy_directline_passthrough(value, &mut reply);
        operator_log::info(
            module_path!(),
            format!(
                "[messaging_app] parse_envelopes path=directline_passthrough shape={}",
                summarize_output_shape(value)
            ),
        );
        return Ok(vec![reply]);
    }
    // Last-resort: runner lifts node failures onto metadata.error_kind/error_message
    // when ending a user-facing flow at the failure point. Reply text is a generic
    // categorized message; raw fields preserved on metadata for logs and TierA cards.
    if let Some(metadata) = value.get("metadata").and_then(JsonValue::as_object) {
        let error_kind = metadata
            .get("error_kind")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let error_message = metadata
            .get("error_message")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let (Some(kind), Some(message)) = (error_kind, error_message) {
            let categorization = categorize_flow_error(kind, message);
            let mut reply = base_reply_envelope(ingress_envelope);
            reply.text = Some(categorization.user_message.clone());
            reply
                .metadata
                .insert("error_kind".to_string(), kind.to_string());
            reply
                .metadata
                .insert("error_message".to_string(), message.to_string());
            reply.metadata.insert(
                "error_category".to_string(),
                categorization.category.to_string(),
            );
            reply.metadata.insert(
                "error_user_message".to_string(),
                categorization.user_message.clone(),
            );
            reply
                .metadata
                .insert("error_fault".to_string(), categorization.fault.to_string());
            if let Some(node_id) = metadata
                .get("node_id")
                .and_then(JsonValue::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                reply
                    .metadata
                    .insert("error_node_id".to_string(), node_id.to_string());
            }
            operator_log::info(
                module_path!(),
                format!(
                    "[messaging_app] parse_envelopes path=flow_error kind={} category={} fault={} shape={}",
                    kind,
                    categorization.category,
                    categorization.fault,
                    summarize_output_shape(value)
                ),
            );
            return Ok(vec![reply]);
        }
    }

    operator_log::warn(
        module_path!(),
        format!(
            "[messaging_app] parse_envelopes failed shape={}",
            summarize_output_shape(value)
        ),
    );
    Err(anyhow::anyhow!(
        "app flow output did not produce envelope(s)"
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ErrorFault {
    BundleProvider,
    UpstreamService,
    Greentic,
}

impl std::fmt::Display for ErrorFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            ErrorFault::BundleProvider => "bundle_provider",
            ErrorFault::UpstreamService => "upstream_service",
            ErrorFault::Greentic => "greentic",
        };
        f.write_str(label)
    }
}

struct FlowErrorCategorization {
    category: &'static str,
    user_message: String,
    fault: ErrorFault,
}

/// Map a raw `(error_kind, error_message)` from the engine onto a stable
/// category and a generic, service-name-free user message. Pattern-matches on
/// known shapes (MCP tool errors, HTTP status hints, timeout / auth keywords)
/// and falls back to a generic message so the user never sees raw engine text.
fn categorize_flow_error(error_kind: &str, error_message: &str) -> FlowErrorCategorization {
    let lower = error_message.to_ascii_lowercase();
    let status = extract_http_status(error_message);

    let auth_signal = status == Some(401)
        || status == Some(403)
        || lower.contains("api key")
        || lower.contains("apikey")
        || lower.contains("unauthorized")
        || lower.contains("forbidden")
        || lower.contains("authentication");
    if auth_signal {
        return FlowErrorCategorization {
            category: "service_auth",
            user_message: "There's an authentication problem with this service. Please contact your service provider so they can refresh the credentials.".to_string(),
            fault: ErrorFault::BundleProvider,
        };
    }

    let timeout_signal = lower.contains("timeout") || lower.contains("timed out");
    if timeout_signal {
        return FlowErrorCategorization {
            category: "service_timeout",
            user_message: "This service didn't respond in time. Please try again in a moment."
                .to_string(),
            fault: ErrorFault::UpstreamService,
        };
    }

    if let Some(status) = status {
        if (500..600).contains(&status) {
            return FlowErrorCategorization {
                category: "service_unavailable",
                user_message:
                    "This service is temporarily unavailable. Please try again in a few minutes."
                        .to_string(),
                fault: ErrorFault::UpstreamService,
            };
        }
        if (400..500).contains(&status) {
            return FlowErrorCategorization {
                category: "service_bad_request",
                user_message: "This service couldn't process the request. Please contact your service provider if this keeps happening.".to_string(),
                fault: ErrorFault::BundleProvider,
            };
        }
    }

    if error_kind == "flow_execution_failed" {
        return FlowErrorCategorization {
            category: "flow_internal",
            user_message: "Something went wrong while processing your request. Please try again."
                .to_string(),
            fault: ErrorFault::Greentic,
        };
    }

    FlowErrorCategorization {
        category: "service_error",
        user_message: "Something went wrong with this service. Please try again, and contact your service provider if it persists.".to_string(),
        fault: ErrorFault::BundleProvider,
    }
}

/// Extract the first 3-digit HTTP status code mentioned in the error message.
/// Recognises both bare numbers (" 401 ", " status 500 ") and JSON shapes
/// (`"status":401`). Returns None when no plausible status is found.
fn extract_http_status(message: &str) -> Option<u16> {
    let bytes = message.as_bytes();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        if bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
        {
            let preceded_by_digit = i > 0 && bytes[i - 1].is_ascii_digit();
            let followed_by_digit = i + 3 < bytes.len() && bytes[i + 3].is_ascii_digit();
            if !preceded_by_digit && !followed_by_digit {
                let n: u16 = (bytes[i] - b'0') as u16 * 100
                    + (bytes[i + 1] - b'0') as u16 * 10
                    + (bytes[i + 2] - b'0') as u16;
                if (100..600).contains(&n) {
                    return Some(n);
                }
            }
        }
        i += 1;
    }
    None
}

fn base_reply_envelope(ingress_envelope: &ChannelMessageEnvelope) -> ChannelMessageEnvelope {
    let mut reply = ingress_envelope.clone();
    reply.id = uuid::Uuid::new_v4().to_string();
    reply.text = None;
    reply.attachments.clear();
    reply.correlation_id = None;
    reply.reply_scope = None;
    reply.from = None;

    let mut clean_metadata = BTreeMap::new();
    for key in [
        "env",
        "tenant",
        "team",
        "route",
        "locale",
        "universal",
        "autoStart",
    ] {
        if let Some(value) = reply.metadata.get(key).cloned() {
            clean_metadata.insert(key.to_string(), value);
        }
    }
    reply.metadata = clean_metadata;
    reply
}

fn parse_envelope_array(
    array: &[JsonValue],
    ingress_envelope: &ChannelMessageEnvelope,
) -> Result<Vec<ChannelMessageEnvelope>> {
    let mut envelopes = Vec::new();
    let mut seen = BTreeSet::new();
    for element in array {
        if let Ok(envelope) = serde_json::from_value::<ChannelMessageEnvelope>(element.clone()) {
            push_unique_envelope(&mut envelopes, &mut seen, envelope, ingress_envelope)?;
            continue;
        }

        let nested = parse_envelopes(element, ingress_envelope)
            .context("app flow output array contains invalid channel envelope")?;
        for envelope in nested {
            push_unique_envelope(&mut envelopes, &mut seen, envelope, ingress_envelope)?;
        }
    }
    Ok(envelopes)
}

fn push_unique_envelope(
    envelopes: &mut Vec<ChannelMessageEnvelope>,
    seen: &mut BTreeSet<String>,
    mut envelope: ChannelMessageEnvelope,
    ingress_envelope: &ChannelMessageEnvelope,
) -> Result<()> {
    preserve_ingress_reply_route(&mut envelope, ingress_envelope);
    let key = unique_envelope_key(&envelope)?;
    if seen.insert(key) {
        envelopes.push(envelope);
    }
    Ok(())
}

fn preserve_ingress_reply_route(
    envelope: &mut ChannelMessageEnvelope,
    ingress_envelope: &ChannelMessageEnvelope,
) {
    if envelope.to.is_empty() {
        envelope.to = ingress_envelope.to.clone();
    }
    if envelope.session_id.trim().is_empty() {
        envelope.session_id = ingress_envelope.session_id.clone();
    }
}

fn unique_envelope_key(envelope: &ChannelMessageEnvelope) -> Result<String> {
    let mut value =
        serde_json::to_value(envelope).context("failed to serialize channel envelope")?;
    if let Some(object) = value.as_object_mut() {
        object.remove("id");
        object.remove("correlation_id");
    }
    serde_json::to_string(&value).context("failed to serialize normalized channel envelope")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use tempfile::tempdir;

    fn envelope() -> ChannelMessageEnvelope {
        serde_json::from_value(json!({
            "id": "msg-1",
            "tenant": {
                "env": "dev",
                "tenant": "demo",
                "tenant_id": "demo",
                "team": "default",
                "attempt": 0
            },
            "channel": "conv-1",
            "session_id": "conv-1",
            "from": {
                "id": "user-1",
                "kind": "user"
            },
            "to": [{
                "id": "Y2lzY29zcGFyazovL3VzL1JPT00vcm9vbS0x",
                "kind": "room"
            }],
            "text": "hello",
            "metadata": {}
        }))
        .expect("envelope")
    }

    fn cbor_text(key: &str, value: &str) -> (CborValue, CborValue) {
        (
            CborValue::Text(key.to_string()),
            CborValue::Text(value.to_string()),
        )
    }

    #[test]
    fn resolve_from_bundle_yaml_prefers_direct_gtpack_reference() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path();
        let packs_root = bundle.join("packs");
        std::fs::create_dir_all(&packs_root).expect("packs root");
        let pack_path = packs_root.join("sales-assist.gtpack");
        std::fs::write(&pack_path, b"pack").expect("write pack");
        std::fs::write(
            bundle.join("bundle.yaml"),
            "app_packs:\n  - https://cdn.example.com/sales-assist.gtpack\n",
        )
        .expect("write bundle");

        assert_eq!(
            resolve_from_bundle_yaml(bundle, &packs_root),
            Some(pack_path)
        );
    }

    #[test]
    fn resolve_from_bundle_yaml_falls_back_to_dist_gtpack_and_non_default_scan() {
        let dir = tempdir().expect("tempdir");
        let bundle = dir.path();
        let packs_root = bundle.join("packs");
        let dist_dir = packs_root.join("support.pack").join("dist");
        std::fs::create_dir_all(&dist_dir).expect("dist dir");
        let dist_pack = dist_dir.join("support.pack.gtpack");
        std::fs::write(&dist_pack, b"pack").expect("write dist pack");
        std::fs::write(
            bundle.join("bundle.yaml"),
            "app_packs:\n  - packs/support.pack\n",
        )
        .expect("write bundle");

        assert_eq!(
            resolve_from_bundle_yaml(bundle, &packs_root),
            Some(dist_pack.clone())
        );

        std::fs::remove_file(bundle.join("bundle.yaml")).expect("remove bundle");
        std::fs::remove_file(&dist_pack).expect("remove dist pack");
        let fallback = packs_root.join("assistant.gtpack");
        std::fs::write(&fallback, b"fallback").expect("write fallback");

        assert_eq!(
            resolve_from_bundle_yaml(bundle, &packs_root),
            Some(fallback)
        );
    }

    #[test]
    fn select_app_flow_prefers_default_and_single_messaging_flow() {
        let info = AppPackInfo {
            pack_id: "pack".to_string(),
            flows: vec![
                AppFlowInfo {
                    id: "alternate".to_string(),
                    kind: "messaging".to_string(),
                },
                AppFlowInfo {
                    id: "default".to_string(),
                    kind: "workflow".to_string(),
                },
            ],
            capabilities: Vec::new(),
        };
        assert_eq!(select_app_flow(&info).expect("default flow").id, "default");

        let single_messaging = AppPackInfo {
            pack_id: "pack".to_string(),
            flows: vec![
                AppFlowInfo {
                    id: "notify".to_string(),
                    kind: "messaging".to_string(),
                },
                AppFlowInfo {
                    id: "wizard".to_string(),
                    kind: "setup".to_string(),
                },
            ],
            capabilities: Vec::new(),
        };
        assert_eq!(
            select_app_flow(&single_messaging)
                .expect("single messaging flow")
                .id,
            "notify"
        );
    }

    #[test]
    fn select_app_flow_errors_when_choice_is_ambiguous() {
        let info = AppPackInfo {
            pack_id: "pack".to_string(),
            flows: vec![
                AppFlowInfo {
                    id: "one".to_string(),
                    kind: "messaging".to_string(),
                },
                AppFlowInfo {
                    id: "two".to_string(),
                    kind: "messaging".to_string(),
                },
            ],
            capabilities: Vec::new(),
        };

        let err = select_app_flow(&info).expect_err("ambiguous flow should fail");
        let message = err.to_string();
        assert!(message.contains("APP_FLOW_NOT_RESOLVED"));
        assert!(message.contains("cannot choose which flow to invoke"));
        assert!(message.contains("one (kind=messaging), two (kind=messaging)"));
        assert!(message.contains("flow with id `default`"));
    }

    #[test]
    fn extract_text_or_symbol_and_parse_flow_entry_support_symbol_tables_and_defaults() {
        let value = CborValue::Map(BTreeMap::from([
            (
                CborValue::Text("pack_id".to_string()),
                CborValue::Integer(1),
            ),
            (
                CborValue::Text("symbols".to_string()),
                CborValue::Map(BTreeMap::from([(
                    CborValue::Text("pack_ids".to_string()),
                    CborValue::Array(vec![
                        CborValue::Text("ignored".to_string()),
                        CborValue::Text("demo-pack".to_string()),
                    ]),
                )])),
            ),
        ]));
        assert_eq!(
            extract_text_or_symbol(&value, "pack_id", "pack_ids"),
            Some("demo-pack".to_string())
        );

        let nested_flow = CborValue::Map(BTreeMap::from([
            cbor_text("id", "route-card"),
            (
                CborValue::Text("flow".to_string()),
                CborValue::Map(BTreeMap::from([cbor_text("kind", "workflow")])),
            ),
        ]));
        let parsed = parse_flow_entry(&nested_flow).expect("flow entry");
        assert_eq!(parsed.id, "route-card");
        assert_eq!(parsed.kind, "workflow");

        let default_kind_flow = CborValue::Map(BTreeMap::from([cbor_text("id", "default")]));
        assert_eq!(
            parse_flow_entry(&default_kind_flow)
                .expect("default kind flow")
                .kind,
            "messaging"
        );
    }

    #[test]
    fn extract_capabilities_reads_name_from_component_capability_entries() {
        // Mirrors greentic_types::ComponentCapability { name, description } —
        // the cbor for `capabilities` is Array<Map>, not Array<Text>.
        let manifest = CborValue::Map(BTreeMap::from([(
            CborValue::Text("capabilities".to_string()),
            CborValue::Array(vec![
                CborValue::Map(BTreeMap::from([
                    cbor_text("name", "greentic.cap.fast2flow.v1"),
                    cbor_text("description", "routable flows"),
                ])),
                CborValue::Map(BTreeMap::from([cbor_text("name", "greentic.cap.other.v1")])),
            ]),
        )]));
        assert_eq!(
            extract_capabilities(&manifest),
            vec![
                "greentic.cap.fast2flow.v1".to_string(),
                "greentic.cap.other.v1".to_string(),
            ]
        );
    }

    #[test]
    fn extract_capabilities_skips_entries_without_name_or_wrong_shape() {
        // Bare strings and name-less maps must not surface as capabilities;
        // returning silently keeps the gate fail-closed for malformed packs.
        let manifest = CborValue::Map(BTreeMap::from([(
            CborValue::Text("capabilities".to_string()),
            CborValue::Array(vec![
                CborValue::Map(BTreeMap::from([cbor_text("name", "greentic.cap.ok.v1")])),
                CborValue::Map(BTreeMap::from([cbor_text("description", "no name")])),
                CborValue::Text("legacy flat string".to_string()),
            ]),
        )]));
        assert_eq!(
            extract_capabilities(&manifest),
            vec!["greentic.cap.ok.v1".to_string()]
        );
    }

    #[test]
    fn extract_capabilities_returns_empty_when_field_missing() {
        let manifest = CborValue::Map(BTreeMap::from([cbor_text("pack_id", "demo-pack")]));
        assert!(extract_capabilities(&manifest).is_empty());
    }

    #[test]
    fn extract_capabilities_resolves_symbol_indexed_names() {
        // Canonical EncodedCapability { name: u32, .. } references
        // symbols.capability_names[idx] — what packc + greentic-types emit.
        let manifest = CborValue::Map(BTreeMap::from([
            (
                CborValue::Text("symbols".to_string()),
                CborValue::Map(BTreeMap::from([(
                    CborValue::Text("capability_names".to_string()),
                    CborValue::Array(vec![
                        CborValue::Text("greentic.cap.fast2flow.v1".to_string()),
                        CborValue::Text("greentic.cap.other.v1".to_string()),
                    ]),
                )])),
            ),
            (
                CborValue::Text("capabilities".to_string()),
                CborValue::Array(vec![
                    CborValue::Map(BTreeMap::from([
                        (CborValue::Text("name".to_string()), CborValue::Integer(0)),
                        cbor_text("description", "fast2flow opt-in"),
                    ])),
                    CborValue::Map(BTreeMap::from([(
                        CborValue::Text("name".to_string()),
                        CborValue::Integer(1),
                    )])),
                ]),
            ),
        ]));
        assert_eq!(
            extract_capabilities(&manifest),
            vec![
                "greentic.cap.fast2flow.v1".to_string(),
                "greentic.cap.other.v1".to_string(),
            ]
        );
    }

    #[test]
    fn extract_capabilities_skips_out_of_range_symbol_indices() {
        let manifest = CborValue::Map(BTreeMap::from([
            (
                CborValue::Text("symbols".to_string()),
                CborValue::Map(BTreeMap::from([(
                    CborValue::Text("capability_names".to_string()),
                    CborValue::Array(vec![CborValue::Text("only-one".to_string())]),
                )])),
            ),
            (
                CborValue::Text("capabilities".to_string()),
                CborValue::Array(vec![CborValue::Map(BTreeMap::from([(
                    CborValue::Text("name".to_string()),
                    CborValue::Integer(99),
                )]))]),
            ),
        ]));
        assert!(extract_capabilities(&manifest).is_empty());
    }

    /// End-to-end round-trip: build a real `PackManifest` with our
    /// capability, encode via `greentic_types::encode_pack_manifest` (the
    /// canonical encoder that symbol-indexes the name), zip into a
    /// `.gtpack`, then `load_app_pack_info` and assert detection.
    #[test]
    fn load_app_pack_info_detects_fast2flow_capability_via_canonical_encoding() {
        use greentic_types::pack_manifest::{
            ComponentCapability, PackFlowEntry, PackKind, PackManifest, PackSignatures,
        };
        use greentic_types::{Flow, FlowId, FlowKind, PackId, encode_pack_manifest};
        use semver::Version;
        use tempfile::tempdir;
        use zip::write::FileOptions;

        let flow = Flow {
            schema_version: "flow-v1".to_string(),
            id: FlowId::new("main").expect("flow id"),
            kind: FlowKind::Messaging,
            entrypoints: std::collections::BTreeMap::from([(
                "default".to_string(),
                serde_json::Value::Null,
            )]),
            nodes: Default::default(),
            metadata: Default::default(),
        };
        let manifest = PackManifest {
            schema_version: "pack-v1".into(),
            pack_id: PackId::new("greentic.test.fast2flow").expect("pack id"),
            name: Some("fast2flow-test".into()),
            version: Version::parse("0.1.0").expect("version"),
            kind: PackKind::Application,
            publisher: "test".into(),
            components: Vec::new(),
            flows: vec![PackFlowEntry {
                id: FlowId::new("main").expect("flow id"),
                kind: FlowKind::Messaging,
                flow,
                tags: vec!["default".to_string()],
                entrypoints: vec!["default".to_string()],
            }],
            dependencies: Vec::new(),
            capabilities: vec![ComponentCapability {
                name: "greentic.cap.fast2flow.v1".to_string(),
                description: Some("test fixture".to_string()),
            }],
            secret_requirements: Vec::new(),
            signatures: PackSignatures::default(),
            bootstrap: None,
            extensions: None,
        };
        let cbor_bytes = encode_pack_manifest(&manifest).expect("encode manifest");

        let dir = tempdir().expect("tempdir");
        let pack_path = dir.path().join("test.gtpack");
        let file = std::fs::File::create(&pack_path).expect("create pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())
            .expect("start file");
        zip.write_all(&cbor_bytes).expect("write manifest");
        zip.finish().expect("finish pack");

        let info = load_app_pack_info(&pack_path).expect("load pack info");
        assert_eq!(info.pack_id, "greentic.test.fast2flow");
        assert!(
            info.capabilities
                .contains(&"greentic.cap.fast2flow.v1".to_string()),
            "expected fast2flow capability via canonical encoding, got {:?}",
            info.capabilities
        );
    }

    #[test]
    fn collect_transcript_outputs_prefers_targeted_node_then_last_output() {
        let dir = tempdir().expect("tempdir");
        let transcript = dir.path().join("transcript.jsonl");
        std::fs::write(
            &transcript,
            concat!(
                "{\"node_id\":\"first\",\"outputs\":null}\n",
                "{\"node_id\":\"other\",\"outputs\":{\"text\":\"middle\"}}\n",
                "{\"node_id\":\"target\",\"outputs\":{\"text\":\"targeted\"}}\n"
            ),
        )
        .expect("write transcript");

        // Targeted node takes priority
        let targeted = collect_transcript_outputs(dir.path(), Some("target"))
            .expect("collect outputs")
            .expect("targeted output");
        assert_eq!(targeted["text"], "targeted");

        // When target not found, fall back to LAST non-null output
        let fallback = collect_transcript_outputs(dir.path(), Some("missing"))
            .expect("collect fallback")
            .expect("fallback output");
        assert_eq!(fallback["text"], "targeted");

        let missing = collect_transcript_outputs(&dir.path().join("no-run"), None)
            .expect("missing transcript");
        assert!(missing.is_none());
    }

    #[test]
    fn collect_transcript_outputs_prefers_envelope_compatible_output() {
        let dir = tempdir().expect("tempdir");
        let transcript = dir.path().join("transcript.jsonl");
        std::fs::write(
            &transcript,
            concat!(
                "{\"node_id\":\"call_weather\",\"outputs\":{\"ok\":true,\"result\":{\"structured_content\":{\"temp_c\":21.3}}}}\n",
                "{\"node_id\":\"render_current_card\",\"outputs\":{\"renderedCard\":{\"body\":[{\"text\":\"Current Weather\"}]}}}\n"
            ),
        )
        .expect("write transcript");

        let selected = collect_transcript_outputs(dir.path(), None)
            .expect("collect outputs")
            .expect("selected output");
        assert!(selected.get("renderedCard").is_some());

        let targeted = collect_transcript_outputs(dir.path(), Some("call_weather"))
            .expect("collect targeted")
            .expect("targeted output");
        assert_eq!(targeted["ok"], true);
        assert!(targeted.get("renderedCard").is_none());
    }

    #[test]
    fn collect_transcript_outputs_prefers_latest_envelope_output() {
        let dir = tempdir().expect("tempdir");
        let transcript = dir.path().join("transcript.jsonl");
        std::fs::write(
            &transcript,
            concat!(
                "{\"node_id\":\"main_menu\",\"outputs\":{\"renderedCard\":{\"body\":[{\"text\":\"Main Menu\"}]}}}\n",
                "{\"node_id\":\"research_planner\",\"outputs\":{\"completion\":\"plan\"}}\n",
                "{\"node_id\":\"show_final_report\",\"outputs\":{\"renderedCard\":{\"body\":[{\"text\":\"Final Report\"}]}}}\n"
            ),
        )
        .expect("write transcript");

        let selected = collect_transcript_outputs(dir.path(), None)
            .expect("collect outputs")
            .expect("selected output");
        assert_eq!(selected["renderedCard"]["body"][0]["text"], "Final Report");
    }

    #[test]
    fn collect_transcript_outputs_prefers_envelope_over_trailing_error_record() {
        // Regression: autoStart can execute downstream nodes whose outputs are
        // diagnostic objects (e.g. `{error: AC_BINDING_EVAL_ERROR}`). Those
        // must NOT displace an earlier envelope-shaped reply that the user is
        // expecting to see (the rendered welcome card).
        let dir = tempdir().expect("tempdir");
        let transcript = dir.path().join("transcript.jsonl");
        std::fs::write(
            &transcript,
            concat!(
                "{\"node_id\":\"welcome\",\"outputs\":{\"renderedCard\":{\"body\":[{\"text\":\"Welcome\"}]}}}\n",
                "{\"node_id\":\"midway\",\"outputs\":{\"ok\":true}}\n",
                "{\"node_id\":\"booking_complete\",\"outputs\":{\"error\":\"AC_BINDING_EVAL_ERROR\",\"missing\":[\"consultType\"]}}\n"
            ),
        )
        .expect("write transcript");

        let selected = collect_transcript_outputs(dir.path(), None)
            .expect("collect outputs")
            .expect("selected output");
        assert_eq!(
            selected["renderedCard"]["body"][0]["text"], "Welcome",
            "envelope-shaped welcome card must win over trailing error record"
        );
        assert!(
            selected.get("error").is_none(),
            "diagnostic error output must not be surfaced to the channel"
        );
    }

    #[test]
    fn collect_transcript_outputs_treats_messages_as_envelope_compatible() {
        let dir = tempdir().expect("tempdir");
        let transcript = dir.path().join("transcript.jsonl");
        std::fs::write(
            &transcript,
            concat!(
                "{\"node_id\":\"planner\",\"outputs\":{\"ok\":true}}\n",
                "{\"node_id\":\"present_telco\",\"outputs\":{\"messages\":[{\"type\":\"adaptive_card\",\"card\":{\"type\":\"AdaptiveCard\",\"version\":\"1.5\",\"body\":[{\"type\":\"TextBlock\",\"text\":\"Card A\"}]}}]}}\n"
            ),
        )
        .expect("write transcript");

        let selected = collect_transcript_outputs(dir.path(), None)
            .expect("collect outputs")
            .expect("selected output");
        assert!(selected.get("messages").is_some());
    }

    #[test]
    fn collect_transcript_outputs_with_retry_returns_first_envelope_compatible_output() {
        let dir = tempdir().expect("tempdir");
        let transcript = dir.path().join("transcript.jsonl");
        std::fs::write(
            &transcript,
            "{\"node_id\":\"call_weather\",\"outputs\":{\"messages\":[{\"text\":\"intermediate\"}]}}\n",
        )
        .expect("write transcript");

        let transcript_clone = transcript.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(70));
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&transcript_clone)
                .expect("open transcript");
            use std::io::Write as _;
            file.write_all(
                br#"{"node_id":"render_current_card","outputs":{"renderedCard":{"body":[{"text":"Current Weather"}]}}}
"#,
            )
            .expect("append rendered card output");
        });

        let selected = collect_transcript_outputs_with_retry(dir.path(), None, &envelope())
            .expect("collect outputs with retry")
            .expect("selected output");

        writer.join().expect("join writer");
        assert!(selected.get("messages").is_some());
        assert!(selected.get("renderedCard").is_none());
    }

    #[test]
    fn parse_envelopes_supports_message_events_cards_and_text_payloads() {
        let ingress = envelope();

        let message_output = parse_envelopes(
            &json!({
                "message": {
                    "id": "msg-2",
                    "tenant": ingress.tenant,
                    "channel": "conv-2",
                    "session_id": "conv-2",
                    "from": {
                        "id": "bot-1",
                        "kind": "bot"
                    },
                    "text": "reply",
                    "metadata": {}
                }
            }),
            &ingress,
        )
        .expect("message output");
        assert_eq!(message_output[0].text.as_deref(), Some("reply"));
        assert_eq!(
            message_output[0].to[0].id,
            "Y2lzY29zcGFyazovL3VzL1JPT00vcm9vbS0x"
        );
        assert_eq!(message_output[0].to[0].kind.as_deref(), Some("room"));

        let events_output = parse_envelopes(
            &json!({
                "events": [
                    {
                        "id": "msg-3",
                        "tenant": ingress.tenant,
                        "channel": "conv-3",
                        "session_id": "conv-3",
                        "from": {
                            "id": "bot-1",
                            "kind": "bot"
                        },
                        "text": "event reply",
                        "metadata": {}
                    }
                ]
            }),
            &ingress,
        )
        .expect("events output");
        assert_eq!(events_output[0].text.as_deref(), Some("event reply"));

        let card_output = parse_envelopes(
            &json!({
                "renderedCard": {
                    "body": [
                        {"text": "Welcome card"}
                    ]
                }
            }),
            &ingress,
        )
        .expect("card output");
        assert_eq!(card_output[0].text, None);
        assert!(card_output[0].metadata.contains_key("adaptive_card"));

        let messages_output = parse_envelopes(
            &json!({
                "messages": [
                    {"type": "text", "text": "messages fallback"}
                ]
            }),
            &ingress,
        )
        .expect("messages output");
        assert_eq!(
            messages_output[0].text.as_deref(),
            Some("messages fallback")
        );

        let card_messages_output = parse_envelopes(
            &json!({
                "messages": [
                    {
                        "type": "adaptive_card",
                        "card": {
                            "type": "AdaptiveCard",
                            "version": "1.5",
                            "body": [{"type": "TextBlock", "text": "Card 1"}]
                        }
                    },
                    {
                        "type": "adaptive_card",
                        "card": {
                            "type": "AdaptiveCard",
                            "version": "1.5",
                            "body": [{"type": "TextBlock", "text": "Card 2"}]
                        }
                    }
                ]
            }),
            &ingress,
        )
        .expect("messages adaptive cards output");
        assert_eq!(card_messages_output.len(), 2);
        assert!(
            card_messages_output[0]
                .metadata
                .contains_key("adaptive_card")
        );
        assert!(
            card_messages_output[1]
                .metadata
                .contains_key("adaptive_card")
        );

        let card_array_output = parse_envelopes(
            &json!([
                {
                    "renderedCard": {
                        "type": "AdaptiveCard",
                        "version": "1.5",
                        "body": [{"type": "TextBlock", "text": "Card A"}]
                    }
                },
                {
                    "renderedCard": {
                        "type": "AdaptiveCard",
                        "version": "1.5",
                        "body": [{"type": "TextBlock", "text": "Card B"}]
                    }
                }
            ]),
            &ingress,
        )
        .expect("card array output");
        assert_eq!(card_array_output.len(), 2);
        assert!(
            card_array_output
                .iter()
                .all(|reply| reply.metadata.contains_key("adaptive_card"))
        );
        assert_eq!(card_array_output.len(), 2);

        let duplicate_card_array_output = parse_envelopes(
            &json!([
                {
                    "renderedCard": {
                        "type": "AdaptiveCard",
                        "version": "1.5",
                        "body": [{"type": "TextBlock", "text": "Card A"}]
                    }
                },
                {
                    "renderedCard": {
                        "type": "AdaptiveCard",
                        "version": "1.5",
                        "body": [{"type": "TextBlock", "text": "Card A"}]
                    }
                }
            ]),
            &ingress,
        )
        .expect("duplicate card array output");
        assert_eq!(duplicate_card_array_output.len(), 1);

        let text_output = parse_envelopes(&json!({"payload": {"text": "payload text"}}), &ingress)
            .expect("text output");
        assert_eq!(text_output[0].text.as_deref(), Some("payload text"));
    }

    #[test]
    fn parse_envelopes_reports_invalid_arrays_and_unrecognized_payloads() {
        let ingress = envelope();

        let invalid_array = parse_envelopes(&json!([{"not": "an envelope"}]), &ingress)
            .expect_err("invalid array should fail");
        assert!(
            invalid_array
                .to_string()
                .contains("invalid channel envelope")
        );

        let unknown = parse_envelopes(&json!({"payload": {"unknown": true}}), &ingress)
            .expect_err("unknown payload should fail");
        assert!(unknown.to_string().contains("did not produce envelope"));
    }

    #[test]
    fn categorize_flow_error_detects_auth_signals() {
        let cases = [
            (
                "flow_node_failed",
                "component x failed: MCP_TOOL_ERROR: 401 API key required",
            ),
            ("flow_node_failed", "tool returned an error (status 403)"),
            ("flow_node_failed", "Authentication denied"),
            ("flow_node_failed", "apikey rejected"),
        ];
        for (kind, msg) in cases {
            let cat = categorize_flow_error(kind, msg);
            assert_eq!(cat.category, "service_auth", "msg={msg}");
            assert_eq!(cat.fault, ErrorFault::BundleProvider, "msg={msg}");
            assert!(
                !cat.user_message.contains("MCP")
                    && !cat.user_message.contains("401")
                    && !cat.user_message.contains("API key"),
                "user message must be generic: {}",
                cat.user_message
            );
        }
    }

    #[test]
    fn categorize_flow_error_detects_timeout() {
        let cat = categorize_flow_error("flow_node_failed", "upstream request timed out");
        assert_eq!(cat.category, "service_timeout");
        assert_eq!(cat.fault, ErrorFault::UpstreamService);
    }

    #[test]
    fn categorize_flow_error_detects_5xx_unavailable() {
        let cat = categorize_flow_error(
            "flow_node_failed",
            "component x returned tool error: tool_error: upstream blew up (status 502)",
        );
        assert_eq!(cat.category, "service_unavailable");
        assert_eq!(cat.fault, ErrorFault::UpstreamService);
    }

    #[test]
    fn categorize_flow_error_detects_4xx_bad_request_non_auth() {
        let cat = categorize_flow_error(
            "flow_node_failed",
            "component x returned tool error (status 422 unprocessable)",
        );
        assert_eq!(cat.category, "service_bad_request");
        assert_eq!(cat.fault, ErrorFault::BundleProvider);
    }

    #[test]
    fn categorize_flow_error_flow_execution_failed_maps_to_greentic() {
        let cat = categorize_flow_error("flow_execution_failed", "panic in dispatch_node");
        assert_eq!(cat.category, "flow_internal");
        assert_eq!(cat.fault, ErrorFault::Greentic);
    }

    #[test]
    fn categorize_flow_error_defaults_to_generic_bundle_provider() {
        let cat = categorize_flow_error("flow_node_failed", "some unrecognized failure");
        assert_eq!(cat.category, "service_error");
        assert_eq!(cat.fault, ErrorFault::BundleProvider);
    }

    #[test]
    fn extract_http_status_recognises_common_shapes() {
        assert_eq!(extract_http_status("status 401 unauthorized"), Some(401));
        assert_eq!(extract_http_status("(status 502)"), Some(502));
        assert_eq!(extract_http_status("\"status\":401,"), Some(401));
        assert_eq!(extract_http_status("HTTP 404 not found"), Some(404));
        assert_eq!(extract_http_status("nothing here"), None);
        assert_eq!(extract_http_status("1234"), None);
        assert_eq!(extract_http_status("9999"), None);
    }

    #[test]
    fn parse_envelopes_flow_error_branch_emits_generic_text_and_metadata() {
        let ingress = envelope();
        let output = json!({
            "metadata": {
                "error_kind": "flow_node_failed",
                "error_message": "component weatherapi_current failed: MCP_TOOL_ERROR: 401 API key required",
                "node_id": "call_weather",
            }
        });
        let replies = parse_envelopes(&output, &ingress).expect("flow_error branch");
        assert_eq!(replies.len(), 1);
        let reply = &replies[0];
        let text = reply.text.as_deref().expect("text fallback present");
        assert!(
            !text.contains("MCP")
                && !text.contains("API key")
                && !text.contains("weatherapi_current"),
            "text must be generic: {text}"
        );
        assert_eq!(
            reply.metadata.get("error_category").map(String::as_str),
            Some("service_auth")
        );
        assert_eq!(
            reply.metadata.get("error_fault").map(String::as_str),
            Some("bundle_provider")
        );
        assert!(reply.metadata.contains_key("error_user_message"));
        assert!(reply.metadata.contains_key("error_message"));
        assert_eq!(
            reply.metadata.get("error_node_id").map(String::as_str),
            Some("call_weather")
        );
    }

    #[test]
    fn parse_envelopes_flow_error_branch_ignored_when_rendered_card_present() {
        let ingress = envelope();
        let output = json!({
            "renderedCard": {
                "type": "AdaptiveCard",
                "version": "1.5",
                "body": [{"type": "TextBlock", "text": "hello"}]
            },
            "metadata": {
                "error_kind": "flow_node_failed",
                "error_message": "should not preempt rendered card",
            }
        });
        let replies = parse_envelopes(&output, &ingress).expect("renderedCard branch");
        assert_eq!(replies.len(), 1);
        assert!(
            !replies[0].metadata.contains_key("error_category"),
            "error_category must not be set when a card branch already produced the reply"
        );
    }

    #[test]
    fn parse_envelopes_forwards_directline_fields_from_text_fallback() {
        let ingress = envelope();
        let output = json!({
            "ok": true,
            "text": "hello with card",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "version": "1.5",
                        "body": [{"type": "TextBlock", "text": "card body"}]
                    }
                }
            ],
            "channelData": {"directline": {"conversationId": "c-1"}},
            "entities": [{"type": "mention", "text": "@user"}]
        });

        let replies = parse_envelopes(&output, &ingress).expect("envelope");
        assert_eq!(replies.len(), 1);
        let reply = &replies[0];
        assert_eq!(reply.text.as_deref(), Some("hello with card"));
        assert!(
            reply.extensions.contains_key(ext_keys::ATTACHMENTS),
            "expected ATTACHMENTS in extensions, got keys: {:?}",
            reply.extensions.keys().collect::<Vec<_>>()
        );
        assert!(
            reply.extensions.contains_key(ext_keys::CHANNEL_DATA),
            "expected CHANNEL_DATA in extensions"
        );
        assert!(
            reply.extensions.contains_key(ext_keys::ENTITIES),
            "expected ENTITIES in extensions"
        );
        // ADAPTIVE_CARD is NOT lifted when ATTACHMENTS is already forwarded —
        // the provider reads the card from the attachments array, and lifting
        // would cause the same card to render twice on the outbound activity.
        assert!(
            !reply.extensions.contains_key(ext_keys::ADAPTIVE_CARD),
            "ADAPTIVE_CARD must NOT be lifted when ATTACHMENTS is present"
        );
    }

    #[test]
    fn parse_envelopes_forwards_directline_fields_with_no_text() {
        let ingress = envelope();
        let output = json!({
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "version": "1.5",
                        "body": [{"type": "TextBlock", "text": "no-text card"}]
                    }
                }
            ]
        });

        let replies = parse_envelopes(&output, &ingress).expect("envelope");
        assert_eq!(replies.len(), 1);
        let reply = &replies[0];
        assert_eq!(reply.text, None);
        assert!(
            reply.extensions.contains_key(ext_keys::ATTACHMENTS),
            "expected ATTACHMENTS in extensions"
        );
        assert!(
            !reply.extensions.contains_key(ext_keys::ADAPTIVE_CARD),
            "ADAPTIVE_CARD must NOT be lifted when ATTACHMENTS is present"
        );
    }

    #[test]
    fn load_app_pack_info_reads_manifest_pack_id_and_flows() {
        let dir = tempdir().expect("tempdir");
        let pack_path = dir.path().join("app.gtpack");
        let file = File::create(&pack_path).expect("create pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", zip::write::FileOptions::<()>::default())
            .expect("start manifest");
        let manifest = CborValue::Map(BTreeMap::from([
            cbor_text("pack_id", "demo-pack"),
            (
                CborValue::Text("flows".to_string()),
                CborValue::Array(vec![
                    CborValue::Map(BTreeMap::from([
                        cbor_text("id", "default"),
                        cbor_text("kind", "messaging"),
                    ])),
                    CborValue::Map(BTreeMap::from([
                        cbor_text("id", "setup"),
                        (
                            CborValue::Text("flow".to_string()),
                            CborValue::Map(BTreeMap::from([cbor_text("kind", "workflow")])),
                        ),
                    ])),
                ]),
            ),
        ]));
        let bytes = serde_cbor::to_vec(&manifest).expect("encode manifest");
        zip.write_all(&bytes).expect("write manifest");
        zip.finish().expect("finish zip");

        let info = load_app_pack_info(&pack_path).expect("load pack info");
        assert_eq!(info.pack_id, "demo-pack");
        assert_eq!(info.flows.len(), 2);
        assert_eq!(info.flows[0].id, "default");
        assert_eq!(info.flows[1].kind, "workflow");
    }

    #[test]
    fn inject_pack_setup_answers_merges_strings_without_overwriting_existing() {
        let dir = tempdir().expect("tempdir");
        let pack_id = "demo-pack";
        let cfg_dir = dir.path().join("state").join("config").join(pack_id);
        std::fs::create_dir_all(&cfg_dir).expect("create cfg dir");
        std::fs::write(
            cfg_dir.join("setup-answers.json"),
            r#"{
                "url": "https://api.openai.com/v1",
                "model": "gpt-4o-mini",
                "provider": "openai",
                "api_key_secret": "secrets://openai/key",
                "user_question": "should-not-overwrite",
                "max_tokens": 1024,
                "stream": true,
                "tools": ["web_search"],
                "extra_null": null
            }"#,
        )
        .expect("write setup-answers");

        let mut metadata = BTreeMap::new();
        metadata.insert("user_question".to_string(), "What is 2+2?".to_string());

        inject_pack_setup_answers(dir.path(), pack_id, &mut metadata);

        // pack values present
        assert_eq!(
            metadata.get("url").map(String::as_str),
            Some("https://api.openai.com/v1")
        );
        assert_eq!(
            metadata.get("model").map(String::as_str),
            Some("gpt-4o-mini")
        );
        assert_eq!(metadata.get("provider").map(String::as_str), Some("openai"));
        assert_eq!(
            metadata.get("api_key_secret").map(String::as_str),
            Some("secrets://openai/key")
        );
        // numbers and bools are stringified
        assert_eq!(metadata.get("max_tokens").map(String::as_str), Some("1024"));
        assert_eq!(metadata.get("stream").map(String::as_str), Some("true"));
        // arrays are JSON-encoded
        assert_eq!(
            metadata.get("tools").map(String::as_str),
            Some("[\"web_search\"]")
        );
        // null skipped
        assert!(!metadata.contains_key("extra_null"));
        // existing user input is preserved
        assert_eq!(
            metadata.get("user_question").map(String::as_str),
            Some("What is 2+2?")
        );
    }

    #[test]
    fn inject_pack_setup_answers_is_noop_when_file_missing() {
        let dir = tempdir().expect("tempdir");
        let mut metadata = BTreeMap::new();
        metadata.insert("user_question".to_string(), "hello".to_string());
        inject_pack_setup_answers(dir.path(), "nonexistent-pack", &mut metadata);
        assert_eq!(metadata.len(), 1);
        assert_eq!(
            metadata.get("user_question").map(String::as_str),
            Some("hello")
        );
    }
}
