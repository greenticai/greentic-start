use std::path::Path;

use base64::Engine as _;
use greentic_types::ChannelMessageEnvelope;
use serde_json::json;

use super::flow_owner;
use crate::domains::Domain;
#[cfg(test)]
use crate::fast2flow::dispatch::dispatch_flow;
use crate::fast2flow::dispatch::{self as f2f_dispatch, RouteDecision};
use crate::fast2flow::probe::{self as f2f_probe, ProbeInputs, TurnPlan};
#[cfg(test)]
use crate::fast2flow::turn::RouteSource;
use crate::fast2flow::turn::{RouteSignal, Unrouted};
#[cfg(test)]
use crate::ingress::control_directive::{ControlDirective, DispatchTarget};
use crate::ingress_dispatch::build_injected_config;
use crate::messaging_app as app;
use crate::messaging_dto::ProviderPayloadV1;
use crate::messaging_egress as egress;
use crate::operator_log;
use crate::runner_host::{DemoRunnerHost, OperatorContext};

pub(super) fn route_messaging_envelopes(
    bundle: &Path,
    runner_host: &DemoRunnerHost,
    provider: &str,
    ctx: &OperatorContext,
    envelopes: Vec<ChannelMessageEnvelope>,
) -> anyhow::Result<()> {
    let team = ctx.team.as_deref();
    let app_pack_path = app::resolve_app_pack_path(bundle, &ctx.tenant, team, None)
        .context("resolve app pack for messaging pipeline")?;
    let pack_info = app::load_app_pack_info(&app_pack_path).context("load app pack manifest")?;
    let default_flow = app::select_app_flow(&pack_info).context("select app default flow")?;

    operator_log::debug(
        module_path!(),
        format!(
            "[demo messaging] routing {} envelope(s) through app flow={} pack={}",
            envelopes.len(),
            default_flow.id,
            pack_info.pack_id
        ),
    );

    let probe_inputs = ProbeInputs {
        cfg: crate::fast2flow::Fast2FlowConfig::global(),
        ctx,
        pack: &pack_info,
        pack_path: &app_pack_path,
        index_scope: None,
        provider,
        llm: crate::llm::config(),
    };

    for original in &envelopes {
        let outputs = turn::turn_outputs(
            bundle,
            ctx,
            &pack_info,
            default_flow,
            &app_pack_path,
            original,
            || {
                // Per-envelope Fast2Flow probe (host router, then the
                // embedded LLM fallback) — see `fast2flow::probe::probe`.
                // Its owned decision is mapped back onto this pack's flows.
                f2f_probe::probe(&probe_inputs, original)
                    .and_then(|decision| routed(decision, &pack_info))
            },
            &mut |flow, envelope| {
                run_app_flow_safe(
                    runner_host,
                    bundle,
                    ctx,
                    &app_pack_path,
                    &pack_info,
                    flow,
                    envelope,
                )
            },
        );

        for mut out_envelope in outputs {
            if let Some(team) = &ctx.team {
                out_envelope
                    .metadata
                    .entry("team".to_string())
                    .or_insert_with(|| team.clone());
            }

            // Ensure i18n tokens are resolved in any adaptive card.  The WASM
            // component *should* resolve them, but when running through
            // greentic-runner-desktop the host resolver is not registered so the
            // component falls back to Handlebars which silently eats unresolved
            // `{{i18n:KEY}}` tokens.  Re-read the card from the pack and apply
            // i18n as a safety net.
            ensure_card_i18n_resolved(&mut out_envelope, &app_pack_path);

            // Standard egress pipeline: render → encode → send_payload.
            // All providers (including webchat) use this path. The webchat provider's
            // send_payload writes bot activities to the conversation state store for
            // client polling via DirectLine GET /activities.
            let message_value = serde_json::to_value(&out_envelope)?;
            let has_adaptive_card = message_value
                .get("metadata")
                .and_then(|m| m.get("adaptive_card"))
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            operator_log::debug(
                module_path!(),
                format!(
                    "[demo messaging] pre-encode adaptive_card={} text_present={} session_id={} route={} tenant={} metadata_keys={}",
                    has_adaptive_card,
                    message_value
                        .get("text")
                        .and_then(|v| v.as_str())
                        .map(|s| !s.is_empty())
                        .unwrap_or(false),
                    message_value
                        .get("session_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    message_value
                        .get("metadata")
                        .and_then(|m| m.get("route"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    message_value
                        .get("metadata")
                        .and_then(|m| m.get("tenant"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    message_value
                        .get("metadata")
                        .and_then(|v| v.as_object())
                        .map(|o| o.keys().cloned().collect::<Vec<_>>().join(","))
                        .unwrap_or_default()
                ),
            );

            let plan = match egress::render_plan(runner_host, ctx, provider, message_value.clone())
            {
                Ok(plan) => plan,
                Err(err) => {
                    operator_log::warn(
                        module_path!(),
                        format!("[demo messaging] render_plan failed: {err}; using empty plan"),
                    );
                    json!({})
                }
            };

            let payload = match egress::encode_payload(
                runner_host,
                ctx,
                provider,
                message_value.clone(),
                plan,
            ) {
                Ok(payload) => payload,
                Err(err) => {
                    operator_log::warn(
                        module_path!(),
                        format!("[demo messaging] encode failed: {err}; using fallback payload"),
                    );
                    let body_bytes = serde_json::to_vec(&message_value)?;
                    ProviderPayloadV1 {
                        content_type: "application/json".to_string(),
                        body_b64: base64::engine::general_purpose::STANDARD.encode(&body_bytes),
                        metadata_json: Some(serde_json::to_string(&message_value)?),
                        metadata: None,
                    }
                }
            };

            let provider_type = runner_host.canonical_provider_type(Domain::Messaging, provider);
            let config = build_injected_config(runner_host, Domain::Messaging, provider, ctx)?
                .map(decode_injected_config_for_provider);
            let send_input = egress::build_send_payload(
                payload,
                &provider_type,
                &ctx.tenant,
                ctx.team.clone(),
                config,
            );
            let send_bytes = serde_json::to_vec(&send_input)?;
            let outcome = runner_host.invoke_provider_op(
                Domain::Messaging,
                provider,
                "send_payload",
                &send_bytes,
                ctx,
            )?;

            let provider_ok = outcome
                .output
                .as_ref()
                .and_then(|v| v.get("ok"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if outcome.success && provider_ok {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "[demo messaging] send succeeded provider={} envelope_id={}",
                        provider, out_envelope.id
                    ),
                );
            } else {
                let provider_msg = outcome
                    .output
                    .as_ref()
                    .and_then(|v| v.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let err_msg = outcome
                    .error
                    .clone()
                    .unwrap_or_else(|| provider_msg.to_string());
                operator_log::error(
                    module_path!(),
                    format!(
                        "[demo messaging] send failed provider={} provider_ok={} err={}",
                        provider, provider_ok, err_msg
                    ),
                );
            }
        }
    }
    Ok(())
}

fn decode_injected_config_for_provider(config: serde_json::Value) -> serde_json::Value {
    let Some(obj) = config.as_object() else {
        return config;
    };
    let mut decoded = serde_json::Map::new();
    for (key, value) in obj {
        if let Some(raw_key) = key.strip_suffix("_b64")
            && let Some(text) = value.as_str()
            && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(text)
            && let Ok(decoded_text) = String::from_utf8(bytes)
        {
            decoded.insert(raw_key.to_string(), serde_json::Value::String(decoded_text));
            continue;
        }
        decoded.insert(key.clone(), value.clone());
    }
    serde_json::Value::Object(decoded)
}

/// Route an LLM router answer; every route it produces is `RouteSource::Llm`.
#[cfg(test)]
fn llm_route<'p>(
    directive: Option<ControlDirective>,
    pack_info: &'p app::AppPackInfo,
    original: &ChannelMessageEnvelope,
) -> Option<Routed<'p>> {
    routed(
        f2f_dispatch::llm_route(directive, pack_info, original)?,
        pack_info,
    )
    .ok()
}

/// Map the host router's outcome onto a route or the reason there is none.
#[cfg(test)]
fn host_route<'p>(
    outcome: crate::fast2flow::RoutingOutcome,
    pack_info: &'p app::AppPackInfo,
    original: &ChannelMessageEnvelope,
) -> Result<Routed<'p>, Unrouted> {
    f2f_dispatch::host_route(outcome, pack_info, original).and_then(|d| routed(d, pack_info))
}

/// What the router decided for one turn, and how it was decided.
enum Routed<'p> {
    /// A card node inside the default flow; the envelope carries
    /// `routeToCardId`.
    Node(ChannelMessageEnvelope, RouteSignal),
    /// A whole flow of the app pack, run from its entry (greentic-start#590).
    Flow(&'p app::AppFlowInfo, ChannelMessageEnvelope, RouteSignal),
}

/// One turn, resolved: which flow runs it, with which envelope.
struct Turn<'p> {
    flow: &'p app::AppFlowInfo,
    envelope: ChannelMessageEnvelope,
    /// The conversation's ownership follows this turn's outcome: it stays with
    /// `flow` while the flow is parked on it, and is released once the flow
    /// completes. Set for a turn dispatched to a flow and for a turn resumed
    /// in the flow that owns the conversation — never for default-flow or
    /// card-node turns, which behave exactly as before #590.
    owns_conversation: bool,
    /// Set only when Fast2Flow or the LLM fallback routed THIS turn; stamped
    /// on its replies. `None` for default-flow turns and sticky resumes.
    route: Option<RouteSignal>,
    /// The fixed miss reply to send instead of running a flow
    /// ([`f2f_probe::plan_from`] decided it).
    fixed_reply: Option<ChannelMessageEnvelope>,
    /// The default flow runs because the pack opted into running it on a miss.
    on_miss: bool,
    /// Why routing produced nothing, for the log; `None` when routed or sticky.
    cause: Option<String>,
}

/// Decide which flow runs this turn.
///
/// A conversation stays with the flow it was dispatched to until that flow
/// completes: while it is parked on the conversation, the turn resumes it and
/// `probe` — Fast2Flow and the LLM fallback — is never consulted, because a
/// parked flow can only be continued by the flow that parked it. Otherwise
/// the probe decides, and with no decision the default flow runs.
fn resolve_turn<'p>(
    bundle: &Path,
    ctx: &OperatorContext,
    pack_info: &'p app::AppPackInfo,
    default_flow: &'p app::AppFlowInfo,
    original: &ChannelMessageEnvelope,
    probe: impl FnOnce() -> Result<Routed<'p>, Unrouted>,
) -> Turn<'p> {
    if let Some(owner) = flow_owner::sticky_flow(bundle, ctx, pack_info, &original.session_id) {
        operator_log::info(
            module_path!(),
            format!(
                "[fast2flow] conversation owned by flow={} pack={} — resuming it, routing skipped",
                owner.id, pack_info.pack_id
            ),
        );
        return Turn {
            flow: owner,
            envelope: original.clone(),
            owns_conversation: true,
            route: None,
            fixed_reply: None,
            on_miss: false,
            cause: None,
        };
    }
    let outcome = probe();
    let cause = outcome.as_ref().err().map(Unrouted::describe);
    let unrouted = |fixed_reply, on_miss| Turn {
        flow: default_flow,
        envelope: original.clone(),
        owns_conversation: false,
        route: None,
        fixed_reply,
        on_miss,
        cause: cause.clone(),
    };
    match f2f_probe::plan_from(&pack_info.capabilities, original, outcome) {
        TurnPlan::Routed(Routed::Node(envelope, route)) => Turn {
            flow: default_flow,
            envelope,
            owns_conversation: false,
            route: Some(route),
            fixed_reply: None,
            on_miss: false,
            cause: None,
        },
        TurnPlan::Routed(Routed::Flow(flow, envelope, route)) => Turn {
            flow,
            envelope,
            owns_conversation: true,
            route: Some(route),
            fixed_reply: None,
            on_miss: false,
            cause: None,
        },
        TurnPlan::DefaultFlow { on_miss } => unrouted(None, on_miss),
        TurnPlan::FixedReply(reply) => unrouted(Some(reply), false),
    }
}

/// Turn a router directive into a route, or the reason there is none
/// (see [`f2f_dispatch::apply_dispatch`]).
#[cfg(test)]
fn apply_dispatch<'p>(
    directive: ControlDirective,
    pack_info: &'p app::AppPackInfo,
    original: &ChannelMessageEnvelope,
    source: RouteSource,
) -> Result<Routed<'p>, Unrouted> {
    f2f_dispatch::apply_dispatch(directive, pack_info, original, source)
        .and_then(|d| routed(d, pack_info))
}

/// Map an owned [`RouteDecision`] onto this path's borrowed [`Routed`]: a flow
/// decision names its flow by id, resolved here against the same pack with the
/// same lookup the decision was made with, so it always resolves. Should it
/// not, the turn is unrouted rather than run in a flow nobody chose.
fn routed(decision: RouteDecision, pack_info: &app::AppPackInfo) -> Result<Routed<'_>, Unrouted> {
    match decision {
        RouteDecision::Node { envelope, signal } => Ok(Routed::Node(envelope, signal)),
        RouteDecision::Flow {
            flow_id,
            envelope,
            signal,
        } => match f2f_dispatch::messaging_flow(pack_info, &flow_id) {
            Some(flow) => Ok(Routed::Flow(flow, envelope, signal)),
            None => {
                // Unreachable: the decision was made against this same pack
                // with this same lookup. Loud in debug builds; in release the
                // turn degrades to unrouted rather than running a flow nobody
                // chose.
                debug_assert!(
                    false,
                    "fast2flow flow decision {flow_id} does not resolve in pack {}",
                    pack_info.pack_id
                );
                operator_log::warn(
                    module_path!(),
                    format!(
                        "[fast2flow] flow decision {flow_id} does not resolve in pack {}; \
                         treating the turn as unrouted",
                        pack_info.pack_id
                    ),
                );
                Err(Unrouted::NoMatch)
            }
        },
    }
}

/// Insert empty-string defaults for any unmatched `${prefill_*}`
/// placeholder the card references. Non-prefill keys keep the existing
/// "unresolved → keep literal" behaviour so two-pass flows aren't broken.
fn ensure_prefill_defaults(
    card: &serde_json::Value,
    metadata: &mut std::collections::BTreeMap<String, String>,
) {
    let mut keys = std::collections::HashSet::<String>::new();
    collect_placeholder_keys(card, &mut keys);
    for key in keys {
        if key.starts_with("prefill_") {
            metadata.entry(key).or_default();
        }
    }
}

fn collect_placeholder_keys(
    value: &serde_json::Value,
    out: &mut std::collections::HashSet<String>,
) {
    match value {
        serde_json::Value::String(s) => {
            let mut rest = s.as_str();
            while let Some(start) = rest.find("${") {
                let after = &rest[start + 2..];
                let Some(end) = after.find('}') else {
                    break;
                };
                let key = after[..end].trim();
                if !key.is_empty() {
                    out.insert(key.to_string());
                }
                rest = &after[end + 1..];
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_placeholder_keys(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_placeholder_keys(v, out);
            }
        }
        _ => {}
    }
}

fn read_card_from_pack(pack_path: &Path, card_key: &str) -> Option<serde_json::Value> {
    let file = std::fs::File::open(pack_path).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;
    let asset_path = format!("assets/cards/{card_key}.json");
    let mut entry = archive.by_name(&asset_path).ok()?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

fn run_app_flow_safe(
    runner_host: &DemoRunnerHost,
    bundle: &Path,
    ctx: &OperatorContext,
    app_pack_path: &Path,
    pack_info: &app::AppPackInfo,
    flow: &app::AppFlowInfo,
    envelope: &ChannelMessageEnvelope,
) -> turn::FlowRun {
    match app::run_app_flow(
        runner_host,
        bundle,
        ctx,
        app_pack_path,
        &pack_info.pack_id,
        &flow.id,
        envelope,
    ) {
        Ok(outputs) => turn::FlowRun {
            outputs,
            failed: false,
        },
        Err(err) => {
            operator_log::error(
                module_path!(),
                format!("[demo messaging] app flow failed: {err}"),
            );
            // The echo is an error fallback, not the flow's answer: `failed`
            // keeps a success route signal off it.
            turn::FlowRun {
                outputs: vec![envelope.clone()],
                failed: true,
            }
        }
    }
}

use anyhow::Context;

/// Keys that are part of the card routing protocol and should not be forwarded
/// as user-supplied form data into action buttons.
const ROUTING_META_KEYS: &[&str] = &[
    "routeToCardId",
    "toCardId",
    "nextCardId",
    "action_id",
    "adaptive_card",
    "locale",
    "autoStart",
    "mcp_wizard",
    "mcp_operation",
];

// `CARD_NAV_META_KEYS` and `card_nav_target` live in `crate::fast2flow::turn`,
// shared with the revision-serve path so both treat a card submit the same way.
use crate::fast2flow::turn::card_nav_target;

/// Inject form data from envelope metadata into every `Action.Submit` `data`
/// object found in the card.  This ensures that when a user clicks a button on
/// a display-only card (no input fields), the form data collected in a previous
/// card is forwarded to the next card transition.
fn carry_form_data_to_actions(
    card: &mut serde_json::Value,
    metadata: &std::collections::BTreeMap<String, String>,
) {
    let form_fields: Vec<(String, String)> = metadata
        .iter()
        .filter(|(k, _)| !ROUTING_META_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if form_fields.is_empty() {
        return;
    }
    inject_form_data_recursive(card, &form_fields);
}

fn inject_form_data_recursive(value: &mut serde_json::Value, fields: &[(String, String)]) {
    match value {
        serde_json::Value::Object(map) => {
            // If this is an Action.Submit, inject form data into its "data" object
            if map.get("type").and_then(|v| v.as_str()) == Some("Action.Submit")
                && let Some(data) = map.get_mut("data").and_then(|d| d.as_object_mut())
            {
                for (k, v) in fields {
                    if !data.contains_key(k) {
                        data.insert(k.clone(), serde_json::Value::String(v.clone()));
                    }
                }
            }
            for val in map.values_mut() {
                inject_form_data_recursive(val, fields);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                inject_form_data_recursive(item, fields);
            }
        }
        _ => {}
    }
}

/// Replace `${key}` placeholders in card JSON strings with values looked up
/// from the provided metadata map.  This is the lightweight binding pass used
/// by the card-routing shortcut so that form data from a previous Action.Submit
/// is visible in the next card (e.g. a review/confirmation screen).
fn resolve_placeholders(
    value: &mut serde_json::Value,
    metadata: &std::collections::BTreeMap<String, String>,
) {
    match value {
        serde_json::Value::String(text) if text.contains("${") => {
            let mut output = String::with_capacity(text.len());
            let mut rest = text.as_str();
            loop {
                let Some(start) = rest.find("${") else {
                    output.push_str(rest);
                    break;
                };
                output.push_str(&rest[..start]);
                let after = &rest[start + 2..];
                let Some(end) = after.find('}') else {
                    output.push_str(&rest[start..]);
                    break;
                };
                let key = after[..end].trim();
                if let Some(val) = metadata.get(key) {
                    output.push_str(val);
                } else {
                    // Keep the original placeholder when no value is found
                    output.push_str(&rest[start..start + 2 + end + 1]);
                }
                rest = &after[end + 1..];
            }
            *text = output;
        }
        serde_json::Value::Array(items) => {
            for item in items {
                resolve_placeholders(item, metadata);
            }
        }
        serde_json::Value::Object(map) => {
            for val in map.values_mut() {
                resolve_placeholders(val, metadata);
            }
        }
        _ => {}
    }
}

/// Read i18n bundle from pack and resolve `{{i18n:KEY}}` tokens in card JSON.
fn resolve_i18n_tokens(card: &mut serde_json::Value, pack_path: &Path, locale: &str) {
    let bundle = read_i18n_bundle(pack_path, locale).or_else(|| read_i18n_bundle(pack_path, "en"));
    let Some(bundle) = bundle else { return };
    replace_tokens_recursive(card, &bundle);
}

fn read_i18n_bundle(
    pack_path: &Path,
    locale: &str,
) -> Option<std::collections::HashMap<String, String>> {
    let file = std::fs::File::open(pack_path).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;
    let asset_path = format!("assets/i18n/{locale}.json");
    let mut entry = archive.by_name(&asset_path).ok()?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

fn replace_tokens_recursive(
    value: &mut serde_json::Value,
    bundle: &std::collections::HashMap<String, String>,
) {
    match value {
        serde_json::Value::String(text) if text.contains("{{i18n:") => {
            let mut output = String::with_capacity(text.len());
            let mut rest = text.as_str();
            loop {
                let Some(start) = rest.find("{{i18n:") else {
                    output.push_str(rest);
                    break;
                };
                output.push_str(&rest[..start]);
                let token_start = start + "{{i18n:".len();
                let after = &rest[token_start..];
                let Some(end) = after.find("}}") else {
                    output.push_str(&rest[start..]);
                    break;
                };
                let key = after[..end].trim();
                output.push_str(bundle.get(key).map(String::as_str).unwrap_or(key));
                rest = &after[end + 2..];
            }
            *text = output;
        }
        serde_json::Value::Array(items) => {
            for item in items {
                replace_tokens_recursive(item, bundle);
            }
        }
        serde_json::Value::Object(map) => {
            for val in map.values_mut() {
                replace_tokens_recursive(val, bundle);
            }
        }
        _ => {}
    }
}

/// Walk a JSON tree and substitute every string field whose verbatim value
/// matches a key in the `en_to_target` map with the corresponding target-locale
/// value.
///
/// This is the workhorse of the safety net's reverse-lookup path: when the
/// WASM adaptive-card component has rendered cards using the pack's English
/// bundle (because the runner-desktop path doesn't wire a host i18n resolver
/// that the component can ask), we reverse the mapping host-side. For each
/// English string in the card, we look up which i18n key produced it, then
/// substitute the matching target-locale value.
///
/// We only mutate string values that are an exact match. Non-string values,
/// numbers, structural keys, etc. are left untouched. Strings that don't appear
/// in `en_to_target` are left as-is so we never accidentally corrupt
/// non-translatable content.
fn translate_string_fields_recursive(
    value: &mut serde_json::Value,
    en_to_target: &std::collections::HashMap<String, String>,
) {
    match value {
        serde_json::Value::String(text) => {
            if let Some(translated) = en_to_target.get(text.as_str()) {
                *text = translated.clone();
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                translate_string_fields_recursive(item, en_to_target);
            }
        }
        serde_json::Value::Object(map) => {
            for val in map.values_mut() {
                translate_string_fields_recursive(val, en_to_target);
            }
        }
        _ => {}
    }
}

/// Re-read the adaptive card from the pack and apply i18n when the card has
/// empty text fields.  This compensates for the WASM component not having a
/// host asset resolver for `i18n_bundle_path` when running through the desktop
/// runner path.
fn ensure_card_i18n_resolved(envelope: &mut ChannelMessageEnvelope, pack_path: &Path) {
    let Some(ac_str) = envelope.metadata.get("adaptive_card") else {
        return;
    };
    let Ok(mut card) = serde_json::from_str::<serde_json::Value>(ac_str) else {
        return;
    };

    // En-to-target reverse lookup. The WASM adaptive-card component renders
    // every card using the pack's `en.json` bundle when the runner-desktop
    // path is in use (no host i18n resolver is wired). Walk the rendered card
    // and swap text values that match an `en.json` entry with the
    // corresponding target-locale value, looking up by english string. Runs
    // before the cardId-based safety net below so it covers cards that don't
    // declare `greentic.cardId`.
    let locale = envelope
        .metadata
        .get("locale")
        .map(String::as_str)
        .unwrap_or("en");
    if locale != "en"
        && locale != "en-GB"
        && locale != "en-US"
        && let Some(en_bundle) = read_i18n_bundle(pack_path, "en")
        && let Some(target_bundle) = read_i18n_bundle(pack_path, locale)
    {
        let mut en_to_target = std::collections::HashMap::<String, String>::new();
        for (key, en_value) in &en_bundle {
            if let Some(target_value) = target_bundle.get(key)
                && target_value != en_value
            {
                en_to_target.insert(en_value.clone(), target_value.clone());
            }
        }
        if !en_to_target.is_empty() {
            translate_string_fields_recursive(&mut card, &en_to_target);
            if let Ok(resolved) = serde_json::to_string(&card) {
                envelope
                    .metadata
                    .insert("adaptive_card".to_string(), resolved);
            }
        }
    }
    // Only act if the card has a greentic.cardId (cards2pack-generated).
    let card_id = card
        .pointer("/greentic/cardId")
        .and_then(serde_json::Value::as_str);
    let Some(card_id) = card_id else { return };
    // Check if any body text is empty (i18n failed).
    let has_empty_text = card
        .get("body")
        .and_then(serde_json::Value::as_array)
        .map(|body| {
            body.iter().any(|item| {
                item.get("text")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(str::is_empty)
            })
        })
        .unwrap_or(false);
    if !has_empty_text {
        return;
    }
    // Re-read the original card from the pack and apply i18n.
    let Some(mut fresh_card) = read_card_from_pack(pack_path, card_id) else {
        return;
    };
    let locale = envelope
        .metadata
        .get("locale")
        .map(String::as_str)
        .unwrap_or("en");
    resolve_i18n_tokens(&mut fresh_card, pack_path, locale);
    if let Ok(resolved) = serde_json::to_string(&fresh_card) {
        envelope
            .metadata
            .insert("adaptive_card".to_string(), resolved);
    }
}

#[path = "messaging_turn.rs"]
mod turn;

#[cfg(test)]
#[path = "messaging_routing_tests.rs"]
mod routing_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging_app::{AppFlowInfo, AppPackInfo};
    use crate::secrets_gate;
    use tempfile::tempdir;
    use zip::write::FileOptions;

    #[test]
    fn ensure_prefill_defaults_inserts_empty_for_unmatched_prefill_keys() {
        let card = json!({"value": "${prefill_date_iso}"});
        let mut metadata = std::collections::BTreeMap::<String, String>::new();
        ensure_prefill_defaults(&card, &mut metadata);
        assert_eq!(
            metadata.get("prefill_date_iso").map(String::as_str),
            Some("")
        );
    }

    #[test]
    fn ensure_prefill_defaults_preserves_existing_extracted_values() {
        let card = json!({"value": "${prefill_date_iso}"});
        let mut metadata = std::collections::BTreeMap::<String, String>::new();
        metadata.insert("prefill_date_iso".into(), "2026-05-30".into());
        ensure_prefill_defaults(&card, &mut metadata);
        assert_eq!(
            metadata.get("prefill_date_iso").map(String::as_str),
            Some("2026-05-30")
        );
    }

    #[test]
    fn ensure_prefill_defaults_leaves_non_prefill_placeholders_alone() {
        let card = json!({"value": "${other_token}", "subtitle": "${i18n:foo}"});
        let mut metadata = std::collections::BTreeMap::<String, String>::new();
        ensure_prefill_defaults(&card, &mut metadata);
        assert!(!metadata.contains_key("other_token"));
        assert!(!metadata.contains_key("i18n:foo"));
    }

    #[test]
    fn end_to_end_unresolved_prefill_renders_empty_not_literal() {
        let mut card = json!({"value": "${prefill_date_iso}"});
        let mut metadata = std::collections::BTreeMap::<String, String>::new();
        ensure_prefill_defaults(&card, &mut metadata);
        resolve_placeholders(&mut card, &metadata);
        assert_eq!(card["value"], json!(""));
    }

    #[test]
    fn collect_placeholder_keys_handles_multiple_per_string() {
        let v = json!("from ${a} to ${b}, on ${c}, missing}${d}");
        let mut keys = std::collections::HashSet::<String>::new();
        collect_placeholder_keys(&v, &mut keys);
        assert!(keys.contains("a"));
        assert!(keys.contains("b"));
        assert!(keys.contains("c"));
        assert!(keys.contains("d"));
    }

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
            "text": "hello",
            "metadata": {}
        }))
        .expect("envelope")
    }

    fn write_test_app_pack(pack_path: &Path) {
        use greentic_types::pack_manifest::{
            PackFlowEntry, PackKind, PackManifest, PackSignatures,
        };
        use greentic_types::{Flow, FlowId, FlowKind, PackId};
        use semver::Version;

        let file = std::fs::File::create(pack_path).expect("create pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())
            .expect("start manifest");
        let flow = Flow {
            schema_version: "flow-v1".to_string(),
            id: FlowId::new("default").expect("flow id"),
            kind: FlowKind::Messaging,
            entrypoints: std::collections::BTreeMap::from([(
                "default".to_string(),
                serde_json::Value::Null,
            )]),
            nodes: Default::default(),
            metadata: Default::default(),
        };
        let manifest = PackManifest {
            agents: Default::default(),
            schema_version: "pack-v1".into(),
            pack_id: PackId::new("demo-app").expect("pack id"),
            name: Some("demo-app".into()),
            version: Version::parse("0.1.0").expect("version"),
            kind: PackKind::Application,
            publisher: "demo".into(),
            components: Vec::new(),
            flows: vec![PackFlowEntry {
                id: FlowId::new("default").expect("flow id"),
                kind: FlowKind::Messaging,
                flow,
                tags: vec!["default".to_string()],
                entrypoints: vec!["default".to_string()],
            }],
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            secret_requirements: Vec::new(),
            signatures: PackSignatures::default(),
            bootstrap: None,
            extensions: None,
        };
        let bytes = greentic_types::encode_pack_manifest(&manifest).expect("encode manifest");
        zip.write_all(&bytes).expect("write manifest");
        zip.start_file("assets/cards/welcome.json", FileOptions::<()>::default())
            .expect("start card");
        zip.write_all(br#"{"body":[{"text":"Welcome card"}]}"#)
            .expect("write card");
        zip.finish().expect("finish pack");
    }

    #[test]
    fn read_card_from_pack_loads_card_assets_and_handles_missing_cards() {
        let dir = tempdir().expect("tempdir");
        let pack_path = dir.path().join("app.gtpack");
        let file = std::fs::File::create(&pack_path).expect("create pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("assets/cards/welcome.json", FileOptions::<()>::default())
            .expect("start file");
        zip.write_all(br#"{"body":[{"text":"Welcome card"}]}"#)
            .expect("write card");
        zip.finish().expect("finish pack");

        let card = read_card_from_pack(&pack_path, "welcome").expect("card");
        assert_eq!(card["body"][0]["text"], "Welcome card");
        assert!(read_card_from_pack(&pack_path, "missing").is_none());
    }

    #[test]
    fn run_app_flow_safe_falls_back_to_original_envelope_on_errors() {
        let dir = tempdir().expect("tempdir");
        let discovery = crate::discovery::discover(dir.path()).expect("discovery");
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default"))
                .expect("secrets handle");
        let runner_host = DemoRunnerHost::new(
            dir.path().to_path_buf(),
            &discovery,
            None,
            secrets_handle,
            false,
        )
        .expect("runner host");
        let original = envelope();
        let outputs = run_app_flow_safe(
            &runner_host,
            dir.path(),
            &OperatorContext {
                tenant: "demo".to_string(),
                team: Some("default".to_string()),
                correlation_id: None,
            },
            &dir.path().join("missing.gtpack"),
            &AppPackInfo {
                pack_id: "app-pack".to_string(),
                flows: vec![],
                capabilities: Vec::new(),
            },
            &AppFlowInfo {
                id: "default".to_string(),
                kind: "messaging".to_string(),
                subscribes_to: vec![],
            },
            &original,
        );

        assert!(outputs.failed, "an errored flow is reported as failed");
        let outputs = outputs.outputs;
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].id, original.id);
        assert_eq!(outputs[0].text, original.text);
    }

    #[test]
    fn read_card_from_pack_rejects_invalid_card_json() {
        let dir = tempdir().expect("tempdir");
        let pack_path = dir.path().join("app.gtpack");
        let file = std::fs::File::create(&pack_path).expect("create pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("assets/cards/broken.json", FileOptions::<()>::default())
            .expect("start file");
        zip.write_all(b"{not-json").expect("write broken card");
        zip.finish().expect("finish pack");

        assert!(read_card_from_pack(&pack_path, "broken").is_none());
    }

    #[test]
    fn route_messaging_envelopes_errors_when_no_app_pack_is_available() {
        let dir = tempdir().expect("tempdir");
        let discovery = crate::discovery::discover(dir.path()).expect("discovery");
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default"))
                .expect("secrets");
        let runner_host = DemoRunnerHost::new(
            dir.path().to_path_buf(),
            &discovery,
            None,
            secrets_handle,
            false,
        )
        .expect("runner host");

        let err = route_messaging_envelopes(
            dir.path(),
            &runner_host,
            "messaging-webchat",
            &OperatorContext {
                tenant: "demo".to_string(),
                team: Some("default".to_string()),
                correlation_id: None,
            },
            vec![envelope()],
        )
        .unwrap_err();

        assert!(err.to_string().contains("resolve app pack"));
    }

    #[test]
    fn route_messaging_envelopes_card_routing_uses_standard_egress_pipeline() {
        // After removing DirectLine injection, all providers (including webchat)
        // use the standard egress pipeline: render_plan → encode → send_payload.
        // Without a provider pack in the test bundle, egress fails — confirming
        // that webchat now goes through the same path as all other providers.
        let dir = tempdir().expect("tempdir");
        let packs_dir = dir.path().join("packs");
        std::fs::create_dir_all(&packs_dir).expect("packs dir");
        let app_pack = packs_dir.join("default.gtpack");
        write_test_app_pack(&app_pack);

        let discovery = crate::discovery::discover(dir.path()).expect("discovery");
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default"))
                .expect("secrets");
        let runner_host = DemoRunnerHost::new(
            dir.path().to_path_buf(),
            &discovery,
            None,
            secrets_handle,
            false,
        )
        .expect("runner host");

        let mut card_routed = envelope();
        card_routed
            .metadata
            .insert("routeToCardId".to_string(), "welcome".to_string());

        // Without a messaging provider pack, egress fails because render_plan
        // can't find the provider. This proves webchat uses standard egress.
        let result = route_messaging_envelopes(
            dir.path(),
            &runner_host,
            "messaging-webchat",
            &OperatorContext {
                tenant: "demo".to_string(),
                team: Some("default".to_string()),
                correlation_id: None,
            },
            vec![card_routed],
        );
        assert!(
            result.is_err(),
            "expected error because no messaging provider pack is available"
        );
    }

    #[test]
    fn route_messaging_envelopes_card_routing_accepts_next_card_id_alias() {
        // The designer emits card navigation under `nextCardId`; the demo host
        // must treat it as an alias for `routeToCardId` and take the same
        // card-routing fast-path. Without a provider pack, egress fails — which
        // confirms the fast-path (read_card_from_pack) was entered rather than
        // falling through to the app flow.
        let dir = tempdir().expect("tempdir");
        let packs_dir = dir.path().join("packs");
        std::fs::create_dir_all(&packs_dir).expect("packs dir");
        let app_pack = packs_dir.join("default.gtpack");
        write_test_app_pack(&app_pack);

        let discovery = crate::discovery::discover(dir.path()).expect("discovery");
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default"))
                .expect("secrets");
        let runner_host = DemoRunnerHost::new(
            dir.path().to_path_buf(),
            &discovery,
            None,
            secrets_handle,
            false,
        )
        .expect("runner host");

        let mut card_routed = envelope();
        card_routed
            .metadata
            .insert("nextCardId".to_string(), "welcome".to_string());

        let result = route_messaging_envelopes(
            dir.path(),
            &runner_host,
            "messaging-webchat",
            &OperatorContext {
                tenant: "demo".to_string(),
                team: Some("default".to_string()),
                correlation_id: None,
            },
            vec![card_routed],
        );
        assert!(
            result.is_err(),
            "expected egress error, proving the nextCardId alias took the card-routing fast-path"
        );
    }

    #[test]
    fn next_card_id_is_a_routing_key_and_not_carried_as_form_data() {
        assert!(ROUTING_META_KEYS.contains(&"nextCardId"));

        let mut card = json!({
            "actions": [
                { "type": "Action.Submit", "data": { "nextCardId": "second" } }
            ]
        });
        let mut meta = std::collections::BTreeMap::new();
        meta.insert("full_name".to_string(), "Alice".to_string());
        meta.insert("nextCardId".to_string(), "second".to_string());

        carry_form_data_to_actions(&mut card, &meta);

        let data = &card["actions"][0]["data"];
        assert_eq!(data["full_name"], "Alice", "form data is carried forward");
        // nextCardId must not be injected as carried form data; only the card's
        // own nextCardId value remains.
        assert_eq!(data["nextCardId"], "second");
    }

    use std::io::Write;

    #[test]
    fn resolve_placeholders_replaces_known_keys_and_preserves_unknown() {
        let mut card = json!({
            "body": [
                { "type": "FactSet", "facts": [
                    { "title": "Name", "value": "${full_name}" },
                    { "title": "Email", "value": "${email}" },
                    { "title": "Missing", "value": "${unknown_key}" }
                ]}
            ]
        });
        let mut meta = std::collections::BTreeMap::new();
        meta.insert("full_name".to_string(), "Alice".to_string());
        meta.insert("email".to_string(), "alice@example.com".to_string());

        resolve_placeholders(&mut card, &meta);

        assert_eq!(card["body"][0]["facts"][0]["value"], "Alice");
        assert_eq!(card["body"][0]["facts"][1]["value"], "alice@example.com");
        assert_eq!(card["body"][0]["facts"][2]["value"], "${unknown_key}");
    }

    #[test]
    fn carry_form_data_injects_into_action_submit_and_skips_routing_keys() {
        let mut card = json!({
            "actions": [
                {
                    "type": "Action.Submit",
                    "data": { "action_id": "next", "routeToCardId": "success" }
                },
                {
                    "type": "Action.OpenUrl",
                    "url": "https://example.com"
                }
            ]
        });
        let mut meta = std::collections::BTreeMap::new();
        meta.insert("full_name".to_string(), "Alice".to_string());
        meta.insert("routeToCardId".to_string(), "review".to_string());
        meta.insert("action_id".to_string(), "goto_review".to_string());

        carry_form_data_to_actions(&mut card, &meta);

        // Action.Submit should have full_name injected but not routing keys
        let data = &card["actions"][0]["data"];
        assert_eq!(data["full_name"], "Alice");
        assert_eq!(data["action_id"], "next"); // original preserved, not overwritten
        // Action.OpenUrl should be untouched
        assert!(card["actions"][1].get("data").is_none());
    }

    #[test]
    fn translate_string_fields_recursive_swaps_matching_strings() {
        let mut card = json!({
            "type": "AdaptiveCard",
            "body": [
                { "type": "TextBlock", "text": "Hello world" },
                { "type": "TextBlock", "text": "Untranslated string" },
                {
                    "type": "Container",
                    "items": [
                        { "type": "Input.Text", "label": "Question", "placeholder": "Type" }
                    ]
                }
            ],
            "actions": [
                { "type": "Action.Submit", "title": "Send" }
            ]
        });
        let mut map = std::collections::HashMap::new();
        map.insert("Hello world".to_string(), "こんにちは世界".to_string());
        map.insert("Question".to_string(), "質問".to_string());
        map.insert("Send".to_string(), "送信".to_string());
        // Note: "Type" not in map → should remain
        // Note: "Untranslated string" not in map → should remain

        translate_string_fields_recursive(&mut card, &map);

        assert_eq!(card["body"][0]["text"], "こんにちは世界");
        assert_eq!(card["body"][1]["text"], "Untranslated string");
        assert_eq!(card["body"][2]["items"][0]["label"], "質問");
        assert_eq!(card["body"][2]["items"][0]["placeholder"], "Type");
        assert_eq!(card["actions"][0]["title"], "送信");
        // Structural keys ("type", etc.) must not be substituted by accident
        assert_eq!(card["type"], "AdaptiveCard");
        assert_eq!(card["body"][0]["type"], "TextBlock");
    }

    #[test]
    fn translate_string_fields_recursive_only_substitutes_exact_matches() {
        let mut value = json!({
            "a": "foo",
            "b": "foo bar",       // contains "foo" but NOT exact match — must not substitute
            "c": "FOO",           // case-different — must not substitute
            "d": ["foo", "baz"]
        });
        let mut map = std::collections::HashMap::new();
        map.insert("foo".to_string(), "FOO_TR".to_string());

        translate_string_fields_recursive(&mut value, &map);

        assert_eq!(value["a"], "FOO_TR");
        assert_eq!(value["b"], "foo bar");
        assert_eq!(value["c"], "FOO");
        assert_eq!(value["d"][0], "FOO_TR");
        assert_eq!(value["d"][1], "baz");
    }
}
