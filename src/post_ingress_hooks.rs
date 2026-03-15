use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use greentic_types::cbor::canonical;
use serde_json::{Value as JsonValue, json};

use crate::domains::{self, Domain, ProviderPack};
use crate::ingress::control_directive::{
    ControlDirective, DispatchTarget, IngressReply, try_parse_control_directive,
};
use crate::ingress_types::{IngressDispatchResult, IngressHttpResponse, IngressRequestV1};
use crate::offers::registry::{
    HOOK_CONTRACT_CONTROL_V1, HOOK_STAGE_POST_INGRESS, OfferRegistry, discover_gtpacks,
    load_pack_offers,
};
use crate::operator_log;
use crate::runner_exec::{self, RunRequest};
use crate::runner_host::{DemoRunnerHost, OperatorContext};

static OFFER_REGISTRY_CACHE: OnceLock<Mutex<BTreeMap<PathBuf, Arc<OfferRegistry>>>> =
    OnceLock::new();

pub fn apply_post_ingress_hooks_dispatch(
    bundle: &Path,
    runner_host: &DemoRunnerHost,
    domain: Domain,
    request: &IngressRequestV1,
    result: &mut IngressDispatchResult,
    ctx: &OperatorContext,
) -> anyhow::Result<()> {
    if domain == Domain::Events && !event_hooks_enabled() {
        return Ok(());
    }
    let mut body = HookIngressBody {
        request: serde_json::to_value(request)?,
        response_status: result.response.status,
        response_headers: result.response.headers.clone(),
        response_body: result.response.body.clone(),
        events: result
            .events
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?,
    };
    apply_post_ingress_hooks_json(
        bundle,
        runner_host,
        domain,
        request.provider.as_str(),
        &mut body,
        ctx,
    )?;
    result.response = IngressHttpResponse {
        status: body.response_status,
        headers: body.response_headers,
        body: body.response_body,
    };
    result.events = body
        .events
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| "hook output events were not valid ingress event envelopes")?;
    Ok(())
}

struct HookIngressBody {
    request: JsonValue,
    response_status: u16,
    response_headers: Vec<(String, String)>,
    response_body: Option<Vec<u8>>,
    events: Vec<JsonValue>,
}

fn apply_post_ingress_hooks_json(
    bundle: &Path,
    runner_host: &DemoRunnerHost,
    domain: Domain,
    provider: &str,
    body: &mut HookIngressBody,
    ctx: &OperatorContext,
) -> anyhow::Result<()> {
    if !hooks_enabled() {
        return Ok(());
    }
    let packs_root = bundle.join("packs");
    if !packs_root.exists() {
        return Ok(());
    }
    let refs = discover_gtpacks(&packs_root)?;
    if refs.is_empty() {
        return Ok(());
    }
    let registry = cached_offer_registry(&packs_root, &refs)?;
    emit_registry_loaded(&registry, provider, domain, ctx);
    let selected = registry.select_hooks(HOOK_STAGE_POST_INGRESS, HOOK_CONTRACT_CONTROL_V1);
    for offer in selected {
        emit_hook_invoked(offer, provider, domain, ctx);
        let payload = canonical::to_canonical_cbor(&json!({
            "stage": HOOK_STAGE_POST_INGRESS,
            "contract": HOOK_CONTRACT_CONTROL_V1,
            "provider": provider,
            "request": body.request.clone(),
            "response": {
                "status": body.response_status,
                "headers": body.response_headers.clone(),
                "body_b64": body.response_body.as_ref().map(|value| STANDARD.encode(value)),
            },
            "events": body.events.clone(),
            "tenant": ctx.tenant.clone(),
            "team": ctx.team.clone(),
            "correlation_id": ctx.correlation_id.clone(),
        }))
        .with_context(|| "encode hook post_ingress payload")?;

        let pack = offer_pack(offer.pack_ref.clone(), offer.pack_id.clone())?;
        let outcome = runner_host.invoke_provider_component_op_direct(
            domain,
            &pack,
            &offer.pack_id,
            &offer.provider_op,
            &payload,
            ctx,
        )?;
        if !outcome.success {
            operator_log::warn(
                module_path!(),
                format!(
                    "hook invocation failed offer_key={} err={}",
                    offer.offer_key,
                    outcome.error.unwrap_or_else(|| "unknown error".to_string())
                ),
            );
            continue;
        }
        let Some(output) = outcome.output else {
            continue;
        };
        let Some(directive) = try_parse_control_directive(&output) else {
            emit_hook_parse_error(offer, provider, domain, ctx, "missing_or_invalid_action");
            continue;
        };
        if matches!(directive, ControlDirective::Continue) {
            continue;
        }
        let action = directive_action(&directive);
        let action_target = directive_target_for_audit(&directive);
        match apply_control_directive(bundle, domain, body, ctx, directive) {
            Ok(()) => {
                emit_hook_applied(offer, provider, domain, ctx, action, action_target);
                break;
            }
            Err(err) => {
                emit_hook_parse_error(offer, provider, domain, ctx, &format!("apply_failed:{err}"));
                continue;
            }
        }
    }
    Ok(())
}

fn apply_control_directive(
    bundle: &Path,
    domain: Domain,
    body: &mut HookIngressBody,
    ctx: &OperatorContext,
    directive: ControlDirective,
) -> anyhow::Result<()> {
    apply_control_directive_with_dispatcher(
        bundle,
        domain,
        body,
        ctx,
        directive,
        dispatch_to_target,
    )
}

fn apply_control_directive_with_dispatcher<F>(
    bundle: &Path,
    domain: Domain,
    body: &mut HookIngressBody,
    ctx: &OperatorContext,
    directive: ControlDirective,
    mut dispatch_fn: F,
) -> anyhow::Result<()>
where
    F: FnMut(
        &Path,
        Domain,
        &HookIngressBody,
        &OperatorContext,
        &DispatchTarget,
    ) -> anyhow::Result<()>,
{
    match directive {
        ControlDirective::Continue => {}
        ControlDirective::Respond { reply } => apply_reply(body, reply, false)?,
        ControlDirective::Deny { reply } => apply_reply(body, reply, true)?,
        ControlDirective::Dispatch { target } => {
            dispatch_fn(bundle, domain, body, ctx, &target)?;
            body.response_status = 202;
            body.response_headers =
                vec![("content-type".to_string(), "application/json".to_string())];
            body.response_body = Some(serde_json::to_vec(&json!({
                "ok": true,
                "dispatched": true,
                "target": {
                    "tenant": target.tenant,
                    "team": target.team,
                    "pack": target.pack,
                    "flow": target.flow,
                    "node": target.node,
                }
            }))?);
            body.events.clear();
        }
    }
    Ok(())
}

fn apply_reply(
    body: &mut HookIngressBody,
    reply: IngressReply,
    deny_default: bool,
) -> anyhow::Result<()> {
    let status_default = if deny_default { 403 } else { 200 };
    body.response_status = reply.status_code.unwrap_or(status_default);
    body.response_headers.clear();
    if let Some(code) = reply.reason_code {
        body.response_headers
            .push(("x-reason-code".to_string(), code));
    }
    body.events.clear();
    if let Some(card) = reply.card_cbor {
        body.response_headers
            .push(("content-type".to_string(), "application/json".to_string()));
        let payload = if let Some(text) = reply.text {
            json!({ "text": text, "card": card })
        } else {
            json!({ "card": card })
        };
        body.response_body = Some(serde_json::to_vec(&payload)?);
        return Ok(());
    }
    if let Some(text) = reply.text {
        body.response_headers
            .push(("content-type".to_string(), "text/plain".to_string()));
        body.response_body = Some(text.into_bytes());
    } else {
        body.response_body = None;
    }
    Ok(())
}

fn dispatch_to_target(
    bundle: &Path,
    domain: Domain,
    body: &HookIngressBody,
    ctx: &OperatorContext,
    target: &DispatchTarget,
) -> anyhow::Result<()> {
    ensure_dispatch_target_safe(target)?;
    let pack_path = resolve_dispatch_pack_path(bundle, &target.pack)?;
    let meta = domains::read_pack_meta(&pack_path)?;
    let flow_id = match target.flow.as_deref() {
        Some(flow) => flow.to_string(),
        None => meta
            .entry_flows
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("dispatch target pack has no entry flows"))?,
    };
    let input = json!({
        "request": body.request,
        "response": {
            "status": body.response_status,
            "headers": body.response_headers,
            "body_b64": body.response_body.as_ref().map(|value| STANDARD.encode(value)),
        },
        "events": body.events,
        "hook_dispatch": {
            "tenant": target.tenant,
            "team": target.team,
            "pack": target.pack,
            "flow": target.flow,
            "node": target.node,
        }
    });
    let request = RunRequest {
        root: bundle.to_path_buf(),
        domain,
        pack_path: pack_path.clone(),
        pack_label: meta.pack_id,
        flow_id,
        tenant: target.tenant.clone(),
        team: target.team.clone().or_else(|| ctx.team.clone()),
        input,
        dist_offline: true,
    };
    runner_exec::run_provider_pack_flow(request)
        .with_context(|| format!("hook dispatch failed for {}", pack_path.display()))?;
    Ok(())
}

fn resolve_dispatch_pack_path(bundle: &Path, target_pack: &str) -> anyhow::Result<PathBuf> {
    let packs_root = bundle.join("packs");
    let candidates = [
        PathBuf::from(target_pack),
        packs_root.join(target_pack),
        packs_root.join(format!("{target_pack}.gtpack")),
    ];
    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    for path in discover_gtpacks(&packs_root)? {
        if path
            .file_stem()
            .and_then(|value| value.to_str())
            .map(|value| value == target_pack)
            .unwrap_or(false)
        {
            return Ok(path);
        }
        let parsed = load_pack_offers(&path)?;
        if parsed.pack_id == target_pack {
            return Ok(path);
        }
    }
    anyhow::bail!(
        "dispatch target pack {} not found under {}",
        target_pack,
        packs_root.display()
    );
}

fn offer_pack(path: PathBuf, pack_id: String) -> anyhow::Result<ProviderPack> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid offer pack file name: {}", path.display()))?
        .to_string();
    Ok(ProviderPack {
        pack_id,
        file_name,
        path,
        entry_flows: Vec::new(),
    })
}

fn cached_offer_registry(
    packs_root: &Path,
    refs: &[PathBuf],
) -> anyhow::Result<Arc<OfferRegistry>> {
    let cache = OFFER_REGISTRY_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut guard = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("offer registry cache lock poisoned"))?;
    if let Some(existing) = guard.get(packs_root) {
        return Ok(existing.clone());
    }
    let registry = Arc::new(OfferRegistry::from_pack_refs(refs)?);
    guard.insert(packs_root.to_path_buf(), registry.clone());
    Ok(registry)
}

fn hooks_enabled() -> bool {
    match std::env::var("GREENTIC_OPERATOR_HOOKS_ENABLED") {
        Ok(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            !(normalized == "0"
                || normalized == "false"
                || normalized == "no"
                || normalized == "off")
        }
        Err(_) => true,
    }
}

fn event_hooks_enabled() -> bool {
    match std::env::var("GREENTIC_OPERATOR_ENABLE_EVENT_HOOKS") {
        Ok(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on"
        }
        Err(_) => false,
    }
}

fn ensure_dispatch_target_safe(target: &DispatchTarget) -> anyhow::Result<()> {
    if !is_safe_segment(&target.tenant) {
        anyhow::bail!("invalid dispatch tenant '{}'", target.tenant);
    }
    if let Some(team) = target.team.as_deref()
        && !is_safe_segment(team)
    {
        anyhow::bail!("invalid dispatch team '{}'", team);
    }
    if !is_safe_segment(&target.pack) {
        anyhow::bail!("invalid dispatch pack '{}'", target.pack);
    }
    if let Some(flow) = target.flow.as_deref()
        && !is_safe_segment(flow)
    {
        anyhow::bail!("invalid dispatch flow '{}'", flow);
    }
    if let Some(node) = target.node.as_deref()
        && !is_safe_segment(node)
    {
        anyhow::bail!("invalid dispatch node '{}'", node);
    }
    Ok(())
}

fn is_safe_segment(value: &str) -> bool {
    if value.is_empty() || value == "." || value == ".." {
        return false;
    }
    !value.contains('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && !value.contains(':')
        && !value.starts_with('.')
}

fn emit_registry_loaded(
    registry: &OfferRegistry,
    provider: &str,
    domain: Domain,
    ctx: &OperatorContext,
) {
    let kind_counts = registry.kind_counts();
    let hooks = registry.hook_counts_by_stage_contract();
    let subs = registry.subs_counts_by_contract();
    let payload = json!({
        "event": "offer.registry.loaded",
        "domain": domain_name(domain),
        "provider": provider,
        "tenant": ctx.tenant,
        "team": ctx.team.as_deref().unwrap_or("default"),
        "correlation_id": ctx.correlation_id,
        "packs_total": registry.packs_total(),
        "offers_total": registry.offers_total(),
        "kind_counts": kind_counts,
        "hook_counts": hooks.iter().map(|(stage, contract, count)| json!({
            "stage": stage,
            "contract": contract,
            "count": count
        })).collect::<Vec<_>>(),
        "subs_counts": subs.iter().map(|(contract, count)| json!({
            "contract": contract,
            "count": count
        })).collect::<Vec<_>>(),
    });
    operator_log::info(module_path!(), payload.to_string());
}

fn emit_hook_invoked(
    offer: &crate::offers::registry::Offer,
    provider: &str,
    domain: Domain,
    ctx: &OperatorContext,
) {
    let payload = json!({
        "event": "hook.invoked",
        "offer_key": offer.offer_key,
        "pack_id": offer.pack_id,
        "offer_id": offer.id,
        "stage": HOOK_STAGE_POST_INGRESS,
        "contract": HOOK_CONTRACT_CONTROL_V1,
        "provider": provider,
        "provider_op": offer.provider_op,
        "domain": domain_name(domain),
        "tenant": ctx.tenant,
        "team": ctx.team.as_deref().unwrap_or("default"),
        "correlation_id": ctx.correlation_id,
    });
    operator_log::info(module_path!(), payload.to_string());
}

fn emit_hook_applied(
    offer: &crate::offers::registry::Offer,
    provider: &str,
    domain: Domain,
    ctx: &OperatorContext,
    action: &str,
    action_target: Option<JsonValue>,
) {
    let payload = json!({
        "event": "hook.directive.applied",
        "offer_key": offer.offer_key,
        "pack_id": offer.pack_id,
        "offer_id": offer.id,
        "action": action,
        "target": action_target,
        "provider": provider,
        "domain": domain_name(domain),
        "tenant": ctx.tenant,
        "team": ctx.team.as_deref().unwrap_or("default"),
        "correlation_id": ctx.correlation_id,
    });
    operator_log::info(module_path!(), payload.to_string());
}

fn emit_hook_parse_error(
    offer: &crate::offers::registry::Offer,
    provider: &str,
    domain: Domain,
    ctx: &OperatorContext,
    err: &str,
) {
    let payload = json!({
        "event": "hook.directive.parse_error",
        "offer_key": offer.offer_key,
        "pack_id": offer.pack_id,
        "offer_id": offer.id,
        "provider": provider,
        "domain": domain_name(domain),
        "tenant": ctx.tenant,
        "team": ctx.team.as_deref().unwrap_or("default"),
        "correlation_id": ctx.correlation_id,
        "error": err,
    });
    operator_log::warn(module_path!(), payload.to_string());
}

fn directive_action(directive: &ControlDirective) -> &'static str {
    match directive {
        ControlDirective::Continue => "continue",
        ControlDirective::Dispatch { .. } => "dispatch",
        ControlDirective::Respond { .. } => "respond",
        ControlDirective::Deny { .. } => "deny",
    }
}

fn directive_target_for_audit(directive: &ControlDirective) -> Option<JsonValue> {
    match directive {
        ControlDirective::Dispatch { target } => Some(json!({
            "tenant": target.tenant,
            "team": target.team,
            "pack": target.pack,
            "flow": target.flow,
            "node": target.node,
        })),
        _ => None,
    }
}

fn domain_name(domain: Domain) -> &'static str {
    match domain {
        Domain::Messaging => "messaging",
        Domain::Events => "events",
        Domain::Secrets => "secrets",
        Domain::OAuth => "oauth",
    }
}
