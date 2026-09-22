//! Turning a firing into a flow run (contract §6.5, §7.4, §9), and reading a
//! trigger's secrets the way a component in the same pack reads them (§8).

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use greentic_runner_host::RunnerHost;
use greentic_runner_host::engine::runtime::IngressEnvelope;
use serde_json::{Map, Value, json};

use super::field_ref::RequestView;
use super::schema::{CronSpec, SessionSpec, TriggerKind, TriggerSpec};
use super::table::LoadedTrigger;

/// What the runner is told for one firing.
#[derive(Clone, Debug)]
pub(crate) struct Firing {
    pub firing_id: String,
    pub session_hint: String,
    pub payload: Value,
}

pub(crate) fn new_firing_id() -> String {
    ulid::Ulid::new().to_string()
}

/// The session hint the runner keys the run on (§6.5).
///
/// `per_run` gives every firing its own conversation: a firing parked on an
/// approval must not swallow the next tick, which is exactly what the runner's
/// legacy `session_hint = schedule_id` did. `per_key` shares state across
/// firings with the same key (every reply in one thread); a key that does not
/// resolve falls back to `per_run` and says so, rather than silently merging
/// unrelated firings into one session.
pub(crate) fn session_hint(
    spec: &TriggerSpec,
    firing_id: &str,
    view: Option<&RequestView<'_>>,
) -> String {
    if let SessionSpec::PerKey(key) = &spec.session {
        if let Some(value) = view.and_then(|v| key.resolve(v)) {
            return format!("trigger:{}:{}", spec.trigger_id, value);
        }
        crate::operator_log::warn(
            module_path!(),
            format!(
                "trigger `{}`: session key did not resolve; firing `{firing_id}` runs in its own \
                 session",
                spec.trigger_id
            ),
        );
    }
    format!("trigger:{}:{}", spec.trigger_id, firing_id)
}

fn trigger_block(spec: &TriggerSpec, firing_id: &str, fired_at: DateTime<Utc>) -> Value {
    json!({
        "trigger_id": spec.trigger_id,
        "kind": spec.kind.name(),
        "firing_id": firing_id,
        "fired_at": fired_at.to_rfc3339(),
    })
}

/// §9 payload for a cron firing.
pub(crate) fn cron_payload(
    spec: &TriggerSpec,
    cron: &CronSpec,
    firing_id: &str,
    fired_at: DateTime<Utc>,
    scheduled_for: DateTime<Utc>,
) -> Value {
    json!({
        "trigger": trigger_block(spec, firing_id, fired_at),
        "webhook": Value::Null,
        "cron": {
            "scheduled_for": scheduled_for.to_rfc3339(),
            "expr": cron.expr,
            "timezone": cron.timezone.name(),
        },
    })
}

/// Headers the flow may see (§9): the request, never the credentials that
/// authenticated it. Anything a key reference names is added, because the
/// flow was told it could key on it.
fn allowed_headers(spec: &TriggerSpec) -> Vec<String> {
    let mut names = vec!["content-type".to_string(), "user-agent".to_string()];
    let mut add = |name: Option<&str>| {
        if let Some(n) = name {
            names.push(n.to_ascii_lowercase());
        }
    };
    if let SessionSpec::PerKey(key) = &spec.session {
        add(key.header_name());
    }
    if let TriggerKind::Webhook(w) = &spec.kind
        && let Some(i) = &w.idempotency
    {
        add(i.key.header_name());
    }
    names
}

/// §9 payload for a webhook firing. `body_json` is the parsed body when it is
/// JSON; otherwise the UTF-8 (lossy) text goes to `body_text`.
pub(crate) fn webhook_payload(
    spec: &TriggerSpec,
    firing_id: &str,
    fired_at: DateTime<Utc>,
    method: &str,
    view: &RequestView<'_>,
    raw_body: &[u8],
) -> Value {
    let allowed = allowed_headers(spec);
    let headers: Map<String, Value> = view
        .headers
        .iter()
        .filter(|(k, _)| allowed.iter().any(|a| a.eq_ignore_ascii_case(k)))
        .map(|(k, v)| (k.to_ascii_lowercase(), Value::String(v.clone())))
        .collect();
    let query: Map<String, Value> = view
        .query
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    let (body, body_text) = match view.body {
        Some(json) => (json.clone(), Value::Null),
        None if raw_body.is_empty() => (Value::Null, Value::Null),
        None => (
            Value::Null,
            Value::String(String::from_utf8_lossy(raw_body).into_owned()),
        ),
    };
    json!({
        "trigger": trigger_block(spec, firing_id, fired_at),
        "webhook": {
            "method": method,
            "headers": headers,
            "query": query,
            "body": body,
            "body_text": body_text,
        },
        "cron": Value::Null,
    })
}

/// The ingress envelope for one firing: enters `entry_node` of `flow_id` in the
/// declaring pack, keyed on the firing's session hint. Same shape the runner's
/// own timer adapter builds, generalised to both kinds (§7.4).
pub(crate) fn envelope(loaded: &LoadedTrigger, firing: &Firing) -> IngressEnvelope {
    IngressEnvelope {
        tenant: loaded.tenant.clone(),
        env: None,
        pack_id: Some(loaded.pack_id.clone()),
        flow_id: loaded.spec.flow_id.clone(),
        flow_type: Some("trigger".into()),
        action: Some("trigger".into()),
        session_hint: Some(firing.session_hint.clone()),
        provider: Some("trigger".into()),
        messaging_endpoint_id: None,
        channel: Some(firing.session_hint.clone()),
        conversation: Some(firing.session_hint.clone()),
        user: None,
        entry_node: Some(loaded.spec.entry_node.clone()),
        activity_id: Some(firing.firing_id.clone()),
        timestamp: Some(Utc::now().to_rfc3339()),
        payload: firing.payload.clone(),
        metadata: None,
        reply_scope: None,
    }
    .canonicalize()
}

/// Run one firing on the revision that declared it.
pub(crate) async fn fire(host: &RunnerHost, loaded: &LoadedTrigger, firing: Firing) -> Result<()> {
    let runtime = host
        .active_packs()
        .load_revision(
            &loaded.tenant,
            loaded.scope.deployment_id,
            loaded.scope.bundle_id.clone(),
            loaded.scope.revision_id,
        )
        .ok_or_else(|| anyhow!("revision {} is not loaded", loaded.scope.revision_id))?;
    runtime
        .state_machine()
        .handle(envelope(loaded, &firing))
        .await
        .with_context(|| format!("flow `{}` run failed", loaded.spec.flow_id))?;
    Ok(())
}

/// Read `secret_ref` for `loaded` at the exact address a component in the same
/// pack would read it: the runner's own `tenant_ctx` for this revision plus
/// `scoped_secret_path_for_pack`. One resolution rule, so the secret an
/// operator entered for the extension's tools is the one the trigger verifies
/// with — and the one the designer's `ext_stage` writes.
pub(crate) async fn read_secret(
    host: &RunnerHost,
    loaded: &LoadedTrigger,
    secret_ref: &str,
) -> Result<Vec<u8>> {
    let runtime = host
        .active_packs()
        .load_revision(
            &loaded.tenant,
            loaded.scope.deployment_id,
            loaded.scope.bundle_id.clone(),
            loaded.scope.revision_id,
        )
        .ok_or_else(|| anyhow!("revision {} is not loaded", loaded.scope.revision_id))?;
    let ctx = runtime.config().tenant_ctx();
    let uri = greentic_runner_host::secrets::scoped_secret_path_for_pack(
        &ctx,
        &loaded.pack_id,
        secret_ref,
    )?;
    host.secrets_manager()
        .read(&uri)
        .await
        .map_err(|err| anyhow!("secret `{secret_ref}` unreadable: {err}"))
}

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod tests;
