//! Loading `assets/triggers.json` from a revision's packs, and the table the
//! scheduler and the webhook route read.
//!
//! The table travels inside `RevisionIngressRouting`, so a reload swaps the
//! trigger set together with every other routing artifact of the activation —
//! a firing is always matched against the same activation it is dispatched on.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use greentic_deploy_spec::{DeploymentId, RevisionId};

use super::schema::{self, TriggerKind, TriggerSpec};
use crate::http_routes::RevisionScope;

/// The asset path a pack declares its triggers at (contract §5).
pub(crate) const TRIGGERS_ASSET: &str = "assets/triggers.json";

/// One trigger as declared by one revision.
#[derive(Clone, Debug)]
pub(crate) struct LoadedTrigger {
    pub scope: RevisionScope,
    pub tenant: String,
    /// The declaring pack's manifest id — the pack segment its secrets resolve
    /// under (§8).
    pub pack_id: String,
    pub spec: Arc<TriggerSpec>,
    /// Set when the declaration is valid but asks for something this host
    /// cannot enforce yet. The route then answers 503 instead of serving the
    /// trigger without the check the author asked for.
    pub unavailable: Option<&'static str>,
}

/// Every trigger of the live activation.
#[derive(Clone, Debug, Default)]
pub(crate) struct TriggerTable {
    entries: Vec<Arc<LoadedTrigger>>,
    /// `(deployment, request path) -> trigger_id` for webhook triggers.
    webhook_paths: HashMap<(DeploymentId, String), String>,
}

impl TriggerTable {
    /// Build from every revision's loaded triggers plus the deployment's path
    /// prefixes, which the webhook routes mount under exactly as provider
    /// webhook routes do (`<prefix>/webhook/<provider>`).
    pub(crate) fn build(
        entries: Vec<LoadedTrigger>,
        prefixes: &HashMap<DeploymentId, Vec<String>>,
    ) -> Self {
        let mut webhook_paths = HashMap::new();
        for entry in &entries {
            if !matches!(entry.spec.kind, TriggerKind::Webhook(_)) {
                continue;
            }
            let deployment = entry.scope.deployment_id;
            let deployment_prefixes = prefixes
                .get(&deployment)
                .filter(|p| !p.is_empty())
                .cloned()
                .unwrap_or_else(|| vec![String::new()]);
            for prefix in deployment_prefixes {
                webhook_paths.insert(
                    (deployment, trigger_path(&prefix, &entry.spec.trigger_id)),
                    entry.spec.trigger_id.clone(),
                );
            }
        }
        Self {
            entries: entries.into_iter().map(Arc::new).collect(),
            webhook_paths,
        }
    }

    /// The trigger a request path names on this deployment, if any. Exact
    /// match (one trailing `/` tolerated): unlike provider routes, a trigger
    /// route never matches extra trailing segments, so `/trigger/x/anything`
    /// is not `/trigger/x`.
    pub(crate) fn webhook_trigger_for(&self, deployment: DeploymentId, path: &str) -> Option<&str> {
        let normalized = path
            .strip_suffix('/')
            .filter(|p| !p.is_empty())
            .unwrap_or(path);
        self.webhook_paths
            .get(&(deployment, normalized.to_string()))
            .map(String::as_str)
    }

    /// The declaration of `trigger_id` by one specific revision — the one the
    /// traffic split picked for this firing.
    pub(crate) fn for_revision(
        &self,
        deployment: DeploymentId,
        revision: RevisionId,
        trigger_id: &str,
    ) -> Option<Arc<LoadedTrigger>> {
        self.entries
            .iter()
            .find(|e| {
                e.scope.deployment_id == deployment
                    && e.scope.revision_id == revision
                    && e.spec.trigger_id == trigger_id
            })
            .cloned()
    }

    pub(crate) fn cron_entries(&self) -> impl Iterator<Item = &Arc<LoadedTrigger>> {
        self.entries
            .iter()
            .filter(|e| matches!(e.spec.kind, TriggerKind::Cron(_)))
    }

    /// The `triggers` block of `/status` (contract §7.2): what this host
    /// serves, so an operator — or the designer — can see which triggers
    /// started and where a webhook is mounted. Paths only, no host: the public
    /// base URL is resolved elsewhere, and a route is what the designer joins
    /// to the endpoint it already knows. Never a secret reference's value
    /// (there is none to show) and never a verify setting beyond its scheme.
    pub(crate) fn status_json(&self) -> serde_json::Value {
        let mut routes: HashMap<(DeploymentId, &str), Vec<&str>> = HashMap::new();
        for ((dep, path), id) in &self.webhook_paths {
            routes
                .entry((*dep, id.as_str()))
                .or_default()
                .push(path.as_str());
        }
        let mut out: Vec<serde_json::Value> = self
            .entries
            .iter()
            .map(|e| {
                let mut paths = routes
                    .get(&(e.scope.deployment_id, e.spec.trigger_id.as_str()))
                    .cloned()
                    .unwrap_or_default();
                paths.sort_unstable();
                let detail = match &e.spec.kind {
                    TriggerKind::Cron(c) => serde_json::json!({
                        "expr": c.expr,
                        "timezone": c.timezone.name(),
                    }),
                    TriggerKind::Webhook(_) => serde_json::json!({ "routes": paths }),
                };
                serde_json::json!({
                    "deployment_id": e.scope.deployment_id.to_string(),
                    "revision_id": e.scope.revision_id.to_string(),
                    "pack_id": e.pack_id,
                    "trigger_id": e.spec.trigger_id,
                    "kind": e.spec.kind.name(),
                    "enabled": e.spec.enabled,
                    "served": e.unavailable.is_none(),
                    "unavailable_reason": e.unavailable,
                    e.spec.kind.name(): detail,
                })
            })
            .collect();
        out.sort_by(|a, b| {
            (a["deployment_id"].as_str(), a["trigger_id"].as_str())
                .cmp(&(b["deployment_id"].as_str(), b["trigger_id"].as_str()))
        });
        serde_json::Value::Array(out)
    }
}

/// `<prefix>/trigger/<trigger_id>`, mirroring `build_webhook_pattern`.
pub(crate) fn trigger_path(prefix: &str, trigger_id: &str) -> String {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        format!("/trigger/{trigger_id}")
    } else {
        format!("/{trimmed}/trigger/{trigger_id}")
    }
}

/// Load the triggers every pack of one revision declares.
///
/// Never fails the activation: a broken trigger must not take down the
/// messaging entry points of the same deployment (§7.1). A pack whose file does
/// not validate contributes nothing and logs one line naming the pack and why.
pub(crate) fn load_revision_triggers<P: AsRef<Path>>(
    pack_paths: &[P],
    scope: &RevisionScope,
    tenant: &str,
) -> Vec<LoadedTrigger> {
    let mut out = Vec::new();
    for pack_path in pack_paths {
        let pack_path = pack_path.as_ref();
        let bytes = match crate::static_routes::read_pack_asset_bytes(pack_path, TRIGGERS_ASSET) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(err) => {
                refuse(pack_path, &format!("unreadable {TRIGGERS_ASSET}: {err:#}"));
                continue;
            }
        };
        let info = match crate::messaging_app::load_app_pack_info(pack_path) {
            Ok(info) => info,
            Err(err) => {
                refuse(pack_path, &format!("manifest unreadable: {err:#}"));
                continue;
            }
        };
        match load_pack(&bytes, &info.pack_id, &info.flows, scope, tenant) {
            Ok(triggers) => out.extend(triggers),
            Err(err) => refuse(pack_path, &format!("{err:#}")),
        }
    }
    out
}

fn load_pack(
    bytes: &[u8],
    pack_id: &str,
    flows: &[crate::messaging_app::AppFlowInfo],
    scope: &RevisionScope,
    tenant: &str,
) -> anyhow::Result<Vec<LoadedTrigger>> {
    let parsed = schema::parse(bytes, pack_id)?;
    for spec in &parsed.triggers {
        let Some(flow) = flows.iter().find(|f| f.id == spec.flow_id) else {
            anyhow::bail!(
                "trigger `{}` names flow `{}`, which this pack does not contain",
                spec.trigger_id,
                spec.flow_id
            );
        };
        // Checked here rather than left to the runner: `execute_from` refuses
        // an unknown node too, but only at firing time, where it reads as a
        // runtime failure of a flow that simply never ran. An empty node list
        // means the manifest carried no symbol table, which proves nothing
        // either way, so it is not treated as a mismatch.
        if !flow.node_ids.is_empty() && !flow.node_ids.iter().any(|n| n == &spec.entry_node) {
            anyhow::bail!(
                "trigger `{}` enters flow `{}` at node `{}`, which the flow does not declare",
                spec.trigger_id,
                spec.flow_id,
                spec.entry_node
            );
        }
    }
    for warning in &parsed.skipped {
        crate::operator_log::warn(module_path!(), format!("pack `{pack_id}`: {warning}"));
    }
    Ok(parsed
        .triggers
        .into_iter()
        .map(|spec| {
            let unavailable = unavailable_reason(&spec);
            if let Some(reason) = unavailable {
                crate::operator_log::warn(
                    module_path!(),
                    format!(
                        "pack `{pack_id}` trigger `{}` is not served: {reason}",
                        spec.trigger_id
                    ),
                );
            }
            if let TriggerKind::Webhook(w) = &spec.kind
                && matches!(w.verify, schema::Verify::None)
            {
                crate::operator_log::warn(
                    module_path!(),
                    format!(
                        "pack `{pack_id}` trigger `{}` accepts UNVERIFIED webhooks \
                         (verify.scheme = none): anyone who knows its URL can fire it",
                        spec.trigger_id
                    ),
                );
            }
            LoadedTrigger {
                scope: scope.clone(),
                tenant: tenant.to_string(),
                pack_id: pack_id.to_string(),
                spec: Arc::new(spec),
                unavailable,
            }
        })
        .collect())
}

/// Declarations this host parses but cannot enforce yet. Refusing to serve is
/// the only honest answer: serving without the check would publish exactly the
/// endpoint the author asked to restrict.
fn unavailable_reason(spec: &TriggerSpec) -> Option<&'static str> {
    match &spec.kind {
        TriggerKind::Webhook(w) if !w.allowed_sources.is_empty() => Some(
            "allowed_sources is not enforced by this host yet (no trusted client-address \
             header is configured on the revision path)",
        ),
        _ => None,
    }
}

fn refuse(pack_path: &Path, reason: &str) {
    crate::operator_log::warn(
        module_path!(),
        format!(
            "no trigger from pack {} is started: {reason}",
            pack_path.display()
        ),
    );
}

#[cfg(test)]
#[path = "table_tests.rs"]
mod tests;
