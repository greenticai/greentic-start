use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

use crate::config::DemoDesiredSubscription;
use crate::discovery;
use crate::domains::{Domain, ProviderPack, discover_provider_packs_cbor_only};
use crate::runner_host::{DemoRunnerHost, OperatorContext};
use crate::secrets_gate;
use crate::subscriptions_universal::scheduler::Scheduler;
use crate::subscriptions_universal::{AuthUserRefV1, SubscriptionEnsureRequest};

pub fn state_root(bundle: &Path) -> PathBuf {
    bundle.join("state").join("subscriptions")
}

pub fn build_runner(
    bundle: &Path,
    tenant: &str,
    team: Option<String>,
    runner_binary: Option<PathBuf>,
) -> Result<(DemoRunnerHost, OperatorContext)> {
    let discovery =
        discovery::discover_with_options(bundle, discovery::DiscoveryOptions { cbor_only: true })?;
    let secrets_handle = secrets_gate::resolve_secrets_manager(bundle, tenant, team.as_deref())?;
    let runner_host = DemoRunnerHost::new(
        bundle.to_path_buf(),
        &discovery,
        runner_binary,
        secrets_handle,
        false,
    )?;
    let context = OperatorContext {
        tenant: tenant.to_string(),
        team,
        correlation_id: None,
    };
    Ok((runner_host, context))
}

pub fn ensure_desired_subscriptions(
    bundle: &Path,
    tenant: &str,
    team: Option<String>,
    desired: &[DemoDesiredSubscription],
    scheduler: &Scheduler<DemoRunnerHost>,
) -> Result<()> {
    if desired.is_empty() {
        return Ok(());
    }
    let team_ref = team.as_deref();
    let packs = discover_provider_packs_cbor_only(bundle, Domain::Messaging)?;
    for entry in desired {
        let pack = resolve_demo_provider_pack(&packs, &entry.provider)?;
        let binding_id = entry
            .binding_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let request = SubscriptionEnsureRequest {
            binding_id,
            resource: Some(entry.resource.clone()),
            change_types: if entry.change_types.is_empty() {
                vec!["created".to_string()]
            } else {
                entry.change_types.clone()
            },
            notification_url: entry.notification_url.clone(),
            client_state: entry.client_state.clone(),
            user: entry.user.as_ref().map(|value| AuthUserRefV1 {
                user_id: value.user_id.clone(),
                token_key: value.token_key.clone(),
                tenant_id: Some(tenant.to_string()),
                email: None,
                display_name: None,
            }),
            expiration_target_unix_ms: None,
        };
        let provider_id = provider_id_for_pack(pack, &entry.provider);
        let _ = team_ref;
        scheduler.ensure_once(&provider_id, &request)?;
    }
    Ok(())
}

fn resolve_demo_provider_pack<'a>(
    packs: &'a [ProviderPack],
    provider: &str,
) -> Result<&'a ProviderPack> {
    packs
        .iter()
        .find(|pack| {
            pack.pack_id == provider
                || pack.file_name.strip_suffix(".gtpack") == Some(provider)
                || pack.pack_id.ends_with(provider)
        })
        .ok_or_else(|| anyhow!("provider pack not found for {}", provider))
}

fn provider_id_for_pack(pack: &ProviderPack, provider: &str) -> String {
    if !provider.trim().is_empty() {
        provider.to_string()
    } else {
        pack.pack_id.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DemoDesiredSubscription;
    use tempfile::tempdir;

    fn pack(pack_id: &str, file_name: &str) -> ProviderPack {
        ProviderPack {
            pack_id: pack_id.to_string(),
            display_name: None,
            description: None,
            tags: Vec::new(),
            file_name: file_name.to_string(),
            path: PathBuf::from(format!("/tmp/{file_name}")),
            entry_flows: Vec::new(),
        }
    }

    #[test]
    fn state_root_uses_bundle_state_subdirectory() {
        assert_eq!(
            state_root(Path::new("/tmp/demo-bundle")),
            PathBuf::from("/tmp/demo-bundle/state/subscriptions")
        );
    }

    #[test]
    fn resolve_demo_provider_pack_matches_pack_id_suffix_and_filename() {
        let packs = vec![
            pack("messaging.graph", "messaging-graph.gtpack"),
            pack("messaging.webex", "custom-webex.gtpack"),
        ];

        assert_eq!(
            resolve_demo_provider_pack(&packs, "messaging.graph")
                .expect("exact pack")
                .pack_id,
            "messaging.graph"
        );
        assert_eq!(
            resolve_demo_provider_pack(&packs, "graph")
                .expect("suffix pack")
                .pack_id,
            "messaging.graph"
        );
        assert_eq!(
            resolve_demo_provider_pack(&packs, "custom-webex")
                .expect("filename pack")
                .pack_id,
            "messaging.webex"
        );
        assert!(resolve_demo_provider_pack(&packs, "missing").is_err());
    }

    #[test]
    fn provider_id_for_pack_prefers_explicit_provider_and_falls_back_to_pack_id() {
        let pack = pack("messaging.graph", "messaging-graph.gtpack");
        assert_eq!(
            provider_id_for_pack(&pack, "messaging-graph"),
            "messaging-graph"
        );
        assert_eq!(provider_id_for_pack(&pack, "   "), "messaging.graph");
    }

    #[test]
    fn ensure_desired_subscriptions_is_noop_for_empty_desired_list() {
        let dir = tempdir().expect("tempdir");
        let (runner_host, context) =
            build_runner(dir.path(), "demo", Some("default".to_string()), None).unwrap();
        let scheduler = Scheduler::new(
            crate::subscriptions_universal::service::SubscriptionService::new(runner_host, context),
            crate::subscriptions_universal::store::SubscriptionStore::new(state_root(dir.path())),
        );

        ensure_desired_subscriptions(
            dir.path(),
            "demo",
            Some("default".to_string()),
            &Vec::<DemoDesiredSubscription>::new(),
            &scheduler,
        )
        .expect("empty desired");
    }
}
