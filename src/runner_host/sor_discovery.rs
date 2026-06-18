//! Startup wiring: discover deployed SoRLa (SoRX) instances and register their
//! capabilities as remote offers. Default-OFF — inert unless `SORX_BASE_URL`
//! is set.

use std::time::Duration;

use crate::capabilities::CapabilityRegistry;
use crate::capability_discovery::{CapabilityDiscovery, HttpSorxDiscoverySource};

const DEFAULT_TTL_SECS: u64 = 300;

/// Read `SORX_BASE_URL` (+ optional `SORX_DISCOVERY_TTL_SECS`); when set, poll
/// SoRX and merge discovered capabilities into `registry`. No-op otherwise.
pub(super) fn discover_and_register_remote_offers(registry: &mut CapabilityRegistry) {
    let Ok(base_url) = std::env::var("SORX_BASE_URL") else {
        return;
    };
    let base_url = base_url.trim().to_string();
    if base_url.is_empty() {
        return;
    }
    let ttl = Duration::from_secs(
        std::env::var("SORX_DISCOVERY_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_TTL_SECS),
    );
    let discovery = CapabilityDiscovery::new(Box::new(HttpSorxDiscoverySource), ttl);
    register_from_discovery(registry, &discovery, &base_url);
}

/// Thin wrapper over [`CapabilityDiscovery::missing_capabilities`] for the
/// startup diagnostic; kept separate so it is unit-testable.
fn unmet_required(
    discovery: &CapabilityDiscovery,
    sor_base_url: &str,
    required: &[String],
) -> Vec<String> {
    discovery.missing_capabilities(sor_base_url, required)
}

/// Testable core: poll `discovery` for `sor_base_url`, log, and merge.
/// Emits a `warn!` for each unmet required capability, sourced from
/// `SORX_REQUIRED_CAPABILITIES` (comma-separated). Startup is never blocked.
fn register_from_discovery(
    registry: &mut CapabilityRegistry,
    discovery: &CapabilityDiscovery,
    sor_base_url: &str,
) {
    let instances = discovery.instances(sor_base_url);
    let cap_total: usize = instances.iter().map(|i| i.capabilities.len()).sum();
    tracing::info!(
        sor_base_url,
        instances = instances.len(),
        capabilities = cap_total,
        "discovered SoRLa instances"
    );

    // Non-blocking diagnostic: warn on any unmet required capabilities.
    // Required caps are sourced from the SORX_REQUIRED_CAPABILITIES env var
    // (comma-separated list). Hookup to dependency_resolver's pack-manifest
    // required_capabilities is deferred (see task-A4-report.md).
    let required: Vec<String> = std::env::var("SORX_REQUIRED_CAPABILITIES")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    if !required.is_empty() {
        for missing in unmet_required(discovery, sor_base_url, &required) {
            tracing::warn!(
                sor_base_url,
                capability = %missing,
                "required SoRLa capability not available at startup (non-blocking)"
            );
        }
    }

    registry.register_remote_offers(&instances, sor_base_url);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::CapabilityRegistry;
    use crate::capability_discovery::{CapabilityDiscovery, RouteRow, SorxDiscoverySource};
    use std::time::Duration;

    struct FakeSource;
    impl SorxDiscoverySource for FakeSource {
        fn routing_table(&self, _b: &str) -> Result<Vec<RouteRow>, String> {
            Ok(vec![RouteRow {
                tenant_id: "acme".into(),
                sor_name: "landlord".into(),
                alias: "stable".into(),
                deployment_id: "d1".into(),
                pack_name: "landlord".into(),
                pack_version: "0.1.0".into(),
                base_path: "/acme/landlord".into(),
                state_namespace: "ns".into(),
                visibility: "private".into(),
                routable: true,
                traffic: serde_json::Value::Null,
            }])
        }
        fn capabilities(&self, _b: &str) -> Result<Vec<String>, String> {
            Ok(vec![
                "cap://greentic/business-functions/landlord/pay/v1".into(),
            ])
        }
    }

    #[test]
    fn missing_required_capabilities_are_reported() {
        let disco = CapabilityDiscovery::new(Box::new(FakeSource), Duration::from_secs(60));
        let required = vec![
            "cap://greentic/business-functions/landlord/pay/v1".to_string(), // present
            "cap://greentic/business-functions/landlord/evict/v1".to_string(), // missing
        ];
        let missing = unmet_required(&disco, "http://sorx:9080", &required);
        assert_eq!(
            missing,
            vec!["cap://greentic/business-functions/landlord/evict/v1".to_string()]
        );
    }

    #[test]
    fn register_from_discovery_merges_remote_offers() {
        let mut reg = CapabilityRegistry::default();
        let disco = CapabilityDiscovery::new(Box::new(FakeSource), Duration::from_secs(60));
        register_from_discovery(&mut reg, &disco, "http://sorx:9080");
        let b = reg
            .resolve(
                "cap://greentic/business-functions/landlord/pay/v1",
                None,
                &crate::capabilities::ResolveScope {
                    env: None,
                    tenant: None,
                    team: None,
                },
            )
            .expect("binding");
        assert_eq!(b.remote.unwrap().sor_base_url, "http://sorx:9080");
    }
}
