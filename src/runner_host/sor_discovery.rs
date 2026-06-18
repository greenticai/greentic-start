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

/// Testable core: poll `discovery` for `sor_base_url`, log, and merge.
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
