//! Consumer-side capability discovery (S6, decision B4: poll-based v1).
//!
//! This module polls a SoRX deployment's routing-table and each routable
//! deployment's advertised capabilities, caches the result with a TTL, and
//! validates an env-pack's required capabilities against what was discovered.
//!
//! # Why a separate module from [`crate::discovery`]
//!
//! [`crate::discovery`] performs *provider-pack* discovery on the local
//! filesystem (which packs/providers ship inside a bundle). This module is
//! about *runtime instance* discovery: querying a live SoRX deployment over
//! HTTP for the deployments it routes and the capabilities they offer. The two
//! concerns are deliberately kept apart.
//!
//! # SoRX surfaces consumed
//!
//! - `GET {sorx_base_url}/v1/sorx/routing-table` returns the deployment routing
//!   table. Each [`RouteRow`] describes one routable (or non-routable)
//!   deployment.
//! - `GET {sorx_base_url}/admin/v1/capabilities` returns the capability
//!   manifest (`greentic.capabilities.v1`) whose `offers[].capability` ids we
//!   collect.
//!
//! # Instance base-url resolution (v1 limitation)
//!
//! The routing-table exposes a `base_path` (a URL *path*, e.g. `/acme/sor-1`),
//! not a reachable `host:port`. Mapping a deployment to its own network
//! endpoint is the deployer's responsibility and is out of scope here. For v1
//! we therefore fetch capabilities from the *same* `sorx_base_url` for every
//! routable deployment, i.e. we assume a single SoRX instance hosting the
//! deployments. Per-deployment capability differentiation (distinct
//! capabilities per `host:port`) is a documented v2 follow-up that needs the
//! deployer's instance map. The poll-based model itself is also v1 only;
//! event-driven invalidation is the planned v2 (decision B4).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

/// One row of the SoRX routing-table (`GET /v1/sorx/routing-table`).
///
/// Unknown fields are ignored so the consumer tolerates additive schema
/// changes from SoRX.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RouteRow {
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub sor_name: String,
    #[serde(default)]
    pub alias: String,
    #[serde(default)]
    pub deployment_id: String,
    #[serde(default)]
    pub pack_name: String,
    #[serde(default)]
    pub pack_version: String,
    #[serde(default)]
    pub base_path: String,
    #[serde(default)]
    pub state_namespace: String,
    #[serde(default)]
    pub visibility: String,
    /// Only routable deployments are surfaced as discovered instances.
    #[serde(default)]
    pub routable: bool,
    #[serde(default)]
    pub traffic: serde_json::Value,
}

/// One discovered SoRLa instance: a routable deployment plus its advertised
/// capabilities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredInstance {
    pub tenant_id: String,
    pub sor_name: String,
    pub alias: String,
    pub deployment_id: String,
    pub pack_name: String,
    pub pack_version: String,
    pub base_path: String,
    /// Capability ids drawn from the instance's `/admin/v1/capabilities`
    /// `offers[].capability`, e.g.
    /// `cap://greentic/business-functions/{pack}/{action}/v{n}`.
    pub capabilities: Vec<String>,
}

/// Abstraction over the SoRX HTTP surfaces so tests can drive discovery
/// without real network access.
pub trait SorxDiscoverySource: Send + Sync {
    /// Fetch the routing-table from `{base_url}/v1/sorx/routing-table`.
    fn routing_table(&self, base_url: &str) -> Result<Vec<RouteRow>, String>;
    /// Fetch the offered capability ids from
    /// `{base_url}/admin/v1/capabilities`.
    fn capabilities(&self, base_url: &str) -> Result<Vec<String>, String>;
}

/// Poll-based capability-discovery client with a TTL cache.
///
/// On each call the cache is refreshed only when it is empty or older than the
/// configured `ttl`. If a refresh fails, the previous (stale) cache is served
/// when present; otherwise an empty result is returned.
pub struct CapabilityDiscovery {
    source: Box<dyn SorxDiscoverySource>,
    ttl: Duration,
    cache: Mutex<Option<(Instant, Vec<DiscoveredInstance>)>>,
}

impl CapabilityDiscovery {
    /// Build a discovery client backed by `source`, refreshing no more often
    /// than `ttl`.
    pub fn new(source: Box<dyn SorxDiscoverySource>, ttl: Duration) -> Self {
        Self {
            source,
            ttl,
            cache: Mutex::new(None),
        }
    }

    /// Return the discovered routable instances, refreshing on a TTL miss.
    ///
    /// Polls the routing-table and, for each `routable == true` route, attaches
    /// the capabilities discovered for its hosting SoRX instance (see the
    /// module-level instance base-url note). On any error the previously cached
    /// value is served if present; otherwise the result is empty.
    pub fn instances(&self, sorx_base_url: &str) -> Vec<DiscoveredInstance> {
        let mut guard = match self.cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some((fetched_at, cached)) = guard.as_ref()
            && fetched_at.elapsed() < self.ttl
        {
            return cached.clone();
        }

        match self.refresh(sorx_base_url) {
            Ok(fresh) => {
                *guard = Some((Instant::now(), fresh.clone()));
                fresh
            }
            Err(err) => {
                tracing::warn!(
                    sorx_base_url,
                    error = %err,
                    "capability discovery refresh failed; serving stale cache if present"
                );
                guard
                    .as_ref()
                    .map(|(_, cached)| cached.clone())
                    .unwrap_or_default()
            }
        }
    }

    /// Validate `required` capability ids against the discovered set, returning
    /// the missing ones (empty = satisfied). Matching is exact-id (see
    /// [`unmet_requirements`]).
    pub fn missing_capabilities(&self, sorx_base_url: &str, required: &[String]) -> Vec<String> {
        let discovered: Vec<String> = self
            .instances(sorx_base_url)
            .into_iter()
            .flat_map(|instance| instance.capabilities)
            .collect();
        unmet_requirements(required, &discovered)
    }

    /// Poll SoRX once: routing-table + per-instance capabilities. Errors are
    /// propagated to the caller, which decides whether to serve a stale cache.
    fn refresh(&self, sorx_base_url: &str) -> Result<Vec<DiscoveredInstance>, String> {
        let routes = self.source.routing_table(sorx_base_url)?;

        // v1: capabilities are hosted by the single SoRX instance, so fetch
        // them once and apply to every routable deployment. v2 will resolve a
        // per-deployment host:port from the deployer's instance map.
        let mut capabilities: Option<Vec<String>> = None;

        let mut instances = Vec::new();
        for route in routes.into_iter().filter(|route| route.routable) {
            let caps = match &capabilities {
                Some(caps) => caps.clone(),
                None => {
                    let caps = self.source.capabilities(sorx_base_url)?;
                    capabilities = Some(caps.clone());
                    caps
                }
            };
            instances.push(DiscoveredInstance {
                tenant_id: route.tenant_id,
                sor_name: route.sor_name,
                alias: route.alias,
                deployment_id: route.deployment_id,
                pack_name: route.pack_name,
                pack_version: route.pack_version,
                base_path: route.base_path,
                capabilities: caps,
            });
        }

        Ok(instances)
    }
}

/// Pure capability-requirement check used by an env-pack/bundle startup gate.
///
/// Given a pack's declared `required` capability ids and the `discovered` set,
/// returns the requirements that are not satisfied (empty = all met).
///
/// v1 uses **exact capability-id matching** (including the trailing `/v{n}`
/// version segment): a required `cap://.../v1` is satisfied only by a
/// discovered `cap://.../v1`. Prefix/semantic-version matching (e.g. accepting
/// `v2` for a `v1` requirement) is intentionally out of scope and is a
/// documented v2 follow-up. Duplicate requirements are de-duplicated in the
/// output while preserving first-seen order.
pub fn unmet_requirements(required: &[String], discovered: &[String]) -> Vec<String> {
    let mut missing = Vec::new();
    for req in required {
        if !discovered.iter().any(|cap| cap == req) && !missing.contains(req) {
            missing.push(req.clone());
        }
    }
    missing
}

/// Schema id of the SoRX capabilities manifest.
pub const CAPABILITIES_SCHEMA_V1: &str = "greentic.capabilities.v1";

/// HTTP-backed [`SorxDiscoverySource`] using the repo's `ureq` blocking client.
pub struct HttpSorxDiscoverySource;

/// Shape of `GET /v1/sorx/routing-table`.
#[derive(Debug, Deserialize)]
struct RoutingTableResponse {
    #[serde(default)]
    routes: Vec<RouteRow>,
}

/// One `offers[]` entry of `GET /admin/v1/capabilities`.
#[derive(Debug, Deserialize)]
struct CapabilityOffer {
    #[serde(default)]
    capability: String,
}

/// Shape of `GET /admin/v1/capabilities`.
#[derive(Debug, Deserialize)]
struct CapabilitiesResponse {
    #[serde(default)]
    offers: Vec<CapabilityOffer>,
}

impl SorxDiscoverySource for HttpSorxDiscoverySource {
    fn routing_table(&self, base_url: &str) -> Result<Vec<RouteRow>, String> {
        let url = format!("{}/v1/sorx/routing-table", base_url.trim_end_matches('/'));
        let body: RoutingTableResponse = ureq::get(&url)
            .call()
            .map_err(|err| format!("GET {url} failed: {err}"))?
            .body_mut()
            .read_json()
            .map_err(|err| format!("decode {url} failed: {err}"))?;
        Ok(body.routes)
    }

    fn capabilities(&self, base_url: &str) -> Result<Vec<String>, String> {
        let url = format!("{}/admin/v1/capabilities", base_url.trim_end_matches('/'));
        let body: CapabilitiesResponse = ureq::get(&url)
            .call()
            .map_err(|err| format!("GET {url} failed: {err}"))?
            .body_mut()
            .read_json()
            .map_err(|err| format!("decode {url} failed: {err}"))?;
        Ok(body
            .offers
            .into_iter()
            .map(|offer| offer.capability)
            .filter(|cap| !cap.is_empty())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn route(alias: &str, routable: bool) -> RouteRow {
        RouteRow {
            tenant_id: "acme".to_string(),
            sor_name: "sor-1".to_string(),
            alias: alias.to_string(),
            deployment_id: format!("dep-{alias}"),
            pack_name: "billing".to_string(),
            pack_version: "1.0.0".to_string(),
            base_path: format!("/acme/{alias}"),
            state_namespace: "ns".to_string(),
            visibility: "public".to_string(),
            routable,
            traffic: serde_json::Value::Null,
        }
    }

    /// Fake source: returns fixed routes/caps and counts how often each surface
    /// is hit. After `fail_after_calls` routing-table calls it returns Err.
    struct FakeSource {
        routes: Vec<RouteRow>,
        capabilities: Vec<String>,
        routing_calls: Arc<AtomicUsize>,
        capability_calls: Arc<AtomicUsize>,
        fail_after_calls: Option<usize>,
    }

    impl FakeSource {
        fn new(routes: Vec<RouteRow>, capabilities: Vec<String>) -> Self {
            Self {
                routes,
                capabilities,
                routing_calls: Arc::new(AtomicUsize::new(0)),
                capability_calls: Arc::new(AtomicUsize::new(0)),
                fail_after_calls: None,
            }
        }
    }

    impl SorxDiscoverySource for FakeSource {
        fn routing_table(&self, _base_url: &str) -> Result<Vec<RouteRow>, String> {
            let n = self.routing_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if let Some(limit) = self.fail_after_calls
                && n > limit
            {
                return Err("simulated routing-table outage".to_string());
            }
            Ok(self.routes.clone())
        }

        fn capabilities(&self, _base_url: &str) -> Result<Vec<String>, String> {
            self.capability_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.capabilities.clone())
        }
    }

    #[test]
    fn discovery_lists_routable_instances() {
        let source = FakeSource::new(
            vec![route("alpha", true), route("beta", false)],
            vec!["cap://a".to_string(), "cap://b".to_string()],
        );
        let discovery = CapabilityDiscovery::new(Box::new(source), Duration::from_secs(60));

        let instances = discovery.instances("http://sorx");

        assert_eq!(instances.len(), 1, "only the routable deployment surfaces");
        assert_eq!(instances[0].alias, "alpha");
        assert_eq!(
            instances[0].capabilities,
            vec!["cap://a".to_string(), "cap://b".to_string()]
        );
    }

    #[test]
    fn discovery_ttl_refetch() {
        let source = FakeSource::new(vec![route("alpha", true)], vec!["cap://a".to_string()]);
        let routing_calls = source.routing_calls.clone();
        let discovery = CapabilityDiscovery::new(Box::new(source), Duration::from_millis(20));

        discovery.instances("http://sorx");
        discovery.instances("http://sorx");
        assert_eq!(
            routing_calls.load(Ordering::SeqCst),
            1,
            "second call within TTL is served from cache"
        );

        std::thread::sleep(Duration::from_millis(40));
        discovery.instances("http://sorx");
        assert_eq!(
            routing_calls.load(Ordering::SeqCst),
            2,
            "call after TTL expiry refetches"
        );
    }

    #[test]
    fn discovery_stale_on_error() {
        let mut source = FakeSource::new(vec![route("alpha", true)], vec!["cap://a".to_string()]);
        // First routing-table call succeeds; subsequent calls fail.
        source.fail_after_calls = Some(1);
        let discovery = CapabilityDiscovery::new(Box::new(source), Duration::from_millis(10));

        let first = discovery.instances("http://sorx");
        assert_eq!(first.len(), 1, "initial fetch populates the cache");

        std::thread::sleep(Duration::from_millis(20));
        let stale = discovery.instances("http://sorx");
        assert_eq!(
            stale, first,
            "on refresh error the stale cache is served, not empty"
        );
    }

    #[test]
    fn missing_capabilities_detects_gap() {
        let source = FakeSource::new(vec![route("alpha", true)], vec!["cap://a".to_string()]);
        let discovery = CapabilityDiscovery::new(Box::new(source), Duration::from_secs(60));

        let required = vec!["cap://a".to_string(), "cap://b".to_string()];
        let missing = discovery.missing_capabilities("http://sorx", &required);

        assert_eq!(missing, vec!["cap://b".to_string()]);
    }

    #[test]
    fn missing_capabilities_satisfied() {
        let source = FakeSource::new(
            vec![route("alpha", true)],
            vec!["cap://a".to_string(), "cap://b".to_string()],
        );
        let discovery = CapabilityDiscovery::new(Box::new(source), Duration::from_secs(60));

        let required = vec!["cap://a".to_string(), "cap://b".to_string()];
        let missing = discovery.missing_capabilities("http://sorx", &required);

        assert!(missing.is_empty(), "all requirements discovered");
    }

    #[test]
    fn unmet_requirements_exact_match() {
        let required = vec![
            "cap://greentic/business-functions/billing/charge/v1".to_string(),
            "cap://greentic/business-functions/billing/refund/v1".to_string(),
            // exact-id: a v2 discovery does NOT satisfy a v1 requirement.
            "cap://greentic/business-functions/billing/quote/v1".to_string(),
        ];
        let discovered = vec![
            "cap://greentic/business-functions/billing/charge/v1".to_string(),
            "cap://greentic/business-functions/billing/quote/v2".to_string(),
        ];

        let missing = unmet_requirements(&required, &discovered);

        assert_eq!(
            missing,
            vec![
                "cap://greentic/business-functions/billing/refund/v1".to_string(),
                "cap://greentic/business-functions/billing/quote/v1".to_string(),
            ]
        );
    }
}
