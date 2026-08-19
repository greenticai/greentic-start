//! Process-wide Fast2Flow config loaded once from env on first access.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use super::gate::{AlwaysEnabledGate, AnyGate, BundleCapabilityGate, Fast2FlowGate};

// Env vars: HOST_BIN (default greentic-fast2flow-routing-host),
// REGISTRY_PATH (default /mnt/registry), INDEXES_PATH (unset = hard-skip),
// TIME_BUDGET_MS (default 500), FORCE_ENABLE (any non-empty = AlwaysEnabledGate).
const ENV_HOST_BIN: &str = "GREENTIC_FAST2FLOW_HOST_BIN";
const ENV_REGISTRY_PATH: &str = "GREENTIC_FAST2FLOW_REGISTRY_PATH";
const ENV_INDEXES_PATH: &str = "GREENTIC_FAST2FLOW_INDEXES_PATH";
const ENV_TIME_BUDGET: &str = "GREENTIC_FAST2FLOW_TIME_BUDGET_MS";
const ENV_FORCE_ENABLE: &str = "GREENTIC_FAST2FLOW_FORCE_ENABLE";

const DEFAULT_HOST_BIN: &str = "greentic-fast2flow-routing-host";
const DEFAULT_REGISTRY_PATH: &str = "/mnt/registry";
const DEFAULT_TIME_BUDGET_MS: u64 = 500;

#[derive(Clone)]
pub struct Fast2FlowConfig {
    pub host_bin: PathBuf,
    pub registry_path: PathBuf,
    /// `None` = hard-skip; deployer hasn't pointed at a materialized root.
    pub indexes_path: Option<PathBuf>,
    /// Soft budget; host self-enforces. FIXME(timeout): no process-level kill yet.
    pub time_budget_ms: u64,
    pub gate: Arc<dyn Fast2FlowGate>,
}

impl std::fmt::Debug for Fast2FlowConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fast2FlowConfig")
            .field("host_bin", &self.host_bin)
            .field("registry_path", &self.registry_path)
            .field("indexes_path", &self.indexes_path)
            .field("time_budget_ms", &self.time_budget_ms)
            .field("gate", &self.gate)
            .finish()
    }
}

impl Fast2FlowConfig {
    pub fn from_env() -> Self {
        let host_bin = std::env::var(ENV_HOST_BIN)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_HOST_BIN));
        let registry_path = std::env::var(ENV_REGISTRY_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_REGISTRY_PATH));
        // When the env var is unset, fall back to a per-process temp dir.
        // The pack-fallback materializer writes `<scope>/index.json` here
        // from `assets/intent-index.json` inside the pack, so a pack that
        // ships its routing index inline runs without operator setup.
        // External deployers (k8s, cloud bundle controllers) can still
        // pin a durable path via `GREENTIC_FAST2FLOW_INDEXES_PATH`.
        let indexes_path = Some(
            std::env::var(ENV_INDEXES_PATH)
                .map(PathBuf::from)
                .unwrap_or_else(|_| std::env::temp_dir().join("greentic-fast2flow-indexes")),
        );
        let time_budget_ms = std::env::var(ENV_TIME_BUDGET)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TIME_BUDGET_MS);

        let mut gates: Vec<Arc<dyn Fast2FlowGate>> = vec![Arc::new(BundleCapabilityGate)];
        if std::env::var(ENV_FORCE_ENABLE)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
            gates.push(Arc::new(AlwaysEnabledGate));
        }
        let gate: Arc<dyn Fast2FlowGate> = Arc::new(AnyGate::new(gates));

        Self {
            host_bin,
            registry_path,
            indexes_path,
            time_budget_ms,
            gate,
        }
    }

    pub fn global() -> &'static Self {
        static CONFIG: OnceLock<Fast2FlowConfig> = OnceLock::new();
        CONFIG.get_or_init(Self::from_env)
    }

    /// Cheapest pre-check. `indexes_path` is now always populated
    /// (env-provided or temp-dir default), so this only short-circuits
    /// when an operator explicitly suppresses fast2flow via a follow-up
    /// hook. Kept as a public surface for forward-compat.
    pub fn has_deploy_intent(&self) -> bool {
        self.indexes_path.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging_app::{AppFlowInfo, AppPackInfo};
    use crate::runner_host::OperatorContext;

    fn pack(caps: &[&str]) -> AppPackInfo {
        AppPackInfo {
            pack_id: "pack".into(),
            flows: vec![AppFlowInfo {
                id: "default".into(),
                kind: "messaging".into(),
                subscribes_to: vec![],
                node_ids: vec![],
            }],
            capabilities: caps.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn ctx() -> OperatorContext {
        OperatorContext {
            tenant: "acme".into(),
            team: None,
            correlation_id: None,
        }
    }

    fn config_with(
        indexes_path: Option<&str>,
        force_enable: bool,
        time_budget_ms: u64,
    ) -> Fast2FlowConfig {
        let mut gates: Vec<Arc<dyn Fast2FlowGate>> = vec![Arc::new(BundleCapabilityGate)];
        if force_enable {
            gates.push(Arc::new(AlwaysEnabledGate));
        }
        Fast2FlowConfig {
            host_bin: PathBuf::from(DEFAULT_HOST_BIN),
            registry_path: PathBuf::from(DEFAULT_REGISTRY_PATH),
            indexes_path: indexes_path.map(PathBuf::from),
            time_budget_ms,
            gate: Arc::new(AnyGate::new(gates)),
        }
    }

    #[test]
    fn no_indexes_path_means_no_deploy_intent() {
        let cfg = config_with(None, false, 500);
        assert!(!cfg.has_deploy_intent());
    }

    #[test]
    fn indexes_path_set_implies_deploy_intent() {
        let cfg = config_with(Some("/tmp/indexes"), false, 500);
        assert!(cfg.has_deploy_intent());
    }

    #[test]
    fn bundle_capability_alone_enables_only_declared_packs() {
        let cfg = config_with(Some("/tmp/idx"), false, 500);
        assert!(
            cfg.gate
                .is_enabled(&ctx(), &pack(&["greentic.cap.fast2flow.v1"]))
        );
        assert!(!cfg.gate.is_enabled(&ctx(), &pack(&[])));
    }

    #[test]
    fn force_enable_overrides_undeclared_packs() {
        let cfg = config_with(Some("/tmp/idx"), true, 500);
        assert!(cfg.gate.is_enabled(&ctx(), &pack(&[])));
    }
}

#[cfg(test)]
mod default_env_tests {
    use super::*;

    #[test]
    fn from_env_without_indexes_var_falls_back_to_temp_dir() {
        // SAFETY: tests are single-threaded for env mutation by default in cargo test.
        // We restore the previous state at end.
        let prev = std::env::var(ENV_INDEXES_PATH).ok();
        // SAFETY: removing env var in single-threaded test context.
        unsafe { std::env::remove_var(ENV_INDEXES_PATH) };

        let cfg = Fast2FlowConfig::from_env();
        let path = cfg.indexes_path.as_ref().expect("default should populate");
        assert!(
            path.starts_with(std::env::temp_dir()),
            "default indexes_path should live under temp_dir, got {:?}",
            path
        );
        assert!(cfg.has_deploy_intent());

        // restore
        if let Some(val) = prev {
            // SAFETY: restoring previous env var in single-threaded test context.
            unsafe { std::env::set_var(ENV_INDEXES_PATH, val) };
        }
    }
}
