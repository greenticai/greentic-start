//! Per-request enable gate. Default reads the pack manifest's capabilities;
//! `AnyGate` composes additional sources (operator overrides, sidecars).

use std::sync::Arc;

use crate::messaging_app::AppPackInfo;
use crate::runner_host::OperatorContext;

pub const FAST2FLOW_CAPABILITY: &str = "greentic.cap.fast2flow.v1";

/// Cheap, side-effect-free per-request check. Called on the inbound hot path.
pub trait Fast2FlowGate: Send + Sync + std::fmt::Debug {
    fn is_enabled(&self, ctx: &OperatorContext, pack: &AppPackInfo) -> bool;
}

/// Default: enabled iff the pack manifest declares `FAST2FLOW_CAPABILITY`.
#[derive(Debug, Default, Clone, Copy)]
pub struct BundleCapabilityGate;

impl Fast2FlowGate for BundleCapabilityGate {
    fn is_enabled(&self, _ctx: &OperatorContext, pack: &AppPackInfo) -> bool {
        pack.capabilities.iter().any(|c| c == FAST2FLOW_CAPABILITY)
    }
}

/// Force-enable. Operator override — bypasses bundle intent.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysEnabledGate;

impl Fast2FlowGate for AlwaysEnabledGate {
    fn is_enabled(&self, _ctx: &OperatorContext, _pack: &AppPackInfo) -> bool {
        true
    }
}

/// OR-composition. Empty list means disabled.
#[derive(Debug, Default, Clone)]
pub struct AnyGate {
    gates: Vec<Arc<dyn Fast2FlowGate>>,
}

impl AnyGate {
    pub fn new(gates: Vec<Arc<dyn Fast2FlowGate>>) -> Self {
        Self { gates }
    }

    #[allow(dead_code)] // public API for future composition; not yet consumed in-crate.
    pub fn push(&mut self, gate: Arc<dyn Fast2FlowGate>) {
        self.gates.push(gate);
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.gates.is_empty()
    }
}

impl Fast2FlowGate for AnyGate {
    fn is_enabled(&self, ctx: &OperatorContext, pack: &AppPackInfo) -> bool {
        self.gates.iter().any(|g| g.is_enabled(ctx, pack))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging_app::{AppFlowInfo, AppPackInfo};

    fn ctx() -> OperatorContext {
        OperatorContext {
            tenant: "acme".into(),
            team: None,
            correlation_id: None,
        }
    }

    fn pack(caps: &[&str]) -> AppPackInfo {
        AppPackInfo {
            pack_id: "pack".into(),
            flows: vec![AppFlowInfo {
                id: "default".into(),
                kind: "messaging".into(),
                subscribes_to: vec![],
            }],
            capabilities: caps.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn bundle_gate_requires_declared_capability() {
        let gate = BundleCapabilityGate;
        assert!(!gate.is_enabled(&ctx(), &pack(&[])));
        assert!(!gate.is_enabled(&ctx(), &pack(&["greentic.cap.other.v1"])));
        assert!(gate.is_enabled(&ctx(), &pack(&[FAST2FLOW_CAPABILITY])));
    }

    #[test]
    fn always_gate_ignores_bundle_state() {
        let gate = AlwaysEnabledGate;
        assert!(gate.is_enabled(&ctx(), &pack(&[])));
        assert!(gate.is_enabled(&ctx(), &pack(&[FAST2FLOW_CAPABILITY])));
    }

    #[test]
    fn any_gate_combines_with_or_semantics() {
        let composed = AnyGate::new(vec![
            Arc::new(BundleCapabilityGate),
            Arc::new(AlwaysEnabledGate),
        ]);
        assert!(composed.is_enabled(&ctx(), &pack(&[])));
    }

    #[test]
    fn empty_any_gate_is_disabled() {
        let composed = AnyGate::new(vec![]);
        assert!(composed.is_empty());
        assert!(!composed.is_enabled(&ctx(), &pack(&[FAST2FLOW_CAPABILITY])));
    }
}
