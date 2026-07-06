//! Selection of the routed revision(s) from a parsed `RuntimeConfig`.
//!
//! Slice 1a supports only a fully-routed (100%) revision per deployment; a
//! partial canary split (multiple non-zero weights within a deployment) is
//! rejected as [`EnvHomeError::UnsupportedSplit`], and a group whose weights
//! don't sum to exactly 10000 bps is rejected as
//! [`EnvHomeError::InvalidTrafficSplit`].

use super::{EnvHomeError, RevisionRuntimeBlock, RuntimeConfig};
use std::collections::BTreeMap;

/// Select the single routed [`RevisionRuntimeBlock`] for each
/// `deployment_id` present in `rc.revisions`.
///
/// Blocks are grouped by `deployment_id`. Within each group, the
/// `weight_bps` values must sum to exactly `10000`
/// ([`EnvHomeError::InvalidTrafficSplit`] otherwise), and exactly one block
/// must carry the full `10000` weight ([`EnvHomeError::UnsupportedSplit`] if
/// the split is partial, i.e. more than one non-zero-weight block).
pub fn select_routed_revisions(
    rc: &RuntimeConfig,
) -> Result<Vec<&RevisionRuntimeBlock>, EnvHomeError> {
    let mut by_dep: BTreeMap<&str, Vec<&RevisionRuntimeBlock>> = BTreeMap::new();
    for block in &rc.revisions {
        by_dep
            .entry(block.deployment_id.as_str())
            .or_default()
            .push(block);
    }

    let mut selected = Vec::with_capacity(by_dep.len());
    for (dep, blocks) in by_dep {
        let sum: u32 = blocks.iter().map(|b| b.weight_bps).sum();
        if sum != 10000 {
            return Err(EnvHomeError::InvalidTrafficSplit {
                deployment_id: dep.to_string(),
                sum,
            });
        }
        let full: Vec<_> = blocks.iter().filter(|b| b.weight_bps == 10000).collect();
        match full.as_slice() {
            [only] => selected.push(**only),
            _ => {
                return Err(EnvHomeError::UnsupportedSplit {
                    deployment_id: dep.to_string(),
                });
            }
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_home::{EnvHomeError, RevisionRuntimeBlock, RuntimeConfig};

    fn block(dep: &str, rev: &str, w: u32) -> RevisionRuntimeBlock {
        RevisionRuntimeBlock {
            deployment_id: dep.into(),
            revision_id: rev.into(),
            bundle_id: "app".into(),
            pack_list_refs: vec![],
            pack_config_refs: vec![],
            weight_bps: w,
        }
    }
    fn rc(revs: Vec<RevisionRuntimeBlock>) -> RuntimeConfig {
        RuntimeConfig {
            schema: crate::env_home::RUNTIME_CONFIG_SCHEMA.into(),
            env_id: "local".into(),
            revisions: revs,
        }
    }

    #[test]
    fn selects_single_full_weight_revision() {
        let cfg = rc(vec![block("dep-1", "rev-1", 10000)]);
        let sel = select_routed_revisions(&cfg).expect("select");
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].revision_id, "rev-1");
    }

    #[test]
    fn rejects_weights_not_summing_to_10000() {
        let cfg = rc(vec![block("dep-1", "rev-1", 9000)]);
        assert!(matches!(
            select_routed_revisions(&cfg).unwrap_err(),
            EnvHomeError::InvalidTrafficSplit { .. }
        ));
    }

    #[test]
    fn rejects_partial_split() {
        let cfg = rc(vec![
            block("dep-1", "rev-1", 6000),
            block("dep-1", "rev-2", 4000),
        ]);
        assert!(matches!(
            select_routed_revisions(&cfg).unwrap_err(),
            EnvHomeError::UnsupportedSplit { .. }
        ));
    }

    #[test]
    fn selects_full_weight_block_ignoring_zero_weight_block() {
        let cfg = rc(vec![
            block("dep-1", "rev-zero", 0),
            block("dep-1", "rev-full", 10000),
        ]);
        let sel = select_routed_revisions(&cfg).expect("select");
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].revision_id, "rev-full");
    }

    #[test]
    fn selects_one_revision_per_deployment_across_multiple_deployments() {
        let cfg = rc(vec![
            block("dep-1", "rev-1", 10000),
            block("dep-2", "rev-2", 10000),
        ]);
        let mut sel = select_routed_revisions(&cfg).expect("select");
        sel.sort_by(|a, b| a.deployment_id.cmp(&b.deployment_id));
        assert_eq!(sel.len(), 2);
        assert_eq!(sel[0].deployment_id, "dep-1");
        assert_eq!(sel[1].deployment_id, "dep-2");
    }
}
