#![allow(dead_code)]

use super::{GmapPath, GmapRule, Policy};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MatchDecision {
    pub policy: Policy,
    pub rank: u8,
}

pub fn eval_policy(rules: &[GmapRule], target: &GmapPath) -> Option<MatchDecision> {
    let mut best: Option<MatchDecision> = None;
    let mut best_index = 0usize;
    for (idx, rule) in rules.iter().enumerate() {
        if !matches_target(&rule.path, target) {
            continue;
        }
        let rank = specificity_rank(&rule.path);
        let candidate = MatchDecision {
            policy: rule.policy.clone(),
            rank,
        };
        match best {
            None => {
                best = Some(candidate);
                best_index = idx;
            }
            Some(ref current) => {
                if rank > current.rank || (rank == current.rank && idx > best_index) {
                    best = Some(candidate);
                    best_index = idx;
                }
            }
        }
    }
    best
}

pub fn eval_with_overlay(
    tenant_rules: &[GmapRule],
    team_rules: &[GmapRule],
    target: &GmapPath,
) -> Option<MatchDecision> {
    eval_policy(team_rules, target).or_else(|| eval_policy(tenant_rules, target))
}

fn matches_target(rule: &GmapPath, target: &GmapPath) -> bool {
    match (&rule.pack, &rule.flow, &rule.node) {
        (None, None, None) => true,
        (Some(pack), None, None) => target.pack.as_deref() == Some(pack.as_str()),
        (Some(pack), Some(flow), None) => {
            if flow == "_" {
                target.pack.as_deref() == Some(pack.as_str())
            } else {
                target.pack.as_deref() == Some(pack.as_str())
                    && target.flow.as_deref() == Some(flow.as_str())
            }
        }
        (Some(pack), Some(flow), Some(node)) => {
            target.pack.as_deref() == Some(pack.as_str())
                && target.flow.as_deref() == Some(flow.as_str())
                && target.node.as_deref() == Some(node.as_str())
        }
        _ => false,
    }
}

fn specificity_rank(path: &GmapPath) -> u8 {
    match (&path.pack, &path.flow, &path.node) {
        (None, None, None) => 0,
        (Some(_), None, None) => 3,
        (Some(_), Some(flow), None) if flow == "_" => 2,
        (Some(_), Some(_), None) => 4,
        (Some(_), Some(_), Some(_)) => 5,
        _ => 0,
    }
}
