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

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(path: GmapPath, policy: Policy) -> GmapRule {
        GmapRule {
            path,
            policy,
            line: 1,
        }
    }

    #[test]
    fn eval_policy_prefers_more_specific_and_later_rules() {
        let rules = vec![
            rule(
                GmapPath {
                    pack: None,
                    flow: None,
                    node: None,
                },
                Policy::Forbidden,
            ),
            rule(
                GmapPath {
                    pack: Some("pack".to_string()),
                    flow: Some("flow".to_string()),
                    node: None,
                },
                Policy::Public,
            ),
            rule(
                GmapPath {
                    pack: Some("pack".to_string()),
                    flow: Some("flow".to_string()),
                    node: None,
                },
                Policy::Forbidden,
            ),
        ];
        let target = GmapPath {
            pack: Some("pack".to_string()),
            flow: Some("flow".to_string()),
            node: None,
        };

        let decision = eval_policy(&rules, &target).expect("decision");
        assert_eq!(decision.policy, Policy::Forbidden);
        assert_eq!(decision.rank, 4);
    }

    #[test]
    fn eval_policy_matches_pack_wildcards_and_nodes() {
        let rules = vec![
            rule(
                GmapPath {
                    pack: Some("pack".to_string()),
                    flow: Some("_".to_string()),
                    node: None,
                },
                Policy::Public,
            ),
            rule(
                GmapPath {
                    pack: Some("pack".to_string()),
                    flow: Some("flow".to_string()),
                    node: Some("node".to_string()),
                },
                Policy::Forbidden,
            ),
        ];
        let target = GmapPath {
            pack: Some("pack".to_string()),
            flow: Some("flow".to_string()),
            node: Some("node".to_string()),
        };
        assert_eq!(
            eval_policy(&rules, &target).expect("decision").policy,
            Policy::Forbidden
        );
    }

    #[test]
    fn eval_with_overlay_prefers_team_then_tenant() {
        let tenant_rules = vec![rule(
            GmapPath {
                pack: Some("pack".to_string()),
                flow: None,
                node: None,
            },
            Policy::Forbidden,
        )];
        let team_rules = vec![rule(
            GmapPath {
                pack: Some("pack".to_string()),
                flow: Some("flow".to_string()),
                node: None,
            },
            Policy::Public,
        )];
        let target = GmapPath {
            pack: Some("pack".to_string()),
            flow: Some("flow".to_string()),
            node: None,
        };
        assert_eq!(
            eval_with_overlay(&tenant_rules, &team_rules, &target)
                .expect("team overlay")
                .policy,
            Policy::Public
        );

        assert_eq!(
            eval_with_overlay(&tenant_rules, &[], &target)
                .expect("tenant fallback")
                .policy,
            Policy::Forbidden
        );
    }
}
