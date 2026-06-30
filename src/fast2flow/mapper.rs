//! Map Fast2Flow's `RoutingDirective` into the existing `ControlDirective`.
//! Tenant/team inherit from the request context. Confidence + reason are not
//! carried into `ControlDirective`; the caller (`try_for_request`) emits them
//! via `tracing`/operator_log before this mapping, so the routing decision is
//! observable without threading them through the dispatch type.

use crate::ingress::control_directive::{
    ControlDirective, DispatchTarget, IngressReply, PrefillEntity,
};
use crate::runner_host::OperatorContext;

use super::contracts::RoutingDirective;

pub fn map_directive_to_control(
    directive: RoutingDirective,
    ctx: &OperatorContext,
) -> ControlDirective {
    match directive {
        RoutingDirective::Continue => ControlDirective::Continue,
        RoutingDirective::Dispatch {
            target, entities, ..
        } => match parse_target(&target, ctx) {
            Some(dispatch) => ControlDirective::Dispatch {
                target: dispatch,
                entities: entities
                    .into_iter()
                    .map(|e| PrefillEntity {
                        kind: e.kind,
                        normalized: e.normalized,
                        role: e.role,
                        formats: e.formats,
                    })
                    .collect(),
            },
            None => ControlDirective::Continue,
        },
        RoutingDirective::Respond { message } => ControlDirective::Respond {
            reply: IngressReply {
                text: Some(message),
                card_cbor: None,
                status_code: Some(200),
                reason_code: None,
            },
        },
        RoutingDirective::Deny { reason } => ControlDirective::Deny {
            reply: IngressReply {
                text: Some(reason),
                card_cbor: None,
                status_code: Some(403),
                reason_code: None,
            },
        },
    }
}

/// 1–3 `/`-separated segments: `pack`, `pack/flow`, `pack/flow/node`.
fn parse_target(raw: &str, ctx: &OperatorContext) -> Option<DispatchTarget> {
    let segments: Vec<&str> = raw
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if segments.is_empty() || segments.len() > 3 {
        return None;
    }
    let pack = segments[0].to_string();
    if pack.is_empty() {
        return None;
    }
    Some(DispatchTarget {
        tenant: ctx.tenant.clone(),
        team: ctx.team.clone(),
        pack,
        flow: segments.get(1).map(|s| s.to_string()),
        node: segments.get(2).map(|s| s.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> OperatorContext {
        OperatorContext {
            tenant: "acme".into(),
            team: Some("legal".into()),
            correlation_id: None,
        }
    }

    #[test]
    fn continue_maps_to_continue() {
        let mapped = map_directive_to_control(RoutingDirective::Continue, &ctx());
        assert!(matches!(mapped, ControlDirective::Continue));
    }

    #[test]
    fn respond_carries_message_as_text_with_200() {
        let mapped = map_directive_to_control(
            RoutingDirective::Respond {
                message: "hi there".into(),
            },
            &ctx(),
        );
        match mapped {
            ControlDirective::Respond { reply } => {
                assert_eq!(reply.text.as_deref(), Some("hi there"));
                assert_eq!(reply.status_code, Some(200));
            }
            other => panic!("expected respond, got {other:?}"),
        }
    }

    #[test]
    fn deny_carries_reason_with_403() {
        let mapped = map_directive_to_control(
            RoutingDirective::Deny {
                reason: "blocked".into(),
            },
            &ctx(),
        );
        match mapped {
            ControlDirective::Deny { reply } => {
                assert_eq!(reply.text.as_deref(), Some("blocked"));
                assert_eq!(reply.status_code, Some(403));
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_pack_only_inherits_tenant_team() {
        let mapped = map_directive_to_control(
            RoutingDirective::Dispatch {
                target: "support".into(),
                confidence: 0.8,
                reason: "match".into(),
                entities: Vec::new(),
            },
            &ctx(),
        );
        match mapped {
            ControlDirective::Dispatch { target, .. } => {
                assert_eq!(target.tenant, "acme");
                assert_eq!(target.team.as_deref(), Some("legal"));
                assert_eq!(target.pack, "support");
                assert!(target.flow.is_none());
                assert!(target.node.is_none());
            }
            other => panic!("expected dispatch, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_pack_and_flow() {
        let mapped = map_directive_to_control(
            RoutingDirective::Dispatch {
                target: "support/refund_flow".into(),
                confidence: 0.9,
                reason: "refund keyword".into(),
                entities: Vec::new(),
            },
            &ctx(),
        );
        match mapped {
            ControlDirective::Dispatch { target, .. } => {
                assert_eq!(target.pack, "support");
                assert_eq!(target.flow.as_deref(), Some("refund_flow"));
                assert!(target.node.is_none());
            }
            other => panic!("expected dispatch, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_pack_flow_and_node() {
        let mapped = map_directive_to_control(
            RoutingDirective::Dispatch {
                target: "support/refund_flow/confirm".into(),
                confidence: 0.95,
                reason: "deep link".into(),
                entities: Vec::new(),
            },
            &ctx(),
        );
        match mapped {
            ControlDirective::Dispatch { target, .. } => {
                assert_eq!(target.pack, "support");
                assert_eq!(target.flow.as_deref(), Some("refund_flow"));
                assert_eq!(target.node.as_deref(), Some("confirm"));
            }
            other => panic!("expected dispatch, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_too_many_segments_falls_open_to_continue() {
        let mapped = map_directive_to_control(
            RoutingDirective::Dispatch {
                target: "a/b/c/d".into(),
                confidence: 1.0,
                reason: "".into(),
                entities: Vec::new(),
            },
            &ctx(),
        );
        assert!(matches!(mapped, ControlDirective::Continue));
    }

    #[test]
    fn dispatch_empty_target_falls_open_to_continue() {
        let mapped = map_directive_to_control(
            RoutingDirective::Dispatch {
                target: "  /  ".into(),
                confidence: 1.0,
                reason: "".into(),
                entities: Vec::new(),
            },
            &ctx(),
        );
        assert!(matches!(mapped, ControlDirective::Continue));
    }
}
