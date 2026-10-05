//! Local mirror of `fast2flow-contracts` types. FIXME(contracts-dep): swap
//! for a crates.io dep when published so contract bumps fail compile here.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fast2FlowHookInV1 {
    pub scope: String,
    pub envelope: MessageEnvelope,
    pub session_active: bool,
    pub input_locale: String,
    pub time_budget_ms: u64,
    pub registry_path: String,
    pub indexes_path: String,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageEnvelope {
    pub text: String,
    pub channel: Option<String>,
    pub provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fast2FlowHookOutV1 {
    pub directive: RoutingDirective,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RoutingDirective {
    Continue,
    Dispatch {
        target: String,
        confidence: f32,
        reason: String,
        /// Entities extracted by the routing host's intent prefill.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        entities: Vec<RoutingEntity>,
    },
    Respond {
        message: String,
    },
    Deny {
        reason: String,
    },
}

/// Mirrors `fast2flow_contracts::RoutingEntity`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RoutingEntity {
    pub kind: String,
    pub normalized: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Alternate serializations keyed by format name (e.g. `"iso"`).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub formats: std::collections::BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The routing host derives its index scope from `messaging_endpoint_id`
    /// when the request carries one, IGNORING `scope`
    /// (`fast2flow_contracts::Fast2FlowHookInV1::effective_scope`, greentic-fast2flow
    /// `ec88623`). This mirror has no such field, so the scope this crate
    /// sends — the revision-qualified one on the revision-serve path — is the
    /// one the host reads.
    #[test]
    fn the_hook_input_never_carries_a_messaging_endpoint_id() {
        let input = Fast2FlowHookInV1 {
            scope: "acme:default--00".to_string(),
            envelope: MessageEnvelope {
                text: "hi".to_string(),
                channel: None,
                provider: Some("webchat".to_string()),
            },
            session_active: false,
            input_locale: "en".to_string(),
            time_budget_ms: 500,
            registry_path: "/r".to_string(),
            indexes_path: "/i".to_string(),
            now_unix_ms: 0,
        };
        let wire = serde_json::to_value(&input).unwrap();
        assert!(wire.get("messaging_endpoint_id").is_none(), "{wire}");
        assert_eq!(wire["scope"], "acme:default--00");
    }

    #[test]
    fn directive_continue_round_trips() {
        let out: Fast2FlowHookOutV1 =
            serde_json::from_str(r#"{"directive":{"type":"continue"}}"#).unwrap();
        assert_eq!(out.directive, RoutingDirective::Continue);
    }

    #[test]
    fn directive_dispatch_round_trips() {
        let json = r#"{"directive":{"type":"dispatch","target":"support/refund_flow","confidence":0.87,"reason":"matched 'refund'"}}"#;
        let out: Fast2FlowHookOutV1 = serde_json::from_str(json).unwrap();
        match out.directive {
            RoutingDirective::Dispatch {
                target,
                confidence,
                reason,
                entities,
            } => {
                assert_eq!(target, "support/refund_flow");
                assert!((confidence - 0.87).abs() < 1e-6);
                assert_eq!(reason, "matched 'refund'");
                assert!(entities.is_empty(), "no entities in canonical fixture");
            }
            other => panic!("expected dispatch, got {other:?}"),
        }
    }

    #[test]
    fn directive_respond_round_trips() {
        let json = r#"{"directive":{"type":"respond","message":"hi"}}"#;
        let out: Fast2FlowHookOutV1 = serde_json::from_str(json).unwrap();
        match out.directive {
            RoutingDirective::Respond { message } => assert_eq!(message, "hi"),
            other => panic!("expected respond, got {other:?}"),
        }
    }

    #[test]
    fn directive_deny_round_trips() {
        let json = r#"{"directive":{"type":"deny","reason":"policy"}}"#;
        let out: Fast2FlowHookOutV1 = serde_json::from_str(json).unwrap();
        match out.directive {
            RoutingDirective::Deny { reason } => assert_eq!(reason, "policy"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn hook_in_round_trip() {
        let input = Fast2FlowHookInV1 {
            scope: "acme:default".into(),
            envelope: MessageEnvelope {
                text: "hello".into(),
                channel: Some("chat".into()),
                provider: Some("teams".into()),
            },
            session_active: true,
            input_locale: "en-US".into(),
            time_budget_ms: 500,
            registry_path: "/mnt/registry".into(),
            indexes_path: "/mnt/indexes".into(),
            now_unix_ms: 1_700_000_000_000,
        };
        let json = serde_json::to_string(&input).unwrap();
        let parsed: Fast2FlowHookInV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, input);
    }
}
