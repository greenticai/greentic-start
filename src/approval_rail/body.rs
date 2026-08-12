//! A rail body that may carry a `decision_token`.
//!
//! The approval rail contract (`greentic-designer/docs/approval-rail-contract-v2.md`,
//! §4) forbids the token reaching a log line at any level, in any form —
//! including truncated, hashed, and on failure paths. This crate never needs to
//! read the token: a request body is handed to the delivery component verbatim
//! and a response body is published verbatim. But a bare [`serde_json::Value`]
//! leaks through any `{:?}` or `{}` a future edit adds, and this repo sits in
//! the middle of the token's path, which makes it the easiest place to leak one.
//!
//! So every rail body held here is wrapped. `Debug` and `Display` are redacted
//! and the only reader is [`RailBody::expose`], which is greppable — the same
//! shape `provider-common`'s `DecisionToken` uses on the other side of the wire,
//! and the same shape [`crate::secret_value::SecretValue`] already uses here.

use std::fmt;

use serde_json::Value;

/// A `greentic.approval.request.v1` or `greentic.approval.response.v1` body.
///
/// Cheap to clone; the inner value is only ever moved or serialized.
#[derive(Clone, PartialEq)]
pub struct RailBody(Value);

impl RailBody {
    pub fn new(value: Value) -> Self {
        Self(value)
    }

    /// Every call site of this is a place a `decision_token` can escape.
    pub fn expose(&self) -> &Value {
        &self.0
    }

    /// Serialize for the wire. Same caveat as [`RailBody::expose`].
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&self.0)
    }
}

impl fmt::Debug for RailBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RailBody(<redacted>)")
    }
}

impl fmt::Display for RailBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body_with_token() -> RailBody {
        RailBody::new(json!({
            "target": "default::run=RUN-1::node=gate",
            "operation": "request",
            "routing": {"decision_token": "s3cr3t-token-value"},
        }))
    }

    #[test]
    fn debug_never_prints_the_decision_token() {
        let rendered = format!("{:?}", body_with_token());
        assert_eq!(rendered, "RailBody(<redacted>)");
        assert!(!rendered.contains("s3cr3t"));
    }

    #[test]
    fn display_never_prints_the_decision_token() {
        let rendered = format!("{}", body_with_token());
        assert_eq!(rendered, "<redacted>");
        assert!(!rendered.contains("s3cr3t"));
    }

    #[test]
    fn a_body_inside_a_larger_debug_render_stays_redacted() {
        // The realistic leak is not `format!("{body:?}")` on its own — it is a
        // body reaching a log line as a field of some other struct.
        #[derive(Debug)]
        struct Carrier {
            correlation_id: String,
            body: RailBody,
        }
        let carrier = Carrier {
            correlation_id: "default::run=RUN-1::node=gate".to_string(),
            body: body_with_token(),
        };
        assert_eq!(carrier.correlation_id, "default::run=RUN-1::node=gate");
        assert_eq!(carrier.body.expose()["operation"], "request");

        let rendered = format!("{carrier:?}");
        assert!(rendered.contains("default::run=RUN-1::node=gate"));
        assert!(!rendered.contains("s3cr3t"), "rendered: {rendered}");
    }

    #[test]
    fn the_wire_bytes_still_carry_the_body_verbatim() {
        let bytes = body_with_token().to_wire_bytes().expect("serialize");
        let decoded: Value = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(decoded["routing"]["decision_token"], "s3cr3t-token-value");
    }
}
