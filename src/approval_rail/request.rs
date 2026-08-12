//! Reading a `greentic.approval.request.v1` message off the rail.
//!
//! Contract: `greentic-designer/docs/approval-rail-contract-v2.md` §1 and §2.
//! Two rules from §1 shape this module and both have a wrong reading that
//! works most of the time:
//!
//! * **Unknown keys are ignored, in both directions.** That is the mechanism by
//!   which the contract grows without a coordinated release across four
//!   repositories (§7 already reserves two additions), so nothing here is
//!   `deny_unknown_fields` and nothing asserts on a key count. The body is
//!   carried to delivery verbatim rather than being re-serialized from a typed
//!   model, so a field this build has never heard of still reaches the channel.
//! * **The correlation id identifies the gate.** It is the header, falling back
//!   to `target` (§2 says the two are the same string). A `pack=` shaped id
//!   belongs to the flow rail, not here.
//!
//! `Greentic-Tenant` is deliberately not read. Per §1 it is the executor's
//! checkpoint-partition tenant on the first publish and the approval row's real
//! tenant on a sweeper republish — the two differ for the same gate — so
//! keying anything on it is a bug. See `crate::approval_rail`'s module docs for
//! how this bridge identifies a tenant instead.

use serde_json::Value;

use super::body::RailBody;

/// Why a message on the request subject was not delivered.
///
/// Stable snake_case tokens, carrying no credential material — a `Display`
/// rendering of one of these ends up in an operator log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestParseError {
    /// Not JSON, or not a JSON object.
    Undecodable,
    /// `operation` was not `"request"`. A response or an unknown operation on
    /// this subject is somebody else's traffic, not an error to report loudly.
    NotARequest,
    /// Neither the header nor `target` named a gate.
    NoCorrelationId,
    /// A correlation id shaped `…::pack=…` belongs to the flow rail (§1).
    NotAnApprovalGate,
}

impl RequestParseError {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestParseError::Undecodable => "undecodable",
            RequestParseError::NotARequest => "not_a_request",
            RequestParseError::NoCorrelationId => "no_correlation_id",
            RequestParseError::NotAnApprovalGate => "not_an_approval_gate",
        }
    }
}

/// One approval request, ready to hand to a delivery component.
#[derive(Clone, Debug, PartialEq)]
pub struct RailRequest {
    /// `<checkpoint-tenant>::run=<run_id>::node=<node_id>`. Not a credential.
    pub correlation_id: String,
    /// `routing.channels`, in the designer's order. **Advisory** (§2): the
    /// designer neither enforces nor verifies it, so this is used only to
    /// prefer one installed delivery provider over another, never to decide
    /// whether a request may be delivered.
    pub channels: Vec<String>,
    /// The request body, verbatim, including a `routing.decision_token` this
    /// crate never reads.
    pub body: RailBody,
}

/// Parse one message off `greentic.approval.request.v1`.
///
/// `correlation_header` is the message's `Greentic-Correlation-Id`, when it
/// carried one.
pub fn parse(
    correlation_header: Option<&str>,
    payload: &[u8],
) -> Result<RailRequest, RequestParseError> {
    let value: Value =
        serde_json::from_slice(payload).map_err(|_| RequestParseError::Undecodable)?;
    if !value.is_object() {
        return Err(RequestParseError::Undecodable);
    }

    if value.get("operation").and_then(Value::as_str) != Some("request") {
        return Err(RequestParseError::NotARequest);
    }

    let correlation_id = correlation_header
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            value
                .get("target")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|target| !target.is_empty())
                .map(str::to_string)
        })
        .ok_or(RequestParseError::NoCorrelationId)?;

    // §1: "a correlation id shaped `…::pack=…` belongs to the flow rail and is
    // ignored here". Checked on the segment, not with `contains`, so a run id
    // that merely spells the word is not mistaken for a flow-rail id.
    if correlation_id
        .split("::")
        .any(|segment| segment.starts_with("pack="))
    {
        return Err(RequestParseError::NotAnApprovalGate);
    }

    // Read defensively, field by field. §7 reserves a change that turns
    // `approvers` from an object into an array; reading each field
    // independently is what makes such a change degrade one field instead of
    // failing the delivery.
    let channels = value
        .get("routing")
        .and_then(|routing| routing.get("channels"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    Ok(RailRequest {
        correlation_id,
        channels,
        body: RailBody::new(value),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The contract's own conformance fixture, vendored so a drift in the
    /// designer's payload fails here rather than in production.
    const CONFORMANCE_REQUEST: &str =
        include_str!("../../tests/fixtures/approval_rail/request_v2.json");

    #[test]
    fn the_conformance_fixture_parses() {
        let request = parse(
            Some("default::run=RUN-1::node=gate"),
            CONFORMANCE_REQUEST.as_bytes(),
        )
        .expect("the contract's own fixture must parse");

        assert_eq!(request.correlation_id, "default::run=RUN-1::node=gate");
        assert_eq!(request.channels, vec!["slack".to_string()]);
        // Carried verbatim — including the token this crate never reads.
        assert_eq!(
            request.body.expose()["routing"]["decision_token"],
            "EXAMPLE-TOKEN-NOT-A-REAL-SECRET"
        );
        assert_eq!(request.body.expose()["input"]["title"], "Refund 1200 USD");
    }

    #[test]
    fn the_header_wins_over_target_and_target_is_the_fallback() {
        let body = json!({"target": "from-body::run=R::node=n", "operation": "request"});
        let bytes = serde_json::to_vec(&body).expect("serialize");

        let from_header = parse(Some("from-header::run=R::node=n"), &bytes).expect("parse");
        assert_eq!(from_header.correlation_id, "from-header::run=R::node=n");

        let from_target = parse(None, &bytes).expect("parse");
        assert_eq!(from_target.correlation_id, "from-body::run=R::node=n");

        let blank_header = parse(Some("   "), &bytes).expect("parse");
        assert_eq!(blank_header.correlation_id, "from-body::run=R::node=n");
    }

    #[test]
    fn a_flow_rail_correlation_id_is_not_an_approval_gate() {
        let bytes = serde_json::to_vec(&json!({
            "target": "default::pack=p1::node=gate",
            "operation": "request",
        }))
        .expect("serialize");
        assert_eq!(
            parse(None, &bytes),
            Err(RequestParseError::NotAnApprovalGate)
        );

        // A run id that merely spells the word is still an approval gate.
        let bytes = serde_json::to_vec(&json!({
            "target": "default::run=repack=1::node=gate",
            "operation": "request",
        }))
        .expect("serialize");
        assert_eq!(
            parse(None, &bytes).expect("parse").correlation_id,
            "default::run=repack=1::node=gate"
        );
    }

    #[test]
    fn only_a_request_operation_is_delivered() {
        for operation in ["response", "", "REQUEST"] {
            let bytes = serde_json::to_vec(&json!({
                "target": "default::run=R::node=n",
                "operation": operation,
            }))
            .expect("serialize");
            assert_eq!(parse(None, &bytes), Err(RequestParseError::NotARequest));
        }
    }

    #[test]
    fn an_absent_routing_block_still_delivers() {
        // §2: "The whole `routing` block may be absent from a request", and
        // when present may carry `decision_token` alone. Delivery must render a
        // generic affordance rather than failing.
        let bytes = serde_json::to_vec(&json!({
            "target": "default::run=R::node=n",
            "operation": "request",
            "input": {"title": "Refund"},
        }))
        .expect("serialize");
        let request = parse(None, &bytes).expect("an absent routing block must still parse");
        assert!(request.channels.is_empty());

        let bytes = serde_json::to_vec(&json!({
            "target": "default::run=R::node=n",
            "operation": "request",
            "routing": {"decision_token": "tok"},
        }))
        .expect("serialize");
        let request = parse(None, &bytes).expect("a token-only routing block must still parse");
        assert!(request.channels.is_empty());
    }

    #[test]
    fn unknown_keys_are_ignored_rather_than_refused() {
        // §1's additive promise, and §7's two reserved additions. A future
        // designer publishing `approvers` as an ARRAY (the reserved
        // per-approver-token shape) must still deliver.
        let bytes = serde_json::to_vec(&json!({
            "target": "default::run=R::node=n",
            "operation": "request",
            "routing": {
                "channels": ["slack"],
                "approvers": [{"email": "boss@acme.test", "decision_token": "tok"}],
                "some_field_from_the_future": {"nested": true},
            },
            "another_top_level_key": 7,
        }))
        .expect("serialize");
        let request = parse(None, &bytes).expect("unknown keys must not fail the parse");
        assert_eq!(request.channels, vec!["slack".to_string()]);
        assert_eq!(request.body.expose()["another_top_level_key"], 7);
    }

    #[test]
    fn a_malformed_channels_entry_is_dropped_not_fatal() {
        let bytes = serde_json::to_vec(&json!({
            "target": "default::run=R::node=n",
            "operation": "request",
            "routing": {"channels": ["slack", 7, "", "  ", "teams"]},
        }))
        .expect("serialize");
        let request = parse(None, &bytes).expect("parse");
        assert_eq!(
            request.channels,
            vec!["slack".to_string(), "teams".to_string()]
        );
    }

    #[test]
    fn undecodable_and_gateless_messages_are_reported_distinctly() {
        assert_eq!(
            parse(None, b"{ not json"),
            Err(RequestParseError::Undecodable)
        );
        assert_eq!(parse(None, b""), Err(RequestParseError::Undecodable));
        assert_eq!(
            parse(None, b"[\"an array is not a request body\"]"),
            Err(RequestParseError::Undecodable)
        );

        let bytes = serde_json::to_vec(&json!({"operation": "request"})).expect("serialize");
        assert_eq!(parse(None, &bytes), Err(RequestParseError::NoCorrelationId));
    }
}
