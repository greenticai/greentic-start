//! Env-canvas unit usage Phase 2 §7, wired end to end through the listener:
//! a unit whose runtime carries the runner's worker-usage meter
//! (`routing.runtime_metered`) still has every A2A and MCP turn RECORDED, with
//! zero tokens; a unit without it records its tokens as before.
//!
//! The unit tests in `interop::metering::runtime_meter` cover each piece;
//! these fail if `serve_interop` / `serve_mcp` stop consulting the set.

use super::*;
use crate::interop::metering::Meter;

/// A `dw.agent` reply activity carrying a usage reading, the shape
/// greentic-runner-host builds.
fn reply_with_usage() -> Activity {
    Activity::custom(
        "response",
        json!({
            "reply": "Use the reset link.",
            "trail": [],
            "terminated_by": "final",
            "usage": {"tokens_in": 310, "tokens_out": 88, "iterations": 2},
        }),
    )
}

/// Serve one turn on `binding` for a metered unit whose runtime meter is on
/// or off, and return the one usage event the interop reporter queued.
async fn recorded_turn(
    binding: &str,
    runtime_metered: bool,
) -> crate::interop::metering::event::UsageEvent {
    let (activation, _, _) = activation_built(Store::Metered, runtime_metered);
    let meter = Arc::new(Meter::inspectable());
    let state = state_with(
        activation,
        crate::interop::InteropState {
            meter: Arc::clone(&meter),
            ..interop_with_base_url(vec![reply_with_usage()])
        },
    );
    let request = match binding {
        "a2a" => post("/a2a", &[AUTH], &send_message_body("ctx-1")),
        "mcp" => post(
            "/mcp",
            &mcp_headers("tools/call"),
            &tools_call("how?", Some("c-1")),
        ),
        other => panic!("unknown binding {other}"),
    };
    let response = exchange(&state, false, &request).await;
    assert_eq!(response.status, 200, "{binding}: {}", response.body);

    let mut queued = meter.drain();
    assert_eq!(
        queued.len(),
        1,
        "{binding}: the interop turn itself must still be recorded"
    );
    queued.remove(0).event
}

#[tokio::test]
async fn a_runtime_metered_unit_records_its_interop_turns_with_zero_tokens() {
    for binding in ["a2a", "mcp"] {
        let event = recorded_turn(binding, true).await;
        assert_eq!(event.surface, binding);
        assert_eq!(
            (event.tokens_in, event.tokens_out),
            (0, 0),
            "{binding}: the runner meter already recorded these tokens"
        );
        assert_eq!(event.iterations, 2, "{binding}");
        assert_eq!(event.bundle_id, BUNDLE, "{binding}");
    }
}

#[tokio::test]
async fn a_unit_without_the_runtime_meter_records_its_interop_tokens() {
    for binding in ["a2a", "mcp"] {
        let event = recorded_turn(binding, false).await;
        assert_eq!(event.surface, binding);
        assert_eq!((event.tokens_in, event.tokens_out), (310, 88), "{binding}");
        assert_eq!(event.iterations, 2, "{binding}");
    }
}
