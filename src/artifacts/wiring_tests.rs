//! The inbound hook lives in `revision_serve.rs`, which has no harness that
//! can drive a real provider. These checks read that file and pin WHERE the
//! hook sits, because each placement is a security property:
//! - after the request was authenticated (the verdict is what the hook reads),
//! - after the approval intercept (an approval click never reaches it),
//! - inside the task spawned after the HTTP ack (a webhook is never held up),
//! - before the first turn.

const SOURCE: &str = include_str!("../revision_serve.rs");

fn at(needle: &str) -> usize {
    let first = SOURCE
        .find(needle)
        .unwrap_or_else(|| panic!("`{needle}` is gone from revision_serve.rs"));
    assert_eq!(
        SOURCE.matches(needle).count(),
        1,
        "`{needle}` appears more than once; the order checks would be ambiguous"
    );
    first
}

#[test]
fn the_hook_runs_after_verification_and_the_approval_intercept() {
    let verified = at("transport_verified |=");
    let intercept = at("crate::approval_rail::intercept_inbound(");
    let spawn = at("run_provider_inbound_pipeline(\n                    pipeline_activation,");
    assert!(verified < intercept && intercept < spawn);
}

#[test]
fn the_hook_runs_in_the_detached_pipeline_before_the_first_turn() {
    let pipeline = at("async fn run_provider_inbound_pipeline(");
    let hook = at("crate::artifacts::hook::prepare(");
    let turns = at("    for ingress in &envelopes {\n        // Per-envelope flow targeting");
    assert!(pipeline < hook && hook < turns);
}
