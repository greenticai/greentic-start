//! `dispatch_provider_route` has no harness that drives a real provider, so
//! these checks read `revision_serve.rs` and pin WHERE the inbound
//! verification sits, because each placement is a security property:
//! - after the Telegram and Slack gates (one flag, three gates);
//! - before the session pin (a refused request never pins);
//! - before the identify probe and the provider op (a refused request is
//!   never dispatched);
//! - before the approval intercept and the inbound pipeline (an unverified
//!   request never resolves a fetch reference; a forged approval click is
//!   refused before it can resume a parked gate).

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

fn first(needle: &str) -> usize {
    SOURCE
        .find(needle)
        .unwrap_or_else(|| panic!("`{needle}` is gone from revision_serve.rs"))
}

#[test]
fn inbound_verification_runs_between_the_existing_gates_and_the_pin() {
    let telegram = first("provider_auth::authenticate_provider_webhook(");
    let slack = at("provider_webhook_verify::requires_verification");
    let verify = at("crate::inbound_verify::verify_inbound(");
    let pin = at(".commit_pin(tenant, deployment_id, hint, revision_id)");
    assert!(telegram < slack && slack < verify && verify < pin);
}

#[test]
fn inbound_verification_runs_before_any_dispatch_or_fetch() {
    let verify = at("crate::inbound_verify::verify_inbound(");
    let invoke = first(".invoke_provider_for_revision(");
    let intercept = at("crate::approval_rail::intercept_inbound(");
    let hook = at("crate::artifacts::hook::prepare(");
    assert!(verify < invoke && verify < intercept && verify < hook);
}

#[test]
fn a_refusal_returns_before_anything_else_runs_and_only_verified_counts() {
    let verify = at("crate::inbound_verify::verify_inbound(");
    let window = &SOURCE[verify..verify + 1_200];
    assert!(
        window.contains("Err(response) => return Err(response)"),
        "a refusal must end the request:\n{window}"
    );
    assert!(
        window.contains("verdict == crate::inbound_verify::Verdict::Verified"),
        "only `Verified` may raise the flag:\n{window}"
    );
}

/// The secrets environment is resolved once per process, not per request.
#[test]
fn the_secrets_environment_is_not_resolved_per_request() {
    let verify = at("crate::inbound_verify::verify_inbound(");
    let window = &SOURCE[verify..verify + 1_200];
    assert!(
        window.contains("crate::inbound_verify::secrets_env()"),
        "{window}"
    );
    assert!(!window.contains("resolve_env("), "{window}");
}
