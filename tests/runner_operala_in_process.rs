//! `operala.call` runs in-process in this binary (greentic-runner #774).
//!
//! greentic-start is the runtime every deployed bundle serves through (operator
//! environment, k8s, Cloud Run, the distroless image). A Deep worker compiles to
//! an `operala.call` flow node, and without runner-host's `operala-in-process`
//! feature that node can only dispatch over NATS — which no deployed lane runs —
//! so a Deep worker would load and then fail every turn.
//!
//! These tests pin two things:
//! - the in-process selector is COMPILED IN: `select_operala_handler` and
//!   `OperalaSelection` exist only under `operala-in-process`, so dropping the
//!   feature fails this file to compile rather than shipping silently;
//! - the manifest enables it WITHOUT `desktop-agent-ephemeral`, which drags
//!   greentic-aw-runtime's `test-mock` into the server binary.

use greentic_runner_host::runner::operala_node::{OperalaSelection, select_operala_handler};

#[tokio::test]
async fn nats_dispatch_keeps_the_remote_path_and_never_reads_a_key() {
    let selection = select_operala_handler(
        Some("nats"),
        || async { panic!("GREENTIC_OPERALA_DISPATCH=nats must not resolve an LLM key") },
        None,
        None,
        None,
    )
    .await;
    assert!(matches!(selection, OperalaSelection::Nats));
}

#[tokio::test]
async fn a_resolved_key_wires_the_in_process_handler() {
    let selection = select_operala_handler(
        None,
        || async { Some("sk-test".to_string()) },
        None,
        Some("openai".to_string()),
        Some("gpt-4o-mini".to_string()),
    )
    .await;
    assert!(
        matches!(selection, OperalaSelection::InProcess(_)),
        "with a key and no NATS override, operala.call must run in-process"
    );
}

#[tokio::test]
async fn no_key_reports_no_key_rather_than_wiring_a_keyless_handler() {
    let selection = select_operala_handler(None, || async { None }, None, None, None).await;
    assert!(matches!(selection, OperalaSelection::NoKey));
}

/// The `features = [...]` list under `[dependencies.greentic-runner-host]`.
fn runner_host_features() -> String {
    let manifest = include_str!("../Cargo.toml");
    let section = manifest
        .split("[dependencies.greentic-runner-host]")
        .nth(1)
        .expect("Cargo.toml declares [dependencies.greentic-runner-host]");
    let section = section.split("\n[").next().unwrap_or(section);
    section
        .lines()
        .find(|line| line.trim_start().starts_with("features"))
        .expect("greentic-runner-host declares a features list")
        .to_string()
}

#[test]
fn runner_host_enables_operala_in_process_but_not_the_desktop_feature() {
    let features = runner_host_features();
    assert!(
        features.contains("\"operala-in-process\""),
        "runner-host must enable operala-in-process: {features}"
    );
    assert!(
        features.contains("\"greentic-llm-backend\""),
        "runner-host must keep greentic-llm-backend for dw.agent: {features}"
    );
    for forbidden in ["desktop-agent-ephemeral", "dev-allow-unsigned", "test-mock"] {
        assert!(
            !features.contains(forbidden),
            "`{forbidden}` must stay OFF in the server binary: {features}"
        );
    }
}
