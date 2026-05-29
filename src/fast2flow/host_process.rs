//! Spawn the routing-host binary, pipe JSON in, parse JSON out. Fails open.
//!
//! FIXME(Phase-D-vlad): replace direct spawn with EnvPackRegistry dispatch
//! once `EnvPackHandler` grows an invoke verb in greentic-deployer.
//! FIXME(async-tokio): switch to `tokio::process::Command` when the caller moves async.
//! FIXME(timeout): host self-enforces `time_budget_ms`; add process-level kill if needed.
//! FIXME(wasm-runtime): support the `fast2flow.gtpack` wasm component mode.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use super::contracts::{Fast2FlowHookInV1, Fast2FlowHookOutV1};

pub fn invoke_routing_host(
    host_bin: &Path,
    input: &Fast2FlowHookInV1,
) -> Option<Fast2FlowHookOutV1> {
    let payload = serde_json::to_vec(input).ok()?;

    // Explicitly forward our process env so FAST2FLOW_* tuning vars
    // (MIN_CONFIDENCE, POLICY_PATH, LLM_PROVIDER, …) reach the host.
    // Defensive against any parent-env stripping in the spawn chain.
    let mut child = Command::new(host_bin)
        .envs(std::env::vars())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    {
        let stdin = child.stdin.as_mut()?;
        if stdin.write_all(&payload).is_err() {
            return None;
        }
    }

    let output = child.wait_with_output().ok()?;
    // Surface anything the host wrote to stderr — policy-load failures,
    // FAST2FLOW_TRACE_POLICY output, RUST_LOG diagnostics — so we don't
    // silently drop the host's only feedback channel.
    if !output.stderr.is_empty()
        && let Ok(stderr_text) = std::str::from_utf8(&output.stderr)
    {
        for line in stderr_text.lines().filter(|l| !l.trim().is_empty()) {
            crate::operator_log::info(module_path!(), format!("[fast2flow:host] {line}"));
        }
    }
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice::<Fast2FlowHookOutV1>(&output.stdout).ok()
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::contracts::{MessageEnvelope, RoutingDirective};
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn sample_input() -> Fast2FlowHookInV1 {
        Fast2FlowHookInV1 {
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
            now_unix_ms: 0,
        }
    }

    /// One-shot shell script standing in for the routing-host binary.
    fn fake_host_emitting(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fake-routing-host.sh");
        let mut f = std::fs::File::create(&path).expect("create");
        writeln!(f, "#!/bin/sh\ncat > /dev/null\nprintf '%s' '{body}'").expect("write");
        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("perms");
        (dir, path)
    }

    #[test]
    fn missing_binary_fails_open() {
        let result =
            invoke_routing_host(Path::new("/definitely/not/a/real/binary"), &sample_input());
        assert!(result.is_none());
    }

    #[test]
    fn parses_continue_directive_from_fake_host() {
        let (_dir, bin) = fake_host_emitting(r#"{"directive":{"type":"continue"}}"#);
        let out = invoke_routing_host(&bin, &sample_input()).expect("parsed");
        assert_eq!(out.directive, RoutingDirective::Continue);
    }

    #[test]
    fn parses_dispatch_directive_from_fake_host() {
        let (_dir, bin) = fake_host_emitting(
            r#"{"directive":{"type":"dispatch","target":"support/refund","confidence":0.91,"reason":"keyword match"}}"#,
        );
        let out = invoke_routing_host(&bin, &sample_input()).expect("parsed");
        match out.directive {
            RoutingDirective::Dispatch { target, .. } => assert_eq!(target, "support/refund"),
            other => panic!("expected dispatch, got {other:?}"),
        }
    }

    #[test]
    fn malformed_output_fails_open() {
        let (_dir, bin) = fake_host_emitting("not valid json at all");
        let result = invoke_routing_host(&bin, &sample_input());
        assert!(result.is_none());
    }
}
