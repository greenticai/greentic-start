//! Spawn the routing-host binary, pipe JSON in, parse JSON out. Fails open,
//! with the reason in the `Err` so the caller can log that the router failed.
//!
//! FIXME(Phase-D-vlad): replace direct spawn with EnvPackRegistry dispatch
//! once `EnvPackHandler` grows an invoke verb in greentic-deployer.
//! FIXME(async-tokio): switch to `tokio::process::Command` when the caller moves async.
//! The host is given `time_budget_ms` and enforces it itself; as a backstop a
//! host still running at `time_budget_ms + HOST_GRACE_MS` is killed (its whole
//! process group) and reported as a failure, so a hung host cannot hang the
//! turn or pin the blocking thread it runs on.
//! FIXME(wasm-runtime): support the `fast2flow.gtpack` wasm component mode.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use super::config::ENV_HOST_BIN;
use super::contracts::{Fast2FlowHookInV1, Fast2FlowHookOutV1};
use super::index_refresh::WarnOnce;

/// Time the host gets beyond its own `time_budget_ms` before it is killed:
/// process start-up and JSON round-trip on top of the routing budget.
pub(crate) const HOST_GRACE_MS: u64 = 500;

/// How often a running host is polled for exit.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Host binaries already reported as missing, so a pack that opted into
/// Fast2Flow on a host without the routing host says so ONCE per process
/// rather than only as a per-turn `spawn …: No such file` line.
static MISSING_HOSTS: LazyLock<WarnOnce<PathBuf>> = LazyLock::new(WarnOnce::default);

/// Operator-facing explanation of a routing host that could not be found:
/// where it was looked for and the two ways to fix it.
fn missing_host_hint(host_bin: &Path) -> String {
    let looked_up = if host_bin
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        "at that path"
    } else {
        "on PATH"
    };
    format!(
        "[fast2flow] routing host binary not found: {} (looked up {looked_up}). \
         A pack opted into Fast2Flow, but greentic-start cannot spawn its routing host, \
         so routing is skipped on every turn (fail-open). Install \
         greentic-fast2flow-routing-host on the PATH greentic-start runs with \
         (gtc install writes to $CARGO_HOME/bin, default ~/.cargo/bin) or set \
         {ENV_HOST_BIN} to its absolute path. Reported once per process.",
        host_bin.display()
    )
}

/// Warn once per host path that the routing host is missing. Returns whether
/// this call logged. Changes nothing about the turn: the caller still fails open.
fn report_missing_host(seen: &WarnOnce<PathBuf>, host_bin: &Path) -> bool {
    let first = seen.first(host_bin.to_path_buf());
    if first {
        let hint = missing_host_hint(host_bin);
        crate::operator_log::warn(module_path!(), hint.clone());
        tracing::warn!(target: "greentic.fast2flow", "{hint}");
    }
    first
}

/// What a finished host produced.
struct HostOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Read a pipe to the end on its own thread.
fn drain<R: std::io::Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    })
}

/// `Some(status)` once the host exits, `None` if it is still running at `limit`.
fn wait_with_deadline(child: &mut Child, limit: Duration) -> std::io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Kill the host's process group (unix) and the host itself, then reap it.
fn kill_host(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: plain kill(2) on the group this module created for the host.
        let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Run the routing host. `Err` carries a short, operator-readable reason
/// (spawn failure, non-zero exit, unparseable stdout) — never message text.
pub fn invoke_routing_host_detailed(
    host_bin: &Path,
    input: &Fast2FlowHookInV1,
) -> Result<Fast2FlowHookOutV1, String> {
    let payload = serde_json::to_vec(input).map_err(|err| format!("encode host input: {err}"))?;

    // Explicitly forward our process env so FAST2FLOW_* tuning vars
    // (MIN_CONFIDENCE, POLICY_PATH, LLM_PROVIDER, …) reach the host.
    // Defensive against any parent-env stripping in the spawn chain.
    let mut command = Command::new(host_bin);
    command
        .envs(std::env::vars())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Its own process group, so a timeout kills anything the host started.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            report_missing_host(&MISSING_HOSTS, host_bin);
        }
        format!("spawn {}: {err}", host_bin.display())
    })?;

    // Feed stdin and drain stdout/stderr on their own threads so neither a
    // host that never reads its input nor one that fills a pipe can block us
    // past the deadline.
    let stdin = child.stdin.take();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        match stdin {
            Some(mut stdin) => stdin.write_all(&payload),
            None => Err(std::io::Error::other("host stdin unavailable")),
        }
    });
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());

    let limit = Duration::from_millis(input.time_budget_ms.saturating_add(HOST_GRACE_MS));
    let status = match wait_with_deadline(&mut child, limit) {
        Ok(Some(status)) => status,
        Ok(None) => {
            kill_host(&mut child);
            // Reader threads are not joined: a descendant that escaped the
            // process group could keep a pipe open forever.
            return Err(format!("host timed out after {} ms", limit.as_millis()));
        }
        Err(err) => {
            kill_host(&mut child);
            return Err(format!("wait for host: {err}"));
        }
    };
    match writer.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(format!("write host stdin: {err}")),
        Err(_) => return Err("write host stdin: writer panicked".to_string()),
    }
    let output = HostOutput {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    };
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
        return Err(format!("host exited with {}", output.status));
    }
    serde_json::from_slice::<Fast2FlowHookOutV1>(&output.stdout)
        .map_err(|err| format!("unparseable host output: {err}"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::contracts::{MessageEnvelope, RoutingDirective};
    use super::*;
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
        crate::fast2flow::test_script::write_executable_script(
            &path,
            &format!("cat > /dev/null\nprintf '%s' '{body}'\n"),
        );
        (dir, path)
    }

    #[test]
    fn missing_binary_fails_open() {
        let result = invoke_routing_host_detailed(
            Path::new("/definitely/not/a/real/binary"),
            &sample_input(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn parses_continue_directive_from_fake_host() {
        let (_dir, bin) = fake_host_emitting(r#"{"directive":{"type":"continue"}}"#);
        let out = invoke_routing_host_detailed(&bin, &sample_input()).expect("parsed");
        assert_eq!(out.directive, RoutingDirective::Continue);
    }

    #[test]
    fn parses_dispatch_directive_from_fake_host() {
        let (_dir, bin) = fake_host_emitting(
            r#"{"directive":{"type":"dispatch","target":"support/refund","confidence":0.91,"reason":"keyword match"}}"#,
        );
        let out = invoke_routing_host_detailed(&bin, &sample_input()).expect("parsed");
        match out.directive {
            RoutingDirective::Dispatch { target, .. } => assert_eq!(target, "support/refund"),
            other => panic!("expected dispatch, got {other:?}"),
        }
    }

    #[test]
    fn failures_name_their_reason() {
        let spawn = invoke_routing_host_detailed(
            Path::new("/definitely/not/a/real/binary"),
            &sample_input(),
        )
        .expect_err("spawn fails");
        assert!(spawn.starts_with("spawn "), "{spawn}");
        let (_dir, bin) = fake_host_emitting("not valid json at all");
        let parse = invoke_routing_host_detailed(&bin, &sample_input()).expect_err("parse fails");
        assert!(parse.starts_with("unparseable host output"), "{parse}");
    }

    #[test]
    fn a_missing_host_is_reported_once_per_path() {
        let seen = WarnOnce::default();
        let bare = Path::new("greentic-fast2flow-routing-host");
        assert!(report_missing_host(&seen, bare));
        assert!(!report_missing_host(&seen, bare));
        let explicit = Path::new("/opt/f2f/greentic-fast2flow-routing-host");
        assert!(report_missing_host(&seen, explicit));
        assert!(!report_missing_host(&seen, explicit));
    }

    #[test]
    fn the_missing_host_hint_names_where_it_looked_and_the_override() {
        let bare = missing_host_hint(Path::new("greentic-fast2flow-routing-host"));
        assert!(bare.contains("looked up on PATH"), "{bare}");
        assert!(bare.contains("GREENTIC_FAST2FLOW_HOST_BIN"), "{bare}");
        assert!(bare.contains("~/.cargo/bin"), "{bare}");
        let explicit = missing_host_hint(Path::new("/opt/f2f/host"));
        assert!(explicit.contains("/opt/f2f/host"), "{explicit}");
        assert!(explicit.contains("looked up at that path"), "{explicit}");
    }

    #[test]
    fn a_missing_host_still_fails_open_after_it_was_reported() {
        let bin = Path::new("/definitely/not/a/real/binary-reported");
        for _ in 0..2 {
            let err = invoke_routing_host_detailed(bin, &sample_input()).expect_err("fails open");
            assert!(err.starts_with("spawn "), "{err}");
        }
    }

    #[test]
    fn malformed_output_fails_open() {
        let (_dir, bin) = fake_host_emitting("not valid json at all");
        let result = invoke_routing_host_detailed(&bin, &sample_input());
        assert!(result.is_err());
    }

    /// A host that hangs past its budget is killed — the whole process group,
    /// grandchildren included — and reported as a failure within
    /// budget + grace, so the turn fails open instead of hanging.
    #[test]
    fn a_hung_host_is_killed_after_budget_plus_grace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pids = dir.path().join("pids");
        let bin = dir.path().join("hung-host.sh");
        // The shell records its own pid and its `sleep` child's, then waits:
        // killing only the shell would leave `sleep` holding the pipes.
        crate::fast2flow::test_script::write_executable_script(
            &bin,
            &format!(
                "cat > /dev/null\nsleep 30 &\necho $$ $! > '{}'\nwait\n",
                pids.display()
            ),
        );
        let mut input = sample_input();
        input.time_budget_ms = 100;

        let started = std::time::Instant::now();
        let err = invoke_routing_host_detailed(&bin, &input).expect_err("must time out");
        let elapsed = started.elapsed();
        assert!(err.contains("timed out"), "{err}");
        let limit = std::time::Duration::from_millis(100 + HOST_GRACE_MS + 400);
        assert!(
            elapsed < limit,
            "returned after {elapsed:?}, limit {limit:?}"
        );

        let recorded = std::fs::read_to_string(&pids).expect("pids recorded");
        for pid in recorded.split_whitespace() {
            let pid: i32 = pid.parse().expect("pid");
            let mut gone = false;
            for _ in 0..100 {
                // SAFETY: signal 0 only checks that `pid` exists.
                if unsafe { libc::kill(pid, 0) } != 0 {
                    gone = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(gone, "process {pid} of the hung host is still alive");
        }
    }
}
