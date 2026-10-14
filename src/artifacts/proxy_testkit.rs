//! Test-only: prove a client ignores the proxy environment.
//!
//! `reqwest` reads `HTTP(S)_PROXY`/`ALL_PROXY` when a client is BUILT, and the
//! environment is process-global, so setting it in a running test binary would
//! leak a proxy into every other test building a client at that moment. The
//! check therefore runs in a child copy of the test binary started with the
//! proxy variables set: the parent runs one `#[ignore]`d child test and counts
//! connections to the fake proxy.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Env var through which the parent hands the child its target URL.
pub(crate) const TARGET_ENV: &str = "GREENTIC_TEST_PROXY_TARGET";

/// A fake proxy: accepts and counts connections, answers nothing.
pub(crate) async fn fake_proxy() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            held.push(stream);
        }
    });
    (format!("http://127.0.0.1:{port}"), count)
}

/// Run the ignored test `child` (full path) in a copy of this test binary
/// with every proxy variable pointing at `proxy`; `true` when it passed.
pub(crate) async fn run_child_behind_proxy(child: &str, proxy: &str, target: &str) -> bool {
    let exe = std::env::current_exe().unwrap();
    let mut command = tokio::process::Command::new(exe);
    command
        .args([child, "--exact", "--ignored", "--test-threads=1"])
        .env("HTTP_PROXY", proxy)
        .env("HTTPS_PROXY", proxy)
        .env("ALL_PROXY", proxy)
        .env("http_proxy", proxy)
        .env("https_proxy", proxy)
        .env("all_proxy", proxy)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .env(TARGET_ENV, target)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = command.output().await.unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    out.status.success() && stdout.contains("1 passed")
}
