# Unconditional HTTP Listener Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `greentic-start` always bind its HTTP listener so a bundle with no messaging channel still answers `/healthz`, instead of being silently portless and reported dead.

**Architecture:** Delete the channel-dependent gate in `start_http_ingress_server` so it always returns `Some`. Probes need no new code — `handle_builtin_health_request` is already dispatched ahead of all routing and never consults a provider. Strict bind (range 0) is retained on purpose: we are removing a *silent* failure, and a silent port shift would relocate it. The PR is deliberately narrow — see "Deviations from the spec" at the end for the two cleanups the spec asked for and this plan defers, with reasons.

**Tech Stack:** Rust 1.95.0, `anyhow`, `tokio`, `hyper` (ingress), `reqwest` (blocking, already a main dependency at `Cargo.toml:63`), `tempfile` (dev-dep).

## Global Constraints

- Repo: `greentic-start`, version `1.3.0-research.0`, branch `feat/unconditional-http-listener` off `origin/research`.
- Worktree: `/home/bima-pangestu/.cache/wt/start-listener-gate`. All paths below are relative to it.
- Rust 1.95.0 pinned via `rust-toolchain.toml`. Do not edit it.
- English only in source, tests, comments, and commit messages.
- No `unwrap()` / `panic!()` in production paths — `anyhow` / `thiserror`. Tests may use `expect()`.
- Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`).
- `#![forbid(unsafe_code)]` is the norm — but note `src/lib.rs` and `src/bundle_config.rs` tests already use `unsafe { std::env::set_var }` (Rust 2024 requirement). Follow that existing precedent in test code only.
- **Test port convention:** this repo uses fixed high ports, not dynamic allocation (`src/port_utils.rs` tests use 19876–19891). Under strict bind (range 0) a lost TOCTOU race is a hard failure, so dynamic allocation would be *less* reliable. This plan assigns fixed ports in the 19900+ block, which does not collide with existing usage.
- Final gate: `bash ci/local_check.sh` must pass from the worktree root.

---

### Task 1: Pin explicit ports in the hermetic boot tests

These three tests boot through `run_start_request` with a bundle that declares no gateway port, so they inherit `default_gateway_port()` = 8080 (`src/config.rs:409-411`). Today the gate keeps them portless. The moment Task 2 lands they would all bind 8080 and race.

This race is real, not theoretical: `ci/local_check.sh:19` runs `cargo test --all-features` with default parallelism, and cargo runs test *binaries* as separate OS processes. `test_env_lock()` (`src/lib.rs:942`) is an in-process mutex — it cannot serialize `tests/env_home_boot.rs`, which is a different process. Under range 0 the loser hard-fails.

Doing this first keeps every commit green: the env var is simply inert while the gate still exists.

**Files:**
- Modify: `src/lib.rs:1216-1238` (`run_start_request_embedded_mode_stops_cleanly`)
- Modify: `src/lib.rs:1240-1263` (`run_restart_request_embedded_mode_stops_cleanly`)
- Modify: `tests/env_home_boot.rs:14-19` (module doc), `tests/env_home_boot.rs:95-139` (`boots_from_env_home_and_stops_cleanly`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: no production API. Establishes the port assignment later tasks must not collide with: 19903 (`lib.rs` start), 19904 (`lib.rs` restart), 19905 (env-home boot). Task 2 uses 19901/19902/19906, Task 3 uses 19907.

- [ ] **Step 1: Add a port-pinning guard to the two `src/lib.rs` boot tests**

Both tests already hold `test_env_lock()`, so mutating a process-global env var is serialized against the rest of the `lib.rs` test binary. Add the `set_var` immediately after the existing lock guard, and remove it at the end.

In `src/lib.rs`, in `run_start_request_embedded_mode_stops_cleanly` (line 1217), after the `crate::operator_log::reset_for_tests();` line, insert:

```rust
        // Pin an explicit port: since the ingress listener now always binds,
        // the default 8080 would race with the other boot tests (and with
        // whatever else owns 8080 on a dev machine). Strict bind (range 0)
        // turns such a collision into a hard failure, so the port must be
        // deterministic and unique per test.
        unsafe {
            std::env::set_var("GREENTIC_GATEWAY_PORT", "19903");
        }
```

and immediately before the closing `}` of that test function, after the final `assert!`, insert:

```rust
        unsafe {
            std::env::remove_var("GREENTIC_GATEWAY_PORT");
        }
```

In `run_restart_request_embedded_mode_stops_cleanly` (line 1241), do the same with port `19904`:

```rust
        unsafe {
            std::env::set_var("GREENTIC_GATEWAY_PORT", "19904");
        }
```

and before its closing `}`:

```rust
        unsafe {
            std::env::remove_var("GREENTIC_GATEWAY_PORT");
        }
```

- [ ] **Step 2: Pin the port in `tests/env_home_boot.rs` and correct its module doc**

In `tests/env_home_boot.rs`, replace the module doc lines 14-19 (the paragraph beginning `//! With zero packs in the fixture,`) with:

```rust
//! With zero packs in the fixture, `demo_up_services` takes the existing
//! "embedded runner" path (no gateway/egress/nats spawned), so this reaches
//! and passes through a real `load_env_home` call, a real
//! `bundle_config::load_runtime_demo_config`, and a real `demo_up_services`
//! run, then exits cleanly via a stop-request file — with no external
//! binaries and no gating/skip needed.
//!
//! The ingress listener always binds (it is not gated on discovering a
//! messaging provider), so this test pins `GREENTIC_GATEWAY_PORT` to a fixed
//! high port rather than inheriting the 8080 default, which would race with
//! the boot tests in `src/lib.rs` running as a separate process.
```

In `boots_from_env_home_and_stops_cleanly` (line 96), insert immediately after `let store_root = temp.path().join("store-root");`:

```rust
    // See the module doc: the listener always binds, so pin a unique port.
    unsafe {
        std::env::set_var("GREENTIC_GATEWAY_PORT", "19905");
    }
```

and immediately before the final closing `}` of that test, after the last `assert!`:

```rust
    unsafe {
        std::env::remove_var("GREENTIC_GATEWAY_PORT");
    }
```

Also update the stale claim in the fixture doc comment at `tests/env_home_boot.rs:30-37`: change the trailing phrase `"zero packs -> embedded runner mode, no gateway" path.` to `"zero packs -> embedded runner mode, no supervised gateway process" path.` — the in-process ingress listener is not a gateway *process*, and after this PR that distinction stops being academic.

- [ ] **Step 3: Run the affected tests to verify they still pass (gate still present, env var inert)**

Run:
```bash
cd /home/bima-pangestu/.cache/wt/start-listener-gate
cargo test --all-features run_start_request_embedded_mode_stops_cleanly -- --nocapture
cargo test --all-features run_restart_request_embedded_mode_stops_cleanly -- --nocapture
cargo test --all-features --test env_home_boot -- --nocapture
```
Expected: all PASS. The gate is still in place, so no listener binds yet and the env var has no effect — this step only proves the edits did not break anything.

- [ ] **Step 4: Commit**

```bash
git add src/lib.rs tests/env_home_boot.rs
git commit -m "test(boot): pin explicit gateway ports in hermetic boot tests

These three tests inherit the 8080 default and are kept portless today only
by the ingress gate. Once the listener always binds they would all bind 8080
and race: cargo runs test binaries as separate processes, so test_env_lock()
cannot serialize tests/env_home_boot.rs against src/lib.rs, and strict bind
(range 0) turns the collision into a hard failure rather than a port bump.

Pin fixed high ports (19903/19904/19905) following the existing convention in
src/port_utils.rs tests. Inert until the gate is removed."
```

---

### Task 2: Remove the gate so the listener always binds

The core change. `domains` is computed from discovered provider packs (`src/runtime.rs:1617-1651`), and every component declaring `ingest_http` is a messaging provider — so this gate makes "does a port open?" depend on "did you attach a chat channel?".

**Files:**
- Modify: `src/runtime.rs:1678-1681` (delete the gate)
- Modify: `src/runtime.rs:2421-2432` (invert `is_none` → `is_some`, pin port 19901)
- Modify: `src/runtime.rs:2518-2557` (pin port 19902, invert `public_http_enabled`)
- Test: `src/runtime.rs` (new test `zero_provider_bundle_binds_listener_and_serves_healthz`, port 19906)

**Interfaces:**
- Consumes: the port block established in Task 1 (19903–19905 are taken).
- Produces: `start_http_ingress_server(...) -> anyhow::Result<Option<HttpIngressServer>>` keeps its signature — the `Option` is retained because the `Err` path (invalid bind address, port in use) still exists and callers already match on it. It now returns `Ok(None)` never; `Ok(Some(_))` or `Err(_)` only. Downstream `handles.ingress_server` is therefore always `Some` after a successful boot.

- [ ] **Step 1: Write the failing test — a zero-provider bundle must bind and serve /healthz**

Add this test to the `mod tests` block in `src/runtime.rs`, immediately after `ingress_detection_and_runtime_noop_paths_cover_remaining_helpers` (which ends at line 2475). It reuses that test's fixture shape but with an empty `providers` vec.

```rust
    #[test]
    fn zero_provider_bundle_binds_listener_and_serves_healthz() -> anyhow::Result<()> {
        // A bundle with no messaging/events provider at all — the exact shape
        // that used to be silently portless. greentic-secrets' provider packs
        // (30 `type: event` flows, zero messaging) are the real-world case.
        let dir = tempdir()?;
        let discovery = DiscoveryResult {
            domains: DetectedDomains {
                messaging: false,
                events: false,
                oauth: false,
            },
            providers: Vec::new(),
        };
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default"))?;
        let runner_host = DemoRunnerHost::new(
            dir.path().to_path_buf(),
            &discovery,
            None,
            secrets_handle,
            false,
        )?;

        let domains = detect_http_ingress_domains(&discovery, &runner_host);
        assert!(
            domains.is_empty(),
            "fixture must have no ingress domains: that is the point of the test"
        );

        let config = DemoConfig {
            services: crate::config::DemoServicesConfig {
                gateway: crate::config::DemoGatewayConfig {
                    port: 19906,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let server = start_http_ingress_server(
            &config,
            &domains,
            Arc::new(runner_host),
            false,
            None,
            crate::notifier::NotifierConfig::default(),
        )?
        .expect("listener must bind even with zero providers");

        let response = reqwest::blocking::Client::new()
            .get(format!("http://127.0.0.1:{}/healthz", server.actual_port))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .context("GET /healthz")?;
        assert_eq!(response.status().as_u16(), 200);
        Ok(())
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
cargo test --all-features zero_provider_bundle_binds_listener_and_serves_healthz -- --nocapture
```
Expected: FAIL at `.expect("listener must bind even with zero providers")` — panics with that message, because the gate currently returns `Ok(None)` for an empty `domains`.

- [ ] **Step 3: Remove the gate**

In `src/runtime.rs`, delete lines 1678-1681 — the comment and the `if` block:

```rust
    // Start HTTP server if we have ingress domains, static routes, or health probes to serve.
    if domains.is_empty() && !enable_static_routes && !health_probe_listener_required {
        return Ok(None);
    }
```

`health_probe_listener_required` (lines 1671-1677) becomes unused and will trip `-D warnings` on the next clippy run. Do **not** delete the env reads — `GREENTIC_HEALTH_LIVENESS_PATH` / `GREENTIC_HEALTH_READINESS_PATH` are set by `greentic-deployer/src/single_vm.rs:892-893` and removing the contract is a separate cross-repo change. Replace lines 1671-1677 with a binding that documents why it is retained and keeps it referenced:

```rust
    // The listener now always binds: channel presence decides routing, never
    // whether a port opens. These probe-path env vars used to be the only way
    // to force a listener with zero providers (they are set by
    // greentic-deployer's systemd unit); they are now redundant but remain
    // read so that removing them from the deployer stays a separate,
    // deliberate cross-repo change rather than a silent behaviour drift.
    let health_probe_listener_required = std::env::var("GREENTIC_HEALTH_LIVENESS_PATH")
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
        || std::env::var("GREENTIC_HEALTH_READINESS_PATH")
            .ok()
            .is_some_and(|value| !value.trim().is_empty());
    if health_probe_listener_required {
        operator_log::debug(
            module_path!(),
            "health-probe env vars set; listener would bind regardless (now unconditional)"
                .to_string(),
        );
    }
```

- [ ] **Step 4: Run the new test to verify it passes**

Run:
```bash
cargo test --all-features zero_provider_bundle_binds_listener_and_serves_healthz -- --nocapture
```
Expected: PASS.

- [ ] **Step 5: Invert the two now-wrong assertions in `ingress_detection_and_runtime_noop_paths_cover_remaining_helpers`**

This test asserted the old behaviour. In `src/runtime.rs`, replace lines 2421-2432:

```rust
        let config = DemoConfig::default();
        assert!(
            start_http_ingress_server(
                &config,
                &[],
                Arc::new(runner_host.clone()),
                false,
                None,
                crate::notifier::NotifierConfig::default(),
            )?
            .is_none()
        );
```

with:

```rust
        // An empty domain list no longer suppresses the listener: the port is
        // opened unconditionally and `/healthz` answers regardless of channels.
        let config = DemoConfig {
            services: crate::config::DemoServicesConfig {
                gateway: crate::config::DemoGatewayConfig {
                    port: 19901,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            start_http_ingress_server(
                &config,
                &[],
                Arc::new(runner_host.clone()),
                false,
                None,
                crate::notifier::NotifierConfig::default(),
            )?
            .is_some()
        );
```

- [ ] **Step 6: Pin the port and invert the contract assertion in `demo_up_services_in_embedded_mode_writes_runtime_artifacts`**

In `src/runtime.rs`, in the `DemoConfig` literal at lines 2518-2530, add a `gateway` entry to the existing `services` block so the whole literal reads:

```rust
        let config = DemoConfig {
            tenant: "demo".to_string(),
            team: "default".to_string(),
            services: crate::config::DemoServicesConfig {
                nats: crate::config::DemoNatsConfig {
                    enabled: false,
                    ..Default::default()
                },
                gateway: crate::config::DemoGatewayConfig {
                    port: 19902,
                    ..Default::default()
                },
                ..Default::default()
            },
            providers: None,
            sql: None,
        };
```

Then replace line 2547:

```rust
        assert!(handles.ingress_server.is_none());
```

with:

```rust
        // Embedded runner mode (nats off, zero packs) still opens its port:
        // "embedded" governs whether GSM sidecar processes are spawned, not
        // whether the in-process HTTP ingress listens.
        assert!(handles.ingress_server.is_some());
```

and replace line 2556:

```rust
        assert!(!startup_contract.public_http_enabled);
```

with:

```rust
        assert!(startup_contract.public_http_enabled);
```

Leave line 2557 (`assert!(!startup_contract.static_routes_enabled);`) unchanged — this bundle declares no static routes, so `static_routes_enabled` stays false via `bundle_has_static_routes`.

- [ ] **Step 7: Run the full test suite for the two modified files**

Run:
```bash
cargo test --all-features --lib -- --nocapture
```
Expected: PASS. Watch specifically for `ingress_detection_and_runtime_noop_paths_cover_remaining_helpers`, `demo_up_services_in_embedded_mode_writes_runtime_artifacts`, `zero_provider_bundle_binds_listener_and_serves_healthz`, and the two `*_embedded_mode_stops_cleanly` tests from Task 1 — all must pass.

- [ ] **Step 8: Run clippy to confirm no unused-variable warning survives**

Run:
```bash
cargo clippy --all-targets --all-features -- -D warnings
```
Expected: clean. If `health_probe_listener_required` is reported unused, the `if` block from Step 3 was not added.

- [ ] **Step 9: Commit**

```bash
git add src/runtime.rs
git commit -m "feat(ingress): always bind the HTTP listener, independent of channels

The gate tied 'does a port open?' to 'did you attach a chat channel?'. Its
domain list is computed purely from discovered provider packs, and every
component declaring ingest_http is a messaging provider — so a legitimately
channel-less worker (greentic-secrets ships 30 type: event flows) was
silently portless: /healthz never answered and supervisors reported it dead
after a generic health timeout.

Remove the gate. Probes need no new code: handle_builtin_health_request is
already dispatched ahead of all routing and never consults a provider.
Requests for a domain with no provider still 404, which is correct — the port
is open, the route genuinely does not exist.

The GREENTIC_HEALTH_* env reads are retained (deployer's systemd unit sets
them) but are now redundant rather than load-bearing."
```

---

### Task 3: Name `GREENTIC_GATEWAY_PORT` in the port-conflict error

The existing error (`src/http_ingress/mod.rs:242-250`) is already good: it names the port, gives an `ss` command to diagnose, and tells you to kill the orphan. It has one gap — it never mentions the supported way to run side-by-side instances, which matters more now that a channel-less bundle binds where it previously did not.

**Files:**
- Modify: `src/http_ingress/mod.rs:242-250`
- Test: `src/runtime.rs` (new test `zero_provider_bundle_fails_loudly_when_port_busy`, port 19907)

**Interfaces:**
- Consumes: `start_http_ingress_server` from Task 2 (always binds; returns `Err` on a busy port).
- Produces: no API change. The error string gains a line containing `GREENTIC_GATEWAY_PORT`.

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block in `src/runtime.rs`, after the test added in Task 2:

```rust
    #[test]
    fn zero_provider_bundle_fails_loudly_when_port_busy() -> anyhow::Result<()> {
        // Strict bind is deliberate: we removed a silent failure, so we must
        // not replace it with a silent port shift. A busy port is a loud,
        // actionable boot failure.
        let dir = tempdir()?;
        let discovery = DiscoveryResult {
            domains: DetectedDomains {
                messaging: false,
                events: false,
                oauth: false,
            },
            providers: Vec::new(),
        };
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default"))?;
        let runner_host = DemoRunnerHost::new(
            dir.path().to_path_buf(),
            &discovery,
            None,
            secrets_handle,
            false,
        )?;

        let _hold = std::net::TcpListener::bind("127.0.0.1:19907").context("hold port busy")?;

        let config = DemoConfig {
            services: crate::config::DemoServicesConfig {
                gateway: crate::config::DemoGatewayConfig {
                    port: 19907,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let err = start_http_ingress_server(
            &config,
            &[],
            Arc::new(runner_host),
            false,
            None,
            crate::notifier::NotifierConfig::default(),
        )
        .expect_err("a busy port must fail the boot, not silently shift ports");

        let text = format!("{err:#}");
        assert!(text.contains("19907"), "error must name the port: {text}");
        assert!(
            text.contains("GREENTIC_GATEWAY_PORT"),
            "error must point at the supported way to pick another port: {text}"
        );
        Ok(())
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
cargo test --all-features zero_provider_bundle_fails_loudly_when_port_busy -- --nocapture
```
Expected: FAIL on the second assertion — `error must point at the supported way to pick another port`. The first assertion already passes because the current message names the port.

- [ ] **Step 3: Add the hint to the error**

In `src/http_ingress/mod.rs`, replace the `map_err` closure body at lines 242-250:

```rust
                .map_err(|err| {
                    anyhow::anyhow!(
                        "port {requested_port} on {listen_addr_str} is already in use.\n\
                         Likely cause: an orphaned greentic-start (or other process) from a previous run.\n\
                         Diagnose:  ss -tlnp 2>/dev/null | grep ':{requested_port} '\n\
                         Resolve:   kill the listener PID and re-run gtc start\n\
                         (underlying error: {err})"
                    )
                })?;
```

with:

```rust
                .map_err(|err| {
                    anyhow::anyhow!(
                        "port {requested_port} on {listen_addr_str} is already in use.\n\
                         Likely cause: an orphaned greentic-start (or other process) from a previous run.\n\
                         Diagnose:  ss -tlnp 2>/dev/null | grep ':{requested_port} '\n\
                         Resolve:   kill the listener PID and re-run gtc start\n\
                         Or:        pick a different port with GREENTIC_GATEWAY_PORT=<port>\n\
                         (underlying error: {err})"
                    )
                })?;
```

- [ ] **Step 4: Run the test to verify it passes**

Run:
```bash
cargo test --all-features zero_provider_bundle_fails_loudly_when_port_busy -- --nocapture
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/runtime.rs src/http_ingress/mod.rs
git commit -m "fix(ingress): point at GREENTIC_GATEWAY_PORT on a port conflict

Strict bind (range 0) is deliberate — silently shifting ports leaves the
displayed URLs pointing at whatever else owns the requested port. Now that a
channel-less bundle binds where it previously stayed portless, operators hit
this path more often, so the error should name the supported way to pick
another port instead of only suggesting they kill the other process."
```

---

### Task 4: Live verification and full CI gate

Tests prove the unit behaviour. They do not prove the original report is fixed — only booting a real channel-less pack does.

**Files:**
- No source changes expected. If this task finds a defect, fix it here and note it in the PR body.

**Interfaces:**
- Consumes: everything from Tasks 1–3.
- Produces: the evidence quoted in the PR body.

- [ ] **Step 1: Build the binary under test**

Run:
```bash
cd /home/bima-pangestu/.cache/wt/start-listener-gate
cargo build --release --bin greentic-start
```
Expected: builds clean. Note the artifact path: `target/release/greentic-start`.

- [ ] **Step 2: Boot a genuinely channel-less pack**

`greentic-secrets/packs/vault-kv` has 6 `type: event` flows and zero messaging providers — the real-world shape this PR exists for.

Run:
```bash
GREENTIC_GATEWAY_PORT=19950 \
GREENTIC_GATEWAY_LISTEN_ADDR=127.0.0.1 \
  ./target/release/greentic-start start \
  --bundle /home/bima-pangestu/projects/Works/greentic/greentic-secrets/packs/vault-kv \
  --tenant demo --team default \
  --nats off --cloudflared off --no-browser --verbose
```

Leave it running. Expected in the log: `HTTP ingress ready at http://127.0.0.1:19950`.

If the bundle path is rejected (it is a pack source tree, not a built `.gtbundle`), do **not** substitute a bundle that has a messaging provider — that would silently verify nothing. Instead build it first with `greentic-bundle wizard` / `gtc`, or fall back to any bundle whose `providers/` directory contains no messaging provider, and record in the PR body exactly which artifact was used.

- [ ] **Step 3: Prove `/healthz` answers**

In a second shell:
```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:19950/healthz
```
Expected: `200`.

This is the assertion the whole PR exists to make true. Before this change the port was never bound and curl would fail with `Connection refused`.

- [ ] **Step 4: Prove the negative case is unchanged**

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:19950/v1/messaging/ingress/telegram/demo/default
```
Expected: `404`. The port is open; the route genuinely does not exist. A `200` here would mean routing was loosened, which is **not** the intent — stop and investigate.

Stop the process (Ctrl-C) once both checks pass.

- [ ] **Step 5: Run the full local CI gate**

Run:
```bash
bash ci/local_check.sh
```
Expected: PASS (fmt + clippy `-D warnings` + tests + repo extras).

**Run it at least twice.** The flake this plan guards against is a port race between parallel test binaries; a single green run does not disprove it. If any boot test fails with a port/`AddrInUse` error, a port was missed — find it and pin it rather than retrying.

If a failure is unrelated to this change, document it in the PR body rather than hiding or "fixing" it out of scope.

- [ ] **Step 6: Push and open the PR**

```bash
git push -u origin feat/unconditional-http-listener
```

PR body must state:
- The behaviour change: `startup_contract.json` now reports `public_http_enabled: true` for probes-only runs, and the startup banner prints an `HTTP: http://…` line where it previously printed none. Do NOT claim `endpoints.json` changed — it does not (`DemoEndpoints` has no `http_url`, and its `gateway_port` was always written); an earlier draft of this plan said otherwise and was wrong.
- `--cloudflared on` / `--ngrok on` on a zero-provider bundle now opens a real tunnel to a probes-only listener instead of warning and skipping (`src/runtime.rs:1106`, `:1182`).
- `gtc start` on a channel-less bundle now fails loudly if the port is busy, where it previously ran portless. This is intentional.
- The live verification output from Steps 3 and 4.
- A pointer to the spec: `docs/superpowers/specs/2026-07-15-unconditional-http-listener-design.md`.
- That this is a **no-op for greentic-designer**: since #1046 it injects `messaging-webchat-gui` into every bundle, so its bundles already always bind.

---

## Deviations from the spec (deliberate — flag in review)

Both deviations were found by reading the code while writing this plan. The spec was written before that reading and is wrong on these two points; it should be amended to match. Nothing else in the spec changes.

### 1. The static-routes guard stays (spec §3 said delete it)

The spec says to delete the guard at `src/startup_contract.rs:116-121` and its test `resolve_rejects_missing_public_http` (`src/startup_contract.rs:275`), on the grounds that they become unreachable dead code.

**This plan keeps both.** The premise is wrong: `startup_contract::resolve` is a **pure function** and `http_listener_enabled` is one of its *inputs*, not a global. Removing the gate makes the real caller (`src/runtime.rs:1308` → `:1335`) always pass `true`, but `resolve` remains callable with `false` and its guard remains ordinary input validation. Deleting it removes a safety net and drops coverage of a legitimate input combination, buying nothing.

It also guards a future this codebase already gestures at: `greentic_types::FlowKind::Job` ("Batch/background jobs") exists as a spec-only variant today. A batch launch mode with no listener is exactly when "bundle declares static routes but this launch mode does not expose public HTTP" would be a real bug worth catching.

### 2. The HTTP route-table decoupling is deferred (spec §4 said do it here)

The spec says to stop gating pack-declared HTTP route discovery (`greentic.http-routes.v1`) on `enable_static_routes` at `src/http_ingress/mod.rs:146`, arguing it is "the same class of coupling, in the same file".

**This plan defers it to the flow→ingress project.** Three reasons, in order of weight:

1. **It cannot be observed without also fixing an out-of-scope check.** A pack-declared route matches at `src/http_ingress/mod.rs:687`, but then still passes through `state.domains.contains(&domain)` (`:718` → 404 "domain disabled") and `supports_op(domain, provider, "ingest_http")` (`:721` → 404). So populating the table changes behaviour only for a bundle that has a real `ingest_http` provider **and** declares http-routes **and** ships no static assets — a narrow shape that the listener change does not affect either way.
2. **The fixture to test it does not exist.** `discover_http_routes_from_bundle` (`src/http_routes.rs:240`) has **zero test coverage** today; `src/http_routes.rs`'s tests only build in-memory descriptors via `make_route` (`:359`). Covering this properly needs a new `.gtpack` fixture writing `greentic.http-routes.v1` into `manifest.cbor` (`read_pack_http_routes` parses it out of the zip), plus a real `ingest_http` provider to observe the effect end-to-end.
3. **Shipping it untested would contradict the PR.** This PR exists to stop silent behaviour. Adding an unobservable, uncovered change to it is the same mistake in a new place.

It is a real bug and should be fixed — with the `:718`/`:721` domain check, in the project that gives it a reason to be observable.
