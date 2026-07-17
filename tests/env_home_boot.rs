//! Integration tests for booting `greentic-start` from a greentic-deployer
//! environment home (`--store-root`) instead of a bundle.
//!
//! The bundle-less boot goes through main's revision engine: it loads the
//! deployer `environment.json` record for the env, reads (or synthesizes an
//! empty) `runtime-config.json`, activates the revisions, and brings the
//! listener up. This test hand-builds a bare environment record on disk (via the
//! deployer's own `EnvironmentStore`, so the schema tracks the pinned
//! deploy-spec) and drives the full public `greentic_start::run_start_request`
//! boot path against it — no external binaries, no gating/skip.
//!
//! It exercises the zero-revision case: an env with no deployments activates an
//! empty runtime that serves probes/404s until bundles are attached, so the
//! boot needs no real `.gtpack`. A *routed* revision cannot be hand-built here —
//! the revision engine rejects a revision with no pinned packs (`revision_boot`'s
//! "no pinned packs" guard), and a real pinned pack is a deployer-produced,
//! digest-verified `.gtpack` that only `op deploy` / `gtc` can mint. The routed
//! serve path is covered by `revision_boot`'s own unit tests instead.
//!
//! The ingress listener always binds (it is not gated on discovering a
//! messaging provider), so this test pins `GREENTIC_GATEWAY_PORT` to a fixed
//! high port rather than inheriting the 8080 default, which would race with
//! the boot tests in `src/lib.rs` running as a separate process.

use std::path::Path;
use std::thread;
use std::time::Duration;

use greentic_start::runtime_state;
use greentic_start::{
    CloudflaredModeArg, NatsModeArg, NgrokModeArg, StartRequest, run_start_request,
};

/// Persist a bare deployer environment record for env `local` under
/// `<store_root>/local/` — no deployments, so the bundle-less boot activates a
/// zero-revision runtime (listener up, probes only). Written through the
/// deployer's `EnvironmentStore` so the on-disk schema matches the pinned
/// deploy-spec.
fn write_env_home_fixture(store_root: &Path) {
    use greentic_deploy_spec::{Environment, EnvironmentHostConfig, SchemaVersion};
    use greentic_deployer::environment::{EnvironmentStore, LocalFsStore};
    use greentic_types::EnvId;

    let env_id = EnvId::try_from("local").expect("env id");

    // A bare deployer environment record (no deployments): the bundle-less boot
    // loads it, synthesizes an empty runtime-config, and activates a
    // zero-revision runtime that brings the listener up and serves probes/404s
    // until bundles are attached. This exercises the `--store-root` ->
    // revision-engine boot path end-to-end without a real `.gtpack` (a routed
    // revision requires a deployer-produced, digest-verified pack, which the
    // revision engine rejects if empty — see `revision_boot`'s "no pinned packs"
    // guard — and which is out of a hand-built fixture's reach).
    let environment = Environment {
        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
        environment_id: env_id.clone(),
        name: "local".to_string(),
        host_config: EnvironmentHostConfig {
            env_id: env_id.clone(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
            gui_enabled: None,
        },
        packs: Vec::new(),
        credentials_ref: None,
        bundles: Vec::new(),
        revisions: Vec::new(),
        traffic_splits: Vec::new(),
        messaging_endpoints: Vec::new(),
        extensions: Vec::new(),
        revocation: Default::default(),
        retention: Default::default(),
        health: Default::default(),
    };
    LocalFsStore::new(store_root.to_path_buf())
        .save(&environment)
        .expect("save environment record");
}

/// RAII guard that pins `GREENTIC_GATEWAY_PORT` for the lifetime of a test
/// and always clears it on drop, including when the test body panics — a
/// plain set_var/remove_var pair would leak the var into the other tests
/// sharing this process if an `.expect()`/`assert!` in between panicked
/// before the manual `remove_var` ran.
#[must_use = "bind the guard to a named variable (e.g. `let _gateway_port = ...`); \
              dropping it immediately clears the variable it just set"]
struct GatewayPortGuard;

impl GatewayPortGuard {
    fn set(port: &str) -> Self {
        // The three tests in this file share one process, and only
        // `boots_from_env_home_and_stops_cleanly` writes this variable, so
        // there is no competing writer. The guard clears it on every exit
        // path, including panics, so it never leaks into the other two. This
        // mirrors the env-mutation pattern already used across this crate's
        // tests (bundle_config.rs, bin_resolver.rs); it does not establish
        // the absence of concurrent readers that set_var's contract formally
        // asks for.
        unsafe { std::env::set_var("GREENTIC_GATEWAY_PORT", port) };
        Self
    }
}

impl Drop for GatewayPortGuard {
    fn drop(&mut self) {
        unsafe { std::env::remove_var("GREENTIC_GATEWAY_PORT") };
    }
}

fn env_home_start_request(store_root: &Path, log_dir: &Path) -> StartRequest {
    StartRequest {
        bundle: None,
        store_root: Some(store_root.to_path_buf()),
        env: Some("local".to_string()),
        tenant: None,
        team: None,
        no_nats: false,
        nats: NatsModeArg::Off,
        nats_url: None,
        config: None,
        cloudflared: CloudflaredModeArg::Off,
        cloudflared_binary: None,
        ngrok: NgrokModeArg::Off,
        ngrok_binary: None,
        runner_binary: None,
        restart: Vec::new(),
        log_dir: Some(log_dir.to_path_buf()),
        verbose: false,
        quiet: true,
        no_browser: true,
        no_updates: false,
        no_auto_restart: false,
        admin: false,
        admin_port: 9443,
        admin_certs_dir: None,
        admin_allowed_clients: Vec::new(),
        tunnel_explicit: true,
    }
}

#[test]
fn boots_from_store_root_and_stops_cleanly() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_root = temp.path().join("store-root");
    write_env_home_fixture(&store_root);

    // See the module doc: the listener always binds, so pin a unique port.
    let _gateway_port = GatewayPortGuard::set("19905");

    let log_dir = temp.path().join("logs");

    // The bundle-less boot writes its runtime state (incl. the stop-request file
    // the serve loop watches) under `<store_root>/<env>/state`, keyed by the
    // reserved tenant `env` and the env id — mirroring `env_tunnel::
    // env_runtime_paths`, which is `pub(crate)` so we reconstruct it here.
    let runtime_paths =
        runtime_state::RuntimePaths::new(store_root.join("local").join("state"), "env", "local");
    let stop_thread = {
        let runtime_paths = runtime_paths.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(350));
            runtime_state::write_stop_request(
                &runtime_paths,
                &runtime_state::StopRequest {
                    requested_by: "env_home_boot test".to_string(),
                    reason: Some("coverage".to_string()),
                },
            )
            .expect("write stop request");
        })
    };

    let request = env_home_start_request(&store_root, &log_dir);
    // The `--store-root` boot loads the (bare) environment record, activates a
    // zero-revision runtime, brings the listener up, then exits when it observes
    // the stop-request file — proving the store-root -> revision-engine boot
    // path is wired end-to-end.
    run_start_request(request).expect("store-root boot should succeed and stop cleanly");
    stop_thread.join().expect("join stop thread");

    assert!(
        runtime_state::read_stop_request(&runtime_paths)
            .expect("read stop request")
            .is_none(),
        "stop request should be cleared after a clean shutdown"
    );
}

#[test]
fn store_root_and_bundle_together_are_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_root = temp.path().join("store-root");
    write_env_home_fixture(&store_root);
    let log_dir = temp.path().join("logs");

    let mut request = env_home_start_request(&store_root, &log_dir);
    request.bundle = Some("some-bundle-ref".to_string());

    let err = run_start_request(request).expect_err("store_root + bundle must be rejected");
    assert_eq!(
        err.to_string(),
        "--store-root is mutually exclusive with --bundle/--config"
    );
}

#[test]
fn store_root_and_config_together_are_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_root = temp.path().join("store-root");
    write_env_home_fixture(&store_root);
    let log_dir = temp.path().join("logs");

    let mut request = env_home_start_request(&store_root, &log_dir);
    request.config = Some(temp.path().join("some-config.yaml"));

    let err = run_start_request(request).expect_err("store_root + config must be rejected");
    assert_eq!(
        err.to_string(),
        "--store-root is mutually exclusive with --bundle/--config"
    );
}
