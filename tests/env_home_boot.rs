//! Integration tests for booting `greentic-start` from a greentic-deployer
//! environment home (`--store-root`) instead of a bundle.
//!
//! `greentic-deployer`'s CLI (as installed in this environment, v0.5.15) does
//! not yet expose the `op env init` / `op deploy` subcommands sketched in the
//! original task brief, so this test does not shell out to that binary at
//! all. Instead it hand-builds a minimal, real environment-home tree on disk
//! (`runtime-config.json` + a routed revision's `pack-list.lock` + an
//! extracted `bundle/` directory) — the exact on-disk shape
//! `env_home::load_env_home`'s own unit tests already exercise against the
//! real resolver/verifier — and drives the full public
//! `greentic_start::run_start_request` boot path against it.
//!
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

use std::path::Path;
use std::thread;
use std::time::Duration;

use greentic_start::runtime_state;
use greentic_start::{
    CloudflaredModeArg, NatsModeArg, NgrokModeArg, StartRequest, run_start_request,
};

/// Build `<store_root>/local/...` as a minimal env-home: one deployment
/// (`d1`) fully routed (10000 bps) to revision `r1`, whose `pack-list.lock`
/// pins zero packs, and whose `<rev>/bundle/` is a normalized bundle
/// directory (`bundle.yaml` + the `bundle-manifest.json` sentinel) carrying
/// just `tenant`/`team` — the same minimal shape
/// `write_demo_bundle`/`make_start_request` use in `src/lib.rs`'s own
/// embedded-mode boot tests, so this exercises exactly that already-proven
/// "zero packs -> embedded runner mode, no supervised gateway process" path.
fn write_env_home_fixture(store_root: &Path) {
    let env_home = store_root.join("local");
    let rev_dir = env_home.join("revisions").join("r1");
    let bundle_dir = rev_dir.join("bundle");
    std::fs::create_dir_all(&bundle_dir).expect("create bundle dir");

    std::fs::write(
        bundle_dir.join("bundle.yaml"),
        "tenant: envhome\nteam: default\n",
    )
    .expect("write bundle.yaml");
    // Sentinel marking bundle.yaml as a normalized-bundle payload (see
    // bundle_config::normalized_bundle_has_runtime_payload).
    std::fs::write(bundle_dir.join("bundle-manifest.json"), "{}").expect("write bundle-manifest");

    std::fs::write(
        rev_dir.join("pack-list.lock"),
        r#"{"schema":"greentic.pack-list-lock.v1","revision_id":"r1","packs":[]}"#,
    )
    .expect("write pack-list.lock");

    std::fs::write(
        env_home.join("runtime-config.json"),
        r#"{"schema":"greentic.runtime-config.v1","env_id":"local","revisions":[{"deployment_id":"d1","revision_id":"r1","bundle_id":"app","pack_list_refs":["revisions/r1/pack-list.lock"],"pack_config_refs":[],"weight_bps":10000}]}"#,
    )
    .expect("write runtime-config.json");
}

fn env_home_start_request(store_root: &Path, log_dir: &Path) -> StartRequest {
    StartRequest {
        bundle: None,
        store_root: Some(store_root.to_path_buf()),
        env: "local".to_string(),
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
        admin: false,
        admin_port: 9443,
        admin_certs_dir: None,
        admin_allowed_clients: Vec::new(),
        tunnel_explicit: true,
    }
}

#[test]
fn boots_from_env_home_and_stops_cleanly() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_root = temp.path().join("store-root");
    write_env_home_fixture(&store_root);

    // See the module doc: the listener always binds, so pin a unique port.
    unsafe {
        std::env::set_var("GREENTIC_GATEWAY_PORT", "19905");
    }

    let bundle_dir = store_root.join("local/revisions/r1/bundle");
    let log_dir = temp.path().join("logs");

    // The routed bundle's state dir lives under the resolved bundle
    // directory (see bundle_config::resolve_bundle_dir_paths), and its
    // tenant/team come from the fixture's bundle.yaml.
    let runtime_paths =
        runtime_state::RuntimePaths::new(bundle_dir.join("state"), "envhome", "default");
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
    run_start_request(request).expect("env-home boot should succeed and stop cleanly");
    stop_thread.join().expect("join stop thread");

    // The bundle directory picked by the env-home branch is the routed
    // revision's `bundle/` dir, not the store root itself — this is the
    // load-bearing assertion that `load_env_home` (not the `--bundle`
    // fallback) drove the boot.
    assert!(runtime_paths.service_manifest_path().exists());
    assert!(
        runtime_state::read_stop_request(&runtime_paths)
            .expect("read stop request")
            .is_none(),
        "stop request should be cleared after a clean shutdown"
    );
    unsafe {
        std::env::remove_var("GREENTIC_GATEWAY_PORT");
    }
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
