//! Tunnel orchestration for the bundle-less env-serving boot (`greentic-start`
//! with no `--bundle` / `--config`).
//!
//! The legacy bundle arm spawns `--cloudflared on` / `--ngrok on` tunnels
//! inside `runtime::demo_up_services`; the bundle-less arm returns before that
//! code, so the flags were silently ignored and webhook auto-registration
//! skipped itself for lack of a public URL. This module gives the env-serving
//! path its own tunnel lifecycle, rooted under the environment directory:
//!
//! - pidfiles:  `<env_dir>/state/pids/env.<env_id>/<service>.pid`
//! - URL cache: `<env_dir>/state/runtime/env.<env_id>/public_base_url.txt`
//! - logs:      `<env_dir>/logs/<service>.log`
//!
//! It reuses the same [`cloudflared`] / [`ngrok`] service modules as the
//! legacy arm, so reuse-running-tunnel semantics (stable URL across quick
//! restarts) and orphan cleanup behave identically. The tunnel deliberately
//! OUTLIVES Ctrl+C — the next boot reuses it; `greentic-start stop` tears it
//! down via the pidfile (see [`stop_env_tunnels`]).

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use crate::cli_args::{CloudflaredModeArg, NgrokModeArg, StartRequest, restart_name};
use crate::runtime_state::RuntimePaths;
use crate::{bin_resolver, cloudflared, ngrok, operator_log, supervisor};

/// Tenant slot of the env-rooted [`RuntimePaths`] key: services land under
/// `pids/env.<env_id>/`. The state root is the env dir's own `state/`, so
/// these never collide with bundle-rooted `<tenant>.<team>` keys.
const ENV_PATHS_TENANT: &str = "env";

/// Upper bound for the post-start reachability probe. Mirrors the legacy
/// arm's policy: not-yet-reachable warns and continues (providers retry
/// deliveries; trycloudflare DNS can lag a few seconds).
const TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// `RuntimePaths` for env-rooted tunnel children, shared by the serve boot
/// (spawn + stop-request watch) and `greentic-start stop` (teardown).
pub(crate) fn env_runtime_paths(env_dir: &Path, env_id: &str) -> RuntimePaths {
    RuntimePaths::new(env_dir.join("state"), ENV_PATHS_TENANT, env_id)
}

/// Which tunnel a request asks for. Single owner of the mutual-exclusivity
/// policy — explicit ngrok wins over cloudflared (logged when both are on) —
/// shared by the legacy bundle arm and the bundle-less env-serving arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TunnelChoice {
    Off,
    Cloudflared,
    Ngrok,
}

pub(crate) fn choose_tunnel(cloudflared: CloudflaredModeArg, ngrok: NgrokModeArg) -> TunnelChoice {
    match (cloudflared, ngrok) {
        (CloudflaredModeArg::On, NgrokModeArg::On) => {
            operator_log::info(
                module_path!(),
                "ngrok enabled, disabling cloudflared (use --cloudflared on --ngrok off to override)",
            );
            TunnelChoice::Ngrok
        }
        (_, NgrokModeArg::On) => TunnelChoice::Ngrok,
        (CloudflaredModeArg::On, NgrokModeArg::Off) => TunnelChoice::Cloudflared,
        (CloudflaredModeArg::Off, NgrokModeArg::Off) => TunnelChoice::Off,
    }
}

pub(crate) struct EnvTunnelHandle {
    pub(crate) service: &'static str,
    pub(crate) url: String,
}

/// Start the tunnel the request asks for against the bound revision-serve
/// port and return its public URL. `Ok(None)` when no tunnel was requested.
///
/// Hard error on spawn/URL-discovery failure: the flag is an explicit opt-in,
/// so a tunnel that cannot start must fail the boot rather than silently
/// serving local-only (the exact bug this module exists to fix).
pub(crate) fn start_env_tunnel(
    request: &StartRequest,
    env_dir: &Path,
    env_id: &str,
    local_port: u16,
    log_dir: &Path,
) -> anyhow::Result<Option<EnvTunnelHandle>> {
    let choice = choose_tunnel(request.cloudflared, request.ngrok);
    let (service, explicit_binary) = match choice {
        TunnelChoice::Off => return Ok(None),
        TunnelChoice::Cloudflared => ("cloudflared", request.cloudflared_binary.clone()),
        TunnelChoice::Ngrok => ("ngrok", request.ngrok_binary.clone()),
    };
    let restart: BTreeSet<String> = request.restart.iter().map(restart_name).collect();
    let paths = env_runtime_paths(env_dir, env_id);
    let binary = bin_resolver::resolve_binary(
        service,
        &bin_resolver::ResolveCtx {
            config_dir: env_dir.to_path_buf(),
            explicit_path: explicit_binary,
        },
    )?;
    let log_path = operator_log::reserve_service_log(log_dir, service)?;
    let restart_service = crate::runtime::should_restart(&restart, service);
    let url = match choice {
        TunnelChoice::Off => unreachable!("Off returned above"),
        TunnelChoice::Cloudflared => {
            cloudflared::start_quick_tunnel(
                &paths,
                &cloudflared::CloudflaredConfig {
                    binary,
                    local_port,
                    extra_args: Vec::new(),
                    restart: restart_service,
                },
                &log_path,
            )?
            .url
        }
        TunnelChoice::Ngrok => {
            ngrok::start_tunnel(
                &paths,
                &ngrok::NgrokConfig {
                    binary,
                    local_port,
                    extra_args: Vec::new(),
                    restart: restart_service,
                },
                &log_path,
            )?
            .url
        }
    };
    let handle = EnvTunnelHandle { service, url };

    // Reachability probe is best-effort (HEAD requests until the edge
    // answers), exactly like the legacy arm — the URL is already known, and
    // a slow edge must not fail the boot.
    match cloudflared::wait_tunnel_ready(&handle.url, TUNNEL_READY_TIMEOUT) {
        Ok(()) => operator_log::info(
            module_path!(),
            format!(
                "{} tunnel verified reachable at {}",
                handle.service, handle.url
            ),
        ),
        Err(err) => operator_log::warn(
            module_path!(),
            format!(
                "{} tunnel not yet reachable, continuing anyway: {err}",
                handle.service
            ),
        ),
    }
    Ok(Some(handle))
}

/// Stop env-rooted tunnel children via their pidfiles and clear the cached
/// URL so the next start discovers a fresh one. Returns the services whose
/// pidfile was consumed (process stopped, or stale pidfile cleaned up).
///
/// Pidfile-scoped on purpose: a cloudflared/ngrok the user started by hand is
/// not ours to kill — unlike the legacy bundle stop path, which pkills any
/// process by name. Warnings go to stderr because `greentic-start stop` runs
/// without an initialized operator log.
pub(crate) fn stop_env_tunnels(paths: &RuntimePaths) -> Vec<&'static str> {
    let mut stopped = Vec::new();
    for service in ["cloudflared", "ngrok"] {
        let pid_path = paths.pid_path(service);
        if !pid_path.exists() {
            continue;
        }
        match supervisor::stop_pidfile(&pid_path, 2_000) {
            Ok(()) => stopped.push(service),
            Err(err) => eprintln!(
                "warning: failed to stop {service} via {}: {err:#}",
                pid_path.display()
            ),
        }
    }
    cloudflared::cleanup_url_file(paths);
    stopped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_runtime_paths_root_under_env_dir() {
        let paths = env_runtime_paths(Path::new("/envs/local"), "local");
        assert_eq!(
            paths.pid_path("cloudflared"),
            Path::new("/envs/local/state/pids/env.local/cloudflared.pid")
        );
        assert_eq!(
            cloudflared::public_url_path(&paths),
            Path::new("/envs/local/state/runtime/env.local/public_base_url.txt")
        );
    }

    #[test]
    fn choose_tunnel_ngrok_wins_over_cloudflared() {
        assert_eq!(
            choose_tunnel(CloudflaredModeArg::Off, NgrokModeArg::Off),
            TunnelChoice::Off
        );
        assert_eq!(
            choose_tunnel(CloudflaredModeArg::On, NgrokModeArg::Off),
            TunnelChoice::Cloudflared
        );
        assert_eq!(
            choose_tunnel(CloudflaredModeArg::Off, NgrokModeArg::On),
            TunnelChoice::Ngrok
        );
        assert_eq!(
            choose_tunnel(CloudflaredModeArg::On, NgrokModeArg::On),
            TunnelChoice::Ngrok
        );
    }

    #[test]
    fn stop_env_tunnels_consumes_stale_pidfile_and_url_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = env_runtime_paths(dir.path(), "local");
        let pid_path = paths.pid_path("cloudflared");
        std::fs::create_dir_all(pid_path.parent().expect("pids dir")).expect("mkdir pids");
        // u32::MAX is above every real pid_max — guaranteed not running.
        std::fs::write(&pid_path, u32::MAX.to_string()).expect("write pidfile");
        let url_path = cloudflared::public_url_path(&paths);
        std::fs::create_dir_all(url_path.parent().expect("runtime dir")).expect("mkdir runtime");
        std::fs::write(&url_path, "https://stale.trycloudflare.com").expect("write url");

        let stopped = stop_env_tunnels(&paths);

        assert_eq!(stopped, vec!["cloudflared"]);
        assert!(!pid_path.exists(), "stale pidfile must be removed");
        assert!(!url_path.exists(), "cached URL must be cleared");
    }

    #[test]
    fn stop_env_tunnels_is_a_no_op_without_pidfiles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = env_runtime_paths(dir.path(), "local");
        assert!(stop_env_tunnels(&paths).is_empty());
    }
}
