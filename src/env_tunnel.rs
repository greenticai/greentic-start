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
//! legacy arm. Cloudflared tunnels live in the machine-wide shared record
//! (see [`crate::tunnel_state`]) — the env pidfile namespace above only
//! applies to ngrok and to pre-shared-record leftovers, which get adopted
//! into the shared record on the next start. The tunnel deliberately
//! OUTLIVES Ctrl+C — the next boot reuses it; `greentic-start stop` tears it
//! down via the pidfile (see [`stop_env_tunnels`]).

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use crate::cli_args::{
    CloudflaredModeArg, GtunnelModeArg, NgrokModeArg, StartRequest, restart_name,
};
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
    Gtunnel,
}

pub(crate) fn choose_tunnel(
    cloudflared: CloudflaredModeArg,
    ngrok: NgrokModeArg,
    gtunnel: GtunnelModeArg,
) -> TunnelChoice {
    match (cloudflared, ngrok, gtunnel) {
        (CloudflaredModeArg::On, NgrokModeArg::On, _) => {
            operator_log::info(
                module_path!(),
                "ngrok enabled, disabling cloudflared (use --cloudflared on --ngrok off to override)",
            );
            TunnelChoice::Ngrok
        }
        (_, NgrokModeArg::On, _) => TunnelChoice::Ngrok,
        (CloudflaredModeArg::On, NgrokModeArg::Off, _) => TunnelChoice::Cloudflared,
        (CloudflaredModeArg::Off, NgrokModeArg::Off, GtunnelModeArg::On) => TunnelChoice::Gtunnel,
        (CloudflaredModeArg::Off, NgrokModeArg::Off, GtunnelModeArg::Off) => TunnelChoice::Off,
    }
}

/// Resolve the zero-config gtunnel settings for this request. Order for each
/// field: explicit flag > env var > derived/default. Keeps setup input-free.
pub(crate) fn gtunnel_config(
    request: &StartRequest,
    default_tunnel_id: &str,
    local_port: u16,
    restart: bool,
) -> crate::gtunnel::GtunnelConfig {
    let worker_base_url = request
        .gtunnel_worker_url
        .clone()
        .or_else(|| std::env::var("GREENTIC_TUNNEL_WORKER_URL").ok())
        .unwrap_or_else(|| crate::gtunnel::DEFAULT_WORKER_BASE_URL.to_string());
    let tunnel_id = request
        .gtunnel_tunnel_id
        .clone()
        .or_else(|| std::env::var("GREENTIC_TUNNEL_ID").ok())
        .unwrap_or_else(|| sanitize_tunnel_id(default_tunnel_id));
    // Prefer the per-tunnel secret greentic-setup provisioned (shared store),
    // falling back to the GREENTIC_TUNNEL_SECRET env override.
    let secret = crate::gtunnel::resolve_secret(&tunnel_id);
    crate::gtunnel::GtunnelConfig {
        worker_base_url,
        tunnel_id,
        secret,
        local_port,
        restart,
    }
}

/// Normalize a derived tunnel id into a URL-path-safe slug.
fn sanitize_tunnel_id(raw: &str) -> String {
    let slug: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = slug.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed
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
    let choice = choose_tunnel(request.cloudflared, request.ngrok, request.gtunnel);
    if let TunnelChoice::Off = choice {
        return Ok(None);
    }
    let restart: BTreeSet<String> = request.restart.iter().map(restart_name).collect();
    let paths = env_runtime_paths(env_dir, env_id);
    // gtunnel has no external binary — the agent is this same executable, so it
    // takes a distinct, self-contained path (spawn the agent, report the URL).
    if let TunnelChoice::Gtunnel = choice {
        let restart_service = crate::runtime::should_restart(&restart, crate::gtunnel::SERVICE_ID);
        // Derive the tunnel id from tenant/team (same rule setup uses) so both
        // binaries compute the same id and share one agent — never from env_id.
        let default_id = format!(
            "{}-{}",
            request.tenant.as_deref().unwrap_or("default"),
            request.team.as_deref().unwrap_or("default"),
        );
        let config = gtunnel_config(request, &default_id, local_port, restart_service);
        let handle = crate::gtunnel::start_agent(&config)?;
        match cloudflared::wait_tunnel_ready(&handle.url, TUNNEL_READY_TIMEOUT) {
            Ok(()) => operator_log::info(
                module_path!(),
                format!("gtunnel reachable url={}", handle.url),
            ),
            Err(err) => operator_log::warn(
                module_path!(),
                format!("gtunnel not yet reachable, continuing anyway: {err}"),
            ),
        }
        return Ok(Some(EnvTunnelHandle {
            service: crate::gtunnel::SERVICE_ID,
            url: handle.url,
        }));
    }
    let (service, explicit_binary) = match choice {
        TunnelChoice::Cloudflared => ("cloudflared", request.cloudflared_binary.clone()),
        TunnelChoice::Ngrok => ("ngrok", request.ngrok_binary.clone()),
        TunnelChoice::Off | TunnelChoice::Gtunnel => {
            unreachable!("Off and Gtunnel handled above")
        }
    };
    let binary = bin_resolver::resolve_binary(
        service,
        &bin_resolver::ResolveCtx {
            config_dir: env_dir.to_path_buf(),
            explicit_path: explicit_binary,
        },
    )?;
    let restart_service = crate::runtime::should_restart(&restart, service);
    let url = match choice {
        TunnelChoice::Off | TunnelChoice::Gtunnel => {
            unreachable!("Off and Gtunnel handled above")
        }
        TunnelChoice::Cloudflared => {
            // Logs live under the shared tunnel record, not this env's log
            // dir — the tunnel is machine-wide and may outlive this boot.
            cloudflared::start_quick_tunnel(
                &paths,
                &cloudflared::CloudflaredConfig {
                    binary,
                    local_port,
                    extra_args: Vec::new(),
                    restart: restart_service,
                },
            )?
            .url
        }
        TunnelChoice::Ngrok => {
            let log_path = operator_log::reserve_service_log(log_dir, service)?;
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
    // Cloudflared normally lives in the machine-wide shared record, not the
    // env namespace swept above. Also pidfile-scoped — never a name-based kill.
    if !cloudflared::stop_shared_tunnels().is_empty() && !stopped.contains(&"cloudflared") {
        stopped.push("cloudflared");
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
            choose_tunnel(
                CloudflaredModeArg::Off,
                NgrokModeArg::Off,
                GtunnelModeArg::Off
            ),
            TunnelChoice::Off
        );
        assert_eq!(
            choose_tunnel(
                CloudflaredModeArg::On,
                NgrokModeArg::Off,
                GtunnelModeArg::Off
            ),
            TunnelChoice::Cloudflared
        );
        assert_eq!(
            choose_tunnel(
                CloudflaredModeArg::Off,
                NgrokModeArg::On,
                GtunnelModeArg::Off
            ),
            TunnelChoice::Ngrok
        );
        assert_eq!(
            choose_tunnel(
                CloudflaredModeArg::On,
                NgrokModeArg::On,
                GtunnelModeArg::Off
            ),
            TunnelChoice::Ngrok
        );
    }

    #[test]
    fn choose_tunnel_selects_gtunnel_when_only_it_is_on() {
        assert_eq!(
            choose_tunnel(
                CloudflaredModeArg::Off,
                NgrokModeArg::Off,
                GtunnelModeArg::On
            ),
            TunnelChoice::Gtunnel
        );
    }

    /// Points the shared tunnel record at a tempdir for the duration of a
    /// test, so stop paths never touch the developer's real ~/.greentic.
    struct TunnelStateOverride {
        _guard: std::sync::MutexGuard<'static, ()>,
        previous: Option<std::ffi::OsString>,
    }

    impl TunnelStateOverride {
        fn set(dir: &Path) -> Self {
            let guard = crate::test_env_lock()
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            let previous = std::env::var_os("GREENTIC_TUNNEL_STATE_DIR");
            // SAFETY: process-global env mutation serialized by test_env_lock.
            unsafe { std::env::set_var("GREENTIC_TUNNEL_STATE_DIR", dir) };
            Self {
                _guard: guard,
                previous,
            }
        }
    }

    impl Drop for TunnelStateOverride {
        fn drop(&mut self) {
            // SAFETY: still serialized by the held test_env_lock guard.
            unsafe {
                match self.previous.take() {
                    Some(value) => std::env::set_var("GREENTIC_TUNNEL_STATE_DIR", value),
                    None => std::env::remove_var("GREENTIC_TUNNEL_STATE_DIR"),
                }
            }
        }
    }

    #[test]
    fn stop_env_tunnels_consumes_stale_pidfile_and_url_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _tunnel_state = TunnelStateOverride::set(&dir.path().join("tunnel"));
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
        let _tunnel_state = TunnelStateOverride::set(&dir.path().join("tunnel"));
        let paths = env_runtime_paths(dir.path(), "local");
        assert!(stop_env_tunnels(&paths).is_empty());
    }

    #[test]
    fn stop_env_tunnels_consumes_shared_record_pidfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tunnel_root = dir.path().join("tunnel");
        let _tunnel_state = TunnelStateOverride::set(&tunnel_root);
        let paths = env_runtime_paths(dir.path(), "local");

        let shared_pid_path = tunnel_root
            .join("state")
            .join("pids")
            .join("shared.cloudflared-8080")
            .join("cloudflared.pid");
        std::fs::create_dir_all(shared_pid_path.parent().expect("pids dir")).expect("mkdir");
        // u32::MAX is above every real pid_max — guaranteed not running.
        std::fs::write(&shared_pid_path, u32::MAX.to_string()).expect("write pidfile");

        let stopped = stop_env_tunnels(&paths);

        assert_eq!(stopped, vec!["cloudflared"]);
        assert!(
            !shared_pid_path.exists(),
            "stale shared pidfile must be removed"
        );
    }
}
