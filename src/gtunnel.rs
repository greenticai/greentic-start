//! Greentic self-hosted tunnel provider.
//!
//! Supervises the outbound WebSocket agent (`__tunnel-agent`, see
//! [`crate::gtunnel_agent`]) that connects this box to the Greentic-operated
//! Worker tunnel. Unlike cloudflared/ngrok there is no URL to discover: the
//! public URL is `<worker_base_url>/<tunnel_id>`, known up front, so start-up is
//! just "adopt or spawn the agent and report the URL".
//!
//! The agent runs under the machine-wide shared record (`crate::tunnel_state`,
//! keyed by `("gtunnel", port)`), the same protocol `greentic-setup` writes to.
//! So if setup already started the agent for this port, `start` ADOPTS it rather
//! than spawning a second one — the Worker allows only one socket per tunnel id.
//!
//! Zero-config by design — the Worker base URL, tunnel id, and secret all have
//! defaults (see `crate::env_tunnel`), so selecting this tunnel needs no operator
//! input. Per-tunnel secret provisioning and hardening come later.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::runtime_state::atomic_write;
use crate::supervisor::{self, ServiceId, ServiceSpec};
use crate::{cloudflared, tunnel_state};

pub const SERVICE_ID: &str = "gtunnel";

/// How long to wait for another process racing the check-then-spawn section.
const LOCK_WAIT: Duration = Duration::from_secs(30);

/// Default Greentic-operated Worker tunnel base. Overridable per boot via
/// `--gtunnel-worker-url` / `GREENTIC_TUNNEL_WORKER_URL`.
pub const DEFAULT_WORKER_BASE_URL: &str = "https://greentic-webhook-proxy.greentic.workers.dev";

/// Env vars the provider passes to the spawned agent. Kept out of argv so the
/// secret never lands in `ps`/process listings.
const ENV_EDGE_URL: &str = "GREENTIC_TUNNEL_EDGE_URL";
const ENV_SECRET: &str = "GREENTIC_TUNNEL_SECRET";
const ENV_TARGET: &str = "GREENTIC_TUNNEL_TARGET";

#[derive(Clone, Debug)]
pub struct GtunnelConfig {
    /// Worker base URL (http/https), e.g. `https://…workers.dev`.
    pub worker_base_url: String,
    /// Tunnel id (first URL path segment), e.g. `<tenant>-<team>`.
    pub tunnel_id: String,
    /// Shared secret the agent presents (global fallback for now).
    pub secret: String,
    /// Local origin port the agent forwards to.
    pub local_port: u16,
    pub restart: bool,
}

pub struct GtunnelHandle {
    pub url: String,
    pub log_path: PathBuf,
}

/// The public base URL callers hand out for a tunnel.
pub fn public_url(worker_base_url: &str, tunnel_id: &str) -> String {
    format!("{}/{}", worker_base_url.trim_end_matches('/'), tunnel_id)
}

/// The `ws(s)://…/_tunnel` registration URL derived from an `http(s)` base.
pub fn registration_url(worker_base_url: &str, tunnel_id: &str) -> String {
    let base = worker_base_url.trim_end_matches('/');
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    };
    format!("{ws_base}/{tunnel_id}/_tunnel")
}

/// Adopt (or spawn) the supervised tunnel agent under the machine-wide shared
/// record and return the public URL it exposes. Reuses a live agent — e.g. one
/// started by `greentic-setup` — instead of spawning a duplicate.
pub fn start_agent(config: &GtunnelConfig) -> anyhow::Result<GtunnelHandle> {
    let url = public_url(&config.worker_base_url, &config.tunnel_id);
    let shared = tunnel_state::shared_runtime_paths(SERVICE_ID, config.local_port);
    let pid_path = shared.pid_path(SERVICE_ID);
    let url_path = cloudflared::public_url_path(&shared);
    let log_path = shared.log_path(SERVICE_ID);
    let _lock = tunnel_state::TunnelLock::acquire(
        &tunnel_state::lock_path(SERVICE_ID, config.local_port),
        LOCK_WAIT,
    )?;

    if config.restart {
        let _ = supervisor::stop_pidfile(&pid_path, 2_000);
        let _ = std::fs::remove_file(&url_path);
    }

    // Adopt a live agent (e.g. started by setup) — but only if it is actually
    // SERVING. A pid can be alive while its WebSocket to the Worker is dead
    // (evicted, network drop), so a bare pid check would reuse a tunnel that
    // silently 502s. Verify reachability; a stale agent is killed and replaced.
    if let Ok(Some(pid)) = read_pid(&pid_path)
        && supervisor::is_running(pid)
    {
        if serving(&url) {
            let _ = atomic_write(&url_path, url.as_bytes());
            return Ok(GtunnelHandle { url, log_path });
        }
        crate::operator_log::info(
            module_path!(),
            format!("gtunnel agent pid {pid} alive but {url} not serving — replacing it"),
        );
        let _ = supervisor::stop_pidfile(&pid_path, 2_000);
    }
    let _ = std::fs::remove_file(&pid_path); // stale/absent record
    let _ = std::fs::remove_file(&url_path);

    let exe = std::env::current_exe()?;
    let mut env = BTreeMap::new();
    env.insert(
        ENV_EDGE_URL.to_string(),
        registration_url(&config.worker_base_url, &config.tunnel_id),
    );
    env.insert(ENV_SECRET.to_string(), config.secret.clone());
    env.insert(
        ENV_TARGET.to_string(),
        format!("http://127.0.0.1:{}", config.local_port),
    );

    let spec = ServiceSpec {
        id: ServiceId::new(SERVICE_ID)?,
        argv: vec![
            exe.to_string_lossy().to_string(),
            "__tunnel-agent".to_string(),
        ],
        cwd: None,
        env,
    };
    let handle = supervisor::spawn_service(&shared, spec, Some(log_path.clone()))?;
    let _ = atomic_write(&url_path, url.as_bytes());
    Ok(GtunnelHandle {
        url,
        log_path: handle.log_path,
    })
}

/// Whether the tunnel actually serves end to end: a bounded GET to the public
/// URL. A routed response (2xx/3xx/4xx) means the agent is connected and
/// forwarding; the Worker's `502 tunnel offline` (or any 5xx / transport error)
/// means it is stale. Mirrors the `< 500` convention greentic-setup already uses.
fn serving(public_url: &str) -> bool {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .build()
        .new_agent();
    match agent.get(public_url).call() {
        Ok(_) => true,
        Err(ureq::Error::StatusCode(code)) => code < 500,
        Err(_) => false,
    }
}

/// `~/.greentic/tunnel` (override: `GREENTIC_TUNNEL_STATE_DIR`).
fn tunnel_state_root() -> PathBuf {
    std::env::var_os("GREENTIC_TUNNEL_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
            std::env::var_os(var)
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join(".greentic")
                .join("tunnel")
        })
}

/// Machine-wide per-tunnel secret file (shared on-disk format with
/// greentic-setup, which provisions it): `<root>/secrets/<tunnelId>`.
fn tunnel_secret_path(tunnel_id: &str) -> PathBuf {
    tunnel_state_root().join("secrets").join(tunnel_id)
}

/// Operator's shared tunnel secret, set once so the managed tunnel works with no
/// per-run env var: `<root>/secret`.
fn operator_secret_path() -> PathBuf {
    tunnel_state_root().join("secret")
}

fn read_secret_file(path: PathBuf) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Resolve a tunnel's secret in precedence order:
///   1. `GREENTIC_TUNNEL_SECRET` env override,
///   2. the per-tunnel secret greentic-setup provisioned (`<root>/secrets/<id>`),
///   3. the operator's shared secret (`<root>/secret`, set once — the zero-config
///      path so the managed tunnel is used without exporting anything each run).
///
/// Empty when none is set; start never generates, only setup provisions.
pub(crate) fn resolve_secret(tunnel_id: &str) -> String {
    if let Ok(secret) = std::env::var("GREENTIC_TUNNEL_SECRET")
        && !secret.is_empty()
    {
        return secret;
    }
    read_secret_file(tunnel_secret_path(tunnel_id))
        .or_else(|| read_secret_file(operator_secret_path()))
        .unwrap_or_default()
}

fn read_pid(path: &Path) -> anyhow::Result<Option<u32>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(path)?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.parse()?))
}

/// Read the agent's config from the environment the provider set. Used by the
/// `__tunnel-agent` subcommand entry point.
pub fn agent_config_from_env() -> anyhow::Result<crate::gtunnel_agent::AgentConfig> {
    let get = |key: &str| -> anyhow::Result<String> {
        std::env::var(key).map_err(|_| anyhow::anyhow!("{key} not set"))
    };
    Ok(crate::gtunnel_agent::AgentConfig {
        edge_url: get(ENV_EDGE_URL)?,
        secret: std::env::var(ENV_SECRET).unwrap_or_default(),
        target: get(ENV_TARGET)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_url_joins_base_and_id_without_double_slash() {
        assert_eq!(
            public_url("https://x.workers.dev/", "acme-default"),
            "https://x.workers.dev/acme-default"
        );
        assert_eq!(
            public_url("https://x.workers.dev", "acme-default"),
            "https://x.workers.dev/acme-default"
        );
    }

    #[test]
    fn registration_url_maps_scheme_to_websocket() {
        assert_eq!(
            registration_url("https://x.workers.dev", "t1"),
            "wss://x.workers.dev/t1/_tunnel"
        );
        assert_eq!(
            registration_url("http://127.0.0.1:8790", "t1"),
            "ws://127.0.0.1:8790/t1/_tunnel"
        );
    }
}
