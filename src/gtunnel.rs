//! Greentic self-hosted tunnel provider.
//!
//! Supervises the outbound WebSocket agent (`__tunnel-agent`, see
//! [`crate::gtunnel_agent`]) that connects this box to the Greentic-operated
//! Worker tunnel. Unlike cloudflared/ngrok there is no URL to discover: the
//! public URL is `<worker_base_url>/<tunnel_id>`, known up front, so start-up is
//! just "spawn the agent and report the URL".
//!
//! Zero-config by design — the Worker base URL, tunnel id, and secret all have
//! defaults (see `crate::env_tunnel`), so selecting this tunnel needs no operator
//! input. Per-tunnel secret provisioning and hardening come later.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::runtime_state::RuntimePaths;
use crate::supervisor::{self, ServiceId, ServiceSpec};

pub const SERVICE_ID: &str = "gtunnel";

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

/// Spawn (or restart) the supervised tunnel agent for this tenant and return
/// the public URL it exposes.
pub fn start_agent(
    paths: &RuntimePaths,
    config: &GtunnelConfig,
    log_path: &Path,
) -> anyhow::Result<GtunnelHandle> {
    if config.restart {
        let _ = supervisor::stop_pidfile(&paths.pid_path(SERVICE_ID), 2_000);
    }

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
    let handle = supervisor::spawn_service(paths, spec, Some(log_path.to_path_buf()))?;
    Ok(GtunnelHandle {
        url: public_url(&config.worker_base_url, &config.tunnel_id),
        log_path: handle.log_path,
    })
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
