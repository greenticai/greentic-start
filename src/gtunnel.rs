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
//! than spawning a second one.
//!
//! Port-keying alone is not enough here. It came from the quick-tunnel providers,
//! where each tunnel mints its own hostname, so one-per-port is exactly
//! one-per-public-identity. A gtunnel's public identity is its TUNNEL ID, and the
//! Worker admits one socket per id — while setup and start deliberately share one
//! id across two ports (setup fronts its own UI port, the runtime fronts ingress).
//! Two records, one slot. So `start` additionally evicts any agent claiming this
//! tunnel id under another port: the runtime is the authority on where an id
//! points. See [`evict_foreign_claimants`].
//!
//! Zero-config by design — the Worker base URL, tunnel id, and secret all have
//! defaults (see `crate::env_tunnel`), so selecting this tunnel needs no operator
//! input. Per-tunnel secret provisioning and hardening come later.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::runtime_state::{RuntimePaths, atomic_write};
use crate::supervisor::{self, ServiceId, ServiceSpec};
use crate::{cloudflared, tunnel_state};

pub const SERVICE_ID: &str = "gtunnel";

/// How long to wait for another process racing the check-then-spawn section.
const LOCK_WAIT: Duration = Duration::from_secs(30);

/// Default Greentic-operated Worker tunnel base. Overridable per boot via
/// `--gtunnel-worker-url` / `GREENTIC_TUNNEL_WORKER_URL`.
pub const DEFAULT_WORKER_BASE_URL: &str = "https://greentic-webhook-proxy.greentic.workers.dev";

/// Shared demo secret so a fresh box uses the managed tunnel with zero setup;
/// matches the Worker's global `TUNNEL_SECRET`. Demo/beta only — no tenant
/// isolation; rotate to per-tunnel KV secrets for production.
pub const DEFAULT_TUNNEL_SECRET: &str =
    "d00a7591949699785228c42504afa41ce168f84e4118bb127e47c5cb98e4dd90";

/// Env vars the provider passes to the spawned agent. Kept out of argv so the
/// secret never lands in `ps`/process listings.
const ENV_EDGE_URL: &str = "GREENTIC_TUNNEL_EDGE_URL";
const ENV_SECRET: &str = "GREENTIC_TUNNEL_SECRET";
const ENV_TARGET: &str = "GREENTIC_TUNNEL_TARGET";

#[derive(Clone, Debug)]
pub struct GtunnelConfig {
    /// Worker base URL (http/https), e.g. `https://…workers.dev`. Used for
    /// path-prefix routing (`<worker>/<tunnelId>`).
    pub worker_base_url: String,
    /// When set (e.g. `hooks.greentic.dev`), use subdomain routing
    /// (`https://<tunnelId>.<base_domain>`) so an app is served at the host root
    /// — required for SPAs with root-absolute URLs (the WebChat UI).
    pub base_domain: Option<String>,
    /// Root-map mode: the Worker hosts this one tunnel at its own host root, so
    /// the public URL is the bare Worker host (no `/<tunnelId>`) — SPAs work on
    /// workers.dev with no custom domain. Mutually exclusive with `base_domain`.
    pub root_map: bool,
    /// Tunnel id (first URL path segment / subdomain label), e.g. `<tenant>-<team>`.
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
pub fn public_url(
    worker_base_url: &str,
    base_domain: Option<&str>,
    root_map: bool,
    tunnel_id: &str,
) -> String {
    if let Some(base) = base_domain {
        // Subdomain routing: the tunnel is served at its own host root.
        return format!("https://{}.{}", tunnel_id, base.trim_matches('.'));
    }
    if root_map {
        // Root-map: the whole Worker host serves this one tunnel at root.
        return worker_base_url.trim_end_matches('/').to_string();
    }
    // Path-prefix routing under the shared Worker host.
    format!("{}/{}", worker_base_url.trim_end_matches('/'), tunnel_id)
}

/// The `ws(s)://…/_tunnel` registration URL for the resolved routing mode.
pub fn registration_url(
    worker_base_url: &str,
    base_domain: Option<&str>,
    root_map: bool,
    tunnel_id: &str,
) -> String {
    if let Some(base) = base_domain {
        return format!("wss://{}.{}/_tunnel", tunnel_id, base.trim_matches('.'));
    }
    let base = worker_base_url.trim_end_matches('/');
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    };
    // Root-map registers at the host root (`/_tunnel`); path-prefix under `/<id>`.
    if root_map {
        format!("{ws_base}/_tunnel")
    } else {
        format!("{ws_base}/{tunnel_id}/_tunnel")
    }
}

/// Adopt (or spawn) the supervised tunnel agent under the machine-wide shared
/// record and return the public URL it exposes. Reuses a live agent — e.g. one
/// started by `greentic-setup` — instead of spawning a duplicate.
pub fn start_agent(config: &GtunnelConfig) -> anyhow::Result<GtunnelHandle> {
    let url = public_url(
        &config.worker_base_url,
        config.base_domain.as_deref(),
        config.root_map,
        &config.tunnel_id,
    );
    // Keyed by tunnel id, not port: a multi-tenant env runs several agents on
    // ONE port, and a port-keyed record would make them share a pidfile, URL
    // cache and lock — each boot stopping its predecessor.
    let shared = tunnel_state::instance_runtime_paths(SERVICE_ID, &config.tunnel_id);
    let pid_path = shared.pid_path(SERVICE_ID);
    let url_path = cloudflared::public_url_path(&shared);
    let log_path = shared.log_path(SERVICE_ID);
    let _lock = tunnel_state::TunnelLock::acquire(
        &tunnel_state::instance_lock_path(SERVICE_ID, &config.tunnel_id),
        LOCK_WAIT,
    )?;

    if config.restart {
        let _ = supervisor::stop_pidfile(&pid_path, 2_000);
        let _ = std::fs::remove_file(&url_path);
    }

    // Claim the tunnel id before judging our own record: the `serving()` probe
    // below asks the Worker, which answers from whichever agent currently holds
    // the slot. With a foreign agent still connected that probe reports someone
    // else's tunnel as ours.
    evict_foreign_claimants(&url, &config.tunnel_id);

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
        registration_url(
            &config.worker_base_url,
            config.base_domain.as_deref(),
            config.root_map,
            &config.tunnel_id,
        ),
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

/// Stop any agent under ANOTHER port's shared record that already claims `url`,
/// so the agent for `keep_port` owns the tunnel id outright.
///
/// Without this the two agents livelock. The Worker admits one socket per tunnel
/// id, so the second to connect evicts the first; the evicted agent reconnects
/// and evicts the second, forever. Inbound webhooks then land on whichever agent
/// won the last round — for a setup-started agent that means the Setup UI port,
/// which serves no provider routes (and is usually gone by then, since setup
/// leaves its agent running after exiting).
///
/// Records are matched on the stored public URL rather than a parsed tunnel id:
/// the URL is what both binaries already write to `public_base_url.txt`, and
/// comparing it whole keeps this correct across the path-prefix, subdomain, and
/// root-map routing modes without re-deriving any of them.
fn evict_foreign_claimants(url: &str, keep_instance: &str) {
    evict_claimants_in(
        tunnel_state::existing_instance_records(SERVICE_ID),
        url,
        keep_instance,
    );
}

/// Body of [`evict_foreign_claimants`], over an explicit record set so tests can
/// supply a temp state root instead of the process-wide one.
fn evict_claimants_in(records: Vec<(String, RuntimePaths)>, url: &str, keep_instance: &str) {
    for (instance, shared) in records {
        if instance == keep_instance {
            continue;
        }
        let foreign_url_path = cloudflared::public_url_path(&shared);
        // Compared verbatim (modulo trim): gtunnel writes this file itself, as
        // the exact public URL. `cloudflared::parse_public_url` is not usable
        // here — it only recognises `*.trycloudflare.com`.
        let claims_url =
            std::fs::read_to_string(&foreign_url_path).is_ok_and(|contents| contents.trim() == url);
        if !claims_url {
            continue;
        }
        let foreign_pid_path = shared.pid_path(SERVICE_ID);
        if let Ok(Some(pid)) = read_pid(&foreign_pid_path)
            && supervisor::is_running(pid)
        {
            crate::operator_log::info(
                module_path!(),
                format!(
                    "gtunnel agent pid {pid} (tunnel {instance}) also claims {url}; stopping it so the \
                     runtime on tunnel {keep_instance} owns it — the Worker admits one socket \
                     per tunnel id, and two agents would evict each other indefinitely"
                ),
            );
        }
        let _ = supervisor::stop_pidfile(&foreign_pid_path, 2_000);
        let _ = std::fs::remove_file(&foreign_pid_path);
        let _ = std::fs::remove_file(&foreign_url_path);
    }
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

/// Per-INSTALL seed for deriving the managed-tunnel clash suffix, persisted at
/// `<root>/instance-seed` (see [`tunnel_state_root`]).
///
/// This used to be a fresh per-process nonce "mirroring cloudflared's rotating
/// hostname". That analogy does not hold: a cloudflared quick tunnel hands its
/// new hostname to whatever reads the log, whereas this suffix lands in URLs
/// already registered with third parties — Slack Event Subscriptions, Webex
/// webhooks, OAuth redirect URIs — and in the tenant those providers' secrets
/// are scoped under. Rotating it per process invalidated all of that on every
/// `gtc start`, so a bundle that worked once broke on the next boot.
///
/// Persisting restores the pre-rotation behaviour and, because the file lives in
/// the state root greentic-setup ALSO uses (it keeps `secret` and
/// `secrets/<tunnelId>` there), lets both binaries derive the SAME suffix. That
/// is what makes the id setup registers and the id start serves agree while
/// still being unique per install on the shared Worker.
///
/// Still held in a `OnceLock` so every call within one invocation agrees. Falls
/// back to an in-memory value if the file cannot be read or written, which keeps
/// a read-only HOME working at the cost of stability.
fn instance_seed() -> String {
    static SEED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SEED.get_or_init(|| load_or_create_instance_seed(&tunnel_state_root()))
        .clone()
}

/// Read `<root>/instance-seed`, creating it on first use. Root passed explicitly
/// so tests never touch a developer's `~/.greentic/tunnel`.
fn load_or_create_instance_seed(root: &Path) -> String {
    let path = root.join("instance-seed");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let existing = existing.trim().to_string();
        // 64 hex chars = the 256-bit seed we write. Anything else is corrupt or
        // truncated; replace it rather than derive suffixes from garbage.
        if existing.len() == 64 && existing.chars().all(|c| c.is_ascii_hexdigit()) {
            return existing;
        }
    }
    let seed: String = (0..32)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(err) = std::fs::write(&path, &seed) {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "could not persist the managed-tunnel seed at {} ({err}); the clash suffix will \
                 change on the next start, which invalidates URLs already registered with \
                 providers",
                path.display()
            ),
        );
    }
    seed
}

/// Stable 5-hex clash suffix for `base_tenant`: last 5 hex of
/// `sha256(instance-seed || 0x00 || base_tenant)`.
fn tenant_clash_suffix(base_tenant: &str) -> String {
    tenant_clash_suffix_from_seed(&instance_seed(), base_tenant)
}

/// Pure hashing core of [`tenant_clash_suffix`], seed passed explicitly so it is
/// deterministically testable.
fn tenant_clash_suffix_from_seed(seed: &str, base_tenant: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update([0u8]);
    hasher.update(base_tenant.as_bytes());
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    hex[hex.len() - 5..].to_string()
}

/// The managed-tunnel public tenant alias `{base}-{suffix}` (gtunnel only).
/// The per-invocation suffix keeps operators sharing a base tenant unique on the
/// one shared Worker. cloudflared/ngrok keep the bare tenant.
pub(crate) fn managed_tenant_alias(base_tenant: &str) -> String {
    format!("{base_tenant}-{}", tenant_clash_suffix(base_tenant))
}

/// Resolve a tunnel's secret: `GREENTIC_TUNNEL_SECRET` env > per-tunnel store
/// (`<root>/secrets/<id>`) > operator secret (`<root>/secret`) >
/// [`DEFAULT_TUNNEL_SECRET`]. Never empty.
pub(crate) fn resolve_secret(tunnel_id: &str) -> String {
    if let Ok(secret) = std::env::var("GREENTIC_TUNNEL_SECRET")
        && !secret.is_empty()
    {
        return secret;
    }
    read_secret_file(tunnel_secret_path(tunnel_id))
        .or_else(|| read_secret_file(operator_secret_path()))
        .unwrap_or_else(|| DEFAULT_TUNNEL_SECRET.to_string())
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

    /// Known-answer vectors for the FALLBACK derivation, pinning the exact
    /// bytes fed to sha256. greentic-setup carries the identical test against
    /// the identical constants (`setup_tunnel::tests::
    /// clash_suffix_known_answers_match_greentic_start`). The two crates cannot
    /// share the rule through `greentic-types` (exact-pinned at `=1.1.2` across
    /// this graph), so this pair of tests is what keeps them byte-identical:
    /// change one side's hashing and the other side's assertion fails. That
    /// matters because the derivation is what BOTH binaries fall back to for a
    /// bundle with no recorded tunnel id — if they disagree, setup registers a
    /// webhook URL on an id this runtime never serves.
    #[test]
    fn clash_suffix_known_answers_match_greentic_setup() {
        const SEED: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(tenant_clash_suffix_from_seed(SEED, "acme"), "0c7fe");
        assert_eq!(tenant_clash_suffix_from_seed(SEED, "default"), "871fd");
    }

    #[test]
    fn tenant_clash_suffix_is_stable_5_hex_and_scoped() {
        let a = tenant_clash_suffix_from_seed("seed-123", "default");
        // Stable for the same (seed, tenant).
        assert_eq!(a, tenant_clash_suffix_from_seed("seed-123", "default"));
        // Exactly 5 lowercase-hex chars.
        assert_eq!(a.len(), 5);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        // Distinct per tenant and per seed (so different operators/tenants differ).
        assert_ne!(a, tenant_clash_suffix_from_seed("seed-123", "acme"));
        assert_ne!(a, tenant_clash_suffix_from_seed("other-seed", "default"));
    }

    /// Plant a shared gtunnel record for `port` claiming `url`, with `pid`.
    fn plant_record(root: &Path, port: u16, url: &str, pid: u32) -> RuntimePaths {
        let paths = RuntimePaths::new(root.join("state"), "shared", format!("gtunnel-{port}"));
        let pid_path = paths.pid_path(SERVICE_ID);
        let url_path = cloudflared::public_url_path(&paths);
        for path in [&pid_path, &url_path] {
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        }
        std::fs::write(&pid_path, pid.to_string()).expect("write pid");
        std::fs::write(&url_path, url).expect("write url");
        paths
    }

    /// The setup-vs-runtime collision: one tunnel id, two ports. Only the
    /// runtime's record may survive, or the two agents evict each other on the
    /// Worker forever and webhooks land on the Setup UI half the time.
    #[test]
    fn eviction_clears_other_records_claiming_the_same_tunnel_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let url = "https://x.workers.dev/default-ba564";
        // pid 0 never names a live process, so stop_pidfile just reaps the record.
        let setup = plant_record(dir.path(), 55662, url, 0);
        let runtime = plant_record(dir.path(), 8080, url, 0);
        // A different tunnel id on a third port must be left completely alone.
        let other = plant_record(dir.path(), 9090, "https://x.workers.dev/acme-77777", 0);

        // Instance-keyed now: a stale record for the SAME tunnel id under a
        // different instance key still claims the Worker's single socket.
        let records = vec![
            ("stale-setup".to_string(), setup.clone()),
            ("default-ba564".to_string(), runtime.clone()),
            ("acme-77777".to_string(), other.clone()),
        ];
        evict_claimants_in(records, url, "default-ba564");

        assert!(
            !cloudflared::public_url_path(&setup).exists(),
            "the setup-port record claiming our tunnel id must be cleared"
        );
        assert!(!setup.pid_path(SERVICE_ID).exists());
        assert!(
            cloudflared::public_url_path(&runtime).exists(),
            "our own record must survive — start owns the tunnel id"
        );
        assert!(
            cloudflared::public_url_path(&other).exists(),
            "a record for a different tunnel id shares no slot and must be untouched"
        );
        assert!(other.pid_path(SERVICE_ID).exists());
    }

    #[test]
    fn eviction_is_a_no_op_when_no_other_record_claims_the_tunnel_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let url = "https://x.workers.dev/default-ba564";
        let runtime = plant_record(dir.path(), 8080, url, 0);

        evict_claimants_in(
            vec![("default-ba564".to_string(), runtime.clone())],
            url,
            "default-ba564",
        );

        assert!(cloudflared::public_url_path(&runtime).exists());
        assert!(runtime.pid_path(SERVICE_ID).exists());
    }

    #[test]
    fn public_url_path_mode_joins_base_and_id_without_double_slash() {
        assert_eq!(
            public_url("https://x.workers.dev/", None, false, "acme-default"),
            "https://x.workers.dev/acme-default"
        );
        assert_eq!(
            public_url("https://x.workers.dev", None, false, "acme-default"),
            "https://x.workers.dev/acme-default"
        );
    }

    #[test]
    fn public_url_subdomain_mode_uses_host_root() {
        assert_eq!(
            public_url(
                "https://x.workers.dev",
                Some("hooks.greentic.dev"),
                false,
                "acme-default"
            ),
            "https://acme-default.hooks.greentic.dev"
        );
    }

    #[test]
    fn public_url_root_map_uses_bare_worker_host() {
        assert_eq!(
            public_url("https://x.workers.dev/", None, true, "acme-default"),
            "https://x.workers.dev"
        );
    }

    #[test]
    fn registration_url_maps_scheme_to_websocket() {
        assert_eq!(
            registration_url("https://x.workers.dev", None, false, "t1"),
            "wss://x.workers.dev/t1/_tunnel"
        );
        assert_eq!(
            registration_url("http://127.0.0.1:8790", None, false, "t1"),
            "ws://127.0.0.1:8790/t1/_tunnel"
        );
    }

    #[test]
    fn registration_url_subdomain_and_root_map() {
        assert_eq!(
            registration_url(
                "https://x.workers.dev",
                Some("hooks.greentic.dev"),
                false,
                "t1"
            ),
            "wss://t1.hooks.greentic.dev/_tunnel"
        );
        assert_eq!(
            registration_url("https://x.workers.dev", None, true, "t1"),
            "wss://x.workers.dev/_tunnel"
        );
    }
}
