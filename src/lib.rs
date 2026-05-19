use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use clap::Parser;
use clap::error::ErrorKind;

mod admin_certs;
mod admin_server;
mod bin_resolver;
mod bundle_config;
mod bundle_ref;
mod capabilities;
mod cards;
mod cli_args;
mod cloudflared;
mod component_qa_ops;
pub mod config;
mod demo_qa_bridge;
mod dependency_resolver;
mod dev_store_path;
mod discovery;
mod doctor;
mod domains;
mod event_router;
pub(crate) mod flow_log;
mod gmap;
mod http_ingress;
mod http_routes;
mod ingress;
mod ingress_dispatch;
mod ingress_types;
mod messaging_app;
mod messaging_dto;
mod messaging_egress;
mod ngrok;
pub mod notifier;
mod offers;
mod onboard;
mod operator_i18n;
mod operator_log;
#[doc(hidden)]
pub mod perf_harness;
mod port_utils;
mod post_ingress_hooks;
mod project;
pub mod provider_config_envelope;
mod qa_persist;
mod runner_exec;
mod runner_host;
mod runner_integration;
pub mod runtime;
pub mod runtime_state;
mod secret_name;
mod secret_requirements;
mod secret_value;
mod secrets_backend;
mod secrets_client;
mod secrets_gate;
mod secrets_manager;
mod secrets_setup;
mod services;
mod setup_input;
mod setup_to_formspec;
mod startup_contract;
mod state_layout;
mod static_routes;
mod subscriptions_universal;
pub mod supervisor;
mod timer_scheduler;
mod tunnel_prompt;
mod warmup;
mod webhook_updater;
#[doc(hidden)]
pub mod ws_test_support;

use cli_args::{
    Cli, Command, normalize_args, restart_name, start_request_from_args, stop_request_from_args,
};
pub use cli_args::{
    CloudflaredModeArg, NatsModeArg, NgrokModeArg, RestartTarget, StartRequest, StopRequest,
};

const DEMO_DEFAULT_TENANT: &str = "demo";
const DEMO_DEFAULT_TEAM: &str = "default";

/// Default environment id when nothing is set. Flipped from `"dev"` to
/// `"local"` as part of A4b — the `local` env is what `gtc setup` and
/// `gtc start` auto-create per A4.
pub const DEFAULT_ENV_ID: &str = "local";

/// Legacy env id this crate accepts via the compat alias. Resolved values
/// that match this string are remapped to [`DEFAULT_ENV_ID`] with a
/// once-per-process warning, unless the operator disables the alias.
pub const LEGACY_ENV_ID: &str = "dev";

/// Env-var that disables the [`LEGACY_ENV_ID`] → [`DEFAULT_ENV_ID`] compat
/// alias. Set to `1`, `true`, `yes`, or `on` (case-insensitive) to make
/// any resolved value of `dev` hard-fail with a remediation hint.
pub const DISABLE_ALIAS_ENV_VAR: &str = "GREENTIC_DISABLE_DEV_ALIAS";

/// Resolve the effective environment string.
///
/// Priority: explicit override > `$GREENTIC_ENV` > [`DEFAULT_ENV_ID`]
/// (`"local"`). After resolution, applies the [`LEGACY_ENV_ID`] →
/// [`DEFAULT_ENV_ID`] compat alias: any value of `dev` is remapped to
/// `local` with a once-per-process `tracing::warn!` unless
/// [`DISABLE_ALIAS_ENV_VAR`] is set, in which case the resolution panics
/// with a remediation hint.
///
/// This is the canonical helper for the `runner_host`, `secrets_setup`,
/// and `qa_persist` paths. Mirrors `greentic_setup::resolve_env` (A4b
/// PR2 in `greentic-setup`). If the duplication ever proves load-bearing,
/// fold both into a shared helper in `greentic-deployer::cli::bootstrap`
/// or similar.
pub fn resolve_env(override_env: Option<&str>) -> String {
    let raw = override_env
        .map(|v| v.to_string())
        .or_else(|| std::env::var("GREENTIC_ENV").ok())
        .unwrap_or_else(|| DEFAULT_ENV_ID.to_string());
    compat_alias::apply_dev_alias(&raw)
}

mod compat_alias {
    //! `dev` → `local` compatibility alias (A4b).
    //!
    //! Mirrors `greentic_setup::compat_alias`. Centralizing into a shared
    //! crate is deferred until the duplication starts mattering — the
    //! logic is ~30 lines and the two crates have distinct test surfaces.

    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{DEFAULT_ENV_ID, DISABLE_ALIAS_ENV_VAR, LEGACY_ENV_ID};

    static WARNED: AtomicBool = AtomicBool::new(false);

    /// Apply the `dev` → `local` compat alias. Returns the remapped value
    /// for any input equal to [`LEGACY_ENV_ID`]; returns the input
    /// unchanged for any other value. Panics if the alias is disabled via
    /// [`DISABLE_ALIAS_ENV_VAR`] and the input is the legacy id.
    pub fn apply_dev_alias(env: &str) -> String {
        if env != LEGACY_ENV_ID {
            return env.to_string();
        }
        if alias_disabled() {
            // Hard-fail expiry gate. The panic message is the remediation —
            // tracing may not be wired in every binary that consumes
            // `resolve_env`, and `process::exit()` bypasses test harnesses.
            panic!(
                "environment `{LEGACY_ENV_ID}` is no longer accepted (set via {DISABLE_ALIAS_ENV_VAR}=1). \
                 Migrate to `{DEFAULT_ENV_ID}` via `gtc op env migrate-dev {DEFAULT_ENV_ID} --check` then `--apply`, \
                 or pass `--env {DEFAULT_ENV_ID}` / unset $GREENTIC_ENV.",
            );
        }
        if !WARNED.swap(true, Ordering::SeqCst) {
            tracing::warn!(
                target: "greentic_start::compat_alias",
                legacy = LEGACY_ENV_ID,
                target_env = DEFAULT_ENV_ID,
                "env `{LEGACY_ENV_ID}` is deprecated; resolving as `{DEFAULT_ENV_ID}` for this process. \
                 Plan the migration with `gtc op env migrate-dev {DEFAULT_ENV_ID} --check`; \
                 set {DISABLE_ALIAS_ENV_VAR}=1 to hard-fail on `{LEGACY_ENV_ID}` in CI.",
            );
        }
        DEFAULT_ENV_ID.to_string()
    }

    fn alias_disabled() -> bool {
        std::env::var(DISABLE_ALIAS_ENV_VAR)
            .ok()
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                matches!(v.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false)
    }

    /// Reset the warning latch. Test-only so multiple `apply_dev_alias`
    /// invocations can each verify the once-per-process behavior.
    #[cfg(test)]
    pub(super) fn reset_warning_latch_for_tests() {
        WARNED.store(false, Ordering::SeqCst);
    }
}

pub fn run_start_request(request: StartRequest) -> anyhow::Result<()> {
    run_start(request)
}

pub fn run_restart_request(mut request: StartRequest) -> anyhow::Result<()> {
    if request.restart.is_empty() {
        request.restart.push(RestartTarget::All);
    }
    run_start(request)
}

pub fn run_stop_request(request: StopRequest) -> anyhow::Result<()> {
    let state_dir = resolve_state_dir(request.state_dir, request.bundle.as_deref())?;
    runtime::demo_down_runtime(&state_dir, &request.tenant, &request.team, false)
}

pub fn run_from_env() -> anyhow::Result<()> {
    let raw_tail: Vec<String> = std::env::args().skip(1).collect();
    let tunnel_explicit = raw_tail
        .iter()
        .any(|a| a.starts_with("--cloudflared") || a.starts_with("--ngrok"));
    let args = normalize_args(raw_tail);
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            print!("{err}");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    if let Some(locale) = cli.locale.as_deref() {
        operator_i18n::set_locale(locale);
    }

    match cli.command {
        Command::Start(args) | Command::Up(args) => {
            run_start_request(start_request_from_args(args, tunnel_explicit))
        }
        Command::Restart(args) => {
            run_restart_request(start_request_from_args(args, tunnel_explicit))
        }
        Command::Stop(args) => run_stop_request(stop_request_from_args(args)),
        Command::Warmup(args) => crate::warmup::run_warmup_request(crate::warmup::WarmupRequest {
            bundle: args.bundle,
            cache_dir: args.cache_dir,
            strict: args.strict,
        }),
        Command::Doctor(args) => {
            let has_errors = crate::doctor::run_doctor(args)?;
            if has_errors {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

fn run_start(mut request: StartRequest) -> anyhow::Result<()> {
    // Disable provider-core-only mode in demo so WASM components can access secrets directly.
    // Without this, the runner-host blocks secrets_store.get() calls from WASM.
    // SAFETY: This is called early in single-threaded startup before spawning workers.
    unsafe {
        std::env::set_var("GREENTIC_PROVIDER_CORE_ONLY", "0");
    }

    // Set GREENTIC_ENV to the A4b default (`local`) if not already set.
    // A4's `bootstrap_local_environment` (below) creates `~/.greentic/environments/local/`
    // and downstream secret resolution keys off this env. If the user already exported
    // `GREENTIC_ENV=dev`, the A4b compat alias inside `resolve_env` remaps it to
    // `local` with a once-per-process warning until the alias is disabled.
    // SAFETY: This is called early in single-threaded startup before spawning workers.
    if std::env::var("GREENTIC_ENV").is_err() {
        unsafe {
            std::env::set_var("GREENTIC_ENV", DEFAULT_ENV_ID);
        }
    }

    bootstrap_local_environment()?;

    // Temporary process-level API key fallback disabled while debugging the
    // adaptive card/runtime path. Keep this block for quick re-enable if we
    // need to revisit local Ollama compatibility.
    //
    // for key in ["OPENAI_API_KEY", "OLLAMA_API_KEY", "API_KEY"] {
    //     if std::env::var(key).is_err() {
    //         unsafe {
    //             std::env::set_var(key, "ollama-placeholder");
    //         }
    //     }
    // }

    let restart: BTreeSet<String> = request.restart.iter().map(restart_name).collect();
    let log_level = if request.quiet {
        operator_log::Level::Warn
    } else if request.verbose {
        operator_log::Level::Debug
    } else {
        operator_log::Level::Info
    };

    let demo_paths =
        bundle_config::resolve_demo_paths(request.config.clone(), request.bundle.as_deref())?;
    let config_path = demo_paths.config_path.clone();
    let config_dir = demo_paths.root_dir.clone();
    let state_dir = demo_paths.state_dir.clone();

    crate::warmup::adopt_bundle_cache_dir(&config_dir);
    let log_dir = operator_log::init(
        request
            .log_dir
            .clone()
            .unwrap_or_else(|| config_dir.join("logs")),
        log_level,
    )?;

    // Initialize flow execution logger (writes to logs/flow.log)
    match flow_log::init(&log_dir) {
        Ok(path) => {
            operator_log::info(
                module_path!(),
                format!("flow.log initialized at {}", path.display()),
            );
        }
        Err(e) => {
            operator_log::warn(module_path!(), format!("failed to init flow.log: {e}"));
        }
    }

    let mut demo_config = bundle_config::load_runtime_demo_config(&demo_paths, &request)?;
    apply_nats_overrides(&mut demo_config, &request);
    let static_routes = startup_contract::inspect_bundle(&config_dir)?;
    let configured_public_base_url = startup_contract::configured_public_base_url_from_env()?;
    let tenant = demo_config.tenant.clone();
    let team = demo_config.team.clone();
    let runtime_paths =
        runtime_state::RuntimePaths::new(state_dir.clone(), tenant.clone(), team.clone());
    runtime_state::clear_stop_request(&runtime_paths)?;

    // Apply tunnel configuration from setup answers (.greentic/tunnel.json),
    // then fall back to deployer auto-detection, then interactive prompt.
    // CLI flags (--cloudflared/--ngrok) always take precedence.
    if !request.tunnel_explicit
        && let Some(tunnel) = load_tunnel_config(&config_dir)
    {
        match tunnel.mode.as_deref() {
            Some("cloudflared") => {
                operator_log::info(
                    module_path!(),
                    "tunnel mode 'cloudflared' configured in setup answers",
                );
                request.cloudflared = CloudflaredModeArg::On;
                request.tunnel_explicit = true;
            }
            Some("ngrok") => {
                operator_log::info(
                    module_path!(),
                    "tunnel mode 'ngrok' configured in setup answers",
                );
                request.ngrok = NgrokModeArg::On;
                request.tunnel_explicit = true;
            }
            Some("off") => {
                operator_log::info(
                    module_path!(),
                    "tunnel mode 'off' configured in setup answers",
                );
                request.tunnel_explicit = true;
            }
            _ => {}
        }
    }

    // Auto-enable cloudflared when no deployer packs are present in the bundle
    // (i.e. local dev mode). External webhooks (Webex, Telegram, etc.) need a
    // public URL to reach the local instance.
    if !request.tunnel_explicit {
        let has_deployer =
            !greentic_setup::deployment_targets::discover_deployer_pack_candidates(&config_dir)
                .unwrap_or_default()
                .is_empty();
        if !has_deployer {
            operator_log::info(
                module_path!(),
                "no deployer packs detected; defaulting to cloudflared tunnel",
            );
            request.cloudflared = CloudflaredModeArg::On;
            request.tunnel_explicit = true;
        }
    }

    // If the user didn't explicitly set a tunnel flag, prompt for tunnel selection
    tunnel_prompt::maybe_prompt_tunnel(&mut request);

    // Mutual exclusivity: if ngrok is explicitly enabled, disable cloudflared
    // This allows `--ngrok on` to work without needing `--cloudflared off`
    let effective_cloudflared = match (&request.cloudflared, &request.ngrok) {
        // ngrok explicitly enabled → disable cloudflared (unless cloudflared also explicitly set)
        (CloudflaredModeArg::On, NgrokModeArg::On) => {
            operator_log::info(
                module_path!(),
                "ngrok enabled, disabling cloudflared (use --cloudflared on --ngrok off to override)",
            );
            CloudflaredModeArg::Off
        }
        (mode, _) => *mode,
    };

    let cloudflared = match effective_cloudflared {
        CloudflaredModeArg::Off => None,
        CloudflaredModeArg::On => {
            let explicit = request.cloudflared_binary.clone();
            let binary = bin_resolver::resolve_binary(
                "cloudflared",
                &bin_resolver::ResolveCtx {
                    config_dir: config_dir.clone(),
                    explicit_path: explicit,
                },
            )?;
            Some(cloudflared::CloudflaredConfig {
                binary,
                local_port: demo_config.services.gateway.port,
                extra_args: Vec::new(),
                restart: restart.contains("cloudflared"),
            })
        }
    };

    let ngrok = match request.ngrok {
        NgrokModeArg::Off => None,
        NgrokModeArg::On => {
            let explicit = request.ngrok_binary.clone();
            let binary = bin_resolver::resolve_binary(
                "ngrok",
                &bin_resolver::ResolveCtx {
                    config_dir: config_dir.clone(),
                    explicit_path: explicit,
                },
            )?;
            Some(ngrok::NgrokConfig {
                binary,
                local_port: demo_config.services.gateway.port,
                extra_args: Vec::new(),
                restart: restart.contains("ngrok"),
            })
        }
    };

    let handles = runtime::demo_up_services(
        &config_path,
        &demo_config,
        &static_routes,
        configured_public_base_url,
        cloudflared,
        ngrok,
        &restart,
        request.runner_binary.clone(),
        &log_dir,
        request.verbose,
        request.no_browser,
    )?;

    let _admin_server = if request.admin {
        let resolved_certs_dir = admin_certs::resolve_admin_certs_dir(
            &config_dir,
            &state_dir,
            request.admin_certs_dir.as_deref(),
        )?;
        let admin_cert_refs = admin_certs::load_admin_cert_refs();
        operator_log::info(
            module_path!(),
            format!(
                "admin certs source={} path={}",
                resolved_certs_dir.source.as_str(),
                resolved_certs_dir.path.display()
            ),
        );
        if !admin_cert_refs.is_empty() {
            operator_log::info(
                module_path!(),
                format!("admin cert refs {}", admin_cert_refs.join(" ")),
            );
        }
        let tls_config = greentic_setup::admin::AdminTlsConfig {
            server_cert: resolved_certs_dir.path.join("server.crt"),
            server_key: resolved_certs_dir.path.join("server.key"),
            client_ca: resolved_certs_dir.path.join("ca.crt"),
            allowed_clients: admin_certs::load_admin_allowed_clients(
                &config_dir,
                &request.admin_allowed_clients,
            ),
            port: request.admin_port,
        };
        let admin_config = admin_server::AdminServerConfig {
            tls_config,
            bundle_root: config_dir.clone(),
            runtime_paths: runtime_paths.clone(),
        };
        Some(
            admin_server::AdminServer::start(admin_config).map_err(|err| {
                anyhow!("admin mode requested but admin server failed to start: {err}")
            })?,
        )
    } else {
        None
    };

    operator_log::info(
        module_path!(),
        format!(
            "demo start running config={} tenant={} team={}",
            config_path.display(),
            tenant,
            team
        ),
    );
    println!("\nReady. Press Ctrl+C to stop.");
    let shutdown_reason = wait_for_shutdown(&runtime_paths)?;
    operator_log::info(
        module_path!(),
        format!(
            "runtime shutdown requested via {}",
            shutdown_reason.as_str()
        ),
    );
    if let Some(server) = _admin_server {
        let _ = server.stop();
    }
    handles.stop()?;
    runtime::demo_down_runtime(&state_dir, &tenant, &team, false)?;
    let _ = runtime_state::clear_stop_request(&runtime_paths);
    Ok(())
}

/// Idempotently auto-create the `local` Environment on first `gtc start`.
///
/// Per A4 of `plans/next-gen-deployment.md`: every `gtc start`, `gtc up`, or
/// `gtc restart` invocation guarantees a `local` Environment exists with the
/// five default capability-slot bindings (deployer / secrets / telemetry /
/// sessions / state) before any runner work runs. Subsequent calls find the
/// env on disk and stay silent.
fn bootstrap_local_environment() -> anyhow::Result<()> {
    use greentic_deployer::cli::bootstrap::{LocalEnvOutcome, ensure_local_environment};
    use greentic_deployer::environment::LocalFsStore;

    let root = LocalFsStore::default_root()
        .context("Cannot determine default environment store root (no home directory).")?;
    let store = LocalFsStore::new(root.clone());
    let (_env, outcome) = ensure_local_environment(&store)
        .with_context(|| format!("Bootstrapping `local` environment at {}", root.display()))?;
    if outcome == LocalEnvOutcome::Created {
        operator_log::info(
            module_path!(),
            format!(
                "bootstrapped `local` environment with default capability bindings at {}",
                root.display()
            ),
        );
    }
    Ok(())
}

fn apply_nats_overrides(config: &mut config::DemoConfig, args: &StartRequest) {
    let nats_mode = if args.no_nats {
        NatsModeArg::Off
    } else {
        args.nats
    };

    if let Some(nats_url) = args.nats_url.as_ref() {
        config.services.nats.url = nats_url.clone();
    }

    match nats_mode {
        NatsModeArg::Off => {
            config.services.nats.enabled = false;
            config.services.nats.spawn.enabled = false;
        }
        NatsModeArg::On => {
            config.services.nats.enabled = true;
            config.services.nats.spawn.enabled = true;
        }
        NatsModeArg::External => {
            config.services.nats.enabled = true;
            config.services.nats.spawn.enabled = false;
        }
    }
}

fn resolve_state_dir(state_dir: Option<PathBuf>, bundle: Option<&str>) -> anyhow::Result<PathBuf> {
    if let Some(state_dir) = state_dir {
        return Ok(state_dir);
    }
    if let Some(bundle_ref) = bundle {
        let resolved = bundle_ref::resolve_bundle_ref(bundle_ref)?;
        return Ok(resolved.bundle_dir.join("state"));
    }
    Ok(PathBuf::from("state"))
}

/// Tunnel configuration loaded from `.greentic/tunnel.json`.
/// Written by `greentic-setup` when `platform_setup.tunnel` is present in
/// the setup answers document.
#[derive(serde::Deserialize)]
struct TunnelConfig {
    mode: Option<String>,
}

fn load_tunnel_config(bundle_root: &std::path::Path) -> Option<TunnelConfig> {
    let path = bundle_root.join(".greentic").join("tunnel.json");
    let raw = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&raw).ok()
}

enum ShutdownReason {
    CtrlC,
    AdminStop,
}

impl ShutdownReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::CtrlC => "ctrl_c",
            Self::AdminStop => "admin_stop",
        }
    }
}

fn wait_for_shutdown(paths: &runtime_state::RuntimePaths) -> anyhow::Result<ShutdownReason> {
    let runtime =
        tokio::runtime::Runtime::new().context("failed to spawn runtime for Ctrl+C listener")?;
    let paths = paths.clone();
    runtime.block_on(async move {
        loop {
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    result.map_err(|err| anyhow!("failed to wait for Ctrl+C: {err}"))?;
                    return Ok(ShutdownReason::CtrlC);
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
                    if runtime_state::read_stop_request(&paths)?.is_some() {
                        return Ok(ShutdownReason::AdminStop);
                    }
                }
            }
        }
    })
}

#[cfg(test)]
pub(crate) fn test_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn apply_nats_overrides_disables_nats_for_flag() {
        let mut config = config::DemoConfig::default();
        let args = StartRequest {
            bundle: None,
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
            log_dir: None,
            verbose: false,
            quiet: false,
            no_browser: false,
            admin: false,
            admin_port: 9443,
            admin_certs_dir: None,
            admin_allowed_clients: Vec::new(),
            tunnel_explicit: true,
        };
        apply_nats_overrides(&mut config, &args);
        assert!(!config.services.nats.enabled);
        assert!(!config.services.nats.spawn.enabled);
    }

    #[test]
    fn apply_nats_overrides_uses_external_url_without_spawn() {
        let mut config = config::DemoConfig::default();
        let args = StartRequest {
            bundle: None,
            tenant: None,
            team: None,
            no_nats: false,
            nats: NatsModeArg::External,
            nats_url: Some("nats://127.0.0.1:5555".into()),
            config: None,
            cloudflared: CloudflaredModeArg::Off,
            cloudflared_binary: None,
            ngrok: NgrokModeArg::Off,
            ngrok_binary: None,
            runner_binary: None,
            restart: Vec::new(),
            log_dir: None,
            verbose: false,
            quiet: false,
            no_browser: false,
            admin: false,
            admin_port: 9443,
            admin_certs_dir: None,
            admin_allowed_clients: Vec::new(),
            tunnel_explicit: true,
        };
        apply_nats_overrides(&mut config, &args);
        assert!(config.services.nats.enabled);
        assert!(!config.services.nats.spawn.enabled);
        assert_eq!(config.services.nats.url, "nats://127.0.0.1:5555");
    }

    #[test]
    fn resolve_state_dir_uses_bundle_state_when_requested() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        let state_dir =
            resolve_state_dir(None, Some(bundle.to_string_lossy().as_ref())).expect("state dir");
        assert_eq!(state_dir, bundle.join("state"));
    }

    fn make_start_request(bundle: &Path) -> StartRequest {
        StartRequest {
            bundle: Some(bundle.display().to_string()),
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
            log_dir: None,
            verbose: false,
            quiet: false,
            no_browser: false,
            admin: false,
            admin_port: 9443,
            admin_certs_dir: None,
            admin_allowed_clients: Vec::new(),
            tunnel_explicit: true,
        }
    }

    fn write_demo_bundle(bundle: &Path) {
        std::fs::create_dir_all(bundle).expect("bundle dir");
        std::fs::write(
            bundle.join("greentic.demo.yaml"),
            "tenant: demo\nteam: default\n",
        )
        .expect("write demo config");
    }

    /// RAII guard that points `$HOME` at the given tempdir for the lifetime of
    /// the returned value, restoring the previous value on drop. Used to keep
    /// `bootstrap_local_environment` (and any other HOME-rooted state) from
    /// writing into the host's real `~/.greentic` during tests.
    struct HomeOverride {
        prev: Option<std::ffi::OsString>,
    }

    impl HomeOverride {
        fn set(home: &Path) -> Self {
            let prev = std::env::var_os("HOME");
            // SAFETY: tests holding `test_env_lock` serialize env mutations.
            unsafe {
                std::env::set_var("HOME", home);
            }
            Self { prev }
        }
    }

    impl Drop for HomeOverride {
        fn drop(&mut self) {
            // SAFETY: tests holding `test_env_lock` serialize env mutations.
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }

    fn request_runtime_stop(bundle: &Path) -> thread::JoinHandle<()> {
        let runtime_paths =
            runtime_state::RuntimePaths::new(bundle.join("state"), "demo", "default");
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(350));
            runtime_state::write_stop_request(
                &runtime_paths,
                &runtime_state::StopRequest {
                    requested_by: "test".to_string(),
                    reason: Some("coverage".to_string()),
                },
            )
            .expect("write stop request");
        })
    }

    #[test]
    fn run_start_request_embedded_mode_stops_cleanly() {
        let _env_guard = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        crate::operator_log::reset_for_tests();
        let temp = tempfile::tempdir().expect("tempdir");
        let _home = HomeOverride::set(temp.path());
        let bundle = temp.path().join("bundle");
        write_demo_bundle(&bundle);
        let stop_thread = request_runtime_stop(&bundle);

        let request = make_start_request(&bundle);
        run_start_request(request).expect("start request");
        stop_thread.join().expect("join stop thread");

        let paths = runtime_state::RuntimePaths::new(bundle.join("state"), "demo", "default");
        assert!(paths.service_manifest_path().exists());
        assert!(
            runtime_state::read_stop_request(&paths)
                .expect("read stop")
                .is_none()
        );
    }

    #[test]
    fn run_restart_request_embedded_mode_stops_cleanly() {
        let _env_guard = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        crate::operator_log::reset_for_tests();
        let temp = tempfile::tempdir().expect("tempdir");
        let _home = HomeOverride::set(temp.path());
        let bundle = temp.path().join("bundle");
        write_demo_bundle(&bundle);
        let stop_thread = request_runtime_stop(&bundle);

        let mut request = make_start_request(&bundle);
        request.verbose = true;
        run_restart_request(request).expect("restart request");
        stop_thread.join().expect("join stop thread");

        let paths = runtime_state::RuntimePaths::new(bundle.join("state"), "demo", "default");
        assert!(paths.service_manifest_path().exists());
        assert!(
            runtime_state::read_stop_request(&paths)
                .expect("read stop")
                .is_none()
        );
    }

    #[test]
    fn run_start_request_quiet_mode_returns_bundle_errors() {
        let _env_guard = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        crate::operator_log::reset_for_tests();
        let temp = tempfile::tempdir().expect("tempdir");
        let _home = HomeOverride::set(temp.path());
        let missing_bundle = temp.path().join("missing-bundle");
        let mut request = make_start_request(&missing_bundle);
        request.quiet = true;

        let err = run_start_request(request).expect_err("missing bundle should error");
        let message = err.to_string();
        assert!(
            message.contains("bundle config not found")
                || message.contains("bundle path does not exist")
                || message.contains("unsupported bundle reference"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn auto_enables_cloudflared_when_no_deployer_packs() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Empty bundle dir → no deployer packs
        std::fs::create_dir_all(dir.path().join("packs")).expect("packs dir");
        let candidates =
            greentic_setup::deployment_targets::discover_deployer_pack_candidates(dir.path())
                .unwrap_or_default();
        assert!(
            candidates.is_empty(),
            "empty bundle should have no deployer"
        );
    }

    #[test]
    fn detects_deployer_pack_when_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let deployer_dir = dir.path().join("providers").join("deployer");
        std::fs::create_dir_all(&deployer_dir).expect("deployer dir");
        std::fs::write(deployer_dir.join("terraform.gtpack"), b"fake").expect("write pack");
        let candidates =
            greentic_setup::deployment_targets::discover_deployer_pack_candidates(dir.path())
                .unwrap_or_default();
        assert!(
            !candidates.is_empty(),
            "bundle with terraform.gtpack should detect deployer"
        );
    }

    #[test]
    fn bootstrap_creates_local_env_under_default_root() {
        let _env_guard = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let temp = tempfile::tempdir().expect("tempdir");
        let _home = HomeOverride::set(temp.path());
        super::bootstrap_local_environment().expect("first bootstrap");
        let env_file = temp
            .path()
            .join(".greentic")
            .join("environments")
            .join("local")
            .join("environment.json");
        assert!(env_file.exists(), "expected env file at {env_file:?}");
    }

    #[test]
    fn bootstrap_is_idempotent_across_calls() {
        let _env_guard = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let temp = tempfile::tempdir().expect("tempdir");
        let _home = HomeOverride::set(temp.path());
        super::bootstrap_local_environment().expect("first bootstrap");
        super::bootstrap_local_environment().expect("second bootstrap");
        let env_file = temp
            .path()
            .join(".greentic")
            .join("environments")
            .join("local")
            .join("environment.json");
        assert!(env_file.exists());
    }

    // ---- A4b compat-alias tests ------------------------------------------
    //
    // `GREENTIC_ENV` and `GREENTIC_DISABLE_DEV_ALIAS` are process-global;
    // serialize via the shared `test_env_lock`. Each test snapshots and
    // restores both vars + the warning latch so neighbors stay clean.

    struct EnvVarsOverride {
        prev_env: Option<std::ffi::OsString>,
        prev_disable: Option<std::ffi::OsString>,
    }

    impl EnvVarsOverride {
        fn clean() -> Self {
            let prev_env = std::env::var_os("GREENTIC_ENV");
            let prev_disable = std::env::var_os(DISABLE_ALIAS_ENV_VAR);
            // SAFETY: tests holding `test_env_lock` serialize env mutations.
            unsafe {
                std::env::remove_var("GREENTIC_ENV");
                std::env::remove_var(DISABLE_ALIAS_ENV_VAR);
            }
            super::compat_alias::reset_warning_latch_for_tests();
            Self {
                prev_env,
                prev_disable,
            }
        }
    }

    impl Drop for EnvVarsOverride {
        fn drop(&mut self) {
            // SAFETY: tests holding `test_env_lock` serialize env mutations.
            unsafe {
                match self.prev_env.take() {
                    Some(v) => std::env::set_var("GREENTIC_ENV", v),
                    None => std::env::remove_var("GREENTIC_ENV"),
                }
                match self.prev_disable.take() {
                    Some(v) => std::env::set_var(DISABLE_ALIAS_ENV_VAR, v),
                    None => std::env::remove_var(DISABLE_ALIAS_ENV_VAR),
                }
            }
        }
    }

    fn set_env_var(key: &str, value: &str) {
        // SAFETY: tests holding `test_env_lock` serialize env mutations.
        unsafe {
            std::env::set_var(key, value);
        }
    }

    #[test]
    fn resolve_env_returns_local_by_default() {
        let _guard = test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarsOverride::clean();
        assert_eq!(resolve_env(None), "local");
    }

    #[test]
    fn resolve_env_passes_through_non_legacy_override() {
        let _guard = test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarsOverride::clean();
        assert_eq!(resolve_env(Some("staging")), "staging");
        assert_eq!(resolve_env(Some("prod")), "prod");
        assert_eq!(resolve_env(Some("local")), "local");
    }

    #[test]
    fn resolve_env_remaps_dev_override_to_local() {
        let _guard = test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarsOverride::clean();
        assert_eq!(resolve_env(Some("dev")), "local");
    }

    #[test]
    fn resolve_env_remaps_dev_env_var_to_local() {
        let _guard = test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarsOverride::clean();
        set_env_var("GREENTIC_ENV", "dev");
        assert_eq!(resolve_env(None), "local");
    }

    #[test]
    fn alias_warning_latches_once_until_reset() {
        let _guard = test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarsOverride::clean();
        // First two calls remap; only the first fires warn. We can't count
        // tracing events without wiring a subscriber, so we exercise the
        // latch state by re-resetting and re-calling.
        assert_eq!(compat_alias::apply_dev_alias("dev"), "local");
        assert_eq!(compat_alias::apply_dev_alias("dev"), "local");
        compat_alias::reset_warning_latch_for_tests();
        assert_eq!(compat_alias::apply_dev_alias("dev"), "local");
    }

    #[test]
    fn disable_alias_env_var_panics_on_dev() {
        let _guard = test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarsOverride::clean();
        set_env_var(DISABLE_ALIAS_ENV_VAR, "1");
        let result = std::panic::catch_unwind(|| resolve_env(Some("dev")));
        assert!(
            result.is_err(),
            "resolve_env should panic when alias is disabled and input is `dev`"
        );
    }

    #[test]
    fn disable_alias_accepts_truthy_strings() {
        for value in ["1", "true", "TRUE", "yes", "YES", "on", " true "] {
            let _guard = test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
            let _env = EnvVarsOverride::clean();
            set_env_var(DISABLE_ALIAS_ENV_VAR, value);
            let result = std::panic::catch_unwind(|| resolve_env(Some("dev")));
            assert!(
                result.is_err(),
                "DISABLE value `{value}` should hard-fail on dev resolution"
            );
        }
    }

    #[test]
    fn disable_alias_does_not_panic_on_non_legacy_values() {
        let _guard = test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarsOverride::clean();
        set_env_var(DISABLE_ALIAS_ENV_VAR, "1");
        // Non-legacy values pass through unaffected even when the alias is
        // disabled — the gate only fires on `dev`.
        assert_eq!(resolve_env(Some("local")), "local");
        assert_eq!(resolve_env(Some("staging")), "staging");
        assert_eq!(resolve_env(None), "local");
    }
}
