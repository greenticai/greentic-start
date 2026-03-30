use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
mod admin_server;
mod bin_resolver;
mod bundle_ref;
mod capabilities;
mod cards;
mod cloudflared;
mod component_qa_ops;
pub mod config;
mod demo_qa_bridge;
mod dev_store_path;
pub mod directline;
mod discovery;
mod domains;
mod event_router;
mod gmap;
mod http_ingress;
mod ingress;
mod ingress_dispatch;
mod ingress_types;
mod messaging_app;
mod messaging_dto;
mod messaging_egress;
mod ngrok;
mod offers;
mod onboard;
mod operator_i18n;
mod operator_log;
mod post_ingress_hooks;
mod project;
mod provider_config_envelope;
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
mod webhook_updater;

use runtime::NatsMode;

const DEMO_DEFAULT_TENANT: &str = "demo";
const DEMO_DEFAULT_TEAM: &str = "default";

#[derive(Parser)]
#[command(name = "greentic-start", version)]
struct Cli {
    #[arg(long, global = true)]
    locale: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Start(StartArgs),
    Up(StartArgs),
    Stop(StopArgs),
    Restart(StartArgs),
}

#[derive(Parser, Clone)]
struct StartArgs {
    #[arg(long)]
    bundle: Option<String>,
    #[arg(long)]
    tenant: Option<String>,
    #[arg(long)]
    team: Option<String>,
    #[arg(long, hide = true, conflicts_with = "nats")]
    no_nats: bool,
    #[arg(long = "nats", value_enum, default_value_t = NatsModeArg::Off)]
    nats: NatsModeArg,
    #[arg(long)]
    nats_url: Option<String>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = CloudflaredModeArg::On)]
    cloudflared: CloudflaredModeArg,
    #[arg(long)]
    cloudflared_binary: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = NgrokModeArg::Off)]
    ngrok: NgrokModeArg,
    #[arg(long)]
    ngrok_binary: Option<PathBuf>,
    #[arg(long)]
    runner_binary: Option<PathBuf>,
    #[arg(long, value_enum, value_delimiter = ',')]
    restart: Vec<RestartTarget>,
    #[arg(long, value_name = "DIR")]
    log_dir: Option<PathBuf>,
    #[arg(long, conflicts_with = "quiet")]
    verbose: bool,
    #[arg(long, conflicts_with = "verbose")]
    quiet: bool,
    #[arg(long, help = "Enable mTLS admin API endpoint")]
    admin: bool,
    #[arg(long, default_value = "8443", help = "Port for the admin API endpoint")]
    admin_port: u16,
    #[arg(
        long,
        value_name = "DIR",
        help = "Directory containing admin TLS certs (server.crt, server.key, ca.crt)"
    )]
    admin_certs_dir: Option<PathBuf>,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma-separated list of allowed client CNs (empty = allow all valid certs)"
    )]
    admin_allowed_clients: Vec<String>,
}

#[derive(Parser, Clone)]
struct StopArgs {
    #[arg(long)]
    bundle: Option<String>,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long, default_value = DEMO_DEFAULT_TENANT)]
    tenant: String,
    #[arg(long, default_value = DEMO_DEFAULT_TEAM)]
    team: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum NatsModeArg {
    Off,
    On,
    External,
}

impl From<NatsModeArg> for NatsMode {
    fn from(value: NatsModeArg) -> Self {
        match value {
            NatsModeArg::Off => NatsMode::Off,
            NatsModeArg::On => NatsMode::On,
            NatsModeArg::External => NatsMode::External,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CloudflaredModeArg {
    On,
    Off,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum NgrokModeArg {
    On,
    Off,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RestartTarget {
    All,
    Cloudflared,
    Ngrok,
    Nats,
    Gateway,
    Egress,
    Subscriptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartRequest {
    pub bundle: Option<String>,
    pub tenant: Option<String>,
    pub team: Option<String>,
    pub no_nats: bool,
    pub nats: NatsModeArg,
    pub nats_url: Option<String>,
    pub config: Option<PathBuf>,
    pub cloudflared: CloudflaredModeArg,
    pub cloudflared_binary: Option<PathBuf>,
    pub ngrok: NgrokModeArg,
    pub ngrok_binary: Option<PathBuf>,
    pub runner_binary: Option<PathBuf>,
    pub restart: Vec<RestartTarget>,
    pub log_dir: Option<PathBuf>,
    pub verbose: bool,
    pub quiet: bool,
    pub admin: bool,
    pub admin_port: u16,
    pub admin_certs_dir: Option<PathBuf>,
    pub admin_allowed_clients: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopRequest {
    pub bundle: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub tenant: String,
    pub team: String,
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
    let selected_locale = std::env::args().skip(1).collect::<Vec<_>>();
    let args = normalize_args(selected_locale);
    let cli = Cli::try_parse_from(args)?;
    if let Some(locale) = cli.locale.as_deref() {
        operator_i18n::set_locale(locale);
    }

    match cli.command {
        Command::Start(args) | Command::Up(args) => {
            run_start_request(start_request_from_args(args))
        }
        Command::Restart(args) => run_restart_request(start_request_from_args(args)),
        Command::Stop(args) => run_stop_request(stop_request_from_args(args)),
    }
}

fn normalize_args(raw_tail: Vec<String>) -> Vec<String> {
    let mut out = vec!["greentic-start".to_string()];
    let mut stripped_demo_prefix = false;
    let mut skip_next_value = false;
    for arg in raw_tail {
        if skip_next_value {
            skip_next_value = false;
            out.push(arg);
            continue;
        }
        if arg_takes_value(&arg) {
            skip_next_value = true;
            out.push(arg);
            continue;
        }
        if !stripped_demo_prefix && !arg.starts_with('-') {
            stripped_demo_prefix = true;
            if arg == "demo" {
                continue;
            }
        }
        out.push(arg);
    }

    let known = ["start", "up", "stop", "restart"];
    let mut first_pos = None;
    let mut skip_next_value = false;
    for arg in out.iter().skip(1) {
        if skip_next_value {
            skip_next_value = false;
            continue;
        }
        if arg_takes_value(arg) {
            skip_next_value = true;
            continue;
        }
        if !arg.starts_with('-') {
            first_pos = Some(arg.clone());
            break;
        }
    }
    let should_insert_start = match first_pos {
        Some(cmd) => !known.contains(&cmd.as_str()),
        None => true,
    };
    if should_insert_start {
        out.insert(1, "start".to_string());
    }
    out
}

fn arg_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "--locale"
            | "--bundle"
            | "--tenant"
            | "--team"
            | "--nats"
            | "--nats-url"
            | "--config"
            | "--cloudflared"
            | "--cloudflared-binary"
            | "--ngrok"
            | "--ngrok-binary"
            | "--runner-binary"
            | "--restart"
            | "--log-dir"
            | "--state-dir"
            | "--admin-port"
            | "--admin-certs-dir"
            | "--admin-allowed-clients"
    )
}

fn run_start(request: StartRequest) -> anyhow::Result<()> {
    // Disable provider-core-only mode in demo so WASM components can access secrets directly.
    // Without this, the runner-host blocks secrets_store.get() calls from WASM.
    // SAFETY: This is called early in single-threaded startup before spawning workers.
    unsafe {
        std::env::set_var("GREENTIC_PROVIDER_CORE_ONLY", "0");
    }

    // Set GREENTIC_ENV to "dev" if not already set. Secrets are persisted with env="dev"
    // (see providers.rs, onboard/wizard.rs), so the runtime must match when reading.
    // SAFETY: This is called early in single-threaded startup before spawning workers.
    if std::env::var("GREENTIC_ENV").is_err() {
        unsafe {
            std::env::set_var("GREENTIC_ENV", "dev");
        }
    }

    let restart: BTreeSet<String> = request.restart.iter().map(restart_name).collect();
    let log_level = if request.quiet {
        operator_log::Level::Warn
    } else if request.verbose {
        operator_log::Level::Debug
    } else {
        operator_log::Level::Info
    };

    let demo_paths = resolve_demo_paths(request.config.clone(), request.bundle.as_deref())?;
    let config_path = demo_paths.config_path.clone();
    let config_dir = demo_paths.root_dir.clone();
    let state_dir = demo_paths.state_dir.clone();
    let log_dir = operator_log::init(
        request
            .log_dir
            .clone()
            .unwrap_or_else(|| config_dir.join("logs")),
        log_level,
    )?;

    let mut demo_config = load_runtime_demo_config(&demo_paths, &request)?;
    apply_nats_overrides(&mut demo_config, &request);
    let static_routes = startup_contract::inspect_bundle(&config_dir)?;
    let configured_public_base_url = startup_contract::configured_public_base_url_from_env()?;
    let tenant = demo_config.tenant.clone();
    let team = demo_config.team.clone();
    let runtime_paths =
        runtime_state::RuntimePaths::new(state_dir.clone(), tenant.clone(), team.clone());
    runtime_state::clear_stop_request(&runtime_paths)?;

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
    )?;

    let _admin_server = if request.admin {
        let resolved_certs_dir =
            resolve_admin_certs_dir(&config_dir, &state_dir, request.admin_certs_dir.as_deref())?;
        let admin_cert_refs = load_admin_cert_refs();
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
            allowed_clients: load_admin_allowed_clients(
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

    println!(
        "demo start running (config={} tenant={} team={}); press Ctrl+C to stop",
        config_path.display(),
        tenant,
        team
    );
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

fn start_request_from_args(args: StartArgs) -> StartRequest {
    StartRequest {
        bundle: args.bundle,
        tenant: args.tenant,
        team: args.team,
        no_nats: args.no_nats,
        nats: args.nats,
        nats_url: args.nats_url,
        config: args.config,
        cloudflared: args.cloudflared,
        cloudflared_binary: args.cloudflared_binary,
        ngrok: args.ngrok,
        ngrok_binary: args.ngrok_binary,
        runner_binary: args.runner_binary,
        restart: args.restart,
        log_dir: args.log_dir,
        verbose: args.verbose,
        quiet: args.quiet,
        admin: args.admin,
        admin_port: args.admin_port,
        admin_certs_dir: args.admin_certs_dir,
        admin_allowed_clients: args.admin_allowed_clients,
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct AdminRegistryDocument {
    #[serde(default)]
    admins: Vec<AdminRegistryEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminRegistryEntry {
    client_cn: String,
}

fn load_admin_allowed_clients(bundle_root: &Path, explicit: &[String]) -> Vec<String> {
    let mut allowed = explicit.to_vec();
    if let Ok(raw) = std::env::var("GREENTIC_ADMIN_ALLOWED_CLIENTS") {
        allowed.extend(
            raw.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    let path = bundle_root
        .join(".greentic")
        .join("admin")
        .join("admins.json");
    let Ok(raw) = std::fs::read_to_string(&path) else {
        allowed.sort();
        allowed.dedup();
        return allowed;
    };
    let Ok(doc) = serde_json::from_str::<AdminRegistryDocument>(&raw) else {
        allowed.sort();
        allowed.dedup();
        return allowed;
    };
    allowed.extend(
        doc.admins
            .into_iter()
            .map(|entry| entry.client_cn)
            .filter(|cn| !cn.trim().is_empty()),
    );
    allowed.sort();
    allowed.dedup();
    allowed
}

fn resolve_admin_certs_dir(
    bundle_root: &Path,
    state_dir: &Path,
    explicit: Option<&Path>,
) -> anyhow::Result<ResolvedAdminCertsDir> {
    if let Some(path) = explicit {
        return Ok(ResolvedAdminCertsDir {
            path: path.to_path_buf(),
            source: AdminCertsSource::ExplicitPath,
        });
    }

    let bundle_local = bundle_root.join(".greentic").join("admin").join("certs");
    if has_admin_cert_files(&bundle_local) {
        return Ok(ResolvedAdminCertsDir {
            path: bundle_local,
            source: AdminCertsSource::BundleLocal,
        });
    }

    let generated = maybe_materialize_admin_certs_from_env(state_dir)?;
    if let Some(path) = generated {
        return Ok(ResolvedAdminCertsDir {
            path,
            source: AdminCertsSource::EnvMaterialized,
        });
    }

    Ok(ResolvedAdminCertsDir {
        path: bundle_local,
        source: AdminCertsSource::BundleLocalFallback,
    })
}

fn has_admin_cert_files(dir: &Path) -> bool {
    ["ca.crt", "server.crt", "server.key"]
        .into_iter()
        .all(|name| dir.join(name).exists())
}

fn maybe_materialize_admin_certs_from_env(state_dir: &Path) -> anyhow::Result<Option<PathBuf>> {
    let ca_pem = std::env::var("GREENTIC_ADMIN_CA_PEM").ok();
    let cert_pem = std::env::var("GREENTIC_ADMIN_SERVER_CERT_PEM").ok();
    let key_pem = std::env::var("GREENTIC_ADMIN_SERVER_KEY_PEM").ok();

    let Some(ca_pem) = ca_pem else {
        return Ok(None);
    };
    let Some(cert_pem) = cert_pem else {
        return Ok(None);
    };
    let Some(key_pem) = key_pem else {
        return Ok(None);
    };

    let cert_dir = state_dir.join("admin").join("certs");
    fs::create_dir_all(&cert_dir).with_context(|| {
        format!(
            "failed to create generated admin cert directory {}",
            cert_dir.display()
        )
    })?;
    fs::write(cert_dir.join("ca.crt"), ca_pem)
        .with_context(|| format!("failed to write {}", cert_dir.join("ca.crt").display()))?;
    fs::write(cert_dir.join("server.crt"), cert_pem)
        .with_context(|| format!("failed to write {}", cert_dir.join("server.crt").display()))?;
    fs::write(cert_dir.join("server.key"), key_pem)
        .with_context(|| format!("failed to write {}", cert_dir.join("server.key").display()))?;
    Ok(Some(cert_dir))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedAdminCertsDir {
    path: PathBuf,
    source: AdminCertsSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdminCertsSource {
    ExplicitPath,
    BundleLocal,
    EnvMaterialized,
    BundleLocalFallback,
}

impl AdminCertsSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitPath => "explicit_path",
            Self::BundleLocal => "bundle_local",
            Self::EnvMaterialized => "env_materialized",
            Self::BundleLocalFallback => "bundle_local_fallback",
        }
    }
}

fn load_admin_cert_refs() -> Vec<String> {
    [
        ("GREENTIC_ADMIN_CA_SECRET_REF", "ca"),
        ("GREENTIC_ADMIN_SERVER_CERT_SECRET_REF", "server_cert"),
        ("GREENTIC_ADMIN_SERVER_KEY_SECRET_REF", "server_key"),
    ]
    .into_iter()
    .filter_map(|(env_key, label)| {
        std::env::var(env_key)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| format!("{label}={value}"))
    })
    .collect()
}

fn stop_request_from_args(args: StopArgs) -> StopRequest {
    StopRequest {
        bundle: args.bundle,
        state_dir: args.state_dir,
        tenant: args.tenant,
        team: args.team,
    }
}

struct DemoPaths {
    config_path: PathBuf,
    root_dir: PathBuf,
    state_dir: PathBuf,
    config_source: DemoConfigSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DemoConfigSource {
    LegacyFile,
    NormalizedBundle,
}

fn resolve_demo_paths(
    explicit: Option<PathBuf>,
    bundle: Option<&str>,
) -> anyhow::Result<DemoPaths> {
    if let Some(path) = explicit {
        let root_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        let config_source = resolve_runtime_config_source(&root_dir, &path)?;
        return Ok(DemoPaths {
            state_dir: root_dir.join("state"),
            root_dir,
            config_path: path,
            config_source,
        });
    }
    if let Some(bundle_ref) = bundle {
        let resolved = bundle_ref::resolve_bundle_ref(bundle_ref)?;
        let root_dir = resolved.bundle_dir;
        let (config_path, config_source) = resolve_bundle_config_path(&root_dir)?;
        return Ok(DemoPaths {
            state_dir: root_dir.join("state"),
            root_dir,
            config_path,
            config_source,
        });
    }
    let cwd = std::env::current_dir()?;
    let demo_path = cwd.join("demo").join("demo.yaml");
    if demo_path.exists() {
        let root_dir = demo_path.parent().unwrap_or(Path::new(".")).to_path_buf();
        return Ok(DemoPaths {
            state_dir: root_dir.join("state"),
            root_dir,
            config_path: demo_path,
            config_source: DemoConfigSource::LegacyFile,
        });
    }
    let fallback = cwd.join("greentic.operator.yaml");
    if fallback.exists() {
        return Ok(DemoPaths {
            state_dir: cwd.join("state"),
            root_dir: cwd,
            config_path: fallback,
            config_source: DemoConfigSource::LegacyFile,
        });
    }
    Err(anyhow!(
        "no demo config found; pass --config, --bundle, or create ./demo/demo.yaml"
    ))
}

fn resolve_bundle_config_path(root_dir: &Path) -> anyhow::Result<(PathBuf, DemoConfigSource)> {
    let demo = root_dir.join("greentic.demo.yaml");
    if demo.exists() {
        return Ok((demo, DemoConfigSource::LegacyFile));
    }
    let fallback = root_dir.join("greentic.operator.yaml");
    if fallback.exists() {
        return Ok((fallback, DemoConfigSource::LegacyFile));
    }
    let nested_demo = root_dir.join("demo").join("demo.yaml");
    if nested_demo.exists() {
        return Ok((nested_demo, DemoConfigSource::LegacyFile));
    }
    let normalized = root_dir.join("bundle.yaml");
    if normalized.exists() && normalized_bundle_has_runtime_payload(root_dir) {
        return Ok((normalized, DemoConfigSource::NormalizedBundle));
    }
    Err(anyhow!(
        "bundle config not found under {}; expected greentic.demo.yaml, greentic.operator.yaml, demo/demo.yaml, or a normalized bundle rooted on bundle.yaml",
        root_dir.display()
    ))
}

fn resolve_runtime_config_source(root_dir: &Path, path: &Path) -> anyhow::Result<DemoConfigSource> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if matches!(
        name,
        "greentic.demo.yaml" | "greentic.operator.yaml" | "demo.yaml"
    ) {
        return Ok(DemoConfigSource::LegacyFile);
    }
    if name == "bundle.yaml" && normalized_bundle_has_runtime_payload(root_dir) {
        return Ok(DemoConfigSource::NormalizedBundle);
    }
    Err(anyhow!(
        "unsupported startup config {}; expected greentic.demo.yaml, greentic.operator.yaml, demo/demo.yaml, or bundle.yaml for a normalized bundle",
        path.display()
    ))
}

fn normalized_bundle_has_runtime_payload(root_dir: &Path) -> bool {
    root_dir.join("bundle-manifest.json").exists() || root_dir.join("resolved").is_dir()
}

/// Extended bundle.yaml structure with optional demo config fields
#[derive(Debug, Deserialize)]
struct ExtendedBundleYaml {
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    providers: Option<std::collections::BTreeMap<String, config::DemoProviderConfig>>,
}

/// Result of loading extended bundle.yaml
struct ExtendedBundleResult {
    tenant: Option<String>,
    team: Option<String>,
    providers: Option<std::collections::BTreeMap<String, config::DemoProviderConfig>>,
}

/// Load extended config from bundle.yaml if present (tenant, team, providers)
fn load_extended_bundle_config(
    bundle_path: &Path,
    root_dir: &Path,
) -> anyhow::Result<Option<ExtendedBundleResult>> {
    if !bundle_path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(bundle_path)
        .with_context(|| format!("read {}", bundle_path.display()))?;

    let parsed: ExtendedBundleYaml = serde_yaml_bw::from_str(&raw)
        .with_context(|| format!("parse extended config from {}", bundle_path.display()))?;

    let mut providers = parsed.providers;

    // Resolve relative pack paths to absolute paths
    if let Some(ref mut provider_map) = providers {
        for (_name, cfg) in provider_map.iter_mut() {
            if let Some(pack) = cfg.pack.as_mut() {
                let pack_path = Path::new(pack);
                if !pack_path.is_absolute() {
                    let resolved = root_dir.join(pack_path);
                    *pack = resolved.to_string_lossy().to_string();
                }
            }
        }
    }

    Ok(Some(ExtendedBundleResult {
        tenant: parsed.tenant,
        team: parsed.team,
        providers,
    }))
}

fn load_runtime_demo_config(
    demo_paths: &DemoPaths,
    request: &StartRequest,
) -> anyhow::Result<config::DemoConfig> {
    let mut demo_config = match demo_paths.config_source {
        DemoConfigSource::LegacyFile => config::load_demo_config(&demo_paths.config_path)?,
        DemoConfigSource::NormalizedBundle => {
            let mut config = config::DemoConfig::default();
            let mut tenant_from_bundle = false;
            let mut team_from_bundle = false;

            // Try to load extended config from bundle.yaml (tenant, team, providers)
            if let Some(extended) =
                load_extended_bundle_config(&demo_paths.config_path, &demo_paths.root_dir)?
            {
                // Use tenant/team from bundle.yaml if present
                if let Some(tenant) = extended.tenant {
                    config.tenant = tenant;
                    tenant_from_bundle = true;
                }
                if let Some(team) = extended.team {
                    config.team = team;
                    team_from_bundle = true;
                }
                // Load providers
                if extended.providers.is_some() {
                    config.providers = extended.providers;
                }
            }

            // Fallback to inferred target from resolved/ directory if tenant/team not set in bundle.yaml
            if !tenant_from_bundle
                && let Some(target) = infer_normalized_bundle_target(&demo_paths.root_dir)?
            {
                config.tenant = target.tenant;
                if !team_from_bundle && let Some(team) = target.team {
                    config.team = team;
                }
            }

            config
        }
    };
    apply_target_overrides(&mut demo_config, request);
    Ok(demo_config)
}

fn apply_target_overrides(config: &mut config::DemoConfig, request: &StartRequest) {
    if let Some(tenant) = request.tenant.as_ref() {
        config.tenant = tenant.clone();
    }
    if let Some(team) = request.team.as_ref() {
        config.team = team.clone();
    }
    if let Ok(listen_addr) = std::env::var("GREENTIC_GATEWAY_LISTEN_ADDR") {
        let trimmed = listen_addr.trim();
        if !trimmed.is_empty() {
            config.services.gateway.listen_addr = trimmed.to_string();
        }
    }
    if let Ok(port) = std::env::var("GREENTIC_GATEWAY_PORT") {
        let trimmed = port.trim();
        if !trimmed.is_empty()
            && let Ok(parsed) = trimmed.parse::<u16>()
        {
            config.services.gateway.port = parsed;
        }
    }
}

#[derive(Debug, Deserialize)]
struct BundleManifestSummary {
    #[serde(default)]
    resolved_targets: Vec<ResolvedTargetSummary>,
}

#[derive(Debug, Deserialize)]
struct ResolvedTargetSummary {
    tenant: String,
    #[serde(default)]
    team: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResolvedManifestSummary {
    tenant: String,
    #[serde(default)]
    team: Option<String>,
}

fn infer_normalized_bundle_target(
    root_dir: &Path,
) -> anyhow::Result<Option<ResolvedTargetSummary>> {
    let manifest_path = root_dir.join("bundle-manifest.json");
    if manifest_path.exists() {
        let raw = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?;
        let parsed: BundleManifestSummary = serde_json::from_str(&raw)
            .with_context(|| format!("parse {}", manifest_path.display()))?;
        if let Some(target) = parsed.resolved_targets.into_iter().next() {
            return Ok(Some(target));
        }
    }

    let resolved_dir = root_dir.join("resolved");
    if !resolved_dir.is_dir() {
        return Ok(None);
    }

    let mut entries = std::fs::read_dir(&resolved_dir)?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("read {}", resolved_dir.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("yaml") {
            continue;
        }
        if let Some(target) = infer_target_from_resolved_file(&path)? {
            return Ok(Some(target));
        }
    }

    Ok(None)
}

fn infer_target_from_resolved_file(path: &Path) -> anyhow::Result<Option<ResolvedTargetSummary>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if let Ok(parsed) = serde_yaml_bw::from_str::<ResolvedManifestSummary>(&raw) {
        return Ok(Some(ResolvedTargetSummary {
            tenant: parsed.tenant,
            team: parsed.team,
        }));
    }

    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if stem.is_empty() {
        return Ok(None);
    }
    if let Some((tenant, team)) = stem.split_once('.') {
        return Ok(Some(ResolvedTargetSummary {
            tenant: tenant.to_string(),
            team: Some(team.to_string()),
        }));
    }
    Ok(Some(ResolvedTargetSummary {
        tenant: stem.to_string(),
        team: None,
    }))
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

fn restart_name(target: &RestartTarget) -> String {
    match target {
        RestartTarget::All => "all",
        RestartTarget::Cloudflared => "cloudflared",
        RestartTarget::Ngrok => "ngrok",
        RestartTarget::Nats => "nats",
        RestartTarget::Gateway => "gateway",
        RestartTarget::Egress => "egress",
        RestartTarget::Subscriptions => "subscriptions",
    }
    .to_string()
}

#[cfg(test)]
pub(crate) fn test_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_args_inserts_start_for_short_form() {
        let args = normalize_args(vec!["--tenant".into(), "demo".into()]);
        assert_eq!(args[0], "greentic-start");
        assert_eq!(args[1], "start");
        assert_eq!(args[2], "--tenant");
    }

    #[test]
    fn normalize_args_removes_demo_prefix() {
        let args = normalize_args(vec!["demo".into(), "start".into(), "--tenant".into()]);
        assert_eq!(args[0], "greentic-start");
        assert_eq!(args[1], "start");
        assert_eq!(args[2], "--tenant");
    }

    #[test]
    fn normalize_args_keeps_explicit_stop() {
        let args = normalize_args(vec!["stop".into(), "--tenant".into(), "demo".into()]);
        assert_eq!(args[0], "greentic-start");
        assert_eq!(args[1], "stop");
        assert_eq!(args[2], "--tenant");
        assert_eq!(args[3], "demo");
    }

    #[test]
    fn normalize_args_strips_only_leading_demo_prefix() {
        let args = normalize_args(vec![
            "--locale".into(),
            "en".into(),
            "demo".into(),
            "start".into(),
            "--tenant".into(),
            "demo".into(),
        ]);
        assert_eq!(args[0], "greentic-start");
        assert_eq!(args[1], "--locale");
        assert_eq!(args[2], "en");
        assert_eq!(args[3], "start");
        assert_eq!(args[4], "--tenant");
        assert_eq!(args[5], "demo");
    }

    #[test]
    fn normalize_args_keeps_runner_binary_value_with_demo_prefix() {
        let args = normalize_args(vec![
            "demo".into(),
            "start".into(),
            "--runner-binary".into(),
            "/tmp/runner".into(),
        ]);
        assert_eq!(args[0], "greentic-start");
        assert_eq!(args[1], "start");
        assert_eq!(args[2], "--runner-binary");
        assert_eq!(args[3], "/tmp/runner");
    }

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
            admin: false,
            admin_port: 9443,
            admin_certs_dir: None,
            admin_allowed_clients: Vec::new(),
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
            admin: false,
            admin_port: 9443,
            admin_certs_dir: None,
            admin_allowed_clients: Vec::new(),
        };
        apply_nats_overrides(&mut config, &args);
        assert!(config.services.nats.enabled);
        assert!(!config.services.nats.spawn.enabled);
        assert_eq!(config.services.nats.url, "nats://127.0.0.1:5555");
    }

    #[test]
    fn resolve_demo_paths_prefers_bundle_greentic_demo_yaml() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        std::fs::write(
            bundle.join("greentic.demo.yaml"),
            "version: \"1\"\nproject_root: \"./\"\n",
        )
        .expect("write config");

        let paths =
            resolve_demo_paths(None, Some(bundle.to_string_lossy().as_ref())).expect("paths");
        assert_eq!(paths.root_dir, bundle);
        assert_eq!(paths.config_path, bundle.join("greentic.demo.yaml"));
        assert_eq!(paths.state_dir, bundle.join("state"));
        assert_eq!(paths.config_source, DemoConfigSource::LegacyFile);
    }

    #[test]
    fn resolve_demo_paths_accepts_file_bundle_ref() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        std::fs::write(
            bundle.join("greentic.demo.yaml"),
            "version: \"1\"\nproject_root: \"./\"\n",
        )
        .expect("write config");
        let file_ref = format!("file://{}", bundle.display());

        let paths = resolve_demo_paths(None, Some(&file_ref)).expect("paths");
        assert_eq!(paths.config_path, bundle.join("greentic.demo.yaml"));
    }

    #[test]
    fn resolve_demo_paths_accepts_normalized_bundle_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        std::fs::write(bundle.join("bundle.yaml"), "bundle_id: demo-bundle\n").expect("bundle");
        std::fs::create_dir_all(bundle.join("resolved")).expect("resolved dir");
        std::fs::write(bundle.join("resolved/default.yaml"), "tenant: default\n")
            .expect("resolved output");

        let paths =
            resolve_demo_paths(None, Some(bundle.to_string_lossy().as_ref())).expect("paths");
        assert_eq!(paths.config_path, bundle.join("bundle.yaml"));
        assert_eq!(paths.config_source, DemoConfigSource::NormalizedBundle);
    }

    #[test]
    fn load_runtime_demo_config_infers_normalized_bundle_target() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        std::fs::write(bundle.join("bundle.yaml"), "bundle_id: demo-bundle\n").expect("bundle");
        std::fs::write(
            bundle.join("bundle-manifest.json"),
            r#"{"resolved_targets":[{"tenant":"default","team":null}]}"#,
        )
        .expect("manifest");
        let request = StartRequest {
            bundle: Some(bundle.display().to_string()),
            tenant: None,
            team: None,
            no_nats: false,
            nats: NatsModeArg::Off,
            nats_url: None,
            config: None,
            cloudflared: CloudflaredModeArg::On,
            cloudflared_binary: None,
            ngrok: NgrokModeArg::Off,
            ngrok_binary: None,
            runner_binary: None,
            restart: Vec::new(),
            log_dir: None,
            verbose: false,
            quiet: false,
            admin: false,
            admin_port: 9443,
            admin_certs_dir: None,
            admin_allowed_clients: Vec::new(),
        };
        let paths = DemoPaths {
            config_path: bundle.join("bundle.yaml"),
            root_dir: bundle.to_path_buf(),
            state_dir: bundle.join("state"),
            config_source: DemoConfigSource::NormalizedBundle,
        };

        let config = load_runtime_demo_config(&paths, &request).expect("config");
        assert_eq!(config.tenant, "default");
        assert_eq!(config.team, DEMO_DEFAULT_TEAM);
    }

    #[test]
    fn load_runtime_demo_config_applies_cli_target_overrides() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        std::fs::write(bundle.join("bundle.yaml"), "bundle_id: demo-bundle\n").expect("bundle");
        std::fs::create_dir_all(bundle.join("resolved")).expect("resolved dir");
        std::fs::write(
            bundle.join("resolved/default.platform.yaml"),
            "tenant: default\nteam: platform\n",
        )
        .expect("resolved output");
        let request = StartRequest {
            bundle: Some(bundle.display().to_string()),
            tenant: Some("tenant-a".to_string()),
            team: Some("team-b".to_string()),
            no_nats: false,
            nats: NatsModeArg::Off,
            nats_url: None,
            config: None,
            cloudflared: CloudflaredModeArg::On,
            cloudflared_binary: None,
            ngrok: NgrokModeArg::Off,
            ngrok_binary: None,
            runner_binary: None,
            restart: Vec::new(),
            log_dir: None,
            verbose: false,
            quiet: false,
            admin: false,
            admin_port: 9443,
            admin_certs_dir: None,
            admin_allowed_clients: Vec::new(),
        };
        let paths = DemoPaths {
            config_path: bundle.join("bundle.yaml"),
            root_dir: bundle.to_path_buf(),
            state_dir: bundle.join("state"),
            config_source: DemoConfigSource::NormalizedBundle,
        };

        let config = load_runtime_demo_config(&paths, &request).expect("config");
        assert_eq!(config.tenant, "tenant-a");
        assert_eq!(config.team, "team-b");
    }

    #[test]
    fn load_runtime_demo_config_applies_gateway_env_overrides() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        std::fs::write(bundle.join("bundle.yaml"), "bundle_id: demo-bundle\n").expect("bundle");
        let request = StartRequest {
            bundle: Some(bundle.display().to_string()),
            tenant: None,
            team: None,
            no_nats: false,
            nats: NatsModeArg::Off,
            nats_url: None,
            config: None,
            cloudflared: CloudflaredModeArg::On,
            cloudflared_binary: None,
            ngrok: NgrokModeArg::Off,
            ngrok_binary: None,
            runner_binary: None,
            restart: Vec::new(),
            log_dir: None,
            verbose: false,
            quiet: false,
            admin: false,
            admin_port: 9443,
            admin_certs_dir: None,
            admin_allowed_clients: Vec::new(),
        };
        let paths = DemoPaths {
            config_path: bundle.join("bundle.yaml"),
            root_dir: bundle.to_path_buf(),
            state_dir: bundle.join("state"),
            config_source: DemoConfigSource::NormalizedBundle,
        };

        unsafe {
            std::env::set_var("GREENTIC_GATEWAY_LISTEN_ADDR", "0.0.0.0");
            std::env::set_var("GREENTIC_GATEWAY_PORT", "18080");
        }
        let config = load_runtime_demo_config(&paths, &request).expect("config");
        unsafe {
            std::env::remove_var("GREENTIC_GATEWAY_LISTEN_ADDR");
            std::env::remove_var("GREENTIC_GATEWAY_PORT");
        }

        assert_eq!(config.services.gateway.listen_addr, "0.0.0.0");
        assert_eq!(config.services.gateway.port, 18080);
    }

    #[test]
    fn resolve_state_dir_uses_bundle_state_when_requested() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        let state_dir =
            resolve_state_dir(None, Some(bundle.to_string_lossy().as_ref())).expect("state dir");
        assert_eq!(state_dir, bundle.join("state"));
    }

    #[test]
    fn resolve_admin_certs_dir_prefers_bundle_local_certs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        let certs = bundle.join(".greentic").join("admin").join("certs");
        std::fs::create_dir_all(&certs).expect("cert dir");
        std::fs::write(certs.join("ca.crt"), "ca").expect("ca");
        std::fs::write(certs.join("server.crt"), "cert").expect("cert");
        std::fs::write(certs.join("server.key"), "key").expect("key");

        let resolved = resolve_admin_certs_dir(bundle, &bundle.join("state"), None).expect("dir");
        assert_eq!(resolved.path, certs);
        assert_eq!(resolved.source, AdminCertsSource::BundleLocal);
    }

    #[test]
    fn resolve_admin_certs_dir_materializes_env_pems_into_state_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        let state_dir = bundle.join("state");

        unsafe {
            std::env::set_var("GREENTIC_ADMIN_CA_PEM", "ca-pem");
            std::env::set_var("GREENTIC_ADMIN_SERVER_CERT_PEM", "cert-pem");
            std::env::set_var("GREENTIC_ADMIN_SERVER_KEY_PEM", "key-pem");
        }

        let resolved = resolve_admin_certs_dir(bundle, &state_dir, None).expect("dir");
        assert_eq!(resolved.path, state_dir.join("admin").join("certs"));
        assert_eq!(resolved.source, AdminCertsSource::EnvMaterialized);
        assert_eq!(
            std::fs::read_to_string(resolved.path.join("ca.crt")).expect("read ca"),
            "ca-pem"
        );
        assert_eq!(
            std::fs::read_to_string(resolved.path.join("server.crt")).expect("read cert"),
            "cert-pem"
        );
        assert_eq!(
            std::fs::read_to_string(resolved.path.join("server.key")).expect("read key"),
            "key-pem"
        );

        unsafe {
            std::env::remove_var("GREENTIC_ADMIN_CA_PEM");
            std::env::remove_var("GREENTIC_ADMIN_SERVER_CERT_PEM");
            std::env::remove_var("GREENTIC_ADMIN_SERVER_KEY_PEM");
        }
    }

    #[test]
    fn resolve_admin_certs_dir_marks_explicit_source() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        let explicit = bundle.join("custom-certs");

        let resolved =
            resolve_admin_certs_dir(bundle, &bundle.join("state"), Some(&explicit)).expect("dir");
        assert_eq!(resolved.path, explicit);
        assert_eq!(resolved.source, AdminCertsSource::ExplicitPath);
    }

    #[test]
    fn load_admin_cert_refs_reads_optional_env_vars() {
        unsafe {
            std::env::set_var("GREENTIC_ADMIN_CA_SECRET_REF", "ca-ref");
            std::env::set_var("GREENTIC_ADMIN_SERVER_CERT_SECRET_REF", "cert-ref");
            std::env::set_var("GREENTIC_ADMIN_SERVER_KEY_SECRET_REF", "key-ref");
        }

        let refs = load_admin_cert_refs();
        assert_eq!(
            refs,
            vec![
                "ca=ca-ref".to_string(),
                "server_cert=cert-ref".to_string(),
                "server_key=key-ref".to_string()
            ]
        );

        unsafe {
            std::env::remove_var("GREENTIC_ADMIN_CA_SECRET_REF");
            std::env::remove_var("GREENTIC_ADMIN_SERVER_CERT_SECRET_REF");
            std::env::remove_var("GREENTIC_ADMIN_SERVER_KEY_SECRET_REF");
        }
    }

    #[test]
    fn load_admin_allowed_clients_merges_env_and_registry() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        let admin_dir = bundle.join(".greentic").join("admin");
        std::fs::create_dir_all(&admin_dir).expect("admin dir");
        std::fs::write(
            admin_dir.join("admins.json"),
            r#"{"admins":[{"client_cn":"bundle-admin"}]}"#,
        )
        .expect("admins");

        unsafe {
            std::env::set_var("GREENTIC_ADMIN_ALLOWED_CLIENTS", "env-a, env-b");
        }

        let allowed = load_admin_allowed_clients(bundle, &["explicit-a".to_string()]);
        assert_eq!(
            allowed,
            vec![
                "bundle-admin".to_string(),
                "env-a".to_string(),
                "env-b".to_string(),
                "explicit-a".to_string()
            ]
        );

        unsafe {
            std::env::remove_var("GREENTIC_ADMIN_ALLOWED_CLIENTS");
        }
    }
}
