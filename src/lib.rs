use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
mod bin_resolver;
mod capabilities;
mod cards;
mod cloudflared;
mod config;
mod demo_qa_bridge;
mod dev_store_path;
mod discovery;
mod domains;
mod gmap;
mod ngrok;
mod operator_i18n;
mod operator_log;
mod provider_config_envelope;
mod qa_persist;
mod runner_exec;
mod runner_host;
mod runner_integration;
mod runtime;
mod runtime_state;
mod secret_name;
mod secret_requirements;
mod secret_value;
mod secrets_backend;
mod secrets_client;
mod secrets_gate;
mod secrets_manager;
mod secrets_setup;
mod services;
mod state_layout;
mod subscriptions_universal;
mod supervisor;

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
    #[arg(long, value_enum, value_delimiter = ',')]
    restart: Vec<RestartTarget>,
    #[arg(long, value_name = "DIR")]
    log_dir: Option<PathBuf>,
    #[arg(long, conflicts_with = "quiet")]
    verbose: bool,
    #[arg(long, conflicts_with = "verbose")]
    quiet: bool,
}

#[derive(Parser, Clone)]
struct StopArgs {
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long, default_value = DEMO_DEFAULT_TENANT)]
    tenant: String,
    #[arg(long, default_value = DEMO_DEFAULT_TEAM)]
    team: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NatsModeArg {
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

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CloudflaredModeArg {
    On,
    Off,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NgrokModeArg {
    On,
    Off,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RestartTarget {
    All,
    Cloudflared,
    Ngrok,
    Nats,
    Gateway,
    Egress,
    Subscriptions,
}

pub fn run_from_env() -> anyhow::Result<()> {
    let selected_locale = std::env::args().skip(1).collect::<Vec<_>>();
    let args = normalize_args(selected_locale);
    let cli = Cli::try_parse_from(args)?;
    if let Some(locale) = cli.locale.as_deref() {
        operator_i18n::set_locale(locale);
    }

    match cli.command {
        Command::Start(args) | Command::Up(args) => run_start(args),
        Command::Restart(mut args) => {
            if args.restart.is_empty() {
                args.restart.push(RestartTarget::All);
            }
            run_start(args)
        }
        Command::Stop(args) => run_stop(args),
    }
}

fn normalize_args(raw_tail: Vec<String>) -> Vec<String> {
    let mut out = vec!["greentic-start".to_string()];
    let mut removed_demo = false;
    let mut idx = 0usize;
    while idx < raw_tail.len() {
        let arg = &raw_tail[idx];
        if !removed_demo && !arg.starts_with('-') && arg == "demo" {
            removed_demo = true;
            idx += 1;
            continue;
        }
        out.push(arg.clone());
        idx += 1;
    }

    let known = ["start", "up", "stop", "restart"];
    let first_pos = out
        .iter()
        .skip(1)
        .find(|arg| !arg.starts_with('-'))
        .cloned();
    let should_insert_start = match first_pos {
        Some(cmd) => !known.contains(&cmd.as_str()),
        None => true,
    };
    if should_insert_start {
        out.insert(1, "start".to_string());
    }
    out
}

fn run_start(args: StartArgs) -> anyhow::Result<()> {
    let restart: BTreeSet<String> = args.restart.iter().map(restart_name).collect();
    let log_level = if args.quiet {
        operator_log::Level::Warn
    } else if args.verbose {
        operator_log::Level::Debug
    } else {
        operator_log::Level::Info
    };

    let config_path = resolve_demo_config_path(args.config.clone())?;
    let config_dir = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let state_dir = config_dir.join("state");
    let log_dir = operator_log::init(
        args.log_dir
            .clone()
            .unwrap_or_else(|| config_dir.join("logs")),
        log_level,
    )?;

    let demo_config = config::load_demo_config(&config_path)?;
    let tenant = demo_config.tenant.clone();
    let team = demo_config.team.clone();

    let cloudflared = match args.cloudflared {
        CloudflaredModeArg::Off => None,
        CloudflaredModeArg::On => {
            let explicit = args.cloudflared_binary.clone();
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

    let ngrok = match args.ngrok {
        NgrokModeArg::Off => None,
        NgrokModeArg::On => {
            let explicit = args.ngrok_binary.clone();
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

    runtime::demo_up_services(
        &config_path,
        &demo_config,
        cloudflared,
        ngrok,
        &restart,
        &log_dir,
        args.verbose,
    )?;

    println!(
        "demo start running (config={} tenant={} team={}); press Ctrl+C to stop",
        config_path.display(),
        tenant,
        team
    );
    wait_for_ctrlc()?;
    runtime::demo_down_runtime(&state_dir, &tenant, &team, false)?;
    Ok(())
}

fn run_stop(args: StopArgs) -> anyhow::Result<()> {
    let state_dir = resolve_state_dir(args.state_dir);
    runtime::demo_down_runtime(&state_dir, &args.tenant, &args.team, false)
}

fn resolve_demo_config_path(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let cwd = std::env::current_dir()?;
    let demo_path = cwd.join("demo").join("demo.yaml");
    if demo_path.exists() {
        return Ok(demo_path);
    }
    let fallback = cwd.join("greentic.operator.yaml");
    if fallback.exists() {
        return Ok(fallback);
    }
    Err(anyhow!(
        "no demo config found; pass --config or create ./demo/demo.yaml"
    ))
}

fn resolve_state_dir(state_dir: Option<PathBuf>) -> PathBuf {
    if let Some(state_dir) = state_dir {
        return state_dir;
    }
    PathBuf::from("state")
}

fn wait_for_ctrlc() -> anyhow::Result<()> {
    let runtime =
        tokio::runtime::Runtime::new().context("failed to spawn runtime for Ctrl+C listener")?;
    runtime.block_on(async {
        tokio::signal::ctrl_c()
            .await
            .map_err(|err| anyhow!("failed to wait for Ctrl+C: {err}"))
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
    }
}
