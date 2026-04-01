use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::DEMO_DEFAULT_TEAM;
use crate::DEMO_DEFAULT_TENANT;
use crate::runtime::NatsMode;

#[derive(Parser)]
#[command(name = "greentic-start", version)]
pub(crate) struct Cli {
    #[arg(long, global = true)]
    pub(crate) locale: Option<String>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Start(StartArgs),
    Up(StartArgs),
    Stop(StopArgs),
    Restart(StartArgs),
}

#[derive(Parser, Clone)]
pub(crate) struct StartArgs {
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
    #[arg(long, value_enum, default_value_t = CloudflaredModeArg::Off)]
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
pub(crate) struct StopArgs {
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
    /// Whether the user explicitly set `--cloudflared` or `--ngrok` on the CLI.
    /// When `false` and the terminal is interactive, we prompt for tunnel selection.
    pub tunnel_explicit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopRequest {
    pub bundle: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub tenant: String,
    pub team: String,
}

pub(crate) fn start_request_from_args(args: StartArgs, tunnel_explicit: bool) -> StartRequest {
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
        tunnel_explicit,
    }
}

pub(crate) fn stop_request_from_args(args: StopArgs) -> StopRequest {
    StopRequest {
        bundle: args.bundle,
        state_dir: args.state_dir,
        tenant: args.tenant,
        team: args.team,
    }
}

pub(crate) fn normalize_args(raw_tail: Vec<String>) -> Vec<String> {
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

pub(crate) fn restart_name(target: &RestartTarget) -> String {
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
}
