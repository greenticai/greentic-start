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
    Warmup(WarmupArgs),
    Doctor(DoctorArgs),
    #[command(hide = true)]
    ResolveSecret(ResolveSecretArgs),
    /// Internal: run the outbound tunnel agent. Spawned by the gtunnel provider;
    /// reads its config (edge url, secret, target) from the environment.
    #[command(name = "__tunnel-agent", hide = true)]
    TunnelAgent,
}

#[derive(Parser, Clone)]
pub(crate) struct DoctorArgs {
    /// Bundle reference or extracted bundle directory to inspect. When
    /// omitted, doctor checks the environment-store readiness of `--env`
    /// (or the resolved default env) instead.
    pub(crate) bundle: Option<String>,
    /// Environment id whose store-backed runtime readiness should be
    /// checked (trust root, messaging-endpoint linkage, secret-ref
    /// resolvability). Defaults to `$GREENTIC_ENV` / `local` when no
    /// bundle is given.
    #[arg(long)]
    pub(crate) env: Option<String>,
    /// Emit stable machine-readable JSON.
    #[arg(long)]
    pub(crate) json: bool,
    /// Promote drift/tag/cache and env-readiness warnings to errors.
    #[arg(long)]
    pub(crate) strict: bool,
    /// Include longer remediation hints in human output.
    #[arg(long)]
    pub(crate) fix_hints: bool,
    /// Include informational checks in output.
    #[arg(long)]
    pub(crate) show_info: bool,
    /// Restrict checks to one diagnostic stage.
    #[arg(long, value_enum, default_value_t = DoctorStageArg::All)]
    pub(crate) stage: DoctorStageArg,
}

impl DoctorArgs {
    /// Whether this invocation runs the env-store readiness checks:
    /// explicitly requested via `--env`, or by default when no bundle
    /// target was given (mirroring the bundle-less `greentic-start` boot).
    pub(crate) fn env_mode(&self) -> bool {
        self.env.is_some() || self.bundle.is_none()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum DoctorStageArg {
    All,
    Setup,
    Cache,
    Locks,
    Answers,
    Runtime,
    Routes,
    Provider,
    Secrets,
}

#[derive(Parser, Clone)]
pub(crate) struct WarmupArgs {
    /// Path to a setup-resolved bundle directory whose components should be precompiled.
    #[arg(long)]
    pub(crate) bundle: PathBuf,
    /// Cache root directory. Defaults to `${GREENTIC_CACHE_DIR}` or `.greentic/cache/components`.
    #[arg(long, value_name = "DIR")]
    pub(crate) cache_dir: Option<PathBuf>,
    /// Fail on the first compile error instead of counting it as skipped.
    #[arg(long)]
    pub(crate) strict: bool,
}

#[derive(Parser, Clone)]
pub(crate) struct ResolveSecretArgs {
    /// Bundle root to resolve against.
    #[arg(long)]
    pub(crate) bundle: PathBuf,
    #[arg(long, default_value = DEMO_DEFAULT_TENANT)]
    pub(crate) tenant: String,
    #[arg(long, default_value = DEMO_DEFAULT_TEAM)]
    pub(crate) team: String,
    /// Canonical secrets:// URI to read.
    #[arg(long)]
    pub(crate) uri: String,
}

#[derive(Parser, Clone)]
pub(crate) struct StartArgs {
    #[arg(long)]
    bundle: Option<String>,
    /// Environment id whose persisted state the bundle-less boot serves.
    /// Wins over `$GREENTIC_ENV`; defaults to `local`. Ignored (with a
    /// warning) on the legacy `--bundle` / `--config` path, which has no
    /// environment concept.
    #[arg(long)]
    env: Option<String>,
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
    /// Greentic self-hosted tunnel (Cloudflare Worker + agent). Zero-config:
    /// the Worker URL, tunnel id, and secret are resolved from defaults/env.
    #[arg(long, value_enum, default_value_t = GtunnelModeArg::Off)]
    gtunnel: GtunnelModeArg,
    /// Override the Greentic Worker tunnel base URL (else GREENTIC_TUNNEL_WORKER_URL
    /// or the built-in default).
    #[arg(long)]
    gtunnel_worker_url: Option<String>,
    /// Override the tunnel id (else GREENTIC_TUNNEL_ID or a value derived from
    /// tenant/team).
    #[arg(long)]
    gtunnel_tunnel_id: Option<String>,
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
    #[arg(long, help = "Do not open the first web UI URL in the default browser")]
    no_browser: bool,
    #[arg(
        long,
        help = "Do not subscribe this runtime to its environment's update channel"
    )]
    no_updates: bool,
    #[arg(
        long,
        help = "Do not auto-restart after a binary self-update (stage only, like P7d)"
    )]
    no_auto_restart: bool,
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
    /// Environment id whose serving runtime should be stopped. Wins over
    /// `$GREENTIC_ENV`; defaults to `local`. Ignored on the legacy
    /// `--bundle` / `--state-dir` path.
    #[arg(long)]
    env: Option<String>,
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
pub enum GtunnelModeArg {
    On,
    Off,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RestartTarget {
    All,
    Cloudflared,
    Ngrok,
    Gtunnel,
    Nats,
    Gateway,
    Egress,
    Subscriptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartRequest {
    pub bundle: Option<String>,
    /// Environment id override for the bundle-less boot (flag >
    /// `$GREENTIC_ENV` > `local` — precedence lives in `resolve_env`).
    pub env: Option<String>,
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
    pub gtunnel: GtunnelModeArg,
    pub gtunnel_worker_url: Option<String>,
    pub gtunnel_tunnel_id: Option<String>,
    pub runner_binary: Option<PathBuf>,
    pub restart: Vec<RestartTarget>,
    pub log_dir: Option<PathBuf>,
    pub verbose: bool,
    pub quiet: bool,
    pub no_browser: bool,
    /// Kill switch for the updater, not a policy knob: skip the update poll
    /// loop and refuse `/v1/updates/notify` on this box. The environment's
    /// `update-channel.json` policy (`on_update` / `enabled`) is untouched, so
    /// a restart without the flag resumes whatever the operator declared.
    pub no_updates: bool,
    pub no_auto_restart: bool,
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
    /// Environment id override for the bundle-less stop path (flag >
    /// `$GREENTIC_ENV` > `local`).
    pub env: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub tenant: String,
    pub team: String,
}

pub(crate) fn start_request_from_args(args: StartArgs, tunnel_explicit: bool) -> StartRequest {
    StartRequest {
        bundle: args.bundle,
        env: args.env,
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
        gtunnel: args.gtunnel,
        gtunnel_worker_url: args.gtunnel_worker_url,
        gtunnel_tunnel_id: args.gtunnel_tunnel_id,
        runner_binary: args.runner_binary,
        restart: args.restart,
        log_dir: args.log_dir,
        verbose: args.verbose,
        quiet: args.quiet,
        no_browser: args.no_browser,
        no_updates: args.no_updates,
        no_auto_restart: args.no_auto_restart,
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
        env: args.env,
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

    if only_global_flags(&out[1..]) {
        return out;
    }

    let known = [
        "start",
        "up",
        "stop",
        "restart",
        "warmup",
        "doctor",
        "resolve-secret",
        "__tunnel-agent",
    ];
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

fn only_global_flags(args: &[String]) -> bool {
    if args.is_empty() {
        return false;
    }

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--help" | "-h" | "--version" | "-V" => {
                index += 1;
            }
            "--locale" => {
                if index + 1 >= args.len() {
                    return false;
                }
                index += 2;
            }
            value if value.starts_with("--locale=") => {
                index += 1;
            }
            _ => return false,
        }
    }

    true
}

fn arg_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "--locale"
            | "--bundle"
            | "--env"
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
            | "--stage"
            | "--state-dir"
            | "--admin-port"
            | "--admin-certs-dir"
            | "--admin-allowed-clients"
            | "--uri"
    )
}

pub(crate) fn restart_name(target: &RestartTarget) -> String {
    match target {
        RestartTarget::All => "all",
        RestartTarget::Cloudflared => "cloudflared",
        RestartTarget::Ngrok => "ngrok",
        RestartTarget::Gtunnel => "gtunnel",
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
    fn start_and_stop_parse_env_flag_into_requests() {
        let cli = Cli::try_parse_from(["greentic-start", "start", "--env", "staging"]).unwrap();
        let Command::Start(args) = cli.command else {
            panic!("expected start");
        };
        let req = start_request_from_args(args, false);
        assert_eq!(req.env.as_deref(), Some("staging"));

        let cli = Cli::try_parse_from(["greentic-start", "stop", "--env", "staging"]).unwrap();
        let Command::Stop(args) = cli.command else {
            panic!("expected stop");
        };
        let req = stop_request_from_args(args);
        assert_eq!(req.env.as_deref(), Some("staging"));
    }

    #[test]
    fn env_defaults_to_none_when_flag_absent() {
        // `None` is load-bearing: it keeps `resolve_env`'s
        // flag > $GREENTIC_ENV > `local` precedence intact.
        let cli = Cli::try_parse_from(["greentic-start", "start"]).unwrap();
        let Command::Start(args) = cli.command else {
            panic!("expected start");
        };
        assert_eq!(start_request_from_args(args, false).env, None);
    }

    #[test]
    fn normalize_args_treats_env_value_as_value_not_positional() {
        // `--env demo`: "demo" is the flag's VALUE — it must be neither
        // stripped as the legacy `demo` subcommand prefix nor mistaken for
        // a positional when deciding to insert `start`.
        let args = normalize_args(vec!["--env".into(), "demo".into()]);
        assert_eq!(args, ["greentic-start", "start", "--env", "demo"]);
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
    fn normalize_args_keeps_explicit_doctor() {
        let args = normalize_args(vec!["doctor".into(), ".".into(), "--json".into()]);
        assert_eq!(args[0], "greentic-start");
        assert_eq!(args[1], "doctor");
        assert_eq!(args[2], ".");
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
    fn normalize_args_keeps_global_version_flag_without_start() {
        let args = normalize_args(vec!["--version".into()]);
        assert_eq!(
            args,
            vec!["greentic-start".to_string(), "--version".to_string()]
        );
    }

    #[test]
    fn normalize_args_keeps_global_help_flag_without_start() {
        let args = normalize_args(vec!["--help".into()]);
        assert_eq!(
            args,
            vec!["greentic-start".to_string(), "--help".to_string()]
        );
    }

    #[test]
    fn normalize_args_keeps_locale_and_version_without_start() {
        let args = normalize_args(vec!["--locale".into(), "en".into(), "--version".into()]);
        assert_eq!(
            args,
            vec![
                "greentic-start".to_string(),
                "--locale".to_string(),
                "en".to_string(),
                "--version".to_string(),
            ]
        );
    }
}
