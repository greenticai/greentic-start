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
mod business_event_listener;
mod capabilities;
pub mod capability_discovery;
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
// `pub` (doc-hidden) so integration tests in later env-home tasks can drive
// the loader directly, the same way `ws_test_support` and `perf_harness` are
// exposed for their own integration tests.
#[doc(hidden)]
pub mod env_home;
pub mod event_router;
mod fast2flow;
pub(crate) mod flow_log;
mod gmap;
mod http_ingress;
mod http_routes;
mod ingress;
mod ingress_dispatch;
pub mod ingress_types;
mod llm;
pub mod messaging_app;
mod messaging_dto;
mod messaging_egress;
mod metrics;
mod ngrok;
pub mod notifier;
mod oauth_engine;
mod oauth_secret_bridge;
mod oauth_state;
mod offers;
mod onboard;
mod operator_i18n;
mod operator_log;
mod otlp_telemetry;
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
mod secrets_provider_binding;
mod secrets_setup;
mod services;
mod setup_input;
mod setup_to_formspec;
mod startup_contract;
mod state_layout;
mod static_routes;
mod subscription_updater;
mod subscriptions_universal;
pub mod supervisor;
// `pub` (doc-hidden) so `tests/threshold_watcher.rs` can drive `poll_once`
// and the config/state/eval types directly, the same way `ws_test_support`
// and `perf_harness` are exposed for their own integration tests.
#[doc(hidden)]
pub mod threshold_watcher;
mod timer_scheduler;
pub(crate) mod topic_match;
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
        Command::ResolveSecret(args) => run_resolve_secret(args),
        Command::Doctor(args) => {
            let has_errors = crate::doctor::run_doctor(args)?;
            if has_errors {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

fn run_resolve_secret(args: cli_args::ResolveSecretArgs) -> anyhow::Result<()> {
    let handle =
        secrets_gate::resolve_secrets_manager(&args.bundle, &args.tenant, Some(&args.team))
            .with_context(|| {
                format!(
                    "resolve secrets manager for bundle={} tenant={} team={}",
                    args.bundle.display(),
                    args.tenant,
                    args.team
                )
            })?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create secret resolver runtime")?;
    runtime
        .block_on(async { handle.manager().read(&args.uri).await })
        .map_err(|err| anyhow!("resolve secret {}: {err}", args.uri))?;
    Ok(())
}

/// Best-effort TCP reachability probe for a Redis endpoint.
///
/// Parses `host:port` out of a `redis[s]://[user:pass@]host:port[/db]` URL and
/// attempts a short-timeout TCP connect. Used only to decide whether the
/// agentic worker should use Redis-backed state (durable across restarts) or
/// the in-process fallback; a false result is never fatal.
fn redis_endpoint_reachable(url: &str) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    let after_auth = without_scheme.rsplit('@').next().unwrap_or(without_scheme);
    let host_port = after_auth.split('/').next().unwrap_or(after_auth);
    let host_port = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:6379")
    };

    match host_port.to_socket_addrs() {
        Ok(addrs) => addrs
            .into_iter()
            .any(|addr| TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()),
        Err(_) => false,
    }
}

fn run_start(mut request: StartRequest) -> anyhow::Result<()> {
    if request.store_root.is_some() && (request.bundle.is_some() || request.config.is_some()) {
        anyhow::bail!("--store-root is mutually exclusive with --bundle/--config");
    }

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

    // Agentic Worker (dw.agent) state backend. Redis is OPTIONAL: when one is
    // reachable we point the AW at it so conversation memory survives process
    // restarts; when it isn't, the desktop runner uses a process-global
    // in-memory store that keeps multi-turn memory alive for the lifetime of
    // this `gtc start` process (no external infrastructure required). Either
    // way a multi-turn agent can propose an action and act on the user's later
    // "yes" — the difference is only durability across restarts.
    // SAFETY: single-threaded startup, before any worker spawns.
    if std::env::var("GREENTIC_AW_REDIS_URL").is_err() {
        let candidate = std::env::var("REDIS_URL")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());
        if redis_endpoint_reachable(&candidate) {
            unsafe {
                std::env::set_var("GREENTIC_AW_REDIS_URL", &candidate);
            }
            operator_log::info(
                module_path!(),
                format!(
                    "agentic worker state: using Redis at {candidate} (dw.agent memory persists across restarts)"
                ),
            );
        } else {
            operator_log::info(
                module_path!(),
                "agentic worker state: no Redis found; using in-process memory \
                 (multi-turn dw.agent memory works for this session, reset on restart). \
                 Set GREENTIC_AW_REDIS_URL to persist across restarts.",
            );
        }
    }

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

    // Initialize operator.log before any fallible setup so startup failures (bad
    // bundle.yaml, missing config, unreadable paths) leave an on-disk trace.
    //
    // Default log dir selection must never resolve to an unwritable path: in
    // cloud/operator mode `--bundle` is a URL or a read-only mount, and the root
    // filesystem may be read-only for security, so `<bundle>/logs` and `<cwd>/logs`
    // both fail and the operator blocks at log init. Only use `<bundle>/logs` when
    // the bundle is an existing local directory (local dev); otherwise fall back to
    // a writable scratch dir under the system temp dir. Operators can always pin it
    // explicitly with `--log-dir`.
    let early_log_dir =
        default_operator_log_dir(request.log_dir.clone(), request.bundle.as_deref());
    let log_dir = operator_log::init(early_log_dir, log_level)?;

    let (peeked_telemetry, peeked_service_name) = peek_startup_telemetry(&request);

    // Install a tracing subscriber that writes RUST_LOG-filtered events to
    // <log_dir>/system.log. When a bundle's `telemetry:` block (or the
    // TELEMETRY_EXPORT/OTLP_ENDPOINT env vars) requests OTLP, an additional
    // OpenTelemetry tracer + meter + logger layer is composed into the same
    // subscriber. Absent → file-only, today's behaviour.
    let _trace_guard = init_trace_log(&log_dir, peeked_telemetry.as_ref(), &peeked_service_name);

    let (demo_paths, mut demo_config) = if let Some(store_root) = request.store_root.clone() {
        match crate::env_home::load_env_home(&store_root, &request.env, &request) {
            Ok(pair) => pair,
            Err(err) => {
                operator_log::error(module_path!(), format!("load_env_home failed: {err:#}"));
                return Err(err);
            }
        }
    } else {
        let demo_paths = match bundle_config::resolve_demo_paths(
            request.config.clone(),
            request.bundle.as_deref(),
        ) {
            Ok(paths) => paths,
            Err(err) => {
                operator_log::error(
                    module_path!(),
                    format!("resolve_demo_paths failed: {err:#}"),
                );
                return Err(err);
            }
        };
        let demo_config = bundle_config::load_runtime_demo_config(&demo_paths, &request)?;
        (demo_paths, demo_config)
    };
    let config_path = demo_paths.config_path.clone();
    let config_dir = demo_paths.root_dir.clone();
    let state_dir = demo_paths.state_dir.clone();

    crate::warmup::adopt_bundle_cache_dir(&config_dir);

    let resolved_log_dir = config_dir.join("logs");
    if request.log_dir.is_none() && resolved_log_dir != log_dir {
        operator_log::warn(
            module_path!(),
            format!(
                "operator.log is at {} but resolved bundle log dir is {}; future logs stay at the former",
                log_dir.display(),
                resolved_log_dir.display()
            ),
        );
    }

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

    apply_nats_overrides(&mut demo_config, &request);

    // Make the bundle's `llm:` instance available to every LLM consumer (the
    // Fast2Flow routing fallback today; other features later). Peeked once at
    // startup, mirroring the telemetry peek.
    let llm_cfg = bundle_config::peek_bundle_llm(&config_dir.join("bundle.yaml"))
        .or_else(|| bundle_config::peek_bundle_llm(&config_path));
    llm::set_config(llm_cfg);
    // Resolve the LLM credential once (a `secrets://` dev-store ref or an env-var
    // name) so keyed providers (OpenAI/Anthropic/…) work; Ollama needs none.
    if let Some(cfg) = llm::config() {
        let key = llm::resolve_credential(cfg, &config_dir);
        llm::set_resolved_api_key(key);
    }
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
    let watched_runtime_config = request
        .store_root
        .as_deref()
        .map(|store_root| store_root.join(&request.env).join("runtime-config.json"));
    let shutdown_reason = wait_for_shutdown(&runtime_paths, watched_runtime_config)?;
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

/// Crates whose log output is unconditionally clamped to `warn` regardless of
/// the user's `RUST_LOG` setting. These are very chatty runtime/internals that
/// drown trace.log under any debug-level base filter and rarely help debug
/// greentic itself. Override by adjusting this list.
const NOISY_TRACE_TARGETS: &[&str] = &[
    "wasmtime",
    "wasmtime_wasi",
    "wasi_common",
    "cranelift_codegen",
    "cranelift_frontend",
    "cranelift_wasm",
    "regalloc2",
    "h2",
    "hyper",
    "hyper_util",
    "rustls",
    "reqwest",
    "tonic",
    "tokio_util",
    "tokio_tungstenite",
    "tungstenite",
    "want",
    "mio",
    "tower",
    // The OTLP SDK logs about its own exports — clamp so telemetry plumbing
    // doesn't feed itself back into Loki at debug/trace volume.
    "opentelemetry",
    "opentelemetry_sdk",
];

/// Best-effort peek of the bundle's `telemetry:` block (or its sidecar
/// artifact) before the tracing subscriber is installed.
fn peek_startup_telemetry(
    request: &StartRequest,
) -> (Option<bundle_config::BundleTelemetryConfig>, String) {
    let demo_paths = if let Some(store_root) = request.store_root.as_deref() {
        // Env-home mode: resolve the routed revision's bundle dir cheaply
        // (no pack-digest verification — that happens for real in
        // `env_home::load_env_home` once logging is up). Best-effort, same
        // as the `--bundle`/`--config` branch below: any failure here just
        // means default telemetry/service-name until the real boot runs.
        let Ok(bundle_dir) = crate::env_home::resolve_routed_bundle_dir(store_root, &request.env)
        else {
            return (None, "greentic".to_string());
        };
        let Ok(paths) = bundle_config::resolve_bundle_dir_paths(&bundle_dir) else {
            return (None, "greentic".to_string());
        };
        paths
    } else {
        let Ok(paths) =
            bundle_config::resolve_demo_paths(request.config.clone(), request.bundle.as_deref())
        else {
            return (None, "greentic".to_string());
        };
        paths
    };
    let bundle_yaml = demo_paths.root_dir.join("bundle.yaml");
    let telemetry = bundle_config::peek_bundle_telemetry(&bundle_yaml)
        .or_else(|| bundle_config::peek_bundle_telemetry(&demo_paths.config_path))
        .or_else(|| bundle_config::peek_sidecar_telemetry(&demo_paths.root_dir));
    let service_name = telemetry
        .as_ref()
        .and_then(|t| t.service_name.clone())
        .or_else(|| {
            demo_paths
                .root_dir
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "greentic".to_string());
    (telemetry, service_name)
}

/// Build the trace.log `EnvFilter`. Resolution order for the base directive:
/// `RUST_LOG` (when set) → the bundle's `telemetry.log_level` → `info`. The
/// base then has known-noisy crates (wasmtime, h2, hyper, rustls, etc.) forcibly
/// clamped to `warn`. EnvFilter resolves last-write-wins per target, so
/// appending the clamp after the user's directives is what makes it stick.
///
/// The resulting filter gates BOTH the `system.log` file appender and the OTLP
/// exporter, so raising `telemetry.log_level` to `debug`/`trace` is what lets
/// sub-INFO events reach Loki without exporting `RUST_LOG` on every run.
fn build_trace_filter(bundle_level: Option<&str>) -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;
    let base = if std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    } else if let Some(level) = bundle_level.map(str::trim).filter(|s| !s.is_empty()) {
        EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"))
    } else {
        EnvFilter::new("info")
    };
    NOISY_TRACE_TARGETS.iter().fold(base, |filter, target| {
        match format!("{target}=warn").parse() {
            Ok(directive) => filter.add_directive(directive),
            Err(_) => filter,
        }
    })
}

/// Install a `tracing` subscriber writing to `<log_dir>/system.log`. When
/// `telemetry` resolves to OTLP, an additional OpenTelemetry tracer + meter
/// + logger layer is composed alongside the file appender.
fn init_trace_log(
    log_dir: &std::path::Path,
    telemetry: Option<&bundle_config::BundleTelemetryConfig>,
    fallback_service_name: &str,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use std::fs::OpenOptions;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let path = log_dir.join("system.log");
    let file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!("could not open system.log at {}: {err}", path.display()),
            );
            return None;
        }
    };
    let (nb, guard) = tracing_appender::non_blocking(file);
    let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "<unset>".to_string());
    let bundle_level = telemetry.and_then(|t| t.log_level.as_deref());
    let filter = build_trace_filter(bundle_level);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(nb)
        .with_ansi(false)
        .with_target(true)
        // operator_log already wrote these records to system.log directly; it
        // also mirrors them onto OTLP_BRIDGE_TARGET so the OTLP exporter sees
        // them. Drop that target here so the file does not get a duplicate line.
        .with_filter(tracing_subscriber::filter::FilterFn::new(|meta| {
            meta.target() != crate::operator_log::OTLP_BRIDGE_TARGET
        }));

    let resolved = otlp_telemetry::resolve(telemetry, fallback_service_name);
    let otlp_layer = resolved
        .as_ref()
        .and_then(|r| match otlp_telemetry::install_layer(r) {
            Ok(layer) => Some(layer),
            Err(err) => {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "OTLP exporter init failed (endpoint={}); file logging only: {err:#}",
                        r.endpoint
                    ),
                );
                None
            }
        });
    let otlp_summary = resolved
        .as_ref()
        .map(|r| format!("{:?} endpoint={}", r.exporter, r.endpoint))
        .unwrap_or_else(|| "none".to_string());

    let init_result = match otlp_layer {
        Some(layer) => tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .with(layer)
            .try_init(),
        None => tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .try_init(),
    };
    match init_result {
        Ok(()) => {
            operator_log::info(
                module_path!(),
                format!(
                    "tracing subscriber writing to {} (RUST_LOG={rust_log} bundle_log_level={} otlp={otlp_summary})",
                    path.display(),
                    bundle_level.unwrap_or("<unset>")
                ),
            );
            tracing::info!(
                target: "greentic_start",
                rust_log = %rust_log,
                otlp = %otlp_summary,
                "tracing subscriber installed"
            );
        }
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "tracing subscriber try_init failed (another subscriber already installed?): {err}"
                ),
            );
            return None;
        }
    }
    Some(guard)
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

/// Choose the operator log directory without ever resolving to an unwritable path.
///
/// Honors an explicit `--log-dir`. Otherwise it uses `<bundle>/logs` only when the
/// bundle is an existing local directory (local dev, where users expect logs beside
/// the bundle); for a URL / `.gtbundle` file / read-only mount — i.e. cloud/operator
/// mode, possibly under a read-only root filesystem — it falls back to a writable
/// scratch dir under the system temp dir instead of an unwritable `<bundle>/logs` or
/// `<cwd>/logs`.
fn default_operator_log_dir(log_dir: Option<PathBuf>, bundle: Option<&str>) -> PathBuf {
    if let Some(dir) = log_dir {
        return dir;
    }
    if let Some(bundle) = bundle {
        let candidate = PathBuf::from(bundle);
        if candidate.is_dir() {
            return candidate.join("logs");
        }
    }
    std::env::temp_dir().join("greentic-start").join("logs")
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
    /// The watched env-home `runtime-config.json` changed (redeploy) or was
    /// deleted (traffic cleared). Slice-1a scope: this only detects the
    /// change and asks the process to exit cleanly so an external supervisor
    /// restarts it onto the new revision — no in-process hot-swap or graceful
    /// drain here.
    ConfigChanged,
}

impl ShutdownReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::CtrlC => "ctrl_c",
            Self::AdminStop => "admin_stop",
            Self::ConfigChanged => "config_changed",
        }
    }
}

/// Blocks until Ctrl+C, an admin stop request, or (in env-home mode) a change
/// to the watched `runtime-config.json` is observed.
///
/// `watched_runtime_config` is `Some(<env-home>/runtime-config.json)` when
/// this process was started via `--store-root`/`--env`; `None` in bundle mode
/// (`--bundle`/`--config`), which preserves today's behavior exactly — no
/// third condition is ever checked.
fn wait_for_shutdown(
    paths: &runtime_state::RuntimePaths,
    watched_runtime_config: Option<PathBuf>,
) -> anyhow::Result<ShutdownReason> {
    let runtime =
        tokio::runtime::Runtime::new().context("failed to spawn runtime for Ctrl+C listener")?;
    let paths = paths.clone();
    // Baseline captured once, before the loop starts, so the very first tick
    // compares against the config's state at process start rather than
    // against itself.
    let baseline = watched_runtime_config.as_deref().and_then(|p| {
        let modified = std::fs::metadata(p).ok().and_then(|m| m.modified().ok());
        if modified.is_none() {
            tracing::warn!(
                path = %p.display(),
                "failed to capture baseline mtime for runtime-config.json; config-change watch disabled for this process"
            );
        }
        modified
    });
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
                    if let (Some(watched), Some(baseline)) =
                        (watched_runtime_config.as_deref(), baseline)
                        && crate::env_home::runtime_config_changed(watched, baseline)
                    {
                        return Ok(ShutdownReason::ConfigChanged);
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
    fn detects_runtime_config_change_by_mtime() {
        use crate::env_home::runtime_config_changed;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("runtime-config.json");
        std::fs::write(&p, b"{}").unwrap();
        let baseline = std::fs::metadata(&p).unwrap().modified().unwrap();
        // no change yet
        assert!(!runtime_config_changed(&p, baseline));
        // touch with a newer mtime
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&p, b"{ }").unwrap();
        assert!(runtime_config_changed(&p, baseline));
    }

    #[test]
    fn runtime_config_changed_treats_deletion_as_a_change() {
        use crate::env_home::runtime_config_changed;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("runtime-config.json");
        std::fs::write(&p, b"{}").unwrap();
        let baseline = std::fs::metadata(&p).unwrap().modified().unwrap();
        std::fs::remove_file(&p).unwrap();
        // Slice-1a semantics: a deleted runtime-config.json (traffic cleared)
        // must also trigger a restart, same as a redeploy would. This is
        // specifically a `NotFound` stat error — the only error kind treated
        // as "changed"; any other stat error (e.g. permission denied) must
        // return `false` instead, to avoid a restart-loop on a persistent,
        // non-deletion stat failure.
        assert!(runtime_config_changed(&p, baseline));
    }

    #[test]
    fn build_trace_filter_clamps_noisy_targets_even_when_rust_log_unset() {
        let _guard = test_env_lock().lock().unwrap();
        // SAFETY: tests serialized via test_env_lock above.
        unsafe { std::env::remove_var("RUST_LOG") };
        let filter = build_trace_filter(None);
        let printed = filter.to_string();
        for target in NOISY_TRACE_TARGETS {
            assert!(
                printed.contains(&format!("{target}=warn")),
                "expected `{target}=warn` in filter, got: {printed}"
            );
        }
    }

    #[test]
    fn build_trace_filter_clamps_noisy_targets_overriding_explicit_debug() {
        let _guard = test_env_lock().lock().unwrap();
        // SAFETY: tests serialized via test_env_lock above.
        unsafe { std::env::set_var("RUST_LOG", "wasmtime=debug,info") };
        let filter = build_trace_filter(None);
        let printed = filter.to_string();
        // The clamp directive appended after the user's directive should win
        // because EnvFilter resolves last-write-wins per target.
        assert!(
            printed.contains("wasmtime=warn"),
            "wasmtime clamp must override RUST_LOG override, got: {printed}"
        );
        // SAFETY: serialized.
        unsafe { std::env::remove_var("RUST_LOG") };
    }

    #[test]
    fn build_trace_filter_uses_bundle_level_when_rust_log_unset() {
        let _guard = test_env_lock().lock().unwrap();
        // SAFETY: tests serialized via test_env_lock above.
        unsafe { std::env::remove_var("RUST_LOG") };
        let filter = build_trace_filter(Some("trace"));
        let printed = filter.to_string();
        // The bundle directive seeds the base level...
        assert!(
            printed.contains("trace"),
            "expected bundle `trace` level in filter, got: {printed}"
        );
        // ...while the noisy clamps still apply on top of it.
        assert!(
            printed.contains("wasmtime=warn"),
            "noisy clamp must still apply over bundle level, got: {printed}"
        );
    }

    #[test]
    fn build_trace_filter_prefers_rust_log_over_bundle_level() {
        let _guard = test_env_lock().lock().unwrap();
        // SAFETY: tests serialized via test_env_lock above.
        unsafe { std::env::set_var("RUST_LOG", "warn") };
        let filter = build_trace_filter(Some("trace"));
        let printed = filter.to_string();
        // RUST_LOG wins: the bundle's `trace` must not leak into the base.
        assert!(
            !printed.contains("trace"),
            "RUST_LOG must override bundle level, got: {printed}"
        );
        // SAFETY: serialized.
        unsafe { std::env::remove_var("RUST_LOG") };
    }

    #[test]
    fn apply_nats_overrides_disables_nats_for_flag() {
        let mut config = config::DemoConfig::default();
        let args = StartRequest {
            bundle: None,
            store_root: None,
            env: "local".to_string(),
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
            store_root: None,
            env: "local".to_string(),
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

    #[test]
    fn default_operator_log_dir_honors_explicit_override() {
        let explicit = PathBuf::from("/var/run/greentic/logs");
        assert_eq!(
            default_operator_log_dir(Some(explicit.clone()), Some("/some/bundle")),
            explicit
        );
    }

    #[test]
    fn default_operator_log_dir_uses_bundle_logs_for_local_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        assert_eq!(
            default_operator_log_dir(None, Some(bundle.to_string_lossy().as_ref())),
            bundle.join("logs")
        );
    }

    #[test]
    fn default_operator_log_dir_falls_back_to_temp_for_non_local_bundle() {
        // A URL or a read-only mount is not an existing directory, so the default
        // must land in a writable temp scratch dir, never an unwritable path.
        let expected = std::env::temp_dir().join("greentic-start").join("logs");
        assert_eq!(
            default_operator_log_dir(None, Some("https://example.com/bundle.gtbundle?x=1")),
            expected
        );
        assert_eq!(default_operator_log_dir(None, None), expected);
    }

    fn make_start_request(bundle: &Path) -> StartRequest {
        StartRequest {
            bundle: Some(bundle.display().to_string()),
            store_root: None,
            env: "local".to_string(),
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

    /// RAII guard that pins `GREENTIC_GATEWAY_PORT` for the lifetime of a
    /// test and always clears it on drop, including when the test body
    /// panics — a plain set_var/remove_var pair would leak the var into
    /// later tests in this binary if an `.expect()`/`assert!` in between
    /// panicked before the manual `remove_var` ran.
    struct GatewayPortGuard;

    impl GatewayPortGuard {
        fn set(port: &str) -> Self {
            // SAFETY: tests in this binary that mutate this variable are
            // serialized by test_env_lock(); the guard clears it on every
            // exit path, including panics.
            unsafe { std::env::set_var("GREENTIC_GATEWAY_PORT", port) };
            Self
        }
    }

    impl Drop for GatewayPortGuard {
        fn drop(&mut self) {
            unsafe { std::env::remove_var("GREENTIC_GATEWAY_PORT") };
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
        // Pin an explicit port: since the ingress listener now always binds,
        // the default 8080 would race with the other boot tests (and with
        // whatever else owns 8080 on a dev machine). Strict bind (range 0)
        // turns such a collision into a hard failure, so the port must be
        // deterministic and unique per test.
        let _gateway_port = GatewayPortGuard::set("19903");
        let temp = tempfile::tempdir().expect("tempdir");
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
        let _gateway_port = GatewayPortGuard::set("19904");
        let temp = tempfile::tempdir().expect("tempdir");
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
}
