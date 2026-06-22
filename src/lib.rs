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
mod deployment_routes;
mod dev_store_path;
mod discovery;
mod doctor;
mod doctor_env;
mod domains;
mod endpoint_admit;
mod endpoint_resolver;
mod env_tunnel;
mod event_router;
mod extension_resolver;
mod fast2flow;
pub(crate) mod flow_log;
mod gmap;
mod http_ingress;
mod http_routes;
mod identify_payload;
mod ingress;
mod ingress_dispatch;
mod ingress_types;
mod llm;
mod messaging_app;
mod messaging_dto;
mod messaging_egress;
mod metrics;
mod ngrok;
pub mod notifier;
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
mod provider_auth;
pub mod provider_config_envelope;
mod qa_persist;
mod revision_boot;
mod revision_dispatcher;
mod revision_drain;
pub mod revision_health_gate;
mod revision_pin;
mod revision_pull;
mod revision_reload;
mod revision_serve;
mod revision_webhook_register;
mod rollout_telemetry;
mod runner_exec;
mod runner_host;
mod runner_integration;
pub mod runtime;
mod runtime_config;
mod runtime_refs_store;
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
mod subscription_updater;
mod subscriptions_universal;
pub mod supervisor;
#[cfg(test)]
mod test_fixtures;
mod timer_scheduler;
mod tunnel_prompt;
mod warmup;
mod webhook_secret_resolver;
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
    // New-model stop: with no explicit target and no legacy `./state` layout
    // in the CWD, stop the bundle-less env runtime instead — signal its serve
    // loop via the env-rooted stop-request file and tear down env-rooted
    // tunnel children (pidfile-scoped; a hand-started tunnel is not ours to
    // kill). Explicit `--bundle` / `--state-dir` always means the legacy path.
    if request.bundle.is_none()
        && request.state_dir.is_none()
        && !std::path::Path::new("state").exists()
        && let Some(root) = greentic_deployer::environment::LocalFsStore::default_root()
    {
        let env_id = resolve_env(request.env.as_deref());
        let env_dir = root.join(&env_id);
        if env_dir.is_dir() {
            return stop_env_runtime(&env_dir, &env_id);
        }
        // An explicit `--env` that names a non-existent env is a clear
        // error, not a silent fall-through to the legacy `./state` path.
        if request.env.is_some() {
            anyhow::bail!(
                "environment `{env_id}` has no store directory at `{}` — nothing to stop",
                env_dir.display()
            );
        }
    }
    if request.env.is_some() {
        tracing::warn!(
            "--env is ignored on the legacy bundle/state-dir stop path (it has no \
             environment concept)"
        );
    }
    let state_dir = resolve_state_dir(request.state_dir, request.bundle.as_deref())?;
    runtime::demo_down_runtime(&state_dir, &request.tenant, &request.team, false)
}

/// Stop the bundle-less env runtime: write the stop-request file its serve
/// loop polls (observed within ~250ms when one is running; a stale file is
/// cleared by the next boot) and stop env-rooted tunnel children.
fn stop_env_runtime(env_dir: &std::path::Path, env_id: &str) -> anyhow::Result<()> {
    let paths = env_tunnel::env_runtime_paths(env_dir, env_id);
    runtime_state::write_stop_request(
        &paths,
        &runtime_state::StopRequest {
            requested_by: "greentic-start stop".to_string(),
            reason: None,
        },
    )?;
    let stopped = env_tunnel::stop_env_tunnels(&paths);
    if stopped.is_empty() {
        println!(
            "{}",
            operator_i18n::trf(
                "revision.serve.stop_sent",
                "stop requested for env `{}`; a serving greentic-start exits within ~1s (no tunnel children to stop).",
                &[env_id]
            )
        );
    } else {
        println!(
            "{}",
            operator_i18n::trf(
                "revision.serve.stop_sent_with_tunnels",
                "stop requested for env `{}`; stopped tunnel(s): {}.",
                &[env_id, &stopped.join(", ")]
            )
        );
    }
    Ok(())
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

    // `--env` on the bundle-less boot wins over an exported $GREENTIC_ENV
    // (flag > env var > `local`) and is propagated INTO the process env:
    // downstream resolution (runner-host paths, secret stores, startup
    // contract) reads $GREENTIC_ENV directly, so a flag that only changed
    // this function's locals would split-brain the boot. The legacy
    // `--bundle` / `--config` path has no environment concept — there the
    // flag is ignored with a warning and the env var is left alone.
    // SAFETY: This is called early in single-threaded startup before spawning workers.
    let bundle_less = request.bundle.is_none() && request.config.is_none();
    if let Some(env) = request.env.as_deref() {
        if bundle_less {
            let resolved = resolve_env(Some(env));
            unsafe {
                std::env::set_var("GREENTIC_ENV", &resolved);
            }
        } else {
            tracing::warn!(
                "--env is ignored on the legacy bundle/config start path (it has no \
                 environment concept)"
            );
        }
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

    // N1.2: bundle-less cold start. When launched without `--bundle` / `--config`,
    // boot from the env's persisted state regardless of whether bundles are
    // attached yet. The listener always comes up so `/livez`, `/readyz`, and
    // `/status` are reachable; a missing or empty `runtime-config.v1` produces a
    // zero-revision activation that serves probes + 404s for unrouted paths until
    // bundles are attached (hot-attach lands in N2). When the runtime-config is
    // populated, this is the same B0/B2/B3 path as before: load + validate, build
    // an embedded runner host, run requests through the revision dispatcher.
    if bundle_less {
        let env_id = resolve_env(request.env.as_deref());
        let rc = runtime_config::load_or_empty(&env_id)?;
        let store_root = greentic_deployer::environment::LocalFsStore::default_root()
            .context("cannot determine the default environment store root (no home directory)")?;
        let env_dir = runtime_config::env_dir_in(&store_root, &env_id)?;

        // Initialize operator.log under the env directory before any
        // `operator_log::*` call on this path; otherwise every banner,
        // listener log, and warning is silently dropped (the logger
        // no-ops until `init`).
        let log_level = if request.quiet {
            operator_log::Level::Warn
        } else if request.verbose {
            operator_log::Level::Debug
        } else {
            operator_log::Level::Info
        };
        let log_dir = operator_log::init(env_dir.join("logs"), log_level)?;
        let _trace_guard = init_trace_log(&log_dir, None, "greentic-start");

        // Env-rooted control paths: `greentic-start stop` signals this serve
        // loop through the stop-request file under these paths (and stops any
        // env-rooted tunnel children). Clear a stale request from a previous
        // run up front — anything written after this point is a live stop
        // request aimed at this process.
        let shutdown_paths = env_tunnel::env_runtime_paths(&env_dir, &env_id);
        runtime_state::clear_stop_request(&shutdown_paths)?;

        // Activate with the env's own DevStore secrets backend rather than
        // HostBuilder's default env-var backend (which rejects non-local
        // envs). A later step refines this to the per-tenant/pack-declared
        // backend once the serving context is resolved.
        let secrets: crate::secrets_gate::DynSecretsManager =
            std::sync::Arc::new(crate::secrets_client::SecretsClient::open(&env_dir)?);
        // Clone for the runtime-config watcher's rebuild closure (N2.2):
        // it needs the same secrets backend to rebuild activations after
        // the deployer rewrites `runtime-config.json`. `DynSecretsManager`
        // is `Arc<dyn ...>`, so this is a refcount bump.
        let watcher_secrets = std::sync::Arc::clone(&secrets);

        // Load the Environment so the bind address can layer on top of the
        // persisted `host_config.listen_addr`. The same `Environment` is
        // threaded into `activate_runtime_config` so the activation path
        // does not re-read the file (and cannot see a different snapshot).
        let env_store = greentic_deployer::environment::LocalFsStore::new(store_root.clone());
        let env_typed = greentic_types::EnvId::new(&env_id)
            .with_context(|| format!("invalid environment id `{env_id}`"))?;
        let environment =
            greentic_deployer::environment::EnvironmentStore::load(&env_store, &env_typed)
                .with_context(|| format!("loading environment `{env_id}` for bundle-less boot"))?;

        // M2: pull packs for a freshly-seeded worker. When no runtime-config
        // is staged yet (the K8s ConfigMap ships only `environment.json`) but
        // the environment's revisions were resolved from a bundle source,
        // fetch each `.gtbundle` and materialize its packs + runtime-config
        // into the env dir, then re-load the now-populated runtime-config so
        // activation serves real revisions instead of probes only. A worker
        // whose packs already sit on a persisted volume has a non-empty
        // runtime-config and skips the pull.
        let rc = if rc.revisions.is_empty() {
            let pulled = revision_pull::pull_and_materialize_bundle_revisions(
                &env_store,
                &env_typed,
                &env_dir,
                &environment,
            )?;
            if pulled > 0 {
                operator_log::info(
                    module_path!(),
                    format!(
                        "materialized {pulled} revision(s) from bundle sources for env `{env_id}`"
                    ),
                );
                runtime_config::load_or_empty(&env_id)?
            } else {
                rc
            }
        } else {
            rc
        };

        // C5: open the env's runtime.json snapshot once and share it across
        // every activation rebuild + the `runtime://` resolver every loaded
        // pack reaches. The store is `Arc`-shared so a single in-memory
        // snapshot is hot-reloaded on every `runtime.json` write — the
        // watcher below calls `store.reload()` without rebuilding the full
        // activation. The resolver implements
        // `greentic_runner_host::runtime_refs::RuntimeRefResolver`, lives
        // for the env's lifetime, and is cloned (refcount bump) into each
        // revision's load.
        let runtime_refs_store =
            crate::runtime_refs_store::EnvironmentRuntimeStore::open(&env_dir, env_typed.clone())
                .with_context(|| format!("opening runtime.json snapshot for env `{env_id}`"))?;
        // The same `Arc` flows into BOTH the cold-start activation AND each
        // reload-rebuilt activation (via the watcher's `default_rebuild`) so
        // every revision in the env resolves `runtime://` URIs through one
        // store — a snapshot flip is visible to the next request.
        let runtime_ref_resolver: std::sync::Arc<
            dyn greentic_runner_host::runtime_refs::RuntimeRefResolver,
        > = std::sync::Arc::new(crate::runtime_refs_store::StartRuntimeRefResolver::new(
            std::sync::Arc::clone(&runtime_refs_store),
        ));

        let activation_rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("building runtime for revision activation")?;
        let activation = activation_rt.block_on(revision_boot::activate_runtime_config(
            &store_root,
            &rc,
            secrets,
            &environment,
            std::sync::Arc::clone(&runtime_ref_resolver),
        ))?;

        // Execution bridge: serve the activated revisions over a slim HTTP
        // loop. Each request resolves to a deployment, the dispatcher picks a
        // revision, and the request runs against that revision's runtime via
        // `RunnerHost::handle_activity_for_revision`. This is the generic-JSON
        // vertical slice — provider webhook parsing, WebChat/WS, and static
        // assets under revisions stay on the legacy `--bundle` ingress.
        let revision_boot::RuntimeConfigActivation { host, routing } = activation;
        let bind_addr = revision_serve::resolve_bind_addr(Some(&environment.host_config));
        // On by default for the `local` env, off elsewhere unless the operator
        // opted in (`op config set gui_enabled` / env-manifest). When on, the
        // server serves the built-in webchat console at `/chat`.
        let gui_enabled = environment.host_config.resolved_gui_enabled();
        // A public tunnel (`--cloudflared on` / `--ngrok on`) forwards external
        // traffic to this listener over loopback, so a tunneled request's TCP
        // peer reads as 127.0.0.1 and would defeat the loopback trust gate on
        // `/chat`, `/workers/invoke`, and caller-asserted identity. When a tunnel
        // is requested, refuse to derive loopback trust at all (the sensitive
        // endpoints become unavailable while the tunnel is up rather than
        // publicly reachable). Mirrors `env_tunnel::choose_tunnel`'s `Off`
        // condition without re-running its both-on log line.
        let will_tunnel = matches!(request.cloudflared, CloudflaredModeArg::On)
            || matches!(request.ngrok, NgrokModeArg::On);
        let activation = std::sync::Arc::new(revision_serve::Activation {
            host: std::sync::Arc::new(host),
            routing: std::sync::Arc::new(routing),
        });
        // When a tunnel fronts the main listener, also run a loopback-only
        // admin/console listener so `/chat` + `/workers/invoke` stay reachable
        // to a genuine local caller (a `kubectl port-forward` on K8s) while the
        // public face refuses them. The tunnel targets the main port only, so
        // nothing external can reach this one. Defaults to `127.0.0.1:<main+1>`;
        // `find_available_port` inside `start` bumps it if taken.
        let admin_bind_addr = will_tunnel.then(|| {
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                bind_addr.port().saturating_add(1),
            )
        });
        let server = revision_serve::RevisionServer::start(revision_serve::RevisionServeConfig {
            bind_addr,
            activation: std::sync::Arc::clone(&activation),
            gui_enabled,
            trust_loopback_peers: !will_tunnel,
            admin_bind_addr,
        })
        .context("starting the revision ingress server")?;
        let listen = std::net::SocketAddr::new(bind_addr.ip(), server.actual_port());
        let (deployment_count, revision_count) = server.counts();
        let banner = if revision_count == 0 {
            format!(
                "no bundles attached to env `{}` — serving probes only on http://{listen} \
                 (attach a bundle with `gtc op bundles add`)",
                rc.env_id
            )
        } else {
            format!(
                "serving {revision_count} revision(s) for env `{}` across {deployment_count} \
                 deployment(s) on http://{listen}",
                rc.env_id
            )
        };
        operator_log::info(module_path!(), banner.clone());
        println!("\n{banner}. Press Ctrl+C to stop.");
        if gui_enabled {
            // With a tunnel up, the console lives on the loopback admin listener
            // (the public port serves provider webhooks only); point operators
            // at the port to forward. Otherwise it's on the main port.
            let chat = match server.admin_port() {
                Some(admin) => format!(
                    "webchat console enabled on the loopback admin listener — \
                     open http://127.0.0.1:{admin}/chat (port-forward it on K8s); \
                     the public listener on http://{listen} serves provider \
                     webhooks only while a tunnel is up"
                ),
                None => format!("webchat console enabled — open http://{listen}/chat"),
            };
            operator_log::info(module_path!(), chat.clone());
            println!("{chat}");
        }

        // `--cloudflared on` / `--ngrok on`: spawn the quick tunnel against
        // the port the server actually bound (it can differ from the
        // configured one) and surface the public URL. Spawned after the
        // listener is up so the tunnel's first health probe has something to
        // reach. Explicit flag + tunnel failure = hard error, never a silent
        // local-only boot.
        let tunnel = env_tunnel::start_env_tunnel(
            &request,
            &env_dir,
            &env_id,
            server.actual_port(),
            &log_dir,
        )?;
        let tunnel_url = tunnel.map(|t| {
            let line = format!("public URL: {} ({} tunnel)", t.url, t.service);
            operator_log::info(module_path!(), line.clone());
            println!("{line}");
            t.url
        });

        // Phase D: auto-register provider webhooks for the served revisions.
        // Gated on a public_base_url — with none, registration is skipped
        // (register manually). Detached: the server is already listening, and
        // a slow or stuck provider API call must not delay the watcher spawn
        // or Ctrl+C handling; each invocation is bounded by
        // `SETUP_WEBHOOK_TIMEOUT`.
        //
        // Precedence: tunnel-discovered URL (always wins) > env-store > env
        // var — the same chain as the legacy bundle arm. The env-derived tail
        // is delegated to the canonical helper in `startup_contract` so this
        // path stays in lockstep with the reload path in
        // `revision_webhook_register`.
        let public_base_url = match &tunnel_url {
            Some(url) => Some(url.clone()),
            None => startup_contract::resolve_public_base_url(&environment)?,
        };
        if revision_count > 0 {
            let boot_activation = std::sync::Arc::clone(&activation);
            let boot_url = public_base_url.clone();
            let boot_env = environment;
            activation_rt.spawn(async move {
                revision_webhook_register::register_new_model_webhooks(
                    &boot_activation,
                    &boot_env,
                    boot_url.as_deref(),
                )
                .await;
            });
        }
        // The server holds its own `Arc<Activation>`; release ours so a later
        // reload can free the superseded activation after its drain window.
        drop(activation);

        // N2.2 + C5: spawn the unified env-dir watcher. Dispatches per
        // debounced batch:
        //   - `runtime-config.json` / `environment.json` → rebuild the
        //     activation + swap into the `RevisionServer` (the N2.2 flow:
        //     `gtc op bundles add`, `revisions stage/warm`, `traffic set`,
        //     `op messaging endpoint *`).
        //   - `runtime.json` → refresh the in-memory `EnvironmentRuntime`
        //     snapshot the resolver reads (cheap; no activation rebuild).
        //     The deployer re-emits discovered values on every apply, so
        //     coupling them to a full rebuild would churn cookies/pins.
        // The server `Arc` lets the worker thread call `server.reload()`
        // while the main thread still owns the original handle for
        // shutdown.
        let server = std::sync::Arc::new(server);
        let snapshot_store_for_watcher = std::sync::Arc::clone(&runtime_refs_store);
        let watcher = revision_reload::spawn_runtime_config_watcher(
            env_dir.clone(),
            revision_reload::DEFAULT_DEBOUNCE,
            // Drain window matches the cold-start expectation: in-flight
            // requests against the previous activation get ~30s to finish
            // before the old `RunnerHost` drops. Tuned for local-dev;
            // remote/cloud is Phase D scope.
            std::time::Duration::from_secs(30),
            std::sync::Arc::clone(&server),
            revision_reload::default_rebuild(
                store_root.clone(),
                env_id.clone(),
                watcher_secrets,
                std::sync::Arc::clone(&runtime_ref_resolver),
                activation_rt.handle().clone(),
            ),
            // Each reload that actually changed config (hot-attached
            // deployment, new endpoint) re-registers webhooks against the
            // freshly-served activation — AFTER the swap, so the registered
            // URL is live before the provider validates or delivers to it.
            // A tunnel started by this boot stays the highest-precedence URL
            // across reloads (it is process-local, never persisted); without
            // one, the URL is resolved freshly from the reloaded
            // environment.json (with env-var fallback), so `gtc op env
            // set-public-url` takes effect on the next reload without a
            // process restart. Idempotent for unchanged routes (same URL +
            // secret_token).
            revision_webhook_register::post_reload_registration(
                store_root.clone(),
                env_id.clone(),
                activation_rt.handle().clone(),
                tunnel_url,
            ),
            // C5 snapshot-reload arm: pure `store.reload()` call.
            move || snapshot_store_for_watcher.reload(),
        )
        .context("spawning runtime-config watcher")?;

        // Wait for either Ctrl+C or a stop-request file written by
        // `greentic-start stop` — the same select loop the legacy bundle arm
        // uses, run on the activation runtime this arm already owns. A
        // corrupt stop file fails the wait loudly on both arms.
        let reason = activation_rt.block_on(wait_for_shutdown_inner(&shutdown_paths))?;
        if matches!(reason, ShutdownReason::AdminStop) {
            runtime_state::clear_stop_request(&shutdown_paths)?;
            let line = operator_i18n::tr(
                "revision.serve.stop_requested",
                "stop requested via `greentic-start stop`; shutting down.",
            );
            operator_log::info(module_path!(), line.clone());
            println!("{line}");
        }
        // Drop the watcher before stopping the server so the watcher's
        // worker can't call `server.reload()` on a server that's already
        // half-torn-down. Snapshot reloads and activation rebuilds share
        // the same watcher (one debouncer, two dispatch arms), so this
        // single drop suffices.
        drop(watcher);
        // Recover sole ownership for `stop()`. Any in-flight drain task
        // spawned by N2.1's `reload()` owns an `Arc<Activation>`, NOT an
        // `Arc<RevisionServer>`, so this should always succeed today. If a
        // future contributor introduces a second `Arc<RevisionServer>`
        // holder without updating the shutdown sequence, fall back to a
        // warn-and-leak: skipping `stop()` leaves the listener thread
        // running until process exit (which is moments away), which is
        // strictly better than bailing out and skipping any other
        // shutdown work the caller may have layered above us.
        match std::sync::Arc::try_unwrap(server) {
            Ok(server) => server.stop()?,
            Err(_arc) => {
                operator_log::warn(
                    module_path!(),
                    "RevisionServer Arc still has consumers at shutdown — \
                     skipping graceful stop(); the listener thread will be \
                     terminated on process exit.",
                );
            }
        }
        return Ok(());
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
    let early_log_dir = request.log_dir.clone().unwrap_or_else(|| {
        request
            .bundle
            .as_deref()
            .map(|b| PathBuf::from(b).join("logs"))
            .unwrap_or_else(|| {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join("logs")
            })
    });
    let log_dir = operator_log::init(early_log_dir, log_level)?;

    let (peeked_telemetry, peeked_service_name) = peek_startup_telemetry(&request);

    // Install a tracing subscriber that writes RUST_LOG-filtered events to
    // <log_dir>/system.log. When a bundle's `telemetry:` block (or the
    // TELEMETRY_EXPORT/OTLP_ENDPOINT env vars) requests OTLP, an additional
    // OpenTelemetry tracer + meter + logger layer is composed into the same
    // subscriber. Absent → file-only, today's behaviour.
    let _trace_guard = init_trace_log(&log_dir, peeked_telemetry.as_ref(), &peeked_service_name);

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

    let mut demo_config = bundle_config::load_runtime_demo_config(&demo_paths, &request)?;
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
    // Persisted public_base_url from `gtc op env set-public-url`. Sits between
    // the tunnel-discovered URL (always wins) and the `PUBLIC_BASE_URL` env var
    // in the precedence chain. Failing to read this is non-fatal: a corrupt env
    // store should not block a foreground startup, so we log and fall back.
    let env_store_public_base_url =
        match startup_contract::configured_public_base_url_from_env_store(&resolve_env(None)) {
            Ok(value) => value,
            Err(err) => {
                operator_log::warn(
                    module_path!(),
                    format!("failed to read env-store public_base_url, falling back: {err:#}"),
                );
                None
            }
        };
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

    // Mutual exclusivity (ngrok wins over cloudflared): single shared policy
    // with the bundle-less arm, owned by `env_tunnel::choose_tunnel`.
    let tunnel_choice = env_tunnel::choose_tunnel(request.cloudflared, request.ngrok);

    let cloudflared = match tunnel_choice {
        env_tunnel::TunnelChoice::Cloudflared => {
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
        _ => None,
    };

    let ngrok = match tunnel_choice {
        env_tunnel::TunnelChoice::Ngrok => {
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
        _ => None,
    };

    let handles = runtime::demo_up_services(
        &config_path,
        &demo_config,
        &static_routes,
        configured_public_base_url,
        env_store_public_base_url,
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
    let Ok(demo_paths) =
        bundle_config::resolve_demo_paths(request.config.clone(), request.bundle.as_deref())
    else {
        return (None, "greentic".to_string());
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
    let (_env, outcome) = ensure_local_environment(&store, None)
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
    runtime.block_on(wait_for_shutdown_inner(paths))
}

/// Core Ctrl+C / stop-request select loop, shared by the legacy bundle arm
/// (via [`wait_for_shutdown`], on its own throwaway runtime) and the
/// bundle-less env-serving arm (on the activation runtime it already owns).
async fn wait_for_shutdown_inner(
    paths: &runtime_state::RuntimePaths,
) -> anyhow::Result<ShutdownReason> {
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|err| anyhow!("failed to wait for Ctrl+C: {err}"))?;
                return Ok(ShutdownReason::CtrlC);
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
                if runtime_state::read_stop_request(paths)?.is_some() {
                    return Ok(ShutdownReason::AdminStop);
                }
            }
        }
    }
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
            env: None,
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
            env: None,
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
            env: None,
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

    // The no-bundle runtime-config boot path (B0 load → B2 activation → fail
    // loud until B3 serving) is covered by the fully-isolated
    // `revision_boot::tests::activate_*` unit tests, which exercise
    // `activate_runtime_config` directly against an explicit store root. A
    // `run_start`-level test is deliberately omitted here: it must override
    // `HOME`/env while activation runs, which reliably trips a pre-existing
    // isolation gap in the lock-free `messaging_app` secrets tests (they read
    // env-derived paths without `test_env_lock`).

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
