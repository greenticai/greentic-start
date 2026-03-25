#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use std::collections::{BTreeMap, BTreeSet};

use crate::domains::Domain;
use crate::http_ingress::{HttpIngressConfig, HttpIngressServer};
use crate::operator_log;
use crate::runner_host::DemoRunnerHost;
use crate::runtime_state::{
    RuntimePaths, persist_service_manifest, read_service_manifest, remove_service_manifest,
    write_json,
};
use crate::secrets_gate;
use crate::services;
use crate::startup_contract::{
    BundleStaticRoutesInspection, RuntimeConfig, RuntimePublicBaseUrl, RuntimePublicBaseUrlSource,
    StartupContract, StartupContractInput,
};
use crate::supervisor;
use anyhow::Context;

use crate::cloudflared::{self, CloudflaredConfig};
use crate::config::{DemoConfig, DemoSubscriptionsMode};
use crate::ngrok::{self, NgrokConfig};

use crate::subscriptions_universal::{
    build_runner, ensure_desired_subscriptions, scheduler::Scheduler, service::SubscriptionService,
    state_root, store::SubscriptionStore,
};

#[derive(Default)]
pub struct ForegroundRuntimeHandles {
    pub ingress_server: Option<HttpIngressServer>,
}

impl ForegroundRuntimeHandles {
    pub fn stop(mut self) -> anyhow::Result<()> {
        if let Some(server) = self.ingress_server.take() {
            server.stop()?;
        }
        Ok(())
    }
}

struct ServiceSummary {
    id: String,
    pid: Option<u32>,
    details: Vec<String>,
}

impl ServiceSummary {
    fn new(id: impl Into<String>, pid: Option<u32>) -> Self {
        Self {
            id: id.into(),
            pid,
            details: Vec::new(),
        }
    }

    fn with_details(id: impl Into<String>, pid: Option<u32>, details: Vec<String>) -> Self {
        Self {
            id: id.into(),
            pid,
            details,
        }
    }

    fn add_detail(&mut self, detail: impl Into<String>) {
        self.details.push(detail.into());
    }

    fn describe(&self) -> String {
        let pid_str = self
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".to_string());
        if self.details.is_empty() {
            format!("{} (pid={})", self.id, pid_str)
        } else {
            format!(
                "{} (pid={}) [{}]",
                self.id,
                pid_str,
                self.details.join(" | ")
            )
        }
    }
}

struct ServiceTracker<'a> {
    paths: &'a RuntimePaths,
    manifest: crate::runtime_state::ServiceManifest,
}

impl<'a> ServiceTracker<'a> {
    fn new(paths: &'a RuntimePaths, log_dir: Option<&Path>) -> anyhow::Result<Self> {
        remove_service_manifest(paths)?;
        let mut manifest = crate::runtime_state::ServiceManifest::default();
        if let Some(dir) = log_dir {
            manifest.log_dir = Some(dir.display().to_string());
        }
        persist_service_manifest(paths, &manifest)?;
        Ok(Self { paths, manifest })
    }

    fn record(&mut self, entry: crate::runtime_state::ServiceEntry) -> anyhow::Result<()> {
        self.manifest.services.push(entry);
        persist_service_manifest(self.paths, &self.manifest)
    }

    fn record_with_log(
        &mut self,
        id: impl Into<String>,
        kind: impl Into<String>,
        log_path: Option<&Path>,
    ) -> anyhow::Result<()> {
        let entry = crate::runtime_state::ServiceEntry::new(id, kind, log_path);
        self.record(entry)
    }
}

fn log_service_spec_debug(
    service_id: &str,
    kind: &str,
    spec: &supervisor::ServiceSpec,
    tenant: &str,
    team: &str,
    debug_enabled: bool,
) {
    if !debug_enabled {
        return;
    }
    let cwd = spec
        .cwd
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<unset>".to_string());
    let argv = spec.argv.join(" ");
    let env_pairs = spec
        .env
        .iter()
        .map(|(key, value)| format!("{}={}", key, value))
        .collect::<Vec<_>>()
        .join(" ");
    let env_display = if env_pairs.is_empty() {
        "<empty>".to_string()
    } else {
        env_pairs
    };
    operator_log::debug(
        module_path!(),
        format!(
            "[demo dev] service {} kind={} tenant={} team={} cwd={} argv=\"{}\" env={}",
            service_id, kind, tenant, team, cwd, argv, env_display
        ),
    );
}

#[allow(clippy::too_many_arguments)]
fn spawn_supervised_service(
    service_id: &str,
    kind: &str,
    spec: &supervisor::ServiceSpec,
    log_dir: &Path,
    paths: &RuntimePaths,
    restart: &BTreeSet<String>,
    tracker: &mut ServiceTracker,
    tenant: &str,
    team: &str,
    debug_enabled: bool,
) -> anyhow::Result<ServiceSummary> {
    let log_path = operator_log::reserve_service_log(log_dir, service_id)?;
    log_service_spec_debug(service_id, kind, spec, tenant, team, debug_enabled);
    let handle = spawn_if_needed(paths, spec, restart, Some(log_path.clone()))?;
    let pid = if let Some(handle) = &handle {
        Some(handle.pid)
    } else {
        read_pid(&paths.pid_path(service_id))?
    };
    let actual_log = handle
        .as_ref()
        .map(|handle| handle.log_path.clone())
        .unwrap_or(log_path.clone());
    tracker.record_with_log(service_id, kind, Some(&actual_log))?;
    operator_log::info(
        module_path!(),
        format!(
            "service {} ready pid={:?} log={}",
            service_id,
            pid,
            actual_log.display()
        ),
    );
    let mut summary = ServiceSummary::new(service_id, pid);
    summary.add_detail(format!("log={}", actual_log.display()));
    Ok(summary)
}

fn print_service_summary(summaries: &[ServiceSummary]) {
    if summaries.is_empty() {
        return;
    }
    println!(
        "\n{}",
        crate::operator_i18n::tr("demo.runtime.started_services", "Started services:")
    );
    for summary in summaries {
        println!("{}", summary.describe());
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_embedded_messaging(
    bundle_root: &Path,
    tenant: &str,
    team: &str,
    env: BTreeMap<String, String>,
    log_dir: &Path,
    restart: &BTreeSet<String>,
    tracker: &mut ServiceTracker,
    debug_enabled: bool,
) -> anyhow::Result<ServiceSummary> {
    let exe = std::env::current_exe()?;
    let mut args = vec![
        "dev".to_string(),
        "embedded".to_string(),
        "--project-root".to_string(),
        bundle_root.display().to_string(),
        "--no-nats".to_string(),
    ];
    let mut argv = vec![exe.to_string_lossy().to_string()];
    argv.append(&mut args);

    let spec = supervisor::ServiceSpec {
        id: supervisor::ServiceId::new("messaging")?,
        argv,
        cwd: None,
        env,
    };

    let mut summary = spawn_supervised_service(
        "messaging",
        "messaging",
        &spec,
        log_dir,
        tracker.paths,
        restart,
        tracker,
        tenant,
        team,
        debug_enabled,
    )?;
    summary.add_detail(format!("tenant={tenant} team={team}"));
    summary.add_detail(format!(
        "cmd=dev embedded --project-root {}",
        bundle_root.display()
    ));
    Ok(summary)
}

#[allow(clippy::too_many_arguments)]
fn spawn_universal_subscriptions_service(
    bundle_root: &Path,
    config: &DemoConfig,
    tenant: &str,
    team: &str,
    runner_binary: Option<PathBuf>,
    tracker: &mut ServiceTracker,
    log_dir: &Path,
    debug_enabled: bool,
) -> anyhow::Result<ServiceSummary> {
    let team_override = if team.trim().is_empty() {
        None
    } else {
        Some(team.to_string())
    };
    let log_path = operator_log::reserve_service_log(log_dir, "subscriptions")
        .with_context(|| "unable to open subscriptions log file")?;
    tracker.record_with_log("subscriptions-universal", "subscriptions", Some(&log_path))?;

    let desired = &config.services.subscriptions.universal.desired;
    let (runner_host, context) =
        build_runner(bundle_root, tenant, team_override.clone(), runner_binary)?;
    let store = SubscriptionStore::new(state_root(bundle_root));
    let scheduler = Scheduler::new(SubscriptionService::new(runner_host, context), store);

    ensure_desired_subscriptions(
        bundle_root,
        tenant,
        team_override.clone(),
        desired,
        &scheduler,
    )?;

    let renew_interval_secs = config
        .services
        .subscriptions
        .universal
        .renew_interval_seconds
        .max(1);
    let renew_skew_secs = config
        .services
        .subscriptions
        .universal
        .renew_skew_minutes
        .max(1)
        .saturating_mul(60);
    let interval = Duration::from_secs(renew_interval_secs);
    let skew = Duration::from_secs(renew_skew_secs);

    let scheduler_handle = scheduler;
    thread::Builder::new()
        .name("subscriptions-universal".to_string())
        .spawn(move || {
            operator_log::info(
                module_path!(),
                format!(
                    "subscriptions-universal scheduler running interval={}s skew={}s",
                    renew_interval_secs, renew_skew_secs
                ),
            );
            loop {
                std::thread::sleep(interval);
                if let Err(err) = scheduler_handle.renew_due(skew) {
                    operator_log::error(
                        module_path!(),
                        format!("subscriptions-universal renew failed err={}", err),
                    );
                }
            }
        })?;

    let mut summary = ServiceSummary::new("subscriptions-universal", None);
    summary.add_detail(format!("log={}", log_path.display()));
    summary.add_detail(format!("renew_interval={}s", renew_interval_secs));
    summary.add_detail("mode=universal".to_string());
    if debug_enabled {
        operator_log::debug(
            module_path!(),
            format!(
                "[demo dev] tenant={} team={} universal subscriptions running",
                tenant, team
            ),
        );
    }
    Ok(summary)
}

fn spawn_if_needed(
    paths: &RuntimePaths,
    spec: &supervisor::ServiceSpec,
    restart: &BTreeSet<String>,
    log_path_override: Option<PathBuf>,
) -> anyhow::Result<Option<supervisor::ServiceHandle>> {
    if should_restart(restart, spec.id.as_str()) {
        let _ = supervisor::stop_service(paths, &spec.id, 2_000);
    }

    let pid_path = paths.pid_path(spec.id.as_str());
    if let Some(pid) = read_pid(&pid_path)?
        && supervisor::is_running(pid)
    {
        println!(
            "{}",
            crate::operator_i18n::trf(
                "demo.runtime.service_already_running",
                "{}: already running (pid={})",
                &[spec.id.as_str(), &pid.to_string()]
            )
        );
        return Ok(None);
    }
    let handle = supervisor::spawn_service(paths, spec.clone(), log_path_override.clone())?;
    println!(
        "{}",
        crate::operator_i18n::trf(
            "demo.runtime.service_started",
            "{}: started (pid={})",
            &[spec.id.as_str(), &handle.pid.to_string()]
        )
    );
    if spec.id.as_str() == "nats" {
        operator_log::info(
            module_path!(),
            format!(
                "spawned nats pid={} log={}",
                handle.pid,
                handle.log_path.display()
            ),
        );
    }
    Ok(Some(handle))
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

fn looks_like_path(value: &str) -> bool {
    value.contains('/') || value.contains('\\') || Path::new(value).is_absolute()
}

fn should_restart(restart: &BTreeSet<String>, service: &str) -> bool {
    restart.contains("all") || restart.contains(service)
}

#[allow(clippy::too_many_arguments)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatsMode {
    Off,
    On,
    External,
}

#[allow(clippy::too_many_arguments)]
pub fn demo_up(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
    nats_url: Option<&str>,
    nats_mode: NatsMode,
    messaging_enabled: bool,
    cloudflared: Option<CloudflaredConfig>,
    ngrok: Option<NgrokConfig>,
    log_dir: &Path,
    debug_enabled: bool,
) -> anyhow::Result<()> {
    let team_id = team.unwrap_or("default");
    let state_dir = bundle_root.join("state");
    std::fs::create_dir_all(&state_dir)?;
    let paths = RuntimePaths::new(&state_dir, tenant, team_id);
    let mut service_tracker = ServiceTracker::new(&paths, Some(log_dir))?;
    let mut service_summaries = Vec::new();
    let restart_targets = BTreeSet::new();
    let mut public_base_url: Option<String> = None;
    if debug_enabled {
        operator_log::debug(
            module_path!(),
            format!(
                "[demo dev] demo_up tenant={} team={} nats_mode={:?} messaging_enabled={}",
                tenant, team_id, nats_mode, messaging_enabled
            ),
        );
    }
    if let Some(config) = cloudflared {
        let cloudflared_log = operator_log::reserve_service_log(log_dir, "cloudflared")
            .with_context(|| "unable to open cloudflared.log")?;
        operator_log::info(
            module_path!(),
            format!(
                "starting cloudflared log={} bundle={}",
                cloudflared_log.display(),
                bundle_root.display()
            ),
        );
        let handle = cloudflared::start_quick_tunnel(&paths, &config, &cloudflared_log)?;
        operator_log::info(
            module_path!(),
            format!(
                "cloudflared ready url={} log={}",
                handle.url,
                handle.log_path.display()
            ),
        );
        if debug_enabled {
            operator_log::debug(
                module_path!(),
                format!(
                    "[demo dev] tenant={} team={} cloudflared url={} log={}",
                    tenant,
                    team_id,
                    handle.url,
                    handle.log_path.display()
                ),
            );
        }
        let url = handle.url.clone();
        let log_path = handle.log_path.clone();
        service_tracker.record_with_log("cloudflared", "cloudflared", Some(&log_path))?;
        let summary = ServiceSummary::with_details(
            "cloudflared",
            Some(handle.pid),
            vec![
                format!("url={}", url),
                format!("log={}", log_path.display()),
            ],
        );
        service_summaries.push(summary);
        public_base_url = Some(url.clone());
        println!(
            "{}",
            crate::operator_i18n::trf(
                "demo.runtime.public_url_cloudflared",
                "Public URL (service=cloudflared): {}",
                &[&url]
            )
        );
    } else if let Some(config) = ngrok {
        let ngrok_log = operator_log::reserve_service_log(log_dir, "ngrok")
            .with_context(|| "unable to open ngrok.log")?;
        operator_log::info(
            module_path!(),
            format!(
                "starting ngrok log={} bundle={}",
                ngrok_log.display(),
                bundle_root.display()
            ),
        );
        let handle = ngrok::start_tunnel(&paths, &config, &ngrok_log)?;
        operator_log::info(
            module_path!(),
            format!(
                "ngrok ready url={} log={}",
                handle.url,
                handle.log_path.display()
            ),
        );
        if debug_enabled {
            operator_log::debug(
                module_path!(),
                format!(
                    "[demo dev] tenant={} team={} ngrok url={} log={}",
                    tenant,
                    team_id,
                    handle.url,
                    handle.log_path.display()
                ),
            );
        }
        let url = handle.url.clone();
        let log_path = handle.log_path.clone();
        service_tracker.record_with_log("ngrok", "ngrok", Some(&log_path))?;
        let summary = ServiceSummary::with_details(
            "ngrok",
            Some(handle.pid),
            vec![
                format!("url={}", url),
                format!("log={}", log_path.display()),
            ],
        );
        service_summaries.push(summary);
        public_base_url = Some(url.clone());
        println!(
            "{}",
            crate::operator_i18n::trf(
                "demo.runtime.public_url_ngrok",
                "Public URL (service=ngrok): {}",
                &[&url]
            )
        );
    }

    let mut resolved_nats_url = nats_url.map(|value| value.to_string());
    if matches!(nats_mode, NatsMode::On) && resolved_nats_url.is_none() {
        match operator_log::reserve_service_log(log_dir, "nats") {
            Ok(nats_log) => {
                operator_log::info(
                    module_path!(),
                    format!("starting nats log={}", nats_log.display()),
                );
                match services::start_nats_with_log(bundle_root, Some(nats_log.clone())) {
                    Ok(state) => {
                        operator_log::info(
                            module_path!(),
                            format!("nats started state={:?} log={}", state, nats_log.display()),
                        );
                        if debug_enabled {
                            operator_log::debug(
                                module_path!(),
                                format!(
                                    "[demo dev] tenant={} team={} nats state={:?} log={}",
                                    tenant,
                                    team_id,
                                    state,
                                    nats_log.display()
                                ),
                            );
                        }
                        service_tracker
                            .record_with_log("nats", "nats", Some(&nats_log))
                            .with_context(|| "failed to record nats service state")?;
                        resolved_nats_url = Some(services::nats_url(bundle_root));
                        let pid = read_pid(&paths.pid_path("nats"))?;
                        let mut summary = ServiceSummary::new("nats", pid);
                        summary.add_detail(format!("state={:?}", state));
                        summary.add_detail(format!("url={}", services::nats_url(bundle_root)));
                        summary.add_detail(format!("log={}", nats_log.display()));
                        service_summaries.push(summary);
                        mark_nats_started(&paths)?;
                    }
                    Err(err) => {
                        eprintln!(
                            "{}",
                            crate::operator_i18n::trf(
                                "demo.runtime.warn_failed_start_nats",
                                "Warning: failed to start NATS: {}",
                                &[&err.to_string()]
                            )
                        );
                        operator_log::error(
                            module_path!(),
                            format!("failed to start nats (log={}): {err}", nats_log.display()),
                        );
                    }
                }
            }
            Err(err) => {
                eprintln!(
                    "{}",
                    crate::operator_i18n::trf(
                        "demo.runtime.warn_failed_prepare_nats_log",
                        "Warning: failed to prepare NATS log: {}",
                        &[&err.to_string()]
                    )
                );
                operator_log::error(module_path!(), format!("failed to open nats.log: {err}"));
            }
        }
    }

    let run_gsm_services = matches!(nats_mode, NatsMode::On);
    if messaging_enabled && run_gsm_services {
        let mut env_map = build_env(tenant, team_id, resolved_nats_url.as_deref(), None);
        if let Some(url) = public_base_url.as_deref() {
            env_map.insert("PUBLIC_BASE_URL".to_string(), url.to_string());
        }
        if debug_enabled {
            operator_log::debug(
                module_path!(),
                format!(
                    "[demo dev] launching GSM gateway/egress/subscriptions tenant={} team={} envs={:?}",
                    tenant, team_id, env_map
                ),
            );
        }
        let mut messaging_summary = spawn_embedded_messaging(
            bundle_root,
            tenant,
            team_id,
            env_map,
            log_dir,
            &restart_targets,
            &mut service_tracker,
            debug_enabled,
        )?;
        messaging_summary.add_detail("embedded messaging stack".to_string());
        service_summaries.push(messaging_summary);
    } else {
        println!(
            "{}",
            crate::operator_i18n::tr(
                "demo.runtime.messaging_embedded",
                "messaging: running embedded runner (no gsm gateway/egress)"
            )
        );
    }

    println!(
        "{}",
        crate::operator_i18n::tr(
            "demo.runtime.events_in_process",
            "events: handled in-process (HTTP ingress + timer scheduler)"
        )
    );
    print_service_summary(&service_summaries);

    if !run_gsm_services {
        operator_log::info(
            module_path!(),
            "demo running in embedded runner mode; gateway/egress disabled",
        );
        if debug_enabled {
            operator_log::debug(
                module_path!(),
                format!(
                    "[demo dev] embedded runner mode only tenant={} team={} (gateway/egress/subscriptions skipped)",
                    tenant, team_id
                ),
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn demo_up_services(
    config_path: &Path,
    config: &DemoConfig,
    static_routes: &BundleStaticRoutesInspection,
    configured_public_base_url: Option<String>,
    cloudflared: Option<CloudflaredConfig>,
    ngrok: Option<NgrokConfig>,
    restart: &BTreeSet<String>,
    runner_binary: Option<PathBuf>,
    log_dir: &Path,
    debug_enabled: bool,
) -> anyhow::Result<ForegroundRuntimeHandles> {
    let config_dir = config_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path has no parent directory"))?;
    let state_dir = config_dir.join("state");
    let tenant = config.tenant.as_str();
    let team = config.team.as_str();
    let paths = RuntimePaths::new(&state_dir, tenant, team);
    let mut service_tracker = ServiceTracker::new(&paths, Some(log_dir))?;
    let discovery = crate::discovery::discover(config_dir)?;
    crate::discovery::persist(config_dir, tenant, &discovery)?;
    let secrets_handle = secrets_gate::resolve_secrets_manager(config_dir, tenant, Some(team))?;
    let runner_host = Arc::new(DemoRunnerHost::new(
        config_dir.to_path_buf(),
        &discovery,
        runner_binary.clone(),
        secrets_handle.clone(),
        debug_enabled,
    )?);
    let ingress_domains = detect_http_ingress_domains(&discovery, runner_host.as_ref());
    // Enable static routes if bundle declares them - no longer requires NATS mode
    let enable_static_routes = static_routes.bundle_has_static_routes();
    let ingress_server = start_http_ingress_server(
        config,
        &ingress_domains,
        runner_host.clone(),
        enable_static_routes,
    )
    .with_context(|| "failed to start local HTTP ingress server")?;
    let run_gsm_services = config.services.nats.enabled;
    operator_log::info(
        module_path!(),
        format!(
            "demo start services start bundle={} tenant={} team={} log_dir={}",
            config_path.display(),
            tenant,
            team,
            log_dir.display()
        ),
    );
    if debug_enabled {
        operator_log::debug(
            module_path!(),
            format!(
                "[demo verbose] bundle={} tenant={} team={} logging=debug",
                config_path.display(),
                tenant,
                team
            ),
        );
    }

    if should_restart(restart, "cloudflared") {
        let _ = supervisor::stop_pidfile(&paths.pid_path("cloudflared"), 2_000);
    }
    if should_restart(restart, "ngrok") {
        let _ = supervisor::stop_pidfile(&paths.pid_path("ngrok"), 2_000);
    }

    let tunnel_public_base_url = if let Some(cfg) = cloudflared {
        if ingress_server.is_none() {
            operator_log::warn(
                module_path!(),
                "cloudflared requested but no local HTTP ingress listener is enabled; skipping tunnel startup",
            );
            None
        } else {
            let cloudflared_log = operator_log::reserve_service_log(log_dir, "cloudflared")
                .with_context(|| "unable to open cloudflared.log")?;
            operator_log::info(
                module_path!(),
                format!("starting cloudflared log={}", cloudflared_log.display()),
            );
            let handle = cloudflared::start_quick_tunnel(&paths, &cfg, &cloudflared_log)?;
            let mut domain_labels = Vec::new();
            if discovery.domains.messaging {
                domain_labels.push("messaging");
            }
            if discovery.domains.events {
                domain_labels.push("events");
            }
            if discovery.domains.oauth {
                domain_labels.push("oauth");
            }
            let domain_list = if domain_labels.is_empty() {
                "none".to_string()
            } else {
                domain_labels.join(",")
            };
            operator_log::info(
                module_path!(),
                format!(
                    "cloudflared ready domains={} url={} log={}",
                    domain_list,
                    handle.url,
                    handle.log_path.display()
                ),
            );
            if debug_enabled {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "[demo dev] tenant={} team={} cloudflared domains={} url={} log={}",
                        tenant,
                        team,
                        domain_list,
                        handle.url,
                        handle.log_path.display()
                    ),
                );
            }
            println!(
                "{}",
                crate::operator_i18n::trf(
                    "demo.runtime.public_url_cloudflared_domains",
                    "Public URL (service=cloudflared domains={}): {}",
                    &[&domain_list, &handle.url]
                )
            );
            service_tracker.record_with_log(
                "cloudflared",
                "cloudflared",
                Some(&handle.log_path),
            )?;
            Some(handle.url)
        }
    } else if let Some(cfg) = ngrok {
        if ingress_server.is_none() {
            operator_log::warn(
                module_path!(),
                "ngrok requested but no local HTTP ingress listener is enabled; skipping tunnel startup",
            );
            None
        } else {
            let ngrok_log = operator_log::reserve_service_log(log_dir, "ngrok")
                .with_context(|| "unable to open ngrok.log")?;
            operator_log::info(
                module_path!(),
                format!("starting ngrok log={}", ngrok_log.display()),
            );
            let handle = ngrok::start_tunnel(&paths, &cfg, &ngrok_log)?;
            let mut domain_labels = Vec::new();
            if discovery.domains.messaging {
                domain_labels.push("messaging");
            }
            if discovery.domains.events {
                domain_labels.push("events");
            }
            let domain_list = if domain_labels.is_empty() {
                "none".to_string()
            } else {
                domain_labels.join(",")
            };
            operator_log::info(
                module_path!(),
                format!(
                    "ngrok ready domains={} url={} log={}",
                    domain_list,
                    handle.url,
                    handle.log_path.display()
                ),
            );
            if debug_enabled {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "[demo dev] tenant={} team={} ngrok domains={} url={} log={}",
                        tenant,
                        team,
                        domain_list,
                        handle.url,
                        handle.log_path.display()
                    ),
                );
            }
            println!(
                "{}",
                crate::operator_i18n::trf(
                    "demo.runtime.public_url_ngrok_domains",
                    "Public URL (service=ngrok domains={}): {}",
                    &[&domain_list, &handle.url]
                )
            );
            service_tracker.record_with_log("ngrok", "ngrok", Some(&handle.log_path))?;
            Some(handle.url)
        }
    } else {
        None
    };

    // Read previous public URL before it gets overwritten
    let previous_public_url =
        crate::webhook_updater::read_previous_public_url(&paths.runtime_root());

    // Resolve public_base_url with fallback to local HTTP listener for local dev
    let public_base_url = tunnel_public_base_url
        .clone()
        .or(configured_public_base_url.clone())
        .or_else(|| {
            // Fallback: derive from local HTTP listener if static routes are enabled
            if ingress_server.is_some() && enable_static_routes {
                let host = &config.services.gateway.listen_addr;
                let port = config.services.gateway.port;
                Some(format!("http://{}:{}", host, port))
            } else {
                None
            }
        });

    // Auto-update webhooks if public URL changed
    if let Some(ref new_url) = public_base_url
        && let Err(err) = crate::webhook_updater::update_webhooks_if_url_changed(
            config_dir,
            &discovery,
            &secrets_handle,
            tenant,
            team,
            previous_public_url.as_deref(),
            new_url,
        )
    {
        operator_log::warn(
            module_path!(),
            format!("[webhook-updater] failed to update webhooks: {}", err),
        );
    }

    // http_listener_enabled: true if HTTP ingress server started (not tied to NATS)
    // asset_serving_enabled: true if bundle declares static routes we're enabling
    let http_listener_enabled = ingress_server.is_some();
    let asset_serving_enabled = enable_static_routes;
    let runtime_config = if let Some(url) = tunnel_public_base_url {
        Some(RuntimeConfig {
            public_base_url: Some(RuntimePublicBaseUrl {
                value: url,
                source: RuntimePublicBaseUrlSource::Tunnel,
            }),
        })
    } else if let Some(url) = configured_public_base_url {
        Some(RuntimeConfig {
            public_base_url: Some(RuntimePublicBaseUrl {
                value: url,
                source: RuntimePublicBaseUrlSource::Configured,
            }),
        })
    } else {
        public_base_url.clone().map(|url| RuntimeConfig {
            public_base_url: Some(RuntimePublicBaseUrl {
                value: url,
                source: RuntimePublicBaseUrlSource::Derived,
            }),
        })
    };

    let startup_contract = resolve_startup_contract(
        static_routes,
        http_listener_enabled,
        asset_serving_enabled,
        public_base_url.clone(),
        runtime_config,
    )?;
    write_json(
        &paths.runtime_root().join("startup_contract.json"),
        &startup_contract,
    )?;

    if should_restart(restart, "nats") {
        let _ = supervisor::stop_pidfile(&paths.pid_path("nats"), 2_000);
    }

    let nats_url = if config.services.nats.enabled {
        if config.services.nats.spawn.enabled {
            let spec = build_service_spec(
                config_dir,
                "nats",
                &config.services.nats.spawn.binary,
                &config.services.nats.spawn.args,
                &build_env(tenant, team, None, Some(&startup_contract)),
            )?;
            log_service_spec_debug("nats", "nats", &spec, tenant, team, debug_enabled);
            let nats_log = operator_log::reserve_service_log(log_dir, "nats")
                .with_context(|| "unable to open nats.log")?;
            if let Some(handle) = spawn_if_needed(&paths, &spec, restart, Some(nats_log.clone()))? {
                service_tracker
                    .record_with_log("nats", "nats", Some(&handle.log_path))
                    .with_context(|| "failed to record nats service")?;
            }
        }
        Some(config.services.nats.url.clone())
    } else {
        None
    };

    operator_log::info(
        module_path!(),
        "events provider packs run in-process; external events components are disabled",
    );

    if run_gsm_services {
        if should_restart(restart, "gateway") {
            let _ = supervisor::stop_pidfile(&paths.pid_path("gateway"), 2_000);
        }
        let gateway_spec = build_service_spec(
            config_dir,
            "gateway",
            &config.services.gateway.binary,
            &config.services.gateway.args,
            &build_env(tenant, team, nats_url.as_deref(), Some(&startup_contract)),
        )?;
        if let Some(handle) = spawn_if_needed(&paths, &gateway_spec, restart, None)? {
            service_tracker.record_with_log("gateway", "gateway", Some(&handle.log_path))?;
        }

        if should_restart(restart, "egress") {
            let _ = supervisor::stop_pidfile(&paths.pid_path("egress"), 2_000);
        }
        let egress_spec = build_service_spec(
            config_dir,
            "egress",
            &config.services.egress.binary,
            &config.services.egress.args,
            &build_env(tenant, team, nats_url.as_deref(), Some(&startup_contract)),
        )?;
        if let Some(handle) = spawn_if_needed(&paths, &egress_spec, restart, None)? {
            service_tracker.record_with_log("egress", "egress", Some(&handle.log_path))?;
        }

        match config.services.subscriptions.mode {
            DemoSubscriptionsMode::LegacyGsm => {
                if config.services.subscriptions.msgraph.enabled {
                    if should_restart(restart, "subscriptions")
                        || should_restart(restart, "msgraph")
                    {
                        let _ = supervisor::stop_pidfile(&paths.pid_path("subscriptions"), 2_000);
                    }
                    let mut args = config.services.subscriptions.msgraph.args.clone();
                    if !config.services.subscriptions.msgraph.mode.is_empty() {
                        args.insert(0, config.services.subscriptions.msgraph.mode.clone());
                    }
                    let spec = build_service_spec(
                        config_dir,
                        "subscriptions",
                        &config.services.subscriptions.msgraph.binary,
                        &args,
                        &build_env(tenant, team, nats_url.as_deref(), Some(&startup_contract)),
                    )?;
                    if let Some(handle) = spawn_if_needed(&paths, &spec, restart, None)? {
                        service_tracker.record_with_log(
                            "subscriptions",
                            "subscriptions",
                            Some(&handle.log_path),
                        )?;
                    }
                }
            }
            DemoSubscriptionsMode::UniversalOps => {
                spawn_universal_subscriptions_service(
                    config_dir,
                    config,
                    tenant,
                    team,
                    runner_binary.clone(),
                    &mut service_tracker,
                    log_dir,
                    debug_enabled,
                )?;
            }
        }
    } else {
        println!(
            "{}",
            crate::operator_i18n::tr(
                "demo.runtime.messaging_embedded",
                "messaging: running embedded runner (no gsm gateway/egress)"
            )
        );
        println!(
            "{}",
            crate::operator_i18n::tr(
                "demo.runtime.events_in_process",
                "events: handled in-process (HTTP ingress + timer scheduler)"
            )
        );
        operator_log::info(
            module_path!(),
            "demo running in embedded runner mode; gateway/egress disabled",
        );
        if debug_enabled {
            operator_log::debug(
                module_path!(),
                format!(
                    "[demo dev] embedded runner mode only tenant={} team={} (gateway/egress/subscriptions skipped)",
                    tenant, team
                ),
            );
        }
    }

    let endpoints = DemoEndpoints {
        tenant: tenant.to_string(),
        team: team.to_string(),
        public_base_url: startup_contract.public_base_url.clone(),
        nats_url,
        gateway_listen_addr: config.services.gateway.listen_addr.clone(),
        gateway_port: config.services.gateway.port,
    };
    write_json(&paths.runtime_root().join("endpoints.json"), &endpoints)?;
    Ok(ForegroundRuntimeHandles { ingress_server })
}

fn detect_http_ingress_domains(
    discovery: &crate::discovery::DiscoveryResult,
    runner_host: &DemoRunnerHost,
) -> Vec<Domain> {
    let mut domains = Vec::new();
    for domain in [Domain::Messaging, Domain::Events, Domain::OAuth] {
        let supported = discovery.providers.iter().any(|provider| {
            let domain_match = parse_domain_name(&provider.domain) == Some(domain);
            let op_support = runner_host.supports_op(domain, &provider.provider_id, "ingest_http");
            operator_log::info(
                module_path!(),
                format!(
                    "[domain-detect] domain={:?} provider={} domain_match={} op_support={}",
                    domain, provider.provider_id, domain_match, op_support
                ),
            );
            domain_match && op_support
        });
        let fallback_supported = matches!(domain, Domain::Events) && discovery.domains.events;
        operator_log::info(
            module_path!(),
            format!(
                "[domain-detect] domain={:?} supported={} fallback={} => enabled={}",
                domain,
                supported,
                fallback_supported,
                supported || fallback_supported
            ),
        );
        if supported || fallback_supported {
            domains.push(domain);
        }
    }
    domains
}

fn parse_domain_name(value: &str) -> Option<Domain> {
    match value {
        "messaging" => Some(Domain::Messaging),
        "events" => Some(Domain::Events),
        "oauth" => Some(Domain::OAuth),
        "secrets" => Some(Domain::Secrets),
        _ => None,
    }
}

fn start_http_ingress_server(
    config: &DemoConfig,
    domains: &[Domain],
    runner_host: Arc<DemoRunnerHost>,
    enable_static_routes: bool,
) -> anyhow::Result<Option<HttpIngressServer>> {
    // Start HTTP server if we have ingress domains OR static routes to serve
    if domains.is_empty() && !enable_static_routes {
        return Ok(None);
    }
    let addr = format!(
        "{}:{}",
        config.services.gateway.listen_addr, config.services.gateway.port
    );
    let bind_addr = addr
        .parse()
        .with_context(|| format!("invalid gateway listen address {addr}"))?;
    let server = HttpIngressServer::start(HttpIngressConfig {
        bind_addr,
        domains: domains.to_vec(),
        runner_host,
        enable_static_routes,
    })?;
    println!(
        "HTTP ingress ready at http://{}:{}",
        config.services.gateway.listen_addr, config.services.gateway.port
    );
    Ok(Some(server))
}

pub fn demo_status_runtime(
    state_dir: &Path,
    tenant: &str,
    team: &str,
    verbose: bool,
) -> anyhow::Result<()> {
    let paths = RuntimePaths::new(state_dir, tenant, team);
    let statuses = supervisor::read_status(&paths)?;
    if statuses.is_empty() {
        println!(
            "{}",
            crate::operator_i18n::tr("demo.runtime.none_running", "none running")
        );
        return Ok(());
    }
    for status in statuses {
        let state = if status.running {
            crate::operator_i18n::tr("demo.runtime.status_running", "running")
        } else {
            crate::operator_i18n::tr("demo.runtime.status_stopped", "stopped")
        };
        let pid = status
            .pid
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        if verbose {
            println!(
                "{}: {} (pid={}, log={})",
                status.id.as_str(),
                &state,
                pid,
                status.log_path.display()
            );
        } else {
            println!("{}: {} (pid={})", status.id.as_str(), &state, pid);
        }
    }
    Ok(())
}

pub fn demo_logs_runtime(
    state_dir: &Path,
    log_dir: &Path,
    tenant: &str,
    team: &str,
    service: &str,
    tail: bool,
) -> anyhow::Result<()> {
    let log_dir = resolve_manifest_log_dir(state_dir, tenant, team, log_dir)?;
    let log_path = if service == "operator" {
        log_dir.join("operator.log")
    } else {
        let tenant_log_path = tenant_log_path(&log_dir, service, tenant, team)?;
        select_log_path(&log_dir, service, tenant, &tenant_log_path)
    };
    if tail {
        return services::tail_log(&log_path);
    }
    let lines = read_last_lines(&log_path, 200)?;
    if !lines.is_empty() {
        println!("{lines}");
    }
    Ok(())
}

pub fn demo_down_runtime(
    state_dir: &Path,
    tenant: &str,
    team: &str,
    all: bool,
) -> anyhow::Result<()> {
    let timeout_ms = 2_000;
    let paths = RuntimePaths::new(state_dir, tenant, team);
    stop_started_nats(&paths, state_dir)?;
    // Kill any orphaned ngrok/cloudflared processes not tracked by pidfile
    ngrok::stop_ngrok();
    cloudflared::stop_cloudflared();
    if all {
        let pids_root = state_dir.join("pids");
        if !pids_root.exists() {
            println!(
                "{}",
                crate::operator_i18n::tr(
                    "demo.runtime.no_services_to_stop",
                    "No supervised background services to stop. If runtime was started in the foreground, stop it in the original terminal with Ctrl+C."
                )
            );
            return Ok(());
        }
        for entry in std::fs::read_dir(&pids_root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            for pidfile in std::fs::read_dir(entry.path())? {
                let pidfile = pidfile?;
                if pidfile.path().extension().and_then(|ext| ext.to_str()) != Some("pid") {
                    continue;
                }
                let _ = supervisor::stop_pidfile(&pidfile.path(), timeout_ms);
            }
        }
        remove_service_manifest(&paths)?;
        println!(
            "{}",
            crate::operator_i18n::trf(
                "demo.runtime.stopped_all_under",
                "Stopped all services under {}",
                &[&pids_root.display().to_string()]
            )
        );
        return Ok(());
    }

    if let Some(manifest) = read_service_manifest(&paths)? {
        if manifest.services.is_empty() {
            println!(
                "{}",
                crate::operator_i18n::tr(
                    "demo.runtime.no_services_to_stop",
                    "No supervised background services to stop. If runtime was started in the foreground, stop it in the original terminal with Ctrl+C."
                )
            );
            return Ok(());
        }
        for entry in manifest.services.iter().rev() {
            let id = supervisor::ServiceId::new(entry.id.clone())?;
            if let Err(err) = supervisor::stop_service(&paths, &id, timeout_ms) {
                eprintln!(
                    "{}",
                    crate::operator_i18n::trf(
                        "demo.runtime.warn_failed_stop_service",
                        "Warning: failed to stop {}: {}",
                        &[&entry.id, &err.to_string()]
                    )
                );
            }
        }
        remove_service_manifest(&paths)?;
        return Ok(());
    }

    let pids_dir = paths.pids_dir();
    if !pids_dir.exists() {
        println!(
            "{}",
            crate::operator_i18n::tr(
                "demo.runtime.no_services_to_stop",
                "No supervised background services to stop. If runtime was started in the foreground, stop it in the original terminal with Ctrl+C."
            )
        );
        return Ok(());
    }
    for entry in std::fs::read_dir(&pids_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("pid") {
            continue;
        }
        supervisor::stop_pidfile(&path, timeout_ms)?;
    }
    Ok(())
}

fn select_log_path(log_dir: &Path, service: &str, tenant: &str, tenant_log: &Path) -> PathBuf {
    let candidates = [
        log_dir.join(format!("{service}.log")),
        log_dir.join(format!("{service}-{tenant}.log")),
        log_dir.join(format!("{service}.{tenant}.log")),
    ];
    for candidate in &candidates {
        if candidate.exists() {
            return candidate.clone();
        }
    }
    if tenant_log.exists() {
        return tenant_log.to_path_buf();
    }
    let _ = ensure_log_file(tenant_log);
    tenant_log.to_path_buf()
}

fn tenant_log_path(
    log_dir: &Path,
    service: &str,
    tenant: &str,
    team: &str,
) -> anyhow::Result<PathBuf> {
    let tenant_dir = log_dir.join(format!("{tenant}.{team}"));
    let path = tenant_dir.join(format!("{service}.log"));
    ensure_log_file(&path)?;
    Ok(path)
}

fn ensure_log_file(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        std::fs::File::create(path)?;
    }
    Ok(())
}

fn resolve_manifest_log_dir(
    state_dir: &Path,
    tenant: &str,
    team: &str,
    default: &Path,
) -> anyhow::Result<PathBuf> {
    let paths = RuntimePaths::new(state_dir, tenant, team);
    if let Some(manifest) = read_service_manifest(&paths)?
        && let Some(dir) = manifest.log_dir
    {
        return Ok(PathBuf::from(dir));
    }
    Ok(default.to_path_buf())
}

fn build_env(
    tenant: &str,
    team: &str,
    nats_url: Option<&str>,
    startup_contract: Option<&StartupContract>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert("GREENTIC_TENANT".to_string(), tenant.to_string());
    env.insert("GREENTIC_TEAM".to_string(), team.to_string());
    if let Some(url) = nats_url {
        env.insert("NATS_URL".to_string(), url.to_string());
    }
    if let Some(contract) = startup_contract {
        contract.apply_env(&mut env);
    }
    env
}

fn resolve_startup_contract(
    static_routes: &BundleStaticRoutesInspection,
    http_listener_enabled: bool,
    asset_serving_enabled: bool,
    public_base_url: Option<String>,
    runtime_config: Option<RuntimeConfig>,
) -> anyhow::Result<StartupContract> {
    crate::startup_contract::resolve(StartupContractInput {
        bundle_has_static_routes: static_routes.bundle_has_static_routes(),
        http_listener_enabled,
        asset_serving_enabled,
        public_base_url,
        runtime_config,
    })
}

fn mark_nats_started(paths: &RuntimePaths) -> anyhow::Result<()> {
    let marker = nats_started_marker(paths);
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(marker, "started")?;
    Ok(())
}

fn stop_started_nats(paths: &RuntimePaths, state_dir: &Path) -> anyhow::Result<()> {
    let marker = nats_started_marker(paths);
    if !marker.exists() {
        return Ok(());
    }
    let bundle_root = state_dir.parent().unwrap_or(state_dir);
    match services::stop_nats(bundle_root) {
        Ok(_) => {
            let _ = std::fs::remove_file(&marker);
        }
        Err(err) => {
            eprintln!(
                "{}",
                crate::operator_i18n::trf(
                    "demo.runtime.warn_failed_stop_nats",
                    "Warning: failed to stop nats: {}",
                    &[&err.to_string()]
                )
            );
        }
    }
    Ok(())
}

fn nats_started_marker(paths: &RuntimePaths) -> PathBuf {
    paths.runtime_root().join("nats.started")
}

fn build_service_spec(
    config_dir: &Path,
    service_id: &str,
    binary: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
) -> anyhow::Result<supervisor::ServiceSpec> {
    let explicit = if looks_like_path(binary) {
        let path = Path::new(binary);
        Some(if path.is_absolute() {
            path.to_path_buf()
        } else {
            config_dir.join(path)
        })
    } else {
        None
    };
    let path = crate::bin_resolver::resolve_binary(
        binary,
        &crate::bin_resolver::ResolveCtx {
            config_dir: config_dir.to_path_buf(),
            explicit_path: explicit,
        },
    )?;
    let mut argv = vec![path.to_string_lossy().to_string()];
    argv.extend(args.iter().cloned());
    Ok(supervisor::ServiceSpec {
        id: supervisor::ServiceId::new(service_id)?,
        argv,
        cwd: None,
        env: env.clone(),
    })
}

#[derive(serde::Serialize)]
struct DemoEndpoints {
    tenant: String,
    team: String,
    public_base_url: Option<String>,
    nats_url: Option<String>,
    gateway_listen_addr: String,
    gateway_port: u16,
}

fn read_last_lines(path: &Path, count: usize) -> anyhow::Result<String> {
    if !path.exists() {
        return Err(anyhow::anyhow!(
            "Log file does not exist: {}",
            path.display()
        ));
    }
    let contents = std::fs::read_to_string(path)?;
    let mut lines: Vec<&str> = contents.lines().collect();
    if lines.len() > count {
        lines = lines.split_off(lines.len() - count);
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn tenant_log_path_creates_file() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = tenant_log_path(dir.path(), "messaging", "demo", "default")?;
        assert!(path.exists());
        Ok(())
    }

    #[test]
    fn select_log_path_prefers_service_log_when_present() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let tenant_path = tenant_log_path(dir.path(), "messaging", "demo", "default")?;
        let service_path = dir.path().join("messaging.log");
        fs::write(&service_path, "other")?;
        let selected = select_log_path(dir.path(), "messaging", "demo", &tenant_path);
        assert_eq!(selected, service_path);
        Ok(())
    }

    #[test]
    fn demo_logs_runtime_reads_operator_log() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let log = dir.path().join("operator.log");
        fs::write(&log, "operator ready")?;
        demo_logs_runtime(dir.path(), dir.path(), "demo", "default", "operator", false)?;
        Ok(())
    }
}
