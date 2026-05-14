use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Serialize;
use serde_json::{Value, json};

use crate::StartRequest;
use crate::cli_args::{DoctorArgs, DoctorStageArg};
use crate::domains::Domain;
use crate::runtime_state::RuntimePaths;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warn,
    Info,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticComponent {
    Setup,
    Start,
    Cache,
    Lock,
    Answers,
    Routes,
    Runtime,
    Provider,
}

#[derive(Clone, Debug, Serialize)]
pub struct Diagnostic {
    pub check_id: String,
    pub severity: Severity,
    pub component: DiagnosticComponent,
    pub message: String,
    pub evidence: Value,
    pub expected: Value,
    pub actual: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_pack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_component: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct DoctorBundle {
    input: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_root: Option<PathBuf>,
    source_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct DoctorSummary {
    errors: usize,
    warnings: usize,
    infos: usize,
}

#[derive(Clone, Debug, Serialize)]
struct DoctorReport {
    schema_version: u32,
    tool: String,
    command: String,
    bundle: DoctorBundle,
    summary: DoctorSummary,
    diagnostics: Vec<Diagnostic>,
}

struct DoctorCtx<'a> {
    args: &'a DoctorArgs,
    report: DoctorReport,
}

pub fn run_doctor(args: DoctorArgs) -> anyhow::Result<bool> {
    let mut ctx = DoctorCtx {
        report: DoctorReport {
            schema_version: 1,
            tool: "greentic-start".to_string(),
            command: "doctor".to_string(),
            bundle: DoctorBundle {
                input: args.bundle.clone(),
                resolved_root: None,
                source_kind: bundle_source_kind(&args.bundle).to_string(),
                digest: None,
            },
            summary: DoctorSummary::default(),
            diagnostics: Vec::new(),
        },
        args: &args,
    };

    let resolved_root = match crate::bundle_ref::resolve_bundle_ref(&args.bundle) {
        Ok(resolved) => {
            ctx.report.bundle.resolved_root = Some(resolved.bundle_dir.clone());
            ctx.info(
                "start.bundle.resolve",
                DiagnosticComponent::Start,
                "Bundle reference resolved.",
                json!({ "root": resolved.bundle_dir }),
            );
            Some(resolved.bundle_dir)
        }
        Err(err) => {
            ctx.error(
                "start.bundle.resolve",
                DiagnosticComponent::Start,
                "Bundle reference could not be resolved.",
                json!({ "error": format!("{err:#}") }),
                (
                    json!({ "resolvable_bundle": true }),
                    json!({ "resolvable_bundle": false }),
                ),
                Some("Pass an existing local bundle directory/archive or a reachable supported remote bundle reference."),
            );
            None
        }
    };

    check_tag_refs(&mut ctx);

    if let Some(root) = resolved_root.as_deref() {
        check_bundle_shape(&mut ctx, root);
        let demo = check_runtime_config(&mut ctx, root);
        check_cache(&mut ctx, root);
        check_pack_manifests(&mut ctx, root);
        check_dependencies(&mut ctx, root);
        check_discovery(&mut ctx, root);
        check_static_routes(&mut ctx, root);
        check_app_pack_flow(&mut ctx, root, demo.as_ref());
        check_setup_outputs(&mut ctx, root, demo.as_ref());
        check_runtime_metadata(&mut ctx, root, demo.as_ref());
        check_secret_requirements(&mut ctx, root);
        if let Some((_, config)) = demo.as_ref() {
            check_ports(&mut ctx, config);
        }
    }

    ctx.finalize_summary();
    let has_errors = ctx.report.summary.errors > 0;
    let report = ctx.report.filtered(args.show_info);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_report(&report, args.fix_hints, args.show_info);
    }
    Ok(has_errors)
}

impl DoctorReport {
    fn filtered(&self, show_info: bool) -> Self {
        if show_info {
            return self.clone();
        }
        let mut report = self.clone();
        report
            .diagnostics
            .retain(|diagnostic| diagnostic.severity != Severity::Info);
        report.recalculate_summary();
        report
    }

    fn recalculate_summary(&mut self) {
        self.summary = DoctorSummary::default();
        for diagnostic in &self.diagnostics {
            match diagnostic.severity {
                Severity::Error => self.summary.errors += 1,
                Severity::Warn => self.summary.warnings += 1,
                Severity::Info => self.summary.infos += 1,
            }
        }
    }
}

impl DoctorCtx<'_> {
    fn include(&self, component: DiagnosticComponent) -> bool {
        match self.args.stage {
            DoctorStageArg::All => true,
            DoctorStageArg::Setup => component == DiagnosticComponent::Setup,
            DoctorStageArg::Cache => component == DiagnosticComponent::Cache,
            DoctorStageArg::Locks => component == DiagnosticComponent::Lock,
            DoctorStageArg::Answers => component == DiagnosticComponent::Answers,
            DoctorStageArg::Runtime => component == DiagnosticComponent::Runtime,
            DoctorStageArg::Routes => component == DiagnosticComponent::Routes,
            DoctorStageArg::Provider => component == DiagnosticComponent::Provider,
            DoctorStageArg::Secrets => {
                matches!(
                    component,
                    DiagnosticComponent::Provider | DiagnosticComponent::Setup
                )
            }
        }
    }

    fn push(&mut self, mut diagnostic: Diagnostic) {
        if !self.include(diagnostic.component) {
            return;
        }
        if self.args.strict && should_promote_in_strict(&diagnostic) {
            diagnostic.severity = Severity::Error;
        }
        self.report.diagnostics.push(diagnostic);
    }

    fn error(
        &mut self,
        check_id: &str,
        component: DiagnosticComponent,
        message: &str,
        evidence: Value,
        expected_actual: (Value, Value),
        fix_hint: Option<&str>,
    ) {
        self.push(Diagnostic {
            check_id: check_id.to_string(),
            severity: Severity::Error,
            component,
            message: message.to_string(),
            evidence,
            expected: expected_actual.0,
            actual: expected_actual.1,
            fix_hint: fix_hint.map(str::to_string),
            related_file: None,
            related_pack: None,
            related_component: None,
        });
    }

    fn warn(
        &mut self,
        check_id: &str,
        component: DiagnosticComponent,
        message: &str,
        evidence: Value,
        fix_hint: Option<&str>,
    ) {
        self.push(Diagnostic {
            check_id: check_id.to_string(),
            severity: Severity::Warn,
            component,
            message: message.to_string(),
            evidence,
            expected: Value::Null,
            actual: Value::Null,
            fix_hint: fix_hint.map(str::to_string),
            related_file: None,
            related_pack: None,
            related_component: None,
        });
    }

    fn info(
        &mut self,
        check_id: &str,
        component: DiagnosticComponent,
        message: &str,
        evidence: Value,
    ) {
        self.push(Diagnostic {
            check_id: check_id.to_string(),
            severity: Severity::Info,
            component,
            message: message.to_string(),
            evidence,
            expected: Value::Null,
            actual: Value::Null,
            fix_hint: None,
            related_file: None,
            related_pack: None,
            related_component: None,
        });
    }

    fn finalize_summary(&mut self) {
        self.report.recalculate_summary();
    }
}

fn should_promote_in_strict(diagnostic: &Diagnostic) -> bool {
    diagnostic.severity == Severity::Warn
        && (diagnostic.check_id.contains(".tag_refs")
            || diagnostic.check_id.contains(".cache")
            || diagnostic.check_id.contains(".current")
            || diagnostic.check_id.contains(".dependencies"))
}

fn bundle_source_kind(input: &str) -> &'static str {
    if input.starts_with("oci://") {
        "oci"
    } else if input.starts_with("repo://") {
        "repo"
    } else if input.starts_with("store://") {
        "store"
    } else if input.starts_with("http://") || input.starts_with("https://") {
        "http"
    } else {
        "local"
    }
}

fn check_tag_refs(ctx: &mut DoctorCtx<'_>) {
    let value = ctx.args.bundle.trim();
    if !matches!(bundle_source_kind(value), "oci" | "repo" | "store") {
        return;
    }
    if value.contains("@sha256:") {
        ctx.info(
            "start.pack.tag_refs",
            DiagnosticComponent::Lock,
            "Bundle reference is digest-pinned.",
            json!({ "reference": value }),
        );
        return;
    }
    let tag = value.rsplit_once(':').map(|(_, tag)| tag).unwrap_or("");
    if tag.is_empty() || tag == "latest" {
        ctx.warn(
            "start.pack.tag_refs",
            DiagnosticComponent::Lock,
            "Bundle reference uses a moving tag where exact pins are expected.",
            json!({ "reference": value, "tag": tag }),
            Some("Rebuild or request the bundle with an @sha256 digest reference."),
        );
    }
}

fn check_bundle_shape(ctx: &mut DoctorCtx<'_>, root: &Path) {
    let candidates = [
        "greentic.demo.yaml",
        "greentic.operator.yaml",
        "demo/demo.yaml",
        "bundle.yaml",
    ];
    let present = candidates
        .iter()
        .filter(|candidate| root.join(candidate).exists())
        .copied()
        .collect::<Vec<_>>();
    if present.is_empty() {
        ctx.error(
            "start.bundle.structure",
            DiagnosticComponent::Start,
            "Bundle root does not contain a recognized runtime config file.",
            json!({ "root": root, "searched": candidates }),
            (
                json!({ "one_of": candidates }),
                json!({ "present": present }),
            ),
            Some("Point doctor at an extracted bundle root or rebuild the bundle with runtime config."),
        );
    } else {
        ctx.info(
            "start.bundle.structure",
            DiagnosticComponent::Start,
            "Bundle root contains recognized runtime config.",
            json!({ "root": root, "present": present }),
        );
    }

    if root.join("bundle.yaml").exists()
        && !root.join("bundle-manifest.json").exists()
        && !root.join("resolved").is_dir()
    {
        ctx.warn(
            "start.bundle.manifest",
            DiagnosticComponent::Start,
            "Normalized bundle has bundle.yaml but no bundle-manifest.json or resolved/ payload.",
            json!({ "root": root }),
            Some("Regenerate setup outputs so normalized target metadata is present."),
        );
    }
}

fn check_runtime_config(
    ctx: &mut DoctorCtx<'_>,
    root: &Path,
) -> Option<(crate::bundle_config::DemoPaths, crate::config::DemoConfig)> {
    let root_ref = root.to_string_lossy().to_string();
    let paths = match crate::bundle_config::resolve_demo_paths(None, Some(&root_ref)) {
        Ok(paths) => {
            ctx.info(
                "start.config.resolve",
                DiagnosticComponent::Runtime,
                "Runtime config path resolved.",
                json!({
                    "config_path": paths.config_path,
                    "root": paths.root_dir,
                    "state_dir": paths.state_dir,
                    "source": format!("{:?}", paths.config_source),
                }),
            );
            paths
        }
        Err(err) => {
            ctx.error(
                "start.config.resolve",
                DiagnosticComponent::Runtime,
                "Runtime config could not be resolved.",
                json!({ "error": format!("{err:#}") }),
                (
                    json!({ "config_resolves": true }),
                    json!({ "config_resolves": false }),
                ),
                Some("Check for greentic.demo.yaml, greentic.operator.yaml, demo/demo.yaml, or normalized bundle.yaml outputs."),
            );
            return None;
        }
    };
    let request = default_start_request(Some(root_ref));
    match crate::bundle_config::load_runtime_demo_config(&paths, &request) {
        Ok(config) => {
            ctx.info(
                "start.config.load",
                DiagnosticComponent::Runtime,
                "Runtime config loaded.",
                json!({ "tenant": config.tenant, "team": config.team }),
            );
            Some((paths, config))
        }
        Err(err) => {
            ctx.error(
                "start.config.load",
                DiagnosticComponent::Runtime,
                "Runtime config could not be parsed.",
                json!({ "error": format!("{err:#}"), "config_path": paths.config_path }),
                (
                    json!({ "config_loads": true }),
                    json!({ "config_loads": false }),
                ),
                Some("Fix the selected runtime config YAML or regenerate normalized setup output."),
            );
            None
        }
    }
}

fn default_start_request(bundle: Option<String>) -> StartRequest {
    StartRequest {
        bundle,
        tenant: None,
        team: None,
        no_nats: false,
        nats: crate::NatsModeArg::Off,
        nats_url: None,
        config: None,
        cloudflared: crate::CloudflaredModeArg::Off,
        cloudflared_binary: None,
        ngrok: crate::NgrokModeArg::Off,
        ngrok_binary: None,
        runner_binary: None,
        restart: Vec::new(),
        log_dir: None,
        verbose: false,
        quiet: true,
        no_browser: true,
        admin: false,
        admin_port: 8443,
        admin_certs_dir: None,
        admin_allowed_clients: Vec::new(),
        tunnel_explicit: true,
    }
}

fn check_cache(ctx: &mut DoctorCtx<'_>, root: &Path) {
    let shipped = root.join(".cache").join("v1");
    if shipped.is_dir() {
        ctx.info(
            "start.cache.component",
            DiagnosticComponent::Cache,
            "Bundle ships a component cache.",
            json!({ "cache_dir": shipped }),
        );
    } else {
        ctx.warn(
            "start.cache.component",
            DiagnosticComponent::Cache,
            "Bundle does not ship a .cache/v1 component cache.",
            json!({ "expected": shipped }),
            Some("Run greentic-start warmup or rebuild the bundle with a warmed component cache if cold-start latency or cache corruption is suspected."),
        );
    }
    if let Some(value) = std::env::var_os("GREENTIC_CACHE_DIR") {
        ctx.info(
            "start.cache.env",
            DiagnosticComponent::Cache,
            "GREENTIC_CACHE_DIR is set and will override bundle-shipped cache adoption.",
            json!({ "GREENTIC_CACHE_DIR": value.to_string_lossy() }),
        );
    }
}

fn check_pack_manifests(ctx: &mut DoctorCtx<'_>, root: &Path) {
    if root.join("greentic.demo.yaml").exists() {
        match crate::domains::ensure_cbor_packs(root) {
            Ok(()) => ctx.info(
                "start.pack.manifest",
                DiagnosticComponent::Provider,
                "Runtime packs contain manifest.cbor for legacy demo mode.",
                json!({ "mode": "cbor_only" }),
            ),
            Err(err) => ctx.error(
                "start.pack.manifest",
                DiagnosticComponent::Provider,
                "Runtime pack manifest validation failed.",
                json!({ "error": format!("{err:#}") }),
                (
                    json!({ "manifest_cbor": true }),
                    json!({ "manifest_cbor": false }),
                ),
                Some("Rebuild affected packs with greentic-pack build so manifest.cbor is present and decodable."),
            ),
        }
    }
}

fn check_dependencies(ctx: &mut DoctorCtx<'_>, root: &Path) {
    match crate::dependency_resolver::check_all(root) {
        Ok(report) => {
            if report.missing.is_empty() {
                ctx.info(
                    "start.pack.dependencies",
                    DiagnosticComponent::Provider,
                    "Pack dependency check found no missing dependencies.",
                    json!({ "satisfied": report.satisfied.len() }),
                );
            } else {
                for missing in report.missing {
                    ctx.warn(
                        "start.pack.dependencies",
                        DiagnosticComponent::Provider,
                        "Pack dependency is missing from the bundle.",
                        json!({
                            "pack_id": missing.pack_id,
                            "required_by": missing.required_by,
                            "required_capabilities": missing.required_capabilities,
                        }),
                        Some("Add the required extension pack to the bundle and regenerate setup outputs."),
                    );
                }
            }
        }
        Err(err) => ctx.warn(
            "start.pack.dependencies",
            DiagnosticComponent::Provider,
            "Pack dependency check could not complete.",
            json!({ "error": format!("{err:#}") }),
            Some("Fix unreadable or invalid pack manifests first."),
        ),
    }
}

fn check_discovery(ctx: &mut DoctorCtx<'_>, root: &Path) {
    match crate::discovery::discover(root) {
        Ok(discovery) => ctx.info(
            "start.discovery",
            DiagnosticComponent::Provider,
            "Provider discovery completed.",
            json!({
                "providers": discovery.providers.len(),
                "domains": {
                    "messaging": discovery.domains.messaging,
                    "events": discovery.domains.events,
                    "oauth": discovery.domains.oauth,
                }
            }),
        ),
        Err(err) => ctx.error(
            "start.discovery",
            DiagnosticComponent::Provider,
            "Provider discovery failed.",
            json!({ "error": format!("{err:#}") }),
            (json!({ "discovery": true }), json!({ "discovery": false })),
            Some("Fix the provider pack named in the error, then retry start."),
        ),
    }
}

fn check_static_routes(ctx: &mut DoctorCtx<'_>, root: &Path) {
    match crate::startup_contract::inspect_bundle(root) {
        Ok(inspection) => ctx.info(
            "start.routes.inspect",
            DiagnosticComponent::Routes,
            "Static-route capability inspection completed.",
            json!({
                "bundle_has_static_routes": inspection.bundle_has_static_routes(),
                "packs": inspection.pack_paths,
            }),
        ),
        Err(err) => ctx.error(
            "start.routes.inspect",
            DiagnosticComponent::Routes,
            "Static-route capability inspection failed.",
            json!({ "error": format!("{err:#}") }),
            (
                json!({ "static_route_inspection": true }),
                json!({ "static_route_inspection": false }),
            ),
            Some("Fix the pack manifest or static-route extension payload named in the error."),
        ),
    }

    match crate::static_routes::discover_from_bundle(
        root,
        &crate::static_routes::ReservedRouteSet::operator_defaults(),
    ) {
        Ok(plan) => {
            for warning in plan.warnings {
                ctx.warn(
                    "start.routes.plan",
                    DiagnosticComponent::Routes,
                    "Static-route plan warning.",
                    json!({ "warning": warning }),
                    None,
                );
            }
            for failure in plan.blocking_failures {
                ctx.error(
                    "start.routes.plan",
                    DiagnosticComponent::Routes,
                    "Static-route plan has a blocking failure.",
                    json!({ "failure": failure }),
                    (
                        json!({ "blocking_failures": 0 }),
                        json!({ "blocking_failures": 1 }),
                    ),
                    Some("Adjust route paths, scope placeholders, or asset declarations before starting."),
                );
            }
            ctx.info(
                "start.routes.plan",
                DiagnosticComponent::Routes,
                "Static-route plan built.",
                json!({ "routes": plan.routes.len() }),
            );
        }
        Err(err) => ctx.error(
            "start.routes.plan",
            DiagnosticComponent::Routes,
            "Static-route plan could not be built.",
            json!({ "error": format!("{err:#}") }),
            (
                json!({ "route_plan": true }),
                json!({ "route_plan": false }),
            ),
            Some("Fix pack manifests and route extension payloads before starting."),
        ),
    }

    match crate::startup_contract::configured_public_base_url_from_env() {
        Ok(Some(url)) => ctx.info(
            "start.routes.public_url",
            DiagnosticComponent::Routes,
            "PUBLIC_BASE_URL is valid.",
            json!({ "PUBLIC_BASE_URL": url }),
        ),
        Ok(None) => ctx.info(
            "start.routes.public_url",
            DiagnosticComponent::Routes,
            "PUBLIC_BASE_URL is not set; start may derive a local or tunnel URL.",
            json!({}),
        ),
        Err(err) => ctx.error(
            "start.routes.public_url",
            DiagnosticComponent::Routes,
            "PUBLIC_BASE_URL is invalid.",
            json!({ "error": err.to_string() }),
            (
                json!({ "valid_public_base_url": true }),
                json!({ "valid_public_base_url": false }),
            ),
            Some("Set PUBLIC_BASE_URL to an http:// or https:// origin without a path or query."),
        ),
    }
}

fn check_setup_outputs(
    ctx: &mut DoctorCtx<'_>,
    root: &Path,
    demo: Option<&(crate::bundle_config::DemoPaths, crate::config::DemoConfig)>,
) {
    let Some((_, config)) = demo else {
        return;
    };
    let paths = RuntimePaths::new(root.join("state"), &config.tenant, &config.team);
    let runtime_providers_root = paths.runtime_root().join("providers");
    let legacy_providers_root = root.join(".providers");
    let providers_root = if runtime_providers_root.exists() {
        runtime_providers_root
    } else if legacy_providers_root.exists() {
        ctx.info(
            "start.setup.completed",
            DiagnosticComponent::Setup,
            "Provider setup envelopes exist in legacy .providers layout.",
            json!({ "providers_root": legacy_providers_root }),
        );
        legacy_providers_root
    } else {
        ctx.warn(
            "start.setup.completed",
            DiagnosticComponent::Setup,
            "Provider setup output directory is missing.",
            json!({
                "runtime_providers_root": runtime_providers_root,
                "legacy_providers_root": legacy_providers_root,
            }),
            Some(
                "Run greentic-setup for this bundle before starting providers that require setup.",
            ),
        );
        return;
    };

    let pack_index = provider_pack_index(root);
    let mut envelope_count = 0usize;
    let entries = match std::fs::read_dir(&providers_root) {
        Ok(entries) => entries,
        Err(err) => {
            ctx.warn(
                "start.setup.completed",
                DiagnosticComponent::Setup,
                "Provider setup output directory cannot be read.",
                json!({ "providers_root": providers_root, "error": err.to_string() }),
                None,
            );
            return;
        }
    };
    for entry in entries.flatten() {
        let provider_dir = entry.path();
        if !provider_dir.is_dir()
            || provider_dir.file_name().and_then(|v| v.to_str()) == Some("_contracts")
        {
            continue;
        }
        let Some(provider_id) = provider_dir.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let envelope_path = provider_dir.join("config.envelope.cbor");
        if !envelope_path.exists() {
            ctx.warn(
                "start.setup.completed",
                DiagnosticComponent::Setup,
                "Provider setup directory has no config envelope.",
                json!({ "provider": provider_id, "provider_dir": provider_dir }),
                Some("Rerun setup for this provider or remove stale provider state."),
            );
            continue;
        }
        envelope_count += 1;
        match crate::provider_config_envelope::read_provider_config_envelope(
            &providers_root,
            provider_id,
        ) {
            Ok(Some(envelope)) => {
                if let Some(pack_path) = pack_index.get(provider_id) {
                    match crate::provider_config_envelope::resolved_describe_hash(
                        pack_path,
                        provider_id,
                    ) {
                        Ok(resolved) if resolved == envelope.describe_hash => ctx.info(
                            "start.setup.current",
                            DiagnosticComponent::Setup,
                            "Provider config envelope matches current pack contract.",
                            json!({ "provider": provider_id, "pack": pack_path }),
                        ),
                        Ok(resolved) => {
                            let diagnostic = Diagnostic {
                                check_id: "start.setup.current".to_string(),
                                severity: Severity::Error,
                                component: DiagnosticComponent::Setup,
                                message: "Provider setup output was produced for a different provider contract.".to_string(),
                                evidence: json!({ "provider": provider_id, "operation_id": envelope.operation_id }),
                                expected: json!({ "describe_hash": resolved }),
                                actual: json!({ "describe_hash": envelope.describe_hash }),
                                fix_hint: Some("Rerun greentic-setup for this provider, then retry greentic-start.".to_string()),
                                related_file: Some(envelope_path.clone()),
                                related_pack: Some(pack_path.display().to_string()),
                                related_component: Some(envelope.component_id.clone()),
                            };
                            ctx.push(diagnostic);
                        }
                        Err(err) => ctx.warn(
                            "start.setup.current",
                            DiagnosticComponent::Setup,
                            "Could not recompute provider contract hash.",
                            json!({ "provider": provider_id, "pack": pack_path, "error": format!("{err:#}") }),
                            Some("Fix the provider pack manifest before trusting setup outputs."),
                        ),
                    }
                } else {
                    ctx.warn(
                        "start.setup.current",
                        DiagnosticComponent::Setup,
                        "Provider config envelope has no matching discovered provider pack.",
                        json!({ "provider": provider_id, "envelope": envelope_path }),
                        Some("Check whether the provider pack was removed, renamed, or moved to a different domain."),
                    );
                }
                let contract_path = providers_root
                    .join("_contracts")
                    .join(format!("{}.contract.cbor", envelope.resolved_digest));
                if !contract_path.exists() {
                    ctx.warn(
                        "start.setup.contract_cache",
                        DiagnosticComponent::Setup,
                        "Provider config envelope references a missing contract cache entry.",
                        json!({ "provider": provider_id, "contract_path": contract_path }),
                        Some("Rerun setup to regenerate contract cache metadata."),
                    );
                }
            }
            Ok(None) => {}
            Err(err) => ctx.error(
                "start.setup.outputs.valid",
                DiagnosticComponent::Setup,
                "Provider config envelope could not be decoded.",
                json!({ "provider": provider_id, "path": envelope_path, "error": format!("{err:#}") }),
                (json!({ "decode": true }), json!({ "decode": false })),
                Some("Delete or regenerate the corrupt config.envelope.cbor via setup."),
            ),
        }
    }

    if envelope_count == 0 {
        ctx.warn(
            "start.setup.completed",
            DiagnosticComponent::Setup,
            "No provider config envelopes were found.",
            json!({ "providers_root": providers_root }),
            Some("This is expected only for bundles that require no provider setup."),
        );
    }
}

fn check_app_pack_flow(
    ctx: &mut DoctorCtx<'_>,
    root: &Path,
    demo: Option<&(crate::bundle_config::DemoPaths, crate::config::DemoConfig)>,
) {
    let Some((_, config)) = demo else {
        return;
    };
    let team = Some(config.team.as_str());
    let app_pack_path = match crate::messaging_app::resolve_app_pack_path(
        root,
        &config.tenant,
        team,
        None,
    ) {
        Ok(path) => path,
        Err(err) => {
            ctx.error(
                    "start.app_pack.resolve",
                    DiagnosticComponent::Runtime,
                    "Messaging app pack could not be resolved.",
                    json!({ "error": format!("{err:#}"), "tenant": config.tenant, "team": config.team }),
                    (
                        json!({ "app_pack_resolves": true }),
                        json!({ "app_pack_resolves": false }),
                    ),
                    Some("Check bundle.yaml app_packs and ensure the referenced .gtpack exists under packs/."),
                );
            return;
        }
    };
    let pack_info = match crate::messaging_app::load_app_pack_info(&app_pack_path) {
        Ok(info) => info,
        Err(err) => {
            ctx.error(
                "start.app_pack.manifest",
                DiagnosticComponent::Runtime,
                "Messaging app pack manifest could not be read.",
                json!({ "pack": app_pack_path, "error": format!("{err:#}") }),
                (
                    json!({ "manifest_loads": true }),
                    json!({ "manifest_loads": false }),
                ),
                Some("Rebuild the app pack so manifest.cbor is present and decodable."),
            );
            return;
        }
    };
    match crate::messaging_app::select_app_flow(&pack_info) {
        Ok(flow) => ctx.info(
            "start.app_pack.default_flow",
            DiagnosticComponent::Runtime,
            "Messaging app pack has a selectable default flow.",
            json!({
                "pack": app_pack_path,
                "pack_id": pack_info.pack_id,
                "flow": { "id": flow.id, "kind": flow.kind },
            }),
        ),
        Err(err) => {
            let diagnostic = Diagnostic {
                check_id: "start.app_pack.default_flow".to_string(),
                severity: Severity::Error,
                component: DiagnosticComponent::Runtime,
                message: "Messaging app pack does not have a selectable default flow."
                    .to_string(),
                evidence: json!({
                    "pack_id": pack_info.pack_id,
                    "flows": app_flow_evidence(&pack_info.flows),
                    "error": format!("{err:#}"),
                }),
                expected: json!({
                    "one_flow_id_default": true,
                    "or_exactly_one_flow_kind_messaging": true,
                }),
                actual: json!({
                    "flow_count": pack_info.flows.len(),
                    "messaging_flow_count": pack_info
                        .flows
                        .iter()
                        .filter(|flow| flow.kind.eq_ignore_ascii_case("messaging"))
                        .count(),
                }),
                fix_hint: Some(
                    "Mark one app flow as id `default`, or make exactly one flow kind `messaging` so the webchat runtime can route inbound messages."
                        .to_string(),
                ),
                related_file: None,
                related_pack: Some(app_pack_path.display().to_string()),
                related_component: None,
            };
            ctx.push(diagnostic);
        }
    }
}

fn app_flow_evidence(flows: &[crate::messaging_app::AppFlowInfo]) -> Value {
    Value::Array(
        flows
            .iter()
            .map(|flow| json!({ "id": flow.id, "kind": flow.kind }))
            .collect(),
    )
}

fn provider_pack_index(root: &Path) -> BTreeMap<String, PathBuf> {
    let mut out = BTreeMap::new();
    for domain in [
        Domain::Messaging,
        Domain::Events,
        Domain::Secrets,
        Domain::OAuth,
    ] {
        if let Ok(packs) = crate::domains::discover_provider_packs(root, domain) {
            for pack in packs {
                out.entry(pack.pack_id).or_insert(pack.path);
            }
        }
    }
    for dir in [root.join("providers").join("state"), root.join("packs")] {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "gtpack") {
                continue;
            }
            if let Ok(meta) = crate::domains::read_pack_meta(&path)
                && meta.pack_id.starts_with("state-")
            {
                out.entry(meta.pack_id).or_insert(path);
            }
        }
    }
    out
}

fn check_runtime_metadata(
    ctx: &mut DoctorCtx<'_>,
    root: &Path,
    demo: Option<&(crate::bundle_config::DemoPaths, crate::config::DemoConfig)>,
) {
    let Some((_, config)) = demo else {
        return;
    };
    let paths = RuntimePaths::new(root.join("state"), &config.tenant, &config.team);
    for file in [
        "startup_contract.json",
        "endpoints.json",
        "services.json",
        "detected_domains.json",
        "detected_providers.json",
    ] {
        let path = paths.runtime_root().join(file);
        if !path.exists() {
            ctx.info(
                "start.runtime.metadata",
                DiagnosticComponent::Runtime,
                "Runtime metadata file is missing.",
                json!({ "file": path }),
            );
            continue;
        }
        match std::fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))
            .and_then(|raw| serde_json::from_str::<Value>(&raw).map_err(Into::into))
        {
            Ok(_) => ctx.info(
                "start.runtime.metadata",
                DiagnosticComponent::Runtime,
                "Runtime metadata file is valid JSON.",
                json!({ "file": path }),
            ),
            Err(err) => ctx.error(
                "start.runtime.metadata",
                DiagnosticComponent::Runtime,
                "Runtime metadata file is not valid JSON.",
                json!({ "file": path, "error": format!("{err:#}") }),
                (
                    json!({ "valid_json": true }),
                    json!({ "valid_json": false }),
                ),
                Some("Remove stale runtime state or rerun start after fixing setup/config issues."),
            ),
        }
    }
}

fn check_secret_requirements(ctx: &mut DoctorCtx<'_>, root: &Path) {
    let index = provider_pack_index(root);
    for (provider, pack) in index {
        match crate::secret_requirements::load_secret_keys_from_pack(&pack) {
            Ok(keys) if keys.is_empty() => {}
            Ok(keys) => ctx.info(
                "start.secrets.requirements",
                DiagnosticComponent::Provider,
                "Provider pack declares required secrets.",
                json!({ "provider": provider, "pack": pack, "keys": keys }),
            ),
            Err(err) => ctx.warn(
                "start.secrets.requirements",
                DiagnosticComponent::Provider,
                "Secret requirements could not be read from provider pack.",
                json!({ "provider": provider, "pack": pack, "error": format!("{err:#}") }),
                Some("Fix the pack archive or secret-requirements metadata."),
            ),
        }
    }
}

fn check_ports(ctx: &mut DoctorCtx<'_>, config: &crate::config::DemoConfig) {
    let addr = format!(
        "{}:{}",
        config.services.gateway.listen_addr, config.services.gateway.port
    );
    match TcpListener::bind(&addr) {
        Ok(listener) => {
            drop(listener);
            ctx.info(
                "start.ports.available",
                DiagnosticComponent::Runtime,
                "Gateway port is available.",
                json!({ "addr": addr }),
            );
        }
        Err(err) => ctx.warn(
            "start.ports.available",
            DiagnosticComponent::Runtime,
            "Gateway port is not currently bindable.",
            json!({ "addr": addr, "error": err.to_string() }),
            Some("Stop the process using this port, change GREENTIC_GATEWAY_PORT, or let startup use its port-cycling behavior if applicable."),
        ),
    }
}

fn print_human_report(report: &DoctorReport, fix_hints: bool, show_info: bool) {
    println!("greentic-start doctor");
    println!("  bundle: {}", report.bundle.input);
    if let Some(root) = report.bundle.resolved_root.as_ref() {
        println!("  root:   {}", root.display());
    }
    if show_info {
        println!(
            "  result: {} error(s), {} warning(s), {} info",
            report.summary.errors, report.summary.warnings, report.summary.infos
        );
    } else {
        println!(
            "  result: {} error(s), {} warning(s)",
            report.summary.errors, report.summary.warnings
        );
        println!("  hint:   pass --show-info to include successful checks");
    }
    println!();
    for diagnostic in &report.diagnostics {
        println!(
            "{} {} [{}]",
            severity_label(diagnostic.severity),
            diagnostic.check_id,
            component_label(diagnostic.component)
        );
        println!("  {}", diagnostic.message);
        if diagnostic.evidence != Value::Null && diagnostic.evidence != json!({}) {
            println!("  evidence: {}", compact_json(&diagnostic.evidence));
        }
        if diagnostic.expected != Value::Null {
            println!("  expected: {}", compact_json(&diagnostic.expected));
        }
        if diagnostic.actual != Value::Null {
            println!("  actual: {}", compact_json(&diagnostic.actual));
        }
        if let Some(file) = diagnostic.related_file.as_ref() {
            println!("  file: {}", file.display());
        }
        if let Some(pack) = diagnostic.related_pack.as_ref() {
            println!("  pack: {pack}");
        }
        if fix_hints && let Some(hint) = diagnostic.fix_hint.as_ref() {
            println!("  fix: {hint}");
        }
        println!();
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warn => "warn",
        Severity::Info => "info",
    }
}

fn component_label(component: DiagnosticComponent) -> &'static str {
    match component {
        DiagnosticComponent::Setup => "setup",
        DiagnosticComponent::Start => "start",
        DiagnosticComponent::Cache => "cache",
        DiagnosticComponent::Lock => "lock",
        DiagnosticComponent::Answers => "answers",
        DiagnosticComponent::Routes => "routes",
        DiagnosticComponent::Runtime => "runtime",
        DiagnosticComponent::Provider => "provider",
    }
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unprintable>".to_string())
}
