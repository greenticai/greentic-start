use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::Context;
use chrono::Utc;
use greentic_runner_desktop::{NodeFailure, NodeStatus, NodeSummary, RunResult, RunStatus};
use greentic_runner_host::RunnerWasiPolicy;
use greentic_runner_host::config::{
    FlowRetryConfig, HostConfig, OperatorPolicy, RateLimits, SecretsPolicy, StateStorePolicy,
    WebhookPolicy,
};
use greentic_runner_host::pack::{ComponentResolution, PackRuntime};
use greentic_runner_host::runner::engine::{
    ExecutionObserver, FlowContext, FlowEngine, FlowStatus, NodeEvent,
};
use greentic_runner_host::secrets::default_manager;
use greentic_runner_host::storage::{new_session_store, new_state_store};
use greentic_runner_host::trace::TraceConfig;
use greentic_runner_host::validate::ValidationConfig;
use serde_json::Value as JsonValue;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::domains::Domain;
use crate::secret_requirements::load_secret_keys_from_pack;
use crate::secrets_client::SecretsClient;
use crate::secrets_gate::canonical_secret_uri;
use crate::secrets_setup::resolve_env;
use crate::state_layout;

pub struct RunOutput {
    pub result: RunResult,
    pub run_dir: PathBuf,
}

pub struct RunRequest {
    pub root: PathBuf,
    pub domain: Domain,
    pub pack_path: PathBuf,
    pub pack_label: String,
    pub flow_id: String,
    pub tenant: String,
    pub team: Option<String>,
    pub input: JsonValue,
    pub dist_offline: bool,
}

pub fn run_provider_pack_flow(request: RunRequest) -> anyhow::Result<RunOutput> {
    // Ensure flow.log is initialized in bundle's logs directory
    let _ = crate::flow_log::init(&request.root.join("logs"));

    let run_dir = state_layout::run_dir(
        &request.root,
        request.domain,
        &request.pack_label,
        &request.flow_id,
    )?;
    std::fs::create_dir_all(&run_dir)?;
    let input_path = run_dir.join("input.json");
    let input_json = serde_json::to_string_pretty(&request.input)?;
    std::fs::write(&input_path, input_json)?;

    let log_pack = request.pack_label.clone();
    let log_flow = request.flow_id.clone();
    let log_tenant = request.tenant.clone();
    let log_team = request.team.as_deref().unwrap_or("default").to_string();

    // Extract user input for logging
    let user_text = request
        .input
        .pointer("/input/text")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let user_verb = request
        .input
        .pointer("/input/metadata/verb")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let user_from = request
        .input
        .pointer("/input/from/id")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();

    let input_summary = if !user_verb.is_empty() {
        format!("verb={user_verb}")
    } else if !user_text.is_empty() {
        let truncated = if user_text.len() > 80 {
            format!("{}...", &user_text[..80])
        } else {
            user_text.clone()
        };
        format!("text=\"{truncated}\"")
    } else {
        "empty".to_string()
    };

    crate::flow_log::flow_start(&log_pack, &log_flow, &log_tenant, &log_team);
    crate::flow_log::log(
        "INPUT",
        &format!("pack={log_pack} flow={log_flow} from={user_from} {input_summary}"),
    );

    let result = run_pack_flow_direct(&request, &run_dir)?;

    // Log node-level execution trace
    for node in &result.node_summaries {
        crate::flow_log::log(
            "NODE",
            &format!(
                "pack={log_pack} flow={log_flow} node={} component={} status={:?} duration={}ms",
                node.node_id, node.component, node.status, node.duration_ms,
            ),
        );
    }

    crate::flow_log::flow_end(
        &log_pack,
        &log_flow,
        &log_tenant,
        &log_team,
        result.status == RunStatus::Success,
        result.error.as_deref(),
    );

    write_run_artifacts(&run_dir, &result)?;

    Ok(RunOutput { result, run_dir })
}

fn make_runtime_or_thread_scope<F, T>(f: F) -> T
where
    F: FnOnce(&tokio::runtime::Runtime) -> T + Send,
    T: Send,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::scope(|s| {
            s.spawn(|| {
                let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
                f(&rt)
            })
            .join()
            .expect("runner_exec runtime thread panicked")
        })
    } else {
        let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
        f(&rt)
    }
}

fn run_pack_flow_direct(request: &RunRequest, run_dir: &Path) -> anyhow::Result<RunResult> {
    let started_at = Utc::now();
    let flow_observer = Arc::new(NodeObserver::default());
    let host_config = Arc::new(build_demo_host_config(&request.tenant));
    let archive_source = request
        .pack_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("gtpack"))
        .unwrap_or(false)
        .then_some(request.pack_path.as_path());
    let mut component_resolution = ComponentResolution::default();
    if request.pack_path.is_dir() {
        component_resolution.materialized_root = Some(request.pack_path.clone());
    }
    component_resolution.dist_offline = request.dist_offline;
    let wasi_policy = build_pack_wasi_policy(request)?;

    let execution = make_runtime_or_thread_scope(|runtime| {
        runtime.block_on(async {
            let pack = Arc::new(
                PackRuntime::load(
                    &request.pack_path,
                    Arc::clone(&host_config),
                    None,
                    archive_source,
                    Some(new_session_store()),
                    Some(new_state_store()),
                    Arc::new(wasi_policy),
                    default_manager().context("failed to initialise secrets backend")?,
                    host_config.oauth_broker_config(),
                    false,
                    component_resolution,
                )
                .await
                .with_context(|| format!("failed to load pack {}", request.pack_path.display()))?,
            );

            let engine = FlowEngine::new(vec![Arc::clone(&pack)], Arc::clone(&host_config))
                .await
                .context("failed to prime flow engine")?;
            let retry_config = host_config.retry.clone().into();
            let team = request.team.as_deref().unwrap_or("default");
            let session_id = format!("{}:{}:{}", request.tenant, team, Uuid::new_v4());
            let ctx = FlowContext {
                tenant: request.tenant.as_str(),
                pack_id: pack.metadata().pack_id.as_str(),
                flow_id: request.flow_id.as_str(),
                node_id: None,
                tool: None,
                action: None,
                session_id: Some(session_id.as_str()),
                provider_id: None,
                retry_config,
                attempt: 1,
                observer: Some(flow_observer.as_ref()),
                mocks: None,
            };
            let execution = engine.execute(ctx, request.input.clone()).await;
            anyhow::Ok((pack, execution, session_id))
        })
    })?;

    let finished_at = Utc::now();
    let (pack, execution, session_id) = execution;
    let (status, error, transcript_outputs) = match execution {
        Ok(execution) => match execution.status {
            FlowStatus::Completed => (RunStatus::Success, None, execution.output),
            FlowStatus::Waiting(wait) => (
                RunStatus::Failure,
                Some(format!(
                    "flow paused unexpectedly: {}",
                    wait.reason.unwrap_or_else(|| "unknown".to_string())
                )),
                execution.output,
            ),
        },
        Err(err) => (RunStatus::Failure, Some(err.to_string()), JsonValue::Null),
    };

    write_transcript(run_dir, &transcript_outputs)?;
    let (node_summaries, node_failures) = flow_observer.finish();
    let mut failures = node_failures;
    if let Some(error_message) = error.clone() {
        failures.insert(
            "_runtime".to_string(),
            NodeFailure {
                code: "runtime-error".to_string(),
                message: error_message,
                details: json!({ "stage": "execute" }),
                transcript_offsets: (0, 0),
                log_paths: Vec::new(),
            },
        );
    }

    Ok(RunResult {
        session_id,
        pack_id: pack.metadata().pack_id.clone(),
        pack_version: pack.metadata().version.clone(),
        flow_id: request.flow_id.clone(),
        started_at_utc: started_at.to_rfc3339(),
        finished_at_utc: finished_at.to_rfc3339(),
        status,
        error,
        node_summaries,
        failures,
        artifacts_dir: run_dir.to_path_buf(),
    })
}

fn build_pack_wasi_policy(request: &RunRequest) -> anyhow::Result<RunnerWasiPolicy> {
    let secret_keys = load_secret_keys_from_pack(&request.pack_path).with_context(|| {
        format!(
            "failed to load secret requirements from {}",
            request.pack_path.display()
        )
    })?;
    let mut policy = RunnerWasiPolicy::default();
    if secret_keys.is_empty() {
        return Ok(policy);
    }

    let secrets = SecretsClient::open(&request.root).with_context(|| {
        format!(
            "failed to open secrets store for {}",
            request.root.display()
        )
    })?;
    let env = resolve_env(None);
    for key in secret_keys {
        let uri = canonical_secret_uri(
            &env,
            &request.tenant,
            request.team.as_deref(),
            &request.pack_label,
            &key,
        );
        let value = match make_runtime_or_thread_scope(|runtime| {
            runtime.block_on(async { greentic_secrets_lib::SecretsManager::read(&secrets, &uri).await })
        })
        {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(value) => value,
                Err(_) => continue,
            },
            Err(_) => continue,
        };
        policy = policy.with_env(mcp_secret_env_name(&key), value);
    }

    Ok(policy)
}

fn build_demo_host_config(tenant: &str) -> HostConfig {
    HostConfig {
        tenant: tenant.to_string(),
        bindings_path: PathBuf::from("<demo-provider>"),
        flow_type_bindings: HashMap::new(),
        rate_limits: RateLimits::default(),
        retry: FlowRetryConfig::default(),
        http_enabled: true,
        secrets_policy: SecretsPolicy::allow_all(),
        state_store_policy: StateStorePolicy::default(),
        webhook_policy: WebhookPolicy::default(),
        timers: Vec::new(),
        oauth: None,
        mocks: None,
        pack_bindings: Vec::new(),
        env_passthrough: Vec::new(),
        trace: TraceConfig::from_env(),
        validation: ValidationConfig::from_env(),
        operator_policy: OperatorPolicy::allow_all(),
    }
}

fn write_transcript(run_dir: &Path, outputs: &JsonValue) -> anyhow::Result<()> {
    let path = run_dir.join("transcript.jsonl");
    let line = serde_json::to_string(&json!({ "outputs": outputs }))?;
    std::fs::write(path, format!("{line}\n"))?;
    Ok(())
}

fn mcp_secret_env_name(key: &str) -> String {
    let mut out = String::from("MCP_SECRET_");
    let mut prev_underscore = true;
    for ch in key.chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_uppercase()
        } else {
            '_'
        };
        if normalized == '_' {
            if prev_underscore {
                continue;
            }
            prev_underscore = true;
        } else {
            prev_underscore = false;
        }
        out.push(normalized);
    }
    if out.ends_with('_') {
        out.pop();
    }
    out
}

#[derive(Default)]
struct NodeObserver {
    state: Mutex<NodeObserverState>,
}

#[derive(Default)]
struct NodeObserverState {
    order: Vec<String>,
    records: HashMap<String, NodeObserverRecord>,
}

struct NodeObserverRecord {
    component: String,
    started_at: Instant,
    duration_ms: u64,
    status: NodeStatus,
    error: Option<String>,
}

impl ExecutionObserver for NodeObserver {
    fn on_node_start(&self, event: &NodeEvent<'_>) {
        let mut state = self.state.lock().expect("node observer state poisoned");
        let node_id = event.node_id.to_string();
        if !state.records.contains_key(&node_id) {
            state.order.push(node_id.clone());
        }
        state.records.insert(
            node_id,
            NodeObserverRecord {
                component: event.node.component.clone(),
                started_at: Instant::now(),
                duration_ms: 0,
                status: NodeStatus::Ok,
                error: None,
            },
        );
    }

    fn on_node_end(&self, event: &NodeEvent<'_>, _output: &JsonValue) {
        let mut state = self.state.lock().expect("node observer state poisoned");
        if let Some(record) = state.records.get_mut(event.node_id) {
            record.duration_ms = record.started_at.elapsed().as_millis() as u64;
            record.status = NodeStatus::Ok;
        }
    }

    fn on_node_error(&self, event: &NodeEvent<'_>, error: &dyn std::error::Error) {
        let mut state = self.state.lock().expect("node observer state poisoned");
        if let Some(record) = state.records.get_mut(event.node_id) {
            record.duration_ms = record.started_at.elapsed().as_millis() as u64;
            record.status = NodeStatus::Error;
            record.error = Some(error.to_string());
        }
    }
}

impl NodeObserver {
    fn finish(&self) -> (Vec<NodeSummary>, BTreeMap<String, NodeFailure>) {
        let mut summaries = Vec::new();
        let mut failures = BTreeMap::new();
        let state = self.state.lock().expect("node observer state poisoned");
        for node_id in &state.order {
            let Some(record) = state.records.get(node_id) else {
                continue;
            };
            summaries.push(NodeSummary {
                node_id: node_id.clone(),
                component: record.component.clone(),
                status: record.status.clone(),
                duration_ms: record.duration_ms,
            });
            if let Some(message) = &record.error {
                failures.insert(
                    node_id.clone(),
                    NodeFailure {
                        code: "component-failed".to_string(),
                        message: message.clone(),
                        details: json!({ "node": node_id }),
                        transcript_offsets: (0, 0),
                        log_paths: Vec::new(),
                    },
                );
            }
        }
        (summaries, failures)
    }
}

fn write_run_artifacts(run_dir: &Path, result: &RunResult) -> anyhow::Result<()> {
    let run_json = run_dir.join("run.json");
    let summary_path = run_dir.join("summary.txt");
    let artifacts_path = run_dir.join("artifacts_dir");

    let json = serde_json::to_string_pretty(result)?;
    std::fs::write(run_json, json)?;

    let summary = format!(
        "status: {:?}\npack_id: {}\nflow_id: {}\nerror: {}\n",
        result.status,
        result.pack_id,
        result.flow_id,
        result.error.clone().unwrap_or_else(|| "none".to_string())
    );
    std::fs::write(summary_path, summary)?;
    std::fs::write(artifacts_path, result.artifacts_dir.display().to_string())?;

    Ok(())
}
