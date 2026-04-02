use std::path::{Path, PathBuf};

use greentic_runner_desktop::{RunOptions, RunResult, RunStatus, TenantContext};
use serde_json::Value as JsonValue;

use crate::domains::Domain;
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

    let opts = RunOptions {
        entry_flow: Some(request.flow_id.clone()),
        input: request.input,
        ctx: TenantContext {
            tenant_id: Some(request.tenant),
            team_id: request.team,
            user_id: Some("operator".to_string()),
            session_id: None,
        },
        dist_offline: request.dist_offline,
        artifacts_dir: Some(run_dir.clone()),
        ..RunOptions::default()
    };

    let result = greentic_runner_desktop::run_pack_with_options(&request.pack_path, opts)?;

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
