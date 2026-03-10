use std::path::{Path, PathBuf};

use greentic_runner_desktop::{RunOptions, RunResult, TenantContext};
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
