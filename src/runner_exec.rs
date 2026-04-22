use std::path::{Path, PathBuf};

use anyhow::Context;
use greentic_runner_desktop::{
    DevProfile, MocksConfig, Profile, RunOptions, RunResult, RunStatus, SigningPolicy,
    TenantContext,
};
use serde_json::Value as JsonValue;

use crate::domains::Domain;
use crate::secrets_gate;
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

    let secrets_handle = secrets_gate::resolve_secrets_manager(
        &request.root,
        &request.tenant,
        request.team.as_deref(),
    )
    .with_context(|| {
        format!(
            "resolve secrets manager for tenant={} team={}",
            request.tenant,
            request.team.as_deref().unwrap_or("default")
        )
    })?;

    let team = request
        .team
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let opts = RunOptions {
        profile: Profile::Dev(DevProfile {
            tenant_id: request.tenant.clone(),
            team_id: team.clone(),
            user_id: "developer".to_string(),
            ..DevProfile::default()
        }),
        entry_flow: Some(request.flow_id.clone()),
        input: request.input,
        ctx: TenantContext {
            tenant_id: Some(request.tenant),
            team_id: Some(team),
            user_id: Some("developer".to_string()),
            session_id: None,
        },
        mocks: MocksConfig {
            net_allowlist: vec!["127.0.0.1".to_string(), "localhost".to_string()],
            ..MocksConfig::default()
        },
        artifacts_dir: Some(run_dir.clone()),
        signing: SigningPolicy::DevOk,
        dist_offline: request.dist_offline,
        allow_missing_hash: false,
        secrets_manager: Some(secrets_handle.runtime_manager(Some(&request.pack_label))),
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

#[cfg(test)]
mod tests {
    use super::{RunRequest, run_provider_pack_flow};
    use crate::domains::Domain;
    use serde_json::Value;
    use std::path::PathBuf;

    #[test]
    #[ignore = "requires local /tmp ollama repro artifacts"]
    fn local_ollama_repro_stays_on_ollama_path() {
        let bundle = PathBuf::from("/tmp/ollama-runtime-bundle");
        let pack_path = bundle.join("packs/pack.gtpack");
        let input_path =
            bundle.join("state/runs/messaging/ollama-runtime-repro/main/1776707368/input.json");
        let input: Value =
            serde_json::from_slice(&std::fs::read(&input_path).expect("read captured input.json"))
                .expect("parse captured input.json");

        let output = run_provider_pack_flow(RunRequest {
            root: bundle.clone(),
            domain: Domain::Messaging,
            pack_path,
            pack_label: "ollama-runtime-repro".to_string(),
            flow_id: "main".to_string(),
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            input,
            dist_offline: true,
        })
        .expect("run provider pack flow");

        let error = output.result.error.unwrap_or_default();
        assert!(
            error.contains("OLLAMA_API_KEY"),
            "expected ollama secret failure, got: {error}"
        );
        assert!(
            !error.contains("provider Openai requires an API key"),
            "unexpected openai fallback: {error}"
        );
    }

    #[test]
    #[ignore = "requires local /tmp deep-research repro artifacts"]
    fn local_deep_research_repro_stays_on_ollama_path() {
        let bundle = PathBuf::from("/tmp/deep-research-retest-bundle");
        let pack_path = bundle.join("packs/deep-research-demo.gtpack");
        let input_path =
            bundle.join("state/runs/messaging/deep-research-demo/main/1776805260/input.json");
        let input: Value =
            serde_json::from_slice(&std::fs::read(&input_path).expect("read captured input.json"))
                .expect("parse captured input.json");

        let output = run_provider_pack_flow(RunRequest {
            root: bundle.clone(),
            domain: Domain::Messaging,
            pack_path,
            pack_label: "deep-research-demo".to_string(),
            flow_id: "main".to_string(),
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            input,
            dist_offline: true,
        })
        .expect("run provider pack flow");

        assert_eq!(
            output.result.status,
            greentic_runner_desktop::RunStatus::Success
        );

        let transcript =
            std::fs::read_to_string(output.run_dir.join("transcript.jsonl")).expect("transcript");
        assert!(
            transcript.contains("\"provider\":\"ollama\""),
            "expected ollama provider in transcript, got: {transcript}"
        );
        assert!(
            transcript.contains("\"default_model\":\"llama3:8b\""),
            "expected default_model in transcript, got: {transcript}"
        );
        assert!(
            !transcript.contains("provider Openai requires an API key"),
            "unexpected openai fallback in transcript: {transcript}"
        );
    }
}
