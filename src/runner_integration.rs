#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerFlavor {
    RunSubcommand,
    RunnerCli,
}

pub struct RunFlowOptions<'a> {
    pub dist_offline: bool,
    pub tenant: Option<&'a str>,
    pub team: Option<&'a str>,
    pub artifacts_dir: Option<&'a Path>,
    pub runner_flavor: RunnerFlavor,
}

pub struct RunnerOutput {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub parsed: Option<Value>,
}

pub fn run_flow(
    runner: &Path,
    pack: &Path,
    flow: &str,
    input: &Value,
) -> anyhow::Result<RunnerOutput> {
    run_flow_with_options(
        runner,
        pack,
        flow,
        input,
        RunFlowOptions {
            dist_offline: false,
            tenant: None,
            team: None,
            artifacts_dir: None,
            runner_flavor: RunnerFlavor::RunSubcommand,
        },
    )
}

pub fn run_flow_with_options(
    runner: &Path,
    pack: &Path,
    flow: &str,
    input: &Value,
    options: RunFlowOptions<'_>,
) -> anyhow::Result<RunnerOutput> {
    let input_str = serde_json::to_string(input)?;
    let mut command = Command::new(runner);
    match options.runner_flavor {
        RunnerFlavor::RunSubcommand => {
            command
                .args(["run", "--pack"])
                .arg(pack)
                .args(["--flow", flow, "--input"])
                .arg(&input_str);
            if options.dist_offline {
                command.arg("--offline");
            }
        }
        RunnerFlavor::RunnerCli => {
            command
                .arg("--pack")
                .arg(pack)
                .args(["--flow", flow, "--input"])
                .arg(&input_str);
            if let Some(tenant) = options.tenant {
                command.args(["--tenant", tenant]);
            }
            if let Some(team) = options.team {
                command.args(["--team", team]);
            }
            if let Some(artifacts_dir) = options.artifacts_dir {
                command.arg("--artifacts-dir").arg(artifacts_dir);
            }
            if options.dist_offline {
                command.arg("--offline");
            }
        }
    }
    let output = command.output()?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let parsed = serde_json::from_str(&stdout).ok();

    Ok(RunnerOutput {
        status: output.status,
        stdout,
        stderr,
        parsed,
    })
}

pub fn detect_runner_flavor(runner: &Path) -> RunnerFlavor {
    let name = runner
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if name.contains("runner-cli") {
        RunnerFlavor::RunnerCli
    } else {
        RunnerFlavor::RunSubcommand
    }
}
