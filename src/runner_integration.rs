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
            if let Some(tenant) = options.tenant {
                command.args(["--tenant", tenant]);
            }
            if let Some(team) = options.team {
                command.args(["--team", team]);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_runner_flavor_uses_binary_name() {
        assert_eq!(
            detect_runner_flavor(Path::new("/tmp/greentic-runner-cli")),
            RunnerFlavor::RunnerCli
        );
        assert_eq!(
            detect_runner_flavor(Path::new("/tmp/greentic-runner")),
            RunnerFlavor::RunSubcommand
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_flow_with_options_executes_runner_variants_and_parses_stdout() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let runner = dir.path().join("runner.sh");
        let pack = dir.path().join("pack.gtpack");
        std::fs::write(&pack, b"pack").expect("pack");
        std::fs::write(&runner, b"#!/bin/sh\nprintf '{\"argv\":\"%s\"}' \"$*\"\n").expect("script");
        let mut perms = std::fs::metadata(&runner).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&runner, perms).expect("chmod");

        let output = run_flow_with_options(
            &runner,
            &pack,
            "default",
            &serde_json::json!({"ok": true}),
            RunFlowOptions {
                dist_offline: true,
                tenant: Some("demo"),
                team: Some("ops"),
                artifacts_dir: Some(dir.path()),
                runner_flavor: RunnerFlavor::RunnerCli,
            },
        )
        .expect("runner cli");
        assert!(output.status.success());
        assert!(output.stdout.contains("--pack"));
        assert!(output.stdout.contains("--tenant demo"));
        assert!(output.stdout.contains("--team ops"));
        assert!(output.stdout.contains("--artifacts-dir"));
        assert!(output.stdout.contains("--offline"));

        let output = run_flow(&runner, &pack, "default", &serde_json::json!({"ok": true}))
            .expect("run subcommand");
        assert!(output.status.success());
        assert!(output.stdout.contains("run --pack"));
        assert!(output.stdout.contains("--flow default"));

        let output = run_flow_with_options(
            &runner,
            &pack,
            "default",
            &serde_json::json!({"ok": true}),
            RunFlowOptions {
                dist_offline: true,
                tenant: Some("demo"),
                team: Some("ops"),
                artifacts_dir: None,
                runner_flavor: RunnerFlavor::RunSubcommand,
            },
        )
        .expect("run subcommand with context");
        assert!(output.status.success());
        assert!(output.stdout.contains("run --pack"));
        assert!(output.stdout.contains("--tenant demo"));
        assert!(output.stdout.contains("--team ops"));
        assert!(output.stdout.contains("--offline"));
    }
}
