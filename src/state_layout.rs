#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domains::Domain;

pub fn run_dir(
    root: &Path,
    domain: Domain,
    pack_label: &str,
    flow_id: &str,
) -> anyhow::Result<PathBuf> {
    let timestamp = timestamp_secs()?;
    let domain_name = domain_name(domain);
    Ok(root
        .join("state")
        .join("runs")
        .join(domain_name)
        .join(pack_label)
        .join(flow_id)
        .join(format!("{timestamp}")))
}

pub fn secrets_log_path(root: &Path, action: &str) -> anyhow::Result<PathBuf> {
    let timestamp = timestamp_secs()?;
    Ok(root
        .join("state")
        .join("logs")
        .join("secrets")
        .join(format!("{action}-{timestamp}.log")))
}

fn domain_name(domain: Domain) -> &'static str {
    match domain {
        Domain::Messaging => "messaging",
        Domain::Events => "events",
        Domain::Secrets => "secrets",
        Domain::OAuth => "oauth",
    }
}

fn timestamp_secs() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| anyhow::anyhow!("timestamp error: {err}"))?
        .as_secs())
}
