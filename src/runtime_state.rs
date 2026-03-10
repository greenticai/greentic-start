#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub struct RuntimePaths {
    state_dir: PathBuf,
    log_root: PathBuf,
    tenant: String,
    team: String,
}

impl RuntimePaths {
    pub fn new(
        state_dir: impl Into<PathBuf>,
        tenant: impl Into<String>,
        team: impl Into<String>,
    ) -> Self {
        let state_dir = state_dir.into();
        let log_root = state_dir
            .parent()
            .map(|parent| parent.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
            .join("logs");
        Self {
            state_dir,
            log_root,
            tenant: tenant.into(),
            team: team.into(),
        }
    }

    pub fn key(&self) -> String {
        format!("{}.{}", self.tenant, self.team)
    }

    pub fn runtime_root(&self) -> PathBuf {
        self.state_dir.join("runtime").join(self.key())
    }

    pub fn pids_dir(&self) -> PathBuf {
        self.state_dir.join("pids").join(self.key())
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.log_root.join(self.key())
    }

    pub fn dlq_log_path(&self) -> PathBuf {
        self.logs_dir().join("dlq.log")
    }

    pub fn resolved_dir(&self) -> PathBuf {
        self.runtime_root().join("resolved")
    }

    pub fn pid_path(&self, service_id: &str) -> PathBuf {
        self.pids_dir().join(format!("{service_id}.pid"))
    }

    pub fn log_path(&self, service_id: &str) -> PathBuf {
        self.logs_dir().join(format!("{service_id}.log"))
    }

    pub fn resolved_path(&self, service_id: &str) -> PathBuf {
        self.resolved_dir().join(format!("{service_id}.json"))
    }

    pub fn logs_root(&self) -> PathBuf {
        self.log_root.clone()
    }

    pub fn service_manifest_path(&self) -> PathBuf {
        self.runtime_root().join("services.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logs_dir_uses_bundle_logs() {
        let paths = RuntimePaths::new("/tmp/bundle/state", "demo", "default");
        assert_eq!(
            paths.logs_dir(),
            PathBuf::from("/tmp/bundle/logs").join("demo.default")
        );
    }
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    atomic_write(path, &bytes)
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> anyhow::Result<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(path)?;
    let value = serde_json::from_slice(&data)?;
    Ok(Some(value))
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = path.to_path_buf();
    tmp.set_extension("tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceManifest {
    #[serde(default)]
    pub log_dir: Option<String>,
    #[serde(default)]
    pub services: Vec<ServiceEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub id: String,
    pub kind: String,
    pub log_path: Option<String>,
}

impl ServiceEntry {
    pub fn new(id: impl Into<String>, kind: impl Into<String>, log_path: Option<&Path>) -> Self {
        Self {
            id: id.into(),
            kind: kind.into(),
            log_path: log_path.map(|path| path.display().to_string()),
        }
    }
}

pub fn persist_service_manifest(
    paths: &RuntimePaths,
    manifest: &ServiceManifest,
) -> anyhow::Result<()> {
    write_json(&paths.service_manifest_path(), manifest)
}

pub fn read_service_manifest(paths: &RuntimePaths) -> anyhow::Result<Option<ServiceManifest>> {
    read_json(&paths.service_manifest_path())
}

pub fn remove_service_manifest(paths: &RuntimePaths) -> anyhow::Result<()> {
    let path = paths.service_manifest_path();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
