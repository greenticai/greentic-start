#![allow(dead_code)]

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::runtime_state;

pub use greentic_types::messaging::universal_dto::AuthUserRefV1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionState {
    pub binding_id: String,
    pub provider: String,
    pub tenant: String,
    pub team: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub change_types: Vec<String>,
    #[serde(default)]
    pub notification_url: Option<String>,
    #[serde(default)]
    pub client_state: Option<String>,
    #[serde(default)]
    pub user: Option<AuthUserRefV1>,
    #[serde(default)]
    pub subscription_id: Option<String>,
    #[serde(default)]
    pub expiration_unix_ms: Option<i64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
impl SubscriptionState {
    pub fn from_provider_result(
        provider: &str,
        tenant: &str,
        team: Option<String>,
        binding_id: &str,
        resource: Option<&String>,
        change_types: &[String],
        notification_url: Option<&String>,
        client_state: Option<&String>,
        user: Option<&AuthUserRefV1>,
        response: Option<&Value>,
    ) -> Self {
        let payload = flatten_subscription_response(response);
        let subscription_id = payload
            .and_then(|value| value.get("subscription_id"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());
        let expiration_unix_ms = payload
            .and_then(|value| value.get("expiration_unix_ms"))
            .and_then(|value| value.as_i64());
        let last_error = payload
            .and_then(|value| value.get("last_error"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());
        Self {
            binding_id: binding_id.to_string(),
            provider: provider.to_string(),
            tenant: tenant.to_string(),
            team,
            resource: resource.cloned(),
            change_types: change_types.to_vec(),
            notification_url: notification_url.cloned(),
            client_state: client_state.cloned(),
            user: user.cloned(),
            subscription_id,
            expiration_unix_ms,
            last_error,
        }
    }
}

fn flatten_subscription_response(response: Option<&Value>) -> Option<&Value> {
    let source = response?;
    source.get("subscription").or(Some(source))
}

#[derive(Clone)]
pub struct SubscriptionStore {
    base: PathBuf,
}

impl SubscriptionStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    pub fn state_path(
        &self,
        provider: &str,
        tenant: &str,
        team: Option<&str>,
        binding_id: &str,
    ) -> PathBuf {
        let team_dir = team.unwrap_or("default");
        self.base
            .join(provider)
            .join(tenant)
            .join(team_dir)
            .join(format!("{binding_id}.json"))
    }

    pub fn write_state(&self, state: &SubscriptionState) -> Result<()> {
        let path = self.state_path(
            &state.provider,
            &state.tenant,
            state.team.as_deref(),
            &state.binding_id,
        );
        runtime_state::write_json(&path, state)
            .with_context(|| format!("failed to write subscription state to {path:?}"))
    }

    pub fn read_state(
        &self,
        provider: &str,
        tenant: &str,
        team: Option<&str>,
        binding_id: &str,
    ) -> Result<Option<SubscriptionState>> {
        let path = self.state_path(provider, tenant, team, binding_id);
        runtime_state::read_json(&path)
            .with_context(|| format!("failed to read subscription state from {path:?}"))
    }

    pub fn list_states(&self) -> Result<Vec<SubscriptionState>> {
        let mut states = Vec::new();
        if !self.base.exists() {
            return Ok(states);
        }
        self.collect_states(&self.base, &mut states)?;
        Ok(states)
    }

    #[allow(clippy::collapsible_if)]
    #[allow(clippy::only_used_in_recursion)]
    fn collect_states(&self, dir: &PathBuf, states: &mut Vec<SubscriptionState>) -> Result<()> {
        for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                self.collect_states(&path, states)?;
            } else if path
                .extension()
                .and_then(|value| value.to_str())
                .map(|value| value.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
            {
                if let Some(state) = runtime_state::read_json(&path)? {
                    states.push(state);
                }
            }
        }
        Ok(())
    }

    pub fn delete_state(&self, state: &SubscriptionState) -> Result<()> {
        let path = self.state_path(
            &state.provider,
            &state.tenant,
            state.team.as_deref(),
            &state.binding_id,
        );
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to delete {}", path.display()))?;
        }
        Ok(())
    }
}
