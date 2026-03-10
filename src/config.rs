#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, Default)]
pub struct OperatorConfig {
    #[serde(default)]
    pub services: Option<OperatorServicesConfig>,
    #[serde(default)]
    pub binaries: BTreeMap<String, String>,
}
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainEnabledMode {
    #[default]
    Auto,
    True,
    False,
}

impl DomainEnabledMode {
    pub fn is_enabled(self, has_providers: bool) -> bool {
        match self {
            Self::Auto => has_providers,
            Self::True => true,
            Self::False => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct OperatorServicesConfig {
    #[serde(default)]
    pub messaging: DomainServicesConfig,
    #[serde(default)]
    pub events: DomainServicesConfig,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct DomainServicesConfig {
    #[serde(default)]
    pub enabled: DomainEnabledMode,
    #[serde(default)]
    pub components: Vec<ServiceComponentConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceComponentConfig {
    pub id: String,
    pub binary: String,
    #[serde(default)]
    pub args: Vec<String>,
}

pub fn load_operator_config(root: &Path) -> anyhow::Result<Option<OperatorConfig>> {
    let path = root.join("greentic.yaml");
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path)?;
    if contents
        .lines()
        .all(|line| line.trim().is_empty() || line.trim().starts_with('#'))
    {
        return Ok(None);
    }
    let config: OperatorConfig = serde_yaml_bw::from_str(&contents)?;
    Ok(Some(config))
}

pub fn binary_override(
    config: Option<&OperatorConfig>,
    name: &str,
    config_dir: &Path,
) -> Option<PathBuf> {
    config.and_then(|config| config_binary_path(config, name, config_dir))
}

#[derive(Clone, Debug, Deserialize)]
pub struct DemoConfig {
    #[serde(default = "default_demo_tenant")]
    pub tenant: String,
    #[serde(default = "default_demo_team")]
    pub team: String,
    #[serde(default)]
    pub services: DemoServicesConfig,
    #[serde(default)]
    pub providers: Option<std::collections::BTreeMap<String, DemoProviderConfig>>,
}

impl Default for DemoConfig {
    fn default() -> Self {
        Self {
            tenant: default_demo_tenant(),
            team: default_demo_team(),
            services: DemoServicesConfig::default(),
            providers: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct DemoServicesConfig {
    #[serde(default)]
    pub nats: DemoNatsConfig,
    #[serde(default)]
    pub gateway: DemoGatewayConfig,
    #[serde(default)]
    pub egress: DemoEgressConfig,
    #[serde(default)]
    pub subscriptions: DemoSubscriptionsConfig,
    #[serde(default)]
    pub events: DemoEventsConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DemoNatsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_nats_url")]
    pub url: String,
    #[serde(default)]
    pub spawn: DemoNatsSpawnConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DemoNatsSpawnConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_nats_binary")]
    pub binary: String,
    #[serde(default = "default_nats_args")]
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DemoGatewayConfig {
    #[serde(default = "default_gateway_binary")]
    pub binary: String,
    #[serde(default = "default_gateway_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_gateway_port")]
    pub port: u16,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DemoEgressConfig {
    #[serde(default = "default_egress_binary")]
    pub binary: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DemoSubscriptionsConfig {
    #[serde(default = "default_subscriptions_mode")]
    pub mode: DemoSubscriptionsMode,
    #[serde(default)]
    pub universal: DemoSubscriptionsUniversalConfig,
    #[serde(default)]
    pub msgraph: DemoMsgraphSubscriptionsConfig,
}

impl Default for DemoSubscriptionsConfig {
    fn default() -> Self {
        Self {
            mode: default_subscriptions_mode(),
            universal: DemoSubscriptionsUniversalConfig::default(),
            msgraph: DemoMsgraphSubscriptionsConfig::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DemoSubscriptionsMode {
    #[default]
    LegacyGsm,
    UniversalOps,
}

fn default_subscriptions_mode() -> DemoSubscriptionsMode {
    DemoSubscriptionsMode::LegacyGsm
}

#[derive(Clone, Debug, Deserialize)]
pub struct DemoSubscriptionsUniversalConfig {
    #[serde(default = "default_universal_renew_interval")]
    pub renew_interval_seconds: u64,
    #[serde(default = "default_universal_renew_skew")]
    pub renew_skew_minutes: u64,
    #[serde(default)]
    pub desired: Vec<DemoDesiredSubscription>,
}

impl Default for DemoSubscriptionsUniversalConfig {
    fn default() -> Self {
        Self {
            renew_interval_seconds: default_universal_renew_interval(),
            renew_skew_minutes: default_universal_renew_skew(),
            desired: Vec::new(),
        }
    }
}

fn default_universal_renew_interval() -> u64 {
    60
}

fn default_universal_renew_skew() -> u64 {
    10
}

#[derive(Clone, Debug, Deserialize)]
pub struct DemoDesiredSubscription {
    pub provider: String,
    pub resource: String,
    #[serde(default = "default_change_types")]
    pub change_types: Vec<String>,
    #[serde(default)]
    pub notification_url: Option<String>,
    #[serde(default)]
    pub client_state: Option<String>,
    #[serde(default)]
    pub binding_id: Option<String>,
    #[serde(default)]
    pub user: Option<AuthUserConfig>,
}

fn default_change_types() -> Vec<String> {
    vec!["created".to_string()]
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthUserConfig {
    pub user_id: String,
    pub token_key: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DemoEventsConfig {
    #[serde(default)]
    pub enabled: DomainEnabledMode,
    #[serde(default = "default_events_components")]
    pub components: Vec<ServiceComponentConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DemoMsgraphSubscriptionsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_msgraph_binary")]
    pub binary: String,
    #[serde(default = "default_msgraph_mode")]
    pub mode: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DemoProviderConfig {
    #[serde(default)]
    pub pack: Option<String>,
    #[serde(default)]
    pub setup_flow: Option<String>,
    #[serde(default)]
    pub verify_flow: Option<String>,
}

impl Default for DemoNatsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            url: default_nats_url(),
            spawn: DemoNatsSpawnConfig::default(),
        }
    }
}

impl Default for DemoNatsSpawnConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            binary: default_nats_binary(),
            args: default_nats_args(),
        }
    }
}

impl Default for DemoGatewayConfig {
    fn default() -> Self {
        Self {
            binary: default_gateway_binary(),
            listen_addr: default_gateway_listen_addr(),
            port: default_gateway_port(),
            args: Vec::new(),
        }
    }
}

impl Default for DemoEgressConfig {
    fn default() -> Self {
        Self {
            binary: default_egress_binary(),
            args: Vec::new(),
        }
    }
}

impl Default for DemoMsgraphSubscriptionsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            binary: default_msgraph_binary(),
            mode: default_msgraph_mode(),
            args: Vec::new(),
        }
    }
}

impl Default for DemoEventsConfig {
    fn default() -> Self {
        Self {
            enabled: DomainEnabledMode::Auto,
            components: default_events_components(),
        }
    }
}

pub fn load_demo_config(path: &Path) -> anyhow::Result<DemoConfig> {
    let contents = std::fs::read_to_string(path)?;
    let config: DemoConfig = serde_yaml_bw::from_str(&contents)?;
    Ok(config)
}

fn config_binary_path(config: &OperatorConfig, name: &str, config_dir: &Path) -> Option<PathBuf> {
    config
        .binaries
        .get(name)
        .map(|value| resolve_path(config_dir, value))
}

fn resolve_path(base: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn default_demo_tenant() -> String {
    "demo".to_string()
}

fn default_demo_team() -> String {
    "default".to_string()
}

fn default_true() -> bool {
    true
}

pub fn default_nats_url() -> String {
    "nats://127.0.0.1:4222".to_string()
}

pub fn default_receive_nats_url() -> String {
    "nats://127.0.0.1:4347".to_string()
}

fn default_nats_binary() -> String {
    "nats-server".to_string()
}

fn default_nats_args() -> Vec<String> {
    vec!["-p".to_string(), "4222".to_string(), "-js".to_string()]
}

fn default_gateway_binary() -> String {
    "gateway".to_string()
}

fn default_gateway_listen_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_gateway_port() -> u16 {
    8080
}

fn default_egress_binary() -> String {
    "egress".to_string()
}

fn default_msgraph_binary() -> String {
    "subscriptions-msgraph".to_string()
}

fn default_msgraph_mode() -> String {
    "poll".to_string()
}

pub(crate) fn default_events_components() -> Vec<ServiceComponentConfig> {
    Vec::new()
}
