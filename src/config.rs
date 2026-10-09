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
    #[serde(default)]
    pub webchat: Option<WebchatConfig>,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct WebchatConfig {
    #[serde(default)]
    pub notifier: crate::notifier::NotifierConfig,
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
    /// Optional `sql:` block enabling the localhost SQL gateway (schema +
    /// query endpoints). Uses the published `greentic-runner-host` sql config
    /// so the engine types line up with `sql::pool::build`/`SqlConnection`.
    #[serde(default)]
    pub sql: Option<greentic_runner_host::sql::config::SqlConfig>,
}

impl Default for DemoConfig {
    fn default() -> Self {
        Self {
            tenant: default_demo_tenant(),
            team: default_demo_team(),
            services: DemoServicesConfig::default(),
            providers: None,
            sql: None,
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

/// Environment variable naming the tenant a container-hosted runtime serves.
///
/// greentic-start already EXPORTS this name onto every child it spawns
/// (`runtime::build_env`); this is the read half, so a workload that was only
/// ever configured through the environment lands in the same namespace.
pub const TENANT_ENV_VAR: &str = "GREENTIC_TENANT";

/// Environment variable naming the team. See [`TENANT_ENV_VAR`].
pub const TEAM_ENV_VAR: &str = "GREENTIC_TEAM";

/// Tenant a runtime config assumes when neither `demo.yaml`/`bundle.yaml` nor
/// the CLI names one. Was `demo`; see [`crate::DEFAULT_TENANT`] for why it is
/// now `default` and why the constant is duplicated rather than imported from
/// greentic-types.
///
/// Precedence, most specific first:
///
/// 1. `--tenant` on the CLI — applied last, in
///    `bundle_config::apply_target_overrides`.
/// 2. the config file (`demo.yaml`'s `tenant:`, `bundle.yaml`'s `tenant:`, or
///    the bundle manifest's resolved target).
/// 3. `$GREENTIC_TENANT` — this function.
/// 4. [`crate::DEFAULT_TENANT`].
///
/// Serde is a sound seam for rung 3 precisely because `#[serde(default = …)]`
/// runs ONLY when the key is absent from the document: a `demo.yaml` that says
/// `tenant: default` explicitly still beats the environment, which is the
/// point — the environment must never override a source a human named. Both
/// non-serde construction sites (`DemoConfig::default()`, which
/// `bundle_config::load_runtime_demo_config` uses as the base of the
/// normalized-bundle path) route through here too, and both apply their own
/// explicit sources afterwards, so the ladder holds on every path.
///
/// A Cloud Run or Kubernetes workload has no config file and no CLI argument:
/// the deployer configures the container purely through the environment, so
/// without this rung every deployed workload ran as tenant `default` whatever
/// tenant actually owned the environment — and that string is a segment of
/// every `secrets://` URI the runtime resolves, so a credential staged under
/// the real tenant was never found.
fn default_demo_tenant() -> String {
    target_from_env(TENANT_ENV_VAR).unwrap_or_else(|| crate::DEFAULT_TENANT.to_string())
}

/// Team counterpart of [`default_demo_tenant`]; same ladder, reading
/// [`TEAM_ENV_VAR`].
fn default_demo_team() -> String {
    target_from_env(TEAM_ENV_VAR).unwrap_or_else(|| crate::DEFAULT_TEAM.to_string())
}

/// Read a tenant/team name from the process environment.
///
/// An unset, empty or whitespace-only value is ABSENT, never a tenant named
/// `""`: a container runtime that renders an unresolved substitution leaves an
/// empty string behind, and honouring it would key state directories and
/// `secrets://` URIs on nothing at all.
fn target_from_env(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
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

/// Serializes a test against the shared process environment's tenant/team
/// variables and restores whatever they held on the way out, so a test that
/// sets `GREENTIC_TENANT` cannot decide another test's answer.
///
/// Every assertion about a tenant or team default is env-sensitive now, so
/// each one has to hold this — including the ones that predate the environment
/// rung, which would otherwise read a value a parallel test set.
#[cfg(test)]
pub(crate) struct TargetEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    previous: Vec<(&'static str, Option<String>)>,
}

#[cfg(test)]
impl TargetEnvGuard {
    /// `None` means "make sure this variable is unset for the test".
    pub(crate) fn set(tenant: Option<&str>, team: Option<&str>) -> Self {
        let lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = vec![
            (TENANT_ENV_VAR, std::env::var(TENANT_ENV_VAR).ok()),
            (TEAM_ENV_VAR, std::env::var(TEAM_ENV_VAR).ok()),
        ];
        // SAFETY: `test_env_lock` serializes every env mutation in this
        // crate's tests, and `Drop` restores the previous values.
        unsafe {
            apply_target_env(TENANT_ENV_VAR, tenant);
            apply_target_env(TEAM_ENV_VAR, team);
        }
        Self {
            _lock: lock,
            previous,
        }
    }
}

#[cfg(test)]
impl Drop for TargetEnvGuard {
    fn drop(&mut self) {
        for (name, value) in &self.previous {
            // SAFETY: still holding `test_env_lock`.
            unsafe { apply_target_env(name, value.as_deref()) }
        }
    }
}

/// # Safety
/// Callers must hold `crate::test_env_lock()`.
#[cfg(test)]
unsafe fn apply_target_env(name: &str, value: Option<&str>) {
    match value {
        Some(value) => unsafe { std::env::set_var(name, value) },
        None => unsafe { std::env::remove_var(name) },
    }
}

#[cfg(test)]
mod tenant_default_tests {
    use super::*;

    /// The tenant the runtime uses when neither `demo.yaml`, the environment,
    /// nor the CLI names one. This is the value that ends up in
    /// `state/runtime/<tenant.team>/`, in `GREENTIC_TENANT`, and in every
    /// `secrets://` URI the run resolves. It was `demo` while greentic-deployer
    /// and greentic-setup bound bundles under `default`, so the server ran in
    /// one namespace and served deployments from another.
    #[test]
    fn runtime_config_defaults_to_the_fleet_tenant_not_demo() {
        let _env = TargetEnvGuard::set(None, None);
        let config = DemoConfig::default();
        assert_eq!(config.tenant, "default");
        assert_ne!(config.tenant, "demo");
        assert_eq!(config.team, "default");
    }

    /// The same defaults have to apply when a `demo.yaml` simply omits the
    /// keys — they are `#[serde(default = "...")]`, a separate code path from
    /// `Default::default()`.
    #[test]
    fn a_demo_yaml_without_tenant_keys_gets_the_same_defaults() {
        let _env = TargetEnvGuard::set(None, None);
        let config: DemoConfig =
            serde_yaml_bw::from_str("services: {}\n").expect("minimal demo.yaml parses");
        assert_eq!(config.tenant, "default");
        assert_eq!(config.team, "default");
    }

    /// Rung 3 beats rung 4. A Cloud Run or Kubernetes workload gets no config
    /// file and no CLI argument, so without this the deployed runtime resolves
    /// `secrets://default/default/…` whatever tenant owns the environment.
    #[test]
    fn the_environment_names_the_tenant_when_nothing_else_does() {
        let _env = TargetEnvGuard::set(Some("aws"), Some("platform"));
        let config = DemoConfig::default();
        assert_eq!(config.tenant, "aws");
        assert_eq!(config.team, "platform");
    }

    /// The same rung, reached through serde rather than through
    /// `Default::default()` — a `demo.yaml` that omits the keys.
    #[test]
    fn a_demo_yaml_without_tenant_keys_falls_through_to_the_environment() {
        let _env = TargetEnvGuard::set(Some("aws"), Some("platform"));
        let config: DemoConfig =
            serde_yaml_bw::from_str("services: {}\n").expect("minimal demo.yaml parses");
        assert_eq!(config.tenant, "aws");
        assert_eq!(config.team, "platform");
    }

    /// Rung 2 beats rung 3. Anything a human or a config file names has to keep
    /// winning, or this change silently re-targets working deployments in order
    /// to fix a broken one.
    #[test]
    fn a_config_file_beats_the_environment() {
        let _env = TargetEnvGuard::set(Some("aws"), Some("platform"));
        let config: DemoConfig = serde_yaml_bw::from_str("tenant: acme\nteam: support\n")
            .expect("demo.yaml naming a target parses");
        assert_eq!(config.tenant, "acme");
        assert_eq!(config.team, "support");
    }

    /// And it keeps winning when what it names happens to BE the default —
    /// `#[serde(default = "…")]` runs only on an absent key, so this is a
    /// deliberate choice of `default`, not a fall-through to the environment.
    #[test]
    fn a_config_file_naming_the_default_still_beats_the_environment() {
        let _env = TargetEnvGuard::set(Some("aws"), Some("platform"));
        let config: DemoConfig = serde_yaml_bw::from_str("tenant: default\nteam: default\n")
            .expect("demo.yaml naming the default parses");
        assert_eq!(config.tenant, "default");
        assert_eq!(config.team, "default");
    }

    /// An empty or whitespace-only variable is ABSENT, not a tenant named `""`.
    /// A container runtime that renders an unresolved substitution leaves an
    /// empty string behind, and keying state directories and `secrets://` URIs
    /// on nothing at all is worse than the default.
    #[test]
    fn an_empty_or_blank_environment_value_is_absent() {
        let _env = TargetEnvGuard::set(Some(""), Some("   "));
        let config = DemoConfig::default();
        assert_eq!(config.tenant, "default");
        assert_eq!(config.team, "default");
    }

    /// Surrounding whitespace is stripped rather than carried into the path
    /// segment — `state/runtime/< aws .default>/` is not a directory anyone
    /// meant to create.
    #[test]
    fn a_padded_environment_value_is_trimmed() {
        let _env = TargetEnvGuard::set(Some("  aws  "), Some("\tplatform\n"));
        let config = DemoConfig::default();
        assert_eq!(config.tenant, "aws");
        assert_eq!(config.team, "platform");
    }

    /// The two variables are independent rungs: naming only the tenant must not
    /// drag the team off its default, or a half-configured deployment lands in
    /// a namespace neither side chose.
    #[test]
    fn the_tenant_and_team_variables_are_read_independently() {
        let _env = TargetEnvGuard::set(Some("aws"), None);
        let config = DemoConfig::default();
        assert_eq!(config.tenant, "aws");
        assert_eq!(config.team, "default");
    }
}

#[cfg(test)]
mod webchat_config_tests {
    use super::*;

    #[test]
    fn operator_config_parses_webchat_notifier_redis() {
        let yaml = "\
binaries:
  some_binary: /usr/bin/foo
webchat:
  notifier:
    backend: redis
";
        let cfg: OperatorConfig = serde_yaml_bw::from_str(yaml).expect("parse");
        let webchat = cfg.webchat.expect("webchat section present");
        match webchat.notifier {
            crate::notifier::NotifierConfig::Redis { url, .. } => assert!(url.is_none()),
            _ => panic!("expected Redis notifier"),
        }
    }

    #[test]
    fn operator_config_webchat_absent_is_none() {
        let yaml = "binaries: {}\n";
        let cfg: OperatorConfig = serde_yaml_bw::from_str(yaml).expect("parse");
        assert!(cfg.webchat.is_none());
    }
}
