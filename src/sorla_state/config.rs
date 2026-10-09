//! The `state-sorla` provider configuration and the door it resolves to.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;

use crate::interop::metering::run_outcome::{SiblingDoorError, sibling_door};
use crate::interop::metering::{MeteringConfig, MeteringToken};

/// The pack id whose presence in a revision selects this backend.
pub(crate) const PROVIDER_PACK_ID: &str = "state-sorla";

/// The last path segment of the admin's state door, beside `worker-usage`.
pub(crate) const STATE_SEGMENT: &str = "state";

const DEFAULT_KEY_PREFIX: &str = "greentic-state";
const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MIN_TIMEOUT_MS: u64 = 100;
const MAX_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_CACHE_ENTRIES: usize = 1_024;
const MAX_CACHE_ENTRIES: usize = 100_000;

/// Why a `state-sorla` selection could not be built. Every variant fails the
/// revision activation: the backend was named, and the alternative to refusing
/// is a worker that serves on state the operator did not ask for.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum StateConfigError {
    #[error("`state-sorla` config field `{field}` is invalid: {reason}")]
    Field { field: &'static str, reason: String },
    #[error(
        "`state-sorla` is configured but the unit stages no usable `metering` block, so there \
         is no per-unit token to authenticate the state door with"
    )]
    NoMetering,
    #[error("the metering endpoint `{0}` is not a URL")]
    Unparseable(String),
    #[error(
        "the metering endpoint `{0}` does not end in `/worker-usage`, so the state door beside \
         it cannot be derived (set `endpoint` in the `state-sorla` config to name it)"
    )]
    NotWorkerUsage(String),
    #[error("the state door `{0}` is not https and not loopback http; refusing to send a token")]
    UnsafeEndpoint(String),
}

/// The parsed, validated `state-sorla` provider config (non-secret half).
///
/// `token_ref` is deliberately absent: the credential is the unit's metering
/// token, so there is no second secret to resolve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SorlaStateConfig {
    /// Explicit door base URL; derived from the metering endpoint when `None`.
    pub endpoint: Option<String>,
    pub key_prefix: String,
    /// TTL applied to a write that names none. `None` = no expiry.
    pub default_ttl_seconds: Option<u32>,
    pub request_timeout: Duration,
    /// `0` disables the read cache.
    pub cache_max_entries: usize,
    /// `stable_component_state` (bool, default `false`): when on, component
    /// state written through the WIT `state-store` import is keyed per
    /// environment/unit instead of per revision, so it survives a redeploy.
    /// Flow state stays per revision. See `store::HttpStateStore::door_key`.
    pub stable_component_state: bool,
}

impl SorlaStateConfig {
    pub(crate) fn from_non_secret(map: &BTreeMap<String, Value>) -> Result<Self, StateConfigError> {
        let text = |field: &'static str| -> Result<Option<String>, StateConfigError> {
            match map.get(field) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(value)) if value.trim().is_empty() => Ok(None),
                Some(Value::String(value)) => Ok(Some(value.trim().to_string())),
                Some(_) => Err(field_error(field, "must be a string")),
            }
        };
        let number = |field: &'static str| -> Result<Option<u64>, StateConfigError> {
            match map.get(field) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Number(n)) => n
                    .as_u64()
                    .map(Some)
                    .ok_or_else(|| field_error(field, "must be a non-negative integer")),
                Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
                Some(Value::String(s)) => s
                    .trim()
                    .parse::<u64>()
                    .map(Some)
                    .map_err(|_| field_error(field, "must be a non-negative integer")),
                Some(_) => Err(field_error(field, "must be a non-negative integer")),
            }
        };

        let key_prefix = text("key_prefix")?.unwrap_or_else(|| DEFAULT_KEY_PREFIX.to_string());
        if key_prefix.chars().any(char::is_control) {
            return Err(field_error(
                "key_prefix",
                "must not contain control characters",
            ));
        }
        let default_ttl_seconds = match number("default_ttl_seconds")? {
            None | Some(0) => None,
            Some(n) => Some(u32::try_from(n).map_err(|_| {
                field_error("default_ttl_seconds", "does not fit in 32 bits of seconds")
            })?),
        };
        let timeout_ms = number("request_timeout_ms")?.unwrap_or(DEFAULT_TIMEOUT_MS);
        if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(field_error(
                "request_timeout_ms",
                format!("must be between {MIN_TIMEOUT_MS} and {MAX_TIMEOUT_MS}"),
            ));
        }
        let cache_max_entries = match number("cache_max_entries")? {
            None => DEFAULT_CACHE_ENTRIES,
            Some(n) if n as usize <= MAX_CACHE_ENTRIES => n as usize,
            Some(_) => {
                return Err(field_error(
                    "cache_max_entries",
                    format!("must be at most {MAX_CACHE_ENTRIES}"),
                ));
            }
        };
        let stable_component_state = match map.get("stable_component_state") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(flag)) => *flag,
            Some(Value::String(s)) if s.trim().is_empty() => false,
            Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
                "true" => true,
                "false" => false,
                _ => return Err(field_error("stable_component_state", "must be a boolean")),
            },
            Some(_) => return Err(field_error("stable_component_state", "must be a boolean")),
        };
        Ok(Self {
            endpoint: text("endpoint")?,
            key_prefix,
            default_ttl_seconds,
            request_timeout: Duration::from_millis(timeout_ms),
            cache_max_entries,
            stable_component_state,
        })
    }
}

fn field_error(field: &'static str, reason: impl Into<String>) -> StateConfigError {
    StateConfigError::Field {
        field,
        reason: reason.into(),
    }
}

/// Where the state door is and who to present as. The token is private to this
/// crate's HTTP client and prints as `<redacted>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StateDoor {
    pub base_url: String,
    pub token: MeteringToken,
}

/// A revision's resolved `state-sorla` choice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SorlaStateSelection {
    pub config: SorlaStateConfig,
    pub door: StateDoor,
}

impl SorlaStateSelection {
    /// Resolve the provider config against the unit's metering block.
    pub(crate) fn resolve(
        non_secret: &BTreeMap<String, Value>,
        metering: Option<&MeteringConfig>,
    ) -> Result<Self, StateConfigError> {
        let config = SorlaStateConfig::from_non_secret(non_secret)?;
        let metering = metering.ok_or(StateConfigError::NoMetering)?;
        let base_url = match &config.endpoint {
            Some(explicit) => explicit.trim_end_matches('/').to_string(),
            None => sibling_door(&metering.endpoint, STATE_SEGMENT)
                .map_err(|err| match err {
                    SiblingDoorError::Unparseable => {
                        StateConfigError::Unparseable(metering.endpoint.clone())
                    }
                    SiblingDoorError::NotWorkerUsage => {
                        StateConfigError::NotWorkerUsage(metering.endpoint.clone())
                    }
                })?
                .trim_end_matches('/')
                .to_string(),
        };
        if !is_safe(&base_url) {
            return Err(StateConfigError::UnsafeEndpoint(base_url));
        }
        Ok(Self {
            config,
            door: StateDoor {
                base_url,
                token: metering.token.clone(),
            },
        })
    }
}

fn is_safe(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
        ),
        _ => false,
    }
}

/// Decide whether a revision selects `state-sorla`.
///
/// The pack LIST is the authority, not the pack config: the loader only keeps
/// a pack's config when its non-secret map is non-empty, so a bundle that
/// carries the pack but answered no question has no config entry at all, and
/// keying on the config would silently serve memory. A config entry without the
/// pack in the list (which the loader cannot produce) selects it too, since the
/// operator wrote one. An empty or absent config means every default.
///
/// A selected backend without a usable metering block is refused ([`StateConfigError::NoMetering`]).
pub(crate) fn select(
    revision_pack_ids: &std::collections::BTreeSet<String>,
    non_secret: Option<&BTreeMap<String, Value>>,
    metering: Option<&MeteringConfig>,
) -> Result<Option<SorlaStateSelection>, StateConfigError> {
    if !revision_pack_ids.contains(PROVIDER_PACK_ID) && non_secret.is_none() {
        return Ok(None);
    }
    let empty = BTreeMap::new();
    SorlaStateSelection::resolve(non_secret.unwrap_or(&empty), metering).map(Some)
}
