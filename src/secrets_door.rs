//! Hydrating a unit's deployed secrets from the admin's secrets door.
//!
//! The Cloud Run env-pack ships the whole environment dev store as ONE Secret
//! Manager version, which Google caps at 65,536 bytes. A unit whose staged
//! ingress document says `secrets_door: true` has its credentials in the admin
//! instead; this module fetches them once at revision activation and writes
//! them into the ephemeral dev store the runtime already reads, so nothing
//! downstream (the runner's `read_secret_for_unit` candidate walk, the caching
//! and logging managers, generated-secret seeding) changes.
//!
//! # Wire contract (fixed, the admin implements the server)
//!
//! `POST <door>/read-all`, where `<door>` is the unit's `metering.endpoint`
//! with its last path segment (`worker-usage`) swapped for `secrets` — the same
//! sibling rule the run-outcome, approval and state doors use. Bearer = the
//! unit's metering token, body `{}`, optional `If-None-Match`.
//!
//! `200 {"secrets":[{"path":"<team>/<category>/<name>","value":"…",
//! "encoding":"utf8|base64"}],"etag":"<opaque>"}`; `304` when the ETag still
//! matches; `401`/`403` unauthorised; `404` door absent.
//!
//! # Rules
//!
//! - **No flag, no call.** A unit whose document does not carry
//!   `secrets_door: true` costs nothing and changes nothing.
//! - **A flagged unit fails closed.** The designer set the flag because the
//!   store does not hold these secrets; running without them fails silently
//!   (an LLM answering "Something went wrong" with a keyless client). An
//!   unreachable, unauthorised or absent door — or a flag with no usable
//!   `metering` block to authenticate with — fails the ACTIVATION, naming the
//!   door, after bounded retries with backoff. The same trade `state-sorla`
//!   makes for its state door.
//! - **Addresses are the runner's.** Each secret lands at
//!   `secrets://default/<tenant>/<path>`: env pinned to `default` and the path
//!   tail verbatim, exactly what `greentic_aw_runtime::scoped_secrets` reads.
//! - **Values never leave this module in a message.** No `Debug` is derived on
//!   a type that holds one, errors name paths and statuses only, and a body
//!   that does not parse is reported by position, because serde's own message
//!   can echo the offending value.
//! - **Nothing is written unless everything validated**, so a malformed entry
//!   cannot leave half a unit hydrated.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex, Once, PoisonError};
use std::time::Duration;

use anyhow::{Context, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use greentic_secrets_lib::SecretsManager;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::interop::metering::run_outcome::{SiblingDoorError, sibling_door};
use crate::interop::metering::{MeteringConfig, MeteringToken};
use crate::operator_log;

/// The last path segment of the admin's secrets door, beside `worker-usage`.
pub(crate) const SECRETS_SEGMENT: &str = "secrets";
const READ_ALL_SEGMENT: &str = "read-all";
/// The env segment every runtime-read credential is sealed under; see
/// `greentic_aw_runtime::scoped_secrets::ENV_SEGMENT`.
const ENV_SEGMENT: &str = "default";
/// The admin bounds a unit's set at 1 MiB of values; base64 and JSON framing
/// inflate that, so this is a ceiling against a misbehaving peer, not a limit.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_SECRETS: usize = 10_000;

/// How hard activation tries before it gives up on the door.
#[derive(Clone, Debug)]
pub(crate) struct DoorPolicy {
    pub attempts: u32,
    /// Wait before the second attempt; doubles each time.
    pub backoff: Duration,
    pub request_timeout: Duration,
}

impl Default for DoorPolicy {
    fn default() -> Self {
        Self {
            attempts: 4,
            backoff: Duration::from_millis(500),
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// Why a flagged unit could not be hydrated. Carries statuses, paths and
/// transport reasons — never a token and never a value.
#[derive(Debug, thiserror::Error)]
enum DoorError {
    #[error("the secrets door did not answer: {0}")]
    Transport(String),
    #[error(
        "the secrets door is absent (404); the admin predates it or the unit's token lacks the `secrets` purpose"
    )]
    Absent,
    #[error("the secrets door rejected the unit's credential ({0})")]
    Unauthorised(u16),
    #[error("the secrets door answered {0}")]
    Status(u16),
    #[error("the secrets door answered with a body this build cannot use: {0}")]
    Body(String),
}

/// Where the secrets door is and who to present as.
struct SecretsDoor {
    read_all_url: String,
    token: MeteringToken,
}

fn door_for(metering: &MeteringConfig) -> anyhow::Result<SecretsDoor> {
    let base = sibling_door(&metering.endpoint, SECRETS_SEGMENT).map_err(|err| match err {
        SiblingDoorError::Unparseable => anyhow::anyhow!(
            "the metering endpoint `{}` is not a URL, so the secrets door cannot be derived",
            metering.endpoint
        ),
        SiblingDoorError::NotWorkerUsage => anyhow::anyhow!(
            "the metering endpoint `{}` does not end in `/worker-usage`, so the secrets door \
             beside it cannot be derived",
            metering.endpoint
        ),
    })?;
    let base = base.trim_end_matches('/').to_string();
    if !is_safe(&base) {
        bail!(
            "the secrets door `{base}` is not https and not loopback http; refusing to send a token"
        );
    }
    Ok(SecretsDoor {
        read_all_url: format!("{base}/{READ_ALL_SEGMENT}"),
        token: metering.token.clone(),
    })
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

/// One validated secret, ready to write. Deliberately no `Debug`.
struct Decoded {
    uri: String,
    value: Vec<u8>,
}

#[derive(Deserialize)]
struct RawResponse {
    secrets: Vec<RawEntry>,
    #[serde(default)]
    etag: Option<String>,
}

#[derive(Deserialize)]
struct RawEntry {
    path: String,
    value: String,
    #[serde(default)]
    encoding: Option<String>,
}

enum Fetched {
    NotModified,
    Secrets {
        entries: Vec<RawEntry>,
        etag: Option<String>,
    },
}

/// What one unit's hydration did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Hydration {
    /// The unit does not use the door (or stages no document at all).
    NotRequested,
    /// The door's ETag still matched what an earlier activation wrote.
    Unchanged,
    /// This many secrets were written.
    Written(usize),
}

/// ETags of the last successful hydration per `(door, tenant, unit)`.
///
/// The dev store lives for the process, so a reload that finds the set
/// unchanged has nothing to write and a `304` is a complete answer. A new
/// process starts empty and fetches in full.
static ETAGS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(Mutex::default);

fn etag_key(door: &SecretsDoor, tenant: &str, bundle_id: &str) -> String {
    format!("{}|{tenant}|{bundle_id}", door.read_all_url)
}

fn install_crypto_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        // This binary carries both `ring` and `aws-lc-rs`, so rustls cannot
        // auto-select one and the client builder panics without a default.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Hydrate every distinct `(tenant, bundle id)` unit of one activation.
///
/// `ingress_env` is the env the staged ingress document is read under (the
/// serve path's own `resolve_env`). Fails the activation on the first unit
/// that sets the flag and cannot be served.
pub(crate) async fn hydrate_for_activation<'a>(
    secrets: &dyn SecretsManager,
    ingress_env: &str,
    units: impl IntoIterator<Item = (&'a str, &'a str)>,
    policy: &DoorPolicy,
) -> anyhow::Result<()> {
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    for (tenant, bundle_id) in units {
        if !seen.insert((tenant, bundle_id)) {
            continue;
        }
        hydrate_unit(secrets, ingress_env, tenant, bundle_id, policy)
            .await
            .with_context(|| {
                format!("hydrating the deployed secrets of unit `{bundle_id}` (tenant `{tenant}`)")
            })?;
    }
    Ok(())
}

/// Hydrate one unit, or do nothing when it does not ask for it.
pub(crate) async fn hydrate_unit(
    secrets: &dyn SecretsManager,
    ingress_env: &str,
    tenant: &str,
    bundle_id: &str,
    policy: &DoorPolicy,
) -> anyhow::Result<Hydration> {
    let config = match crate::ingress_auth::load_unit_config(
        secrets,
        ingress_env,
        tenant,
        bundle_id,
    )
    .await
    {
        Ok(Some(config)) => config,
        Ok(None) => return Ok(Hydration::NotRequested),
        Err(crate::ingress_auth::ConfigUnavailable(message)) => {
            // Same trade the metering read makes for a store that cannot
            // answer: the flag is unknowable, so this unit is treated as
            // not using the door, loudly.
            operator_log::warn(
                module_path!(),
                format!(
                    "deployed-secrets door for unit `{bundle_id}` was not consulted: its \
                         staged config could not be read ({message})"
                ),
            );
            return Ok(Hydration::NotRequested);
        }
    };
    if !config.secrets_door {
        return Ok(Hydration::NotRequested);
    }
    let Some(metering) = config.metering.as_ref() else {
        bail!(
            "unit `{bundle_id}` sets `secrets_door` but stages no usable `metering` block, so \
             there is no token to authenticate the secrets door with"
        );
    };
    let door = door_for(metering)?;
    let key = etag_key(&door, tenant, bundle_id);
    let known = ETAGS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key)
        .cloned();

    let fetched = fetch_with_retry(&door, known.as_deref(), policy)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "the secrets door `{}` is not usable: {err}; refusing to activate a unit that \
                 would run without its credentials",
                door.read_all_url
            )
        })?;
    let (entries, etag) = match fetched {
        Fetched::NotModified => {
            operator_log::info(
                module_path!(),
                format!("deployed secrets for unit `{bundle_id}` are unchanged (304)"),
            );
            return Ok(Hydration::Unchanged);
        }
        Fetched::Secrets { entries, etag } => (entries, etag),
    };

    let decoded = decode_all(tenant, entries)?;
    let count = decoded.len();
    for secret in &decoded {
        secrets
            .write(&secret.uri, &secret.value)
            .await
            .map_err(|err| {
                anyhow::anyhow!(
                    "writing a door secret into the runtime store at `{}` failed: {err}",
                    secret.uri
                )
            })?;
    }
    {
        let mut etags = ETAGS.lock().unwrap_or_else(PoisonError::into_inner);
        match etag {
            Some(etag) => {
                etags.insert(key, etag);
            }
            None => {
                etags.remove(&key);
            }
        }
    }
    operator_log::info(
        module_path!(),
        format!("hydrated {count} deployed secret(s) for unit `{bundle_id}` from the secrets door"),
    );
    Ok(Hydration::Written(count))
}

async fn fetch_with_retry(
    door: &SecretsDoor,
    if_none_match: Option<&str>,
    policy: &DoorPolicy,
) -> Result<Fetched, DoorError> {
    install_crypto_provider();
    let client = reqwest::Client::builder()
        .timeout(policy.request_timeout)
        // A redirect would carry the bearer somewhere the unit never named.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| DoorError::Transport(format!("building the HTTP client: {err}")))?;
    let attempts = policy.attempts.max(1);
    let mut wait = policy.backoff;
    let mut last = DoorError::Transport("no attempt was made".into());
    for attempt in 1..=attempts {
        match fetch_once(&client, door, if_none_match).await {
            Ok(fetched) => return Ok(fetched),
            Err(err) => {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "secrets door attempt {attempt}/{attempts} failed: {err}{}",
                        if attempt < attempts { "; retrying" } else { "" }
                    ),
                );
                last = err;
            }
        }
        if attempt < attempts {
            tokio::time::sleep(wait).await;
            wait = wait.saturating_mul(2);
        }
    }
    Err(last)
}

async fn fetch_once(
    client: &reqwest::Client,
    door: &SecretsDoor,
    if_none_match: Option<&str>,
) -> Result<Fetched, DoorError> {
    let mut request = client
        .post(&door.read_all_url)
        // The ONE place the token is used: a header, never the URL or a log.
        .bearer_auth(door.token.expose())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body("{}");
    if let Some(etag) = if_none_match {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    let mut response = request
        .send()
        .await
        .map_err(|err| DoorError::Transport(err.without_url().to_string()))?;
    match response.status() {
        StatusCode::NOT_MODIFIED if if_none_match.is_some() => return Ok(Fetched::NotModified),
        StatusCode::OK => {}
        StatusCode::NOT_FOUND => return Err(DoorError::Absent),
        status @ (StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) => {
            return Err(DoorError::Unauthorised(status.as_u16()));
        }
        other => return Err(DoorError::Status(other.as_u16())),
    }
    let etag_header = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| DoorError::Transport(err.without_url().to_string()))?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(DoorError::Body(format!(
                "the body is larger than {MAX_BODY_BYTES} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    // serde_json's own message can quote the offending value; report where it
    // failed instead.
    let parsed: RawResponse = serde_json::from_slice(&body).map_err(|err| {
        DoorError::Body(format!(
            "not the expected `{{secrets:[…],etag}}` shape (line {}, column {})",
            err.line(),
            err.column()
        ))
    })?;
    if parsed.secrets.len() > MAX_SECRETS {
        return Err(DoorError::Body(format!(
            "more than {MAX_SECRETS} secrets in one answer"
        )));
    }
    Ok(Fetched::Secrets {
        entries: parsed.secrets,
        etag: parsed.etag.or(etag_header),
    })
}

/// Validate every entry and decode its value. Fails on the first bad one,
/// naming its path.
fn decode_all(tenant: &str, entries: Vec<RawEntry>) -> anyhow::Result<Vec<Decoded>> {
    entries
        .into_iter()
        .map(|entry| {
            validate_path(&entry.path)?;
            let value = match entry.encoding.as_deref().map(str::trim) {
                None | Some("") | Some("utf8") => entry.value.into_bytes(),
                Some("base64") => B64
                    .decode(entry.value.as_bytes())
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "door secret `{}` is marked base64 but its value is not valid base64",
                            entry.path
                        )
                    })?,
                Some(other) => bail!(
                    "door secret `{}` names the unknown encoding `{other}` (expected utf8 or base64)",
                    entry.path
                ),
            };
            Ok(Decoded {
                uri: format!("secrets://{ENV_SEGMENT}/{tenant}/{}", entry.path),
                value,
            })
        })
        .collect()
}

/// `<team|_>/<category>/<name>`: exactly three non-empty segments, none of
/// them navigation, whitespace-only or carrying control characters. The path is
/// spliced into a store address, so anything else could name another tenant's
/// or another env's key.
fn validate_path(path: &str) -> anyhow::Result<()> {
    let segments: Vec<&str> = path.split('/').collect();
    let well_formed = segments.len() == 3
        && segments.iter().all(|segment| {
            !segment.trim().is_empty()
                && *segment != "."
                && *segment != ".."
                && !segment.contains('\\')
                && !segment.contains(':')
                && !segment.chars().any(char::is_control)
        });
    if !well_formed {
        bail!("the secrets door sent a path that is not `<team>/<category>/<name>`: `{path}`");
    }
    Ok(())
}

#[cfg(test)]
#[path = "secrets_door_tests.rs"]
mod secrets_door_tests;
