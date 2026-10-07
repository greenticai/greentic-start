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
//! - **Values may be client-side encrypted.** The designer seals each value
//!   before the admin sees it; a decoded value starting with `gtcenc1:` is
//!   `gtcenc1:` + base64(`nonce(12) || AES-256-GCM ciphertext+tag`), opened with
//!   the 32-byte key (base64) the unit's dev store holds at
//!   `secrets://<ingress env>/<tenant>/_/door/key` (the env the deployer writes the
//!   `door` category into), then `secrets://default/<tenant>/_/door/key`. The AAD is
//!   `"gtc-door-v1\0" tenant "\0" unit "\0" path`: start does not know the
//!   designer's environment id (the door answer and the staged ingress document
//!   carry none), so the env id is NOT part of it. The door does not say whether
//!   a row is unit-scoped or environment-shared, so a value is tried with the
//!   unit's bundle id and then with `_env`. A value without the prefix is
//!   written as is. A missing key, bad key, wrong AAD or tag failure fails the
//!   activation; no key or value is ever put in a message.
//! - **The env is chosen per secret by its category.** The runner reads `mcp`,
//!   `a2a`, `llm`, `knowledge` and `sorla` at env `default`; everything else
//!   (pack-scoped extension node/tool credentials, channel secrets) at the
//!   revision's env (`$GREENTIC_ENV`), which is the env the ingress document is
//!   read under. Each secret is written where the runner will look. The
//!   generated webchat `jwt_signing_key` is minted by start into the store at
//!   boot and is not a door secret.
//! - **Addresses are the runner's.** Each secret lands at
//!   `secrets://<env>/<tenant>/<path>`, the path tail verbatim, with `<env>`
//!   chosen as above.
//! - **Values never leave this module in a message.** No `Debug` is derived on
//!   a type that holds one, errors name paths and statuses only, and a body
//!   that does not parse is reported by position, because serde's own message
//!   can echo the offending value.
//! - **Nothing is written unless everything validated**, so a malformed entry
//!   cannot leave half a unit hydrated.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{LazyLock, Mutex, Once, PoisonError};
use std::time::{Duration, Instant};

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
    /// Wall-clock budget for ALL retrying in one activation, shared by every
    /// unit (see [`Budget`]). The first attempt per unit is always made.
    pub total_budget: Duration,
}

impl DoorPolicy {
    pub(crate) fn budget(&self) -> Budget {
        Budget {
            total: self.total_budget,
            clock: Clock::Real(Instant::now()),
        }
    }
}

/// The retry time left in one activation. One per activation, passed to every
/// unit, so N units behind a dead door cost one budget, not N of them.
pub(crate) struct Budget {
    total: Duration,
    clock: Clock,
}

/// Where a [`Budget`] reads elapsed time and how it waits. `Manual` exists so a
/// test can spend a budget by sleeping without any real-time margin.
enum Clock {
    Real(Instant),
    #[cfg(test)]
    Manual(Mutex<Duration>),
}

impl Budget {
    fn remaining(&self) -> Duration {
        let elapsed = match &self.clock {
            Clock::Real(start) => start.elapsed(),
            #[cfg(test)]
            Clock::Manual(elapsed) => *elapsed.lock().unwrap_or_else(PoisonError::into_inner),
        };
        self.total.saturating_sub(elapsed)
    }

    async fn sleep(&self, wait: Duration) {
        match &self.clock {
            Clock::Real(_) => tokio::time::sleep(wait).await,
            #[cfg(test)]
            Clock::Manual(elapsed) => {
                let mut elapsed = elapsed.lock().unwrap_or_else(PoisonError::into_inner);
                *elapsed += wait;
            }
        }
    }

    /// A budget whose time only moves when something sleeps on it.
    #[cfg(test)]
    pub(crate) fn manual(total: Duration) -> Self {
        Self {
            total,
            clock: Clock::Manual(Mutex::new(Duration::ZERO)),
        }
    }
}

/// A longer `Retry-After` than this is not honoured past the budget anyway;
/// the cap keeps a hostile value from parking an activation.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

impl Default for DoorPolicy {
    fn default() -> Self {
        Self {
            attempts: 4,
            backoff: Duration::from_millis(500),
            request_timeout: Duration::from_secs(10),
            total_budget: Duration::from_secs(60),
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
    #[error(
        "the secrets door rejected the unit's credential (401); the token is invalid or revoked"
    )]
    Unauthorised,
    #[error(
        "the secrets door refused the unit's credential (403); the unit's token most likely lacks          the `secrets` purpose (the admin can add it with PATCH purposes on the token)"
    )]
    Forbidden,
    #[error("the secrets door is rate limiting (429)")]
    RateLimited(Option<Duration>),
    #[error("the secrets door answered {0}")]
    Status(u16),
    #[error("the secrets door answered with a body this build cannot use: {0}")]
    Body(String),
}

impl DoorError {
    /// Worth another attempt: the door may be back in a moment. A definite
    /// answer (401/403/404, any other 4xx, a body this build cannot use) will
    /// not change by asking again.
    fn retryable(&self) -> bool {
        match self {
            Self::Transport(_) | Self::RateLimited(_) => true,
            Self::Status(code) => *code >= 500 || *code == 408,
            Self::Absent | Self::Unauthorised | Self::Forbidden | Self::Body(_) => false,
        }
    }

    fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited(after) => *after,
            _ => None,
        }
    }
}

/// `Retry-After` as delta-seconds (the HTTP-date form is not honoured).
fn parse_retry_after(value: &str) -> Option<Duration> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|secs| Duration::from_secs(secs).min(MAX_RETRY_AFTER))
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
    path: String,
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
    /// The door could not be reached on a reload, so the secrets an earlier
    /// activation already wrote keep serving (a warning was logged).
    KeptPrevious,
    /// This many secrets were written.
    Written(usize),
}

/// ETags of the last successful hydration per `(door, tenant, unit)`.
///
/// The dev store lives for the process, so a reload that finds the set
/// unchanged has nothing to write and a `304` is a complete answer. A new
/// process starts empty and fetches in full.
static ETAGS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(Mutex::default);

/// The store addresses the last successful hydration wrote per unit, so the
/// next one can delete what the admin no longer returns.
static WRITTEN: LazyLock<Mutex<HashMap<String, BTreeSet<String>>>> = LazyLock::new(Mutex::default);

/// Categories the runner reads at env `default` (`scoped_secrets`): MCP, A2A,
/// LLM, knowledge-index and SoRLa credentials.
const RUNNER_CATEGORIES: &[&str] = &["mcp", "a2a", "llm", "knowledge", "sorla"];

fn is_runner_category(category: &str) -> bool {
    RUNNER_CATEGORIES.contains(&category)
}

/// The env segment a door secret is written at, chosen by its CATEGORY (the
/// middle path segment):
///
/// - a runner-scoped category (above) lives at `default`;
/// - every other category — a pack segment (`<pack>`,
///   `<pack>_unit_<unit>_<hash>`, a channel pack id) holding an extension
///   node's or tool's credential or a channel secret — is read by the runner at
///   the revision's own env (`$GREENTIC_ENV`, the env the ingress document is
///   read under), so it is written there.
///
/// `path` has been validated as exactly three segments.
fn env_for_path<'a>(path: &str, ingress_env: &'a str) -> &'a str {
    match path.split('/').nth(1) {
        Some(category) if is_runner_category(category) => ENV_SEGMENT,
        _ => ingress_env,
    }
}

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
    let budget = policy.budget();
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    for (tenant, bundle_id) in units {
        if !seen.insert((tenant, bundle_id)) {
            continue;
        }
        hydrate_unit(secrets, ingress_env, tenant, bundle_id, policy, &budget)
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
    budget: &Budget,
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
        // Not staged, or a document the parser refuses (it warns): there is no
        // readable flag, which is the same as no flag.
        Ok(None) => return Ok(Hydration::NotRequested),
        // The store ANSWERED with an error other than not-found, so whether
        // this unit uses the door is unknowable. Guessing "no" would run a
        // flagged unit without its credentials.
        Err(crate::ingress_auth::ConfigUnavailable(message)) => {
            bail!(
                "cannot tell whether unit `{bundle_id}` uses the secrets door: its staged \
                 ingress config could not be read ({message})"
            );
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

    let fetched = match fetch_with_retry(&door, known.as_deref(), policy, budget).await {
        Ok(fetched) => fetched,
        // A reload whose door is momentarily down keeps serving what an
        // earlier activation already wrote, rather than taking a working unit
        // down. Only a transient failure qualifies: a definite refusal means
        // the credential or door is wrong and must be seen.
        Err(err) if known.is_some() && err.retryable() => {
            operator_log::warn(
                module_path!(),
                format!(
                    "the secrets door `{}` is unreachable ({err}); unit `{bundle_id}` keeps the \
                     secrets an earlier activation hydrated",
                    door.read_all_url
                ),
            );
            return Ok(Hydration::KeptPrevious);
        }
        Err(err) => {
            return Err(anyhow::anyhow!(
                "the secrets door `{}` is not usable: {err}; refusing to activate a unit that \
                 would run without its credentials",
                door.read_all_url
            ));
        }
    };
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
    // The designer sets the flag because it moved secrets out of the store. An
    // empty set means it staged none (or the admin lost them), and serving on
    // that is exactly the keyless run this refuses. The etag is NOT recorded,
    // so the next activation asks again instead of trusting a 304.
    if entries.is_empty() {
        bail!(
            "the secrets door `{}` answered an empty set for unit `{bundle_id}`, which sets \
             `secrets_door`; refusing to activate it without any credentials",
            door.read_all_url
        );
    }

    let mut decoded = decode_all(tenant, ingress_env, entries)?;
    if decoded.iter().any(|d| d.value.starts_with(ENC_PREFIX)) {
        let key = load_door_key(secrets, ingress_env, tenant).await?;
        for secret in &mut decoded {
            if secret.value.starts_with(ENC_PREFIX) {
                secret.value = open_value(&key, tenant, bundle_id, &secret.path, &secret.value)?;
            }
        }
    }
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
    // Delete what an earlier hydration wrote and the admin no longer returns.
    let now: BTreeSet<String> = decoded.iter().map(|d| d.uri.clone()).collect();
    let previous = WRITTEN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key.clone(), now.clone())
        .unwrap_or_default();
    for stale in previous.difference(&now) {
        if let Err(err) = secrets.delete(stale).await {
            operator_log::warn(
                module_path!(),
                format!("could not remove the stale door secret at `{stale}`: {err}"),
            );
        }
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
    budget: &Budget,
) -> Result<Fetched, DoorError> {
    install_crypto_provider();
    let client = reqwest::Client::builder()
        .timeout(
            policy
                .request_timeout
                .min(budget.remaining().max(Duration::from_secs(1))),
        )
        // A redirect would carry the bearer somewhere the unit never named.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| DoorError::Transport(format!("building the HTTP client: {err}")))?;
    let attempts = policy.attempts.max(1);
    let mut backoff = policy.backoff;
    let mut attempt = 1;
    loop {
        let err = match fetch_once(&client, door, if_none_match).await {
            Ok(fetched) => return Ok(fetched),
            Err(err) => err,
        };
        let remaining = budget.remaining();
        let will_retry = err.retryable() && attempt < attempts && !remaining.is_zero();
        operator_log::warn(
            module_path!(),
            format!(
                "secrets door attempt {attempt}/{attempts} failed: {err}{}",
                if will_retry { "; retrying" } else { "" }
            ),
        );
        if !will_retry {
            return Err(err);
        }
        let wait = err
            .retry_after()
            .map_or(backoff, |after| after.max(backoff))
            .min(remaining);
        budget.sleep(wait).await;
        backoff = backoff.saturating_mul(2);
        attempt += 1;
    }
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
        StatusCode::UNAUTHORIZED => return Err(DoorError::Unauthorised),
        StatusCode::FORBIDDEN => return Err(DoorError::Forbidden),
        StatusCode::TOO_MANY_REQUESTS => {
            let after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(parse_retry_after);
            return Err(DoorError::RateLimited(after));
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
fn decode_all(
    tenant: &str,
    ingress_env: &str,
    entries: Vec<RawEntry>,
) -> anyhow::Result<Vec<Decoded>> {
    entries
        .into_iter()
        .map(|entry| {
            validate_path(&entry.path)?;
            let env = env_for_path(&entry.path, ingress_env);
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
                path: entry.path.clone(),
                uri: format!("secrets://{env}/{tenant}/{}", entry.path),
                value,
            })
        })
        .collect()
}

/// Marks a value the designer sealed before the admin stored it.
const ENC_PREFIX: &[u8] = b"gtcenc1:";
const AAD_DOMAIN: &str = "gtc-door-v1";
/// Scope name for an environment-shared row (no unit).
const ENV_SHARED_UNIT: &str = "_env";
const NONCE_LEN: usize = 12;

/// The 32-byte value-sealing key. Deliberately no `Debug`.
struct DoorKey([u8; 32]);

/// Where the sealing key may live, in the order they are tried. The deployer's
/// `op secrets put default/_/door/key` lands in the store's own env (`door` is
/// not in its default-env category list), i.e. the env the ingress document is
/// read under; `default` is where the runner-scoped categories live.
fn door_key_uris(ingress_env: &str, tenant: &str) -> Vec<String> {
    let mut envs = vec![ingress_env];
    if ingress_env != ENV_SEGMENT {
        envs.push(ENV_SEGMENT);
    }
    envs.into_iter()
        .map(|env| format!("secrets://{env}/{tenant}/_/door/key"))
        .collect()
}

/// Read the key from the same store the host reads. Addresses are the only
/// thing a message may name.
async fn load_door_key(
    secrets: &dyn SecretsManager,
    ingress_env: &str,
    tenant: &str,
) -> anyhow::Result<DoorKey> {
    let uris = door_key_uris(ingress_env, tenant);
    let mut last = String::new();
    let mut found = None;
    for uri in &uris {
        match secrets.read(uri).await {
            Ok(raw) => {
                found = Some((uri, raw));
                break;
            }
            Err(err) => last = err.to_string(),
        }
    }
    let Some((uri, raw)) = found else {
        bail!(
            "the secrets door returned encrypted values but the decryption key could not be \
             read at {} ({last})",
            uris.iter()
                .map(|uri| format!("`{uri}`"))
                .collect::<Vec<_>>()
                .join(" or ")
        );
    };
    let bad = || {
        anyhow::anyhow!(
            "the secrets door decryption key at `{uri}` is not base64 of exactly 32 bytes"
        )
    };
    let text = std::str::from_utf8(&raw).map_err(|_| bad())?;
    let bytes = B64.decode(text.trim()).map_err(|_| bad())?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| bad())?;
    Ok(DoorKey(key))
}

fn door_aad(tenant: &str, unit: &str, path: &str) -> Vec<u8> {
    format!("{AAD_DOMAIN}\0{tenant}\0{unit}\0{path}").into_bytes()
}

/// Open one `gtcenc1:` value, trying the unit scope and then the
/// environment-shared one.
fn open_value(
    key: &DoorKey,
    tenant: &str,
    bundle_id: &str,
    path: &str,
    value: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    let fail = || {
        anyhow::anyhow!(
            "door secret `{path}` could not be decrypted (wrong key, wrong scope or a tampered \
             value)"
        )
    };
    let body = B64.decode(&value[ENC_PREFIX.len()..]).map_err(|_| {
        anyhow::anyhow!("door secret `{path}` is marked encrypted but is not base64")
    })?;
    if body.len() < NONCE_LEN + AES_256_GCM.tag_len() {
        return Err(fail());
    }
    let (nonce_bytes, sealed) = body.split_at(NONCE_LEN);
    let unbound = UnboundKey::new(&AES_256_GCM, &key.0).map_err(|_| fail())?;
    let opener = LessSafeKey::new(unbound);
    for unit in [bundle_id, ENV_SHARED_UNIT] {
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| fail())?;
        // `open_in_place` may clobber its buffer on failure, so each try gets a
        // fresh copy.
        let mut buffer = sealed.to_vec();
        if let Ok(plain) =
            opener.open_in_place(nonce, Aad::from(door_aad(tenant, unit, path)), &mut buffer)
        {
            return Ok(plain.to_vec());
        }
    }
    Err(fail())
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
