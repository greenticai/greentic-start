//! The per-unit cache and fetcher behind the access-policy door.
//!
//! One [`Slot`] per `(tenant, bundle)`. A slot's async mutex is held across
//! the fetch, which is what coalesces concurrent callers into ONE upstream
//! request: the second caller waits for the lock and then finds a fresh
//! answer. The cost is that a request arriving while a fetch is in flight
//! waits for it, bounded by [`REQUEST_TIMEOUT`].

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use reqwest::StatusCode;
use tokio::sync::Mutex;

use super::{ACCESS_POLICY_SEGMENT, DoorAnswer, parse_answer, tighten};
use crate::interop::config::InteropConfig;
use crate::interop::limits::RateLimiter;
use crate::interop::metering::MeteringConfig;
use crate::interop::metering::run_outcome::{SiblingDoorError, sibling_door};
use crate::operator_log;

/// How long an answer is served before the door is asked again.
pub(super) const TTL: Duration = Duration::from_secs(60);
/// The shortest time between two attempts, so a failing door is not hammered.
pub(super) const REFRESH_FLOOR: Duration = Duration::from_secs(30);
/// One attempt's budget. It sits on the request path of a unit whose answer
/// has gone stale, so it is short.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Which unit a request is for.
pub(crate) struct UnitRef<'a> {
    pub tenant: &'a str,
    pub bundle_id: &'a str,
    /// The deployment id the rate limiter keys the unit on, when the caller
    /// has it. The daily count is reconciled the first time it is known.
    pub deployment: Option<&'a str>,
}

#[derive(Default)]
struct SlotState {
    answer: Option<std::sync::Arc<DoorAnswer>>,
    etag: Option<String>,
    /// The last successful fetch (a `304` included).
    fetched_at: Option<Instant>,
    /// The last attempt, successful or not.
    attempted_at: Option<Instant>,
    /// Bumped on every new answer.
    seq: u64,
    /// The `(deployment, seq)` whose daily count was last raised.
    reconciled: Option<(String, u64)>,
    /// The failure last logged, so a persistent one is said once.
    last_failure: Option<String>,
    /// The answer `seq` whose empty mechanism list was last reported.
    reported_deny_all: Option<u64>,
}

#[derive(Default)]
struct Slot {
    state: Mutex<SlotState>,
}

/// The door client for every unit of one listener.
#[derive(Default)]
pub(crate) struct PolicyDoor {
    slots: DashMap<(String, String), std::sync::Arc<Slot>>,
    client: OnceLock<Result<reqwest::Client, String>>,
    /// Test clock offset, in milliseconds, so a test can pass the TTL without
    /// sleeping.
    #[cfg(test)]
    skew_ms: std::sync::atomic::AtomicU64,
}

enum Fetched {
    NotModified,
    Answer(Box<DoorAnswer>, Option<String>),
}

impl PolicyDoor {
    #[cfg(test)]
    pub(super) fn advance(&self, by: Duration) {
        let ms = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.skew_ms
            .fetch_add(ms, std::sync::atomic::Ordering::Relaxed);
    }

    fn now(&self) -> Instant {
        #[cfg(test)]
        {
            let skew = self.skew_ms.load(std::sync::atomic::Ordering::Relaxed);
            Instant::now() + Duration::from_millis(skew)
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }

    fn client(&self) -> Result<&reqwest::Client, String> {
        self.client
            .get_or_init(|| {
                crate::secrets_door::install_crypto_provider();
                reqwest::Client::builder()
                    .timeout(REQUEST_TIMEOUT)
                    // A redirect would carry the bearer somewhere the unit
                    // never named.
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|err| format!("building the HTTP client: {err}"))
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    /// The unit's config as it is NOW: the staged one, narrowed by the door
    /// when the unit asks for it. A unit without `access.door` is returned
    /// untouched and nothing is fetched.
    pub(crate) async fn effective(
        &self,
        staged: InteropConfig,
        unit: &UnitRef<'_>,
        limiter: &RateLimiter,
        now_ms: u64,
    ) -> InteropConfig {
        if !staged.access_door {
            return staged;
        }
        let Some(metering) = staged.metering.clone() else {
            warn_once(
                unit,
                "its document sets `access.door` but stages no usable `metering` block to \
                 authenticate with; the staged policy stands",
            );
            return staged;
        };
        let url = match door_url(&metering) {
            Ok(url) => url,
            Err(reason) => {
                warn_once(unit, &format!("{reason}; the staged policy stands"));
                return staged;
            }
        };
        let slot = std::sync::Arc::clone(
            self.slots
                .entry((unit.tenant.to_string(), unit.bundle_id.to_string()))
                .or_default()
                .value(),
        );
        let mut state = slot.state.lock().await;
        let now = self.now();
        let fresh = state
            .fetched_at
            .is_some_and(|at| now.saturating_duration_since(at) < TTL);
        let floored = state
            .attempted_at
            .is_some_and(|at| now.saturating_duration_since(at) < REFRESH_FLOOR);
        if !fresh && !floored {
            state.attempted_at = Some(now);
            self.refresh(&mut state, &url, &metering, unit).await;
        }
        let Some(answer) = state.answer.clone() else {
            return staged;
        };
        if let Some(deployment) = unit.deployment {
            let key = (deployment.to_string(), state.seq);
            if state.reconciled.as_ref() != Some(&key) {
                limiter
                    .anonymous
                    .reconcile_daily(deployment, now_ms, answer.daily_turns_used);
                state.reconciled = Some(key);
            }
        }
        let effective = tighten(staged, &answer);
        if effective.access.mechanisms.is_empty() && state.reported_deny_all != Some(state.seq) {
            state.reported_deny_all = Some(state.seq);
            operator_log::error(
                module_path!(),
                format!(
                    "access door for unit `{}`: none of the staged mechanisms is allowed by the \
                     admin's policy (generation {}); every credential is refused",
                    unit.bundle_id, answer.generation
                ),
            );
        }
        effective
    }

    async fn refresh(
        &self,
        state: &mut SlotState,
        url: &str,
        metering: &MeteringConfig,
        unit: &UnitRef<'_>,
    ) {
        let outcome = match self.client() {
            Ok(client) => fetch(client, url, metering, state.etag.as_deref()).await,
            Err(reason) => Err(reason),
        };
        match outcome {
            Ok(Fetched::NotModified) => {
                state.fetched_at = state.attempted_at;
                recovered(state, unit);
            }
            Ok(Fetched::Answer(answer, etag)) => {
                state.fetched_at = state.attempted_at;
                if state.answer.as_deref() != Some(&*answer) {
                    state.seq += 1;
                }
                if state.answer.as_ref().map(|old| old.generation) != Some(answer.generation) {
                    operator_log::info(
                        module_path!(),
                        format!(
                            "access door for unit `{}`: policy generation {} in effect",
                            unit.bundle_id, answer.generation
                        ),
                    );
                }
                state.answer = Some(std::sync::Arc::new(*answer));
                state.etag = etag;
                recovered(state, unit);
            }
            Err(reason) => {
                // The last good answer (or the staged policy) keeps serving.
                if state.last_failure.as_deref() != Some(reason.as_str()) {
                    operator_log::warn(
                        module_path!(),
                        format!(
                            "access door for unit `{}`: {reason}; keeping {}",
                            unit.bundle_id,
                            if state.answer.is_some() {
                                "the last good answer"
                            } else {
                                "the staged policy"
                            }
                        ),
                    );
                    state.last_failure = Some(reason);
                }
            }
        }
    }
}

fn recovered(state: &mut SlotState, unit: &UnitRef<'_>) {
    if state.last_failure.take().is_some() {
        operator_log::info(
            module_path!(),
            format!("access door for unit `{}`: answering again", unit.bundle_id),
        );
    }
}

fn door_url(metering: &MeteringConfig) -> Result<String, String> {
    sibling_door(&metering.endpoint, ACCESS_POLICY_SEGMENT).map_err(|err| match err {
        SiblingDoorError::Unparseable => format!(
            "the metering endpoint `{}` is not a URL, so the access-policy door cannot be derived",
            metering.endpoint
        ),
        SiblingDoorError::NotWorkerUsage => format!(
            "the metering endpoint `{}` does not end in `/worker-usage`, so the access-policy \
             door beside it cannot be derived",
            metering.endpoint
        ),
    })
}

/// One GET. The error text names statuses and transport reasons only: never
/// the token, never a body.
async fn fetch(
    client: &reqwest::Client,
    url: &str,
    metering: &MeteringConfig,
    etag: Option<&str>,
) -> Result<Fetched, String> {
    let mut request = client
        .get(url)
        // The ONE place the token is used: a header, never the URL or a log.
        .bearer_auth(metering.token.expose())
        .header(reqwest::header::ACCEPT, "application/json");
    if let Some(etag) = etag {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    let mut response = request
        .send()
        .await
        .map_err(|err| format!("did not answer: {}", err.without_url()))?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::NOT_MODIFIED if etag.is_some() => return Ok(Fetched::NotModified),
        StatusCode::NOT_FOUND => {
            return Err("answered 404: the admin predates the door".to_string());
        }
        StatusCode::UNAUTHORIZED => {
            return Err("answered 401: the unit's token is invalid or revoked".to_string());
        }
        StatusCode::FORBIDDEN => {
            return Err("answered 403: the unit's token lacks the `access` purpose".to_string());
        }
        other => return Err(format!("answered {}", other.as_u16())),
    }
    let new_etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| format!("did not finish its answer: {}", err.without_url()))?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(format!("answered with a body over {MAX_BODY_BYTES} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    let answer = parse_answer(&body).map_err(|reason| format!("answered with {reason}"))?;
    Ok(Fetched::Answer(Box::new(answer), new_etag))
}

fn warn_once(unit: &UnitRef<'_>, message: &str) {
    use std::collections::HashSet;
    use std::sync::{LazyLock, Mutex};
    static SAID: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Mutex::default);
    let first = SAID.lock().is_ok_and(|mut said| {
        said.len() < 1024 && said.insert(format!("{}|{message}", unit.bundle_id))
    });
    if first {
        operator_log::warn(
            module_path!(),
            format!("access door for unit `{}`: {message}", unit.bundle_id),
        );
    }
}
