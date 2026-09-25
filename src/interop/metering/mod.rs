//! Recording what a deployed interop turn spent (worker-interop contract §8).
//!
//! A worker reachable over A2A and MCP spends its OWNER's LLM credentials on
//! turns nobody in that tenant initiated, and nothing anywhere recorded a
//! deployed turn before this — not for interop, not for any channel. The
//! per-credential rate limiter ([`super::limits`]) bounds a spike per PROCESS;
//! it is not a quota and makes an inflation attack slow rather than visible.
//!
//! **This records. It does not charge, and nothing here may grow a charging
//! path without the four preconditions in §8.4** — a priced meter, the tenant
//! derived from the credential, a model id carried (which needs a new field on
//! `greentic_aw_runtime::StepUsage`), and a written no-back-charge cutoff.
//!
//! # Shape
//!
//! - The unit's staged config gains an optional `metering {endpoint, token}`
//!   block. **Absent means off**, which is every deployment that exists today.
//! - One event per turn that RAN ([`event::UsageEvent`]), fire-and-forget
//!   through a bounded queue drained by one background task ([`sink`]).
//! - A request refused before the turn — bad bearer, rate limited, invalid
//!   params, busy — produces no event: nothing ran, so nothing was spent.
//!
//! # Three properties that must survive any change here
//!
//! - **The turn never waits.** [`Meter::record`] is synchronous and does
//!   nothing but `try_send`. A full queue DROPS rather than blocks or grows:
//!   the caller of an interop turn is holding a connection open, and metering
//!   is not worth a millisecond of it.
//! - **No message content leaves.** The event type has no field that could
//!   hold any. Two tests hold that, at two levels:
//!   `event_tests::the_event_carries_only_identifiers_and_counters` pins the
//!   type's serialized key set, and
//!   `a2a::rpc::rpc_tests::no_turn_content_reaches_the_recorded_event` drives
//!   a REAL turn whose every reply shape carries distinctive content and
//!   asserts the recorded event contains none of it, and no key beyond the
//!   list. The second is the one that catches a field added anywhere between
//!   the reply activities and the queue.
//! - **The token is a credential.** It is never logged, never rendered into an
//!   error, and never printed by `Debug` — only sent as a bearer header, and
//!   only to an `https` endpoint (or a loopback `http` one, which cannot leave
//!   the host).

pub(crate) mod event;
pub(crate) mod run_outcome;
pub(crate) mod runtime_meter;
mod sink;
#[cfg(test)]
pub(crate) mod testkit;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::mpsc;

use greentic_deploy_spec::ids::DeploymentId;

use crate::operator_log;
use event::{Surface, TurnUsage, UsageEvent};

/// Events held before the sink drains them.
///
/// Deep enough that an ordinary burst is never lost, shallow enough that a
/// dead admin cannot turn the queue into unbounded memory in a container with
/// a hard limit. Metering is best-effort by construction: a dropped event is
/// a missing row, not a failed turn.
const QUEUE_CAPACITY: usize = 1024;

/// The admin token this runtime posts usage with.
///
/// A newtype with a redacting [`std::fmt::Debug`], so no `{:?}` anywhere —
/// including one in a crate that has never heard of this module — can print
/// it. The plaintext is reachable only through [`MeteringToken::expose`],
/// whose one caller is the header the POST sends.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MeteringToken(String);

impl MeteringToken {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for MeteringToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MeteringToken(<redacted>)")
    }
}

/// A unit's RESOLVED metering configuration: where its usage events go, and
/// the tenant they are recorded against.
///
/// `tenant_slug` comes from the document's TOP LEVEL rather than from the
/// `metering` block, and it is not optional here on purpose — the admin's
/// ingest door requires the field and refuses a body whose value disagrees
/// with the token's own tenant (§8.3). Holding the slug inside this type is
/// what makes "a configured unit always sends one" structural rather than a
/// rule to remember: there is no way to build a `MeteringConfig` without it,
/// and [`event::UsageEvent::tenant_slug`] is likewise not an `Option`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MeteringConfig {
    pub endpoint: String,
    pub token: MeteringToken,
    pub tenant_slug: String,
}

/// Why a staged `metering` block did not configure metering.
///
/// A typed decision rather than only a log line, so a test can assert WHICH
/// refusal happened without standing up a global log sink. Every variant
/// means the same thing to a caller — metering is off for this unit — and
/// [`parse_metering`] is the one place that turns one into an operator line,
/// so a refusal costs exactly one warn per config read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MeteringRefusal {
    /// The block is not the shape this build reads.
    Malformed(String),
    /// `endpoint` or `token` is missing or blank.
    Incomplete,
    /// The document carries no top-level `tenant_slug`.
    ///
    /// **Metering is switched off rather than sending events without it.**
    /// The admin's ingest door declares `tenant_slug` as a required field and
    /// compares it to the token's tenant, so every such event would be a
    /// `400` — recorded nowhere, forever, with only a warn on this side.
    /// Refusing up front is the same fact stated once instead of per turn.
    /// The designer's contract makes the field non-optional in the staged
    /// document, so reaching this means a hand-written or mis-staged config.
    NoTenantSlug,
    /// The endpoint would carry the token in cleartext off this host.
    UnsafeEndpoint(String),
}

impl MeteringRefusal {
    /// The operator-facing sentence. Names the endpoint where there is one —
    /// an endpoint is not a credential — and never the token.
    pub(crate) fn message(&self) -> String {
        match self {
            MeteringRefusal::Malformed(err) => {
                format!("`metering` is malformed ({err}); metering is off")
            }
            MeteringRefusal::Incomplete => {
                "`metering` needs both an `endpoint` and a `token`; metering is off".to_string()
            }
            MeteringRefusal::NoTenantSlug => {
                "`metering` is staged but the document carries no `tenant_slug`, which the \
                 usage ingest requires and would refuse every event for; metering is off"
                    .to_string()
            }
            MeteringRefusal::UnsafeEndpoint(endpoint) => format!(
                "`metering.endpoint` `{endpoint}` is not https and not loopback http, so the \
                 usage token would travel in cleartext; metering is off"
            ),
        }
    }
}

/// Wire form of the `metering` block, before validation.
#[derive(Deserialize)]
struct RawMetering {
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    token: String,
}

/// Resolve the staged `metering` block against the document's `tenant_slug`.
///
/// Pure: every refusal is a value, so the decision is testable on its own and
/// [`parse_metering`] is the only thing that logs one.
///
/// **The endpoint must be `https`, or `http` on a loopback host.** The token
/// is a bearer credential; posting it in cleartext to anything reachable off
/// the host would disclose it to the network the worker runs on. Loopback is
/// allowed because a test or a sidecar collector on `127.0.0.1` cannot leave
/// the machine, and refusing it would make the feature untestable against a
/// stub.
pub(crate) fn resolve_metering(
    value: serde_json::Value,
    tenant_slug: Option<&str>,
) -> Result<MeteringConfig, MeteringRefusal> {
    let raw: RawMetering =
        serde_json::from_value(value).map_err(|err| MeteringRefusal::Malformed(err.to_string()))?;
    let endpoint = raw.endpoint.trim().to_string();
    let token = raw.token.trim().to_string();
    if endpoint.is_empty() || token.is_empty() {
        return Err(MeteringRefusal::Incomplete);
    }
    let tenant_slug = tenant_slug
        .map(str::trim)
        .filter(|slug| !slug.is_empty())
        .ok_or(MeteringRefusal::NoTenantSlug)?
        .to_string();
    if !endpoint_is_safe(&endpoint) {
        return Err(MeteringRefusal::UnsafeEndpoint(endpoint));
    }
    Ok(MeteringConfig {
        endpoint,
        token: MeteringToken(token),
        tenant_slug,
    })
}

/// [`resolve_metering`], with a refusal turned into one operator line.
///
/// `None` means metering is off for this unit. This is the ONE warn site, so
/// a refused block costs one line per config read rather than one per turn.
pub(crate) fn parse_metering(
    value: serde_json::Value,
    tenant_slug: Option<&str>,
    unit: &str,
) -> Option<MeteringConfig> {
    match resolve_metering(value, tenant_slug) {
        Ok(config) => Some(config),
        Err(refusal) => {
            warn(unit, &refusal.message());
            None
        }
    }
}

fn endpoint_is_safe(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
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

/// The deployment facts every one of a unit's events repeats, resolved once
/// per request rather than rebuilt per event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnitMetering {
    pub config: MeteringConfig,
    pub tenant_slug: String,
    pub deployment_id: String,
    pub bundle_id: String,
    pub agent_id: String,
}

/// The metering half of one in-flight request: the process queue, plus the
/// unit it is serving.
///
/// Carried as an `Option` on both interop contexts, and `None` is the whole
/// off switch: a unit that stages no `metering` block builds no
/// [`TurnMetering`], so no emit site has anything to call.
#[derive(Clone)]
pub(crate) struct TurnMetering {
    meter: Arc<Meter>,
    unit: UnitMetering,
    /// `true` when the unit's loaded revision carries the runner's
    /// worker-usage meter ([`runtime_meter`]), which already records every
    /// LLM iteration this turn runs. The turn is then recorded with its
    /// tokens ZEROED — see [`TurnMetering::tokens_recorded_by_runtime`].
    runtime_records_tokens: bool,
}

impl TurnMetering {
    /// `None` when the unit stages no `metering` block — i.e. the feature is
    /// off, which is every deployment that predates it.
    pub(crate) fn for_unit(
        meter: &Arc<Meter>,
        config: &super::config::InteropConfig,
        deployment_id: DeploymentId,
        bundle_id: &str,
    ) -> Option<Self> {
        let metering = config.metering.clone()?;
        Some(Self {
            meter: Arc::clone(meter),
            unit: UnitMetering {
                // From the metering config, never from `config.tenant_slug`:
                // the two are the same value in production, and reading the
                // one that was VALIDATED is what stops them drifting.
                tenant_slug: metering.tenant_slug.clone(),
                config: metering,
                deployment_id: deployment_id.to_string(),
                bundle_id: bundle_id.to_string(),
                // The runtime has no other source for an agent id: the
                // `dw.agent` node output carries `reply`/`trail`/
                // `terminated_by`/`usage` and no id, and neither does the
                // reply `Activity`. A designer that wants to name one stages
                // it as `agent.id`; the unit's own bundle id is the honest
                // fallback, because that is what this process knows it ran.
                agent_id: config
                    .agent
                    .id
                    .clone()
                    .filter(|id| !id.trim().is_empty())
                    .unwrap_or_else(|| bundle_id.to_string()),
            },
            runtime_records_tokens: false,
        })
    }

    /// Declare whether the runner's worker-usage meter records this unit's
    /// LLM tokens (Phase 2 §7, double counting).
    ///
    /// Token usage has ONE source. When the runner meter is installed it
    /// posts one `surface: "turn"` event per LLM iteration — the iterations an
    /// interop turn runs included — so this reporter keeps posting its
    /// per-turn event (surface, iterations, duration: the fact that an A2A or
    /// MCP turn happened) with `tokens_in` / `tokens_out` set to `0`. The
    /// admin forwarder skips a zero-quantity meter, so the turn stays visible
    /// and its tokens are counted once. `false` (the default, and every unit
    /// with no runner meter) records exactly what it always did.
    #[must_use]
    pub(crate) fn tokens_recorded_by_runtime(mut self, recorded: bool) -> Self {
        self.runtime_records_tokens = recorded;
        self
    }

    /// Record one turn. Synchronous, never fallible, never blocking.
    pub(crate) fn record(
        &self,
        surface: Surface,
        credential_id: Option<&str>,
        usage: TurnUsage,
        duration: Duration,
    ) {
        let usage = if self.runtime_records_tokens {
            TurnUsage {
                tokens_in: 0,
                tokens_out: 0,
                ..usage
            }
        } else {
            usage
        };
        let event = UsageEvent {
            event_id: event::new_event_id(),
            occurred_at: event::now_rfc3339(),
            tenant_slug: self.unit.tenant_slug.clone(),
            deployment_id: self.unit.deployment_id.clone(),
            bundle_id: self.unit.bundle_id.clone(),
            agent_id: self.unit.agent_id.clone(),
            credential_id: credential_id.map(str::to_string),
            surface: surface.as_str(),
            tokens_in: usage.tokens_in,
            tokens_out: usage.tokens_out,
            iterations: usage.iterations,
            // A turn measured in hours would still fit; the cast cannot
            // truncate anything a turn can produce.
            duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        };
        self.meter.record(&self.unit.config, event);
    }
}

/// One queued POST: the event, and the unit's own destination.
///
/// The destination travels WITH the event rather than being a property of the
/// queue, because one process can serve several units and each stages its own
/// endpoint and token. One bounded queue is what the memory bound needs; one
/// endpoint is not.
pub(crate) struct Queued {
    pub endpoint: String,
    pub token: MeteringToken,
    pub event: UsageEvent,
}

/// The process-wide bounded queue and the task that drains it.
pub(crate) struct Meter {
    sender: mpsc::Sender<Queued>,
    /// Taken by the first [`Meter::record`] that runs inside a tokio runtime,
    /// which is what spawns the drain task. Holding it here rather than
    /// spawning at construction keeps `InteropState::from_env` runtime-free.
    receiver: Mutex<Option<mpsc::Receiver<Queued>>>,
    /// `false` in the tests that want to INSPECT the queue instead of having
    /// it drained out from under them.
    spawn_sink: bool,
    dropped: AtomicU64,
}

impl Default for Meter {
    fn default() -> Self {
        Self::new(true)
    }
}

impl Meter {
    fn new(spawn_sink: bool) -> Self {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        Self {
            sender,
            receiver: Mutex::new(Some(receiver)),
            spawn_sink,
            dropped: AtomicU64::new(0),
        }
    }

    /// Enqueue one event. Never blocks, never fails, never retries.
    ///
    /// The counter below is the QUEUE's: events lost because the sink was not
    /// keeping up. Events the sink tried to deliver and could not are counted
    /// separately, per endpoint, and reported on [`sink`]'s suspension line —
    /// two faults with two different fixes, so two different lines.
    pub(crate) fn record(&self, target: &MeteringConfig, event: UsageEvent) {
        self.ensure_sink();
        let queued = Queued {
            endpoint: target.endpoint.clone(),
            token: target.token.clone(),
            event,
        };
        if let Err(mpsc::error::TrySendError::Full(_)) = self.sender.try_send(queued) {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            // Logged on powers of two so a sustained outage costs a handful of
            // lines rather than one per turn, while the first drop is always
            // reported.
            if dropped.is_power_of_two() {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "interop usage metering has dropped {dropped} events: the queue is full, \
                         so the usage sink is not keeping up or cannot be reached"
                    ),
                );
            }
        }
    }

    /// Start the drain task, once, on the first record that runs inside a
    /// tokio runtime.
    ///
    /// Taking the receiver out of the mutex IS the once-guard: a second caller
    /// finds `None` and returns. With no runtime — a synchronous unit test —
    /// nothing is spawned and the receiver stays put, so a later call from
    /// inside one still starts it. `tokio::spawn` is never called without a
    /// handle, because it panics without one and this is a request path.
    fn ensure_sink(&self) {
        if !self.spawn_sink {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Ok(mut slot) = self.receiver.lock() else {
            return;
        };
        let Some(receiver) = slot.take() else {
            return;
        };
        handle.spawn(sink::run(receiver));
    }

    #[cfg(test)]
    pub(crate) fn inspectable() -> Self {
        Self::new(false)
    }

    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Everything queued so far, drained. Only meaningful on an
    /// [`Meter::inspectable`] meter, whose sink never starts.
    #[cfg(test)]
    pub(crate) fn drain(&self) -> Vec<Queued> {
        let mut out = Vec::new();
        if let Ok(mut slot) = self.receiver.lock()
            && let Some(receiver) = slot.as_mut()
        {
            while let Ok(queued) = receiver.try_recv() {
                out.push(queued);
            }
        }
        out
    }
}

fn warn(unit: &str, message: &str) {
    operator_log::warn(
        module_path!(),
        format!("interop metering for unit `{unit}`: {message}"),
    );
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod mod_tests;
