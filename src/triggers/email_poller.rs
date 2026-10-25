//! The `email_imap` poller: one task for the server's life, modelled on
//! [`super::scheduler`]. Each pass finds the email triggers of the live
//! activation that are due, lets the traffic split pick the serving revision,
//! and polls that trigger's mailbox once.
//!
//! The IMAP protocol sits behind [`ImapConnector`] / [`ImapSession`], so the
//! whole policy below (idempotency, size caps, auth failure, backoff, budget)
//! is tested with a fake and no network. No IMAP crate is compiled in yet
//! (none is in the lockfile); [`default_connector`] returns `None` and the
//! loop is then not started. See the addendum for the crate decision.
//!
//! Per message, in this order, and the order is the point:
//! 1. in-flight permit — none free stops the poll, the rest stay unseen;
//! 2. fetch (size-capped) — an oversize mail is reported, never fetched whole;
//! 3. hourly budget, THEN the idempotency claim — a claim taken for a message
//!    the budget then refuses would dedupe it forever;
//! 4. fire (the permit moves into the run);
//! 5. mark seen / move — after the firing is accepted, so a crash in between
//!    re-lists the mail and the idempotency claim stops a second firing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::dispatch::{self, Firing};
use super::email::{AttachmentMode, EmailImapSpec, OnSuccess, SearchFilter};
use super::scheduler::pick_revision;
use super::store::{self, TriggerStore};
use super::table::LoadedTrigger;
use super::webhook::{RunnerTriggerHost, TriggerHost};
use super::{limits, telemetry};
use crate::deployment_routes::RevisionIngressRouting;

const TICK: Duration = Duration::from_secs(5);
/// A whole poll (connect, list, fetch) gets this long.
const POLL_TIMEOUT: Duration = Duration::from_secs(90);
/// How long a seen Message-ID suppresses a repeat. Long on purpose: a mail
/// moved back to the inbox weeks later must not refire.
const SEEN_TTL: Duration = Duration::from_secs(30 * 86_400);
/// Never retry a rejected login sooner than this: repeated bad logins lock
/// real accounts.
const AUTH_BACKOFF: Duration = Duration::from_secs(900);
const MAX_BACKOFF: Duration = Duration::from_secs(900);
const MAX_HEADER_CHARS: usize = 998;

#[allow(
    dead_code,
    reason = "constructed by the IMAP connector, not compiled in yet"
)]
#[derive(Debug, thiserror::Error)]
pub(crate) enum ImapError {
    /// The server refused the credentials.
    #[error("authentication failed")]
    Auth,
    /// Anything else: DNS, TLS, timeout, protocol. The text is for logs only
    /// and must not contain the password.
    #[error("imap transport error: {0}")]
    Transport(String),
}

#[derive(Clone, Debug)]
pub(crate) struct MailboxState {
    pub uid_validity: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct MailAttachment {
    pub name: String,
    pub mime_type: String,
    pub size_bytes: u64,
    /// Present only when the session was asked for bytes.
    pub bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub(crate) struct MailMessage {
    pub message_id: Option<String>,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
    pub received_at: DateTime<Utc>,
    pub attachments: Vec<MailAttachment>,
}

#[allow(
    dead_code,
    reason = "constructed by the IMAP connector, not compiled in yet"
)]
#[derive(Clone, Debug)]
pub(crate) enum Fetched {
    Message(Box<MailMessage>),
    /// RFC822.SIZE exceeded the cap; nothing else was downloaded.
    TooLarge {
        size: u64,
    },
    /// The message vanished between SEARCH and FETCH.
    Gone,
}

/// One authenticated IMAP session. Implementations quote every argument.
#[async_trait]
pub(crate) trait ImapSession: Send {
    async fn select(&mut self, mailbox: &str) -> Result<MailboxState, ImapError>;
    async fn search(&mut self, filter: &SearchFilter) -> Result<Vec<u32>, ImapError>;
    async fn fetch(&mut self, uid: u32, max_bytes: usize) -> Result<Fetched, ImapError>;
    async fn mark_seen(&mut self, uid: u32) -> Result<(), ImapError>;
    async fn move_to(&mut self, uid: u32, mailbox: &str) -> Result<(), ImapError>;
}

#[async_trait]
pub(crate) trait ImapConnector: Send + Sync {
    /// Connect with TLS per `spec.tls` (certificate verification mandatory) and
    /// log in. `password` is the resolved secret value.
    async fn connect(
        &self,
        spec: &EmailImapSpec,
        password: &str,
    ) -> Result<Box<dyn ImapSession>, ImapError>;
}

/// Stores attachment bytes through the artifacts lane; returns a reference.
#[async_trait]
pub(crate) trait AttachmentSink: Send + Sync {
    async fn store(&self, name: &str, mime_type: &str, bytes: Vec<u8>) -> anyhow::Result<String>;
}

/// Placeholder sink until the artifacts lane is wired to triggers: the flow
/// then gets `artifact: null` for every attachment.
pub(crate) struct DroppedAttachments;

#[async_trait]
impl AttachmentSink for DroppedAttachments {
    async fn store(&self, _: &str, _: &str, _: Vec<u8>) -> anyhow::Result<String> {
        anyhow::bail!("attachment storage is not wired for triggers yet")
    }
}

/// The real IMAP client. `None` until a crate is chosen (see addendum).
pub(crate) fn default_connector() -> Option<Arc<dyn ImapConnector>> {
    None
}

/// What one poll of one trigger concluded, for the caller's scheduling.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PollResult {
    /// Polled (possibly nothing new). `fired` counts accepted firings.
    Polled { fired: usize },
    /// Not polled for a reason that retrying at the normal cadence is right for.
    Skipped,
    /// Login refused: back off hard, never run the flow.
    AuthFailed,
    /// Connection or protocol failure: back off exponentially.
    Failed,
}

pub(crate) struct PollCtx<'a> {
    pub host: &'a dyn TriggerHost,
    pub connector: &'a dyn ImapConnector,
    pub sink: &'a dyn AttachmentSink,
    pub store: &'a Arc<dyn TriggerStore>,
}

/// Poll one email trigger once.
pub(crate) async fn poll_entry(
    ctx: &PollCtx<'_>,
    env: &str,
    entry: &Arc<LoadedTrigger>,
    spec: &EmailImapSpec,
    now: DateTime<Utc>,
) -> PollResult {
    if !entry.spec.enabled {
        telemetry::record(entry, "skipped", "disabled");
        return PollResult::Skipped;
    }
    if entry.unavailable.is_some() {
        telemetry::record(entry, "skipped", "unavailable");
        return PollResult::Skipped;
    }
    // One poller per interval across replicas. A store error skips the poll:
    // polling anyway would let every replica list (and race on) the mailbox.
    let bucket = now.timestamp() / spec.poll_interval_s as i64;
    let lease = store::key(
        "poll",
        env,
        &entry.scope.deployment_id.to_string(),
        &entry.spec.trigger_id,
        &bucket.to_string(),
    );
    match ctx
        .store
        .claim(&lease, Duration::from_secs(spec.poll_interval_s))
        .await
    {
        Ok(true) => {}
        Ok(false) => return PollResult::Skipped,
        Err(err) => {
            warn(entry, format!("poll skipped, store unavailable ({err:#})"));
            telemetry::record(entry, "skipped", "store_unavailable");
            return PollResult::Skipped;
        }
    }
    let password = match ctx.host.read_secret(entry, &spec.password_ref).await {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s.trim_end_matches(['\r', '\n']).to_string(),
            Err(_) => {
                telemetry::record(entry, "skipped", "secret_unavailable");
                return PollResult::Skipped;
            }
        },
        Err(err) => {
            // Never poll without credentials, never fall back to anything.
            warn(entry, format!("password unreadable ({err:#})"));
            telemetry::record(entry, "skipped", "secret_unavailable");
            return PollResult::Skipped;
        }
    };
    let mut session = match ctx.connector.connect(spec, &password).await {
        Ok(s) => s,
        Err(ImapError::Auth) => {
            warn(
                entry,
                "login refused by the mail server; backing off".into(),
            );
            telemetry::record(entry, "rejected", "auth");
            return PollResult::AuthFailed;
        }
        Err(err) => return failed(entry, &err),
    };
    match poll_session(ctx, env, entry, spec, session.as_mut()).await {
        Ok(fired) => PollResult::Polled { fired },
        Err(ImapError::Auth) => {
            telemetry::record(entry, "rejected", "auth");
            PollResult::AuthFailed
        }
        Err(err) => failed(entry, &err),
    }
}

fn failed(entry: &LoadedTrigger, err: &ImapError) -> PollResult {
    warn(entry, format!("{err}"));
    telemetry::record(entry, "failed", "transport");
    PollResult::Failed
}

async fn poll_session(
    ctx: &PollCtx<'_>,
    env: &str,
    entry: &Arc<LoadedTrigger>,
    spec: &EmailImapSpec,
    session: &mut dyn ImapSession,
) -> Result<usize, ImapError> {
    let mailbox = session.select(&spec.mailbox).await?;
    let mut uids = session.search(&spec.search).await?;
    uids.sort_unstable();
    uids.truncate(spec.max_messages_per_poll as usize);
    let mut fired = 0;
    for uid in uids {
        let Some(permit) = limits::try_acquire(entry) else {
            telemetry::record(entry, "skipped", "overlap");
            break;
        };
        let message = match session.fetch(uid, spec.max_message_bytes).await? {
            Fetched::Message(m) => *m,
            Fetched::Gone => continue,
            Fetched::TooLarge { size } => {
                // Reported and taken out of the way so it is not re-listed
                // forever; the flow never sees it.
                warn(
                    entry,
                    format!("message uid {uid} is {size} bytes, over the cap; not fired"),
                );
                telemetry::record(entry, "skipped", "too_large");
                finish(session, spec, entry, uid).await;
                continue;
            }
        };
        if !limits::within_budget(ctx.store.as_ref(), env, entry).await {
            telemetry::record(entry, "skipped", "budget");
            break;
        }
        let identity = message_identity(&message, mailbox.uid_validity, uid);
        let seen = store::key(
            "seen",
            env,
            &entry.scope.deployment_id.to_string(),
            &entry.spec.trigger_id,
            &identity,
        );
        match ctx.store.claim(&seen, SEEN_TTL).await {
            Ok(true) => {}
            Ok(false) => {
                telemetry::record(entry, "deduplicated", "message_id");
                finish(session, spec, entry, uid).await;
                continue;
            }
            Err(err) => {
                // Firing without the seen-set could double-fire a mail.
                warn(entry, format!("store unavailable ({err:#}); poll stopped"));
                telemetry::record(entry, "skipped", "store_unavailable");
                break;
            }
        }
        let firing_id = dispatch::new_firing_id();
        let payload = email_payload(
            ctx,
            spec,
            entry,
            &firing_id,
            Utc::now(),
            &message,
            mailbox.uid_validity,
            uid,
        )
        .await;
        let firing = Firing {
            session_hint: dispatch::session_hint(&entry.spec, &firing_id, None),
            payload,
            firing_id,
        };
        ctx.host.spawn_fire(Arc::clone(entry), firing, permit);
        fired += 1;
        finish(session, spec, entry, uid).await;
    }
    Ok(fired)
}

/// Apply the success policy. A failure is logged and swallowed: the message was
/// already claimed, so the worst case is a re-listing, not a second firing.
async fn finish(
    session: &mut dyn ImapSession,
    spec: &EmailImapSpec,
    entry: &LoadedTrigger,
    uid: u32,
) {
    let result = match &spec.on_success {
        OnSuccess::MarkSeen => session.mark_seen(uid).await,
        OnSuccess::MoveTo(target) => session.move_to(uid, target).await,
        OnSuccess::None => Ok(()),
    };
    if let Err(err) = result {
        warn(entry, format!("could not mark uid {uid} processed ({err})"));
    }
}

/// Message-ID when the mail has one, else `<UIDVALIDITY>:<UID>`. The
/// Message-ID is preferred because UIDs are renumbered when the server changes
/// UIDVALIDITY, which would refire the whole mailbox.
fn message_identity(message: &MailMessage, uid_validity: u32, uid: u32) -> String {
    match message.message_id.as_deref().map(str::trim) {
        Some(id) if !id.is_empty() => format!("mid:{id}"),
        _ => format!("uid:{uid_validity}:{uid}"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn email_payload(
    ctx: &PollCtx<'_>,
    spec: &EmailImapSpec,
    entry: &LoadedTrigger,
    firing_id: &str,
    fired_at: DateTime<Utc>,
    message: &MailMessage,
    uid_validity: u32,
    uid: u32,
) -> Value {
    let (text, truncated) = bounded_text(&message.text, spec.max_message_bytes);
    let html = if spec.include_html {
        message
            .html
            .as_deref()
            .map(|h| bounded_text(h, spec.max_message_bytes).0)
    } else {
        None
    };
    let mut attachments = Vec::new();
    for a in &message.attachments {
        let artifact = match (&spec.attachments, &a.bytes) {
            (AttachmentMode::Artifacts, Some(bytes)) => ctx
                .sink
                .store(&a.name, &a.mime_type, bytes.clone())
                .await
                .map_err(|err| warn(entry, format!("attachment not stored ({err:#})")))
                .ok(),
            _ => None,
        };
        attachments.push(json!({
            "name": clean_header(&a.name),
            "mime_type": clean_header(&a.mime_type),
            "size_bytes": a.size_bytes,
            "artifact": artifact,
        }));
    }
    json!({
        "trigger": dispatch::trigger_block(&entry.spec, firing_id, fired_at),
        "webhook": Value::Null,
        "cron": Value::Null,
        "email": {
            "from": clean_header(&message.from),
            "to": message.to.iter().map(|t| clean_header(t)).collect::<Vec<_>>(),
            "subject": clean_header(&message.subject),
            "text": text,
            "html": html,
            "truncated": truncated,
            "message_id": message.message_id.as_deref().map(clean_header),
            "received_at": message.received_at.to_rfc3339(),
            "mailbox": spec.mailbox,
            "uid": uid,
            "uid_validity": uid_validity,
            "attachments": attachments,
        },
    })
}

/// A header value as the flow sees it: no control characters (so no CR/LF to
/// smuggle a second header into a flow that echoes it into a reply), bounded.
pub(crate) fn clean_header(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .take(MAX_HEADER_CHARS)
        .collect()
}

/// Body text with NULs and other control characters (except newline, return,
/// tab) removed, cut to `max` bytes on a character boundary.
fn bounded_text(raw: &str, max: usize) -> (String, bool) {
    let mut out = String::new();
    let mut truncated = false;
    for c in raw.chars() {
        if c.is_control() && !matches!(c, '\n' | '\r' | '\t') {
            continue;
        }
        if out.len() + c.len_utf8() > max {
            truncated = true;
            break;
        }
        out.push(c);
    }
    (out, truncated)
}

fn warn(entry: &LoadedTrigger, detail: String) {
    crate::operator_log::warn(
        module_path!(),
        format!("trigger `{}` (email_imap): {detail}", entry.spec.trigger_id),
    );
}

struct EntryState {
    next_due: Instant,
    failures: u32,
}

/// Run until aborted.
pub(crate) async fn run<F>(
    current: F,
    store: Arc<dyn TriggerStore>,
    connector: Arc<dyn ImapConnector>,
    sink: Arc<dyn AttachmentSink>,
) where
    F: Fn() -> (
            Arc<greentic_runner_host::RunnerHost>,
            Arc<RevisionIngressRouting>,
        ) + Send
        + Sync
        + 'static,
{
    let mut states: HashMap<String, EntryState> = HashMap::new();
    loop {
        tokio::time::sleep(TICK).await;
        let (host, routing) = current();
        let env = routing.dispatcher.env_id().to_string();
        let trigger_host = RunnerTriggerHost(host);
        for entry in routing.triggers.email_entries() {
            let super::schema::TriggerKind::EmailImap(spec) = &entry.spec.kind else {
                continue;
            };
            let key = format!(
                "{}:{}:{}",
                entry.scope.deployment_id, entry.scope.revision_id, entry.spec.trigger_id
            );
            let state = states.entry(key).or_insert(EntryState {
                next_due: Instant::now(),
                failures: 0,
            });
            if Instant::now() < state.next_due {
                continue;
            }
            if pick_revision(&routing, &env, entry).await != Some(entry.scope.revision_id) {
                continue;
            }
            let ctx = PollCtx {
                host: &trigger_host,
                connector: connector.as_ref(),
                sink: sink.as_ref(),
                store: &store,
            };
            let result = tokio::time::timeout(
                POLL_TIMEOUT,
                poll_entry(&ctx, &env, entry, spec, Utc::now()),
            )
            .await
            .unwrap_or(PollResult::Failed);
            let interval = Duration::from_secs(spec.poll_interval_s);
            let (delay, failures) = next_delay(&result, interval, state.failures);
            state.failures = failures;
            state.next_due = Instant::now() + delay;
        }
    }
}

/// When to poll again, and the new consecutive-failure count.
pub(crate) fn next_delay(
    result: &PollResult,
    interval: Duration,
    failures: u32,
) -> (Duration, u32) {
    match result {
        PollResult::Polled { .. } | PollResult::Skipped => (interval, 0),
        PollResult::AuthFailed => (interval.max(AUTH_BACKOFF), failures + 1),
        PollResult::Failed => {
            let n = failures + 1;
            let scaled = interval.saturating_mul(1u32 << n.min(6));
            (scaled.min(MAX_BACKOFF).max(interval), n)
        }
    }
}

#[cfg(test)]
#[path = "email_poller_tests.rs"]
mod tests;
