//! The `email_imap` trigger kind: a flow started by mail arriving in an IMAP
//! mailbox. The host polls; nothing listens. See the addendum
//! `trigger-kind-email-imap.md` (to be merged into `trigger-contract-v1.md`).
//!
//! Parsing follows the rest of `schema.rs`: a malformed block of a kind this
//! host knows refuses the whole file, unknown FIELDS are ignored (§11).
//! Everything that ends up in an IMAP command (host, mailbox, search text) is
//! validated here to be free of control characters and quotes, so a
//! declaration cannot smuggle protocol commands; the client adapter must still
//! quote, this is the second lock.

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::schema::{non_empty, secret_ref};

pub(crate) const MIN_POLL_INTERVAL_S: u64 = 30;
const DEFAULT_POLL_INTERVAL_S: u64 = 60;
const MAX_POLL_INTERVAL_S: u64 = 86_400;
const DEFAULT_MAX_MESSAGES: u32 = 10;
const MAX_MAX_MESSAGES: u32 = 100;
const DEFAULT_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_MAX_MESSAGE_BYTES: usize = 25 * 1024 * 1024;
const MAX_FIELD_LEN: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsMode {
    /// Implicit TLS (IMAPS, port 993). The default.
    Tls,
    /// Plain connect, then STARTTLS; the session is refused if the upgrade
    /// fails. There is deliberately no plaintext mode.
    StartTls,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OnSuccess {
    MarkSeen,
    /// Move to this mailbox (IMAP MOVE, falling back to COPY + delete).
    MoveTo(String),
    /// Leave the message untouched; only the idempotency set prevents a repeat.
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttachmentMode {
    /// Attachments are described (name, type, size) but their bytes are dropped.
    None,
    /// Bytes are stored through the artifacts lane and referenced by URL.
    Artifacts,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SearchFilter {
    pub unseen: bool,
    pub from: Option<String>,
    pub subject: Option<String>,
}

#[allow(
    dead_code,
    reason = "port/tls/username are read by the IMAP connector, which is not compiled in yet"
)]
#[derive(Clone, Debug)]
pub(crate) struct EmailImapSpec {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    pub mailbox: String,
    pub username: String,
    /// A `<provider>/<key>` secret NAME (§8), never the password.
    pub password_ref: String,
    pub poll_interval_s: u64,
    pub search: SearchFilter,
    pub on_success: OnSuccess,
    pub max_messages_per_poll: u32,
    pub max_message_bytes: usize,
    pub include_html: bool,
    pub attachments: AttachmentMode,
}

pub(crate) fn parse(b: &Value) -> Result<EmailImapSpec> {
    let host = non_empty(b, "host")?;
    if host.len() > 253
        || !host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
    {
        bail!("email_imap.host must be a DNS name (letters, digits, `.`, `-`)");
    }
    let tls = match b.get("tls").and_then(Value::as_str) {
        None | Some("tls") => TlsMode::Tls,
        Some("starttls") => TlsMode::StartTls,
        Some(other) => bail!("email_imap.tls `{other}` must be `tls` or `starttls`"),
    };
    let default_port = if tls == TlsMode::Tls { 993 } else { 143 };
    let port = match b.get("port") {
        None | Some(Value::Null) => default_port,
        Some(v) => v
            .as_u64()
            .filter(|p| (1..=65_535).contains(p))
            .ok_or_else(|| anyhow!("email_imap.port must be 1..=65535"))? as u16,
    };
    let mailbox = match b.get("mailbox") {
        None | Some(Value::Null) => "INBOX".to_string(),
        Some(_) => safe_text(b, "mailbox")?,
    };
    let username = safe_text(b, "username")?;
    let password_ref = secret_ref(b, "password_ref")?;
    let poll_interval_s = match b.get("poll_interval_s") {
        None | Some(Value::Null) => DEFAULT_POLL_INTERVAL_S,
        Some(v) => v
            .as_u64()
            .filter(|n| (MIN_POLL_INTERVAL_S..=MAX_POLL_INTERVAL_S).contains(n))
            .ok_or_else(|| {
                anyhow!(
                    "email_imap.poll_interval_s must be {MIN_POLL_INTERVAL_S}..={MAX_POLL_INTERVAL_S}"
                )
            })?,
    };
    let search = match b.get("search") {
        None | Some(Value::Null) => SearchFilter {
            unseen: true,
            ..SearchFilter::default()
        },
        Some(s) => SearchFilter {
            unseen: s.get("unseen").and_then(Value::as_bool).unwrap_or(true),
            from: opt_safe_text(s, "from")?,
            subject: opt_safe_text(s, "subject")?,
        },
    };
    let on_success = match b.get("on_success").and_then(Value::as_str) {
        None | Some("mark_seen") => OnSuccess::MarkSeen,
        Some("none") => OnSuccess::None,
        Some("move") => OnSuccess::MoveTo(safe_text(b, "move_to")?),
        Some(other) => bail!("email_imap.on_success `{other}` must be mark_seen, move or none"),
    };
    if on_success == OnSuccess::None && search.unseen {
        // Nothing would ever take the message out of the UNSEEN set, so every
        // poll would re-list it. Idempotency stops a repeat firing, but the
        // mailbox would be re-scanned forever: an authoring mistake.
        bail!("email_imap.on_success `none` needs search.unseen = false");
    }
    let max_messages_per_poll = match b.get("max_messages_per_poll") {
        None | Some(Value::Null) => DEFAULT_MAX_MESSAGES,
        Some(v) => v
            .as_u64()
            .filter(|n| (1..=u64::from(MAX_MAX_MESSAGES)).contains(n))
            .ok_or_else(|| {
                anyhow!("email_imap.max_messages_per_poll must be 1..={MAX_MAX_MESSAGES}")
            })? as u32,
    };
    let max_message_bytes = match b.get("max_message_bytes") {
        None | Some(Value::Null) => DEFAULT_MAX_MESSAGE_BYTES,
        Some(v) => v
            .as_u64()
            .filter(|n| (1..=MAX_MAX_MESSAGE_BYTES as u64).contains(n))
            .ok_or_else(|| {
                anyhow!("email_imap.max_message_bytes must be 1..={MAX_MAX_MESSAGE_BYTES}")
            })? as usize,
    };
    let attachments = match b.get("attachments").and_then(Value::as_str) {
        None | Some("none") => AttachmentMode::None,
        Some("artifacts") => AttachmentMode::Artifacts,
        Some(other) => bail!("email_imap.attachments `{other}` must be `none` or `artifacts`"),
    };
    Ok(EmailImapSpec {
        host,
        port,
        tls,
        mailbox,
        username,
        password_ref,
        poll_interval_s,
        search,
        on_success,
        max_messages_per_poll,
        max_message_bytes,
        include_html: b
            .get("include_html")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        attachments,
    })
}

/// A value that may reach an IMAP command: no control characters, no quote or
/// backslash (the characters that end an IMAP quoted string), bounded.
fn safe_text(b: &Value, field: &str) -> Result<String> {
    let value = non_empty(b, field)?;
    check_safe(&value, field)?;
    Ok(value)
}

fn opt_safe_text(b: &Value, field: &str) -> Result<Option<String>> {
    match b.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => safe_text(b, field).map(Some),
    }
}

fn check_safe(value: &str, field: &str) -> Result<()> {
    if value.len() > MAX_FIELD_LEN
        || value
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\')
    {
        bail!(
            "email_imap `{field}` must be at most {MAX_FIELD_LEN} characters with no control characters, quote or backslash"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "email_tests.rs"]
mod tests;
