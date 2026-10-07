//! Only the host may write what the runner reads as stored attachments.
//!
//! The runner treats `attachments[i].url = "artifact://…"`,
//! `extensions["artifacts"]` and `extensions["attachment_notes"]` as the
//! host's output: an `artifact://` url is read through the tenant-wide door,
//! and a note is shown to the agent. A provider writing any of them could
//! point the agent at another file of the tenant or put its own words in front
//! of the agent. So every one of them is removed BEFORE the pipeline runs;
//! whatever is there afterwards was written by this host.

use std::sync::atomic::{AtomicU64, Ordering};

use greentic_types::ChannelMessageEnvelope;
use reqwest::Url;

use super::ingest::{ARTIFACTS_KEY, NOTES_KEY};

const ARTIFACT_SCHEME: &str = "artifact";

/// How often forged host fields were removed, per source. They arrive per
/// request, so the operator is told once per process and every later
/// occurrence is counted at debug: a client sending them on every request
/// cannot flood the log.
pub(crate) struct Occurrences(AtomicU64);

impl Occurrences {
    pub(crate) const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Adds `removed`; `true` when this is the first occurrence (warn it).
    pub(crate) fn record(&self, removed: usize) -> bool {
        if removed == 0 {
            return false;
        }
        self.0.fetch_add(removed as u64, Ordering::Relaxed) == 0
    }

    pub(crate) fn total(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

static FROM_PROVIDERS: Occurrences = Occurrences::new();
static FROM_CLIENTS: Occurrences = Occurrences::new();

/// Removes provider-written host fields. Returns how many attachment urls
/// were cleared (for a count-only log line). Leaves every other byte alone.
pub(crate) fn strip_reserved(envelope: &mut ChannelMessageEnvelope) -> usize {
    envelope.extensions.remove(ARTIFACTS_KEY);
    envelope.extensions.remove(NOTES_KEY);
    let mut cleared = 0;
    for attachment in &mut envelope.attachments {
        if attachment.url.as_deref().is_some_and(is_artifact_url) {
            attachment.url = None;
            cleared += 1;
        }
    }
    if FROM_PROVIDERS.record(cleared) {
        tracing::warn!(
            cleared,
            "a provider sent artifact references the host did not create; they were removed \
             (later occurrences are counted at debug)"
        );
    } else if cleared > 0 {
        tracing::debug!(
            cleared,
            total = FROM_PROVIDERS.total(),
            "provider-written artifact references removed"
        );
    }
    cleared
}

/// Invisible format characters (category Cf: BOM, zero-width, bidi marks)
/// that a lenient reader may skip but `Url::parse` does not.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
    )
}

/// Any url whose scheme is `artifact`, however it is spelt: invisible format
/// characters removed, then parsed as a URL (which lowercases the scheme and
/// drops leading control characters and spaces), and checked by a
/// case-insensitive prefix after trimming, so no spelling a lenient reader
/// would accept gets through.
pub(crate) fn is_artifact_url(url: &str) -> bool {
    let url: String = url.chars().filter(|c| !is_invisible_format(*c)).collect();
    if Url::parse(&url).is_ok_and(|u| u.scheme() == ARTIFACT_SCHEME) {
        return true;
    }
    let url = url.trim_start_matches(|c: char| c.is_whitespace() || c.is_control());
    url.get(..ARTIFACT_SCHEME.len() + 1)
        .is_some_and(|head| head.eq_ignore_ascii_case("artifact:"))
}

/// Keys only the host writes into what a flow reads as its entry.
const HOST_ONLY_KEYS: [&str; 3] = [ARTIFACTS_KEY, NOTES_KEY, "attachment_meta"];

/// The JSON-door twin of [`strip_reserved`], for a body a CLIENT wrote
/// (generic ingress, `/workers/invoke`, agent-to-agent and MCP answers): at
/// the root and under `metadata` (the two places a flow reads its entry
/// from), and in each one's `extensions`, the host-only keys are removed and
/// every `artifact://` attachment url is cleared. Every other field is left
/// alone. Returns how many things were removed (for a count-only log line).
pub(crate) fn strip_reserved_json(payload: &mut serde_json::Value) -> usize {
    let mut removed = strip_scope(payload);
    if let Some(metadata) = payload.get_mut("metadata") {
        removed += strip_scope(metadata);
    }
    if FROM_CLIENTS.record(removed) {
        tracing::warn!(
            removed,
            "a request body carried attachment fields only the host may write; they were \
             removed (later occurrences are counted at debug)"
        );
    } else if removed > 0 {
        tracing::debug!(
            removed,
            total = FROM_CLIENTS.total(),
            "client-written attachment fields removed"
        );
    }
    removed
}

fn strip_scope(scope: &mut serde_json::Value) -> usize {
    use serde_json::Value;
    let Value::Object(map) = scope else {
        return 0;
    };
    let mut removed = 0;
    for key in HOST_ONLY_KEYS {
        removed += usize::from(map.remove(key).is_some());
    }
    if let Some(Value::Object(extensions)) = map.get_mut("extensions") {
        for key in HOST_ONLY_KEYS {
            removed += usize::from(extensions.remove(key).is_some());
        }
    }
    if let Some(Value::Array(attachments)) = map.get_mut("attachments") {
        for attachment in attachments {
            match attachment {
                Value::Object(entry) => {
                    let forged = entry
                        .get("url")
                        .and_then(Value::as_str)
                        .is_some_and(is_artifact_url);
                    if forged {
                        entry.insert("url".into(), Value::Null);
                        removed += 1;
                    }
                }
                Value::String(url) if is_artifact_url(url) => {
                    *attachment = Value::Null;
                    removed += 1;
                }
                _ => {}
            }
        }
    }
    removed
}
