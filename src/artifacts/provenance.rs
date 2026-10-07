//! Only the host may write what the runner reads as stored attachments.
//!
//! The runner treats `attachments[i].url = "artifact://…"`,
//! `extensions["artifacts"]` and `extensions["attachment_notes"]` as the
//! host's output: an `artifact://` url is read through the tenant-wide door,
//! and a note is shown to the agent. A provider writing any of them could
//! point the agent at another file of the tenant or put its own words in front
//! of the agent. So every one of them is removed BEFORE the pipeline runs;
//! whatever is there afterwards was written by this host.

use greentic_types::ChannelMessageEnvelope;
use reqwest::Url;

use super::ingest::{ARTIFACTS_KEY, NOTES_KEY};

const ARTIFACT_SCHEME: &str = "artifact";

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
    if cleared > 0 {
        tracing::warn!(
            cleared,
            "a provider sent artifact references the host did not create; they were removed"
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
    if removed > 0 {
        tracing::warn!(
            removed,
            "a request body carried attachment fields only the host may write; they were removed"
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
