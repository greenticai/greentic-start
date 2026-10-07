//! Provider drop counters become agent-visible notes (master plan C1,
//! DECISION on provider-edge drops; host checklist 9).
//!
//! A provider that drops an attachment, or a whole message, before the host
//! sees it keeps a COUNTER in `metadata` (`attachments_dropped`,
//! `messages_dropped`) and never writes a note itself. The host turns the
//! counters into slots appended after every real attachment, each with
//! `url = null`, `extensions["artifacts"][j] = null` and a fixed-text
//! `fetch_failed` note, so the agent can say a file did not arrive instead of
//! answering as if nothing had been sent. Nothing from the envelope (a name, an
//! id, provider text) is ever copied into one of these slots.

use greentic_types::{Attachment, ChannelMessageEnvelope};
use serde_json::{Value, json};

use super::ingest::{ARTIFACTS_KEY, NOTES_KEY};
use super::limits::MAX_FILES;

pub(crate) const FILES_COUNTER: &str = "attachments_dropped";
pub(crate) const MESSAGES_COUNTER: &str = "messages_dropped";
pub(crate) const FILE_DROPPED: &str = "a file sent on the channel could not be received";
pub(crate) const MESSAGE_DROPPED: &str = "an earlier message could not be received";

/// Appends one slot per dropped attachment and one slot when any message was
/// dropped, at most [`MAX_FILES`] in all (a hostile counter cannot grow the
/// envelope; the message slot is kept when the cap bites). A counter that is
/// absent, `0` or not a plain non-negative integer adds nothing. Both counters
/// are removed from `metadata` either way; an envelope without them is left
/// byte for byte unchanged.
pub(crate) fn append_drop_notes(envelope: &mut ChannelMessageEnvelope) {
    let files = take_counter(envelope, FILES_COUNTER);
    let messages = take_counter(envelope, MESSAGES_COUNTER);
    let message_slots = usize::from(messages > 0);
    let file_slots = usize::try_from(files)
        .unwrap_or(usize::MAX)
        .min(MAX_FILES - message_slots);
    if file_slots + message_slots == 0 {
        return;
    }
    let len = envelope.attachments.len();
    let mut artifacts = parallel_array(envelope, ARTIFACTS_KEY, len);
    let mut notes = parallel_array(envelope, NOTES_KEY, len);
    let sentences = std::iter::repeat_n(FILE_DROPPED, file_slots)
        .chain(std::iter::repeat_n(MESSAGE_DROPPED, message_slots));
    for sentence in sentences {
        envelope.attachments.push(Attachment {
            mime_type: "application/octet-stream".into(),
            url: None,
            content: None,
            name: Some("file".into()),
            size_bytes: Some(0),
        });
        artifacts.push(Value::Null);
        notes.push(json!({ "code": "fetch_failed", "message": sentence }));
    }
    envelope
        .extensions
        .insert(ARTIFACTS_KEY.into(), Value::Array(artifacts));
    envelope
        .extensions
        .insert(NOTES_KEY.into(), Value::Array(notes));
}

/// The counter's value, removing it; `0` for anything unusable.
fn take_counter(envelope: &mut ChannelMessageEnvelope, key: &str) -> u64 {
    envelope
        .metadata
        .remove(key)
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// `extensions[key]` as an array exactly as long as the real attachments, so
/// the appended entries line up by index with the appended slots.
fn parallel_array(envelope: &ChannelMessageEnvelope, key: &str, len: usize) -> Vec<Value> {
    let mut items = match envelope.extensions.get(key) {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    items.resize(len, Value::Null);
    items
}
