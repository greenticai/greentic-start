//! A unit that runs without attachments still tells the agent, per file, that
//! a file was sent and not read; it never carries the inline bytes on.

use greentic_types::ChannelMessageEnvelope;
use serde_json::Value;

use super::drops::append_drop_notes;
use super::fetch_ref::{EXTENSION_KEY as FETCH_KEY, parse_refs};
use super::ingest::{ARTIFACTS_KEY, NOTES_KEY, Note};
use super::label::display_label;
use super::unit::Off;

/// Every slot with a usable fetch reference gets `url = null` and a
/// `door_unavailable` note; the fetch references are removed. EVERY slot's
/// inline content is cleared, reference or not: a unit without attachments
/// never carries the request's bytes on. Envelopes without attachments are
/// left as they are. Provider drop counters still become notes.
pub(crate) fn refuse_all(envelope: &mut ChannelMessageEnvelope, off: Off) {
    let refs = parse_refs(&envelope.extensions);
    if refs.iter().any(Option::is_some) {
        let count = envelope.attachments.len();
        let mut notes = vec![Value::Null; count];
        let note = Note::new("door_unavailable", off.reason());
        for (index, attachment) in envelope.attachments.iter_mut().enumerate() {
            if refs.get(index).cloned().flatten().is_none() {
                continue;
            }
            attachment.url = None;
            attachment.content = None;
            notes[index] = note.to_value(&display_label(attachment.name.as_deref(), index));
        }
        envelope.extensions.remove(FETCH_KEY);
        envelope
            .extensions
            .insert(ARTIFACTS_KEY.into(), Value::Array(vec![Value::Null; count]));
        envelope
            .extensions
            .insert(NOTES_KEY.into(), Value::Array(notes));
    }
    for attachment in &mut envelope.attachments {
        attachment.content = None;
    }
    append_drop_notes(envelope);
}
