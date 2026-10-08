//! Per-channel shape of a reply that carries files (docs/outbound-artifacts.md).
//!
//! - WebChat (`messaging.webchat*`): a typed attachment whose `url` is the
//!   signed link (the provider maps it to `contentUrl`); when the envelope
//!   also carries a raw DirectLine `attachments` array, the file is appended
//!   there too, because that array wins in the provider's encoder.
//! - Every other channel: NO typed attachment (it would make providers fetch
//!   the url natively and fail in channel-specific ways); the links go in the
//!   TEXT, one `name: url` line per file, and in a separate follow-up message
//!   when the reply carries a card (which hides or replaces the text).
//!
//! A refused file becomes its fixed sentence. A file name reaches the text
//! and the WebChat attachment only through [`safe_name`], so it cannot inject
//! markup.

use greentic_types::messaging::extensions::ext_keys;
use greentic_types::{Attachment, ChannelMessageEnvelope};
use serde_json::{Value, json};

use super::outbound::{OutboundFile, Resolved};
use super::provenance::{is_artifact_url, is_invisible_format};

const NAME_CHARS_MAX: usize = 80;

pub(crate) fn is_webchat(provider_type: &str) -> bool {
    provider_type.starts_with("messaging.webchat")
}

/// `[A-Za-z0-9 ._-]` kept, anything else `_`, at most 80 characters.
pub(crate) fn safe_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .take(NAME_CHARS_MAX)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        "file".to_string()
    } else {
        cleaned.to_string()
    }
}

fn has_card(envelope: &ChannelMessageEnvelope) -> bool {
    envelope
        .metadata
        .get("adaptive_card")
        .is_some_and(|card| !card.trim().is_empty())
        || envelope.extensions.contains_key(ext_keys::ADAPTIVE_CARD)
}

fn text_of(envelope: &ChannelMessageEnvelope) -> Option<&str> {
    envelope
        .text
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

/// `parts` joined by a blank line, skipping empty ones.
fn joined(parts: &[Option<String>]) -> Option<String> {
    let parts: Vec<&str> = parts
        .iter()
        .flatten()
        .map(String::as_str)
        .filter(|part| !part.is_empty())
        .collect();
    (!parts.is_empty()).then(|| parts.join("\n\n"))
}

fn notes(resolved: &Resolved) -> Option<String> {
    let mut sentences: Vec<&str> = Vec::new();
    for reason in &resolved.refused {
        let sentence = reason.sentence();
        if !sentences.contains(&sentence) {
            sentences.push(sentence);
        }
    }
    (!sentences.is_empty()).then(|| sentences.join("\n"))
}

/// Removes every `artifact://` url from the outgoing attachments and the raw
/// DirectLine `attachments` array, and every raw id from the text, the
/// metadata (the card's JSON string included) and the extensions (the card's
/// JSON included). Returns how many were removed.
pub(crate) fn strip_raw_artifact_urls(envelope: &mut ChannelMessageEnvelope) -> usize {
    let before = envelope.attachments.len();
    envelope
        .attachments
        .retain(|attachment| !attachment.url.as_deref().is_some_and(is_artifact_url));
    let mut removed = before - envelope.attachments.len();
    if let Some(Value::Array(raw)) = envelope.extensions.get_mut(ext_keys::ATTACHMENTS) {
        let before = raw.len();
        raw.retain(|entry| {
            let raw_url = |key: &str| entry.get(key).and_then(Value::as_str);
            let forged = match entry {
                Value::String(url) => is_artifact_url(url),
                _ => ["contentUrl", "url", "thumbnailUrl"]
                    .iter()
                    .any(|key| raw_url(key).is_some_and(is_artifact_url)),
            };
            !forged
        });
        removed += before - raw.len();
    }
    if let Some(text) = envelope.text.as_mut() {
        removed += scrub_string(text);
    }
    for value in envelope.metadata.values_mut() {
        removed += scrub_string(value);
    }
    for value in envelope.extensions.values_mut() {
        removed += scrub_value(value);
    }
    removed
}

/// Ends a raw id inside text.
fn ends_token(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | '`' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | '\\'
        )
}

/// Where `artifact:` (any case, invisible format characters allowed between
/// its letters) starting at `start` ends, if it is there.
fn scheme_end(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start;
    for (n, want) in "artifact:".chars().enumerate() {
        if n > 0 {
            while chars.get(i).is_some_and(|c| is_invisible_format(*c)) {
                i += 1;
            }
        }
        if !chars.get(i)?.eq_ignore_ascii_case(&want) {
            return None;
        }
        i += 1;
    }
    Some(i)
}

/// `text` with every raw id (`artifact:` directly followed by a token)
/// removed, and how many were. Prose such as "artifact: x" is kept.
fn scrub_text(text: &str) -> (String, usize) {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut count = 0;
    let mut i = 0;
    while i < chars.len() {
        if let Some(end) = scheme_end(&chars, i)
            && chars.get(end).is_some_and(|c| !ends_token(*c))
        {
            let mut j = end;
            while chars.get(j).is_some_and(|c| !ends_token(*c)) {
                j += 1;
            }
            count += 1;
            i = j;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    (out, count)
}

fn scrub_string(text: &mut String) -> usize {
    let (scrubbed, count) = scrub_text(text);
    if count > 0 {
        *text = scrubbed;
    }
    count
}

fn scrub_value(value: &mut Value) -> usize {
    match value {
        Value::String(text) => scrub_string(text),
        Value::Array(items) => items.iter_mut().map(scrub_value).sum(),
        Value::Object(map) => map.values_mut().map(scrub_value).sum(),
        _ => 0,
    }
}

fn webchat(mut envelope: ChannelMessageEnvelope, resolved: &Resolved) -> ChannelMessageEnvelope {
    for file in &resolved.files {
        envelope.attachments.push(Attachment {
            mime_type: file.mime_type.clone(),
            url: Some(file.url.clone()),
            content: None,
            name: Some(safe_name(&file.name)),
            size_bytes: Some(file.size_bytes),
        });
    }
    if let Some(Value::Array(raw)) = envelope.extensions.get_mut(ext_keys::ATTACHMENTS) {
        for file in &resolved.files {
            raw.push(json!({
                "contentType": file.mime_type,
                "contentUrl": file.url,
                "name": safe_name(&file.name),
            }));
        }
    }
    let default_text = (text_of(&envelope).is_none()
        && !has_card(&envelope)
        && !resolved.files.is_empty())
    .then(|| {
        let names: Vec<String> = resolved.files.iter().map(|f| safe_name(&f.name)).collect();
        format!("Here is your file: {}", names.join(", "))
    });
    envelope.text = joined(&[
        text_of(&envelope).map(str::to_string),
        default_text,
        notes(resolved),
    ]);
    envelope
}

fn link_lines(files: &[OutboundFile]) -> Option<String> {
    let lines: Vec<String> = files
        .iter()
        .map(|file| format!("{}: {}", safe_name(&file.name), file.url))
        .collect();
    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// One envelope in, one or two out.
pub(crate) fn shape(
    mut envelope: ChannelMessageEnvelope,
    provider_type: &str,
    resolved: &Resolved,
) -> Vec<ChannelMessageEnvelope> {
    if resolved.is_empty() {
        return vec![envelope];
    }
    if is_webchat(provider_type) {
        return vec![webchat(envelope, resolved)];
    }
    let lines = joined(&[link_lines(&resolved.files), notes(resolved)]);
    if has_card(&envelope) {
        let mut follow_up = crate::messaging_app::base_reply_envelope(&envelope);
        follow_up.extensions.clear();
        follow_up.text = lines;
        return vec![envelope, follow_up];
    }
    envelope.text = joined(&[text_of(&envelope).map(str::to_string), lines]);
    vec![envelope]
}
