//! The key the admin's per-conversation quota is counted under (host
//! checklist 11).
//!
//! `session_id` alone is not a conversation: WhatsApp's is the constant
//! `whatsapp` for every user, and Telegram may carry none. The key joins the
//! receiving pack, the channel, the envelope's channel id (Telegram: the chat
//! id), the sender (WhatsApp: the `wa_id`) and the session. Empty parts stay
//! empty, so a missing part never shifts another into its place, and each
//! part is escaped (the separator and the escape character), so a part that
//! contains the separator cannot pose as two parts.

use greentic_types::ChannelMessageEnvelope;

use super::origin::Origin;

const SEPARATOR: char = '\u{1f}';

/// `None` only when nothing in the envelope identifies a conversation.
pub(crate) fn conversation_key(
    envelope: &ChannelMessageEnvelope,
    origin: &Origin,
) -> Option<String> {
    let sender = envelope
        .from
        .as_ref()
        .map(|actor| actor.id.as_str())
        .unwrap_or("");
    let identifying = [
        envelope.channel.as_str(),
        sender,
        envelope.session_id.as_str(),
    ];
    if identifying.iter().all(|part| part.trim().is_empty()) {
        return None;
    }
    let mut key = format!(
        "{:?}{SEPARATOR}{}",
        origin.channel(),
        origin.scope().pack_id
    );
    for part in identifying {
        key.push(SEPARATOR);
        push_escaped(&mut key, part);
    }
    Some(key)
}

/// `\` becomes `\\` and the separator becomes `\u001f`, so the joined key is
/// injective in its parts.
fn push_escaped(key: &mut String, part: &str) {
    for c in part.chars() {
        match c {
            '\\' => key.push_str("\\\\"),
            SEPARATOR => key.push_str("\\u001f"),
            other => key.push(other),
        }
    }
}
