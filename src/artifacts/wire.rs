//! The admin `artifacts` door wire (master plan C3, reconciled with the admin
//! plan). The ONLY file that knows paths and shapes: if the admin wire changes,
//! change it here.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The door refuses a `conversation_id` longer than this many bytes.
pub(crate) const MAX_CONVERSATION_ID_BYTES: usize = 128;
// What is sent is a SHA-256 in hex: it must fit.
const _: () = assert!(64 <= MAX_CONVERSATION_ID_BYTES);

const ID_SCHEME: &str = "artifact://";

/// A well-formed id that no artifact can have (all-zero digest): the probe
/// asks for it so the admin's id check passes and the lookup answers `404`.
pub(crate) const PROBE_ID: &str =
    "artifact://0000000000000000000000000000000000000000000000000000000000000000";

/// The admin's id rule (`media::id::parse_id`): `artifact://` + exactly 64
/// lowercase hex characters.
pub(crate) fn is_artifact_id(id: &str) -> bool {
    id.strip_prefix(ID_SCHEME).is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

pub(super) fn put_url(door: &str) -> String {
    format!("{}/put", door.trim_end_matches('/'))
}

pub(super) fn get_url(door: &str) -> String {
    format!("{}/get", door.trim_end_matches('/'))
}

#[derive(Serialize)]
pub(super) struct PutBody<'a> {
    pub name: &'a str,
    pub mime_type: &'a str,
    pub data_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
}

impl<'a> PutBody<'a> {
    pub(super) fn new(
        name: &'a str,
        mime: &'a str,
        bytes: &[u8],
        derived_from: Option<&'a str>,
        conversation_id: Option<&'a str>,
    ) -> Self {
        Self {
            name,
            mime_type: mime,
            data_base64: B64.encode(bytes),
            derived_from,
            conversation_id: conversation_id.map(door_conversation_id),
        }
    }
}

/// The id the door keys its per-conversation quota on: ALWAYS the SHA-256 of
/// the host's quota key, in lowercase hex (64 characters, inside the door's
/// [`MAX_CONVERSATION_ID_BYTES`]). The key is injective (escaped parts), so
/// the hash is too for any practical purpose, and the door never sees what
/// the key is made of (a WhatsApp sender is a phone number).
pub(crate) fn door_conversation_id(id: &str) -> String {
    let digest = Sha256::digest(id.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[derive(Serialize)]
pub(super) struct GetBody<'a> {
    pub id: &'a str,
}

#[derive(Deserialize)]
pub(super) struct PutResponse {
    pub id: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub kind: String,
    pub mime_type: String,
}
