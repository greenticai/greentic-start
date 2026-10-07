//! The admin `artifacts` door wire (master plan C3, reconciled with the admin
//! plan). The ONLY file that knows paths and shapes: if the admin wire changes,
//! change it here.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

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
    pub conversation_id: Option<&'a str>,
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
            conversation_id,
        }
    }
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
