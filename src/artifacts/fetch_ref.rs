//! The provider-to-host fetch reference (master plan C1). A reference names a
//! credential, it never contains one.
//!
//! `{"kind":"none"}`, a JSON `null`, an unknown kind, a malformed entry and an
//! attachment past the end of the list all mean "never fetch": they parse to
//! `None` (or no entry) and no fetch kind is ever guessed for them.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

pub(crate) const EXTENSION_KEY: &str = "attachment_fetch";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum FetchRef {
    Bearer {
        url: String,
        secret_key: String,
    },
    TelegramFile {
        file_id: String,
    },
    WhatsappMedia {
        media_id: String,
    },
    Public {
        url: String,
    },
    Inline,
    /// Written by THIS host (`super::instance_check`) in place of a reference
    /// it will not resolve: the slot is reported with a neutral
    /// `fetch_failed` note and nothing is fetched. A provider writing it only
    /// earns its own file that note.
    Withheld,
}

impl FetchRef {
    /// A cheap first filter. The host policy decides again, per hop, at fetch
    /// time.
    fn is_plausible(&self) -> bool {
        match self {
            FetchRef::Bearer { url, secret_key } => {
                url.starts_with("https://") && !secret_key.is_empty()
            }
            FetchRef::Public { url } => url.starts_with("https://"),
            FetchRef::TelegramFile { file_id } => is_safe_id(file_id),
            FetchRef::WhatsappMedia { media_id } => is_safe_id(media_id),
            FetchRef::Inline | FetchRef::Withheld => true,
        }
    }
}

/// An id the host interpolates into a URL: 1-256 of `[A-Za-z0-9_:-]`, so it
/// cannot add a path segment, a query or a fragment.
fn is_safe_id(id: &str) -> bool {
    (1..=256).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '-'))
}

/// One entry per attachment, by index. `None` means "no usable reference".
pub(crate) fn parse_refs(extensions: &BTreeMap<String, Value>) -> Vec<Option<FetchRef>> {
    let Some(Value::Array(items)) = extensions.get(EXTENSION_KEY) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|item| {
            serde_json::from_value::<FetchRef>(item.clone())
                .ok()
                .filter(FetchRef::is_plausible)
        })
        .collect()
}
