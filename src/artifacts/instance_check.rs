//! WhatsApp: an envelope must belong to the business number of the instance
//! that received it (host checklist 14).
//!
//! The provider's `identify_instance` routes a webhook by its FIRST change
//! only, while one webhook may carry changes for several numbers. An envelope
//! naming another number would otherwise be served — and its media fetched
//! with this instance's token. An envelope that NAMES another number is
//! dropped before the inbound pipeline; one that names no number is not
//! provably foreign, so the message is served but its media fetch references
//! are removed (fail closed for media only). Logged by count only, never by
//! payload.
//!
//! Limitation: the configured number is the pack-level provider config's.
//! A unit with several WhatsApp endpoints on different numbers would need a
//! per-endpoint number, which this path does not have.

use greentic_types::ChannelMessageEnvelope;
use serde_json::Value;

use super::fetch_ref::EXTENSION_KEY as FETCH_KEY;
use super::origin::Channel;

const NUMBER_KEY: &str = "phone_number_id";

/// The instance's configured number, from its provider config.
pub(crate) fn configured_number(provider_config: Option<&Value>) -> Option<String> {
    provider_config?
        .get(NUMBER_KEY)?
        .as_str()
        .map(str::trim)
        .filter(|number| !number.is_empty())
        .map(str::to_string)
}

/// Removes every WhatsApp envelope whose `phone_number_id` is present and is
/// not `configured`, and returns how many were removed. An envelope with no
/// number keeps its message and loses its media fetch references. Other
/// channels, and an instance whose number is not configured (nothing to
/// compare against), are left alone.
pub(crate) fn drop_foreign_numbers(
    provider_type: &str,
    configured: Option<&str>,
    envelopes: &mut Vec<ChannelMessageEnvelope>,
) -> usize {
    if Channel::from_provider_type(provider_type) != Channel::Whatsapp {
        return 0;
    }
    let Some(configured) = configured else {
        return 0;
    };
    let before = envelopes.len();
    envelopes.retain(|envelope| {
        envelope
            .metadata
            .get(NUMBER_KEY)
            .is_none_or(|number| number.trim() == configured)
    });
    let mut unproven = 0;
    for envelope in envelopes.iter_mut() {
        if !envelope.metadata.contains_key(NUMBER_KEY)
            && envelope.extensions.remove(FETCH_KEY).is_some()
        {
            for attachment in &mut envelope.attachments {
                attachment.url = None;
                attachment.content = None;
            }
            unproven += 1;
        }
    }
    if unproven > 0 {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "{unproven} WhatsApp envelope(s) named no business number; their media was not \
                 fetched"
            ),
        );
    }
    let dropped = before - envelopes.len();
    if dropped > 0 {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "dropped {dropped} WhatsApp envelope(s) addressed to another business number \
                 than the one this instance is configured for"
            ),
        );
    }
    dropped
}
