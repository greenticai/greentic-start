//! WhatsApp: an envelope must belong to the business number of the instance
//! that received it (host checklist 14).
//!
//! The provider's `identify_instance` routes a webhook by its FIRST change
//! only, while one webhook may carry changes for several numbers. An envelope
//! naming another number would otherwise be served — and its media fetched
//! with this instance's token. Such envelopes are dropped before the inbound
//! pipeline, logged by count and instance only, never by payload.

use greentic_types::ChannelMessageEnvelope;
use serde_json::Value;

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

/// Removes every WhatsApp envelope whose `phone_number_id` is not `configured`
/// and returns how many were removed. Other channels, and an instance whose
/// number is not configured (nothing to compare against), are left alone.
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
            .is_some_and(|number| number.trim() == configured)
    });
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
