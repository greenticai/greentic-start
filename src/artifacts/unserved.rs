//! What activation says about channels whose REMOTE file references depend on
//! request verification (host checklist 12).
//!
//! - Telegram without a `webhook_secret_ref` can never be verified by this
//!   host, so its files are never read: one warning per activation.
//! - WhatsApp, Webex and Microsoft Teams are verified by this host itself
//!   (`crate::inbound_verify`) once their input is configured (app secret,
//!   stored webhook secret, bot app id). Activation cannot see that input, so
//!   it says ONE short pointer line; the per-channel warning names the missing
//!   setting the first time a request arrives without it.
//!
//! A file from a request this host did not verify reaches the agent as a
//! `fetch_failed` note saying the channel is not set up to verify its
//! messages.

use std::collections::BTreeSet;

use greentic_deploy_spec::Environment;

use super::origin::Channel;

/// Channel classes among `(provider_type, has_webhook_secret)` whose requests
/// this host can never verify.
pub(crate) fn unserved_channel_classes(endpoints: &[(String, bool)]) -> BTreeSet<&'static str> {
    endpoints
        .iter()
        .filter_map(|(provider_type, has_secret)| {
            match Channel::from_provider_type(provider_type) {
                Channel::Telegram if !has_secret => Some("Telegram"),
                _ => None,
            }
        })
        .collect()
}

/// Declared channel classes whose files are read only from requests this
/// host verifies itself.
pub(crate) fn verified_on_request_classes(endpoints: &[(String, bool)]) -> BTreeSet<&'static str> {
    endpoints
        .iter()
        .filter_map(
            |(provider_type, _)| match Channel::from_provider_type(provider_type) {
                Channel::Whatsapp => Some("WhatsApp"),
                Channel::Webex => Some("Webex"),
                Channel::Teams => Some("Microsoft Teams"),
                _ => None,
            },
        )
        .collect()
}

/// The lines one activation says, in order: one warning per unserved class,
/// then at most one pointer line.
pub(crate) fn activation_lines(endpoints: &[(String, bool)]) -> Vec<String> {
    let mut lines: Vec<String> = unserved_channel_classes(endpoints)
        .into_iter()
        .map(|class| {
            format!(
                "files sent through {class} are not read: this host verifies {class} \
                 requests only with a webhook secret on the endpoint, so set one to \
                 have its files read"
            )
        })
        .collect();
    if !verified_on_request_classes(endpoints).is_empty() {
        lines.push(
            "inbound files from WhatsApp, Webex and Microsoft Teams are read only from \
             requests this host verifies; see the per-channel warning if one is not \
             configured"
                .to_string(),
        );
    }
    lines
}

/// Says [`activation_lines`] for this environment: the Telegram lines as
/// warnings, the pointer line as information.
pub(crate) fn warn_unserved_channels(env: &Environment) {
    let endpoints: Vec<(String, bool)> = env
        .messaging_endpoints
        .iter()
        .map(|ep| (ep.provider_type.clone(), ep.webhook_secret_ref.is_some()))
        .collect();
    let unserved = unserved_channel_classes(&endpoints).len();
    for (index, line) in activation_lines(&endpoints).into_iter().enumerate() {
        if index < unserved {
            crate::operator_log::warn(module_path!(), line);
        } else {
            crate::operator_log::info(module_path!(), line);
        }
    }
}
