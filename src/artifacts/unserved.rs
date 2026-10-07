//! Channels whose inbound requests this host cannot verify itself, so their
//! REMOTE file references are never resolved (host checklist 12): WhatsApp
//! (no host-side `X-Hub-Signature-256` check), Webex and Microsoft Teams (the
//! provider, not the host, checks them), and Telegram without a
//! `webhook_secret_ref`. Each file from them reaches the agent as a neutral
//! "not supported yet" note; this names the classes once per activation so
//! an operator is not left guessing.

use std::collections::BTreeSet;

use greentic_deploy_spec::Environment;

use super::origin::Channel;

/// The unserved channel classes among `(provider_type, has_webhook_secret)`.
pub(crate) fn unserved_channel_classes(endpoints: &[(String, bool)]) -> BTreeSet<&'static str> {
    endpoints
        .iter()
        .filter_map(|(provider_type, has_secret)| {
            match Channel::from_provider_type(provider_type) {
                Channel::Whatsapp => Some("WhatsApp"),
                Channel::Webex => Some("Webex"),
                Channel::Teams => Some("Microsoft Teams"),
                Channel::Telegram if !has_secret => Some("Telegram"),
                _ => None,
            }
        })
        .collect()
}

/// One warning per unserved channel class this environment declares.
pub(crate) fn warn_unserved_channels(env: &Environment) {
    let endpoints: Vec<(String, bool)> = env
        .messaging_endpoints
        .iter()
        .map(|ep| (ep.provider_type.clone(), ep.webhook_secret_ref.is_some()))
        .collect();
    for class in unserved_channel_classes(&endpoints) {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "files sent through {class} are not supported yet: this host cannot verify \
                 that channel's requests itself, so its file references are not downloaded \
                 and the agent is told the file was not read"
            ),
        );
    }
}
