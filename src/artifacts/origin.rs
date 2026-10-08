//! Where an envelope came from, decided by the HOST (the route that received
//! it), never by the envelope: which channel's credentials a fetch reference
//! may name, and which pack's secrets the host reads for it.
//!
//! Closes the confused deputy: a provider's envelope names a credential by
//! NAME, so without this rule a Slack envelope could make the host spend the
//! WhatsApp token (or another pack's Slack token) on a URL it chose.

use super::fetch_ref::FetchRef;
use crate::http_routes::derive_provider_name;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Channel {
    Slack,
    Webex,
    Telegram,
    Whatsapp,
    Teams,
    WebChat,
    Other,
}

impl Channel {
    /// From the provider type of the route that received the request
    /// (`messaging.slack.api` is Slack). A family matches its own name or a
    /// `<family>-<kind>` refinement, as the webhook verifier matches.
    pub(crate) fn from_provider_type(provider_type: &str) -> Self {
        let Some(name) = derive_provider_name(provider_type) else {
            return Channel::Other;
        };
        let family = |family: &str| {
            name == family
                || name
                    .strip_prefix(family)
                    .is_some_and(|rest| rest.starts_with('-'))
        };
        if family("slack") {
            Channel::Slack
        } else if family("webex") {
            Channel::Webex
        } else if family("telegram") {
            Channel::Telegram
        } else if family("whatsapp") {
            Channel::Whatsapp
        } else if family("teams") {
            Channel::Teams
        } else if family("webchat") {
            Channel::WebChat
        } else {
            Channel::Other
        }
    }

    /// The one credential this channel's `bearer` references may name.
    fn own_credential(self) -> Option<&'static str> {
        match self {
            Channel::Slack => Some("SLACK_BOT_TOKEN"),
            Channel::Webex => Some("WEBEX_BOT_TOKEN"),
            // Telegram and WhatsApp use their token only through their own
            // id kinds below, never through a `bearer` URL.
            Channel::Telegram
            | Channel::Whatsapp
            | Channel::Teams
            | Channel::WebChat
            | Channel::Other => None,
        }
    }

    /// Whether an envelope received on this channel may use `reference`.
    /// Credential-less kinds (`public`, `inline`) are open to every channel.
    pub(crate) fn allows(self, reference: &FetchRef) -> bool {
        match reference {
            FetchRef::Bearer { secret_key, .. } => {
                self.own_credential() == Some(secret_key.as_str())
            }
            FetchRef::TelegramFile { .. } => self == Channel::Telegram,
            FetchRef::WhatsappMedia { .. } => self == Channel::Whatsapp,
            FetchRef::Public { .. } | FetchRef::Inline | FetchRef::Withheld => true,
        }
    }
}

/// Whose secrets a fetch reads: the pack the request was routed to, in the
/// unit's own tenant and team.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretScope {
    pub tenant: String,
    pub team: Option<String>,
    pub pack_id: String,
}

/// What THIS host established about the request that produced the envelope.
/// Three values, so the agent-facing note can tell "not set up" from "set up,
/// but the check could not run right now".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestVerification {
    /// A host gate proved the request came from the channel.
    Verified,
    /// No gate proved it, and none was unavailable: the channel's
    /// verification input is not configured (or the class has none).
    NotConfigured,
    /// A gate was configured but could not run (key set or secret store
    /// outage); the request was admitted unverified.
    Unavailable,
}

impl RequestVerification {
    /// One value from the gates: any proof wins; otherwise an outage is
    /// reported as such rather than as a missing set-up.
    pub(crate) fn from_gates(proved: bool, unavailable: bool) -> Self {
        match (proved, unavailable) {
            (true, _) => Self::Verified,
            (false, true) => Self::Unavailable,
            (false, false) => Self::NotConfigured,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Origin {
    channel: Channel,
    scope: SecretScope,
    /// What THIS host established about the request that produced the
    /// envelope (Slack's signature, Telegram's secret token, the
    /// `crate::inbound_verify` gates). A remote fetch reference is resolved
    /// only from a verified request (host checklist 12).
    verification: RequestVerification,
}

impl Origin {
    pub(crate) fn new(
        provider_type: &str,
        pack_id: &str,
        tenant: &str,
        team: Option<&str>,
    ) -> Self {
        Self {
            channel: Channel::from_provider_type(provider_type),
            scope: SecretScope {
                tenant: tenant.to_string(),
                team: team.map(str::to_string),
                pack_id: pack_id.to_string(),
            },
            verification: RequestVerification::NotConfigured,
        }
    }

    /// Records what this host established. Not configured is the default.
    pub(crate) fn verified_by_host(mut self, verification: RequestVerification) -> Self {
        self.verification = verification;
        self
    }

    pub(crate) fn is_verified(&self) -> bool {
        self.verification == RequestVerification::Verified
    }

    pub(crate) fn verification(&self) -> RequestVerification {
        self.verification
    }

    pub(crate) fn channel(&self) -> Channel {
        self.channel
    }

    pub(crate) fn scope(&self) -> &SecretScope {
        &self.scope
    }
}
