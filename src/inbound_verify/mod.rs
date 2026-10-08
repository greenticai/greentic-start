//! Host-side authenticity checks for WhatsApp, Webex and Microsoft Teams
//! requests on the revision path.
//!
//! [`crate::provider_auth`] covers Telegram (a shared secret in a header) and
//! [`crate::provider_webhook_verify`] covers Slack (the pack's own ingress
//! component). Neither can cover these three: WhatsApp's provider checks no
//! signature at all, Teams' only checks that a bearer value is present, and
//! Webex verifies inside `ingest_http`, which cannot be asked "would you have
//! refused?" without running the op. So this host verifies them itself, on
//! the RAW request bytes, before the session pin, the identify probe and the
//! provider op (`dispatch_provider_route`, pinned by `wiring_tests`).
//!
//! The verdict is ORed into the request's `transport_verified` flag, which is
//! what lets inbound attachments resolve a remote fetch reference
//! (`artifacts::origin::Origin::verified_by_host`). The outcomes:
//!
//! - **Verified** — files are read.
//! - **NotConfigured** (no secret / no bot app id) — the request is admitted
//!   exactly as before this module existed (text flows), files are withheld,
//!   and the operator is told once which setting is missing.
//! - **Unavailable** (Teams: the signing key set could not be read) — admitted
//!   unverified; an outage of the key host must not take chat down.
//! - **Refused** — a configured channel whose proof failed: `401` (`403` for a
//!   Bot Framework endorsement mismatch). Never downgraded, and there is no
//!   switch to turn the check off once configured.

// Consumed by the Bot Framework verifier (next change); tested on its own.
#[allow(dead_code)]
mod bf_keys;
mod hmac_channels;
mod notices;
mod secrets;

use std::collections::BTreeMap;

use greentic_deploy_spec::DeploymentId;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};

use crate::artifacts::origin::Channel;
use crate::secrets_gate::DynSecretsManager;

use notices::Notices;

/// What this host concluded about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// This host proved the request came from the channel.
    Verified,
    /// The channel's verification input (secret / app id) is not configured.
    NotConfigured,
    /// Verification could not run (key set unreachable); never a failed proof.
    Unavailable,
    /// The channel class carries no verification handled here.
    NotApplicable,
}

/// The request as received, plus the route facts that scope its secrets.
#[allow(dead_code)] // `pack_non_secret` is read by the Bot Framework verifier (S5)
pub(crate) struct Inbound<'a> {
    pub provider_type: &'a str,
    pub method: &'a str,
    pub headers: &'a [(String, String)],
    /// The raw body bytes exactly as received.
    pub body: &'a [u8],
    pub pack_id: &'a str,
    /// The running revision's bundle id: the unit scope the provider's own
    /// secret reads try first.
    pub unit_id: &'a str,
    pub tenant: &'a str,
    pub pack_non_secret: Option<&'a BTreeMap<String, serde_json::Value>>,
    pub deployment_id: DeploymentId,
}

/// Why a request was refused. Only ever logged as [`RefusalCode::as_str`];
/// the caller's response never names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // the token codes come with the Bot Framework verifier (S5)
pub(crate) enum RefusalCode {
    MissingSignature,
    BadSignature,
    MissingToken,
    BadToken,
    TokenClaims,
    Endorsement,
}

impl RefusalCode {
    #[cfg(test)]
    pub(crate) const ALL: &'static [RefusalCode] = &[
        RefusalCode::MissingSignature,
        RefusalCode::BadSignature,
        RefusalCode::MissingToken,
        RefusalCode::BadToken,
        RefusalCode::TokenClaims,
        RefusalCode::Endorsement,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RefusalCode::MissingSignature => "missing_signature",
            RefusalCode::BadSignature => "bad_signature",
            RefusalCode::MissingToken => "missing_token",
            RefusalCode::BadToken => "bad_token",
            RefusalCode::TokenClaims => "token_claims",
            RefusalCode::Endorsement => "endorsement",
        }
    }

    /// `403` only for a Bot Framework endorsement mismatch (the channel is
    /// authenticated but not endorsed for this key), per the BF contract.
    fn status(self) -> StatusCode {
        match self {
            RefusalCode::Endorsement => StatusCode::FORBIDDEN,
            _ => StatusCode::UNAUTHORIZED,
        }
    }
}

/// What one channel's verifier decided.
#[allow(dead_code)] // `Unavailable` comes with the Bot Framework verifier (S5)
pub(crate) enum Outcome {
    Verified,
    NotConfigured,
    Unavailable,
    Refused(RefusalCode),
}

/// What the verifiers read from. Production: [`verify_inbound`].
pub(crate) struct Deps<'a> {
    pub secrets: &'a DynSecretsManager,
    /// The secrets environment, the same value `artifacts::secrets::HostSecrets`
    /// is built with (`crate::resolve_env(None)`).
    pub env: &'a str,
    pub notices: &'a Notices,
}

/// Verify one inbound request. `Err` is the refusal response, with fixed text.
pub(crate) async fn verify_inbound(
    inbound: Inbound<'_>,
    secrets: &DynSecretsManager,
    env: &str,
) -> Result<Verdict, Response<Full<Bytes>>> {
    verify_with(
        inbound,
        &Deps {
            secrets,
            env,
            notices: Notices::production(),
        },
    )
    .await
}

pub(crate) async fn verify_with(
    inbound: Inbound<'_>,
    deps: &Deps<'_>,
) -> Result<Verdict, Response<Full<Bytes>>> {
    // Only a POST carries a message. WhatsApp's `hub.challenge` handshake is a
    // GET and stays exactly as it was.
    if !inbound.method.eq_ignore_ascii_case("POST") {
        return Ok(Verdict::NotApplicable);
    }
    let channel = Channel::from_provider_type(inbound.provider_type);
    let outcome = match channel {
        Channel::Whatsapp => whatsapp(&inbound, deps).await,
        Channel::Webex => webex(&inbound, deps).await,
        Channel::Teams => teams(&inbound, deps).await,
        _ => return Ok(Verdict::NotApplicable),
    };
    let label = label(channel);
    match outcome {
        Outcome::Verified => Ok(Verdict::Verified),
        Outcome::NotConfigured => {
            deps.notices
                .once(inbound.deployment_id, label, not_configured_line(channel));
            Ok(Verdict::NotConfigured)
        }
        Outcome::Unavailable => {
            deps.notices.limited(
                label,
                "key_set_unavailable",
                &format!(
                    "{label} requests could not be verified: the signing keys could not \
                     be read; the message was admitted unverified and its files are not read"
                ),
            );
            Ok(Verdict::Unavailable)
        }
        Outcome::Refused(code) => Err(refusal(deps.notices, label, code)),
    }
}

/// The refusal response, and a rate-bounded operator line naming the channel
/// and the fixed code. The body is the same for every condition.
pub(crate) fn refusal(
    notices: &Notices,
    label: &'static str,
    code: RefusalCode,
) -> Response<Full<Bytes>> {
    notices.limited(
        label,
        code.as_str(),
        &format!("refused an inbound {label} request ({})", code.as_str()),
    );
    crate::revision_serve::error_response(code.status(), "webhook verification failed")
}

fn label(channel: Channel) -> &'static str {
    match channel {
        Channel::Whatsapp => "WhatsApp",
        Channel::Webex => "Webex",
        Channel::Teams => "Microsoft Teams",
        _ => "this channel",
    }
}

fn not_configured_line(channel: Channel) -> &'static str {
    match channel {
        Channel::Whatsapp => {
            "WhatsApp requests are not verified: set the app secret (`whatsapp_app_secret`) \
             for this channel; files from WhatsApp are not read until then"
        }
        Channel::Webex => {
            "Webex requests are not verified: no webhook secret is stored for this channel; \
             files from Webex are not read until then"
        }
        Channel::Teams => {
            "Microsoft Teams requests are not verified: set the bot app id (`ms_bot_app_id`) \
             for this channel; files from Teams are not read until then"
        }
        _ => "requests on this channel are not verified; files are not read",
    }
}

async fn whatsapp(inbound: &Inbound<'_>, deps: &Deps<'_>) -> Outcome {
    let secret = channel_secret(inbound, deps, hmac_channels::WHATSAPP_SECRET_NAMES).await;
    hmac_outcome(hmac_channels::check_whatsapp(
        secret.as_ref(),
        inbound.headers,
        inbound.body,
    ))
}

async fn webex(inbound: &Inbound<'_>, deps: &Deps<'_>) -> Outcome {
    let secret = channel_secret(inbound, deps, hmac_channels::WEBEX_SECRET_NAMES).await;
    hmac_outcome(hmac_channels::check_webex(
        secret.as_ref(),
        inbound.headers,
        inbound.body,
    ))
}

/// The channel's secret in the provider op's own scope (`secrets.rs`).
async fn channel_secret(
    inbound: &Inbound<'_>,
    deps: &Deps<'_>,
    names: &[&str],
) -> Option<secrets::ChannelSecret> {
    match secrets::read_channel_secret(
        deps.secrets,
        deps.env,
        inbound.tenant,
        inbound.pack_id,
        inbound.unit_id,
        names,
    )
    .await
    {
        secrets::SecretRead::Found(secret) => Some(secret),
        secrets::SecretRead::Absent => None,
    }
}

fn hmac_outcome(outcome: hmac_channels::HmacOutcome) -> Outcome {
    match outcome {
        hmac_channels::HmacOutcome::Verified => Outcome::Verified,
        hmac_channels::HmacOutcome::NotConfigured => Outcome::NotConfigured,
        hmac_channels::HmacOutcome::Refused(code) => Outcome::Refused(code),
    }
}

async fn teams(_inbound: &Inbound<'_>, _deps: &Deps<'_>) -> Outcome {
    Outcome::NotConfigured
}

#[cfg(test)]
#[path = "hmac_channels_tests.rs"]
mod hmac_channels_tests;
#[cfg(test)]
#[path = "mod_tests.rs"]
mod mod_tests;
#[cfg(test)]
#[path = "secrets_tests.rs"]
mod secrets_tests;
#[cfg(test)]
#[path = "wiring_tests.rs"]
mod wiring_tests;
