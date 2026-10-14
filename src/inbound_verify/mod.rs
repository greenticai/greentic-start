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
//! (`artifacts::origin::Origin::verified_by_host`); an `Unavailable` verdict
//! becomes `RequestVerification::Unavailable` there, so the files note says
//! verification is temporarily unavailable rather than not set up. The
//! outcomes:
//!
//! - **Verified** — files are read.
//! - **NotConfigured** (no secret / no bot app id) — the request is admitted
//!   exactly as before this module existed (text flows), files are withheld,
//!   and the operator is told once which setting is missing.
//! - **Unavailable** (the Teams signing key set, or a channel's stored secret,
//!   could not be read) — admitted unverified, files withheld; an outage must
//!   not take chat down.
//! - **Refused** — a configured channel whose proof failed: `401` (`403` for a
//!   Bot Framework endorsement mismatch). Never downgraded, and there is no
//!   switch to turn the check off once configured.

mod absent_memo;
mod bf_keys;
mod bot_framework;
mod hmac_channels;
mod notices;
mod secrets;
mod service_url;

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
pub(crate) enum RefusalCode {
    MissingSignature,
    BadSignature,
    MissingToken,
    BadToken,
    TokenClaims,
    Endorsement,
    /// A Teams `serviceUrl` outside the Bot Framework hosts (`service_url`).
    ServiceUrl,
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
        RefusalCode::ServiceUrl,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RefusalCode::MissingSignature => "missing_signature",
            RefusalCode::BadSignature => "bad_signature",
            RefusalCode::MissingToken => "missing_token",
            RefusalCode::BadToken => "bad_token",
            RefusalCode::TokenClaims => "token_claims",
            RefusalCode::Endorsement => "endorsement",
            RefusalCode::ServiceUrl => "service_url",
        }
    }

    /// `403` for a Bot Framework endorsement mismatch (the channel is
    /// authenticated but not endorsed for this key, per the BF contract) and
    /// for a `serviceUrl` this host will not let the bot token reach.
    fn status(self) -> StatusCode {
        match self {
            RefusalCode::Endorsement | RefusalCode::ServiceUrl => StatusCode::FORBIDDEN,
            _ => StatusCode::UNAUTHORIZED,
        }
    }
}

/// What one channel's verifier decided.
pub(crate) enum Outcome {
    Verified,
    NotConfigured,
    Unavailable(Unavailable),
    Refused(RefusalCode),
}

/// Why a verification could not run. Never a failed proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// The Bot Framework signing keys could not be read.
    KeySet,
    /// The channel's stored secret could not be read (store error).
    SecretStore,
}

/// What the verifiers read from. Production: [`verify_inbound`].
pub(crate) struct Deps<'a> {
    pub secrets: &'a DynSecretsManager,
    /// The secrets environment, the same value `artifacts::secrets::HostSecrets`
    /// is built with (`crate::resolve_env(None)`).
    pub env: &'a str,
    pub notices: &'a Notices,
    /// The Bot Framework key set; `None` when no client could be built.
    pub bf_keys: Option<&'a dyn bot_framework::BfKeys>,
    /// Unix seconds, for the token clock checks.
    pub now: u64,
    /// The monotonic clock, for windows that must not follow wall-clock
    /// steps (`absent_memo`).
    pub instant: std::time::Instant,
    /// Exact extra hosts a Teams `serviceUrl` may name
    /// (`service_url::EXTRA_HOSTS_ENV`).
    pub teams_service_hosts: &'a [String],
    /// Recently observed "no secret" answers (`absent_memo`).
    pub absent_memo: &'a absent_memo::AbsentMemo,
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
            bf_keys: bf_keys::BfKeySource::production()
                .map(|source| source as &dyn bot_framework::BfKeys),
            now: unix_now(),
            instant: std::time::Instant::now(),
            teams_service_hosts: service_url::extra_hosts(),
            absent_memo: absent_memo::AbsentMemo::production(),
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
        Outcome::Unavailable(cause) => {
            let (code, what) = match cause {
                Unavailable::KeySet => ("key_set_unavailable", "the signing keys"),
                Unavailable::SecretStore => ("secret_unavailable", "the stored secret"),
            };
            deps.notices.limited(
                label,
                code,
                &format!(
                    "{label} request verification is unavailable: {what} could not be \
                     read; the message was admitted unverified and its files are not read"
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
    let secret = match channel_secret(inbound, deps, hmac_channels::WHATSAPP_SECRET_NAMES).await {
        Ok(secret) => secret,
        Err(cause) => return Outcome::Unavailable(cause),
    };
    hmac_outcome(hmac_channels::check_whatsapp(
        secret.as_ref(),
        inbound.headers,
        inbound.body,
    ))
}

async fn webex(inbound: &Inbound<'_>, deps: &Deps<'_>) -> Outcome {
    let secret = match channel_secret(inbound, deps, hmac_channels::WEBEX_SECRET_NAMES).await {
        Ok(secret) => secret,
        Err(cause) => return Outcome::Unavailable(cause),
    };
    hmac_outcome(hmac_channels::check_webex(
        secret.as_ref(),
        inbound.headers,
        inbound.body,
    ))
}

/// The channel's secret in the provider op's own scope (`secrets.rs`);
/// `Ok(None)` when none is stored, `Err` when the store could not say.
async fn channel_secret(
    inbound: &Inbound<'_>,
    deps: &Deps<'_>,
    names: &[&str],
) -> Result<Option<secrets::ChannelSecret>, Unavailable> {
    let memo_key = absent_memo::AbsentMemo::key(
        deps.env,
        inbound.tenant,
        inbound.pack_id,
        inbound.unit_id,
        names,
    );
    if deps.absent_memo.recently_absent(&memo_key, deps.instant) {
        return Ok(None);
    }
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
        secrets::SecretRead::Found(secret) => Ok(Some(secret)),
        secrets::SecretRead::Absent => {
            deps.absent_memo.record(memo_key, deps.instant);
            Ok(None)
        }
        secrets::SecretRead::Unavailable => Err(Unavailable::SecretStore),
    }
}

fn hmac_outcome(outcome: hmac_channels::HmacOutcome) -> Outcome {
    match outcome {
        hmac_channels::HmacOutcome::Verified => Outcome::Verified,
        hmac_channels::HmacOutcome::NotConfigured => Outcome::NotConfigured,
        hmac_channels::HmacOutcome::Refused(code) => Outcome::Refused(code),
    }
}

async fn teams(inbound: &Inbound<'_>, deps: &Deps<'_>) -> Outcome {
    let app_id = bot_framework::configured_app_id(inbound.pack_non_secret);
    let outcome = match bot_framework::check(
        app_id.as_deref(),
        inbound.headers,
        inbound.body,
        deps.bf_keys,
        deps.now,
    )
    .await
    {
        bot_framework::BfOutcome::Refused(code) => return Outcome::Refused(code),
        bot_framework::BfOutcome::Verified => Outcome::Verified,
        bot_framework::BfOutcome::NotConfigured => Outcome::NotConfigured,
        bot_framework::BfOutcome::Unavailable => Outcome::Unavailable(Unavailable::KeySet),
    };
    // The provider replies to `serviceUrl` with the bot's token. On a
    // VERIFIED activity Microsoft signed that URL (the `serviceurl` claim
    // matched it), so the host list adds nothing there and would refuse real
    // Microsoft hosts (GCC). Unverified, nothing proved who named it: only
    // Bot Framework's own hosts (and the operator's exact extras) may be.
    if !matches!(outcome, Outcome::Verified)
        && service_url::classify(inbound.body, deps.teams_service_hosts)
            == service_url::ServiceUrl::Refused
    {
        return Outcome::Refused(RefusalCode::ServiceUrl);
    }
    outcome
}

/// The secrets environment the provider ops read under, resolved once per
/// process (`crate::resolve_env(None)`, the value `HostSecrets` is built
/// with), instead of reading `GREENTIC_ENV` on every request. Boot already
/// resolved it, so the alias check that can panic has run before any request.
pub(crate) fn secrets_env() -> &'static str {
    static ENV: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ENV.get_or_init(|| crate::resolve_env(None))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "absent_memo_tests.rs"]
mod absent_memo_tests;
#[cfg(test)]
#[path = "bot_framework_tests.rs"]
mod bot_framework_tests;
#[cfg(test)]
#[path = "hmac_channels_tests.rs"]
mod hmac_channels_tests;
#[cfg(test)]
#[path = "mod_tests.rs"]
mod mod_tests;
#[cfg(test)]
#[path = "routing_tests.rs"]
mod routing_tests;
#[cfg(test)]
#[path = "secrets_error_tests.rs"]
mod secrets_error_tests;
#[cfg(test)]
#[path = "secrets_tests.rs"]
mod secrets_tests;
#[cfg(test)]
#[path = "service_url_tests.rs"]
mod service_url_tests;
#[cfg(test)]
#[path = "shared_vectors_tests.rs"]
mod shared_vectors_tests;
#[cfg(test)]
#[path = "wiring_tests.rs"]
mod wiring_tests;
