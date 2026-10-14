//! WhatsApp and Webex sign each webhook body with a shared secret; this host
//! recomputes the MAC over the RAW body and compares in constant time
//! ([`crate::triggers::verify::verify_hmac`], which already does the length
//! check and the `subtle` compare).
//!
//! - WhatsApp (Meta Cloud API): `X-Hub-Signature-256: sha256=<hex>`,
//!   HMAC-SHA256 keyed with the app secret. The legacy SHA-1
//!   `X-Hub-Signature` is ignored: it proves nothing a SHA-256 header does not.
//! - Webex: `X-Spark-Signature: <hex>` (also `X-Webex-Signature`, read only
//!   when the first is absent — the provider's own order), HMAC-SHA1 keyed
//!   with the webhook secret registered with Webex.
//!
//! Neither carries a timestamp, so no replay window can be enforced; a
//! replayed request re-delivers the same message and media ids.

use crate::triggers::schema::{HmacAlgo, SignatureEncoding};
use crate::triggers::verify::{VerifyError, verify_hmac};

use super::RefusalCode;
use super::secrets::ChannelSecret;

/// Secret names the WhatsApp provider's setup writes (`WHATSAPP_APP_SECRET`)
/// and the designer stages (the question id).
pub(crate) const WHATSAPP_SECRET_NAMES: &[&str] = &["WHATSAPP_APP_SECRET", "whatsapp_app_secret"];

/// The Webex pack's generated webhook secret, under both spellings.
pub(crate) const WEBEX_SECRET_NAMES: &[&str] = &["WEBEX_WEBHOOK_SECRET", "webex_webhook_secret"];

const WHATSAPP_HEADER: &str = "x-hub-signature-256";
const WEBEX_HEADERS: &[&str] = &["x-spark-signature", "x-webex-signature"];

#[derive(Debug)]
pub(crate) enum HmacOutcome {
    Verified,
    NotConfigured,
    Refused(RefusalCode),
}

pub(crate) fn check_whatsapp(
    secret: Option<&ChannelSecret>,
    headers: &[(String, String)],
    body: &[u8],
) -> HmacOutcome {
    check(
        secret,
        header(headers, &[WHATSAPP_HEADER]),
        body,
        &HmacAlgo::Sha256,
        "sha256=",
    )
}

pub(crate) fn check_webex(
    secret: Option<&ChannelSecret>,
    headers: &[(String, String)],
    body: &[u8],
) -> HmacOutcome {
    check(
        secret,
        header(headers, WEBEX_HEADERS),
        body,
        &HmacAlgo::Sha1,
        "",
    )
}

fn check(
    secret: Option<&ChannelSecret>,
    presented: Option<&str>,
    body: &[u8],
    algo: &HmacAlgo,
    prefix: &str,
) -> HmacOutcome {
    let Some(secret) = secret else {
        return HmacOutcome::NotConfigured;
    };
    match verify_hmac(
        algo,
        secret.expose().as_bytes(),
        body,
        presented,
        prefix,
        &SignatureEncoding::Hex,
    ) {
        Ok(()) => HmacOutcome::Verified,
        Err(VerifyError::MissingHeader) => HmacOutcome::Refused(RefusalCode::MissingSignature),
        Err(VerifyError::Malformed | VerifyError::Mismatch) => {
            HmacOutcome::Refused(RefusalCode::BadSignature)
        }
    }
}

/// The first header among `names` (in that order of preference), matched
/// case-insensitively; within one name, the first occurrence.
fn header<'a>(headers: &'a [(String, String)], names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
}
