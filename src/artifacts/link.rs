//! Signed artifact download links (docs/outbound-artifacts.md).
//!
//! A link names one artifact of one unit for a bounded time:
//! `/v1/artifacts/<deployment ULID>/<artifact hex>/<exp>/<mac>`.
//!
//! - The key is DERIVED per unit from the unit's own `gtm_` metering token,
//!   bound to its tenant slug, bundle and deployment. No new secret is stored,
//!   no key is shared across units or tenants, and every instance of the unit
//!   (cold starts, replicas) derives the same key. Rotating or revoking the
//!   token invalidates every outstanding link of that unit.
//! - The MAC is HMAC-SHA256 truncated to 128 bits, checked in constant time.
//! - The token lives in the PATH: its alphabet (`[0-9A-Z]` + `[0-9a-f]`)
//!   survives Slack/Telegram/Webex/Teams/WebChat text without escaping.
//!
//! Pure: no I/O, no logging. Nothing here may print a key, token or MAC.

// Staged: the serving route and outbound shaping (outbound-delivery plan
// Tasks 4 and 6) are the consumers. Remove once both are wired.
#![allow(dead_code)]

use std::sync::OnceLock;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::wire::is_artifact_id;

pub(crate) const LINK_PREFIX: &str = "/v1/artifacts/";
pub(crate) const TTL_ENV: &str = "GREENTIC_ARTIFACT_LINK_TTL_SECS";
pub(crate) const DEFAULT_TTL_SECS: u64 = 86_400;
pub(crate) const MIN_TTL_SECS: u64 = 300;
pub(crate) const MAX_TTL_SECS: u64 = 604_800;
/// Clock skew accepted on both sides of the expiry checks.
pub(crate) const SKEW_SECS: u64 = 60;

const ID_SCHEME: &str = "artifact://";
const KEY_DOMAIN: &[u8] = b"greentic/artifact-link/v1";
const MAC_VERSION: &[u8] = b"v1";
const SEP: &[u8] = &[0x1f];
const ULID_LEN: usize = 26;
const ARTIFACT_HEX_LEN: usize = 64;
/// 128-bit truncated tag.
const MAC_BYTES: usize = 16;
const MAX_EXP_DIGITS: usize = 11;

type HmacSha256 = Hmac<Sha256>;

/// A unit's link key, derived and never stored. `Debug` redacts; no `Clone`,
/// no `Serialize`.
pub(crate) struct LinkKey([u8; 32]);

impl std::fmt::Debug for LinkKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LinkKey(<redacted>)")
    }
}

/// SHA-256 block size: HMAC's key normalisation width (RFC 2104 §2).
const BLOCK_BYTES: usize = 64;

/// HMAC-SHA256 keyed with `key`, without a fallible constructor: the key is
/// normalised exactly as RFC 2104 does (hashed when longer than a block, then
/// zero-padded), which is what `new_from_slice` does internally.
fn hmac(key: &[u8]) -> HmacSha256 {
    use sha2::Digest as _;
    let mut block = [0u8; BLOCK_BYTES];
    if key.len() <= BLOCK_BYTES {
        block[..key.len()].copy_from_slice(key);
    } else {
        let digest = Sha256::digest(key);
        block[..digest.len()].copy_from_slice(&digest);
    }
    <HmacSha256 as KeyInit>::new(&block.into())
}

impl LinkKey {
    /// `HMAC-SHA256(key = token, msg = "greentic/artifact-link/v1" 0x1f tenant 0x1f bundle 0x1f deployment)`.
    pub(crate) fn derive(
        token: &str,
        tenant_slug: &str,
        bundle_id: &str,
        deployment: &str,
    ) -> Self {
        let mut mac = hmac(token.as_bytes());
        for (i, part) in [
            KEY_DOMAIN,
            tenant_slug.as_bytes(),
            bundle_id.as_bytes(),
            deployment.as_bytes(),
        ]
        .into_iter()
        .enumerate()
        {
            if i > 0 {
                mac.update(SEP);
            }
            mac.update(part);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.finalize().into_bytes());
        Self(out)
    }

    #[cfg(test)]
    pub(crate) fn expose_for_test(&self) -> &[u8] {
        &self.0
    }

    fn link_mac(&self, deployment: &str, artifact_hex: &str, exp: u64) -> HmacSha256 {
        let mut mac = hmac(&self.0);
        mac.update(MAC_VERSION);
        mac.update(SEP);
        mac.update(deployment.as_bytes());
        mac.update(SEP);
        mac.update(artifact_hex.as_bytes());
        mac.update(SEP);
        mac.update(exp.to_string().as_bytes());
        mac
    }
}

/// The four parsed path segments. Only built by [`LinkPath::parse`] or
/// [`mint`] in production; the fields are public for the route and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkPath {
    pub deployment: String,
    pub artifact_hex: String,
    pub exp: u64,
    pub mac_hex: String,
}

fn is_crockford_upper(b: u8) -> bool {
    b.is_ascii_digit() || (b.is_ascii_uppercase() && !matches!(b, b'I' | b'L' | b'O' | b'U'))
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_exp(s: &str) -> Option<u64> {
    let ok = (1..=MAX_EXP_DIGITS).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_digit())
        && !s.starts_with('0');
    if ok { s.parse().ok() } else { None }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn decode_mac(hex: &str) -> Option<[u8; MAC_BYTES]> {
    if !is_lower_hex(hex, MAC_BYTES * 2) {
        return None;
    }
    let mut out = [0u8; MAC_BYTES];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

impl LinkPath {
    /// Strict: exactly four segments after [`LINK_PREFIX`]; a 26-char ULID of
    /// the uppercase Crockford alphabet; 64 lowercase hex; `exp` of 1..=11
    /// digits without a leading zero; 32 lowercase hex. Anything else is `None`.
    pub(crate) fn parse(path: &str) -> Option<Self> {
        let rest = path.strip_prefix(LINK_PREFIX)?;
        let mut segments = rest.split('/');
        let deployment = segments.next()?;
        let artifact_hex = segments.next()?;
        let exp = segments.next()?;
        let mac_hex = segments.next()?;
        if segments.next().is_some() {
            return None;
        }
        let ulid_ok = deployment.len() == ULID_LEN && deployment.bytes().all(is_crockford_upper);
        if !ulid_ok || !is_lower_hex(artifact_hex, ARTIFACT_HEX_LEN) {
            return None;
        }
        let exp = parse_exp(exp)?;
        decode_mac(mac_hex)?;
        Some(Self {
            deployment: deployment.to_string(),
            artifact_hex: artifact_hex.to_string(),
            exp,
            mac_hex: mac_hex.to_string(),
        })
    }

    pub(crate) fn to_path(&self) -> String {
        format!(
            "{LINK_PREFIX}{}/{}/{}/{}",
            self.deployment, self.artifact_hex, self.exp, self.mac_hex
        )
    }
}

/// Pure TTL rule: clamped to `MIN..=MAX`, unparsable or absent = default.
pub(crate) fn ttl_from(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(DEFAULT_TTL_SECS, |v| v.clamp(MIN_TTL_SECS, MAX_TTL_SECS))
}

/// Whether signed artifact links are minted and served at all, in CODE.
///
/// OFF until the WebChat reconnect-token hardening (gap G2,
/// docs/superpowers/plans/2026-10-08-webchat-reconnect-token-hardening.md in
/// the designer repo) ships in the same release: a hijacked WebChat
/// conversation would otherwise expose every file link it holds. No deploy
/// lane can set an env var on a remote workload today, so the release that
/// carries G2 flips this constant (and its pin test) rather than relying on
/// operators to switch it on.
pub(crate) const OUTBOUND_LINKS_ENABLED: bool = false;
/// Can only force links ON (`1`/`true`/`yes`/`on`, case-insensitive) for a
/// host that has G2, e.g. local testing; there is no off-override, so a build
/// whose constant is `true` cannot be switched off by a stray variable.
pub(crate) const LINKS_ENV: &str = "GREENTIC_ARTIFACT_LINKS";

/// Pure rule: the code default, or an explicit "on" value.
pub(crate) fn links_enabled_with(code_default: bool, raw: Option<&str>) -> bool {
    code_default
        || raw.is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
}

/// [`links_enabled_with`] over [`OUTBOUND_LINKS_ENABLED`].
pub(crate) fn links_enabled_from(raw: Option<&str>) -> bool {
    links_enabled_with(OUTBOUND_LINKS_ENABLED, raw)
}

/// [`LINKS_ENV`], read once per process. When `false`, outbound shaping
/// mints nothing (the "file delivery is turned off" sentence) and the link
/// route answers every request with the uniform 404.
pub(crate) fn links_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| links_enabled_from(std::env::var(LINKS_ENV).ok().as_deref()))
}

/// [`TTL_ENV`], read once per process.
pub(crate) fn ttl_secs() -> u64 {
    static TTL: OnceLock<u64> = OnceLock::new();
    *TTL.get_or_init(|| ttl_from(std::env::var(TTL_ENV).ok().as_deref()))
}

/// A link for `artifact_id`, valid until `now + ttl`. `None` when the id is
/// not a well-formed artifact id or `deployment` is not a ULID.
pub(crate) fn mint(
    key: &LinkKey,
    deployment: &str,
    artifact_id: &str,
    now: u64,
    ttl: u64,
) -> Option<LinkPath> {
    if !is_artifact_id(artifact_id) {
        return None;
    }
    let artifact_hex = artifact_id.strip_prefix(ID_SCHEME)?;
    let exp = now.checked_add(ttl)?;
    let tag = key
        .link_mac(deployment, artifact_hex, exp)
        .finalize()
        .into_bytes();
    let link = LinkPath {
        deployment: deployment.to_string(),
        artifact_hex: artifact_hex.to_string(),
        exp,
        mac_hex: hex_lower(&tag[..MAC_BYTES]),
    };
    // Never hand out a path the route would refuse to parse.
    LinkPath::parse(&link.to_path())?;
    Some(link)
}

pub(crate) enum Verdict {
    Valid { artifact_id: String },
    Invalid,
}

/// MAC first (constant time, over the parsed canonical fields), then expiry:
/// `exp + SKEW < now` is expired, and `exp > now + ttl_max + SKEW` is refused
/// so that LOWERING the TTL revokes longer links already sent.
pub(crate) fn verify(key: &LinkKey, link: &LinkPath, now: u64, ttl_max: u64) -> Verdict {
    let Some(tag) = decode_mac(&link.mac_hex) else {
        return Verdict::Invalid;
    };
    let mac_ok = key
        .link_mac(&link.deployment, &link.artifact_hex, link.exp)
        .verify_truncated_left(&tag)
        .is_ok();
    if !mac_ok {
        return Verdict::Invalid;
    }
    if link.exp.saturating_add(SKEW_SECS) < now {
        return Verdict::Invalid;
    }
    if link.exp > now.saturating_add(ttl_max).saturating_add(SKEW_SECS) {
        return Verdict::Invalid;
    }
    Verdict::Valid {
        artifact_id: format!("{ID_SCHEME}{}", link.artifact_hex),
    }
}
