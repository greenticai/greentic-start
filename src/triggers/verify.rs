//! Host-side webhook verification (contract §6.3.3, §6.3.4, decision D2).
//!
//! Pure: every function takes the already-resolved secret bytes, so each rule
//! is tested without a secrets backend. Resolving the secret — and refusing
//! with 503 when it cannot be read — is the caller's job, and it never falls
//! back to "unverified".
//!
//! Every comparison is constant-time (`subtle`): an early-exit `==` on a MAC or
//! a token leaks, byte by byte, how much of a guess was right.

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use subtle::ConstantTimeEq;

use super::schema::{HmacAlgo, SignatureEncoding};

/// Why a request was refused. Deliberately coarse: the HTTP response carries
/// the status only (§7.2), so none of this detail reaches the caller.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VerifyError {
    MissingHeader,
    Malformed,
    Mismatch,
}

/// HMAC over the RAW body bytes exactly as received, before any parsing, so a
/// parser that normalizes whitespace or key order cannot change what is
/// verified.
pub(crate) fn verify_hmac(
    algo: &HmacAlgo,
    secret: &[u8],
    body: &[u8],
    header_value: Option<&str>,
    prefix: &str,
    encoding: &SignatureEncoding,
) -> Result<(), VerifyError> {
    let header_value = header_value.ok_or(VerifyError::MissingHeader)?.trim();
    let presented = header_value
        .strip_prefix(prefix)
        .ok_or(VerifyError::Malformed)?;
    let presented = match encoding {
        SignatureEncoding::Hex => decode_hex(presented).ok_or(VerifyError::Malformed)?,
        SignatureEncoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(presented)
            .map_err(|_| VerifyError::Malformed)?,
    };
    let expected = match algo {
        HmacAlgo::Sha256 => {
            let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(secret)
                .map_err(|_| VerifyError::Malformed)?;
            mac.update(body);
            mac.finalize().into_bytes().to_vec()
        }
        HmacAlgo::Sha1 => {
            let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(secret)
                .map_err(|_| VerifyError::Malformed)?;
            mac.update(body);
            mac.finalize().into_bytes().to_vec()
        }
    };
    // Length is not secret (it is fixed by the algorithm), so a length check
    // before the constant-time compare leaks nothing.
    if presented.len() == expected.len() && bool::from(presented.ct_eq(&expected)) {
        Ok(())
    } else {
        Err(VerifyError::Mismatch)
    }
}

/// `Authorization: Bearer <value>` for the `Authorization` header, the bare
/// value for any other header (§6.3.3).
pub(crate) fn verify_bearer(
    header: &str,
    secret: &[u8],
    header_value: Option<&str>,
) -> Result<(), VerifyError> {
    let raw = header_value.ok_or(VerifyError::MissingHeader)?.trim();
    let presented = if header.eq_ignore_ascii_case("authorization") {
        raw.strip_prefix("Bearer ")
            .or_else(|| raw.strip_prefix("bearer "))
            .ok_or(VerifyError::Malformed)?
    } else {
        raw
    };
    if bool::from(presented.as_bytes().ct_eq(secret)) {
        Ok(())
    } else {
        Err(VerifyError::Mismatch)
    }
}

/// The Meta subscription handshake: what a `GET` answers.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChallengeOutcome {
    /// Echo this value verbatim as `text/plain` with 200.
    Echo(String),
    /// Right shape, wrong token: 403.
    Forbidden,
    /// Not a subscription handshake at all: 405.
    NotAChallenge,
}

pub(crate) fn meta_hub_challenge(
    query: &[(String, String)],
    verify_token: &[u8],
) -> ChallengeOutcome {
    let get = |name: &str| {
        query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    if get("hub.mode") != Some("subscribe") {
        return ChallengeOutcome::NotAChallenge;
    }
    let (Some(token), Some(challenge)) = (get("hub.verify_token"), get("hub.challenge")) else {
        return ChallengeOutcome::Forbidden;
    };
    if bool::from(token.as_bytes().ct_eq(verify_token)) {
        ChallengeOutcome::Echo(challenge.to_string())
    } else {
        ChallengeOutcome::Forbidden
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(secret: &[u8], body: &[u8]) -> String {
        let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(secret).unwrap();
        mac.update(body);
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn a_meta_signature_over_the_raw_body_verifies() {
        let body = br#"{"object":"threads","entry":[]}"#;
        let header = format!("sha256={}", sign(b"app-secret", body));
        assert_eq!(
            verify_hmac(
                &HmacAlgo::Sha256,
                b"app-secret",
                body,
                Some(&header),
                "sha256=",
                &SignatureEncoding::Hex
            ),
            Ok(())
        );
    }

    #[test]
    fn changing_one_body_byte_fails_verification() {
        let body = br#"{"object":"threads","entry":[]}"#;
        let header = format!("sha256={}", sign(b"app-secret", body));
        let tampered = br#"{"object":"threads","entry":[1]}"#;
        assert_eq!(
            verify_hmac(
                &HmacAlgo::Sha256,
                b"app-secret",
                tampered,
                Some(&header),
                "sha256=",
                &SignatureEncoding::Hex
            ),
            Err(VerifyError::Mismatch)
        );
    }

    #[test]
    fn a_missing_or_malformed_signature_header_fails() {
        let body = b"{}";
        for (header, expected) in [
            (None, VerifyError::MissingHeader),
            (Some("md5=abc"), VerifyError::Malformed),
            (Some("sha256=zz"), VerifyError::Malformed),
            (Some("sha256=00"), VerifyError::Mismatch),
        ] {
            assert_eq!(
                verify_hmac(
                    &HmacAlgo::Sha256,
                    b"k",
                    body,
                    header,
                    "sha256=",
                    &SignatureEncoding::Hex
                ),
                Err(expected),
                "{header:?}"
            );
        }
    }

    #[test]
    fn hmac_sha1_and_base64_encoding_verify() {
        let body = b"payload";
        let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(b"k").unwrap();
        mac.update(body);
        let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        assert_eq!(
            verify_hmac(
                &HmacAlgo::Sha1,
                b"k",
                body,
                Some(&sig),
                "",
                &SignatureEncoding::Base64
            ),
            Ok(())
        );
    }

    #[test]
    fn bearer_requires_the_scheme_on_authorization_and_the_bare_value_elsewhere() {
        assert_eq!(
            verify_bearer("Authorization", b"tok", Some("Bearer tok")),
            Ok(())
        );
        assert_eq!(
            verify_bearer("Authorization", b"tok", Some("tok")),
            Err(VerifyError::Malformed)
        );
        assert_eq!(verify_bearer("X-Api-Key", b"tok", Some("tok")), Ok(()));
        assert_eq!(
            verify_bearer("X-Api-Key", b"tok", Some("nope")),
            Err(VerifyError::Mismatch)
        );
        assert_eq!(
            verify_bearer("X-Api-Key", b"tok", None),
            Err(VerifyError::MissingHeader)
        );
    }

    #[test]
    fn the_hub_challenge_echoes_only_with_the_right_token() {
        let q = |token: &str| {
            vec![
                ("hub.mode".to_string(), "subscribe".to_string()),
                ("hub.verify_token".to_string(), token.to_string()),
                ("hub.challenge".to_string(), "1158201444".to_string()),
            ]
        };
        assert_eq!(
            meta_hub_challenge(&q("vt"), b"vt"),
            ChallengeOutcome::Echo("1158201444".into())
        );
        assert_eq!(
            meta_hub_challenge(&q("wrong"), b"vt"),
            ChallengeOutcome::Forbidden
        );
        assert_eq!(
            meta_hub_challenge(&[], b"vt"),
            ChallengeOutcome::NotAChallenge
        );
    }
}
