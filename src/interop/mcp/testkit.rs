//! Test-only helpers for the MCP surface: a fixed RS256 keypair, a JWKS
//! document matching it, and a token minter.
//!
//! Lifted from greentic-designer's `src/ui/mcp_server/testkit.rs` so both
//! surfaces are exercised against the same fixture key.
//!
//! The keypair is a fixture, not a secret: it exists only in this file, is
//! generated for the test suite alone, and signs nothing outside it. It is
//! checked in deliberately rather than generated per run — a keypair minted at
//! test time makes a signature-verification failure indistinguishable from a
//! key-generation quirk, and RSA keygen is slow enough to be felt in a suite
//! this size.

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;

/// The `kid` both the JWKS document and every minted token carry. A token
/// whose `kid` is absent from the served key set must be refused, so the two
/// are deliberately spelled once, here.
pub const TEST_KID: &str = "mcp-test-key-1";

pub const TEST_PRIVATE_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCz86daiEPDadpk
OQ2zjhgguVEB/nphDpAByzc3vrhG/tjRv6gT1MijYL6qOkEKdYNyaxORXvIvbrmI
23eDEVsfln4Z3joYWKPjDGdY8GMhSeHUpfXOqd8mS4wt7MV+nnjoY2YWGY4ta5pt
R9ErLxRokCmTfL8MKN8OwwotmC0nYoC7fgDAMuA1FJDNnjbuX0UiRtTkSJsEr9Ep
y3FUwm4v2GdmjmqcSKHi/0jT/uIfNbwvTBMeN1+8ekXmYxX0nUf9jVeM0fPSkq41
Z1O1YdIyFkPGWafDKa11hBjIMuGurjrzw2XOao/wGNFDRdCMYsiUqvYbFHJHEwed
nVHhb357AgMBAAECggEAMZx3AwqWRAWm5AKmuF3wYPU2VCpoauGs6hGwg3ndLBWO
iSUhnXYIaqJ9bkjpLY0AVEcY+fcHJfSMyiJXbJcYXDkNQux1b8jgRfRhea+sZL0N
uaaXggZrMw+Y8gBY4nOmOctNlcIt5G/J/17RV+p+4eT80WCO+zc5Z8R1xeQybqzO
3ZegMmVXXHDy4xflxLMm1tPm8hBGLIgQCzcav+7MKRSIHMofjI/CLNJvWpnWSJIk
i17mZOj1kCzWgvxeEPINjrxuAP0X+KlsOQJYKhJPAXuTsatsVk8u17h9pdkkbZKA
cVP2/zlRKcD0sm1zMNgZ1cypZyQxL0MUe+dmrtdMYQKBgQDlUj5ES5Mt8D/G2/NE
mrK4tyDqE9qBE9Q+UZwPG9S4keY/0Py16+w8WGRwdhuID9iBH+WpQoaTUcKjg8D/
KSPkxhg01QJ+cC/IcbHH6sUq9j7PeIVFpMZRzOdhKc+fYcxMebqYVLqAyVHBx9RB
LbZi4YYqcIy2D/IDuXTnyirHnwKBgQDI4xCALn7M0veYv+ytWF1v4hHUSVQVkMMj
fR7rjxvl59cMFAkdYshvypUBU/QAbE4Gq9SQdNXFqA/lQ5dc04UydxM/bplvEYxe
9RfcNQMbIvtBj/tKWPChx+f2RJNJdaWZ3RicPIf8ELN5E3i8HEK3rmeDWhYKfa9x
SbiAchcLpQKBgQDdQXzSaBiZOjROqekNSDUoA4i+UGmCIJ+ngRYRfcjATATbjchF
vlsv3hkKaOonXSKHcz8jEAzIFxq0qWqMxiTblkXEs8C0PYnc29WsDdgum2f+xUnQ
6CpwwkJ8fNrV7IYxQ0HFt/o6SAOZ9DPWr0RKI05PpEgfYUMgVM921JhyAQKBgEJY
5CFBufVSFB5p/PQ/hBSouLTBRzkcJ6b38xdfm5oyGQ9PKrd+4a4yXUYkASmGm7qO
U9UmEViHqkBRM5Of9JT3SO8hSyGozRCrqCa9h3oV8p/zus4SU99K0+y9N1wCtB/+
KtunDk6NAYmSicSvHMXnnx59yVvLqP8klwAtLjlVAoGBAJ4/rMCZBl1ycAzUZezf
pDnk0rrPtTmgXAqPTWaf1vbl6XEHQWUpDVfjwPgQGDIxfapmPeAIKOyA+1mTSjdL
5bzRCY8AGqITt7xQE0xURtgxMpf9Ud/CBckGaNWW7XkaXhTUsrGj27nwpW94yJZW
xyssQ8717D6m3L/HgdiUuU3I
-----END PRIVATE KEY-----
";

/// The RSA modulus of [`TEST_PRIVATE_KEY_PEM`], base64url, unpadded.
pub const TEST_JWKS_N: &str = "s_OnWohDw2naZDkNs44YILlRAf56YQ6QAcs3N764Rv7Y0b-oE9TIo2C-qjpBCnWDcmsTkV7yL265iNt3gxFbH5Z-Gd46GFij4wxnWPBjIUnh1KX1zqnfJkuMLezFfp546GNmFhmOLWuabUfRKy8UaJApk3y_DCjfDsMKLZgtJ2KAu34AwDLgNRSQzZ427l9FIkbU5EibBK_RKctxVMJuL9hnZo5qnEih4v9I0_7iHzW8L0wTHjdfvHpF5mMV9J1H_Y1XjNHz0pKuNWdTtWHSMhZDxlmnwymtdYQYyDLhrq4688NlzmqP8BjRQ0XQjGLIlKr2GxRyRxMHnZ1R4W9-ew";

/// The public exponent, 65537.
pub const TEST_JWKS_E: &str = "AQAB";

/// The JWKS document a fake issuer serves.
pub fn jwks_document() -> serde_json::Value {
    json!({ "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": TEST_KID,
        "n": TEST_JWKS_N,
        "e": TEST_JWKS_E,
    }]})
}

/// A `sub` no other token in this test binary carries.
///
/// The rate limiter keys its bucket on `sub`, so two tests sharing one literal
/// subject would share one allowance: a long enough suite would start
/// answering `429` to tests that have nothing to do with rate limiting. Each
/// test authenticating as its own subject is also the truthful model — a `sub`
/// is minted per OAuth authorization, so two tests are two connections.
pub fn unique_sub() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "u-test-{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// Mint a token. Every field is a parameter so a test can make exactly one of
/// them wrong.
pub fn mint_token(
    issuer: &str,
    audience: &str,
    sub: &str,
    tenant: &str,
    expires_in_secs: i64,
) -> String {
    mint_token_with_kid(TEST_KID, issuer, audience, sub, tenant, expires_in_secs)
}

/// Mint a token whose header names an arbitrary `kid`.
///
/// The signature is still made with the real key; what varies is only which
/// key the gate is asked to LOOK UP — the whole unauthenticated surface of the
/// JWKS cache, since `decode_header` runs before any signature check.
pub fn mint_token_with_kid(
    kid: &str,
    issuer: &str,
    audience: &str,
    sub: &str,
    tenant: &str,
    expires_in_secs: i64,
) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "tenant": tenant,
        "iat": now,
        "exp": now + expires_in_secs,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY_PEM.as_bytes()).expect("test RSA private key"),
    )
    .expect("minting a test token")
}
