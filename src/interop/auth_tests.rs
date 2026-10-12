//! The shared gate against a real RS256 keypair and a stub JWKS endpoint:
//! mechanism filtering, audience binding per surface, service-client subjects,
//! and the public-mode rules (access-policy spec §6.2, §9).

use std::sync::atomic::Ordering;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::*;
use crate::interop::config::{AccessPolicy, Credential, PublicLimits};
use crate::interop::mcp::testkit::{self, StubIssuer};

const TENANT: &str = "acme";
const MCP_RESOURCE: &str = "https://w.example/mcp";
const A2A_RESOURCE: &str = "https://w.example/a2a";
const BEARER_TOKEN: &str = "gtw_staged-token";
const CLIENT: &str = "203.0.113.7";

fn config(issuer: Option<&str>, access: AccessPolicy) -> InteropConfig {
    InteropConfig {
        mcp: true,
        a2a: true,
        credentials: vec![Credential {
            id: "c1".into(),
            sha256: Sha256::digest(BEARER_TOKEN.as_bytes()).into(),
            expires_at_ms: None,
        }],
        tenant_slug: Some(TENANT.to_string()),
        issuer: issuer.map(str::to_string),
        mcp_resource: Some(MCP_RESOURCE.to_string()),
        a2a_resource: Some(A2A_RESOURCE.to_string()),
        access,
        ..InteropConfig::default()
    }
}

fn policy(visibility: Visibility, mechanisms: &[Mechanism]) -> AccessPolicy {
    AccessPolicy {
        visibility,
        mechanisms: mechanisms.to_vec(),
        public: PublicLimits::default(),
        generation: 1,
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

async fn gate(config: &InteropConfig, audience: Option<&str>, header: Option<&str>) -> Auth {
    authenticate(config, audience, header, false, 0, CLIENT).await
}

/// A Direct Line style token: HS256 under a provider signing key, naming this
/// very tenant and audience so that nothing but the algorithm refuses it.
fn direct_line_token(issuer: &str, audience: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": issuer, "aud": audience, "sub": "user-1", "tenant": TENANT,
        "iat": now, "exp": now + 600,
    });
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(testkit::TEST_KID.to_string());
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_secret(b"jwt_signing_key"),
    )
    .expect("minting a Direct Line style token")
}

fn both() -> AccessPolicy {
    AccessPolicy::default()
}

#[tokio::test]
async fn a2a_accepts_an_oauth_token_for_its_own_resource() {
    let issuer = StubIssuer::serving_keys(1).await;
    let sub = testkit::unique_sub();
    let token = testkit::mint_token(&issuer.url, A2A_RESOURCE, &sub, TENANT, 600);
    let outcome = gate(
        &config(Some(&issuer.url), both()),
        Some(A2A_RESOURCE),
        Some(&bearer(&token)),
    )
    .await;
    assert_eq!(outcome, Auth::Allowed(Caller::Oauth(sub)));
}

#[tokio::test]
async fn a_token_minted_for_the_other_surface_is_refused() {
    let issuer = StubIssuer::serving_keys(2).await;
    let cfg = config(Some(&issuer.url), both());
    let mcp_token = testkit::mint_token(
        &issuer.url,
        MCP_RESOURCE,
        &testkit::unique_sub(),
        TENANT,
        600,
    );
    let a2a_token = testkit::mint_token(
        &issuer.url,
        A2A_RESOURCE,
        &testkit::unique_sub(),
        TENANT,
        600,
    );
    assert_eq!(
        gate(&cfg, Some(A2A_RESOURCE), Some(&bearer(&mcp_token))).await,
        Auth::Unauthorized,
        "an MCP-audience token must not call A2A"
    );
    assert_eq!(
        gate(&cfg, Some(MCP_RESOURCE), Some(&bearer(&a2a_token))).await,
        Auth::Unauthorized,
        "an A2A-audience token must not call MCP"
    );
}

#[tokio::test]
async fn the_api_key_only_policy_rejects_a_valid_oauth_token() {
    let issuer = StubIssuer::serving_keys(1).await;
    let token = testkit::mint_token(
        &issuer.url,
        A2A_RESOURCE,
        &testkit::unique_sub(),
        TENANT,
        600,
    );
    let cfg = config(
        Some(&issuer.url),
        policy(Visibility::Private, &[Mechanism::ApiKey]),
    );
    assert_eq!(
        gate(&cfg, Some(A2A_RESOURCE), Some(&bearer(&token))).await,
        Auth::Unauthorized
    );
    // The bearer still passes.
    assert_eq!(
        gate(&cfg, Some(A2A_RESOURCE), Some(&bearer(BEARER_TOKEN))).await,
        Auth::Allowed(Caller::Bearer("c1".into()))
    );
}

#[tokio::test]
async fn the_oauth_only_policy_rejects_a_valid_bearer() {
    let issuer = StubIssuer::serving_keys(1).await;
    let cfg = config(
        Some(&issuer.url),
        policy(Visibility::Private, &[Mechanism::Oauth]),
    );
    assert_eq!(
        gate(&cfg, Some(A2A_RESOURCE), Some(&bearer(BEARER_TOKEN))).await,
        Auth::Unauthorized
    );
}

/// Strict: an OAuth-only policy on a surface where OAuth cannot be verified
/// refuses everyone, the staged bearer included. It is never quietly relaxed.
#[tokio::test]
async fn an_oauth_only_policy_without_an_audience_refuses_the_bearer_too() {
    let issuer = StubIssuer::serving_keys(1).await;
    let cfg = config(
        Some(&issuer.url),
        policy(Visibility::Private, &[Mechanism::Oauth]),
    );
    let token = testkit::mint_token(
        &issuer.url,
        A2A_RESOURCE,
        &testkit::unique_sub(),
        TENANT,
        600,
    );
    assert_eq!(
        gate(&cfg, None, Some(&bearer(BEARER_TOKEN))).await,
        Auth::Unauthorized
    );
    assert_eq!(
        gate(&cfg, None, Some(&bearer(&token))).await,
        Auth::Unauthorized
    );
    // The same for each missing prerequisite.
    let mut no_issuer = config(None, policy(Visibility::Private, &[Mechanism::Oauth]));
    assert_eq!(
        gate(&no_issuer, Some(A2A_RESOURCE), Some(&bearer(BEARER_TOKEN))).await,
        Auth::Unauthorized
    );
    no_issuer.issuer = Some(issuer.url.clone());
    no_issuer.tenant_slug = None;
    assert_eq!(
        gate(&no_issuer, Some(A2A_RESOURCE), Some(&bearer(BEARER_TOKEN))).await,
        Auth::Unauthorized
    );
}

/// The default policy (no `access` block) is unchanged: both mechanisms, and
/// the bearer works whether or not OAuth can run.
#[tokio::test]
async fn the_default_policy_accepts_the_bearer_without_any_oauth_prerequisite() {
    let cfg = config(None, both());
    assert_eq!(
        gate(&cfg, None, Some(&bearer(BEARER_TOKEN))).await,
        Auth::Allowed(Caller::Bearer("c1".into()))
    );
    let bare = InteropConfig {
        issuer: None,
        tenant_slug: None,
        ..cfg
    };
    assert_eq!(
        gate(&bare, None, Some(&bearer(BEARER_TOKEN))).await,
        Auth::Allowed(Caller::Bearer("c1".into()))
    );
    assert_eq!(gate(&bare, None, None).await, Auth::Unauthorized);
}

#[tokio::test]
async fn a_service_client_subject_is_mapped_to_a_colon_free_key() {
    let issuer = StubIssuer::serving_keys(1).await;
    let sub = "svc:mcpc_01J@acme";
    let token = testkit::mint_token(&issuer.url, A2A_RESOURCE, sub, TENANT, 600);
    let outcome = gate(
        &config(Some(&issuer.url), both()),
        Some(A2A_RESOURCE),
        Some(&bearer(&token)),
    )
    .await;
    let Auth::Allowed(caller) = outcome else {
        panic!("a service token for this tenant must pass: {outcome:?}");
    };
    assert_eq!(caller, Caller::Oauth("svc~mcpc_01J~acme".into()));
    assert!(
        !caller.key().contains(':'),
        "a colon would break the session hint"
    );
    assert_eq!(caller.credential_id(), None);
}

#[test]
fn only_an_exact_service_subject_for_this_tenant_is_mapped() {
    use crate::interop::mcp::auth::caller_key_for_sub;
    assert_eq!(caller_key_for_sub("u-1", TENANT).as_deref(), Some("u-1"));
    assert_eq!(
        caller_key_for_sub("svc:c1@acme", TENANT).as_deref(),
        Some("svc~c1~acme")
    );
    for bad in [
        "svc:c1@other",  // another workspace's service client
        "svc:c1@",       // no tenant
        "svc:@acme",     // no client
        "svc:a:b@acme",  // a colon in the client id
        "svc:c1@acme@x", // two separators
        "svc:c1@ac me",  // outside the alphabet
        "svc~c1~acme",   // a user cannot present the mapped form
        "svc:",
        "",
        "u:1",
    ] {
        assert_eq!(caller_key_for_sub(bad, TENANT), None, "{bad}");
    }
}

#[test]
fn a_mapped_service_key_cannot_equal_any_user_key() {
    // The mapping's separator is outside the alphabet every user key obeys.
    assert!(!crate::interop::valid_caller_key("svc~c1~acme"));
}

// ---- public mode ----------------------------------------------------------

fn public(mechanisms: &[Mechanism]) -> AccessPolicy {
    policy(Visibility::Public, mechanisms)
}

#[tokio::test]
async fn a_public_unit_serves_a_caller_with_no_credential_as_anonymous() {
    let cfg = config(None, public(&[Mechanism::ApiKey, Mechanism::Oauth]));
    for header in [None, Some(""), Some("   ")] {
        let outcome = gate(&cfg, Some(A2A_RESOURCE), header).await;
        assert_eq!(
            outcome,
            Auth::Allowed(Caller::anonymous(CLIENT)),
            "{header:?}"
        );
    }
}

#[tokio::test]
async fn a_private_unit_refuses_a_caller_with_no_credential() {
    let cfg = config(None, both());
    for header in [None, Some(""), Some("Bearer ")] {
        assert_eq!(
            gate(&cfg, Some(A2A_RESOURCE), header).await,
            Auth::Unauthorized
        );
    }
}

#[tokio::test]
async fn a_credential_that_is_presented_and_invalid_is_refused_even_on_a_public_unit() {
    let issuer = StubIssuer::serving_keys(4).await;
    let cfg = config(
        Some(&issuer.url),
        public(&[Mechanism::ApiKey, Mechanism::Oauth]),
    );
    let expired = testkit::mint_token(
        &issuer.url,
        A2A_RESOURCE,
        &testkit::unique_sub(),
        TENANT,
        -600,
    );
    let wrong_audience = testkit::mint_token(
        &issuer.url,
        MCP_RESOURCE,
        &testkit::unique_sub(),
        TENANT,
        600,
    );
    let wrong_tenant = testkit::mint_token(
        &issuer.url,
        A2A_RESOURCE,
        &testkit::unique_sub(),
        "other",
        600,
    );
    for header in [
        bearer("gtw_a-typo-in-the-key"),
        bearer(&expired),
        bearer(&wrong_audience),
        bearer(&wrong_tenant),
        "Basic dXNlcjpwYXNz".to_string(),
        "Bearer".to_string(),
        "garbage".to_string(),
    ] {
        assert_eq!(
            gate(&cfg, Some(A2A_RESOURCE), Some(&header)).await,
            Auth::Unauthorized,
            "{header}"
        );
    }
}

#[tokio::test]
async fn a_valid_credential_beats_anonymous_on_a_public_unit() {
    let issuer = StubIssuer::serving_keys(1).await;
    let cfg = config(
        Some(&issuer.url),
        public(&[Mechanism::ApiKey, Mechanism::Oauth]),
    );
    assert_eq!(
        gate(&cfg, Some(A2A_RESOURCE), Some(&bearer(BEARER_TOKEN))).await,
        Auth::Allowed(Caller::Bearer("c1".into()))
    );
    let sub = testkit::unique_sub();
    let token = testkit::mint_token(&issuer.url, A2A_RESOURCE, &sub, TENANT, 600);
    assert_eq!(
        gate(&cfg, Some(A2A_RESOURCE), Some(&bearer(&token))).await,
        Auth::Allowed(Caller::Oauth(sub))
    );
}

/// A mechanism the policy does not list is a presented-and-invalid credential,
/// not a reason to serve the caller anonymously.
#[tokio::test]
async fn a_valid_credential_of_an_unlisted_mechanism_is_refused_on_a_public_unit() {
    let cfg = config(None, public(&[Mechanism::Oauth]));
    // OAuth cannot run on this unit (no issuer): still a refusal, not a bearer.
    assert_eq!(
        gate(&cfg, Some(A2A_RESOURCE), Some(&bearer(BEARER_TOKEN))).await,
        Auth::Unauthorized
    );
    let issuer = StubIssuer::serving_keys(1).await;
    let cfg = config(Some(&issuer.url), public(&[Mechanism::Oauth]));
    assert_eq!(
        gate(&cfg, Some(A2A_RESOURCE), Some(&bearer(BEARER_TOKEN))).await,
        Auth::Unauthorized
    );
}

/// A Direct Line token (HS256) is never an identity: refused on a private
/// unit, anonymous on a public one — on both surfaces' audiences — and the
/// gate never even asks the issuer for keys on its account.
#[tokio::test]
async fn a_direct_line_token_never_authenticates() {
    let issuer = StubIssuer::serving_keys(0).await;
    let token = direct_line_token(&issuer.url, A2A_RESOURCE);
    assert!(is_direct_line_token(&token));
    assert!(!is_direct_line_token(&testkit::mint_token(
        &issuer.url,
        A2A_RESOURCE,
        "u-1",
        TENANT,
        600
    )));
    for audience in [A2A_RESOURCE, MCP_RESOURCE] {
        let private = config(Some(&issuer.url), both());
        assert_eq!(
            gate(&private, Some(audience), Some(&bearer(&token))).await,
            Auth::Unauthorized,
            "private, {audience}"
        );
        let open = config(
            Some(&issuer.url),
            public(&[Mechanism::ApiKey, Mechanism::Oauth]),
        );
        let outcome = gate(&open, Some(audience), Some(&bearer(&token))).await;
        assert_eq!(
            outcome,
            Auth::Allowed(Caller::anonymous(CLIENT)),
            "public, {audience}"
        );
        let Auth::Allowed(caller) = outcome else {
            unreachable!()
        };
        assert!(caller.is_anonymous(), "never the token's `sub`");
    }
    assert_eq!(issuer.fetches.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn an_hmac_token_in_the_other_hmac_widths_is_a_direct_line_token_too() {
    for alg in [Algorithm::HS384, Algorithm::HS512] {
        let header = Header::new(alg);
        let token = jsonwebtoken::encode(
            &header,
            &json!({"sub": "u", "exp": 4_000_000_000u64}),
            &EncodingKey::from_secret(b"k"),
        )
        .expect("token");
        assert!(is_direct_line_token(&token), "{alg:?}");
    }
    assert!(!is_direct_line_token("not-a-jwt"));
    assert!(!is_direct_line_token(BEARER_TOKEN));
}

/// A header that is present but not text is a credential the caller tried to
/// present: a 401 on a public unit, never anonymous.
#[tokio::test]
async fn an_unreadable_authorization_header_is_presented_and_invalid() {
    let cfg = config(None, public(&[Mechanism::ApiKey, Mechanism::Oauth]));
    let outcome = authenticate(&cfg, Some(A2A_RESOURCE), None, true, 0, CLIENT).await;
    assert_eq!(outcome, Auth::Unauthorized);
    let private = config(None, both());
    let outcome = authenticate(&private, Some(A2A_RESOURCE), None, true, 0, CLIENT).await;
    assert_eq!(outcome, Auth::Unauthorized);
    // The same request with the header genuinely absent is still anonymous.
    let outcome = authenticate(&cfg, Some(A2A_RESOURCE), None, false, 0, CLIENT).await;
    assert_eq!(outcome, Auth::Allowed(Caller::anonymous(CLIENT)));
}
