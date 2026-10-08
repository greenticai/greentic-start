use std::collections::HashMap;
use std::sync::Arc;

use greentic_deploy_spec::DeploymentId;
use greentic_secrets_lib::{SecretError, SecretsManager};
use http_body_util::BodyExt;

use super::notices::Notices;
use super::{Deps, Inbound, RefusalCode, Verdict, refusal, verify_with};
use crate::secrets_gate::DynSecretsManager;

/// Fails the test if any secret is read: the channels these tests name must
/// be decided without touching the store.
struct NoReads;

#[async_trait::async_trait]
impl SecretsManager for NoReads {
    async fn read(&self, path: &str) -> greentic_secrets_lib::Result<Vec<u8>> {
        panic!("no secret may be read here, but `{path}` was")
    }
    async fn write(&self, _: &str, _: &[u8]) -> greentic_secrets_lib::Result<()> {
        Err(SecretError::Permission("read-only".into()))
    }
    async fn delete(&self, _: &str) -> greentic_secrets_lib::Result<()> {
        Err(SecretError::Permission("read-only".into()))
    }
}

fn no_reads() -> DynSecretsManager {
    Arc::new(NoReads)
}

pub(super) fn empty_store() -> DynSecretsManager {
    Arc::new(crate::test_fixtures::FakeSecrets(HashMap::new()))
}

pub(super) fn inbound<'a>(
    provider_type: &'a str,
    method: &'a str,
    headers: &'a [(String, String)],
    body: &'a [u8],
    deployment_id: DeploymentId,
) -> Inbound<'a> {
    Inbound {
        provider_type,
        method,
        headers,
        body,
        pack_id: "messaging-pack",
        unit_id: "unit-a",
        tenant: "default",
        pack_non_secret: None,
        deployment_id,
    }
}

pub(super) fn deps<'a>(secrets: &'a DynSecretsManager, notices: &'a Notices) -> Deps<'a> {
    Deps {
        secrets,
        env: "local",
        notices,
        bf_keys: None,
        now: 0,
        teams_service_hosts: &[],
    }
}

#[tokio::test]
async fn slack_telegram_webchat_and_other_are_not_applicable() {
    let secrets = no_reads();
    let (notices, said) = Notices::recording();
    for provider_type in [
        "messaging.slack.api",
        "messaging.telegram.bot",
        "messaging.webchat.directline",
        "messaging.email.smtp",
        "events.webhook",
    ] {
        let verdict = verify_with(
            inbound(provider_type, "POST", &[], b"{}", DeploymentId::new()),
            &deps(&secrets, &notices),
        )
        .await
        .expect("never refused");
        assert_eq!(verdict, Verdict::NotApplicable, "{provider_type}");
    }
    assert!(said.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_whatsapp_get_is_not_applicable() {
    // The `hub.challenge` handshake is a GET; only a POST carries a message.
    let secrets = no_reads();
    let (notices, _) = Notices::recording();
    for method in ["GET", "get", "HEAD"] {
        let verdict = verify_with(
            inbound(
                "messaging.whatsapp.cloud",
                method,
                &[],
                b"",
                DeploymentId::new(),
            ),
            &deps(&secrets, &notices),
        )
        .await
        .expect("never refused");
        assert_eq!(verdict, Verdict::NotApplicable, "{method}");
    }
}

#[tokio::test]
async fn each_channel_routes_to_its_own_verifier() {
    let secrets = empty_store();
    for (provider_type, names) in [
        ("messaging.whatsapp.cloud", "whatsapp_app_secret"),
        ("messaging.webex.bot", "webhook secret"),
        ("messaging.teams", "ms_bot_app_id"),
    ] {
        let (notices, said) = Notices::recording();
        let verdict = verify_with(
            inbound(provider_type, "post", &[], b"{}", DeploymentId::new()),
            &deps(&secrets, &notices),
        )
        .await
        .expect("an unconfigured channel is admitted");
        assert_eq!(verdict, Verdict::NotConfigured, "{provider_type}");
        let said = said.lock().unwrap();
        assert_eq!(said.len(), 1, "{provider_type}: {said:?}");
        assert!(said[0].contains(names), "{provider_type}: {}", said[0]);
    }
}

async fn body_text(response: hyper::Response<http_body_util::Full<hyper::body::Bytes>>) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

#[tokio::test]
async fn refusal_bodies_never_name_the_condition() {
    let (notices, said) = Notices::recording();
    for code in RefusalCode::ALL {
        let response = refusal(&notices, "WhatsApp", *code);
        let status = response.status();
        let text = body_text(response).await.to_ascii_lowercase();
        assert_eq!(text, "webhook verification failed", "{code:?}");
        for forbidden in ["secret", "app id", "jwks", "kid", "signature mismatch"] {
            assert!(!text.contains(forbidden), "{code:?}: {text}");
        }
        let expected = if matches!(*code, RefusalCode::Endorsement | RefusalCode::ServiceUrl) {
            hyper::StatusCode::FORBIDDEN
        } else {
            hyper::StatusCode::UNAUTHORIZED
        };
        assert_eq!(status, expected, "{code:?}");
    }
    // The operator line names the channel and the fixed code only.
    let said = said.lock().unwrap();
    assert!(
        said.iter().all(|line| line.contains("WhatsApp")),
        "{said:?}"
    );
}

#[tokio::test]
async fn not_configured_warns_once_per_deployment_and_channel() {
    let secrets = empty_store();
    let (notices, said) = Notices::recording();
    let first = DeploymentId::new();
    let second = DeploymentId::new();
    for deployment in [first, first, second] {
        let _ = verify_with(
            inbound("messaging.whatsapp.cloud", "POST", &[], b"{}", deployment),
            &deps(&secrets, &notices),
        )
        .await;
    }
    let _ = verify_with(
        inbound("messaging.teams", "POST", &[], b"{}", first),
        &deps(&secrets, &notices),
    )
    .await;
    let said = said.lock().unwrap();
    assert_eq!(said.len(), 3, "{said:?}");
}

#[tokio::test]
async fn repeated_refusals_are_logged_at_a_bounded_rate() {
    // An unauthenticated caller reaches a refusal at will; the operator log
    // must not become theirs to fill.
    let (notices, said) = Notices::recording();
    for _ in 0..50 {
        let _ = refusal(&notices, "Webex", RefusalCode::BadSignature);
    }
    assert_eq!(said.lock().unwrap().len(), 1);
}

/// Seeds the WhatsApp/Webex shared fixture secret where the provider reads it
/// for pack `messaging-pack`, and returns (store, headers, body).
fn signed(fixture: &str, secret_name: &str) -> (DynSecretsManager, Vec<(String, String)>, Vec<u8>) {
    use base64::Engine;
    let v: serde_json::Value = serde_json::from_str(fixture).expect("fixture");
    let text = |key: &str| v[key].as_str().expect("field").to_string();
    let uri = crate::runner_host::secret_read_uris(
        "local",
        "default",
        None,
        "messaging-pack",
        secret_name,
    )
    .last()
    .cloned()
    .expect("uri");
    let store: DynSecretsManager = Arc::new(crate::test_fixtures::FakeSecrets(HashMap::from([(
        uri,
        text("secret").into_bytes(),
    )])));
    let body = base64::engine::general_purpose::STANDARD
        .decode(text("body_base64"))
        .expect("body");
    (store, vec![(text("header_name"), text("header"))], body)
}

const WHATSAPP_FIXTURE: &str = include_str!("fixtures/inbound-auth-v1/whatsapp.json");
const WEBEX_FIXTURE: &str = include_str!("fixtures/inbound-auth-v1/webex.json");

#[tokio::test]
async fn a_correctly_signed_whatsapp_or_webex_request_is_verified() {
    for (provider_type, fixture, name) in [
        (
            "messaging.whatsapp.cloud",
            WHATSAPP_FIXTURE,
            "WHATSAPP_APP_SECRET",
        ),
        ("messaging.webex.bot", WEBEX_FIXTURE, "WEBEX_WEBHOOK_SECRET"),
    ] {
        let (store, headers, body) = signed(fixture, name);
        let (notices, said) = Notices::recording();
        let verdict = verify_with(
            inbound(provider_type, "POST", &headers, &body, DeploymentId::new()),
            &deps(&store, &notices),
        )
        .await
        .expect("admitted");
        assert_eq!(verdict, Verdict::Verified, "{provider_type}");
        assert!(said.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_bad_whatsapp_or_webex_signature_is_refused_before_any_dispatch() {
    for (provider_type, fixture, name) in [
        (
            "messaging.whatsapp.cloud",
            WHATSAPP_FIXTURE,
            "WHATSAPP_APP_SECRET",
        ),
        ("messaging.webex.bot", WEBEX_FIXTURE, "WEBEX_WEBHOOK_SECRET"),
    ] {
        let (store, headers, mut body) = signed(fixture, name);
        body[10] ^= 0x01;
        let (notices, said) = Notices::recording();
        let refused = verify_with(
            inbound(provider_type, "POST", &headers, &body, DeploymentId::new()),
            &deps(&store, &notices),
        )
        .await
        .expect_err("refused");
        assert_eq!(
            refused.status(),
            hyper::StatusCode::UNAUTHORIZED,
            "{provider_type}"
        );
        {
            // Scoped: the recording sink locks the same mutex.
            let said = said.lock().unwrap();
            assert!(
                said.iter().all(|line| !line.contains("test-")),
                "no secret in logs: {said:?}"
            );
        }
        // A missing header is refused too once a secret is configured.
        let refused = verify_with(
            inbound(provider_type, "POST", &[], &body, DeploymentId::new()),
            &deps(&store, &notices),
        )
        .await
        .expect_err("refused");
        assert_eq!(refused.status(), hyper::StatusCode::UNAUTHORIZED);
    }
}

fn teams_config() -> std::collections::BTreeMap<String, serde_json::Value> {
    std::collections::BTreeMap::from([(
        "ms_bot_app_id".to_string(),
        serde_json::json!("9f6b3c2e-1d4a-4b7f-8e2a-5c1d0e9f7a3b"),
    )])
}

fn unsigned_token(alg: &str) -> String {
    use base64::Engine;
    let b64 = |v: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    format!(
        "{}.{}.c2ln",
        b64(serde_json::json!({"alg": alg, "kid": "k"})),
        b64(serde_json::json!({"iss": "https://api.botframework.com"}))
    )
}

#[tokio::test]
async fn a_configured_teams_unit_without_a_key_set_is_admitted_unverified() {
    let secrets = empty_store();
    let config = teams_config();
    let headers = vec![(
        "authorization".to_string(),
        format!("Bearer {}", unsigned_token("RS256")),
    )];
    let (notices, said) = Notices::recording();
    let mut request = inbound(
        "messaging.teams",
        "POST",
        &headers,
        b"{}",
        DeploymentId::new(),
    );
    request.pack_non_secret = Some(&config);
    let verdict = verify_with(request, &deps(&secrets, &notices))
        .await
        .expect("an outage never refuses");
    assert_eq!(verdict, Verdict::Unavailable);
    assert_eq!(said.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_forged_teams_token_is_refused_once_the_app_id_is_set() {
    let secrets = empty_store();
    let config = teams_config();
    let (notices, _) = Notices::recording();
    for headers in [
        vec![],
        vec![(
            "authorization".to_string(),
            format!("Bearer {}", unsigned_token("none")),
        )],
        vec![(
            "authorization".to_string(),
            format!("Bearer {}", unsigned_token("HS256")),
        )],
    ] {
        let mut request = inbound(
            "messaging.teams",
            "POST",
            &headers,
            b"{}",
            DeploymentId::new(),
        );
        request.pack_non_secret = Some(&config);
        let refused = verify_with(request, &deps(&secrets, &notices))
            .await
            .expect_err("refused");
        assert_eq!(refused.status(), hyper::StatusCode::UNAUTHORIZED);
    }
}
