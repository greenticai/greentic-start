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
        let expected = if *code == RefusalCode::Endorsement {
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
