//! Each channel reads ONLY its own verification secret: a Webex route never
//! reads WhatsApp's app secret (or the reverse), and no other provider type
//! reads either.

use std::sync::{Arc, Mutex};

use greentic_deploy_spec::DeploymentId;
use greentic_secrets_lib::{SecretError, SecretsManager};

use super::mod_tests::{deps, inbound};
use super::notices::Notices;
use super::verify_with;
use crate::secrets_gate::DynSecretsManager;

#[derive(Default)]
struct Recording(Mutex<Vec<String>>);

#[async_trait::async_trait]
impl SecretsManager for Recording {
    async fn read(&self, path: &str) -> greentic_secrets_lib::Result<Vec<u8>> {
        self.0.lock().unwrap().push(path.to_ascii_lowercase());
        Err(SecretError::NotFound(path.to_string()))
    }
    async fn write(&self, _: &str, _: &[u8]) -> greentic_secrets_lib::Result<()> {
        Ok(())
    }
    async fn delete(&self, _: &str) -> greentic_secrets_lib::Result<()> {
        Ok(())
    }
}

async fn reads_for(provider_type: &str) -> Vec<String> {
    let store = Arc::new(Recording::default());
    let manager: DynSecretsManager = store.clone();
    let (notices, _) = Notices::recording();
    let _ = verify_with(
        inbound(provider_type, "POST", &[], b"{}", DeploymentId::new()),
        &deps(&manager, &notices),
    )
    .await;
    store.0.lock().unwrap().clone()
}

#[tokio::test]
async fn webex_routes_read_only_the_webex_secret() {
    for provider_type in ["messaging.webex.bot", "messaging.webex"] {
        let reads = reads_for(provider_type).await;
        assert!(!reads.is_empty(), "{provider_type} read nothing");
        assert!(
            reads
                .iter()
                .all(|uri| uri.ends_with("webex_webhook_secret")),
            "{provider_type}: {reads:?}"
        );
    }
}

#[tokio::test]
async fn whatsapp_routes_read_only_the_whatsapp_secret() {
    for provider_type in ["messaging.whatsapp", "messaging.whatsapp.cloud"] {
        let reads = reads_for(provider_type).await;
        assert!(!reads.is_empty(), "{provider_type} read nothing");
        assert!(
            reads.iter().all(|uri| uri.ends_with("whatsapp_app_secret")),
            "{provider_type}: {reads:?}"
        );
    }
}

#[tokio::test]
async fn no_other_route_reads_a_verification_secret() {
    for provider_type in [
        "messaging.teams",
        "messaging.slack.api",
        "messaging.telegram.bot",
        "messaging.webchat-gui",
        "messaging.email.smtp",
        "events.webhook",
    ] {
        assert!(reads_for(provider_type).await.is_empty(), "{provider_type}");
    }
}
