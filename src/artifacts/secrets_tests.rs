use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::fetch::SecretLookup;
use super::origin::SecretScope;
use super::secrets::HostSecrets;

#[derive(Default)]
struct MapSecrets {
    values: HashMap<String, Vec<u8>>,
    asked: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl greentic_secrets_lib::SecretsManager for MapSecrets {
    async fn read(&self, path: &str) -> greentic_secrets_lib::Result<Vec<u8>> {
        self.asked.lock().unwrap().push(path.to_string());
        self.values
            .get(path)
            .cloned()
            .ok_or_else(|| greentic_secrets_lib::SecretError::NotFound(path.to_string()))
    }
    async fn write(&self, _: &str, _: &[u8]) -> greentic_secrets_lib::Result<()> {
        Ok(())
    }
    async fn delete(&self, _: &str) -> greentic_secrets_lib::Result<()> {
        Ok(())
    }
}

fn scope(pack: &str) -> SecretScope {
    SecretScope {
        tenant: "acme".into(),
        team: Some("ops".into()),
        pack_id: pack.into(),
    }
}

#[tokio::test]
async fn a_secret_is_read_where_the_provider_reads_it() {
    // The same candidates the provider's own config read uses.
    let uris = crate::runner_host::secret_read_uris(
        "dev",
        "acme",
        Some("ops"),
        "messaging-provider-slack",
        "SLACK_BOT_TOKEN",
    );
    let stored = uris.last().unwrap().clone();
    let manager = Arc::new(MapSecrets {
        values: HashMap::from([(stored, b" xoxb-1\n".to_vec())]),
        ..Default::default()
    });
    let lookup = HostSecrets::new(manager.clone(), "dev".into());
    assert_eq!(
        lookup
            .get(&scope("messaging-provider-slack"), "SLACK_BOT_TOKEN")
            .await
            .as_deref(),
        Some("xoxb-1")
    );
    // Another pack's scope never reaches that secret.
    assert_eq!(
        lookup
            .get(&scope("messaging-provider-webex"), "SLACK_BOT_TOKEN")
            .await,
        None
    );
    assert!(
        manager
            .asked
            .lock()
            .unwrap()
            .iter()
            .all(|uri| uri.starts_with("secrets://dev/acme/ops/")),
        "a read left the unit's own tenant and team"
    );
}

#[tokio::test]
async fn a_missing_or_unreadable_secret_is_none() {
    let manager = Arc::new(MapSecrets::default());
    let lookup = HostSecrets::new(manager, "dev".into());
    assert_eq!(lookup.get(&scope("p"), "WEBEX_BOT_TOKEN").await, None);
}
