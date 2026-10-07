//! Resolves a credential NAME (`SLACK_BOT_TOKEN`, …) the way the provider's
//! own config is read on the revision path
//! ([`crate::runner_host::secret_read_uris`]), in the scope of the pack that
//! received the request. The value never enters an envelope or a log.

use std::sync::Arc;

use async_trait::async_trait;
use greentic_secrets_lib::SecretsManager;

use super::fetch::SecretLookup;
use super::origin::SecretScope;

pub(crate) struct HostSecrets {
    manager: Arc<dyn SecretsManager>,
    env: String,
}

impl HostSecrets {
    pub(crate) fn new(manager: Arc<dyn SecretsManager>, env: String) -> Self {
        Self { manager, env }
    }
}

#[async_trait]
impl SecretLookup for HostSecrets {
    async fn get(&self, scope: &SecretScope, name: &str) -> Option<String> {
        let uris = crate::runner_host::secret_read_uris(
            &self.env,
            &scope.tenant,
            scope.team.as_deref(),
            &scope.pack_id,
            name,
        );
        for uri in uris {
            // A failed read is treated as absent; its text can name the
            // store, so it is not logged here.
            if let Ok(bytes) = self.manager.read(&uri).await {
                let value = String::from_utf8(bytes).ok()?;
                let value = value.trim();
                return (!value.is_empty()).then(|| value.to_string());
            }
        }
        None
    }
}
