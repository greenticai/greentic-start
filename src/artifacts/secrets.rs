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
            // A failed read, an empty value or one that is not text is
            // treated as absent and the next candidate (the canonical one
            // last) is tried; the read's error text can name the store, so it
            // is not logged here.
            let Ok(bytes) = self.manager.read(&uri).await else {
                continue;
            };
            let Ok(value) = String::from_utf8(bytes) else {
                continue;
            };
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        None
    }
}
