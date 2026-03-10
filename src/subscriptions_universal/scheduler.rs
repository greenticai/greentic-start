#![allow(dead_code)]

use std::time::Duration;

use anyhow::Result;
use chrono::Utc;

use crate::operator_log;
use crate::subscriptions_universal::service::{
    ProviderRunner, SubscriptionDeleteRequest, SubscriptionEnsureRequest, SubscriptionRenewRequest,
    SubscriptionService,
};
use crate::subscriptions_universal::store::{SubscriptionState, SubscriptionStore};

const DEFAULT_RENEW_EXTENSION_MS: u64 = 86_400_000;

pub struct Scheduler<R: ProviderRunner> {
    service: SubscriptionService<R>,
    store: SubscriptionStore,
}

impl<R: ProviderRunner> Scheduler<R> {
    pub fn new(service: SubscriptionService<R>, store: SubscriptionStore) -> Self {
        Self { service, store }
    }

    pub fn ensure_once(&self, provider: &str, request: &SubscriptionEnsureRequest) -> Result<()> {
        let state = self.service.ensure_once(provider, request)?;
        self.store.write_state(&state)
    }

    pub fn renew_due(&self, skew: Duration) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let skew_ms = skew.as_millis() as i64;
        let states = self.store.list_states()?;
        for state in states {
            if let Some(expiration) = state.expiration_unix_ms {
                let renew_at = expiration.saturating_sub(skew_ms);
                if now >= renew_at
                    && let Err(err) = self.renew_binding(&state)
                {
                    operator_log::error(
                        module_path!(),
                        format!(
                            "subscription renew failed binding={} provider={} err={}",
                            state.binding_id, state.provider, err
                        ),
                    );
                }
            }
        }
        Ok(())
    }

    pub fn renew_binding(&self, state: &SubscriptionState) -> Result<()> {
        let request = SubscriptionRenewRequest {
            binding_id: state.binding_id.clone(),
            subscription_id: state.subscription_id.clone(),
            user: state.user.clone(),
            resource: state.resource.clone(),
            change_types: state.change_types.clone(),
            expiration_target_unix_ms: Some(next_expiration_target(state)),
        };
        let renewed = self.service.renew_once(&state.provider, &request)?;
        self.store.write_state(&renewed)
    }

    pub fn delete_binding(&self, state: &SubscriptionState) -> Result<()> {
        let request = SubscriptionDeleteRequest {
            binding_id: state.binding_id.clone(),
            subscription_id: state.subscription_id.clone(),
            user: state.user.clone(),
        };
        self.service.delete_once(&state.provider, &request)?;
        self.store.delete_state(state)
    }
}

fn next_expiration_target(state: &SubscriptionState) -> u64 {
    let now_ms = Utc::now().timestamp_millis();
    let base = state
        .expiration_unix_ms
        .filter(|ms| *ms > 0)
        .map(|ms| ms as u64)
        .unwrap_or_else(|| now_ms as u64);
    base + DEFAULT_RENEW_EXTENSION_MS
}
