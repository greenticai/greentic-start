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
            // The store is shared across tenants/teams under one bundle; this
            // scheduler's runner is bound to a single context, so renewing a
            // foreign binding would invoke the provider with the wrong tenant
            // and rewrite the state under a different path.
            if !self.service.owns_state(&state) {
                continue;
            }
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
        let mut renewed = self.service.renew_once(&state.provider, &request)?;
        // A renew response does not echo the ensure-time inputs or always the
        // subscription id; keep what we already know so later renewals work.
        if renewed.notification_url.is_none() {
            renewed.notification_url = state.notification_url.clone();
        }
        if renewed.client_state.is_none() {
            renewed.client_state = state.client_state.clone();
        }
        if renewed.subscription_id.is_none() {
            renewed.subscription_id = state.subscription_id.clone();
        }
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
    let now = now_ms.max(0) as u64;
    // Never target a moment in the past: an already-expired binding extended
    // from its stale expiration would still be expired.
    let base = state
        .expiration_unix_ms
        .filter(|ms| *ms > 0)
        .map(|ms| ms as u64)
        .unwrap_or(now)
        .max(now);
    base.saturating_add(DEFAULT_RENEW_EXTENSION_MS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner_host::{FlowOutcome, OperatorContext, RunnerExecutionMode};
    use serde_json::json;
    use std::cell::RefCell;
    use tempfile::tempdir;

    struct FakeRunner {
        outcomes: RefCell<Vec<FlowOutcome>>,
    }

    impl FakeRunner {
        fn new(outcomes: Vec<FlowOutcome>) -> Self {
            Self {
                outcomes: RefCell::new(outcomes),
            }
        }
    }

    impl ProviderRunner for FakeRunner {
        fn invoke(
            &self,
            _provider: &str,
            _op: &str,
            _payload: &[u8],
            _context: &OperatorContext,
        ) -> anyhow::Result<FlowOutcome> {
            Ok(self.outcomes.borrow_mut().remove(0))
        }
    }

    fn test_context() -> OperatorContext {
        OperatorContext {
            tenant: "demo".to_string(),
            team: Some("ops".to_string()),
            correlation_id: None,
        }
    }

    fn success_outcome(output: serde_json::Value) -> FlowOutcome {
        FlowOutcome {
            success: true,
            output: Some(output),
            raw: None,
            error: None,
            mode: RunnerExecutionMode::Exec,
        }
    }

    fn sample_state(expiration_unix_ms: Option<i64>) -> SubscriptionState {
        SubscriptionState {
            binding_id: "binding-1".to_string(),
            provider: "messaging-graph".to_string(),
            tenant: "demo".to_string(),
            team: Some("ops".to_string()),
            resource: Some("/me/messages".to_string()),
            change_types: vec!["created".to_string()],
            notification_url: Some("https://example.test/hook".to_string()),
            client_state: Some("secret".to_string()),
            user: None,
            subscription_id: Some("sub-123".to_string()),
            expiration_unix_ms,
            last_error: None,
        }
    }

    #[test]
    fn next_expiration_target_uses_existing_future_or_now() {
        let state = sample_state(Some(1_000));
        assert!(next_expiration_target(&state) >= 1_000 + 86_400_000);

        let none_state = sample_state(None);
        assert!(next_expiration_target(&none_state) > 86_400_000);
    }

    #[test]
    fn ensure_once_and_delete_binding_roundtrip_store_state() {
        let dir = tempdir().expect("tempdir");
        let service = SubscriptionService::new(
            FakeRunner::new(vec![success_outcome(json!({
                "subscription_id": "sub-123",
                "expiration_unix_ms": 123456789i64
            }))]),
            test_context(),
        );
        let store = SubscriptionStore::new(dir.path());
        let scheduler = Scheduler::new(service, store.clone());

        scheduler
            .ensure_once(
                "messaging-graph",
                &SubscriptionEnsureRequest {
                    binding_id: "binding-1".to_string(),
                    resource: Some("/me/messages".to_string()),
                    change_types: vec!["created".to_string()],
                    notification_url: Some("https://example.test/hook".to_string()),
                    client_state: Some("secret".to_string()),
                    user: None,
                    expiration_target_unix_ms: None,
                },
            )
            .expect("ensure");

        let stored = store
            .read_state("messaging-graph", "demo", Some("ops"), "binding-1")
            .expect("read")
            .expect("state");
        assert_eq!(stored.subscription_id.as_deref(), Some("sub-123"));

        let delete_service = SubscriptionService::new(
            FakeRunner::new(vec![success_outcome(json!({}))]),
            test_context(),
        );
        let delete_scheduler = Scheduler::new(delete_service, store.clone());
        delete_scheduler.delete_binding(&stored).expect("delete");
        assert!(
            store
                .read_state("messaging-graph", "demo", Some("ops"), "binding-1")
                .expect("read after delete")
                .is_none()
        );
    }

    #[test]
    fn renew_due_updates_only_expired_bindings() {
        let dir = tempdir().expect("tempdir");
        let store = SubscriptionStore::new(dir.path());
        let due = sample_state(Some(Utc::now().timestamp_millis() - 1_000));
        let later = sample_state(Some(Utc::now().timestamp_millis() + 86_400_000));
        store.write_state(&due).expect("write due");
        let later_state = SubscriptionState {
            binding_id: "binding-2".to_string(),
            subscription_id: Some("sub-later".to_string()),
            ..later
        };
        store.write_state(&later_state).expect("write later");

        let service = SubscriptionService::new(
            FakeRunner::new(vec![success_outcome(json!({
                "subscription_id": "sub-renewed",
                "expiration_unix_ms": Utc::now().timestamp_millis() + 172_800_000
            }))]),
            test_context(),
        );
        let scheduler = Scheduler::new(service, store.clone());
        scheduler
            .renew_due(Duration::from_secs(0))
            .expect("renew due");

        let renewed = store
            .read_state("messaging-graph", "demo", Some("ops"), "binding-1")
            .expect("read renewed")
            .expect("renewed state");
        assert_eq!(renewed.subscription_id.as_deref(), Some("sub-renewed"));

        let untouched = store
            .read_state("messaging-graph", "demo", Some("ops"), "binding-2")
            .expect("read later")
            .expect("later state");
        assert_eq!(untouched.subscription_id.as_deref(), Some("sub-later"));
    }

    #[test]
    fn renew_due_skips_foreign_tenant_and_keeps_ensure_inputs() {
        let dir = tempdir().expect("tempdir");
        let store = SubscriptionStore::new(dir.path());
        let expired = Utc::now().timestamp_millis() - 1_000;
        let own = sample_state(Some(expired));
        let foreign = SubscriptionState {
            tenant: "other".to_string(),
            ..sample_state(Some(expired))
        };
        store.write_state(&own).expect("write own");
        store.write_state(&foreign).expect("write foreign");

        // Exactly one outcome: a second invocation would panic in FakeRunner.
        let service = SubscriptionService::new(
            FakeRunner::new(vec![success_outcome(json!({
                "subscription_id": "sub-renewed",
                "expiration_unix_ms": Utc::now().timestamp_millis() + 172_800_000
            }))]),
            test_context(),
        );
        let scheduler = Scheduler::new(service, store.clone());
        scheduler.renew_due(Duration::from_secs(0)).expect("renew");

        let renewed = store
            .read_state("messaging-graph", "demo", Some("ops"), "binding-1")
            .expect("read")
            .expect("state");
        assert_eq!(
            renewed.notification_url.as_deref(),
            Some("https://example.test/hook")
        );
        assert_eq!(renewed.client_state.as_deref(), Some("secret"));
        let untouched = store
            .read_state("messaging-graph", "other", Some("ops"), "binding-1")
            .expect("read")
            .expect("state");
        assert_eq!(untouched.subscription_id.as_deref(), Some("sub-123"));
    }

    #[test]
    fn next_expiration_target_never_in_the_past() {
        let state = sample_state(Some(1_000));
        assert!(next_expiration_target(&state) > Utc::now().timestamp_millis() as u64);
    }
}
