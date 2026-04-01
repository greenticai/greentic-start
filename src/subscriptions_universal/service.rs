#![allow(dead_code)]

use anyhow::{Result, anyhow};
use greentic_types::messaging::universal_dto::{
    AuthUserRefV1, SubscriptionDeleteInV1, SubscriptionEnsureInV1, SubscriptionRenewInV1,
};
use serde_json::to_vec;

use crate::domains::Domain;
use crate::runner_host::{DemoRunnerHost, FlowOutcome, OperatorContext};
use crate::subscriptions_universal::store::SubscriptionState;

pub trait ProviderRunner {
    fn invoke(
        &self,
        provider: &str,
        op: &str,
        payload: &[u8],
        context: &OperatorContext,
    ) -> Result<FlowOutcome>;
}

impl ProviderRunner for DemoRunnerHost {
    fn invoke(
        &self,
        provider: &str,
        op: &str,
        payload: &[u8],
        context: &OperatorContext,
    ) -> Result<FlowOutcome> {
        self.invoke_provider_op(Domain::Messaging, provider, op, payload, context)
    }
}

#[derive(Clone, Debug)]
pub struct SubscriptionEnsureRequest {
    pub binding_id: String,
    pub resource: Option<String>,
    pub change_types: Vec<String>,
    pub notification_url: Option<String>,
    pub client_state: Option<String>,
    pub user: Option<AuthUserRefV1>,
    pub expiration_target_unix_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct SubscriptionRenewRequest {
    pub binding_id: String,
    pub subscription_id: Option<String>,
    pub user: Option<AuthUserRefV1>,
    pub resource: Option<String>,
    pub change_types: Vec<String>,
    pub expiration_target_unix_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct SubscriptionDeleteRequest {
    pub binding_id: String,
    pub subscription_id: Option<String>,
    pub user: Option<AuthUserRefV1>,
}

pub struct SubscriptionService<R: ProviderRunner> {
    runner_host: R,
    context: OperatorContext,
}

impl<R: ProviderRunner> SubscriptionService<R> {
    pub fn new(runner_host: R, context: OperatorContext) -> Self {
        Self {
            runner_host,
            context,
        }
    }

    pub fn ensure_once(
        &self,
        provider: &str,
        request: &SubscriptionEnsureRequest,
    ) -> Result<SubscriptionState> {
        let dto = self.build_ensure_payload(provider, request)?;
        let payload = to_vec(&dto)?;
        let outcome =
            self.runner_host
                .invoke(provider, "subscription_ensure", &payload, &self.context)?;
        let outcome = Self::ensure_success(outcome)?;
        let state = SubscriptionState::from_provider_result(
            provider,
            &self.context.tenant,
            self.context.team.clone(),
            &request.binding_id,
            request.resource.as_ref(),
            &dto.change_types,
            request.notification_url.as_ref(),
            request.client_state.as_ref(),
            request.user.as_ref(),
            outcome.output.as_ref(),
        );
        Ok(state)
    }

    pub fn renew_once(
        &self,
        provider: &str,
        request: &SubscriptionRenewRequest,
    ) -> Result<SubscriptionState> {
        let dto = self.build_renew_payload(provider, request)?;
        let payload = to_vec(&dto)?;
        let outcome =
            self.runner_host
                .invoke(provider, "subscription_renew", &payload, &self.context)?;
        let outcome = Self::ensure_success(outcome)?;
        let state = SubscriptionState::from_provider_result(
            provider,
            &self.context.tenant,
            self.context.team.clone(),
            &request.binding_id,
            request.resource.as_ref(),
            &request.change_types,
            None,
            None,
            request.user.as_ref(),
            outcome.output.as_ref(),
        );
        Ok(state)
    }

    pub fn delete_once(&self, provider: &str, request: &SubscriptionDeleteRequest) -> Result<()> {
        let dto = self.build_delete_payload(provider, request)?;
        let payload = to_vec(&dto)?;
        let outcome =
            self.runner_host
                .invoke(provider, "subscription_delete", &payload, &self.context)?;
        let _ = Self::ensure_success(outcome)?;
        Ok(())
    }

    fn build_ensure_payload(
        &self,
        provider: &str,
        request: &SubscriptionEnsureRequest,
    ) -> Result<SubscriptionEnsureInV1> {
        let resource = request
            .resource
            .as_ref()
            .ok_or_else(|| anyhow!("resource is required for subscription ensure"))?;
        let notification_url = request
            .notification_url
            .as_ref()
            .ok_or_else(|| anyhow!("notification_url is required for subscription ensure"))?;
        let change_types = if request.change_types.is_empty() {
            vec!["created".to_string()]
        } else {
            request.change_types.clone()
        };
        Ok(SubscriptionEnsureInV1 {
            v: 1,
            provider: provider.to_string(),
            tenant_hint: Some(self.context.tenant.clone()),
            team_hint: self.context.team.clone(),
            binding_id: Some(request.binding_id.clone()),
            resource: resource.clone(),
            change_types,
            notification_url: notification_url.clone(),
            expiration_minutes: None,
            expiration_target_unix_ms: request.expiration_target_unix_ms,
            client_state: request.client_state.clone(),
            metadata: None,
            user: request
                .user
                .clone()
                .unwrap_or_else(|| self.default_user_ref()),
        })
    }

    fn build_renew_payload(
        &self,
        provider: &str,
        request: &SubscriptionRenewRequest,
    ) -> Result<SubscriptionRenewInV1> {
        let subscription_id = request
            .subscription_id
            .clone()
            .ok_or_else(|| anyhow!("subscription_id is required to renew a binding"))?;
        Ok(SubscriptionRenewInV1 {
            v: 1,
            provider: provider.to_string(),
            subscription_id,
            expiration_minutes: None,
            expiration_target_unix_ms: request.expiration_target_unix_ms,
            metadata: None,
            user: request
                .user
                .clone()
                .unwrap_or_else(|| self.default_user_ref()),
        })
    }

    fn build_delete_payload(
        &self,
        provider: &str,
        request: &SubscriptionDeleteRequest,
    ) -> Result<SubscriptionDeleteInV1> {
        let subscription_id = request
            .subscription_id
            .clone()
            .ok_or_else(|| anyhow!("subscription_id is required to delete a binding"))?;
        Ok(SubscriptionDeleteInV1 {
            v: 1,
            provider: provider.to_string(),
            subscription_id,
            user: request
                .user
                .clone()
                .unwrap_or_else(|| self.default_user_ref()),
        })
    }

    fn ensure_success(outcome: FlowOutcome) -> Result<FlowOutcome> {
        if outcome.success {
            Ok(outcome)
        } else {
            let error = outcome
                .error
                .unwrap_or_else(|| "provider returned failure".to_string());
            Err(anyhow!("{error}"))
        }
    }

    fn default_user_ref(&self) -> AuthUserRefV1 {
        let team_hint = self
            .context
            .team
            .clone()
            .unwrap_or_else(|| "default".to_string());
        AuthUserRefV1 {
            user_id: format!("{}-{}", self.context.tenant, team_hint),
            token_key: format!("operator-{}", team_hint),
            tenant_id: Some(self.context.tenant.clone()),
            email: None,
            display_name: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner_host::RunnerExecutionMode;
    use serde_json::json;
    use std::cell::RefCell;

    #[derive(Clone, Debug)]
    struct CallRecord {
        provider: String,
        op: String,
        payload: serde_json::Value,
    }

    struct FakeRunner {
        outcome: RefCell<Option<FlowOutcome>>,
        calls: RefCell<Vec<CallRecord>>,
    }

    impl FakeRunner {
        fn new(outcome: FlowOutcome) -> Self {
            Self {
                outcome: RefCell::new(Some(outcome)),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl ProviderRunner for FakeRunner {
        fn invoke(
            &self,
            provider: &str,
            op: &str,
            payload: &[u8],
            _context: &OperatorContext,
        ) -> Result<FlowOutcome> {
            self.calls.borrow_mut().push(CallRecord {
                provider: provider.to_string(),
                op: op.to_string(),
                payload: serde_json::from_slice(payload).expect("json payload"),
            });
            Ok(self
                .outcome
                .borrow_mut()
                .take()
                .expect("runner outcome available"))
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

    #[test]
    fn build_ensure_payload_defaults_change_types_and_user() {
        let service =
            SubscriptionService::new(FakeRunner::new(success_outcome(json!({}))), test_context());
        let dto = service
            .build_ensure_payload(
                "messaging-graph",
                &SubscriptionEnsureRequest {
                    binding_id: "binding-1".to_string(),
                    resource: Some("/me/messages".to_string()),
                    change_types: Vec::new(),
                    notification_url: Some("https://example.test/hook".to_string()),
                    client_state: None,
                    user: None,
                    expiration_target_unix_ms: Some(42),
                },
            )
            .expect("payload");

        assert_eq!(dto.change_types, vec!["created".to_string()]);
        assert_eq!(dto.user.user_id, "demo-ops");
        assert_eq!(dto.user.token_key, "operator-ops");
        assert_eq!(dto.expiration_target_unix_ms, Some(42));
    }

    #[test]
    fn build_payloads_require_resource_and_subscription_id() {
        let service =
            SubscriptionService::new(FakeRunner::new(success_outcome(json!({}))), test_context());

        let ensure_err = service
            .build_ensure_payload(
                "messaging-graph",
                &SubscriptionEnsureRequest {
                    binding_id: "binding-1".to_string(),
                    resource: None,
                    change_types: Vec::new(),
                    notification_url: Some("https://example.test/hook".to_string()),
                    client_state: None,
                    user: None,
                    expiration_target_unix_ms: None,
                },
            )
            .unwrap_err();
        assert!(ensure_err.to_string().contains("resource is required"));

        let renew_err = service
            .build_renew_payload(
                "messaging-graph",
                &SubscriptionRenewRequest {
                    binding_id: "binding-1".to_string(),
                    subscription_id: None,
                    user: None,
                    resource: None,
                    change_types: Vec::new(),
                    expiration_target_unix_ms: None,
                },
            )
            .unwrap_err();
        assert!(
            renew_err
                .to_string()
                .contains("subscription_id is required")
        );

        let delete_err = service
            .build_delete_payload(
                "messaging-graph",
                &SubscriptionDeleteRequest {
                    binding_id: "binding-1".to_string(),
                    subscription_id: None,
                    user: None,
                },
            )
            .unwrap_err();
        assert!(
            delete_err
                .to_string()
                .contains("subscription_id is required")
        );
    }

    #[test]
    fn ensure_once_invokes_runner_and_builds_subscription_state() {
        let runner = FakeRunner::new(success_outcome(json!({
            "subscription": {
                "subscription_id": "sub-123",
                "expiration_unix_ms": 123456789i64
            }
        })));
        let service = SubscriptionService::new(runner, test_context());
        let request = SubscriptionEnsureRequest {
            binding_id: "binding-1".to_string(),
            resource: Some("/me/messages".to_string()),
            change_types: Vec::new(),
            notification_url: Some("https://example.test/hook".to_string()),
            client_state: Some("secret".to_string()),
            user: None,
            expiration_target_unix_ms: None,
        };

        let state = service
            .ensure_once("messaging-graph", &request)
            .expect("state");
        assert_eq!(state.subscription_id.as_deref(), Some("sub-123"));
        assert_eq!(state.change_types, vec!["created".to_string()]);

        let calls = service.runner_host.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].provider, "messaging-graph");
        assert_eq!(calls[0].op, "subscription_ensure");
        assert_eq!(calls[0].payload["resource"], "/me/messages");
    }

    #[test]
    fn renew_delete_and_failure_paths_use_runner_outputs() {
        let renew_runner = FakeRunner::new(success_outcome(json!({
            "subscription_id": "sub-456",
            "expiration_unix_ms": 987654321i64
        })));
        let renew_service = SubscriptionService::new(renew_runner, test_context());
        let renewed = renew_service
            .renew_once(
                "messaging-graph",
                &SubscriptionRenewRequest {
                    binding_id: "binding-1".to_string(),
                    subscription_id: Some("sub-123".to_string()),
                    user: None,
                    resource: Some("/me/messages".to_string()),
                    change_types: vec!["updated".to_string()],
                    expiration_target_unix_ms: Some(77),
                },
            )
            .expect("renewed");
        assert_eq!(renewed.subscription_id.as_deref(), Some("sub-456"));

        let delete_runner = FakeRunner::new(success_outcome(json!({})));
        let delete_service = SubscriptionService::new(delete_runner, test_context());
        delete_service
            .delete_once(
                "messaging-graph",
                &SubscriptionDeleteRequest {
                    binding_id: "binding-1".to_string(),
                    subscription_id: Some("sub-123".to_string()),
                    user: None,
                },
            )
            .expect("delete");
        assert_eq!(
            delete_service.runner_host.calls.borrow()[0].op,
            "subscription_delete"
        );

        let err = match SubscriptionService::<FakeRunner>::ensure_success(FlowOutcome {
            success: false,
            output: None,
            raw: None,
            error: Some("provider boom".to_string()),
            mode: RunnerExecutionMode::Exec,
        }) {
            Ok(_) => panic!("expected provider failure"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("provider boom"));
    }
}
