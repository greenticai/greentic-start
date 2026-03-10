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
            &request.change_types,
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
