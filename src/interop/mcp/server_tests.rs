//! The `ask` tool's own metering (worker-interop contract §8).
//!
//! The A2A binding's tests cover the shared event shape end to end against a
//! stub admin; what is specific here is WHO an MCP caller is. The same tool
//! serves a staged bearer and an OAuth token, and only the first names a
//! credential the designer issued.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{AskArgs, McpContext, WorkerMcpServer};
use crate::interop::a2a::rpc::{TurnFailure, TurnRunner};
use crate::interop::config::InteropConfig;
use crate::interop::limits::{DEFAULT_MAX_CONCURRENT_TURNS, RateLimiter, TurnGate};
use crate::interop::metering::testkit::{StubAdmin, unreachable_metering};
use crate::interop::metering::{Meter, TurnMetering};
use greentic_deploy_spec::ids::DeploymentId;
use greentic_runner_host::Activity;
use rmcp::handler::server::wrapper::Parameters;

struct FakeRunner {
    replies: Vec<Activity>,
}

#[async_trait::async_trait]
impl TurnRunner for FakeRunner {
    async fn run(
        &self,
        _session_hint: &str,
        _user: &str,
        _payload: &Value,
    ) -> Result<Vec<Activity>, TurnFailure> {
        Ok(self.replies.clone())
    }
}

fn dw_agent_reply(text: &str) -> Activity {
    Activity::custom(
        "response",
        json!({
            "reply": text,
            "trail": [],
            "terminated_by": "final",
            "usage": {"tokens_in": 64, "tokens_out": 16, "iterations": 1},
        }),
    )
}

fn config_with(metering: crate::interop::metering::MeteringConfig) -> InteropConfig {
    InteropConfig {
        mcp: true,
        tenant_slug: Some("acme".into()),
        metering: Some(metering),
        ..InteropConfig::default()
    }
}

/// The tenant every staged fixture records against — the one the metering
/// config carries, which is what reaches the wire.
const TENANT: &str = crate::interop::metering::testkit::TEST_TENANT;

fn server(
    meter: &Arc<Meter>,
    config: &InteropConfig,
    caller_key: &str,
    credential_id: Option<&str>,
) -> WorkerMcpServer {
    let deployment_id = DeploymentId::new();
    WorkerMcpServer::new(Arc::new(McpContext {
        runner: Arc::new(FakeRunner {
            replies: vec![dw_agent_reply("the answer")],
        }),
        turns: Arc::new(TurnGate::new(DEFAULT_MAX_CONCURRENT_TURNS)),
        limiter: Arc::new(RateLimiter::default()),
        prepaid: 0.0,
        deployment_id,
        tenant: "default".into(),
        bundle_id: "support-bot".into(),
        caller_key: caller_key.into(),
        credential_id: credential_id.map(str::to_string),
        metering: TurnMetering::for_unit(meter, config, deployment_id, "support-bot"),
        agent_name: "Support Bot".into(),
    }))
}

async fn ask(server: &WorkerMcpServer, message: &str) -> rmcp::model::CallToolResult {
    server
        .ask(Parameters(AskArgs {
            message: message.into(),
            conversation_id: None,
        }))
        .await
        .expect("the tool answers")
}

/// The whole feature on the MCP binding: the stub admin receives the usage
/// POST **while the caller still gets its answer**.
#[tokio::test]
async fn an_ask_records_usage_while_the_caller_still_gets_its_reply() {
    let stub = StubAdmin::accepting().await;
    let meter = Arc::new(Meter::default());
    let config = config_with(stub.metering());
    let result = ask(
        &server(&meter, &config, "c_01J", Some("c_01J")),
        "how long do refunds take?",
    )
    .await;
    assert_ne!(result.is_error, Some(true), "the turn succeeded");

    assert_eq!(
        stub.wait_for(1).await,
        1,
        "no usage event reached the admin"
    );
    let event = stub.last_body();
    assert_eq!(event["surface"], "mcp");
    assert_eq!(event["tokens_in"], 64);
    assert_eq!(event["credential_id"], "c_01J");
    assert_eq!(event["tenant_slug"], TENANT);
    let wire = event.to_string();
    assert!(!wire.contains("refunds"), "{wire}");
    assert!(!wire.contains("the answer"), "{wire}");
}

/// An OAuth caller's `sub` is minted by the authorization server and is not a
/// credential the designer staged, so the event names none — which is exactly
/// why the admin made the field optional.
#[tokio::test]
async fn an_oauth_caller_names_no_credential() {
    let meter = Arc::new(Meter::inspectable());
    let config = config_with(unreachable_metering());
    let _ = ask(&server(&meter, &config, "u-oauth-sub", None), "hello").await;
    let queued = meter.drain();
    assert_eq!(queued.len(), 1);
    assert!(queued[0].event.credential_id.is_none());
    assert_eq!(queued[0].event.surface, "mcp");
}

#[tokio::test]
async fn a_unit_with_no_metering_block_emits_nothing() {
    let meter = Arc::new(Meter::inspectable());
    let config = InteropConfig {
        mcp: true,
        ..InteropConfig::default()
    };
    let _ = ask(&server(&meter, &config, "c_01J", Some("c_01J")), "hello").await;
    assert!(meter.drain().is_empty());
}

/// An `ask` refused before the turn ran spent nothing.
#[tokio::test]
async fn an_empty_message_is_refused_and_records_nothing() {
    let meter = Arc::new(Meter::inspectable());
    let config = config_with(unreachable_metering());
    let refused = server(&meter, &config, "c_01J", Some("c_01J"))
        .ask(Parameters(AskArgs {
            message: "   ".into(),
            conversation_id: None,
        }))
        .await;
    assert!(refused.is_err());
    assert!(meter.drain().is_empty());
}
