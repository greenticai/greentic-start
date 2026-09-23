//! The `rmcp` service behind `POST /mcp`, its one tool, and the transport
//! configuration that makes it correct for a public, multi-instance
//! deployment.
//!
//! The three settings in [`service`] all differ from `rmcp`'s defaults, and
//! two of those defaults fail silently rather than loudly here — so each
//! carries its reasoning rather than a bare value. They are the same three
//! greentic-designer's own MCP surface sets, for the same reasons.

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerInfo};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, ServerHandler, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::interop::a2a::rpc::TurnRunner;
use crate::interop::limits::TurnGate;
use crate::interop::reply::{ReplyItem, project_replies};
use greentic_deploy_spec::ids::DeploymentId;

/// Longest `conversation_id` accepted; it becomes part of a session key.
const MAX_CONVERSATION_ID_LEN: usize = 256;

/// Everything one authenticated caller's tools may reach.
///
/// Built per request in [`crate::revision_serve`] and captured by the service
/// factory, so the caller is baked into the handler rather than read back out
/// of an `rmcp` request extension. That is the whole reason this surface needs
/// no `caller()` helper: a service instance serves exactly one authenticated
/// request.
pub(crate) struct McpContext {
    pub runner: Arc<dyn TurnRunner>,
    pub turns: Arc<TurnGate>,
    pub deployment_id: DeploymentId,
    pub tenant: String,
    pub bundle_id: String,
    /// The OAuth `sub` or the staged credential id — the conversation
    /// namespace, so two callers cannot resume each other's parked flow.
    pub caller_key: String,
    /// What the worker calls itself, for the server's `instructions`.
    pub agent_name: String,
}

/// The MCP service. Cloned per request by the factory in [`service`].
#[derive(Clone)]
pub(crate) struct WorkerMcpServer {
    ctx: Arc<McpContext>,
    tool_router: ToolRouter<Self>,
}

impl WorkerMcpServer {
    pub(crate) fn new(ctx: Arc<McpContext>) -> Self {
        Self {
            ctx,
            tool_router: Self::tool_router_ask(),
        }
    }
}

/// `ask`'s arguments. Exactly the two the contract names: everything else a
/// turn needs is a property of the deployment, not of the call.
#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(crate) struct AskArgs {
    /// What to say to the worker.
    pub message: String,
    /// The conversation to continue. Omit it to start one; the id is returned
    /// so the next call can pass it back.
    #[serde(default)]
    pub conversation_id: Option<String>,
}

#[tool_router(router = tool_router_ask, vis = "pub(crate)")]
impl WorkerMcpServer {
    /// Send one message to the worker and return its reply.
    ///
    /// ONE tool, deliberately. The worker's own bound tools are NOT exposed:
    /// they are the worker's private means, an MCP client has no business
    /// driving them directly, and re-publishing them would let a caller run a
    /// tool the worker's instructions and guardrails never chose to run.
    #[tool(
        name = "ask",
        description = "Ask this Greentic worker a question, or continue a conversation with it. Returns the worker's reply."
    )]
    pub(crate) async fn ask(
        &self,
        Parameters(args): Parameters<AskArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let message = args.message.trim();
        if message.is_empty() {
            return Err(ErrorData::invalid_params(
                "`message` must not be empty",
                None,
            ));
        }
        let conversation_id = match args.conversation_id.as_deref().map(str::trim) {
            Some(id) if !id.is_empty() => {
                if id.len() > MAX_CONVERSATION_ID_LEN || id.chars().any(char::is_control) {
                    return Err(ErrorData::invalid_params("invalid `conversation_id`", None));
                }
                id.to_string()
            }
            _ => ulid::Ulid::new().to_string(),
        };
        let session_hint = format!("mcp:{}:{conversation_id}", self.ctx.caller_key);
        let user = format!("mcp:{}", self.ctx.caller_key);

        // The cap is per deployment and nothing queues: an MCP caller holds
        // its connection open for the whole turn, so a queue would convert a
        // burst into a pile of timeouts.
        let Some(_permit) = self.ctx.turns.try_acquire(self.ctx.deployment_id) else {
            return Ok(busy(&conversation_id));
        };

        let payload = json!({ "text": message });
        let Ok(replies) = self.ctx.runner.run(&session_hint, &user, &payload).await else {
            // A tool-level error, not a protocol error: the request was valid
            // and reached the worker; the TURN is what failed.
            return Ok(failed(
                &conversation_id,
                "the worker could not answer this turn",
            ));
        };

        let projected = project_replies(
            &replies,
            "mcp",
            &self.ctx.tenant,
            &self.ctx.bundle_id,
            &session_hint,
        );
        let mut texts: Vec<String> = Vec::new();
        let mut cards: Vec<Value> = Vec::new();
        for item in projected.items {
            match item {
                ReplyItem::Text(text) => texts.push(text),
                ReplyItem::Card { card, fallback } => {
                    // The fallback is pushed as TEXT as well as the card being
                    // returned structurally: an MCP client renders the text
                    // content, and a caller that ignores `structuredContent`
                    // must still read something.
                    texts.push(fallback);
                    cards.push(card);
                }
            }
        }
        let mut structured = json!({ "conversation_id": conversation_id });
        if !cards.is_empty()
            && let Value::Object(map) = &mut structured
        {
            map.insert("cards".to_string(), Value::Array(cards));
        }
        // Additive, and not in the contract's shape: a parked flow is the one
        // thing a caller cannot infer from the text, and the next `ask` with
        // this `conversation_id` is what resumes it.
        if projected.awaiting_input
            && let Value::Object(map) = &mut structured
        {
            map.insert("awaiting_input".to_string(), Value::Bool(true));
        }

        let content = if texts.is_empty() {
            Vec::new()
        } else {
            vec![ContentBlock::text(texts.join("\n\n"))]
        };
        let mut result = if projected.flow_error {
            // The flow ran and ended at a failure. `isError` is how an MCP
            // client knows the answer is not an answer — without it the
            // categorized error text reads as the worker's reply.
            CallToolResult::error(content)
        } else {
            CallToolResult::success(content)
        };
        result.structured_content = Some(structured);
        Ok(result)
    }
}

/// A tool-level error carrying the conversation id, so a caller can retry the
/// same conversation.
fn failed(conversation_id: &str, message: &str) -> CallToolResult {
    let mut result = CallToolResult::error(vec![ContentBlock::text(message.to_string())]);
    result.structured_content = Some(json!({ "conversation_id": conversation_id }));
    result
}

fn busy(conversation_id: &str) -> CallToolResult {
    failed(
        conversation_id,
        "this worker is running as many turns as it can at once; retry shortly",
    )
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for WorkerMcpServer {
    fn get_info(&self) -> ServerInfo {
        // Built through the constructors rather than a struct literal: both
        // types are `#[non_exhaustive]`, so a literal would not compile — and
        // that is the point, since a field added upstream must not silently
        // acquire this crate's `Default`.
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "greentic-worker",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(format!(
                "Talk to {}, a Greentic worker. Use `ask` to send a message; pass the \
                 `conversation_id` it returns to continue the same conversation.",
                self.ctx.agent_name
            ))
    }
}

/// The `rmcp` transport for `POST /mcp`.
///
/// # Two `rmcp` defaults deliberately KEPT
///
/// **`stateless_protocol_metadata_required` stays `false`.** Setting it would
/// refuse the ordinary (non-`initialize`) requests of any client negotiated
/// below `2026-07-28`, which today is most of them — `rmcp` 3.1.4 shipped one
/// day before that revision was written. Statelessness does not depend on it:
/// `legacy_session_mode(false)` plus [`NeverSessionManager`] guarantee that
/// independently.
///
/// **`allowed_origins` stays empty, so `Origin` validation is OFF.** What
/// makes that safe is a property of this surface rather than of this line: the
/// only credential accepted is a bearer token in `Authorization` (see
/// [`super::auth`]), and `/mcp` is excluded from CORS
/// (`crate::interop::mcp::is_cors_excluded`), so a browser cannot present a
/// usable credential cross-origin — the preflight for `Authorization` never
/// succeeds. ⚠️ Serving CORS on this path would make both this knob and
/// `allowed_hosts` load-bearing, and they would have to be set in the same
/// change.
pub(crate) fn service(
    ctx: Arc<McpContext>,
) -> StreamableHttpService<WorkerMcpServer, NeverSessionManager> {
    let config = StreamableHttpServerConfig::default()
        // ⚠️ `legacy_session_mode` DEFAULTS TO TRUE, and the default is wrong
        // for this deployment in a way that cannot reproduce on one instance.
        // The contract picks the stateless MCP core precisely so `/mcp` runs
        // unchanged across many Cloud Run instances: no sticky sessions, no
        // shared store. Left true, a client negotiating an OLDER revision
        // still gets a session — held in this process only — and its next
        // request lands on another instance, which answers
        // `404 Not Found: Session not found`. Load-dependent and
        // client-version-dependent, and invisible to a single local instance.
        .with_legacy_session_mode(false)
        // Prefer plain JSON for simple request/response tools; rmcp falls back
        // to SSE by itself if a handler emits anything before the result.
        .with_json_response(true)
        // ⚠️ `allowed_hosts` DEFAULTS TO `["localhost", "127.0.0.1", "::1"]`,
        // and an EMPTY list is `rmcp`'s documented "allow any host"
        // (`host_is_allowed` returns `true` on an empty slice). Passing the
        // empty vec is therefore a deliberate opt-out, not an oversight, and
        // it must stay explicit: dropping this call silently restores the
        // loopback default, which a public deployment fails every request
        // against — rmcp reads the RAW `Host` (or HTTP/2 `:authority`) and
        // never `X-Forwarded-Host`, so a proxied request presents the origin
        // authority and is refused AFTER the token has verified. That took the
        // designer's whole MCP surface down for a release, reading as a client
        // bug. DNS rebinding, which the default defends against, needs a
        // browser to make a CREDENTIALED request, and this surface accepts
        // only a bearer header with no CORS.
        .with_allowed_hosts(Vec::<String>::new());

    StreamableHttpService::new(
        move || Ok(WorkerMcpServer::new(Arc::clone(&ctx))),
        // `NeverSessionManager`, not `LocalSessionManager`. With
        // `legacy_session_mode = false` no session is ever created, so the two
        // behave identically today — but this one makes the statelessness
        // STRUCTURAL: if that flag is ever flipped back, session creation
        // fails loudly here instead of quietly minting per-process sessions
        // that break only behind a load balancer.
        Arc::new(NeverSessionManager::default()),
        config,
    )
}
