//! A verified caller enters a turn only from a messaging PROVIDER, never from
//! a request body.
//!
//! The runner reads the turn's caller from `extensions.caller` on the activity
//! payload (`greentic_runner_host::caller_identity::caller_block`) and trusts
//! it: `user_verified: true` there is what a tool, a component and the run
//! audit see as a provider-verified end user. On the provider route that
//! payload is the envelope the provider component produced from its ingest op
//! (see [`super::envelope_to_activity`]), and the provider is the only party
//! that checked the end user's token. That is the whole basis for trusting the
//! block.
//!
//! Every OTHER ingress builds its activity from JSON the caller wrote — the
//! generic JSON ingress, `/workers/invoke`, and the agent-to-agent and MCP
//! doors, all through [`super::build_activity`]. A body carrying
//! `{"extensions":{"caller":{"user_verified":true,"sub":"<victim>"}}}` used to
//! reach the runner unchanged there, so anyone holding a unit's bearer, any
//! loopback peer, and everyone when the generic-ingress gate was switched off
//! could present themselves as any verified end user.
//!
//! [`without_client_caller`] removes that one key and leaves every other
//! extension where the caller put it. A caller has no legitimate reason to
//! send it: nothing in the platform posts a caller block to these doors.

use greentic_runner_host::caller_identity::CALLER_EXT_KEY;
use serde_json::Value;

/// The payload key the runner looks for the caller block under.
const EXTENSIONS_KEY: &str = "extensions";

/// `payload` with any client-supplied `extensions.caller` removed.
///
/// Only the exact keys the runner decodes are touched (it matches both by
/// exact, case-sensitive name), and only the `caller` entry: every other
/// extension a flow may read still travels.
pub(super) fn without_client_caller(payload: &Value) -> Value {
    let mut payload = payload.clone();
    if let Some(Value::Object(extensions)) = payload.get_mut(EXTENSIONS_KEY)
        && extensions.remove(CALLER_EXT_KEY).is_some()
    {
        crate::operator_log::warn(
            module_path!(),
            "dropped a caller block from a request body: only a messaging provider may \
             establish the turn's caller",
        );
    }
    payload
}

#[cfg(test)]
#[path = "client_caller_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "client_artifacts_tests.rs"]
mod artifacts_tests;
