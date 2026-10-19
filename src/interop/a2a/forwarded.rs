//! A verified end-user caller forwarded by a router (`message.metadata.caller`).
//!
//! A router (the `a2a` flow node with `forward_caller`) received the end user
//! through a messaging provider, which verified them, and forwards that
//! identity to the target unit over agent-to-agent. This module is the
//! receiving half. It is deliberately the mirror image of
//! `revision_serve::client_caller`, which DROPS any caller block a client
//! writes into a request body: here a block is accepted only when ALL of these
//! hold, and otherwise it is dropped silently and the turn runs exactly as it
//! did before this existed:
//!
//! 1. the request authenticated as a staged credential whose OWN entry in the
//!    unit's ingress document says `forwards_caller: true` (looked up from the
//!    authenticated [`Caller`], never from a value in the request);
//! 2. the block is valid: exactly the whitelisted fields, `user_verified` is
//!    `true`, `sub` is non-empty, and it is within the size bounds below;
//! 3. the binding is A2A (JSON-RPC or REST `SendMessage`) — the MCP surface and
//!    the generic ingress never call [`accept`].
//!
//! An accepted block is rebuilt from the validated fields (never passed
//! through), stamped with `via: "router:<credential id>"`, and handed to the
//! turn runner, which writes it to `extensions.caller` of the turn's activity
//! — the one place the runner and the flow-audience gate read a caller from.

use serde_json::{Map, Value, json};

use super::super::caller::Caller;
use super::super::config::InteropConfig;

/// The A2A `message.metadata` key a router puts the block under.
pub(crate) const METADATA_KEY: &str = "caller";

/// Largest accepted block, as compact JSON.
const MAX_BLOCK_BYTES: usize = 4096;
/// Most entries accepted in `teams` and in `groups`.
const MAX_LIST_ENTRIES: usize = 64;
/// Longest accepted string, in characters.
const MAX_STRING_CHARS: usize = 256;

const ALLOWED_KEYS: &[&str] = &["sub", "iss", "teams", "groups", "role", "user_verified"];

/// Whether `caller` authenticated with a credential flagged `forwards_caller`.
///
/// A credential id can appear twice (a rotated-out entry beside the current
/// one), so EVERY entry with the id must carry the flag: a mixed pair reads as
/// not flagged rather than letting the unflagged token ride the flagged one.
fn forwards_caller(config: &InteropConfig, caller: &Caller) -> bool {
    let Some(id) = caller.credential_id() else {
        return false;
    };
    let mut entries = config.credentials.iter().filter(|c| c.id == id).peekable();
    entries.peek().is_some() && entries.all(|c| c.forwards_caller)
}

/// Take the forwarded caller out of `metadata`, whatever happens.
///
/// `metadata` is the request's `message.metadata`. The `caller` key is REMOVED
/// from it unconditionally, so the raw value can never travel on by accident;
/// only the rebuilt, validated block is returned.
pub(crate) fn accept(
    config: &InteropConfig,
    caller: &Caller,
    metadata: &mut Option<Value>,
) -> Option<Value> {
    let raw = match metadata {
        Some(Value::Object(map)) => map.remove(METADATA_KEY)?,
        _ => return None,
    };
    if !forwards_caller(config, caller) {
        crate::operator_log::warn(
            module_path!(),
            "dropped a forwarded caller block: the credential is not flagged `forwards_caller`",
        );
        return None;
    }
    let id = caller.credential_id()?;
    match validate(&raw, id) {
        Some(block) => Some(block),
        None => {
            // Never the block's content: it is end-user data.
            crate::operator_log::warn(
                module_path!(),
                "dropped a forwarded caller block: it is not a valid verified caller",
            );
            None
        }
    }
}

/// Validate `raw` and rebuild it from its own fields, stamped `via`.
fn validate(raw: &Value, credential_id: &str) -> Option<Value> {
    let map = raw.as_object()?;
    if serde_json::to_vec(raw).ok()?.len() > MAX_BLOCK_BYTES {
        return None;
    }
    if map.keys().any(|key| !ALLOWED_KEYS.contains(&key.as_str())) {
        return None;
    }
    if map.get("user_verified")?.as_bool() != Some(true) {
        return None;
    }
    let sub = string(map.get("sub")?)?;
    if sub.trim().is_empty() {
        return None;
    }
    let mut block = Map::new();
    block.insert("sub".into(), json!(sub));
    if let Some(iss) = map.get("iss") {
        block.insert("iss".into(), json!(string(iss)?));
    }
    block.insert("teams".into(), list(map.get("teams"))?);
    block.insert("groups".into(), list(map.get("groups"))?);
    if let Some(role) = map.get("role") {
        block.insert("role".into(), json!(string(role)?));
    }
    block.insert("user_verified".into(), json!(true));
    block.insert("via".into(), json!(format!("router:{credential_id}")));
    Some(Value::Object(block))
}

/// A bounded string with no control characters.
fn string(value: &Value) -> Option<&str> {
    let text = value.as_str()?;
    (text.chars().count() <= MAX_STRING_CHARS && !text.chars().any(char::is_control))
        .then_some(text)
}

/// A bounded list of bounded strings; absent is the empty list.
fn list(value: Option<&Value>) -> Option<Value> {
    let Some(value) = value else {
        return Some(json!([]));
    };
    let items = value.as_array()?;
    if items.len() > MAX_LIST_ENTRIES {
        return None;
    }
    let strings: Option<Vec<&str>> = items.iter().map(string).collect();
    Some(json!(strings?))
}

#[cfg(test)]
#[path = "forwarded_tests.rs"]
mod tests;
