//! The API channel's SSE stream adapter.
//!
//! The `messaging-api` provider pack owns one conversation log with a `u64`
//! cursor and exports the provider op `poll_events`. This module serves that
//! log as Server-Sent Events by running `websocket::Pump` against an
//! `ActivitySource` that calls the op. See
//! `docs/superpowers/specs/2026-10-14-api-channel-design.md` in
//! greentic-designer for the contract.

pub(crate) mod event;
pub(crate) mod limits;
pub(crate) mod source;
pub(crate) mod sse;

/// The conversation id of `.../conversations/{id}/stream` that is NOT a Direct
/// Line path (`.../v3/directline/conversations/{id}/stream`), which belongs to
/// the WebSocket route.
pub(crate) fn stream_conversation_id(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        [.., "conversations", id, "stream"] if !id.is_empty() => {
            let before = &segments[..segments.len() - 3];
            if before.last() == Some(&"directline") {
                None
            } else {
                Some((*id).to_string())
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod event_tests;
#[cfg(test)]
mod sse_boundary_tests;
#[cfg(test)]
mod sse_tests;
