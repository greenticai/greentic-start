//! Flow audience: which teams may use a flow, read from the pack.
//!
//! The designer writes `assets/flow-meta.json` into an app pack:
//!
//! ```json
//! {"version":1,"audience":["sales","support"],"example_requests":["..."]}
//! ```
//!
//! An empty (or absent) `audience` means everyone. This module owns the
//! runtime half, all of it pure so it can be tested without a runner host:
//!
//! * [`FlowMeta::parse`] — tolerant read of the sidecar;
//! * [`caller_team`] — the caller's team, from the provider-authored
//!   `extensions.caller` block, and only when the provider verified the user;
//! * [`stamp_team_hint`] — the `team_hint` metadata key the flow and the
//!   router read, always overwritten (never trusted from the inbound message);
//! * [`decide`] — allow / deny.
//!
//! Policy (conservative, see `docs/flow-audience.md`):
//!
//! * empty audience → [`Decision::Allow`], no restriction;
//! * caller team unknown (anonymous chat, unverified provider block, no team
//!   claim) → [`Decision::AllowUnknownTeam`]: NOT refused, logged by the
//!   caller. Refusing would break every anonymous channel;
//! * caller team known and listed → allow; known and not listed →
//!   [`Decision::Deny`] with a plain reply, never an error.

use greentic_types::ChannelMessageEnvelope;
use serde::Deserialize;
use serde_json::Value;

/// Pack path of the sidecar.
pub const FLOW_META_ENTRY: &str = "assets/flow-meta.json";

/// Envelope metadata key carrying the caller's team for the flow and router.
pub const TEAM_HINT_KEY: &str = "team_hint";

/// Upper bound on the sidecar we are willing to read.
pub const MAX_FLOW_META_BYTES: u64 = 64 * 1024;

/// Reply sent to a caller whose team is outside the audience.
pub const DENIED_REPLY_TEXT: &str = "Sorry, this assistant is not available to your team.";

/// Parsed `assets/flow-meta.json`. Unknown fields are ignored so a newer
/// designer can add keys without breaking an older runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct FlowMeta {
    /// Team slugs allowed to use the flow; empty means everyone.
    #[serde(default)]
    pub audience: Vec<String>,
    /// Phrases the designer feeds to the router index; unused by the gate.
    #[serde(default)]
    pub example_requests: Vec<String>,
}

impl FlowMeta {
    /// Parse the sidecar. A document this runtime cannot read, or one of a
    /// version it does not know, yields `Err` and the caller treats the pack
    /// as having no audience (fail open, with a warning).
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|err| format!("not valid JSON: {err}"))?;
        match value.get("version").and_then(Value::as_u64) {
            Some(1) => {}
            other => return Err(format!("unsupported version {other:?}")),
        }
        let mut meta: FlowMeta =
            serde_json::from_value(value).map_err(|err| format!("unexpected shape: {err}"))?;
        meta.audience = meta
            .audience
            .iter()
            .map(|slug| normalize(slug))
            .filter(|slug| !slug.is_empty())
            .collect();
        Ok(meta)
    }

    /// True when the flow restricts who may use it.
    pub fn is_restricted(&self) -> bool {
        !self.audience.is_empty()
    }
}

/// Outcome of the audience check for one inbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No restriction applies, or the caller's team is in the audience.
    Allow,
    /// The flow is restricted but the caller's team is unknown. Allowed
    /// (fail open); the caller logs it.
    AllowUnknownTeam,
    /// The caller's team is known and outside the audience.
    Deny { team: String },
}

fn normalize(slug: &str) -> String {
    slug.trim().to_ascii_lowercase()
}

/// The caller's team, when the provider vouches for it.
///
/// Read from `extensions.caller` — the block only a messaging provider may
/// author on this route (see `revision_serve::client_caller`) — and only when
/// `user_verified` is `true`. An unverified block is a claim nobody checked.
pub fn caller_team(envelope: &ChannelMessageEnvelope) -> Option<String> {
    let block = envelope.extensions.get("caller")?;
    if block.get("user_verified").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let team = normalize(block.get("team").and_then(Value::as_str)?);
    (!team.is_empty()).then_some(team)
}

/// Apply the audience policy.
pub fn decide(meta: Option<&FlowMeta>, team: Option<&str>) -> Decision {
    let Some(meta) = meta.filter(|meta| meta.is_restricted()) else {
        return Decision::Allow;
    };
    match team {
        None => Decision::AllowUnknownTeam,
        Some(team) => {
            let team = normalize(team);
            if meta.audience.contains(&team) {
                Decision::Allow
            } else {
                Decision::Deny { team }
            }
        }
    }
}

/// A copy of `envelope` whose `team_hint` metadata is the verified caller
/// team, or absent when there is none. Always overwritten: card submits flatten
/// user-controlled data into `metadata`, so an inbound `team_hint` is never
/// trustworthy.
pub fn stamp_team_hint(
    envelope: &ChannelMessageEnvelope,
    team: Option<&str>,
) -> ChannelMessageEnvelope {
    let mut stamped = envelope.clone();
    match team {
        Some(team) => {
            stamped
                .metadata
                .insert(TEAM_HINT_KEY.to_string(), team.to_string());
        }
        None => {
            stamped.metadata.remove(TEAM_HINT_KEY);
        }
    }
    stamped
}

/// The reply for a denied caller, addressed like the inbound message.
pub fn denied_reply(envelope: &ChannelMessageEnvelope) -> ChannelMessageEnvelope {
    let mut reply = envelope.clone();
    reply.metadata.remove("adaptive_card");
    reply.metadata.remove(TEAM_HINT_KEY);
    reply.text = Some(DENIED_REPLY_TEXT.to_string());
    reply
}

/// What the ingress does with one inbound message.
#[derive(Debug, Clone, PartialEq)]
pub enum Applied {
    /// Run the turn with this envelope (its `team_hint` already stamped).
    Proceed(ChannelMessageEnvelope),
    /// Do not run a flow; send this reply instead.
    Denied(ChannelMessageEnvelope),
}

/// Stamp `team_hint`, then enforce the audience. `scope` is only for logs
/// (never log message content).
pub fn apply(meta: Option<&FlowMeta>, envelope: &ChannelMessageEnvelope, scope: &str) -> Applied {
    let team = caller_team(envelope);
    let stamped = stamp_team_hint(envelope, team.as_deref());
    match decide(meta, team.as_deref()) {
        Decision::Allow => Applied::Proceed(stamped),
        Decision::AllowUnknownTeam => {
            crate::operator_log::info(
                module_path!(),
                format!("[flow-audience] {scope}: caller team unknown, audience not enforced"),
            );
            Applied::Proceed(stamped)
        }
        Decision::Deny { team } => {
            crate::operator_log::info(
                module_path!(),
                format!("[flow-audience] {scope}: team {team:?} is outside the audience, refused"),
            );
            Applied::Denied(denied_reply(envelope))
        }
    }
}

#[cfg(test)]
#[path = "flow_audience_tests.rs"]
mod tests;
