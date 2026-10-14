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
//! * [`caller_teams`] — the caller's teams (`team` plus `teams`), from the
//!   provider-authored `extensions.caller` block, and only when the provider
//!   verified the user;
//! * [`stamp_team_hint`] — the `team_hint` metadata key the flow and the
//!   router read, always overwritten (never trusted from the inbound message);
//! * [`decide`] — allow / deny.
//!
//! Policy (conservative, see `docs/flow-audience.md`):
//!
//! * empty audience → [`Decision::Allow`], no restriction;
//! * caller teams unknown (anonymous chat, unverified provider block, no or
//!   invalid team claim) → [`Decision::AllowUnknownTeam`]: NOT refused, logged
//!   by the caller. Refusing would break every anonymous channel;
//! * any caller team listed → allow; teams known and none listed →
//!   [`Decision::Deny`] with a plain reply, never an error.

use greentic_types::ChannelMessageEnvelope;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

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
    /// Per-node audiences of a ROUTER pack: node id (`ask_<unit>`) to the team
    /// slugs allowed to be routed to it. A node absent here, or mapped to an
    /// empty list, is open. Enforced by the Fast2Flow hook, never by
    /// [`decide`] on the pack as a whole.
    #[serde(default)]
    pub node_audience: BTreeMap<String, Vec<String>>,
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
        meta.node_audience = std::mem::take(&mut meta.node_audience)
            .into_iter()
            .filter_map(|(node, slugs)| {
                let node = node.trim().to_string();
                let slugs: Vec<String> = slugs
                    .iter()
                    .map(|slug| normalize(slug))
                    .filter(|slug| !slug.is_empty())
                    .collect();
                // An entry that lists nobody means "open", so it is not kept:
                // a restriction must name at least one team.
                (!node.is_empty() && !slugs.is_empty()).then_some((node, slugs))
            })
            .collect();
        Ok(meta)
    }

    /// The audience of one routed node as a stand-alone [`FlowMeta`], or
    /// `None` when the node is open.
    pub fn node_meta(&self, node: &str) -> Option<FlowMeta> {
        self.node_audience.get(node).map(|audience| FlowMeta {
            audience: audience.clone(),
            ..FlowMeta::default()
        })
    }

    /// True when the flow restricts who may use it.
    pub fn is_restricted(&self) -> bool {
        !self.audience.is_empty()
    }
}

/// Outcome of the audience check for one inbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No restriction applies, or one of the caller's teams is in the audience.
    Allow,
    /// The flow is restricted but the caller's teams are unknown. Allowed
    /// (fail open); the caller logs it.
    AllowUnknownTeam,
    /// The caller's teams are known and none is in the audience.
    Deny { teams: Vec<String> },
}

/// Upper bound on teams read from one caller block.
pub const MAX_CALLER_TEAMS: usize = 50;

/// Longest DNS label.
const MAX_SLUG_LEN: usize = 50;

fn normalize(slug: &str) -> String {
    slug.trim().to_ascii_lowercase()
}

/// A team slug is a DNS label of at most 50 characters: lowercase ASCII
/// letters, digits and `-`, not starting or ending with `-`.
fn is_valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= MAX_SLUG_LEN
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The caller's teams, when the provider vouches for them.
///
/// Read from `extensions.caller` — the block only a messaging provider may
/// author on this route (see `revision_serve::client_caller`) — and only when
/// `user_verified` is `true`. An unverified block is a claim nobody checked.
///
/// The result is `team` (if valid) followed by the entries of `teams` (at most
/// [`MAX_CALLER_TEAMS`] are read), normalised, invalid slugs dropped,
/// duplicates removed, order kept. Empty means "unknown".
pub fn caller_teams(envelope: &ChannelMessageEnvelope) -> Vec<String> {
    let Some(block) = envelope.extensions.get("caller") else {
        return Vec::new();
    };
    if block.get("user_verified").and_then(Value::as_bool) != Some(true) {
        return Vec::new();
    }
    let single = block.get("team").and_then(Value::as_str);
    let many = block
        .get("teams")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_CALLER_TEAMS)
        .filter_map(Value::as_str);
    let mut teams: Vec<String> = Vec::new();
    for slug in single.into_iter().chain(many) {
        let slug = normalize(slug);
        if is_valid_slug(&slug) && !teams.contains(&slug) {
            teams.push(slug);
        }
    }
    teams
}

/// Apply the audience policy.
pub fn decide(meta: Option<&FlowMeta>, teams: &[String]) -> Decision {
    let Some(meta) = meta.filter(|meta| meta.is_restricted()) else {
        return Decision::Allow;
    };
    if teams.is_empty() {
        return Decision::AllowUnknownTeam;
    }
    if teams
        .iter()
        .any(|team| meta.audience.contains(&normalize(team)))
    {
        Decision::Allow
    } else {
        Decision::Deny {
            teams: teams.to_vec(),
        }
    }
}

/// Apply the audience policy to a routed node of a router pack. Same
/// semantics as [`decide`]: an open node allows, unknown caller teams fail
/// open, known teams none of which is listed are denied.
pub fn decide_node(meta: Option<&FlowMeta>, node: &str, teams: &[String]) -> Decision {
    decide(meta.and_then(|meta| meta.node_meta(node)).as_ref(), teams)
}

/// The single value stamped as `team_hint`: the first caller team that is in
/// the flow's audience (so the router uses the relevant team), else the first
/// caller team, else none.
pub fn hint_team(meta: Option<&FlowMeta>, teams: &[String]) -> Option<String> {
    let in_audience = meta.and_then(|meta| {
        teams
            .iter()
            .find(|team| meta.audience.contains(&normalize(team)))
    });
    in_audience.or_else(|| teams.first()).cloned()
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
    let teams = caller_teams(envelope);
    let hint = hint_team(meta, &teams);
    let stamped = stamp_team_hint(envelope, hint.as_deref());
    match decide(meta, &teams) {
        Decision::Allow => Applied::Proceed(stamped),
        Decision::AllowUnknownTeam => {
            crate::operator_log::info(
                module_path!(),
                format!("[flow-audience] {scope}: caller team unknown, audience not enforced"),
            );
            Applied::Proceed(stamped)
        }
        Decision::Deny { teams } => {
            crate::operator_log::info(
                module_path!(),
                format!(
                    "[flow-audience] {scope}: teams {teams:?} are outside the audience, refused"
                ),
            );
            Applied::Denied(denied_reply(envelope))
        }
    }
}

#[cfg(test)]
#[path = "flow_audience_tests.rs"]
mod tests;
