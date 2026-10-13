//! The runtime access-policy door (access-policy spec §5.4 and §6.2, phase 3).
//!
//! The deploy stages an access policy; this module lets the admin NARROW it
//! while the unit runs, so a revocation, a narrower mechanism list or the
//! anonymous daily budget takes effect within a minute instead of at the next
//! deploy.
//!
//! # Wire contract (fixed, the admin implements the server)
//!
//! `GET <door>` where `<door>` is the unit's `metering.endpoint` with its last
//! path segment (`worker-usage`) swapped for `access-policy` (the same sibling
//! rule the other doors use). Bearer = the unit's metering token (it needs the
//! purpose `access`), optional `If-None-Match`.
//!
//! ```json
//! { "generation": 7,
//!   "policy": { "private_mechanisms": ["api_key", "oauth"],
//!               "public_allowed": true,
//!               "public_rate_per_min": 60, "public_burst": 20,
//!               "public_daily_turn_cap": null },
//!   "revoked_credential_ids": ["c_01J"],
//!   "revoked_client_ids": ["mcpc_01J"],
//!   "public": { "daily_turns_used": 12 } }
//! ```
//!
//! `304` when the ETag still matches; `401` bad token, `403` the token lacks
//! the purpose, `404` an admin without the door.
//!
//! # Rules
//!
//! - **No flag, no call.** A unit whose document does not carry
//!   `access.door: true` is never fetched for and is served byte-identically
//!   to before this existed.
//! - **The door only tightens (spec D17).** The effective policy is computed
//!   by [`tighten`] from the staged one and can only remove: mechanisms are
//!   intersected, a public unit may be made private but a private one is never
//!   made public, limits are the minimum of the two, a daily cap can appear
//!   but never be lifted. A wider answer is simply ignored.
//! - **A door that cannot answer opens nothing and denies nothing new.** Any
//!   failure (timeout, 5xx, 401/403/404, a body this build cannot read) keeps
//!   the last good answer; with none, the staged policy stands.
//! - **Revocation is rejection by name.** A revoked credential id is removed
//!   from the unit's credentials; a revoked service-client id is refused by
//!   its `svc:<client_id>@<tenant>` subject before the issuer is asked
//!   anything, including for a JWT minted before the revocation.
//! - **The anonymous daily count survives a cold start.** The door reports how
//!   many anonymous turns the unit already served today; the local counter is
//!   raised to it, so a restart cannot hand back the budget.
//! - **No token or body content is ever logged.**

mod cache;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use serde::Deserialize;

use super::config::{InteropConfig, Mechanism, Visibility};

pub(crate) use cache::{PolicyDoor, UnitRef};

/// The last path segment of the admin's access-policy door.
pub(crate) const ACCESS_POLICY_SEGMENT: &str = "access-policy";

/// The most ids one list may carry; a ceiling against a misbehaving peer.
const MAX_IDS: usize = 10_000;

/// One parsed door answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DoorAnswer {
    pub generation: u64,
    pub private_mechanisms: Vec<Mechanism>,
    pub public_allowed: bool,
    pub public_rate_per_min: u32,
    pub public_burst: u32,
    pub public_daily_turn_cap: Option<u32>,
    pub revoked_credential_ids: BTreeSet<String>,
    pub revoked_client_ids: BTreeSet<String>,
    pub daily_turns_used: u64,
}

#[derive(Deserialize)]
struct RawAnswer {
    generation: u64,
    policy: RawPolicy,
    revoked_credential_ids: Vec<String>,
    revoked_client_ids: Vec<String>,
    public: RawPublic,
}

#[derive(Deserialize)]
struct RawPolicy {
    private_mechanisms: Vec<String>,
    public_allowed: bool,
    public_rate_per_min: u32,
    public_burst: u32,
    #[serde(default)]
    public_daily_turn_cap: Option<u32>,
}

#[derive(Deserialize)]
struct RawPublic {
    daily_turns_used: u64,
}

/// Read one door body. `Err` carries a position-only description: serde's own
/// message can quote the offending value.
///
/// Unknown fields are ignored (the admin may add fields ahead of this build);
/// a missing documented field, a zero rate or burst, or an oversized list is a
/// body this build cannot use, so the caller keeps its last good answer.
pub(crate) fn parse_answer(bytes: &[u8]) -> Result<DoorAnswer, String> {
    let raw: RawAnswer = serde_json::from_slice(bytes).map_err(|err| {
        format!(
            "not the expected access-policy shape (line {}, column {})",
            err.line(),
            err.column()
        )
    })?;
    if raw.policy.public_rate_per_min == 0 || raw.policy.public_burst == 0 {
        return Err("the public rate or burst is zero".to_string());
    }
    if raw.revoked_credential_ids.len() > MAX_IDS || raw.revoked_client_ids.len() > MAX_IDS {
        return Err(format!("more than {MAX_IDS} revoked ids in one answer"));
    }
    // An unknown mechanism name is dropped alone: it can only narrow what a
    // listed name allows, never add one.
    let mut private_mechanisms = Vec::new();
    for name in &raw.policy.private_mechanisms {
        let mechanism = match name.as_str() {
            "api_key" => Mechanism::ApiKey,
            "oauth" => Mechanism::Oauth,
            _ => continue,
        };
        if !private_mechanisms.contains(&mechanism) {
            private_mechanisms.push(mechanism);
        }
    }
    Ok(DoorAnswer {
        generation: raw.generation,
        private_mechanisms,
        public_allowed: raw.policy.public_allowed,
        public_rate_per_min: raw.policy.public_rate_per_min,
        public_burst: raw.policy.public_burst,
        public_daily_turn_cap: raw.policy.public_daily_turn_cap,
        revoked_credential_ids: raw.revoked_credential_ids.into_iter().collect(),
        revoked_client_ids: raw.revoked_client_ids.into_iter().collect(),
        daily_turns_used: raw.public.daily_turns_used,
    })
}

/// The staged config narrowed by one door answer. **Pure, and only ever
/// removes access** — see the module docs for each rule.
///
/// The effective mechanism list may come out EMPTY: that is a deny, not a
/// fallback to something wider (the gate refuses every credential on it).
pub(crate) fn tighten(mut staged: InteropConfig, door: &DoorAnswer) -> InteropConfig {
    let access = &mut staged.access;
    access
        .mechanisms
        .retain(|mechanism| door.private_mechanisms.contains(mechanism));
    if access.visibility == Visibility::Public && !door.public_allowed {
        access.visibility = Visibility::Private;
    }
    access.public.rate_per_min = access.public.rate_per_min.min(door.public_rate_per_min);
    access.public.burst = access.public.burst.min(door.public_burst);
    access.public.daily_turn_cap = match (access.public.daily_turn_cap, door.public_daily_turn_cap)
    {
        (Some(staged), Some(door)) => Some(staged.min(door)),
        (cap, None) | (None, cap) => cap,
    };
    staged
        .credentials
        .retain(|credential| !door.revoked_credential_ids.contains(&credential.id));
    staged.revoked_client_ids = door.revoked_client_ids.clone();
    staged
}
