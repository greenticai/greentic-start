//! `state-sorla`: the conversation-state backend that stores through an HTTP
//! door instead of a database the deployed worker would have to reach.
//!
//! A deployed WebChat keeps its whole conversation behind the
//! `greentic:state/state-store` import, which runner-host serves from a
//! [`greentic_state::StateStore`] (`pack.rs`, `StateStoreHost for HostState`).
//! In memory that store dies with the process, so a Cloud Run cold start loses
//! the conversation. This module is the third backend for that trait, beside
//! the in-memory and Redis ones: a key/value client of the admin's state door.
//!
//! # Where the endpoint and the credential come from
//!
//! Nothing new is staged. The unit's `metering { endpoint, token }` block
//! already carries a per-unit `gtm_` bearer and the admin's worker-usage URL;
//! the state door is derived from it exactly as the run-outcome and approval
//! doors are (the last path segment swapped, here for `state`). The token
//! never leaves [`MeteringConfig`] except into the `Authorization` header, and
//! no type in this module prints it.
//!
//! # Rules
//!
//! * **Selected, never inferred.** Only a revision that carries a `state-sorla`
//!   pack config selects it (see [`config::PROVIDER_PACK_ID`]).
//! * **No silent fallback to memory.** A named backend that cannot be built, or
//!   whose door does not answer the boot probe, fails the revision activation.
//!   A door error on a write or an uncached read fails that operation.
//! * **Reads may outlive an outage, writes may not.** A read that the door
//!   cannot answer is served from the bounded cache when it holds the key,
//!   with a warning; a write is never buffered.
//! * **Scoped per revision.** The revision's isolation suffix is part of every
//!   key, the rule `crate::durable_state` applies to the session keyspace, so
//!   two revisions of a rolling deploy cannot read each other's state.

pub(crate) mod config;
mod store;

pub(crate) use config::{PROVIDER_PACK_ID, SorlaStateSelection, select};
pub(crate) use store::HttpStateStore;

#[cfg(test)]
mod tests;
