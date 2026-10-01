//! A bounded, in-memory record of the tasks `SendMessage` answered with, so
//! `GetTask` can resolve an id this server minted (worker-interop contract
//! §9.3).
//!
//! # What it records, and what it does not
//!
//! Every `SendMessage` that answers with a [`Task`] — a parked turn
//! (`TASK_STATE_INPUT_REQUIRED`) or a completed one carrying artifacts
//! (`TASK_STATE_COMPLETED`) — puts a snapshot of that exact `Task` here. A
//! turn that answers with a bare `Message` created no task (contract D8) and
//! records nothing. `GetTask` answers the snapshot; it never runs a turn and
//! never reads the runtime's session store, so it cannot disagree with what
//! `SendMessage` already said.
//!
//! The task id is the conversation's `contextId` (D9), so a later
//! `SendMessage` in the same conversation REPLACES the snapshot: `GetTask`
//! always answers the latest state this server reported for that id.
//!
//! # Who may read an entry
//!
//! An entry is keyed by the tenant, the deployment, the verified credential
//! id that created it, and the task id. A lookup under any other credential
//! misses and answers `TaskNotFoundError` exactly like an id that never
//! existed — never a "forbidden", which would confirm the id exists for
//! somebody else. The `tenant` field of a `GetTaskRequest` is NOT consulted:
//! the verified credential is the only authority on whose task it is.
//!
//! # Bounds
//!
//! - **Idle expiry** ([`IDLE_TTL`], 1 h): an entry neither written nor read
//!   for that long is dropped. That is far below the runtime's default
//!   parked-conversation TTL (24 h), so a snapshot cannot claim a park the
//!   runtime has already forgotten for the default configuration.
//! - **Per credential** ([`MAX_ENTRIES_PER_CREDENTIAL`]): a caller over its
//!   share evicts its OWN oldest entry, so one caller cannot flush another's.
//! - **Total entries** ([`MAX_ENTRIES`]) and **total bytes**
//!   ([`MAX_TOTAL_BYTES`], the serialized size of the snapshots): past either,
//!   the least recently touched entries go first.
//! - A single snapshot above [`MAX_ENTRY_BYTES`] is not stored at all.
//!
//! Everything is per PROCESS and per revision listener, like the rate
//! limiter: a restart, or a poll landing on another instance or revision,
//! misses and answers `-32001` — the honest answer for an id this process
//! cannot vouch for.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use greentic_deploy_spec::ids::DeploymentId;

use super::types::Task;

/// How long an entry survives without being written or read.
pub(crate) const IDLE_TTL: Duration = Duration::from_secs(60 * 60);

/// The most entries the store holds across every caller.
pub(crate) const MAX_ENTRIES: usize = 4096;

/// The most entries one credential of one deployment may hold.
pub(crate) const MAX_ENTRIES_PER_CREDENTIAL: usize = 256;

/// The most serialized bytes the store holds across every entry.
pub(crate) const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// The largest single snapshot the store accepts.
pub(crate) const MAX_ENTRY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Owner {
    tenant: String,
    deployment_id: DeploymentId,
    credential_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    owner: Owner,
    task_id: String,
}

struct Entry {
    task: Task,
    bytes: usize,
    touched: Instant,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<Key, Entry>,
    total_bytes: usize,
}

impl Inner {
    fn remove(&mut self, key: &Key) {
        if let Some(entry) = self.entries.remove(key) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
        }
    }

    fn sweep_expired(&mut self, now: Instant) {
        let expired: Vec<Key> = self
            .entries
            .iter()
            .filter(|(_, entry)| now.saturating_duration_since(entry.touched) >= IDLE_TTL)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.remove(&key);
        }
    }

    /// The least recently touched key, optionally restricted to one owner.
    fn oldest(&self, owner: Option<&Owner>) -> Option<Key> {
        self.entries
            .iter()
            .filter(|(key, _)| owner.is_none_or(|owner| &key.owner == owner))
            .min_by_key(|(_, entry)| entry.touched)
            .map(|(key, _)| key.clone())
    }
}

/// Why a snapshot was not stored. Logged by the caller; never fails a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotStored {
    /// The snapshot serialized above [`MAX_ENTRY_BYTES`].
    TooLarge,
    /// The snapshot could not be serialized to measure it.
    Unmeasurable,
    /// The lock was poisoned by a panic elsewhere.
    Unavailable,
}

/// See the module docs.
#[derive(Default)]
pub(crate) struct TaskStore {
    inner: Mutex<Inner>,
}

impl TaskStore {
    /// Record `task` as the latest state of `task.id` for this owner,
    /// replacing any earlier snapshot of the same id.
    pub(crate) fn put(
        &self,
        tenant: &str,
        deployment_id: DeploymentId,
        credential_id: &str,
        task: &Task,
        now: Instant,
    ) -> Result<(), NotStored> {
        let bytes = serde_json::to_vec(task)
            .map_err(|_| NotStored::Unmeasurable)?
            .len();
        if bytes > MAX_ENTRY_BYTES {
            return Err(NotStored::TooLarge);
        }
        let owner = Owner {
            tenant: tenant.to_string(),
            deployment_id,
            credential_id: credential_id.to_string(),
        };
        let key = Key {
            owner: owner.clone(),
            task_id: task.id.clone(),
        };
        let mut inner = self.inner.lock().map_err(|_| NotStored::Unavailable)?;
        inner.sweep_expired(now);
        inner.remove(&key);
        // The caller's own share first, so its flood evicts only its own.
        while inner
            .entries
            .keys()
            .filter(|existing| existing.owner == owner)
            .count()
            >= MAX_ENTRIES_PER_CREDENTIAL
        {
            let Some(oldest) = inner.oldest(Some(&owner)) else {
                break;
            };
            inner.remove(&oldest);
        }
        while inner.entries.len() >= MAX_ENTRIES
            || inner.total_bytes.saturating_add(bytes) > MAX_TOTAL_BYTES
        {
            let Some(oldest) = inner.oldest(None) else {
                break;
            };
            inner.remove(&oldest);
        }
        inner.total_bytes = inner.total_bytes.saturating_add(bytes);
        inner.entries.insert(
            key,
            Entry {
                task: task.clone(),
                bytes,
                touched: now,
            },
        );
        Ok(())
    }

    /// The latest snapshot of `task_id` recorded for this owner, if it is
    /// still held. A hit refreshes the entry's idle clock.
    pub(crate) fn get(
        &self,
        tenant: &str,
        deployment_id: DeploymentId,
        credential_id: &str,
        task_id: &str,
        now: Instant,
    ) -> Option<Task> {
        let key = Key {
            owner: Owner {
                tenant: tenant.to_string(),
                deployment_id,
                credential_id: credential_id.to_string(),
            },
            task_id: task_id.to_string(),
        };
        let mut inner = self.inner.lock().ok()?;
        let expired = inner
            .entries
            .get(&key)
            .is_some_and(|entry| now.saturating_duration_since(entry.touched) >= IDLE_TTL);
        if expired {
            inner.remove(&key);
            return None;
        }
        let entry = inner.entries.get_mut(&key)?;
        entry.touched = now;
        Some(entry.task.clone())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().map(|i| i.entries.len()).unwrap_or(0)
    }
}

#[cfg(test)]
#[path = "tasks_tests.rs"]
mod tasks_tests;
