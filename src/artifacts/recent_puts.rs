//! Provenance for outbound links: which artifacts THIS unit's extension port
//! created (docs/outbound-artifacts.md).
//!
//! A link is minted only for an id recorded here within the link TTL. A tool
//! result naming any other id (another conversation's upload, an id a flow
//! made up) gets no link. The record holds the DOOR's answer at put time
//! (media type, size) and the port's cleaned name, never what a tool later
//! claims about the file.
//!
//! In process memory and bounded: a turn's put and its reply happen in the
//! same process within one turn, which is the only time this is consulted.
//! A later download is authorised by the link's MAC, not by this record.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PutRecord {
    pub mime_type: String,
    pub name: String,
    pub size_bytes: u64,
    /// Unix seconds when the door accepted the bytes.
    pub at: u64,
}

#[derive(Default)]
struct Inner {
    records: HashMap<String, PutRecord>,
    /// Insertion order, oldest first; holds each recorded id exactly once.
    order: VecDeque<String>,
}

#[derive(Default)]
pub(crate) struct RecentPuts {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for RecentPuts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecentPuts")
            .field("len", &self.lock().records.len())
            .finish()
    }
}

impl RecentPuts {
    pub(crate) const CAPACITY: usize = 4096;

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves a consistent map: recover.
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Records `id`; past [`Self::CAPACITY`] the oldest record is evicted. A
    /// second put of the same id replaces the record and makes it newest.
    pub(crate) fn record(&self, id: &str, record: PutRecord) {
        let mut inner = self.lock();
        if inner.records.insert(id.to_string(), record).is_some() {
            inner.order.retain(|known| known != id);
        }
        inner.order.push_back(id.to_string());
        while inner.order.len() > Self::CAPACITY {
            if let Some(oldest) = inner.order.pop_front() {
                inner.records.remove(&oldest);
            }
        }
    }

    /// The record for `id`, unless it is absent or older than `max_age`.
    pub(crate) fn lookup(&self, id: &str, now: u64, max_age: u64) -> Option<PutRecord> {
        let inner = self.lock();
        let record = inner.records.get(id)?;
        (now.saturating_sub(record.at) <= max_age).then(|| record.clone())
    }
}
