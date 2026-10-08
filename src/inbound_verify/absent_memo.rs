//! A short memory of "this channel has no secret", so an unauthenticated
//! caller cannot make every POST cost a full walk of the secret store (up to
//! eight reads: two names, two spellings, two scopes). Only ABSENT is
//! remembered: a found secret is read on every request (a rotation takes
//! effect at once), and a store failure is never remembered either.
//!
//! The window runs on the MONOTONIC clock, so a wall-clock step (NTP) can
//! neither freeze "absent" nor expire it early.

use std::time::{Duration, Instant};

use dashmap::DashMap;

/// How long "absent" is believed. An operator who adds the secret sees it
/// take effect within this window.
pub(crate) const ABSENT_TTL: Duration = Duration::from_secs(10);
/// Remembered scopes at most; past it the memory is cleared.
pub(crate) const MAX_ENTRIES: usize = 4_096;

#[derive(Default)]
pub(crate) struct AbsentMemo {
    /// Scope key → when absence was observed.
    seen: DashMap<String, Instant>,
}

impl AbsentMemo {
    pub(crate) fn production() -> &'static AbsentMemo {
        static MEMO: std::sync::LazyLock<AbsentMemo> =
            std::sync::LazyLock::new(AbsentMemo::default);
        &MEMO
    }

    /// The memory key for one channel secret lookup.
    pub(crate) fn key(
        env: &str,
        tenant: &str,
        pack_id: &str,
        unit_id: &str,
        names: &[&str],
    ) -> String {
        format!(
            "{env}\u{1f}{tenant}\u{1f}{pack_id}\u{1f}{unit_id}\u{1f}{}",
            names.join(",")
        )
    }

    /// Whether absence was observed for `key` within [`ABSENT_TTL`].
    pub(crate) fn recently_absent(&self, key: &str, now: Instant) -> bool {
        self.seen
            .get(key)
            .is_some_and(|at| now.saturating_duration_since(*at) < ABSENT_TTL)
    }

    pub(crate) fn record(&self, key: String, now: Instant) {
        if self.seen.len() >= MAX_ENTRIES {
            self.seen.clear();
        }
        self.seen.insert(key, now);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.seen.len()
    }
}
