//! A short memory of "this channel has no secret", so an unauthenticated
//! caller cannot make every POST cost a full walk of the secret store (up to
//! eight reads: two names, two spellings, two scopes). Only ABSENT is
//! remembered: a found secret is read on every request (a rotation takes
//! effect at once), and a store failure is never remembered either.

use dashmap::DashMap;

/// How long "absent" is believed, in seconds. An operator who adds the secret
/// sees it take effect within this window.
pub(crate) const ABSENT_TTL_SECS: u64 = 10;
/// Remembered scopes at most; past it the memory is cleared.
pub(crate) const MAX_ENTRIES: usize = 4_096;

#[derive(Default)]
pub(crate) struct AbsentMemo {
    /// Scope key → unix seconds when absence was observed.
    seen: DashMap<String, u64>,
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

    /// Whether absence was observed for `key` within [`ABSENT_TTL_SECS`].
    pub(crate) fn recently_absent(&self, key: &str, now: u64) -> bool {
        self.seen
            .get(key)
            .is_some_and(|at| now.saturating_sub(*at) < ABSENT_TTL_SECS)
    }

    pub(crate) fn record(&self, key: String, now: u64) {
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
