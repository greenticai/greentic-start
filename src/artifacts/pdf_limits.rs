//! Resource limits of the isolated PDF worker, and their environment overrides.
//!
//! Defaults are sized for small containers (deployed tasks may have 512 MiB to
//! 1 GiB): ONE worker at a time with a 320 MiB data limit. An rlimit bounds
//! the worker process; it does not stop the container's cgroup from OOM-killing
//! the host when host + worker exceed the container's memory, so raise these
//! only together with the container's memory:
//!
//! - `GREENTIC_PDF_WORKER_MEM_MB` — worker `RLIMIT_DATA` in MiB, clamped to
//!   64..=1024 (default 320);
//! - `GREENTIC_PDF_WORKER_SLOTS` — workers running at once, clamped to 1..=4
//!   (default 1).
//!
//! A value that is not a plain non-negative integer is ignored (default).

use std::time::Duration;

use super::limits::MAX_TEXT_CHARS;

/// A PDF with more pages than this yields no text.
pub(crate) const MAX_PDF_PAGES: usize = 300;
pub(crate) const DEFAULT_WORKER_MEM_MB: u64 = 320;
pub(crate) const DEFAULT_WORKER_SLOTS: usize = 1;
const MEM_MB_RANGE: (u64, u64) = (64, 1024);
const SLOTS_RANGE: (usize, usize) = (1, 4);
pub(crate) const MEM_ENV: &str = "GREENTIC_PDF_WORKER_MEM_MB";
pub(crate) const SLOTS_ENV: &str = "GREENTIC_PDF_WORKER_SLOTS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// `RLIMIT_DATA` of the worker, in bytes.
    pub data_bytes: u64,
    /// `RLIMIT_CPU` of the worker, in seconds.
    pub cpu_secs: u64,
    /// Wall-clock deadline, also the longest wait for a free worker slot.
    pub wall: Duration,
    pub max_pages: usize,
    pub max_chars: usize,
}

impl Limits {
    pub(crate) const DEFAULT: Limits = Limits {
        data_bytes: DEFAULT_WORKER_MEM_MB * 1024 * 1024,
        cpu_secs: 15,
        wall: Duration::from_secs(30),
        max_pages: MAX_PDF_PAGES,
        max_chars: MAX_TEXT_CHARS,
    };

    /// [`Limits::DEFAULT`] with a different data limit.
    pub(crate) const fn with_mem_mb(mem_mb: u64) -> Limits {
        Limits {
            data_bytes: mem_mb * 1024 * 1024,
            ..Limits::DEFAULT
        }
    }

    /// The limits this process uses, read from the environment once.
    pub(crate) fn production() -> Limits {
        Limits::with_mem_mb(worker_mem_mb(std::env::var(MEM_ENV).ok().as_deref()))
    }
}

/// Worker data limit in MiB from a raw override.
pub(crate) fn worker_mem_mb(raw: Option<&str>) -> u64 {
    parse(raw).map_or(DEFAULT_WORKER_MEM_MB, |mb| {
        mb.clamp(MEM_MB_RANGE.0, MEM_MB_RANGE.1)
    })
}

/// Concurrent workers from a raw override.
pub(crate) fn worker_slots(raw: Option<&str>) -> usize {
    parse(raw).map_or(DEFAULT_WORKER_SLOTS, |n| {
        usize::try_from(n)
            .unwrap_or(SLOTS_RANGE.1)
            .clamp(SLOTS_RANGE.0, SLOTS_RANGE.1)
    })
}

fn parse(raw: Option<&str>) -> Option<u64> {
    raw?.trim().parse().ok()
}
