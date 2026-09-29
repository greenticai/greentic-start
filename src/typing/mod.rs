//! Channel "is typing" signal (typing-signal contract v1). Cosmetic: nothing here may
//! fail, delay a reply beyond `STOP_GRACE`, or alter a turn. See docs/typing-signal.md.

use std::time::Duration;

mod driver;
mod dto;
mod schedule;

pub(crate) use driver::{
    BlockingTypingSender, TypingSender, keep_typing_blocking, keep_typing_while,
};
pub(crate) use dto::{SendTypingInV1, SendTypingOutV1};

/// The OPTIONAL provider op. The host calls it only when the provider declares it.
pub(crate) const TYPING_OP: &str = "send_typing";
/// No refresh starts at or past this, measured from the FIRST send.
pub(crate) const MAX_TYPING: Duration = Duration::from_secs(120);
/// Upper clamp on the refresh interval.
pub(crate) const MAX_REFRESH: Duration = Duration::from_millis(30_000);
/// The host re-sends this long before the provider's indicator lapses.
pub(crate) const REFRESH_MARGIN: Duration = Duration::from_millis(500);
/// Lower clamp on the refresh interval, so a tiny value cannot become a hot loop.
pub(crate) const MIN_REFRESH: Duration = Duration::from_millis(1000);
/// Longest a finished turn waits for an in-flight `send_typing` before its reply.
pub(crate) const STOP_GRACE: Duration = Duration::from_secs(2);
/// Kill switch. Default on; `0`/`false`/`no`/`off` disable every typing call.
pub(crate) const KILL_SWITCH_ENV: &str = "GREENTIC_TYPING_SIGNAL";

pub(crate) fn enabled() -> bool {
    enabled_from(std::env::var(KILL_SWITCH_ENV).ok().as_deref())
}

/// Same trimmed, case-insensitive match as `post_ingress_hooks::hooks_enabled`.
pub(crate) fn enabled_from(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            !matches!(normalized.as_str(), "0" | "false" | "no" | "off")
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn kill_switch_values() {
        use super::enabled_from as on;
        assert!(on(None));
        for v in ["1", "true", "yes", "", "anything"] {
            assert!(on(Some(v)), "{v}");
        }
        for v in ["0", "false", "no", "off", " OFF ", "False"] {
            assert!(!on(Some(v)), "{v}");
        }
    }
}
