//! Pure refresh schedule for the typing signal. No clock, no I/O: the drivers feed it
//! the time since the FIRST send and the outcome of the send that just finished.

use std::time::Duration;

use super::{MAX_REFRESH, MAX_TYPING, MIN_REFRESH, REFRESH_MARGIN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendOutcome {
    Sent { refresh_after_ms: Option<u64> },
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopReason {
    /// The provider did not ask for a refresh (absent or `0` `refresh_after_ms`).
    NoRefresh,
    /// The send failed; a turn never retries typing.
    Failed,
    /// The next refresh would start at or past `MAX_TYPING` from the first send.
    CapReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Next {
    Refresh(Duration),
    Stop(StopReason),
}

/// `clamp(refresh_after_ms − 500 ms, 1 s, 30 s)`; `None` for absent or `0`.
pub(crate) fn refresh_interval(refresh_after_ms: Option<u64>) -> Option<Duration> {
    let ms = refresh_after_ms.filter(|ms| *ms > 0)?;
    let interval = Duration::from_millis(ms).saturating_sub(REFRESH_MARGIN);
    Some(interval.clamp(MIN_REFRESH, MAX_REFRESH))
}

pub(crate) fn plan_next(elapsed_since_first_send: Duration, outcome: SendOutcome) -> Next {
    let SendOutcome::Sent { refresh_after_ms } = outcome else {
        return Next::Stop(StopReason::Failed);
    };
    let Some(interval) = refresh_interval(refresh_after_ms) else {
        return Next::Stop(StopReason::NoRefresh);
    };
    if elapsed_since_first_send.saturating_add(interval) >= MAX_TYPING {
        return Next::Stop(StopReason::CapReached);
    }
    Next::Refresh(interval)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    #[test]
    fn refresh_interval_table() {
        assert_eq!(refresh_interval(None), None, "absent = do not refresh");
        assert_eq!(refresh_interval(Some(0)), None, "zero = do not refresh");
        assert_eq!(refresh_interval(Some(4000)), Some(ms(3500)));
        assert_eq!(refresh_interval(Some(3000)), Some(ms(2500)));
        assert_eq!(
            refresh_interval(Some(20_000)),
            Some(ms(19_500)),
            "provider value wins below the cap"
        );
        assert_eq!(
            refresh_interval(Some(u64::MAX)),
            Some(ms(30_000)),
            "huge is capped, never overflows"
        );
        assert_eq!(
            refresh_interval(Some(600)),
            Some(ms(1000)),
            "floored, never a hot loop"
        );
        assert_eq!(refresh_interval(Some(1)), Some(ms(1000)));
    }

    #[test]
    fn failure_stops_refreshing() {
        assert_eq!(
            plan_next(ms(0), SendOutcome::Failed),
            Next::Stop(StopReason::Failed)
        );
    }

    #[test]
    fn no_refresh_stops_after_first_send() {
        assert_eq!(
            plan_next(
                ms(0),
                SendOutcome::Sent {
                    refresh_after_ms: None
                }
            ),
            Next::Stop(StopReason::NoRefresh)
        );
    }

    #[test]
    fn cap_stops_refresh_at_120s() {
        let sent = SendOutcome::Sent {
            refresh_after_ms: Some(4000),
        };
        assert_eq!(
            plan_next(ms(115_500), sent),
            Next::Refresh(ms(3500)),
            "119.0 s < cap"
        );
        assert_eq!(
            plan_next(ms(116_500), sent),
            Next::Stop(StopReason::CapReached),
            "120.0 s = cap"
        );
        assert_eq!(
            plan_next(ms(119_000), sent),
            Next::Stop(StopReason::CapReached)
        );
        assert_eq!(
            plan_next(ms(500_000), sent),
            Next::Stop(StopReason::CapReached)
        );
    }
}
