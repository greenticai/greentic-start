//! When a cron trigger is due, evaluated in its own timezone (contract
//! §6.3.1). Pure, so DST and window edges are testable without a clock.

use chrono::{DateTime, Utc};

/// The LATEST tick of `schedule` in `(after, upto]`, evaluated in `tz`.
///
/// Only the latest, never a backlog: a scheduler loop that fell behind (a
/// stalled runtime, a suspended container) fires once for the window it
/// missed rather than replaying every tick — the contract's no-catch-up rule
/// applied inside a running host as well as across restarts.
pub(crate) fn latest_due(
    schedule: &cron::Schedule,
    tz: chrono_tz::Tz,
    after: DateTime<Utc>,
    upto: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if upto <= after {
        return None;
    }
    schedule
        .after(&after.with_timezone(&tz))
        .map(|t| t.with_timezone(&Utc))
        .take_while(|t| *t <= upto)
        .last()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::str::FromStr;

    fn schedule(expr: &str) -> cron::Schedule {
        cron::Schedule::from_str(expr).unwrap()
    }

    #[test]
    fn a_tick_inside_the_window_is_due() {
        let s = schedule("0 */15 * * * *");
        let after = Utc.with_ymd_and_hms(2026, 9, 22, 10, 14, 59).unwrap();
        let upto = Utc.with_ymd_and_hms(2026, 9, 22, 10, 15, 0).unwrap();
        assert_eq!(latest_due(&s, chrono_tz::UTC, after, upto), Some(upto));
    }

    #[test]
    fn the_window_is_half_open_so_a_tick_is_never_fired_twice() {
        let s = schedule("0 */15 * * * *");
        let tick = Utc.with_ymd_and_hms(2026, 9, 22, 10, 15, 0).unwrap();
        let next = Utc.with_ymd_and_hms(2026, 9, 22, 10, 15, 1).unwrap();
        assert_eq!(latest_due(&s, chrono_tz::UTC, tick, next), None);
    }

    #[test]
    fn a_lagging_loop_fires_only_the_latest_missed_tick() {
        let s = schedule("0 * * * * *");
        let after = Utc.with_ymd_and_hms(2026, 9, 22, 10, 0, 30).unwrap();
        let upto = Utc.with_ymd_and_hms(2026, 9, 22, 10, 5, 30).unwrap();
        assert_eq!(
            latest_due(&s, chrono_tz::UTC, after, upto),
            Some(Utc.with_ymd_and_hms(2026, 9, 22, 10, 5, 0).unwrap())
        );
    }

    #[test]
    fn nine_am_means_local_time_in_the_declared_zone() {
        // 09:00 Europe/Amsterdam on 2026-09-22 (CEST, UTC+2) is 07:00 UTC.
        let s = schedule("0 0 9 * * *");
        let after = Utc.with_ymd_and_hms(2026, 9, 22, 6, 59, 59).unwrap();
        let upto = Utc.with_ymd_and_hms(2026, 9, 22, 7, 0, 0).unwrap();
        assert_eq!(
            latest_due(&s, chrono_tz::Europe::Amsterdam, after, upto),
            Some(upto)
        );
        // …and in winter (CET, UTC+1) the same expression is 08:00 UTC.
        let after = Utc.with_ymd_and_hms(2026, 12, 1, 7, 59, 59).unwrap();
        let upto = Utc.with_ymd_and_hms(2026, 12, 1, 8, 0, 0).unwrap();
        assert_eq!(
            latest_due(&s, chrono_tz::Europe::Amsterdam, after, upto),
            Some(upto)
        );
    }

    #[test]
    fn an_empty_or_inverted_window_is_never_due() {
        let s = schedule("* * * * * *");
        let t = Utc.with_ymd_and_hms(2026, 9, 22, 10, 0, 0).unwrap();
        assert_eq!(latest_due(&s, chrono_tz::UTC, t, t), None);
    }
}
