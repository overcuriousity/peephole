//! Automatic retries of failed scans. A failed job stays failed (the
//! scanner weights and the failure counts read it); its arbiter queues a
//! new job for the same IP and level that names the chain's first failed
//! job. Retries go on until [`WINDOW_HOURS`] after that first failure, or
//! until a scan of the IP at that level or higher succeeds anywhere in the
//! cluster.
//!
//! Each retry waits: [`FIRST_DELAY`], doubling per failure of the chain up
//! to [`MAX_DELAY`], for every scanner (two scanners failing in turn would
//! otherwise retry without pause). The scanner that failed last waits
//! [`LAST_FAILER_WAIT`] longer, so another scanner gets the first try.
use chrono::{DateTime, NaiveDateTime, TimeDelta, Utc};

/// How long after the first failure retries are queued.
pub const WINDOW_HOURS: i64 = 24;
/// The wait before the first retry.
pub const FIRST_DELAY: TimeDelta = TimeDelta::minutes(10);
/// The longest wait between retries.
pub const MAX_DELAY: TimeDelta = TimeDelta::hours(2);
/// Minutes the scanner that failed last waits beyond the retry time.
pub const LAST_FAILER_WAIT: i64 = 30;

/// Whether a failure with this error is worth another try: an invalid
/// target is the job's own fault.
pub fn retryable(error: Option<&str>) -> bool {
    error != Some("invalid target")
}

/// The wait after `failures` failures of a chain (1 for the first).
pub fn delay(failures: i64) -> TimeDelta {
    let doublings = failures.clamp(1, 16) - 1;
    (FIRST_DELAY * 2i32.pow(doublings as u32)).min(MAX_DELAY)
}

/// When the next retry may run, as a stored timestamp: `now` plus the
/// [`delay`] after `failures` failures. None once that falls past the
/// window that opened with the first failure at `first_failed` (or when
/// that time does not parse).
pub fn next_at(first_failed: &str, failures: i64, now: DateTime<Utc>) -> Option<String> {
    let first = NaiveDateTime::parse_from_str(first_failed, "%Y-%m-%d %H:%M:%S")
        .ok()?
        .and_utc();
    let at = now + delay(failures);
    (at <= first + TimeDelta::hours(WINDOW_HOURS))
        .then(|| at.format("%Y-%m-%d %H:%M:%S").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_delay_doubles_up_to_a_ceiling() {
        assert_eq!(delay(1), TimeDelta::minutes(10));
        assert_eq!(delay(2), TimeDelta::minutes(20));
        assert_eq!(delay(4), TimeDelta::minutes(80));
        assert_eq!(delay(5), MAX_DELAY);
        assert_eq!(delay(400), MAX_DELAY);
    }

    #[test]
    fn retries_stop_when_the_window_is_over() {
        let now = NaiveDateTime::parse_from_str("2026-10-07 12:00:00", "%Y-%m-%d %H:%M:%S")
            .unwrap()
            .and_utc();
        assert_eq!(
            next_at("2026-10-07 11:59:00", 1, now).as_deref(),
            Some("2026-10-07 12:10:00")
        );
        // 23 h in: a 2 h wait would end past the window.
        assert_eq!(next_at("2026-10-06 13:00:00", 9, now), None);
        assert!(next_at("2026-10-06 13:00:00", 1, now).is_some());
        assert_eq!(next_at("garbage", 1, now), None);
    }

    #[test]
    fn invalid_targets_are_not_retried() {
        assert!(!retryable(Some("invalid target")));
        assert!(retryable(Some("timeout after 900 s")));
        assert!(retryable(None));
    }
}
