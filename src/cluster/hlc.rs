//! Hybrid logical clock: wall-clock milliseconds in the high 48 bits, a
//! counter in the low 16. Orders last-write-wins updates across nodes even
//! when their clocks disagree slightly.
use std::sync::Mutex;

/// Remote timestamps further ahead than this are not adopted, so one node
/// with a wrong clock cannot drag every other clock into the future.
pub const MAX_DRIFT_MS: u64 = 5 * 60 * 1000;

pub struct Hlc {
    last: Mutex<u64>,
}

pub(crate) fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn physical_ms(hlc: u64) -> u64 {
    hlc >> 16
}

/// The latest HLC a remote entry received at `recv_ms` may carry for
/// ordering: its origin's clock may run ahead by [`MAX_DRIFT_MS`], no more.
pub fn latest_at(recv_ms: u64) -> u64 {
    (recv_ms
        .saturating_add(MAX_DRIFT_MS)
        .min(i64::MAX as u64 >> 16)
        << 16)
        | 0xffff
}

/// The timestamp a remote entry is ordered by (last write wins, liveness):
/// its HLC, but never later than its receipt plus the allowed drift. A
/// member that dates its entries into the future gains nothing, and the
/// value always fits the database's signed 64-bit integers.
pub fn effective(hlc: u64, recv_ms: u64) -> u64 {
    hlc.min(latest_at(recv_ms))
}

/// An HLC as stored in an ordering column (signed in SQLite).
pub fn to_db(hlc: u64) -> i64 {
    hlc.min(i64::MAX as u64) as i64
}

/// An HLC read from an ordering column; negative values (written by a
/// build without clamping) count as 0.
pub fn from_db(v: i64) -> u64 {
    v.max(0) as u64
}

impl Hlc {
    pub const fn new() -> Self {
        Self {
            last: Mutex::new(0),
        }
    }

    /// A timestamp greater than every one issued or observed before.
    pub fn now(&self) -> u64 {
        let mut last = self.last.lock().unwrap();
        let t = (wall_ms() << 16).max(*last + 1);
        *last = t;
        t
    }

    /// Take a remote timestamp into account.
    pub fn observe(&self, remote: u64) {
        if physical_ms(remote) > wall_ms() + MAX_DRIFT_MS {
            return;
        }
        let mut last = self.last.lock().unwrap();
        *last = (*last).max(remote);
    }
}

impl Default for Hlc {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_and_follows_observed_time() {
        let c = Hlc::new();
        let a = c.now();
        let b = c.now();
        assert!(b > a);
        let ahead = (wall_ms() + 1000) << 16;
        c.observe(ahead);
        assert!(c.now() > ahead);
        let far = (wall_ms() + MAX_DRIFT_MS * 10) << 16;
        c.observe(far);
        assert!(c.now() < far, "far-future timestamps are not adopted");
    }

    #[test]
    fn effective_time_is_capped_by_receipt() {
        let now = wall_ms();
        let honest = (now - 1000) << 16;
        assert_eq!(effective(honest, now), honest);
        let future = (now + 400 * 24 * 3600 * 1000) << 16;
        assert!(physical_ms(effective(future, now)) <= now + MAX_DRIFT_MS);
        // Values beyond i64 (which would sort negative) are clamped too.
        assert!(effective(u64::MAX, now) <= i64::MAX as u64);
        assert_eq!(to_db(u64::MAX), i64::MAX);
        assert_eq!(from_db(-5), 0);
    }
}
