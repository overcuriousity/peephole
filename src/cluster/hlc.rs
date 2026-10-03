//! Hybrid logical clock: wall-clock milliseconds in the high 48 bits, a
//! counter in the low 16. Orders last-write-wins updates across nodes even
//! when their clocks disagree slightly.
use std::sync::Mutex;

/// Remote timestamps further ahead than this are not adopted, so one node
/// with a wrong clock cannot drag every other clock into the future; log
/// entries dated further ahead wait until they are not (see [`ahead`]).
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

/// Whether `hlc` lies further than [`MAX_DRIFT_MS`] ahead of `now_ms`. A
/// remote log entry dated like that is not taken yet: its origin's stream
/// waits here until the time comes, and then applies with its own HLC, so
/// every node orders it the same way whenever it arrived. Everything taken
/// therefore fits the database's signed 64-bit integers.
pub fn ahead(hlc: u64, now_ms: u64) -> bool {
    physical_ms(hlc) > now_ms.saturating_add(MAX_DRIFT_MS)
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
        if ahead(remote, wall_ms()) {
            return;
        }
        let mut last = self.last.lock().unwrap();
        *last = (*last).max(remote);
    }

    /// Take a timestamp this node issued itself into account, however far
    /// ahead: its entries must keep rising (peers ignore one that does not)
    /// even after the wall clock was set back.
    pub fn observe_own(&self, own: u64) {
        let mut last = self.last.lock().unwrap();
        *last = (*last).max(own);
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
        c.observe_own(far);
        assert!(c.now() > far, "our own are");
    }

    #[test]
    fn entries_too_far_ahead_wait() {
        let now = 1_000_000_000_000;
        assert!(!ahead(now << 16, now));
        assert!(!ahead(((now + MAX_DRIFT_MS) << 16) | 0xffff, now));
        assert!(ahead((now + MAX_DRIFT_MS + 1) << 16, now));
        assert!(ahead(u64::MAX, now));
        assert_eq!(to_db(u64::MAX), i64::MAX);
        assert_eq!(from_db(-5), 0);
    }
}
