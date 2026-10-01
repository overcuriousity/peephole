//! Hybrid logical clock: wall-clock milliseconds in the high 48 bits, a
//! counter in the low 16. Orders last-write-wins updates across nodes even
//! when their clocks disagree slightly.
use std::sync::Mutex;

/// Remote timestamps further ahead than this are not adopted, so one node
/// with a wrong clock cannot drag every other clock into the future.
const MAX_DRIFT_MS: u64 = 5 * 60 * 1000;

pub struct Hlc {
    last: Mutex<u64>,
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn physical_ms(hlc: u64) -> u64 {
    hlc >> 16
}

impl Hlc {
    pub fn new() -> Self {
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
}
