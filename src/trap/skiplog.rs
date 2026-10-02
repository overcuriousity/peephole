//! Light rows for the requests the flood gate answers without recording
//! them in full: time, method and path, buffered per IP and written as one
//! replicated batch.

use crate::cluster::record::SkipRow;
use crate::store::data::{SKIP_BATCH_MAX, SKIP_PATH_MAX, cut};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Most addresses buffered at once; past it everything is flushed.
const MAX_TRACKED: usize = 100_000;

/// Skipped requests of one IP, ready to be written.
#[derive(Debug)]
pub struct Batch {
    pub ip: IpAddr,
    /// Requests past the light-row rate, only counted.
    pub dropped: i64,
    pub rows: Vec<SkipRow>,
}

struct Pending {
    rows: Vec<SkipRow>,
    dropped: i64,
    opened: Instant,
    /// The wall-clock second `in_sec` counts rows for.
    sec: i64,
    in_sec: u32,
}

#[derive(Default)]
pub struct SkipLog {
    pending: Mutex<HashMap<IpAddr, Pending>>,
}

impl SkipLog {
    /// Note a skipped request. Past `rate` light rows per IP and second
    /// (0: no limit) it is only counted. Returns the IP's batch once it is
    /// full, or every batch when too many addresses are buffered.
    pub fn note(
        &self,
        ip: IpAddr,
        ts_ms: i64,
        method: &str,
        path: &str,
        rate: u32,
        now: Instant,
    ) -> Option<Batch> {
        let mut map = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let p = map.entry(ip).or_insert(Pending {
            rows: vec![],
            dropped: 0,
            opened: now,
            sec: i64::MIN,
            in_sec: 0,
        });
        let sec = ts_ms.div_euclid(1000);
        if sec != p.sec {
            p.sec = sec;
            p.in_sec = 0;
        }
        if rate > 0 && p.in_sec >= rate {
            p.dropped += 1;
            return None;
        }
        p.in_sec += 1;
        p.rows.push(SkipRow {
            ts_ms,
            method: cut(method, 64).to_string(),
            path: cut(path, SKIP_PATH_MAX).to_string(),
        });
        if p.rows.len() >= SKIP_BATCH_MAX {
            return map.remove(&ip).map(|p| batch(ip, p));
        }
        None
    }

    /// Take the IP's pending batch (when its next request is recorded).
    pub fn take(&self, ip: IpAddr) -> Option<Batch> {
        let mut map = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        map.remove(&ip).map(|p| batch(ip, p))
    }

    /// Take every batch opened at least `age` ago (all of them when more
    /// than [`MAX_TRACKED`] addresses are buffered).
    pub fn take_older(&self, age: Duration, now: Instant) -> Vec<Batch> {
        let mut map = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let all = map.len() > MAX_TRACKED;
        let due: Vec<IpAddr> = map
            .iter()
            .filter(|(_, p)| all || now.saturating_duration_since(p.opened) >= age)
            .map(|(ip, _)| *ip)
            .collect();
        due.into_iter()
            .filter_map(|ip| map.remove(&ip).map(|p| batch(ip, p)))
            .collect()
    }
}

fn batch(ip: IpAddr, p: Pending) -> Batch {
    Batch {
        ip,
        dropped: p.dropped,
        rows: p.rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn ip() -> IpAddr {
        "192.0.2.1".parse().unwrap()
    }

    #[test]
    fn rows_past_the_rate_in_one_second_are_only_counted() {
        let s = SkipLog::default();
        let now = Instant::now();
        for i in 0..150 {
            assert!(s.note(ip(), 1_000_000 + i, "GET", "/x", 100, now).is_none());
        }
        // The next second has room again.
        assert!(s.note(ip(), 1_001_000, "GET", "/y", 100, now).is_none());
        let b = s.take(ip()).unwrap();
        assert_eq!((b.rows.len(), b.dropped), (101, 50));
        assert!(s.take(ip()).is_none());
    }

    #[test]
    fn a_full_batch_is_handed_out_at_the_limit() {
        let s = SkipLog::default();
        let now = Instant::now();
        let mut got = None;
        for i in 0..1000 {
            assert!(got.is_none());
            got = s.note(ip(), i * 1000, "GET", "/x", 0, now);
        }
        assert_eq!(got.unwrap().rows.len(), 1000);
        assert!(s.take(ip()).is_none());
    }

    #[test]
    fn long_paths_are_cut_on_a_char_boundary() {
        let s = SkipLog::default();
        s.note(ip(), 0, "GET", &"é".repeat(600), 0, Instant::now());
        let b = s.take(ip()).unwrap();
        assert!(b.rows[0].path.len() <= 1024);
        assert!(b.rows[0].path.starts_with('é'));
    }

    #[test]
    fn old_batches_are_taken_and_young_ones_stay() {
        let s = SkipLog::default();
        let t0 = Instant::now();
        s.note(ip(), 0, "GET", "/a", 0, t0);
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        s.note(other, 0, "GET", "/b", 0, t0 + Duration::from_secs(8));
        let old = s.take_older(Duration::from_secs(10), t0 + Duration::from_secs(11));
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].ip, ip());
        assert!(s.take(other).is_some());
    }
}
