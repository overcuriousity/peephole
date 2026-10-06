//! Light rows for the requests the flood gate answers without recording
//! them in full: time, method and path, buffered per IP and written as one
//! replicated batch. Their rate is limited per source (IPv6 by /64, see
//! [`crate::net::source_key`]), so rotating addresses buys no more rows.

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
}

/// Light rows one source was given in the current second.
struct Rate {
    /// The wall-clock second `in_sec` counts rows for.
    sec: i64,
    in_sec: u32,
    /// The address of its latest row, which requests past the rate are
    /// counted against when their own address has nothing pending.
    last: IpAddr,
    seen: Instant,
}

#[derive(Default)]
struct Buffers {
    pending: HashMap<IpAddr, Pending>,
    /// Per source key.
    rates: HashMap<IpAddr, Rate>,
}

#[derive(Default)]
pub struct SkipLog {
    buffers: Mutex<Buffers>,
}

fn pending(now: Instant) -> Pending {
    Pending {
        rows: vec![],
        dropped: 0,
        opened: now,
    }
}

/// What a light row keeps when its request was answered with a decoy.
#[derive(Debug, Clone)]
pub struct SkipDecoy {
    pub page_token: String,
    pub host: Option<String>,
    pub answer: String,
    pub decoy_v: i64,
    /// The site word it was served under.
    pub site: String,
    /// What an MCP or LLM decoy was rendered from (compact JSON).
    pub decoy_in: Option<String>,
}

/// How a skipped request was answered, as far as its light row keeps it.
pub enum SkipAnswer {
    /// The trap page or another answer a light row does not name.
    Plain,
    /// A decoy. Its light row keeps no `held_ms` (the tarpit's and the
    /// legacy SSE stream's): that stays tarpit-only.
    Decoy(SkipDecoy),
    /// The tarpit, and how long it held the client.
    Tarpit { held_ms: i64 },
}

impl SkipLog {
    /// Note a skipped request. Past `rate` light rows per source and second
    /// (0: no limit) it is only counted, against its own address when that
    /// has rows pending, else against the source's latest address if that
    /// has (else it gets a row after all). Returns the IP's
    /// batch once it is full. The number of addresses buffered is not
    /// capped here: [`SkipLog::take_older`] flushes them all past
    /// [`MAX_TRACKED`].
    #[allow(clippy::too_many_arguments)]
    pub fn note(
        &self,
        ip: IpAddr,
        ts_ms: i64,
        method: &str,
        path: &str,
        answer: SkipAnswer,
        rate: u32,
        now: Instant,
    ) -> Option<Batch> {
        let mut b = self.buffers.lock().unwrap_or_else(|p| p.into_inner());
        let Buffers {
            pending: map,
            rates,
        } = &mut *b;
        let r = rates.entry(crate::net::source_key(ip)).or_insert(Rate {
            sec: i64::MIN,
            in_sec: 0,
            last: ip,
            seen: now,
        });
        r.seen = now;
        let sec = ts_ms.div_euclid(1000);
        if sec != r.sec {
            r.sec = sec;
            r.in_sec = 0;
        }
        // A count needs a row to go with it (the export weighs it onto the
        // batch's last row): with nothing pending to count it against, this
        // one gets a row past the rate, as after every batch taken.
        let to = [ip, r.last].into_iter().find(|a| map.contains_key(a));
        if rate > 0
            && r.in_sec >= rate
            && let Some(to) = to
        {
            map.get_mut(&to).expect("found above").dropped += 1;
            return None;
        }
        r.in_sec += 1;
        r.last = ip;
        let p = map.entry(ip).or_insert_with(|| pending(now));
        let mut row = SkipRow {
            ts_ms,
            method: cut(method, 64).to_string(),
            path: cut(path, SKIP_PATH_MAX).to_string(),
            ..Default::default()
        };
        match answer {
            SkipAnswer::Plain => {}
            SkipAnswer::Decoy(d) => {
                row.page_token = Some(d.page_token);
                row.host = d.host.as_deref().map(|h| cut(h, 255).to_string());
                row.answer = Some(d.answer);
                row.decoy_v = Some(d.decoy_v);
                row.decoy_site = Some(d.site);
                row.decoy_in = d.decoy_in;
            }
            SkipAnswer::Tarpit { held_ms } => {
                row.answer = Some("tarpit".into());
                row.held_ms = Some(held_ms);
            }
        }
        p.rows.push(row);
        if p.rows.len() >= SKIP_BATCH_MAX {
            return map.remove(&ip).map(|p| batch(ip, p));
        }
        None
    }

    /// Take the IP's pending batch (when its next request is recorded).
    pub fn take(&self, ip: IpAddr) -> Option<Batch> {
        let mut b = self.buffers.lock().unwrap_or_else(|p| p.into_inner());
        b.pending.remove(&ip).map(|p| batch(ip, p))
    }

    /// Take every batch opened at least `age` ago (all of them when more
    /// than [`MAX_TRACKED`] addresses are buffered). Forgets the rates of
    /// sources not seen in the last two seconds.
    pub fn take_older(&self, age: Duration, now: Instant) -> Vec<Batch> {
        let mut b = self.buffers.lock().unwrap_or_else(|p| p.into_inner());
        b.rates
            .retain(|_, r| now.saturating_duration_since(r.seen) < Duration::from_secs(2));
        let map = &mut b.pending;
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
            assert!(
                s.note(
                    ip(),
                    1_000_000 + i,
                    "GET",
                    "/x",
                    SkipAnswer::Plain,
                    100,
                    now
                )
                .is_none()
            );
        }
        // The next second has room again.
        assert!(
            s.note(ip(), 1_001_000, "GET", "/y", SkipAnswer::Plain, 100, now)
                .is_none()
        );
        let b = s.take(ip()).unwrap();
        assert_eq!((b.rows.len(), b.dropped), (101, 50));
        assert!(s.take(ip()).is_none());
        // Past the rate with nothing pending (just taken): a row, never a
        // count without one.
        s.note(ip(), 1_001_500, "GET", "/z", SkipAnswer::Plain, 1, now);
        let b = s.take(ip()).unwrap();
        assert_eq!((b.rows.len(), b.dropped), (1, 0));
    }

    #[test]
    fn the_rate_holds_for_a_whole_ipv6_64() {
        let s = SkipLog::default();
        let now = Instant::now();
        let v6 = |i: u16| IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, i));
        for i in 0..150 {
            assert!(
                s.note(
                    v6(i),
                    1_000_000 + i64::from(i),
                    "GET",
                    "/x",
                    SkipAnswer::Plain,
                    100,
                    now
                )
                .is_none()
            );
        }
        // 100 rows, one per address; the rest counted against the latest.
        let rows: usize = (0..150)
            .filter_map(|i| s.take(v6(i)))
            .map(|b| b.rows.len())
            .sum();
        assert_eq!(rows, 100);
        let s = SkipLog::default();
        for i in 0..150 {
            s.note(
                v6(i),
                1_000_000 + i64::from(i),
                "GET",
                "/x",
                SkipAnswer::Plain,
                100,
                now,
            );
        }
        let last = s.take(v6(99)).unwrap();
        assert_eq!((last.rows.len(), last.dropped), (1, 50));
        // Another /64 has its own rate.
        let other: IpAddr = "2001:db8:0:2::1".parse().unwrap();
        s.note(other, 1_000_000, "GET", "/y", SkipAnswer::Plain, 100, now);
        assert_eq!(s.take(other).unwrap().rows.len(), 1);
    }

    #[test]
    fn a_full_batch_is_handed_out_at_the_limit() {
        let s = SkipLog::default();
        let now = Instant::now();
        let mut got = None;
        for i in 0..1000 {
            assert!(got.is_none());
            got = s.note(ip(), i * 1000, "GET", "/x", SkipAnswer::Plain, 0, now);
        }
        assert_eq!(got.unwrap().rows.len(), 1000);
        assert!(s.take(ip()).is_none());
    }

    #[test]
    fn long_paths_are_cut_on_a_char_boundary() {
        let s = SkipLog::default();
        s.note(
            ip(),
            0,
            "GET",
            &"é".repeat(600),
            SkipAnswer::Plain,
            0,
            Instant::now(),
        );
        let b = s.take(ip()).unwrap();
        assert!(b.rows[0].path.len() <= 1024);
        assert!(b.rows[0].path.starts_with('é'));
    }

    #[test]
    fn old_batches_are_taken_and_young_ones_stay() {
        let s = SkipLog::default();
        let t0 = Instant::now();
        s.note(ip(), 0, "GET", "/a", SkipAnswer::Plain, 0, t0);
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        s.note(
            other,
            0,
            "GET",
            "/b",
            SkipAnswer::Plain,
            0,
            t0 + Duration::from_secs(8),
        );
        let old = s.take_older(Duration::from_secs(10), t0 + Duration::from_secs(11));
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].ip, ip());
        assert!(s.take(other).is_some());
    }

    #[test]
    fn a_decoy_light_row_keeps_its_trace() {
        let log = SkipLog::default();
        let ip: IpAddr = "198.51.100.5".parse().unwrap();
        let d = SkipDecoy {
            page_token: "t".into(),
            host: Some("203.0.113.7".into()),
            answer: "decoy:git-config".into(),
            decoy_v: 1,
            site: "shop".into(),
            decoy_in: None,
        };
        log.note(
            ip,
            1_000,
            "GET",
            "/.git/config",
            SkipAnswer::Decoy(d),
            0,
            Instant::now(),
        );
        let b = log.take(ip).unwrap();
        assert_eq!(b.rows[0].page_token.as_deref(), Some("t"));
        assert_eq!(b.rows[0].answer.as_deref(), Some("decoy:git-config"));
        assert_eq!(b.rows[0].decoy_v, Some(1));
        assert_eq!(b.rows[0].held_ms, None);
    }

    #[test]
    fn a_tarpit_light_row_keeps_the_time_held() {
        let log = SkipLog::default();
        let ip: IpAddr = "198.51.100.5".parse().unwrap();
        let t = SkipAnswer::Tarpit { held_ms: 31_000 };
        log.note(ip, 1_000, "GET", "/cgi-bin/x", t, 0, Instant::now());
        let b = log.take(ip).unwrap();
        assert_eq!(b.rows[0].answer.as_deref(), Some("tarpit"));
        assert_eq!(b.rows[0].held_ms, Some(31_000));
        assert_eq!(b.rows[0].page_token, None);
    }
}
