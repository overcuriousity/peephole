//! Keeping a flood from one address off the database: a per-source token
//! bucket (IPv6 by /64, see [`crate::net::source_key`]) decides which
//! requests are recorded in full, and a short-lived cache spares the intel
//! lookups for an IP seen moments ago.
use super::config::TrapConfig;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Most addresses tracked at once; an attacker rotating source addresses
/// cannot grow the maps past this.
const MAX_TRACKED: usize = 100_000;

/// Whether to record a request.
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    /// Record it. `unrecorded`: requests from this source answered but not
    /// recorded since its previous recorded one.
    Record { unrecorded: u64 },
    /// Answer it, record nothing (counted for the next recorded request).
    Skip,
}

struct Bucket {
    tokens: f64,
    last: Instant,
    unrecorded: u64,
}

/// Per-source token bucket over recorded requests.
#[derive(Default)]
pub struct FloodGate {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl FloodGate {
    pub fn admit(&self, ip: IpAddr, cfg: &TrapConfig) -> Admission {
        self.admit_at(ip, cfg, Instant::now())
    }

    fn admit_at(&self, ip: IpAddr, cfg: &TrapConfig, now: Instant) -> Admission {
        if cfg.record_rate <= 0.0 {
            return Admission::Record { unrecorded: 0 };
        }
        let ip = crate::net::source_key(ip);
        let burst = f64::from(cfg.record_burst);
        let refill = |b: &Bucket| {
            (b.tokens + now.saturating_duration_since(b.last).as_secs_f64() * cfg.record_rate)
                .min(burst)
        };
        let mut map = self.buckets.lock().unwrap();
        if map.len() >= MAX_TRACKED && !map.contains_key(&ip) {
            // Forget addresses whose bucket is full again and that owe no
            // count; if that is not enough, start over (counts are lost).
            map.retain(|_, b| b.unrecorded > 0 || refill(b) < burst);
            if map.len() >= MAX_TRACKED {
                map.clear();
            }
        }
        let b = map.entry(ip).or_insert(Bucket {
            tokens: burst,
            last: now,
            unrecorded: 0,
        });
        b.tokens = refill(b);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            return Admission::Record {
                unrecorded: std::mem::take(&mut b.unrecorded),
            };
        }
        b.unrecorded += 1;
        if cfg.sample_every > 0 && b.unrecorded >= u64::from(cfg.sample_every) {
            let unrecorded = b.unrecorded - 1;
            b.unrecorded = 0;
            return Admission::Record { unrecorded };
        }
        Admission::Skip
    }

    /// Count a request answered without being recorded for another reason
    /// than its rate (its body did not fit the budget), so the next
    /// recorded one from its source reports it like a skipped one.
    pub fn count_unrecorded(&self, ip: IpAddr, cfg: &TrapConfig) {
        if cfg.record_rate <= 0.0 {
            return;
        }
        let ip = crate::net::source_key(ip);
        let mut map = self.buckets.lock().unwrap();
        if map.len() >= MAX_TRACKED && !map.contains_key(&ip) {
            return;
        }
        let b = map.entry(ip).or_insert(Bucket {
            tokens: f64::from(cfg.record_burst),
            last: Instant::now(),
            unrecorded: 0,
        });
        b.unrecorded += 1;
    }
}

/// How long an intel result written for an IP is trusted to be current.
const INTEL_TTL: Duration = Duration::from_secs(300);

/// Per (IP, provider): the result and when it was recorded.
type IntelMap = HashMap<(IpAddr, &'static str), (serde_json::Value, Instant)>;

/// The last intel result this trap wrote (or found unchanged) per IP and
/// provider, so repeated requests do not read it back every time.
#[derive(Default)]
pub struct IntelCache {
    map: Mutex<IntelMap>,
}

impl IntelCache {
    /// True if `data` is what was recorded for this IP and provider
    /// within the last few minutes.
    pub fn is_current(&self, ip: IpAddr, provider: &'static str, data: &serde_json::Value) -> bool {
        let map = self.map.lock().unwrap();
        map.get(&(ip, provider))
            .is_some_and(|(d, at)| d == data && at.elapsed() < INTEL_TTL)
    }

    pub fn put(&self, ip: IpAddr, provider: &'static str, data: serde_json::Value) {
        let mut map = self.map.lock().unwrap();
        if map.len() >= MAX_TRACKED {
            map.retain(|_, (_, at)| at.elapsed() < INTEL_TTL);
            if map.len() >= MAX_TRACKED {
                map.clear();
            }
        }
        map.insert((ip, provider), (data, Instant::now()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(rate: f64, burst: u32, every: u32) -> TrapConfig {
        TrapConfig {
            record_rate: rate,
            record_burst: burst,
            sample_every: every,
            ..Default::default()
        }
    }

    #[test]
    fn burst_then_sampled_with_counts() {
        let g = FloodGate::default();
        let c = cfg(1.0, 3, 4);
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(g.admit_at(ip, &c, t0), Admission::Record { unrecorded: 0 });
        }
        // Over the limit: 3 skipped, the 4th recorded with the count.
        for _ in 0..3 {
            assert_eq!(g.admit_at(ip, &c, t0), Admission::Skip);
        }
        assert_eq!(g.admit_at(ip, &c, t0), Admission::Record { unrecorded: 3 });
        assert_eq!(g.admit_at(ip, &c, t0), Admission::Skip);
        // Another address has its own bucket.
        let other: IpAddr = "203.0.113.2".parse().unwrap();
        assert_eq!(
            g.admit_at(other, &c, t0),
            Admission::Record { unrecorded: 0 }
        );
        // A token refills after a second; the skipped one is reported.
        let t1 = t0 + Duration::from_millis(1100);
        assert_eq!(g.admit_at(ip, &c, t1), Admission::Record { unrecorded: 1 });
        // An IPv4-mapped address shares the IPv4 bucket.
        let mapped: IpAddr = "::ffff:203.0.113.1".parse().unwrap();
        assert_eq!(g.admit_at(mapped, &c, t1), Admission::Skip);
    }

    #[test]
    fn an_ipv6_64_shares_one_bucket() {
        let g = FloodGate::default();
        let c = cfg(1.0, 2, 0);
        let t0 = Instant::now();
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        assert_eq!(g.admit_at(a, &c, t0), Admission::Record { unrecorded: 0 });
        assert_eq!(g.admit_at(b, &c, t0), Admission::Record { unrecorded: 0 });
        // Rotating within the /64 does not get a fresh bucket.
        for i in 0..100u16 {
            let ip = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 7, i));
            assert_eq!(g.admit_at(ip, &c, t0), Admission::Skip);
        }
        g.count_unrecorded(a, &c);
        assert_eq!(
            g.admit_at(b, &c, t0 + Duration::from_secs(1)),
            Admission::Record { unrecorded: 101 }
        );
        // The next /64 has its own.
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(
            g.admit_at(other, &c, t0),
            Admission::Record { unrecorded: 0 }
        );
        // A count for a source not seen before is kept too.
        let new: IpAddr = "203.0.113.7".parse().unwrap();
        g.count_unrecorded(new, &c);
        assert_eq!(g.admit_at(new, &c, t0), Admission::Record { unrecorded: 1 });
    }

    #[test]
    fn rate_zero_records_everything_and_sample_zero_records_nothing_over() {
        let g = FloodGate::default();
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..1000 {
            assert_eq!(
                g.admit_at(ip, &cfg(0.0, 1, 0), t0),
                Admission::Record { unrecorded: 0 }
            );
        }
        let c = cfg(1.0, 1, 0);
        assert_eq!(g.admit_at(ip, &c, t0), Admission::Record { unrecorded: 0 });
        for _ in 0..1000 {
            assert_eq!(g.admit_at(ip, &c, t0), Admission::Skip);
        }
        assert_eq!(
            g.admit_at(ip, &c, t0 + Duration::from_secs(2)),
            Admission::Record { unrecorded: 1000 }
        );
    }

    #[test]
    fn the_map_stays_bounded() {
        let g = FloodGate::default();
        let c = cfg(1.0, 2, 0);
        let t0 = Instant::now();
        for i in 0..(MAX_TRACKED as u32 + 10) {
            g.admit_at(IpAddr::V4(i.into()), &c, t0);
        }
        assert!(g.buckets.lock().unwrap().len() <= MAX_TRACKED);
    }

    #[test]
    fn intel_cache_matches_value_and_expires() {
        let c = IntelCache::default();
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let v = serde_json::json!({"exit": false});
        assert!(!c.is_current(ip, "tor", &v));
        c.put(ip, "tor", v.clone());
        assert!(c.is_current(ip, "tor", &v));
        assert!(!c.is_current(ip, "tor", &serde_json::json!({"exit": true})));
        assert!(!c.is_current(ip, "geo", &v));
        if let Some(old) = Instant::now().checked_sub(INTEL_TTL + Duration::from_secs(1)) {
            c.map.lock().unwrap().get_mut(&(ip, "tor")).unwrap().1 = old;
            assert!(!c.is_current(ip, "tor", &v));
        }
    }
}
