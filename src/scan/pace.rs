//! Runtime scan pacing: how many nmap workers run at once and how many scans
//! may start per hour. Defaults come from `[scan]` in the config; the admin
//! Scans page can override both at runtime (persisted in the `settings` table).
//!
//! The queue metrics feed [`recommend`], which sizes the pace so the queue
//! keeps up with arrivals and drains any backlog within a day.
use crate::config::ScanConfig;
use crate::store::Store;
use anyhow::Result;
use std::sync::{Arc, RwLock};

/// Upper bound for workers settable from the admin UI (nmap -sS/-O is heavy).
pub const MAX_WORKERS: usize = 16;
/// Fewest workers a scanning node runs: one may run a level-4 scan while
/// the other keeps the shorter levels moving (0 still pauses).
pub const MIN_WORKERS: usize = 2;

/// Level-4 scans one scanner runs at once: `share` of its workers, rounded
/// down, but at least one while it scans at all.
pub fn level4_cap(workers: usize, share: f64) -> usize {
    if workers == 0 {
        return 0;
    }
    ((workers as f64 * share).floor() as usize).clamp(1, workers)
}

/// Upper bound for the hourly start cap settable from the admin UI.
pub const MAX_PER_HOUR: i64 = 3600;
/// Assumed scan duration until enough scans have finished to measure it.
pub const DEFAULT_SCAN_SECS: f64 = 180.0;
/// Headroom over the measured arrival rate so short bursts don't pile up.
const HEADROOM: f64 = 1.25;
/// Horizon over which a recommendation drains the current backlog.
const DRAIN_HOURS: f64 = 24.0;
/// Window over which the queue's actual inflow and outflow are measured
/// for the drain estimate: recent enough to follow a pace change.
pub const DRAIN_WINDOW_HOURS: i64 = 6;

/// Per-scan wall-clock limit bounds settable from the admin UI.
pub const MIN_TIMEOUT: u64 = 60;
pub const MAX_TIMEOUT: u64 = 4 * 3600;
/// Longest any one scan may run: the level-4 limit is capped here.
pub const MAX_RUN_SECS: u64 = 12 * 3600;
/// A job marked running for longer than this is dead (no scan runs past
/// [`MAX_RUN_SECS`]): it neither shields its IP nor blocks a takeover.
pub const STALE_RUNNING_HOURS: u64 = MAX_RUN_SECS / 3600 + 1;
/// Bounds of `scan.level4_timeout_factor`.
pub const MAX_LEVEL4_FACTOR: u32 = 12;

/// Wall-clock limit of one scan at `level`. Level 4 scans every port with
/// version, OS and script detection and needs far longer than the others,
/// so it gets `level4_factor` times the base limit, capped at
/// [`MAX_RUN_SECS`].
pub fn level_timeout_secs(base: u64, level: u8, level4_factor: u32) -> u64 {
    if level >= 4 {
        base.saturating_mul(level4_factor.max(1) as u64)
            .min(MAX_RUN_SECS)
            .max(base)
    } else {
        base
    }
}

/// Share of finished scans that may time out before a longer limit is advised.
const TIMEOUT_SHARE: f64 = 0.10;

pub const KEY_WORKERS: &str = "scan.max_workers";
pub const KEY_PER_HOUR: &str = "scan.max_scans_per_hour";
pub const KEY_TIMEOUT: &str = "scan.timeout_secs";

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Pace {
    /// Concurrent nmap processes. 0 pauses scanning.
    pub max_workers: usize,
    /// Scans started per rolling hour; starts are spaced evenly. 0 pauses.
    pub max_scans_per_hour: i64,
    /// Wall-clock limit per nmap run; the process is killed after it.
    pub timeout_secs: u64,
}

impl Pace {
    pub fn from_config(c: &ScanConfig) -> Self {
        Self {
            max_workers: c.max_workers,
            max_scans_per_hour: c.max_scans_per_hour,
            timeout_secs: c.timeout_secs,
        }
    }

    pub fn paused(&self) -> bool {
        self.max_workers == 0 || self.max_scans_per_hour <= 0
    }

    /// Minimum gap between two scan starts, or None when paused.
    pub fn interval(&self) -> Option<std::time::Duration> {
        (!self.paused())
            .then(|| std::time::Duration::from_secs_f64(3600.0 / self.max_scans_per_hour as f64))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.max_workers != 0 && !(MIN_WORKERS..=MAX_WORKERS).contains(&self.max_workers) {
            return Err(format!(
                "workers must be 0 or between {MIN_WORKERS} and {MAX_WORKERS}"
            ));
        }
        if !(0..=MAX_PER_HOUR).contains(&self.max_scans_per_hour) {
            return Err(format!(
                "scans per hour must be between 0 and {MAX_PER_HOUR}"
            ));
        }
        if !(MIN_TIMEOUT..=MAX_TIMEOUT).contains(&self.timeout_secs) {
            return Err(format!(
                "timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds"
            ));
        }
        Ok(())
    }
}

/// Shared between the admin UI (writer) and the scan workers (reader): the
/// scan pace, and the rescan cooldown that trap and scanners apply.
#[derive(Clone)]
pub struct SharedPace(Arc<RwLock<Pace>>, Arc<std::sync::atomic::AtomicI64>);

impl SharedPace {
    pub fn new(p: Pace) -> Self {
        Self(
            Arc::new(RwLock::new(p)),
            Arc::new(std::sync::atomic::AtomicI64::new(24)),
        )
    }

    /// Hours within which an IP is not scanned again at the same level.
    pub fn cooldown_hours(&self) -> i64 {
        self.1.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_cooldown_hours(&self, h: i64) {
        self.1.store(h, std::sync::atomic::Ordering::Relaxed);
    }

    /// Replace the pace in memory (persisting is the caller's business).
    pub fn replace(&self, p: Pace) {
        *self.0.write().unwrap() = p;
    }

    /// Config defaults overridden by whatever the admin saved earlier.
    pub async fn load(store: &Store, c: &ScanConfig) -> Result<Self> {
        let mut p = Pace::from_config(c);
        if let Some(v) = store
            .setting_get(KEY_WORKERS)
            .await?
            .and_then(|v| v.parse().ok())
        {
            p.max_workers = v;
        }
        // Saved before the minimum existed (e.g. an applied recommendation).
        if p.max_workers == 1 {
            p.max_workers = MIN_WORKERS;
        }
        if let Some(v) = store
            .setting_get(KEY_PER_HOUR)
            .await?
            .and_then(|v| v.parse().ok())
        {
            p.max_scans_per_hour = v;
        }
        if let Some(v) = store
            .setting_get(KEY_TIMEOUT)
            .await?
            .and_then(|v| v.parse().ok())
        {
            p.timeout_secs = v;
        }
        if p.validate().is_err() {
            p = Pace::from_config(c);
        }
        let s = Self::new(p);
        s.set_cooldown_hours(c.rescan_cooldown_hours);
        Ok(s)
    }

    pub fn get(&self) -> Pace {
        *self.0.read().unwrap()
    }

    /// Validate, persist and apply. Workers pick it up on their next pass.
    pub async fn set(&self, store: &Store, p: Pace) -> Result<Result<(), String>> {
        if let Err(e) = p.validate() {
            return Ok(Err(e));
        }
        store
            .setting_set(KEY_WORKERS, &p.max_workers.to_string())
            .await?;
        store
            .setting_set(KEY_PER_HOUR, &p.max_scans_per_hour.to_string())
            .await?;
        store
            .setting_set(KEY_TIMEOUT, &p.timeout_secs.to_string())
            .await?;
        *self.0.write().unwrap() = p;
        Ok(Ok(()))
    }
}

/// Raw queue measurements (see `Store::queue_metrics`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QueueMetrics {
    pub backlog: i64,
    pub running: i64,
    pub arrivals_1h: i64,
    pub arrivals_24h: i64,
    pub completed_1h: i64,
    pub completed_24h: i64,
    /// Failed / timed-out jobs among `completed_24h`.
    pub failed_24h: i64,
    pub timeouts_24h: i64,
    /// Jobs queued within the last [`DRAIN_WINDOW_HOURS`].
    pub arrivals_recent: i64,
    /// Jobs that left the queue for good (done, failed, refused,
    /// superseded) within the last [`DRAIN_WINDOW_HOURS`].
    pub left_recent: i64,
    /// Hours the 24h window actually covers (a fresh install has less), >= 1.
    pub observed_hours: f64,
    /// Mean seconds a job held a worker (done, failed or timed out), last 7 days.
    pub avg_scan_secs: Option<f64>,
    pub oldest_queued_secs: Option<i64>,
    /// Per hour, oldest first, 24 entries.
    pub hourly_arrivals: Vec<i64>,
    pub hourly_completions: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Recommendation {
    /// Jobs queued per hour, averaged over the observed window.
    pub arrival_per_hour: f64,
    /// Jobs the cluster's scanners can finish per hour at their current
    /// paces (this node's and the other live scanners').
    pub capacity_per_hour: f64,
    /// This node's part of `capacity_per_hour`.
    pub own_capacity_per_hour: f64,
    /// Scanners counted in `capacity_per_hour`, this node included.
    pub scanners: usize,
    /// Jobs that actually left the queue per hour, measured over
    /// [`DRAIN_WINDOW_HOURS`].
    pub throughput_per_hour: f64,
    /// Positive: the outstanding jobs (queued and running) grew by this
    /// much per hour over [`DRAIN_WINDOW_HOURS`] (arrivals minus jobs that
    /// left), measured rather than derived from the paces.
    pub net_growth_per_hour: f64,
    /// Hours until the outstanding jobs are gone if the measured drain
    /// continues; None = never (not draining).
    pub drain_hours: Option<f64>,
    pub scan_secs: f64,
    pub scan_secs_measured: bool,
    /// Share of jobs finished in the last 24h that hit the timeout.
    pub timeout_share: f64,
    pub pace: Pace,
}

impl Recommendation {
    pub fn growing(&self) -> bool {
        self.net_growth_per_hour > 0.0
    }
    /// Seconds between scan starts at the recommended pace.
    pub fn cadence_secs(&self) -> Option<f64> {
        self.pace.interval().map(|d| d.as_secs_f64())
    }
}

/// Jobs one pace can finish per hour: the lower of the start cap and what
/// the workers can physically get through at the given scan duration.
pub fn capacity(p: Pace, scan_secs: f64) -> f64 {
    if p.paused() {
        return 0.0;
    }
    (p.max_scans_per_hour as f64).min(p.max_workers as f64 * 3600.0 / scan_secs.max(1.0))
}

/// Capacity of the cluster's other live scanners.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Others {
    pub capacity_per_hour: f64,
    pub scanners: usize,
}

/// What the other live scanners of this node's cluster can finish per
/// hour, from the paces they announce in heartbeats. The queue is shared,
/// so its arrivals are the cluster's and so must be the capacity.
pub fn others(node: &crate::cluster::Node, scan_secs: f64) -> Others {
    let me = node.id();
    let mut o = Others::default();
    for id in node.live_members(crate::scan::arbiter::LIVE_WINDOW) {
        if id == me || node.is_blocked(&id) {
            continue;
        }
        let Some(k) = node.status.known(&id) else {
            continue;
        };
        if !k.hb.roles.iter().any(|r| r == "scanner") {
            continue;
        }
        if let Some(p) = k.hb.pace {
            let p = Pace {
                max_workers: p.max_workers as usize,
                max_scans_per_hour: p.max_scans_per_hour,
                timeout_secs: p.timeout_secs,
            };
            o.capacity_per_hour += capacity(p, scan_secs);
            // A paused scanner takes no share.
            if !p.paused() {
                o.scanners += 1;
            }
        }
    }
    o
}

/// Size the pace to absorb arrivals with headroom and drain the backlog
/// within [`DRAIN_HOURS`], never below one scan per hour and [`MIN_WORKERS`] workers.
/// When more than [`TIMEOUT_SHARE`] of recent scans hit the limit, the
/// timeout is raised by half (rounded up to a minute) and the worker count
/// is sized for scans that may take that long. In a cluster, capacity
/// counts `others` too, and the recommendation is this node's even share
/// of what the cluster needs.
pub fn recommend(m: &QueueMetrics, current: Pace, others: Others) -> Recommendation {
    let timeout_share = if m.completed_24h > 0 {
        m.timeouts_24h as f64 / m.completed_24h as f64
    } else {
        0.0
    };
    let timeout_secs = if m.completed_24h >= 3 && timeout_share > TIMEOUT_SHARE {
        (current.timeout_secs * 3 / 2).div_ceil(60) * 60
    } else {
        current.timeout_secs
    }
    .clamp(MIN_TIMEOUT, MAX_TIMEOUT);
    let measured = m
        .avg_scan_secs
        .unwrap_or(DEFAULT_SCAN_SECS)
        .clamp(1.0, current.timeout_secs.max(1) as f64);
    // Timed-out scans would have run longer: budget them at the new limit.
    let scan_secs = measured * (1.0 - timeout_share) + timeout_secs as f64 * timeout_share;
    let arrival = m.arrivals_24h as f64 / m.observed_hours.clamp(1.0, 24.0);
    let own = capacity(current, measured);
    let cap_now = own + others.capacity_per_hour;
    // The drain estimate measures the queue rather than modelling it:
    // what came in and what left over the recent window. Jobs that are
    // refused, superseded or fail count as leaving, and scanners that sit
    // idle or are slower than their pace show up as they are.
    let window = m.observed_hours.clamp(1.0, DRAIN_WINDOW_HOURS as f64);
    let throughput = m.left_recent as f64 / window;
    let net = (m.arrivals_recent - m.left_recent) as f64 / window;
    let drain_hours = match m.backlog + m.running {
        0 => Some(0.0),
        b if net < 0.0 => Some(b as f64 / -net),
        _ => None,
    };

    let target = (arrival * HEADROOM + m.backlog as f64 / DRAIN_HOURS).ceil();
    // Split evenly over the live scanners, this one included: every node
    // gets the same share whatever the others run at now, so applying the
    // recommendations anywhere, in any order, settles at once.
    let target = (target / (others.scanners + 1) as f64).ceil().max(1.0);
    let workers = ((target * scan_secs / 3600.0).ceil() as usize).clamp(MIN_WORKERS, MAX_WORKERS);
    let per_hour = (target as i64).clamp(1, MAX_PER_HOUR);
    Recommendation {
        arrival_per_hour: arrival,
        capacity_per_hour: cap_now,
        own_capacity_per_hour: own,
        scanners: others.scanners + 1,
        throughput_per_hour: throughput,
        net_growth_per_hour: net,
        drain_hours,
        scan_secs,
        scan_secs_measured: m.avg_scan_secs.is_some(),
        timeout_share,
        pace: Pace {
            max_workers: workers,
            max_scans_per_hour: per_hour,
            timeout_secs,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_four_gets_its_own_limit() {
        assert_eq!(level_timeout_secs(1800, 1, 4), 1800);
        assert_eq!(level_timeout_secs(1800, 3, 4), 1800);
        assert_eq!(level_timeout_secs(1800, 4, 4), 7200);
        assert_eq!(level_timeout_secs(1800, 4, 1), 1800);
        // Capped, and never below the base limit.
        assert_eq!(level_timeout_secs(MAX_TIMEOUT, 4, 12), MAX_RUN_SECS);
        assert_eq!(level_timeout_secs(1800, 4, 0), 1800);
        const { assert!(STALE_RUNNING_HOURS * 3600 > MAX_RUN_SECS) };
    }

    fn m(backlog: i64, arrivals_24h: i64, scan_secs: Option<f64>) -> QueueMetrics {
        QueueMetrics {
            backlog,
            arrivals_24h,
            observed_hours: 24.0,
            avg_scan_secs: scan_secs,
            ..Default::default()
        }
    }
    const P: Pace = Pace {
        max_workers: 2,
        max_scans_per_hour: 30,
        timeout_secs: 900,
    };

    #[test]
    fn other_scanners_count_toward_capacity_and_the_need_is_split_evenly() {
        let o = Others {
            capacity_per_hour: 20.0,
            scanners: 1,
        };
        // 240/day = 10/h arrivals, no backlog, 300 s scans.
        let r = recommend(&m(0, 240, Some(300.0)), P, o);
        assert_eq!(r.own_capacity_per_hour, 24.0);
        assert_eq!(r.capacity_per_hour, 44.0);
        assert_eq!(r.scanners, 2);
        // target 10 × 1.25 = 12.5 → 13, over two scanners → 7 each,
        // whatever the other one runs at now.
        assert_eq!(r.pace.max_scans_per_hour, 7);
        assert_eq!(r.pace.max_workers, MIN_WORKERS);
        let o = Others {
            capacity_per_hour: 5.0,
            scanners: 1,
        };
        assert_eq!(
            recommend(&m(0, 240, Some(300.0)), P, o)
                .pace
                .max_scans_per_hour,
            7
        );
    }

    /// Every node applying its recommendation at once lands on the same
    /// split: nothing swings back and forth.
    #[test]
    fn applying_everywhere_at_once_is_stable() {
        let mut paces = [P, P, P];
        for _ in 0..3 {
            let next: Vec<Pace> = (0..3)
                .map(|i| {
                    let others = Others {
                        capacity_per_hour: (0..3)
                            .filter(|j| *j != i)
                            .map(|j| capacity(paces[j], 300.0))
                            .sum(),
                        scanners: 2,
                    };
                    recommend(&m(0, 24 * 30, Some(300.0)), paces[i], others).pace
                })
                .collect();
            paces = [next[0], next[1], next[2]];
        }
        // 30/h × 1.25 = 37.5 → 38, over three → 13 each, every round.
        assert!(paces.iter().all(|p| p.max_scans_per_hour == 13));
    }

    #[test]
    fn alone_is_unchanged() {
        let a = recommend(&m(480, 240, Some(300.0)), P, Others::default());
        assert_eq!(a.capacity_per_hour, 24.0);
        assert_eq!(a.scanners, 1);
    }

    #[test]
    fn capacity_is_bounded_by_cap_and_by_workers() {
        assert_eq!(capacity(P, 60.0), 30.0); // workers could do 120/h
        assert_eq!(capacity(P, 600.0), 12.0); // 2 × 6/h
        assert_eq!(
            capacity(
                Pace {
                    max_workers: 0,
                    ..P
                },
                60.0
            ),
            0.0
        );
    }

    #[test]
    fn keeps_up_with_arrivals_and_drains_backlog_in_a_day() {
        // 240 arrivals/day = 10/h; backlog 480 → +20/h; ×1.25 headroom on arrivals.
        let r = recommend(&m(480, 240, Some(300.0)), P, Others::default());
        assert_eq!(r.arrival_per_hour, 10.0);
        assert_eq!(r.pace.max_scans_per_hour, 33); // ceil(12.5 + 20)
        assert_eq!(r.pace.max_workers, 3); // 33 × 300s / 3600 = 2.75
        assert_eq!(r.capacity_per_hour, 24.0); // 2 workers × 12/h
        assert!(r.scan_secs_measured);
    }

    #[test]
    fn growing_queue_raises_the_pace() {
        let r = recommend(&m(100, 24 * 50, None), P, Others::default());
        assert_eq!(r.scan_secs, DEFAULT_SCAN_SECS);
        assert!(r.pace.max_scans_per_hour > 50);
    }

    /// The drain estimate follows what actually left the queue, not what
    /// the paces would allow.
    #[test]
    fn drain_is_measured_from_the_queue() {
        let mut q = m(90, 240, Some(300.0));
        q.running = 10;
        // 6 h window: 30 in, 90 out → −10/h; 100 outstanding → 10 h.
        q.arrivals_recent = 30;
        q.left_recent = 90;
        let r = recommend(&q, P, Others::default());
        assert_eq!(r.throughput_per_hour, 15.0);
        assert_eq!(r.net_growth_per_hour, -10.0);
        assert!(!r.growing());
        assert_eq!(r.drain_hours, Some(10.0));
        // The paces would allow 24/h, but nothing left: it never drains.
        q.left_recent = 0;
        let r = recommend(&q, P, Others::default());
        assert!(r.growing());
        assert_eq!(r.drain_hours, None);
        // A young install measures over the hours it has.
        q.observed_hours = 2.0;
        q.left_recent = 60;
        let r = recommend(&q, P, Others::default());
        assert_eq!(r.net_growth_per_hour, -15.0);
        // Nothing outstanding: empty, whatever the rates.
        let r = recommend(&m(0, 0, None), P, Others::default());
        assert_eq!(r.drain_hours, Some(0.0));
    }

    #[test]
    fn idle_queue_recommends_the_minimum() {
        let r = recommend(&m(0, 0, None), P, Others::default());
        assert_eq!(
            r.pace,
            Pace {
                max_workers: MIN_WORKERS,
                max_scans_per_hour: 1,
                timeout_secs: 900,
            }
        );
        assert_eq!(r.drain_hours, Some(0.0));
    }

    #[test]
    fn short_observation_window_is_not_diluted() {
        let mut q = m(0, 20, Some(60.0));
        q.observed_hours = 2.0;
        assert_eq!(recommend(&q, P, Others::default()).arrival_per_hour, 10.0);
    }

    #[test]
    fn workers_are_capped() {
        let r = recommend(&m(0, 24 * 1000, Some(900.0)), P, Others::default());
        assert_eq!(r.pace.max_workers, MAX_WORKERS);
    }

    #[test]
    fn frequent_timeouts_raise_the_limit_and_the_workers() {
        let mut q = m(0, 24 * 10, Some(300.0));
        q.completed_24h = 20;
        q.timeouts_24h = 5; // 25% hit the 900 s limit
        let r = recommend(&q, P, Others::default());
        assert_eq!(r.timeout_share, 0.25);
        assert_eq!(r.pace.timeout_secs, 1380); // 1350 rounded up to a minute
        // 75% × 300 s + 25% × 1380 s = 570 s per job; 13/h needs 3 workers.
        assert_eq!(r.scan_secs, 570.0);
        assert_eq!(r.pace.max_workers, 3);

        q.timeouts_24h = 1; // 5%: below the threshold
        assert_eq!(recommend(&q, P, Others::default()).pace.timeout_secs, 900);
    }

    #[test]
    fn validation_and_interval() {
        assert!(
            Pace {
                timeout_secs: 30,
                ..P
            }
            .validate()
            .is_err()
        );
        assert!(
            Pace {
                max_workers: 17,
                ..P
            }
            .validate()
            .is_err()
        );
        assert!(
            Pace {
                max_scans_per_hour: -1,
                ..P
            }
            .validate()
            .is_err()
        );
        assert_eq!(P.interval(), Some(std::time::Duration::from_secs(120)));
        assert_eq!(
            Pace {
                max_scans_per_hour: 0,
                ..P
            }
            .interval(),
            None
        );
    }

    #[test]
    fn one_worker_is_not_a_valid_pace() {
        let one = Pace { max_workers: 1, ..P };
        assert!(one.validate().unwrap_err().contains("0 or between 2"));
        assert!(Pace { max_workers: 0, ..P }.validate().is_ok(), "0 pauses");
        assert!(Pace { max_workers: 2, ..P }.validate().is_ok());
    }

    #[test]
    fn recommendations_never_go_below_two_workers() {
        let r = recommend(&m(0, 0, None), P, Others::default());
        assert_eq!(r.pace.max_workers, MIN_WORKERS);
    }

    #[test]
    fn level4_cap_is_half_the_workers_and_at_least_one() {
        assert_eq!(level4_cap(2, 0.5), 1);
        assert_eq!(level4_cap(3, 0.5), 1);
        assert_eq!(level4_cap(4, 0.5), 2);
        assert_eq!(level4_cap(16, 0.5), 8);
        assert_eq!(level4_cap(2, 0.1), 1, "never 0 while scanning");
        assert_eq!(level4_cap(2, 1.0), 2);
        assert_eq!(level4_cap(0, 0.5), 0, "paused");
    }

    /// Review focus 1: a stored 1 from before the minimum is raised to 2;
    /// the other saved values survive.
    #[tokio::test]
    async fn a_stored_single_worker_is_raised_not_reset() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        store.setting_set(KEY_WORKERS, "1").await.unwrap();
        store.setting_set(KEY_PER_HOUR, "11").await.unwrap();
        let c = crate::config::ScanConfig::default();
        let p = SharedPace::load(&store, &c).await.unwrap().get();
        assert_eq!(p.max_workers, 2);
        assert_eq!(p.max_scans_per_hour, 11);
    }
}
