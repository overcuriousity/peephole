//! Runtime scan pacing: how many nmap workers run at once. The default
//! comes from `scan.max_workers` in the config; the admin Scans page can
//! override it at runtime (persisted in the `settings` table). The scan
//! timeout and the rescan cooldown are fixed (see [`SCAN_TIMEOUT_SECS`],
//! [`COOLDOWN_HOURS`]).
//!
//! The queue metrics feed [`report`], which says how the queue keeps up.
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

/// Assumed scan duration until enough scans have finished to measure it.
pub const DEFAULT_SCAN_SECS: f64 = 180.0;
/// Window over which the queue's actual inflow and outflow are measured
/// for the drain estimate: recent enough to follow a pace change.
pub const DRAIN_WINDOW_HOURS: i64 = 6;

/// Wall-clock limit of one scan of levels 1 to 3.
pub const SCAN_TIMEOUT_SECS: u64 = 1800;
/// Level 4 scans every port with version, OS and script detection: it gets
/// this many times the base limit.
pub const LEVEL4_TIMEOUT_FACTOR: u64 = 4;
/// Hours within which an IP is not scanned again at the same level.
pub const COOLDOWN_HOURS: i64 = 24;
/// The hourly start cap announced to nodes of earlier versions, which still
/// read one: as many as an hour has seconds, so the workers alone bind.
pub const ANNOUNCED_PER_HOUR: i64 = 3600;
/// Longest any one scan may run: the level-4 limit is capped here.
pub const MAX_RUN_SECS: u64 = 12 * 3600;
/// A job marked running for longer than this is dead (no scan runs past
/// [`MAX_RUN_SECS`]): it neither shields its IP nor blocks a takeover.
pub const STALE_RUNNING_HOURS: u64 = MAX_RUN_SECS / 3600 + 1;

/// Wall-clock limit of one scan at `level`: level 4 gets
/// [`LEVEL4_TIMEOUT_FACTOR`] times `base`, capped at [`MAX_RUN_SECS`].
pub fn level_timeout_secs(base: u64, level: u8) -> u64 {
    if level >= 4 {
        base.saturating_mul(LEVEL4_TIMEOUT_FACTOR)
            .min(MAX_RUN_SECS)
            .max(base)
    } else {
        base
    }
}

pub const KEY_WORKERS: &str = "scan.max_workers";

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Pace {
    /// Concurrent nmap processes. 0 pauses scanning.
    pub max_workers: usize,
    /// Wall-clock limit per nmap run; the process is killed after it.
    /// Always [`SCAN_TIMEOUT_SECS`] outside tests.
    pub timeout_secs: u64,
}

impl Pace {
    pub fn new(max_workers: usize) -> Self {
        Self {
            max_workers,
            timeout_secs: SCAN_TIMEOUT_SECS,
        }
    }

    /// The pace `scan.max_workers` in the config asks for.
    pub fn from_config(c: &crate::config::ScanConfig) -> Self {
        Self::new(c.max_workers)
    }

    pub fn paused(&self) -> bool {
        self.max_workers == 0
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.max_workers != 0 && !(MIN_WORKERS..=MAX_WORKERS).contains(&self.max_workers) {
            return Err(format!(
                "workers must be 0 or between {MIN_WORKERS} and {MAX_WORKERS}"
            ));
        }
        Ok(())
    }
}

/// Shared between the admin UI (writer) and the scan workers (reader).
#[derive(Clone)]
pub struct SharedPace(Arc<RwLock<Pace>>);

impl SharedPace {
    pub fn new(p: Pace) -> Self {
        Self(Arc::new(RwLock::new(p)))
    }

    /// Hours within which an IP is not scanned again at the same level.
    pub fn cooldown_hours(&self) -> i64 {
        COOLDOWN_HOURS
    }

    /// Replace the pace in memory (persisting is the caller's business).
    pub fn replace(&self, p: Pace) {
        *self.0.write().unwrap() = p;
    }

    /// The config's worker count overridden by whatever the admin saved.
    pub async fn load(store: &Store, max_workers: usize) -> Result<Self> {
        let mut p = Pace::new(max_workers);
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
        if p.validate().is_err() {
            p = Pace::new(max_workers);
        }
        Ok(Self::new(p))
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
    /// Jobs refused in the last 24 h (never_scan, Tor exit, verified
    /// crawler, …); the reason is on each job.
    pub refused_24h: i64,
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

/// How the queue keeps up, measured.
#[derive(Debug, Clone, PartialEq)]
pub struct QueueReport {
    /// Jobs queued per hour, averaged over the observed window.
    pub arrival_per_hour: f64,
    /// Jobs the cluster's scanners can finish per hour with their current
    /// workers (this node's and the other live scanners').
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
}

impl QueueReport {
    pub fn growing(&self) -> bool {
        self.net_growth_per_hour > 0.0
    }
}

/// Jobs `workers` can finish per hour at the given scan duration.
pub fn capacity(workers: usize, scan_secs: f64) -> f64 {
    workers as f64 * 3600.0 / scan_secs.max(1.0)
}

/// Capacity of the cluster's other live scanners.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Others {
    pub capacity_per_hour: f64,
    pub scanners: usize,
}

/// What the other live scanners of this node's cluster can finish per
/// hour, from the workers they announce in heartbeats. The queue is
/// shared, so its arrivals are the cluster's and so must be the capacity.
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
            o.capacity_per_hour += capacity(p.max_workers as usize, scan_secs);
            // A paused scanner takes no share.
            if p.max_workers > 0 {
                o.scanners += 1;
            }
        }
    }
    o
}

/// Measure how the queue keeps up: arrivals against what this node's
/// `workers` and `others` can do, and how fast it actually drains.
pub fn report(m: &QueueMetrics, workers: usize, others: Others) -> QueueReport {
    let timeout_share = if m.completed_24h > 0 {
        m.timeouts_24h as f64 / m.completed_24h as f64
    } else {
        0.0
    };
    let scan_secs = m
        .avg_scan_secs
        .unwrap_or(DEFAULT_SCAN_SECS)
        .clamp(1.0, SCAN_TIMEOUT_SECS as f64);
    let arrival = m.arrivals_24h as f64 / m.observed_hours.clamp(1.0, 24.0);
    let own = capacity(workers, scan_secs);
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
    QueueReport {
        arrival_per_hour: arrival,
        capacity_per_hour: own + others.capacity_per_hour,
        own_capacity_per_hour: own,
        scanners: others.scanners + 1,
        throughput_per_hour: throughput,
        net_growth_per_hour: net,
        drain_hours,
        scan_secs,
        scan_secs_measured: m.avg_scan_secs.is_some(),
        timeout_share,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_four_gets_its_own_limit() {
        assert_eq!(level_timeout_secs(1800, 1), 1800);
        assert_eq!(level_timeout_secs(1800, 3), 1800);
        assert_eq!(level_timeout_secs(1800, 4), 7200);
        // Capped, and never below the base limit.
        assert_eq!(level_timeout_secs(MAX_RUN_SECS, 4), MAX_RUN_SECS);
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

    #[test]
    fn other_scanners_count_toward_capacity() {
        let o = Others {
            capacity_per_hour: 20.0,
            scanners: 1,
        };
        // 2 workers at 300 s scans do 24 an hour.
        let r = report(&m(0, 240, Some(300.0)), 2, o);
        assert_eq!(r.arrival_per_hour, 10.0);
        assert_eq!(r.own_capacity_per_hour, 24.0);
        assert_eq!(r.capacity_per_hour, 44.0);
        assert_eq!(r.scanners, 2);
        let alone = report(&m(480, 240, Some(300.0)), 2, Others::default());
        assert_eq!((alone.capacity_per_hour, alone.scanners), (24.0, 1));
    }

    #[test]
    fn capacity_is_bounded_by_workers() {
        assert_eq!(capacity(2, 60.0), 120.0);
        assert_eq!(capacity(2, 600.0), 12.0);
        assert_eq!(capacity(0, 60.0), 0.0);
    }

    /// The drain estimate follows what actually left the queue, not what
    /// the workers would allow.
    #[test]
    fn drain_is_measured_from_the_queue() {
        let mut q = m(90, 240, Some(300.0));
        q.running = 10;
        // 6 h window: 30 in, 90 out → −10/h; 100 outstanding → 10 h.
        q.arrivals_recent = 30;
        q.left_recent = 90;
        let r = report(&q, 2, Others::default());
        assert_eq!(r.throughput_per_hour, 15.0);
        assert_eq!(r.net_growth_per_hour, -10.0);
        assert!(!r.growing());
        assert_eq!(r.drain_hours, Some(10.0));
        // The workers would allow 24/h, but nothing left: it never drains.
        q.left_recent = 0;
        let r = report(&q, 2, Others::default());
        assert!(r.growing());
        assert_eq!(r.drain_hours, None);
        // A young install measures over the hours it has.
        q.observed_hours = 2.0;
        q.left_recent = 60;
        let r = report(&q, 2, Others::default());
        assert_eq!(r.net_growth_per_hour, -15.0);
        // Nothing outstanding: empty, whatever the rates.
        let r = report(&m(0, 0, None), 2, Others::default());
        assert_eq!(r.drain_hours, Some(0.0));
        assert_eq!(r.scan_secs, DEFAULT_SCAN_SECS);
        assert!(!r.scan_secs_measured);
    }

    #[test]
    fn short_observation_window_is_not_diluted() {
        let mut q = m(0, 20, Some(60.0));
        q.observed_hours = 2.0;
        assert_eq!(report(&q, 2, Others::default()).arrival_per_hour, 10.0);
    }

    #[test]
    fn timeout_share_is_reported() {
        let mut q = m(0, 240, Some(300.0));
        q.completed_24h = 20;
        q.timeouts_24h = 5;
        assert_eq!(report(&q, 2, Others::default()).timeout_share, 0.25);
    }

    #[test]
    fn one_worker_is_not_a_valid_pace() {
        assert!(
            Pace::new(1)
                .validate()
                .unwrap_err()
                .contains("0 or between 2")
        );
        assert!(Pace::new(17).validate().is_err());
        assert!(Pace::new(0).validate().is_ok(), "0 pauses");
        assert!(Pace::new(0).paused());
        assert!(Pace::new(2).validate().is_ok());
        assert_eq!(Pace::new(2).timeout_secs, SCAN_TIMEOUT_SECS);
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

    /// A stored 1 from before the minimum is raised to 2; the hourly cap
    /// and timeout saved by earlier versions no longer count.
    #[tokio::test]
    async fn a_stored_single_worker_is_raised_and_old_keys_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        store.setting_set(KEY_WORKERS, "1").await.unwrap();
        store.setting_set("scan.timeout_secs", "60").await.unwrap();
        let p = SharedPace::load(&store, 2).await.unwrap().get();
        assert_eq!(p, Pace::new(2));
    }
}
