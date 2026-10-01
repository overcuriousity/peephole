//! Runtime scan pacing: how many nmap workers run at once and how many scans
//! may start per hour. Defaults come from `[scan]` in the config; the admin
//! queue page can override both at runtime (persisted in the `settings` table).
//!
//! The queue metrics feed [`recommend`], which sizes the pace so the queue
//! keeps up with arrivals and drains any backlog within a day.
use crate::config::ScanConfig;
use crate::store::Store;
use anyhow::Result;
use std::sync::{Arc, RwLock};

/// Upper bound for workers settable from the admin UI (nmap -sS/-O is heavy).
pub const MAX_WORKERS: usize = 16;
/// Upper bound for the hourly start cap settable from the admin UI.
pub const MAX_PER_HOUR: i64 = 3600;
/// Assumed scan duration until enough scans have finished to measure it.
pub const DEFAULT_SCAN_SECS: f64 = 180.0;
/// Headroom over the measured arrival rate so short bursts don't pile up.
const HEADROOM: f64 = 1.25;
/// Horizon over which a recommendation drains the current backlog.
const DRAIN_HOURS: f64 = 24.0;

/// Per-scan wall-clock limit bounds settable from the admin UI.
pub const MIN_TIMEOUT: u64 = 60;
pub const MAX_TIMEOUT: u64 = 4 * 3600;
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
        if self.max_workers > MAX_WORKERS {
            return Err(format!("workers must be between 0 and {MAX_WORKERS}"));
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
    /// Jobs the current pace can finish per hour.
    pub capacity_per_hour: f64,
    /// Positive: the backlog grows by this much per hour.
    pub net_growth_per_hour: f64,
    /// Hours until the backlog is empty at the current pace; None = never.
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

/// Size the pace to absorb arrivals with headroom and drain the backlog
/// within [`DRAIN_HOURS`], never below one scan per hour and one worker.
/// When more than [`TIMEOUT_SHARE`] of recent scans hit the limit, the
/// timeout is raised by half (rounded up to a minute) and the worker count
/// is sized for scans that may take that long.
pub fn recommend(m: &QueueMetrics, current: Pace) -> Recommendation {
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
    let cap_now = capacity(current, measured);
    let net = arrival - cap_now;
    let drain_hours = match m.backlog {
        0 => Some(0.0),
        b if net < 0.0 => Some(b as f64 / -net),
        _ => None,
    };

    let target = (arrival * HEADROOM + m.backlog as f64 / DRAIN_HOURS)
        .ceil()
        .max(1.0);
    let workers = ((target * scan_secs / 3600.0).ceil() as usize).clamp(1, MAX_WORKERS);
    let per_hour = (target as i64).clamp(1, MAX_PER_HOUR);
    Recommendation {
        arrival_per_hour: arrival,
        capacity_per_hour: cap_now,
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

/// Answer pace changes sent by web nodes (scanner nodes in a cluster).
pub fn serve_remote(node: &Arc<crate::cluster::Node>, pace: SharedPace) {
    use crate::cluster::msg::Msg;
    let store = node.store.clone();
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |from, msg| {
        let (pace, store, weak) = (pace.clone(), store.clone(), weak.clone());
        Box::pin(async move {
            let Msg::SetPace { pace: p } = msg else {
                return None;
            };
            let new = Pace {
                max_workers: p.max_workers as usize,
                max_scans_per_hour: p.max_scans_per_hour,
                timeout_secs: p.timeout_secs,
            };
            let error = match pace.set(&store, new).await {
                Ok(Ok(())) => {
                    tracing::info!(by = %from.short(), ?new, "scan pace changed remotely");
                    if let Some(node) = weak.upgrade() {
                        node.status.local.lock().unwrap().pace = Some(p);
                        node.publish_status();
                    }
                    None
                }
                Ok(Err(e)) => Some(e),
                Err(e) => Some(format!("{e:#}")),
            };
            Some(Msg::SetPaceReply { error })
        })
    }));
}

/// Change the pace of scanner `target` from this node.
pub async fn set_remote(
    node: &Arc<crate::cluster::Node>,
    target: crate::cluster::identity::NodeId,
    p: Pace,
) -> Result<Result<(), String>> {
    use crate::cluster::msg::Msg;
    if let Err(e) = p.validate() {
        return Ok(Err(e));
    }
    let pace = crate::cluster::status::PaceInfo {
        max_workers: p.max_workers as u32,
        max_scans_per_hour: p.max_scans_per_hour,
        timeout_secs: p.timeout_secs,
    };
    match node
        .request(
            target,
            Msg::SetPace { pace },
            std::time::Duration::from_secs(15),
        )
        .await?
    {
        Msg::SetPaceReply { error: None } => Ok(Ok(())),
        Msg::SetPaceReply { error: Some(e) } => Ok(Err(e)),
        other => anyhow::bail!("unexpected answer {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let r = recommend(&m(480, 240, Some(300.0)), P);
        assert_eq!(r.arrival_per_hour, 10.0);
        assert_eq!(r.pace.max_scans_per_hour, 33); // ceil(12.5 + 20)
        assert_eq!(r.pace.max_workers, 3); // 33 × 300s / 3600 = 2.75
        assert_eq!(r.capacity_per_hour, 24.0); // 2 workers × 12/h
        assert!(!r.growing());
        assert_eq!(r.drain_hours, Some(480.0 / 14.0));
        assert!(r.scan_secs_measured);
    }

    #[test]
    fn growing_queue_never_drains() {
        let r = recommend(&m(100, 24 * 50, None), P);
        assert!(r.growing());
        assert_eq!(r.drain_hours, None);
        assert_eq!(r.scan_secs, DEFAULT_SCAN_SECS);
        assert!(r.pace.max_scans_per_hour > 50);
    }

    #[test]
    fn idle_queue_recommends_the_minimum() {
        let r = recommend(&m(0, 0, None), P);
        assert_eq!(
            r.pace,
            Pace {
                max_workers: 1,
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
        assert_eq!(recommend(&q, P).arrival_per_hour, 10.0);
    }

    #[test]
    fn workers_are_capped() {
        let r = recommend(&m(0, 24 * 1000, Some(900.0)), P);
        assert_eq!(r.pace.max_workers, MAX_WORKERS);
    }

    #[test]
    fn frequent_timeouts_raise_the_limit_and_the_workers() {
        let mut q = m(0, 24 * 10, Some(300.0));
        q.completed_24h = 20;
        q.timeouts_24h = 5; // 25% hit the 900 s limit
        let r = recommend(&q, P);
        assert_eq!(r.timeout_share, 0.25);
        assert_eq!(r.pace.timeout_secs, 1380); // 1350 rounded up to a minute
        // 75% × 300 s + 25% × 1380 s = 570 s per job; 13/h needs 3 workers.
        assert_eq!(r.scan_secs, 570.0);
        assert_eq!(r.pace.max_workers, 3);

        q.timeouts_24h = 1; // 5%: below the threshold
        assert_eq!(recommend(&q, P).pace.timeout_secs, 900);
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
}
