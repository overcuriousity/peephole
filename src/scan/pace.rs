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

const KEY_WORKERS: &str = "scan.max_workers";
const KEY_PER_HOUR: &str = "scan.max_scans_per_hour";

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Pace {
    /// Concurrent nmap processes. 0 pauses scanning.
    pub max_workers: usize,
    /// Scans started per rolling hour; starts are spaced evenly. 0 pauses.
    pub max_scans_per_hour: i64,
}

impl Pace {
    pub fn from_config(c: &ScanConfig) -> Self {
        Self {
            max_workers: c.max_workers,
            max_scans_per_hour: c.max_scans_per_hour,
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
        if p.validate().is_err() {
            p = Pace::from_config(c);
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
        store
            .setting_set(KEY_PER_HOUR, &p.max_scans_per_hour.to_string())
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
    /// Hours the 24h window actually covers (a fresh install has less), >= 1.
    pub observed_hours: f64,
    /// Mean wall-clock seconds of scans finished in the last 7 days.
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
pub fn recommend(m: &QueueMetrics, current: Pace, timeout_secs: u64) -> Recommendation {
    let scan_secs = m
        .avg_scan_secs
        .unwrap_or(DEFAULT_SCAN_SECS)
        .clamp(1.0, timeout_secs.max(1) as f64);
    let arrival = m.arrivals_24h as f64 / m.observed_hours.clamp(1.0, 24.0);
    let cap_now = capacity(current, scan_secs);
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
        pace: Pace {
            max_workers: workers,
            max_scans_per_hour: per_hour,
        },
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
        let r = recommend(&m(480, 240, Some(300.0)), P, 900);
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
        let r = recommend(&m(100, 24 * 50, None), P, 900);
        assert!(r.growing());
        assert_eq!(r.drain_hours, None);
        assert_eq!(r.scan_secs, DEFAULT_SCAN_SECS);
        assert!(r.pace.max_scans_per_hour > 50);
    }

    #[test]
    fn idle_queue_recommends_the_minimum() {
        let r = recommend(&m(0, 0, None), P, 900);
        assert_eq!(
            r.pace,
            Pace {
                max_workers: 1,
                max_scans_per_hour: 1
            }
        );
        assert_eq!(r.drain_hours, Some(0.0));
    }

    #[test]
    fn short_observation_window_is_not_diluted() {
        let mut q = m(0, 20, Some(60.0));
        q.observed_hours = 2.0;
        assert_eq!(recommend(&q, P, 900).arrival_per_hour, 10.0);
    }

    #[test]
    fn workers_are_capped() {
        let r = recommend(&m(0, 24 * 1000, Some(900.0)), P, 900);
        assert_eq!(r.pace.max_workers, MAX_WORKERS);
    }

    #[test]
    fn validation_and_interval() {
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
