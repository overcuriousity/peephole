//! Per-level scanner weights (distributed mode). Some scanners fail scans
//! of a given level far more often than others (a host that cannot run
//! nmap's OS or script detection, a network that drops full port sweeps).
//! The arbiter gives such a scanner a lower weight at that level, measured
//! against the best live scanner with a record there: its price buys a
//! result only that often (see `rank`), so the better scanners pick those
//! jobs up instead.
//!
//! The weights are measured once an hour (see [`Weights`]): the snapshot
//! of hour H counts the scans finished in the [`WINDOW_HOURS`] before H
//! and is taken at H + 5 min, so arbiters with the same log agree.
//!
//! Recovery is built in: only the last [`WINDOW_HOURS`] count, so old
//! failures age out; the weight never drops below [`MIN_WEIGHT`], so a
//! weak scanner keeps taking the odd job and proves itself again; and a job
//! that has waited [`OVERRIDE_WAIT_MINS`] goes to whoever asks.
//!
//! Only hard failures count. Timeouts are a pacing matter (see `pace`), an
//! invalid target is the job's fault, and declines, hand-backs and expired
//! leases ran nothing.
use crate::cluster::identity::NodeId;
use anyhow::Result;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;

/// Hours of finished scans a weight is measured over.
pub const WINDOW_HOURS: i64 = 24;
/// Successes assumed before any are seen: a scanner new to a level starts
/// at full weight, and a single failure does not halve it.
const PRIOR_OK: f64 = 4.0;
/// Lowest weight a scanner can drop to.
pub const MIN_WEIGHT: f64 = 0.1;
/// A job queued this long goes to any scanner that asks, whatever its weight.
pub const OVERRIDE_WAIT_MINS: i64 = 30;
/// Finished scans at a level before a scanner sets the bar for the others
/// there: one that is idle, paused or new does not make the rest look bad.
pub const MIN_SAMPLE: i64 = 5;

/// Finished scans of one scanner at one level within [`WINDOW_HOURS`].
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Tally {
    pub ok: i64,
    pub failed: i64,
}

impl Tally {
    /// Success rate with [`PRIOR_OK`] assumed successes, in (0, 1].
    pub fn rate(self) -> f64 {
        (self.ok as f64 + PRIOR_OK) / ((self.ok + self.failed) as f64 + PRIOR_OK)
    }
}

pub type Tallies = HashMap<(NodeId, i64), Tally>;

/// When a snapshot is taken after the end of its hour: scans finished
/// just before the hour have replicated by then.
const SNAPSHOT_DELAY_SECS: u64 = 300;

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The hour (Unix seconds / 3600) whose snapshot holds at `unix_secs`.
pub fn due_hour(unix_secs: u64) -> i64 {
    (unix_secs.saturating_sub(SNAPSHOT_DELAY_SECS) / 3600) as i64
}

/// Finished scans per scanner and level in the [`WINDOW_HOURS`] before
/// `hour` (Unix seconds / 3600), from the replicated job rows: every node
/// with the same rows gets the same tallies.
pub async fn tallies_before(pool: &SqlitePool, hour: i64) -> Result<Tallies> {
    let rows: Vec<(Vec<u8>, i64, i64, i64)> = sqlx::query_as(
        "SELECT scanner, level, SUM(status = 'done'),
                SUM(status = 'failed' AND COALESCE(error, '') NOT LIKE 'timeout%'
                    AND COALESCE(error, '') != 'invalid target')
         FROM scan_jobs
         WHERE scanner IS NOT NULL AND status IN ('done', 'failed')
           AND finished_at >= datetime(?, 'unixepoch')
           AND finished_at < datetime(?, 'unixepoch')
         GROUP BY scanner, level",
    )
    .bind((hour - WINDOW_HOURS) * 3600)
    .bind(hour * 3600)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(s, level, ok, failed)| {
            Some(((NodeId::from_slice(&s).ok()?, level), Tally { ok, failed }))
        })
        .collect())
}

/// The tallies of the [`WINDOW_HOURS`] before `hour`.
#[derive(Debug, Default)]
pub struct Snapshot {
    pub hour: i64,
    pub tallies: Tallies,
}

/// The snapshot in force: the one of the last full hour, taken
/// [`SNAPSHOT_DELAY_SECS`] after it, and kept until the next is due.
#[derive(Default)]
pub struct Weights(tokio::sync::Mutex<Option<Arc<Snapshot>>>);

impl Weights {
    pub async fn get(&self, pool: &SqlitePool) -> Result<Arc<Snapshot>> {
        let hour = due_hour(unix_now());
        let mut g = self.0.lock().await;
        if let Some(s) = g.as_ref().filter(|s| s.hour == hour) {
            return Ok(s.clone());
        }
        let s = Arc::new(Snapshot {
            hour,
            tallies: tallies_before(pool, hour).await?,
        });
        *g = Some(s.clone());
        Ok(s)
    }
}

/// `scanner`'s weight at `level`: its success rate over the best rate among
/// the other `scanners` with at least [`MIN_SAMPLE`] finished scans there,
/// floored at [`MIN_WEIGHT`]. 1 when it is the best or nobody else has a
/// record at that level.
pub fn weight(t: &Tallies, scanner: NodeId, scanners: &[NodeId], level: i64) -> f64 {
    let tally = |s: NodeId| t.get(&(s, level)).copied().unwrap_or_default();
    let own = tally(scanner).rate();
    let best = scanners
        .iter()
        .copied()
        .filter(|s| *s != scanner)
        .map(tally)
        .filter(|t| t.ok + t.failed >= MIN_SAMPLE)
        .map(Tally::rate)
        .fold(own, f64::max);
    (own / best).clamp(MIN_WEIGHT, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        NodeId([b; 32])
    }

    fn t(rows: &[(u8, i64, i64, i64)]) -> Tallies {
        rows.iter()
            .map(|(s, l, ok, failed)| {
                (
                    (id(*s), *l),
                    Tally {
                        ok: *ok,
                        failed: *failed,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn weight_is_relative_to_the_best_live_scanner() {
        let all = [id(1), id(2)];
        // 1 fails level 4 half the time, 2 never does.
        let ts = t(&[(1, 4, 6, 6), (2, 4, 10, 0), (1, 2, 10, 0)]);
        let w = weight(&ts, id(1), &all, 4);
        assert!((w - 10.0 / 16.0).abs() < 1e-9, "{w}");
        // The same failure rate everywhere (the targets' doing): no one is
        // weighted down.
        let ts = t(&[(1, 4, 7, 3), (2, 4, 7, 3)]);
        assert_eq!(weight(&ts, id(1), &all, 4), 1.0);
        let ts = t(&[(1, 4, 6, 6), (2, 4, 10, 0), (1, 2, 10, 0)]);
        assert_eq!(weight(&ts, id(2), &all, 4), 1.0);
        // Other levels are unaffected.
        assert_eq!(weight(&ts, id(1), &all, 2), 1.0);
        // Alone, or with the better scanner gone: full weight.
        assert_eq!(weight(&ts, id(1), &[id(1)], 4), 1.0);
        assert_eq!(weight(&ts, id(1), &[], 4), 1.0);
    }

    #[test]
    fn idle_or_new_scanners_set_no_bar() {
        let all = [id(1), id(2), id(3)];
        // 3 is paused or new: no record, so 1 and 2 keep full weight.
        let ts = t(&[(1, 4, 7, 3), (2, 4, 7, 3)]);
        assert_eq!(weight(&ts, id(1), &all, 4), 1.0);
        // 3 has finished too few to count; 2 sets the bar for 1.
        let ts = t(&[(1, 3, 6, 4), (2, 3, 10, 0), (3, 3, 4, 0)]);
        assert!((weight(&ts, id(1), &all, 3) - 10.0 / 14.0).abs() < 1e-9);
        // A new scanner itself starts at full weight.
        assert_eq!(weight(&ts, id(3), &all, 3), 1.0);
    }

    #[test]
    fn one_failure_is_mild() {
        let all = [id(1), id(2)];
        let ts = t(&[(1, 3, 0, 1), (2, 3, 10, 0)]);
        assert_eq!(weight(&ts, id(1), &all, 3), 0.8);
    }

    #[test]
    fn weight_is_floored_so_a_weak_scanner_still_probes() {
        let all = [id(1), id(2)];
        let ts = t(&[(1, 4, 0, 500), (2, 4, 100, 0)]);
        assert_eq!(weight(&ts, id(1), &all, 4), MIN_WEIGHT);
    }

    #[tokio::test]
    async fn tallies_count_hard_failures_only_within_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let ip = s.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
        for (status, error, age) in [
            ("done", None, "-1 hours"),
            ("failed", Some("nmap exited 1"), "-1 hours"),
            ("failed", Some("timeout after 900 s"), "-1 hours"),
            ("failed", Some("invalid target"), "-1 hours"),
            ("failed", Some("nmap exited 1"), "-30 hours"),
            ("refused", None, "-1 hours"),
        ] {
            s.enqueue_scan(ip.id, 4, 0).await.unwrap();
            sqlx::query(
                "UPDATE scan_jobs SET status = ?, error = ?, scanner = ?,
                        finished_at = datetime('now', ?)
                 WHERE id = (SELECT MAX(id) FROM scan_jobs)",
            )
            .bind(status)
            .bind(error)
            .bind(&id(7).0[..])
            .bind(age)
            .execute(&s.pool)
            .await
            .unwrap();
        }
        let t = tallies_before(&s.pool, due_hour(unix_now()) + 1)
            .await
            .unwrap();
        assert_eq!(t[&(id(7), 4)], Tally { ok: 1, failed: 1 });
    }

    #[test]
    fn the_snapshot_of_an_hour_is_due_five_minutes_after_it() {
        let h = 500_000i64;
        let at = |s: i64| (h * 3600 + s) as u64;
        assert_eq!(due_hour(at(0)), h - 1);
        assert_eq!(due_hour(at(299)), h - 1);
        assert_eq!(due_hour(at(300)), h);
        assert_eq!(due_hour(at(3599)), h);
    }

    #[tokio::test]
    async fn a_snapshot_counts_the_24_hours_before_its_hour() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let ip = s.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
        let h = 500_000i64;
        // Seconds relative to the start of hour h.
        for (status, rel) in [
            ("done", -1i64),
            ("done", 0),
            ("done", -24 * 3600),
            ("failed", -24 * 3600 - 1),
        ] {
            sqlx::query(
                "INSERT INTO scan_jobs (uid, origin, arbiter, hlc, ip_id, level, status, queued_at,
                                        error, scanner, finished_at)
                 VALUES (lower(hex(randomblob(16))), ?3, ?3, 1, ?4, 4, ?1, '2000-01-01 00:00:00',
                         'nmap exited 1', ?3, datetime(?2, 'unixepoch'))",
            )
            .bind(status)
            .bind(h * 3600 + rel)
            .bind(&id(7).0[..])
            .bind(ip.id)
            .execute(&s.pool)
            .await
            .unwrap();
        }
        let t = tallies_before(&s.pool, h).await.unwrap();
        // The second before the hour and exactly 24 h before count; the
        // hour itself and anything older do not.
        assert_eq!(t[&(id(7), 4)], Tally { ok: 2, failed: 0 });
        // The same rows give the same snapshot on any node.
        assert_eq!(tallies_before(&s.pool, h).await.unwrap(), t);
    }
}
