//! Per-level scanner weights (distributed mode). Some scanners fail scans
//! of a given level far more often than others (a host that cannot run
//! nmap's OS or script detection, a network that drops full port sweeps).
//! The arbiter gives such a scanner a lower weight at that level, measured
//! against the best live scanner with a record there, and has it sit out
//! that level for stretches of [`HOLD`], a share `1 - weight` of them, so
//! the better scanners pick those jobs up instead.
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
use std::time::{Duration, Instant};

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
/// How long one decision to sit a level out (or not) holds. Scanners claim
/// every few seconds when idle, so a fresh roll per claim would let a weak
/// scanner take the level's jobs almost at once anyway.
pub const HOLD: Duration = Duration::from_secs(600);

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

/// Finished scans per scanner and level within [`WINDOW_HOURS`], from the
/// replicated job rows: every node sees the whole cluster's record.
pub async fn tallies(pool: &SqlitePool) -> Result<Tallies> {
    let rows: Vec<(Vec<u8>, i64, i64, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT scanner, level, SUM(status = 'done'),
                SUM(status = 'failed' AND COALESCE(error, '') NOT LIKE 'timeout%'
                    AND COALESCE(error, '') != 'invalid target')
         FROM scan_jobs
         WHERE scanner IS NOT NULL AND status IN ('done', 'failed')
           AND finished_at > datetime('now', '-{WINDOW_HOURS} hours')
         GROUP BY scanner, level"
    )))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(s, level, ok, failed)| {
            Some(((NodeId::from_slice(&s).ok()?, level), Tally { ok, failed }))
        })
        .collect())
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

/// Standing decisions to sit a level out, per scanner and level.
#[derive(Default)]
pub struct Holds(HashMap<(NodeId, i64), (Instant, bool)>);

impl Holds {
    /// The levels `scanner` sits out now. A level with weight `w < 1` is
    /// sat out unless the roll (uniform in [0, 1)) comes in below `w`; the
    /// decision then stands for [`HOLD`]. Full weight clears it at once.
    pub fn skipped(
        &mut self,
        t: &Tallies,
        scanner: NodeId,
        scanners: &[NodeId],
        now: Instant,
        mut roll: impl FnMut() -> f64,
    ) -> Vec<i64> {
        self.0.retain(|_, (until, _)| *until > now);
        (1..=4)
            .filter(|l| {
                let w = weight(t, scanner, scanners, *l);
                if w >= 1.0 {
                    self.0.remove(&(scanner, *l));
                    return false;
                }
                self.0
                    .entry((scanner, *l))
                    .or_insert_with(|| (now + HOLD, roll() >= w))
                    .1
            })
            .collect()
    }
}

/// Uniform in [0, 1).
pub fn roll() -> f64 {
    let mut b = [0u8; 4];
    let _ = aws_lc_rs::rand::fill(&mut b);
    u32::from_le_bytes(b) as f64 / (u32::MAX as f64 + 1.0)
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
        let t = tallies(&s.pool).await.unwrap();
        assert_eq!(t[&(id(7), 4)], Tally { ok: 1, failed: 1 });
    }

    #[test]
    fn a_decision_holds_then_is_rolled_again() {
        let all = [id(1), id(2)];
        let ts = t(&[(1, 4, 0, 4), (2, 4, 10, 0)]); // weight 0.5 at level 4
        let now = Instant::now();
        let mut h = Holds::default();
        assert_eq!(h.skipped(&ts, id(1), &all, now, || 0.7), vec![4]);
        // Within the hold a lucky roll changes nothing.
        let later = now + HOLD / 2;
        assert_eq!(h.skipped(&ts, id(1), &all, later, || 0.0), vec![4]);
        // After it, the next roll decides.
        let after = now + HOLD + Duration::from_secs(1);
        assert!(h.skipped(&ts, id(1), &all, after, || 0.3).is_empty());
        // The good scanner never sits out.
        assert!(h.skipped(&ts, id(2), &all, now, || 0.99).is_empty());
        // Recovered to full weight: the standing decision is dropped.
        let mut h = Holds::default();
        assert_eq!(h.skipped(&ts, id(1), &all, now, || 0.7), vec![4]);
        let ok = t(&[(1, 4, 10, 0), (2, 4, 10, 0)]);
        assert!(h.skipped(&ok, id(1), &all, now, || 0.99).is_empty());
        let r = roll();
        assert!((0.0..1.0).contains(&r));
    }
}
