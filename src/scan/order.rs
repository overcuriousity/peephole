//! Queue order: highest response ratio next. A job's priority is
//! `(minutes waited + estimate) / estimate`, where the estimate is how long
//! a scan of its level keeps a worker busy. Short jobs go first while
//! everything is fresh; a waiting long job's priority keeps rising, so no
//! level starves. Every node measures the estimates from its replicated
//! `scan_jobs`, so arbiters and scanners agree closely (order is a
//! preference, not a correctness property).
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Lowest estimate: keeps a 30-second level from outranking everything.
pub const FLOOR_MIN: f64 = 5.0;
/// Highest estimate: the longest any scan may run (`pace::MAX_RUN_SECS`).
pub const CEIL_MIN: f64 = (super::pace::MAX_RUN_SECS / 60) as f64;
/// Finished jobs of a level before its measured mean replaces the default.
const MIN_SAMPLE: i64 = 5;
/// How often [`Cached`] re-measures.
const REFRESH: Duration = Duration::from_secs(60);

/// Minutes a scan of each level keeps a worker busy; index `level - 1`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Estimates(pub [f64; 4]);

impl Estimates {
    pub const DEFAULT: Estimates = Estimates([5.0, 5.0, 5.0, 20.0]);

    /// From `(level, jobs, mean minutes)` rows.
    pub fn from_rows(rows: &[(i64, i64, Option<f64>)]) -> Self {
        let mut e = Self::DEFAULT;
        for &(level, n, mean) in rows {
            let Some(i) = usize::try_from(level - 1).ok().filter(|i| *i < 4) else {
                continue;
            };
            if n < MIN_SAMPLE {
                continue;
            }
            let m = mean.filter(|m| m.is_finite()).unwrap_or(FLOOR_MIN);
            e.0[i] = m.clamp(FLOOR_MIN, CEIL_MIN);
        }
        e
    }

    /// Mean worker time per level of the jobs that finished or failed in
    /// the last 7 days.
    pub async fn measure(pool: &sqlx::SqlitePool) -> anyhow::Result<Self> {
        let rows: Vec<(i64, i64, Option<f64>)> = sqlx::query_as(
            "SELECT level, COUNT(*),
                    AVG((julianday(finished_at) - julianday(started_at)) * 1440.0)
             FROM scan_jobs
             WHERE status IN ('done', 'failed') AND started_at IS NOT NULL
               AND finished_at > datetime('now', '-7 days')
             GROUP BY level",
        )
        .fetch_all(pool)
        .await?;
        Ok(Self::from_rows(&rows))
    }

    fn est(&self, level: u8) -> f64 {
        self.0[(level.clamp(1, 4) - 1) as usize]
    }

    /// Response ratio of a job of `level` that has waited `waited_min`.
    pub fn ratio(&self, level: u8, waited_min: f64) -> f64 {
        let e = self.est(level);
        (waited_min.max(0.0) + e) / e
    }

    /// SQL expression for the response ratio of the `scan_jobs` row `alias`.
    /// The estimates are our own floats, so they are inlined, not bound.
    pub fn ratio_sql(&self, alias: &str) -> String {
        let [a, b, c, d] = self.0;
        let est = format!(
            "(CASE {alias}.level WHEN 1 THEN {a:.4} WHEN 2 THEN {b:.4} \
             WHEN 3 THEN {c:.4} ELSE {d:.4} END)"
        );
        format!(
            "((MAX(0.0, (julianday('now') - julianday({alias}.queued_at)) * 1440.0) + {est}) / {est})"
        )
    }

    /// `ORDER BY` body: highest ratio first, then `queued_at`, then `tie`
    /// (`j.uid` in a cluster, `j.id` standalone).
    pub fn order_by(&self, alias: &str, tie: &str) -> String {
        format!(
            "{} DESC, {alias}.queued_at ASC, {tie} ASC",
            self.ratio_sql(alias)
        )
    }
}

/// [`Estimates`] re-measured at most once per [`REFRESH`]. A failed
/// measurement keeps the last value.
pub struct Cached(Mutex<Option<(Instant, Estimates)>>);

impl Default for Cached {
    fn default() -> Self {
        Self::new()
    }
}

impl Cached {
    pub fn new() -> Self {
        Self(Mutex::new(None))
    }

    pub async fn get(&self, pool: &sqlx::SqlitePool) -> Estimates {
        let cur = *self.0.lock().unwrap();
        if let Some((at, e)) = cur
            && at.elapsed() < REFRESH
        {
            return e;
        }
        let e = match Estimates::measure(pool).await {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(?err, "measuring scan durations failed");
                cur.map(|(_, e)| e).unwrap_or(Estimates::DEFAULT)
            }
        };
        *self.0.lock().unwrap() = Some((Instant::now(), e));
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_without_enough_jobs_use_the_defaults() {
        let e = Estimates::from_rows(&[(1, 4, Some(30.0)), (4, 9, Some(13.0))]);
        assert_eq!(e.0[0], 5.0, "4 jobs are too few");
        assert_eq!(e.0[3], 13.0);
        assert_eq!(e.0[1], Estimates::DEFAULT.0[1]);
    }

    /// NULL averages and skewed (negative) durations clamp
    /// to the floor; nothing is NaN.
    #[test]
    fn estimates_are_clamped() {
        let e = Estimates::from_rows(&[
            (1, 50, Some(-3.0)),
            (2, 50, None),
            (3, 50, Some(f64::NAN)),
            (4, 50, Some(10_000.0)),
        ]);
        assert_eq!(e.0, [FLOOR_MIN, 5.0, 5.0, CEIL_MIN]);
    }

    #[test]
    fn short_jobs_first_but_waiting_long_jobs_catch_up() {
        let e = Estimates::DEFAULT; // L2 5 min, L4 20 min
        assert!(e.ratio(2, 5.0) > e.ratio(4, 10.0));
        assert!(e.ratio(4, 60.0) > e.ratio(2, 5.0));
        assert_eq!(e.ratio(4, 40.0), e.ratio(2, 10.0));
    }

    /// The SQL expression orders rows exactly like `ratio`.
    #[tokio::test]
    async fn sql_order_matches_ratio() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut ids = vec![];
        for (level, mins) in [(4, 10), (2, 5), (4, 60), (1, 1)] {
            let ip = store
                .upsert_ip(format!("203.0.113.{}", 10 + ids.len()).parse().unwrap())
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO scan_jobs (ip_id, level, status, queued_at)
                 VALUES (?, ?, 'queued', datetime('now', ?))",
            )
            .bind(ip.id)
            .bind(level)
            .bind(format!("-{mins} minutes"))
            .execute(&store.pool)
            .await
            .unwrap();
            ids.push((level, mins));
        }
        let e = Estimates::DEFAULT;
        let sql = format!(
            "SELECT j.level FROM scan_jobs j WHERE j.status = 'queued' ORDER BY {}",
            e.order_by("j", "j.id")
        );
        let got: Vec<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_all(&store.pool)
            .await
            .unwrap();
        // ratios: L4/60 → 4.0, L2/5 → 2.0, L4/10 → 1.5, L1/1 → 1.2
        assert_eq!(got, vec![4, 2, 4, 1]);
    }

    #[tokio::test]
    async fn measure_reads_done_and_failed_jobs_of_the_last_week() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store.upsert_ip("203.0.113.40".parse().unwrap()).await.unwrap();
        for (status, mins, age_days) in [
            ("done", 10, 1), ("done", 20, 1), ("failed", 30, 1), ("done", 20, 1),
            ("failed", 20, 1), ("done", 999, 30), ("refused", 999, 1),
        ] {
            sqlx::query(
                "INSERT INTO scan_jobs (ip_id, level, status, queued_at, started_at, finished_at)
                 VALUES (?1, 4, ?2, datetime('now', ?3), datetime('now', ?3),
                         datetime('now', ?3, ?4))",
            )
            .bind(ip.id)
            .bind(status)
            .bind(format!("-{age_days} days"))
            .bind(format!("+{mins} minutes"))
            .execute(&store.pool)
            .await
            .unwrap();
        }
        let e = Estimates::measure(&store.pool).await.unwrap();
        assert!((e.0[3] - 20.0).abs() < 0.01, "{e:?}"); // (10+20+30+20+20)/5
        assert_eq!(e.0[0], Estimates::DEFAULT.0[0]);
    }
}
