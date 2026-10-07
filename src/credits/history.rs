//! Hourly price snapshots (`price_history`), written by `price::refresh`
//! and read by the Credits page's charts. Local only; kept 8 days.
use anyhow::Result;
use sqlx::SqlitePool;

/// Hours of history kept.
pub const KEEP_HOURS: i64 = 8 * 24;

/// One good in one hour.
#[derive(Debug, Clone, PartialEq, serde::Serialize, sqlx::FromRow)]
pub struct Point {
    /// Unix time / 3600.
    pub hour: i64,
    pub good: String,
    /// This node's price; None: it does not offer the good.
    pub own_mc: Option<i64>,
    /// Lowest, median and highest price live members announce.
    pub lo_mc: Option<i64>,
    pub median_mc: Option<i64>,
    pub hi_mc: Option<i64>,
    /// Asked for, and offered, per hour.
    pub demand: f64,
    pub supply: f64,
}

/// `(lowest, median, highest)` of announced prices; the median of an even
/// count is the lower middle one, a price someone actually asks.
pub fn spread(announced: &[u32]) -> (Option<i64>, Option<i64>, Option<i64>) {
    let mut v = announced.to_vec();
    v.sort_unstable();
    let at = |i: usize| v.get(i).map(|x| *x as i64);
    if v.is_empty() {
        return (None, None, None);
    }
    (at(0), at((v.len() - 1) / 2), at(v.len() - 1))
}

/// The hour `ms` (Unix milliseconds) falls in.
pub fn hour_of(ms: u64) -> i64 {
    (ms / 3_600_000) as i64
}

/// Write `points` (one hour, replacing a rerun's) and drop what is older
/// than [`KEEP_HOURS`] before their hour.
pub async fn record(pool: &SqlitePool, points: &[Point]) -> Result<()> {
    let mut tx = pool.begin().await?;
    for p in points {
        sqlx::query(
            "INSERT OR REPLACE INTO price_history
             (hour, good, own_mc, lo_mc, median_mc, hi_mc, demand, supply)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(p.hour)
        .bind(&p.good)
        .bind(p.own_mc)
        .bind(p.lo_mc)
        .bind(p.median_mc)
        .bind(p.hi_mc)
        .bind(p.demand)
        .bind(p.supply)
        .execute(&mut *tx)
        .await?;
    }
    if let Some(now) = points.iter().map(|p| p.hour).max() {
        sqlx::query("DELETE FROM price_history WHERE hour < ?")
            .bind(now - KEEP_HOURS)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// `good`'s points from `since` (an hour), oldest first.
pub async fn series(pool: &SqlitePool, good: &str, since: i64) -> Result<Vec<Point>> {
    Ok(sqlx::query_as(
        "SELECT hour, good, own_mc, lo_mc, median_mc, hi_mc, demand, supply
         FROM price_history WHERE good = ? AND hour >= ? ORDER BY hour",
    )
    .bind(good)
    .bind(since)
    .fetch_all(pool)
    .await?)
}

/// Every good's points from `since`, oldest first (the sparklines).
pub async fn all_since(pool: &SqlitePool, since: i64) -> Result<Vec<Point>> {
    Ok(sqlx::query_as(
        "SELECT hour, good, own_mc, lo_mc, median_mc, hi_mc, demand, supply
         FROM price_history WHERE hour >= ? ORDER BY good, hour",
    )
    .bind(since)
    .fetch_all(pool)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn point(hour: i64, good: &str, own: i64) -> Point {
        Point {
            hour,
            good: good.into(),
            own_mc: Some(own),
            lo_mc: Some(own - 1),
            median_mc: Some(own),
            hi_mc: Some(own + 1),
            demand: 2.0,
            supply: 4.0,
        }
    }

    #[test]
    fn spread_of_announced_prices() {
        assert_eq!(spread(&[]), (None, None, None));
        assert_eq!(spread(&[7]), (Some(7), Some(7), Some(7)));
        assert_eq!(spread(&[9, 1, 4, 6]), (Some(1), Some(4), Some(9)));
        assert_eq!(spread(&[5, 3, 8]), (Some(3), Some(5), Some(8)));
    }

    #[tokio::test]
    async fn record_replaces_an_hour_and_keeps_eight_days() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let now = 500_000;
        record(&store.pool, &[point(now - KEEP_HOURS - 1, "scan", 1)])
            .await
            .unwrap();
        record(
            &store.pool,
            &[point(now - 1, "scan", 10), point(now - 1, "rdap", 3)],
        )
        .await
        .unwrap();
        // A rerun of the hour replaces it; the oldest point is now past the window.
        record(&store.pool, &[point(now, "scan", 20)])
            .await
            .unwrap();
        record(&store.pool, &[point(now, "scan", 30)])
            .await
            .unwrap();
        let s = series(&store.pool, "scan", 0).await.unwrap();
        assert_eq!(
            s.iter().map(|p| (p.hour, p.own_mc)).collect::<Vec<_>>(),
            [(now - 1, Some(10)), (now, Some(30))]
        );
        assert_eq!(all_since(&store.pool, now - 1).await.unwrap().len(), 3);
        assert_eq!(hour_of(3_600_000 * 7 + 5), 7);
    }
}
