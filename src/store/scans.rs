use super::Store;
use crate::events::QueueJob;
use crate::scan::nmap_xml::ScanResult;
use anyhow::Result;
use chrono::{DateTime, Utc};

#[derive(Debug, PartialEq)]
pub enum EnqueueOutcome {
    Queued(i64),
    Cooldown,
    Suppressed,
    /// Not queued: a queue budget is used up (`scan::guard`).
    Throttled(&'static str),
}

#[derive(sqlx::FromRow)]
pub struct ScanJobRow {
    pub id: i64,
    pub ip_id: i64,
    pub level: i64,
    pub status: String,
    pub queued_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub attempts: i64,
    pub error: Option<String>,
}

impl Store {
    /// See [`super::recorder::Recorder::enqueue_scan`].
    pub async fn enqueue_scan(
        &self,
        ip_id: i64,
        level: u8,
        cooldown_hours: i64,
    ) -> Result<EnqueueOutcome> {
        self.local()
            .enqueue_scan(ip_id, level, cooldown_hours)
            .await
    }

    pub async fn jobs_started_last_hour(&self) -> Result<i64> {
        self.local().jobs_started_last_hour().await
    }

    pub async fn requeue_orphaned_jobs(&self) -> Result<u64> {
        self.local().requeue_orphaned_jobs().await
    }

    pub async fn setting_get(&self, key: &str) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn setting_set(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Queue growth measurements for the pacing recommendation.
    pub async fn queue_metrics(&self) -> Result<crate::scan::pace::QueueMetrics> {
        let recent = format!("-{} hours", crate::scan::pace::DRAIN_WINDOW_HOURS);
        // SUM over zero rows is NULL.
        type Sums = (
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
        );
        let (backlog, running, a1, a24, c1, c24, f24, t24, ar, lr, r24): Sums = sqlx::query_as(
            // A job "running" past any scan's limit is dead and never leaves.
            "SELECT SUM(status='queued'),
                    SUM(status='running' AND started_at > datetime('now', ?)),
                    SUM(queued_at > datetime('now','-1 hour')),
                    SUM(queued_at > datetime('now','-24 hours')),
                    SUM(status IN ('done','failed') AND finished_at > datetime('now','-1 hour')),
                    SUM(status IN ('done','failed') AND finished_at > datetime('now','-24 hours')),
                    SUM(status = 'failed' AND finished_at > datetime('now','-24 hours')),
                    SUM(status = 'failed' AND error LIKE 'timeout%'
                        AND finished_at > datetime('now','-24 hours')),
                    SUM(queued_at > datetime('now', ?)),
                    SUM(status IN ('done','failed','refused','superseded')
                        AND finished_at > datetime('now', ?)),
                    SUM(status = 'refused' AND finished_at > datetime('now','-24 hours'))
             FROM scan_jobs",
        )
        .bind(format!("-{} hours", crate::scan::pace::STALE_RUNNING_HOURS))
        .bind(&recent)
        .bind(&recent)
        .fetch_one(&self.pool)
        .await?;
        // How much of the 24h window has data: the first job ever queued.
        let first_age_h: Option<f64> = sqlx::query_scalar(
            "SELECT (julianday('now') - julianday(MIN(queued_at))) * 24 FROM scan_jobs",
        )
        .fetch_one(&self.pool)
        .await?;
        let avg_scan_secs: Option<f64> = sqlx::query_scalar(
            "SELECT AVG((julianday(finished_at) - julianday(started_at)) * 86400)
             FROM scan_jobs WHERE status IN ('done','failed') AND started_at IS NOT NULL
               AND finished_at > datetime('now','-7 days')",
        )
        .fetch_one(&self.pool)
        .await?;
        let oldest_queued_secs: Option<i64> = sqlx::query_scalar(
            "SELECT CAST((julianday('now') - julianday(MIN(queued_at))) * 86400 AS INTEGER)
             FROM scan_jobs WHERE status = 'queued'",
        )
        .fetch_one(&self.pool)
        .await?;
        // Hour buckets by age: 0 = the last 60 minutes.
        let hourly = |col: &'static str, extra: &'static str| {
            format!(
                "SELECT CAST((julianday('now') - julianday({col})) * 24 AS INTEGER) AS h, COUNT(*)
                 FROM scan_jobs WHERE {col} > datetime('now','-24 hours'){extra} GROUP BY h"
            )
        };
        let mut hourly_arrivals = vec![0i64; 24];
        let mut hourly_completions = vec![0i64; 24];
        for (sql, out) in [
            (hourly("queued_at", ""), &mut hourly_arrivals),
            (
                hourly("finished_at", " AND status IN ('done','failed')"),
                &mut hourly_completions,
            ),
        ] {
            let rows: Vec<(i64, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .fetch_all(&self.pool)
                .await?;
            for (h, n) in rows {
                if (0..24).contains(&h) {
                    out[23 - h as usize] += n;
                }
            }
        }
        Ok(crate::scan::pace::QueueMetrics {
            backlog: backlog.unwrap_or(0),
            running: running.unwrap_or(0),
            arrivals_1h: a1.unwrap_or(0),
            arrivals_24h: a24.unwrap_or(0),
            completed_1h: c1.unwrap_or(0),
            completed_24h: c24.unwrap_or(0),
            failed_24h: f24.unwrap_or(0),
            refused_24h: r24.unwrap_or(0),
            timeouts_24h: t24.unwrap_or(0),
            arrivals_recent: ar.unwrap_or(0),
            left_recent: lr.unwrap_or(0),
            observed_hours: first_age_h.unwrap_or(24.0).clamp(1.0, 24.0),
            avg_scan_secs,
            oldest_queued_secs,
            hourly_arrivals,
            hourly_completions,
        })
    }

    pub async fn next_queued_job(&self) -> Result<Option<ScanJobRow>> {
        self.local().next_queued_job().await
    }

    pub async fn finish_job(
        &self,
        job_id: i64,
        result: Option<&ScanResult>,
        error: Option<&str>,
    ) -> Result<()> {
        self.local().finish_job(job_id, result, error).await
    }
}

pub(crate) const QUEUE_JOB_SQL: &str =
    "SELECT j.id, i.ip, j.level, j.status, j.queued_at, j.started_at, j.finished_at, j.error,
            (SELECT name FROM members m WHERE m.id = j.scanner) AS scanner,
            (SELECT name FROM members m WHERE m.id = j.arbiter) AS arbiter,
            j.retry_at
     FROM scan_jobs j JOIN ips i ON j.ip_id = i.id";

impl Store {
    pub async fn queue_job(&self, id: i64) -> Result<Option<QueueJob>> {
        Ok(sqlx::query_as::<_, QueueJob>(sqlx::AssertSqlSafe(format!(
            "{QUEUE_JOB_SQL} WHERE j.id = ?"
        )))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Queued and running jobs, newest first; `limit` rows. Finished jobs
    /// are in [`Store::job_history`].
    pub async fn active_jobs(&self, limit: i64) -> Result<Vec<QueueJob>> {
        Ok(sqlx::query_as::<_, QueueJob>(sqlx::AssertSqlSafe(format!(
            "{QUEUE_JOB_SQL} WHERE j.status IN ('queued', 'running') ORDER BY j.id DESC LIMIT ?"
        )))
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    #[tokio::test]
    async fn queue_job_and_snapshot_join_ip() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = s.upsert_ip("203.0.113.5".parse().unwrap()).await.unwrap();
        let id = match s.enqueue_scan(ip.id, 2, 24).await.unwrap() {
            EnqueueOutcome::Queued(id) => id,
            other => panic!("{other:?}"),
        };
        let job = s.queue_job(id).await.unwrap().unwrap();
        assert_eq!(job.ip, "203.0.113.5");
        assert_eq!(job.status, "queued");
        let snap = s.active_jobs(50).await.unwrap();
        assert_eq!(snap.len(), 1);
        assert!(s.queue_job(9999).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn orphaned_running_jobs_are_requeued_and_rate_counts_starts() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = s.upsert_ip("203.0.113.6".parse().unwrap()).await.unwrap();
        s.enqueue_scan(ip.id, 2, 24).await.unwrap();
        let job = s.next_queued_job().await.unwrap().unwrap();
        assert_eq!(s.jobs_started_last_hour().await.unwrap(), 1);
        // Simulated restart mid-scan.
        assert_eq!(s.requeue_orphaned_jobs().await.unwrap(), 1);
        assert_eq!(s.queue_job(job.id).await.unwrap().unwrap().status, "queued");
        assert_eq!(s.next_queued_job().await.unwrap().unwrap().id, job.id);
        s.finish_job(job.id, None, Some("timeout")).await.unwrap();
        // The IP can be queued again once the job has ended.
        assert_eq!(s.requeue_orphaned_jobs().await.unwrap(), 0);
    }

    /// (uid, retry_of, retry_at in the future) of the queued jobs.
    async fn queued_retries(s: &Store) -> Vec<(String, Option<String>, bool)> {
        sqlx::query_as(
            "SELECT uid, retry_of, retry_at > datetime('now') FROM scan_jobs
             WHERE status = 'queued' ORDER BY id",
        )
        .fetch_all(&s.pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn failed_scans_are_retried_after_a_wait() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = s.upsert_ip("203.0.113.20".parse().unwrap()).await.unwrap();
        s.enqueue_scan(ip.id, 3, 24).await.unwrap();
        let first = s.next_queued_job().await.unwrap().unwrap();
        s.finish_job(first.id, None, Some("nmap exited 1"))
            .await
            .unwrap();
        let root: String = sqlx::query_scalar("SELECT uid FROM scan_jobs WHERE id = ?")
            .bind(first.id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        // The failure stays on record; a retry waits in the queue.
        assert_eq!(
            s.queue_job(first.id).await.unwrap().unwrap().status,
            "failed"
        );
        let q = queued_retries(&s).await;
        assert_eq!(q.len(), 1);
        assert_eq!((q[0].1.as_deref(), q[0].2), (Some(root.as_str()), true));
        assert!(
            s.next_queued_job().await.unwrap().is_none(),
            "not before its time"
        );
        // Due: it runs at the same level, fails again, and the next retry
        // still names the first failure, with a longer wait.
        sqlx::query("UPDATE scan_jobs SET retry_at = datetime('now', '-1 minute')")
            .execute(&s.pool)
            .await
            .unwrap();
        let second = s.next_queued_job().await.unwrap().unwrap();
        assert_eq!(second.level, 3);
        s.finish_job(second.id, None, Some("timeout after 900 s"))
            .await
            .unwrap();
        let (retry_of, wait): (Option<String>, i64) = sqlx::query_as(
            "SELECT retry_of, CAST(strftime('%s', retry_at) AS INTEGER) - CAST(strftime('%s', 'now') AS INTEGER)
             FROM scan_jobs WHERE status = 'queued'",
        )
        .fetch_one(&s.pool)
        .await
        .unwrap();
        assert_eq!(retry_of.as_deref(), Some(root.as_str()));
        assert!((19 * 60..=20 * 60).contains(&wait), "{wait}");
    }

    #[tokio::test]
    async fn retries_stop_on_success_invalid_targets_and_after_a_day() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let fail = |ip: &'static str, error: &'static str| {
            let s = s.clone();
            async move {
                let ip = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
                s.enqueue_scan(ip.id, 2, 0).await.unwrap();
                let j = s.next_queued_job().await.unwrap().unwrap();
                s.finish_job(j.id, None, Some(error)).await.unwrap();
                (ip.id, j.id)
            }
        };
        // Invalid target: never retried.
        fail("203.0.113.30", "invalid target").await;
        assert!(queued_retries(&s).await.is_empty());
        // The retry of a failure from over a day ago fails too: the window
        // is closed.
        let (_, old) = fail("203.0.113.31", "nmap exited 1").await;
        sqlx::query("UPDATE scan_jobs SET finished_at = datetime('now', '-25 hours') WHERE id = ?")
            .bind(old)
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE scan_jobs SET retry_at = datetime('now') WHERE status = 'queued'")
            .execute(&s.pool)
            .await
            .unwrap();
        let retry = s.next_queued_job().await.unwrap().unwrap();
        s.finish_job(retry.id, None, Some("nmap exited 1"))
            .await
            .unwrap();
        assert!(queued_retries(&s).await.is_empty(), "past the window");
        // A scan of the IP at this level or higher succeeded since: done.
        let (ip, _) = fail("203.0.113.32", "nmap exited 1").await;
        sqlx::query("DELETE FROM scan_jobs WHERE status = 'queued'")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO scan_jobs (uid, ip_id, level, status, queued_at, finished_at)
             VALUES ('ok', ?, 3, 'done', datetime('now'), datetime('now'))",
        )
        .bind(ip)
        .execute(&s.pool)
        .await
        .unwrap();
        let failed: String =
            sqlx::query_scalar("SELECT uid FROM scan_jobs WHERE ip_id = ? AND status = 'failed'")
                .bind(ip)
                .fetch_one(&s.pool)
                .await
                .unwrap();
        assert_eq!(s.local().retry_failed(&failed, None).await.unwrap(), None);
    }

    #[tokio::test]
    async fn queue_metrics_count_arrivals_completions_and_duration() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        for i in 0..3 {
            let ip = s
                .upsert_ip(format!("203.0.113.{}", 10 + i).parse().unwrap())
                .await
                .unwrap();
            s.enqueue_scan(ip.id, 2, 24).await.unwrap();
        }
        let job = s.next_queued_job().await.unwrap().unwrap();
        sqlx::query(
            "UPDATE scan_jobs SET status='done', started_at=datetime('now','-2 minutes'),
             finished_at=datetime('now') WHERE id=?",
        )
        .bind(job.id)
        .execute(&s.pool)
        .await
        .unwrap();
        let m = s.queue_metrics().await.unwrap();
        assert_eq!(m.backlog, 2);
        assert_eq!(m.arrivals_1h, 3);
        assert_eq!(m.arrivals_24h, 3);
        assert_eq!(m.completed_24h, 1);
        assert_eq!(m.arrivals_recent, 3);
        assert_eq!(m.left_recent, 1);
        assert_eq!(m.hourly_arrivals.len(), 24);
        assert_eq!(m.hourly_arrivals[23], 3);
        assert_eq!(m.hourly_completions[23], 1);
        assert_eq!(m.observed_hours, 1.0);
        assert!((m.avg_scan_secs.unwrap() - 120.0).abs() < 1.0);
        assert!(m.oldest_queued_secs.is_some());

        // Refused and superseded jobs left the queue too; a job "running"
        // past any scan's limit is dead and not outstanding.
        let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM scan_jobs WHERE status='queued'")
            .fetch_all(&s.pool)
            .await
            .unwrap();
        for (id, status) in ids.iter().zip(["refused", "superseded"]) {
            sqlx::query("UPDATE scan_jobs SET status=?, finished_at=datetime('now') WHERE id=?")
                .bind(status)
                .bind(id)
                .execute(&s.pool)
                .await
                .unwrap();
        }
        let ip = s.upsert_ip("203.0.113.40".parse().unwrap()).await.unwrap();
        s.enqueue_scan(ip.id, 2, 24).await.unwrap();
        sqlx::query(
            "UPDATE scan_jobs SET status='running', started_at=datetime('now','-14 hours')
             WHERE ip_id=?",
        )
        .bind(ip.id)
        .execute(&s.pool)
        .await
        .unwrap();
        let m = s.queue_metrics().await.unwrap();
        assert_eq!(m.left_recent, 3);
        assert_eq!(m.refused_24h, 1, "one job was set to refused above");
        assert_eq!((m.backlog, m.running), (0, 0));

        assert_eq!(s.setting_get("k").await.unwrap(), None);
        s.setting_set("k", "1").await.unwrap();
        s.setting_set("k", "2").await.unwrap();
        assert_eq!(s.setting_get("k").await.unwrap().as_deref(), Some("2"));
    }
}
