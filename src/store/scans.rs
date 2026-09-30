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
    /// Cooldown (spec §5): a finished scan of level >= requested within the
    /// window suppresses; a higher requested level upgrades exactly once.
    pub async fn enqueue_scan(
        &self,
        ip_id: i64,
        level: u8,
        cooldown_hours: i64,
    ) -> Result<EnqueueOutcome> {
        if level == 0 {
            return Ok(EnqueueOutcome::Suppressed);
        }
        let recent: Option<(i64,)> = sqlx::query_as(
            "SELECT level FROM scan_jobs WHERE ip_id = ? AND status IN ('done','failed')
             AND finished_at > datetime('now', ?) ORDER BY level DESC LIMIT 1",
        )
        .bind(ip_id)
        .bind(format!("-{cooldown_hours} hours"))
        .fetch_optional(&self.pool)
        .await?;
        if let Some((last_level,)) = recent
            && (level as i64) <= last_level
        {
            return Ok(EnqueueOutcome::Cooldown);
        }
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_jobs WHERE ip_id = ? AND status IN ('queued','running')",
        )
        .bind(ip_id)
        .fetch_one(&self.pool)
        .await?;
        if pending > 0 {
            return Ok(EnqueueOutcome::Cooldown);
        }
        let r = sqlx::query(
            "INSERT INTO scan_jobs (ip_id, level, status, queued_at) VALUES (?,?,'queued',datetime('now'))",
        ).bind(ip_id).bind(level as i64).execute(&self.pool).await?;
        Ok(EnqueueOutcome::Queued(r.last_insert_rowid()))
    }

    /// Jobs started in the last hour, whatever their outcome: the global rate
    /// cap limits nmap launches, so failed and still-running scans count too.
    pub async fn jobs_started_last_hour(&self) -> Result<i64> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_jobs WHERE started_at > datetime('now','-1 hour')",
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Jobs left `running` by a crash or restart go back to the queue;
    /// otherwise they block their IP from ever being scanned again.
    pub async fn requeue_orphaned_jobs(&self) -> Result<u64> {
        Ok(sqlx::query(
            "UPDATE scan_jobs SET status='queued', started_at=NULL WHERE status='running'",
        )
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    /// Put jobs that failed in the last `days` back in the queue, unless
    /// their IP already has a pending job. Returns how many were requeued.
    pub async fn requeue_failed_jobs(&self, days: i64) -> Result<u64> {
        Ok(sqlx::query(
            "UPDATE scan_jobs SET status='queued', started_at=NULL, finished_at=NULL, error=NULL
             WHERE status='failed' AND finished_at > datetime('now', ?)
               AND NOT EXISTS (SELECT 1 FROM scan_jobs p WHERE p.ip_id = scan_jobs.ip_id
                               AND p.status IN ('queued','running'))
               AND id = (SELECT MAX(f.id) FROM scan_jobs f
                         WHERE f.ip_id = scan_jobs.ip_id AND f.status = 'failed')",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?
        .rows_affected())
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
        );
        let (backlog, running, a1, a24, c1, c24, f24, t24): Sums = sqlx::query_as(
            "SELECT SUM(status='queued'), SUM(status='running'),
                    SUM(queued_at > datetime('now','-1 hour')),
                    SUM(queued_at > datetime('now','-24 hours')),
                    SUM(status IN ('done','failed') AND finished_at > datetime('now','-1 hour')),
                    SUM(status IN ('done','failed') AND finished_at > datetime('now','-24 hours')),
                    SUM(status = 'failed' AND finished_at > datetime('now','-24 hours')),
                    SUM(status = 'failed' AND error LIKE 'timeout%'
                        AND finished_at > datetime('now','-24 hours'))
             FROM scan_jobs",
        )
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
            timeouts_24h: t24.unwrap_or(0),
            observed_hours: first_age_h.unwrap_or(24.0).clamp(1.0, 24.0),
            avg_scan_secs,
            oldest_queued_secs,
            hourly_arrivals,
            hourly_completions,
        })
    }

    pub async fn next_queued_job(&self) -> Result<Option<ScanJobRow>> {
        let job = sqlx::query_as::<_, ScanJobRow>(
            "SELECT * FROM scan_jobs WHERE status = 'queued' ORDER BY level DESC, queued_at ASC LIMIT 1",
        ).fetch_optional(&self.pool).await?;
        if let Some(j) = &job {
            sqlx::query("UPDATE scan_jobs SET status='running', started_at=datetime('now'), attempts=attempts+1 WHERE id=?")
                .bind(j.id).execute(&self.pool).await?;
        }
        Ok(job)
    }

    pub async fn finish_job(
        &self,
        job_id: i64,
        result: Option<&ScanResult>,
        error: Option<&str>,
    ) -> Result<()> {
        let job = sqlx::query_as::<_, ScanJobRow>("SELECT * FROM scan_jobs WHERE id=?")
            .bind(job_id)
            .fetch_one(&self.pool)
            .await?;
        match result {
            Some(res) => {
                let compressed = zstd::encode_all(res.raw_xml.as_slice(), 3)?;
                let r = sqlx::query(
                    "INSERT INTO scans (job_id, ip_id, level, started_at, finished_at, os_guess, raw_xml)
                     VALUES (?,?,?,COALESCE((SELECT started_at FROM scan_jobs WHERE id=?),datetime('now')),datetime('now'),?,?)",
                )
                .bind(job_id).bind(job.ip_id).bind(job.level).bind(job_id)
                .bind(&res.os_guess).bind(&compressed)
                .execute(&self.pool).await?;
                let scan_id = r.last_insert_rowid();
                for p in &res.ports {
                    sqlx::query(
                        "INSERT INTO ports (scan_id, port, proto, state, service, product, version) VALUES (?,?,?,?,?,?,?)",
                    )
                    .bind(scan_id).bind(p.port as i64).bind(&p.proto).bind(&p.state)
                    .bind(&p.service).bind(&p.product).bind(&p.version)
                    .execute(&self.pool).await?;
                }
                sqlx::query(
                    "UPDATE scan_jobs SET status='done', finished_at=datetime('now') WHERE id=?",
                )
                .bind(job_id)
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("UPDATE scan_jobs SET status='failed', finished_at=datetime('now'), error=? WHERE id=?")
                    .bind(error).bind(job_id).execute(&self.pool).await?;
            }
        }
        Ok(())
    }
}

const QUEUE_JOB_SQL: &str =
    "SELECT j.id, i.ip, j.level, j.status, j.queued_at, j.started_at, j.finished_at, j.error
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

    /// Newest jobs first; `limit` rows.
    pub async fn queue_snapshot(&self, limit: i64) -> Result<Vec<QueueJob>> {
        Ok(sqlx::query_as::<_, QueueJob>(sqlx::AssertSqlSafe(format!(
            "{QUEUE_JOB_SQL} ORDER BY j.id DESC LIMIT ?"
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
        let snap = s.queue_snapshot(50).await.unwrap();
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

    #[tokio::test]
    async fn failed_jobs_can_be_retried_once_per_ip() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let a = s.upsert_ip("203.0.113.20".parse().unwrap()).await.unwrap();
        let b = s.upsert_ip("203.0.113.21".parse().unwrap()).await.unwrap();
        // a: two failures (only the latest is retried); b: a failure plus a pending job.
        for _ in 0..2 {
            s.enqueue_scan(a.id, 3, 0).await.unwrap();
            let j = s.next_queued_job().await.unwrap().unwrap();
            s.finish_job(j.id, None, Some("host reported down"))
                .await
                .unwrap();
        }
        s.enqueue_scan(b.id, 3, 0).await.unwrap();
        let j = s.next_queued_job().await.unwrap().unwrap();
        s.finish_job(j.id, None, Some("timeout")).await.unwrap();
        sqlx::query("INSERT INTO scan_jobs (ip_id, level, status, queued_at) VALUES (?, 4, 'queued', datetime('now'))")
            .bind(b.id)
            .execute(&s.pool)
            .await
            .unwrap();

        assert_eq!(s.requeue_failed_jobs(7).await.unwrap(), 1);
        let queued: Vec<(i64, Option<String>)> = sqlx::query_as(
            "SELECT ip_id, error FROM scan_jobs WHERE status = 'queued' ORDER BY id",
        )
        .fetch_all(&s.pool)
        .await
        .unwrap();
        assert_eq!(queued, vec![(a.id, None), (b.id, None)]);
        assert_eq!(s.requeue_failed_jobs(7).await.unwrap(), 0, "idempotent");
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
        assert_eq!(m.hourly_arrivals.len(), 24);
        assert_eq!(m.hourly_arrivals[23], 3);
        assert_eq!(m.hourly_completions[23], 1);
        assert_eq!(m.observed_hours, 1.0);
        assert!((m.avg_scan_secs.unwrap() - 120.0).abs() < 1.0);
        assert!(m.oldest_queued_secs.is_some());

        assert_eq!(s.setting_get("k").await.unwrap(), None);
        s.setting_set("k", "1").await.unwrap();
        s.setting_set("k", "2").await.unwrap();
        assert_eq!(s.setting_get("k").await.unwrap().as_deref(), Some("2"));
    }
}
