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

    pub async fn recent_scans_last_hour(&self) -> Result<i64> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM scans WHERE finished_at > datetime('now','-1 hour')",
        )
        .fetch_one(&self.pool)
        .await?)
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
        Ok(
            sqlx::query_as::<_, QueueJob>(&format!("{QUEUE_JOB_SQL} WHERE j.id = ?"))
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Newest jobs first; `limit` rows.
    pub async fn queue_snapshot(&self, limit: i64) -> Result<Vec<QueueJob>> {
        Ok(
            sqlx::query_as::<_, QueueJob>(&format!("{QUEUE_JOB_SQL} ORDER BY j.id DESC LIMIT ?"))
                .bind(limit)
                .fetch_all(&self.pool)
                .await?,
        )
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
}
