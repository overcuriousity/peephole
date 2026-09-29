use anyhow::Result;
use chrono::{DateTime, Utc};
use crate::scan::nmap_xml::ScanResult;
use super::Store;

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
    pub async fn enqueue_scan(&self, ip_id: i64, level: u8, cooldown_hours: i64) -> Result<EnqueueOutcome> {
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
        if let Some((last_level,)) = recent {
            if (level as i64) <= last_level {
                return Ok(EnqueueOutcome::Cooldown);
            }
        }
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_jobs WHERE ip_id = ? AND status IN ('queued','running')",
        ).bind(ip_id).fetch_one(&self.pool).await?;
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
        ).fetch_one(&self.pool).await?)
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

    pub async fn finish_job(&self, job_id: i64, result: Option<&ScanResult>, error: Option<&str>) -> Result<()> {
        let job = sqlx::query_as::<_, ScanJobRow>("SELECT * FROM scan_jobs WHERE id=?")
            .bind(job_id).fetch_one(&self.pool).await?;
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
                sqlx::query("UPDATE scan_jobs SET status='done', finished_at=datetime('now') WHERE id=?")
                    .bind(job_id).execute(&self.pool).await?;
            }
            None => {
                sqlx::query("UPDATE scan_jobs SET status='failed', finished_at=datetime('now'), error=? WHERE id=?")
                    .bind(error).bind(job_id).execute(&self.pool).await?;
            }
        }
        Ok(())
    }
}
