//! Admin-only read models: scans, ports, fingerprints, claims, queue
//! health, full request detail. Never called from public handlers.
use super::Store;
use super::browse::{PAGE_SIZE, Page, offset};
use super::requests::RequestRow;
use crate::events::QueueJob;
use anyhow::Result;

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ScanSummary {
    pub id: i64,
    pub ip_id: i64,
    pub ip: String,
    pub level: i64,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub os_guess: Option<String>,
    pub open_ports: i64,
    /// Distributed mode: the node that ran the scan (admin only).
    pub node: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct PortRow {
    pub port: i64,
    pub proto: String,
    pub state: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FpSummary {
    pub hash: String,
    pub count: i64,
    pub other_ips: i64,
    pub visitor_ids: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FpCluster {
    pub hash: String,
    pub ips: Vec<String>,
    pub count: i64,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct FpClaimRow {
    pub id: i64,
    pub ts: String,
    pub ip: String,
    pub contact_email: Option<String>,
    pub user_agent: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QueueSummary {
    pub queued: i64,
    pub running: i64,
    pub done_24h: i64,
    pub failed_24h: i64,
    pub scans_last_hour: i64,
}

pub struct RequestDetail {
    pub row: RequestRow,
    pub ip: String,
    pub headers: Vec<(String, String)>,
    pub body_text: String,
    /// Base64 of the raw (shown) body bytes, for an accurate hex view — the
    /// lossy `body_text` and HTML newline normalisation corrupt binary bytes.
    pub body_b64: String,
    pub body_len: usize,
    pub body_truncated: bool,
    pub fingerprint: Option<FpSummary>,
    /// Distributed mode: the node that recorded it.
    pub node: Option<String>,
}

const SCAN_SELECT: &str =
    "SELECT s.id, s.ip_id, i.ip, s.level, s.started_at, s.finished_at, s.os_guess,
            (SELECT COUNT(*) FROM ports p WHERE p.scan_id = s.id AND p.state = 'open') AS open_ports,
            (SELECT name FROM members m WHERE m.id = s.origin) AS node
     FROM scans s JOIN ips i ON s.ip_id = i.id";

const CLAIM_SELECT: &str = "SELECT c.id, c.ts, i.ip, c.contact_email, c.user_agent FROM fp_claims c JOIN ips i ON c.ip_id = i.id";

const BODY_LIMIT: usize = 16 * 1024;
/// Upper bound on a decompressed scan's raw nmap XML.
const MAX_RAW_XML: u64 = 64 * 1024 * 1024;

/// Decompress zstd data, refusing output larger than `limit` (bomb guard).
fn zstd_decode_capped(data: &[u8], limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut dec = zstd::stream::Decoder::new(data)?;
    let mut out = Vec::new();
    // Read one byte past the limit to detect overflow.
    let n = dec.by_ref().take(limit + 1).read_to_end(&mut out)?;
    anyhow::ensure!(
        n as u64 <= limit,
        "decompressed scan XML exceeds {limit} bytes"
    );
    Ok(out)
}

/// `(ip, provider, fetched_at, source_version, origin, data_json)`.
pub type IntelRow = (String, String, String, Option<String>, Vec<u8>, String);

impl Store {
    /// Enrichment results with the node that looked them up, newest first.
    /// Only IPs that still have a row (results outlive deleted IPs).
    pub async fn intel_export(&self, limit: i64) -> Result<Vec<IntelRow>> {
        Ok(sqlx::query_as(
            "SELECT ip, provider, fetched_at, source_version, origin, data_json
             FROM ip_intel
             WHERE EXISTS (SELECT 1 FROM ips WHERE ips.ip = ip_intel.ip)
             ORDER BY fetched_at DESC, ip LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn scans_for_ip(&self, ip_id: i64) -> Result<Vec<ScanSummary>> {
        let sql = format!("{SCAN_SELECT} WHERE s.ip_id = ? ORDER BY s.id DESC");
        Ok(
            sqlx::query_as::<_, ScanSummary>(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(ip_id)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn list_scans(&self, page: u32) -> Result<Page<ScanSummary>> {
        let page = page.max(1);
        let sql = format!(
            "{SCAN_SELECT} ORDER BY s.id DESC LIMIT {} OFFSET {}",
            PAGE_SIZE + 1,
            offset(page)
        );
        let rows = sqlx::query_as::<_, ScanSummary>(sqlx::AssertSqlSafe(sql.as_str()))
            .fetch_all(&self.pool)
            .await?;
        Ok(Page::from_rows(rows, page))
    }

    pub async fn scan_by_id(&self, id: i64) -> Result<Option<ScanSummary>> {
        let sql = format!("{SCAN_SELECT} WHERE s.id = ?");
        Ok(
            sqlx::query_as::<_, ScanSummary>(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn ports_for_scan(&self, scan_id: i64) -> Result<Vec<PortRow>> {
        Ok(sqlx::query_as::<_, PortRow>(
            "SELECT port, proto, state, service, product, version FROM ports WHERE scan_id = ? ORDER BY port",
        )
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Decompressed nmap XML, or `None` when the scan does not exist.
    pub async fn scan_raw_xml(&self, id: i64) -> Result<Option<Vec<u8>>> {
        let blob: Option<Option<Vec<u8>>> =
            sqlx::query_scalar("SELECT raw_xml FROM scans WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        match blob.flatten() {
            // Cap the decompressed size: raw_xml can arrive from any cluster
            // member, so a decompression bomb must not exhaust memory when an
            // admin opens the scan.
            Some(b) => Ok(Some(zstd_decode_capped(&b, MAX_RAW_XML)?)),
            None => Ok(None),
        }
    }

    pub async fn fingerprints_for_ip(&self, ip_id: i64) -> Result<Vec<FpSummary>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT fp_hash, COUNT(*) FROM fingerprints WHERE ip_id = ? AND fp_hash IS NOT NULL
             GROUP BY fp_hash ORDER BY 2 DESC",
        )
        .bind(ip_id)
        .fetch_all(&self.pool)
        .await?;
        let mut out = vec![];
        for (hash, count) in rows {
            let other_ips = self.fingerprint_ip_count(&hash, ip_id).await?;
            let visitor_ids: Vec<String> = sqlx::query_scalar(
                "SELECT DISTINCT visitor_id FROM fingerprints
                 WHERE ip_id = ? AND fp_hash = ? AND visitor_id IS NOT NULL",
            )
            .bind(ip_id)
            .bind(&hash)
            .fetch_all(&self.pool)
            .await?;
            out.push(FpSummary {
                hash,
                count,
                other_ips,
                visitor_ids,
            });
        }
        Ok(out)
    }

    /// Fingerprint hashes seen from more than one source IP.
    pub async fn fingerprint_clusters(&self) -> Result<Vec<FpCluster>> {
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT f.fp_hash, GROUP_CONCAT(DISTINCT i.ip), COUNT(*)
             FROM fingerprints f JOIN ips i ON f.ip_id = i.id WHERE f.fp_hash IS NOT NULL
             GROUP BY f.fp_hash HAVING COUNT(DISTINCT f.ip_id) > 1
             ORDER BY COUNT(DISTINCT f.ip_id) DESC LIMIT 200",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(hash, ips, count)| FpCluster {
                hash,
                ips: ips.split(',').map(str::to_string).collect(),
                count,
            })
            .collect())
    }

    pub async fn claims_for_ip(&self, ip_id: i64) -> Result<Vec<FpClaimRow>> {
        let sql = format!("{CLAIM_SELECT} WHERE c.ip_id = ? ORDER BY c.id DESC");
        Ok(
            sqlx::query_as::<_, FpClaimRow>(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(ip_id)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn inbox(&self) -> Result<Vec<FpClaimRow>> {
        let sql = format!("{CLAIM_SELECT} ORDER BY c.id DESC LIMIT 500");
        Ok(
            sqlx::query_as::<_, FpClaimRow>(sqlx::AssertSqlSafe(sql.as_str()))
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn queue_summary(&self) -> Result<QueueSummary> {
        // SUM over zero rows is NULL, hence the Options.
        let (q, r, d, f): (Option<i64>, Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
            "SELECT SUM(status='queued'), SUM(status='running'),
                    SUM(status='done' AND finished_at > datetime('now','-24 hours')),
                    SUM(status='failed' AND finished_at > datetime('now','-24 hours'))
             FROM scan_jobs",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(QueueSummary {
            queued: q.unwrap_or(0),
            running: r.unwrap_or(0),
            done_24h: d.unwrap_or(0),
            failed_24h: f.unwrap_or(0),
            // Same count the hourly cap uses: every nmap launch, any outcome.
            scans_last_hour: self.jobs_started_last_hour().await?,
        })
    }

    pub async fn recent_failed_jobs(&self, limit: i64) -> Result<Vec<QueueJob>> {
        Ok(sqlx::query_as::<_, QueueJob>(sqlx::AssertSqlSafe(format!(
            "{} WHERE j.status = 'failed' ORDER BY j.id DESC LIMIT ?",
            super::scans::QUEUE_JOB_SQL
        )))
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn request_detail(&self, id: i64) -> Result<Option<RequestDetail>> {
        let Some(row) = self.request_by_id(id).await? else {
            return Ok(None);
        };
        let ip: String = sqlx::query_scalar("SELECT ip FROM ips WHERE id = ?")
            .bind(row.ip_id)
            .fetch_one(&self.pool)
            .await?;
        let headers: Vec<(String, String)> =
            serde_json::from_str(&row.headers_json).unwrap_or_default();
        let body = row.body.clone().unwrap_or_default();
        let body_len = body.len();
        let body_truncated = body_len > BODY_LIMIT;
        let shown = &body[..body_len.min(BODY_LIMIT)];
        let body_text = String::from_utf8_lossy(shown).into_owned();
        let body_b64 = data_encoding::BASE64.encode(shown);
        let fp: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT fp_hash, visitor_id FROM fingerprints WHERE request_id = ? ORDER BY id DESC LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        let fingerprint = match fp {
            Some((hash, visitor)) => Some(FpSummary {
                other_ips: self.fingerprint_ip_count(&hash, row.ip_id).await?,
                count: 1,
                visitor_ids: visitor.into_iter().collect(),
                hash,
            }),
            None => None,
        };
        let node: Option<String> = sqlx::query_scalar(
            "SELECT m.name FROM requests r JOIN members m ON m.id = r.origin WHERE r.id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(Some(RequestDetail {
            node,
            row,
            ip,
            headers,
            body_text,
            body_b64,
            body_len,
            body_truncated,
            fingerprint,
        }))
    }

    pub async fn list_credential_labels(&self) -> Result<Vec<(String, String, String)>> {
        Ok(sqlx::query_as(
            "SELECT hex(cred_id), COALESCE(label,'(unnamed)'), created_at FROM credentials ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::nmap_xml::{PortResult, ScanResult};
    use crate::store::requests::NewRequest;

    async fn seeded() -> (Store, i64) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let a = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        let b = s.upsert_ip("203.0.113.2".parse().unwrap()).await.unwrap();
        let rid = s
            .insert_request(&NewRequest {
                ip_id: a.id,
                method: "POST".into(),
                path: "/login".into(),
                query: None,
                headers_json: r#"[["user-agent","sqlmap"],["x-a","b"]]"#.into(),
                body: Some(b"username=admin".to_vec()),
                labels_json: r#"["bait"]"#.into(),
                severity: 3,
                scan_level: 3,
                is_fp_claim: false,
                page_token: Some("tok".into()),
            })
            .await
            .unwrap();
        s.insert_fingerprint(Some(rid), a.id, "h1", Some("v1"), "{}", "{}", b"[]")
            .await
            .unwrap();
        s.insert_fingerprint(None, b.id, "h1", Some("v1"), "{}", "{}", b"[]")
            .await
            .unwrap();
        s.insert_fp_claim(a.id, rid, Some("me@x.y"), "UA")
            .await
            .unwrap();
        let job = match s.enqueue_scan(a.id, 3, 24).await.unwrap() {
            crate::store::scans::EnqueueOutcome::Queued(j) => j,
            o => panic!("{o:?}"),
        };
        s.next_queued_job().await.unwrap();
        s.finish_job(
            job,
            Some(&ScanResult {
                os_guess: Some("Linux 5".into()),
                raw_xml: b"<nmaprun/>".to_vec(),
                ports: vec![
                    PortResult {
                        port: 22,
                        proto: "tcp".into(),
                        state: "open".into(),
                        service: Some("ssh".into()),
                        product: Some("OpenSSH".into()),
                        version: Some("9".into()),
                    },
                    PortResult {
                        port: 80,
                        proto: "tcp".into(),
                        state: "closed".into(),
                        service: None,
                        product: None,
                        version: None,
                    },
                ],
            }),
            None,
        )
        .await
        .unwrap();
        let job2 = match s.enqueue_scan(b.id, 1, 24).await.unwrap() {
            crate::store::scans::EnqueueOutcome::Queued(j) => j,
            o => panic!("{o:?}"),
        };
        s.next_queued_job().await.unwrap();
        s.finish_job(job2, None, Some("timeout")).await.unwrap();
        (s, a.id)
    }

    #[tokio::test]
    async fn scans_ports_and_xml() {
        let (s, a) = seeded().await;
        let scans = s.scans_for_ip(a).await.unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].open_ports, 1);
        assert_eq!(scans[0].os_guess.as_deref(), Some("Linux 5"));
        let ports = s.ports_for_scan(scans[0].id).await.unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, 22);
        assert_eq!(
            s.scan_raw_xml(scans[0].id).await.unwrap().unwrap(),
            b"<nmaprun/>"
        );
        assert!(s.scan_raw_xml(999).await.unwrap().is_none());
        let page = s.list_scans(1).await.unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].ip, "203.0.113.1");
        assert_eq!(s.scan_by_id(scans[0].id).await.unwrap().unwrap().level, 3);
    }

    #[tokio::test]
    async fn fingerprints_claims_and_clusters() {
        let (s, a) = seeded().await;
        let fps = s.fingerprints_for_ip(a).await.unwrap();
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0].hash, "h1");
        assert_eq!(fps[0].other_ips, 1);
        assert_eq!(fps[0].visitor_ids, vec!["v1".to_string()]);
        let clusters = s.fingerprint_clusters().await.unwrap();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].ips.len(), 2);
        let claims = s.claims_for_ip(a).await.unwrap();
        assert_eq!(claims[0].contact_email.as_deref(), Some("me@x.y"));
        assert_eq!(s.inbox().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn queue_summary_failed_jobs_and_request_detail() {
        let (s, a) = seeded().await;
        let q = s.queue_summary().await.unwrap();
        assert_eq!(q.done_24h, 1);
        assert_eq!(q.failed_24h, 1);
        assert_eq!(q.queued, 0);
        assert_eq!(q.scans_last_hour, 2, "done + failed: both were launched");
        let failed = s.recent_failed_jobs(10).await.unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].error.as_deref(), Some("timeout"));
        let rid: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE ip_id = ?")
            .bind(a)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        let d = s.request_detail(rid).await.unwrap().unwrap();
        assert_eq!(d.ip, "203.0.113.1");
        assert_eq!(d.headers[0].0, "user-agent");
        assert_eq!(d.body_text, "username=admin");
        assert_eq!(d.body_len, 14);
        assert!(!d.body_truncated);
        assert_eq!(d.fingerprint.as_ref().unwrap().hash, "h1");
        assert!(s.request_detail(999).await.unwrap().is_none());
    }
}
