//! Admin-only read models: scans, ports, fingerprints, claims, queue
//! health, full request detail. Never called from public handlers.
use super::Store;
use super::browse::{PAGE_SIZE, Page, offset};
use super::recorder::Recorder;
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

/// Job states that end a job; the history filter offers these.
pub const FINISHED_STATUSES: [&str; 4] = ["done", "failed", "superseded", "refused"];

/// Scan history filter. A status that is not finished is ignored.
#[derive(Debug, Clone, Default)]
pub struct JobFilter {
    pub status: Option<String>,
    pub level: Option<i64>,
}

/// One finished job, with its scan when it produced one.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct HistoryRow {
    pub id: i64,
    pub ip: String,
    pub level: i64,
    pub status: String,
    pub finished_at: Option<String>,
    pub error: Option<String>,
    pub scanner: Option<String>,
    pub arbiter: Option<String>,
    pub scan_id: Option<i64>,
    pub os_guess: Option<String>,
    pub open_ports: i64,
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
    /// The start of the fingerprint of the ruleset that classified it.
    pub rules_short: Option<String>,
}

const SCAN_SELECT: &str =
    "SELECT s.id, s.ip_id, i.ip, s.level, s.started_at, s.finished_at, s.os_guess,
            (SELECT COUNT(*) FROM ports p WHERE p.scan_id = s.id AND p.state = 'open') AS open_ports,
            (SELECT name FROM members m WHERE m.id = s.origin) AS node
     FROM scans s JOIN ips i ON s.ip_id = i.id";

const CLAIM_SELECT: &str = "SELECT c.id, c.ts, i.ip, c.contact_email, COALESCE(c.user_agent, '') AS user_agent FROM fp_claims c JOIN ips i ON c.ip_id = i.id";

const BODY_LIMIT: usize = 16 * 1024;
/// Upper bound on a decompressed scan's raw nmap XML.
pub(crate) const MAX_RAW_XML: u64 = 64 * 1024 * 1024;

/// Decompress zstd data, refusing output larger than `limit` (bomb guard).
pub(crate) fn zstd_decode_capped(data: &[u8], limit: u64) -> Result<Vec<u8>> {
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

/// One provider result for one IP, as the IP page shows it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IpIntelRow {
    pub provider: String,
    pub fetched_at: String,
    pub source_version: Option<String>,
    pub data_json: String,
    pub node: Option<String>,
}

/// Lookups per provider shown on the IP page.
pub const INTEL_HISTORY_PER_PROVIDER: i64 = 50;

impl Store {
    /// Every provider's results for one IP from the lookup history, newest
    /// first per provider (at most [`INTEL_HISTORY_PER_PROVIDER`] each), with
    /// the cluster node that looked each one up (None standalone or for a
    /// node no longer in `members`).
    pub async fn intel_for_ip(&self, ip: &str) -> Result<Vec<IpIntelRow>> {
        Ok(sqlx::query_as::<_, IpIntelRow>(
            "SELECT provider, fetched_at, source_version, data_json, node FROM (
               SELECT t.provider, t.fetched_at, t.source_version, t.data_json, t.hlc, t.origin,
                      (SELECT name FROM members m WHERE m.id = t.origin) AS node,
                      row_number() OVER (PARTITION BY t.provider
                                         ORDER BY t.hlc DESC, t.origin DESC) AS n
               FROM ip_intel_log t WHERE t.ip = ?)
             WHERE n <= ?
             ORDER BY provider, hlc DESC, origin DESC",
        )
        .bind(ip)
        .bind(INTEL_HISTORY_PER_PROVIDER)
        .fetch_all(&self.read)
        .await?)
    }

    /// Provider tags present on any IP, most common first (admin filter).
    pub async fn intel_tags(&self) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT tag FROM ip_intel_tags GROUP BY tag ORDER BY COUNT(*) DESC, tag LIMIT 300",
        )
        .fetch_all(&self.read)
        .await?)
    }

    /// Scan jobs for one IP in any state, newest first.
    pub async fn jobs_for_ip(
        &self,
        ip_id: i64,
        limit: i64,
    ) -> Result<Vec<crate::events::QueueJob>> {
        Ok(
            sqlx::query_as::<_, crate::events::QueueJob>(sqlx::AssertSqlSafe(format!(
                "{} WHERE j.ip_id = ? ORDER BY j.id DESC LIMIT ?",
                crate::store::scans::QUEUE_JOB_SQL
            )))
            .bind(ip_id)
            .bind(limit)
            .fetch_all(&self.read)
            .await?,
        )
    }

    pub async fn scans_for_ip(&self, ip_id: i64) -> Result<Vec<ScanSummary>> {
        let sql = format!("{SCAN_SELECT} WHERE s.ip_id = ? ORDER BY s.id DESC");
        Ok(
            sqlx::query_as::<_, ScanSummary>(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(ip_id)
                .fetch_all(&self.read)
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
            .fetch_all(&self.read)
            .await?;
        Ok(Page::from_rows(rows, page))
    }

    /// Finished jobs, newest first, one page.
    pub async fn job_history(&self, f: &JobFilter, page: u32) -> Result<Page<HistoryRow>> {
        let page = page.max(1);
        let status = f
            .status
            .as_deref()
            .filter(|s| FINISHED_STATUSES.contains(s));
        let mut sql = String::from(
            "SELECT j.id, i.ip, j.level, j.status, j.finished_at, j.error,
                    (SELECT name FROM members m WHERE m.id = j.scanner) AS scanner,
                    (SELECT name FROM members m WHERE m.id = j.arbiter) AS arbiter,
                    s.id AS scan_id, s.os_guess,
                    (SELECT COUNT(*) FROM ports p
                      WHERE s.id IS NOT NULL AND p.scan_id = s.id AND p.state = 'open') AS open_ports
             FROM scan_jobs j JOIN ips i ON j.ip_id = i.id
             LEFT JOIN scans s ON s.id = (SELECT MAX(x.id) FROM scans x WHERE x.job_id = j.id)
             WHERE j.status IN ('done', 'failed', 'superseded', 'refused')",
        );
        if status.is_some() {
            sql.push_str(" AND j.status = ?");
        }
        if f.level.is_some() {
            sql.push_str(" AND j.level = ?");
        }
        sql.push_str(&format!(
            " ORDER BY j.id DESC LIMIT {} OFFSET {}",
            PAGE_SIZE + 1,
            offset(page)
        ));
        let mut q = sqlx::query_as::<_, HistoryRow>(sqlx::AssertSqlSafe(sql.as_str()));
        if let Some(s) = status {
            q = q.bind(s);
        }
        if let Some(l) = f.level {
            q = q.bind(l);
        }
        Ok(Page::from_rows(q.fetch_all(&self.read).await?, page))
    }

    pub async fn scan_by_id(&self, id: i64) -> Result<Option<ScanSummary>> {
        let sql = format!("{SCAN_SELECT} WHERE s.id = ?");
        Ok(
            sqlx::query_as::<_, ScanSummary>(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(id)
                .fetch_optional(&self.read)
                .await?,
        )
    }

    pub async fn ports_for_scan(&self, scan_id: i64) -> Result<Vec<PortRow>> {
        Ok(sqlx::query_as::<_, PortRow>(
            "SELECT port, proto, state, service, product, version FROM ports WHERE scan_id = ? ORDER BY port",
        )
        .bind(scan_id)
        .fetch_all(&self.read)
        .await?)
    }

    /// Decompressed nmap XML, or `None` when the scan does not exist.
    pub async fn scan_raw_xml(&self, id: i64) -> Result<Option<Vec<u8>>> {
        let blob: Option<Option<Vec<u8>>> =
            sqlx::query_scalar("SELECT raw_xml FROM scans WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.read)
                .await?;
        match blob.flatten() {
            // Cap the decompressed size: raw_xml can arrive from any cluster
            // member, so a decompression bomb must not exhaust memory when an
            // admin opens the scan.
            Some(b) => Ok(Some(zstd_decode_capped(&b, MAX_RAW_XML)?)),
            None => Ok(None),
        }
    }

    /// Ports of several scans in one query, by scan id.
    pub async fn ports_for_scans(
        &self,
        scan_ids: &[i64],
    ) -> Result<std::collections::HashMap<i64, Vec<PortRow>>> {
        let mut out: std::collections::HashMap<i64, Vec<PortRow>> = Default::default();
        for chunk in scan_ids.chunks(400) {
            let sql = format!(
                "SELECT scan_id, port, proto, state, service, product, version FROM ports
                 WHERE scan_id IN ({}) ORDER BY scan_id, port",
                vec!["?"; chunk.len()].join(",")
            );
            type Row = (
                i64,
                i64,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
            );
            let mut q = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql));
            for id in chunk {
                q = q.bind(id);
            }
            for (scan_id, port, proto, state, service, product, version) in
                q.fetch_all(&self.read).await?
            {
                out.entry(scan_id).or_default().push(PortRow {
                    port,
                    proto,
                    state,
                    service,
                    product,
                    version,
                });
            }
        }
        Ok(out)
    }

    /// The IP's fingerprints by hash, with how many other IPs share each
    /// hash and the visitor ids seen with it (three queries in all).
    pub async fn fingerprints_for_ip(&self, ip_id: i64) -> Result<Vec<FpSummary>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT fp_hash, COUNT(*) FROM fingerprints WHERE ip_id = ? AND fp_hash IS NOT NULL
             GROUP BY fp_hash ORDER BY 2 DESC",
        )
        .bind(ip_id)
        .fetch_all(&self.read)
        .await?;
        let others: std::collections::HashMap<String, i64> = sqlx::query_as(
            "SELECT f.fp_hash, COUNT(DISTINCT f.ip_id) FROM fingerprints f
             WHERE f.fp_hash IN (SELECT fp_hash FROM fingerprints
                                 WHERE ip_id = ?1 AND fp_hash IS NOT NULL)
               AND f.ip_id != ?1
             GROUP BY f.fp_hash",
        )
        .bind(ip_id)
        .fetch_all(&self.read)
        .await?
        .into_iter()
        .collect();
        let mut visitors: std::collections::HashMap<String, Vec<String>> = Default::default();
        let pairs: Vec<(String, String)> = sqlx::query_as(
            "SELECT DISTINCT fp_hash, visitor_id FROM fingerprints
             WHERE ip_id = ? AND fp_hash IS NOT NULL AND visitor_id IS NOT NULL
             ORDER BY fp_hash, visitor_id",
        )
        .bind(ip_id)
        .fetch_all(&self.read)
        .await?;
        for (hash, visitor) in pairs {
            visitors.entry(hash).or_default().push(visitor);
        }
        Ok(rows
            .into_iter()
            .map(|(hash, count)| FpSummary {
                other_ips: others.get(&hash).copied().unwrap_or(0),
                visitor_ids: visitors.remove(&hash).unwrap_or_default(),
                hash,
                count,
            })
            .collect())
    }

    /// Fingerprint hashes seen from more than one source IP.
    pub async fn fingerprint_clusters(&self) -> Result<Vec<FpCluster>> {
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT f.fp_hash, GROUP_CONCAT(DISTINCT i.ip), COUNT(*)
             FROM fingerprints f JOIN ips i ON f.ip_id = i.id WHERE f.fp_hash IS NOT NULL
             GROUP BY f.fp_hash HAVING COUNT(DISTINCT f.ip_id) > 1
             ORDER BY COUNT(DISTINCT f.ip_id) DESC LIMIT 200",
        )
        .fetch_all(&self.read)
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

    /// Requests from this IP answered without being recorded in full: light
    /// rows plus the ones only counted.
    pub async fn skipped_for_ip(&self, ip_id: i64) -> Result<i64> {
        Ok(sqlx::query_scalar(
            "SELECT COALESCE(SUM(dropped + (SELECT COUNT(*) FROM skipped_requests r
                                            WHERE r.batch_id = b.id)), 0)
             FROM skipped_batches b WHERE b.ip_id = ?",
        )
        .bind(ip_id)
        .fetch_one(&self.read)
        .await?)
    }

    pub async fn claims_for_ip(&self, ip_id: i64) -> Result<Vec<FpClaimRow>> {
        let sql = format!("{CLAIM_SELECT} WHERE c.ip_id = ? ORDER BY c.id DESC");
        Ok(
            sqlx::query_as::<_, FpClaimRow>(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(ip_id)
                .fetch_all(&self.read)
                .await?,
        )
    }

    pub async fn inbox(&self) -> Result<Vec<FpClaimRow>> {
        let sql = format!("{CLAIM_SELECT} ORDER BY c.id DESC LIMIT 500");
        Ok(
            sqlx::query_as::<_, FpClaimRow>(sqlx::AssertSqlSafe(sql.as_str()))
                .fetch_all(&self.read)
                .await?,
        )
    }

    /// Number of false-positive claims (the inbox).
    pub async fn inbox_count(&self) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM fp_claims")
            .fetch_one(&self.read)
            .await?)
    }

    /// `rec` is this node's recorder, so the hourly count is the one the
    /// node's rate cap uses (in a cluster: this node's scanner launches).
    pub async fn queue_summary(&self, rec: &Recorder) -> Result<QueueSummary> {
        // Each count is a range of the (status, finished_at) index, not a
        // pass over every job ever queued.
        let (q, r, d, f): (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued'),
                    (SELECT COUNT(*) FROM scan_jobs WHERE status = 'running'),
                    (SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'
                       AND finished_at > datetime('now','-24 hours')),
                    (SELECT COUNT(*) FROM scan_jobs WHERE status = 'failed'
                       AND finished_at > datetime('now','-24 hours'))",
        )
        .fetch_one(&self.read)
        .await?;
        Ok(QueueSummary {
            queued: q,
            running: r,
            done_24h: d,
            failed_24h: f,
            // Same count the hourly cap uses: every nmap launch, any outcome.
            scans_last_hour: rec.jobs_started_last_hour().await?,
        })
    }

    pub async fn recent_failed_jobs(&self, limit: i64) -> Result<Vec<QueueJob>> {
        Ok(sqlx::query_as::<_, QueueJob>(sqlx::AssertSqlSafe(format!(
            "{} WHERE j.status = 'failed' ORDER BY j.id DESC LIMIT ?",
            super::scans::QUEUE_JOB_SQL
        )))
        .bind(limit)
        .fetch_all(&self.read)
        .await?)
    }

    pub async fn request_detail(&self, id: i64) -> Result<Option<RequestDetail>> {
        let Some(row) = self.request_by_id(id).await? else {
            return Ok(None);
        };
        let ip: String = sqlx::query_scalar("SELECT ip FROM ips WHERE id = ?")
            .bind(row.ip_id)
            .fetch_one(&self.read)
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
        .fetch_optional(&self.read)
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
        .fetch_optional(&self.read)
        .await?;
        Ok(Some(RequestDetail {
            node,
            rules_short: row.rules.as_ref().map(|h| h.chars().take(12).collect()),
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
        .fetch_all(&self.read)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::nmap_xml::{PortResult, ScanResult};
    use crate::store::requests::NewRequest;

    #[tokio::test]
    async fn skipped_counts_light_rows_and_drops() {
        let (s, a) = seeded().await;
        assert_eq!(s.skipped_for_ip(a).await.unwrap(), 0);
        let row = |ts_ms| crate::cluster::record::SkipRow {
            ts_ms,
            method: "GET".into(),
            path: "/".into(),
            ..Default::default()
        };
        s.local()
            .insert_skip_batch("203.0.113.1", 4, vec![row(1), row(2)])
            .await
            .unwrap();
        assert_eq!(s.skipped_for_ip(a).await.unwrap(), 6);
    }

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
                ..Default::default()
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
        // A replicated claim may carry no user agent.
        sqlx::query("UPDATE fp_claims SET user_agent = NULL")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(s.inbox().await.unwrap()[0].user_agent, "");
        assert_eq!(s.claims_for_ip(a).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn active_jobs_leave_finished_ones_out() {
        let (s, _) = seeded().await;
        for ip in ["203.0.113.10", "203.0.113.11"] {
            let id = s.upsert_ip(ip.parse().unwrap()).await.unwrap().id;
            s.enqueue_scan(id, 1, 24).await.unwrap();
        }
        let two = s.active_jobs(2).await.unwrap();
        assert_eq!(two.len(), 2, "the two finished jobs take no rows");
        assert!(two.iter().all(|j| j.status == "queued"));
        assert_eq!(s.active_jobs(10).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn job_history_filters_and_links_scans() {
        let (s, _) = seeded().await;
        let all = s.job_history(&JobFilter::default(), 1).await.unwrap();
        assert_eq!(all.items.len(), 2);
        let done = all.items.iter().find(|r| r.status == "done").unwrap();
        assert!(done.scan_id.is_some(), "a done job links to its scan");
        assert_eq!(done.open_ports, 1);
        assert_eq!(done.os_guess.as_deref(), Some("Linux 5"));
        let failed = s
            .job_history(
                &JobFilter {
                    status: Some("failed".into()),
                    level: None,
                },
                1,
            )
            .await
            .unwrap();
        assert_eq!(failed.items.len(), 1);
        assert_eq!(failed.items[0].error.as_deref(), Some("timeout"));
        assert!(failed.items[0].scan_id.is_none());
        let l3 = s
            .job_history(
                &JobFilter {
                    status: None,
                    level: Some(3),
                },
                1,
            )
            .await
            .unwrap();
        assert_eq!(l3.items.len(), 1);
        // Not a finished status: ignored, never an active job.
        let s2 = s
            .upsert_ip("203.0.113.12".parse().unwrap())
            .await
            .unwrap()
            .id;
        s.enqueue_scan(s2, 1, 24).await.unwrap();
        for bogus in ["queued", "running", "x' OR 1=1 --"] {
            let r = s
                .job_history(
                    &JobFilter {
                        status: Some(bogus.into()),
                        level: None,
                    },
                    1,
                )
                .await
                .unwrap();
            assert_eq!(r.items.len(), 2, "{bogus}");
        }
    }

    #[tokio::test]
    async fn queue_summary_failed_jobs_and_request_detail() {
        let (s, a) = seeded().await;
        let q = s.queue_summary(&s.local()).await.unwrap();
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
