//! The blocklist feed's query: addresses that sent requests of a severity
//! in a time window. Exclusions that need more than the database (cluster
//! members, the node's own networks) are applied by the handler.
use super::Store;
use anyhow::Result;

/// What the feed asks for.
#[derive(Debug, Clone, PartialEq)]
pub struct BlocklistQuery {
    /// Earliest request time, `YYYY-MM-DD HH:MM:SS` UTC.
    pub since: String,
    /// Lowest severity (1-4) of a request that puts an IP on the list.
    pub min_severity: i64,
    pub limit: i64,
}

impl Store {
    /// IPs with at least one request of `min_severity` or above since
    /// `since`, newest first. Tor exits never qualify (they are not the
    /// scanner), nor do addresses a scanner refused as a verified crawler.
    pub async fn blocklist_ips(&self, q: &BlocklistQuery) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "SELECT i.ip FROM ips i
             WHERE i.last_seen >= ?1 AND i.max_severity >= ?2 AND i.is_tor_exit = 0
               AND EXISTS (SELECT 1 FROM requests r
                           WHERE r.ip_id = i.id AND r.severity >= ?2 AND r.ts >= ?1)
               AND NOT EXISTS (SELECT 1 FROM scan_jobs j
                               WHERE j.ip_id = i.id AND j.status = 'refused'
                                 AND j.error LIKE 'verified crawler%')
             ORDER BY i.last_seen DESC LIMIT ?3",
        )
        .bind(&q.since)
        .bind(q.min_severity)
        .bind(q.limit)
        .fetch_all(&self.read)
        .await?)
    }

    /// IPs seen since `since` that [`Store::blocklist_ips`] leaves out as
    /// Tor exits or verified crawlers, so the feed does not collapse a
    /// prefix that holds one.
    pub async fn blocklist_spared_ips(&self, since: &str) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "SELECT i.ip FROM ips i
             WHERE i.last_seen >= ?1
               AND (i.is_tor_exit = 1
                    OR EXISTS (SELECT 1 FROM scan_jobs j
                               WHERE j.ip_id = i.id AND j.status = 'refused'
                                 AND j.error LIKE 'verified crawler%'))",
        )
        .bind(since)
        .fetch_all(&self.read)
        .await?)
    }
}
