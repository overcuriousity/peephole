//! The blocklist feed's query: addresses that sent requests of a severity
//! in a time window. Exclusions that need more than the database (cluster
//! members, the node's own networks) are applied by the handler.
//!
//! Public, like the IP directory it is drawn from: only released requests
//! count (`[public] delay_minutes`).
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
             WHERE i.pub_last_seen >= ?1 AND i.pub_max_severity >= ?2 AND i.is_tor_exit = 0
               AND EXISTS (SELECT 1 FROM requests r
                           WHERE r.ip_id = i.id AND r.severity >= ?2 AND r.ts >= ?1
                             AND r.public_at IS NULL)
               AND NOT EXISTS (SELECT 1 FROM scan_jobs j
                               WHERE j.ip_id = i.id AND j.status = 'refused'
                                 AND j.error LIKE 'verified crawler%')
             ORDER BY i.pub_last_seen DESC LIMIT ?3",
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
             WHERE i.pub_last_seen >= ?1
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    #[tokio::test]
    async fn pending_rows_stay_off_the_blocklist() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        s.set_publish_delay(
            std::time::Duration::from_secs(300),
            std::time::Duration::ZERO,
        )
        .await
        .unwrap();
        let ip = s.upsert_ip("203.0.113.5".parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: "/x".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            severity: 4,
            ..Default::default()
        })
        .await
        .unwrap();
        let q = BlocklistQuery {
            since: "2000-01-01 00:00:00".into(),
            min_severity: 3,
            limit: 100,
        };
        assert!(s.blocklist_ips(&q).await.unwrap().is_empty());
        sqlx::query("UPDATE requests SET public_at = datetime('now', '-1 seconds')")
            .execute(&s.pool)
            .await
            .unwrap();
        s.release_due().await.unwrap();
        assert_eq!(s.blocklist_ips(&q).await.unwrap(), ["203.0.113.5"]);
    }
}
