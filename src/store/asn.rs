//! The ASN roll-up: one network's recorded IPs in aggregate, for the admin
//! page `/admin/asn/{n}`. Four read-only queries, each driven by
//! `idx_ips_asn`; no cache.
use super::Store;
use anyhow::Result;

/// Labels, open ports and campaigns shown on the roll-up.
pub const ROLLUP_TOP: i64 = 8;

#[derive(Debug, Clone, Default)]
pub struct AsnRollup {
    /// The network's name as the geo lookups gave it.
    pub org: Option<String>,
    pub ips: i64,
    pub requests: i64,
    pub max_severity: i64,
    pub first_seen: String,
    pub last_seen: String,
    /// Label and the number of the network's IPs that carry it.
    pub labels: Vec<(String, i64)>,
    /// Port open in a stored scan and the number of IPs it is open on.
    pub open_ports: Vec<(i64, i64)>,
    /// Campaign key, its number and the network's IPs in it.
    pub campaigns: Vec<(String, i64, i64)>,
}

const TILES: &str = "SELECT count(*), coalesce(sum(request_count), 0),
        coalesce(max(max_severity), 0), min(first_seen), max(last_seen), max(asn_org)
     FROM ips WHERE asn = ?";
const LABELS: &str = "SELECT l.label, count(*) AS n
     FROM ips i JOIN ip_labels l ON l.ip_id = i.id
     WHERE i.asn = ? AND l.count > 0
     GROUP BY l.label ORDER BY n DESC, l.label LIMIT ?";
const OPEN_PORTS: &str = "SELECT p.port, count(DISTINCT i.id) AS n
     FROM ips i JOIN scans s ON s.ip_id = i.id JOIN ports p ON p.scan_id = s.id
     WHERE i.asn = ? AND p.state = 'open'
     GROUP BY p.port ORDER BY n DESC, p.port LIMIT ?";
const CAMPAIGNS: &str = "SELECT c.key, c.num, count(*) AS n
     FROM ips i JOIN campaign_members m ON m.ip_id = i.id
     JOIN campaigns c ON c.key = m.campaign_key
     WHERE i.asn = ?
     GROUP BY c.key ORDER BY n DESC, c.num LIMIT ?";

type Tiles = (
    i64,
    i64,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
);

impl Store {
    /// The roll-up of every IP in `asn`; `None` when none is recorded.
    pub async fn asn_rollup(&self, asn: i64) -> Result<Option<AsnRollup>> {
        let (ips, requests, max_severity, first_seen, last_seen, org): Tiles =
            sqlx::query_as(TILES)
                .bind(asn)
                .fetch_one(&self.pool)
                .await?;
        if ips == 0 {
            return Ok(None);
        }
        let labels = sqlx::query_as(LABELS)
            .bind(asn)
            .bind(ROLLUP_TOP)
            .fetch_all(&self.pool)
            .await?;
        let open_ports = sqlx::query_as(OPEN_PORTS)
            .bind(asn)
            .bind(ROLLUP_TOP)
            .fetch_all(&self.pool)
            .await?;
        let campaigns = sqlx::query_as(CAMPAIGNS)
            .bind(asn)
            .bind(ROLLUP_TOP)
            .fetch_all(&self.pool)
            .await?;
        Ok(Some(AsnRollup {
            org,
            ips,
            requests,
            max_severity,
            first_seen: first_seen.unwrap_or_default(),
            last_seen: last_seen.unwrap_or_default(),
            labels,
            open_ports,
            campaigns,
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    /// Two IPs in AS 64500 (labelled requests, one open port on the first,
    /// both in one campaign) and one in AS 64501.
    pub(crate) async fn seeded() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let req = |ip_id, sev, labels: &str| NewRequest {
            ip_id,
            method: "GET".into(),
            path: "/".into(),
            headers_json: "[]".into(),
            labels_json: labels.into(),
            severity: sev,
            scan_level: 1,
            ..Default::default()
        };
        let a = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        let b = s.upsert_ip("203.0.113.2".parse().unwrap()).await.unwrap();
        let c = s.upsert_ip("198.51.100.1".parse().unwrap()).await.unwrap();
        for (ip, asn) in [(a.id, 64500), (b.id, 64500), (c.id, 64501)] {
            s.set_ip_geo(ip, Some("DE"), Some(asn), Some("Example Net"))
                .await
                .unwrap();
        }
        for _ in 0..2 {
            s.insert_request(&req(a.id, 3, r#"["wp","env"]"#))
                .await
                .unwrap();
        }
        s.insert_request(&req(b.id, 1, r#"["wp"]"#)).await.unwrap();
        s.insert_request(&req(c.id, 4, r#"["other"]"#))
            .await
            .unwrap();
        s.enqueue_scan(a.id, 2, 0).await.unwrap();
        let job = s.next_queued_job().await.unwrap().unwrap();
        let port = |port, state: &str| crate::model::nmap_xml::PortResult {
            port,
            proto: "tcp".into(),
            state: state.into(),
            service: None,
            product: None,
            version: None,
        };
        s.finish_job(
            job.id,
            Some(&crate::model::nmap_xml::ScanResult {
                scrubbed: 0,
                os_guess: None,
                raw_xml: vec![],
                ports: vec![port(22, "open"), port(23, "closed")],
            }),
            None,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO campaigns (key, num, anchor_ip_id, size, first_seen, last_seen,
                hard_edges, soft_edges, v, computed_at)
             VALUES ('203.0.113.1', 7, ?, 2, '2026-01-01 00:00:00', '2026-01-01 00:00:00',
                1, 0, 1, '2026-01-01 00:00:00')",
        )
        .bind(a.id)
        .execute(&s.pool)
        .await
        .unwrap();
        for ip in [a.id, b.id] {
            sqlx::query("INSERT INTO campaign_members (ip_id, campaign_key) VALUES (?, '203.0.113.1')")
                .bind(ip)
                .execute(&s.pool)
                .await
                .unwrap();
        }
        s
    }

    #[tokio::test]
    async fn rollup_counts_the_networks_ips() {
        let s = seeded().await;
        let r = s.asn_rollup(64500).await.unwrap().unwrap();
        assert_eq!(r.org.as_deref(), Some("Example Net"));
        assert_eq!((r.ips, r.requests, r.max_severity), (2, 3, 3));
        assert!(!r.first_seen.is_empty() && r.first_seen <= r.last_seen);
        assert_eq!(r.labels, [("wp".to_string(), 2), ("env".to_string(), 1)]);
        assert_eq!(r.open_ports, [(22, 1)], "the closed port is not counted");
        assert_eq!(r.campaigns, [("203.0.113.1".to_string(), 7, 2)]);
        assert!(s.asn_rollup(64999).await.unwrap().is_none());
    }

    /// Every roll-up query starts from the network's IPs.
    #[tokio::test]
    async fn rollup_queries_read_the_asn_index() {
        let s = seeded().await;
        for sql in [TILES, LABELS, OPEN_PORTS, CAMPAIGNS] {
            let plan: Vec<(i64, i64, i64, String)> =
                sqlx::query_as(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}")))
                    .bind(64500)
                    .bind(ROLLUP_TOP)
                    .fetch_all(&s.pool)
                    .await
                    .unwrap();
            assert!(
                plan.iter().any(|p| p.3.contains("idx_ips_asn")),
                "{sql}: {plan:?}"
            );
        }
    }
}
