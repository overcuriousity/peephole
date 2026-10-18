//! The network roll-up: one network's recorded IPs in aggregate, for the
//! admin pages `/admin/asn/{n}` and `/admin/net/{handle}`. Four read-only
//! queries, each driven by the network's index (`idx_ips_asn`,
//! `idx_ips_rdap_handle`); no cache.
use super::Store;
use anyhow::Result;

/// Labels, open ports and campaigns shown on the roll-up.
pub const ROLLUP_TOP: i64 = 8;

/// The network rolled up: an ASN, or an RDAP network by its handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollupKey {
    Asn(i64),
    Net(String),
}

impl RollupKey {
    /// `(column, name column)` of `ips` the network is read from.
    fn cols(&self) -> (&'static str, &'static str) {
        match self {
            RollupKey::Asn(_) => ("asn", "asn_org"),
            RollupKey::Net(_) => ("rdap_handle", "rdap_name"),
        }
    }

    /// `sql` for this network: `{col}` and `{name}` filled in.
    fn sql(&self, sql: &str) -> String {
        let (col, name) = self.cols();
        sql.replace("{col}", col).replace("{name}", name)
    }

    fn bind<'q, O>(
        &self,
        q: sqlx::query::QueryAs<'q, sqlx::Sqlite, O, sqlx::sqlite::SqliteArguments>,
    ) -> sqlx::query::QueryAs<'q, sqlx::Sqlite, O, sqlx::sqlite::SqliteArguments> {
        match self {
            RollupKey::Asn(n) => q.bind(*n),
            RollupKey::Net(h) => q.bind(h.clone()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Rollup {
    /// The network's name: the geo lookups' for an ASN, RDAP's for a
    /// network.
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
        coalesce(max(max_severity), 0), min(first_seen), max(last_seen), max({name})
     FROM ips WHERE {col} = ?";
const LABELS: &str = "SELECT l.label, count(*) AS n
     FROM ips i JOIN ip_labels l ON l.ip_id = i.id
     WHERE i.{col} = ? AND l.count > 0
     GROUP BY l.label ORDER BY n DESC, l.label LIMIT ?";
const OPEN_PORTS: &str = "SELECT p.port, count(DISTINCT i.id) AS n
     FROM ips i JOIN scans s ON s.ip_id = i.id JOIN ports p ON p.scan_id = s.id
     WHERE i.{col} = ? AND p.state = 'open'
     GROUP BY p.port ORDER BY n DESC, p.port LIMIT ?";
const CAMPAIGNS: &str = "SELECT c.key, c.num, count(*) AS n
     FROM ips i JOIN campaign_members m ON m.ip_id = i.id
     JOIN campaigns c ON c.key = m.campaign_key
     WHERE i.{col} = ?
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
    /// The roll-up of every IP in the network; `None` when none is recorded.
    pub async fn rollup(&self, key: &RollupKey) -> Result<Option<Rollup>> {
        let q = |sql| sqlx::AssertSqlSafe(key.sql(sql));
        let (ips, requests, max_severity, first_seen, last_seen, org): Tiles = key
            .bind(sqlx::query_as(q(TILES)))
            .fetch_one(&self.pool)
            .await?;
        if ips == 0 {
            return Ok(None);
        }
        let labels = key
            .bind(sqlx::query_as(q(LABELS)))
            .bind(ROLLUP_TOP)
            .fetch_all(&self.pool)
            .await?;
        let open_ports = key
            .bind(sqlx::query_as(q(OPEN_PORTS)))
            .bind(ROLLUP_TOP)
            .fetch_all(&self.pool)
            .await?;
        let campaigns = key
            .bind(sqlx::query_as(q(CAMPAIGNS)))
            .bind(ROLLUP_TOP)
            .fetch_all(&self.pool)
            .await?;
        Ok(Some(Rollup {
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

    pub(crate) async fn seeded() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        seed(&s).await;
        s
    }

    /// Two IPs in AS 64500 and RDAP network `NET-1` (labelled requests, one
    /// open port on the first, both in one campaign) and one in AS 64501 and
    /// `NET-2`.
    pub(crate) async fn seed(s: &Store) {
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
        for (ip, handle) in [(&a.ip, "NET-1"), (&b.ip, "NET-1"), (&c.ip, "NET-2")] {
            crate::store::rdap_net::tests::rdap(s, ip, None, 1, handle, "Example RDAP").await;
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
            sqlx::query(
                "INSERT INTO campaign_members (ip_id, campaign_key) VALUES (?, '203.0.113.1')",
            )
            .bind(ip)
            .execute(&s.pool)
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn rollup_counts_the_networks_ips() {
        let s = seeded().await;
        let r = s.rollup(&RollupKey::Asn(64500)).await.unwrap().unwrap();
        assert_eq!(r.org.as_deref(), Some("Example Net"));
        assert_eq!((r.ips, r.requests, r.max_severity), (2, 3, 3));
        assert!(!r.first_seen.is_empty() && r.first_seen <= r.last_seen);
        assert_eq!(r.labels, [("wp".to_string(), 2), ("env".to_string(), 1)]);
        assert_eq!(r.open_ports, [(22, 1)], "the closed port is not counted");
        assert_eq!(r.campaigns, [("203.0.113.1".to_string(), 7, 2)]);
        assert!(s.rollup(&RollupKey::Asn(64999)).await.unwrap().is_none());
    }

    /// Every roll-up query starts from the network's IPs, through its index.
    #[tokio::test]
    async fn rollup_queries_read_the_network_index() {
        let s = seeded().await;
        for (key, index) in [
            (RollupKey::Asn(64500), "idx_ips_asn"),
            (RollupKey::Net("NET-1".into()), "idx_ips_rdap_handle"),
        ] {
            for sql in [TILES, LABELS, OPEN_PORTS, CAMPAIGNS] {
                let sql = format!("EXPLAIN QUERY PLAN {}", key.sql(sql));
                let plan: Vec<(i64, i64, i64, String)> = key
                    .bind(sqlx::query_as(sqlx::AssertSqlSafe(sql.clone())))
                    .bind(ROLLUP_TOP)
                    .fetch_all(&s.pool)
                    .await
                    .unwrap();
                assert!(plan.iter().any(|p| p.3.contains(index)), "{sql}: {plan:?}");
                assert!(
                    !plan.iter().any(|p| p.3.starts_with("SCAN i")),
                    "{sql}: {plan:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn an_rdap_network_rolls_up_like_an_asn() {
        let s = seeded().await;
        let r = s
            .rollup(&RollupKey::Net("NET-1".into()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.org.as_deref(), Some("Example RDAP"));
        assert_eq!((r.ips, r.requests, r.max_severity), (2, 3, 3));
        assert_eq!(r.labels, [("wp".to_string(), 2), ("env".to_string(), 1)]);
        assert_eq!(r.open_ports, [(22, 1)]);
        assert_eq!(r.campaigns, [("203.0.113.1".to_string(), 7, 2)]);
        let none = RollupKey::Net("nope".into());
        assert!(s.rollup(&none).await.unwrap().is_none());
    }
}
