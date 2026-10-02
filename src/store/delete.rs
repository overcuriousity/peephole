//! Admin deletes, as tombstone records (see `store::data`). Each returns
//! whether the primary row existed.
use super::Store;
use anyhow::Result;

impl Store {
    pub async fn delete_request(&self, id: i64) -> Result<bool> {
        Ok(self.local().delete_request(id).await?.deleted > 0)
    }

    pub async fn delete_ip(&self, ip_id: i64) -> Result<bool> {
        self.local().delete_ip(ip_id).await
    }

    pub async fn delete_scan(&self, scan_id: i64) -> Result<bool> {
        Ok(self.local().delete_scan(scan_id).await?.deleted > 0)
    }

    pub async fn delete_claim(&self, id: i64) -> Result<bool> {
        Ok(self.local().delete_claim(id).await?.deleted > 0)
    }

    /// Delete many requests (and their claims/fingerprints).
    pub async fn delete_requests(&self, ids: &[i64]) -> Result<u64> {
        Ok(self.local().delete_requests(ids).await?.deleted)
    }

    /// Delete many IPs with everything hanging off them; returns how many
    /// of them existed.
    pub async fn delete_ips(&self, ids: &[i64]) -> Result<u64> {
        let mut n = 0;
        for id in ids {
            n += self.local().delete_ip(*id).await? as u64;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use crate::scan::nmap_xml::{PortResult, ScanResult};
    use crate::store::Store;
    use crate::store::requests::NewRequest;

    async fn seeded() -> (Store, i64, i64) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let mut ids = vec![];
        for ip in ["203.0.113.1", "203.0.113.2"] {
            let row = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
            let rid = s
                .insert_request(&NewRequest {
                    ip_id: row.id,
                    method: "GET".into(),
                    path: "/x".into(),
                    query: None,
                    headers_json: "[]".into(),
                    body: None,
                    labels_json: "[]".into(),
                    severity: 1,
                    scan_level: 1,
                    is_fp_claim: false,
                    page_token: None,
                    ..Default::default()
                })
                .await
                .unwrap();
            s.local()
                .insert_skip_batch(
                    ip,
                    2,
                    vec![crate::cluster::record::SkipRow {
                        ts_ms: chrono::Utc::now().timestamp_millis(),
                        method: "GET".into(),
                        path: "/y".into(),
                    }],
                )
                .await
                .unwrap();
            s.insert_fp_claim(row.id, rid, Some("a@b.c"), "UA")
                .await
                .unwrap();
            s.insert_fingerprint(Some(rid), row.id, "hash", None, "{}", "{}", b"[]")
                .await
                .unwrap();
            let job = match s.enqueue_scan(row.id, 2, 24).await.unwrap() {
                crate::store::scans::EnqueueOutcome::Queued(j) => j,
                o => panic!("{o:?}"),
            };
            s.next_queued_job().await.unwrap();
            s.finish_job(
                job,
                Some(&ScanResult {
                    os_guess: Some("Linux".into()),
                    raw_xml: b"<nmaprun/>".to_vec(),
                    ports: vec![PortResult {
                        port: 22,
                        proto: "tcp".into(),
                        state: "open".into(),
                        service: Some("ssh".into()),
                        product: None,
                        version: None,
                    }],
                }),
                None,
            )
            .await
            .unwrap();
            ids.push(row.id);
        }
        (s, ids[0], ids[1])
    }

    async fn count(s: &Store, table: &str, col: &str, id: i64) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM {table} WHERE {col} = ?"
        )))
        .bind(id)
        .fetch_one(&s.pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn delete_ip_cascades_and_spares_neighbours() {
        let (s, a, b) = seeded().await;
        assert!(s.delete_ip(a).await.unwrap());
        for t in [
            "requests",
            "fp_claims",
            "fingerprints",
            "scan_jobs",
            "scans",
            "skipped_batches",
        ] {
            assert_eq!(count(&s, t, "ip_id", a).await, 0, "{t}");
            assert_eq!(count(&s, t, "ip_id", b).await, 1, "{t} neighbour");
        }
        assert_eq!(count(&s, "ips", "id", a).await, 0);
        let ports: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ports")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(ports, 1);
        assert!(
            !s.delete_ip(a).await.unwrap(),
            "second delete reports absence"
        );
    }

    #[tokio::test]
    async fn delete_request_removes_dependents_only() {
        let (s, a, _) = seeded().await;
        let rid: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE ip_id = ?")
            .bind(a)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert!(s.delete_request(rid).await.unwrap());
        assert_eq!(count(&s, "requests", "id", rid).await, 0);
        assert_eq!(count(&s, "fp_claims", "request_id", rid).await, 0);
        assert_eq!(count(&s, "fingerprints", "request_id", rid).await, 0);
        assert_eq!(count(&s, "ips", "id", a).await, 1, "ip row stays");
        assert_eq!(count(&s, "scans", "ip_id", a).await, 1, "scans stay");
    }

    #[tokio::test]
    async fn bulk_matching_and_delete() {
        use crate::store::browse::{IpFilter, RequestFilter};
        let (s, a, b) = seeded().await;
        let c = s.upsert_ip("198.51.100.9".parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: c.id,
            method: "GET".into(),
            path: "/x".into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: "[]".into(),
            severity: 1,
            scan_level: 1,
            is_fp_claim: false,
            page_token: None,
            ..Default::default()
        })
        .await
        .unwrap();
        let f = RequestFilter {
            path: Some("/x".into()),
            ..Default::default()
        };
        let ids = s.matching_request_ids(&f).await.unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(s.count_requests(&f).await.unwrap().n, 3);
        assert_eq!(s.delete_requests(&ids[1..]).await.unwrap(), 2);
        assert_eq!(s.matching_request_ids(&f).await.unwrap().len(), 1);
        let total_claims: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fp_claims")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert!(total_claims <= 1, "claims of deleted requests are gone");

        let ipf = IpFilter {
            q: Some("203.0.113.0/24".into()),
            ..Default::default()
        };
        let ip_ids = s.matching_ip_ids(&ipf).await.unwrap();
        assert_eq!(ip_ids.len(), 2);
        assert_eq!(s.count_ips(&ipf).await.unwrap(), 2);
        // a and b lost their requests above; only c still has a severity-1 row.
        assert_eq!(
            s.count_ips(&IpFilter {
                min_severity: Some(1),
                ..Default::default()
            })
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            s.count_ips(&IpFilter {
                q: Some("garbage".into()),
                ..Default::default()
            })
            .await
            .unwrap(),
            0
        );
        assert!(ip_ids.contains(&a) && ip_ids.contains(&b));
        assert_eq!(s.delete_ips(&ip_ids).await.unwrap(), 2);
        assert_eq!(count(&s, "ips", "id", a).await, 0);
        assert_eq!(count(&s, "ips", "id", c.id).await, 1);
        assert_eq!(count(&s, "requests", "ip_id", c.id).await, 1);
        assert_eq!(s.delete_ips(&[]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn delete_scan_and_claim() {
        let (s, a, _) = seeded().await;
        let sid: i64 = sqlx::query_scalar("SELECT id FROM scans WHERE ip_id = ?")
            .bind(a)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert!(s.delete_scan(sid).await.unwrap());
        assert_eq!(count(&s, "ports", "scan_id", sid).await, 0);
        let cid: i64 = sqlx::query_scalar("SELECT id FROM fp_claims WHERE ip_id = ?")
            .bind(a)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert!(s.delete_claim(cid).await.unwrap());
        assert!(!s.delete_claim(cid).await.unwrap());
    }

    /// Retention (standalone) finds old light-row batches by index, not by
    /// scanning the table.
    #[tokio::test]
    async fn retention_of_light_rows_uses_an_index() {
        let (s, _a, _b) = seeded().await;
        for sql in [
            "EXPLAIN QUERY PLAN SELECT uid FROM skipped_batches
             WHERE last_ms < 5 ORDER BY last_ms LIMIT 10",
        ] {
            let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .fetch_all(&s.pool)
                .await
                .unwrap();
            let text: Vec<&str> = plan.iter().map(|r| r.3.as_str()).collect();
            assert!(
                text.iter().any(|t| t.contains("last_ms")),
                "{sql}: {text:?}"
            );
        }
    }

    #[tokio::test]
    async fn retention_prunes_old_requests_and_scans() {
        let (s, _a, _b) = seeded().await;
        // Age everything past the window.
        sqlx::query("UPDATE requests SET ts = datetime('now','-100 days')")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE scans SET finished_at = datetime('now','-100 days')")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE scan_jobs SET finished_at = datetime('now','-100 days')")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE skipped_batches SET first_ms = 0, last_ms = 0")
            .execute(&s.pool)
            .await
            .unwrap();
        let (reqs, scans) = s.local().prune_older_than(90).await.unwrap();
        // Finished jobs go too, and with them the last rows of both IPs.
        for table in ["scan_jobs", "skipped_batches", "skipped_requests", "ips"] {
            let n: i64 =
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                    .fetch_one(&s.pool)
                    .await
                    .unwrap();
            assert_eq!(n, 0, "{table}");
        }
        // The local tombstones these deletes left behind are dropped on a
        // standalone node.
        assert!(s.prune_local_tombstones().await.unwrap() > 0);
        let t: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tombstoned")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(t, 0);
        assert_eq!(reqs, 2);
        assert_eq!(scans, 2);
        let rc: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requests")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        let sc: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(rc, 0, "old requests pruned");
        assert_eq!(sc, 0, "old scans pruned");
        // Claims and fingerprints of pruned requests are gone too.
        let fc: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fingerprints")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(fc, 0);
        // Disabled retention is a no-op.
        assert_eq!(s.local().prune_older_than(0).await.unwrap(), (0, 0));
    }
}
