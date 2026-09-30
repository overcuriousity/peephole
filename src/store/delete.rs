//! Admin deletes. Each runs in one transaction and returns whether the
//! primary row existed. Foreign keys are ON, so dependents go first.
use super::Store;
use anyhow::Result;

impl Store {
    pub async fn delete_request(&self, id: i64) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM fp_claims WHERE request_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM fingerprints WHERE request_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let n = sqlx::query("DELETE FROM requests WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(n > 0)
    }

    pub async fn delete_ip(&self, ip_id: i64) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        for sql in [
            "DELETE FROM ports WHERE scan_id IN (SELECT id FROM scans WHERE ip_id = ?)",
            "DELETE FROM scans WHERE ip_id = ?",
            "DELETE FROM scan_jobs WHERE ip_id = ?",
            "DELETE FROM fingerprints WHERE ip_id = ?",
            "DELETE FROM fp_claims WHERE ip_id = ?",
            "DELETE FROM requests WHERE ip_id = ?",
        ] {
            sqlx::query(sql).bind(ip_id).execute(&mut *tx).await?;
        }
        let n = sqlx::query("DELETE FROM ips WHERE id = ?")
            .bind(ip_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(n > 0)
    }

    pub async fn delete_scan(&self, scan_id: i64) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM ports WHERE scan_id = ?")
            .bind(scan_id)
            .execute(&mut *tx)
            .await?;
        let n = sqlx::query("DELETE FROM scans WHERE id = ?")
            .bind(scan_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(n > 0)
    }

    pub async fn delete_claim(&self, id: i64) -> Result<bool> {
        let n = sqlx::query("DELETE FROM fp_claims WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n > 0)
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
                })
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
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {col} = ?"))
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
}
