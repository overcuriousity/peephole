//! Delayed publication: a request reaches the public pages only once
//! released (`requests.public_at` NULL). The insert trigger sets
//! `public_at` from `publish_cfg`; [`run`] releases due rows. Local to each
//! node: neither the column nor the table is replicated.
use super::Store;
use anyhow::Result;
use std::time::Duration;

/// Rows released per write transaction.
pub(crate) const CHUNK: i64 = 2000;
/// Pause between two chunks, so the trap's inserts waiting for the lock
/// get in.
const CHUNK_PAUSE: Duration = Duration::from_millis(50);
/// How often due rows are released.
pub const TICK: Duration = Duration::from_secs(15);

impl Store {
    /// Delay and jitter for requests inserted from now on; zero releases
    /// them at insert.
    pub async fn set_publish_delay(&self, delay: Duration, jitter: Duration) -> Result<()> {
        sqlx::query("UPDATE publish_cfg SET delay_s = ?, jitter_s = ? WHERE id = 1")
            .bind(delay.as_secs() as i64)
            .bind(jitter.as_secs() as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Release every request whose `public_at` has passed. Returns how many.
    pub async fn release_due(&self) -> Result<u64> {
        let mut total = 0;
        loop {
            let n = sqlx::query(
                "UPDATE requests SET public_at = NULL
                 WHERE id IN (SELECT id FROM requests
                              WHERE public_at IS NOT NULL AND public_at <= datetime('now')
                              ORDER BY public_at LIMIT ?)",
            )
            .bind(CHUNK)
            .execute(&self.pool)
            .await?
            .rows_affected();
            total += n;
            if n < CHUNK as u64 {
                return Ok(total);
            }
            tokio::time::sleep(CHUNK_PAUSE).await;
        }
    }
}

/// Release due rows every [`TICK`] until `shutdown` turns `true`.
pub async fn run(store: Store, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        if let Err(e) = store.release_due().await {
            tracing::warn!(?e, "releasing requests to the public pages failed");
        }
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = shutdown.changed() => {}
        }
        if *shutdown.borrow() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (s, dir)
    }

    async fn hit(s: &Store, ip: &str, severity: i64, labels: &str) -> (i64, i64) {
        let row = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
        let id = s
            .insert_request(&NewRequest {
                ip_id: row.id,
                method: "GET".into(),
                path: "/p".into(),
                headers_json: "[]".into(),
                labels_json: labels.into(),
                severity,
                ..Default::default()
            })
            .await
            .unwrap();
        (row.id, id)
    }

    /// (request_count, max_severity, pub_request_count, pub_max_severity,
    ///  pub_first_seen IS NOT NULL, pub_last_seen IS NOT NULL)
    async fn models(s: &Store, ip_id: i64) -> (i64, i64, i64, i64, bool, bool) {
        sqlx::query_as(
            "SELECT request_count, max_severity, pub_request_count, pub_max_severity,
                    pub_first_seen IS NOT NULL, pub_last_seen IS NOT NULL
             FROM ips WHERE id = ?",
        )
        .bind(ip_id)
        .fetch_one(&s.read)
        .await
        .unwrap()
    }

    async fn label(s: &Store, ip_id: i64, l: &str) -> (i64, i64) {
        sqlx::query_as("SELECT count, pub_count FROM ip_labels WHERE ip_id = ? AND label = ?")
            .bind(ip_id)
            .bind(l)
            .fetch_optional(&s.read)
            .await
            .unwrap()
            .unwrap_or((0, 0))
    }

    /// Make every pending row due now.
    async fn make_due(s: &Store) {
        sqlx::query("UPDATE requests SET public_at = datetime('now', '-1 seconds') WHERE public_at IS NOT NULL")
            .execute(&s.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn without_a_delay_rows_are_public_at_once() {
        let (s, _d) = store().await;
        let (ip, _) = hit(&s, "203.0.113.1", 3, r#"["wp"]"#).await;
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM requests WHERE public_at IS NOT NULL")
                .fetch_one(&s.read)
                .await
                .unwrap();
        assert_eq!(pending, 0);
        assert_eq!(models(&s, ip).await, (1, 3, 1, 3, true, true));
        assert_eq!(label(&s, ip, "wp").await, (1, 1));
    }

    #[tokio::test]
    async fn a_delayed_row_waits_within_delay_plus_jitter() {
        let (s, _d) = store().await;
        s.set_publish_delay(Duration::from_secs(300), Duration::from_secs(300))
            .await
            .unwrap();
        let (ip, id) = hit(&s, "203.0.113.1", 3, r#"["wp"]"#).await;
        let wait: i64 = sqlx::query_scalar(
            "SELECT CAST(strftime('%s', public_at) AS INTEGER) - CAST(strftime('%s', 'now') AS INTEGER)
             FROM requests WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&s.read)
        .await
        .unwrap();
        assert!((299..=601).contains(&wait), "waits {wait} s");
        assert_eq!(models(&s, ip).await, (1, 3, 0, 0, false, false));
        assert_eq!(label(&s, ip, "wp").await, (1, 0));
    }

    #[tokio::test]
    async fn release_moves_the_public_models() {
        let (s, _d) = store().await;
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        let (ip, _) = hit(&s, "203.0.113.1", 3, r#"["wp","sqli"]"#).await;
        assert_eq!(s.release_due().await.unwrap(), 0, "nothing due yet");
        make_due(&s).await;
        assert_eq!(s.release_due().await.unwrap(), 1);
        assert_eq!(models(&s, ip).await, (1, 3, 1, 3, true, true));
        assert_eq!(label(&s, ip, "wp").await, (1, 1));
        assert_eq!(label(&s, ip, "sqli").await, (1, 1));
        assert_eq!(s.release_due().await.unwrap(), 0, "idempotent");
    }

    #[tokio::test]
    async fn release_covers_more_than_one_chunk() {
        let (s, _d) = store().await;
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        let (ip, _) = hit(&s, "203.0.113.1", 1, "[]").await;
        // CHUNK + 5 pending rows, inserted in one statement.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < {})
             INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, labels_json, severity)
             SELECT 'bulk' || x, datetime('now'), {ip}, 'GET', '/b', '[]', '[]', 1 FROM n",
            CHUNK + 4
        )))
        .execute(&s.pool)
        .await
        .unwrap();
        make_due(&s).await;
        assert_eq!(s.release_due().await.unwrap(), CHUNK as u64 + 5);
        assert_eq!(models(&s, ip).await.2, CHUNK + 5);
    }

    #[tokio::test]
    async fn deletes_adjust_the_right_side() {
        let (s, _d) = store().await;
        let (ip, released) = hit(&s, "203.0.113.1", 4, r#"["wp"]"#).await;
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        let (_, pending) = hit(&s, "203.0.113.1", 2, r#"["wp"]"#).await;
        assert_eq!(models(&s, ip).await, (2, 4, 1, 4, true, true));
        assert!(s.delete_request(pending).await.unwrap());
        assert_eq!(
            models(&s, ip).await,
            (1, 4, 1, 4, true, true),
            "pending delete leaves public side"
        );
        assert_eq!(label(&s, ip, "wp").await, (1, 1));
        // A further pending row keeps the IP alive (the last delete drops it).
        hit(&s, "203.0.113.1", 1, r#"["wp"]"#).await;
        assert!(s.delete_request(released).await.unwrap());
        assert_eq!(models(&s, ip).await, (1, 1, 0, 0, true, true));
        assert_eq!(label(&s, ip, "wp").await, (1, 0));
    }

    #[tokio::test]
    async fn reclassifying_moves_public_models_only_when_released() {
        let (s, _d) = store().await;
        let (ip, released) = hit(&s, "203.0.113.1", 1, r#"["a"]"#).await;
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        let (_, pending) = hit(&s, "203.0.113.1", 1, r#"["a"]"#).await;
        sqlx::query("UPDATE requests SET severity = 4, labels_json = '[\"b\"]' WHERE id = ?")
            .bind(released)
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(models(&s, ip).await, (2, 4, 1, 4, true, true));
        assert_eq!(label(&s, ip, "a").await, (1, 0));
        assert_eq!(label(&s, ip, "b").await, (1, 1));
        sqlx::query("UPDATE requests SET severity = 3, labels_json = '[\"c\"]' WHERE id = ?")
            .bind(pending)
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(models(&s, ip).await, (2, 4, 1, 4, true, true));
        assert_eq!(label(&s, ip, "c").await, (1, 0));
        assert_eq!(label(&s, ip, "b").await, (1, 1));
    }

    #[tokio::test]
    async fn run_releases_and_stops_on_shutdown() {
        let (s, _d) = store().await;
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        let (ip, _) = hit(&s, "203.0.113.1", 2, "[]").await;
        make_due(&s).await;
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(run(s.clone(), rx));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while models(&s, ip).await.2 == 0 {
            assert!(std::time::Instant::now() < deadline, "not released");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("stops")
            .unwrap();
    }
}
