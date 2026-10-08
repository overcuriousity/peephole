//! Reverse DNS names of the sources (`intel::rdns`): which addresses are
//! due a lookup, and storing what one found. Local to this node, like
//! nmap's PTR names: never replicated.
use super::Store;
use anyhow::Result;

/// Most names kept of one lookup (`crawler::confirmed_names` checks 4).
const MAX_NAMES: usize = 4;

impl Store {
    /// Sources due a reverse lookup, most recently seen first: never looked
    /// up, or seen again more than a day after the last lookup.
    pub async fn rdns_due(&self, limit: i64) -> Result<Vec<(i64, String)>> {
        Ok(sqlx::query_as(
            "SELECT id, ip FROM ips
             WHERE request_count > 0
               AND (rdns_at IS NULL OR last_seen > datetime(rdns_at, '+1 day'))
             ORDER BY last_seen DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.read)
        .await?)
    }

    /// Store what a lookup found (possibly nothing) and when it ran.
    /// Names no longer found keep their row; `last_seen` dates them.
    pub async fn record_rdns(&self, ip_id: i64, names: &[String]) -> Result<()> {
        let now = super::data::now_ts();
        let mut tx = self.pool.begin().await?;
        for name in names.iter().take(MAX_NAMES) {
            sqlx::query(
                "INSERT INTO ip_names (ip_id, name, source, first_seen, last_seen, agreed)
                 VALUES (?1, ?2, 'rdns', ?3, ?3, 1)
                 ON CONFLICT(ip_id, name, source) DO UPDATE SET last_seen = excluded.last_seen",
            )
            .bind(ip_id)
            .bind(name)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("UPDATE ips SET rdns_at = ? WHERE id = ?")
            .bind(&now)
            .bind(ip_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    async fn source(s: &Store, ip: &str) -> i64 {
        let row = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: row.id,
            method: "GET".into(),
            path: "/".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        row.id
    }

    #[tokio::test]
    async fn new_and_returning_sources_are_due() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let fresh = source(&s, "198.51.100.7").await;
        let done = source(&s, "198.51.100.8").await;
        s.upsert_ip("198.51.100.9".parse().unwrap()).await.unwrap(); // no request
        s.record_rdns(done, &[]).await.unwrap();
        let due: Vec<i64> = s
            .rdns_due(50)
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.0)
            .collect();
        assert_eq!(due, vec![fresh]);

        s.record_rdns(fresh, &["host-7.example.net".into()])
            .await
            .unwrap();
        assert!(s.rdns_due(50).await.unwrap().is_empty());
        // Back more than a day after the lookup: due again.
        sqlx::query("UPDATE ips SET last_seen = datetime('now', '+2 days') WHERE id = ?")
            .bind(done)
            .execute(&s.pool)
            .await
            .unwrap();
        let due: Vec<i64> = s
            .rdns_due(50)
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.0)
            .collect();
        assert_eq!(due, vec![done]);

        let names = s.names_for_ip(fresh).await.unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(
            (
                names[0].name.as_str(),
                names[0].source.as_str(),
                names[0].agreed
            ),
            ("host-7.example.net", "rdns", true)
        );
        // Found again: one row, last_seen moves.
        s.record_rdns(fresh, &["host-7.example.net".into()])
            .await
            .unwrap();
        assert_eq!(s.names_for_ip(fresh).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rdns_names_go_with_the_last_request() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = source(&s, "198.51.100.7").await;
        s.record_rdns(id, &["host-7.example.net".into()])
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        crate::store::data::drop_orphan_ip(&mut conn, id)
            .await
            .unwrap();
        assert_eq!(
            s.names_for_ip(id).await.unwrap().len(),
            1,
            "a request remains"
        );
        sqlx::query("DELETE FROM requests WHERE ip_id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await
            .unwrap();
        crate::store::data::drop_orphan_ip(&mut conn, id)
            .await
            .unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ips WHERE id = ?")
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(left, 0, "the name kept nothing alive");
    }
}
