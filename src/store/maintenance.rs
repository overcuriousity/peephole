//! Housekeeping that keeps the database bounded and its query plans good:
//! expired sessions and WebAuthn ceremonies, `PRAGMA optimize`, returning
//! freed pages to the file system, and (standalone nodes only) the
//! tombstones that local deletes leave behind.
use super::Store;
use anyhow::Result;
use std::time::Duration;

/// How often expired auth rows are removed.
const AUTH_EVERY: Duration = Duration::from_secs(600);
/// How often the daily work runs (the first run is one `AUTH_EVERY` after start).
const DAILY_EVERY: Duration = Duration::from_secs(24 * 3600);
/// Pages freed per incremental-vacuum step; the write lock is released
/// between steps so the trap's inserts are not held up.
const VACUUM_STEP: i64 = 2000;

/// What one daily pass did.
#[derive(Debug, Default, PartialEq)]
pub struct Report {
    pub tombstones: u64,
    pub pages_freed: u64,
}

/// Run until `shutdown` turns `true`. `standalone`: the node is not in a
/// cluster, so tombstones of local deletes protect nothing and can go.
pub async fn run(store: Store, standalone: bool, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut next_daily = tokio::time::Instant::now() + AUTH_EVERY;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(AUTH_EVERY) => {}
            _ = shutdown.changed() => return,
        }
        if *shutdown.borrow() {
            return;
        }
        if let Err(e) = store.prune_expired_auth().await {
            tracing::warn!(?e, "pruning expired sessions failed");
        }
        if tokio::time::Instant::now() >= next_daily {
            next_daily = tokio::time::Instant::now() + DAILY_EVERY;
            match store.daily_maintenance(standalone).await {
                Ok(r) => tracing::info!(
                    tombstones = r.tombstones,
                    pages_freed = r.pages_freed,
                    "database maintenance done"
                ),
                Err(e) => tracing::warn!(?e, "database maintenance failed"),
            }
        }
    }
}

impl Store {
    /// Drop local tombstones (when `standalone`), refresh the planner's
    /// statistics and return free pages to the file system.
    pub async fn daily_maintenance(&self, standalone: bool) -> Result<Report> {
        let tombstones = if standalone {
            self.prune_local_tombstones().await?
        } else {
            0
        };
        sqlx::query("PRAGMA optimize").execute(&self.pool).await?;
        let pages_freed = self.incremental_vacuum().await?;
        Ok(Report {
            tombstones,
            pages_freed,
        })
    }

    /// Forget uids deleted by local (standalone) tombstones. Those were never
    /// in a replication log, so no record carrying them can arrive again.
    /// Tombstones that are in the log, or held as a proof for one, stay:
    /// they keep deleted records of a cluster from coming back. Call only on
    /// a node that is not in a cluster.
    pub async fn prune_local_tombstones(&self) -> Result<u64> {
        let mut total = 0;
        loop {
            let n = sqlx::query(
                "DELETE FROM tombstoned WHERE rowid IN (
                   SELECT t.rowid FROM tombstoned t
                   WHERE NOT EXISTS (SELECT 1 FROM repl_log l WHERE l.uid = t.tombstone_uid)
                     AND NOT EXISTS (SELECT 1 FROM tomb_proofs p WHERE p.tomb_uid = t.tombstone_uid)
                   LIMIT 5000)",
            )
            .execute(&self.pool)
            .await?
            .rows_affected();
            total += n;
            if n == 0 {
                return Ok(total);
            }
        }
    }

    /// `PRAGMA auto_vacuum` of the database: 0 none, 1 full, 2 incremental.
    pub async fn auto_vacuum_mode(&self) -> Result<i64> {
        // Inside a read transaction: a connection re-reads the file header
        // (where the mode lives) only when it starts one, so a bare PRAGMA
        // can report what the header said before another connection's VACUUM.
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT 1 FROM sqlite_master LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
        let mode = sqlx::query_scalar("PRAGMA auto_vacuum")
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(mode)
    }

    /// Return free pages to the file system, in steps, when the database
    /// is in incremental auto-vacuum mode (new databases are; older ones
    /// are converted by `peephole db vacuum`). Returns the pages freed.
    pub async fn incremental_vacuum(&self) -> Result<u64> {
        if self.auto_vacuum_mode().await? != 2 {
            return Ok(0);
        }
        let mut freed = 0u64;
        loop {
            let free: i64 = sqlx::query_scalar("PRAGMA freelist_count")
                .fetch_one(&self.pool)
                .await?;
            if free <= 0 {
                return Ok(freed);
            }
            let step = free.min(VACUUM_STEP);
            // PRAGMA takes no bind parameters; step is our own integer.
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "PRAGMA incremental_vacuum({step})"
            )))
            .execute(&self.pool)
            .await?;
            let after: i64 = sqlx::query_scalar("PRAGMA freelist_count")
                .fetch_one(&self.pool)
                .await?;
            if after >= free {
                return Ok(freed);
            }
            freed += (free - after) as u64;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Rebuild the database file in incremental auto-vacuum mode (`VACUUM`).
    /// Takes the database's write lock for the whole rebuild and needs free
    /// disk space of about the database's size: run it with the service
    /// stopped. Returns the file size (bytes) before and after.
    pub async fn vacuum(&self) -> Result<(i64, i64)> {
        let size = |pool: &sqlx::SqlitePool| {
            let pool = pool.clone();
            async move {
                let (pages, page_size): (i64, i64) = sqlx::query_as(
                    "SELECT (SELECT page_count FROM pragma_page_count()),
                            (SELECT page_size FROM pragma_page_size())",
                )
                .fetch_one(&pool)
                .await?;
                anyhow::Ok(pages * page_size)
            }
        };
        let before = size(&self.pool).await?;
        let mut conn = self.pool.acquire().await?;
        sqlx::query("PRAGMA auto_vacuum = INCREMENTAL")
            .execute(&mut *conn)
            .await?;
        sqlx::query("VACUUM").execute(&mut *conn).await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&mut *conn)
            .await?;
        drop(conn);
        Ok((before, size(&self.pool).await?))
    }
}

#[cfg(test)]
mod tests {
    use crate::store::Store;
    use crate::store::requests::NewRequest;

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (s, dir)
    }

    fn req(ip_id: i64) -> NewRequest {
        NewRequest {
            ip_id,
            method: "GET".into(),
            path: "/x".into(),
            query: None,
            headers_json: "[]".into(),
            body: Some(vec![7; 64 * 1024]),
            labels_json: "[]".into(),
            severity: 0,
            scan_level: 0,
            is_fp_claim: false,
            page_token: None,
            ..Default::default()
        }
    }

    async fn count(s: &Store, sql: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn local_tombstones_go_and_logged_ones_stay() {
        let (s, _dir) = store().await;
        let ip = s.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
        let id = s.insert_request(&req(ip.id)).await.unwrap();
        assert!(s.delete_request(id).await.unwrap());
        assert_eq!(count(&s, "SELECT COUNT(*) FROM tombstoned").await, 1);
        // A tombstone that is in the replication log is kept.
        sqlx::query("INSERT INTO tombstoned (uid, tombstone_uid) VALUES ('peer-rec', 'peer-tomb')")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO repl_log (origin, seq, hlc, kind, uid, received_at)
             VALUES (x'01', 1, 1, 'tombstone', 'peer-tomb', datetime('now'))",
        )
        .execute(&s.pool)
        .await
        .unwrap();
        let r = s.daily_maintenance(true).await.unwrap();
        assert_eq!(r.tombstones, 1);
        assert_eq!(
            count(&s, "SELECT COUNT(*) FROM tombstoned WHERE uid = 'peer-rec'").await,
            1
        );
        assert_eq!(count(&s, "SELECT COUNT(*) FROM tombstoned").await, 1);
        // In a cluster nothing is pruned.
        sqlx::query("INSERT INTO tombstoned (uid, tombstone_uid) VALUES ('l', 'local-tomb')")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(s.daily_maintenance(false).await.unwrap().tombstones, 0);
    }

    #[tokio::test]
    async fn new_databases_vacuum_incrementally() {
        let (s, _dir) = store().await;
        assert_eq!(s.auto_vacuum_mode().await.unwrap(), 2);
        let ip = s.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
        let mut ids = vec![];
        for _ in 0..40 {
            ids.push(s.insert_request(&req(ip.id)).await.unwrap());
        }
        s.delete_requests(&ids).await.unwrap();
        let free = count(&s, "SELECT * FROM pragma_freelist_count()").await;
        assert!(free > 0, "deleting bodies frees pages");
        let freed = s.incremental_vacuum().await.unwrap();
        assert!(freed > 0);
        assert_eq!(count(&s, "SELECT * FROM pragma_freelist_count()").await, 0);
    }

    #[tokio::test]
    async fn vacuum_converts_an_old_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        {
            // A database created before incremental auto-vacuum.
            let opts = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .connect_with(opts)
                .await
                .unwrap();
            sqlx::query("CREATE TABLE t (x)")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        }
        let s = Store::connect(&path).await.unwrap();
        assert_eq!(s.auto_vacuum_mode().await.unwrap(), 0);
        assert_eq!(s.incremental_vacuum().await.unwrap(), 0, "not enabled");
        s.vacuum().await.unwrap();
        assert_eq!(s.auto_vacuum_mode().await.unwrap(), 2);
    }
}
