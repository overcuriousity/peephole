pub mod auth;
pub mod browse;
pub mod data;
pub mod delete;
pub mod fingerprints;
pub mod inspect;
pub mod recorder;
pub mod requests;
pub mod scans;
pub mod stats;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::path::Path;

/// Schema migrations, applied in order. `PRAGMA user_version` records how
/// many have run. Append new files only; never edit a shipped one. `--`
/// comments are stripped, then each file is split on `;`, so statements
/// must not contain semicolons themselves (no string literals with `;`).
/// 0001 is idempotent (`IF NOT EXISTS`) so databases from before versioning
/// (user_version 0, tables present) pass through it unharmed.
const MIGRATIONS: &[&str] = &[
    include_str!("migrations/0001_initial.sql"),
    include_str!("migrations/0002_replication.sql"),
    include_str!("migrations/0003_replicated_rows.sql"),
    include_str!("migrations/0004_scan_arbiter.sql"),
    include_str!("migrations/0005_intel_files.sql"),
    include_str!("migrations/0006_repl_heads.sql"),
    include_str!("migrations/0007_webauthn_states.sql"),
    include_str!("migrations/0008_indexes.sql"),
    include_str!("migrations/0009_member_info.sql"),
    include_str!("migrations/0010_invites.sql"),
    include_str!("migrations/0011_scoped_tombstones.sql"),
    include_str!("migrations/0012_tomb_proofs.sql"),
    include_str!("migrations/0013_hide_block.sql"),
    include_str!("migrations/0014_origin_indexes.sql"),
    include_str!("migrations/0015_config_audit.sql"),
    include_str!("migrations/0016_config_keys.sql"),
    include_str!("migrations/0017_ip_intel.sql"),
    include_str!("migrations/0022_cluster_limits.sql"),
];

#[derive(Clone)]
pub struct Store {
    pub pool: sqlx::SqlitePool,
}

impl Store {
    pub async fn connect(path: &Path) -> anyhow::Result<Self> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            // NORMAL is durable under WAL (only a crash mid-checkpoint can lose
            // the last transactions) and much cheaper than the FULL default,
            // which fsyncs on every commit and throttles the inline write path.
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_secs(10))
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await
            .context("opening sqlite")?;
        migrate(&pool, MIGRATIONS).await?;
        Ok(Self { pool })
    }

    /// Writes as a standalone node (applied directly, not replicated).
    pub fn local(&self) -> recorder::Recorder {
        recorder::Recorder::Local(self.clone())
    }

    /// Schema version of the open database.
    pub async fn schema_version(&self) -> anyhow::Result<i64> {
        Ok(sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&self.pool)
            .await?)
    }
}

/// Statements of a migration file: `--` comments removed, split on `;`.
fn statements(sql: &str) -> Vec<String> {
    let code: String = sql
        .lines()
        .map(|l| l.split_once("--").map_or(l, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n");
    code.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Apply pending migrations, each in its own write transaction so a second
/// process (the CLI) racing the daemon cannot apply one twice.
async fn migrate(pool: &sqlx::SqlitePool, migrations: &[&str]) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    for (i, sql) in migrations.iter().enumerate() {
        let target = i as i64 + 1;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let applied = async {
            let current: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *conn)
                .await?;
            if current >= target {
                return Ok(());
            }
            for stmt in statements(sql) {
                sqlx::query(sqlx::AssertSqlSafe(stmt))
                    .execute(&mut *conn)
                    .await
                    .with_context(|| format!("migration {target}"))?;
            }
            // PRAGMA takes no bind parameters; target is our own integer.
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "PRAGMA user_version = {target}"
            )))
            .execute(&mut *conn)
            .await?;
            anyhow::Ok(())
        }
        .await;
        match applied {
            Ok(()) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(e);
            }
        }
    }
    let current: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *conn)
        .await?;
    if current > migrations.len() as i64 {
        // A newer build migrated this database (e.g. before an installer
        // rollback). Migrations are additive, so keep going.
        tracing::warn!(
            schema = current,
            known = migrations.len(),
            "database schema is newer than this build"
        );
    }
    Ok(())
}

impl Store {
    pub async fn intel_get(&self, key: &str) -> anyhow::Result<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT value FROM intel_meta WHERE key = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn intel_set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO intel_meta (key, value) VALUES (?, ?)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// What `ip` did in the last hour, counting the request to `path` that
    /// is being classified (it is stored with its verdict, so afterwards).
    /// The IP need not have a row yet.
    pub async fn ip_history(
        &self,
        ip: &str,
        path: &str,
    ) -> anyhow::Result<crate::classify::IpHistory> {
        let (paths, reqs, seen): (i64, i64, bool) = sqlx::query_as(
            "SELECT COUNT(DISTINCT r.path), COUNT(*), COALESCE(MAX(r.path = ?2), 0)
             FROM requests r JOIN ips i ON i.id = r.ip_id
             WHERE i.ip = ?1 AND r.ts > datetime('now','-1 hour')",
        )
        .bind(ip)
        .bind(path)
        .fetch_one(&self.pool)
        .await?;
        Ok(crate::classify::IpHistory {
            distinct_paths_1h: (paths + i64::from(!seen)) as u32,
            requests_1h: (reqs + 1) as u32,
        })
    }
}

impl Store {
    pub async fn export_requests(
        &self,
        f: &crate::export::ExportFilter,
    ) -> anyhow::Result<Vec<crate::export::ExportRow>> {
        let mut sql = String::from(
            "SELECT r.ts, i.ip, r.method, r.path, r.query, r.severity, r.scan_level,
                    r.labels_json, i.country, i.asn, i.asn_org, i.is_tor_exit
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1",
        );
        let mut binds: Vec<String> = vec![];
        if let Some(v) = &f.from {
            sql.push_str(" AND r.ts >= ?");
            binds.push(v.clone());
        }
        if let Some(v) = &f.to {
            sql.push_str(" AND r.ts <= ?");
            binds.push(v.clone());
        }
        if let Some(v) = &f.ip {
            sql.push_str(" AND i.ip = ?");
            binds.push(v.clone());
        }
        if let Some(v) = &f.label {
            // Exact label match via json_each, matching the admin search
            // (a LIKE on the raw JSON would treat %/_ as wildcards and could
            // match a label as a substring of another).
            sql.push_str(
                " AND EXISTS (SELECT 1 FROM json_each(r.labels_json) je WHERE je.value = ?)",
            );
            binds.push(v.clone());
        }
        if let Some(v) = &f.min_severity {
            sql.push_str(" AND r.severity >= ?");
            binds.push(v.to_string());
        }
        sql.push_str(" ORDER BY r.ts ASC LIMIT 100000");
        let mut q = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                Option<String>,
                i64,
                i64,
                String,
                Option<String>,
                Option<i64>,
                Option<String>,
                bool,
            ),
        >(sqlx::AssertSqlSafe(sql.as_str()));
        for b in binds {
            q = q.bind(b);
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    ts,
                    ip,
                    method,
                    path,
                    query,
                    severity,
                    scan_level,
                    labels_json,
                    country,
                    asn,
                    asn_org,
                    is_tor,
                )| {
                    crate::export::ExportRow {
                        ts,
                        ip,
                        method,
                        path,
                        query,
                        severity,
                        scan_level,
                        labels: serde_json::from_str(&labels_json).unwrap_or_default(),
                        country,
                        asn,
                        asn_org,
                        is_tor,
                    }
                },
            )
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fresh_database_reaches_latest_version() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        assert_eq!(s.schema_version().await.unwrap(), MIGRATIONS.len() as i64);
        // Reconnecting is a no-op.
        drop(s);
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        assert_eq!(s.schema_version().await.unwrap(), MIGRATIONS.len() as i64);
    }

    /// Databases created before versioning have the tables but user_version 0.
    #[tokio::test]
    async fn pre_versioning_database_is_adopted_with_its_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
            for stmt in MIGRATIONS[0]
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                sqlx::query(sqlx::AssertSqlSafe(stmt))
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            sqlx::query("INSERT INTO settings (key, value) VALUES ('k','v')")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        }
        let s = Store::connect(&path).await.unwrap();
        assert_eq!(s.schema_version().await.unwrap(), MIGRATIONS.len() as i64);
        assert_eq!(s.setting_get("k").await.unwrap().as_deref(), Some("v"));
    }

    /// 0017 keeps the facts already shown as this node's results.
    #[tokio::test]
    async fn migration_0017_keeps_existing_facts_as_results() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
            migrate(&pool, &MIGRATIONS[..16]).await.unwrap();
            sqlx::query(
                "INSERT INTO ips (ip, first_seen, last_seen, country, asn, asn_org, is_tor_exit)
                 VALUES ('203.0.113.7', '2026-01-01 00:00:00', '2026-01-02 00:00:00',
                         'DE', 3320, 'DTAG', 1),
                        ('203.0.113.8', '2026-01-01 00:00:00', '2026-01-02 00:00:00',
                         NULL, NULL, NULL, 0)",
            )
            .execute(&pool)
            .await
            .unwrap();
            pool.close().await;
        }
        let s = Store::connect(&path).await.unwrap();
        let rows: Vec<(String, String, Vec<u8>, i64, String)> = sqlx::query_as(
            "SELECT ip, provider, origin, hlc, data_json FROM ip_intel ORDER BY provider",
        )
        .fetch_all(&s.pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 2, "{rows:?}");
        let (ip, provider, origin, hlc, data) = &rows[0];
        assert_eq!(
            (ip.as_str(), provider.as_str()),
            ("203.0.113.7", "maxmind-geolite2")
        );
        assert!(origin.is_empty());
        assert_eq!(*hlc, 0);
        let data: serde_json::Value = serde_json::from_str(data).unwrap();
        assert_eq!(data["country"], "DE");
        assert_eq!(data["asn"], 3320);
        assert_eq!(data["asn_org"], "DTAG");
        let (ip, provider, origin, _, data) = &rows[1];
        assert_eq!(
            (ip.as_str(), provider.as_str()),
            ("203.0.113.7", "tor-exits")
        );
        assert!(origin.is_empty());
        assert_eq!(data, r#"{"exit":true}"#);
        type View = (String, Option<String>, Option<i64>, Option<String>, bool);
        let view: Vec<View> =
            sqlx::query_as("SELECT ip, country, asn, asn_org, is_tor_exit FROM ips ORDER BY ip")
                .fetch_all(&s.pool)
                .await
                .unwrap();
        assert_eq!(
            view,
            [
                (
                    "203.0.113.7".into(),
                    Some("DE".into()),
                    Some(3320),
                    Some("DTAG".into()),
                    true
                ),
                ("203.0.113.8".into(), None, None, None, false),
            ]
        );
    }

    #[tokio::test]
    async fn failed_migration_rolls_back_and_keeps_version() {
        // A migration file may carry comments containing semicolons.
        assert_eq!(statements("-- a; b\nSELECT 1; -- c;\nSELECT 2").len(), 2);
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut bad = MIGRATIONS.to_vec();
        bad.push("CREATE TABLE t2 (x INTEGER); SELECT * FROM missing");
        assert!(migrate(&s.pool, &bad).await.is_err());
        assert_eq!(s.schema_version().await.unwrap(), MIGRATIONS.len() as i64);
        let t2: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE name = 't2'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(t2, 0, "partial migration must not persist");
    }
}
