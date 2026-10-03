pub mod auth;
pub mod blocklist;
pub mod browse;
pub mod cli;
pub mod data;
pub mod delete;
pub mod export;
pub mod fingerprints;
pub mod inspect;
pub mod maintenance;
pub mod recorder;
pub mod requests;
pub mod scans;
pub mod stats;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Schema migrations, applied in order. `PRAGMA user_version` records how
/// many have run. Append new files only; never edit a shipped one. `--`
/// comments are stripped, then each file is split on `;`, so statements
/// must not contain semicolons themselves (no string literals with `;`).
/// 0001 is the schema as of 0.1.0; databases of earlier builds are refused
/// (see [`APPLICATION_ID`]).
const MIGRATIONS: &[&str] = &[include_str!("migrations/0001_initial.sql")];

/// `PRAGMA application_id` of a peephole database ("peep"). Databases of
/// builds before 0.1.0 do not carry it and are refused rather than migrated.
const APPLICATION_ID: i32 = 0x7065_6570;

#[derive(Clone)]
pub struct Store {
    /// Writes, and reads that must see them inside a transaction.
    pub pool: sqlx::SqlitePool,
    /// Read-only connections for page and export reads. SQLite in WAL mode
    /// lets readers run beside the writer, so a slow public or admin query
    /// never holds a connection the trap needs for its inserts.
    pub read: sqlx::SqlitePool,
    /// Whether the trigram index over request paths and queries exists.
    search_index: Arc<AtomicBool>,
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
        incremental_vacuum_if_new(&pool).await;
        check_application_id(&pool)
            .await
            .with_context(|| path.display().to_string())?;
        migrate(&pool, MIGRATIONS).await?;
        backfill_ip_keys(&pool).await?;
        let search = ensure_search_index(&pool).await;
        let read_opts = SqliteConnectOptions::new()
            .filename(path)
            .busy_timeout(std::time::Duration::from_secs(10))
            .pragma("query_only", "ON");
        let read = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(read_opts)
            .await
            .context("opening sqlite (readers)")?;
        Ok(Self {
            pool,
            read,
            search_index: Arc::new(AtomicBool::new(search)),
        })
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

    /// Whether request search can use the trigram index.
    pub fn search_indexed(&self) -> bool {
        self.search_index.load(Ordering::Relaxed)
    }
}

/// A new (empty) database file gets incremental auto-vacuum, so pages freed
/// by deletes can be returned to the file system (`store::maintenance`).
/// The mode is fixed once tables exist; existing databases are converted by
/// `peephole db vacuum`. Best effort: a database another process is
/// creating at the same moment simply keeps the default.
async fn incremental_vacuum_if_new(pool: &sqlx::SqlitePool) {
    let r = async {
        let mut conn = pool.acquire().await?;
        let tables: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master")
            .fetch_one(&mut *conn)
            .await?;
        if tables == 0 {
            sqlx::query("PRAGMA auto_vacuum = INCREMENTAL")
                .execute(&mut *conn)
                .await?;
            // WAL mode was set first; the empty file is rewritten (instant).
            sqlx::query("VACUUM").execute(&mut *conn).await?;
        }
        anyhow::Ok(())
    };
    if let Err(e) = r.await {
        tracing::debug!(?e, "incremental auto-vacuum not enabled");
    }
}

/// An address as a fixed-width sortable key: 16 bytes big-endian (IPv4 as
/// `::ffff:a.b.c.d`), lowercase hex. Text order is address order.
pub fn ip_key(ip: std::net::IpAddr) -> String {
    let bytes = match crate::net::canonical(ip) {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(v6) => v6.octets(),
    };
    data_encoding::HEXLOWER.encode(&bytes)
}

/// [`ip_key`] of a stored address text; `None` for anything else.
pub fn ip_key_of(ip: &str) -> Option<String> {
    ip.parse().ok().map(ip_key)
}

/// First and last [`ip_key`] of a network.
pub fn net_key_range(net: &ipnet::IpNet) -> (String, String) {
    (ip_key(net.network()), ip_key(net.broadcast()))
}

/// Fill `ips.ip_key` where it is missing (rows from before migration 0019,
/// or written by a path that does not set it). Cheap when nothing is
/// missing: the column is indexed.
pub(crate) async fn backfill_ip_keys(pool: &sqlx::SqlitePool) -> anyhow::Result<u64> {
    let mut filled = 0;
    loop {
        let rows: Vec<(i64, String)> =
            sqlx::query_as("SELECT id, ip FROM ips WHERE ip_key IS NULL LIMIT 1000")
                .fetch_all(pool)
                .await?;
        if rows.is_empty() {
            return Ok(filled);
        }
        let mut tx = pool.begin().await?;
        let mut progressed = false;
        for (id, ip) in &rows {
            // Not an address: an empty key never falls inside a range and
            // is not picked up again.
            let key = ip_key_of(ip).unwrap_or_default();
            let n = sqlx::query("UPDATE ips SET ip_key = ? WHERE id = ? AND ip_key IS NULL")
                .bind(key)
                .bind(id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            progressed |= n > 0;
            filled += n;
        }
        tx.commit().await?;
        if !progressed {
            return Ok(filled);
        }
    }
}

/// Statements of the trigram index over request paths and queries, kept in
/// step with `requests` by triggers. An external-content FTS5 table: it
/// stores only the index, the text stays in `requests`.
const SEARCH_INDEX: &[&str] = &[
    "CREATE VIRTUAL TABLE IF NOT EXISTS requests_fts USING fts5(
       path, query, content='requests', content_rowid='id', tokenize='trigram')",
    "CREATE TRIGGER IF NOT EXISTS requests_fts_ai AFTER INSERT ON requests BEGIN
       INSERT INTO requests_fts(rowid, path, query) VALUES (NEW.id, NEW.path, NEW.query);
     END",
    "CREATE TRIGGER IF NOT EXISTS requests_fts_ad AFTER DELETE ON requests BEGIN
       INSERT INTO requests_fts(requests_fts, rowid, path, query)
         VALUES ('delete', OLD.id, OLD.path, OLD.query);
     END",
    "CREATE TRIGGER IF NOT EXISTS requests_fts_au AFTER UPDATE OF path, query ON requests BEGIN
       INSERT INTO requests_fts(requests_fts, rowid, path, query)
         VALUES ('delete', OLD.id, OLD.path, OLD.query);
       INSERT INTO requests_fts(rowid, path, query) VALUES (NEW.id, NEW.path, NEW.query);
     END",
];

/// Create the request search index if this SQLite supports it (FTS5 with
/// the trigram tokenizer, SQLite >= 3.34; the bundled build does). Without
/// it, search falls back to `LIKE` scans. Returns whether the index exists.
async fn ensure_search_index(pool: &sqlx::SqlitePool) -> bool {
    let attempt = async {
        let mut conn = pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let r = async {
            let existed: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'requests_fts'",
            )
            .fetch_one(&mut *conn)
            .await?;
            for stmt in SEARCH_INDEX {
                sqlx::query(sqlx::AssertSqlSafe(*stmt))
                    .execute(&mut *conn)
                    .await?;
            }
            if existed == 0 {
                // Index what is already there (once, on the first start).
                sqlx::query("INSERT INTO requests_fts(requests_fts) VALUES ('rebuild')")
                    .execute(&mut *conn)
                    .await?;
            }
            anyhow::Ok(())
        }
        .await;
        match r {
            Ok(()) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                anyhow::Ok(())
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(e)
            }
        }
    };
    match attempt.await {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                ?e,
                "request search index unavailable (needs SQLite FTS5 with the trigram \
                 tokenizer); request search scans the table"
            );
            false
        }
    }
}

/// Refuse a database that is not peephole's or predates 0.1.0; stamp a new
/// one. Tables without the stamp come from a pre-release build, whose
/// schema history was squashed into 0001: they are not migrated.
async fn check_application_id(pool: &sqlx::SqlitePool) -> anyhow::Result<()> {
    let id: i32 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(pool)
        .await?;
    if id == APPLICATION_ID {
        return Ok(());
    }
    let tables: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master")
        .fetch_one(pool)
        .await?;
    if tables > 0 || id != 0 {
        anyhow::bail!(
            "not a peephole 0.1.0 database (from a pre-release build, or another \
             program's); move it aside and start again with an empty one"
        );
    }
    // PRAGMA takes no bind parameters; the id is our own constant.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "PRAGMA application_id = {APPLICATION_ID}"
    )))
    .execute(pool)
    .await?;
    Ok(())
}

/// Statements of a migration file: `--` comments removed, split on `;`.
/// A `CREATE TRIGGER … BEGIN …; …; END` stays one statement.
fn statements(sql: &str) -> Vec<String> {
    let code: String = sql
        .lines()
        .map(|l| l.split_once("--").map_or(l, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n");
    let mut out: Vec<String> = vec![];
    let mut open_trigger = false;
    for part in code.split(';') {
        if open_trigger {
            let last = out.last_mut().expect("a trigger is open");
            last.push(';');
            last.push_str(part);
            let t = last.trim_end();
            if t.len() >= 3 && t[t.len() - 3..].eq_ignore_ascii_case("end") {
                open_trigger = false;
                *last = last.trim().to_string();
            }
            continue;
        }
        let stmt = part.trim();
        if stmt.is_empty() {
            continue;
        }
        let words: Vec<String> = stmt
            .split_whitespace()
            .take(4)
            .map(str::to_ascii_uppercase)
            .collect();
        open_trigger = words.first().is_some_and(|w| w == "CREATE")
            && words.iter().skip(1).any(|w| w == "TRIGGER");
        out.push(stmt.to_string());
    }
    out
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

    /// Pre-release databases (no application id) are refused, untouched.
    #[tokio::test]
    async fn a_database_without_the_application_id_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
            sqlx::query("CREATE TABLE ips (id INTEGER PRIMARY KEY)")
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("PRAGMA user_version = 25")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        }
        let e = Store::connect(&path).await.err().expect("refused");
        assert!(
            format!("{e:#}").contains("not a peephole 0.1.0 database"),
            "{e:#}"
        );
        // A new database is stamped and opens again.
        let fresh = dir.path().join("fresh.db");
        drop(Store::connect(&fresh).await.unwrap());
        let s = Store::connect(&fresh).await.unwrap();
        let id: i32 = sqlx::query_scalar("PRAGMA application_id")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(id, APPLICATION_ID);
    }

    #[test]
    fn trigger_bodies_stay_one_statement() {
        let sql = "CREATE TABLE a (x);
            CREATE TRIGGER t AFTER INSERT ON a BEGIN
              UPDATE a SET x = CASE WHEN 1 THEN 2 ELSE 3 END;
              DELETE FROM a WHERE x = 0;
            END;
            create temp trigger u after delete on a begin select 1; end;
            DROP TABLE b";
        let s = statements(sql);
        assert_eq!(s.len(), 4, "{s:#?}");
        assert!(s[1].starts_with("CREATE TRIGGER") && s[1].ends_with("END"));
        assert!(s[1].contains("DELETE FROM a WHERE x = 0;"));
        assert!(s[2].starts_with("create temp trigger") && s[2].ends_with("end"));
        assert_eq!(s[3], "DROP TABLE b");
    }

    #[test]
    fn ip_keys_sort_like_addresses() {
        let k = |s: &str| ip_key(s.parse().unwrap());
        assert!(k("9.255.255.255") < k("10.0.0.0"));
        assert!(k("255.255.255.255") < k("::ffff:1:0:0"));
        assert_eq!(k("::ffff:10.0.0.1"), k("10.0.0.1"), "mapped = plain v4");
        let net: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let (lo, hi) = net_key_range(&net);
        assert!(lo <= k("10.1.2.3") && k("10.1.2.3") <= hi);
        assert!(k("11.0.0.0") > hi);
        assert_eq!(ip_key_of("not an ip"), None);
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
