pub mod analytics;
pub mod asn;
pub mod auth;
mod backfill;
pub mod blocklist;
pub mod browse;
pub mod campaigns;
pub mod canaries;
pub mod cli;
pub mod data;
pub mod decoys;
pub mod delete;
pub mod devices;
pub mod events;
pub mod evidence;
pub mod export;
pub mod facts;
pub mod fingerprints;
pub mod guard;
pub mod hostkeys;
pub mod inspect;
pub mod ja4h;
pub mod links;
pub mod maintenance;
pub mod probes;
pub mod publish;
pub mod rdap_net;
pub mod rdns;
pub mod recorder;
pub mod requests;
pub mod scans;
pub mod shapes;
pub mod stats;
pub mod uploads;
pub mod useragent;
pub mod waves;
pub mod webshell_cmd;

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
/// (see [`APPLICATION_ID`]). 0002 adds `host_keys`.
const MIGRATIONS: &[&str] = &[
    include_str!("migrations/0001_initial.sql"),
    include_str!("migrations/0002_host_keys.sql"),
    include_str!("migrations/0003_canaries.sql"),
    include_str!("migrations/0004_ja4h.sql"),
    include_str!("migrations/0005_public_delay.sql"),
    include_str!("migrations/0006_links.sql"),
    include_str!("migrations/0007_user_agent.sql"),
    include_str!("migrations/0008_tarpit.sql"),
    include_str!("migrations/0009_decoy_in.sql"),
    include_str!("migrations/0010_ownership.sql"),
    include_str!("migrations/0011_clear_config_keys.sql"),
    include_str!("migrations/0012_owner_log_kinds.sql"),
    include_str!("migrations/0013_credit_entries.sql"),
    include_str!("migrations/0014_seals.sql"),
    include_str!("migrations/0015_forks.sql"),
    include_str!("migrations/0016_credit_scans.sql"),
    include_str!("migrations/0017_scan_audits.sql"),
    include_str!("migrations/0018_probes.sql"),
    include_str!("migrations/0019_probe_charged.sql"),
    include_str!("migrations/0020_scan_retries.sql"),
    include_str!("migrations/0021_market.sql"),
    include_str!("migrations/0022_price_history.sql"),
    include_str!("migrations/0023_scan_self_mc.sql"),
    include_str!("migrations/0024_no_collecting_node.sql"),
    include_str!("migrations/0025_rdns.sql"),
    include_str!("migrations/0026_job_handouts.sql"),
    include_str!("migrations/0027_scan_facts.sql"),
    include_str!("migrations/0028_manual_scan_jobs.sql"),
    include_str!("migrations/0029_scarce_credits.sql"),
    include_str!("migrations/0030_vouched.sql"),
    include_str!("migrations/0031_stats_index.sql"),
    include_str!("migrations/0032_devices.sql"),
    include_str!("migrations/0033_device_actions.sql"),
    include_str!("migrations/0034_uploads.sql"),
    include_str!("migrations/0035_webshell_hits.sql"),
    include_str!("migrations/0036_rdap_checks.sql"),
    include_str!("migrations/0037_name_refreshes.sql"),
    include_str!("migrations/0038_unseen_ips.sql"),
    include_str!("migrations/0039_shapes.sql"),
    include_str!("migrations/0040_campaigns.sql"),
    include_str!("migrations/0041_campaign_agreement.sql"),
    include_str!("migrations/0042_webshell_cmd.sql"),
    include_str!("migrations/0043_rdap_net.sql"),
    include_str!("migrations/0044_price_history_cluster.sql"),
    include_str!("migrations/0045_waves.sql"),
    include_str!("migrations/0046_persona.sql"),
    include_str!("migrations/0047_ip_evidence.sql"),
    include_str!("migrations/0048_campaign_edge_detail.sql"),
    include_str!("migrations/0049_requests_ip_id.sql"),
    include_str!("migrations/0050_api_keys.sql"),
    include_str!("migrations/0051_api_key_never_used.sql"),
];

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
    /// Held from an automatic enqueue's checks to its write
    /// (`Recorder::enqueue_scan_with`). The write may be a replicated
    /// append, so one transaction cannot cover both.
    pub(crate) enqueue: Arc<tokio::sync::Mutex<()>>,
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
            // Blank the space of deleted values where that costs no extra
            // writes (rows of small tables): a deleted key, token or
            // setting is not left readable in the file.
            .pragma("secure_delete", "FAST")
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await
            .context("opening sqlite")?;
        crate::warn_if_exposed(path, "database");
        incremental_vacuum_if_new(&pool).await;
        check_application_id(&pool)
            .await
            .with_context(|| path.display().to_string())?;
        migrate(&pool, MIGRATIONS).await?;
        backfill_ip_keys(&pool).await?;
        // Scans never read at all (stored before `host_keys`); a newer
        // parser's reparse runs as a task once the node serves.
        hostkeys::backfill(&pool, 1).await?;
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
            enqueue: Default::default(),
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
    let mut from = None;
    for (i, sql) in migrations.iter().enumerate() {
        let target = i as i64 + 1;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let applied = async {
            let current: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *conn)
                .await?;
            if current >= target {
                return Ok(None);
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
            anyhow::Ok(Some(current))
        }
        .await;
        match applied {
            Ok(was) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                from = from.or(was);
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
    if let Some(from) = from {
        tracing::info!(from, to = current, "database schema migrated");
    }
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

    /// Every `(key, value)` whose key starts with `prefix`, by key. The
    /// prefix is bound, its `%`, `_` and `\` escaped: it matches only
    /// itself (and, unlike `LIKE`, case-sensitively).
    pub async fn intel_prefix(&self, prefix: &str) -> anyhow::Result<Vec<(String, String)>> {
        let mut pattern = String::with_capacity(prefix.len() + 1);
        for c in prefix.chars() {
            if matches!(c, '%' | '_' | '\\') {
                pattern.push('\\');
            }
            pattern.push(c);
        }
        pattern.push('%');
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT key, value FROM intel_meta WHERE key LIKE ? ESCAPE '\\' ORDER BY key",
        )
        .bind(pattern)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .collect())
    }

    pub async fn intel_delete(&self, key: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM intel_meta WHERE key = ?")
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// What `ip` did in the last hour, counting the request to `path` that
    /// is being classified (it is stored with its verdict, so afterwards).
    /// The IP need not have a row yet. Every row dated in the last hour
    /// counts, also one of another node dated (slightly) in the future:
    /// `classify::stored::History` brackets this count.
    pub async fn ip_history(
        &self,
        ip: &str,
        path: &str,
    ) -> anyhow::Result<crate::classify::IpHistory> {
        // Rows are filed under the canonical text (`data::ensure_ip`): look
        // the IP up the same way, or a `::ffff:a.b.c.d` would count nothing.
        let ip = match ip.parse::<std::net::IpAddr>() {
            Ok(a) => crate::net::canonical(a).to_string(),
            Err(_) => ip.to_string(),
        };
        let (paths, reqs, seen): (i64, i64, bool) = sqlx::query_as(
            "SELECT COUNT(DISTINCT r.path), COUNT(*), COALESCE(MAX(r.path = ?2), 0)
             FROM requests r JOIN ips i ON i.id = r.ip_id
             WHERE i.ip = ?1 AND r.ts > datetime('now','-1 hour')",
        )
        .bind(&ip)
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

    /// Config keys are gone after the upgrade, their table is not: a
    /// database restored to the previous version still opens there.
    #[tokio::test]
    async fn the_config_key_table_stays_and_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM config_keys")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
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

    #[tokio::test]
    async fn migration_0051_clears_last_seen_only_for_untouched_api_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
            check_application_id(&pool).await.unwrap();
            migrate(&pool, &MIGRATIONS[..50]).await.unwrap();
            sqlx::query(
                "INSERT INTO devices (id, name, token_hash, scopes, paired_by, created_at, last_seen_at, kind) VALUES
                 ('unused', 'k1', 'h1', 'read', 'admin', '2026-10-01 00:00:00', '2026-10-01 00:00:00', 'api_key'),
                 ('used', 'k2', 'h2', 'read', 'admin', '2026-10-01 00:00:00', '2026-10-02 00:00:00', 'api_key'),
                 ('phone', 'p', 'h3', 'read', 'admin', '2026-10-01 00:00:00', '2026-10-01 00:00:00', 'device')",
            )
            .execute(&pool)
            .await
            .unwrap();
            pool.close().await;
        }
        let s = Store::connect(&path).await.unwrap();
        let rows: Vec<(String, Option<String>)> =
            sqlx::query_as("SELECT id, last_seen_at FROM devices ORDER BY id")
                .fetch_all(&s.read)
                .await
                .unwrap();
        assert_eq!(
            rows,
            vec![
                ("phone".into(), Some("2026-10-01 00:00:00".into())),
                ("unused".into(), None),
                ("used".into(), Some("2026-10-02 00:00:00".into())),
            ]
        );
    }

    #[tokio::test]
    async fn migration_0005_keeps_existing_rows_public() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        // A 0.4.0 database: migrations 0001-0004 only, with one request.
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
            check_application_id(&pool).await.unwrap();
            migrate(&pool, &MIGRATIONS[..4]).await.unwrap();
            sqlx::query(
                "INSERT INTO ips (ip, ip_key, first_seen, last_seen)
                 VALUES ('203.0.113.7', '', '2026-01-01 00:00:00', '2026-01-02 00:00:00')",
            )
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, labels_json, severity)
                 VALUES ('old', '2026-01-02 00:00:00', (SELECT id FROM ips WHERE ip = '203.0.113.7'),
                         'GET', '/', '[]', '[\"wp\"]', 2)",
            )
            .execute(&pool)
            .await
            .unwrap();
            pool.close().await;
        }
        let s = Store::connect(&path).await.unwrap();
        assert_eq!(s.schema_version().await.unwrap(), MIGRATIONS.len() as i64);
        let row: (i64, i64, String, String) = sqlx::query_as(
            "SELECT pub_request_count, pub_max_severity, pub_first_seen, pub_last_seen
             FROM ips WHERE ip = '203.0.113.7'",
        )
        .fetch_one(&s.read)
        .await
        .unwrap();
        assert_eq!(
            row,
            (
                1,
                2,
                "2026-01-01 00:00:00".into(),
                "2026-01-02 00:00:00".into()
            )
        );
        let pc: i64 = sqlx::query_scalar("SELECT pub_count FROM ip_labels WHERE label = 'wp'")
            .fetch_one(&s.read)
            .await
            .unwrap();
        assert_eq!(pc, 1);
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM requests WHERE public_at IS NOT NULL")
                .fetch_one(&s.read)
                .await
                .unwrap();
        assert_eq!(pending, 0);
    }

    /// A raw pool on `path` (no migrations): an older build's database.
    async fn raw_pool(path: &Path) -> sqlx::SqlitePool {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        SqlitePoolOptions::new().connect_with(opts).await.unwrap()
    }

    async fn exec(pool: &sqlx::SqlitePool, sql: &str) {
        sqlx::query(sqlx::AssertSqlSafe(sql.to_string()))
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }

    /// A node on v0.22.2 is at `user_version` 49 with master's
    /// `0049_requests_ip_id`. The API-key migration is numbered 0050, so
    /// opening that database with this build still adds `devices.kind`
    /// (MIK-788).
    #[tokio::test]
    async fn a_v0_22_2_database_gets_the_api_key_migration() {
        assert!(MIGRATIONS[48].contains("idx_requests_ip_id"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        {
            let pool = raw_pool(&path).await;
            check_application_id(&pool).await.unwrap();
            migrate(&pool, &MIGRATIONS[..49]).await.unwrap();
            pool.close().await;
        }
        let s = Store::connect(&path).await.unwrap();
        assert_eq!(s.schema_version().await.unwrap(), MIGRATIONS.len() as i64);
        let kind: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name = 'kind'",
        )
        .fetch_one(&s.read)
        .await
        .unwrap();
        assert_eq!(kind, 1, "devices.kind exists");
    }

    /// A database of the first release, holding data, written again by the
    /// build of migration 0017 (just before 0018 rebuilds `host_keys`),
    /// opens with the current build: every row survives, the schema reaches
    /// the latest version, and the migrations that drop data drop only
    /// theirs (MIK-372 T3).
    #[tokio::test]
    async fn an_old_database_with_data_migrates_and_keeps_its_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        {
            let pool = raw_pool(&path).await;
            check_application_id(&pool).await.unwrap();
            migrate(&pool, &MIGRATIONS[..1]).await.unwrap();
            for sql in [
                "INSERT INTO ips (id, ip, first_seen, last_seen, country, notes)
                 VALUES (1, '203.0.113.9', '2025-06-01 00:00:00', '2025-06-02 00:00:00',
                         'DE', 'kept')",
                "INSERT INTO requests (id, uid, ts, ip_id, method, path, headers_json,
                                       labels_json, severity)
                 VALUES (1, 'r-old', '2025-06-02 00:00:00', 1, 'GET', '/.env', '[]',
                         '[\"env\"]', 3)",
                "INSERT INTO scan_jobs (id, uid, ip_id, level, status, queued_at, finished_at)
                 VALUES (1, 'j-old', 1, 2, 'done', '2025-06-02 00:00:00',
                         '2025-06-02 00:05:00')",
                "INSERT INTO scans (id, uid, job_id, ip_id, level, started_at, finished_at, os_guess)
                 VALUES (1, 's-old', 1, 1, 2, '2025-06-02 00:01:00', '2025-06-02 00:05:00',
                         'Linux 5.x')",
                "INSERT INTO ports (scan_id, port, proto, state, service)
                 VALUES (1, 22, 'tcp', 'open', 'ssh')",
                "INSERT INTO settings (key, value) VALUES ('scan.max_workers', '3')",
                // Dropped on purpose by 0011 and 0024.
                "INSERT INTO settings (key, value) VALUES ('cluster.config_key', 'x')",
                "INSERT INTO settings (key, value) VALUES ('credits.collect_to', 'y')",
            ] {
                exec(&pool, sql).await;
            }
            migrate(&pool, &MIGRATIONS[..17]).await.unwrap();
            // A host key of the scan (0002), already parsed: 0018 copies it
            // into the rebuilt table.
            exec(
                &pool,
                "INSERT INTO host_keys (scan_id, ip_id, port, kind, fingerprint)
                 VALUES (1, 1, 22, 'ssh-ed25519', 'SHA256:kept')",
            )
            .await;
            exec(&pool, "UPDATE scans SET keys_parsed = 1").await;
            pool.close().await;
        }
        let s = Store::connect(&path).await.unwrap();
        assert_eq!(s.schema_version().await.unwrap(), MIGRATIONS.len() as i64);
        let ip: (String, String, String, i64, i64, String) = sqlx::query_as(
            "SELECT ip, country, notes, request_count, max_severity, ip_key
             FROM ips WHERE id = 1",
        )
        .fetch_one(&s.read)
        .await
        .unwrap();
        assert_eq!(ip.0, "203.0.113.9");
        assert_eq!((ip.1.as_str(), ip.2.as_str()), ("DE", "kept"));
        assert_eq!((ip.3, ip.4), (1, 3), "the aggregates stand");
        assert!(!ip.5.is_empty(), "the range key is backfilled");
        let req: (String, String, String, i64) =
            sqlx::query_as("SELECT uid, path, labels_json, severity FROM requests WHERE id = 1")
                .fetch_one(&s.read)
                .await
                .unwrap();
        assert_eq!(req, ("r-old".into(), "/.env".into(), "[\"env\"]".into(), 3));
        let scan: (String, String, i64) = sqlx::query_as(
            "SELECT s.uid, s.os_guess, j.level FROM scans s JOIN scan_jobs j ON j.id = s.job_id
             WHERE s.id = 1",
        )
        .fetch_one(&s.read)
        .await
        .unwrap();
        assert_eq!(scan, ("s-old".into(), "Linux 5.x".into(), 2));
        let port: (i64, String) =
            sqlx::query_as("SELECT port, service FROM ports WHERE scan_id = 1")
                .fetch_one(&s.read)
                .await
                .unwrap();
        assert_eq!(port, (22, "ssh".into()));
        let key: (Option<i64>, Option<i64>, String) =
            sqlx::query_as("SELECT scan_id, probe_id, fingerprint FROM host_keys WHERE port = 22")
                .fetch_one(&s.read)
                .await
                .unwrap();
        assert_eq!(key, (Some(1), None, "SHA256:kept".into()));
        let settings: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM settings ORDER BY key")
                .fetch_all(&s.read)
                .await
                .unwrap();
        assert_eq!(settings, vec![("scan.max_workers".into(), "3".into())]);
        // Reopening changes nothing.
        drop(s);
        let s = Store::connect(&path).await.unwrap();
        assert_eq!(s.schema_version().await.unwrap(), MIGRATIONS.len() as i64);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requests")
            .fetch_one(&s.read)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    /// Every intermediate version upgrades: a database left at schema `v`
    /// by any older build, with a row, reaches the latest version.
    #[tokio::test]
    async fn every_older_schema_version_upgrades_with_its_rows() {
        let dir = tempfile::tempdir().unwrap();
        for v in 1..MIGRATIONS.len() {
            let path = dir.path().join(format!("v{v}.db"));
            {
                let pool = raw_pool(&path).await;
                check_application_id(&pool).await.unwrap();
                migrate(&pool, &MIGRATIONS[..v]).await.unwrap();
                exec(
                    &pool,
                    "INSERT INTO ips (ip, first_seen, last_seen)
                     VALUES ('198.51.100.3', '2025-01-01 00:00:00', '2025-01-01 00:00:00')",
                )
                .await;
                pool.close().await;
            }
            let s = Store::connect(&path)
                .await
                .unwrap_or_else(|e| panic!("from schema {v}: {e:#}"));
            assert_eq!(
                s.schema_version().await.unwrap(),
                MIGRATIONS.len() as i64,
                "from schema {v}"
            );
            let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ips WHERE ip = '198.51.100.3'")
                .fetch_one(&s.read)
                .await
                .unwrap();
            assert_eq!(n, 1, "from schema {v}");
        }
    }

    /// A database a newer build migrated (an installer rollback) is opened
    /// as it is: no migration runs, its version is not lowered and its
    /// schema and rows are untouched. Not refused: the build only warns,
    /// as migrations are additive (see the end of [`migrate`]).
    #[tokio::test]
    async fn a_database_newer_than_the_build_opens_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let newer = MIGRATIONS.len() as i64 + 3;
        {
            let s = Store::connect(&path).await.unwrap();
            exec(
                &s.pool,
                "INSERT INTO ips (ip, ip_key, first_seen, last_seen)
                 VALUES ('192.0.2.1', '', '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
            )
            .await;
            // What the newer build's migrations added.
            exec(&s.pool, "CREATE TABLE from_the_future (x INTEGER)").await;
            exec(&s.pool, "INSERT INTO from_the_future VALUES (42)").await;
            exec(&s.pool, &format!("PRAGMA user_version = {newer}")).await;
            s.pool.close().await;
            s.read.close().await;
        }
        let schema = |pool: sqlx::SqlitePool| async move {
            let v: Vec<(String, String, Option<String>)> =
                sqlx::query_as("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
                    .fetch_all(&pool)
                    .await
                    .unwrap();
            v
        };
        let before = {
            let pool = raw_pool(&path).await;
            let v = schema(pool.clone()).await;
            pool.close().await;
            v
        };
        let s = Store::connect(&path).await.expect("a newer schema opens");
        assert_eq!(s.schema_version().await.unwrap(), newer, "not lowered");
        assert_eq!(schema(s.pool.clone()).await, before, "schema untouched");
        let x: i64 = sqlx::query_scalar("SELECT x FROM from_the_future")
            .fetch_one(&s.read)
            .await
            .unwrap();
        assert_eq!(x, 42);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ips WHERE ip = '192.0.2.1'")
            .fetch_one(&s.read)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn intel_prefix_matches_only_the_literal_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        for k in [
            "relay.leased.aa",
            "relay.leased.bb",
            "relay.leasedX",
            "RELAY.LEASED.cc",
            "relayXleased.dd",
            "%other",
        ] {
            s.intel_set(k, "v").await.unwrap();
        }
        let keys = |rows: Vec<(String, String)>| rows.into_iter().map(|r| r.0).collect::<Vec<_>>();
        assert_eq!(
            keys(s.intel_prefix("relay.leased.").await.unwrap()),
            ["relay.leased.aa", "relay.leased.bb"]
        );
        assert_eq!(keys(s.intel_prefix("%").await.unwrap()), ["%other"]);
        assert!(s.intel_prefix("relay_leased.").await.unwrap().is_empty());
        assert!(s.intel_prefix("relay.leased.%").await.unwrap().is_empty());
    }
}
