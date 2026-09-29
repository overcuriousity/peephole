pub mod auth;
pub mod fingerprints;
pub mod requests;
pub mod scans;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::path::Path;

const MIGRATIONS: &str = include_str!("schema.sql");

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
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new().max_connections(8).connect_with(opts).await
            .context("opening sqlite")?;
        for stmt in MIGRATIONS.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            sqlx::query(stmt).execute(&pool).await.context("migration")?;
        }
        Ok(Self { pool })
    }
}

impl Store {
    pub async fn intel_get(&self, key: &str) -> anyhow::Result<Option<String>> {
        Ok(sqlx::query_scalar("SELECT value FROM intel_meta WHERE key = ?")
            .bind(key).fetch_optional(&self.pool).await?)
    }

    pub async fn intel_set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO intel_meta (key, value) VALUES (?, ?)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            .bind(key).bind(value).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn ip_history(&self, ip_id: i64) -> anyhow::Result<crate::classify::IpHistory> {
        let (paths, reqs): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(DISTINCT path), COUNT(*) FROM requests
             WHERE ip_id = ? AND ts > datetime('now','-1 hour')",
        ).bind(ip_id).fetch_one(&self.pool).await?;
        let last_level: Option<i64> = sqlx::query_scalar(
            "SELECT level FROM scans WHERE ip_id = ? ORDER BY finished_at DESC LIMIT 1",
        ).bind(ip_id).fetch_optional(&self.pool).await?;
        Ok(crate::classify::IpHistory {
            distinct_paths_1h: paths as u32,
            requests_1h: reqs as u32,
            last_scan_level: last_level.unwrap_or(0) as u8,
        })
    }
}

#[derive(serde::Serialize)]
pub struct PublicStats {
    pub total_requests: i64,
    pub unique_ips: i64,
    pub scans_done: i64,
    pub top_ips: Vec<(String, i64)>,
    pub top_countries: Vec<(String, i64)>,
    pub top_asns: Vec<(String, i64)>,
    pub severity_distribution: Vec<(i64, i64)>,
    pub recent: Vec<RecentRequest>,
    pub intel: std::collections::HashMap<String, String>,
}

#[derive(serde::Serialize)]
pub struct RecentRequest {
    pub ts: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub severity: i64,
    pub labels: String,
    pub country: Option<String>,
    pub is_tor: bool,
}

impl PublicStats {
    pub fn default_stats() -> Self {
        Self {
            total_requests: 0, unique_ips: 0, scans_done: 0,
            top_ips: vec![], top_countries: vec![], top_asns: vec![],
            severity_distribution: vec![], recent: vec![],
            intel: Default::default(),
        }
    }
}

impl Store {
    pub async fn public_stats(&self) -> anyhow::Result<PublicStats> {
        let total_requests = sqlx::query_scalar("SELECT COUNT(*) FROM requests").fetch_one(&self.pool).await?;
        let unique_ips = sqlx::query_scalar("SELECT COUNT(*) FROM ips").fetch_one(&self.pool).await?;
        let scans_done = sqlx::query_scalar("SELECT COUNT(*) FROM scans").fetch_one(&self.pool).await?;
        let top_ips = sqlx::query_as(
            "SELECT i.ip, COUNT(*) c FROM requests r JOIN ips i ON r.ip_id = i.id
             GROUP BY i.ip ORDER BY c DESC LIMIT 20").fetch_all(&self.pool).await?;
        let top_countries = sqlx::query_as(
            "SELECT COALESCE(country,'unknown'), COUNT(*) c FROM ips
             GROUP BY country ORDER BY c DESC LIMIT 20").fetch_all(&self.pool).await?;
        let top_asns = sqlx::query_as(
            "SELECT COALESCE(asn_org,'unknown'), COUNT(*) c FROM ips
             GROUP BY asn_org ORDER BY c DESC LIMIT 20").fetch_all(&self.pool).await?;
        let severity_distribution = sqlx::query_as(
            "SELECT severity, COUNT(*) FROM requests GROUP BY severity ORDER BY severity").fetch_all(&self.pool).await?;
        let recent = sqlx::query_as::<_, (String, String, String, String, i64, String, Option<String>, bool)>(
            "SELECT r.ts, i.ip, r.method, r.path, r.severity, r.labels_json, i.country, i.is_tor_exit
             FROM requests r JOIN ips i ON r.ip_id = i.id ORDER BY r.id DESC LIMIT 50")
            .fetch_all(&self.pool).await?
            .into_iter().map(|(ts, ip, method, path, severity, labels, country, is_tor)|
                RecentRequest { ts, ip, method, path, severity, labels, country, is_tor })
            .collect();
        let intel = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM intel_meta")
            .fetch_all(&self.pool).await?.into_iter().collect();
        Ok(PublicStats { total_requests, unique_ips, scans_done, top_ips, top_countries,
                         top_asns, severity_distribution, recent, intel })
    }
}
