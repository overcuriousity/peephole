pub mod auth;
pub mod browse;
pub mod delete;
pub mod fingerprints;
pub mod inspect;
pub mod requests;
pub mod scans;
pub mod stats;

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
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await
            .context("opening sqlite")?;
        for stmt in MIGRATIONS
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            sqlx::query(stmt)
                .execute(&pool)
                .await
                .context("migration")?;
        }
        Ok(Self { pool })
    }
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

    pub async fn ip_history(&self, ip_id: i64) -> anyhow::Result<crate::classify::IpHistory> {
        let (paths, reqs): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(DISTINCT path), COUNT(*) FROM requests
             WHERE ip_id = ? AND ts > datetime('now','-1 hour')",
        )
        .bind(ip_id)
        .fetch_one(&self.pool)
        .await?;
        let last_level: Option<i64> = sqlx::query_scalar(
            "SELECT level FROM scans WHERE ip_id = ? ORDER BY finished_at DESC LIMIT 1",
        )
        .bind(ip_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(crate::classify::IpHistory {
            distinct_paths_1h: paths as u32,
            requests_1h: reqs as u32,
            last_scan_level: last_level.unwrap_or(0) as u8,
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
            sql.push_str(" AND r.labels_json LIKE ?");
            binds.push(format!("%\"{v}\"%"));
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
        >(&sql);
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
