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
}
