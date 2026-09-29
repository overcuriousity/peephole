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

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct RequestListRow {
    pub id: i64, pub ts: String, pub ip_id: i64, pub ip: String,
    pub method: String, pub path: String, pub severity: i64, pub labels_json: String,
}

pub struct FpClaimRow {
    pub ts: String, pub ip: String, pub contact_email: Option<String>, pub user_agent: String,
}

impl Store {
    pub async fn search_requests(&self, f: &crate::admin::detail::RequestFilter) -> anyhow::Result<Vec<RequestListRow>> {
        let mut sql = String::from(
            "SELECT r.id, r.ts, r.ip_id, i.ip, r.method, r.path, r.severity, r.labels_json
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1");
        let mut binds: Vec<String> = vec![];
        if let Some(v) = &f.ip       { sql.push_str(" AND i.ip = ?"); binds.push(v.clone()); }
        if let Some(v) = &f.path     { sql.push_str(" AND r.path LIKE ?"); binds.push(format!("%{v}%")); }
        if let Some(v) = &f.label    { sql.push_str(" AND r.labels_json LIKE ?"); binds.push(format!("%\"{v}\"%")); }
        if let Some(v) = &f.severity { sql.push_str(" AND r.severity = ?"); binds.push(v.to_string()); }
        if let Some(v) = &f.country  { sql.push_str(" AND i.country = ?"); binds.push(v.clone()); }
        if let Some(v) = &f.asn      { sql.push_str(" AND i.asn = ?"); binds.push(v.to_string()); }
        if let Some(v) = &f.from     { sql.push_str(" AND r.ts >= ?"); binds.push(v.clone()); }
        if let Some(v) = &f.to       { sql.push_str(" AND r.ts <= ?"); binds.push(v.clone()); }
        sql.push_str(" ORDER BY r.id DESC LIMIT 500");
        let mut q = sqlx::query_as::<_, RequestListRow>(&sql);
        for b in binds { q = q.bind(b); }
        Ok(q.fetch_all(&self.pool).await?)
    }

    pub async fn request_detail(&self, id: i64)
        -> anyhow::Result<Option<(crate::store::requests::RequestRow, String, String)>>
    {
        let Some(row) = self.request_by_id(id).await? else { return Ok(None) };
        let headers: Vec<(String, String)> =
            serde_json::from_str(&row.headers_json).unwrap_or_default();
        let headers_pretty = headers.iter()
            .map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join("\n");
        let body_pretty = row.body.as_ref()
            .map(|b| String::from_utf8_lossy(b).chars().take(16384).collect::<String>())
            .unwrap_or_default();
        Ok(Some((row, headers_pretty, body_pretty)))
    }

    pub async fn ip_detail(&self, ip_id: i64) -> anyhow::Result<Option<String>> {
        let Some(ip) = self.ip_by_id(ip_id).await? else { return Ok(None) };
        let requests = sqlx::query_as::<_, (String, String, String, i64, String)>(
            "SELECT ts, method, path, severity, labels_json FROM requests
             WHERE ip_id = ? ORDER BY id DESC LIMIT 100")
            .bind(ip_id).fetch_all(&self.pool).await?;
        let scans = sqlx::query_as::<_, (i64, i64, String, Option<String>)>(
            "SELECT id, level, COALESCE(finished_at,''), os_guess FROM scans
             WHERE ip_id = ? ORDER BY id DESC")
            .bind(ip_id).fetch_all(&self.pool).await?;
        let fps = sqlx::query_as::<_, (String, i64)>(
            "SELECT fp_hash, COUNT(*) FROM fingerprints WHERE ip_id = ? GROUP BY fp_hash")
            .bind(ip_id).fetch_all(&self.pool).await?;
        let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
        let mut html = format!(
            "<h1>{}</h1><p>first seen {} · last seen {} · country {} · AS{} {} {}</p>",
            esc(&ip.ip), ip.first_seen, ip.last_seen,
            esc(&ip.country.clone().unwrap_or("?".into())),
            ip.asn.map(|a| a.to_string()).unwrap_or("?".into()),
            esc(&ip.asn_org.clone().unwrap_or_default()),
            if ip.is_tor_exit { " · <b>tor exit node</b>" } else { "" });
        html.push_str("<h2>Scans</h2>");
        for (scan_id, level, finished, os) in &scans {
            html.push_str(&format!("<h3>level {level} · {finished} · {}</h3><ul>",
                esc(&os.clone().unwrap_or("os unknown".into()))));
            let ports = sqlx::query_as::<_, (i64, String, String, Option<String>, Option<String>, Option<String>)>(
                "SELECT port, proto, state, service, product, version FROM ports WHERE scan_id = ?")
                .bind(scan_id).fetch_all(&self.pool).await?;
            for (port, proto, state, service, product, version) in &ports {
                html.push_str(&format!("<li>{port}/{proto} {state} {} {} {}</li>",
                    esc(&service.clone().unwrap_or_default()),
                    esc(&product.clone().unwrap_or_default()),
                    esc(&version.clone().unwrap_or_default())));
            }
            html.push_str("</ul>");
        }
        html.push_str("<h2>Fingerprints</h2><ul>");
        for (hash, n) in &fps {
            let others = self.fingerprint_ip_count(hash, ip_id).await.unwrap_or(0);
            html.push_str(&format!("<li><code>{}</code> ×{n} — seen from {others} other IPs</li>",
                esc(&hash[..16.min(hash.len())])));
        }
        html.push_str("</ul><h2>Requests</h2><table><tr><th>ts</th><th>method</th><th>path</th><th>severity</th><th>labels</th></tr>");
        for (ts, method, path, severity, labels) in &requests {
            html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{severity}</td><td>{}</td></tr>",
                esc(ts), esc(method), esc(path), esc(labels)));
        }
        html.push_str("</table>");
        Ok(Some(html))
    }

    pub async fn inbox(&self) -> anyhow::Result<Vec<FpClaimRow>> {
        Ok(sqlx::query_as::<_, (String, String, Option<String>, String)>(
            "SELECT c.ts, i.ip, c.contact_email, c.user_agent
             FROM fp_claims c JOIN ips i ON c.ip_id = i.id ORDER BY c.id DESC")
            .fetch_all(&self.pool).await?
            .into_iter()
            .map(|(ts, ip, contact_email, user_agent)| FpClaimRow { ts, ip, contact_email, user_agent })
            .collect())
    }

    pub async fn list_credential_labels(&self) -> anyhow::Result<Vec<(String, String, String)>> {
        Ok(sqlx::query_as(
            "SELECT hex(cred_id), COALESCE(label,'(unnamed)'), created_at FROM credentials ORDER BY id")
            .fetch_all(&self.pool).await?)
    }
}
