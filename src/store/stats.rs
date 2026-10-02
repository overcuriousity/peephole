//! Aggregates for the public wall of shame, per time range, plus a short
//! TTL cache so anonymous traffic cannot hammer SQLite.
use super::Store;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Range {
    H24,
    D7,
    D30,
    All,
}

impl Range {
    pub const ALL: [Range; 4] = [Range::H24, Range::D7, Range::D30, Range::All];

    pub fn parse(s: Option<&str>) -> Range {
        match s {
            Some("7d") => Range::D7,
            Some("30d") => Range::D30,
            Some("all") => Range::All,
            _ => Range::H24,
        }
    }
    pub fn key(self) -> &'static str {
        match self {
            Range::H24 => "24h",
            Range::D7 => "7d",
            Range::D30 => "30d",
            Range::All => "all",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Range::H24 => "Last 24 hours",
            Range::D7 => "Last 7 days",
            Range::D30 => "Last 30 days",
            Range::All => "All time",
        }
    }
    /// SQLite modifier for `datetime('now', ?)`; `None` = no bound.
    pub fn since(self) -> Option<&'static str> {
        match self {
            Range::H24 => Some("-24 hours"),
            Range::D7 => Some("-7 days"),
            Range::D30 => Some("-30 days"),
            Range::All => None,
        }
    }
    pub fn hourly(self) -> bool {
        matches!(self, Range::H24 | Range::D7)
    }
    /// `WHERE`-fragment and bind value for a timestamp column.
    fn ts_clause(self, col: &str) -> (String, Option<&'static str>) {
        match self.since() {
            Some(m) => (format!(" AND {col} >= datetime('now', ?)"), Some(m)),
            None => (String::new(), None),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct Named {
    pub name: String,
    pub count: i64,
}

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct TopIp {
    pub ip: String,
    pub count: i64,
    pub country: Option<String>,
    pub max_severity: i64,
    pub is_tor: bool,
}

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct Bucket {
    pub ts: String,
    pub count: i64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RecentRequest {
    pub id: i64,
    pub ts: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub severity: i64,
    pub labels: Vec<String>,
    pub country: Option<String>,
    pub is_tor: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Stats {
    pub range: &'static str,
    pub generated_at: String,
    pub total_requests: i64,
    pub unique_ips: i64,
    pub countries: i64,
    pub tor_ips: i64,
    pub scans_done: i64,
    pub top_ips: Vec<TopIp>,
    pub top_countries: Vec<Named>,
    pub top_asns: Vec<Named>,
    pub top_labels: Vec<Named>,
    pub severity_distribution: Vec<Named>,
    pub timeline: Vec<Bucket>,
    /// Admin-only, rendered server-side on the wall. Never serialized to the
    /// public `/api/stats` JSON — request rows identify individual clients.
    #[serde(skip_serializing)]
    pub recent: Vec<RecentRequest>,
    pub intel: HashMap<String, String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MapCounts {
    pub range: &'static str,
    pub generated_at: String,
    pub countries: HashMap<String, i64>,
    pub max: i64,
}

/// Bind the optional range modifier onto a query builder.
macro_rules! bind_since {
    ($q:expr, $since:expr) => {{
        let mut q = $q;
        if let Some(m) = $since {
            q = q.bind(m);
        }
        q
    }};
}

type RecentTuple = (
    i64,
    String,
    String,
    String,
    String,
    i64,
    String,
    Option<String>,
    bool,
);

impl Store {
    async fn count_where(&self, sql: &str, since: Option<&'static str>) -> Result<i64> {
        Ok(bind_since!(
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql)),
            since
        )
        .fetch_one(&self.pool)
        .await?)
    }

    async fn named(&self, sql: &str, since: Option<&'static str>) -> Result<Vec<Named>> {
        Ok(
            bind_since!(sqlx::query_as::<_, Named>(sqlx::AssertSqlSafe(sql)), since)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn stats(&self, r: Range) -> Result<Stats> {
        let (w, since) = r.ts_clause("r.ts");
        let total_requests = self
            .count_where(
                &format!("SELECT COUNT(*) FROM requests r WHERE 1=1{w}"),
                since,
            )
            .await?;
        let unique_ips = self
            .count_where(
                &format!("SELECT COUNT(DISTINCT r.ip_id) FROM requests r WHERE 1=1{w}"),
                since,
            )
            .await?;
        let countries = self
            .count_where(
                &format!(
                    "SELECT COUNT(DISTINCT i.country) FROM requests r JOIN ips i ON r.ip_id = i.id
                     WHERE i.country IS NOT NULL{w}"
                ),
                since,
            )
            .await?;
        let tor_ips = self
            .count_where(
                &format!(
                    "SELECT COUNT(DISTINCT r.ip_id) FROM requests r JOIN ips i ON r.ip_id = i.id
                     WHERE i.is_tor_exit = 1{w}"
                ),
                since,
            )
            .await?;
        let (ws, since_s) = r.ts_clause("s.finished_at");
        let scans_done = self
            .count_where(
                &format!("SELECT COUNT(*) FROM scans s WHERE 1=1{ws}"),
                since_s,
            )
            .await?;

        let sql = format!(
            "SELECT i.ip, COUNT(*) AS count, i.country, MAX(r.severity) AS max_severity,
                    i.is_tor_exit AS is_tor
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w}
             GROUP BY i.id ORDER BY count DESC LIMIT 20"
        );
        let top_ips = bind_since!(
            sqlx::query_as::<_, TopIp>(sqlx::AssertSqlSafe(sql.as_str())),
            since
        )
        .fetch_all(&self.pool)
        .await?;
        let top_countries = self
            .named(
                &format!(
                    "SELECT COALESCE(i.country,'??') AS name, COUNT(DISTINCT i.id) AS count
                     FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w}
                     GROUP BY i.country ORDER BY count DESC LIMIT 20"
                ),
                since,
            )
            .await?;
        let top_asns = self
            .named(
                &format!(
                    // Group by ASN (not the org text): different ASNs can
                    // share an org name, and one ASN can carry slightly
                    // different org strings. Show a representative org, else
                    // the AS number.
                    "SELECT COALESCE(MAX(i.asn_org), 'AS' || i.asn, 'unknown') AS name,
                            COUNT(DISTINCT i.id) AS count
                     FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w}
                     GROUP BY i.asn ORDER BY count DESC LIMIT 20"
                ),
                since,
            )
            .await?;
        let top_labels = self
            .named(
                &format!(
                    "SELECT je.value AS name, COUNT(*) AS count
                     FROM requests r, json_each(r.labels_json) je WHERE 1=1{w}
                     GROUP BY je.value ORDER BY count DESC LIMIT 20"
                ),
                since,
            )
            .await?;
        let severity_distribution = self
            .named(
                &format!(
                    "SELECT CAST(r.severity AS TEXT) AS name, COUNT(*) AS count
                     FROM requests r WHERE 1=1{w} GROUP BY r.severity ORDER BY r.severity"
                ),
                since,
            )
            .await?;
        let fmt = if r.hourly() {
            "%Y-%m-%dT%H:00"
        } else {
            "%Y-%m-%d"
        };
        let sql = format!(
            "SELECT strftime('{fmt}', r.ts) AS ts, COUNT(*) AS count FROM requests r
             WHERE 1=1{w} GROUP BY ts ORDER BY ts"
        );
        let timeline = bind_since!(
            sqlx::query_as::<_, Bucket>(sqlx::AssertSqlSafe(sql.as_str())),
            since
        )
        .fetch_all(&self.pool)
        .await?;
        let sql = format!(
            "SELECT r.id, r.ts, i.ip, r.method, r.path, r.severity, r.labels_json, i.country,
                    i.is_tor_exit
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w}
             ORDER BY r.id DESC LIMIT 50"
        );
        let recent_rows = bind_since!(
            sqlx::query_as::<_, RecentTuple>(sqlx::AssertSqlSafe(sql.as_str())),
            since
        )
        .fetch_all(&self.pool)
        .await?;
        let recent = recent_rows
            .into_iter()
            .map(
                |(id, ts, ip, method, path, severity, labels, country, is_tor)| RecentRequest {
                    id,
                    ts,
                    ip,
                    method,
                    path,
                    severity,
                    labels: serde_json::from_str(&labels).unwrap_or_default(),
                    country,
                    is_tor,
                },
            )
            .collect();
        // Only the public refresh timestamps — never the whole intel_meta
        // table, which also holds webauthn_setup_token_hash. `intel` is
        // serialized into the public /api/stats response.
        let intel = sqlx::query_as::<_, (String, String)>(
            "SELECT key, value FROM intel_meta
             WHERE key IN ('tor_last_fetch','maxmind_last_fetch','maxmind_cluster_seen')",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .collect();
        Ok(Stats {
            range: r.key(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_requests,
            unique_ips,
            countries,
            tor_ips,
            scans_done,
            top_ips,
            top_countries,
            top_asns,
            top_labels,
            severity_distribution,
            timeline,
            recent,
            intel,
        })
    }

    pub async fn map_counts(&self, r: Range) -> Result<MapCounts> {
        let (w, since) = r.ts_clause("r.ts");
        let rows = self
            .named(
                &format!(
                    "SELECT i.country AS name, COUNT(DISTINCT i.id) AS count
                     FROM requests r JOIN ips i ON r.ip_id = i.id
                     WHERE i.country IS NOT NULL{w} GROUP BY i.country"
                ),
                since,
            )
            .await?;
        let max = rows.iter().map(|n| n.count).max().unwrap_or(0);
        Ok(MapCounts {
            range: r.key(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            countries: rows.into_iter().map(|n| (n.name, n.count)).collect(),
            max,
        })
    }
}

/// Warn when Tor/MaxMind data is missing or older than 48h (original spec §9).
/// GeoIP counts as current on a cluster node without its own databases while
/// a member offers lookups (`maxmind_cluster_seen`).
pub fn intel_stale(intel: &HashMap<String, String>) -> bool {
    let stale = |key: &str| {
        intel
            .get(key)
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .map(|t| chrono::Utc::now().signed_duration_since(t).num_hours() > 48)
            .unwrap_or(true)
    };
    stale("tor_last_fetch") || (stale("maxmind_last_fetch") && stale("maxmind_cluster_seen"))
}

const TTL: Duration = Duration::from_secs(15);

/// Bound on cached IP-directory pages (anonymous traffic only).
pub const IPS_CACHE_MAX: usize = 64;

type IpsPage = Arc<super::browse::Page<super::browse::IpSummary>>;

#[derive(Default)]
pub struct StatsCache {
    stats: RwLock<HashMap<Range, (Instant, Arc<Stats>)>>,
    map: RwLock<HashMap<Range, (Instant, Arc<MapCounts>)>>,
    /// Keyed by the full query string (filter + page).
    ips: RwLock<HashMap<String, (Instant, IpsPage)>>,
    /// Single-flight guard: on a miss only one task recomputes (each of these
    /// aggregations scans much of the table), the rest wait and read the
    /// freshly cached value, so an expiry under load is not a stampede.
    refresh: tokio::sync::Mutex<()>,
}

impl StatsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn stats(&self, store: &Store, r: Range) -> Result<Arc<Stats>> {
        if let Some((t, v)) = self.stats.read().await.get(&r)
            && t.elapsed() < TTL
        {
            return Ok(v.clone());
        }
        let _flight = self.refresh.lock().await;
        // Another task may have refreshed while we waited for the guard.
        if let Some((t, v)) = self.stats.read().await.get(&r)
            && t.elapsed() < TTL
        {
            return Ok(v.clone());
        }
        let fresh = Arc::new(store.stats(r).await?);
        self.stats
            .write()
            .await
            .insert(r, (Instant::now(), fresh.clone()));
        Ok(fresh)
    }

    /// Public IP-directory pages: the unfiltered first page is what anonymous
    /// crawlers hit, and it aggregates the whole requests table.
    pub async fn ips(
        &self,
        store: &Store,
        f: &super::browse::IpFilter,
        key: String,
    ) -> Result<IpsPage> {
        if let Some((t, v)) = self.ips.read().await.get(&key)
            && t.elapsed() < TTL
        {
            return Ok(v.clone());
        }
        let _flight = self.refresh.lock().await;
        if let Some((t, v)) = self.ips.read().await.get(&key)
            && t.elapsed() < TTL
        {
            return Ok(v.clone());
        }
        let fresh = Arc::new(store.list_ips(f).await?);
        let mut w = self.ips.write().await;
        if w.len() >= IPS_CACHE_MAX {
            // Drop expired entries first, then the oldest, to stay bounded.
            w.retain(|_, (t, _)| t.elapsed() < TTL);
            if w.len() >= IPS_CACHE_MAX
                && let Some(oldest) = w
                    .iter()
                    .min_by_key(|(_, (t, _))| *t)
                    .map(|(k, _)| k.clone())
            {
                w.remove(&oldest);
            }
        }
        w.insert(key, (Instant::now(), fresh.clone()));
        Ok(fresh)
    }

    #[cfg(test)]
    pub async fn ips_len(&self) -> usize {
        self.ips.read().await.len()
    }

    pub async fn map(&self, store: &Store, r: Range) -> Result<Arc<MapCounts>> {
        if let Some((t, v)) = self.map.read().await.get(&r)
            && t.elapsed() < TTL
        {
            return Ok(v.clone());
        }
        let _flight = self.refresh.lock().await;
        if let Some((t, v)) = self.map.read().await.get(&r)
            && t.elapsed() < TTL
        {
            return Ok(v.clone());
        }
        let fresh = Arc::new(store.map_counts(r).await?);
        self.map
            .write()
            .await
            .insert(r, (Instant::now(), fresh.clone()));
        Ok(fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    async fn seeded() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let a = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        let b = s.upsert_ip("198.51.100.2".parse().unwrap()).await.unwrap();
        s.set_ip_geo(a.id, Some("DE"), Some(3320), Some("Deutsche Telekom"))
            .await
            .unwrap();
        s.set_ip_geo(b.id, Some("US"), Some(15169), Some("Google"))
            .await
            .unwrap();
        s.set_ip_tor(b.id, true).await.unwrap();
        let req = |ip_id, path: &str, sev| NewRequest {
            ip_id,
            method: "GET".into(),
            path: path.into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: r#"["sensitive-path"]"#.into(),
            severity: sev,
            scan_level: 1,
            is_fp_claim: false,
            page_token: None,
        };
        s.insert_request(&req(a.id, "/.env", 3)).await.unwrap();
        s.insert_request(&req(a.id, "/wp-login.php", 2))
            .await
            .unwrap();
        s.insert_request(&req(b.id, "/", 0)).await.unwrap();
        // One request 3 days old: outside 24h, inside 7d.
        sqlx::query("INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, labels_json, severity) VALUES ('raw-old', datetime('now','-3 days'), ?, 'GET', '/old', '[]', '[]', 1)")
            .bind(b.id).execute(&s.pool).await.unwrap();
        s
    }

    #[test]
    fn range_parse_falls_back_to_24h() {
        assert_eq!(Range::parse(Some("7d")), Range::D7);
        assert_eq!(Range::parse(Some("all")), Range::All);
        assert_eq!(Range::parse(Some("1y")), Range::H24);
        assert_eq!(Range::parse(None), Range::H24);
    }

    #[tokio::test]
    async fn stats_intel_excludes_setup_token_hash() {
        let s = seeded().await;
        s.intel_set("webauthn_setup_token_hash", "deadbeef")
            .await
            .unwrap();
        s.intel_set("tor_last_fetch", "2026-01-01T00:00:00Z")
            .await
            .unwrap();
        let st = s.stats(Range::All).await.unwrap();
        assert!(
            !st.intel.contains_key("webauthn_setup_token_hash"),
            "setup token hash must never reach public /api/stats"
        );
        assert!(st.intel.contains_key("tor_last_fetch"));
    }

    #[tokio::test]
    async fn stats_respect_range() {
        let s = seeded().await;
        let h24 = s.stats(Range::H24).await.unwrap();
        assert_eq!(h24.total_requests, 3);
        assert_eq!(h24.unique_ips, 2);
        assert_eq!(h24.countries, 2);
        assert_eq!(h24.tor_ips, 1);
        assert_eq!(h24.top_ips[0].ip, "203.0.113.1");
        assert_eq!(h24.top_ips[0].count, 2);
        assert_eq!(h24.top_ips[0].max_severity, 3);
        assert_eq!(h24.top_labels[0].name, "sensitive-path");
        assert_eq!(h24.top_labels[0].count, 3);
        assert_eq!(h24.recent.len(), 3);
        assert_eq!(h24.recent[0].labels, vec!["sensitive-path".to_string()]);
        let d7 = s.stats(Range::D7).await.unwrap();
        assert_eq!(d7.total_requests, 4);
        assert!(d7.timeline.iter().map(|b| b.count).sum::<i64>() == 4);
        assert!(d7.timeline.len() >= 2, "hourly buckets over 7 days");
        let all = s.stats(Range::All).await.unwrap();
        assert_eq!(all.total_requests, 4);
        assert!(
            all.timeline.iter().all(|b| b.ts.len() == 10),
            "daily buckets are YYYY-MM-DD"
        );
    }

    #[tokio::test]
    async fn map_counts_unique_ips_per_country() {
        let s = seeded().await;
        let m = s.map_counts(Range::All).await.unwrap();
        assert_eq!(m.countries.get("DE"), Some(&1));
        assert_eq!(m.countries.get("US"), Some(&1));
        assert_eq!(m.max, 1);
    }

    #[tokio::test]
    async fn cache_serves_same_instance_within_ttl() {
        let s = seeded().await;
        let c = StatsCache::new();
        let a = c.stats(&s, Range::H24).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: 1,
            method: "GET".into(),
            path: "/new".into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: "[]".into(),
            severity: 0,
            scan_level: 0,
            is_fp_claim: false,
            page_token: None,
        })
        .await
        .unwrap();
        let b = c.stats(&s, Range::H24).await.unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(b.total_requests, 3, "stale within ttl by design");
        let d7 = c.stats(&s, Range::D7).await.unwrap();
        assert_eq!(d7.total_requests, 5, "other range is computed fresh");
    }

    #[tokio::test]
    async fn ip_directory_cache_is_keyed_and_bounded() {
        use crate::store::browse::IpFilter;
        let s = seeded().await;
        let c = StatsCache::new();
        let f = IpFilter::default();
        let a = c.ips(&s, &f, "".into()).await.unwrap();
        let b = c.ips(&s, &f, "".into()).await.unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let other = c
            .ips(
                &s,
                &IpFilter {
                    country: Some("DE".into()),
                    ..Default::default()
                },
                "country=DE&".into(),
            )
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&a, &other));
        assert_eq!(other.items.len(), 1);
        for i in 0..(IPS_CACHE_MAX + 5) {
            c.ips(&s, &f, format!("k{i}&")).await.unwrap();
        }
        assert!(c.ips_len().await <= IPS_CACHE_MAX);
    }

    #[test]
    fn intel_stale_when_missing_or_old() {
        let mut m = HashMap::new();
        assert!(intel_stale(&m));
        m.insert("tor_last_fetch".into(), chrono::Utc::now().to_rfc3339());
        m.insert(
            "maxmind_last_fetch".into(),
            (chrono::Utc::now() - chrono::Duration::hours(72)).to_rfc3339(),
        );
        assert!(intel_stale(&m));
        m.insert("maxmind_last_fetch".into(), chrono::Utc::now().to_rfc3339());
        assert!(!intel_stale(&m));
        // A cluster node without its own databases: a member's lookups count.
        m.remove("maxmind_last_fetch");
        assert!(intel_stale(&m));
        m.insert(
            "maxmind_cluster_seen".into(),
            chrono::Utc::now().to_rfc3339(),
        );
        assert!(!intel_stale(&m));
    }
}
