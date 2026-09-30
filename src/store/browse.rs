//! Read models for the public directory and search pages (and, with a
//! session, the same pages' admin affordances). No admin-only data here.
use super::Store;
use super::requests::IpRow;
use super::stats::Named;
use anyhow::Result;
use ipnet::IpNet;
use std::net::IpAddr;

pub const PAGE_SIZE: i64 = 100;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: u32,
    pub has_next: bool,
}

impl<T> Page<T> {
    pub fn prev(&self) -> Option<u32> {
        (self.page > 1).then(|| self.page - 1)
    }
    pub fn next(&self) -> Option<u32> {
        self.has_next.then(|| self.page + 1)
    }
    pub fn from_rows(mut items: Vec<T>, page: u32) -> Self {
        let has_next = items.len() as i64 > PAGE_SIZE;
        items.truncate(PAGE_SIZE as usize);
        Self {
            items,
            page,
            has_next,
        }
    }
}

pub fn page_num(p: Option<i64>) -> u32 {
    p.filter(|n| *n >= 1)
        .map(|n| n.min(u32::MAX as i64) as u32)
        .unwrap_or(1)
}

pub fn offset(page: u32) -> i64 {
    (page as i64 - 1) * PAGE_SIZE
}

/// Numeric query params that must never 400: garbage becomes `None`.
pub fn lenient_i64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    let s: Option<String> = serde::Deserialize::deserialize(d)?;
    Ok(s.and_then(|v| v.trim().parse().ok()))
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct IpFilter {
    pub q: Option<String>,
    pub country: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub asn: Option<i64>,
    pub label: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub min_severity: Option<i64>,
    pub tor: Option<String>,
    pub sort: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub page: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct IpSummary {
    pub ip: String,
    pub country: Option<String>,
    pub asn: Option<i64>,
    pub asn_org: Option<String>,
    pub is_tor: bool,
    pub first_seen: String,
    pub last_seen: String,
    pub request_count: i64,
    pub max_severity: i64,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct RequestFilter {
    pub ip: Option<String>,
    pub path: Option<String>,
    pub label: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub severity: Option<i64>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub min_severity: Option<i64>,
    pub country: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub asn: Option<i64>,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub page: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct RequestListRow {
    pub id: i64,
    pub ts: String,
    pub ip_id: i64,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub severity: i64,
    pub labels_json: String,
    pub country: Option<String>,
    pub is_tor: bool,
}

impl RequestListRow {
    pub fn labels(&self) -> Vec<String> {
        serde_json::from_str(&self.labels_json).unwrap_or_default()
    }
}

pub struct IpOverview {
    pub ip: IpRow,
    pub request_count: i64,
    pub max_severity: i64,
    pub labels: Vec<Named>,
    /// 24 hourly buckets, oldest first, last = current hour.
    pub sparkline: Vec<i64>,
}

/// What the `q` box means.
enum IpQuery {
    Exact(String),
    Net(IpNet),
    Prefix(String),
    Invalid,
}

fn parse_q(q: &str) -> IpQuery {
    let q = q.trim();
    if q.is_empty() {
        return IpQuery::Prefix(String::new());
    }
    if let Ok(ip) = q.parse::<IpAddr>() {
        return IpQuery::Exact(ip.to_string());
    }
    if let Ok(net) = q.parse::<IpNet>() {
        return IpQuery::Net(net);
    }
    // A bare prefix: only digits, dots, hex and colons.
    if q.chars()
        .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
    {
        return IpQuery::Prefix(q.to_string());
    }
    IpQuery::Invalid
}

/// LIKE prefix that bounds a CIDR's candidates before exact filtering in Rust.
fn net_like_prefix(net: &IpNet) -> String {
    match net {
        IpNet::V4(n) => {
            let o = n.network().octets();
            match n.prefix_len() {
                0..=7 => String::new(),
                8..=15 => format!("{}.", o[0]),
                16..=23 => format!("{}.{}.", o[0], o[1]),
                _ => format!("{}.{}.{}.", o[0], o[1], o[2]),
            }
        }
        IpNet::V6(n) => {
            // The first hextet is stable for /16 and longer; SQLite stores the
            // canonical Rust `Display` form, whose first group has no leading zeros.
            if n.prefix_len() >= 16 {
                let s = n.network().segments();
                format!("{:x}:", s[0])
            } else {
                String::new()
            }
        }
    }
}

const IP_SUMMARY_SELECT: &str =
    "SELECT i.ip, i.country, i.asn, i.asn_org, i.is_tor_exit AS is_tor, i.first_seen, i.last_seen,
            COUNT(r.id) AS request_count, COALESCE(MAX(r.severity), 0) AS max_severity
     FROM ips i LEFT JOIN requests r ON r.ip_id = i.id";

const REQUEST_ROW_SELECT: &str =
    "SELECT r.id, r.ts, r.ip_id, i.ip, r.method, r.path, r.query, r.severity, r.labels_json,
            i.country, i.is_tor_exit AS is_tor
     FROM requests r JOIN ips i ON r.ip_id = i.id";

fn nonempty(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// SQL fragments for an `IpFilter`; `None` when the query box holds garbage.
struct IpFilterSql {
    where_sql: String,
    binds: Vec<String>,
    having: &'static str,
    net: Option<IpNet>,
}

fn ip_filter_sql(f: &IpFilter) -> Option<IpFilterSql> {
    let mut wheres: Vec<String> = vec![];
    let mut binds: Vec<String> = vec![];
    let mut net: Option<IpNet> = None;
    if let Some(q) = nonempty(&f.q) {
        match parse_q(&q) {
            IpQuery::Exact(ip) => {
                wheres.push("i.ip = ?".into());
                binds.push(ip);
            }
            IpQuery::Net(n) => {
                let p = net_like_prefix(&n);
                if !p.is_empty() {
                    wheres.push("i.ip LIKE ?".into());
                    binds.push(format!("{p}%"));
                }
                net = Some(n);
            }
            IpQuery::Prefix(p) => {
                wheres.push("i.ip LIKE ?".into());
                binds.push(format!("{p}%"));
            }
            IpQuery::Invalid => return None,
        }
    }
    if let Some(c) = nonempty(&f.country) {
        wheres.push("i.country = ?".into());
        binds.push(c.to_ascii_uppercase());
    }
    if let Some(a) = f.asn {
        wheres.push("i.asn = ?".into());
        binds.push(a.to_string());
    }
    if f.tor.as_deref() == Some("1") {
        wheres.push("i.is_tor_exit = 1".into());
    }
    if let Some(l) = nonempty(&f.label) {
        wheres.push(
            "EXISTS (SELECT 1 FROM requests rx, json_each(rx.labels_json) je \
             WHERE rx.ip_id = i.id AND je.value = ?)"
                .into(),
        );
        binds.push(l);
    }
    let having = match f.min_severity {
        Some(m) => {
            binds.push(m.to_string());
            " HAVING COALESCE(MAX(r.severity),0) >= CAST(? AS INTEGER)"
        }
        None => "",
    };
    let where_sql = if wheres.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", wheres.join(" AND "))
    };
    Some(IpFilterSql {
        where_sql,
        binds,
        having,
        net,
    })
}

/// `AND …` fragments plus binds for a `RequestFilter`.
fn request_filter_sql(f: &RequestFilter) -> (String, Vec<String>) {
    let mut sql = String::new();
    let mut binds: Vec<String> = vec![];
    if let Some(v) = nonempty(&f.ip) {
        sql.push_str(" AND i.ip = ?");
        binds.push(canonical_ip(&v));
    }
    if let Some(v) = nonempty(&f.path) {
        sql.push_str(" AND (r.path LIKE ? OR r.query LIKE ?)");
        binds.push(format!("%{v}%"));
        binds.push(format!("%{v}%"));
    }
    if let Some(v) = nonempty(&f.label) {
        sql.push_str(" AND EXISTS (SELECT 1 FROM json_each(r.labels_json) je WHERE je.value = ?)");
        binds.push(v);
    }
    if let Some(v) = f.severity {
        sql.push_str(" AND r.severity = ?");
        binds.push(v.to_string());
    }
    if let Some(v) = f.min_severity {
        sql.push_str(" AND r.severity >= ?");
        binds.push(v.to_string());
    }
    if let Some(v) = nonempty(&f.country) {
        sql.push_str(" AND i.country = ?");
        binds.push(v.to_ascii_uppercase());
    }
    if let Some(v) = f.asn {
        sql.push_str(" AND i.asn = ?");
        binds.push(v.to_string());
    }
    if let Some(v) = nonempty(&f.from) {
        sql.push_str(" AND r.ts >= ?");
        binds.push(ts_bound(&v, false));
    }
    if let Some(v) = nonempty(&f.to) {
        sql.push_str(" AND r.ts <= ?");
        binds.push(ts_bound(&v, true));
    }
    (sql, binds)
}

/// IPs are stored in canonical form (`IpAddr::to_string`); match user input
/// like `2001:DB8:0::1` against that. Non-IPs pass through unchanged.
pub fn canonical_ip(v: &str) -> String {
    v.trim()
        .parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| v.trim().to_string())
}

/// A `datetime-local` value (`2026-09-30T12:00`) as a bound on SQLite's
/// `YYYY-MM-DD HH:MM:SS` timestamps. Upper bounds cover their whole last
/// minute (or day, for a bare date), so `to=12:00` includes 12:00:59.
pub fn ts_bound(v: &str, upper: bool) -> String {
    let v = v.trim().replace('T', " ");
    match (upper, v.len()) {
        (true, 10) => format!("{v} 23:59:59"),
        (true, 16) => format!("{v}:59"),
        _ => v,
    }
}

/// Upper bound for one unpaged id lookup (bulk delete works in rounds of this size).
pub const MATCH_LIMIT: i64 = 100_000;

impl Store {
    pub async fn list_ips(&self, f: &IpFilter) -> Result<Page<IpSummary>> {
        let page = page_num(f.page);
        let Some(fs) = ip_filter_sql(f) else {
            return Ok(Page {
                items: vec![],
                page,
                has_next: false,
            });
        };
        let order = if f.sort.as_deref() == Some("recent") {
            "i.last_seen DESC"
        } else {
            "request_count DESC, i.last_seen DESC"
        };
        // CIDR: fetch candidates unpaged (bounded by the LIKE prefix), filter,
        // then page in Rust.
        let (limit, off) = if fs.net.is_some() {
            (MATCH_LIMIT, 0)
        } else {
            (PAGE_SIZE + 1, offset(page))
        };
        let sql = format!(
            "{IP_SUMMARY_SELECT}{} GROUP BY i.id{} ORDER BY {order} LIMIT {limit} OFFSET {off}",
            fs.where_sql, fs.having
        );
        let mut q = sqlx::query_as::<_, IpSummary>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &fs.binds {
            q = q.bind(b);
        }
        let mut rows = q.fetch_all(&self.pool).await?;
        if let Some(net) = fs.net {
            rows.retain(|r| {
                r.ip.parse::<IpAddr>()
                    .map(|ip| net.contains(&ip))
                    .unwrap_or(false)
            });
            rows = rows
                .into_iter()
                .skip(offset(page) as usize)
                .take(PAGE_SIZE as usize + 1)
                .collect();
        }
        Ok(Page::from_rows(rows, page))
    }

    /// Every IP id matching the filter (unpaged; bulk delete + counts).
    pub async fn matching_ip_ids(&self, f: &IpFilter) -> Result<Vec<i64>> {
        let Some(fs) = ip_filter_sql(f) else {
            return Ok(vec![]);
        };
        let sql = format!(
            "SELECT i.id, i.ip FROM ips i LEFT JOIN requests r ON r.ip_id = i.id{} GROUP BY i.id{} LIMIT {MATCH_LIMIT}",
            fs.where_sql, fs.having
        );
        let mut q = sqlx::query_as::<_, (i64, String)>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &fs.binds {
            q = q.bind(b);
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .filter(|(_, ip)| match fs.net {
                Some(net) => ip
                    .parse::<IpAddr>()
                    .map(|a| net.contains(&a))
                    .unwrap_or(false),
                None => true,
            })
            .map(|(id, _)| id)
            .collect())
    }

    /// Number of IPs matching the filter (CIDR filtered in Rust, like `list_ips`).
    pub async fn count_ips(&self, f: &IpFilter) -> Result<i64> {
        let Some(fs) = ip_filter_sql(f) else {
            return Ok(0);
        };
        if fs.net.is_some() {
            return Ok(self.matching_ip_ids(f).await?.len() as i64);
        }
        let sql = format!(
            "SELECT COUNT(*) FROM (SELECT i.id FROM ips i LEFT JOIN requests r ON r.ip_id = i.id{} GROUP BY i.id{})",
            fs.where_sql, fs.having
        );
        let mut q = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &fs.binds {
            q = q.bind(b);
        }
        Ok(q.fetch_one(&self.pool).await?)
    }

    /// Number of requests matching the filter.
    pub async fn count_requests(&self, f: &RequestFilter) -> Result<i64> {
        let (w, binds) = request_filter_sql(f);
        let sql =
            format!("SELECT COUNT(*) FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w}");
        let mut q = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &binds {
            q = q.bind(b);
        }
        Ok(q.fetch_one(&self.pool).await?)
    }

    /// Every request id matching the filter (unpaged; bulk delete + counts).
    pub async fn matching_request_ids(&self, f: &RequestFilter) -> Result<Vec<i64>> {
        let (w, binds) = request_filter_sql(f);
        let sql = format!(
            "SELECT r.id FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w} ORDER BY r.id DESC LIMIT {MATCH_LIMIT}"
        );
        let mut q = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &binds {
            q = q.bind(b);
        }
        Ok(q.fetch_all(&self.pool).await?)
    }

    pub async fn ip_by_addr(&self, addr: &str) -> Result<Option<IpRow>> {
        let Ok(ip) = addr.trim().parse::<IpAddr>() else {
            return Ok(None);
        };
        Ok(sqlx::query_as::<_, IpRow>("SELECT * FROM ips WHERE ip = ?")
            .bind(ip.to_string())
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn ip_overview(&self, ip_id: i64) -> Result<Option<IpOverview>> {
        let Some(ip) = self.ip_by_id(ip_id).await? else {
            return Ok(None);
        };
        let (request_count, max_severity): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(MAX(severity),0) FROM requests WHERE ip_id = ?",
        )
        .bind(ip_id)
        .fetch_one(&self.pool)
        .await?;
        let labels = sqlx::query_as::<_, Named>(
            "SELECT je.value AS name, COUNT(*) AS count FROM requests r, json_each(r.labels_json) je
             WHERE r.ip_id = ? GROUP BY je.value ORDER BY count DESC LIMIT 20",
        )
        .bind(ip_id)
        .fetch_all(&self.pool)
        .await?;
        // Hours ago (0 = current hour) → count.
        let rows: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT CAST((julianday('now') - julianday(ts)) * 24 AS INTEGER) AS h, COUNT(*)
             FROM requests WHERE ip_id = ? AND ts >= datetime('now','-24 hours') GROUP BY h",
        )
        .bind(ip_id)
        .fetch_all(&self.pool)
        .await?;
        let mut sparkline = vec![0i64; 24];
        for (h, c) in rows {
            if (0..24).contains(&h) {
                sparkline[23 - h as usize] += c;
            }
        }
        Ok(Some(IpOverview {
            ip,
            request_count,
            max_severity,
            labels,
            sparkline,
        }))
    }

    pub async fn requests_for_ip(&self, ip_id: i64, page: u32) -> Result<Page<RequestListRow>> {
        let sql = format!(
            "{REQUEST_ROW_SELECT} WHERE r.ip_id = ? ORDER BY r.id DESC LIMIT {} OFFSET {}",
            PAGE_SIZE + 1,
            offset(page)
        );
        let rows = sqlx::query_as::<_, RequestListRow>(sqlx::AssertSqlSafe(sql.as_str()))
            .bind(ip_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(Page::from_rows(rows, page))
    }

    pub async fn search_requests(&self, f: &RequestFilter) -> Result<Page<RequestListRow>> {
        let page = page_num(f.page);
        let (w, binds) = request_filter_sql(f);
        let sql = format!(
            "{REQUEST_ROW_SELECT} WHERE 1=1{w} ORDER BY r.id DESC LIMIT {} OFFSET {}",
            PAGE_SIZE + 1,
            offset(page)
        );
        let mut q = sqlx::query_as::<_, RequestListRow>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &binds {
            q = q.bind(b);
        }
        Ok(Page::from_rows(q.fetch_all(&self.pool).await?, page))
    }
}

#[cfg(test)]
mod ts_tests {
    #[test]
    fn ts_bounds_match_sqlite_format() {
        use super::ts_bound;
        assert_eq!(ts_bound("2026-09-30T12:00", false), "2026-09-30 12:00");
        assert_eq!(ts_bound("2026-09-30T12:00", true), "2026-09-30 12:00:59");
        assert_eq!(ts_bound("2026-09-30", true), "2026-09-30 23:59:59");
        assert_eq!(ts_bound("2026-09-30T12:00:05", true), "2026-09-30 12:00:05");
    }

    #[test]
    fn ip_filter_input_is_canonicalised() {
        use super::canonical_ip;
        assert_eq!(canonical_ip(" 2001:DB8:0::1 "), "2001:db8::1");
        assert_eq!(canonical_ip("203.0.113.1"), "203.0.113.1");
        assert_eq!(canonical_ip("not-an-ip"), "not-an-ip");
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
        let mk = |ip_id, path: &str, sev, labels: &str| NewRequest {
            ip_id,
            method: "GET".into(),
            path: path.into(),
            query: Some("a=1".into()),
            headers_json: "[]".into(),
            body: None,
            labels_json: labels.into(),
            severity: sev,
            scan_level: 1,
            is_fp_claim: false,
            page_token: None,
        };
        let a = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        let b = s.upsert_ip("203.0.113.200".parse().unwrap()).await.unwrap();
        let c = s.upsert_ip("2001:db8::1".parse().unwrap()).await.unwrap();
        s.set_ip_geo(a.id, Some("DE"), Some(3320), Some("DTAG"))
            .await
            .unwrap();
        s.set_ip_geo(b.id, Some("DE"), Some(3320), Some("DTAG"))
            .await
            .unwrap();
        s.set_ip_geo(c.id, Some("US"), Some(15169), Some("Google"))
            .await
            .unwrap();
        s.set_ip_tor(c.id, true).await.unwrap();
        for _ in 0..3 {
            s.insert_request(&mk(a.id, "/.env", 3, r#"["sensitive-path"]"#))
                .await
                .unwrap();
        }
        s.insert_request(&mk(b.id, "/wp-login.php", 2, r#"["wp"]"#))
            .await
            .unwrap();
        s.insert_request(&mk(c.id, "/", 0, "[]")).await.unwrap();
        s
    }

    #[test]
    fn lenient_query_numbers() {
        let f: RequestFilter = serde_urlencoded::from_str("page=abc&asn=&min_severity=2").unwrap();
        assert_eq!(f.page, None);
        assert_eq!(f.asn, None);
        assert_eq!(f.min_severity, Some(2));
    }

    #[test]
    fn page_num_clamps() {
        assert_eq!(page_num(None), 1);
        assert_eq!(page_num(Some(0)), 1);
        assert_eq!(page_num(Some(-5)), 1);
        assert_eq!(page_num(Some(7)), 7);
    }

    #[tokio::test]
    async fn list_ips_filters_and_sorts() {
        let s = seeded().await;
        let all = s.list_ips(&IpFilter::default()).await.unwrap();
        assert_eq!(all.items.len(), 3);
        assert_eq!(all.items[0].ip, "203.0.113.1", "most requests first");
        assert_eq!(all.items[0].request_count, 3);
        assert_eq!(all.items[0].max_severity, 3);
        let q = |q: &str| IpFilter {
            q: Some(q.into()),
            ..Default::default()
        };
        let cidr = s.list_ips(&q("203.0.113.0/25")).await.unwrap();
        assert_eq!(cidr.items.len(), 1);
        assert_eq!(cidr.items[0].ip, "203.0.113.1");
        let v6 = s.list_ips(&q("2001:db8::/32")).await.unwrap();
        assert_eq!(v6.items.len(), 1);
        let prefix = s.list_ips(&q("203.0.113.")).await.unwrap();
        assert_eq!(prefix.items.len(), 2);
        let exact = s.list_ips(&q("203.0.113.200")).await.unwrap();
        assert_eq!(exact.items.len(), 1);
        let tor = s
            .list_ips(&IpFilter {
                tor: Some("1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(tor.items.len(), 1);
        assert!(tor.items[0].is_tor);
        let sev = s
            .list_ips(&IpFilter {
                min_severity: Some(2),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(sev.items.len(), 2);
        let label = s
            .list_ips(&IpFilter {
                label: Some("wp".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(label.items.len(), 1);
        let asn = s
            .list_ips(&IpFilter {
                asn: Some(15169),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(asn.items[0].ip, "2001:db8::1");
        let garbage = s.list_ips(&q("not an ip")).await.unwrap();
        assert!(garbage.items.is_empty());
        assert!(!garbage.has_next);
    }

    #[tokio::test]
    async fn ip_by_addr_and_overview() {
        let s = seeded().await;
        assert!(s.ip_by_addr("hello").await.unwrap().is_none());
        assert!(s.ip_by_addr("203.0.113.77").await.unwrap().is_none());
        let ip = s.ip_by_addr("203.0.113.1").await.unwrap().unwrap();
        let ov = s.ip_overview(ip.id).await.unwrap().unwrap();
        assert_eq!(ov.request_count, 3);
        assert_eq!(ov.max_severity, 3);
        assert_eq!(ov.labels[0].name, "sensitive-path");
        assert_eq!(ov.sparkline.len(), 24);
        assert_eq!(ov.sparkline.iter().sum::<i64>(), 3);
        assert_eq!(
            *ov.sparkline.last().unwrap(),
            3,
            "current hour is the last bucket"
        );
        let v6 = s.ip_by_addr("2001:db8::1").await.unwrap().unwrap();
        assert_eq!(v6.ip, "2001:db8::1");
    }

    #[tokio::test]
    async fn requests_paginate_and_filter() {
        let s = seeded().await;
        let ip = s.ip_by_addr("203.0.113.1").await.unwrap().unwrap();
        let p = s.requests_for_ip(ip.id, 1).await.unwrap();
        assert_eq!(p.items.len(), 3);
        assert!(!p.has_next);
        assert_eq!(p.items[0].labels(), vec!["sensitive-path".to_string()]);
        assert_eq!(p.items[0].query.as_deref(), Some("a=1"));
        let f = RequestFilter {
            path: Some("wp".into()),
            ..Default::default()
        };
        let r = s.search_requests(&f).await.unwrap();
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].ip, "203.0.113.200");
        assert_eq!(r.items[0].country.as_deref(), Some("DE"));
        let f = RequestFilter {
            min_severity: Some(1),
            country: Some("DE".into()),
            ..Default::default()
        };
        assert_eq!(s.search_requests(&f).await.unwrap().items.len(), 4);
        // Pagination: 103 rows → page 1 has 100 and has_next, page 2 has the rest.
        for _ in 0..100 {
            s.insert_request(&NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/bulk".into(),
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
        }
        let p1 = s.requests_for_ip(ip.id, 1).await.unwrap();
        assert_eq!(p1.items.len(), 100);
        assert!(p1.has_next);
        assert_eq!(p1.next(), Some(2));
        assert_eq!(p1.prev(), None);
        let p2 = s.requests_for_ip(ip.id, 2).await.unwrap();
        assert_eq!(p2.items.len(), 3);
        assert!(!p2.has_next);
        assert_eq!(p2.prev(), Some(1));
    }
}
