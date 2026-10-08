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

/// Hard cap on page number. Bounds the SQL OFFSET so an anonymous caller
/// cannot force a scan deep into the table with a huge `page=` value.
pub const MAX_PAGE: u32 = 100_000;

pub fn page_num(p: Option<i64>) -> u32 {
    p.filter(|n| *n >= 1)
        .map(|n| n.min(MAX_PAGE as i64) as u32)
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
    /// Admin only (the public filter drops these): minimum AbuseIPDB score.
    #[serde(default, deserialize_with = "lenient_i64")]
    pub min_abuse: Option<i64>,
    /// Admin only: a provider tag (`shodan:vpn`, `abuseipdb:…`).
    pub tag: Option<String>,
    /// Admin only: has a result from this provider.
    pub intel: Option<String>,
    /// Admin only: has no result from this provider.
    pub nointel: Option<String>,
    /// Admin only: open in any stored scan (`22` or `22/tcp`).
    pub port: Option<String>,
    /// Admin only: product and version on an open port in any stored scan,
    /// as Analytics names it (`OpenSSH 9.6p1`).
    pub product: Option<String>,
    /// Admin only: nmap's OS guess in any stored scan.
    pub os: Option<String>,
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
    /// Newest AbuseIPDB score (admin pages only show it).
    pub abuse_score: Option<i64>,
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
    /// Admin only: the cluster node that recorded the request (its name).
    pub node: Option<String>,
    /// Admin only: the request's JA4H.
    pub ja4h: Option<String>,
    /// Admin only: the request's JA4.
    pub ja4: Option<String>,
    /// Admin only: the HTTP method (any case).
    pub method: Option<String>,
    /// Admin only: the User-Agent, exactly (`(none)`: without one).
    pub ua: Option<String>,
    /// Admin only: `http`, `https`, …; `unknown` for a row without one.
    pub transport: Option<String>,
    /// Admin only: what the trap answered (`not-found`, `decoy:…`);
    /// `unknown` for a row without one; `decoy` for every `decoy:…`.
    pub answer: Option<String>,
    /// Admin only: an MCP session id as served; the request that started
    /// it and every request that carried it.
    pub session: Option<String>,
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
    pub owasp_json: String,
    pub country: Option<String>,
    pub is_tor: bool,
    /// Admin only: the cluster node that recorded it.
    pub node: Option<String>,
    /// Admin only: it was answered with a decoy that carried canaries.
    #[sqlx(default)]
    #[serde(skip)]
    pub canary_served: bool,
    /// Admin only: a canary it presented ([`crate::canary::hash`]), served
    /// to another request …
    #[sqlx(default)]
    #[serde(skip)]
    pub canary_used: Option<i64>,
    /// … namely this one (None: a light row served it).
    #[sqlx(default)]
    #[serde(skip)]
    pub canary_from: Option<i64>,
}

impl RequestListRow {
    pub fn labels(&self) -> Vec<String> {
        serde_json::from_str(&self.labels_json).unwrap_or_default()
    }
    pub fn owasp(&self) -> Vec<String> {
        serde_json::from_str(&self.owasp_json).unwrap_or_default()
    }
}

pub struct IpOverview {
    pub ip: IpRow,
    pub request_count: i64,
    pub max_severity: i64,
    pub labels: Vec<Named>,
    /// Label hits per family (`classify::FAMILIES` order, non-zero only),
    /// summed from the per-IP label counts.
    pub families: Vec<Named>,
    /// Hourly buckets of the last 7 days that have requests, oldest first,
    /// each split by severity.
    pub week: Vec<super::stats::Bucket>,
    /// Days of the last [`CALENDAR_DAYS`] with requests, oldest first.
    pub calendar: Vec<CalendarDay>,
    /// 1 = most requests of every IP, all time; `ranked` IPs have requests.
    pub rank: i64,
    pub ranked: i64,
    /// The surrounding network (/24 for IPv4, /48 for IPv6), how many other
    /// IPs of it have requests, and the busiest of them.
    pub net: String,
    pub net_count: i64,
    pub neighbours: Vec<Neighbour>,
    /// Other IPs of the same ASN with requests.
    pub asn_count: i64,
}

/// How far back the per-IP activity calendar reaches (26 weeks).
pub const CALENDAR_DAYS: i64 = 182;

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct CalendarDay {
    pub day: String,
    pub count: i64,
    pub max_severity: i64,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct Neighbour {
    pub ip: String,
    pub request_count: i64,
    pub max_severity: i64,
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

/// Escape SQL LIKE metacharacters so user text matches literally under
/// `LIKE ? ESCAPE '\'`. Escapes the backslash itself first.
pub(crate) fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// `IpSummary` columns as `a` sees them.
fn ip_summary_select(a: Audience) -> String {
    let p = a.rm();
    format!(
        "SELECT i.ip, i.country, i.asn, i.asn_org, i.is_tor_exit AS is_tor,
                i.{p}first_seen AS first_seen, i.{p}last_seen AS last_seen,
                i.{p}request_count AS request_count, i.{p}max_severity AS max_severity,
                i.abuse_score
         FROM ips i"
    )
}

/// Who a request listing is for. A mistyped legitimate API call lands in
/// the trap with its credentials in the query string, so query strings are
/// admin-only: public views never show them and public search never
/// matches them (it would otherwise reveal a hidden value by probing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    Public,
    Admin,
}

impl Audience {
    pub fn of(authed: bool) -> Self {
        if authed { Self::Admin } else { Self::Public }
    }
    /// The query column this audience may see.
    fn query_col(self) -> &'static str {
        match self {
            Self::Admin => "r.query",
            Self::Public => "NULL",
        }
    }
    /// Which node recorded a request: admin only (node names would map
    /// out the sensor network).
    fn node_col(self) -> &'static str {
        match self {
            Self::Admin => "(SELECT name FROM members m WHERE m.id = r.origin)",
            Self::Public => "NULL",
        }
    }
    /// The canary marks of a request row: admin only.
    fn canary_cols(self) -> String {
        match self {
            Self::Admin => format!(
                ", EXISTS (SELECT 1 FROM canaries c WHERE c.request_id = r.id) AS canary_served,
                 ({}) AS canary_used, ({}) AS canary_from",
                CANARY_USED.replace("{}", "t.value_hash"),
                CANARY_USED.replace("{}", "c.request_id")
            ),
            Self::Public => String::new(),
        }
    }
    /// `AND`-fragment keeping only the requests this audience may count
    /// (`alias` names a `requests` table): the public sees released rows.
    /// Phrased as a subquery on the partial index `idx_requests_pending`
    /// rather than `public_at IS NULL`, which would force a row lookup and
    /// cost the `idx_requests_ts` covering scan of count queries.
    pub(crate) fn released(self, alias: &str) -> String {
        match self {
            Self::Admin => String::new(),
            Self::Public => format!(
                " AND {alias}.id NOT IN (SELECT id FROM requests WHERE public_at IS NOT NULL)"
            ),
        }
    }
    /// Prefix of the per-IP read models (`request_count`, `max_severity`,
    /// `first_seen`, `last_seen`) this audience reads: `pub_` for the public.
    pub(crate) fn rm(self) -> &'static str {
        match self {
            Self::Admin => "",
            Self::Public => "pub_",
        }
    }
    /// The `ip_labels` column holding this audience's count.
    pub(crate) fn label_count(self) -> &'static str {
        match self {
            Self::Admin => "count",
            Self::Public => "pub_count",
        }
    }
    /// `AND`-fragment for the scans this audience may count (`alias` names
    /// the scans table): the public sees scans finished at least the
    /// publication delay ago, of IPs it can see.
    pub(crate) fn scans(self, alias: &str) -> String {
        match self {
            Self::Admin => String::new(),
            Self::Public => format!(
                " AND {alias}.finished_at <= datetime('now', '-' || \
                 (SELECT delay_s FROM publish_cfg WHERE id = 1) || ' seconds') \
                 AND EXISTS (SELECT 1 FROM ips pi WHERE pi.id = {alias}.ip_id \
                 AND pi.pub_request_count > 0)"
            ),
        }
    }
}

fn request_row_select(a: Audience) -> String {
    format!(
        "SELECT r.id, r.ts, r.ip_id, i.ip, r.method, r.path, {} AS query,
                r.severity, r.labels_json, r.owasp_json, i.country, i.is_tor_exit AS is_tor, {} AS node{}
         FROM requests r JOIN ips i ON r.ip_id = i.id",
        a.query_col(),
        a.node_col(),
        a.canary_cols()
    )
}

/// The first canary a request presented that another request (or a light
/// row) was served: (value hash, serving request) as in
/// `canaries::REUSE_SELECT`. A full row that served it ranks first.
const CANARY_USED: &str =
    "SELECT {} FROM request_tokens t JOIN canaries c ON c.value_hash = t.value_hash
     WHERE t.request_id = r.id AND (c.request_id IS NULL OR c.request_id != r.id)
     ORDER BY c.request_id IS NULL, c.ts LIMIT 1";

pub(crate) fn nonempty(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// SQL fragments for an `IpFilter`; `None` when the query box holds garbage.
/// Everything is answered from the `ips` row and its read models
/// (`request_count`, `max_severity`, `ip_key`, `ip_labels`; for the public
/// the released-only variants `pub_*` and `ip_labels.pub_count`), never by
/// aggregating requests.
struct IpFilterSql {
    where_sql: String,
    binds: Vec<String>,
}

fn ip_filter_sql(f: &IpFilter, a: Audience) -> Option<IpFilterSql> {
    let mut wheres: Vec<String> = vec![];
    let mut binds: Vec<String> = vec![];
    if a == Audience::Public {
        wheres.push("i.pub_request_count > 0".into());
    }
    if let Some(q) = nonempty(&f.q) {
        match parse_q(&q) {
            IpQuery::Exact(ip) => {
                wheres.push("i.ip = ?".into());
                binds.push(ip);
            }
            IpQuery::Net(n) => {
                let (lo, hi) = super::net_key_range(&n);
                wheres.push("i.ip_key BETWEEN ? AND ?".into());
                binds.push(lo);
                binds.push(hi);
                // IPv4 keys live in ::ffff:0:0/96; an IPv6 network that
                // covers that range still means IPv6 addresses only.
                if n.addr().is_ipv6() {
                    wheres.push("instr(i.ip, ':') > 0".into());
                }
            }
            IpQuery::Prefix(p) => {
                wheres.push("i.ip LIKE ? ESCAPE '\\'".into());
                binds.push(format!("{}%", like_escape(&p)));
            }
            IpQuery::Invalid => return None,
        }
    }
    if let Some(c) = nonempty(&f.country) {
        wheres.push("i.country = ?".into());
        binds.push(c.to_ascii_uppercase());
    }
    if let Some(asn) = f.asn {
        wheres.push("i.asn = ?".into());
        binds.push(asn.to_string());
    }
    if f.tor.as_deref() == Some("1") {
        wheres.push("i.is_tor_exit = 1".into());
    }
    if let Some(l) = nonempty(&f.label) {
        wheres.push(format!(
            "i.id IN (SELECT l.ip_id FROM ip_labels l WHERE l.label = ? AND l.{} > 0)",
            a.label_count()
        ));
        binds.push(l);
    }
    if let Some(m) = f.min_severity {
        wheres.push(format!("i.{}max_severity >= CAST(? AS INTEGER)", a.rm()));
        binds.push(m.to_string());
    }
    if let Some(m) = f.min_abuse {
        wheres.push("i.abuse_score >= CAST(? AS INTEGER)".into());
        binds.push(m.to_string());
    }
    if let Some(t) = nonempty(&f.tag) {
        wheres.push("i.ip IN (SELECT t.ip FROM ip_intel_tags t WHERE t.tag = ?)".into());
        binds.push(t);
    }
    if let Some(p) = nonempty(&f.intel) {
        wheres
            .push("EXISTS (SELECT 1 FROM ip_intel x WHERE x.provider = ? AND x.ip = i.ip)".into());
        binds.push(p);
    }
    if let Some(p) = nonempty(&f.nointel) {
        wheres.push(
            "NOT EXISTS (SELECT 1 FROM ip_intel x WHERE x.provider = ? AND x.ip = i.ip)".into(),
        );
        binds.push(p);
    }
    if a == Audience::Admin {
        if let Some(p) = nonempty(&f.port) {
            let (port, proto) = p.split_once('/').unwrap_or((&p, ""));
            let Ok(port) = port.trim().parse::<u16>() else {
                return None;
            };
            let mut sql = "EXISTS (SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                 WHERE s.ip_id = i.id AND p.state = 'open' AND p.port = ?"
                .to_string();
            binds.push(port.to_string());
            if !proto.trim().is_empty() {
                sql.push_str(" AND p.proto = ?");
                binds.push(proto.trim().to_ascii_lowercase());
            }
            wheres.push(sql + ")");
        }
        if let Some(v) = nonempty(&f.product) {
            wheres.push(
                "EXISTS (SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                 WHERE s.ip_id = i.id AND p.state = 'open'
                   AND p.product || COALESCE(' ' || p.version, '') = ?)"
                    .into(),
            );
            binds.push(v);
        }
        if let Some(v) = nonempty(&f.os) {
            wheres.push(
                "EXISTS (SELECT 1 FROM scans s WHERE s.ip_id = i.id AND s.os_guess = ?)".into(),
            );
            binds.push(v);
        }
    }
    let where_sql = if wheres.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", wheres.join(" AND "))
    };
    Some(IpFilterSql { where_sql, binds })
}

/// FTS5 query for a substring of the given columns (trigram tokenizer: a
/// quoted phrase matches wherever its text occurs).
fn fts_substring(cols: &str, v: &str) -> String {
    format!("{cols} : \"{}\"", v.replace('"', "\"\""))
}

/// `AND …` fragments plus binds for a `RequestFilter`. `indexed`: the
/// trigram index over path and query exists.
fn request_filter_sql(f: &RequestFilter, a: Audience, indexed: bool) -> (String, Vec<String>) {
    let mut sql = String::new();
    let mut binds: Vec<String> = vec![];
    if let Some(v) = nonempty(&f.ip) {
        sql.push_str(" AND i.ip = ?");
        binds.push(canonical_ip(&v));
    }
    if let Some(v) = nonempty(&f.path) {
        // The index narrows the candidates (trigrams need three or more
        // characters); the LIKE below keeps the exact semantics.
        if indexed && v.chars().count() >= 3 {
            let cols = match a {
                Audience::Admin => "{path query}",
                Audience::Public => "path",
            };
            sql.push_str(
                " AND r.id IN (SELECT rowid FROM requests_fts WHERE requests_fts MATCH ?)",
            );
            binds.push(fts_substring(cols, &v));
        }
        // Escape LIKE wildcards so a path containing % or _ (both common in
        // scanner traffic, e.g. _vti_bin) matches literally — otherwise the
        // listing, its count, and "delete all matching" cover a broader set.
        let pat = format!("%{}%", like_escape(&v));
        if a == Audience::Admin {
            sql.push_str(" AND (r.path LIKE ? ESCAPE '\\' OR r.query LIKE ? ESCAPE '\\')");
            binds.push(pat.clone());
        } else {
            sql.push_str(" AND r.path LIKE ? ESCAPE '\\'");
        }
        binds.push(pat);
    }
    if let Some(v) = nonempty(&f.label) {
        sql.push_str(" AND EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(r.labels_json) THEN r.labels_json ELSE '[]' END) je WHERE je.value = ?)");
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
    if a == Audience::Admin
        && let Some(v) = nonempty(&f.node)
    {
        sql.push_str(" AND r.origin IN (SELECT id FROM members WHERE name = ?)");
        binds.push(v);
    }
    if a == Audience::Admin
        && let Some(v) = nonempty(&f.ja4h)
    {
        sql.push_str(" AND r.ja4h = ?");
        binds.push(v);
    }
    if a == Audience::Admin
        && let Some(v) = nonempty(&f.ja4)
    {
        sql.push_str(" AND r.ja4 = ?");
        binds.push(v);
    }
    if a == Audience::Admin {
        if let Some(v) = nonempty(&f.method) {
            sql.push_str(" AND r.method = ?");
            binds.push(v.to_ascii_uppercase());
        }
        if let Some(v) = nonempty(&f.ua) {
            sql.push_str(" AND r.user_agent = ?");
            binds.push(v);
        }
        if let Some(v) = nonempty(&f.session) {
            sql.push_str(
                " AND r.id IN (SELECT c.request_id FROM canaries c WHERE c.kind = 'mcp-session' AND c.value_hash = ?
                              UNION SELECT t.request_id FROM request_tokens t WHERE t.value_hash = ?)",
            );
            let h = crate::canary::hash(v.trim()).to_string();
            binds.push(h.clone());
            binds.push(h);
        }
        // Analytics shows a missing value as `unknown`. An answer also takes
        // its variants: `decoy` finds `decoy:dotenv`, `decoy:mcp` finds
        // `decoy:mcp:ping`.
        for (col, v) in [("transport", &f.transport), ("answer", &f.answer)] {
            match nonempty(v).as_deref() {
                Some("unknown") => sql.push_str(&format!(" AND r.{col} IS NULL")),
                Some(v) if col == "answer" => {
                    sql.push_str(" AND (r.answer = ? OR r.answer LIKE ? ESCAPE '\\')");
                    binds.push(v.to_string());
                    binds.push(format!("{}:%", like_escape(v)));
                }
                Some(v) => {
                    sql.push_str(&format!(" AND r.{col} = ?"));
                    binds.push(v.to_string());
                }
                None => {}
            }
        }
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

/// Counts stop here: past it the admin sees "N+" (counting every match of a
/// broad filter would walk the whole table on each page view).
pub const COUNT_CAP: i64 = 10_000;

/// A row count, possibly capped at [`COUNT_CAP`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Count {
    pub n: i64,
    /// More rows match than `n`.
    pub capped: bool,
}

impl std::fmt::Display for Count {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.capped {
            write!(f, "{}+", self.n)
        } else {
            write!(f, "{}", self.n)
        }
    }
}

impl Count {
    fn of(n: i64) -> Self {
        Self {
            n: n.min(COUNT_CAP),
            capped: n > COUNT_CAP,
        }
    }
}

impl Store {
    /// Stored IPs among `addrs` or inside `nets`, by address, at most
    /// `limit` (admin bulk lookup).
    pub async fn ips_matching(
        &self,
        addrs: &[IpAddr],
        nets: &[IpNet],
        limit: i64,
    ) -> Result<Vec<IpSummary>> {
        let mut ors = vec![];
        let mut binds = vec![];
        for a in addrs {
            ors.push("i.ip = ?".to_string());
            binds.push(a.to_string());
        }
        for n in nets {
            let (lo, hi) = super::net_key_range(n);
            ors.push(if n.addr().is_ipv6() {
                "(i.ip_key BETWEEN ? AND ? AND instr(i.ip, ':') > 0)".to_string()
            } else {
                "i.ip_key BETWEEN ? AND ?".to_string()
            });
            binds.push(lo);
            binds.push(hi);
        }
        if ors.is_empty() {
            return Ok(vec![]);
        }
        let sql = format!(
            "{} WHERE {} ORDER BY i.ip_key LIMIT {limit}",
            ip_summary_select(Audience::Admin),
            ors.join(" OR ")
        );
        let mut q = sqlx::query_as::<_, IpSummary>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &binds {
            q = q.bind(b);
        }
        Ok(q.fetch_all(&self.read).await?)
    }

    pub async fn list_ips(&self, f: &IpFilter) -> Result<Page<IpSummary>> {
        self.list_ips_as(f, Audience::Admin).await
    }

    pub async fn list_ips_as(&self, f: &IpFilter, a: Audience) -> Result<Page<IpSummary>> {
        let page = page_num(f.page);
        let Some(fs) = ip_filter_sql(f, a) else {
            return Ok(Page {
                items: vec![],
                page,
                has_next: false,
            });
        };
        let p = a.rm();
        let order = match f.sort.as_deref() {
            Some("recent") => format!("i.{p}last_seen DESC"),
            Some("abuse") => {
                format!("i.abuse_score IS NULL, i.abuse_score DESC, i.{p}last_seen DESC")
            }
            _ => format!("i.{p}request_count DESC, i.{p}last_seen DESC"),
        };
        let sql = format!(
            "{}{} ORDER BY {order} LIMIT {} OFFSET {}",
            ip_summary_select(a),
            fs.where_sql,
            PAGE_SIZE + 1,
            offset(page)
        );
        let mut q = sqlx::query_as::<_, IpSummary>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &fs.binds {
            q = q.bind(b);
        }
        Ok(Page::from_rows(q.fetch_all(&self.read).await?, page))
    }

    /// Up to [`MATCH_LIMIT`] ids of IPs matching the filter, in id order,
    /// above `after` (keyset paging, so bulk delete covers every match).
    pub async fn matching_ip_ids_after(&self, f: &IpFilter, after: i64) -> Result<Vec<i64>> {
        let Some(fs) = ip_filter_sql(f, Audience::Admin) else {
            return Ok(vec![]);
        };
        let glue = if fs.where_sql.is_empty() {
            " WHERE"
        } else {
            " AND"
        };
        let sql = format!(
            "SELECT i.id FROM ips i{}{glue} i.id > ? ORDER BY i.id LIMIT {MATCH_LIMIT}",
            fs.where_sql
        );
        let mut q = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &fs.binds {
            q = q.bind(b);
        }
        Ok(q.bind(after).fetch_all(&self.read).await?)
    }

    /// The first [`MATCH_LIMIT`] ids of IPs matching the filter.
    pub async fn matching_ip_ids(&self, f: &IpFilter) -> Result<Vec<i64>> {
        self.matching_ip_ids_after(f, 0).await
    }

    /// Number of IPs matching the filter.
    pub async fn count_ips(&self, f: &IpFilter) -> Result<i64> {
        let Some(fs) = ip_filter_sql(f, Audience::Admin) else {
            return Ok(0);
        };
        let sql = format!("SELECT COUNT(*) FROM ips i{}", fs.where_sql);
        let mut q = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &fs.binds {
            q = q.bind(b);
        }
        Ok(q.fetch_one(&self.read).await?)
    }

    /// Number of requests matching the filter, counted up to [`COUNT_CAP`].
    pub async fn count_requests(&self, f: &RequestFilter) -> Result<Count> {
        let (w, binds) = request_filter_sql(f, Audience::Admin, self.search_indexed());
        let sql = format!(
            "SELECT COUNT(*) FROM (SELECT 1 FROM requests r JOIN ips i ON r.ip_id = i.id
             WHERE 1=1{w} LIMIT {})",
            COUNT_CAP + 1
        );
        let mut q = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &binds {
            q = q.bind(b);
        }
        Ok(Count::of(q.fetch_one(&self.read).await?))
    }

    /// Up to [`MATCH_LIMIT`] ids of requests matching the filter, newest
    /// first, below `before` (keyset paging for bulk delete).
    pub async fn matching_request_ids_before(
        &self,
        f: &RequestFilter,
        before: i64,
    ) -> Result<Vec<i64>> {
        let (w, binds) = request_filter_sql(f, Audience::Admin, self.search_indexed());
        let sql = format!(
            "SELECT r.id FROM requests r JOIN ips i ON r.ip_id = i.id WHERE r.id < ?{w}
             ORDER BY r.id DESC LIMIT {MATCH_LIMIT}"
        );
        let mut q = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.as_str())).bind(before);
        for b in &binds {
            q = q.bind(b);
        }
        Ok(q.fetch_all(&self.read).await?)
    }

    /// The newest [`MATCH_LIMIT`] ids of requests matching the filter.
    pub async fn matching_request_ids(&self, f: &RequestFilter) -> Result<Vec<i64>> {
        self.matching_request_ids_before(f, i64::MAX).await
    }

    pub async fn ip_by_addr(&self, addr: &str) -> Result<Option<IpRow>> {
        let Ok(ip) = addr.trim().parse::<IpAddr>() else {
            return Ok(None);
        };
        Ok(sqlx::query_as::<_, IpRow>("SELECT * FROM ips WHERE ip = ?")
            .bind(ip.to_string())
            .fetch_optional(&self.read)
            .await?)
    }

    /// The IP's public aggregates, from its read models. Only the week and
    /// the calendar read requests, through the (ip_id, ts) index.
    pub async fn ip_overview(&self, ip_id: i64) -> Result<Option<IpOverview>> {
        self.ip_overview_as(ip_id, Audience::Admin).await
    }

    /// [`Store::ip_overview`] as `a` sees it; `None` for the public when
    /// none of the IP's requests is released.
    pub async fn ip_overview_as(&self, ip_id: i64, a: Audience) -> Result<Option<IpOverview>> {
        let (p, lc, rel) = (a.rm(), a.label_count(), a.released("requests"));
        let row_sql = match a {
            Audience::Admin => "SELECT * FROM ips WHERE id = ?",
            Audience::Public => {
                "SELECT id, ip, pub_first_seen AS first_seen, pub_last_seen AS last_seen,
                        country, asn, asn_org, is_tor_exit, fp_claimed, notes,
                        pub_request_count AS request_count, pub_max_severity AS max_severity
                 FROM ips WHERE id = ? AND pub_request_count > 0"
            }
        };
        let Some(ip) = sqlx::query_as::<_, IpRow>(row_sql)
            .bind(ip_id)
            .fetch_optional(&self.read)
            .await?
        else {
            return Ok(None);
        };
        let labels = sqlx::query_as::<_, Named>(sqlx::AssertSqlSafe(format!(
            "SELECT label AS name, {lc} AS count FROM ip_labels WHERE ip_id = ? AND {lc} > 0
             ORDER BY count DESC, label LIMIT 20"
        )))
        .bind(ip_id)
        .fetch_all(&self.read)
        .await?;
        let mut fam: std::collections::HashMap<&'static str, i64> = Default::default();
        for (label, n) in sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(format!(
            "SELECT label, {lc} FROM ip_labels WHERE ip_id = ? AND {lc} > 0"
        )))
        .bind(ip_id)
        .fetch_all(&self.read)
        .await?
        {
            *fam.entry(crate::classify::label_family(&label))
                .or_default() += n;
        }
        let families = crate::classify::FAMILIES
            .iter()
            .filter_map(|f| {
                fam.get(f).map(|&count| Named {
                    name: (*f).to_string(),
                    count,
                })
            })
            .collect();
        let rows: Vec<(String, i64, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT strftime('%Y-%m-%dT%H:00', ts) AS h, severity, COUNT(*)
             FROM requests WHERE ip_id = ? AND ts >= datetime('now','-7 days'){rel}
             GROUP BY h, severity ORDER BY h"
        )))
        .bind(ip_id)
        .fetch_all(&self.read)
        .await?;
        let mut week: Vec<super::stats::Bucket> = Vec::new();
        for (h, sev, n) in rows {
            if week.last().map(|b| b.ts != h).unwrap_or(true) {
                week.push(super::stats::Bucket {
                    ts: h,
                    count: 0,
                    by_severity: [0; 5],
                });
            }
            let b = week.last_mut().expect("pushed above");
            b.count += n;
            b.by_severity[sev.clamp(0, 4) as usize] += n;
        }
        let calendar = sqlx::query_as::<_, CalendarDay>(sqlx::AssertSqlSafe(format!(
            "SELECT date(ts) AS day, COUNT(*) AS count, MAX(severity) AS max_severity
             FROM requests WHERE ip_id = ? AND ts >= date('now', ?){rel}
             GROUP BY day ORDER BY day"
        )))
        .bind(ip_id)
        .bind(format!("-{} days", CALENDAR_DAYS - 1))
        .fetch_all(&self.read)
        .await?;
        let (rank, ranked): (i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT (SELECT COUNT(*) + 1 FROM ips WHERE {p}request_count > ?1),
                    (SELECT COUNT(*) FROM ips WHERE {p}request_count > 0)"
        )))
        .bind(ip.request_count)
        .fetch_one(&self.read)
        .await?;
        let (net, net_count, neighbours) = match ip.ip.parse::<IpAddr>() {
            Ok(addr) => {
                let n = IpNet::new(addr, if addr.is_ipv4() { 24 } else { 48 })
                    .map(|n| n.trunc())
                    .expect("valid prefix length");
                let (lo, hi) = super::net_key_range(&n);
                let v6 = if addr.is_ipv6() {
                    " AND instr(ip, ':') > 0"
                } else {
                    ""
                };
                let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                    "SELECT COUNT(*) FROM ips WHERE ip_key BETWEEN ? AND ? AND id != ?
                     AND {p}request_count > 0{v6}"
                )))
                .bind(&lo)
                .bind(&hi)
                .bind(ip_id)
                .fetch_one(&self.read)
                .await?;
                let top = sqlx::query_as::<_, Neighbour>(sqlx::AssertSqlSafe(format!(
                    "SELECT ip, {p}request_count AS request_count, {p}max_severity AS max_severity
                     FROM ips
                     WHERE ip_key BETWEEN ? AND ? AND id != ? AND {p}request_count > 0{v6}
                     ORDER BY {p}request_count DESC, ip LIMIT 8"
                )))
                .bind(&lo)
                .bind(&hi)
                .bind(ip_id)
                .fetch_all(&self.read)
                .await?;
                (n.to_string(), count, top)
            }
            Err(_) => (String::new(), 0, vec![]),
        };
        let asn_count: i64 =
            match ip.asn {
                Some(a) => sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                    "SELECT COUNT(*) FROM ips WHERE asn = ? AND id != ? AND {p}request_count > 0"
                )))
                .bind(a)
                .bind(ip_id)
                .fetch_one(&self.read)
                .await?,
                None => 0,
            };
        Ok(Some(IpOverview {
            request_count: ip.request_count,
            max_severity: ip.max_severity,
            ip,
            labels,
            families,
            week,
            calendar,
            rank,
            ranked,
            net,
            net_count,
            neighbours,
            asn_count,
        }))
    }

    pub async fn requests_for_ip(
        &self,
        ip_id: i64,
        page: u32,
        a: Audience,
    ) -> Result<Page<RequestListRow>> {
        let sql = format!(
            "{} WHERE r.ip_id = ? ORDER BY r.id DESC LIMIT {} OFFSET {}",
            request_row_select(a),
            PAGE_SIZE + 1,
            offset(page)
        );
        let rows = sqlx::query_as::<_, RequestListRow>(sqlx::AssertSqlSafe(sql.as_str()))
            .bind(ip_id)
            .fetch_all(&self.read)
            .await?;
        Ok(Page::from_rows(rows, page))
    }

    pub async fn search_requests(
        &self,
        f: &RequestFilter,
        a: Audience,
    ) -> Result<Page<RequestListRow>> {
        let page = page_num(f.page);
        let (w, binds) = request_filter_sql(f, a, self.search_indexed());
        let sql = format!(
            "{} WHERE 1=1{w} ORDER BY r.id DESC LIMIT {} OFFSET {}",
            request_row_select(a),
            PAGE_SIZE + 1,
            offset(page)
        );
        let mut q = sqlx::query_as::<_, RequestListRow>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &binds {
            q = q.bind(b);
        }
        Ok(Page::from_rows(q.fetch_all(&self.read).await?, page))
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

    /// A released hit from `known`, then (delay on) a pending hit from
    /// `known` and one from `fresh`.
    async fn delayed() -> (Store, tempfile::TempDir, i64, i64) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let req = |ip_id, path: &str, sev, labels: &str| NewRequest {
            ip_id,
            method: "GET".into(),
            path: path.into(),
            headers_json: "[]".into(),
            labels_json: labels.into(),
            severity: sev,
            ..Default::default()
        };
        let known = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        s.insert_request(&req(known.id, "/old", 1, r#"["wp"]"#))
            .await
            .unwrap();
        s.set_publish_delay(
            std::time::Duration::from_secs(300),
            std::time::Duration::ZERO,
        )
        .await
        .unwrap();
        s.insert_request(&req(known.id, "/new", 4, r#"["sqli"]"#))
            .await
            .unwrap();
        let fresh = s.upsert_ip("203.0.113.2".parse().unwrap()).await.unwrap();
        s.insert_request(&req(fresh.id, "/fresh", 4, r#"["sqli"]"#))
            .await
            .unwrap();
        (s, dir, known.id, fresh.id)
    }

    #[tokio::test]
    async fn public_directory_lists_released_ips_with_public_counts() {
        let (s, _d, _, _) = delayed().await;
        let p = s
            .list_ips_as(&IpFilter::default(), Audience::Public)
            .await
            .unwrap();
        assert_eq!(p.items.len(), 1);
        assert_eq!(p.items[0].ip, "203.0.113.1");
        assert_eq!((p.items[0].request_count, p.items[0].max_severity), (1, 1));
        let by_label = |l: &str| IpFilter {
            label: Some(l.into()),
            ..Default::default()
        };
        assert!(
            s.list_ips_as(&by_label("sqli"), Audience::Public)
                .await
                .unwrap()
                .items
                .is_empty()
        );
        let sev4 = IpFilter {
            min_severity: Some(4),
            ..Default::default()
        };
        assert!(
            s.list_ips_as(&sev4, Audience::Public)
                .await
                .unwrap()
                .items
                .is_empty()
        );
        let exact = IpFilter {
            q: Some("203.0.113.2".into()),
            ..Default::default()
        };
        assert!(
            s.list_ips_as(&exact, Audience::Public)
                .await
                .unwrap()
                .items
                .is_empty()
        );
    }

    #[tokio::test]
    async fn admin_sees_pending_rows() {
        let (s, _d, known, fresh) = delayed().await;
        assert_eq!(
            s.list_ips(&IpFilter::default()).await.unwrap().items.len(),
            2
        );
        let ov = s.ip_overview(known).await.unwrap().unwrap();
        assert_eq!((ov.request_count, ov.max_severity), (2, 4));
        assert!(s.ip_overview(fresh).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn known_ip_overview_ignores_pending_rows() {
        let (s, _d, known, fresh) = delayed().await;
        assert!(
            s.ip_overview_as(fresh, Audience::Public)
                .await
                .unwrap()
                .is_none()
        );
        let ov = s
            .ip_overview_as(known, Audience::Public)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((ov.request_count, ov.max_severity), (1, 1));
        assert_eq!(
            ov.labels
                .iter()
                .map(|l| l.name.as_str())
                .collect::<Vec<_>>(),
            ["wp"]
        );
        assert_eq!(ov.week.iter().map(|b| b.count).sum::<i64>(), 1);
        assert_eq!(ov.calendar.iter().map(|d| d.count).sum::<i64>(), 1);
        assert_eq!(ov.net_count, 0, "the pending-only neighbour is not public");
        assert_eq!(ov.ranked, 1);
    }

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
            ..Default::default()
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
    async fn list_rows_expose_owasp_tags() {
        let s = seeded().await;
        let ip = s.upsert_ip("198.51.100.30".parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: "/login".into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: r#"["sqli"]"#.into(),
            owasp_json: Some(r#"["A03:2021"]"#.into()),
            severity: 4,
            scan_level: 4,
            is_fp_claim: false,
            page_token: None,
            ..Default::default()
        })
        .await
        .unwrap();
        let page = s
            .search_requests(&RequestFilter::default(), Audience::Admin)
            .await
            .unwrap();
        assert_eq!(page.items[0].owasp(), vec!["A03:2021".to_string()]);
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
        assert_eq!(ov.week.iter().map(|b| b.count).sum::<i64>(), 3);
        assert_eq!(ov.calendar.len(), 1);
        assert_eq!(ov.calendar[0].count, 3);
        assert_eq!(ov.rank, 1);
        assert_eq!(ov.net, "203.0.113.0/24");
        assert_eq!((ov.net_count, ov.asn_count), (1, 1));
        assert_eq!(ov.neighbours[0].ip, "203.0.113.200");
        assert_eq!(ov.families[0].name, "exposure");
        let c = s.ip_by_addr("2001:db8::1").await.unwrap().unwrap();
        let ov6 = s.ip_overview(c.id).await.unwrap().unwrap();
        assert_eq!(ov6.net, "2001:db8::/48");
        assert_eq!((ov6.net_count, ov6.rank, ov6.ranked), (0, 2, 3));
        let v6 = s.ip_by_addr("2001:db8::1").await.unwrap().unwrap();
        assert_eq!(v6.ip, "2001:db8::1");
    }

    #[tokio::test]
    async fn requests_paginate_and_filter() {
        let s = seeded().await;
        let ip = s.ip_by_addr("203.0.113.1").await.unwrap().unwrap();
        let p = s.requests_for_ip(ip.id, 1, Audience::Admin).await.unwrap();
        assert_eq!(p.items.len(), 3);
        assert!(!p.has_next);
        assert_eq!(p.items[0].labels(), vec!["sensitive-path".to_string()]);
        assert_eq!(p.items[0].query.as_deref(), Some("a=1"));
        let f = RequestFilter {
            path: Some("wp".into()),
            ..Default::default()
        };
        let r = s.search_requests(&f, Audience::Admin).await.unwrap();
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].ip, "203.0.113.200");
        assert_eq!(r.items[0].country.as_deref(), Some("DE"));
        let f = RequestFilter {
            min_severity: Some(1),
            country: Some("DE".into()),
            ..Default::default()
        };
        assert_eq!(
            s.search_requests(&f, Audience::Admin)
                .await
                .unwrap()
                .items
                .len(),
            4
        );
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
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let p1 = s.requests_for_ip(ip.id, 1, Audience::Admin).await.unwrap();
        assert_eq!(p1.items.len(), 100);
        assert!(p1.has_next);
        assert_eq!(p1.next(), Some(2));
        assert_eq!(p1.prev(), None);
        let p2 = s.requests_for_ip(ip.id, 2, Audience::Admin).await.unwrap();
        assert_eq!(p2.items.len(), 3);
        assert!(!p2.has_next);
        assert_eq!(p2.prev(), Some(1));
    }

    /// Insert `n` requests for `ip_id` in one statement (triggers run).
    async fn bulk_requests(s: &Store, ip_id: i64, n: i64, path: &str, sev: i64, labels: &str) {
        sqlx::query(
            "WITH RECURSIVE k(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM k WHERE x < ?)
             INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, labels_json, severity)
             SELECT lower(hex(randomblob(16))), datetime('now'), ?, 'GET', ?, '[]', ?, ? FROM k",
        )
        .bind(n)
        .bind(ip_id)
        .bind(path)
        .bind(labels)
        .bind(sev)
        .execute(&s.pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cidr_searches_run_in_sql_and_are_complete() {
        let s = seeded().await;
        // 250 addresses in one /24: more than a page, all must be found.
        for i in 0..250u32 {
            s.upsert_ip(format!("198.51.100.{i}").parse().unwrap())
                .await
                .unwrap();
        }
        s.upsert_ip("198.51.101.1".parse().unwrap()).await.unwrap();
        let f = IpFilter {
            q: Some("198.51.100.0/24".into()),
            ..Default::default()
        };
        assert_eq!(s.count_ips(&f).await.unwrap(), 250);
        let p1 = s.list_ips(&f).await.unwrap();
        assert_eq!(p1.items.len(), 100);
        assert!(p1.has_next);
        let p3 = s
            .list_ips(&IpFilter {
                page: Some(3),
                ..f.clone()
            })
            .await
            .unwrap();
        assert_eq!(p3.items.len(), 50);
        assert!(!p3.has_next);
        // Keyset rounds cover every match exactly once.
        let mut seen = vec![];
        let mut after = 0;
        loop {
            let ids = s.matching_ip_ids_after(&f, after).await.unwrap();
            let Some(&last) = ids.last() else { break };
            seen.extend(ids);
            after = last;
        }
        assert_eq!(seen.len(), 250);
        // A /16 spans the neighbouring /24 too; a /0 everything IPv4.
        let q = |q: &str| IpFilter {
            q: Some(q.into()),
            ..Default::default()
        };
        assert_eq!(s.count_ips(&q("198.51.0.0/16")).await.unwrap(), 251);
        assert_eq!(s.count_ips(&q("0.0.0.0/0")).await.unwrap(), 253);
        // IPv6 networks whose first group is zero (stored as "::…").
        s.upsert_ip("::5".parse().unwrap()).await.unwrap();
        s.upsert_ip("0:1::1".parse().unwrap()).await.unwrap();
        assert_eq!(s.count_ips(&q("::/16")).await.unwrap(), 2);
        assert_eq!(s.count_ips(&q("::/127")).await.unwrap(), 0);
        assert_eq!(s.count_ips(&q("::4/126")).await.unwrap(), 1);
        assert_eq!(s.count_ips(&q("2001:db8::/32")).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn per_ip_read_models_follow_inserts_and_deletes() {
        let s = seeded().await;
        let ip = s.ip_by_addr("203.0.113.200").await.unwrap().unwrap();
        assert_eq!((ip.request_count, ip.max_severity), (1, 2));
        let worst = s
            .insert_request(&NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/x".into(),
                query: None,
                headers_json: "[]".into(),
                body: None,
                labels_json: r#"["wp","rce","rce"]"#.into(),
                severity: 4,
                scan_level: 0,
                is_fp_claim: false,
                page_token: None,
                ..Default::default()
            })
            .await
            .unwrap();
        let ov = s.ip_overview(ip.id).await.unwrap().unwrap();
        assert_eq!((ov.request_count, ov.max_severity), (2, 4));
        let labels: Vec<(String, i64)> = ov
            .labels
            .iter()
            .map(|n| (n.name.clone(), n.count))
            .collect();
        assert_eq!(labels, [("wp".into(), 2), ("rce".into(), 1)]);
        // Deleting the worst request brings the maximum back down.
        assert!(s.delete_request(worst).await.unwrap());
        let ov = s.ip_overview(ip.id).await.unwrap().unwrap();
        assert_eq!((ov.request_count, ov.max_severity), (1, 2));
        let labels: Vec<String> = ov.labels.iter().map(|n| n.name.clone()).collect();
        assert_eq!(labels, ["wp"]);
        let label = |l: &str| IpFilter {
            label: Some(l.into()),
            ..Default::default()
        };
        assert_eq!(s.count_ips(&label("rce")).await.unwrap(), 0);
        assert_eq!(s.count_ips(&label("wp")).await.unwrap(), 1);
        // Requests with junk label JSON are recorded, just without labels.
        bulk_requests(&s, ip.id, 2, "/junk", 1, "not json").await;
        let ip = s.ip_by_addr("203.0.113.200").await.unwrap().unwrap();
        assert_eq!(ip.request_count, 3);
    }

    #[tokio::test]
    async fn path_search_uses_the_index_and_keeps_like_semantics() {
        let s = seeded().await;
        assert!(s.search_indexed());
        let ip = s.ip_by_addr("203.0.113.1").await.unwrap().unwrap();
        bulk_requests(&s, ip.id, 3, "/a_b%c/WP-Admin", 0, "[]").await;
        let find = |path: &str| RequestFilter {
            path: Some(path.into()),
            ..Default::default()
        };
        let n = |f: RequestFilter| {
            let s = s.clone();
            async move {
                s.search_requests(&f, Audience::Admin)
                    .await
                    .unwrap()
                    .items
                    .len()
            }
        };
        assert_eq!(n(find("wp-admin")).await, 3, "case-insensitive substring");
        assert_eq!(n(find("_b%")).await, 3, "LIKE wildcards are literal");
        assert_eq!(n(find("a=1")).await, 5, "admin search covers queries");
        assert_eq!(
            s.search_requests(&find("a=1"), Audience::Public)
                .await
                .unwrap()
                .items
                .len(),
            0,
            "public search never matches queries"
        );
        assert_eq!(n(find("wp")).await, 4, "short terms scan");
        assert_eq!(n(find("\"quoted\"")).await, 0);
        assert_eq!(s.count_requests(&find("wp-admin")).await.unwrap().n, 3);
    }

    /// Method, transport and answer as Analytics names them; `unknown` is
    /// a row without one. Admin only.
    #[tokio::test]
    async fn requests_are_found_by_method_transport_and_answer() {
        let s = seeded().await;
        let ip = s.ip_by_addr("203.0.113.1").await.unwrap().unwrap();
        for (method, transport, answer) in [
            ("PROPFIND", Some("https"), Some("decoy:dotenv")),
            ("PROPFIND", None, None),
        ] {
            s.insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: method.into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                transport: transport.map(String::from),
                answer: answer.map(String::from),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let n = |f: RequestFilter| {
            let s = s.clone();
            async move { s.count_requests(&f).await.unwrap().n }
        };
        let f = |m: Option<&str>, t: Option<&str>, a: Option<&str>| RequestFilter {
            method: m.map(String::from),
            transport: t.map(String::from),
            answer: a.map(String::from),
            ..Default::default()
        };
        assert_eq!(n(f(Some("PROPFIND"), None, None)).await, 2);
        assert_eq!(n(f(Some("propfind"), None, None)).await, 2, "any case");
        assert_eq!(n(f(Some("PROPFIND"), Some("https"), None)).await, 1);
        assert_eq!(n(f(Some("PROPFIND"), Some("unknown"), None)).await, 1);
        assert_eq!(n(f(None, None, Some("decoy:dotenv"))).await, 1);
        assert_eq!(n(f(None, None, Some("decoy"))).await, 1, "every decoy");
        assert_eq!(n(f(None, None, Some("decoy:git-config"))).await, 0);
        assert_eq!(n(f(Some("PROPFIND"), None, Some("unknown"))).await, 1);
        let all = s
            .search_requests(&RequestFilter::default(), Audience::Public)
            .await
            .unwrap()
            .items
            .len();
        let public = s
            .search_requests(&f(Some("PROPFIND"), None, None), Audience::Public)
            .await
            .unwrap()
            .items
            .len();
        assert_eq!(public, all, "admin-only filters");
    }

    /// Port, product and OS from any stored scan of the IP. Admin only.
    #[tokio::test]
    async fn ips_are_found_by_open_port_product_and_os() {
        let s = seeded().await;
        let ip = s.ip_by_addr("203.0.113.1").await.unwrap().unwrap();
        s.enqueue_scan(ip.id, 2, 0).await.unwrap();
        let job = s.next_queued_job().await.unwrap().unwrap();
        let port = |port, state: &str, product: Option<&str>| crate::scan::nmap_xml::PortResult {
            port,
            proto: "tcp".into(),
            state: state.into(),
            service: Some("ssh".into()),
            product: product.map(String::from),
            version: product.map(|_| "9.6p1".into()),
        };
        s.finish_job(
            job.id,
            Some(&crate::scan::nmap_xml::ScanResult {
                os_guess: Some("Linux 5.X".into()),
                raw_xml: vec![],
                ports: vec![port(22, "open", Some("OpenSSH")), port(23, "closed", None)],
            }),
            None,
        )
        .await
        .unwrap();
        let n = |f: IpFilter, a: Audience| {
            let s = s.clone();
            async move { s.list_ips_as(&f, a).await.unwrap().items.len() }
        };
        let f = |port: Option<&str>, product: Option<&str>, os: Option<&str>| IpFilter {
            port: port.map(String::from),
            product: product.map(String::from),
            os: os.map(String::from),
            ..Default::default()
        };
        assert_eq!(n(f(Some("22"), None, None), Audience::Admin).await, 1);
        assert_eq!(n(f(Some("22/tcp"), None, None), Audience::Admin).await, 1);
        assert_eq!(n(f(Some("22/udp"), None, None), Audience::Admin).await, 0);
        assert_eq!(
            n(f(Some("23"), None, None), Audience::Admin).await,
            0,
            "closed"
        );
        assert_eq!(
            n(f(Some("x"), None, None), Audience::Admin).await,
            0,
            "not a port"
        );
        assert_eq!(
            n(f(None, Some("OpenSSH 9.6p1"), None), Audience::Admin).await,
            1
        );
        assert_eq!(
            n(f(None, Some("OpenSSH"), None), Audience::Admin).await,
            0,
            "as Analytics names it"
        );
        assert_eq!(
            n(f(None, None, Some("Linux 5.X")), Audience::Admin).await,
            1
        );
        let all = n(IpFilter::default(), Audience::Public).await;
        assert!(all > 1);
        assert_eq!(
            n(f(Some("22"), None, None), Audience::Public).await,
            all,
            "admin only"
        );
    }

    #[tokio::test]
    async fn requests_are_found_by_ja4_for_the_admin_only() {
        let s = seeded().await;
        let ip = s.ip_by_addr("203.0.113.1").await.unwrap().unwrap();
        for ja4 in [Some("t13d_only"), None] {
            s.insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                ja4: ja4.map(String::from),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let f = RequestFilter {
            ja4: Some("t13d_only".into()),
            ..Default::default()
        };
        let found = s.search_requests(&f, Audience::Admin).await.unwrap().items;
        assert_eq!(found.len(), 1);
        assert_eq!(s.count_requests(&f).await.unwrap().n, 1);
        let public = s
            .search_requests(&f, Audience::Public)
            .await
            .unwrap()
            .items
            .len();
        let all = s
            .search_requests(&RequestFilter::default(), Audience::Public)
            .await
            .unwrap()
            .items
            .len();
        assert_eq!(public, all, "fingerprints are never public");
    }

    #[tokio::test]
    async fn requests_are_found_by_ja4h_for_the_admin_only() {
        let s = seeded().await;
        let ip = s.ip_by_addr("203.0.113.1").await.unwrap().unwrap();
        let head = b"GET / HTTP/1.1\r\nHost: x\r\nX-Odd: 1\r\n\r\n";
        for raw_head in [Some(head.to_vec()), None] {
            s.insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                raw_head,
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let f = RequestFilter {
            ja4h: crate::trap::ja4h::ja4h(head),
            ..Default::default()
        };
        let found = s.search_requests(&f, Audience::Admin).await.unwrap().items;
        assert_eq!(found.len(), 1);
        assert_eq!(s.count_requests(&f).await.unwrap().n, 1);
        let public = |f: RequestFilter| {
            let s = s.clone();
            async move {
                s.search_requests(&f, Audience::Public)
                    .await
                    .unwrap()
                    .items
                    .len()
            }
        };
        assert_eq!(
            public(f).await,
            public(RequestFilter::default()).await,
            "fingerprints are never public"
        );
    }

    #[tokio::test]
    async fn request_counts_are_capped() {
        let s = seeded().await;
        let ip = s.ip_by_addr("203.0.113.1").await.unwrap().unwrap();
        bulk_requests(&s, ip.id, COUNT_CAP + 5, "/many", 0, "[]").await;
        let c = s.count_requests(&RequestFilter::default()).await.unwrap();
        assert_eq!(
            c,
            Count {
                n: COUNT_CAP,
                capped: true
            }
        );
        assert_eq!(c.to_string(), format!("{COUNT_CAP}+"));
        let few = s
            .count_requests(&RequestFilter {
                path: Some("/.env".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            few,
            Count {
                n: 3,
                capped: false
            }
        );
        assert_eq!(few.to_string(), "3");
    }
}
