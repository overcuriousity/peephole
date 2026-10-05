//! Unauthenticated pages. Never load admin-only data here.
use crate::admin::auth::SessionUser;
use crate::admin::countries;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::Chrome;
use crate::admin::{AdminState, RangeQuery};
use crate::store::browse::{
    Audience, IpFilter, IpOverview, IpSummary, Page, RequestFilter, RequestListRow, page_num,
};
use crate::store::inspect::{FpClaimRow, FpSummary, IpIntelRow, PortRow, ScanSummary};
use crate::store::stats::{MapCounts, Range, Stats, intel_stale};
use askama::Template;
use axum::{
    Router,
    extract::{FromRequestParts, Path, Query, State},
    http::request::Parts,
    response::{Html, IntoResponse, Json, Response},
    routing::get,
};
use std::convert::Infallible;
use std::sync::Arc;

/// `true` when the request carries a valid admin session. Never rejects.
pub struct MaybeUser(pub bool);

impl FromRequestParts<Arc<AdminState>> for MaybeUser {
    type Rejection = Infallible;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AdminState>,
    ) -> Result<Self, Infallible> {
        let jar = axum_extra::extract::CookieJar::from_request_parts(parts, state)
            .await
            .unwrap_or_else(|_| axum_extra::extract::CookieJar::new());
        Ok(MaybeUser(
            crate::admin::auth::session_valid(state, &jar).await,
        ))
    }
}

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/", get(wall))
        .route("/ips", get(ips))
        .route("/ip/{addr}", get(ip_page))
        .route("/requests", get(requests))
        .route("/api/stats", get(stats_json))
        .route("/api/map", get(map_json))
        .route("/api/countries", get(countries_json))
        .route("/api/blocklist", get(crate::admin::blocklist::feed))
        .route("/healthz", get(healthz))
}

#[derive(Template)]
#[template(path = "wall.html")]
struct WallPage {
    chrome: Chrome,
    range: Range,
    stats: Arc<Stats>,
    stale: bool,
    /// Show rule labels (always with a session; `[public] show_labels`).
    labels: bool,
    /// Requests and unique IPs against the previous window.
    delta_requests: Option<(String, &'static str)>,
    delta_ips: Option<(String, &'static str)>,
    /// OWASP Top 10 (always all ten) and the Automated Threats seen.
    owasp: Vec<OwaspTile>,
    /// Largest values, for the bar widths.
    ip_max: i64,
    asn_max: i64,
    port_max: i64,
    family_max: i64,
    /// "Recent requests": the newest `[public] recent_rows` of `stats.recent`.
    recent: Vec<crate::store::stats::RecentRequest>,
    /// Shortest and longest publication delay, in minutes.
    delay_min: u32,
    delay_max: u32,
}

pub struct OwaspTile {
    pub tag: String,
    pub name: &'static str,
    pub count: i64,
    /// 0 (none) .. 4 (the most frequent), on the accent ramp.
    pub bin: u8,
}

/// The OWASP grid: the ten Top 10 classes in order, whether seen or not,
/// then every Automated Threat seen, most frequent first.
fn owasp_tiles(counts: &[crate::store::stats::Named]) -> Vec<OwaspTile> {
    let max = counts.iter().map(|n| n.count).max().unwrap_or(0);
    let bin = |c: i64| -> u8 {
        if c <= 0 || max <= 0 {
            0
        } else {
            ((c as f64 / max as f64) * 4.0).ceil().clamp(1.0, 4.0) as u8
        }
    };
    let get = |tag: &str| counts.iter().find(|n| n.name == tag).map_or(0, |n| n.count);
    let mut tiles: Vec<OwaspTile> = (1..=10)
        .map(|i| {
            let tag = format!("A{i:02}:2021");
            let count = get(&tag);
            OwaspTile {
                name: crate::admin::views::owasp_name(&tag),
                bin: bin(count),
                tag,
                count,
            }
        })
        .collect();
    tiles.extend(
        counts
            .iter()
            .filter(|n| n.name.starts_with("OAT-"))
            .map(|n| OwaspTile {
                tag: n.name.clone(),
                name: crate::admin::views::owasp_name(&n.name),
                count: n.count,
                bin: bin(n.count),
            }),
    );
    tiles
}

/// Whether this viewer sees rule labels.
fn labels_shown(state: &AdminState, authed: bool) -> bool {
    authed || state.cfg.public.show_labels
}

async fn wall(
    MaybeUser(authed): MaybeUser,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<RangeQuery>,
) -> AppResult<Html<String>> {
    let range = Range::parse(q.range.as_deref());
    let stats = wall_stats(&state, authed, range).await?;
    let stale = intel_stale(&stats.intel);
    let prev = stats.previous.as_ref();
    let max = |v: &mut dyn Iterator<Item = i64>| v.max().unwrap_or(0);
    let recent: Vec<_> = stats
        .recent
        .iter()
        .take(state.cfg.public.recent_rows)
        .cloned()
        .collect();
    render(&WallPage {
        chrome: Chrome::new(authed, "wall"),
        range,
        delta_requests: crate::admin::views::delta(
            stats.total_requests,
            prev.map(|p| p.total_requests),
        ),
        delta_ips: crate::admin::views::delta(stats.unique_ips, prev.map(|p| p.unique_ips)),
        owasp: owasp_tiles(&stats.owasp),
        ip_max: max(&mut stats.top_ips.iter().map(|t| t.count)),
        asn_max: max(&mut stats.top_asns.iter().map(|n| n.count)),
        port_max: max(&mut stats.ports.iter().map(|p| p.ips)),
        family_max: max(&mut stats.families.iter().map(|n| n.count)),
        recent,
        delay_min: state.cfg.public.delay_minutes,
        delay_max: state.cfg.public.delay_minutes + state.cfg.public.jitter_minutes,
        stats,
        stale,
        labels: labels_shown(&state, authed),
    })
}

/// Anonymous views go through the cache; an admin always reads fresh (the
/// wall lists recent rows, which may just have been deleted).
async fn wall_stats(state: &AdminState, authed: bool, range: Range) -> AppResult<Arc<Stats>> {
    Ok(if authed {
        Arc::new(state.store.stats(range).await?)
    } else {
        state.stats_cache.stats(&state.store, range).await?
    })
}

async fn stats_json(
    MaybeUser(authed): MaybeUser,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<RangeQuery>,
) -> AppResult<Json<Arc<Stats>>> {
    let stats = wall_stats(&state, authed, Range::parse(q.range.as_deref())).await?;
    if labels_shown(&state, authed) {
        return Ok(Json(stats));
    }
    let mut hidden = (*stats).clone();
    hidden.top_labels.clear();
    hidden.families.clear();
    hidden.owasp.clear();
    Ok(Json(Arc::new(hidden)))
}

async fn map_json(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<RangeQuery>,
) -> AppResult<Json<Arc<MapCounts>>> {
    Ok(Json(
        state
            .stats_cache
            .map(&state.store, Range::parse(q.range.as_deref()))
            .await?,
    ))
}

async fn countries_json() -> impl IntoResponse {
    let map: std::collections::HashMap<&'static str, &'static str> =
        countries::TABLE.iter().copied().collect();
    (
        [(axum::http::header::CACHE_CONTROL, "public, max-age=86400")],
        Json(map),
    )
}

async fn healthz(State(state): State<Arc<AdminState>>) -> Response {
    match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.store.pool)
        .await
    {
        Ok(_) => "ok".into_response(),
        Err(e) => {
            // Log the detail; return a generic body (the endpoint is public).
            tracing::warn!(?e, "healthz database check failed");
            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response()
        }
    }
}

/// Query string of every filter except `page`, ending in `&` when non-empty.
pub(crate) fn qs_without_page(pairs: &[(&str, Option<String>)]) -> String {
    let mut out = String::new();
    for (k, v) in pairs {
        if let Some(v) = v.as_deref().filter(|s| !s.is_empty()) {
            out.push_str(&format!("{k}={}&", urlencode(v)));
        }
    }
    out
}

fn urlencode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

#[derive(Template)]
#[template(path = "ips.html")]
struct IpsPage {
    chrome: Chrome,
    f: IpFilter,
    page: Arc<Page<IpSummary>>,
    qs: String,
    /// Rows matching the filter across all pages; `Some` only with a session.
    bulk_total: Option<i64>,
    /// Admin on a standalone node: rows can be deleted.
    can_delete: bool,
    labels: bool,
    /// Admin only: provider tags to filter by, and the API providers.
    tags: Vec<String>,
    api_providers: Vec<(&'static str, &'static str)>,
    /// Largest request count on this page, for the bar widths.
    count_max: i64,
}

/// Deepest IP-directory page anonymous visitors can open; with a session
/// the limit is `browse::MAX_PAGE`.
pub const PUBLIC_MAX_PAGE: i64 = 50;

/// Longest free-text filter value accepted from anonymous visitors.
const PUBLIC_MAX_INPUT: usize = 64;

/// An anonymous visitor's IP filter, normalised so equivalent queries share
/// one cache entry and bounded so it cannot ask for arbitrarily deep pages.
/// Filters the visitor may not use (labels, when hidden) are dropped.
pub(crate) fn public_ip_filter(f: &IpFilter, show_labels: bool) -> IpFilter {
    let text = |v: &Option<String>| {
        v.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= PUBLIC_MAX_INPUT)
            .map(str::to_string)
    };
    let q = text(&f.q).map(|q| {
        if let Ok(ip) = q.parse::<std::net::IpAddr>() {
            ip.to_string()
        } else if let Ok(net) = q.parse::<ipnet::IpNet>() {
            net.trunc().to_string()
        } else {
            q.to_ascii_lowercase()
        }
    });
    IpFilter {
        q,
        country: text(&f.country)
            .filter(|c| c.len() == 2)
            .map(|c| c.to_ascii_uppercase()),
        asn: f.asn.filter(|a| (0..=u32::MAX as i64).contains(a)),
        label: if show_labels { text(&f.label) } else { None },
        min_severity: f.min_severity.filter(|s| (1..=4).contains(s)),
        tor: f.tor.clone().filter(|t| t == "1"),
        sort: f.sort.clone().filter(|s| s == "recent"),
        page: Some(i64::from(page_num(f.page)).min(PUBLIC_MAX_PAGE)),
        // Admin-only providers: never filtered on for the public.
        min_abuse: None,
        tag: None,
        intel: None,
        nointel: None,
    }
}

pub(crate) fn ip_qs(f: &IpFilter) -> String {
    qs_without_page(&[
        ("q", f.q.clone()),
        ("country", f.country.clone()),
        ("asn", f.asn.map(|a| a.to_string())),
        ("label", f.label.clone()),
        ("min_severity", f.min_severity.map(|a| a.to_string())),
        ("tor", f.tor.clone()),
        ("sort", f.sort.clone()),
        ("min_abuse", f.min_abuse.map(|a| a.to_string())),
        ("tag", f.tag.clone()),
        ("intel", f.intel.clone()),
        ("nointel", f.nointel.clone()),
    ])
}

pub(crate) fn request_qs(f: &RequestFilter) -> String {
    qs_without_page(&[
        ("ip", f.ip.clone()),
        ("path", f.path.clone()),
        ("label", f.label.clone()),
        ("severity", f.severity.map(|a| a.to_string())),
        ("min_severity", f.min_severity.map(|a| a.to_string())),
        ("country", f.country.clone()),
        ("asn", f.asn.map(|a| a.to_string())),
        ("from", f.from.clone()),
        ("to", f.to.clone()),
        ("node", f.node.clone()),
        ("ja4h", f.ja4h.clone()),
    ])
}

async fn ips(
    MaybeUser(authed): MaybeUser,
    State(state): State<Arc<AdminState>>,
    Query(f): Query<IpFilter>,
) -> AppResult<Html<String>> {
    // Anonymous views go through the cache (spec §6.3 rationale) with a
    // normalised, bounded filter; an admin always sees fresh rows.
    let (f, page, bulk_total) = if authed {
        let page = Arc::new(state.store.list_ips(&f).await?);
        let total = state.store.count_ips(&f).await?;
        (f, page, Some(total))
    } else {
        let f = public_ip_filter(&f, state.cfg.public.show_labels);
        let key = format!("{}page={}", ip_qs(&f), page_num(f.page));
        let cached = state.stats_cache.ips(&state.store, &f, key).await?;
        // AbuseIPDB is admin-only: its score never reaches a public page.
        let mut page = (*cached).clone();
        for i in &mut page.items {
            i.abuse_score = None;
        }
        if page.has_next && i64::from(page.page) >= PUBLIC_MAX_PAGE {
            page.has_next = false;
        }
        let page = Arc::new(page);
        (f, page, None)
    };
    let (tags, api_providers) = if authed {
        let providers = crate::intel::KNOWN_PROVIDERS
            .iter()
            .filter(|p| p.api)
            .map(|p| (p.name, p.label))
            .collect();
        (state.store.intel_tags().await?, providers)
    } else {
        (vec![], vec![])
    };
    let count_max = page
        .items
        .iter()
        .map(|i| i.request_count)
        .max()
        .unwrap_or(0);
    render(&IpsPage {
        chrome: Chrome::new(authed, "ips"),
        count_max,
        qs: ip_qs(&f),
        f,
        page,
        bulk_total,
        can_delete: authed && state.can_delete(),
        labels: labels_shown(&state, authed),
        tags,
        api_providers,
    })
}

#[derive(Template)]
#[template(path = "requests.html")]
struct RequestsPage {
    chrome: Chrome,
    f: RequestFilter,
    page: Page<RequestListRow>,
    qs: String,
    bulk_total: Option<crate::store::browse::Count>,
    /// Standalone node: rows can be deleted.
    can_delete: bool,
    /// Cluster member names for the admin-only node filter (empty
    /// standalone or for the public).
    nodes: Vec<String>,
}

/// Admin-only: request rows (timestamp, method, path, severity, labels)
/// identify individual clients, so the public side never lists them.
async fn requests(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Query(f): Query<RequestFilter>,
) -> AppResult<Html<String>> {
    let page = state.store.search_requests(&f, Audience::Admin).await?;
    let bulk_total = Some(state.store.count_requests(&f).await?);
    let qs = request_qs(&f);
    let nodes = crate::cluster::members::all(&state.store)
        .await?
        .into_iter()
        .map(|m| m.name)
        .collect();
    render(&RequestsPage {
        chrome: Chrome::new(true, "requests"),
        f,
        page,
        qs,
        bulk_total,
        can_delete: state.can_delete(),
        nodes,
    })
}

pub struct ScanWithPorts {
    pub s: ScanSummary,
    pub ports: Vec<PortRow>,
}

/// One fact a provider reported, ready to show.
pub struct IntelFact {
    pub label: String,
    pub value: String,
    pub mono: bool,
}

/// One node's result from one provider.
pub struct IntelResult {
    pub facts: Vec<IntelFact>,
    pub fetched_at: String,
    pub source_version: Option<String>,
    /// Admin only: the node that looked it up.
    pub node: Option<String>,
}

/// A provider's card on the IP page: its newest result, and (admin only)
/// the other nodes' results.
pub struct IntelCard {
    pub label: &'static str,
    pub name: String,
    pub newest: Option<IntelResult>,
    pub others: Vec<IntelResult>,
}

fn fact(label: &str, value: impl Into<String>, mono: bool) -> IntelFact {
    IntelFact {
        label: label.to_string(),
        value: value.into(),
        mono,
    }
}

/// A provider's data as labelled facts. Known fields get a readable form;
/// anything else is listed under its own key, so a new provider shows up
/// without template changes.
fn intel_facts(provider: &str, data: &serde_json::Value) -> Vec<IntelFact> {
    let Some(obj) = data.as_object() else {
        return vec![fact("Data", data.to_string(), true)];
    };
    if let Some(fields) = api_fields(provider) {
        return api_facts(fields, obj);
    }
    // Known fields first, in reading order; the map itself is sorted by key.
    const ORDER: [&str; 4] = ["exit", "country", "asn", "asn_org"];
    let mut fields: Vec<(&String, &serde_json::Value)> = obj.iter().collect();
    fields.sort_by_key(|(k, _)| ORDER.iter().position(|o| o == k).unwrap_or(ORDER.len()));
    let mut out = Vec::new();
    let mut rest: Vec<(&String, &serde_json::Value)> = Vec::new();
    for (k, v) in fields {
        match (provider, k.as_str()) {
            (crate::intel::TOR, "exit") => out.push(fact(
                "Exit node",
                match v.as_bool() {
                    Some(true) => "listed",
                    Some(false) => "not listed",
                    None => "unknown",
                },
                false,
            )),
            (crate::intel::MAXMIND, "country") => {
                if let Some(c) = v.as_str() {
                    out.push(fact(
                        "Country",
                        format!(
                            "{} {} ({c})",
                            countries::flag(c),
                            countries::country_name(c)
                        ),
                        false,
                    ));
                }
            }
            (crate::intel::MAXMIND, "asn") => out.push(fact("ASN", format!("AS{v}"), true)),
            (crate::intel::MAXMIND, "asn_org") => {
                out.push(fact("Organisation", v.as_str().unwrap_or_default(), false))
            }
            _ if v.is_null() => {}
            _ => rest.push((k, v)),
        }
    }
    for (k, v) in rest {
        let value = match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        out.push(fact(k, value, !v.is_string()));
    }
    if out.is_empty() {
        out.push(fact("Result", "nothing known about this address", false));
    }
    out
}

/// `(key, label, monospaced)` of an API provider's fields, in reading order.
type Fields = &'static [(&'static str, &'static str, bool)];

fn api_fields(provider: &str) -> Option<Fields> {
    use crate::intel::{ABUSEIPDB, GREYNOISE, INTERNETDB, SHODAN};
    Some(match provider {
        ABUSEIPDB => &[
            ("score", "Abuse score", true),
            ("reports", "Reports", true),
            ("reporters", "Reporters", true),
            ("last_reported_at", "Last reported", true),
            ("categories", "Categories", false),
            ("usage_type", "Usage type", false),
            ("isp", "ISP", false),
            ("domain", "Domain", true),
            ("hostnames", "Hostnames", true),
            ("whitelisted", "Whitelisted", false),
            ("tor", "Tor", false),
        ],
        SHODAN => &[
            ("ports", "Open ports", true),
            ("services", "Services", true),
            ("os", "OS", false),
            ("org", "Organisation", false),
            ("isp", "ISP", false),
            ("asn", "ASN", true),
            ("hostnames", "Hostnames", true),
            ("domains", "Domains", true),
            ("tags", "Tags", false),
            ("vulns", "CVEs", true),
            ("last_update", "Last crawled", true),
        ],
        INTERNETDB => &[
            ("ports", "Open ports", true),
            ("cpes", "CPEs", true),
            ("hostnames", "Hostnames", true),
            ("tags", "Tags", false),
            ("vulns", "CVEs", true),
        ],
        GREYNOISE => &[
            ("classification", "Classification", false),
            ("noise", "Mass-scanning", false),
            ("riot", "Known benign service", false),
            ("name", "Actor / provider", false),
            ("last_seen", "Last seen scanning", true),
        ],
        _ => return None,
    })
}

/// One value as text: lists comma-separated, Shodan services as
/// `port/transport product version`, flags as yes/no.
fn fact_text(key: &str, v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "yes" } else { "no" }.to_string(),
        Value::Array(items) if key == "services" => items
            .iter()
            .map(|s| {
                let mut out = format!(
                    "{}/{}",
                    s.get("port").map_or("?".into(), |p| p.to_string()),
                    s.get("transport").and_then(|t| t.as_str()).unwrap_or("tcp")
                );
                for k in ["product", "version"] {
                    if let Some(x) = s.get(k).and_then(|x| x.as_str()) {
                        out.push(' ');
                        out.push_str(x);
                    }
                }
                out
            })
            .collect::<Vec<_>>()
            .join(" · "),
        Value::Array(items) => items
            .iter()
            .map(|x| match x {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

fn api_facts(fields: Fields, obj: &serde_json::Map<String, serde_json::Value>) -> Vec<IntelFact> {
    let mut out: Vec<IntelFact> = fields
        .iter()
        .filter_map(|(k, label, mono)| {
            let v = obj.get(*k).filter(|v| !v.is_null())?;
            let mut text = fact_text(k, v);
            if *k == "score" {
                text.push_str(" / 100");
            }
            if *k == "vulns"
                && let Some(n) = v.as_array().map(Vec::len).filter(|n| *n > 1)
            {
                text = format!("{n}: {text}");
            }
            Some(fact(label, text, *mono))
        })
        .collect();
    // Fields this version does not know yet (a newer node's), as they are.
    for (k, v) in obj {
        if !v.is_null() && !fields.iter().any(|(f, _, _)| f == k) {
            out.push(fact(k, fact_text(k, v), !v.is_string()));
        }
    }
    if out.is_empty() {
        out.push(fact("Result", "nothing known about this address", false));
    }
    out
}

/// Cards for the IP page. Anonymous visitors see only public providers and
/// no node names; an admin sees every provider and every node's result.
/// A known provider without a result still gets a card, saying so.
pub fn intel_cards(rows: Vec<IpIntelRow>, admin: bool) -> Vec<IntelCard> {
    let mut by_provider: Vec<(String, Vec<IpIntelRow>)> = Vec::new();
    for r in rows {
        match by_provider.iter_mut().find(|(p, _)| *p == r.provider) {
            Some((_, v)) => v.push(r),
            None => by_provider.push((r.provider.clone(), vec![r])),
        }
    }
    let mut names: Vec<(&'static str, String)> = crate::intel::KNOWN_PROVIDERS
        .iter()
        .filter(|p| admin || p.public)
        .map(|p| (p.label, p.name.to_string()))
        .collect();
    if admin {
        for (p, _) in &by_provider {
            if crate::intel::provider_info(p).is_none() {
                names.push(("Other provider", p.clone()));
            }
        }
    }
    names
        .into_iter()
        .map(|(label, name)| {
            let rows = by_provider
                .iter()
                .find(|(p, _)| *p == name)
                .map(|(_, v)| v.as_slice())
                .unwrap_or_default();
            let mut results = rows.iter().map(|r| {
                let data = serde_json::from_str(&r.data_json).unwrap_or(serde_json::Value::Null);
                IntelResult {
                    facts: intel_facts(&name, &data),
                    fetched_at: r.fetched_at.clone(),
                    source_version: r.source_version.clone(),
                    node: if admin { r.node.clone() } else { None },
                }
            });
            let newest = results.next();
            let others = if admin { results.collect() } else { vec![] };
            IntelCard {
                label,
                name,
                newest,
                others,
            }
        })
        .collect()
}

/// Admin-only sections of the IP page. Loaded only with a session.
pub struct IpAdminData {
    pub jobs: Vec<crate::events::QueueJob>,
    pub scans: Vec<ScanWithPorts>,
    pub fingerprints: Vec<FpSummary>,
    pub claims: Vec<FpClaimRow>,
    /// Requests answered but not recorded in full (flood sampling).
    pub skipped: i64,
    pub host_keys: Vec<crate::store::hostkeys::HostKeyRow>,
    /// Other IPs that used canaries harvested here, and other IPs whose
    /// canaries this IP used.
    pub canary_links: (i64, i64),
}

impl IpAdminData {
    /// The most other IPs any one host key or certificate links this IP to.
    pub fn linked_ips(&self) -> i64 {
        self.host_keys
            .iter()
            .filter(|k| k.identifies())
            .map(|k| k.other_ips)
            .max()
            .unwrap_or(0)
    }
}

#[derive(Template)]
#[template(path = "ip.html")]
struct IpPage {
    chrome: Chrome,
    ov: Arc<IpOverview>,
    /// `ov.week` and `ov.calendar` for the page's charts.
    week_json: String,
    calendar_json: String,
    /// Largest family count, for the bar widths.
    family_max: i64,
    page: Page<RequestListRow>,
    intel: Vec<IntelCard>,
    admin: Option<IpAdminData>,
    /// Admin on a standalone node: the IP can be deleted.
    can_delete: bool,
    labels: bool,
}

#[derive(serde::Deserialize, Default)]
pub struct PageQuery {
    #[serde(default, deserialize_with = "crate::store::browse::lenient_i64")]
    pub page: Option<i64>,
}

async fn ip_page(
    MaybeUser(authed): MaybeUser,
    State(state): State<Arc<AdminState>>,
    Path(addr): Path<String>,
    Query(q): Query<PageQuery>,
) -> AppResult<Html<String>> {
    let Some(ip) = state.store.ip_by_addr(&addr).await? else {
        return Err(AppError::NotFound);
    };
    // Anonymous views go through the cache; an admin always reads fresh.
    let ov = if authed {
        state.store.ip_overview(ip.id).await?.map(Arc::new)
    } else {
        state.stats_cache.ip(&state.store, ip.id).await?
    };
    let Some(ov) = ov else {
        return Err(AppError::NotFound);
    };
    // Per-request rows are admin-only; the public page shows only the IP's
    // aggregates (geo, counts, max severity, labels). Not even queried for
    // the public.
    let page = if authed {
        state
            .store
            .requests_for_ip(ip.id, page_num(q.page), Audience::Admin)
            .await?
    } else {
        Page {
            items: vec![],
            page: 1,
            has_next: false,
        }
    };
    // Admin-only data is only *queried* with a session (spec §5).
    let admin = if authed {
        let found = state.store.scans_for_ip(ip.id).await?;
        let ids: Vec<i64> = found.iter().map(|s| s.id).collect();
        let mut ports = state.store.ports_for_scans(&ids).await?;
        let scans = found
            .into_iter()
            .map(|s| ScanWithPorts {
                ports: ports.remove(&s.id).unwrap_or_default(),
                s,
            })
            .collect();
        Some(IpAdminData {
            jobs: state.store.jobs_for_ip(ip.id, 20).await?,
            scans,
            fingerprints: state.store.fingerprints_for_ip(ip.id).await?,
            claims: state.store.claims_for_ip(ip.id).await?,
            skipped: state.store.skipped_for_ip(ip.id).await?,
            host_keys: state.store.host_keys_for_ip(ip.id).await?,
            canary_links: state.store.canary_links_for_ip(ip.id).await?,
        })
    } else {
        None
    };
    let intel = intel_cards(state.store.intel_for_ip(&ip.ip).await?, authed);
    let week_json = serde_json::to_string(&ov.week).unwrap_or_else(|_| "[]".into());
    let calendar_json = serde_json::to_string(&ov.calendar).unwrap_or_else(|_| "[]".into());
    let family_max = ov.families.iter().map(|f| f.count).max().unwrap_or(0);
    render(&IpPage {
        chrome: Chrome::new(authed, "ips"),
        ov,
        week_json,
        calendar_json,
        family_max,
        page,
        intel,
        admin,
        can_delete: authed && state.can_delete(),
        labels: labels_shown(&state, authed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[test]
    fn anonymous_filters_are_normalised_and_bounded() {
        let f: IpFilter = serde_urlencoded::from_str(
            "q=+203.0.113.77/24+&country=de&label=wp&min_severity=9&tor=yes&sort=x&page=999",
        )
        .unwrap();
        let p = public_ip_filter(&f, true);
        assert_eq!(p.q.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(p.country.as_deref(), Some("DE"));
        assert_eq!(p.label.as_deref(), Some("wp"));
        assert_eq!(p.min_severity, None);
        assert_eq!((p.tor, p.sort), (None, None));
        assert_eq!(p.page, Some(PUBLIC_MAX_PAGE));
        // Equivalent spellings share one cache key.
        let a = public_ip_filter(
            &IpFilter {
                q: Some("2001:DB8:0::1".into()),
                ..Default::default()
            },
            true,
        );
        let b = public_ip_filter(
            &IpFilter {
                q: Some("2001:db8::1".into()),
                ..Default::default()
            },
            true,
        );
        assert_eq!(ip_qs(&a), ip_qs(&b));
        assert_eq!(public_ip_filter(&f, false).label, None, "labels hidden");
    }

    async fn app(show_labels: bool) -> (axum::Router, tempfile::TempDir) {
        let (state, dir) = state(show_labels).await;
        (crate::admin::full_router(state), dir)
    }

    async fn state(show_labels: bool) -> (Arc<AdminState>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg: crate::config::Config = toml::from_str(&format!(
            r#"
admin_listen = "127.0.0.1:1"
database_path = "{db}"
data_dir = "{d}"
[roles]
listener = false
scanner = false
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
secure_cookies = false
[public]
show_labels = {show_labels}
"#,
            db = dir.path().join("t.db").display(),
            d = dir.path().display()
        ))
        .unwrap();
        let store = crate::store::Store::connect(&cfg.database_path)
            .await
            .unwrap();
        let ip = store
            .upsert_ip("203.0.113.9".parse().unwrap())
            .await
            .unwrap();
        store
            .insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/x".into(),
                query: None,
                headers_json: "[]".into(),
                body: None,
                labels_json: r#"["secret-category"]"#.into(),
                severity: 2,
                scan_level: 0,
                is_fp_claim: false,
                page_token: None,
                ..Default::default()
            })
            .await
            .unwrap();
        (Arc::new(AdminState::public_only(store, cfg)), dir)
    }

    async fn admin_cookie(st: &AdminState) -> String {
        let token = st.store.create_session().await.unwrap();
        format!(
            "{}={token}",
            crate::admin::auth::session_cookie_name(&st.cfg)
        )
    }

    async fn get_with(app: &axum::Router, path: &str, cookie: Option<&str>) -> (u16, String) {
        let mut req = axum::http::Request::get(path);
        if let Some(c) = cookie {
            req = req.header(axum::http::header::COOKIE, c);
        }
        let r = app
            .clone()
            .oneshot(req.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        let status = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&b).into_owned())
    }

    /// `state(true)` plus, with a 5 min delay, a pending request from a
    /// new IP with a long path and a query string.
    async fn delayed_state() -> (Arc<AdminState>, tempfile::TempDir) {
        let (st, dir) = state(true).await;
        st.store
            .set_publish_delay(
                std::time::Duration::from_secs(300),
                std::time::Duration::ZERO,
            )
            .await
            .unwrap();
        let ip = st
            .store
            .upsert_ip("198.51.100.77".parse().unwrap())
            .await
            .unwrap();
        st.store
            .insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/pending-path".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                severity: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        (st, dir)
    }

    #[tokio::test]
    async fn anonymous_wall_is_static_and_lists_released_requests() {
        let (st, _d) = delayed_state().await;
        let app = crate::admin::full_router(st.clone());
        let (_, wall) = get_with(&app, "/", None).await;
        for live in [
            "data-refresh",
            "data-ago",
            "pulse-dot",
            "data-recent",
            "data-live",
        ] {
            assert!(!wall.contains(live), "anonymous wall carries {live}");
        }
        assert!(wall.contains("Recent requests"));
        assert!(wall.contains("Data delayed by about 5–10 min"));
        assert!(
            wall.contains(r#"<td class="path">/x</td>"#),
            "released request listed"
        );
        assert!(!wall.contains("/pending-path"), "pending request hidden");
        assert!(!wall.contains("198.51.100.77"));
    }

    #[tokio::test]
    async fn signed_in_wall_shows_pending_rows() {
        let (st, _d) = delayed_state().await;
        let cookie = admin_cookie(&st).await;
        let app = crate::admin::full_router(st.clone());
        let (_, wall) = get_with(&app, "/", Some(&cookie)).await;
        assert!(wall.contains("/pending-path"));
        assert!(wall.contains("Live view (signed in)"));
        assert!(
            !wall.contains("data-recent"),
            "the live feed lives on /admin now"
        );
    }

    #[tokio::test]
    async fn admin_overview_has_the_live_feed() {
        let (st, _d) = delayed_state().await;
        let cookie = admin_cookie(&st).await;
        let app = crate::admin::full_router(st.clone());
        let (status, home) = get_with(&app, "/admin", Some(&cookie)).await;
        assert_eq!(status, 200);
        assert!(home.contains("data-recent"));
        assert!(home.contains("/admin/api/recent?after="));
        assert!(
            home.contains("/pending-path"),
            "admins see pending rows at once"
        );
    }

    #[tokio::test]
    async fn pending_only_ip_is_a_404_for_the_public() {
        let (st, _d) = delayed_state().await;
        let cookie = admin_cookie(&st).await;
        let app = crate::admin::full_router(st.clone());
        assert_eq!(get_with(&app, "/ip/198.51.100.77", None).await.0, 404);
        assert_eq!(
            get_with(&app, "/ip/198.51.100.77", Some(&cookie)).await.0,
            200
        );
        let (_, ips) = get_with(&app, "/ips", None).await;
        assert!(!ips.contains("198.51.100.77"));
        assert!(!ips.contains("data-ago"));
        let (_, ip) = get_with(&app, "/ip/203.0.113.9", None).await;
        assert!(!ip.contains("data-ago"));
    }

    #[tokio::test]
    async fn recent_requests_hide_queries_cut_paths_and_respect_labels() {
        let (st, _d) = state(false).await;
        let ip = st
            .store
            .upsert_ip("203.0.113.9".parse().unwrap())
            .await
            .unwrap();
        st.store
            .insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: format!("/{}", "z".repeat(120)),
                query: Some("token=hunter2".into()),
                headers_json: "[]".into(),
                labels_json: r#"["secret-category"]"#.into(),
                severity: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        let app = crate::admin::full_router(st.clone());
        let (_, wall) = get_with(&app, "/", None).await;
        assert!(!wall.contains("hunter2"));
        assert!(wall.contains(&format!("/{}…", "z".repeat(78))));
        assert!(!wall.contains(&"z".repeat(80)));
        assert!(
            !wall.contains("secret-category"),
            "labels hidden with show_labels = false"
        );
    }

    #[tokio::test]
    async fn admin_wall_reads_past_the_cache() {
        let (st, _d) = state(true).await;
        let cached = wall_stats(&st, false, Range::All).await.unwrap();
        assert_eq!(cached.total_requests, 1);
        let ip = st.store.ip_by_addr("203.0.113.9").await.unwrap().unwrap();
        assert!(st.store.delete_ip(ip.id).await.unwrap());
        // The public keeps the cached figures until they expire; an admin
        // who just deleted sees the rows gone.
        let public = wall_stats(&st, false, Range::All).await.unwrap();
        assert_eq!(public.total_requests, 1);
        let admin = wall_stats(&st, true, Range::All).await.unwrap();
        assert_eq!(admin.total_requests, 0);
        assert!(admin.recent.is_empty());
    }

    #[tokio::test]
    async fn canary_tile_shows_only_from_five_reuses() {
        let (st, _dir) = state(true).await;
        let mut conn = st.store.pool.acquire().await.unwrap();
        let ctx = crate::store::data::Ctx {
            origin: None,
            hlc: 1,
        };
        let now = chrono::Utc::now();
        let ts = |h: i64| {
            (now - chrono::Duration::hours(h))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        };
        let rec = |uid: &str,
                   ts: String,
                   ip: &str,
                   path: &str,
                   headers: String,
                   answer: &str,
                   v: Option<i64>| {
            crate::cluster::record::Record::Request(Box::new(crate::cluster::record::RequestRec {
                uid: uid.into(),
                ts,
                ip: ip.into(),
                method: "GET".into(),
                path: path.into(),
                headers_json: headers,
                labels_json: "[]".into(),
                page_token: Some(format!("tok-{uid}")),
                answer: Some(answer.into()),
                decoy_v: v,
                ..Default::default()
            }))
        };
        for i in 0..5 {
            let srv = format!("s{i}");
            crate::store::data::apply(
                &mut conn,
                ctx,
                &rec(
                    &srv,
                    ts(5),
                    "198.51.100.1",
                    "/.git/config",
                    "[]".into(),
                    "decoy:git-config",
                    Some(1),
                ),
            )
            .await
            .unwrap();
            if i < 4 {
                let token =
                    crate::canary::value(&format!("tok-{srv}"), crate::canary::Kind::GitToken);
                let auth = data_encoding::BASE64.encode(format!("deploy:{token}").as_bytes());
                crate::store::data::apply(
                    &mut conn,
                    ctx,
                    &rec(
                        &format!("u{i}"),
                        ts(1),
                        "198.51.100.2",
                        "/x",
                        format!(r#"[["authorization","Basic {auth}"]]"#),
                        "not-found",
                        None,
                    ),
                )
                .await
                .unwrap();
            }
        }
        drop(conn);
        assert!(
            st.store.stats(Range::H24).await.unwrap().canaries.is_none(),
            "4 reuses: hidden"
        );
        let mut conn = st.store.pool.acquire().await.unwrap();
        let token = crate::canary::value("tok-s4", crate::canary::Kind::GitToken);
        let auth = data_encoding::BASE64.encode(format!("deploy:{token}").as_bytes());
        crate::store::data::apply(
            &mut conn,
            ctx,
            &rec(
                "u4",
                ts(1),
                "198.51.100.3",
                "/x",
                format!(r#"[["authorization","Basic {auth}"]]"#),
                "not-found",
                None,
            ),
        )
        .await
        .unwrap();
        drop(conn);
        let t = st.store.stats(Range::H24).await.unwrap().canaries.unwrap();
        assert_eq!((t.reused, t.median_s, t.share_pct), (5, 4 * 3600, 100));
        let html = get(&crate::admin::full_router(st.clone()), "/").await;
        assert!(html.contains("Harvest to first use"));
        assert!(!html.contains(&token));
    }

    #[tokio::test]
    async fn one_harvest_used_once_never_shows_on_the_wall() {
        // A checker posting a whole .env back carries seven canaries: still
        // one event, so the tile stays hidden.
        let (st, _dir) = state(true).await;
        let mut conn = st.store.pool.acquire().await.unwrap();
        let ctx = crate::store::data::Ctx {
            origin: None,
            hlc: 1,
        };
        let now = chrono::Utc::now();
        let ts = |h: i64| {
            (now - chrono::Duration::hours(h))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        };
        let rec = |uid: &str,
                   ts: String,
                   path: &str,
                   body: Option<Vec<u8>>,
                   answer: &str,
                   v: Option<i64>| {
            crate::cluster::record::Record::Request(Box::new(crate::cluster::record::RequestRec {
                uid: uid.into(),
                ts,
                ip: "198.51.100.1".into(),
                method: "POST".into(),
                path: path.into(),
                headers_json: "[]".into(),
                body,
                labels_json: "[]".into(),
                page_token: Some(format!("tok-{uid}")),
                answer: Some(answer.into()),
                decoy_v: v,
                ..Default::default()
            }))
        };
        crate::store::data::apply(
            &mut conn,
            ctx,
            &rec("env", ts(5), "/.env", None, "decoy:dotenv", Some(1)),
        )
        .await
        .unwrap();
        let all: Vec<String> = crate::canary::served(Some(1), "tok-env", "dotenv")
            .into_iter()
            .map(|(_, v)| v)
            .collect();
        let body = all
            .iter()
            .enumerate()
            .map(|(i, v)| format!("k{i}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        crate::store::data::apply(
            &mut conn,
            ctx,
            &rec(
                "chk",
                ts(1),
                "/check",
                Some(body.into_bytes()),
                "not-found",
                None,
            ),
        )
        .await
        .unwrap();
        drop(conn);
        assert!(st.store.stats(Range::H24).await.unwrap().canaries.is_none());
    }

    async fn get(app: &axum::Router, path: &str) -> String {
        let r = app
            .clone()
            .oneshot(
                axum::http::Request::get(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "{path}");
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&b).into_owned()
    }

    #[tokio::test]
    async fn labels_can_be_kept_off_the_public_pages() {
        let (shown, _d1) = app(true).await;
        assert!(
            get(&shown, "/ip/203.0.113.9")
                .await
                .contains("secret-category")
        );
        assert!(get(&shown, "/ips").await.contains("name=\"label\""));
        assert!(
            get(&shown, "/api/stats?range=all")
                .await
                .contains("secret-category")
        );
        let wall = get(&shown, "/").await;
        assert!(wall.contains("Top labels") && wall.contains("OWASP map"));
        assert!(wall.contains("What they were after"));
        assert!(
            get(&shown, "/ip/203.0.113.9")
                .await
                .contains("What it was after")
        );

        let (hidden, _d2) = app(false).await;
        assert!(
            !get(&hidden, "/ip/203.0.113.9")
                .await
                .contains("secret-category")
        );
        assert!(!get(&hidden, "/ips").await.contains("name=\"label\""));
        assert!(
            !get(&hidden, "/api/stats?range=all")
                .await
                .contains("secret-category")
        );
        let wall = get(&hidden, "/").await;
        assert!(!wall.contains("Top labels") && !wall.contains("OWASP map"));
        assert!(!wall.contains("What they were after"));
        assert!(
            !get(&hidden, "/ip/203.0.113.9")
                .await
                .contains("What it was after")
        );
        // Families and OWASP tags are derived from labels: hidden with them.
        let json: serde_json::Value =
            serde_json::from_str(&get(&hidden, "/api/stats?range=all").await).unwrap();
        assert_eq!(json["families"], serde_json::json!([]));
        assert_eq!(json["owasp"], serde_json::json!([]));
        assert!(json["top_labels"].as_array().unwrap().is_empty());
        // The filter cannot be used to probe: it is ignored.
        let html = get(&hidden, "/ips?label=no-such-label").await;
        assert!(html.contains("203.0.113.9"), "label filter ignored");
    }

    #[tokio::test]
    async fn ip_page_lists_every_public_provider_with_or_without_a_result() {
        let (app, _d) = app(true).await;
        let html = get(&app, "/ip/203.0.113.9").await;
        assert!(html.contains("Tor exit list") && html.contains("MaxMind GeoLite2"));
        assert_eq!(html.matches("No result yet").count(), 2);
    }

    fn row(provider: &str, data: &str, node: Option<&str>) -> IpIntelRow {
        IpIntelRow {
            provider: provider.into(),
            fetched_at: "2026-10-01T00:00:00Z".into(),
            source_version: None,
            data_json: data.into(),
            node: node.map(str::to_string),
        }
    }

    #[test]
    fn intel_cards_hide_nodes_and_unknown_providers_from_the_public() {
        let rows = || {
            vec![
                row(crate::intel::TOR, r#"{"exit":false}"#, Some("a")),
                row(crate::intel::TOR, r#"{"exit":true}"#, Some("b")),
                row(
                    crate::intel::MAXMIND,
                    r#"{"country":"DE","asn":64500,"asn_org":"Ex"}"#,
                    None,
                ),
                row("shodan", r#"{"ports":[22,80]}"#, Some("a")),
            ]
        };
        let public = intel_cards(rows(), false);
        assert_eq!(public.len(), 2);
        let tor = &public[0];
        let newest = tor.newest.as_ref().unwrap();
        assert_eq!(newest.facts[0].value, "not listed");
        assert_eq!(newest.node, None);
        assert!(tor.others.is_empty());
        let geo = public[1].newest.as_ref().unwrap();
        let labels: Vec<_> = geo.facts.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(labels, ["Country", "ASN", "Organisation"]);
        assert!(geo.facts.iter().any(|f| f.value == "AS64500"));

        let admin = intel_cards(rows(), true);
        assert_eq!(admin.len(), crate::intel::KNOWN_PROVIDERS.len());
        assert_eq!(admin[0].newest.as_ref().unwrap().node.as_deref(), Some("a"));
        assert_eq!(admin[0].others.len(), 1);
        let shodan = admin.iter().find(|c| c.name == "shodan").unwrap();
        assert_eq!(shodan.label, "Shodan");
        assert_eq!(shodan.newest.as_ref().unwrap().facts[0].value, "22, 80");
        let row = |p: &str| row(p, r#"{"ports":[22]}"#, None);
        let cards = intel_cards(vec![row("not-a-provider")], true);
        assert!(cards.iter().any(|c| c.label == "Other provider"));
    }

    #[test]
    fn api_results_read_as_facts() {
        let f = intel_facts(
            crate::intel::ABUSEIPDB,
            &serde_json::json!({"score": 87, "reports": 41, "categories": ["SSH", "Port Scan"],
                                "whitelisted": false, "future_field": 1}),
        );
        let got: Vec<_> = f
            .iter()
            .map(|f| (f.label.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("Abuse score", "87 / 100"),
                ("Reports", "41"),
                ("Categories", "SSH, Port Scan"),
                ("Whitelisted", "no"),
                ("future_field", "1"),
            ]
        );
        let f = intel_facts(
            crate::intel::SHODAN,
            &serde_json::json!({"services": [{"port": 22, "transport": "tcp", "product": "OpenSSH",
                                              "version": "8.9p1"}, {"port": 443}],
                                "vulns": ["CVE-1", "CVE-2"]}),
        );
        assert_eq!(f[0].value, "22/tcp OpenSSH 8.9p1 · 443/tcp");
        assert_eq!(f[1].value, "2: CVE-1, CVE-2");
        let f = intel_facts(crate::intel::GREYNOISE, &serde_json::json!({}));
        assert_eq!(f[0].label, "Result");
    }

    #[test]
    fn an_empty_result_says_nothing_is_known() {
        let f = intel_facts(crate::intel::MAXMIND, &serde_json::json!({}));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].label, "Result");
    }
}
