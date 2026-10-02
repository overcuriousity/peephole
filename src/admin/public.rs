//! Unauthenticated pages. Never load admin-only data here.
use crate::admin::auth::SessionUser;
use crate::admin::countries;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::Chrome;
use crate::admin::{AdminState, RangeQuery};
use crate::store::browse::{
    Audience, IpFilter, IpOverview, IpSummary, Page, RequestFilter, RequestListRow, page_num,
};
use crate::store::inspect::{FpClaimRow, FpSummary, PortRow, ScanSummary};
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
        .route("/healthz", get(healthz))
}

#[derive(Template)]
#[template(path = "wall.html")]
struct WallPage {
    chrome: Chrome,
    range: Range,
    stats: Arc<Stats>,
    stale: bool,
}

async fn wall(
    MaybeUser(authed): MaybeUser,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<RangeQuery>,
) -> AppResult<Html<String>> {
    let range = Range::parse(q.range.as_deref());
    let stats = state.stats_cache.stats(&state.store, range).await?;
    let stale = intel_stale(&stats.intel);
    render(&WallPage {
        chrome: Chrome::new(authed, "wall"),
        range,
        stats,
        stale,
    })
}

async fn stats_json(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<RangeQuery>,
) -> AppResult<Json<Arc<Stats>>> {
    Ok(Json(
        state
            .stats_cache
            .stats(&state.store, Range::parse(q.range.as_deref()))
            .await?,
    ))
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
}

/// Deepest IP-directory page anonymous visitors can open; with a session
/// the limit is `browse::MAX_PAGE`.
pub const PUBLIC_MAX_PAGE: i64 = 50;

/// Longest free-text filter value accepted from anonymous visitors.
const PUBLIC_MAX_INPUT: usize = 64;

/// An anonymous visitor's IP filter, normalised so equivalent queries share
/// one cache entry and bounded so it cannot ask for arbitrarily deep pages.
pub(crate) fn public_ip_filter(f: &IpFilter) -> IpFilter {
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
        label: text(&f.label),
        min_severity: f.min_severity.filter(|s| (1..=4).contains(s)),
        tor: f.tor.clone().filter(|t| t == "1"),
        sort: f.sort.clone().filter(|s| s == "recent"),
        page: Some(i64::from(page_num(f.page)).min(PUBLIC_MAX_PAGE)),
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
        let f = public_ip_filter(&f);
        let key = format!("{}page={}", ip_qs(&f), page_num(f.page));
        let mut page = state.stats_cache.ips(&state.store, &f, key).await?;
        if page.has_next && i64::from(page.page) >= PUBLIC_MAX_PAGE {
            let mut last = (*page).clone();
            last.has_next = false;
            page = Arc::new(last);
        }
        (f, page, None)
    };
    render(&IpsPage {
        chrome: Chrome::new(authed, "ips"),
        qs: ip_qs(&f),
        f,
        page,
        bulk_total,
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
        nodes,
    })
}

pub struct ScanWithPorts {
    pub s: ScanSummary,
    pub ports: Vec<PortRow>,
}

/// Admin-only sections of the IP page. Loaded only with a session.
pub struct IpAdminData {
    pub scans: Vec<ScanWithPorts>,
    pub fingerprints: Vec<FpSummary>,
    pub claims: Vec<FpClaimRow>,
}

#[derive(Template)]
#[template(path = "ip.html")]
struct IpPage {
    chrome: Chrome,
    ov: Arc<IpOverview>,
    sparkline_json: String,
    page: Page<RequestListRow>,
    admin: Option<IpAdminData>,
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
            scans,
            fingerprints: state.store.fingerprints_for_ip(ip.id).await?,
            claims: state.store.claims_for_ip(ip.id).await?,
        })
    } else {
        None
    };
    let sparkline_json = serde_json::to_string(&ov.sparkline).unwrap_or_else(|_| "[]".into());
    render(&IpPage {
        chrome: Chrome::new(authed, "ips"),
        ov,
        sparkline_json,
        page,
        admin,
    })
}
