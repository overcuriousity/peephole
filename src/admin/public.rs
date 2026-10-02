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
    let stats = state.stats_cache.stats(&state.store, range).await?;
    let stale = intel_stale(&stats.intel);
    render(&WallPage {
        chrome: Chrome::new(authed, "wall"),
        range,
        stats,
        stale,
        labels: labels_shown(&state, authed),
    })
}

async fn stats_json(
    MaybeUser(authed): MaybeUser,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<RangeQuery>,
) -> AppResult<Json<Arc<Stats>>> {
    let stats = state
        .stats_cache
        .stats(&state.store, Range::parse(q.range.as_deref()))
        .await?;
    if labels_shown(&state, authed) {
        return Ok(Json(stats));
    }
    let mut hidden = (*stats).clone();
    hidden.top_labels.clear();
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
    labels: bool,
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
        let f = public_ip_filter(&f, state.cfg.public.show_labels);
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
        labels: labels_shown(&state, authed),
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
}

#[derive(Template)]
#[template(path = "ip.html")]
struct IpPage {
    chrome: Chrome,
    ov: Arc<IpOverview>,
    sparkline_json: String,
    page: Page<RequestListRow>,
    intel: Vec<IntelCard>,
    admin: Option<IpAdminData>,
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
        })
    } else {
        None
    };
    let intel = intel_cards(state.store.intel_for_ip(&ip.ip).await?, authed);
    let sparkline_json = serde_json::to_string(&ov.sparkline).unwrap_or_else(|_| "[]".into());
    render(&IpPage {
        chrome: Chrome::new(authed, "ips"),
        ov,
        sparkline_json,
        page,
        intel,
        admin,
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
            })
            .await
            .unwrap();
        let state = Arc::new(AdminState::public_only(store, cfg));
        (crate::admin::full_router(state), dir)
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
        assert!(get(&shown, "/").await.contains("Top labels"));

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
        assert!(!get(&hidden, "/").await.contains("Top labels"));
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
        assert_eq!(admin.len(), 3);
        assert_eq!(admin[0].newest.as_ref().unwrap().node.as_deref(), Some("a"));
        assert_eq!(admin[0].others.len(), 1);
        assert_eq!(admin[2].name, "shodan");
        assert_eq!(admin[2].newest.as_ref().unwrap().facts[0].value, "[22,80]");
    }

    #[test]
    fn an_empty_result_says_nothing_is_known() {
        let f = intel_facts(crate::intel::MAXMIND, &serde_json::json!({}));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].label, "Result");
    }
}
