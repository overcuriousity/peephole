//! Authenticated admin pages. Every handler takes `SessionUser` first.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::Chrome;
use crate::events::QueueJob;
use crate::store::analytics::{Analytics, RELATED_JA4_DAYS};
use crate::store::browse::{IpFilter, RequestFilter};
use crate::store::inspect::{FpClaimRow, FpCluster, QueueSummary, RequestDetail};
use crate::store::recorder::Deleted;
use crate::store::stats::{Range, RecentRequest};
use askama::Template;
use axum::{
    Router,
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin", get(home))
        .route("/admin/analytics", get(analytics))
        .route("/admin/requests/{id}", get(request_page))
        .route("/admin/requests/{id}/delete", post(request_delete))
        .route("/admin/ips/{addr}/delete", post(ip_delete))
        .route("/admin/requests/bulk-delete", post(bulk_delete_requests))
        .route("/admin/ips/bulk-delete", post(bulk_delete_ips))
        .route("/admin/fingerprints", get(fingerprints))
        .route("/admin/canaries", get(canaries))
        .route("/admin/inbox", get(inbox))
        .route("/admin/claims/{id}/delete", post(claim_delete))
}

fn chrome() -> Chrome {
    Chrome::new(true, "admin")
}

#[derive(Template)]
#[template(path = "admin_home.html")]
struct HomePage {
    chrome: Chrome,
    q: QueueSummary,
    workers: usize,
    cap: i64,
    inbox: i64,
    jobs: Vec<QueueJob>,
    failed: Vec<QueueJob>,
    intel: crate::admin::system::IntelStatus,
    /// "Recent activity": the newest requests, then live over SSE.
    recent: Vec<crate::store::stats::RecentRequest>,
    /// The newest request id shown (the live feed's cursor).
    recent_max_id: i64,
}

async fn home(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    let recent = st
        .store
        .recent_requests(50, crate::store::browse::Audience::Admin)
        .await?;
    // Nothing in the last 24 h: follow from the newest row overall, so the
    // live feed does not backfill the table with old requests.
    let recent_max_id = match recent.iter().map(|r| r.id).max() {
        Some(id) => id,
        None => st.store.max_request_id().await?,
    };
    render(&HomePage {
        chrome: chrome(),
        q: st.store.queue_summary(&st.recorder).await?,
        workers: st.pace.get().max_workers,
        cap: st.pace.get().max_scans_per_hour,
        inbox: st.store.inbox_count().await?,
        jobs: st.store.queue_snapshot(25).await?,
        failed: st.store.recent_failed_jobs(10).await?,
        intel: crate::admin::system::intel_status(&st).await?,
        recent,
        recent_max_id,
    })
}

#[derive(Template)]
#[template(path = "admin_analytics.html")]
struct AnalyticsPage {
    chrome: Chrome,
    range: Range,
    a: Arc<Analytics>,
    /// Largest value per list, for the bar widths.
    max: AnalyticsMax,
}

struct AnalyticsMax {
    paths: i64,
    user_agents: i64,
    ja4: i64,
    ja4h: i64,
    ports: i64,
    products: i64,
    os: i64,
    hassh: i64,
    ja4x: i64,
    abuse: i64,
    levels: i64,
}

fn max_of<T>(v: &[T], f: impl Fn(&T) -> i64) -> i64 {
    v.iter().map(f).max().unwrap_or(0)
}

async fn analytics(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(q): Query<crate::admin::RangeQuery>,
) -> AppResult<Html<String>> {
    let range = Range::parse(q.range.as_deref());
    let a = st.stats_cache.analytics(&st.store, range).await?;
    let max = AnalyticsMax {
        paths: max_of(&a.paths, |n| n.count),
        user_agents: max_of(&a.user_agents, |n| n.count),
        ja4: max_of(&a.ja4, |n| n.count),
        ja4h: max_of(&a.ja4h, |n| n.count),
        ports: max_of(&a.ports, |p| p.ips),
        products: max_of(&a.products, |n| n.ips),
        os: max_of(&a.os_guesses, |n| n.ips),
        hassh: max_of(&a.hassh, |n| n.ips),
        ja4x: max_of(&a.ja4x, |n| n.ips),
        abuse: max_of(&a.abuse, |n| n.count),
        levels: max_of(&a.scan_levels, |n| n.count),
    };
    render(&AnalyticsPage {
        chrome: chrome(),
        range,
        a,
        max,
    })
}

#[derive(Template)]
#[template(path = "request.html")]
struct RequestPage {
    chrome: Chrome,
    d: RequestDetail,
    labels: Vec<String>,
    owasp: Vec<String>,
    can_delete: bool,
    /// The request's User-Agent header, if it sent one.
    user_agent: Option<String>,
    /// Path and query as requested, for the copy button.
    request_target: String,
    /// Other requests of the same IP, newest first.
    same_ip: Vec<RecentRequest>,
    /// Requests of other IPs with the same JA4 lately, and how many IPs.
    same_ja4: Vec<RecentRequest>,
    ja4_ips: i64,
    ja4_days: i64,
    /// Canaries this request was served (kind, value) and where its links point.
    served: Vec<(String, String)>,
    return_host: Option<String>,
    /// Reuses where this request is either side.
    reuses: Vec<crate::store::canaries::Reuse>,
}

async fn request_page(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> AppResult<Html<String>> {
    let Some(d) = st.store.request_detail(id).await? else {
        return Err(AppError::NotFound);
    };
    let labels = serde_json::from_str(&d.row.labels_json).unwrap_or_default();
    let owasp = serde_json::from_str(&d.row.owasp_json).unwrap_or_default();
    let user_agent = d
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map(|(_, v)| v.clone());
    let same_ip = st.store.related_by_ip(d.row.ip_id, d.row.id).await?;
    let (same_ja4, ja4_ips) = match &d.row.ja4 {
        Some(j) => st.store.related_by_ja4(j, d.row.ip_id).await?,
        None => (vec![], 0),
    };
    let name = d
        .row
        .answer
        .as_deref()
        .and_then(|a| a.strip_prefix("decoy:"));
    let served = match (d.row.page_token.as_deref(), name) {
        (Some(t), Some(n)) => crate::canary::served(d.row.decoy_v, t, n)
            .into_iter()
            .map(|(k, v)| (k.name().to_string(), v))
            .collect(),
        _ => vec![],
    };
    let return_host = d
        .row
        .decoy_site
        .as_deref()
        .filter(|_| !served.is_empty())
        .map(|w| {
            let site = format!("{w}.internal");
            crate::canary::site::return_host(crate::canary::site::request_host(&d.headers), &site)
        });
    let reuses = st
        .store
        .reuses(&crate::store::canaries::ReuseFilter {
            request: Some(id),
            range: Range::All,
            limit: 50,
            ..Default::default()
        })
        .await?;
    let request_target = match &d.row.query {
        Some(q) => format!("{}?{q}", d.row.path),
        None => d.row.path.clone(),
    };
    render(&RequestPage {
        chrome: chrome(),
        request_target,
        d,
        labels,
        owasp,
        can_delete: st.can_delete(),
        user_agent,
        same_ip,
        same_ja4,
        ja4_ips,
        ja4_days: RELATED_JA4_DAYS,
        served,
        return_host,
        reuses,
    })
}

/// What a delete did, for the admin.
pub(crate) fn deleted_msg(d: Deleted) -> String {
    match (d.deleted, d.hidden) {
        (n, 0) => format!("Deleted {n} record(s)."),
        (0, h) => format!(
            "Hid {h} record(s) on this node only: other nodes recorded them, so they stay in the cluster."
        ),
        (n, h) => format!(
            "Deleted {n} record(s) cluster-wide; hid {h} record(s) of other nodes on this node only."
        ),
    }
}

/// Redirect with a one-shot notice. It travels in a short-lived cookie the
/// page script shows and clears, so a crafted link cannot plant a message.
pub(crate) fn redirect_with_notice(to: &str, msg: &str) -> Response {
    redirect_with_flash("peephole_flash", to, msg)
}

/// [`redirect_with_notice`] for a failed action: shown as a warning.
pub(crate) fn redirect_with_error(to: &str, msg: &str) -> Response {
    redirect_with_flash("peephole_flash_error", to, msg)
}

fn redirect_with_flash(name: &str, to: &str, msg: &str) -> Response {
    // An error chain can be long; a cookie cannot.
    let mut end = msg.len().min(1000);
    while !msg.is_char_boundary(end) {
        end -= 1;
    }
    let enc = serde_urlencoded::to_string([("m", &msg[..end])]).unwrap_or_default();
    let cookie = format!(
        "{name}={}; Path=/; Max-Age=30; SameSite=Strict",
        enc.trim_start_matches("m=")
    );
    ([(axum::http::header::SET_COOKIE, cookie)], Redirect::to(to)).into_response()
}

/// Deleting is for standalone nodes; a cluster node refuses (the buttons
/// are not shown there).
pub(crate) fn deletes_allowed(st: &AdminState) -> AppResult<()> {
    if st.can_delete() {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "Records cannot be deleted on a cluster node; retention prunes them.".into(),
        ))
    }
}

async fn request_delete(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> AppResult<Response> {
    deletes_allowed(&st)?;
    let out = st.recorder.delete_request(id).await?;
    if out.deleted + out.hidden == 0 {
        return Err(AppError::NotFound);
    }
    Ok(redirect_with_notice("/requests", &deleted_msg(out)))
}

async fn ip_delete(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(addr): Path<String>,
) -> AppResult<Response> {
    deletes_allowed(&st)?;
    let Some(ip) = st.store.ip_by_addr(&addr).await? else {
        return Err(AppError::NotFound);
    };
    let out = st.recorder.delete_ips(&[ip.id]).await?;
    Ok(redirect_with_notice("/ips", &deleted_msg(out)))
}

#[derive(Template)]
#[template(path = "admin_fingerprints.html")]
struct FingerprintsPage {
    chrome: Chrome,
    clusters: Vec<FpCluster>,
    /// Host keys and certificates found on more than one source.
    host_keys: Vec<crate::store::hostkeys::HostKeyCluster>,
    /// `clusters` and `host_keys` for the graph.
    clusters_json: String,
}

async fn fingerprints(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
) -> AppResult<Html<String>> {
    let clusters = st.store.fingerprint_clusters().await?;
    let host_keys = st.store.host_key_clusters().await?;
    // One graph: browser fingerprints and host keys are both hubs, typed
    // by `kind` (absent: a browser fingerprint).
    let mut hubs: Vec<serde_json::Value> = clusters
        .iter()
        .map(|c| serde_json::json!({ "hash": c.hash, "ips": c.ips, "count": c.count }))
        .collect();
    hubs.extend(host_keys.iter().map(|c| {
        serde_json::json!({
            "hash": c.hash,
            "ips": c.ips,
            "count": c.count,
            "kind": if c.kind == crate::scan::hostkeys::SSH_HOSTKEY { "ssh" } else { "tls" },
        })
    }));
    render(&FingerprintsPage {
        chrome: chrome(),
        clusters_json: serde_json::to_string(&hubs).unwrap_or_else(|_| "[]".into()),
        clusters,
        host_keys,
    })
}

#[derive(serde::Deserialize, Default)]
pub struct CanaryQuery {
    pub range: Option<String>,
    pub kind: Option<String>,
    pub node: Option<String>,
    /// `same` | `other`; anything else: both.
    pub source: Option<String>,
    pub ip: Option<String>,
}

#[derive(Template)]
#[template(path = "admin_canaries.html")]
struct CanariesPage {
    chrome: Chrome,
    range: Range,
    q: CanaryQuery,
    sum: crate::store::canaries::CanarySummary,
    reuses: Vec<crate::store::canaries::Reuse>,
    kinds: Vec<&'static str>,
}

async fn canaries(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(q): Query<CanaryQuery>,
) -> AppResult<Html<String>> {
    let range = Range::parse(q.range.as_deref());
    // An address the store does not know matches no row (id 0 is never
    // used), rather than dropping the filter.
    let ip_id = match q.ip.as_deref().filter(|s| !s.is_empty()) {
        Some(a) => Some(st.store.ip_by_addr(a).await?.map_or(0, |i| i.id)),
        None => None,
    };
    let filter = crate::store::canaries::ReuseFilter {
        kind: q.kind.clone().filter(|k| !k.is_empty()),
        node: q.node.clone().filter(|n| !n.is_empty()),
        same_source: match q.source.as_deref() {
            Some("same") => Some(true),
            Some("other") => Some(false),
            _ => None,
        },
        range,
        request: None,
        ip_id,
        limit: 500,
    };
    let reuses = st.store.reuses(&filter).await?;
    let sum = st.store.canary_summary(range).await?;
    render(&CanariesPage {
        chrome: chrome(),
        range,
        q,
        sum,
        reuses,
        kinds: crate::canary::Kind::ALL_V1
            .iter()
            .map(|k| k.name())
            .chain(["legacy"])
            .collect(),
    })
}

#[derive(Template)]
#[template(path = "admin_inbox.html")]
struct InboxPage {
    chrome: Chrome,
    claims: Vec<FpClaimRow>,
    can_delete: bool,
}

async fn inbox(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    render(&InboxPage {
        chrome: chrome(),
        claims: st.store.inbox().await?,
        can_delete: st.can_delete(),
    })
}

async fn claim_delete(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> AppResult<Response> {
    deletes_allowed(&st)?;
    let out = st.recorder.delete_claim(id).await?;
    if out.deleted + out.hidden == 0 {
        return Err(AppError::NotFound);
    }
    Ok(redirect_with_notice("/admin/inbox", &deleted_msg(out)))
}

/// Parsed bulk form: checked row keys, or "everything matching the filter".
struct BulkForm<F> {
    all: bool,
    ids: Vec<String>,
    filter: F,
}

fn parse_bulk<F: serde::de::DeserializeOwned>(body: &str) -> AppResult<BulkForm<F>> {
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let filter: F =
        serde_urlencoded::from_str(body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    Ok(BulkForm {
        all: pairs.iter().any(|(k, v)| k == "all" && v == "1"),
        ids: pairs
            .into_iter()
            .filter(|(k, _)| k == "ids")
            .map(|(_, v)| v)
            .collect(),
        filter,
    })
}

async fn bulk_delete_requests(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    body: String,
) -> AppResult<Response> {
    deletes_allowed(&st)?;
    let form = parse_bulk::<RequestFilter>(&body)?;
    let mut total = Deleted::default();
    if form.all {
        // Rounds of MATCH_LIMIT, walking down the ids, so "all" means all
        // and a row that cannot be removed from here does not end the walk.
        let mut before = i64::MAX;
        loop {
            let ids = st
                .store
                .matching_request_ids_before(&form.filter, before)
                .await?;
            let Some(&last) = ids.last() else {
                break;
            };
            let out = st.recorder.delete_requests(&ids).await?;
            total.deleted += out.deleted;
            total.hidden += out.hidden;
            before = last;
        }
    } else {
        let ids: Vec<i64> = form.ids.iter().filter_map(|v| v.parse().ok()).collect();
        total = st.recorder.delete_requests(&ids).await?;
    }
    tracing::info!(
        deleted = total.deleted,
        hidden = total.hidden,
        all = form.all,
        "bulk request delete"
    );
    Ok(redirect_with_notice(
        &format!(
            "/requests?{}",
            crate::admin::public::request_qs(&form.filter)
        ),
        &deleted_msg(total),
    ))
}

async fn bulk_delete_ips(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    body: String,
) -> AppResult<Response> {
    deletes_allowed(&st)?;
    let form = parse_bulk::<IpFilter>(&body)?;
    let mut total = Deleted::default();
    if form.all {
        // Walk up the ids: IPs without records of their own (nothing to
        // delete or hide) no longer end the loop early.
        let mut after = 0;
        loop {
            let ids = st.store.matching_ip_ids_after(&form.filter, after).await?;
            let Some(&last) = ids.last() else {
                break;
            };
            let out = st.recorder.delete_ips(&ids).await?;
            total.deleted += out.deleted;
            total.hidden += out.hidden;
            after = last;
        }
    } else {
        let mut ids = vec![];
        for addr in &form.ids {
            if let Some(ip) = st.store.ip_by_addr(addr).await? {
                ids.push(ip.id);
            }
        }
        total = st.recorder.delete_ips(&ids).await?;
    }
    tracing::info!(
        deleted = total.deleted,
        hidden = total.hidden,
        all = form.all,
        "bulk ip delete"
    );
    Ok(redirect_with_notice(
        &format!("/ips?{}", crate::admin::public::ip_qs(&form.filter)),
        &deleted_msg(total),
    ))
}

#[cfg(test)]
mod delete_notice_tests {
    use super::*;

    #[test]
    fn notice_names_what_happened_and_fits_a_cookie() {
        assert_eq!(
            deleted_msg(Deleted {
                deleted: 2,
                hidden: 0
            }),
            "Deleted 2 record(s)."
        );
        assert!(
            deleted_msg(Deleted {
                deleted: 0,
                hidden: 1
            })
            .starts_with("Hid 1 record(s) on this node only")
        );
        let r = redirect_with_notice(
            "/requests",
            &deleted_msg(Deleted {
                deleted: 1,
                hidden: 3,
            }),
        );
        let c = r.headers()[axum::http::header::SET_COOKIE]
            .to_str()
            .unwrap();
        assert!(c.starts_with("peephole_flash=Deleted+1+record"), "{c}");
        let value = c.split(';').next().unwrap();
        assert!(!value.contains(' '), "cookie value must be encoded: {c}");
        assert!(c.contains("hid+3+record"), "{c}");
        let r = redirect_with_error("/admin/cluster", &"é".repeat(2000));
        let c = r.headers()[axum::http::header::SET_COOKIE]
            .to_str()
            .unwrap();
        assert!(c.starts_with("peephole_flash_error=%C3%A9"), "{c}");
        assert!(c.len() < 4096, "a long message is cut to fit a cookie");
    }
}
