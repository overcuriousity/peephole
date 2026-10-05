//! Authenticated admin pages. Every handler takes `SessionUser` first.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::Chrome;
use crate::events::QueueJob;
use crate::scan::pace::{self, Pace, QueueMetrics, recommend};
use crate::store::analytics::{Analytics, RELATED_JA4_DAYS};
use crate::store::browse::{IpFilter, Page, RequestFilter, page_num};
use crate::store::inspect::{
    FpClaimRow, FpCluster, PortRow, QueueSummary, RequestDetail, ScanSummary,
};
use crate::store::recorder::Deleted;
use crate::store::stats::{Range, RecentRequest};
use askama::Template;
use axum::{
    Router,
    extract::{Form, Path, Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use std::collections::HashMap;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin", get(home))
        .route("/admin/analytics", get(analytics))
        .route("/admin/queue", get(queue))
        .route("/admin/queue/pace", post(queue_pace))
        .route("/admin/queue/retry-failed", post(queue_retry_failed))
        .route("/admin/requests/{id}", get(request_page))
        .route("/admin/requests/{id}/delete", post(request_delete))
        .route("/admin/ips/{addr}/delete", post(ip_delete))
        .route("/admin/requests/bulk-delete", post(bulk_delete_requests))
        .route("/admin/ips/bulk-delete", post(bulk_delete_ips))
        .route("/admin/scans", get(scans))
        .route("/admin/scans/{id}", get(scan_page))
        .route("/admin/scans/{id}/xml", get(scan_xml))
        .route("/admin/scans/{id}/delete", post(scan_delete))
        .route("/admin/fingerprints", get(fingerprints))
        .route("/admin/canaries", get(canaries))
        .route("/admin/inbox", get(inbox))
        .route("/admin/claims/{id}/delete", post(claim_delete))
        .route("/admin/export", get(export_page))
        .route("/admin/export/download", get(export_download))
        .route("/admin/keys", get(keys))
        .route("/admin/keys/delete", post(key_delete))
}

/// Job states the queue filter offers.
const STATUSES: [&str; 6] = [
    "queued",
    "running",
    "done",
    "failed",
    "superseded",
    "refused",
];

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

#[derive(serde::Deserialize, Default)]
pub struct QueueFilter {
    pub status: Option<String>,
    pub level: Option<String>,
    /// Set by the redirect after saving the pace.
    pub saved: Option<String>,
    /// Set by the redirect after retrying failed jobs: how many.
    pub retried: Option<String>,
}

#[derive(Template)]
#[template(path = "admin_queue.html")]
struct QueuePage {
    chrome: Chrome,
    jobs: Vec<QueueJob>,
    f: QueueFilter,
    statuses: [&'static str; 6],
    pace: PaceView,
}

/// Queue growth, current pace and the recommendation, pre-formatted.
struct PaceView {
    current: Pace,
    rec: Pace,
    rec_differs: bool,
    paused: bool,
    growing: bool,
    m: QueueMetrics,
    arrival: String,
    capacity: String,
    /// Jobs that actually left the queue per hour, recent window.
    throughput: String,
    drain_window_h: i64,
    /// In a cluster with other live scanners: how the capacity splits.
    cluster_note: Option<String>,
    net: String,
    drain: String,
    cadence: String,
    rec_cadence: String,
    scan_secs: String,
    scan_secs_measured: bool,
    oldest: String,
    arrivals_json: String,
    completions_json: String,
    max_workers: usize,
    max_per_hour: i64,
    timeout_min: String,
    rec_timeout_min: String,
    min_timeout_min: u64,
    max_timeout_min: u64,
    /// Level-4 limit at the current timeout, e.g. "120".
    level4_timeout_min: String,
    /// Share of last-24h jobs that hit the timeout, e.g. "25%".
    timeout_share: String,
    timeouts_high: bool,
    notice: Option<String>,
    error: Option<String>,
    /// Distributed mode on a node without the scanner role: its own pace
    /// does nothing; scanners are paced on the Cluster page.
    not_scanning: bool,
}

/// Seconds as minutes for the form: "15", or "1.5" when not whole.
fn minutes(secs: u64) -> String {
    if secs.is_multiple_of(60) {
        (secs / 60).to_string()
    } else {
        format!("{:.1}", secs as f64 / 60.0)
    }
}

fn fmt_rate(v: f64) -> String {
    if v >= 10.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    }
}

fn fmt_secs(secs: f64) -> String {
    let s = secs.round() as i64;
    match s {
        s if s < 90 => format!("{s} s"),
        s if s < 90 * 60 => format!("{:.0} min", s as f64 / 60.0),
        s if s < 48 * 3600 => format!("{:.1} h", s as f64 / 3600.0),
        s => format!("{:.1} days", s as f64 / 86400.0),
    }
}

fn cadence(p: Pace) -> String {
    match p.interval() {
        Some(d) => format!("one start every {}", fmt_secs(d.as_secs_f64())),
        None => "paused".into(),
    }
}

async fn pace_view(
    st: &AdminState,
    notice: Option<String>,
    error: Option<String>,
) -> AppResult<PaceView> {
    let m = st.store.queue_metrics().await?;
    let current = st.pace.get();
    let scan_secs = m.avg_scan_secs.unwrap_or(pace::DEFAULT_SCAN_SECS);
    let others = st
        .recorder
        .node()
        .map(|n| pace::others(n, scan_secs))
        .unwrap_or_default();
    let r = recommend(&m, current, others);
    Ok(PaceView {
        current,
        rec: r.pace,
        rec_differs: r.pace != current,
        paused: current.paused(),
        growing: r.growing(),
        arrival: fmt_rate(r.arrival_per_hour),
        capacity: fmt_rate(r.capacity_per_hour),
        throughput: fmt_rate(r.throughput_per_hour),
        drain_window_h: pace::DRAIN_WINDOW_HOURS,
        cluster_note: (others.scanners > 0).then(|| {
            format!(
                "{} here + {} from {} other scanner{}",
                fmt_rate(r.own_capacity_per_hour),
                fmt_rate(others.capacity_per_hour),
                others.scanners,
                if others.scanners == 1 { "" } else { "s" }
            )
        }),
        net: format!(
            "{}{}",
            if r.net_growth_per_hour > 0.0 { "+" } else { "" },
            fmt_rate(r.net_growth_per_hour)
        ),
        drain: match r.drain_hours {
            Some(0.0) => "empty".into(),
            Some(h) => fmt_secs(h * 3600.0),
            None => "never at this pace".into(),
        },
        cadence: cadence(current),
        rec_cadence: cadence(r.pace),
        scan_secs: m
            .avg_scan_secs
            .map(fmt_secs)
            .unwrap_or_else(|| fmt_secs(pace::DEFAULT_SCAN_SECS)),
        scan_secs_measured: r.scan_secs_measured,
        oldest: m
            .oldest_queued_secs
            .map(|s| fmt_secs(s as f64))
            .unwrap_or_else(|| "—".into()),
        arrivals_json: serde_json::to_string(&m.hourly_arrivals).unwrap_or_default(),
        completions_json: serde_json::to_string(&m.hourly_completions).unwrap_or_default(),
        m,
        max_workers: pace::MAX_WORKERS,
        max_per_hour: pace::MAX_PER_HOUR,
        timeout_min: minutes(current.timeout_secs),
        rec_timeout_min: minutes(r.pace.timeout_secs),
        min_timeout_min: pace::MIN_TIMEOUT / 60,
        max_timeout_min: pace::MAX_TIMEOUT / 60,
        level4_timeout_min: minutes(pace::level_timeout_secs(
            current.timeout_secs,
            4,
            st.cfg.scan.level4_timeout_factor,
        )),
        timeout_share: format!("{:.0}%", r.timeout_share * 100.0),
        timeouts_high: r.pace.timeout_secs > current.timeout_secs,
        notice,
        error,
        not_scanning: st.recorder.node().is_some() && !st.settings.roles().scanner,
    })
}

async fn queue(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(f): Query<QueueFilter>,
) -> AppResult<Html<String>> {
    let mut jobs = st.store.queue_snapshot(500).await?;
    if let Some(s) = f.status.as_deref().filter(|s| !s.is_empty()) {
        jobs.retain(|j| j.status == s);
    }
    if let Some(l) = f
        .level
        .as_deref()
        .and_then(|l| l.trim().parse::<i64>().ok())
    {
        jobs.retain(|j| j.level == l);
    }
    let notice = match (
        &f.saved,
        f.retried.as_deref().and_then(|n| n.parse::<u64>().ok()),
    ) {
        (Some(_), _) => Some("Pace saved. Workers apply it on their next pass.".to_string()),
        (_, Some(n)) => Some(format!(
            "{n} failed {} back in the queue.",
            if n == 1 { "job is" } else { "jobs are" }
        )),
        _ => None,
    };
    let pace = pace_view(&st, notice, None).await?;
    render(&QueuePage {
        chrome: chrome(),
        jobs,
        f,
        statuses: STATUSES,
        pace,
    })
}

/// Retry the last week's failed jobs (one per IP, none with a pending job).
async fn queue_retry_failed(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
) -> AppResult<Redirect> {
    let n = st.recorder.requeue_failed_everywhere(7).await?;
    tracing::info!(requeued = n, "retry failed scans");
    Ok(Redirect::to(&format!("/admin/queue?retried={n}")))
}

#[derive(serde::Deserialize)]
struct PaceForm {
    max_workers: String,
    max_scans_per_hour: String,
    /// Minutes; absent keeps the current timeout.
    timeout_minutes: Option<String>,
}

async fn queue_pace(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(form): Form<PaceForm>,
) -> AppResult<Response> {
    let parsed = form
        .max_workers
        .trim()
        .parse::<u32>()
        .ok()
        .zip(form.max_scans_per_hour.trim().parse::<i64>().ok())
        .zip(match form.timeout_minutes.as_deref().map(str::trim) {
            None | Some("") => Some(st.pace.get().timeout_secs),
            Some(m) => m
                .parse::<f64>()
                .ok()
                .filter(|m| m.is_finite() && *m > 0.0)
                .map(|m| (m * 60.0).round() as u64),
        })
        .map(|((w, h), t)| Pace {
            max_workers: w as usize,
            max_scans_per_hour: h,
            timeout_secs: t,
        });
    let outcome = match parsed {
        Some(p) => st
            .settings
            .apply(
                &crate::settings::Changes {
                    max_workers: Some(p.max_workers as u32),
                    max_scans_per_hour: Some(p.max_scans_per_hour),
                    timeout_secs: Some(p.timeout_secs),
                    ..Default::default()
                },
                None,
            )
            .await?
            .map(|_| ()),
        None => Err("workers, scans per hour and timeout must be numbers".into()),
    };
    match outcome {
        Ok(()) => Ok(Redirect::to("/admin/queue?saved=1").into_response()),
        Err(e) => {
            let pace = pace_view(&st, None, Some(e)).await?;
            let body = render(&QueuePage {
                chrome: chrome(),
                jobs: st.store.queue_snapshot(500).await?,
                f: QueueFilter::default(),
                statuses: STATUSES,
                pace,
            })?;
            Ok((StatusCode::BAD_REQUEST, body).into_response())
        }
    }
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
fn deleted_msg(d: Deleted) -> String {
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
fn deletes_allowed(st: &AdminState) -> AppResult<()> {
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

#[derive(serde::Deserialize, Default)]
pub struct PageOnly {
    #[serde(default, deserialize_with = "crate::store::browse::lenient_i64")]
    pub page: Option<i64>,
}

#[derive(Template)]
#[template(path = "admin_scans.html")]
struct ScansPage {
    chrome: Chrome,
    page: Page<ScanSummary>,
    qs: String,
}

async fn scans(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(q): Query<PageOnly>,
) -> AppResult<Html<String>> {
    render(&ScansPage {
        chrome: chrome(),
        page: st.store.list_scans(page_num(q.page)).await?,
        qs: String::new(),
    })
}

#[derive(Template)]
#[template(path = "admin_scan.html")]
struct ScanPage {
    chrome: Chrome,
    s: ScanSummary,
    ports: Vec<PortRow>,
    keys: Vec<crate::store::hostkeys::HostKeyRow>,
    can_delete: bool,
}

async fn scan_page(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> AppResult<Html<String>> {
    let Some(s) = st.store.scan_by_id(id).await? else {
        return Err(AppError::NotFound);
    };
    let ports = st.store.ports_for_scan(id).await?;
    render(&ScanPage {
        chrome: chrome(),
        s,
        ports,
        keys: st.store.host_keys_for_scan(id).await?,
        can_delete: st.can_delete(),
    })
}

async fn scan_xml(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> AppResult<Response> {
    let Some(xml) = st.store.scan_raw_xml(id).await? else {
        return Err(AppError::NotFound);
    };
    Ok((
        [
            (header::CONTENT_TYPE, "application/xml".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"peephole-scan-{id}.xml\""),
            ),
        ],
        xml,
    )
        .into_response())
}

async fn scan_delete(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> AppResult<Response> {
    deletes_allowed(&st)?;
    let out = st.recorder.delete_scan(id).await?;
    if out.deleted + out.hidden == 0 {
        return Err(AppError::NotFound);
    }
    Ok(redirect_with_notice("/admin/scans", &deleted_msg(out)))
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

#[derive(Template)]
#[template(path = "admin_export.html")]
struct ExportPage {
    chrome: Chrome,
}

async fn export_page(_u: SessionUser) -> AppResult<Html<String>> {
    render(&ExportPage { chrome: chrome() })
}

async fn export_download(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    // The form submits blank fields; blank means "no filter".
    let field = |k: &str| q.get(k).map(|v| v.trim()).filter(|v| !v.is_empty());
    let filter = crate::export::ExportFilter {
        from: field("from").map(|v| crate::store::browse::ts_bound(v, false)),
        to: field("to").map(|v| crate::store::browse::ts_bound(v, true)),
        ip: field("ip").map(crate::store::browse::canonical_ip),
        label: field("label").map(str::to_string),
        min_severity: field("min_severity").and_then(|s| s.parse().ok()),
    };
    use crate::export::Format;
    let (format, ext, mime) = match q.get("format").map(String::as_str) {
        Some("csv") => (Format::Csv, "csv", "text/csv"),
        Some("jsonl") => (Format::Jsonl, "jsonl", "application/x-ndjson"),
        Some("parquet") => (Format::Parquet, "parquet", "application/octet-stream"),
        _ => return (StatusCode::BAD_REQUEST, "format must be csv|jsonl|parquet").into_response(),
    };
    let mode = match q.get("mode").map(String::as_str) {
        None | Some("" | "full") => crate::export::Mode::Full,
        Some("redistributable") => crate::export::Mode::Redistributable,
        _ => return (StatusCode::BAD_REQUEST, "mode must be full|redistributable").into_response(),
    };
    let names = match state.recorder.node() {
        Some(node) => match crate::cluster::members::all(&node.store).await {
            Ok(m) => m.into_iter().map(|m| (m.id.0.to_vec(), m.name)).collect(),
            Err(e) => {
                tracing::warn!(?e, "export: reading member names");
                HashMap::new()
            }
        },
        None => HashMap::new(),
    };
    // Streamed, uncapped: rows are read and written page by page.
    let body = axum::body::Body::from_stream(crate::export::stream_requests(
        state.store.clone(),
        filter,
        format,
        crate::export::ExportOptions { mode, names },
    ));
    (
        [
            (header::CONTENT_TYPE, mime.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"peephole-export.{ext}\""),
            ),
        ],
        body,
    )
        .into_response()
}

struct KeyRow {
    id: String,
    short: String,
    label: String,
    created: String,
}

#[derive(Template)]
#[template(path = "admin_keys.html")]
struct KeysPage {
    chrome: Chrome,
    keys: Vec<KeyRow>,
    can_delete: bool,
}

async fn keys(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    let keys: Vec<KeyRow> = st
        .store
        .list_credential_labels()
        .await?
        .into_iter()
        .map(|(id, label, created)| KeyRow {
            short: id.chars().take(16).collect(),
            id,
            label,
            created,
        })
        .collect();
    render(&KeysPage {
        chrome: chrome(),
        can_delete: keys.len() > 1,
        keys,
    })
}

#[derive(serde::Deserialize)]
pub struct KeyDeleteForm {
    cred_id: String,
}

async fn key_delete(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Form(f): Form<KeyDeleteForm>,
) -> Redirect {
    // SQLite hex() is uppercase; normalize before decoding.
    if let Ok(bytes) = data_encoding::HEXLOWER.decode(f.cred_id.to_lowercase().as_bytes()) {
        // Never delete the last remaining key (would lock the admin out). The
        // check and delete are one atomic statement, so two concurrent deletes
        // cannot both pass and leave zero keys.
        let _ = state.store.delete_credential_keeping_last(&bytes).await;
    }
    Redirect::to("/admin/keys")
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
