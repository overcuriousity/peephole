//! Authenticated admin pages. Every handler takes `SessionUser` first.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::Chrome;
use crate::events::QueueJob;
use crate::scan::pace::{self, Pace, QueueMetrics, recommend};
use crate::store::browse::{IpFilter, Page, RequestFilter, page_num};
use crate::store::inspect::{
    FpClaimRow, FpCluster, PortRow, QueueSummary, RequestDetail, ScanSummary,
};
use crate::store::recorder::Deleted;
use crate::store::stats::intel_stale;
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
        .route("/admin/inbox", get(inbox))
        .route("/admin/claims/{id}/delete", post(claim_delete))
        .route("/admin/export", get(export_page))
        .route("/admin/export/download", get(export_download))
        .route("/admin/export/intel", get(export_intel))
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
    inbox: usize,
    jobs: Vec<QueueJob>,
    failed: Vec<QueueJob>,
    tor_fetch: String,
    maxmind_fetch: String,
    stale: bool,
}

async fn home(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    let intel: HashMap<String, String> =
        sqlx::query_as::<_, (String, String)>("SELECT key, value FROM intel_meta")
            .fetch_all(&st.store.pool)
            .await?
            .into_iter()
            .collect();
    let stale = intel_stale(&intel);
    let fetched = |k: &str| intel.get(k).cloned().unwrap_or_else(|| "never".into());
    render(&HomePage {
        chrome: chrome(),
        q: st.store.queue_summary().await?,
        workers: st.pace.get().max_workers,
        cap: st.pace.get().max_scans_per_hour,
        inbox: st.store.inbox().await?.len(),
        jobs: st.store.queue_snapshot(25).await?,
        failed: st.store.recent_failed_jobs(10).await?,
        tor_fetch: fetched("tor_last_fetch"),
        maxmind_fetch: fetched("maxmind_last_fetch"),
        stale,
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
    let r = recommend(&m, current);
    Ok(PaceView {
        current,
        rec: r.pace,
        rec_differs: r.pace != current,
        paused: current.paused(),
        growing: r.growing(),
        arrival: fmt_rate(r.arrival_per_hour),
        capacity: fmt_rate(r.capacity_per_hour),
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
        .parse::<usize>()
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
            max_workers: w,
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
#[template(path = "request.html")]
struct RequestPage {
    chrome: Chrome,
    d: RequestDetail,
    labels: Vec<String>,
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
    render(&RequestPage {
        chrome: chrome(),
        d,
        labels,
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
fn redirect_with_notice(to: &str, msg: &str) -> Response {
    let enc = serde_urlencoded::to_string([("m", msg)]).unwrap_or_default();
    let cookie = format!(
        "peephole_flash={}; Path=/; Max-Age=30; SameSite=Strict",
        enc.trim_start_matches("m=")
    );
    ([(axum::http::header::SET_COOKIE, cookie)], Redirect::to(to)).into_response()
}

async fn request_delete(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> AppResult<Response> {
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
}

async fn fingerprints(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
) -> AppResult<Html<String>> {
    render(&FingerprintsPage {
        chrome: chrome(),
        clusters: st.store.fingerprint_clusters().await?,
    })
}

#[derive(Template)]
#[template(path = "admin_inbox.html")]
struct InboxPage {
    chrome: Chrome,
    claims: Vec<FpClaimRow>,
}

async fn inbox(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    render(&InboxPage {
        chrome: chrome(),
        claims: st.store.inbox().await?,
    })
}

async fn claim_delete(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> AppResult<Response> {
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

/// Enrichment results as JSON Lines: what each provider said about each
/// IP, when, from which data version, and which node looked it up.
async fn export_intel(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let names: HashMap<Vec<u8>, String> = match st.recorder.node() {
        Some(node) => crate::cluster::members::all(&node.store)
            .await?
            .into_iter()
            .map(|m| (m.id.0.to_vec(), m.name))
            .collect(),
        None => HashMap::new(),
    };
    let mut out = String::new();
    for (ip, provider, fetched_at, source_version, origin, data_json) in
        st.store.intel_export(100_000).await?
    {
        let node = match names.get(&origin) {
            Some(n) => n.clone(),
            None if origin.is_empty() => "this node".to_string(),
            None => data_encoding::HEXLOWER.encode(&origin[..origin.len().min(6)]),
        };
        let data: serde_json::Value =
            serde_json::from_str(&data_json).unwrap_or(serde_json::Value::Null);
        out.push_str(
            &serde_json::json!({
                "ip": ip, "provider": provider, "fetched_at": fetched_at,
                "source_version": source_version, "node": node, "data": data,
            })
            .to_string(),
        );
        out.push('\n');
    }
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/x-ndjson"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"peephole-enrichment.jsonl\"",
            ),
        ],
        out,
    )
        .into_response())
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
    let rows = match state.store.export_requests(&filter).await {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let (body, ext, mime) = match q.get("format").map(String::as_str) {
        Some("csv") => (
            crate::export::requests_csv(&rows).into_bytes(),
            "csv",
            "text/csv".to_string(),
        ),
        Some("jsonl") => (
            crate::export::requests_timesketch(&rows).into_bytes(),
            "jsonl",
            "application/x-ndjson".to_string(),
        ),
        Some("parquet") => match crate::export::parquet::requests_parquet(&rows) {
            Ok(b) => (b, "parquet", "application/octet-stream".to_string()),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        _ => return (StatusCode::BAD_REQUEST, "format must be csv|jsonl|parquet").into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, mime),
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
    let form = parse_bulk::<RequestFilter>(&body)?;
    let mut total = Deleted::default();
    if form.all {
        // Rounds of MATCH_LIMIT until nothing matches, so "all" means all.
        loop {
            let ids = st.store.matching_request_ids(&form.filter).await?;
            if ids.is_empty() {
                break;
            }
            let out = st.recorder.delete_requests(&ids).await?;
            total.deleted += out.deleted;
            total.hidden += out.hidden;
            // Stop when a round changed nothing: what still matches cannot
            // be removed from here.
            if out.deleted + out.hidden == 0
                || (ids.len() as i64) < crate::store::browse::MATCH_LIMIT
            {
                break;
            }
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
    let form = parse_bulk::<IpFilter>(&body)?;
    let mut total = Deleted::default();
    if form.all {
        loop {
            let ids = st.store.matching_ip_ids(&form.filter).await?;
            if ids.is_empty() {
                break;
            }
            let out = st.recorder.delete_ips(&ids).await?;
            total.deleted += out.deleted;
            total.hidden += out.hidden;
            if out.deleted + out.hidden == 0
                || (ids.len() as i64) < crate::store::browse::MATCH_LIMIT
            {
                break;
            }
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
    }
}
