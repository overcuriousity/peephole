//! Authenticated admin pages. Every handler takes `SessionUser` first.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::Chrome;
use crate::events::QueueJob;
use crate::store::browse::{Page, page_num};
use crate::store::inspect::{
    FpClaimRow, FpCluster, PortRow, QueueSummary, RequestDetail, ScanSummary,
};
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
        .route("/admin/requests/{id}", get(request_page))
        .route("/admin/requests/{id}/delete", post(request_delete))
        .route("/admin/ips/{addr}/delete", post(ip_delete))
        .route("/admin/scans", get(scans))
        .route("/admin/scans/{id}", get(scan_page))
        .route("/admin/scans/{id}/xml", get(scan_xml))
        .route("/admin/scans/{id}/delete", post(scan_delete))
        .route("/admin/fingerprints", get(fingerprints))
        .route("/admin/inbox", get(inbox))
        .route("/admin/claims/{id}/delete", post(claim_delete))
        .route("/admin/export", get(export_page))
        .route("/admin/export/download", get(export_download))
        .route("/admin/keys", get(keys))
        .route("/admin/keys/delete", post(key_delete))
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
        workers: st.cfg.scan.max_workers,
        cap: st.cfg.scan.max_scans_per_hour,
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
}

#[derive(Template)]
#[template(path = "admin_queue.html")]
struct QueuePage {
    chrome: Chrome,
    jobs: Vec<QueueJob>,
    f: QueueFilter,
    statuses: [&'static str; 4],
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
    render(&QueuePage {
        chrome: chrome(),
        jobs,
        f,
        statuses: ["queued", "running", "done", "failed"],
    })
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

async fn request_delete(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> AppResult<Redirect> {
    if !st.store.delete_request(id).await? {
        return Err(AppError::NotFound);
    }
    Ok(Redirect::to("/requests"))
}

async fn ip_delete(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(addr): Path<String>,
) -> AppResult<Redirect> {
    let Some(ip) = st.store.ip_by_addr(&addr).await? else {
        return Err(AppError::NotFound);
    };
    st.store.delete_ip(ip.id).await?;
    Ok(Redirect::to("/ips"))
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
) -> AppResult<Redirect> {
    if !st.store.delete_scan(id).await? {
        return Err(AppError::NotFound);
    }
    Ok(Redirect::to("/admin/scans"))
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
) -> AppResult<Redirect> {
    if !st.store.delete_claim(id).await? {
        return Err(AppError::NotFound);
    }
    Ok(Redirect::to("/admin/inbox"))
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
    let filter = crate::export::ExportFilter {
        from: q.get("from").cloned(),
        to: q.get("to").cloned(),
        ip: q.get("ip").cloned(),
        label: q.get("label").cloned(),
        min_severity: q.get("min_severity").and_then(|s| s.parse().ok()),
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
        // Guard: never delete the last remaining key (would lock the admin out).
        if state
            .store
            .load_credentials()
            .await
            .map(|c| c.len() > 1)
            .unwrap_or(false)
        {
            let _ = state.store.delete_credential(&bytes).await;
        }
    }
    Redirect::to("/admin/keys")
}
