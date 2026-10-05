//! Scans: pace, the live queue, the finished-job history, scan details.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::pages::{deleted_msg, deletes_allowed, redirect_with_notice};
use crate::admin::views::Chrome;
use crate::events::QueueJob;
use crate::scan::pace::{self, Pace, QueueMetrics, recommend};
use crate::store::browse::{Page, page_num};
use crate::store::inspect::{FINISHED_STATUSES, HistoryRow, JobFilter, PortRow, ScanSummary};
use askama::Template;
use axum::{
    Router,
    extract::{Form, Path, Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use std::sync::Arc;

/// Rows the live card keeps (the SSE snapshot sends as many).
pub const LIVE_ROWS: i64 = 500;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/scans", get(page))
        .route("/admin/scans/{id}", get(scan_page))
        .route("/admin/scans/{id}/xml", get(scan_xml))
        .route("/admin/scans/{id}/delete", post(scan_delete))
        .route("/admin/queue", get(queue_moved))
        .route("/admin/queue/pace", post(queue_pace))
        .route("/admin/queue/retry-failed", post(queue_retry_failed))
}

fn chrome() -> Chrome {
    Chrome::new(true, "admin")
}

#[derive(serde::Deserialize, Default)]
pub struct ScansQuery {
    pub status: Option<String>,
    pub level: Option<String>,
    #[serde(default, deserialize_with = "crate::store::browse::lenient_i64")]
    pub page: Option<i64>,
    /// Set by the redirect after saving the pace.
    pub saved: Option<String>,
    /// Set by the redirect after retrying failed jobs: how many.
    pub retried: Option<String>,
}

impl ScansQuery {
    fn filter(&self) -> JobFilter {
        JobFilter {
            status: self
                .status
                .clone()
                .filter(|s| FINISHED_STATUSES.contains(&s.as_str())),
            level: self.level.as_deref().and_then(|l| l.trim().parse().ok()),
        }
    }
}

#[derive(Template)]
#[template(path = "admin_scans.html")]
struct ScansPage {
    chrome: Chrome,
    pace: PaceView,
    jobs: Vec<QueueJob>,
    /// Queued + running in all; more than `jobs` holds when over `LIVE_ROWS`.
    active_total: i64,
    history: Page<HistoryRow>,
    f: JobFilter,
    statuses: [&'static str; 4],
    /// Query string for the pagination links ("status=failed&").
    qs: String,
    /// This node and the cluster's scanners, for the pace table.
    scanners: Vec<crate::admin::cluster::MemberView>,
}

async fn render_page(st: &AdminState, q: &ScansQuery, pace: PaceView) -> AppResult<Html<String>> {
    let f = q.filter();
    let mut qs = String::new();
    if let Some(s) = &f.status {
        qs.push_str(&format!("status={s}&"));
    }
    if let Some(l) = f.level {
        qs.push_str(&format!("level={l}&"));
    }
    let summary = st.store.queue_summary(&st.recorder).await?;
    render(&ScansPage {
        chrome: chrome(),
        pace,
        jobs: st.store.active_jobs(LIVE_ROWS).await?,
        active_total: summary.queued + summary.running,
        history: st.store.job_history(&f, page_num(q.page)).await?,
        f,
        statuses: FINISHED_STATUSES,
        qs,
        scanners: crate::admin::cluster::scanner_rows(st).await?,
    })
}

async fn page(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(q): Query<ScansQuery>,
) -> AppResult<Html<String>> {
    let notice = match (
        &q.saved,
        q.retried.as_deref().and_then(|n| n.parse::<u64>().ok()),
    ) {
        (Some(_), _) => Some("Pace saved. Workers apply it on their next pass.".to_string()),
        (_, Some(n)) => Some(format!(
            "{n} failed {} back in the queue.",
            if n == 1 { "job is" } else { "jobs are" }
        )),
        _ => None,
    };
    let pace = pace_view(&st, notice, None).await?;
    render_page(&st, &q, pace).await
}

/// The Queue page became part of Scans.
async fn queue_moved(Query(q): Query<ScansQuery>) -> Redirect {
    match q.filter().status {
        Some(s) => Redirect::permanent(&format!("/admin/scans?status={s}")),
        None => Redirect::permanent("/admin/scans"),
    }
}

/// Queue growth, current pace and the recommendation, pre-formatted.
pub(crate) struct PaceView {
    pub(crate) current: Pace,
    pub(crate) rec: Pace,
    pub(crate) rec_differs: bool,
    pub(crate) paused: bool,
    pub(crate) growing: bool,
    pub(crate) m: QueueMetrics,
    pub(crate) arrival: String,
    pub(crate) capacity: String,
    /// Jobs that actually left the queue per hour, recent window.
    pub(crate) throughput: String,
    pub(crate) drain_window_h: i64,
    /// In a cluster with other live scanners: how the capacity splits.
    pub(crate) cluster_note: Option<String>,
    pub(crate) net: String,
    pub(crate) drain: String,
    pub(crate) cadence: String,
    pub(crate) rec_cadence: String,
    pub(crate) scan_secs: String,
    pub(crate) scan_secs_measured: bool,
    pub(crate) oldest: String,
    pub(crate) arrivals_json: String,
    pub(crate) completions_json: String,
    pub(crate) max_workers: usize,
    pub(crate) max_per_hour: i64,
    pub(crate) timeout_min: String,
    pub(crate) rec_timeout_min: String,
    pub(crate) min_timeout_min: u64,
    pub(crate) max_timeout_min: u64,
    /// Level-4 limit at the current timeout, e.g. "120".
    pub(crate) level4_timeout_min: String,
    /// Share of last-24h jobs that hit the timeout, e.g. "25%".
    pub(crate) timeout_share: String,
    pub(crate) timeouts_high: bool,
    pub(crate) notice: Option<String>,
    pub(crate) error: Option<String>,
    /// Distributed mode on a node without the scanner role: its own pace
    /// does nothing; scanners are paced on the Cluster page.
    pub(crate) not_scanning: bool,
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

pub(crate) async fn pace_view(
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

/// Retry the last week's failed jobs (one per IP, none with a pending job).
async fn queue_retry_failed(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
) -> AppResult<Redirect> {
    let n = st.recorder.requeue_failed_everywhere(7).await?;
    tracing::info!(requeued = n, "retry failed scans");
    Ok(Redirect::to(&format!(
        "/admin/scans?status=failed&retried={n}"
    )))
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
        Ok(()) => Ok(Redirect::to("/admin/scans?saved=1").into_response()),
        Err(e) => {
            let pace = pace_view(&st, None, Some(e)).await?;
            let body = render_page(&st, &ScansQuery::default(), pace).await?;
            Ok((StatusCode::BAD_REQUEST, body).into_response())
        }
    }
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
