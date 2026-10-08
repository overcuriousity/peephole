//! Scans: pace, the live queue, the finished-job history, scan details.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::pages::{deleted_msg, deletes_allowed, redirect_with_notice};
use crate::admin::views::Chrome;
use crate::cluster::identity::NodeId;
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
    let qs = history_qs(&f);
    let summary = st.store.queue_summary(&st.recorder).await?;
    let mut history = st.store.job_history(&f, page_num(q.page)).await?;
    if let Some(node) = st.recorder.node() {
        let name = crate::scan::handout::names(node);
        add_handouts(&st.store.read, &name, &mut history.items).await?;
    }
    render(&ScansPage {
        chrome: chrome(),
        pace,
        jobs: st.store.active_jobs(LIVE_ROWS).await?,
        active_total: summary.queued + summary.running,
        history,
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
    let notice = q
        .saved
        .as_ref()
        .map(|_| "Pace saved. Workers apply it on their next pass.".to_string());
    let pace = pace_view(&st, notice, None).await?;
    render_page(&st, &q, pace).await
}

/// The history filter as a query string prefix ("status=failed&level=3&"),
/// from validated values only.
fn history_qs(f: &JobFilter) -> String {
    let mut qs = String::new();
    if let Some(s) = &f.status {
        qs.push_str(&format!("status={s}&"));
    }
    if let Some(l) = f.level {
        qs.push_str(&format!("level={l}&"));
    }
    qs
}

/// The Queue page became part of Scans; its filter and page carry over.
async fn queue_moved(Query(q): Query<ScansQuery>) -> Redirect {
    let mut qs = history_qs(&q.filter());
    if let Some(p) = q.page.filter(|p| *p > 1) {
        qs.push_str(&format!("page={p}&"));
    }
    if qs.is_empty() {
        Redirect::permanent("/admin/scans")
    } else {
        Redirect::permanent(&format!(
            "/admin/scans?{}#history",
            qs.trim_end_matches('&')
        ))
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
    /// Most level-4 scans at once at the current worker count.
    pub(crate) level4_cap: usize,
    /// Share of last-24h jobs that hit the timeout, e.g. "25%".
    pub(crate) timeout_share: String,
    pub(crate) timeouts_high: bool,
    pub(crate) notice: Option<String>,
    pub(crate) error: Option<String>,
    /// Distributed mode on a node without the scanner role: its own pace
    /// does nothing; scanners are paced in the Scans page's Scanners table.
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
        level4_cap: pace::level4_cap(current.max_workers, st.cfg.scan.level4_max_share),
        timeout_share: format!("{:.0}%", r.timeout_share * 100.0),
        timeouts_high: r.pace.timeout_secs > current.timeout_secs,
        notice,
        error,
        not_scanning: st.recorder.node().is_some() && !st.settings.roles().scanner,
    })
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
    /// When this scan is an audit: the page of the scan it checks.
    audit_of: Option<i64>,
    /// Audits of this scan: `(auditor, result)`.
    audits: Vec<(String, String)>,
    /// Why the job went to its scanner (`scan::handout`).
    handed_out: Option<String>,
}

/// Why the job of scan `scan_id` went to its scanner: the record when
/// `me` was its arbiter, a pointer to the arbiter otherwise. None for a
/// scan without a job, or a grant from before the record existed.
pub(crate) async fn handed_out(
    pool: &sqlx::SqlitePool,
    me: NodeId,
    name: &(dyn Fn(&NodeId) -> String + Sync),
    scan_id: i64,
) -> anyhow::Result<Option<String>> {
    let job: Option<(String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT j.uid, j.arbiter FROM scans s JOIN scan_jobs j ON j.uid = s.job_uid WHERE s.id = ?",
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;
    let Some((uid, Some(arbiter))) = job else {
        return Ok(None);
    };
    let Ok(arbiter) = NodeId::from_slice(&arbiter) else {
        return Ok(None);
    };
    if arbiter != me {
        return Ok(Some(format!(
            "Handed out by {}; the reason is on that node.",
            name(&arbiter)
        )));
    }
    Ok(
        crate::scan::handout::latest(pool, std::slice::from_ref(&uid))
            .await?
            .get(&uid)
            .map(|h| crate::scan::handout::describe(h, name)),
    )
}

/// Fill in why each job of `rows` went to its scanner, where this node
/// recorded it (only its own grants are recorded here).
pub(crate) async fn add_handouts(
    pool: &sqlx::SqlitePool,
    name: &(dyn Fn(&NodeId) -> String + Sync),
    rows: &mut [HistoryRow],
) -> anyhow::Result<()> {
    let uids: Vec<String> = rows.iter().map(|r| r.uid.clone()).collect();
    let got = crate::scan::handout::latest(pool, &uids).await?;
    for r in rows {
        r.handout = got
            .get(&r.uid)
            .map(|h| crate::scan::handout::describe(h, name));
    }
    Ok(())
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
    let audit_of: Option<i64> = match &s.audit_of {
        Some(uid) => {
            sqlx::query_scalar("SELECT id FROM scans WHERE uid = ?")
                .bind(uid)
                .fetch_optional(&st.store.read)
                .await?
        }
        None => None,
    };
    let audits: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT (SELECT name FROM members m WHERE m.id = a.origin), a.audit_result
         FROM scans a WHERE a.audit_of = (SELECT uid FROM scans WHERE id = ?) ORDER BY a.id",
    )
    .bind(id)
    .fetch_all(&st.store.read)
    .await?;
    let handed_out = match st.recorder.node() {
        Some(node) => {
            let name = crate::scan::handout::names(node);
            handed_out(&st.store.read, node.id(), &name, id).await?
        }
        None => None,
    };
    render(&ScanPage {
        chrome: chrome(),
        handed_out,
        s,
        ports,
        keys: st.store.host_keys_for_scan(id).await?,
        can_delete: st.can_delete(),
        audit_of,
        audits: audits
            .into_iter()
            .map(|(n, r)| {
                (
                    n.unwrap_or_else(|| "another node".into()),
                    r.unwrap_or_else(|| "not compared yet".into()),
                )
            })
            .collect(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::handout::{Handout, Reason};

    const ME: NodeId = NodeId([1; 32]);
    const FAST: NodeId = NodeId([2; 32]);
    const OTHER: NodeId = NodeId([3; 32]);

    fn name(id: &NodeId) -> String {
        match id.0[0] {
            2 => "Fast".into(),
            3 => "Other".into(),
            _ => "?".into(),
        }
    }

    /// A finished job `uid` of `arbiter`, with its scan; the scan's id.
    async fn scanned(store: &crate::store::Store, uid: &str, arbiter: NodeId) -> i64 {
        let ip = store
            .upsert_ip("203.0.113.7".parse().unwrap())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO scan_jobs (uid, origin, arbiter, hlc, ip_id, level, status, queued_at, scanner)
             VALUES (?1, ?2, ?2, 1, ?3, 4, 'done', datetime('now'), ?4)",
        )
        .bind(uid)
        .bind(&arbiter.0[..])
        .bind(ip.id)
        .bind(&FAST.0[..])
        .execute(&store.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO scans (job_id, ip_id, level, started_at, finished_at, uid, origin, job_uid)
             VALUES ((SELECT id FROM scan_jobs WHERE uid = ?1), ?2, 4, datetime('now'),
                     datetime('now'), ?1 || '-scan', ?3, ?1)",
        )
        .bind(uid)
        .bind(ip.id)
        .bind(&FAST.0[..])
        .execute(&store.pool)
        .await
        .unwrap();
        sqlx::query_scalar("SELECT id FROM scans WHERE job_uid = ?")
            .bind(uid)
            .fetch_one(&store.pool)
            .await
            .unwrap()
    }

    fn given(uid: &str) -> Handout {
        Handout {
            job_uid: uid.into(),
            scanner: FAST,
            level: 4,
            paid: true,
            price_mc: Some(30),
            rate: 1.0,
            effective_mc: 30,
            next: None,
            waited_secs: 0,
            reason: Reason::Cheapest,
            sat_out: 0,
        }
    }

    #[tokio::test]
    async fn the_scan_page_says_why_the_job_went_where() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let mine = scanned(&store, "j1", ME).await;
        assert_eq!(
            handed_out(&store.pool, ME, &name, mine).await.unwrap(),
            None
        );
        crate::scan::handout::record(&store.pool, &given("j1"))
            .await
            .unwrap();
        assert_eq!(
            handed_out(&store.pool, ME, &name, mine)
                .await
                .unwrap()
                .as_deref(),
            Some(
                "Given to Fast for 0.03 per delivered result (price 0.03, 100 % of the best success rate at L4)."
            )
        );
        let theirs = scanned(&store, "j2", OTHER).await;
        assert_eq!(
            handed_out(&store.pool, ME, &name, theirs)
                .await
                .unwrap()
                .as_deref(),
            Some("Handed out by Other; the reason is on that node.")
        );
    }

    #[tokio::test]
    async fn the_history_titles_the_scanner_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        scanned(&store, "j1", ME).await;
        scanned(&store, "j2", ME).await;
        crate::scan::handout::record(&store.pool, &given("j1"))
            .await
            .unwrap();
        let mut page = store.job_history(&JobFilter::default(), 1).await.unwrap();
        add_handouts(&store.pool, &name, &mut page.items)
            .await
            .unwrap();
        let by = |uid: &str| {
            page.items
                .iter()
                .find(|r| r.uid == uid)
                .and_then(|r| r.handout.clone())
        };
        assert!(by("j1").unwrap().starts_with("Given to Fast"));
        assert_eq!(by("j2"), None);
    }

    #[test]
    fn the_scan_page_shows_the_hand_out_line() {
        let page = |handed_out: Option<String>| ScanPage {
            chrome: chrome(),
            s: ScanSummary {
                id: 1,
                ip_id: 1,
                ip: "203.0.113.7".into(),
                level: 4,
                started_at: String::new(),
                finished_at: None,
                os_guess: None,
                open_ports: 0,
                node: None,
                audit_of: None,
                audit_result: None,
            },
            ports: vec![],
            keys: vec![],
            can_delete: false,
            audit_of: None,
            audits: vec![],
            handed_out,
        };
        let html = page(Some("Given to Fast for 0.03 per delivered result.".into()))
            .render()
            .unwrap();
        assert!(html.contains("Handed out: Given to Fast for 0.03 per delivered result."));
        assert!(!page(None).render().unwrap().contains("Handed out"));
    }
}
