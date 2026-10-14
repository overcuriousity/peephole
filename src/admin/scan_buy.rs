//! Buying a counter-scan from the Actions card: `POST /admin/lookup/scan`.
//! The job goes through the normal queue (`Recorder::enqueue_manual`,
//! marked so the scanners skip their evidence re-check); its price grows
//! with its level (`credits::jobs::level_factor`). A finished scan of the
//! same level less than a day old is shown instead and costs nothing.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::AppResult;
use crate::admin::pages::{redirect_with_error, redirect_with_notice};
use crate::scan::valid_level;
use crate::store::scans::EnqueueOutcome;
use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    response::{
        Response,
        sse::{Event, Sse},
    },
    routing::{get, post},
};
use futures::stream::Stream;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

/// A scan of an address this fresh needs no buying: the result stands.
pub const FRESH_HOURS: i64 = 24;

/// One level's offer on the Actions card.
pub struct ScanOffer {
    pub level: u8,
    /// What the level scans, for the button's title.
    pub about: &'static str,
    /// "1.23–4.56 credits" in a cluster, "free" standalone; empty when no
    /// live scanner announces a price.
    pub price: String,
    /// A finished scan of exactly this level under [`FRESH_HOURS`] old
    /// (its finish date): no new scan is sold.
    pub fresh: Option<String>,
    /// That scan's id, for the link to its result.
    pub fresh_id: Option<i64>,
    /// "queued" or "running": a job of this level is on its way.
    pub waiting: Option<&'static str>,
}

impl ScanOffer {
    /// How long ago the fresh scan finished: "3 h".
    pub fn fresh_ago(&self) -> String {
        self.fresh
            .as_deref()
            .map(crate::admin::views::ago)
            .unwrap_or_default()
    }
}

/// What each level scans (`scan::profiles::builtin`).
pub fn about(level: u8) -> &'static str {
    match level {
        1 => "top 100 ports, light version detection",
        2 => "top 1000 ports, versions, OS, host keys and certificates",
        3 => "top 1000 ports, versions, OS, traceroute, safe scripts",
        4 => "every port, versions, OS, traceroute, safe scripts",
        _ => "top 1000 ports, versions, OS, traceroute, vulnerability scripts",
    }
}

/// Whether `ts` (a store timestamp) is less than [`FRESH_HOURS`] old.
fn fresh_enough(ts: &str) -> bool {
    let cutoff = (chrono::Utc::now() - chrono::Duration::hours(FRESH_HOURS))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    ts > cutoff.as_str()
}

/// The five levels' offers for `ip_id` (None: an address the dataset does
/// not hold, with nothing scanned or on its way).
pub async fn offers_for(state: &AdminState, ip_id: Option<i64>) -> Vec<ScanOffer> {
    let (scans, jobs) = match ip_id {
        Some(id) => (
            state.store.scans_for_ip(id).await.unwrap_or_default(),
            state.store.jobs_for_ip(id, 20).await.unwrap_or_default(),
        ),
        None => (vec![], vec![]),
    };
    let node = state.recorder.node();
    let table = node.map(|n| n.price_table());
    (1u8..=5)
        .map(|level| {
            let fresh = scans
                .iter()
                .filter(|s| s.level == level as i64 && s.audit_of.is_none())
                .filter_map(|s| Some((s.id, s.finished_at.clone()?)))
                .find(|(_, f)| fresh_enough(f));
            // Running wins over queued when both are there.
            let waiting = jobs
                .iter()
                .filter(|j| j.level == level as i64)
                .filter_map(|j| match j.status.as_str() {
                    "running" => Some("running"),
                    "queued" => Some("queued"),
                    _ => None,
                })
                .min_by_key(|s| *s != "running");
            let price = match &table {
                None => "free".into(),
                Some(t) => match price_range(&t.scanners, level) {
                    Some(p) => p.text(),
                    None => String::new(),
                },
            };
            ScanOffer {
                level,
                about: about(level),
                price,
                fresh_id: fresh.as_ref().map(|f| f.0),
                fresh: fresh.map(|f| f.1),
                waiting,
            }
        })
        .collect()
}

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/lookup/scan", post(buy))
        .route("/admin/api/scan-jobs", get(stream))
}

/// The form: the address and the level.
#[derive(Debug, Default)]
struct BuyForm {
    ip: String,
    level: String,
}

impl BuyForm {
    fn parse(body: &[u8]) -> Self {
        let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(body).unwrap_or_default();
        let mut f = Self::default();
        for (k, v) in pairs {
            match k.as_str() {
                "ip" => f.ip = v,
                "level" => f.level = v,
                _ => {}
            }
        }
        f
    }
}

/// What a scan costs, level-scaled, in millicredits: the cheapest live
/// scanner's price (what the Actions card offers and the budget must
/// cover) and the dearest's (the arbiter pays whichever scanner wins the
/// job). Both 0 standalone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Price {
    pub floor_mc: u64,
    pub max_mc: u64,
}

impl Price {
    /// "{floor}–{max} credits", or "{floor} credits" when both show the
    /// same: the Actions card's level buttons and the app's `costText`
    /// alike.
    pub fn text(&self) -> String {
        let floor = crate::credits::show(self.floor_mc);
        let max = crate::credits::show(self.max_mc);
        if max == floor {
            format!("{floor} credits")
        } else {
            format!("{floor}–{max} credits")
        }
    }
}

/// Why no scan of a level is sold now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotSold {
    /// A job of the level is "queued" or "running".
    OnItsWay(&'static str),
    /// A finished scan of the level under [`FRESH_HOURS`] old: its finish
    /// date and its id.
    Fresh(String, i64),
    /// No live scanner announces a price.
    NoPrice,
    /// The scan budget does not cover the floor price.
    NoBudget,
}

/// The level-scaled price range over `scanners`; None without any.
pub fn price_range(scanners: &[crate::credits::price::ScannerPrice], level: u8) -> Option<Price> {
    let factor = crate::credits::jobs::level_factor(level as i64) as u64;
    let min = scanners.iter().map(|s| s.price_mc).min()?;
    let max = scanners.iter().map(|s| s.price_mc).max()?;
    Some(Price {
        floor_mc: min as u64 * factor,
        max_mc: max as u64 * factor,
    })
}

/// Where a scan of `ip` goes: its dataset row, or None when the dataset
/// does not hold it and a sale makes the row, unseen (MIK-329). Err: why
/// an unrecorded address gets neither row nor scan: the checks a probe
/// obeys before it reaches out (non-global, `never_scan`, this node's or
/// a member's address, the operator's lists). A recorded address keeps
/// the checks it always had, at the scanner.
pub async fn scan_target(
    state: &AdminState,
    ip: IpAddr,
) -> anyhow::Result<Result<Option<i64>, String>> {
    let ip = crate::net::canonical(ip);
    if let Some(row) = state.store.ip_by_addr(&ip.to_string()).await? {
        return Ok(Ok(Some(row.id)));
    }
    if let Some(r) = crate::scan::locally_refused(&ip, &state.cfg.scan.never_scan) {
        return Ok(Err(r.reason().to_string()));
    }
    let mut s = state.safety.lock().await;
    s.refresh(&state.cfg, state.recorder.node().map(|n| &**n))
        .await;
    // Fail closed: what the lists cover is not known.
    Ok(
        match s
            .refuses(&ip)
            .or_else(|| s.unavailable())
            .or_else(|| s.listed(&ip))
        {
            Some(why) => Err(why),
            None => Ok(None),
        },
    )
}

/// Whether a level-`level` scan of `ip_id` (None: an address the dataset
/// does not hold yet) is sold now, and at what price: the checks of the
/// Actions card's buy button (`POST /admin/lookup/scan`) and of the
/// machine API's quote and buy alike. A job of the level on its way or a
/// fresh result of it sells nothing; in a cluster the scan budget must
/// cover the floor price, otherwise the job would silently wait in the
/// queue.
pub async fn sale(
    state: &AdminState,
    ip_id: Option<i64>,
    level: u8,
) -> anyhow::Result<Result<Price, NotSold>> {
    if let Some(ip_id) = ip_id
        && let Some(n) = held(state, ip_id, level).await?
    {
        return Ok(Err(n));
    }
    let Some(node) = state.recorder.node() else {
        return Ok(Ok(Price {
            floor_mc: 0,
            max_mc: 0,
        }));
    };
    let Some(price) = price_range(&node.price_table().scanners, level) else {
        return Ok(Err(NotSold::NoPrice));
    };
    let book = crate::credits::book(node).await?;
    let self_mc = crate::credits::jobs::self_committed(&state.store.pool, &node.id()).await?;
    let left = crate::credits::jobs::budget(&book.ledger, &node.id(), self_mc);
    if (left as u64) < price.floor_mc {
        return Ok(Err(NotSold::NoBudget));
    }
    Ok(Ok(price))
}

/// Why `ip_id` gets no level-`level` scan now: one on its way, or fresh.
async fn held(state: &AdminState, ip_id: i64, level: u8) -> anyhow::Result<Option<NotSold>> {
    let jobs = state.store.jobs_for_ip(ip_id, 20).await?;
    if let Some(j) = jobs
        .iter()
        .filter(|j| j.level == level as i64)
        .find(|j| matches!(j.status.as_str(), "queued" | "running"))
    {
        let waiting = if j.status == "running" {
            "running"
        } else {
            "queued"
        };
        return Ok(Some(NotSold::OnItsWay(waiting)));
    }
    let fresh = offers_for(state, Some(ip_id))
        .await
        .into_iter()
        .find(|o| o.level == level)
        .and_then(|o| Some((o.fresh?, o.fresh_id?)));
    Ok(fresh.map(|(at, id)| NotSold::Fresh(at, id)))
}

/// Queue a marked level-`level` job for `ip` (canonical) and tell the
/// queue view; an address the dataset does not hold gets its unseen row
/// with the job. Its id; otherwise why not: [`NotSold::OnItsWay`] when a
/// job of the level got there first (the check of [`sale`] again, under
/// the queue's lock), None when the queue did not take it for another
/// reason.
pub async fn enqueue(
    state: &AdminState,
    ip: IpAddr,
    level: u8,
) -> anyhow::Result<Result<i64, Option<NotSold>>> {
    match state
        .recorder
        .enqueue_manual_addr(&ip.to_string(), level)
        .await?
    {
        EnqueueOutcome::Queued(id) => {
            if let Ok(Some(job)) = state.store.queue_job(id).await {
                state.notifier.publish(job);
            }
            Ok(Ok(id))
        }
        EnqueueOutcome::OnItsWay(status) => Ok(Err(Some(NotSold::OnItsWay(status)))),
        _ => Ok(Err(None)),
    }
}

/// POST /admin/lookup/scan: queue a marked job, then back to the IP
/// page's Counter-scans section. A job of this level already on its way,
/// or a fresh result of it, sells nothing.
async fn buy(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    body: Bytes,
) -> AppResult<Response> {
    let form = BuyForm::parse(&body);
    let Ok(ip) = form.ip.trim().parse::<IpAddr>() else {
        return Ok(redirect_with_error("/admin/lookup", "Not an IP address."));
    };
    let ip = crate::net::canonical(ip);
    let lookup = format!("/admin/lookup?ip={ip}");
    let row = match scan_target(&state, ip).await? {
        Ok(row) => row,
        Err(why) => return Ok(redirect_with_error(&lookup, &format!("No scan: {why}."))),
    };
    // An unrecorded address has no page until the job makes its row.
    let back = match row {
        Some(_) => format!("/ip/{ip}#actions"),
        None => lookup,
    };
    let Some(level) = form.level.parse::<i64>().ok().and_then(valid_level) else {
        return Ok(redirect_with_error(&back, "No scan: not a scan level."));
    };
    match sale(&state, row, level).await? {
        Err(NotSold::OnItsWay(_)) => {
            return Ok(redirect_with_notice(
                &back,
                &format!("A level {level} scan of this address is already on its way."),
            ));
        }
        Err(NotSold::Fresh(fresh, _)) => {
            return Ok(redirect_with_notice(
                &back,
                &format!("No new scan: the level {level} scan of {fresh} is less than a day old."),
            ));
        }
        Err(NotSold::NoPrice) => {
            return Ok(redirect_with_error(
                &back,
                "No scan: no live scanner announces a price.",
            ));
        }
        Err(NotSold::NoBudget) => {
            return Ok(redirect_with_error(
                &back,
                "No scan: the scan budget does not cover this.",
            ));
        }
        Ok(_) => {}
    }
    match enqueue(&state, ip, level).await? {
        Ok(_) => Ok(redirect_with_notice(
            &format!("/ip/{ip}#actions"),
            &match row {
                Some(_) => {
                    format!("Level {level} scan queued; the result appears below when it is in.")
                }
                None => format!(
                    "Level {level} scan queued. The address is now in the dataset, marked unseen: \
                     no traffic recorded. The result appears below when it is in."
                ),
            },
        )),
        Err(Some(NotSold::OnItsWay(_))) => Ok(redirect_with_notice(
            &back,
            &format!("A level {level} scan of this address is already on its way."),
        )),
        Err(_) => Ok(redirect_with_error(
            &back,
            "No scan: the job was not queued.",
        )),
    }
}

/// `[id, status]` per job: what the stream compares.
pub fn states_json(jobs: &[crate::events::QueueJob]) -> String {
    let v: Vec<(i64, &str)> = jobs.iter().map(|j| (j.id, j.status.as_str())).collect();
    serde_json::to_string(&v).unwrap_or_else(|_| "[]".into())
}

/// A job is still on its way, or a recently done one's result has not
/// landed here yet (the scanner and the arbiter write separately).
pub async fn any_waiting(store: &crate::store::Store, ip_id: i64) -> bool {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_jobs j WHERE j.ip_id = ?
           AND (j.status IN ('queued','running')
                OR (j.status = 'done' AND j.finished_at > datetime('now', '-2 days')
                    AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.job_uid = j.uid)))",
    )
    .bind(ip_id)
    .fetch_one(&store.pool)
    .await
    .unwrap_or(0);
    n > 0
}

#[derive(serde::Deserialize)]
pub struct JobsQuery {
    ip: String,
}

/// GET /admin/api/scan-jobs?ip=…: a `scan-jobs` event with the states
/// whenever they change, while a job waits for its result.
async fn stream(
    _u: SessionUser,
    jar: axum_extra::extract::CookieJar,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<JobsQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let session = crate::admin::auth::session_token(&state, &jar);
    let ip_id = match q.ip.trim().parse::<IpAddr>() {
        Ok(ip) => state
            .store
            .ip_by_addr(&crate::net::canonical(ip).to_string())
            .await
            .ok()
            .flatten()
            .map(|r| r.id),
        Err(_) => None,
    };
    crate::admin::sse::watch(state, session, "scan-jobs", move |state| async move {
        match ip_id {
            Some(id) => {
                let jobs = state.store.jobs_for_ip(id, 20).await.unwrap_or_default();
                (states_json(&jobs), any_waiting(&state.store, id).await)
            }
            None => (states_json(&[]), false),
        }
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::admin::AdminState;
    use crate::scan::probe::gate::tests::scanned;
    use std::sync::Arc;
    use tower::ServiceExt;

    pub(crate) const IP: &str = "203.0.113.40";

    /// A standalone admin; `IP` is in the dataset.
    pub(crate) async fn state() -> (Arc<AdminState>, String, i64, tempfile::TempDir) {
        state_with("").await
    }

    /// [`state`] with more `[scan]` settings.
    pub(crate) async fn state_with(
        scan: &str,
    ) -> (Arc<AdminState>, String, i64, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg: crate::config::Config = toml::from_str(&format!(
            r#"
admin_listen = "127.0.0.1:1"
database_path = "{db}"
data_dir = "{d}"
[roles]
listener = false
scanner = false
[scan]
tor_unknown = "scan"
verify_crawlers = false
{scan}
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
secure_cookies = false
"#,
            db = dir.path().join("t.db").display(),
            d = dir.path().display()
        ))
        .unwrap();
        let store = crate::store::Store::connect(&cfg.database_path)
            .await
            .unwrap();
        let ip = store.upsert_ip(IP.parse().unwrap()).await.unwrap();
        let token = store.create_session().await.unwrap();
        let cookie = format!("{}={token}", crate::admin::auth::session_cookie_name(&cfg));
        (
            Arc::new(AdminState::public_only(store, cfg)),
            cookie,
            ip.id,
            dir,
        )
    }

    pub(crate) fn post(cookie: &str, body: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::post("/admin/lookup/scan")
            .header("cookie", cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    #[test]
    fn a_price_reads_as_its_range_or_one_amount() {
        let p = |floor_mc, max_mc| Price { floor_mc, max_mc }.text();
        assert_eq!(p(1280, 2560), "1.28–2.56 credits");
        assert_eq!(p(1280, 1280), "1.28 credits");
        assert_eq!(p(0, 0), "0.00 credits");
        // Rounded to the cent, half up, like `credits::show`; equal once
        // rounded is one amount.
        assert_eq!(p(1005, 2994), "1.01–2.99 credits");
        assert_eq!(p(1001, 1004), "1.00 credits");
    }

    #[test]
    fn a_price_ranges_from_the_cheapest_to_the_dearest_scanner_level_scaled() {
        let sp = |price_mc| crate::credits::price::ScannerPrice {
            node: crate::scan::probe::gate::LOCAL,
            price_mc,
            paid: 0.0,
            supply: 0.0,
        };
        assert_eq!(price_range(&[], 1), None);
        let scanners = [sp(320), sp(80), sp(160)];
        assert_eq!(
            price_range(&scanners, 1),
            Some(Price {
                floor_mc: 80,
                max_mc: 320
            })
        );
        assert_eq!(
            price_range(&scanners, 3),
            Some(Price {
                floor_mc: 80 * 16,
                max_mc: 320 * 16
            })
        );
    }

    #[test]
    fn the_fresh_window_is_24_hours() {
        let at = |h: i64| {
            (chrono::Utc::now() - chrono::Duration::hours(h))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        };
        assert!(fresh_enough(&at(23)));
        assert!(!fresh_enough(&at(25)));
    }

    #[tokio::test]
    async fn standalone_offers_are_free_and_a_fresh_result_stands() {
        let (state, _c, ip_id, _d) = state().await;
        let offers = offers_for(&state, Some(ip_id)).await;
        assert_eq!(offers.len(), 5);
        assert!(
            offers
                .iter()
                .all(|o| o.price == "free" && o.fresh.is_none())
        );
        scanned(&state.store, IP, &[(80, "open", Some("http"))]).await;
        let offers = offers_for(&state, Some(ip_id)).await;
        let l2 = offers.iter().find(|o| o.level == 2).unwrap();
        assert!(l2.fresh.is_some(), "the level-2 scan just finished");
        let scan_id: i64 = sqlx::query_scalar("SELECT id FROM scans WHERE ip_id = ?")
            .bind(ip_id)
            .fetch_one(&state.store.pool)
            .await
            .unwrap();
        assert_eq!(l2.fresh_id, Some(scan_id), "links to that result");
        assert!(l2.fresh_ago().ends_with(" s"), "{}", l2.fresh_ago());
        assert!(
            offers
                .iter()
                .filter(|o| o.level != 2)
                .all(|o| o.fresh.is_none() && o.fresh_id.is_none())
        );
    }

    /// A level with a job on its way says so: queued, then running.
    #[tokio::test]
    async fn an_offer_shows_its_job_on_the_way() {
        let (state, _c, ip_id, _d) = state().await;
        assert!(
            offers_for(&state, Some(ip_id))
                .await
                .iter()
                .all(|o| o.waiting.is_none())
        );
        state.recorder.enqueue_manual(ip_id, 3).await.unwrap();
        let waiting = |offers: &[ScanOffer]| -> Vec<(u8, Option<&'static str>)> {
            offers.iter().map(|o| (o.level, o.waiting)).collect()
        };
        let offers = offers_for(&state, Some(ip_id)).await;
        assert_eq!(
            waiting(&offers),
            vec![
                (1, None),
                (2, None),
                (3, Some("queued")),
                (4, None),
                (5, None)
            ]
        );
        sqlx::query("UPDATE scan_jobs SET status = 'running' WHERE ip_id = ?")
            .bind(ip_id)
            .execute(&state.store.pool)
            .await
            .unwrap();
        let offers = offers_for(&state, Some(ip_id)).await;
        assert_eq!(offers[2].waiting, Some("running"));
        assert_eq!(offers[2].about, about(3));
    }

    #[tokio::test]
    async fn buying_a_scan_queues_a_marked_job_once() {
        let (state, cookie, ip_id, _d) = state().await;
        let app = crate::admin::full_router(state.clone());
        let r = app
            .clone()
            .oneshot(post(&cookie, &format!("ip={IP}&level=2")))
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        let jobs: Vec<(i64, i64)> =
            sqlx::query_as("SELECT level, manual FROM scan_jobs WHERE ip_id = ?")
                .bind(ip_id)
                .fetch_all(&state.store.pool)
                .await
                .unwrap();
        assert_eq!(jobs, vec![(2, 1)]);
        // Again at the same level while queued: no second job.
        let r = app
            .clone()
            .oneshot(post(&cookie, &format!("ip={IP}&level=2")))
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs WHERE ip_id = ?")
            .bind(ip_id)
            .fetch_one(&state.store.pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
        // Not a level.
        let r = app
            .oneshot(post(&cookie, &format!("ip={IP}&level=9")))
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(
            r.headers()["location"],
            format!("/ip/{IP}#actions").as_str()
        );
        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs WHERE ip_id = ? AND level = 9")
                .bind(ip_id)
                .fetch_one(&state.store.pool)
                .await
                .unwrap();
        assert_eq!(n, 0, "no job at a level that is not offered");
    }

    /// Not in the dataset, global, nobody's: the job makes its row, unseen.
    pub(crate) const UNRECORDED: &str = "198.51.100.200";

    #[tokio::test]
    async fn buying_a_scan_of_an_unrecorded_address_adds_it_unseen() {
        let (state, cookie, _, _d) = state().await;
        let app = crate::admin::full_router(state.clone());
        let r = app
            .clone()
            .oneshot(post(&cookie, &format!("ip={UNRECORDED}&level=2")))
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(
            r.headers()["location"],
            format!("/ip/{UNRECORDED}#actions").as_str()
        );
        let row = state.store.ip_by_addr(UNRECORDED).await.unwrap().unwrap();
        assert!(row.unseen);
        assert_eq!(row.request_count, 0);
        assert_eq!((row.country, row.asn, row.asn_org), (None, None, None));
        let jobs: Vec<(i64, i64)> =
            sqlx::query_as("SELECT level, manual FROM scan_jobs WHERE ip_id = ?")
                .bind(row.id)
                .fetch_all(&state.store.pool)
                .await
                .unwrap();
        assert_eq!(jobs, vec![(2, 1)]);
        // Labelled wherever it is shown.
        for page in [format!("/ip/{UNRECORDED}"), "/ips".to_string()] {
            let r = app
                .clone()
                .oneshot(
                    axum::http::Request::get(&page)
                        .header("cookie", &cookie)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), 200, "{page}");
            let html = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            let html = String::from_utf8_lossy(&html);
            assert!(
                html.contains(r#"class="badge badge-unseen""#),
                "{page}: {html}"
            );
        }
    }

    /// What the guard refuses gets neither a row nor a job: non-global,
    /// this node's own, `never_scan`, a member's address.
    #[tokio::test]
    async fn a_refused_unrecorded_address_gets_no_row_and_no_scan() {
        let (state, cookie, _, _d) =
            state_with("own_addresses = [\"198.51.100.5\"]\nnever_scan = [\"198.51.100.64/26\"]")
                .await;
        state
            .safety
            .lock()
            .await
            .saw_member("198.51.100.9".parse().unwrap(), "peer");
        let app = crate::admin::full_router(state.clone());
        for (ip, why) in [
            ("10.0.0.1", "private"),
            ("127.0.0.1", "loopback"),
            ("169.254.169.254", "link-local"),
            ("::1", "IPv6 loopback"),
            ("198.51.100.5", "own address"),
            ("198.51.100.70", "never_scan"),
            ("198.51.100.9", "member"),
        ] {
            let r = app
                .clone()
                .oneshot(post(&cookie, &format!("ip={ip}&level=2")))
                .await
                .unwrap();
            assert_eq!(r.status(), 303, "{why}");
            assert_eq!(
                r.headers()["location"],
                format!("/admin/lookup?ip={ip}").as_str(),
                "{why}"
            );
        }
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ips WHERE ip != ?")
            .bind(IP)
            .fetch_one(&state.store.pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "no row for a refused address");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs")
            .fetch_one(&state.store.pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "no scan of a refused address");
    }

    #[tokio::test]
    async fn a_fresh_level_does_not_block_a_different_level() {
        let (state, cookie, ip_id, _d) = state().await;
        scanned(&state.store, IP, &[(80, "open", Some("http"))]).await;
        let app = crate::admin::full_router(state.clone());
        let r = app
            .oneshot(post(&cookie, &format!("ip={IP}&level=3")))
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_jobs WHERE ip_id = ? AND level = 3 AND manual = 1",
        )
        .bind(ip_id)
        .fetch_one(&state.store.pool)
        .await
        .unwrap();
        assert_eq!(n, 1, "a fresh level-2 result does not block level 3");
    }

    #[tokio::test]
    async fn a_fresh_exact_level_scan_is_not_bought_again() {
        let (state, cookie, ip_id, _d) = state().await;
        scanned(&state.store, IP, &[(80, "open", Some("http"))]).await;
        let app = crate::admin::full_router(state.clone());
        let r = app
            .oneshot(post(&cookie, &format!("ip={IP}&level=2")))
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs WHERE ip_id = ? AND manual = 1")
                .bind(ip_id)
                .fetch_one(&state.store.pool)
                .await
                .unwrap();
        assert_eq!(n, 0, "the fresh level-2 result stands");
    }

    #[test]
    fn job_states_are_id_status_pairs() {
        let j = |id, status: &str| crate::events::QueueJob {
            id,
            ip: IP.into(),
            level: 2,
            status: status.into(),
            queued_at: String::new(),
            started_at: None,
            finished_at: None,
            error: None,
            scanner: None,
            arbiter: None,
            retry_at: None,
        };
        assert_eq!(
            states_json(&[j(3, "queued"), j(2, "done")]),
            "[[3,\"queued\"],[2,\"done\"]]"
        );
    }

    #[tokio::test]
    async fn waiting_until_the_result_lands() {
        let (state, _c, ip_id, _d) = state().await;
        let store = &state.store;
        assert!(!any_waiting(store, ip_id).await);
        state.recorder.enqueue_manual(ip_id, 2).await.unwrap();
        assert!(any_waiting(store, ip_id).await, "queued");
        sqlx::query(
            "UPDATE scan_jobs SET status = 'done', finished_at = datetime('now') WHERE ip_id = ?",
        )
        .bind(ip_id)
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(any_waiting(store, ip_id).await, "done, result not here yet");
        sqlx::query(
            "INSERT INTO scans (job_id, ip_id, level, started_at, finished_at, uid, origin, job_uid)
             SELECT id, ip_id, level, datetime('now'), datetime('now'), 's1', NULL, uid
             FROM scan_jobs WHERE ip_id = ?",
        )
        .bind(ip_id)
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(!any_waiting(store, ip_id).await, "the result landed");
    }

    #[tokio::test]
    async fn the_stream_reports_the_job_states() {
        use futures::StreamExt;
        let (state, cookie, ip_id, _d) = state().await;
        state.recorder.enqueue_manual(ip_id, 2).await.unwrap();
        let app = crate::admin::full_router(state.clone());
        let r = app
            .oneshot(
                axum::http::Request::get(format!("/admin/api/scan-jobs?ip={IP}"))
                    .header("cookie", &cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let mut body = r.into_body().into_data_stream();
        let mut seen = String::new();
        let read = async {
            while let Some(Ok(chunk)) = body.next().await {
                seen.push_str(&String::from_utf8_lossy(&chunk));
                if seen.contains("event: scan-jobs") {
                    return;
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), read)
            .await
            .unwrap_or_else(|_| panic!("no scan-jobs event in {seen:?}"));
        assert!(seen.contains("queued"), "{seen}");
    }

    #[tokio::test]
    async fn the_stream_ends_once_nothing_waits() {
        use futures::StreamExt;
        let (state, cookie, _ip_id, _d) = state().await;
        let app = crate::admin::full_router(state.clone());
        let r = app
            .oneshot(
                axum::http::Request::get(format!("/admin/api/scan-jobs?ip={IP}"))
                    .header("cookie", &cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let mut body = r.into_body().into_data_stream();
        let mut seen = String::new();
        let read = async {
            while let Some(Ok(chunk)) = body.next().await {
                seen.push_str(&String::from_utf8_lossy(&chunk));
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(15), read)
            .await
            .unwrap_or_else(|_| panic!("the stream never closed: {seen:?}"));
        assert!(seen.contains("event: scan-jobs"), "{seen}");
    }
}
