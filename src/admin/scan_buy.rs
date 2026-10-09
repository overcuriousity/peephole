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
use axum::{Router, body::Bytes, extract::State, response::Response, routing::post};
use std::net::IpAddr;
use std::sync::Arc;

/// A scan of an address this fresh needs no buying: the result stands.
pub const FRESH_HOURS: i64 = 24;

/// One level's offer on the Actions card.
pub struct ScanOffer {
    pub level: u8,
    /// "from 1.23 credits" in a cluster, "free" standalone; empty when no
    /// live scanner announces a price.
    pub price: String,
    /// A finished scan of exactly this level under [`FRESH_HOURS`] old
    /// (its finish date): no new scan is sold.
    pub fresh: Option<String>,
}

/// Whether `ts` (a store timestamp) is less than [`FRESH_HOURS`] old.
fn fresh_enough(ts: &str) -> bool {
    let cutoff = (chrono::Utc::now() - chrono::Duration::hours(FRESH_HOURS))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    ts > cutoff.as_str()
}

/// The four levels' offers for `ip_id`.
pub async fn offers_for(state: &AdminState, ip_id: i64) -> Vec<ScanOffer> {
    let scans = state.store.scans_for_ip(ip_id).await.unwrap_or_default();
    let node = state.recorder.node();
    let cheapest = node.and_then(|n| n.price_table().scanners.iter().map(|s| s.price_mc).min());
    (1u8..=4)
        .map(|level| {
            let fresh = scans
                .iter()
                .filter(|s| s.level == level as i64 && s.audit_of.is_none())
                .filter_map(|s| s.finished_at.clone())
                .find(|f| fresh_enough(f));
            let price = match (node.is_some(), cheapest) {
                (false, _) => "free".into(),
                (true, Some(c)) => format!(
                    "from {} credits",
                    crate::credits::show(
                        c as u64 * crate::credits::jobs::level_factor(level as i64) as u64
                    )
                ),
                (true, None) => String::new(),
            };
            ScanOffer {
                level,
                price,
                fresh,
            }
        })
        .collect()
}

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new().route("/admin/lookup/scan", post(buy))
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
    let back = format!("/ip/{ip}#scans");
    let Some(level) = form.level.parse::<i64>().ok().and_then(valid_level) else {
        return Ok(redirect_with_error(&back, "No scan: not a scan level."));
    };
    let Some(row) = state.store.ip_by_addr(&ip.to_string()).await? else {
        return Ok(redirect_with_error(
            &format!("/admin/lookup?ip={ip}"),
            "No scan: the address is not in the dataset.",
        ));
    };
    let jobs = state.store.jobs_for_ip(row.id, 20).await?;
    if jobs
        .iter()
        .any(|j| j.level == level as i64 && matches!(j.status.as_str(), "queued" | "running"))
    {
        return Ok(redirect_with_notice(
            &back,
            &format!("A level {level} scan of this address is already on its way."),
        ));
    }
    let fresh = offers_for(&state, row.id)
        .await
        .into_iter()
        .find(|o| o.level == level)
        .and_then(|o| o.fresh);
    if let Some(fresh) = fresh {
        return Ok(redirect_with_notice(
            &back,
            &format!("No new scan: the level {level} scan of {fresh} is less than a day old."),
        ));
    }
    // In a cluster the scan budget must cover the level-scaled cheapest
    // price; otherwise the job would silently run unfunded.
    if let Some(node) = state.recorder.node() {
        let Some(cheapest) = node.price_table().scanners.iter().map(|s| s.price_mc).min() else {
            return Ok(redirect_with_error(
                &back,
                "No scan: no live scanner announces a price.",
            ));
        };
        let price = cheapest as u64 * crate::credits::jobs::level_factor(level as i64) as u64;
        let book = crate::credits::book(node).await?;
        let self_mc = crate::credits::jobs::self_committed(&state.store.pool, &node.id()).await?;
        let left =
            crate::credits::jobs::budget(&book.ledger, &node.id(), node.scan_share(), self_mc);
        if (left as u64) < price {
            return Ok(redirect_with_error(
                &back,
                "No scan: the scan budget does not cover this.",
            ));
        }
    }
    match state.recorder.enqueue_manual(row.id, level).await? {
        EnqueueOutcome::Queued(id) => {
            if let Ok(Some(job)) = state.store.queue_job(id).await {
                state.notifier.publish(job);
            }
            Ok(redirect_with_notice(
                &back,
                &format!("Level {level} scan queued; the result appears below when it is in."),
            ))
        }
        _ => Ok(redirect_with_error(
            &back,
            "No scan: the job was not queued.",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::AdminState;
    use crate::scan::probe::gate::tests::scanned;
    use std::sync::Arc;
    use tower::ServiceExt;

    pub(crate) const IP: &str = "203.0.113.40";

    /// A standalone admin; `IP` is in the dataset.
    pub(crate) async fn state() -> (Arc<AdminState>, String, i64, tempfile::TempDir) {
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
        let offers = offers_for(&state, ip_id).await;
        assert_eq!(offers.len(), 4);
        assert!(
            offers
                .iter()
                .all(|o| o.price == "free" && o.fresh.is_none())
        );
        scanned(&state.store, IP, &[(80, "open", Some("http"))]).await;
        let offers = offers_for(&state, ip_id).await;
        let l2 = offers.iter().find(|o| o.level == 2).unwrap();
        assert!(l2.fresh.is_some(), "the level-2 scan just finished");
        assert!(
            offers
                .iter()
                .filter(|o| o.level != 2)
                .all(|o| o.fresh.is_none())
        );
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
        assert_eq!(r.headers()["location"], format!("/ip/{IP}#scans").as_str());
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
}
