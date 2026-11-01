pub mod api_v1;
pub mod asn;
pub mod assets;
pub mod auth;
pub mod blocklist;
pub mod campaigns;
pub mod cli;
pub mod cluster;
pub mod cluster_access;
pub mod cluster_owner;
pub mod countries;
pub mod credits;
pub mod decoys;
pub mod devices;
pub mod dossier;
pub mod error;
pub mod glossary;
pub mod limit;
pub mod links;
pub mod lookup;
pub mod moved;
pub mod overview;
pub mod pages;
pub mod password;
pub mod paths;
pub mod probes;
pub mod public;
pub mod scan_buy;
pub mod scans;
pub mod search;
pub mod signals;
pub mod sse;
pub mod system;
pub mod target;
pub mod uploads;
pub mod views;
pub mod web_quote;
pub mod xray;

use crate::config::Config;
use crate::store::Store;
use axum::{Router, routing::get};
use std::sync::Arc;

pub struct AdminState {
    pub store: Store,
    /// Writes (deletes, requeues); replicated in a cluster.
    pub recorder: crate::store::recorder::Recorder,
    pub cfg: Config,
    pub notifier: crate::events::Notifier,
    pub stats_cache: crate::store::stats::StatsCache,
    pub pace: crate::scan::pace::SharedPace,
    /// Runtime settings (pace, cooldown, roles) and their one write path.
    pub settings: crate::settings::Settings,
    /// Set to `true` when the web role is switched off: long-lived
    /// responses (the live queue) end, so the listener can stop.
    pub closing: Option<tokio::sync::watch::Receiver<bool>>,
    /// Per-client rate limits (public pages, sign-in ceremonies).
    pub limits: limit::Limits,
    /// This node's enrichment providers (their budgets on System › Status).
    pub providers: crate::intel::Providers,
    /// Addresses the blocklist feed must leave out (members, own networks).
    pub safety: tokio::sync::Mutex<crate::scan::safety::Safety>,
    /// This node's tarpit, for System › Status; None without a trap here.
    pub tarpit: Option<Arc<crate::trap::tarpit::Tarpit>>,
    /// This node's prober, when it probes (`scan::probe`).
    pub prober: Option<Arc<crate::scan::probe::serve::Prober>>,
    /// GeoLite2, for the countries of the probe vantages.
    pub geo: crate::intel::SharedGeo,
    /// Probe requests made here and not yet answered by a result, by
    /// group uid (`admin::probes`). In memory: a restart forgets them.
    pub pending_probes: std::sync::Mutex<probes::PendingMap>,
    /// The gate a member that does not probe judges addresses with, built
    /// on first use (`admin::probes`).
    pub probe_judge: std::sync::OnceLock<crate::scan::probe::serve::Prober>,
    /// Password checks running at once (each takes ~19 MiB and a thread).
    pub verify_slots: tokio::sync::Semaphore,
}

impl AdminState {
    /// This node's own addresses and names, to scrub from served scans
    /// (`scan::scrub`); the safety list is refreshed first, as the
    /// blocklist feed does.
    pub async fn own_identity(&self) -> crate::scan::scrub::Own {
        let mut s = self.safety.lock().await;
        s.refresh(&self.cfg, self.recorder.node().map(|n| &**n))
            .await;
        s.own_identity()
    }

    /// Records can be deleted from the admin only on a standalone node. In
    /// a cluster the data belongs to the cluster: retention prunes it.
    pub fn can_delete(&self) -> bool {
        matches!(self.recorder, crate::store::recorder::Recorder::Local(_))
    }
}

impl AdminState {
    pub fn new(
        store: Store,
        cfg: Config,
        notifier: crate::events::Notifier,
        pace: crate::scan::pace::SharedPace,
        geo: crate::intel::SharedGeo,
    ) -> Self {
        Self {
            recorder: store.local(),
            settings: crate::settings::Settings::with_pace(store.clone(), &cfg, pace.clone()),
            limits: limit::Limits::new(&cfg),
            safety: tokio::sync::Mutex::new(crate::scan::safety::Safety::new(&cfg)),
            store,
            cfg,
            notifier,
            stats_cache: crate::store::stats::StatsCache::new(),
            pace,
            closing: None,
            providers: vec![],
            tarpit: None,
            prober: None,
            geo,
            pending_probes: Default::default(),
            probe_judge: Default::default(),
            verify_slots: tokio::sync::Semaphore::new(auth::MAX_VERIFIES),
        }
    }

    /// This node's prober (None: it does not probe).
    pub fn with_prober(mut self, prober: Option<Arc<crate::scan::probe::serve::Prober>>) -> Self {
        self.prober = prober;
        self
    }

    /// The enrichment providers this node runs.
    pub fn with_providers(mut self, providers: crate::intel::Providers) -> Self {
        self.providers = providers;
        self
    }
    /// Route writes through `recorder` (a cluster node's log).
    pub fn with_recorder(mut self, recorder: crate::store::recorder::Recorder) -> Self {
        self.recorder = recorder;
        self
    }

    /// Use the process-wide runtime settings (so UI changes reach the trap,
    /// the scan workers and the role supervisor).
    pub fn with_settings(mut self, settings: crate::settings::Settings) -> Self {
        self.pace = settings.pace.clone();
        self.settings = settings;
        self
    }

    /// End long-lived responses once `closing` turns `true`.
    /// Show this node's tarpit on System › Status.
    pub fn with_tarpit(mut self, tarpit: Arc<crate::trap::tarpit::Tarpit>) -> Self {
        self.tarpit = Some(tarpit);
        self
    }

    pub fn with_closing(mut self, closing: tokio::sync::watch::Receiver<bool>) -> Self {
        self.closing = Some(closing);
        self
    }

    /// State with a private notifier (tests, or when nothing publishes).
    pub fn public_only(store: Store, cfg: Config) -> Self {
        let pace =
            crate::scan::pace::SharedPace::new(crate::scan::pace::Pace::from_config(&cfg.scan));
        let geo = Arc::new(std::sync::RwLock::new(None));
        Self::new(store, cfg, crate::events::Notifier::new(), pace, geo)
    }
}

pub fn router_with_auth(store: Store, cfg: Config) -> Router {
    let state = Arc::new(AdminState::public_only(store, cfg));
    full_router(state)
}

/// Every route on the admin listener: public pages, assets, auth, admin.
pub fn full_router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/admin/api/queue", get(sse::queue_stream))
        .route("/admin/api/recent", get(sse::recent_stream))
        .merge(public::routes())
        .merge(assets::router())
        .merge(auth::auth_routes())
        .merge(pages::routes())
        .merge(links::routes())
        .merge(campaigns::routes())
        .merge(dossier::routes())
        .merge(paths::routes())
        .merge(asn::routes())
        .merge(decoys::routes())
        .merge(search::routes())
        .merge(system::routes())
        .merge(scans::routes())
        .merge(overview::routes())
        .merge(lookup::routes())
        .merge(probes::routes())
        .merge(scan_buy::routes())
        .merge(web_quote::routes())
        .merge(cluster::routes())
        .merge(cluster_access::routes())
        .merge(cluster_owner::routes())
        .merge(credits::routes())
        .merge(devices::routes())
        .merge(uploads::routes())
        .merge(moved::routes())
        .merge(api_v1::routes())
        .fallback(error::not_found)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            limit::enforce,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            market_scope,
        ))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

/// Public-only router used by early tests; same middleware.
pub fn router(state: Arc<AdminState>) -> Router {
    full_router(state)
}

/// Lets the admin nav know whether Market (the credits page) answers.
async fn market_scope(
    axum::extract::State(st): axum::extract::State<Arc<AdminState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let market = st.recorder.node().is_some();
    views::MARKET.scope(market, next.run(req)).await
}

async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // CSRF defence in depth: a mutating request must be same-origin. The
    // SameSite=Strict session cookie already covers this, but a browser also
    // sends Sec-Fetch-Site (and/or Origin); reject a cross-site write so XSS
    // on a sibling vhost behind the same proxy cannot drive admin actions.
    // A write carrying a session cookie must show one of them (every
    // current browser sends at least Origin on a POST); one without a
    // session (the sign-in ceremony, bearer API calls) may send neither.
    if method_mutates(&method) && !same_origin(req.headers(), carries_session(req.headers())) {
        use axum::response::IntoResponse;
        return (
            axum::http::StatusCode::FORBIDDEN,
            "cross-site request refused",
        )
            .into_response();
    }
    // Admin/auth pages must not sit in a shared or back/forward cache after
    // logout (invite tokens, request bodies, headers); the machine API's
    // JSON is bearer-gated and just as little cacheable.
    let sensitive = path.starts_with("/admin")
        || path.starts_with("/api/")
        || path.starts_with("/login")
        || path.starts_with("/enroll")
        || path == "/logout"
        || path == "/requests";
    // Public pages (`/`, `/ips`, `/ip/{addr}`) show private data to a
    // signed-in admin: never cache those responses either.
    let signed_in = carries_session(req.headers());

    let mut res = error::SIGNED_IN.scope(signed_in, next.run(req)).await;
    let h = res.headers_mut();
    h.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; \
             connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    );
    h.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    // The admin listener is reached over TLS via nginx; pin that with HSTS.
    h.insert(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        axum::http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    if sensitive {
        h.insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
    } else if signed_in {
        h.insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("private, no-store"),
        );
    } else if !h.contains_key(axum::http::header::CACHE_CONTROL) {
        // What a page shows depends on the session cookie; responses that
        // set their own caching (assets, the blocklist) do not.
        h.append(
            axum::http::header::VARY,
            axum::http::HeaderValue::from_static("Cookie"),
        );
    }
    res
}

/// Whether the request carries a session cookie (either name, see
/// [`auth::session_cookie_name`]), valid or not.
fn carries_session(h: &axum::http::HeaderMap) -> bool {
    h.get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.split_once('=').map(|(name, _)| name.trim()))
        .any(|name| name == "peephole_session" || name == "__Host-peephole_session")
}

fn method_mutates(m: &axum::http::Method) -> bool {
    matches!(
        *m,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
    )
}

/// Whether a mutating request is same-origin, from the browser fetch-metadata
/// and Origin headers. A request with neither passes only without a session
/// cookie (`session`): nothing it could do rides on an admin's sign-in. With
/// one it is refused, so a browser or proxy that strips both headers cannot
/// carry a cross-site write past this check (MIK-372 S2).
fn same_origin(h: &axum::http::HeaderMap, session: bool) -> bool {
    if let Some(site) = h.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        // "same-origin"/"none" are safe; "same-site"/"cross-site" are not.
        return site == "same-origin" || site == "none";
    }
    match (
        h.get(axum::http::header::ORIGIN)
            .and_then(|v| v.to_str().ok()),
        h.get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok()),
    ) {
        // Compare the Origin's host:port to the Host header.
        (Some(origin), Some(host)) => origin
            .split_once("://")
            .map(|(_, rest)| rest)
            .is_some_and(|oh| oh.eq_ignore_ascii_case(host)),
        // No Origin header at all: allowed only where no session is at stake.
        (None, _) => !session,
        _ => false,
    }
}

#[derive(serde::Deserialize, Default)]
pub struct RangeQuery {
    pub range: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    async fn headers(path: &str, cookie: Option<&str>) -> axum::http::HeaderMap {
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "page" }))
            .route(
                "/feed",
                axum::routing::get(|| async {
                    (
                        [(axum::http::header::CACHE_CONTROL, "public, max-age=60")],
                        "feed",
                    )
                }),
            )
            .layer(axum::middleware::from_fn(security_headers));
        let mut req = axum::http::Request::get(path);
        if let Some(c) = cookie {
            req = req.header(axum::http::header::COOKIE, c);
        }
        let res = app
            .oneshot(req.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        res.headers().clone()
    }

    #[tokio::test]
    async fn signed_in_pages_are_never_cached() {
        let h = headers("/", Some("theme=dark; __Host-peephole_session=x")).await;
        assert_eq!(h[axum::http::header::CACHE_CONTROL], "private, no-store");
        let h = headers("/feed", Some("peephole_session=x")).await;
        assert_eq!(h[axum::http::header::CACHE_CONTROL], "private, no-store");
        // Anonymous visitors keep the handler's caching.
        let h = headers("/feed", None).await;
        assert_eq!(h[axum::http::header::CACHE_CONTROL], "public, max-age=60");
        let h = headers("/", Some("theme=dark")).await;
        assert!(!h.contains_key(axum::http::header::CACHE_CONTROL));
        assert_eq!(h[axum::http::header::VARY], "Cookie");
    }

    #[tokio::test]
    async fn error_page_nav_follows_the_session_cookie() {
        let body = |cookie: Option<&'static str>| async move {
            let app = axum::Router::new()
                .fallback(error::not_found)
                .layer(axum::middleware::from_fn(security_headers));
            let mut req = axum::http::Request::get("/nowhere");
            if let Some(c) = cookie {
                req = req.header(axum::http::header::COOKIE, c);
            }
            let res = app
                .oneshot(req.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), axum::http::StatusCode::NOT_FOUND);
            let b = axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap();
            String::from_utf8(b.to_vec()).unwrap()
        };
        let signed_in = body(Some("__Host-peephole_session=x")).await;
        assert!(signed_in.contains("Log out"), "{signed_in}");
        let anonymous = body(None).await;
        assert!(anonymous.contains("Admin login"), "{anonymous}");
        assert!(!anonymous.contains("Log out"));
    }

    /// What a refused write must leave as is: scan jobs and spent quotes.
    async fn jobs_and_spent(state: &AdminState) -> (i64, i64) {
        let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs")
            .fetch_one(&state.store.pool)
            .await
            .unwrap();
        let spent: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_actions")
            .fetch_one(&state.store.pool)
            .await
            .unwrap();
        (jobs, spent)
    }

    /// `req` with the browser headers of `site`: pairs of header and value.
    fn with(
        mut req: axum::http::request::Builder,
        site: &[(&str, &str)],
    ) -> axum::http::request::Builder {
        req = req.header(axum::http::header::HOST, "localhost");
        for (k, v) in site {
            req = req.header(*k, *v);
        }
        req
    }

    /// Headers a cross-site or sandboxed page sends with a write. Each is
    /// refused (MIK-372 T1).
    const FOREIGN: &[&[(&str, &str)]] = &[
        &[("origin", "https://evil.example")],
        // Same host name, other port: another origin.
        &[("origin", "https://localhost:8443")],
        // A sandboxed iframe or a redirect chain.
        &[("origin", "null")],
        &[("sec-fetch-site", "cross-site")],
        // A sibling vhost behind the same proxy.
        &[("sec-fetch-site", "same-site")],
        // Fetch metadata wins over a matching Origin.
        &[
            ("sec-fetch-site", "cross-site"),
            ("origin", "https://localhost"),
        ],
    ];

    /// Headers of the admin's own pages: allowed.
    const OWN: &[&[(&str, &str)]] = &[
        &[("origin", "https://localhost")],
        &[("sec-fetch-site", "same-origin")],
        &[
            ("sec-fetch-site", "same-origin"),
            ("origin", "https://localhost"),
        ],
        // Typed into the address bar / a bookmark.
        &[("sec-fetch-site", "none")],
    ];

    #[tokio::test]
    async fn a_cross_site_form_post_is_refused_and_queues_nothing() {
        use crate::admin::scan_buy::tests::{IP, state};
        let (state, cookie, _ip, _d) = state().await;
        let app = full_router(state.clone());
        let form = |site: &[(&str, &str)]| {
            with(axum::http::Request::post("/admin/lookup/scan"), site)
                .header("cookie", &cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!("ip={IP}&level=2")))
                .unwrap()
        };
        for site in FOREIGN {
            let r = app.clone().oneshot(form(site)).await.unwrap();
            assert_eq!(r.status(), 403, "{site:?}");
            let b = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&b[..], b"cross-site request refused", "{site:?}");
            assert_eq!(jobs_and_spent(&state).await, (0, 0), "{site:?}");
        }
        // The same post from the admin's own page goes through.
        let r = app.clone().oneshot(form(OWN[0])).await.unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(jobs_and_spent(&state).await, (1, 0));
        // Reading a page from anywhere is not a write.
        let r = app
            .oneshot(
                with(
                    axum::http::Request::get("/admin/investigate/lookup"),
                    FOREIGN[0],
                )
                .header("cookie", &cookie)
                .body(axum::body::Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn every_own_origin_form_post_goes_through() {
        use crate::admin::scan_buy::tests::{IP, state};
        for (level, site) in OWN.iter().enumerate() {
            let (state, cookie, _ip, _d) = state().await;
            let r = full_router(state.clone())
                .oneshot(
                    with(axum::http::Request::post("/admin/lookup/scan"), site)
                        .header("cookie", &cookie)
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(axum::body::Body::from(format!(
                            "ip={IP}&level={}",
                            level + 1
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), 303, "{site:?}");
            assert_eq!(jobs_and_spent(&state).await, (1, 0), "{site:?}");
        }
    }

    /// The guard sits in front of the JSON API too: a cross-site buy is
    /// refused before the quote is spent; the same buy from the own origin
    /// spends it.
    #[tokio::test]
    async fn a_cross_site_json_buy_is_refused_and_spends_no_quote() {
        use crate::admin::scan_buy::tests::{IP, state};
        let (state, _cookie, _ip, _d) = state().await;
        let app = full_router(state.clone());
        let code = state
            .store
            .mint_pairing_code("read,act", "admin")
            .await
            .unwrap();
        let (_, token) = state
            .store
            .redeem_pairing_code(&code, "Pixel 8")
            .await
            .unwrap()
            .unwrap();
        let bearer = format!("Bearer {token}");
        // The quote is a read: no Origin check.
        let r = app
            .clone()
            .oneshot(
                with(
                    axum::http::Request::get(format!("/api/v1/ips/{IP}/scan/quote?level=2")),
                    FOREIGN[0],
                )
                .header("authorization", &bearer)
                .body(axum::body::Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        let q: serde_json::Value = serde_json::from_slice(&b).unwrap();
        let body = serde_json::json!({"quote_id": q["quote_id"]}).to_string();
        let buy = |site: &[(&str, &str)]| {
            with(
                axum::http::Request::post(format!("/api/v1/ips/{IP}/scan")),
                site,
            )
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.clone()))
            .unwrap()
        };
        for site in FOREIGN {
            let r = app.clone().oneshot(buy(site)).await.unwrap();
            assert_eq!(r.status(), 403, "{site:?}");
            assert_eq!(jobs_and_spent(&state).await, (0, 0), "{site:?}");
        }
        // The quote was not spent by the refusals: it buys now.
        let r = app.oneshot(buy(OWN[0])).await.unwrap();
        assert_eq!(r.status(), 202);
        assert_eq!(jobs_and_spent(&state).await, (1, 1));
    }

    /// A write with a session cookie but neither Origin nor Sec-Fetch-Site
    /// is refused (MIK-372 S2); Sec-Fetch-Site alone suffices; without a
    /// session cookie (the sign-in ceremony) neither is needed.
    #[tokio::test]
    async fn a_signed_in_write_without_origin_or_fetch_metadata_is_refused() {
        use crate::admin::scan_buy::tests::{IP, post, state};
        let (state, cookie, _ip, _d) = state().await;
        let bare = |level: u8| {
            let mut req = post(&cookie, &format!("ip={IP}&level={level}"));
            req.headers_mut().remove("origin");
            req.headers_mut().remove("sec-fetch-site");
            req
        };
        let r = full_router(state.clone()).oneshot(bare(2)).await.unwrap();
        assert_eq!(r.status(), 403);
        assert_eq!(jobs_and_spent(&state).await, (0, 0));
        // Fetch metadata without an Origin (some same-origin requests).
        let mut req = bare(2);
        req.headers_mut()
            .insert("sec-fetch-site", "same-origin".parse().unwrap());
        let r = full_router(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(jobs_and_spent(&state).await, (1, 0));
        // An Origin without a Host to compare it to is refused.
        let mut req = bare(3);
        req.headers_mut().remove("host");
        req.headers_mut()
            .insert("origin", "https://localhost".parse().unwrap());
        let r = full_router(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(r.status(), 403);
        assert_eq!(jobs_and_spent(&state).await, (1, 0));
        // No session cookie: the sign-in ceremony needs neither header.
        let r = full_router(state.clone())
            .oneshot(
                axum::http::Request::post("/login/start")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 412, "no keys enrolled: the handler ran");
    }
}
