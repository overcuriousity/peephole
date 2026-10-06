pub mod assets;
pub mod auth;
pub mod blocklist;
pub mod cli;
pub mod cluster;
pub mod cluster_access;
pub mod cluster_owner;
pub mod countries;
pub mod decoys;
pub mod error;
pub mod limit;
pub mod links;
pub mod lookup;
pub mod overview;
pub mod pages;
pub mod public;
pub mod scans;
pub mod search;
pub mod sse;
pub mod system;
pub mod views;

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
    /// How members' requests compare with this node's rules (Cluster pages).
    pub rules_check: crate::store::stats::SwrCache<(), cluster::RulesCheck>,
    /// This node's tarpit, for System › Status; None without a trap here.
    pub tarpit: Option<Arc<crate::trap::tarpit::Tarpit>>,
}

impl AdminState {
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
            rules_check: crate::store::stats::SwrCache::new(1),
            tarpit: None,
        }
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
        Self::new(store, cfg, crate::events::Notifier::new(), pace)
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
        .merge(decoys::routes())
        .merge(search::routes())
        .merge(system::routes())
        .merge(scans::routes())
        .merge(overview::routes())
        .merge(lookup::routes())
        .merge(cluster::routes())
        .merge(cluster_access::routes())
        .merge(cluster_owner::routes())
        .fallback(error::not_found)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            limit::enforce,
        ))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

/// Public-only router used by early tests; same middleware.
pub fn router(state: Arc<AdminState>) -> Router {
    full_router(state)
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
    // Non-browser clients (curl, the test suite) send neither and are allowed;
    // the cookie still gates them.
    if method_mutates(&method) && !same_origin(req.headers()) {
        use axum::response::IntoResponse;
        return (
            axum::http::StatusCode::FORBIDDEN,
            "cross-site request refused",
        )
            .into_response();
    }
    // Admin/auth pages must not sit in a shared or back/forward cache after
    // logout (invite tokens, request bodies, headers).
    let sensitive = path.starts_with("/admin")
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
/// and Origin headers. Requests with neither (non-browser clients) are treated
/// as allowed — the SameSite=Strict cookie is the primary control.
fn same_origin(h: &axum::http::HeaderMap) -> bool {
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
        // No Origin header at all: not a cross-site browser form post.
        (None, _) => true,
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
}
