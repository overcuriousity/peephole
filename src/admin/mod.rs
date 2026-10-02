pub mod assets;
pub mod auth;
pub mod cli;
pub mod cluster;
pub mod countries;
pub mod error;
pub mod pages;
pub mod public;
pub mod sse;
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
            store,
            cfg,
            notifier,
            stats_cache: crate::store::stats::StatsCache::new(),
            pace,
            closing: None,
        }
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
        .merge(public::routes())
        .merge(assets::router())
        .merge(auth::auth_routes())
        .merge(pages::routes())
        .merge(cluster::routes())
        .fallback(error::not_found)
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

    let mut res = next.run(req).await;
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
    }
    res
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
