pub mod assets;
pub mod auth;
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
            store,
            cfg,
            notifier,
            stats_cache: crate::store::stats::StatsCache::new(),
            pace,
        }
    }
    /// Route writes through `recorder` (a cluster node's log).
    pub fn with_recorder(mut self, recorder: crate::store::recorder::Recorder) -> Self {
        self.recorder = recorder;
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
    res
}

#[derive(serde::Deserialize, Default)]
pub struct RangeQuery {
    pub range: Option<String>,
}
