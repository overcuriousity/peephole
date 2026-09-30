pub mod assets;
pub mod auth;
pub mod detail;
pub mod error;
pub mod sse;
pub mod views;

use crate::admin::error::AppResult;
use crate::config::Config;
use crate::store::Store;
use crate::store::stats::{MapCounts, Range, Stats};
use axum::{
    Router,
    extract::{Query, State},
    response::{Html, Json},
    routing::get,
};
use std::sync::Arc;

pub struct AdminState {
    pub store: Store,
    pub cfg: Config,
    pub notifier: crate::events::Notifier,
    pub stats_cache: crate::store::stats::StatsCache,
}

impl AdminState {
    pub fn new(store: Store, cfg: Config, notifier: crate::events::Notifier) -> Self {
        Self {
            store,
            cfg,
            notifier,
            stats_cache: crate::store::stats::StatsCache::new(),
        }
    }
    /// State with a private notifier (tests, or when nothing publishes).
    pub fn public_only(store: Store, cfg: Config) -> Self {
        Self::new(store, cfg, crate::events::Notifier::new())
    }
}

pub fn router_with_auth(store: Store, cfg: Config) -> Router {
    let state = Arc::new(AdminState::public_only(store, cfg));
    full_router(state)
}

/// Every route on the admin listener: public pages, assets, auth, admin.
pub fn full_router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/api/stats", get(stats_json))
        .route("/api/map", get(map_json))
        .route("/admin/api/queue", get(sse::queue_stream))
        .merge(assets::router())
        .merge(auth::auth_routes())
        .merge(detail::routes())
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

async fn dashboard(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<RangeQuery>,
) -> AppResult<Html<String>> {
    let stats = state
        .stats_cache
        .stats(&state.store, Range::parse(q.range.as_deref()))
        .await?;
    Ok(Html(render_dashboard(&stats)))
}

async fn stats_json(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<RangeQuery>,
) -> AppResult<Json<Arc<Stats>>> {
    Ok(Json(
        state
            .stats_cache
            .stats(&state.store, Range::parse(q.range.as_deref()))
            .await?,
    ))
}

async fn map_json(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<RangeQuery>,
) -> AppResult<Json<Arc<MapCounts>>> {
    Ok(Json(
        state
            .stats_cache
            .map(&state.store, Range::parse(q.range.as_deref()))
            .await?,
    ))
}

/// Interim renderer for the old dashboard template; replaced in Task 8.
fn render_dashboard(s: &Stats) -> String {
    let mut rows = String::new();
    for r in &s.recent {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}{}</td></tr>",
            esc(&r.ts),
            esc(&r.ip),
            esc(&r.method),
            esc(&r.path),
            r.severity,
            esc(&r.country.clone().unwrap_or_default()),
            if r.is_tor { " [tor]" } else { "" },
        ));
    }
    let mut top = String::new();
    for t in &s.top_ips {
        top.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            esc(&t.ip),
            t.count
        ));
    }
    let badge = if crate::store::stats::intel_stale(&s.intel) {
        "<div class=\"banner banner-warning\">Intel data missing or older than 48h — check the intel scheduler.</div>"
    } else {
        ""
    };
    include_str!("../../templates/dashboard.html")
        .replace("__TOTAL__", &s.total_requests.to_string())
        .replace("__UNIQUE_IPS__", &s.unique_ips.to_string())
        .replace("__SCANS__", &s.scans_done.to_string())
        .replace("__RECENT_ROWS__", &rows)
        .replace("__TOP_IP_ROWS__", &top)
        .replace("__INTEL_BADGE__", badge)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
