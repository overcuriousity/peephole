pub mod auth;
pub mod sse;

use crate::config::Config;
use crate::store::Store;
use axum::{Router, extract::State, response::{Html, IntoResponse, Json}, routing::get};
use std::sync::Arc;

pub struct AdminState {
    pub store: Store,
    pub cfg: Config,
}

impl AdminState {
    /// Public-only state (Tasks 9–11 extend this struct with auth).
    pub fn public_only(store: Store, cfg: Config) -> Self {
        Self { store, cfg }
    }
}

pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/api/stats", get(stats_json))
        .route("/api/queue", get(sse::queue_stream))
        .with_state(state)
}

/// Full admin router including auth + authenticated routes (Task 10 mounts its
/// routes behind `auth::SessionUser` here too).
pub fn router_with_auth(store: Store, cfg: Config) -> Router {
    let state = Arc::new(AdminState::public_only(store, cfg));
    // Gated placeholders until Tasks 10–11 mount the real detail/export routes.
    let stubs = Router::new()
        .route("/requests", get(auth_placeholder))
        .route("/ips/{id}", get(auth_placeholder))
        .route("/inbox", get(auth_placeholder))
        .route("/export", get(auth_placeholder))
        .route("/keys", get(auth_placeholder))
        .with_state(state.clone());
    router(state.clone())
        .merge(auth::auth_routes().with_state(state.clone()))
        .merge(stubs)
}

async fn auth_placeholder(_u: auth::SessionUser) -> impl IntoResponse {
    (axum::http::StatusCode::NOT_IMPLEMENTED, "landing in Tasks 10–11")
}

async fn dashboard(State(state): State<Arc<AdminState>>) -> impl IntoResponse {
    let stats = state.store.public_stats().await.unwrap_or_else(|_| crate::store::PublicStats::default_stats());
    Html(render_dashboard(&stats))
}

async fn stats_json(State(state): State<Arc<AdminState>>) -> impl IntoResponse {
    match state.store.public_stats().await {
        Ok(s) => Json(serde_json::to_value(s).unwrap()).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn render_dashboard(s: &crate::store::PublicStats) -> String {
    let mut rows = String::new();
    for r in &s.recent {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}{}</td></tr>",
            esc(&r.ts), esc(&r.ip), esc(&r.method), esc(&r.path), r.severity,
            esc(&r.country.clone().unwrap_or_default()),
            if r.is_tor { " [tor]" } else { "" },
        ));
    }
    let mut top = String::new();
    for (ip, c) in &s.top_ips {
        top.push_str(&format!("<tr><td>{}</td><td>{c}</td></tr>", esc(ip)));
    }
    // Stale-intel badge (spec §9): warn when tor/maxmind data is older than 48h.
    let stale = |key: &str| -> bool {
        s.intel.get(key)
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .map(|t| chrono::Utc::now().signed_duration_since(t).num_hours() > 48)
            .unwrap_or(true)
    };
    let badge = if stale("tor_last_fetch") || stale("maxmind_last_fetch") {
        "<div style=\"background:#fef3c7;color:#92400e;border:1px solid #f59e0b;border-radius:8px;padding:.5rem 1rem;margin-bottom:1rem\">Intel data missing or older than 48h — check the intel scheduler.</div>"
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
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
