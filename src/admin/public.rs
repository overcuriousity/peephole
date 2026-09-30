//! Unauthenticated pages. Never load admin-only data here.
use crate::admin::countries;
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use crate::admin::{AdminState, RangeQuery};
use crate::store::stats::{MapCounts, Range, Stats, intel_stale};
use askama::Template;
use axum::{
    Router,
    extract::{FromRequestParts, Query, State},
    http::request::Parts,
    response::{Html, IntoResponse, Json, Response},
    routing::get,
};
use std::convert::Infallible;
use std::sync::Arc;

/// `true` when the request carries a valid admin session. Never rejects.
pub struct MaybeUser(pub bool);

impl FromRequestParts<Arc<AdminState>> for MaybeUser {
    type Rejection = Infallible;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AdminState>,
    ) -> Result<Self, Infallible> {
        let jar = axum_extra::extract::CookieJar::from_request_parts(parts, state)
            .await
            .unwrap_or_else(|_| axum_extra::extract::CookieJar::new());
        let ok = match jar.get("peephole_session") {
            Some(c) => state
                .store
                .validate_session(c.value())
                .await
                .unwrap_or(false),
            None => false,
        };
        Ok(MaybeUser(ok))
    }
}

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/", get(wall))
        .route("/api/stats", get(stats_json))
        .route("/api/map", get(map_json))
        .route("/api/countries", get(countries_json))
        .route("/healthz", get(healthz))
}

#[derive(Template)]
#[template(path = "wall.html")]
struct WallPage {
    chrome: Chrome,
    range: Range,
    stats: Arc<Stats>,
    stale: bool,
}

async fn wall(
    MaybeUser(authed): MaybeUser,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<RangeQuery>,
) -> AppResult<Html<String>> {
    let range = Range::parse(q.range.as_deref());
    let stats = state.stats_cache.stats(&state.store, range).await?;
    let stale = intel_stale(&stats.intel);
    render(&WallPage {
        chrome: Chrome::new(authed, "wall"),
        range,
        stats,
        stale,
    })
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

async fn countries_json() -> impl IntoResponse {
    let map: std::collections::HashMap<&'static str, &'static str> =
        countries::TABLE.iter().copied().collect();
    (
        [(axum::http::header::CACHE_CONTROL, "public, max-age=86400")],
        Json(map),
    )
}

async fn healthz(State(state): State<Arc<AdminState>>) -> Response {
    match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.store.pool)
        .await
    {
        Ok(_) => "ok".into_response(),
        Err(e) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
