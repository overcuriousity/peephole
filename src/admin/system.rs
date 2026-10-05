//! System: this node's intel feeds, settings, admin keys and export.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use crate::store::stats::intel_stale;
use askama::Template;
use axum::{
    Router,
    extract::{Form, Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use std::collections::HashMap;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/system", get(status))
        .route("/admin/system/settings", get(settings))
        .route("/admin/system/keys", get(keys))
        .route("/admin/keys/delete", post(key_delete))
        .route("/admin/system/export", get(export_page))
        .route("/admin/export/download", get(export_download))
        // Moved pages; old bookmarks keep working.
        .route(
            "/admin/keys",
            get(|| async { Redirect::permanent("/admin/system/keys") }),
        )
        .route(
            "/admin/export",
            get(|| async { Redirect::permanent("/admin/system/export") }),
        )
}

fn chrome() -> Chrome {
    Chrome::new(true, "admin")
}

/// The intel feeds as this node sees them.
pub struct IntelStatus {
    pub tor_fetch: String,
    pub maxmind_fetch: String,
    /// Tor or GeoIP data missing or older than 48 h.
    pub stale: bool,
    /// `(label, state)` per API provider.
    pub api: Vec<(&'static str, String)>,
}

/// The intel feeds' fetch times (`intel_meta`).
async fn intel_meta(st: &AdminState) -> AppResult<HashMap<String, String>> {
    Ok(
        sqlx::query_as::<_, (String, String)>("SELECT key, value FROM intel_meta")
            .fetch_all(&st.store.pool)
            .await?
            .into_iter()
            .collect(),
    )
}

/// Tor or GeoIP data missing or older than 48 h (cheap: one small table).
pub(crate) async fn intel_is_stale(st: &AdminState) -> AppResult<bool> {
    Ok(intel_stale(&intel_meta(st).await?))
}

pub(crate) async fn intel_status(st: &AdminState) -> AppResult<IntelStatus> {
    let intel = intel_meta(st).await?;
    let fetched = |k: &str| intel.get(k).cloned().unwrap_or_else(|| "never".into());
    Ok(IntelStatus {
        stale: intel_stale(&intel),
        tor_fetch: fetched("tor_last_fetch"),
        maxmind_fetch: match (
            intel.get("maxmind_last_fetch"),
            intel.get(crate::intel::MAXMIND_CLUSTER_SEEN),
        ) {
            (None, Some(seen)) => format!("via a cluster member (seen {seen})"),
            _ => fetched("maxmind_last_fetch"),
        },
        api: api_provider_states(st).await?,
    })
}

/// Each API provider's state as this node sees it: its own budget and
/// pause, or whether a cluster member serves it; and how many lookups the
/// dataset holds.
async fn api_provider_states(st: &AdminState) -> anyhow::Result<Vec<(&'static str, String)>> {
    let counts: HashMap<String, i64> = sqlx::query_as::<_, (String, i64)>(
        "SELECT provider, COUNT(*) FROM ip_intel_log GROUP BY provider",
    )
    .fetch_all(&st.store.read)
    .await?
    .into_iter()
    .collect();
    let served_elsewhere = |name: &str| {
        st.recorder.node().is_some_and(|node| {
            let me = node.id();
            node.live_members(std::time::Duration::from_secs(45))
                .into_iter()
                .any(|id| {
                    id != me
                        && node
                            .status
                            .known(&id)
                            .is_some_and(|k| k.hb.providers.iter().any(|n| n == name))
                })
        })
    };
    Ok(crate::intel::KNOWN_PROVIDERS
        .iter()
        .filter(|p| p.api)
        .map(|p| {
            let here = st.providers.iter().find(|x| x.name() == p.name);
            let mut state = match here {
                Some(x) => {
                    let s = x.status().unwrap_or_default();
                    if x.ready() {
                        format!("active · {s}")
                    } else {
                        format!("waiting · {s}")
                    }
                }
                None if served_elsewhere(p.name) => "via a cluster member".to_string(),
                None => "not configured".to_string(),
            };
            if let Some(n) = counts.get(p.name) {
                state.push_str(&format!(" · {n} lookups recorded"));
            }
            (p.label, state)
        })
        .collect())
}

#[derive(Template)]
#[template(path = "admin_system.html")]
struct StatusPage {
    chrome: Chrome,
    intel: IntelStatus,
    /// Shared intel files; None on a standalone node.
    shared: Option<Vec<crate::admin::cluster::IntelView>>,
    rules: &'static str,
    rules_short: String,
    /// How full this node's tarpit is; None without a trap here.
    tarpit: Option<String>,
}

/// This node's tarpit, as System › Status says it.
fn tarpit_line(s: crate::trap::tarpit::Status) -> String {
    if s.pool == 0 {
        return "off".into();
    }
    let plural = if s.marked == 1 { "" } else { "s" };
    let mut line = format!(
        "{} of {} connections held ({} %) · {} source{plural} marked",
        s.held,
        s.pool,
        s.held * 100 / s.pool,
        s.marked
    );
    if s.held >= s.pool {
        line.push_str(" · full: new requests get the normal answer");
    }
    line
}

async fn status(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    let shared = match st.recorder.node() {
        Some(node) => Some(crate::admin::cluster::intel(node).await?),
        None => None,
    };
    let rules = crate::admin::cluster::builtin_rules();
    render(&StatusPage {
        chrome: chrome(),
        intel: intel_status(&st).await?,
        shared,
        rules,
        rules_short: rules
            .chars()
            .take(crate::admin::cluster::SHORT_HASH)
            .collect(),
        tarpit: st.tarpit.as_ref().map(|t| tarpit_line(t.status())),
    })
}

#[derive(Template)]
#[template(path = "admin_system_settings.html")]
struct SettingsPage {
    chrome: Chrome,
    settings: crate::admin::cluster::SettingsView,
    audit: Vec<crate::admin::cluster::AuditView>,
}

async fn settings(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    render(&SettingsPage {
        chrome: chrome(),
        settings: crate::admin::cluster::SettingsView::of(&st),
        audit: crate::admin::cluster::audit_views(&st).await?,
    })
}

#[derive(Template)]
#[template(path = "admin_export.html")]
struct ExportPage {
    chrome: Chrome,
}

async fn export_page(_u: SessionUser) -> AppResult<Html<String>> {
    render(&ExportPage { chrome: chrome() })
}

async fn export_download(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    // The form submits blank fields; blank means "no filter".
    let field = |k: &str| q.get(k).map(|v| v.trim()).filter(|v| !v.is_empty());
    let filter = crate::export::ExportFilter {
        from: field("from").map(|v| crate::store::browse::ts_bound(v, false)),
        to: field("to").map(|v| crate::store::browse::ts_bound(v, true)),
        ip: field("ip").map(crate::store::browse::canonical_ip),
        label: field("label").map(str::to_string),
        min_severity: field("min_severity").and_then(|s| s.parse().ok()),
    };
    use crate::export::Format;
    let (format, ext, mime) = match q.get("format").map(String::as_str) {
        Some("csv") => (Format::Csv, "csv", "text/csv"),
        Some("jsonl") => (Format::Jsonl, "jsonl", "application/x-ndjson"),
        Some("parquet") => (Format::Parquet, "parquet", "application/octet-stream"),
        _ => return (StatusCode::BAD_REQUEST, "format must be csv|jsonl|parquet").into_response(),
    };
    let mode = match q.get("mode").map(String::as_str) {
        None | Some("" | "full") => crate::export::Mode::Full,
        Some("redistributable") => crate::export::Mode::Redistributable,
        _ => return (StatusCode::BAD_REQUEST, "mode must be full|redistributable").into_response(),
    };
    let names = match state.recorder.node() {
        Some(node) => match crate::cluster::members::all(&node.store).await {
            Ok(m) => m.into_iter().map(|m| (m.id.0.to_vec(), m.name)).collect(),
            Err(e) => {
                tracing::warn!(?e, "export: reading member names");
                HashMap::new()
            }
        },
        None => HashMap::new(),
    };
    // Streamed, uncapped: rows are read and written page by page.
    let body = axum::body::Body::from_stream(crate::export::stream_requests(
        state.store.clone(),
        filter,
        format,
        crate::export::ExportOptions { mode, names },
    ));
    (
        [
            (header::CONTENT_TYPE, mime.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"peephole-export.{ext}\""),
            ),
        ],
        body,
    )
        .into_response()
}

struct KeyRow {
    id: String,
    short: String,
    label: String,
    created: String,
}

#[derive(Template)]
#[template(path = "admin_keys.html")]
struct KeysPage {
    chrome: Chrome,
    keys: Vec<KeyRow>,
    can_delete: bool,
}

async fn keys(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    let keys: Vec<KeyRow> = st
        .store
        .list_credential_labels()
        .await?
        .into_iter()
        .map(|(id, label, created)| KeyRow {
            short: id.chars().take(16).collect(),
            id,
            label,
            created,
        })
        .collect();
    render(&KeysPage {
        chrome: chrome(),
        can_delete: keys.len() > 1,
        keys,
    })
}

#[derive(serde::Deserialize)]
pub struct KeyDeleteForm {
    cred_id: String,
}

async fn key_delete(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Form(f): Form<KeyDeleteForm>,
) -> Redirect {
    // SQLite hex() is uppercase; normalize before decoding.
    if let Ok(bytes) = data_encoding::HEXLOWER.decode(f.cred_id.to_lowercase().as_bytes()) {
        // Never delete the last remaining key (would lock the admin out). The
        // check and delete are one atomic statement, so two concurrent deletes
        // cannot both pass and leave zero keys.
        let _ = state.store.delete_credential_keeping_last(&bytes).await;
    }
    Redirect::to("/admin/system/keys")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trap::tarpit::Status;

    #[test]
    fn the_tarpit_line_says_how_full_it_is() {
        let s = |held, pool, marked| Status { held, pool, marked };
        assert_eq!(tarpit_line(s(0, 0, 0)), "off");
        assert_eq!(
            tarpit_line(s(3, 256, 12)),
            "3 of 256 connections held (1 %) · 12 sources marked"
        );
        assert_eq!(
            tarpit_line(s(256, 256, 1)),
            "256 of 256 connections held (100 %) · 1 source marked · full: new requests get the normal answer"
        );
    }
}
