use crate::admin::{AdminState, auth::SessionUser};
use axum::{
    Router,
    extract::{Form, Path, Query, State},
    response::Html,
    routing::{get, post},
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/requests", get(requests_page))
        .route("/requests/{id}", get(request_detail_page))
        .route("/ips/{id}", get(ip_detail_page))
        .route("/inbox", get(inbox_page))
        .route("/keys", get(keys_page))
        .route("/keys/delete", post(key_delete))
}

#[derive(serde::Deserialize, Default)]
pub struct RequestFilter {
    pub ip: Option<String>, pub path: Option<String>, pub label: Option<String>,
    pub severity: Option<i64>, pub country: Option<String>, pub asn: Option<i64>,
    pub from: Option<String>, pub to: Option<String>,
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

async fn requests_page(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Query(f): Query<RequestFilter>,
) -> Html<String> {
    let rows = state.store.search_requests(&f).await.unwrap_or_default();
    let mut trs = String::new();
    for r in &rows {
        trs.push_str(&format!(
            "<tr><td>{}</td><td><a href=\"/ips/{}\">{}</a></td><td>{}</td>\
             <td><a href=\"/requests/{}\">{}</a></td><td>{}</td><td>{}</td></tr>",
            esc(&r.ts), r.ip_id, esc(&r.ip), esc(&r.method), r.id, esc(&r.path),
            r.severity, esc(&r.labels_json)));
    }
    Html(include_str!("../../templates/requests.html").replace("__ROWS__", &trs))
}

async fn request_detail_page(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> Html<String> {
    let d = state.store.request_detail(id).await.ok().flatten();
    Html(match d {
        Some((req, headers_pretty, body_pretty)) => include_str!("../../templates/request_detail.html")
            .replace("__METHOD__", &esc(&req.method))
            .replace("__PATH__", &esc(&req.path))
            .replace("__TS__", &esc(&req.ts.to_string()))
            .replace("__LABELS__", &esc(&req.labels_json))
            .replace("__SEVERITY__", &req.severity.to_string())
            .replace("__HEADERS__", &esc(&headers_pretty))
            .replace("__BODY__", &esc(&body_pretty)),
        None => "<p>not found</p>".to_string(),
    })
}

async fn ip_detail_page(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> Html<String> {
    let d = state.store.ip_detail(id).await.ok().flatten();
    Html(match d {
        Some(page) => include_str!("../../templates/ip_detail.html").replace("__CONTENT__", &page),
        None => "<p>not found</p>".to_string(),
    })
}

async fn inbox_page(_u: SessionUser, State(state): State<Arc<AdminState>>) -> Html<String> {
    let claims = state.store.inbox().await.unwrap_or_default();
    let mut trs = String::new();
    for c in &claims {
        trs.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&c.ts), esc(&c.ip), esc(&c.contact_email.clone().unwrap_or_default()), esc(&c.user_agent)));
    }
    Html(include_str!("../../templates/inbox.html").replace("__ROWS__", &trs))
}

async fn keys_page(_u: SessionUser, State(state): State<Arc<AdminState>>) -> Html<String> {
    let keys = state.store.list_credential_labels().await.unwrap_or_default();
    let mut trs = String::new();
    for (cred_id_hex, label, created) in &keys {
        trs.push_str(&format!(
            "<tr><td><code>{}…</code></td><td>{}</td><td>{}</td>\
             <td><form method=\"post\" action=\"/keys/delete\"><input type=\"hidden\" name=\"cred_id\" value=\"{}\"><button>Remove</button></form></td></tr>",
            esc(&cred_id_hex[..16.min(cred_id_hex.len())]), esc(label), esc(created), esc(cred_id_hex)));
    }
    Html(include_str!("../../templates/keys.html").replace("__ROWS__", &trs))
}

#[derive(serde::Deserialize)]
pub struct KeyDeleteForm { cred_id: String }

async fn key_delete(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Form(f): Form<KeyDeleteForm>,
) -> axum::response::Redirect {
    // SQLite hex() is uppercase; normalize before decoding.
    if let Ok(bytes) = data_encoding::HEXLOWER.decode(f.cred_id.to_lowercase().as_bytes()) {
        // Guard: never delete the last remaining key (would lock the admin out).
        if state.store.load_credentials().await.map(|c| c.len() > 1).unwrap_or(false) {
            let _ = state.store.delete_credential(&bytes).await;
        }
    }
    axum::response::Redirect::to("/keys")
}
