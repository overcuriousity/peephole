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
        .route("/export", get(export_page))
        .route("/export/download", get(export_download))
}

use crate::store::browse::RequestFilter;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn requests_page(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Query(f): Query<RequestFilter>,
) -> Html<String> {
    let rows = state
        .store
        .search_requests(&f)
        .await
        .map(|p| p.items)
        .unwrap_or_default();
    let mut trs = String::new();
    for r in &rows {
        trs.push_str(&format!(
            "<tr><td>{}</td><td><a href=\"/ips/{}\">{}</a></td><td>{}</td>\
             <td><a href=\"/requests/{}\">{}</a></td><td>{}</td><td>{}</td></tr>",
            esc(&r.ts),
            r.ip_id,
            esc(&r.ip),
            esc(&r.method),
            r.id,
            esc(&r.path),
            r.severity,
            esc(&r.labels_json)
        ));
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
        Some((req, headers_pretty, body_pretty)) => {
            include_str!("../../templates/request_detail.html")
                .replace("__METHOD__", &esc(&req.method))
                .replace("__PATH__", &esc(&req.path))
                .replace("__TS__", &esc(&req.ts.to_string()))
                .replace("__LABELS__", &esc(&req.labels_json))
                .replace("__SEVERITY__", &req.severity.to_string())
                .replace("__HEADERS__", &esc(&headers_pretty))
                .replace("__BODY__", &esc(&body_pretty))
        }
        None => "<p>not found</p>".to_string(),
    })
}

async fn ip_detail_page(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> Html<String> {
    // Interim: replaced by the public/admin IP page in Task 9.
    let Ok(Some(ip)) = state.store.ip_by_id(id).await else {
        return Html("<p>not found</p>".to_string());
    };
    let rows = state
        .store
        .requests_for_ip(id, 1)
        .await
        .map(|p| p.items)
        .unwrap_or_default();
    let mut html = format!("<h1>{}</h1><ul>", esc(&ip.ip));
    for r in &rows {
        html.push_str(&format!("<li>{}</li>", esc(&r.path)));
    }
    html.push_str("</ul>");
    Html(include_str!("../../templates/ip_detail.html").replace("__CONTENT__", &html))
}

async fn inbox_page(_u: SessionUser, State(state): State<Arc<AdminState>>) -> Html<String> {
    let claims = state.store.inbox().await.unwrap_or_default();
    let mut trs = String::new();
    for c in &claims {
        trs.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&c.ts),
            esc(&c.ip),
            esc(&c.contact_email.clone().unwrap_or_default()),
            esc(&c.user_agent)
        ));
    }
    Html(include_str!("../../templates/inbox.html").replace("__ROWS__", &trs))
}

async fn keys_page(_u: SessionUser, State(state): State<Arc<AdminState>>) -> Html<String> {
    let keys = state
        .store
        .list_credential_labels()
        .await
        .unwrap_or_default();
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
pub struct KeyDeleteForm {
    cred_id: String,
}

async fn key_delete(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Form(f): Form<KeyDeleteForm>,
) -> axum::response::Redirect {
    // SQLite hex() is uppercase; normalize before decoding.
    if let Ok(bytes) = data_encoding::HEXLOWER.decode(f.cred_id.to_lowercase().as_bytes()) {
        // Guard: never delete the last remaining key (would lock the admin out).
        if state
            .store
            .load_credentials()
            .await
            .map(|c| c.len() > 1)
            .unwrap_or(false)
        {
            let _ = state.store.delete_credential(&bytes).await;
        }
    }
    axum::response::Redirect::to("/keys")
}

async fn export_page(_u: SessionUser) -> Html<&'static str> {
    Html(include_str!("../../templates/export.html"))
}

async fn export_download(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let filter = crate::export::ExportFilter {
        from: q.get("from").cloned(),
        to: q.get("to").cloned(),
        ip: q.get("ip").cloned(),
        label: q.get("label").cloned(),
        min_severity: q.get("min_severity").and_then(|s| s.parse().ok()),
    };
    let rows = match state.store.export_requests(&filter).await {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let (body, ext, mime) = match q.get("format").map(String::as_str) {
        Some("csv") => (
            crate::export::requests_csv(&rows).into_bytes(),
            "csv",
            "text/csv".to_string(),
        ),
        Some("jsonl") => (
            crate::export::requests_timesketch(&rows).into_bytes(),
            "jsonl",
            "application/x-ndjson".to_string(),
        ),
        Some("parquet") => match crate::export::parquet::requests_parquet(&rows) {
            Ok(b) => (b, "parquet", "application/octet-stream".to_string()),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        _ => return (StatusCode::BAD_REQUEST, "format must be csv|jsonl|parquet").into_response(),
    };
    (
        [
            (axum::http::header::CONTENT_TYPE, mime),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"peephole-export.{ext}\""),
            ),
        ],
        body,
    )
        .into_response()
}
