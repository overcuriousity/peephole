//! Admin → Devices: pair a companion app (single-use code in a QR, 5
//! minutes) and revoke pairings. The code is never stored (its SHA-256 is,
//! briefly) and never logged; it is rendered once, here.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use askama::Template;
use axum::{
    Router,
    extract::{Form, State},
    response::{Html, Response},
    routing::{get, post},
};
use axum_extra::extract::CookieJar;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/devices", get(page))
        .route("/admin/devices/pair", post(pair))
        .route("/admin/devices/revoke", post(revoke))
}

/// A freshly minted pairing code, shown once.
pub struct Pairing {
    /// The QR as inline SVG (server-rendered; CSP is unchanged).
    qr: String,
    /// The QR's payload, for manual entry.
    payload: String,
    scopes: String,
    minutes: i64,
}

#[derive(Template)]
#[template(path = "admin_devices.html")]
struct DevicesPage {
    chrome: Chrome,
    devices: Vec<crate::store::devices::Device>,
    pair: Option<Pairing>,
    /// What devices queued, newest first.
    actions: Vec<crate::store::devices::DeviceAction>,
}

/// Rows of the Recent actions table.
const RECENT_ACTIONS: i64 = 50;

async fn render_page(state: &AdminState, pair: Option<Pairing>) -> AppResult<Html<String>> {
    render(&DevicesPage {
        chrome: Chrome::new(true, "admin"),
        devices: state.store.list_devices().await?,
        pair,
        actions: state.store.recent_device_actions(RECENT_ACTIONS).await?,
    })
}

async fn page(_u: SessionUser, State(state): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    render_page(&state, None).await
}

#[derive(serde::Deserialize)]
pub struct PairForm {
    /// Checkbox: grant the `act` scope too (probes, scans). `read` always is.
    act: Option<String>,
}

async fn pair(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    jar: CookieJar,
    Form(f): Form<PairForm>,
) -> AppResult<Html<String>> {
    let scopes = if f.act.is_some() { "read,act" } else { "read" };
    let by = match crate::admin::auth::session_token(&state, &jar) {
        Some(t) => state.store.session_admin_label(&t).await?,
        None => "admin".to_string(),
    };
    let code = state.store.mint_pairing_code(scopes, &by).await?;
    let mut payload = serde_json::json!({
        "v": 1,
        "origin": state.cfg.webauthn().origin,
        "code": code,
    });
    // Without a configured pin the app falls back to ordinary PKI validation.
    if let Some(pin) = state
        .cfg
        .api_tls_spki_sha256
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        payload["tls_spki_sha256"] = serde_json::json!(pin);
    }
    let payload = serde_json::to_string(&payload).map_err(anyhow::Error::from)?;
    let qr = qrcode::QrCode::new(payload.as_bytes())
        .map_err(anyhow::Error::from)?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(240, 240)
        .build();
    render_page(
        &state,
        Some(Pairing {
            qr,
            payload,
            scopes: scopes.to_string(),
            minutes: crate::store::devices::PAIRING_CODE_MINUTES,
        }),
    )
    .await
}

#[derive(serde::Deserialize)]
pub struct RevokeForm {
    id: String,
}

async fn revoke(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Form(f): Form<RevokeForm>,
) -> Response {
    match state.store.revoke_device(&f.id).await {
        Ok(true) => crate::admin::pages::redirect_with_notice("/admin/devices", "Device revoked."),
        Ok(false) => crate::admin::pages::redirect_with_error("/admin/devices", "No such device."),
        Err(e) => {
            tracing::warn!(?e, "could not revoke the device");
            crate::admin::pages::redirect_with_error(
                "/admin/devices",
                "Could not revoke the device.",
            )
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::admin::AdminState;
    use axum::body::Body;
    use std::sync::Arc;
    use tower::ServiceExt;

    pub(crate) async fn app() -> (Arc<AdminState>, String, axum::Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg: crate::config::Config = toml::from_str(&format!(
            r#"
admin_listen = "127.0.0.1:1"
database_path = "{db}"
data_dir = "{d}"
[roles]
listener = false
scanner = false
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
secure_cookies = false
"#,
            db = dir.path().join("t.db").display(),
            d = dir.path().display()
        ))
        .unwrap();
        let store = crate::store::Store::connect(&cfg.database_path)
            .await
            .unwrap();
        let token = store.create_session().await.unwrap();
        let cookie = format!("{}={token}", crate::admin::auth::session_cookie_name(&cfg));
        let state = Arc::new(AdminState::public_only(store, cfg));
        let router = crate::admin::full_router(state.clone());
        (state, cookie, router, dir)
    }

    pub(crate) async fn send(
        app: &axum::Router,
        req: axum::http::request::Builder,
        body: Body,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, String) {
        let r = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = r.status();
        let headers = r.headers().clone();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, headers, String::from_utf8_lossy(&b).into_owned())
    }

    #[tokio::test]
    async fn the_devices_page_pairs_and_revokes() {
        let (state, cookie, app, _d) = app().await;
        // Anonymous: redirected to the login page.
        let (st, _, _) = send(
            &app,
            axum::http::Request::get("/admin/devices"),
            Body::empty(),
        )
        .await;
        assert_eq!(st, axum::http::StatusCode::SEE_OTHER);
        let get = || axum::http::Request::get("/admin/devices").header("cookie", &cookie);
        let (st, _, html) = send(&app, get(), Body::empty()).await;
        assert_eq!(st, 200);
        assert!(html.contains("No devices paired yet"), "{html}");
        // Pair, with the act scope: the QR and its payload render inline.
        let (st, _, html) = send(
            &app,
            axum::http::Request::post("/admin/devices/pair")
                .header("cookie", &cookie)
                .header("content-type", "application/x-www-form-urlencoded"),
            Body::from("act=1"),
        )
        .await;
        assert_eq!(st, 200);
        assert!(html.contains("<svg"), "{html}");
        let html = html.replace("&#34;", "\"");
        assert!(html.contains(r#""origin":"https://localhost""#), "{html}");
        let code = html
            .split(r#""code":""#)
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("the payload carries the code")
            .to_string();
        // The pairing admin resolved from the (password) session.
        let (device, _) = state
            .store
            .redeem_pairing_code(&code, "Pixel 8")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(device.scopes, "read,act");
        assert_eq!(device.paired_by, "password");
        let (st, _, html) = send(&app, get(), Body::empty()).await;
        assert_eq!(st, 200);
        assert!(
            html.contains("Pixel 8") && html.contains("read,act"),
            "{html}"
        );
        // Revoke: flash redirect, then listed as revoked.
        let (st, headers, _) = send(
            &app,
            axum::http::Request::post("/admin/devices/revoke")
                .header("cookie", &cookie)
                .header("content-type", "application/x-www-form-urlencoded"),
            Body::from(format!("id={}", device.id)),
        )
        .await;
        assert_eq!(st, axum::http::StatusCode::SEE_OTHER);
        let set = headers["set-cookie"].to_str().unwrap();
        assert!(set.starts_with("peephole_flash=Device+revoked"), "{set}");
        let (_, _, html) = send(&app, get(), Body::empty()).await;
        assert!(html.contains("revoked"), "{html}");
        let (st, headers, _) = send(
            &app,
            axum::http::Request::post("/admin/devices/revoke")
                .header("cookie", &cookie)
                .header("content-type", "application/x-www-form-urlencoded"),
            Body::from(format!("id={}", device.id)),
        )
        .await;
        assert_eq!(st, axum::http::StatusCode::SEE_OTHER);
        let set = headers["set-cookie"].to_str().unwrap();
        assert!(
            set.starts_with("peephole_flash_error=No+such+device"),
            "{set}"
        );
    }
}
