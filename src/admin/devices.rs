//! Admin → Devices: pair a companion app (single-use code in a QR, 5
//! minutes), mint API keys, and revoke either. The code is never stored
//! (its SHA-256 is, briefly) and never logged; it is rendered once, here.
//! An API key is a device row of kind `api_key` (same token, scopes,
//! revocation and audit); its token is rendered once, in the response to
//! the POST that mints it, and never logged.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use askama::Template;
use axum::{
    Router,
    extract::{Form, State},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use axum_extra::extract::CookieJar;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/system/devices", get(page))
        .route("/admin/devices/pair", post(pair))
        .route("/admin/devices/keys", post(create_key))
        .route("/admin/devices/revoke", post(revoke))
}

/// A freshly minted API key, shown once.
pub struct NewKey {
    label: String,
    token: String,
    scopes: String,
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
    /// Paired devices and admin-minted API keys, each newest first.
    devices: Vec<crate::store::devices::Device>,
    keys: Vec<crate::store::devices::Device>,
    pair: Option<Pairing>,
    new_key: Option<NewKey>,
    /// What devices queued, newest first.
    actions: Vec<crate::store::devices::DeviceAction>,
}

/// Rows of the Recent actions table.
const RECENT_ACTIONS: i64 = 50;

async fn render_page(
    state: &AdminState,
    pair: Option<Pairing>,
    new_key: Option<NewKey>,
) -> AppResult<Html<String>> {
    let (keys, devices) = state
        .store
        .list_devices()
        .await?
        .into_iter()
        .partition(|d| d.is_api_key());
    render(&DevicesPage {
        chrome: Chrome::new(true, "admin"),
        devices,
        keys,
        pair,
        new_key,
        actions: state.store.recent_device_actions(RECENT_ACTIONS).await?,
    })
}

async fn page(_u: SessionUser, State(state): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    render_page(&state, None, None).await
}

/// Who the signed-in admin is, for "paired by" / "created by".
async fn admin_label(state: &AdminState, jar: &CookieJar) -> anyhow::Result<String> {
    match crate::admin::auth::session_token(state, jar) {
        Some(t) => state.store.session_admin_label(&t).await,
        None => Ok("admin".to_string()),
    }
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
    let by = admin_label(&state, &jar).await?;
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
        None,
    )
    .await
}

/// Longest API key label (the same rule as a device name).
const LABEL_MAX: usize = 80;

#[derive(serde::Deserialize)]
pub struct KeyForm {
    label: String,
    /// Checkbox: grant the `act` scope too. Off by default.
    act: Option<String>,
}

/// Mint an API key and render the page with it, once: no redirect, which
/// would lose the key or carry it in a flash cookie.
async fn create_key(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    jar: CookieJar,
    Form(f): Form<KeyForm>,
) -> AppResult<Response> {
    let label = f.label.trim();
    if label.is_empty() || label.chars().count() > LABEL_MAX {
        return Ok(crate::admin::pages::redirect_with_error(
            "/admin/system/devices",
            "A key label is 1-80 characters.",
        ));
    }
    let scopes = if f.act.is_some() { "read,act" } else { "read" };
    let by = admin_label(&state, &jar).await?;
    let (key, token) = state.store.create_api_key(label, scopes, &by).await?;
    tracing::info!(id = %key.id, label = %key.name, scopes, by = %by, "api key minted");
    let page = render_page(
        &state,
        None,
        Some(NewKey {
            label: key.name,
            token,
            scopes: scopes.to_string(),
        }),
    )
    .await?;
    Ok(page.into_response())
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
        Ok(true) => crate::admin::pages::redirect_with_notice("/admin/system/devices", "Revoked."),
        Ok(false) => crate::admin::pages::redirect_with_error(
            "/admin/system/devices",
            "No such device or key.",
        ),
        Err(e) => {
            tracing::warn!(?e, "could not revoke the device");
            crate::admin::pages::redirect_with_error(
                "/admin/system/devices",
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
            axum::http::Request::get("/admin/system/devices"),
            Body::empty(),
        )
        .await;
        assert_eq!(st, axum::http::StatusCode::SEE_OTHER);
        let get = || {
            axum::http::Request::get("/admin/system/devices")
                .header("cookie", &cookie)
                .header("sec-fetch-site", "same-origin")
        };
        let (st, _, html) = send(&app, get(), Body::empty()).await;
        assert_eq!(st, 200);
        assert!(html.contains("No devices paired yet"), "{html}");
        // MIK-501 (P33, G21): one line each.
        assert!(html.contains(
            "<span class=\"mono\">read</span> is always granted; <span class=\"mono\">act</span> also starts probes and buys counter-scans (spends credits).</p>"
        ));
        assert!(html.contains("Also grant <span class=\"mono\">act</span></label>"));
        assert!(!html.contains("machine API"));
        // Pair, with the act scope: the QR and its payload render inline.
        let (st, _, html) = send(
            &app,
            axum::http::Request::post("/admin/devices/pair")
                .header("cookie", &cookie)
                .header("sec-fetch-site", "same-origin")
                .header("content-type", "application/x-www-form-urlencoded"),
            Body::from("act=1"),
        )
        .await;
        assert_eq!(st, 200);
        assert!(html.contains("<svg"), "{html}");
        assert!(
            html.contains("minutes; the code works once.</p>"),
            "P33: {html}"
        );
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
                .header("sec-fetch-site", "same-origin")
                .header("content-type", "application/x-www-form-urlencoded"),
            Body::from(format!("id={}", device.id)),
        )
        .await;
        assert_eq!(st, axum::http::StatusCode::SEE_OTHER);
        let set = headers["set-cookie"].to_str().unwrap();
        assert!(set.starts_with("peephole_flash=Revoked."), "{set}");
        let (_, _, html) = send(&app, get(), Body::empty()).await;
        assert!(html.contains("revoked"), "{html}");
        let (st, headers, _) = send(
            &app,
            axum::http::Request::post("/admin/devices/revoke")
                .header("cookie", &cookie)
                .header("sec-fetch-site", "same-origin")
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

    /// The API key in a page that shows it: the `data-copy` panel.
    fn shown_key(html: &str) -> Option<String> {
        let rest = html
            .split("<pre class=\"panel mono break\" data-copy>")
            .nth(1)?;
        Some(rest.split('<').next()?.to_string())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_api_key_is_minted_shown_once_used_and_revoked() {
        let (state, cookie, app, _d) = app().await;
        let mint = |cookie: Option<&str>, body: &'static str| {
            let mut r = axum::http::Request::post("/admin/devices/keys")
                .header("sec-fetch-site", "same-origin")
                .header("content-type", "application/x-www-form-urlencoded");
            if let Some(c) = cookie {
                r = r.header("cookie", c);
            }
            send(&app, r, Body::from(body))
        };
        // Needs a session.
        let (st, _, _) = mint(None, "label=x").await;
        assert_eq!(st, axum::http::StatusCode::SEE_OTHER);
        // A label is 1-80 characters (trimmed).
        let long = format!("label={}", "x".repeat(81)).leak();
        for bad in ["label=", "label=++", long] {
            let (st, h, _) = mint(Some(&cookie), bad).await;
            assert_eq!(st, axum::http::StatusCode::SEE_OTHER, "{bad}");
            assert_eq!(h[axum::http::header::LOCATION], "/admin/system/devices");
        }
        assert!(state.store.list_devices().await.unwrap().is_empty());
        // Minted: the response page carries the key once, uncached, and the
        // log names the key but never carries its token.
        let ((st, h, html), logs) =
            crate::test_log::capture(mint(Some(&cookie), "label=SIEM+enrichment")).await;
        assert_eq!(st, 200);
        assert!(
            h[axum::http::header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("no-store")
        );
        let token = shown_key(&html).expect("the page shows the key");
        assert_eq!(token.len(), 43, "256-bit base64url");
        assert!(html.contains("Shown once:"), "{html}");
        assert!(html.contains("<h1>Devices and API keys</h1>"));
        assert!(logs.contains("api key minted"), "{logs}");
        assert!(!logs.contains(&token), "the token is never logged");
        let keys = state.store.list_devices().await.unwrap();
        assert_eq!(keys.len(), 1);
        let key = &keys[0];
        assert!(key.is_api_key());
        assert_eq!(
            (
                key.name.as_str(),
                key.scopes.as_str(),
                key.paired_by.as_str()
            ),
            ("SIEM enrichment", "read", "password"),
            "act is off by default; created by the session's admin"
        );
        // A second GET lists the key, but not its token.
        let get = || {
            axum::http::Request::get("/admin/system/devices")
                .header("cookie", &cookie)
                .header("sec-fetch-site", "same-origin")
        };
        let (st, _, html) = send(&app, get(), Body::empty()).await;
        assert_eq!(st, 200);
        assert!(!html.contains(&token), "shown once");
        assert!(shown_key(&html).is_none());
        assert!(html.contains("SIEM enrichment"), "{html}");
        assert!(
            html.contains("No devices paired yet"),
            "keys are not devices"
        );
        // It works on /api/v1, with no log line carrying it either.
        let use_key = || {
            axum::http::Request::get("/api/v1/ips")
                .header("authorization", format!("Bearer {token}"))
        };
        let ((st, _, _), logs) =
            crate::test_log::capture(send(&app, use_key(), Body::empty())).await;
        assert_eq!(st, 200);
        assert!(!logs.contains(&token));
        // `act` is the checkbox.
        let (st, _, html) = mint(Some(&cookie), "label=bot&act=1").await;
        assert_eq!(st, 200);
        let act = shown_key(&html).unwrap();
        assert_ne!(act, token);
        let d = state
            .store
            .validate_device_token(&act)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(d.scopes, "read,act");
        // Revoked: 401 on the next call.
        let (st, h, _) = send(
            &app,
            axum::http::Request::post("/admin/devices/revoke")
                .header("cookie", &cookie)
                .header("sec-fetch-site", "same-origin")
                .header("content-type", "application/x-www-form-urlencoded"),
            Body::from(format!("id={}", key.id)),
        )
        .await;
        assert_eq!(st, axum::http::StatusCode::SEE_OTHER);
        assert_eq!(h[axum::http::header::LOCATION], "/admin/system/devices");
        let (st, _, body) = send(&app, use_key(), Body::empty()).await;
        assert_eq!(st, 401);
        assert!(body.contains("\"unauthorized\""), "{body}");
    }
}
