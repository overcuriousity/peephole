use crate::admin::AdminState;
use crate::store::Store;
use crate::store::auth::{SetupToken, token_hash};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{FromRequestParts, State},
    http::{StatusCode, request::Parts},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use std::sync::Arc;
use webauthn_rs::prelude::*;

/// Session extractor: gates authenticated routes (spec §8.4).
pub struct SessionUser;

impl FromRequestParts<Arc<AdminState>> for SessionUser {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AdminState>,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|e| e.into_response())?;
        if session_valid(state, &jar).await {
            Ok(SessionUser)
        } else {
            Err(Redirect::to("/login").into_response())
        }
    }
}

/// Name of the session cookie. Behind TLS it carries the `__Host-` prefix,
/// so the browser only accepts it with `Secure`, `Path=/` and no `Domain`
/// (a sibling subdomain cannot plant or shadow it). Plain-http test setups
/// (`secure_cookies = false`) cannot use the prefix.
pub fn session_cookie_name(cfg: &crate::config::Config) -> &'static str {
    if cfg.webauthn().secure_cookies {
        "__Host-peephole_session"
    } else {
        "peephole_session"
    }
}

/// Name of the cookie holding a WebAuthn ceremony id (see [`session_cookie_name`]).
fn ceremony_cookie_name(cfg: &crate::config::Config) -> &'static str {
    if cfg.webauthn().secure_cookies {
        "__Host-wa_sid"
    } else {
        "wa_sid"
    }
}

/// The session token the request carries, if any.
pub fn session_token(state: &AdminState, jar: &CookieJar) -> Option<String> {
    jar.get(session_cookie_name(&state.cfg))
        .map(|c| c.value().to_string())
}

/// Whether the request carries a live session.
pub async fn session_valid(state: &AdminState, jar: &CookieJar) -> bool {
    match session_token(state, jar) {
        Some(t) => state.store.validate_session(&t).await.unwrap_or(false),
        None => false,
    }
}

/// First-run setup token (spec §8.4): printed to stdout, only its hash
/// stored. Valid for 24 hours; while no key is enrolled, a start after it
/// expired (or was used up) prints a new one. `peephole admin reset-token`
/// issues one on demand.
pub async fn ensure_setup_token(
    store: &Store,
    _data_dir: &std::path::Path,
) -> Result<Option<String>> {
    let creds = store.load_credentials().await?;
    if !creds.is_empty() {
        return Ok(None);
    }
    match store.setup_token_state().await? {
        // Issued earlier; console output is the only copy.
        SetupToken::Live => Ok(None),
        SetupToken::None | SetupToken::Expired => {
            let token = store.issue_setup_token().await?;
            print_setup_token(&token);
            Ok(Some(token))
        }
    }
}

/// The enrollment instructions with a setup token.
pub fn print_setup_token(token: &str) {
    println!(
        "\n=== peephole admin setup ===\nOpen /enroll on the admin interface and enter this one-time token \
         (valid for {} hours):\n\n  {token}\n",
        crate::store::auth::SETUP_TOKEN_HOURS
    );
}

fn webauthn_for(cfg: &crate::config::Config) -> Result<Webauthn> {
    let origin = Url::parse(&cfg.webauthn().origin).context("webauthn origin")?;
    let builder = WebauthnBuilder::new(&cfg.webauthn().rp_id, &origin)
        .context("webauthn builder")?
        .rp_name(&cfg.webauthn().rp_name);
    builder.build().context("webauthn build")
}

/// Password checks allowed at once.
pub const MAX_VERIFIES: usize = 3;

/// A hash nobody knows the password of, verified when none is set so a
/// request takes as long as a real one (made once with `password::hash`).
const DUMMY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$1+M9O+UgGF/mBHjQrx/Mag$2Zo8y2Txjn+t4vTml5CqtqPDb+ilJMk6j89jzN1FbUc";

pub fn auth_routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/login", get(login_page))
        .route("/login/start", post(login_start))
        .route("/login/finish", post(login_finish))
        .route("/login/password", post(login_password))
        .route("/enroll", get(enroll_page))
        .route("/enroll/start", post(enroll_start))
        .route("/enroll/finish", post(enroll_finish))
        .route("/logout", post(logout))
}

/// A `Path=/`, `HttpOnly`, `SameSite=Strict` cookie, `Secure` behind TLS.
fn cookie(cfg: &crate::config::Config, name: &'static str, value: String) -> Cookie<'static> {
    Cookie::build((name, value))
        .path("/")
        .http_only(true)
        .secure(cfg.webauthn().secure_cookies)
        .same_site(SameSite::Strict)
        .build()
}

fn session_cookie(cfg: &crate::config::Config, token: String) -> Cookie<'static> {
    cookie(cfg, session_cookie_name(cfg), token)
}

/// Cookie carrying only the random id of a server-side ceremony state.
fn ceremony_cookie(cfg: &crate::config::Config, id: String) -> Cookie<'static> {
    cookie(cfg, ceremony_cookie_name(cfg), id)
}

/// Remove a cookie set by [`cookie`]. The removal must carry the same path
/// (and `Secure` for a `__Host-` name) or the browser keeps the original.
fn removal(cfg: &crate::config::Config, name: &'static str) -> Cookie<'static> {
    cookie(cfg, name, String::new())
}

fn clear_ceremony(cfg: &crate::config::Config, jar: CookieJar) -> CookieJar {
    jar.remove(removal(cfg, ceremony_cookie_name(cfg)))
}

/// Refusal when too many ceremonies are open (anonymous clients start them).
fn busy() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, "60")],
        "too many sign-ins in progress; try again in a few minutes",
    )
        .into_response()
}

#[derive(askama::Template)]
#[template(path = "login.html")]
struct LoginPage {
    chrome: crate::admin::views::Chrome,
    passkey: bool,
    password: bool,
    error: Option<String>,
}

#[derive(askama::Template)]
#[template(path = "enroll.html")]
struct EnrollPage {
    chrome: crate::admin::views::Chrome,
}

/// The login page for the chosen sign-in method.
async fn render_login(
    state: &AdminState,
    authed: bool,
    error: Option<String>,
) -> crate::admin::error::AppResult<Html<String>> {
    let method = state.store.login_method().await.unwrap_or_default();
    let has_hash = matches!(state.store.password_hash().await, Ok(Some(_)));
    crate::admin::error::render(&LoginPage {
        chrome: crate::admin::views::Chrome::new(authed, ""),
        passkey: method.passkey(),
        password: method.password() && has_hash,
        error,
    })
}

async fn login_page(
    State(state): State<Arc<AdminState>>,
    crate::admin::public::MaybeUser(authed): crate::admin::public::MaybeUser,
) -> crate::admin::error::AppResult<Html<String>> {
    render_login(&state, authed, None).await
}
async fn enroll_page(
    crate::admin::public::MaybeUser(authed): crate::admin::public::MaybeUser,
) -> crate::admin::error::AppResult<Html<String>> {
    crate::admin::error::render(&EnrollPage {
        chrome: crate::admin::views::Chrome::new(authed, ""),
    })
}

/// An enrollment ceremony's server-side state and what authorised it: the
/// hash of the admin's session (`reg`) or of the setup token (`reg-setup`).
/// The finish re-checks that authority, so a session that ended or a token
/// used or replaced meanwhile enrolls nothing.
#[derive(serde::Serialize, serde::Deserialize)]
struct Enrollment {
    reg: PasskeyRegistration,
    by: String,
}

#[derive(serde::Deserialize)]
pub struct EnrollStart {
    setup_token: Option<String>,
    label: Option<String>,
}

async fn enroll_start(
    State(state): State<Arc<AdminState>>,
    jar: CookieJar,
    Json(body): Json<EnrollStart>,
) -> Response {
    // Either the one-time setup token or a live admin session authorises this.
    let by_token = match &body.setup_token {
        Some(t) if state.store.setup_token_valid(t).await.unwrap_or(false) => Some(token_hash(t)),
        _ => None,
    };
    let by_session = match session_token(&state, &jar) {
        Some(t) if state.store.validate_session(&t).await.unwrap_or(false) => Some(token_hash(&t)),
        _ => None,
    };
    let kind = if by_token.is_some() {
        "reg-setup"
    } else {
        "reg"
    };
    let Some(by) = by_token.or(by_session) else {
        return (StatusCode::FORBIDDEN, "invalid setup token").into_response();
    };
    let wa = match webauthn_for(&state.cfg) {
        Ok(w) => w,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let existing: Vec<Passkey> = state
        .store
        .load_credentials()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, j)| serde_json::from_str(&j).ok())
        .collect();
    match wa.start_passkey_registration(
        Uuid::nil(),
        "admin",
        "admin",
        Some(existing.iter().map(|p| p.cred_id().clone()).collect()),
    ) {
        Ok((ccr, state_reg)) => {
            let label = body.label.clone().unwrap_or_default();
            // The ceremony state (challenge + exclude list) lives server-side.
            // The client only receives a random id, so it cannot substitute a
            // challenge or credential it controls.
            let state_json = serde_json::to_string(&Enrollment { reg: state_reg, by }).unwrap();
            let sid = match state
                .store
                .put_webauthn_state(kind, &state_json, Some(&label))
                .await
            {
                Ok(Some(id)) => id,
                Ok(None) => return busy(),
                Err(e) => {
                    tracing::warn!(?e, "could not store enrollment state");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
                }
            };
            let jar = jar.add(ceremony_cookie(&state.cfg, sid));
            (jar, Json(serde_json::json!({"publicKey": ccr.public_key}))).into_response()
        }
        Err(e) => {
            tracing::warn!(?e, "start_passkey_registration failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub struct EnrollFinish {
    credential: RegisterPublicKeyCredential,
}

async fn enroll_finish(
    State(state): State<Arc<AdminState>>,
    jar: CookieJar,
    Json(body): Json<EnrollFinish>,
) -> Response {
    let cfg = &state.cfg;
    let Some(cookie) = jar.get(ceremony_cookie_name(cfg)) else {
        return (StatusCode::BAD_REQUEST, "no enrollment in progress").into_response();
    };
    // Consume the server-side state (single-use). A forged or replayed id finds nothing.
    // Its kind tells whether the setup token authorised the enrollment.
    let mut by_token = false;
    let mut taken = Ok(None);
    for (kind, token) in [("reg", false), ("reg-setup", true)] {
        taken = state.store.take_webauthn_state(cookie.value(), kind).await;
        if !matches!(taken, Ok(None)) {
            by_token = token;
            break;
        }
    }
    let Ok(Some((state_json, label))) = taken else {
        return (
            StatusCode::BAD_REQUEST,
            clear_ceremony(cfg, jar),
            "no enrollment in progress",
        )
            .into_response();
    };
    let Ok(Enrollment { reg: reg_state, by }) = serde_json::from_str(&state_json) else {
        return (
            StatusCode::BAD_REQUEST,
            clear_ceremony(cfg, jar),
            "corrupt enrollment state",
        )
            .into_response();
    };
    let label = label
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty());
    let wa = match webauthn_for(cfg) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(?e, "webauthn build failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    match wa.finish_passkey_registration(&body.credential, &reg_state) {
        Ok(passkey) => {
            let json = serde_json::to_string(&passkey).unwrap();
            let (cred, label) = (passkey.cred_id(), label.as_deref());
            // The key is stored only if what authorised the start still does,
            // checked in the same transaction. The setup token is used up
            // with it, and a key that was not stored leaves it usable (or the
            // admin is locked out). An admin adding a key with their session
            // leaves a setup token issued meanwhile (e.g. for a colleague)
            // alone.
            let stored = if by_token {
                state
                    .store
                    .save_credential_with_setup_token(cred, &json, label, &by)
                    .await
            } else {
                // The browser must still hold that very session.
                match session_token(&state, &jar) {
                    Some(t) if token_hash(&t) == by => {
                        state
                            .store
                            .save_credential_in_session(cred, &json, label, &by)
                            .await
                    }
                    _ => Ok(false),
                }
            };
            match stored {
                Ok(true) => {}
                Ok(false) => {
                    let why = if by_token {
                        "the setup token was used, replaced or has expired"
                    } else {
                        "the session that started this enrollment has ended; sign in again"
                    };
                    return (StatusCode::FORBIDDEN, clear_ceremony(cfg, jar), why).into_response();
                }
                Err(e) => {
                    tracing::warn!(?e, "could not store the enrolled key");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "could not store the key")
                        .into_response();
                }
            }
            // Only the first key (setup token) signs in, with that key; an
            // admin adding a key keeps their session.
            if !by_token || session_valid(&state, &jar).await {
                return (clear_ceremony(cfg, jar), StatusCode::OK).into_response();
            }
            let old = session_token(&state, &jar);
            match state
                .store
                .create_session_for(passkey.cred_id(), old.as_deref())
                .await
            {
                Ok(Some(token)) => (
                    clear_ceremony(cfg, jar.add(session_cookie(cfg, token))),
                    StatusCode::OK,
                )
                    .into_response(),
                Ok(None) => (
                    StatusCode::FORBIDDEN,
                    clear_ceremony(cfg, jar),
                    "the key was deleted meanwhile",
                )
                    .into_response(),
                Err(e) => {
                    tracing::warn!(?e, "could not create session after enrollment");
                    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
                }
            }
        }
        Err(e) => {
            tracing::info!(?e, "passkey registration rejected");
            (StatusCode::BAD_REQUEST, "registration failed").into_response()
        }
    }
}

/// Refusal when the sign-in method leaves security keys out.
async fn passkey_off(state: &AdminState) -> Option<Response> {
    let method = state.store.login_method().await.unwrap_or_default();
    (!method.passkey())
        .then(|| (StatusCode::FORBIDDEN, "security-key sign-in is off").into_response())
}

async fn login_start(State(state): State<Arc<AdminState>>, jar: CookieJar) -> Response {
    if let Some(off) = passkey_off(&state).await {
        return off;
    }
    let creds = state.store.load_credentials().await.unwrap_or_default();
    let passkeys: Vec<Passkey> = creds
        .into_iter()
        .filter_map(|(_, j)| serde_json::from_str(&j).ok())
        .collect();
    if passkeys.is_empty() {
        return (StatusCode::PRECONDITION_FAILED, "no keys enrolled").into_response();
    }
    let wa = match webauthn_for(&state.cfg) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(?e, "webauthn build failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    match wa.start_passkey_authentication(&passkeys) {
        Ok((rcr, auth_state)) => {
            // Server-side state: the allowed-credential list and challenge stay
            // here, so a client cannot present a key and challenge it controls.
            let state_json = serde_json::to_string(&auth_state).unwrap();
            let sid = match state
                .store
                .put_webauthn_state("auth", &state_json, None)
                .await
            {
                Ok(Some(id)) => id,
                Ok(None) => return busy(),
                Err(e) => {
                    tracing::warn!(?e, "could not store auth state");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
                }
            };
            let jar = jar.add(ceremony_cookie(&state.cfg, sid));
            (jar, Json(serde_json::json!({"publicKey": rcr.public_key}))).into_response()
        }
        Err(e) => {
            tracing::warn!(?e, "start_passkey_authentication failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub struct LoginFinish {
    credential: PublicKeyCredential,
}

async fn login_finish(
    State(state): State<Arc<AdminState>>,
    jar: CookieJar,
    Json(body): Json<LoginFinish>,
) -> Response {
    if let Some(off) = passkey_off(&state).await {
        return off;
    }
    let cfg = &state.cfg;
    let Some(cookie) = jar.get(ceremony_cookie_name(cfg)) else {
        return (StatusCode::BAD_REQUEST, "no login in progress").into_response();
    };
    // Consume the server-side state (single-use), so a captured assertion plus
    // cookie cannot be replayed.
    let Ok(Some((state_json, _))) = state
        .store
        .take_webauthn_state(cookie.value(), "auth")
        .await
    else {
        return (
            StatusCode::BAD_REQUEST,
            clear_ceremony(cfg, jar),
            "no login in progress",
        )
            .into_response();
    };
    let Ok(auth_state) = serde_json::from_str::<PasskeyAuthentication>(&state_json) else {
        return (
            StatusCode::BAD_REQUEST,
            clear_ceremony(cfg, jar),
            "corrupt auth state",
        )
            .into_response();
    };
    let wa = match webauthn_for(cfg) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(?e, "webauthn build failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    match wa.finish_passkey_authentication(&body.credential, &auth_state) {
        Ok(result) => {
            // Persist the updated sign counter / backup state for the key used.
            if result.needs_update()
                && let Ok(creds) = state.store.load_credentials().await
            {
                for (cred_id, j) in creds {
                    if let Ok(mut pk) = serde_json::from_str::<Passkey>(&j)
                        && pk.update_credential(&result) == Some(true)
                    {
                        if let Ok(updated) = serde_json::to_string(&pk) {
                            let _ = state.store.update_credential(&cred_id, &updated).await;
                        }
                        break;
                    }
                }
            }
            // The session belongs to the key used (deleting the key ends
            // it; a key deleted since this sign-in started gets none); a
            // session the browser held before ends now.
            let old = session_token(&state, &jar);
            let used: &[u8] = result.cred_id();
            match state.store.create_session_for(used, old.as_deref()).await {
                Ok(Some(token)) => (
                    clear_ceremony(cfg, jar.add(session_cookie(cfg, token))),
                    StatusCode::OK,
                )
                    .into_response(),
                Ok(None) => {
                    tracing::info!("passkey sign-in with a deleted key rejected");
                    (
                        StatusCode::UNAUTHORIZED,
                        clear_ceremony(cfg, jar),
                        "authentication failed",
                    )
                        .into_response()
                }
                Err(e) => {
                    tracing::warn!(?e, "could not create session");
                    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
                }
            }
        }
        Err(e) => {
            tracing::info!(?e, "passkey authentication rejected");
            (
                StatusCode::UNAUTHORIZED,
                clear_ceremony(cfg, jar),
                "authentication failed",
            )
                .into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub struct PasswordLogin {
    password: String,
}

/// Sign in with the admin password (methods `password` and `both`).
async fn login_password(
    State(state): State<Arc<AdminState>>,
    jar: CookieJar,
    axum::Form(f): axum::Form<PasswordLogin>,
) -> Response {
    let method = state.store.login_method().await.unwrap_or_default();
    if !method.password() {
        return (StatusCode::FORBIDDEN, "password sign-in is off").into_response();
    }
    let phc = match state.store.password_hash().await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(?e, "could not read the password hash");
            None
        }
    };
    // Too many checks at once: refuse rather than queue (memory, threads).
    let Ok(_slot) = state.verify_slots.try_acquire() else {
        return busy();
    };
    let found = phc.is_some();
    let phc = phc.unwrap_or_else(|| DUMMY_PHC.to_string());
    let checked = phc.clone();
    let ok = tokio::task::spawn_blocking(move || crate::admin::password::verify(&f.password, &phc))
        .await
        .unwrap_or(false)
        && found;
    if !ok {
        tracing::info!("password sign-in rejected");
        return match render_login(&state, false, Some("Wrong password.".into())).await {
            Ok(page) => (StatusCode::UNAUTHORIZED, page).into_response(),
            Err(e) => e.into_response(),
        };
    }
    // A session the browser held before ends now. None if the password
    // changed or password sign-in went off while it was being checked.
    let old = session_token(&state, &jar);
    match state
        .store
        .create_password_session(&checked, old.as_deref())
        .await
    {
        Ok(Some(token)) => (
            jar.add(session_cookie(&state.cfg, token)),
            Redirect::to("/admin"),
        )
            .into_response(),
        Ok(None) => {
            tracing::info!("password sign-in overtaken by a sign-in change");
            let why = "The sign-in settings changed meanwhile; try again.";
            match render_login(&state, false, Some(why.into())).await {
                Ok(page) => (StatusCode::CONFLICT, page).into_response(),
                Err(e) => e.into_response(),
            }
        }
        Err(e) => {
            tracing::warn!(?e, "could not create session");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

async fn logout(State(state): State<Arc<AdminState>>, jar: CookieJar) -> Response {
    if let Some(t) = session_token(&state, &jar) {
        let _ = state.store.destroy_session(&t).await;
    }
    let jar = jar.remove(removal(&state.cfg, session_cookie_name(&state.cfg)));
    (jar, Redirect::to("/")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(secure: bool) -> crate::config::Config {
        toml::from_str(&format!(
            r#"
admin_listen = "127.0.0.1:1"
database_path = "/tmp/x.db"
data_dir = "/tmp"
[roles]
listener = false
scanner = false
[webauthn]
rp_id = "x.example"
origin = "https://x.example"
rp_name = "x"
secure_cookies = {secure}
"#
        ))
        .unwrap()
    }

    use crate::store::auth::LoginMethod;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use tower::ServiceExt;

    const PW: &str = "correct horse battery";

    /// The admin app on a fresh database (plain-http cookies).
    async fn app() -> (tempfile::TempDir, Arc<AdminState>, axum::Router) {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(false);
        c.database_path = dir.path().join("t.db");
        let store = Store::connect(&c.database_path).await.unwrap();
        let state = Arc::new(AdminState::public_only(store, c));
        let router = crate::admin::full_router(state.clone());
        (dir, state, router)
    }

    /// One request; `body` is form-encoded, `cookie` a session token.
    async fn send(
        app: &axum::Router,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: &str,
    ) -> (StatusCode, Option<String>, String) {
        let peer: std::net::SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let mut b = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .extension(ConnectInfo(peer))
            .header("content-type", "application/x-www-form-urlencoded");
        if let Some(t) = cookie {
            b = b.header("cookie", format!("peephole_session={t}"));
        }
        let r = app
            .clone()
            .oneshot(b.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = r.status();
        let set = r
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        (status, set, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn set_pw(state: &AdminState, pw: &str) {
        let phc = crate::admin::password::hash(pw).unwrap();
        state.store.set_password_hash(&phc, None).await.unwrap();
    }

    #[tokio::test]
    async fn password_login_follows_the_method() {
        let (_d, state, app) = app().await;
        let form = format!("password={PW}").replace(' ', "+");
        let (st, set, _) = send(&app, "POST", "/login/password", None, &form).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "method passkey");
        assert!(set.is_none());
        state
            .store
            .save_credential(b"k1", "{}", Some("one"))
            .await
            .unwrap();
        set_pw(&state, PW).await;
        assert_eq!(state.store.login_method().await.unwrap(), LoginMethod::Both);
        let (st, set, body) = send(&app, "POST", "/login/password", None, "password=nope").await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert!(set.is_none());
        assert!(body.contains("Wrong password."), "{body}");
        let (st, set, _) = send(&app, "POST", "/login/password", None, &form).await;
        assert_eq!(st, StatusCode::SEE_OTHER);
        let set = set.expect("session cookie");
        assert!(set.starts_with("peephole_session="), "{set}");
        // Password only: no security-key ceremony starts.
        state
            .store
            .set_login_method(LoginMethod::Password)
            .await
            .unwrap();
        let (st, _, body) = send(&app, "POST", "/login/start", None, "").await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        assert!(body.contains("security-key sign-in is off"), "{body}");
    }

    #[test]
    fn the_dummy_hash_parses() {
        assert!(argon2::PasswordHash::new(DUMMY_PHC).is_ok());
    }

    #[tokio::test]
    async fn password_login_ends_the_session_held_and_is_capped() {
        let (_d, state, app) = app().await;
        state
            .store
            .save_credential(b"k1", "{}", Some("one"))
            .await
            .unwrap();
        set_pw(&state, PW).await;
        let form = format!("password={PW}").replace(' ', "+");
        let old = state.store.create_session().await.unwrap();
        // All verification slots busy: refused, nothing checked.
        let held = state
            .verify_slots
            .try_acquire_many(MAX_VERIFIES as u32)
            .unwrap();
        let (st, set, _) = send(&app, "POST", "/login/password", Some(&old), &form).await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
        assert!(set.is_none());
        assert!(state.store.validate_session(&old).await.unwrap());
        drop(held);
        let (st, _, _) = send(&app, "POST", "/login/password", Some(&old), &form).await;
        assert_eq!(st, StatusCode::SEE_OTHER);
        assert!(!state.store.validate_session(&old).await.unwrap());
    }

    #[tokio::test]
    async fn the_login_page_offers_what_the_method_allows() {
        let (_d, state, app) = app().await;
        let (_, _, page) = send(&app, "GET", "/login", None, "").await;
        assert!(page.contains("data-go") && !page.contains("/login/password"));
        state
            .store
            .save_credential(b"k1", "{}", Some("one"))
            .await
            .unwrap();
        // Keys but no password yet: no password form to probe.
        state
            .store
            .set_login_method(LoginMethod::Both)
            .await
            .unwrap();
        let (_, _, page) = send(&app, "GET", "/login", None, "").await;
        assert!(page.contains("data-go") && !page.contains("/login/password"));
        set_pw(&state, PW).await;
        state
            .store
            .set_login_method(LoginMethod::Password)
            .await
            .unwrap();
        let (_, _, page) = send(&app, "GET", "/login", None, "").await;
        assert!(page.contains("/login/password") && !page.contains("data-go"));
        state
            .store
            .set_login_method(LoginMethod::Both)
            .await
            .unwrap();
        let (_, _, page) = send(&app, "GET", "/login", None, "").await;
        assert!(page.contains("/login/password") && page.contains("data-go"));
    }

    #[tokio::test]
    async fn the_keys_page_changes_sign_in_and_password() {
        let (_d, state, app) = app().await;
        state
            .store
            .save_credential(b"k1", "{}", Some("one"))
            .await
            .unwrap();
        let me = state.store.create_session().await.unwrap();
        // No password yet: the guard refuses, the method stays.
        let (st, _, page) = send(
            &app,
            "POST",
            "/admin/system/signin",
            Some(&me),
            "method=password",
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert!(page.contains("no password is set"), "{page}");
        assert_eq!(
            state.store.login_method().await.unwrap(),
            LoginMethod::Passkey
        );
        // Too short, then mismatched.
        let (_, _, page) = send(
            &app,
            "POST",
            "/admin/system/password",
            Some(&me),
            "new=short&again=short",
        )
        .await;
        assert!(page.contains("at least 12 characters"), "{page}");
        let (_, _, page) = send(
            &app,
            "POST",
            "/admin/system/password",
            Some(&me),
            "new=aaaaaaaaaaaaaa&again=bbbbbbbbbbbbbb",
        )
        .await;
        assert!(page.contains("differ"), "{page}");
        assert!(state.store.password_hash().await.unwrap().is_none());
        // Quote and backslash survive the form.
        let tricky = "pa\"ss\\word 12345";
        let enc = "pa%22ss%5Cword+12345";
        let (_, _, page) = send(
            &app,
            "POST",
            "/admin/system/password",
            Some(&me),
            &format!("new={enc}&again={enc}"),
        )
        .await;
        assert!(page.contains("Password saved."), "{page}");
        let first = state.store.password_hash().await.unwrap().unwrap();
        assert!(crate::admin::password::verify(tricky, &first));
        // The admin stayed signed in; the method moved to both.
        assert!(state.store.validate_session(&me).await.unwrap());
        assert_eq!(state.store.login_method().await.unwrap(), LoginMethod::Both);
        // Changing needs the current password.
        let (_, _, page) = send(
            &app,
            "POST",
            "/admin/system/password",
            Some(&me),
            "current=wrong&new=another+password+1&again=another+password+1",
        )
        .await;
        assert!(page.contains("current password is wrong"), "{page}");
        assert_eq!(state.store.password_hash().await.unwrap().unwrap(), first);
        let (_, _, page) = send(
            &app,
            "POST",
            "/admin/system/password",
            Some(&me),
            &format!("current={enc}&new=another+password+1&again=another+password+1"),
        )
        .await;
        assert!(page.contains("Password saved."), "{page}");
        assert_ne!(state.store.password_hash().await.unwrap().unwrap(), first);
        // The only key may go while a password stands in for it.
        let (_, _, page) = send(&app, "GET", "/admin/system/keys", Some(&me), "").await;
        assert!(page.contains("/admin/keys/delete"), "{page}");
    }

    #[test]
    fn behind_tls_cookies_use_the_host_prefix() {
        let c = session_cookie(&cfg(true), "t".into()).to_string();
        assert!(c.starts_with("__Host-peephole_session=t"), "{c}");
        assert!(c.contains("Secure") && c.contains("Path=/"), "{c}");
        assert!(!c.contains("Domain"), "{c}");
        // Plain http (tests, local dev) cannot use the prefix.
        let c = session_cookie(&cfg(false), "t".into()).to_string();
        assert!(c.starts_with("peephole_session=t"), "{c}");
    }

    #[test]
    fn removal_cookies_match_the_path_they_clear() {
        for secure in [true, false] {
            let cfg = cfg(secure);
            // As the handlers see it: the request carries both cookies.
            let mut h = axum::http::HeaderMap::new();
            h.insert(
                axum::http::header::COOKIE,
                format!(
                    "{}=a; {}=b",
                    ceremony_cookie_name(&cfg),
                    session_cookie_name(&cfg)
                )
                .parse()
                .unwrap(),
            );
            let jar = CookieJar::from_headers(&h);
            for jar in [
                clear_ceremony(&cfg, jar.clone()),
                jar.remove(removal(&cfg, session_cookie_name(&cfg))),
            ] {
                let res = (jar, StatusCode::OK).into_response();
                let s = res.headers()[axum::http::header::SET_COOKIE]
                    .to_str()
                    .unwrap()
                    .to_string();
                assert!(s.contains("Path=/"), "{s}");
                assert!(s.contains("Max-Age=0"), "{s}");
                assert_eq!(s.contains("Secure"), secure, "{s}");
            }
        }
    }
}
