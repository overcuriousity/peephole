use crate::admin::AdminState;
use crate::store::Store;
use crate::store::auth::SetupToken;
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
/// expired (or was used up) prints a new one. `peephole admin setup-token`
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
        SetupToken::Legacy => {
            // Issued by a build without expiry: keep it, from now on dated.
            store.date_legacy_setup_token().await?;
            tracing::info!(
                hours = crate::store::auth::SETUP_TOKEN_HOURS,
                "the admin setup token printed earlier now expires; \
                 `peephole admin setup-token` prints a new one"
            );
            Ok(None)
        }
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

pub fn auth_routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/login", get(login_page))
        .route("/login/start", post(login_start))
        .route("/login/finish", post(login_finish))
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
}

#[derive(askama::Template)]
#[template(path = "enroll.html")]
struct EnrollPage {
    chrome: crate::admin::views::Chrome,
}

async fn login_page(
    crate::admin::public::MaybeUser(authed): crate::admin::public::MaybeUser,
) -> crate::admin::error::AppResult<Html<String>> {
    crate::admin::error::render(&LoginPage {
        chrome: crate::admin::views::Chrome::new(authed, ""),
    })
}
async fn enroll_page(
    crate::admin::public::MaybeUser(authed): crate::admin::public::MaybeUser,
) -> crate::admin::error::AppResult<Html<String>> {
    crate::admin::error::render(&EnrollPage {
        chrome: crate::admin::views::Chrome::new(authed, ""),
    })
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
    let by_session = session_valid(&state, &jar).await;
    let by_token = match &body.setup_token {
        Some(t) => state.store.setup_token_valid(t).await.unwrap_or(false),
        None => false,
    };
    if !by_session && !by_token {
        return (StatusCode::FORBIDDEN, "invalid setup token").into_response();
    }
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
            let state_json = serde_json::to_string(&state_reg).unwrap();
            let sid = match state
                .store
                .put_webauthn_state("reg", &state_json, Some(&label))
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
    let taken = state.store.take_webauthn_state(cookie.value(), "reg").await;
    let Ok(Some((state_json, label))) = taken else {
        return (
            StatusCode::BAD_REQUEST,
            clear_ceremony(cfg, jar),
            "no enrollment in progress",
        )
            .into_response();
    };
    let Ok(reg_state) = serde_json::from_str::<PasskeyRegistration>(&state_json) else {
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
            // A key that was not stored must not consume the one-time setup
            // token, or the admin is locked out once this session expires.
            if let Err(e) = state
                .store
                .save_credential(passkey.cred_id(), &json, label.as_deref())
                .await
            {
                tracing::warn!(?e, "could not store the enrolled key");
                return (StatusCode::INTERNAL_SERVER_ERROR, "could not store the key")
                    .into_response();
            }
            let _ = state.store.consume_setup_token().await;
            // An admin adding a key keeps their session. The first key
            // (setup token) signs in with that key.
            if session_valid(&state, &jar).await {
                return (clear_ceremony(cfg, jar), StatusCode::OK).into_response();
            }
            let old = session_token(&state, &jar);
            match state
                .store
                .create_session_for(Some(passkey.cred_id()), old.as_deref())
                .await
            {
                Ok(token) => (
                    clear_ceremony(cfg, jar.add(session_cookie(cfg, token))),
                    StatusCode::OK,
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

async fn login_start(State(state): State<Arc<AdminState>>, jar: CookieJar) -> Response {
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
            // it); a session the browser held before ends now.
            let old = session_token(&state, &jar);
            let used: &[u8] = result.cred_id();
            match state
                .store
                .create_session_for(Some(used), old.as_deref())
                .await
            {
                Ok(token) => (
                    clear_ceremony(cfg, jar.add(session_cookie(cfg, token))),
                    StatusCode::OK,
                )
                    .into_response(),
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
