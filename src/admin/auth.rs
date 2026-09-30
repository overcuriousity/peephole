use crate::admin::AdminState;
use crate::store::Store;
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{FromRequestParts, State},
    http::{StatusCode, request::Parts},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use sha2::{Digest, Sha256};
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
        let jar = axum_extra::extract::CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|e| e.into_response())?;
        let ok = match jar.get("peephole_session") {
            Some(c) => state
                .store
                .validate_session(c.value())
                .await
                .unwrap_or(false),
            None => false,
        };
        if ok {
            Ok(SessionUser)
        } else {
            Err(Redirect::to("/login").into_response())
        }
    }
}

/// First-run setup token (spec §8.4): printed once to stdout, hash stored.
pub async fn ensure_setup_token(
    store: &Store,
    _data_dir: &std::path::Path,
) -> Result<Option<String>> {
    let creds = store.load_credentials().await?;
    if !creds.is_empty() {
        return Ok(None);
    }
    if let Some(_hash) = store.intel_get("webauthn_setup_token_hash").await? {
        return Ok(None); // token already issued; console output is the only copy
    }
    let token = uuid::Uuid::new_v4().to_string();
    let hash = data_encoding::HEXLOWER.encode(&Sha256::digest(token.as_bytes()));
    store.intel_set("webauthn_setup_token_hash", &hash).await?;
    println!(
        "\n=== peephole admin setup ===\nOpen /enroll on the admin interface and enter this one-time token:\n\n  {token}\n"
    );
    Ok(Some(token))
}

fn webauthn_for(cfg: &crate::config::Config) -> Result<Webauthn> {
    let origin = Url::parse(&cfg.webauthn.origin).context("webauthn origin")?;
    let builder = WebauthnBuilder::new(&cfg.webauthn.rp_id, &origin)
        .context("webauthn builder")?
        .rp_name(&cfg.webauthn.rp_name);
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

fn session_cookie(
    cfg: &crate::config::Config,
    id: String,
) -> axum_extra::extract::cookie::Cookie<'static> {
    axum_extra::extract::cookie::Cookie::build(("peephole_session", id))
        .path("/")
        .http_only(true)
        .secure(cfg.webauthn.secure_cookies)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .build()
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
    jar: axum_extra::extract::CookieJar,
    Json(body): Json<EnrollStart>,
) -> Response {
    // Either the one-time setup token or a live admin session authorises this.
    let by_session = match jar.get("peephole_session") {
        Some(c) => state
            .store
            .validate_session(c.value())
            .await
            .unwrap_or(false),
        None => false,
    };
    let by_token = match (
        &body.setup_token,
        state.store.intel_get("webauthn_setup_token_hash").await,
    ) {
        (Some(t), Ok(Some(stored))) => {
            stored == data_encoding::HEXLOWER.encode(&Sha256::digest(t.as_bytes()))
        }
        _ => false,
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
            let jar = jar
                .add(
                    axum_extra::extract::cookie::Cookie::build((
                        "wa_reg",
                        serde_json::to_string(&state_reg).unwrap(),
                    ))
                    .path("/")
                    .http_only(true)
                    .same_site(axum_extra::extract::cookie::SameSite::Strict),
                )
                .add(
                    axum_extra::extract::cookie::Cookie::build(("wa_label", label))
                        .path("/")
                        .http_only(true)
                        .same_site(axum_extra::extract::cookie::SameSite::Strict),
                );
            (jar, Json(serde_json::json!({"publicKey": ccr.public_key}))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct EnrollFinish {
    credential: RegisterPublicKeyCredential,
}

async fn enroll_finish(
    State(state): State<Arc<AdminState>>,
    jar: axum_extra::extract::CookieJar,
    Json(body): Json<EnrollFinish>,
) -> Response {
    let Some(cookie) = jar.get("wa_reg") else {
        return (StatusCode::BAD_REQUEST, "no enrollment in progress").into_response();
    };
    let Ok(reg_state) = serde_json::from_str::<PasskeyRegistration>(cookie.value()) else {
        return (StatusCode::BAD_REQUEST, "corrupt enrollment state").into_response();
    };
    let wa = match webauthn_for(&state.cfg) {
        Ok(w) => w,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let label = jar
        .get("wa_label")
        .map(|c| c.value().trim().to_string())
        .filter(|l| !l.is_empty());
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
            let _ = state
                .store
                .intel_set("webauthn_setup_token_hash", "consumed")
                .await;
            // Establish session directly after first enrollment.
            match state.store.create_session().await {
                Ok(id) => {
                    let jar = jar
                        .add(session_cookie(&state.cfg, id))
                        .remove(axum_extra::extract::cookie::Cookie::from("wa_reg"))
                        .remove(axum_extra::extract::cookie::Cookie::from("wa_label"));
                    (jar, StatusCode::OK).into_response()
                }
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn login_start(
    State(state): State<Arc<AdminState>>,
    jar: axum_extra::extract::CookieJar,
) -> Response {
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
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    match wa.start_passkey_authentication(&passkeys) {
        Ok((rcr, auth_state)) => {
            let jar = jar.add(
                axum_extra::extract::cookie::Cookie::build((
                    "wa_auth",
                    serde_json::to_string(&auth_state).unwrap(),
                ))
                .path("/")
                .http_only(true)
                .same_site(axum_extra::extract::cookie::SameSite::Strict),
            );
            (jar, Json(serde_json::json!({"publicKey": rcr.public_key}))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct LoginFinish {
    credential: PublicKeyCredential,
}

async fn login_finish(
    State(state): State<Arc<AdminState>>,
    jar: axum_extra::extract::CookieJar,
    Json(body): Json<LoginFinish>,
) -> Response {
    let Some(cookie) = jar.get("wa_auth") else {
        return (StatusCode::BAD_REQUEST, "no login in progress").into_response();
    };
    let Ok(auth_state) = serde_json::from_str::<PasskeyAuthentication>(cookie.value()) else {
        return (StatusCode::BAD_REQUEST, "corrupt auth state").into_response();
    };
    let wa = match webauthn_for(&state.cfg) {
        Ok(w) => w,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    match wa.finish_passkey_authentication(&body.credential, &auth_state) {
        Ok(_result) => match state.store.create_session().await {
            Ok(id) => {
                let jar = jar
                    .add(session_cookie(&state.cfg, id))
                    .remove(axum_extra::extract::cookie::Cookie::from("wa_auth"));
                (jar, StatusCode::OK).into_response()
            }
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        Err(e) => (StatusCode::UNAUTHORIZED, e.to_string()).into_response(),
    }
}

async fn logout(
    State(state): State<Arc<AdminState>>,
    jar: axum_extra::extract::CookieJar,
) -> Response {
    if let Some(c) = jar.get("peephole_session") {
        let _ = state.store.destroy_session(c.value()).await;
    }
    let jar = jar.remove(axum_extra::extract::cookie::Cookie::from(
        "peephole_session",
    ));
    (jar, Redirect::to("/")).into_response()
}
