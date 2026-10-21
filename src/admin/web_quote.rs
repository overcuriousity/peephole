//! Firm prices for the admin's paid buttons (MIK-505): the Actions card's
//! probe and counter-scan levels and the Lookup page's paid providers open
//! a dialog that fetches one price here, and its Confirm buys with it.
//! Scan and lookup quotes live in the machine API's quote store and
//! pricing (`api_v1::quote_scan`, `api_v1::quote_lookup`), owned by the
//! admin session ([`WebBuyer`]) instead of a device, so neither spends the
//! other's. A probe has no quote: its form carries the price shown, and a
//! higher price at submit is refused. Errors answer in the API's JSON
//! shape; standalone everything is free and no dialog opens.
use crate::admin::AdminState;
use crate::admin::api_v1::{self, err};
use crate::admin::auth::{SessionUser, session_token};
use crate::store::devices::{Device, QUOTE_SECS};
use axum::{
    Json, Router,
    extract::{FromRequestParts, RawQuery, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_extra::extract::CookieJar;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/lookup/scan/quote", get(scan_quote))
        .route("/admin/lookup/quote", get(lookup_quote))
        .route("/admin/lookup/probe/quote", get(probe_quote))
}

/// The admin session as a buyer: what [`SessionUser`] admits (its
/// rejection unchanged), named by its session.
pub struct WebBuyer(pub Device);

impl FromRequestParts<Arc<AdminState>> for WebBuyer {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AdminState>,
    ) -> Result<Self, Self::Rejection> {
        SessionUser::from_request_parts(parts, state).await?;
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|e| e.into_response())?;
        Ok(WebBuyer(buyer(
            &session_token(state, &jar).unwrap_or_default(),
        )))
    }
}

/// The session of `token` as the owner of its quotes and audit entries:
/// `web:` and a digest of the session (a device id is a UUID, so no device
/// shares it).
pub fn buyer(token: &str) -> Device {
    let hash = crate::store::auth::token_hash(token);
    Device {
        id: format!("web:{}", &hash[..16]),
        name: "web session".into(),
        token_hash: String::new(),
        scopes: String::new(),
        paired_by: "admin".into(),
        created_at: String::new(),
        last_seen_at: None,
        revoked_at: None,
        kind: crate::store::devices::KIND_DEVICE.into(),
    }
}

/// The query: `ip`, `level`, and the repeatable `ask`, `again`, `vantage`
/// (the fields of the form the button sits in).
#[derive(Default)]
struct Asked {
    ip: String,
    level: Option<String>,
    ask: Vec<String>,
    again: Vec<String>,
    vantage: Vec<String>,
}

impl Asked {
    fn parse(q: Option<String>) -> Asked {
        let pairs: Vec<(String, String)> =
            serde_urlencoded::from_str(&q.unwrap_or_default()).unwrap_or_default();
        let mut a = Asked::default();
        for (k, v) in pairs {
            match k.as_str() {
                "ip" => a.ip = v,
                "level" => a.level = Some(v),
                "ask" if !v.is_empty() => a.ask.push(v),
                "again" if !v.is_empty() => a.again.push(v),
                "vantage" => a.vantage.push(v),
                _ => {}
            }
        }
        a
    }

    fn ip(&self) -> Result<IpAddr, Box<Response>> {
        self.ip
            .trim()
            .parse::<IpAddr>()
            .map(crate::net::canonical)
            .map_err(|_| Box::new(err(StatusCode::BAD_REQUEST, "invalid", "not an IP address")))
    }
}

/// A quote as the dialog takes it: the API's, with its lifetime in seconds
/// (counted down from receipt, whatever the browser's clock) and the
/// balance now.
async fn answer(state: &AdminState, mut v: Value) -> Response {
    v["expires_in"] = json!(QUOTE_SECS);
    v["balance"] = json!(balance(state).await);
    Json(v).into_response()
}

async fn balance(state: &AdminState) -> Option<String> {
    match state.recorder.node() {
        Some(n) => crate::admin::probes::balance(n).await,
        None => None,
    }
}

/// GET /admin/lookup/scan/quote?ip=&level=: a counter-scan quote.
async fn scan_quote(
    WebBuyer(b): WebBuyer,
    State(state): State<Arc<AdminState>>,
    RawQuery(q): RawQuery,
) -> Response {
    let a = Asked::parse(q);
    let level = match api_v1::level_of(a.level.as_deref()) {
        Ok(l) => l,
        Err(r) => return *r,
    };
    match api_v1::quote_scan(&state, &b.id, &a.ip, level).await {
        Ok(v) => answer(&state, v).await,
        Err(r) => *r,
    }
}

/// GET /admin/lookup/quote?ip=&ask=…&again=…: a quote of the providers an
/// "Ask" (`*`: all of them) or "Ask again" button asks.
async fn lookup_quote(
    WebBuyer(b): WebBuyer,
    State(state): State<Arc<AdminState>>,
    RawQuery(q): RawQuery,
) -> Response {
    let a = Asked::parse(q);
    let ip = match a.ip() {
        Ok(ip) => ip,
        Err(r) => return *r,
    };
    let mut chosen: Vec<String> = a.ask.iter().chain(&a.again).cloned().collect();
    chosen.dedup();
    if chosen.iter().any(|p| p == "*") {
        chosen.clear();
    }
    match api_v1::quote_lookup(&state, &b.id, &ip.to_string(), &chosen).await {
        Ok(v) => answer(&state, v).await,
        Err(r) => *r,
    }
}

/// GET /admin/lookup/probe/quote?ip=&vantage=…: what a probe from the
/// ticked scanners costs now. No quote: the form sends this price back.
async fn probe_quote(
    WebBuyer(_): WebBuyer,
    State(state): State<Arc<AdminState>>,
    RawQuery(q): RawQuery,
) -> Response {
    let a = Asked::parse(q);
    if let Err(r) = a.ip() {
        return *r;
    }
    if a.vantage.is_empty() {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused",
            "pick at least one live scanner",
        );
    }
    let mc = crate::admin::probes::price_mc(&state, Some(&a.vantage));
    Json(json!({
        "credits": crate::credits::show(mc),
        "credits_mc": mc,
        "balance": balance(&state).await,
    }))
    .into_response()
}
