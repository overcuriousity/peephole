mod pages;

use crate::classify::{BotTells, Classifier, RequestView};
use crate::config::Config;
use crate::intel::geo::GeoIp;
use crate::intel::tor::TorExitList;
use crate::store::{Store, requests::NewRequest};
use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, Form, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{any, get, post},
};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

const COLLECTOR_JS: &str = "// peephole collector stub — replaced in Task 7\n";

pub struct TrapState {
    pub store: Store,
    pub cfg: Config,
    pub classifier: Classifier,
    pub geo: Arc<RwLock<Option<GeoIp>>>,
    pub tor: Arc<RwLock<TorExitList>>,
}

impl TrapState {
    pub fn for_test(store: Store, cfg: Config) -> Self {
        let classifier = Classifier::from_dir(&cfg.rules_dir).expect("rules");
        Self {
            store, cfg, classifier,
            geo: Arc::new(RwLock::new(None)),
            tor: Arc::new(RwLock::new(TorExitList::default())),
        }
    }
}

pub fn router(state: Arc<TrapState>) -> Router {
    Router::new()
        .route("/claim", post(claim_handler))
        .route("/collect.js", get(collector_js))
        .fallback(any(trap_handler))
        .with_state(state)
}

/// Source IP: rightmost X-Forwarded-For entry when the peer is a trusted proxy.
pub fn client_ip(headers: &HeaderMap, fallback: IpAddr, trusted: &[IpNet]) -> IpAddr {
    if !trusted.iter().any(|n| n.contains(&fallback)) {
        return fallback;
    }
    headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next_back())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(fallback)
}

async fn record_and_respond(
    state: &TrapState,
    ip: IpAddr,
    view: &RequestView<'_>,
    raw_headers: &[(String, String)],
    body: Option<Bytes>,
    is_fp_claim: bool,
) -> Result<(i64, crate::classify::Verdict, i64)> {
    let ip_row = state.store.upsert_ip(ip).await?;

    // Enrichment (every IP, every request — spec §4).
    let geo_hit = state.geo.read().unwrap().as_ref().map(|g| g.lookup(&ip));
    if let Some(g) = geo_hit {
        state.store.set_ip_geo(ip_row.id, g.country.as_deref(), g.asn, g.asn_org.as_deref()).await?;
    }
    if state.tor.read().unwrap().contains(&ip) {
        state.store.set_ip_tor(ip_row.id, true).await?;
    }

    let history = state.store.ip_history(ip_row.id).await.unwrap_or_default();
    let verdict = state.classifier.classify(view, &history, &BotTells::default());
    let labels_json = serde_json::to_string(&verdict.labels)?;
    let page_token = uuid::Uuid::new_v4().to_string();

    let request_id = state.store.insert_request(&NewRequest {
        ip_id: ip_row.id,
        method: view.method.to_string(),
        path: view.path.to_string(),
        query: view.query.map(str::to_string),
        headers_json: serde_json::to_string(raw_headers)?,
        body: body.map(|b| b.to_vec()),
        labels_json,
        severity: verdict.severity as i64,
        scan_level: verdict.scan_level as i64,
        is_fp_claim,
        page_token: Some(page_token.clone()),
    }).await?;

    // Enqueue counter-scan unless tor / allowlisted / level 0 (spec §4-5).
    let is_tor = state.tor.read().unwrap().contains(&ip);
    let allowlisted = state.cfg.scan.never_scan.iter().any(|n| n.contains(&ip));
    if verdict.scan_level > 0 && !is_tor && !allowlisted {
        state.store.enqueue_scan(ip_row.id, verdict.scan_level, state.cfg.scan.rescan_cooldown_hours).await?;
    }
    Ok((request_id, verdict, ip_row.id))
}

fn header_pairs(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect()
}

async fn trap_handler(
    State(state): State<Arc<TrapState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    method: axum::http::Method,
    body: Bytes,
) -> impl IntoResponse {
    let ip = client_ip(&headers, peer.ip(), &state.cfg.trusted_proxies);
    let view = RequestView {
        method: method.as_str(),
        path: uri.path(),
        query: uri.query(),
        headers: header_pairs(&headers),
        body: if body.is_empty() { None } else { Some(&body) },
    };
    match record_and_respond(&state, ip, &view, &header_pairs(&headers), Some(body.clone()), false).await {
        Ok((_rid, _verdict, _ip_id)) => {
            (StatusCode::NOT_FOUND, Html(pages::trap_page(&uuid::Uuid::new_v4().to_string()))).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct ClaimForm {
    email: Option<String>,
}

async fn claim_handler(
    State(state): State<Arc<TrapState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<ClaimForm>,
) -> impl IntoResponse {
    let ip = client_ip(&headers, peer.ip(), &state.cfg.trusted_proxies);
    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let raw = header_pairs(&headers);
    let view = RequestView {
        method: "POST", path: "/claim", query: None, headers: raw.clone(), body: None,
    };
    if let Ok((rid, _v, ip_id)) = record_and_respond(&state, ip, &view, &raw, None, true).await {
        let email = form.email.filter(|e| !e.trim().is_empty());
        let _ = state.store.insert_fp_claim(ip_id, rid, email.as_deref(), &ua).await;
    }
    Html(pages::claim_confirmation()).into_response()
}

async fn collector_js() -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "text/javascript")], COLLECTOR_JS)
}
