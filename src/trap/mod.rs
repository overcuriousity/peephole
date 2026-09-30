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

const COLLECTOR_JS: &str = include_str!("../fingerprint/collector.js");

pub struct TrapState {
    pub store: Store,
    pub cfg: Config,
    pub classifier: Classifier,
    pub geo: Arc<RwLock<Option<GeoIp>>>,
    pub tor: Arc<RwLock<TorExitList>>,
    pub notifier: crate::events::Notifier,
}

impl TrapState {
    pub fn for_test(store: Store, cfg: Config) -> Self {
        let classifier = Classifier::from_dir(&cfg.rules_dir).expect("rules");
        Self {
            store,
            cfg,
            classifier,
            geo: Arc::new(RwLock::new(None)),
            tor: Arc::new(RwLock::new(TorExitList::default())),
            notifier: Default::default(),
        }
    }
}

pub fn router(state: Arc<TrapState>) -> Router {
    Router::new()
        .route("/claim", post(claim_handler))
        .route("/collect", post(collect_handler))
        .route("/panel", get(panel_handler))
        .route("/collect.js", get(collector_js))
        .fallback(any(trap_handler))
        .with_state(state)
}

/// Source IP: rightmost X-Forwarded-For entry when the peer is a trusted proxy.
pub fn client_ip(headers: &HeaderMap, fallback: IpAddr, trusted: &[IpNet]) -> IpAddr {
    if !trusted.iter().any(|n| n.contains(&fallback)) {
        return fallback;
    }
    headers
        .get("x-forwarded-for")
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
        state
            .store
            .set_ip_geo(ip_row.id, g.country.as_deref(), g.asn, g.asn_org.as_deref())
            .await?;
    }
    if state.tor.read().unwrap().contains(&ip) {
        state.store.set_ip_tor(ip_row.id, true).await?;
    }

    let history = state.store.ip_history(ip_row.id).await.unwrap_or_default();
    let verdict = state
        .classifier
        .classify(view, &history, &BotTells::default());
    let labels_json = serde_json::to_string(&verdict.labels)?;
    let page_token = uuid::Uuid::new_v4().to_string();

    let request_id = state
        .store
        .insert_request(&NewRequest {
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
        })
        .await?;

    // Enqueue counter-scan unless tor / allowlisted / level 0 (spec §4-5).
    let is_tor = state.tor.read().unwrap().contains(&ip);
    let allowlisted = state.cfg.scan.never_scan.iter().any(|n| n.contains(&ip));
    if verdict.scan_level > 0
        && !is_tor
        && !allowlisted
        && let crate::store::scans::EnqueueOutcome::Queued(job_id) = state
            .store
            .enqueue_scan(
                ip_row.id,
                verdict.scan_level,
                state.cfg.scan.rescan_cooldown_hours,
            )
            .await?
        && let Ok(Some(job)) = state.store.queue_job(job_id).await
    {
        state.notifier.publish(job);
    }
    Ok((request_id, verdict, ip_row.id))
}

fn header_pairs(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect()
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
    match record_and_respond(
        &state,
        ip,
        &view,
        &header_pairs(&headers),
        Some(body.clone()),
        false,
    )
    .await
    {
        Ok((_rid, _verdict, _ip_id)) => (
            StatusCode::NOT_FOUND,
            Html(pages::trap_page(&uuid::Uuid::new_v4().to_string())),
        )
            .into_response(),
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
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let raw = header_pairs(&headers);
    let view = RequestView {
        method: "POST",
        path: "/claim",
        query: None,
        headers: raw.clone(),
        body: None,
    };
    if let Ok((rid, _v, ip_id)) = record_and_respond(&state, ip, &view, &raw, None, true).await {
        let email = form.email.filter(|e| !e.trim().is_empty());
        let _ = state
            .store
            .insert_fp_claim(ip_id, rid, email.as_deref(), &ua)
            .await;
    }
    Html(pages::claim_confirmation()).into_response()
}

async fn collector_js() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/javascript")],
        COLLECTOR_JS,
    )
}

#[derive(serde::Deserialize)]
pub struct CollectPayload {
    token: String,
    attrs: serde_json::Value,
    behavior: serde_json::Value,
}

async fn collect_handler(
    State(state): State<Arc<TrapState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<CollectPayload>,
) -> impl IntoResponse {
    let ip = client_ip(&headers, peer.ip(), &state.cfg.trusted_proxies);
    if let Ok(ip_row) = state.store.upsert_ip(ip).await {
        // Attribute the fingerprint to the page view that issued the token;
        // fall back to the connection IP for unknown tokens.
        let req: Option<(i64, i64)> = sqlx::query_as(
            "SELECT id, ip_id FROM requests WHERE page_token = ? ORDER BY id DESC LIMIT 1",
        )
        .bind(&payload.token)
        .fetch_optional(&state.store.pool)
        .await
        .unwrap_or(None);
        let (request_id, ip_id) = match req {
            Some((rid, iid)) => (Some(rid), iid),
            None => (None, ip_row.id),
        };
        let hash = crate::fingerprint::fp_hash(&payload.attrs);
        let visitor = payload
            .attrs
            .get("visitor_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let events = payload
            .behavior
            .get("events")
            .map(|e| e.to_string())
            .unwrap_or_default();
        let _ = state
            .store
            .insert_fingerprint(
                request_id,
                ip_id,
                &hash,
                visitor.as_deref(),
                &payload.attrs.to_string(),
                &payload.behavior.to_string(),
                events.as_bytes(),
            )
            .await;
    }
    axum::Json(serde_json::json!({"ok": true})) // opaque ack (spec §8.3)
}

async fn panel_handler(
    State(state): State<Arc<TrapState>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(token) = q.get("token") else {
        return (StatusCode::BAD_REQUEST, "missing token").into_response();
    };
    match state.store.fingerprint_by_token(token).await {
        Ok(Some((ip_id, hash, attrs, behavior))) => {
            let attrs: serde_json::Value = serde_json::from_str(&attrs).unwrap_or_default();
            let behavior: serde_json::Value = serde_json::from_str(&behavior).unwrap_or_default();
            let seen = state
                .store
                .fingerprint_ip_count(&hash, ip_id)
                .await
                .unwrap_or(0);
            let pairs = crate::fingerprint::panel_summary(&attrs, &behavior, seen);
            Html(render_panel_scrambled(&pairs)).into_response()
        }
        // No fingerprint yet: still scrambled markup (bot-unfriendly, spec §8.3).
        _ => Html(render_panel_scrambled(&[(
            "Status".into(),
            "collecting browser characteristics…".into(),
        )]))
        .into_response(),
    }
}

/// Bot-unfriendly panel rendering (spec §8.3): randomized ids/classes,
/// shuffled section order, values split across multiple text nodes.
fn render_panel_scrambled(pairs: &[(String, String)]) -> String {
    use rand::seq::SliceRandom;
    let mut rng = rand::rng();
    let mut items: Vec<&(String, String)> = pairs.iter().collect();
    items.shuffle(&mut rng);
    let rid = |rng: &mut rand::rngs::ThreadRng| -> String {
        (0..8)
            .map(|_| (b'a' + (rand::RngExt::random_range(rng, 0..26)) as u8) as char)
            .collect()
    };
    let mut html = String::from("<div><h2>What we see about you</h2>");
    for (k, v) in items {
        let cls = rid(&mut rng);
        html.push_str(&format!(
            "<div class=\"{cls}\"><span>{}</span>: ",
            escape(k)
        ));
        // Split value into 2-4 chunks across separate <i> nodes with decoys.
        // Short values stay whole (splitting would destroy any readability gain).
        let chars: Vec<char> = v.chars().collect();
        let n = if chars.len() <= 8 {
            1
        } else {
            2 + rand::RngExt::random_range(&mut rng, 0..3usize)
        };
        let mut idx = 0usize;
        for i in 0..n {
            let end = if i == n - 1 {
                chars.len()
            } else {
                idx + (chars.len() - idx) / (n - i)
            };
            let chunk: String = chars[idx..end].iter().collect();
            idx = end;
            html.push_str(&format!(
                "<i data-x=\"{}\">{}</i><b style=\"display:none\">{}</b>",
                rid(&mut rng),
                escape(&chunk),
                rid(&mut rng)
            ));
        }
        html.push_str("</div>");
    }
    html.push_str("</div>");
    html
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
