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
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

const COLLECTOR_JS: &str = include_str!("../fingerprint/collector.js");

/// Largest request body the public trap will read. Real exploit payloads are
/// tiny; a cap keeps a flood of multi-megabyte POSTs from exhausting memory
/// (every body is held whole and replicated to every cluster node).
const MAX_BODY: usize = 64 * 1024;

/// Fixed-window per-IP limit for the unauthenticated helper endpoints.
const HELPER_LIMIT: u32 = 30;
const HELPER_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

pub struct TrapState {
    pub store: Store,
    /// Writes; replicated in a cluster.
    pub recorder: crate::store::recorder::Recorder,
    pub cfg: Config,
    pub classifier: Classifier,
    pub geo: Arc<RwLock<Option<GeoIp>>>,
    pub tor: Arc<RwLock<TorExitList>>,
    pub notifier: crate::events::Notifier,
    /// Per-IP rate limiter for `/collect` and `/claim`.
    pub helper_rate: RateLimiter,
}

/// Minimal fixed-window rate limiter. Bounded in size so an attacker rotating
/// source addresses cannot grow it without limit.
#[derive(Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    const MAX_TRACKED: usize = 100_000;

    /// Returns true if this hit is allowed (under the limit for its window).
    fn allow(&self, ip: IpAddr, limit: u32, window: std::time::Duration) -> bool {
        let now = Instant::now();
        let mut map = self.windows.lock().unwrap();
        if map.len() > Self::MAX_TRACKED {
            map.retain(|_, (start, _)| now.duration_since(*start) < window);
            if map.len() > Self::MAX_TRACKED {
                map.clear();
            }
        }
        let e = map.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= window {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= limit
    }
}

impl TrapState {
    pub fn for_test(store: Store, cfg: Config) -> Self {
        let classifier =
            Classifier::from_dir(cfg.rules_dir.as_ref().expect("rules_dir")).expect("rules");
        Self {
            recorder: store.local(),
            store,
            cfg,
            classifier,
            geo: Arc::new(RwLock::new(None)),
            tor: Arc::new(RwLock::new(TorExitList::default())),
            notifier: Default::default(),
            helper_rate: RateLimiter::default(),
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
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

/// Source IP from `X-Forwarded-For`, trusting only hops we control.
///
/// `X-Forwarded-For` is `client, proxy1, proxy2, …` with each proxy appending
/// the address it received the connection from. Only entries written by a
/// trusted proxy can be believed, so we start at the direct peer and walk the
/// header right-to-left, stepping over each hop that is itself trusted; the
/// first address that is not a trusted proxy is the real client. Taking the
/// first (leftmost) entry, or a single fixed position, lets a client forge its
/// address — HAProxy's `option forwardfor` appends rather than replaces, so a
/// client-supplied entry survives. Addresses are canonicalised so an
/// IPv4-mapped IPv6 hop matches IPv4 trust CIDRs. All `x-forwarded-for` header
/// lines are considered, newest last, and values are parsed from raw bytes so
/// a non-ASCII byte cannot blank the header and pin everything on the proxy.
pub fn client_ip(headers: &HeaderMap, fallback: IpAddr, trusted: &[IpNet]) -> IpAddr {
    let fallback = crate::net::canonical(fallback);
    let is_trusted = |ip: &IpAddr| {
        trusted
            .iter()
            .any(|n| n.contains(&crate::net::canonical(*ip)))
    };
    if !is_trusted(&fallback) {
        // The direct peer is not a trusted proxy: believe only the peer.
        return fallback;
    }
    // Flatten every XFF entry across all header lines, left to right.
    let entries: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .flat_map(|v| {
            String::from_utf8_lossy(v.as_bytes())
                .split(',')
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .collect::<Vec<_>>()
        })
        .collect();
    // Walk right to left, skipping trusted hops; the first untrusted one wins.
    for ip in entries.iter().rev() {
        let ip = crate::net::canonical(*ip);
        if !is_trusted(&ip) {
            return ip;
        }
    }
    // Every entry (and the peer) is trusted, or there were none: use the peer.
    fallback
}

async fn record_and_respond(
    state: &TrapState,
    ip: IpAddr,
    view: &RequestView<'_>,
    raw_headers: &[(String, String)],
    body: Option<Bytes>,
    is_fp_claim: bool,
) -> Result<Recorded> {
    let ip_row = state.store.upsert_ip(ip).await?;

    // Enrichment (every IP, every request — spec §4). Written only when it
    // changes, so a cluster does not replicate one record per request.
    let geo_hit = state.geo.read().unwrap().as_ref().map(|g| g.lookup(&ip));
    let is_tor = state.tor.read().unwrap().contains(&ip);
    if geo_hit.is_some() || is_tor {
        let g = geo_hit.unwrap_or_else(|| crate::intel::geo::Geo {
            country: ip_row.country.clone(),
            asn: ip_row.asn.map(|a| a as u32),
            asn_org: ip_row.asn_org.clone(),
        });
        state
            .recorder
            .enrich_ip(
                ip_row.id,
                g.country.as_deref(),
                g.asn,
                g.asn_org.as_deref(),
                ip_row.is_tor_exit || is_tor,
            )
            .await?;
    }

    // A false-positive claim is the visitor saying "I'm not a scanner"; it must
    // not be classified as hostile or trigger a counter-scan (otherwise the
    // POST alone scores form-interaction and escalates the claimant).
    let verdict = if is_fp_claim {
        crate::classify::Verdict {
            severity: 0,
            scan_level: 0,
            labels: vec!["fp-claim".into()],
        }
    } else {
        let history = state.store.ip_history(ip_row.id).await.unwrap_or_default();
        state
            .classifier
            .classify(view, &history, &BotTells::default())
    };
    let labels_json = serde_json::to_string(&verdict.labels)?;
    let page_token = uuid::Uuid::new_v4().to_string();

    let request_id = state
        .recorder
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

    // Enqueue counter-scan unless tor / allowlisted / non-global / level 0
    // (spec §4-5). The non-global guard is absolute: a spoofed X-Forwarded-For
    // or a misconfigured never_scan must never aim nmap at loopback, the
    // internal network or a link-local metadata endpoint. never_scan is checked
    // on the canonical address so IPv4-mapped IPv6 cannot slip past IPv4 CIDRs.
    let canon = crate::net::canonical(ip);
    // never_scan is the business of this node's own scanner. Standalone
    // that is the only scanner, so the job is not queued at all; in a
    // cluster another scanner may take it.
    let allowlisted = state.recorder.node().is_none()
        && state.cfg.scan.never_scan.iter().any(|n| n.contains(&canon));
    if verdict.scan_level > 0
        && !is_tor
        && !allowlisted
        && crate::net::is_scannable_target(ip)
        && let crate::store::scans::EnqueueOutcome::Queued(job_id) = state
            .recorder
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
    Ok(Recorded {
        request_id,
        ip_id: ip_row.id,
        page_token,
    })
}

/// What the trap stored for one request.
struct Recorded {
    request_id: i64,
    ip_id: i64,
    /// Rendered into the trap page so `/collect` can link the fingerprint.
    page_token: String,
}

fn header_pairs(h: &HeaderMap) -> Vec<(String, String)> {
    // Lossy decode rather than dropping the value: a header carrying a byte
    // >=0x80 (a UTF-8 exploit payload, or a sloppy scanner User-Agent) is
    // evidence; blanking it would hide it from the classifier and the admin.
    h.iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
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
    let stored_body = if body.is_empty() {
        None
    } else {
        Some(body.clone())
    };
    match record_and_respond(
        &state,
        ip,
        &view,
        &header_pairs(&headers),
        stored_body,
        false,
    )
    .await
    {
        Ok(rec) => (
            StatusCode::NOT_FOUND,
            Html(pages::trap_page(&rec.page_token)),
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
    if !state.helper_rate.allow(ip, HELPER_LIMIT, HELPER_WINDOW) {
        return (StatusCode::TOO_MANY_REQUESTS, "slow down").into_response();
    }
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
    if let Ok(rec) = record_and_respond(&state, ip, &view, &raw, None, true).await {
        let email = form.email.filter(|e| !e.trim().is_empty());
        let _ = state
            .recorder
            .insert_fp_claim(rec.ip_id, rec.request_id, email.as_deref(), &ua)
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
    if !state.helper_rate.allow(ip, HELPER_LIMIT, HELPER_WINDOW) {
        return (StatusCode::TOO_MANY_REQUESTS, "slow down").into_response();
    }
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
            .recorder
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

        // The fingerprint arrives after the page view that triggered it, so it
        // cannot influence that request's own verdict. When it reveals a bot
        // (navigator.webdriver, or a form filled inhumanly fast with no mouse
        // movement), escalate a counter-scan now — subject to the same tor /
        // never_scan / non-global guards as the request path.
        let tells = crate::fingerprint::bot_tells(&payload.attrs, &payload.behavior);
        if tells.webdriver || tells.inhuman_fill {
            let canon = crate::net::canonical(ip);
            let is_tor = state.tor.read().unwrap().contains(&ip);
            // never_scan is the business of this node's own scanner. Standalone
            // that is the only scanner, so the job is not queued at all; in a
            // cluster another scanner may take it.
            let allowlisted = state.recorder.node().is_none()
                && state.cfg.scan.never_scan.iter().any(|n| n.contains(&canon));
            if !is_tor && !allowlisted && crate::net::is_scannable_target(ip) {
                let level = if tells.inhuman_fill { 3 } else { 2 };
                if let Ok(crate::store::scans::EnqueueOutcome::Queued(job_id)) = state
                    .recorder
                    .enqueue_scan(ip_id, level, state.cfg.scan.rescan_cooldown_hours)
                    .await
                    && let Ok(Some(job)) = state.store.queue_job(job_id).await
                {
                    state.notifier.publish(job);
                }
            }
        }
    }
    axum::Json(serde_json::json!({"ok": true})).into_response() // opaque ack (spec §8.3)
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
        // 202 tells the page to poll again; the beacon may still be in flight.
        _ => (
            StatusCode::ACCEPTED,
            Html(render_panel_scrambled(&[(
                "Status".into(),
                "collecting browser characteristics…".into(),
            )])),
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(entries: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for e in entries {
            h.append(
                "x-forwarded-for",
                axum::http::HeaderValue::from_str(e).unwrap(),
            );
        }
        h
    }
    fn trusted() -> Vec<IpNet> {
        vec![
            "10.0.0.0/8".parse().unwrap(),
            "127.0.0.1/32".parse().unwrap(),
        ]
    }

    #[test]
    fn untrusted_peer_is_believed_over_any_xff() {
        // A direct (untrusted) client cannot forge its address via XFF.
        let ip = client_ip(&hm(&["1.2.3.4"]), "8.8.8.8".parse().unwrap(), &trusted());
        assert_eq!(ip, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rightmost_untrusted_entry_wins() {
        // peer is the trusted proxy; the proxy appended the real client last.
        // A client-forged "9.9.9.9" earlier in the list must be ignored.
        let ip = client_ip(
            &hm(&["9.9.9.9", "203.0.113.9"]),
            "10.0.0.1".parse().unwrap(),
            &trusted(),
        );
        assert_eq!(ip, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_hops_are_skipped() {
        // Two trusted proxies in the chain; the client is the first untrusted
        // entry walking right to left.
        let ip = client_ip(
            &hm(&["203.0.113.9", "10.0.0.2"]),
            "10.0.0.1".parse().unwrap(),
            &trusted(),
        );
        assert_eq!(ip, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn multiple_header_lines_are_joined_newest_last() {
        // HAProxy/nginx may emit several XFF lines; the last entry overall wins.
        let ip = client_ip(
            &hm(&["9.9.9.9", "203.0.113.42"]),
            "10.0.0.1".parse().unwrap(),
            &trusted(),
        );
        assert_eq!(ip, "203.0.113.42".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn non_ascii_xff_does_not_pin_on_proxy() {
        // A garbage byte must not blank the header and pin everything on the
        // proxy; the valid trailing entry is still used.
        let mut h = HeaderMap::new();
        h.append(
            "x-forwarded-for",
            axum::http::HeaderValue::from_bytes(b"\xff, 203.0.113.1").unwrap(),
        );
        let ip = client_ip(&h, "10.0.0.1".parse().unwrap(), &trusted());
        assert_eq!(ip, "203.0.113.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn mapped_v4_proxy_is_recognised_as_trusted() {
        // An IPv4-mapped IPv6 proxy address is canonicalised before the trust
        // check, so XFF from it is honoured.
        let ip = client_ip(
            &hm(&["203.0.113.1"]),
            "::ffff:10.0.0.1".parse().unwrap(),
            &trusted(),
        );
        assert_eq!(ip, "203.0.113.1".parse::<IpAddr>().unwrap());
    }
}
