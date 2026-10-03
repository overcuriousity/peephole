mod config;
mod decoy;
mod flood;
pub mod listen;
mod pages;
pub mod proxy_proto;
pub mod raw_head;
pub mod skiplog;
pub mod tls_hello;

pub use config::TrapConfig;

use crate::classify::{BotTells, Classifier, RequestView};
use crate::config::Config;
use crate::intel::geo::GeoIp;
use crate::intel::tor::TorExitList;
use crate::store::{Store, requests::NewRequest};
use anyhow::Result;
use axum::{
    Router,
    extract::{ConnectInfo, Form, Request, State},
    http::{HeaderMap, StatusCode, Version, header},
    response::{Html, IntoResponse, Response},
    routing::{any, get, post},
};
use futures::StreamExt;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

const COLLECTOR_JS: &str = include_str!("../fingerprint/collector.js");

/// Largest request body the trap stores. Real exploit payloads are tiny;
/// a cap keeps a flood of multi-megabyte POSTs from exhausting memory (every
/// body is held whole and replicated to every cluster node). A longer body
/// is cut, not refused: the request is still recorded and answered.
const MAX_BODY: usize = 64 * 1024;
/// Past `MAX_BODY` the rest of a body is read and counted, not kept, up to
/// this many bytes in all; then reading stops.
const MAX_BODY_DRAIN: u64 = 1024 * 1024;
/// How long the trap waits for a body.
const BODY_TIMEOUT: Duration = Duration::from_secs(20);

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
    /// Runtime scan settings; the trap reads the rescan cooldown from it.
    pub pace: crate::scan::pace::SharedPace,
    /// Flood protection for the recording path.
    pub guards: Guards,
}

/// In-memory state that keeps floods off the database.
#[derive(Default)]
pub struct Guards {
    /// Which requests are recorded in full (`[trap]` record_rate).
    flood: flood::FloodGate,
    /// Intel results recorded moments ago.
    intel: flood::IntelCache,
    /// Light rows of the requests the flood gate skips.
    pub skips: skiplog::SkipLog,
    /// Trap requests being handled or recorded right now.
    in_flight: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Guards {
    /// Count a request as in flight until the returned guard is dropped.
    pub fn enter(&self) -> InFlight {
        self.in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        InFlight(self.in_flight.clone())
    }

    fn in_flight(&self) -> usize {
        self.in_flight.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Wait until no request is in flight: every request answered so far
    /// is recorded (requests are recorded after they are answered).
    pub async fn settled(&self) {
        while self.in_flight() > 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// A trap request in progress (see [`Guards::enter`]).
pub struct InFlight(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Write a batch of light rows; a failure is logged, the requests were
/// answered either way.
async fn write_skips(state: &TrapState, b: skiplog::Batch) {
    let ip = b.ip.to_string();
    if let Err(e) = state
        .recorder
        .insert_skip_batch(&ip, b.dropped, b.rows)
        .await
    {
        warn!(%ip, error = %e, "trap: recording skipped requests failed");
    }
}

/// Longest a stopping trap waits for requests in progress to finish: less
/// than the daemon's own shutdown grace, which aborts the trap after it, so
/// the final write still happens.
const STOP_GRACE: Duration = crate::SHUTDOWN_GRACE.saturating_sub(Duration::from_secs(2));

/// Write the light rows that have waited long enough, every few seconds,
/// until `shutdown`.
pub async fn flush_skips(state: Arc<TrapState>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            _ = shutdown.changed() => {
                // Nothing buffered is lost on a clean stop: requests still
                // being handled may note light rows, so wait for them (at
                // most as long as a connection may last), writing as they
                // come, then write the rest.
                let until = Instant::now() + STOP_GRACE;
                loop {
                    for b in state.guards.skips.take_older(Duration::ZERO, Instant::now()) {
                        write_skips(&state, b).await;
                    }
                    if state.guards.in_flight() == 0 || Instant::now() >= until {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                for b in state.guards.skips.take_older(Duration::ZERO, Instant::now()) {
                    write_skips(&state, b).await;
                }
                return;
            }
        }
        for b in state
            .guards
            .skips
            .take_older(Duration::from_secs(10), Instant::now())
        {
            write_skips(&state, b).await;
        }
    }
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
    /// How a counter-scan is queued: the rescan cooldown and the `[scan]`
    /// evidence cap and queue budgets (`scan::guard`).
    fn enqueue_policy(&self) -> crate::scan::guard::EnqueuePolicy {
        crate::scan::guard::EnqueuePolicy::new(&self.cfg.scan.safety, self.pace.cooldown_hours())
    }

    pub fn for_test(store: Store, cfg: Config) -> Self {
        let classifier =
            Classifier::from_dir(cfg.rules_dir.as_ref().expect("rules_dir")).expect("rules");
        let pace =
            crate::scan::pace::SharedPace::new(crate::scan::pace::Pace::from_config(&cfg.scan));
        pace.set_cooldown_hours(cfg.scan.rescan_cooldown_hours);
        Self {
            pace,
            recorder: store.local(),
            store,
            cfg,
            classifier,
            geo: Arc::new(RwLock::new(None)),
            tor: Arc::new(RwLock::new(TorExitList::default())),
            notifier: Default::default(),
            helper_rate: RateLimiter::default(),
            guards: Guards::default(),
        }
    }
}

/// The trap's routes. The helper endpoints the trap page uses sit under
/// `trap.helper_prefix`; everything else is the trap.
pub fn router(state: Arc<TrapState>) -> Router {
    let p = state.cfg.trap.helper_prefix.clone();
    Router::new()
        .route(&format!("{p}/claim"), post(claim_handler))
        .route(&format!("{p}/collect"), post(collect_handler))
        .route(&format!("{p}/panel"), get(panel_handler))
        .route(&format!("{p}/collect.js"), get(collector_js))
        .fallback(any(trap_handler))
        // A wrong method on a helper path is the trap too: axum's own 405
        // would go unrecorded and give the helpers away.
        .method_not_allowed_fallback(trap_handler)
        // Limits the helpers' Form/Json bodies; the trap reads its own.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

/// One `X-Forwarded-For` entry: an address, optionally with a port
/// (`203.0.113.9:4711`, `[2001:db8::1]:4711`, `[2001:db8::1]`).
fn parse_xff_entry(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>()
        .ok()
        .or_else(|| s.parse::<SocketAddr>().ok().map(|a| a.ip()))
        .or_else(|| {
            s.strip_prefix('[')
                .and_then(|r| r.strip_suffix(']'))
                .and_then(|r| r.parse::<IpAddr>().ok())
        })
}

/// Source IP from `X-Forwarded-For`, trusting only hops we control.
///
/// `X-Forwarded-For` is `client, proxy1, proxy2, …` with each proxy appending
/// the address it received the connection from. Only entries written by a
/// trusted proxy can be believed, so we start at the direct peer and walk the
/// header right-to-left, stepping over each hop that is itself trusted; the
/// first address that is not a trusted proxy is the real client. Taking the
/// first (leftmost) entry, or a single fixed position, lets a client forge its
/// address — a proxy that appends rather than replaces keeps a
/// client-supplied entry. Addresses are canonicalised so an
/// IPv4-mapped IPv6 hop matches IPv4 trust CIDRs. All `x-forwarded-for` header
/// lines are considered, newest last, and values are parsed from raw bytes so
/// a non-ASCII byte cannot blank the header and pin everything on the proxy.
///
/// Entries may carry a port (`ip:port`, `[v6]:port`). An entry that is not
/// an address at all stops the walk at the last trusted hop (fail closed):
/// skipping it would let a forged entry further left stand in for the one a
/// trusted proxy wrote. Empty entries (`a,,b`) are skipped.
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
    // Every XFF entry across all header lines, left to right.
    let entries: Vec<String> = headers
        .get_all("x-forwarded-for")
        .iter()
        .flat_map(|v| {
            String::from_utf8_lossy(v.as_bytes())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .collect();
    // Walk right to left, skipping trusted hops; the first untrusted one wins.
    let mut last_trusted = fallback;
    for e in entries.iter().rev() {
        let Some(ip) = parse_xff_entry(e) else {
            return last_trusted;
        };
        let ip = crate::net::canonical(ip);
        if !is_trusted(&ip) {
            return ip;
        }
        last_trusted = ip;
    }
    // Every entry (and the peer) is trusted, or there were none: use the peer.
    fallback
}

/// The body as far as the trap keeps it: at most `MAX_BODY` bytes, plus,
/// when that is not the whole body, the number of bytes received before
/// reading stopped (cut at the cap, drained up to `MAX_BODY_DRAIN`, timed out
/// or broken off).
async fn read_body(body: axum::body::Body) -> (Vec<u8>, Option<u64>) {
    let mut stream = body.into_data_stream();
    let mut kept: Vec<u8> = Vec::new();
    let mut seen: u64 = 0;
    let mut complete = false;
    let deadline = tokio::time::sleep(BODY_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            next = stream.next() => match next {
                Some(Ok(chunk)) => {
                    seen += chunk.len() as u64;
                    let room = MAX_BODY.saturating_sub(kept.len());
                    kept.extend_from_slice(&chunk[..room.min(chunk.len())]);
                    if seen >= MAX_BODY_DRAIN {
                        break;
                    }
                }
                Some(Err(_)) => break,
                None => {
                    complete = true;
                    break;
                }
            },
            _ = &mut deadline => break,
        }
    }
    let whole = complete && seen == kept.len() as u64;
    (kept, (!whole).then_some(seen))
}

/// What the trap stores for one request besides the verdict.
struct Capture<'a> {
    ip: IpAddr,
    view: RequestView<'a>,
    /// Headers as stored (with the trap's `:`-pseudo-headers).
    raw_headers: &'a [(String, String)],
    /// The body as received (not decompressed).
    body: Option<Vec<u8>>,
    is_fp_claim: bool,
    page_token: String,
    /// How the request is answered: `not-found`, `decoy:<name>`, `claim`.
    answer: String,
    status: u16,
    /// Requests from this IP answered but not recorded since its last
    /// recorded one.
    unrecorded: u64,
    /// What the connection showed (None when served without the trap's
    /// listeners, as in some tests).
    conn: Option<ConnCapture>,
}

/// The connection-level part of a capture.
struct ConnCapture {
    transport: &'static str,
    via_proxy: bool,
    raw_head: Option<Vec<u8>>,
    client_hello: Option<Vec<u8>>,
    ja4: Option<String>,
}

impl ConnCapture {
    fn of(meta: &listen::ConnMeta, version: Version) -> Self {
        // HTTP/2 has no text head; for HTTP/1 the connection carries one
        // request, so its first bytes are this request's head.
        let raw_head = (version < Version::HTTP_2)
            .then(|| {
                let b = meta.head.lock().unwrap_or_else(|p| p.into_inner());
                raw_head::head_of(&b).map(<[u8]>::to_vec)
            })
            .flatten();
        Self {
            transport: meta.transport,
            via_proxy: meta.via_proxy,
            raw_head,
            client_hello: meta.client_hello.as_ref().map(|h| h.to_vec()),
            ja4: meta.ja4.clone(),
        }
    }
}

/// What the trap stored for one request.
struct Recorded {
    request_id: i64,
    ip_id: i64,
}

/// Record this node's intel result unless it was recorded moments ago.
/// Best effort: a failure is logged, and the request is recorded anyway.
async fn record_intel(
    state: &TrapState,
    ip: IpAddr,
    provider: &'static str,
    version: Option<&str>,
    data: serde_json::Value,
) {
    if state.guards.intel.is_current(ip, provider, &data) {
        return;
    }
    if let Err(e) = state
        .recorder
        .record_intel(&ip.to_string(), provider, version, data.clone())
        .await
    {
        warn!(%ip, provider, error = %e, "trap: recording intel failed");
        return;
    }
    state.guards.intel.put(ip, provider, data);
}

async fn record(state: &TrapState, c: Capture<'_>) -> Result<Recorded> {
    let ip = c.ip;
    let ip_s = ip.to_string();

    // Enrichment (every IP, every request — spec §4): what this node can
    // look up itself. Written only when it changes. IPs this node cannot
    // look up are filled in by a node that can (intel::enrich_once).
    let geo_hit = state
        .geo
        .read()
        .unwrap()
        .as_ref()
        .map(|g| (g.lookup(&ip), g.build_date()));
    if let Some((g, version)) = geo_hit {
        record_intel(
            state,
            ip,
            crate::intel::MAXMIND,
            version.as_deref(),
            crate::store::recorder::Recorder::geo_data(
                g.country.as_deref(),
                g.asn,
                g.asn_org.as_deref(),
            ),
        )
        .await;
    }
    // With a Tor list loaded, every IP gets a result (false included); with
    // none, this node has nothing to say.
    let tor_hit = {
        let tor = state.tor.read().unwrap();
        (!tor.is_empty()).then(|| tor.contains(&ip))
    };
    let is_tor = tor_hit == Some(true);
    if let Some(exit) = tor_hit {
        record_intel(
            state,
            ip,
            crate::intel::TOR,
            None,
            serde_json::json!({ "exit": exit }),
        )
        .await;
    }

    // A false-positive claim is the visitor saying "I'm not a scanner"; it must
    // not be classified as hostile or trigger a counter-scan (otherwise the
    // POST alone scores form-interaction and escalates the claimant).
    let verdict = if c.is_fp_claim {
        crate::classify::Verdict {
            severity: 0,
            scan_level: 0,
            labels: vec!["fp-claim".into()],
            owasp: vec![],
        }
    } else {
        let history = state
            .store
            .ip_history(&ip_s, c.view.path)
            .await
            .unwrap_or_default();
        state
            .classifier
            .classify(&c.view, &history, &BotTells::default())
    };

    // Creates the IP's row too: one write transaction.
    let (request_id, ip_id) = state
        .recorder
        .insert_request_from(
            &ip_s,
            &NewRequest {
                ip_id: 0,
                method: c.view.method.to_string(),
                path: c.view.path.to_string(),
                query: c.view.query.map(str::to_string),
                headers_json: serde_json::to_string(c.raw_headers)?,
                body: c.body,
                labels_json: serde_json::to_string(&verdict.labels)?,
                owasp_json: Some(serde_json::to_string(&verdict.owasp)?),
                severity: verdict.severity as i64,
                scan_level: verdict.scan_level as i64,
                is_fp_claim: c.is_fp_claim,
                page_token: Some(c.page_token),
                answer: Some(c.answer),
                status: Some(i64::from(c.status)),
                unrecorded: (c.unrecorded > 0).then_some(c.unrecorded as i64),
                transport: c.conn.as_ref().map(|k| k.transport.to_string()),
                via_proxy: c.conn.as_ref().map(|k| k.via_proxy),
                raw_head: c.conn.as_ref().and_then(|k| k.raw_head.clone()),
                tls_client_hello: c.conn.as_ref().and_then(|k| k.client_hello.clone()),
                ja4: c.conn.as_ref().and_then(|k| k.ja4.clone()),
            },
        )
        .await?;

    // Enqueue counter-scan unless tor / allowlisted / non-global / level 0
    // (spec §4-5).
    if verdict.scan_level > 0 && !is_tor && may_scan(state, ip) {
        enqueue(state, ip_id, verdict.scan_level).await?;
    }
    Ok(Recorded { request_id, ip_id })
}

/// Whether this trap may queue a counter-scan of `ip` (Tor is checked by the
/// caller). The non-global guard is absolute: a spoofed X-Forwarded-For or a
/// misconfigured never_scan must never aim nmap at loopback, the internal
/// network or a link-local metadata endpoint. never_scan is checked on the
/// canonical address so IPv4-mapped IPv6 cannot slip past IPv4 CIDRs.
fn may_scan(state: &TrapState, ip: IpAddr) -> bool {
    let canon = crate::net::canonical(ip);
    // never_scan is the business of this node's own scanner. Standalone
    // that is the only scanner, so the job is not queued at all; in a
    // cluster another scanner may take it.
    let allowlisted = state.recorder.node().is_none()
        && state.cfg.scan.never_scan.iter().any(|n| n.contains(&canon));
    !allowlisted && crate::net::is_scannable_target(ip)
}

async fn enqueue(state: &TrapState, ip_id: i64, level: u8) -> Result<()> {
    if let crate::store::scans::EnqueueOutcome::Queued(job_id) = state
        .recorder
        .enqueue_scan_with(ip_id, level, &state.enqueue_policy())
        .await?
        && let Ok(Some(job)) = state.store.queue_job(job_id).await
    {
        state.notifier.publish(job);
    }
    Ok(())
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

/// Every request no other route takes: recorded (unless this IP is over its
/// recording rate), classified, and answered with the trap page (or a decoy).
///
/// Besides the headers as sent, the stored header list carries what the
/// trap observed, as pseudo-headers (names starting with `:` cannot be sent
/// by a client): `:version` (HTTP version on this connection; behind a
/// proxy, the proxy's), `:authority` (the host of an absolute-form target
/// such as an open-proxy probe, or HTTP/2's authority), `:body-truncated`
/// (bytes received when the stored body is not the whole body; the declared
/// length is in `content-length`). Rows recorded before the `unrecorded`
/// column existed carry that count as `:unrecorded`.
async fn trap_handler(
    State(state): State<Arc<TrapState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let in_flight = state.guards.enter();
    let (parts, body) = req.into_parts();
    let ip = client_ip(&parts.headers, peer.ip(), &state.cfg.trusted_proxies);
    let (body, received) = read_body(body).await;
    let page_token = uuid::Uuid::new_v4().to_string();
    // Decided before recording, so the row says what was sent.
    let decoy = if state.cfg.trap.decoys {
        decoy::decoy(
            parts.method.as_str(),
            parts.uri.path(),
            &page_token.replace('-', "")[..12],
        )
    } else {
        None
    };
    let (answer, status) = match &decoy {
        Some(d) => (format!("decoy:{}", d.name), 200),
        None => ("not-found".to_string(), 404),
    };
    // Recorded apart from the answer: hyper drops this future when the
    // client resets the stream or the connection ends, which must not lose
    // the request or a batch of light rows taken but not yet written.
    tokio::spawn(record_trap(
        state.clone(),
        in_flight,
        ip,
        parts,
        body,
        received,
        page_token.clone(),
        answer,
        status,
    ));
    if let Some(d) = decoy {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, d.content_type)],
            d.body,
        )
            .into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Html(pages::trap_page(&page_token, &state.cfg.trap.helper_prefix)),
    )
        .into_response()
}

/// The recording part of [`trap_handler`]: a full row, or a light row when
/// this IP is over its recording rate. In flight until it is done.
#[allow(clippy::too_many_arguments)]
async fn record_trap(
    state: Arc<TrapState>,
    _in_flight: InFlight,
    ip: IpAddr,
    parts: axum::http::request::Parts,
    body: Vec<u8>,
    received: Option<u64>,
    page_token: String,
    answer: String,
    status: u16,
) {
    let method = parts.method.as_str();
    let path = parts.uri.path();
    match state.guards.flood.admit(ip, &state.cfg.trap) {
        flood::Admission::Skip => {
            debug!(%ip, "trap: over the recording rate; answered, light row only");
            let full = state.guards.skips.note(
                ip,
                chrono::Utc::now().timestamp_millis(),
                method,
                path,
                state.cfg.trap.skip_log_rate,
                Instant::now(),
            );
            if let Some(b) = full {
                write_skips(&state, b).await;
            }
        }
        flood::Admission::Record { unrecorded } => {
            // The light rows before it go first, so they precede it in time.
            if let Some(b) = state.guards.skips.take(ip) {
                write_skips(&state, b).await;
            }
            let mut raw = vec![(":version".to_string(), format!("{:?}", parts.version))];
            let authority = parts.uri.authority().map(|a| a.as_str());
            if let Some(a) = authority {
                raw.push((":authority".into(), a.to_string()));
            }
            if let Some(n) = received {
                raw.push((":body-truncated".into(), n.to_string()));
            }
            raw.extend(header_pairs(&parts.headers));
            // HTTP/2 always names the authority; in HTTP/1 only a client
            // that takes us for a forward proxy does.
            let proxy_target = authority.filter(|_| parts.version < Version::HTTP_2);
            let classified = crate::classify::decoded_body(&raw, &body);
            let view = RequestView {
                method,
                path,
                query: parts.uri.query(),
                headers: raw.clone(),
                body: (!classified.is_empty()).then_some(&classified[..]),
                proxy_target,
            };
            let capture = Capture {
                ip,
                view,
                raw_headers: &raw,
                body: (!body.is_empty()).then(|| body.clone()),
                is_fp_claim: false,
                page_token,
                answer,
                status,
                unrecorded,
                conn: parts
                    .extensions
                    .get::<listen::ConnMeta>()
                    .map(|m| ConnCapture::of(m, parts.version)),
            };
            if let Err(e) = record(&state, capture).await {
                // Answered as always: an error page would tell a scanner it
                // found something other than a missing route.
                warn!(%ip, error = %e, "trap: recording the request failed");
            }
        }
    }
}

#[derive(serde::Deserialize)]
pub struct ClaimForm {
    email: Option<String>,
}

async fn claim_handler(
    State(state): State<Arc<TrapState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    version: Version,
    meta: Option<axum::Extension<listen::ConnMeta>>,
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
    let path = format!("{}/claim", state.cfg.trap.helper_prefix);
    let conn = meta.map(|m| ConnCapture::of(&m, version));
    // Recorded apart from the answer, as in `trap_handler`.
    let in_flight = state.guards.enter();
    tokio::spawn(async move {
        let _in_flight = in_flight;
        let capture = Capture {
            ip,
            view: RequestView {
                method: "POST",
                path: &path,
                query: None,
                headers: raw.clone(),
                body: None,
                proxy_target: None,
            },
            raw_headers: &raw,
            body: None,
            is_fp_claim: true,
            page_token: uuid::Uuid::new_v4().to_string(),
            answer: "claim".into(),
            status: 200,
            unrecorded: 0,
            conn,
        };
        if let Ok(rec) = record(&state, capture).await {
            let email = form.email.filter(|e| !e.trim().is_empty());
            let _ = state
                .recorder
                .insert_fp_claim(rec.ip_id, rec.request_id, email.as_deref(), &ua)
                .await;
        }
    });
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
    // Recorded apart from the answer, as in `trap_handler`.
    let in_flight = state.guards.enter();
    tokio::spawn(async move {
        let _in_flight = in_flight;
        if let Ok(ip_row) = state.store.upsert_ip(ip).await {
            // Attribute the fingerprint to the page view that issued the token;
            // fall back to the connection IP for unknown tokens.
            let req: Option<(i64, i64, String)> = sqlx::query_as(
                "SELECT r.id, r.ip_id, i.ip FROM requests r JOIN ips i ON i.id = r.ip_id
                 WHERE r.page_token = ? ORDER BY r.id DESC LIMIT 1",
            )
            .bind(&payload.token)
            .fetch_optional(&state.store.pool)
            .await
            .unwrap_or(None);
            let (request_id, ip_id, page_ip) = match req {
                Some((rid, iid, page_ip)) => (Some(rid), iid, page_ip.parse::<IpAddr>().ok()),
                None => (None, ip_row.id, Some(ip)),
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
            // movement), escalate a counter-scan now — of the address the page
            // was served to, subject to the same tor / never_scan / non-global
            // guards as the request path. Bot evidence posted from another
            // address than the page's is stored but escalates nothing: it is not
            // tied to one address, and a token alone must not aim a scan.
            let tells = crate::fingerprint::bot_tells(&payload.attrs, &payload.behavior);
            if (tells.webdriver || tells.inhuman_fill)
                && let Some(target) = page_ip.map(crate::net::canonical)
                && target == crate::net::canonical(ip)
                && !state.tor.read().unwrap().contains(&target)
                && may_scan(&state, target)
            {
                let level = if tells.inhuman_fill { 3 } else { 2 };
                let _ = enqueue(&state, ip_id, level).await;
            }
        }
    });
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
        // A proxy may emit several XFF lines; the last entry overall wins.
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
    fn entries_with_ports_are_parsed() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        for (xff, want) in [
            ("203.0.113.9:4711", "203.0.113.9"),
            ("[2001:db8::1]:4711", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),
        ] {
            // A forged entry on the left must not win over the proxy's.
            let ip = client_ip(&hm(&["6.6.6.6", xff]), peer, &trusted());
            assert_eq!(ip, want.parse::<IpAddr>().unwrap(), "{xff}");
        }
        // A trusted hop written with a port is still skipped.
        let ip = client_ip(&hm(&["203.0.113.9", "10.0.0.2:80"]), peer, &trusted());
        assert_eq!(ip, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn unparsable_entry_stops_the_walk_at_the_last_trusted_hop() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        // Skipping "garbage" would let the forged 6.6.6.6 win.
        let ip = client_ip(&hm(&["6.6.6.6", "garbage", "10.0.0.2"]), peer, &trusted());
        assert_eq!(ip, "10.0.0.2".parse::<IpAddr>().unwrap());
        // Unparsable as the rightmost entry: the peer.
        let ip = client_ip(&hm(&["6.6.6.6, unknown"]), peer, &trusted());
        assert_eq!(ip, peer);
        let ip = client_ip(&hm(&["6.6.6.6", "203.0.113.9:x"]), peer, &trusted());
        assert_eq!(ip, peer);
        // Empty entries are not addresses a proxy wrote; they are skipped.
        let ip = client_ip(&hm(&["6.6.6.6,, 203.0.113.9,"]), peer, &trusted());
        assert_eq!(ip, "203.0.113.9".parse::<IpAddr>().unwrap());
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
