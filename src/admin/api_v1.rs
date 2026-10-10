//! The machine API (`/api/v1`) of this node, for the companion app. Its
//! credential is the device token (`Authorization: Bearer …`), honoured here
//! and nowhere else; the admin session cookie is honoured everywhere else
//! and never here. Every answer is JSON, errors included
//! (`{error:{code,message}}`, see `docs/api-v1.md`).
use crate::admin::AdminState;
use crate::admin::scan_buy::NotSold;
use crate::store::browse::{IpFilter, IpSummary};
use crate::store::devices::Device;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{FromRequestParts, Path, Query, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::net::IpAddr;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/api/v1/pair", post(pair))
        .route("/api/v1/ips", get(ips))
        .route("/api/v1/ips/{addr}", get(ip_detail))
        .route("/api/v1/lookup", post(lookup))
        .route("/api/v1/ips/{addr}/probe", post(probe))
        .route("/api/v1/ips/{addr}/scan/quote", get(scan_quote))
        .route("/api/v1/ips/{addr}/scan", post(scan_buy))
        .route("/api/v1/jobs/{job_id}", get(job))
        // Unknown API paths answer in the API's error shape, not the HTML 404.
        .route("/api/v1/{*rest}", axum::routing::any(not_found))
}

async fn not_found() -> Response {
    err(StatusCode::NOT_FOUND, "not_found", "no such endpoint")
}

/// The error shape: every non-2xx of `/api/v1` is this JSON.
pub fn err(status: StatusCode, code: &'static str, message: impl std::fmt::Display) -> Response {
    (
        status,
        Json(json!({"error": {"code": code, "message": message.to_string()}})),
    )
        .into_response()
}

fn internal(e: anyhow::Error) -> Response {
    tracing::warn!(?e, "api: request failed");
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "internal error",
    )
}

/// Device-token extractor for `/api/v1/*`: reads `Authorization: Bearer`
/// only, never cookies. The hash is the lookup key (indexed exact match, so
/// constant-time by construction); revoked and unknown tokens are 401, a
/// token without the `read` scope is 403.
pub struct DeviceAuth(pub Device);

impl FromRequestParts<Arc<AdminState>> for DeviceAuth {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AdminState>,
    ) -> Result<Self, Self::Rejection> {
        let Some(token) = bearer(parts) else {
            return Err(err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "a bearer token is required",
            ));
        };
        match state.store.validate_device_token(token).await {
            Ok(Some(d)) if d.has_scope("read") => Ok(DeviceAuth(d)),
            Ok(Some(_)) => Err(err(
                StatusCode::FORBIDDEN,
                "forbidden",
                "the token lacks the read scope",
            )),
            Ok(None) => Err(err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "unknown or revoked token",
            )),
            Err(e) => Err(internal(e)),
        }
    }
}

/// A device token with the `act` scope too: what the endpoints that queue
/// work (and read it back) take. Without it, 403.
pub struct ActAuth(pub Device);

impl FromRequestParts<Arc<AdminState>> for ActAuth {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AdminState>,
    ) -> Result<Self, Self::Rejection> {
        let DeviceAuth(d) = DeviceAuth::from_request_parts(parts, state).await?;
        if !d.has_scope("act") {
            return Err(err(
                StatusCode::FORBIDDEN,
                "forbidden",
                "the token lacks the act scope",
            ));
        }
        Ok(ActAuth(d))
    }
}

/// The token of an `Authorization: Bearer <token>` header, if well-formed.
fn bearer(parts: &Parts) -> Option<&str> {
    let v = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = v.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// A stored timestamp (SQLite `YYYY-MM-DD HH:MM:SS` or RFC 3339, as intel
/// and scans keep it) as RFC 3339 UTC, which the API speaks.
fn rfc3339<S: crate::admin::views::Stamp>(ts: S) -> String {
    ts.utc()
        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// An `IpSummary` as the API serializes it (times in RFC 3339).
fn summary_json(s: &IpSummary) -> Value {
    json!({
        "ip": s.ip,
        "country": s.country,
        "asn": s.asn,
        "asn_org": s.asn_org,
        "is_tor": s.is_tor,
        "first_seen": rfc3339(&s.first_seen),
        "last_seen": rfc3339(&s.last_seen),
        "request_count": s.request_count,
        "max_severity": s.max_severity,
        "abuse_score": s.abuse_score,
    })
}

#[derive(serde::Deserialize)]
pub struct PairBody {
    code: String,
    device_name: String,
}

/// Longest device name a pairing accepts.
const NAME_MAX: usize = 80;

async fn pair(
    State(state): State<Arc<AdminState>>,
    body: Result<Json<PairBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(b)) = body else {
        return err(StatusCode::BAD_REQUEST, "invalid", "malformed body");
    };
    if b.device_name.trim().is_empty() || b.device_name.chars().count() > NAME_MAX {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "device_name must be 1-80 characters",
        );
    }
    match state
        .store
        .redeem_pairing_code(&b.code, &b.device_name)
        .await
    {
        // The token is shown here and only here; the store keeps its hash.
        Ok(Some((device, token))) => Json(json!({
            "token": token,
            "device_id": device.id,
            "scopes": device.scopes(),
            "instance_name": state.cfg.webauthn().rp_name,
        }))
        .into_response(),
        Ok(None) => err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "unknown, expired or already used pairing code",
        ),
        Err(e) => internal(e),
    }
}

/// Default and largest page of `GET /api/v1/ips`.
const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;

/// The continuation token: the query it belongs to and the page to serve
/// next, base64url(JSON). Opaque to the client; a cursor answers only the
/// query it was issued with.
#[derive(serde::Serialize, serde::Deserialize)]
struct Cursor {
    q: String,
    page: u32,
}

fn encode_cursor(c: &Cursor) -> String {
    data_encoding::BASE64URL_NOPAD.encode(&serde_json::to_vec(c).unwrap_or_default())
}

fn decode_cursor(s: &str) -> Option<Cursor> {
    let bytes = data_encoding::BASE64URL_NOPAD.decode(s.as_bytes()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[derive(serde::Deserialize)]
pub struct IpsQuery {
    q: Option<String>,
    cursor: Option<String>,
    limit: Option<String>,
}

async fn ips(
    DeviceAuth(_): DeviceAuth,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<IpsQuery>,
) -> Response {
    let limit = match q.limit.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => DEFAULT_LIMIT,
        Some(v) => match v.parse::<i64>() {
            Ok(n) if n >= 1 => n.min(MAX_LIMIT),
            _ => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid",
                    "limit must be a number, 1-100",
                );
            }
        },
    };
    let query = q.q.unwrap_or_default();
    let page = match q.cursor.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => 1,
        Some(c) => match decode_cursor(c) {
            Some(c) if c.q == query => c.page.max(1),
            Some(_) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid",
                    "the cursor was issued for another query",
                );
            }
            None => return err(StatusCode::BAD_REQUEST, "invalid", "unreadable cursor"),
        },
    };
    // The store pages in 100s; an API page of `limit` rows can straddle two
    // of them. Fetch until limit+1 rows (the +1 decides next_cursor).
    let offset = (page as i64 - 1) * limit;
    let store_page = (offset / crate::store::browse::PAGE_SIZE + 1) as i64;
    let within = (offset % crate::store::browse::PAGE_SIZE) as usize;
    let fetch = |page: i64| {
        let state = &state;
        let query = &query;
        async move {
            state
                .store
                .list_ips_as(
                    &IpFilter {
                        q: Some(query.clone()),
                        page: Some(page),
                        ..Default::default()
                    },
                    crate::store::browse::Audience::Admin,
                )
                .await
        }
    };
    let first = match fetch(store_page).await {
        Ok(p) => p,
        Err(e) => return internal(e),
    };
    let mut rows: Vec<IpSummary> = first.items.into_iter().skip(within).collect();
    if rows.len() <= limit as usize && first.has_next {
        match fetch(store_page + 1).await {
            Ok(p) => rows.extend(p.items),
            Err(e) => return internal(e),
        }
    }
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = more.then(|| {
        encode_cursor(&Cursor {
            q: query,
            page: page + 1,
        })
    });
    Json(json!({
        "items": rows.iter().map(summary_json).collect::<Vec<_>>(),
        "next_cursor": next_cursor,
    }))
    .into_response()
}

async fn ip_detail(
    DeviceAuth(_): DeviceAuth,
    State(state): State<Arc<AdminState>>,
    Path(addr): Path<String>,
) -> Response {
    let Ok(addr) = addr.trim().parse::<std::net::IpAddr>() else {
        return err(StatusCode::BAD_REQUEST, "invalid", "not an IP address");
    };
    let addr = crate::net::canonical(addr).to_string();
    let run = async {
        let store = &state.store;
        let Some(ip) = store.ip_by_addr(&addr).await? else {
            return anyhow::Ok(None);
        };
        let Some(ov) = store.ip_overview(ip.id).await? else {
            return Ok(None);
        };
        // Newest stored answer per provider (intel_for_ip is provider-major,
        // newest first). Tor is not an entry: is_tor comes from the exit list.
        let mut intel = serde_json::Map::new();
        for p in crate::intel::KNOWN_PROVIDERS
            .iter()
            .filter(|p| p.name != crate::intel::TOR)
        {
            intel.insert(p.name.to_string(), Value::Null);
        }
        for row in store.intel_for_ip(&ip.ip).await? {
            let taken = intel.get(&row.provider).is_some_and(|v| !v.is_null());
            if row.provider == crate::intel::TOR || taken {
                continue;
            }
            intel.insert(
                row.provider.clone(),
                json!({
                    "fetched_at": rfc3339(&row.fetched_at),
                    "data": serde_json::from_str::<Value>(&row.data_json).unwrap_or(Value::Null),
                }),
            );
        }
        let scans = store.scans_for_ip(ip.id).await?;
        let ids: Vec<i64> = scans.iter().map(|s| s.id).collect();
        let mut ports = store.ports_for_scans(&ids).await?;
        let scans: Vec<Value> = scans
            .into_iter()
            .filter_map(|s| {
                let ports = ports
                    .remove(&s.id)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|p| p.state == "open")
                    .map(|p| json!({"port": p.port, "service": p.service, "product": p.product}))
                    .collect::<Vec<_>>();
                Some(json!({"scanned_at": rfc3339(s.finished_at?), "ports": ports}))
            })
            .collect();
        let names: Vec<Value> = store
            .names_for_ip(ip.id)
            .await?
            .into_iter()
            .map(|n| json!({"name": n.name, "source": n.source, "agreed": n.agreed}))
            .collect();
        Ok(Some(json!({
            "ip": ip.ip,
            "geo": {"country": ip.country, "asn": ip.asn, "asn_org": ip.asn_org},
            "is_tor": ip.is_tor_exit,
            "severity": ov.max_severity,
            "first_seen": rfc3339(ov.ip.first_seen),
            "last_seen": rfc3339(ov.ip.last_seen),
            "request_count": ov.request_count,
            "labels": ov.labels.iter().map(|l| &l.name).collect::<Vec<_>>(),
            "families": ov.families.iter().map(|f| json!({"name": f.name, "count": f.count})).collect::<Vec<_>>(),
            "intel": Value::Object(intel),
            "scans": scans,
            "names": names,
            "rank": ov.rank,
            "neighbours": {"net": ov.net, "other_ips": ov.net_count, "same_asn": ov.asn_count},
        })))
    };
    match run.await {
        Ok(Some(detail)) => Json(detail).into_response(),
        Ok(None) => err(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such address in the dataset",
        ),
        Err(e) => internal(e),
    }
}

#[derive(serde::Deserialize)]
pub struct LookupBody {
    ips: Vec<String>,
}

/// Stored-data lookup for many addresses at once: the semantics and the cap
/// of the admin bulk lookup, but JSON. No provider is asked.
async fn lookup(
    DeviceAuth(_): DeviceAuth,
    State(state): State<Arc<AdminState>>,
    body: Result<Json<LookupBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(b)) = body else {
        return err(StatusCode::BAD_REQUEST, "invalid", "malformed body");
    };
    let read = match crate::admin::lookup::bulk_read(&state, b.ips.iter().map(|p| p.trim())).await {
        Ok(r) => r,
        Err(e) => return internal(e),
    };
    Json(json!({
        "results": read.rows.iter().map(summary_json).collect::<Vec<_>>(),
        "missing": read.missing,
        "unreadable": read.unreadable,
        "capped": read.capped,
    }))
    .into_response()
}

/// A path address and its dataset row id: 400 when it is not an address,
/// 404 when it is not in the dataset.
async fn row_of(state: &AdminState, addr: &str) -> Result<(IpAddr, i64), Box<Response>> {
    let Ok(ip) = addr.trim().parse::<IpAddr>() else {
        return Err(Box::new(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "not an IP address",
        )));
    };
    let ip = crate::net::canonical(ip);
    match state.store.ip_by_addr(&ip.to_string()).await {
        Ok(Some(row)) => Ok((ip, row.id)),
        Ok(None) => Err(Box::new(err(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such address in the dataset",
        ))),
        Err(e) => Err(Box::new(internal(e))),
    }
}

/// Credits as the API gives them: the decimal string and the integer
/// millicredits.
fn credits(mc: u64) -> (String, u64) {
    (crate::credits::show(mc), mc)
}

/// Log what `device` queued; a failed write is an internal error, so no
/// act call answers 202 without its audit entry.
async fn audit(
    state: &AdminState,
    device: &Device,
    action: &str,
    target: &str,
    credits_mc: u64,
    job_id: &str,
) -> Result<(), Box<Response>> {
    state
        .store
        .record_device_action(device, action, target, credits_mc, job_id)
        .await
        .map_err(|e| Box::new(internal(e)))
}

#[derive(serde::Deserialize, Default)]
pub struct ProbeBody {
    vantages: Option<Vec<String>>,
}

/// POST /api/v1/ips/{addr}/probe: the probe of the Actions card
/// (`probes::start`), the default pick unless `vantages` names others.
async fn probe(
    ActAuth(device): ActAuth,
    State(state): State<Arc<AdminState>>,
    Path(addr): Path<String>,
    body: Bytes,
) -> Response {
    let b: ProbeBody = match body.iter().all(u8::is_ascii_whitespace) {
        true => ProbeBody::default(),
        false => match serde_json::from_slice(&body) {
            Ok(b) => b,
            Err(_) => return err(StatusCode::BAD_REQUEST, "invalid", "malformed body"),
        },
    };
    let (ip, ip_id) = match row_of(&state, &addr).await {
        Ok(r) => r,
        Err(r) => return *r,
    };
    let started = match crate::admin::probes::start(&state, ip, ip_id, b.vantages.as_deref()).await
    {
        Ok(s) => s,
        Err(why) => return err(StatusCode::UNPROCESSABLE_ENTITY, "refused", why),
    };
    let mc: u64 = started.asked.iter().map(|v| v.price_mc as u64).sum();
    let job_id = format!("p_{}", started.group);
    if let Err(r) = audit(&state, &device, "probe", &ip.to_string(), mc, &job_id).await {
        return *r;
    }
    let (credits, credits_mc) = credits(mc);
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "job_id": job_id,
            "credits": credits,
            "credits_mc": credits_mc,
            "vantages": started.asked.iter().map(|v| json!({
                "id": v.id,
                "name": v.name,
                "country": v.country,
                "credits_mc": v.price_mc,
            })).collect::<Vec<_>>(),
        })),
    )
        .into_response()
}

/// 409 for a scan that is not sold (`scan_buy::sale`).
fn not_sold(n: NotSold) -> Response {
    let conflict = |code: &'static str, message: &str, extra: Value| {
        let mut e = json!({"code": code, "message": message});
        if let (Some(e), Value::Object(x)) = (e.as_object_mut(), extra) {
            e.extend(x);
        }
        (StatusCode::CONFLICT, Json(json!({"error": e}))).into_response()
    };
    match n {
        NotSold::Fresh(at, scan_id) => conflict(
            "fresh",
            "a scan of this level is less than a day old",
            json!({"scan_id": scan_id, "scanned_at": rfc3339(at.as_str())}),
        ),
        NotSold::OnItsWay(status) => conflict(
            "on_its_way",
            "a scan of this level is already on its way",
            json!({"status": status}),
        ),
        NotSold::NoPrice => conflict("no_price", "no live scanner announces a price", json!({})),
        NotSold::NoBudget => conflict(
            "no_budget",
            "the scan budget does not cover this",
            json!({}),
        ),
    }
}

/// The level of a query or body: 1-5, else a 400.
fn level_of(v: Option<&str>) -> Result<u8, Box<Response>> {
    v.and_then(|l| l.trim().parse::<i64>().ok())
        .and_then(crate::scan::valid_level)
        .ok_or_else(|| Box::new(err(StatusCode::BAD_REQUEST, "invalid", "level must be 1-5")))
}

#[derive(serde::Deserialize)]
pub struct QuoteQuery {
    level: Option<String>,
}

/// GET /api/v1/ips/{addr}/scan/quote?level=: what a scan costs now, as a
/// quote the device can spend once within `QUOTE_SECS`.
async fn scan_quote(
    ActAuth(device): ActAuth,
    State(state): State<Arc<AdminState>>,
    Path(addr): Path<String>,
    Query(q): Query<QuoteQuery>,
) -> Response {
    let level = match level_of(q.level.as_deref()) {
        Ok(l) => l,
        Err(r) => return *r,
    };
    let (ip, ip_id) = match row_of(&state, &addr).await {
        Ok(r) => r,
        Err(r) => return *r,
    };
    let price = match crate::admin::scan_buy::sale(&state, ip_id, level).await {
        Ok(Ok(p)) => p,
        Ok(Err(n)) => return not_sold(n),
        Err(e) => return internal(e),
    };
    let quote = match state
        .store
        .create_quote(&device.id, &ip.to_string(), level, price.floor_mc)
        .await
    {
        Ok(q) => q,
        Err(e) => return internal(e),
    };
    let (floor, floor_mc) = credits(price.floor_mc);
    let (max, max_mc) = credits(price.max_mc);
    Json(json!({
        "quote_id": quote.id,
        "credits": floor,
        "credits_mc": floor_mc,
        "credits_max": max,
        "credits_max_mc": max_mc,
        "expires_at": rfc3339(quote.expires_at.as_str()),
        "offer": {"level": level, "about": crate::admin::scan_buy::about(level)},
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct BuyBody {
    quote_id: String,
}

/// POST /api/v1/ips/{addr}/scan {quote_id}: buy exactly the quoted scan.
/// The quote is spent first; every refusal after that queues and charges
/// nothing (a scan is charged when a scanner runs its job).
async fn scan_buy(
    ActAuth(device): ActAuth,
    State(state): State<Arc<AdminState>>,
    Path(addr): Path<String>,
    body: Result<Json<BuyBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(b)) = body else {
        return err(StatusCode::BAD_REQUEST, "invalid", "malformed body");
    };
    let Ok(ip) = addr.trim().parse::<IpAddr>() else {
        return err(StatusCode::BAD_REQUEST, "invalid", "not an IP address");
    };
    let ip = crate::net::canonical(ip).to_string();
    let quote = match state.store.spend_quote(&b.quote_id, &device.id).await {
        Ok(Some(q)) => q,
        Ok(None) => {
            return err(
                StatusCode::CONFLICT,
                "quote_invalid",
                "unknown, expired or already used quote",
            );
        }
        Err(e) => return internal(e),
    };
    if quote.addr != ip {
        return err(
            StatusCode::CONFLICT,
            "quote_mismatch",
            "the quote is for another address",
        );
    }
    let Some(level) = crate::scan::valid_level(quote.level) else {
        return err(
            StatusCode::CONFLICT,
            "quote_invalid",
            "the quote is unreadable",
        );
    };
    let (_, ip_id) = match row_of(&state, &ip).await {
        Ok(r) => r,
        Err(r) => return *r,
    };
    match crate::admin::scan_buy::sale(&state, ip_id, level).await {
        Ok(Ok(p)) if p.floor_mc == quote.credits_mc as u64 => {}
        Ok(Ok(_)) => {
            return err(
                StatusCode::CONFLICT,
                "price_changed",
                "the price moved since the quote: get a new one",
            );
        }
        Ok(Err(n)) => return not_sold(n),
        Err(e) => return internal(e),
    }
    let id = match crate::admin::scan_buy::enqueue(&state, ip_id, level).await {
        Ok(Ok(id)) => id,
        Ok(Err(Some(n))) => return not_sold(n),
        Ok(Err(None)) => {
            return err(
                StatusCode::CONFLICT,
                "not_queued",
                "the scan queue did not take the job",
            );
        }
        Err(e) => return internal(e),
    };
    let job_id = format!("s_{id}");
    let mc = quote.credits_mc as u64;
    // The job and its audit entry are written apart (in a cluster the job
    // goes to the replication log): without the entry, the job goes too.
    if let Err(r) = audit(&state, &device, "scan", &ip, mc, &job_id).await {
        match state.recorder.withdraw_job(id, "audit write failed").await {
            Ok(true) => {}
            Ok(false) => tracing::error!(job_id, "unaudited scan job already taken; not withdrawn"),
            Err(e) => tracing::error!(job_id, "unaudited scan job not withdrawn: {e:#}"),
        }
        return *r;
    }
    let (credits, credits_mc) = credits(mc);
    (
        StatusCode::ACCEPTED,
        Json(json!({"job_id": job_id, "credits": credits, "credits_mc": credits_mc})),
    )
        .into_response()
}

/// GET /api/v1/jobs/{job_id}: a job this device queued, by polling.
async fn job(
    ActAuth(device): ActAuth,
    State(state): State<Arc<AdminState>>,
    Path(job_id): Path<String>,
) -> Response {
    let action = match state.store.device_action(&device.id, &job_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return err(StatusCode::NOT_FOUND, "not_found", "no such job"),
        Err(e) => return internal(e),
    };
    let r = match action.action.as_str() {
        "scan" => scan_job(&state, &job_id).await,
        _ => probe_job(&state, &action.target, &job_id).await,
    };
    match r {
        Ok((status, result)) => Json(json!({
            "job_id": job_id,
            "kind": action.action,
            "ip": action.target,
            "status": status,
            "created_at": rfc3339(action.at.as_str()),
            "result": result,
        }))
        .into_response(),
        Err(e) => internal(e),
    }
}

/// A scan job's status and, once it landed, its result (the shape of
/// `ip_detail`'s `scans[]`).
async fn scan_job(state: &AdminState, job_id: &str) -> anyhow::Result<(&'static str, Value)> {
    let id: i64 = job_id
        .strip_prefix("s_")
        .and_then(|i| i.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("unreadable scan job id {job_id}"))?;
    let scan: Option<(i64, String)> = sqlx::query_as(
        "SELECT s.id, s.finished_at FROM scans s JOIN scan_jobs j ON s.job_uid = j.uid
         WHERE j.id = ? AND s.finished_at IS NOT NULL ORDER BY s.id DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.store.pool)
    .await?;
    let job = state.store.queue_job(id).await?;
    let status = match job.as_ref().map(|j| j.status.as_str()) {
        Some("queued") => "queued",
        Some("running") => "running",
        Some("done") => "done",
        // The job row may be gone (pruned) while its scan stays.
        None if scan.is_some() => "done",
        _ => "failed",
    };
    let Some((scan_id, finished_at)) = scan else {
        return Ok((status, Value::Null));
    };
    let ports: Vec<Value> = state
        .store
        .ports_for_scans(&[scan_id])
        .await?
        .remove(&scan_id)
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.state == "open")
        .map(|p| json!({"port": p.port, "service": p.service, "product": p.product}))
        .collect();
    Ok((
        status,
        json!({"scanned_at": rfc3339(finished_at.as_str()), "ports": ports}),
    ))
}

/// A probe request's status (running while a vantage waits) and what each
/// vantage said or saw so far, as the Probes section shows it.
async fn probe_job(
    state: &AdminState,
    target: &str,
    job_id: &str,
) -> anyhow::Result<(&'static str, Value)> {
    let group = job_id.strip_prefix("p_").unwrap_or(job_id);
    let members = match state.store.ip_by_addr(target).await? {
        Some(row) => crate::admin::probes::groups_for(state, row.id)
            .await
            .into_iter()
            .find(|g| g.group == group)
            .map(|g| g.members)
            .unwrap_or_default(),
        None => vec![],
    };
    let waiting = members
        .iter()
        .any(|m| matches!(m.state, "queued" | "running"));
    let vantages: Vec<Value> = members
        .iter()
        .map(|m| {
            json!({
                "node": m.node_id,
                "name": m.node,
                "state": m.state,
                "why": m.why,
                "rtt_ms": m.rtt_ms,
                "ports": m.ports.iter().map(|p| json!({
                    "port": p.port,
                    "protocol": p.protocol,
                    "outcome": p.outcome,
                    "detail": p.detail,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok((
        if waiting { "running" } else { "done" },
        json!({"vantages": vantages}),
    ))
}

#[cfg(test)]
mod tests {
    use crate::admin::AdminState;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    /// The app with an admin session cookie: (state, cookie, router, dir).
    async fn app() -> (Arc<AdminState>, String, axum::Router, tempfile::TempDir) {
        crate::admin::devices::tests::app().await
    }

    async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let r = app.clone().oneshot(req).await.unwrap();
        let status = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
        )
    }

    fn authed(method: &str, path: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn post_json(path: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// Mint a code on the admin page and redeem it: (token, device_id).
    async fn pair(app: &axum::Router, cookie: &str) -> (String, String) {
        let r = app
            .clone()
            .oneshot(
                Request::post("/admin/devices/pair")
                    .header("cookie", cookie)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        // The payload is HTML-escaped in the page.
        let html = String::from_utf8_lossy(&b).replace("&#34;", "\"");
        let code = html
            .split(r#""code":""#)
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("the pairing page carries the code")
            .to_string();
        let (st, v) = send(
            app,
            post_json(
                "/api/v1/pair",
                serde_json::json!({"code": code, "device_name": "Pixel 8"}),
            ),
        )
        .await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["scopes"], serde_json::json!(["read"]));
        assert_eq!(v["instance_name"], "t");
        (
            v["token"].as_str().unwrap().to_string(),
            v["device_id"].as_str().unwrap().to_string(),
        )
    }

    async fn seed_ip(state: &AdminState, ip: &str, labels: &str, sev: i64) {
        let row = state.store.upsert_ip(ip.parse().unwrap()).await.unwrap();
        state
            .store
            .insert_request(&crate::store::requests::NewRequest {
                ip_id: row.id,
                method: "GET".into(),
                path: "/.env".into(),
                headers_json: "[]".into(),
                labels_json: labels.into(),
                severity: sev,
                ..Default::default()
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn pairing_and_the_token_work() {
        let (_state, cookie, app, _d) = app().await;
        let (token, device_id) = pair(&app, &cookie).await;
        assert_eq!(token.len(), 43, "256-bit base64url");
        let (st, v) = send(&app, authed("GET", "/api/v1/ips", &token)).await;
        assert_eq!(st, 200, "{v}");
        assert!(v["items"].is_array() && v["next_cursor"].is_null());
        // The token is stored as a hash only.
        let stored: String = sqlx::query_scalar("SELECT token_hash FROM devices WHERE id = ?")
            .bind(&device_id)
            .fetch_one(&_state.store.pool)
            .await
            .unwrap();
        assert_ne!(stored, token);
        assert_eq!(stored, crate::store::auth::token_hash(&token));
    }

    #[tokio::test]
    async fn reused_and_expired_codes_are_unauthorized() {
        let (state, cookie, app, _d) = app().await;
        let (token, _) = pair(&app, &cookie).await;
        drop(token);
        // The same code again: consumed by the first redemption.
        let code = state
            .store
            .mint_pairing_code("read", "admin")
            .await
            .unwrap();
        let redeem = |code: String| {
            let app = app.clone();
            async move {
                send(
                    &app,
                    post_json(
                        "/api/v1/pair",
                        serde_json::json!({"code": code, "device_name": "d"}),
                    ),
                )
                .await
            }
        };
        let (st, _) = redeem(code.clone()).await;
        assert_eq!(st, 200);
        let (st, v) = redeem(code).await;
        assert_eq!(st, 401);
        assert_eq!(v["error"]["code"], "unauthorized", "{v}");
        // Expired: mint, backdate, redeem.
        let code = state
            .store
            .mint_pairing_code("read", "admin")
            .await
            .unwrap();
        sqlx::query("UPDATE pairing_codes SET expires_at = datetime('now', '-1 second')")
            .execute(&state.store.pool)
            .await
            .unwrap();
        let (st, v) = redeem(code).await;
        assert_eq!(st, 401);
        assert_eq!(v["error"]["code"], "unauthorized", "{v}");
        // Malformed bodies and names are 400, not 401.
        let bad = send(
            &app,
            Request::post("/api/v1/pair")
                .header("content-type", "application/json")
                .body(Body::from("{oops"))
                .unwrap(),
        )
        .await;
        assert_eq!(bad.0, 400);
        assert_eq!(bad.1["error"]["code"], "invalid");
        let long = "x".repeat(81);
        let (st, v) = send(
            &app,
            post_json(
                "/api/v1/pair",
                serde_json::json!({"code": "c", "device_name": long}),
            ),
        )
        .await;
        assert_eq!(st, 400);
        assert_eq!(v["error"]["code"], "invalid", "{v}");
    }

    #[tokio::test]
    async fn a_revoked_device_is_unauthorized() {
        let (_state, cookie, app, _d) = app().await;
        let (token, device_id) = pair(&app, &cookie).await;
        let (st, _) = send(&app, authed("GET", "/api/v1/ips", &token)).await;
        assert_eq!(st, 200);
        let r = app
            .clone()
            .oneshot(
                Request::post("/admin/devices/revoke")
                    .header("cookie", &cookie)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("id={device_id}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        let (st, v) = send(&app, authed("GET", "/api/v1/ips", &token)).await;
        assert_eq!(st, 401);
        assert_eq!(v["error"]["code"], "unauthorized", "{v}");
    }

    #[tokio::test]
    async fn the_two_credentials_never_mix() {
        let (_state, cookie, app, _d) = app().await;
        let (token, _) = pair(&app, &cookie).await;
        // A session cookie is not a device credential on the API.
        let (st, v) = send(
            &app,
            Request::get("/api/v1/ips")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(st, 401);
        assert_eq!(v["error"]["code"], "unauthorized", "{v}");
        // A device token is not a session on the admin HTML pages.
        let r = app
            .clone()
            .oneshot(authed("GET", "/admin/devices", &token))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(r.headers()["location"], "/login");
    }

    #[tokio::test]
    async fn ips_pages_with_a_cursor_bound_to_the_query() {
        let (state, cookie, app, _d) = app().await;
        let (token, _) = pair(&app, &cookie).await;
        for ip in ["203.0.113.1", "203.0.113.2", "2001:db8::1"] {
            seed_ip(&state, ip, "[]", 0).await;
        }
        let (st, v) = send(&app, authed("GET", "/api/v1/ips?limit=2", &token)).await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["items"].as_array().unwrap().len(), 2);
        let cursor = v["next_cursor"].as_str().expect("a third row follows");
        let (st, v) = send(
            &app,
            authed(
                "GET",
                &format!("/api/v1/ips?limit=2&cursor={cursor}"),
                &token,
            ),
        )
        .await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["items"].as_array().unwrap().len(), 1);
        assert!(v["next_cursor"].is_null());
        // The cursor answers only the query it was issued with.
        let (st, v) = send(
            &app,
            authed("GET", &format!("/api/v1/ips?q=203&cursor={cursor}"), &token),
        )
        .await;
        assert_eq!(st, 400);
        assert_eq!(v["error"]["code"], "invalid", "{v}");
        // Garbage cursors and limits are 400 too.
        let (st, _) = send(&app, authed("GET", "/api/v1/ips?cursor=%%%", &token)).await;
        assert_eq!(st, 400);
        let (st, _) = send(&app, authed("GET", "/api/v1/ips?limit=0", &token)).await;
        assert_eq!(st, 400);
        let (st, _) = send(&app, authed("GET", "/api/v1/ips?limit=many", &token)).await;
        assert_eq!(st, 400);
        // Past the maximum the page clamps to it.
        let (st, v) = send(&app, authed("GET", "/api/v1/ips?limit=1000", &token)).await;
        assert_eq!(st, 200);
        assert_eq!(v["items"].as_array().unwrap().len(), 3);
        // A query finds its network.
        let (st, v) = send(&app, authed("GET", "/api/v1/ips?q=203.0.113.0/24", &token)).await;
        assert_eq!(st, 200);
        assert_eq!(v["items"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn ip_detail_is_the_dataset_on_one_address() {
        let (state, cookie, app, _d) = app().await;
        let (token, _) = pair(&app, &cookie).await;
        seed_ip(&state, "203.0.113.9", r#"["sensitive-path"]"#, 3).await;
        let ip = state
            .store
            .ip_by_addr("203.0.113.9")
            .await
            .unwrap()
            .unwrap();
        state
            .store
            .set_ip_geo(ip.id, Some("DE"), Some(6805), Some("Telefonica Germany"))
            .await
            .unwrap();
        let (st, v) = send(&app, authed("GET", "/api/v1/ips/203.0.113.9", &token)).await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["ip"], "203.0.113.9");
        assert_eq!(v["geo"]["country"], "DE");
        assert_eq!(v["geo"]["asn"], 6805);
        assert_eq!(v["is_tor"], false);
        assert_eq!(v["severity"], 3);
        assert_eq!(v["request_count"], 1);
        assert_eq!(v["labels"], serde_json::json!(["sensitive-path"]));
        assert!(v["first_seen"].as_str().unwrap().ends_with('Z'), "{v}");
        assert!(v["intel"]["abuseipdb"].is_null(), "{v}");
        assert!(v["intel"]["shodan-internetdb"].is_null(), "{v}");
        assert!(v["intel"].get("tor-exits").is_none(), "tor is not an entry");
        assert_eq!(v["neighbours"]["net"], "203.0.113.0/24");
        assert!(v["rank"].as_i64().unwrap() >= 1);
        // Not an address: 400. Not in the dataset: 404.
        let (st, v) = send(&app, authed("GET", "/api/v1/ips/not-an-ip", &token)).await;
        assert_eq!(st, 400);
        assert_eq!(v["error"]["code"], "invalid", "{v}");
        let (st, v) = send(&app, authed("GET", "/api/v1/ips/203.0.113.77", &token)).await;
        assert_eq!(st, 404);
        assert_eq!(v["error"]["code"], "not_found", "{v}");
        // A v4-mapped v6 spelling is the same address.
        let (st, v) = send(
            &app,
            authed("GET", "/api/v1/ips/::ffff:203.0.113.9", &token),
        )
        .await;
        assert_eq!(st, 200, "{v}");
        // Unknown API paths are JSON too.
        let (st, v) = send(&app, authed("GET", "/api/v1/nope", &token)).await;
        assert_eq!(st, 404);
        assert_eq!(v["error"]["code"], "not_found", "{v}");
    }

    #[tokio::test]
    async fn lookup_takes_addresses_networks_and_reports_the_rest() {
        let (state, cookie, app, _d) = app().await;
        let (token, _) = pair(&app, &cookie).await;
        seed_ip(&state, "203.0.113.9", "[]", 0).await;
        let lookup = |ips: serde_json::Value| {
            let app = app.clone();
            let token = token.clone();
            async move {
                let mut r = post_json("/api/v1/lookup", serde_json::json!({"ips": ips}));
                r.headers_mut()
                    .insert("authorization", format!("Bearer {token}").parse().unwrap());
                send(&app, r).await
            }
        };
        let (st, v) = lookup(serde_json::json!([
            "203.0.113.9",
            "203.0.113.0/24",
            "2001:db8::1",
            "garbage!!"
        ]))
        .await;
        assert_eq!(st, 200, "{v}");
        let results = v["results"].as_array().unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r["ip"] == "203.0.113.9"), "{v}");
        assert_eq!(v["missing"], serde_json::json!(["2001:db8::1"]));
        assert_eq!(v["unreadable"], serde_json::json!(["garbage!!"]));
        assert_eq!(v["capped"], false);
        // An anonymous call is 401.
        let (st, _) = send(
            &app,
            post_json("/api/v1/lookup", serde_json::json!({"ips": []})),
        )
        .await;
        assert_eq!(st, 401);
    }

    #[tokio::test]
    async fn pairing_is_rate_limited_per_client() {
        let (_state, _cookie, app, _d) = app().await;
        let peer: std::net::SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let call = || {
            let mut r = post_json(
                "/api/v1/pair",
                serde_json::json!({"code": "c", "device_name": "d"}),
            );
            r.extensions_mut().insert(ConnectInfo(peer));
            r.headers_mut()
                .insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
            r
        };
        for _ in 0..crate::admin::limit::AUTH_BURST {
            let (st, _) = send(&app, call()).await;
            assert_eq!(st, 401, "unknown code, within budget");
        }
        let r = app.clone().oneshot(call()).await.unwrap();
        assert_eq!(r.status(), 429);
        assert!(r.headers().contains_key(axum::http::header::RETRY_AFTER));
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["error"]["code"], "rate_limited", "{v}");
    }

    /// A device paired straight through the store: its token.
    async fn device(state: &AdminState, scopes: &str, name: &str) -> String {
        let code = state
            .store
            .mint_pairing_code(scopes, "admin")
            .await
            .unwrap();
        let (_, token) = state
            .store
            .redeem_pairing_code(&code, name)
            .await
            .unwrap()
            .unwrap();
        token
    }

    fn authed_json(
        method: &str,
        path: &str,
        token: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// Scan jobs and audit entries: what a refused buy must leave as is.
    async fn jobs_and_actions(state: &AdminState) -> (i64, i64) {
        let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs")
            .fetch_one(&state.store.pool)
            .await
            .unwrap();
        let actions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_actions")
            .fetch_one(&state.store.pool)
            .await
            .unwrap();
        (jobs, actions)
    }

    const SCAN_IP: &str = crate::admin::scan_buy::tests::IP;

    #[tokio::test]
    async fn act_endpoints_need_the_act_scope() {
        let (state, _c, _id, _d) = crate::admin::scan_buy::tests::state().await;
        let app = crate::admin::full_router(state.clone());
        let read = device(&state, "read", "reader").await;
        let calls = [
            ("POST", format!("/api/v1/ips/{SCAN_IP}/probe")),
            ("GET", format!("/api/v1/ips/{SCAN_IP}/scan/quote?level=2")),
            ("POST", format!("/api/v1/ips/{SCAN_IP}/scan")),
            ("GET", "/api/v1/jobs/s_1".to_string()),
        ];
        for (method, path) in &calls {
            let (st, v) = send(
                &app,
                authed_json(method, path, &read, serde_json::json!({"quote_id": "q_x"})),
            )
            .await;
            assert_eq!(st, 403, "{method} {path}: {v}");
            assert_eq!(v["error"]["code"], "forbidden", "{v}");
            let (st, _) = send(
                &app,
                Request::builder()
                    .method(*method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(st, 401, "{method} {path} without a token");
        }
        assert_eq!(jobs_and_actions(&state).await, (0, 0));
    }

    #[tokio::test]
    async fn a_quoted_scan_is_bought_once_audited_and_polled() {
        let (state, cookie, ip_id, _d) = crate::admin::scan_buy::tests::state().await;
        let app = crate::admin::full_router(state.clone());
        let token = device(&state, "read,act", "Pixel 8").await;
        let (st, q) = send(
            &app,
            authed(
                "GET",
                &format!("/api/v1/ips/{SCAN_IP}/scan/quote?level=3"),
                &token,
            ),
        )
        .await;
        assert_eq!(st, 200, "{q}");
        assert!(q["quote_id"].as_str().unwrap().starts_with("q_"));
        // Standalone: free.
        assert_eq!(q["credits"], "0.00");
        assert_eq!(q["credits_mc"], 0);
        assert_eq!(q["credits_max_mc"], 0);
        assert_eq!(q["offer"]["level"], 3);
        assert!(q["expires_at"].as_str().unwrap().ends_with('Z'), "{q}");
        let buy = |quote: serde_json::Value| {
            authed_json(
                "POST",
                &format!("/api/v1/ips/{SCAN_IP}/scan"),
                &token,
                serde_json::json!({"quote_id": quote}),
            )
        };
        let (st, v) = send(&app, buy(q["quote_id"].clone())).await;
        assert_eq!(st, 202, "{v}");
        let job_id = v["job_id"].as_str().unwrap().to_string();
        assert!(job_id.starts_with("s_"));
        assert_eq!(v["credits_mc"], 0);
        let jobs: Vec<(i64, i64)> =
            sqlx::query_as("SELECT level, manual FROM scan_jobs WHERE ip_id = ?")
                .bind(ip_id)
                .fetch_all(&state.store.pool)
                .await
                .unwrap();
        assert_eq!(jobs, vec![(3, 1)], "the marked job of the quoted level");
        // The same quote again: spent.
        let (st, v) = send(&app, buy(q["quote_id"].clone())).await;
        assert_eq!(st, 409);
        assert_eq!(v["error"]["code"], "quote_invalid", "{v}");
        assert_eq!(jobs_and_actions(&state).await, (1, 1));
        // A new quote while the job is on its way: none.
        let (st, v) = send(
            &app,
            authed(
                "GET",
                &format!("/api/v1/ips/{SCAN_IP}/scan/quote?level=3"),
                &token,
            ),
        )
        .await;
        assert_eq!(st, 409);
        assert_eq!(v["error"]["code"], "on_its_way", "{v}");
        // Polling: queued, no result yet.
        let (st, v) = send(
            &app,
            authed("GET", &format!("/api/v1/jobs/{job_id}"), &token),
        )
        .await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["kind"], "scan");
        assert_eq!(v["ip"], SCAN_IP);
        assert_eq!(v["status"], "queued");
        assert!(v["result"].is_null());
        // The scan lands: done, with its open ports.
        sqlx::query(
            "UPDATE scan_jobs SET status = 'done', finished_at = datetime('now') WHERE ip_id = ?",
        )
        .bind(ip_id)
        .execute(&state.store.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO scans (job_id, ip_id, level, started_at, finished_at, uid, origin, job_uid)
             SELECT id, ip_id, level, datetime('now'), datetime('now'), 's1', NULL, uid
             FROM scan_jobs WHERE ip_id = ?",
        )
        .bind(ip_id)
        .execute(&state.store.pool)
        .await
        .unwrap();
        let (st, v) = send(
            &app,
            authed("GET", &format!("/api/v1/jobs/{job_id}"), &token),
        )
        .await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["status"], "done");
        assert!(
            v["result"]["scanned_at"].as_str().unwrap().ends_with('Z'),
            "{v}"
        );
        assert!(v["result"]["ports"].is_array());
        // Another device does not see it; an unknown id is 404 alike.
        let other = device(&state, "read,act", "other").await;
        for (t, id) in [(&other, job_id.as_str()), (&token, "s_999")] {
            let (st, v) = send(&app, authed("GET", &format!("/api/v1/jobs/{id}"), t)).await;
            assert_eq!(st, 404);
            assert_eq!(v["error"]["code"], "not_found", "{v}");
        }
        // The audit entry, on the admin Devices page too.
        let a = state.store.recent_device_actions(10).await.unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(
            (a[0].device_name.as_str(), a[0].paired_by.as_str()),
            ("Pixel 8", "admin")
        );
        assert_eq!(
            (a[0].action.as_str(), a[0].target.as_str()),
            ("scan", SCAN_IP)
        );
        assert_eq!(
            (a[0].credits_mc, a[0].job_id.as_str()),
            (0, job_id.as_str())
        );
        let r = app
            .clone()
            .oneshot(
                Request::get("/admin/devices")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8_lossy(&html);
        assert!(
            html.contains("Recent actions") && html.contains(&job_id) && html.contains("Pixel 8"),
            "{html}"
        );
    }

    #[tokio::test]
    async fn two_purchases_at_once_queue_one_scan() {
        let (state, _cookie, ip_id, _d) = crate::admin::scan_buy::tests::state().await;
        let app = crate::admin::full_router(state.clone());
        let token = device(&state, "read,act", "Pixel 8").await;
        let quote = || {
            send(
                &app,
                authed(
                    "GET",
                    &format!("/api/v1/ips/{SCAN_IP}/scan/quote?level=2"),
                    &token,
                ),
            )
        };
        // Both quoted before either is spent: both pass `sale`.
        let ((s1, q1), (s2, q2)) = (quote().await, quote().await);
        assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK), "{q1} {q2}");
        let buy = |q: &serde_json::Value| {
            send(
                &app,
                authed_json(
                    "POST",
                    &format!("/api/v1/ips/{SCAN_IP}/scan"),
                    &token,
                    serde_json::json!({"quote_id": q["quote_id"]}),
                ),
            )
        };
        let ((s1, v1), (s2, v2)) = tokio::join!(buy(&q1), buy(&q2));
        let mut codes = [s1.as_u16(), s2.as_u16()];
        codes.sort();
        assert_eq!(codes, [202, 409], "{v1} {v2}");
        let refused = if s1 == StatusCode::CONFLICT { v1 } else { v2 };
        assert_eq!(refused["error"]["code"], "on_its_way", "{refused}");
        let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs WHERE ip_id = ?")
            .bind(ip_id)
            .fetch_one(&state.store.pool)
            .await
            .unwrap();
        assert_eq!(jobs, 1);
        assert_eq!(jobs_and_actions(&state).await, (1, 1));
    }

    #[tokio::test]
    async fn a_scan_without_its_audit_entry_is_withdrawn() {
        let (state, _cookie, ip_id, _d) = crate::admin::scan_buy::tests::state().await;
        let app = crate::admin::full_router(state.clone());
        let token = device(&state, "read,act", "Pixel 8").await;
        let (st, q) = send(
            &app,
            authed(
                "GET",
                &format!("/api/v1/ips/{SCAN_IP}/scan/quote?level=3"),
                &token,
            ),
        )
        .await;
        assert_eq!(st, 200, "{q}");
        sqlx::query(
            "CREATE TRIGGER no_audit BEFORE INSERT ON device_actions
             BEGIN SELECT RAISE(ABORT, 'audit down'); END",
        )
        .execute(&state.store.pool)
        .await
        .unwrap();
        let (st, v) = send(
            &app,
            authed_json(
                "POST",
                &format!("/api/v1/ips/{SCAN_IP}/scan"),
                &token,
                serde_json::json!({"quote_id": q["quote_id"]}),
            ),
        )
        .await;
        assert_eq!(st, 500, "{v}");
        let jobs: Vec<(String, Option<String>)> =
            sqlx::query_as("SELECT status, error FROM scan_jobs WHERE ip_id = ?")
                .bind(ip_id)
                .fetch_all(&state.store.pool)
                .await
                .unwrap();
        assert_eq!(
            jobs,
            vec![("refused".into(), Some("dropped: audit write failed".into()))],
            "nothing left queued"
        );
        // Withdrawn, it is not on its way: a new quote sells.
        sqlx::query("DROP TRIGGER no_audit")
            .execute(&state.store.pool)
            .await
            .unwrap();
        let (st, q) = send(
            &app,
            authed(
                "GET",
                &format!("/api/v1/ips/{SCAN_IP}/scan/quote?level=3"),
                &token,
            ),
        )
        .await;
        assert_eq!(st, 200, "{q}");
    }

    #[tokio::test]
    async fn a_bad_quote_queues_and_charges_nothing() {
        let (state, _c, _ip_id, _d) = crate::admin::scan_buy::tests::state().await;
        let other_ip = "203.0.113.41";
        state
            .store
            .upsert_ip(other_ip.parse().unwrap())
            .await
            .unwrap();
        let app = crate::admin::full_router(state.clone());
        let token = device(&state, "read,act", "phone").await;
        let other = device(&state, "read,act", "other").await;
        let quote = |t: &str, ip: &str| {
            let app = app.clone();
            let t = t.to_string();
            let ip = ip.to_string();
            async move {
                let (st, v) = send(
                    &app,
                    authed("GET", &format!("/api/v1/ips/{ip}/scan/quote?level=2"), &t),
                )
                .await;
                assert_eq!(st, 200, "{v}");
                v["quote_id"].as_str().unwrap().to_string()
            }
        };
        let buy = |t: &str, ip: &str, q: &str| {
            authed_json(
                "POST",
                &format!("/api/v1/ips/{ip}/scan"),
                t,
                serde_json::json!({"quote_id": q}),
            )
        };
        let refused = |req: Request<Body>, code: &'static str| {
            let app = app.clone();
            let state = state.clone();
            async move {
                let (st, v) = send(&app, req).await;
                assert_eq!(st, 409, "{v}");
                assert_eq!(v["error"]["code"], code, "{v}");
                // Nothing queued, so nothing charged (a scan is paid when a
                // scanner runs its job), and nothing audited.
                assert_eq!(jobs_and_actions(&state).await, (0, 0), "{code}");
            }
        };
        // Unknown.
        refused(buy(&token, SCAN_IP, "q_nope"), "quote_invalid").await;
        // Another device's.
        let q = quote(&other, SCAN_IP).await;
        refused(buy(&token, SCAN_IP, &q), "quote_invalid").await;
        // Expired.
        let q = quote(&token, SCAN_IP).await;
        sqlx::query("UPDATE scan_quotes SET expires_at = datetime('now', '-1 second')")
            .execute(&state.store.pool)
            .await
            .unwrap();
        refused(buy(&token, SCAN_IP, &q), "quote_invalid").await;
        // For another address.
        let q = quote(&token, other_ip).await;
        refused(buy(&token, SCAN_IP, &q), "quote_mismatch").await;
        // The price moved since the quote (here: the stored quote differs).
        let q = quote(&token, SCAN_IP).await;
        sqlx::query("UPDATE scan_quotes SET credits_mc = 1000 WHERE id = ?")
            .bind(&q)
            .execute(&state.store.pool)
            .await
            .unwrap();
        refused(buy(&token, SCAN_IP, &q), "price_changed").await;
        // A fresh result landed between quote and buy.
        let q = quote(&token, SCAN_IP).await;
        crate::scan::probe::gate::tests::scanned(
            &state.store,
            SCAN_IP,
            &[(80, "open", Some("http"))],
        )
        .await;
        let jobs_before = jobs_and_actions(&state).await;
        let (st, v) = send(&app, buy(&token, SCAN_IP, &q)).await;
        assert_eq!(st, 409, "{v}");
        assert_eq!(v["error"]["code"], "fresh", "{v}");
        assert!(v["error"]["scan_id"].as_i64().is_some(), "{v}");
        assert_eq!(jobs_and_actions(&state).await, jobs_before);
        // A bad level is 400, not a quote.
        let (st, v) = send(
            &app,
            authed(
                "GET",
                &format!("/api/v1/ips/{SCAN_IP}/scan/quote?level=9"),
                &token,
            ),
        )
        .await;
        assert_eq!(st, 400);
        assert_eq!(v["error"]["code"], "invalid", "{v}");
    }

    #[tokio::test]
    async fn a_probe_runs_is_audited_and_polled() {
        use crate::admin::probes::tests::{IP, state, web};
        let server = web().await;
        let (state, _c, _id, _d) = state(Some(server.port()), "").await;
        let app = crate::admin::full_router(state.clone());
        let token = device(&state, "read,act", "phone").await;
        let (st, v) = send(
            &app,
            authed("POST", &format!("/api/v1/ips/{IP}/probe"), &token),
        )
        .await;
        assert_eq!(st, 202, "{v}");
        let job_id = v["job_id"].as_str().unwrap().to_string();
        assert!(job_id.starts_with("p_"));
        assert_eq!(v["credits_mc"], 0, "standalone: free");
        assert_eq!(v["vantages"], serde_json::json!([]));
        let mut seen = serde_json::Value::Null;
        for _ in 0..100 {
            let (st, v) = send(
                &app,
                authed("GET", &format!("/api/v1/jobs/{job_id}"), &token),
            )
            .await;
            assert_eq!(st, 200, "{v}");
            assert_eq!(v["kind"], "probe");
            seen = v;
            if seen["status"] == "done" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(seen["status"], "done", "{seen}");
        let vantage = &seen["result"]["vantages"][0];
        assert_eq!(vantage["state"], "done", "{seen}");
        assert!(!vantage["ports"].as_array().unwrap().is_empty(), "{seen}");
        let a = state.store.recent_device_actions(10).await.unwrap();
        assert_eq!((a.len(), a[0].action.as_str()), (1, "probe"));
        // Not in the dataset: 404; refused by the gate: 422, nothing logged.
        let (st, _) = send(
            &app,
            authed("POST", "/api/v1/ips/198.51.100.200/probe", &token),
        )
        .await;
        assert_eq!(st, 404);
        state
            .store
            .upsert_ip("10.0.0.1".parse().unwrap())
            .await
            .unwrap();
        let (st, v) = send(&app, authed("POST", "/api/v1/ips/10.0.0.1/probe", &token)).await;
        assert_eq!(st, 422, "{v}");
        assert_eq!(v["error"]["code"], "refused", "{v}");
        assert_eq!(
            state.store.recent_device_actions(10).await.unwrap().len(),
            1
        );
    }
}
