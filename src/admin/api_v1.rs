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
        .route("/api/v1/ips/{addr}/probe/vantages", get(probe_vantages))
        .route("/api/v1/ips/{addr}/scan/prices", get(scan_prices))
        .route("/api/v1/ips/{addr}/scan/quote", get(scan_quote))
        .route("/api/v1/ips/{addr}/scan", post(scan_buy))
        .route("/api/v1/ips/{addr}/lookup/quote", get(lookup_quote))
        .route("/api/v1/ips/{addr}/lookup", post(lookup_buy))
        .route("/api/v1/jobs/{job_id}", get(job))
        .route("/api/v1/uploads", get(uploads))
        .route("/api/v1/uploads/{sha256}", get(upload_by_hash))
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
        "unseen": s.unseen,
    })
}

/// One upload's metadata (MIK-121). Never its content: there is no field
/// for it, and [`crate::store::uploads::UploadMeta`] holds none.
fn upload_json(u: &crate::store::uploads::UploadMeta) -> Value {
    let hex = |b: &[u8]| data_encoding::HEXLOWER.encode(b);
    json!({
        "uid": u.uid,
        "request_uid": u.request_uid,
        "node_id": u.node_id.as_deref().map(hex),
        "ts": rfc3339(&u.ts),
        "ip": u.ip,
        "kind": u.kind,
        "filename": u.filename,
        "sniffed_type": u.sniffed_type,
        "size": u.size,
        "truncated": u.truncated,
        "sha256": hex(&u.sha256),
        "answered_path": u.answered_path,
        "path_is_prefix": u.path_is_prefix,
        "content_state": u.content_state,
    })
}

#[derive(serde::Deserialize)]
pub struct UploadsQuery {
    cursor: Option<String>,
    limit: Option<String>,
}

/// The uploads' continuation token: the id the next page starts below.
#[derive(serde::Serialize, serde::Deserialize)]
struct UploadsCursor {
    before: i64,
}

async fn uploads(
    DeviceAuth(_): DeviceAuth,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<UploadsQuery>,
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
    let before = match q.cursor.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(c) => match data_encoding::BASE64URL_NOPAD
            .decode(c.as_bytes())
            .ok()
            .and_then(|b| serde_json::from_slice::<UploadsCursor>(&b).ok())
        {
            Some(c) => Some(c.before),
            None => return err(StatusCode::BAD_REQUEST, "invalid", "unreadable cursor"),
        },
    };
    let query = crate::store::uploads::UploadQuery {
        before,
        ..Default::default()
    };
    let mut rows = match state.store.uploads_meta(&query, limit + 1).await {
        Ok(r) => r,
        Err(e) => return internal(e),
    };
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = rows.last().filter(|_| more).map(|last| {
        data_encoding::BASE64URL_NOPAD
            .encode(&serde_json::to_vec(&UploadsCursor { before: last.id }).unwrap_or_default())
    });
    Json(json!({
        "items": rows.iter().map(upload_json).collect::<Vec<_>>(),
        "next_cursor": next_cursor,
    }))
    .into_response()
}

/// Every upload of one file, newest first (at most [`MAX_LIMIT`]).
async fn upload_by_hash(
    DeviceAuth(_): DeviceAuth,
    State(state): State<Arc<AdminState>>,
    Path(sha256): Path<String>,
) -> Response {
    let hash = match data_encoding::HEXLOWER_PERMISSIVE.decode(sha256.trim().as_bytes()) {
        Ok(h) if h.len() == 32 => h,
        _ => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid",
                "not a SHA-256 (64 hex digits)",
            );
        }
    };
    let query = crate::store::uploads::UploadQuery {
        sha256: Some(&hash),
        ..Default::default()
    };
    match state.store.uploads_meta(&query, MAX_LIMIT).await {
        Ok(rows) if rows.is_empty() => err(StatusCode::NOT_FOUND, "not_found", "no such upload"),
        Ok(rows) => Json(json!({
            "sha256": data_encoding::HEXLOWER.encode(&hash),
            "uploads": rows.iter().map(upload_json).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => internal(e),
    }
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
            "unseen": ip.unseen,
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
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    names: Vec<String>,
}

/// Host names (or URLs) of one `/api/v1/lookup` resolved at once. Each costs
/// DNS round-trips, on several nodes in a cluster, so a long list is worked
/// through a few at a time; its length is bounded only by the body limit and
/// the per-client rate limit of `/api/*`.
pub const NAMES_PARALLEL: usize = 4;

/// Stored-data lookup for many addresses at once: the semantics and the cap
/// of the admin bulk lookup, but JSON. No provider is asked. `names` are
/// resolved as on the admin lookup page, then their agreed addresses read
/// the same way.
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
    let names = match names_json(&state, &b.names, async |n: &str| {
        crate::intel::dns::resolve_here(n).await
    })
    .await
    {
        Ok(n) => n,
        Err(e) => return internal(e),
    };
    Json(json!({
        "results": read.rows.iter().map(summary_json).collect::<Vec<_>>(),
        "missing": read.missing,
        "unreadable": read.unreadable,
        "capped": read.capped,
        "names": names,
    }))
    .into_response()
}

/// One entry per name, in order: its host, how it resolved (`resolve`),
/// and the stored data on its agreed addresses — or a per-entry `error`.
/// `resolve` stands in for this node's resolver. The input is not echoed:
/// a URL may carry credentials.
async fn names_json(
    state: &AdminState,
    names: &[String],
    resolve: impl AsyncFn(&str) -> Result<Vec<IpAddr>, String> + Copy,
) -> anyhow::Result<Vec<Value>> {
    use futures::{StreamExt, TryStreamExt};
    // Built up front: a closure held across the await trips the `Send`
    // check of the handler (higher-ranked lifetimes).
    let entries: Vec<_> = names.iter().map(|n| name_json(state, n, resolve)).collect();
    futures::stream::iter(entries)
        .buffered(NAMES_PARALLEL)
        .try_collect()
        .await
}

fn entry_err(code: &str, message: &str) -> Value {
    json!({"error": {"code": code, "message": message}})
}

/// The stored summaries of `addrs`, and those not in the dataset.
async fn read_addrs(
    state: &AdminState,
    addrs: &[IpAddr],
) -> anyhow::Result<(Vec<Value>, Vec<String>)> {
    let addrs: Vec<String> = addrs.iter().map(IpAddr::to_string).collect();
    let r = crate::admin::lookup::bulk_read(state, addrs.iter().map(String::as_str)).await?;
    Ok((r.rows.iter().map(summary_json).collect(), r.missing))
}

async fn name_json(
    state: &AdminState,
    input: &str,
    resolve: impl AsyncFn(&str) -> Result<Vec<IpAddr>, String>,
) -> anyhow::Result<Value> {
    use crate::intel::dns::{Host, host_of};
    let name = match host_of(input) {
        None => return Ok(entry_err("invalid", "not an IP address, host name or URL")),
        Some(Host::Ip(ip)) => {
            let (results, missing) = read_addrs(state, &[ip]).await?;
            return Ok(json!({"host": ip.to_string(), "results": results, "missing": missing}));
        }
        Some(Host::Name(name)) => name,
    };
    let (view, followed) = match crate::admin::lookup::resolve_name(state, &name, resolve).await {
        Ok(x) => x,
        Err(e) => {
            let mut v = entry_err("unresolved", &e);
            v["host"] = json!(name);
            return Ok(v);
        }
    };
    let mut v = json!({
        "host": name,
        "resolve": {
            "note": view.note,
            "votes": view.rows.iter().map(|r| json!({
                "ip": r.ip, "agreed": r.agreed, "verdict": r.verdict,
            })).collect::<Vec<_>>(),
            "resolvers": view.resolvers,
            "errors": view.errors.iter().map(|(node, why)| json!({
                "node": node, "why": why,
            })).collect::<Vec<_>>(),
            "also": view.also,
        },
    });
    if followed.is_empty() {
        v["error"] = json!({
            "code": "unresolved",
            "message": view.note.as_deref().unwrap_or("no agreed address"),
        });
    } else {
        let (results, missing) = read_addrs(state, &followed).await?;
        v["results"] = json!(results);
        v["missing"] = json!(missing);
    }
    Ok(v)
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

/// A path address for a scan and its dataset row id, None when the
/// dataset does not hold it and a buy makes the row, unseen (MIK-329):
/// 400 when it is not an address, 422 `refused` when an unrecorded
/// address must not be scanned (`scan_buy::scan_target`).
async fn scan_row(state: &AdminState, addr: &str) -> Result<(IpAddr, Option<i64>), Box<Response>> {
    let Ok(ip) = addr.trim().parse::<IpAddr>() else {
        return Err(Box::new(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "not an IP address",
        )));
    };
    let ip = crate::net::canonical(ip);
    match crate::admin::scan_buy::scan_target(state, ip).await {
        Ok(Ok(row)) => Ok((ip, row)),
        Ok(Err(why)) => Err(Box::new(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused",
            &why,
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

/// GET /api/v1/ips/{addr}/probe/vantages: what the Actions card offers
/// (`probes::actions_for`), so the app can show the total before a probe.
/// Spends nothing.
async fn probe_vantages(
    ActAuth(_device): ActAuth,
    State(state): State<Arc<AdminState>>,
    Path(addr): Path<String>,
) -> Response {
    let (ip, _) = match row_of(&state, &addr).await {
        Ok(r) => r,
        Err(r) => return *r,
    };
    let a = crate::admin::probes::actions_for(&state, &ip).await;
    // `probes::start` refuses these; the card does not check the prober.
    let why_not = a.why_not.clone().or_else(|| {
        (a.standalone && state.prober.is_none()).then(|| "this node does not probe".to_string())
    });
    if let Some(why) = why_not {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "refused", why);
    }
    Json(json!({ "vantages": vantages_json(&a) })).into_response()
}

/// The card's vantages with their prices and default pick; standalone,
/// the node itself, free.
fn vantages_json(a: &crate::admin::probes::ActionsView) -> Vec<Value> {
    if a.standalone {
        let (credits, credits_mc) = credits(0);
        return vec![json!({
            "id": crate::scan::probe::gate::LOCAL.to_string(),
            "name": "this node",
            "country": null,
            "credits": credits,
            "credits_mc": credits_mc,
            "default": true,
        })];
    }
    a.vantages
        .iter()
        .map(|v| {
            let (credits, credits_mc) = credits(v.price_mc as u64);
            json!({
                "id": v.id,
                "name": v.name,
                "country": v.country,
                "credits": credits,
                "credits_mc": credits_mc,
                "default": a.ticked(&v.id),
            })
        })
        .collect()
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

/// GET /api/v1/ips/{addr}/scan/prices: every level's price range, the
/// Actions card's level buttons, so the app's level picker shows them
/// before a quote. Spends nothing.
async fn scan_prices(
    ActAuth(_device): ActAuth,
    State(state): State<Arc<AdminState>>,
    Path(addr): Path<String>,
) -> Response {
    if let Err(r) = scan_row(&state, &addr).await {
        return *r;
    }
    let table = state.recorder.node().map(|n| n.price_table());
    let levels: Vec<Value> = (1u8..=5)
        .filter_map(|level| {
            let p = match &table {
                None => crate::admin::scan_buy::Price {
                    floor_mc: 0,
                    max_mc: 0,
                },
                Some(t) => crate::admin::scan_buy::price_range(&t.scanners, level)?,
            };
            let (floor, floor_mc) = credits(p.floor_mc);
            let (max, max_mc) = credits(p.max_mc);
            Some(json!({
                "level": level,
                "about": crate::admin::scan_buy::about(level),
                "credits": floor,
                "credits_mc": floor_mc,
                "credits_max": max,
                "credits_max_mc": max_mc,
            }))
        })
        .collect();
    Json(json!({ "levels": levels })).into_response()
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
    let (ip, ip_id) = match scan_row(&state, &addr).await {
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
    let (addr, ip_id) = match scan_row(&state, &ip).await {
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
    let id = match crate::admin::scan_buy::enqueue(&state, addr, level).await {
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

/// One provider a fresh lookup asks, by whom and at what price.
#[derive(Debug, Clone, PartialEq)]
struct Priced {
    provider: String,
    node: String,
    mc: u64,
    /// This node serves it itself: asked by every lookup, free.
    own: bool,
}

/// Every provider a fresh lookup could ask now, in the order of
/// [`crate::intel::KNOWN_PROVIDERS`]: as the web lookup page offers them
/// (this node's own quote, else the cheapest). Standalone: this node's
/// ready providers, free.
fn offered(state: &AdminState) -> Vec<Priced> {
    let Some(node) = state.recorder.node() else {
        return crate::intel::KNOWN_PROVIDERS
            .iter()
            .filter(|i| {
                state
                    .providers
                    .iter()
                    .any(|p| p.ready() && p.name() == i.name)
            })
            .map(|i| Priced {
                provider: i.name.to_string(),
                node: "this node".into(),
                mc: 0,
                own: true,
            })
            .collect();
    };
    priced(
        node.id(),
        &crate::credits::pay::quotes(node, &state.providers),
    )
}

/// [`offered`] from the cluster's quotes (`me` is this node).
fn priced(
    me: crate::cluster::identity::NodeId,
    all: &std::collections::HashMap<String, Vec<crate::credits::pay::Quote>>,
) -> Vec<Priced> {
    let cheap = crate::intel::lookup::cheap(me, all);
    crate::intel::KNOWN_PROVIDERS
        .iter()
        .filter_map(|info| {
            let q = all
                .get(info.name)
                .and_then(|l| l.iter().find(|q| q.server == me).or(l.first()))?;
            // A free good is no market: only this node's own answer counts.
            if crate::credits::price::is_free(info.name) && q.server != me {
                return None;
            }
            Some(Priced {
                provider: info.name.to_string(),
                node: q.server_name.clone(),
                mc: q.price_mc as u64,
                own: cheap.iter().any(|c| c == info.name),
            })
        })
        .collect()
}

/// Why a provider set cannot be quoted.
#[derive(Debug, PartialEq)]
enum Unpicked {
    /// No such provider.
    Unknown(String),
    /// Known, but nobody offers it now.
    NotOffered(String),
}

/// The lines of a fresh lookup of `chosen` (empty: every provider
/// offered): this node's own providers always, the others when chosen.
fn pick(offered: &[Priced], chosen: &[String]) -> Result<Vec<Priced>, Unpicked> {
    for name in chosen {
        if crate::intel::provider_info(name).is_none() {
            return Err(Unpicked::Unknown(name.clone()));
        }
        if !offered.iter().any(|p| &p.provider == name) {
            return Err(Unpicked::NotOffered(name.clone()));
        }
    }
    Ok(offered
        .iter()
        .filter(|p| p.own || chosen.is_empty() || chosen.contains(&p.provider))
        .cloned()
        .collect())
}

/// A lookup quote lives in `scan_quotes` with a negative level: -1 minus
/// the bit set of the bought (not own) providers, by their index in
/// [`crate::intel::KNOWN_PROVIDERS`]. A scan level is 1-5, so neither kind
/// of quote is spent as the other.
fn lookup_level(lines: &[Priced]) -> i64 {
    let mask = crate::intel::KNOWN_PROVIDERS
        .iter()
        .enumerate()
        .filter(|(_, i)| lines.iter().any(|p| !p.own && p.provider == i.name))
        .fold(0i64, |m, (n, _)| m | (1 << n));
    -1 - mask
}

/// The bought providers of a lookup quote's level; None: not a lookup quote.
fn lookup_bought(level: i64) -> Option<Vec<String>> {
    let mask = (-1i64).checked_sub(level).filter(|m| *m >= 0)?;
    Some(
        crate::intel::KNOWN_PROVIDERS
            .iter()
            .enumerate()
            .filter(|(n, _)| mask & (1 << n) != 0)
            .map(|(_, i)| i.name.to_string())
            .collect(),
    )
}

fn lines_json(lines: &[Priced]) -> Vec<Value> {
    lines
        .iter()
        .map(|p| {
            let (c, mc) = credits(p.mc);
            json!({
                "provider": p.provider,
                "label": crate::intel::provider_info(&p.provider).map(|i| i.label).unwrap_or_default(),
                "node": p.node,
                "credits": c,
                "credits_mc": mc,
                "own": p.own,
            })
        })
        .collect()
}

#[derive(serde::Deserialize)]
pub struct LookupQuoteQuery {
    providers: Option<String>,
}

/// GET /api/v1/ips/{addr}/lookup/quote?providers=a,b: what a fresh
/// provider lookup costs now, as a quote the device can spend once within
/// `QUOTE_SECS`. The address need not be in the dataset.
async fn lookup_quote(
    ActAuth(device): ActAuth,
    State(state): State<Arc<AdminState>>,
    Path(addr): Path<String>,
    Query(q): Query<LookupQuoteQuery>,
) -> Response {
    let Ok(ip) = addr.trim().parse::<IpAddr>() else {
        return err(StatusCode::BAD_REQUEST, "invalid", "not an IP address");
    };
    let ip = crate::net::canonical(ip).to_string();
    let chosen: Vec<String> = q
        .providers
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect();
    let lines = match pick(&offered(&state), &chosen) {
        Ok(l) if !l.is_empty() => l,
        Ok(_) => {
            return err(
                StatusCode::CONFLICT,
                "no_provider",
                "no provider can be asked now",
            );
        }
        Err(Unpicked::Unknown(p)) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid",
                format!("no provider {p}"),
            );
        }
        Err(Unpicked::NotOffered(p)) => {
            return err(
                StatusCode::CONFLICT,
                "not_offered",
                format!("nobody offers {p} now"),
            );
        }
    };
    let total: u64 = lines.iter().map(|p| p.mc).sum();
    let quote = match state
        .store
        .create_quote_at(&device.id, &ip, lookup_level(&lines), total)
        .await
    {
        Ok(q) => q,
        Err(e) => return internal(e),
    };
    let (c, mc) = credits(total);
    Json(json!({
        "quote_id": quote.id,
        "credits": c,
        "credits_mc": mc,
        "expires_at": rfc3339(quote.expires_at.as_str()),
        "providers": lines_json(&lines),
    }))
    .into_response()
}

/// POST /api/v1/ips/{addr}/lookup {quote_id}: ask the quoted providers
/// now. The quote is spent first; every refusal after that asks and
/// charges nothing. The audit entry (with the quoted credits, the most the
/// lookup may charge) is written before any provider is asked.
async fn lookup_buy(
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
    let ip = crate::net::canonical(ip);
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
    let Some(bought) = lookup_bought(quote.level) else {
        return err(
            StatusCode::CONFLICT,
            "quote_invalid",
            "the quote is for a scan",
        );
    };
    if quote.addr != ip.to_string() {
        return err(
            StatusCode::CONFLICT,
            "quote_mismatch",
            "the quote is for another address",
        );
    }
    // Asked as quoted, or not at all: a provider gone or a price moved.
    let now = match pick(&offered(&state), &bought) {
        Ok(l) if lookup_level(&l) == quote.level => l,
        _ => return price_changed(),
    };
    if now.iter().map(|p| p.mc).sum::<u64>() != quote.credits_mc as u64 {
        return price_changed();
    }
    let quoted = quote.credits_mc as u64;
    if let Err(r) = audit(
        &state,
        &device,
        "lookup",
        &ip.to_string(),
        quoted,
        &quote.id,
    )
    .await
    {
        return *r;
    }
    let out = crate::intel::lookup::run(&state.recorder, &state.providers, ip, &bought, &[]).await;
    let now_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut intel = serde_json::Map::new();
    let (mut declined, mut charges, mut charged) = (vec![], vec![], 0u64);
    for a in &out.answers {
        for f in &a.resp.findings {
            if f.provider == crate::intel::TOR {
                continue;
            }
            intel.insert(
                f.provider.clone(),
                json!({"source": "fresh", "node": a.node, "fetched_at": now_at, "data": f.data}),
            );
        }
        for (p, why) in &a.resp.declined {
            declined.push(json!({"provider": p, "node": a.node, "why": why}));
        }
        if a.charged_mc > 0 {
            let (c, mc) = credits(a.charged_mc as u64);
            charged += mc;
            charges.push(json!({"node": a.node, "credits": c, "credits_mc": mc}));
        }
    }
    for s in out
        .stored
        .iter()
        .filter(|s| s.provider != crate::intel::TOR)
    {
        intel.entry(s.provider.clone()).or_insert_with(|| {
            json!({
                "source": "stored",
                "node": s.node,
                "fetched_at": rfc3339(s.fetched_at.as_str()),
                "data": s.data,
            })
        });
    }
    let (c, mc) = credits(charged);
    Json(json!({
        "ip": ip.to_string(),
        "credits": c,
        "credits_mc": mc,
        "charges": charges,
        "intel": Value::Object(intel),
        "declined": declined,
        "kept": out.kept,
    }))
    .into_response()
}

fn price_changed() -> Response {
    err(
        StatusCode::CONFLICT,
        "price_changed",
        "the price moved since the quote: get a new one",
    )
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
        // A lookup answers at once: its entry is the receipt.
        "lookup" => Ok(("done", Value::Null)),
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
                    .header("sec-fetch-site", "same-origin")
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
                    .header("sec-fetch-site", "same-origin")
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
    async fn uploads_are_metadata_only_paged_and_found_by_hash() {
        let (state, cookie, app, _d) = app().await;
        let (token, _) = pair(&app, &cookie).await;
        let marker = b"<?php echo 'MARK-api-5e2d'; ?>";
        crate::store::uploads::seed_upload(&state.store, "203.0.113.60", "/a.php", marker).await;
        crate::store::uploads::seed_upload(&state.store, "198.51.100.61", "/b.php", b"two").await;
        let (st, v) = send(&app, authed("GET", "/api/v1/uploads?limit=1", &token)).await;
        assert_eq!(st, 200, "{v}");
        let items = v["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["answered_path"], "/b.php", "newest first");
        let keys: Vec<&str> = items[0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert!(
            keys.iter()
                .all(|k| !k.contains("content") || *k == "content_state"),
            "{keys:?}"
        );
        assert!(
            !keys.contains(&"body") && !keys.contains(&"bytes"),
            "{keys:?}"
        );
        let cursor = v["next_cursor"].as_str().unwrap().to_string();
        let (st, v) = send(
            &app,
            authed(
                "GET",
                &format!("/api/v1/uploads?limit=1&cursor={cursor}"),
                &token,
            ),
        )
        .await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["items"][0]["answered_path"], "/a.php");
        assert_eq!(v["items"][0]["ip"], "203.0.113.60");
        assert_eq!(v["items"][0]["content_state"], "held");
        assert!(v["next_cursor"].is_null(), "{v}");
        assert!(!v.to_string().contains("MARK-api-5e2d"), "{v}");
        // By hash.
        use sha2::Digest;
        let sha = data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(marker));
        let (st, v) = send(
            &app,
            authed("GET", &format!("/api/v1/uploads/{sha}"), &token),
        )
        .await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["sha256"], sha.as_str());
        assert_eq!(v["uploads"].as_array().unwrap().len(), 1);
        assert_eq!(v["uploads"][0]["sha256"], sha.as_str());
        assert!(!v.to_string().contains("MARK-api-5e2d"), "{v}");
        let (st, v) = send(&app, authed("GET", "/api/v1/uploads/abc", &token)).await;
        assert_eq!(
            (st, v["error"]["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid"))
        );
        let none = "0".repeat(64);
        let (st, v) = send(
            &app,
            authed("GET", &format!("/api/v1/uploads/{none}"), &token),
        )
        .await;
        assert_eq!(
            (st, v["error"]["code"].as_str()),
            (StatusCode::NOT_FOUND, Some("not_found"))
        );
        let (st, _) = send(&app, authed("GET", "/api/v1/uploads?cursor=%%%", &token)).await;
        assert_eq!(st, 400);
    }

    #[tokio::test]
    async fn uploads_refuse_a_revoked_device_and_the_session_cookie() {
        let (state, cookie, app, _d) = app().await;
        crate::store::uploads::seed_upload(&state.store, "203.0.113.62", "/a.php", b"x").await;
        let (token, device_id) = pair(&app, &cookie).await;
        let (st, _) = send(&app, authed("GET", "/api/v1/uploads", &token)).await;
        assert_eq!(st, 200);
        let r = app
            .clone()
            .oneshot(
                Request::post("/admin/devices/revoke")
                    .header("cookie", &cookie)
                    .header("sec-fetch-site", "same-origin")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("id={device_id}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        for path in [
            "/api/v1/uploads",
            &format!("/api/v1/uploads/{}", "0".repeat(64)),
        ] {
            let (st, v) = send(&app, authed("GET", path, &token)).await;
            assert_eq!(st, 401, "{path}");
            assert_eq!(v["error"]["code"], "unauthorized", "{v}");
            let (st, _) = send(
                &app,
                Request::get(path)
                    .header("cookie", &cookie)
                    .header("sec-fetch-site", "same-origin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(
                st, 401,
                "the admin session is not an API credential: {path}"
            );
        }
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
                .header("sec-fetch-site", "same-origin")
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
    async fn lookup_resolves_names_and_urls_per_entry() {
        let (state, cookie, app, _d) = app().await;
        seed_ip(&state, "203.0.113.9", "[]", 0).await;
        let names: Vec<String> = [
            "https://user:secret@www.example.com:8443/a?b=c",
            "http://[2001:db8::1]:8080/",
            "203.0.113.9/login",
            "gone.example",
            "garbage!!",
        ]
        .map(String::from)
        .to_vec();
        let v = super::names_json(&state, &names, async |n: &str| match n {
            "www.example.com" => Ok(vec![
                "203.0.113.9".parse().unwrap(),
                "198.51.100.7".parse().unwrap(),
                "10.0.0.1".parse().unwrap(),
            ]),
            _ => Err("NXDOMAIN".to_string()),
        })
        .await
        .unwrap();
        let v = serde_json::Value::from(v);
        assert!(
            !v.to_string().contains("secret"),
            "userinfo is dropped: {v}"
        );
        let www = &v[0];
        assert_eq!(www["host"], "www.example.com", "{v}");
        assert_eq!(www["resolve"]["note"], "resolved locally, unverified");
        let votes = www["resolve"]["votes"].as_array().unwrap();
        assert_eq!(votes.len(), 2, "a private answer is dropped: {v}");
        assert!(
            votes
                .iter()
                .all(|x| x["agreed"] == true && x["verdict"] == "agreed by 1 of 1")
        );
        // Storing the resolution puts its addresses in the dataset.
        let ips: Vec<&str> = www["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["ip"].as_str().unwrap())
            .collect();
        assert_eq!(ips, ["198.51.100.7", "203.0.113.9"], "{v}");
        assert_eq!(www["missing"], serde_json::json!([]));
        assert!(www.get("error").is_none());
        // IP-literal hosts take the address path, unresolved.
        assert_eq!(v[1]["host"], "2001:db8::1");
        assert_eq!(v[1]["missing"], serde_json::json!(["2001:db8::1"]));
        assert!(v[1].get("resolve").is_none());
        assert_eq!(v[2]["host"], "203.0.113.9");
        assert_eq!(v[2]["results"][0]["ip"], "203.0.113.9");
        assert_eq!(v[3]["host"], "gone.example");
        assert_eq!(v[3]["error"]["code"], "unresolved", "{v}");
        assert_eq!(v[4]["error"]["code"], "invalid");

        // Over HTTP: every name of a long list is answered, in order, and
        // the `ips` part as before. Nothing is capped.
        let (token, _) = pair(&app, &cookie).await;
        let mut names = vec!["garbage!!"; 24];
        names.push("203.0.113.9");
        let mut r = post_json(
            "/api/v1/lookup",
            serde_json::json!({"ips": ["203.0.113.9"], "names": names}),
        );
        r.headers_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        let (st, v) = send(&app, r).await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["results"][0]["ip"], "203.0.113.9");
        let names = v["names"].as_array().unwrap();
        assert_eq!(names.len(), 25);
        assert!(
            names[..24].iter().all(|n| n["error"]["code"] == "invalid"),
            "{v}"
        );
        assert_eq!(names[24]["host"], "203.0.113.9", "{v}");
        assert_eq!(names[24]["results"][0]["ip"], "203.0.113.9", "{v}");
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
            ("GET", format!("/api/v1/ips/{SCAN_IP}/probe/vantages")),
            ("GET", format!("/api/v1/ips/{SCAN_IP}/scan/prices")),
            ("GET", format!("/api/v1/ips/{SCAN_IP}/scan/quote?level=2")),
            ("POST", format!("/api/v1/ips/{SCAN_IP}/scan")),
            ("GET", format!("/api/v1/ips/{SCAN_IP}/lookup/quote")),
            ("POST", format!("/api/v1/ips/{SCAN_IP}/lookup")),
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
    async fn scan_prices_list_every_level_and_spend_nothing() {
        let (state, _c, _id, _d) = crate::admin::scan_buy::tests::state().await;
        let app = crate::admin::full_router(state.clone());
        let token = device(&state, "read,act", "Pixel 8").await;
        let (st, v) = send(
            &app,
            authed("GET", &format!("/api/v1/ips/{SCAN_IP}/scan/prices"), &token),
        )
        .await;
        assert_eq!(st, 200, "{v}");
        let levels = v["levels"].as_array().unwrap();
        assert_eq!(levels.len(), 5, "{v}");
        for (i, l) in levels.iter().enumerate() {
            assert_eq!(l["level"], i + 1, "{l}");
            assert_eq!(l["about"], crate::admin::scan_buy::about(i as u8 + 1));
            // Standalone: free.
            assert_eq!(l["credits"], "0.00", "{l}");
            assert_eq!(l["credits_max_mc"], 0, "{l}");
        }
        let quotes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_quotes")
            .fetch_one(&state.store.pool)
            .await
            .unwrap();
        assert_eq!(quotes, 0, "no quote");
        // Not in the dataset (MIK-329): priced all the same, no row made.
        let (st, v) = send(
            &app,
            authed("GET", "/api/v1/ips/198.51.100.77/scan/prices", &token),
        )
        .await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["levels"].as_array().unwrap().len(), 5, "{v}");
        assert!(
            state
                .store
                .ip_by_addr("198.51.100.77")
                .await
                .unwrap()
                .is_none()
        );
        // Never scanned: refused.
        let (st, v) = send(
            &app,
            authed("GET", "/api/v1/ips/10.0.0.1/scan/prices", &token),
        )
        .await;
        assert_eq!(st, 422, "{v}");
        assert_eq!(v["error"]["code"], "refused", "{v}");
    }

    /// MIK-329: an address no listener recorded is quoted without a row;
    /// the buy makes it, unseen, and the API says so.
    #[tokio::test]
    async fn a_scan_of_an_unrecorded_address_adds_it_unseen() {
        let (state, _c, _id, _d) = crate::admin::scan_buy::tests::state().await;
        let app = crate::admin::full_router(state.clone());
        let token = device(&state, "read,act", "Pixel 8").await;
        let ip = crate::admin::scan_buy::tests::UNRECORDED;
        let (st, q) = send(
            &app,
            authed(
                "GET",
                &format!("/api/v1/ips/{ip}/scan/quote?level=2"),
                &token,
            ),
        )
        .await;
        assert_eq!(st, 200, "{q}");
        assert!(
            state.store.ip_by_addr(ip).await.unwrap().is_none(),
            "a quote makes no row"
        );
        let (st, v) = send(
            &app,
            authed_json(
                "POST",
                &format!("/api/v1/ips/{ip}/scan"),
                &token,
                serde_json::json!({"quote_id": q["quote_id"]}),
            ),
        )
        .await;
        assert_eq!(st, 202, "{v}");
        let row = state.store.ip_by_addr(ip).await.unwrap().unwrap();
        assert!(row.unseen);
        assert_eq!(row.request_count, 0);
        assert_eq!(jobs_and_actions(&state).await, (1, 1));
        let (st, v) = send(&app, authed("GET", &format!("/api/v1/ips/{ip}"), &token)).await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["unseen"], true, "{v}");
        assert_eq!(v["request_count"], 0, "{v}");
        let (st, v) = send(&app, authed("GET", "/api/v1/ips", &token)).await;
        assert_eq!(st, 200, "{v}");
        let items = v["items"].as_array().unwrap();
        let unseen = |a: &str| {
            items
                .iter()
                .find(|i| i["ip"] == a)
                .map(|i| i["unseen"].clone())
        };
        assert_eq!(unseen(ip), Some(serde_json::json!(true)), "{v}");
        assert_eq!(unseen(SCAN_IP), Some(serde_json::json!(false)), "{v}");
    }

    /// A refused address is not quoted and gets no row.
    #[tokio::test]
    async fn a_refused_unrecorded_address_is_not_quoted() {
        let (state, _c, _id, _d) = crate::admin::scan_buy::tests::state().await;
        let app = crate::admin::full_router(state.clone());
        let token = device(&state, "read,act", "Pixel 8").await;
        for ip in ["10.0.0.1", "127.0.0.1", "fe80::1"] {
            let (st, v) = send(
                &app,
                authed(
                    "GET",
                    &format!("/api/v1/ips/{ip}/scan/quote?level=2"),
                    &token,
                ),
            )
            .await;
            assert_eq!(st, 422, "{ip}: {v}");
            assert_eq!(v["error"]["code"], "refused", "{ip}: {v}");
        }
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ips")
            .fetch_one(&state.store.pool)
            .await
            .unwrap();
        assert_eq!(n, 1, "only the recorded address");
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
                    .header("sec-fetch-site", "same-origin")
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

    #[tokio::test]
    async fn probe_vantages_list_the_node_itself_standalone_and_spend_nothing() {
        use crate::admin::probes::tests::{IP, state};
        let (state, _c, _id, _d) = state(None, "").await;
        let app = crate::admin::full_router(state.clone());
        let token = device(&state, "read,act", "phone").await;
        let path = |ip: &str| format!("/api/v1/ips/{ip}/probe/vantages");
        let (st, v) = send(&app, authed("GET", &path(IP), &token)).await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(
            v["vantages"],
            serde_json::json!([{
                "id": crate::scan::probe::gate::LOCAL.to_string(),
                "name": "this node",
                "country": null,
                "credits": crate::credits::show(0),
                "credits_mc": 0,
                "default": true,
            }])
        );
        let (st, _) = send(&app, authed("GET", &path("198.51.100.200"), &token)).await;
        assert_eq!(st, 404);
        state
            .store
            .upsert_ip("10.0.0.1".parse().unwrap())
            .await
            .unwrap();
        let (st, v) = send(&app, authed("GET", &path("10.0.0.1"), &token)).await;
        assert_eq!(st, 422, "{v}");
        assert_eq!(v["error"]["code"], "refused", "{v}");
        assert!(
            state
                .store
                .recent_device_actions(10)
                .await
                .unwrap()
                .is_empty(),
            "a read is not audited"
        );
    }

    /// In a cluster the list is the card's vantages, ticked as the card
    /// ticks them.
    #[test]
    fn probe_vantages_carry_the_cards_prices_and_default_pick() {
        use crate::admin::probes::{ActionsView, VantageView};
        let vantage = |id: &str, mc: u32| VantageView {
            id: id.into(),
            name: format!("node-{id}"),
            country: Some("DE".into()),
            price: crate::credits::show(mc as u64),
            price_mc: mc,
        };
        let a = ActionsView {
            guard_line: String::new(),
            allowed: true,
            why_not: None,
            vantages: vec![vantage("a", 20), vantage("b", 30), vantage("c", 50)],
            default: vec!["a".into(), "c".into()],
            balance: None,
            standalone: false,
            scans: vec![],
        };
        let v = super::vantages_json(&a);
        let ids: Vec<_> = v.iter().map(|v| v["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["a", "b", "c"]);
        for (j, view) in v.iter().zip(&a.vantages) {
            assert_eq!(j["default"], a.ticked(&view.id), "{j}");
            assert_eq!(j["credits"], view.price, "{j}");
            assert_eq!(j["credits_mc"], view.price_mc, "{j}");
            assert_eq!(j["country"], "DE");
        }
        let total: u64 = v
            .iter()
            .filter(|j| j["default"] == true)
            .map(|j| j["credits_mc"].as_u64().unwrap())
            .sum();
        assert_eq!(crate::credits::show(total), a.default_total());
    }

    /// A provider that answers every address, offline.
    struct Fake;
    impl crate::intel::provider::Provider for Fake {
        fn name(&self) -> &'static str {
            crate::intel::ABUSEIPDB
        }
        fn ready(&self) -> bool {
            true
        }
        fn lookup<'a>(
            &'a self,
            ips: &'a [String],
        ) -> futures::future::BoxFuture<'a, Vec<crate::intel::provider::Finding>> {
            Box::pin(async move {
                ips.iter()
                    .map(|ip| crate::intel::provider::Finding {
                        ip: ip.clone(),
                        source_version: None,
                        data: serde_json::json!({"score": 87}),
                    })
                    .collect()
            })
        }
    }

    #[test]
    fn a_lookup_quote_prices_own_providers_always_and_the_rest_when_chosen() {
        use crate::cluster::identity::NodeId;
        use crate::credits::pay::Quote;
        use crate::intel::{ABUSEIPDB, MAXMIND, SHODAN};
        let (me, bob) = (NodeId([1; 32]), NodeId([2; 32]));
        let q = |p: &str, server: NodeId, name: &str, mc: u32| Quote {
            provider: p.into(),
            server,
            server_name: name.into(),
            price_mc: mc,
        };
        let all = std::collections::HashMap::from([
            (MAXMIND.to_string(), vec![q(MAXMIND, me, "this node", 0)]),
            (ABUSEIPDB.to_string(), vec![q(ABUSEIPDB, bob, "bob", 100)]),
            (SHODAN.to_string(), vec![q(SHODAN, bob, "bob", 250)]),
        ]);
        let offered = super::priced(me, &all);
        let names = |l: &[super::Priced]| l.iter().map(|p| p.provider.clone()).collect::<Vec<_>>();
        // Nothing chosen: everything, as "ask all" on the web page.
        let every = super::pick(&offered, &[]).unwrap();
        assert_eq!(every.iter().map(|p| p.mc).sum::<u64>(), 350);
        let one = super::pick(&offered, &[ABUSEIPDB.into()]).unwrap();
        assert_eq!(names(&one), [MAXMIND, ABUSEIPDB]);
        assert_eq!(one[1].node, "bob");
        assert!(one[0].own && !one[1].own);
        // The bought set survives the quote's level; own ones are not in it.
        assert_eq!(
            super::lookup_bought(super::lookup_level(&one)).unwrap(),
            [ABUSEIPDB]
        );
        assert_eq!(
            super::lookup_bought(super::lookup_level(&every)).unwrap(),
            [ABUSEIPDB, SHODAN]
        );
        assert_eq!(super::lookup_bought(-1).unwrap(), Vec::<String>::new());
        // A scan level is not a lookup quote.
        assert_eq!(super::lookup_bought(3), None);
        assert_eq!(
            super::pick(&offered, &["nope".into()]),
            Err(super::Unpicked::Unknown("nope".into()))
        );
        assert_eq!(
            super::pick(&offered, &[crate::intel::RDAP.into()]),
            Err(super::Unpicked::NotOffered(crate::intel::RDAP.into()))
        );
        // A free good is no market: a member's (older node's) zero price
        // for it is not offered, this node's own answer is.
        let mut all = all;
        all.insert(
            crate::intel::RDAP.to_string(),
            vec![q(crate::intel::RDAP, bob, "bob", 0)],
        );
        all.insert(
            crate::intel::TOR.to_string(),
            vec![q(crate::intel::TOR, me, "this node", 0)],
        );
        let offered = super::priced(me, &all);
        assert!(!offered.iter().any(|p| p.provider == crate::intel::RDAP));
        assert!(
            offered
                .iter()
                .any(|p| p.provider == crate::intel::TOR && p.own && p.mc == 0)
        );
    }

    #[tokio::test]
    async fn a_quoted_lookup_asks_once_is_audited_and_refuses_a_stale_quote() {
        let (mut state, _c, _id, _d) = crate::admin::scan_buy::tests::state().await;
        Arc::get_mut(&mut state).unwrap().providers = vec![Arc::new(Fake)];
        let app = crate::admin::full_router(state.clone());
        let token = device(&state, "read,act", "Pixel 8").await;
        let device_id = state
            .store
            .validate_device_token(&token)
            .await
            .unwrap()
            .unwrap()
            .id;
        // The address need not be in the dataset.
        let ip = "198.51.100.7";
        let (st, q) = send(
            &app,
            authed("GET", &format!("/api/v1/ips/{ip}/lookup/quote"), &token),
        )
        .await;
        assert_eq!(st, 200, "{q}");
        assert_eq!(q["credits"], "0.00", "standalone costs nothing: {q}");
        assert_eq!(
            q["providers"][0]["provider"],
            crate::intel::ABUSEIPDB,
            "{q}"
        );
        assert_eq!(q["providers"][0]["own"], true, "{q}");
        assert!(q["expires_at"].as_str().unwrap().ends_with('Z'), "{q}");
        let (st, v) = send(
            &app,
            authed(
                "GET",
                &format!("/api/v1/ips/{ip}/lookup/quote?providers=nope"),
                &token,
            ),
        )
        .await;
        assert_eq!(
            (st, v["error"]["code"].clone()),
            (StatusCode::BAD_REQUEST, "invalid".into())
        );
        let buy = |addr: &str, id: &serde_json::Value| {
            authed_json(
                "POST",
                &format!("/api/v1/ips/{addr}/lookup"),
                &token,
                serde_json::json!({"quote_id": id}),
            )
        };
        // Another address than quoted: spent, nothing asked.
        let (st, v) = send(&app, buy(SCAN_IP, &q["quote_id"])).await;
        assert_eq!(
            (st, v["error"]["code"].clone()),
            (StatusCode::CONFLICT, "quote_mismatch".into())
        );
        assert_eq!(jobs_and_actions(&state).await, (0, 0));
        let (_, q) = send(
            &app,
            authed("GET", &format!("/api/v1/ips/{ip}/lookup/quote"), &token),
        )
        .await;
        let (st, v) = send(&app, buy(ip, &q["quote_id"])).await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(
            v["intel"][crate::intel::ABUSEIPDB]["source"],
            "fresh",
            "{v}"
        );
        assert_eq!(
            v["intel"][crate::intel::ABUSEIPDB]["data"]["score"],
            87,
            "{v}"
        );
        assert_eq!(v["credits_mc"], 0, "{v}");
        assert_eq!(jobs_and_actions(&state).await, (0, 1));
        let (st, j) = send(
            &app,
            authed(
                "GET",
                &format!("/api/v1/jobs/{}", q["quote_id"].as_str().unwrap()),
                &token,
            ),
        )
        .await;
        assert_eq!(
            (st, j["kind"].clone(), j["status"].clone()),
            (StatusCode::OK, "lookup".into(), "done".into()),
            "{j}"
        );
        // Spent once.
        let (st, v) = send(&app, buy(ip, &q["quote_id"])).await;
        assert_eq!(
            (st, v["error"]["code"].clone()),
            (StatusCode::CONFLICT, "quote_invalid".into())
        );
        // A quote whose price no longer holds asks and charges nothing.
        let stale = state
            .store
            .create_quote_at(&device_id, ip, -1, 500)
            .await
            .unwrap();
        let (st, v) = send(&app, buy(ip, &serde_json::json!(stale.id))).await;
        assert_eq!(
            (st, v["error"]["code"].clone()),
            (StatusCode::CONFLICT, "price_changed".into())
        );
        // A lookup quote buys no scan.
        let other = state
            .store
            .create_quote_at(&device_id, SCAN_IP, -1, 0)
            .await
            .unwrap();
        let (st, v) = send(
            &app,
            authed_json(
                "POST",
                &format!("/api/v1/ips/{SCAN_IP}/scan"),
                &token,
                serde_json::json!({"quote_id": other.id}),
            ),
        )
        .await;
        assert_eq!(
            (st, v["error"]["code"].clone()),
            (StatusCode::CONFLICT, "quote_invalid".into())
        );
        assert_eq!(jobs_and_actions(&state).await, (0, 1));
    }
}
