//! The machine API (`/api/v1`) of this node, for the companion app. Its
//! credential is the device token (`Authorization: Bearer …`), honoured here
//! and nowhere else; the admin session cookie is honoured everywhere else
//! and never here. Every answer is JSON, errors included
//! (`{error:{code,message}}`, see `docs/api-v1.md`).
use crate::admin::AdminState;
use crate::store::browse::{IpFilter, IpSummary};
use crate::store::devices::Device;
use axum::{
    Json, Router,
    extract::{FromRequestParts, Path, Query, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/api/v1/pair", post(pair))
        .route("/api/v1/ips", get(ips))
        .route("/api/v1/ips/{addr}", get(ip_detail))
        .route("/api/v1/lookup", post(lookup))
        // Unknown API paths answer in the API's error shape, not the HTML 404.
        .route("/api/v1/{*rest}", axum::routing::any(not_found))
}

async fn not_found() -> Response {
    err(StatusCode::NOT_FOUND, "not_found", "no such endpoint")
}

/// The error shape: every non-2xx of `/api/v1` is this JSON.
pub fn err(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(json!({"error": {"code": code, "message": message}})),
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
}
