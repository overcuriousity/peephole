//! Per-client rate limits on the web listener: anonymous traffic to the
//! public pages and the unauthenticated WebAuthn endpoints (each sign-in
//! attempt stores a ceremony). Token buckets in memory, keyed by the client
//! address (an IPv6 client by its /64), resolved with the same
//! `X-Forwarded-For` logic as the trap.
//!
//! The admin listener normally sits behind a local nginx; loopback peers
//! are trusted to report the client in `X-Forwarded-For`. Without that
//! header every client looks like the proxy itself, so no per-client limit
//! applies (a shared bucket would let one client lock everyone out); a
//! warning says so once.
use crate::admin::AdminState;
use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Public pages: sustained requests per minute and burst, per client.
pub const PUBLIC_PER_MINUTE: u32 = 120;
pub const PUBLIC_BURST: u32 = 60;
/// `/login/*` and `/enroll/*` POSTs, per client.
pub const AUTH_PER_MINUTE: u32 = 10;
pub const AUTH_BURST: u32 = 10;
/// Clients tracked at most; past it idle (full) buckets are dropped.
const MAX_CLIENTS: usize = 20_000;

struct Bucket {
    tokens: f64,
    at: Instant,
}

/// A token bucket per client.
pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    per_sec: f64,
    burst: f64,
}

impl RateLimiter {
    pub fn new(per_minute: u32, burst: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            per_sec: f64::from(per_minute) / 60.0,
            burst: f64::from(burst.max(1)),
        }
    }

    /// Take one token for `client`; `false` when its bucket is empty.
    pub fn allow(&self, client: IpAddr) -> bool {
        let now = Instant::now();
        let (per_sec, burst) = (self.per_sec, self.burst);
        let refill = |b: &mut Bucket| {
            b.tokens = (b.tokens + now.duration_since(b.at).as_secs_f64() * per_sec).min(burst);
            b.at = now;
        };
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() >= MAX_CLIENTS && !map.contains_key(&client) {
            map.retain(|_, b| {
                refill(b);
                b.tokens < burst
            });
            if map.len() >= MAX_CLIENTS {
                // Under a flood of distinct sources: forget them all rather
                // than grow without bound.
                map.clear();
            }
        }
        let b = map.entry(client).or_insert(Bucket {
            tokens: burst,
            at: now,
        });
        refill(b);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The limits of one web listener.
pub struct Limits {
    public: RateLimiter,
    auth: RateLimiter,
    /// `trusted_proxies` plus loopback (the local reverse proxy).
    trusted: Vec<IpNet>,
    warned: AtomicBool,
}

impl Limits {
    pub fn new(cfg: &crate::config::Config) -> Self {
        let mut trusted = cfg.trusted_proxies.clone();
        trusted.extend(["127.0.0.0/8", "::1/128"].map(|n| n.parse::<IpNet>().expect("valid")));
        Self {
            public: RateLimiter::new(PUBLIC_PER_MINUTE, PUBLIC_BURST),
            auth: RateLimiter::new(AUTH_PER_MINUTE, AUTH_BURST),
            trusted,
            warned: AtomicBool::new(false),
        }
    }
}

#[derive(Debug, PartialEq)]
enum Class {
    /// Unauthenticated WebAuthn ceremony endpoints.
    Auth,
    /// Public pages and their JSON.
    Public,
    /// Assets, health check, admin pages (a session gates them anyway).
    Free,
}

fn classify(method: &axum::http::Method, path: &str) -> Class {
    if method == axum::http::Method::POST
        && (path.starts_with("/login/") || path.starts_with("/enroll/"))
    {
        return Class::Auth;
    }
    if path == "/" || path == "/ips" || path.starts_with("/ip/") || path.starts_with("/api/") {
        return Class::Public;
    }
    Class::Free
}

/// The bucket key: the address, an IPv6 client by its /64 (one host
/// usually holds a whole /64).
fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

fn too_many() -> Response {
    (
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, "30")],
        "too many requests; slow down",
    )
        .into_response()
}

/// Middleware enforcing [`Limits`].
pub async fn enforce(State(state): State<Arc<AdminState>>, req: Request, next: Next) -> Response {
    let class = classify(req.method(), req.uri().path());
    if class == Class::Free {
        return next.run(req).await;
    }
    // No peer address (in-process callers, tests): nothing to key on.
    let Some(ConnectInfo(peer)) = req.extensions().get::<ConnectInfo<SocketAddr>>().copied() else {
        return next.run(req).await;
    };
    let limits = &state.limits;
    let client = crate::trap::client_ip(req.headers(), peer.ip(), &limits.trusted);
    if client.is_loopback() {
        if !limits.warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "web requests arrive from a local proxy without X-Forwarded-For: per-client \
                 rate limits are off. Add `proxy_set_header X-Forwarded-For $remote_addr;` \
                 to the nginx location blocks of the admin site."
            );
        }
        return next.run(req).await;
    }
    let key = client_key(client);
    let allowed = match class {
        Class::Auth => limits.auth.allow(key),
        _ => limits.public.allow(key),
    };
    if allowed {
        return next.run(req).await;
    }
    // An admin browsing the public pages is not limited (checked only once
    // the bucket is empty, so anonymous traffic costs no session lookup).
    if class == Class::Public {
        let jar = axum_extra::extract::CookieJar::from_headers(req.headers());
        if crate::admin::auth::session_valid(&state, &jar).await {
            return next.run(req).await;
        }
    }
    too_many()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_refill_and_are_per_client() {
        let l = RateLimiter::new(60, 3);
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "203.0.113.2".parse().unwrap();
        assert!((0..3).all(|_| l.allow(a)));
        assert!(!l.allow(a), "burst used up");
        assert!(l.allow(b), "another client has its own bucket");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(l.allow(a), "one token back after a second at 60/min");
    }

    #[test]
    fn ipv6_clients_share_their_64() {
        let a = client_key("2001:db8:1:2:aaaa::1".parse().unwrap());
        let b = client_key("2001:db8:1:2:bbbb::9".parse().unwrap());
        let c = client_key("2001:db8:1:3::1".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[tokio::test]
    async fn the_router_limits_each_client_separately() {
        use axum::body::Body;
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let cfg: crate::config::Config = toml::from_str(&format!(
            r#"
admin_listen = "127.0.0.1:1"
database_path = "{db}"
data_dir = "{d}"
[roles]
listener = false
scanner = false
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
secure_cookies = false
"#,
            db = dir.path().join("t.db").display(),
            d = dir.path().display()
        ))
        .unwrap();
        let store = crate::store::Store::connect(&cfg.database_path)
            .await
            .unwrap();
        let app = crate::admin::full_router(Arc::new(AdminState::public_only(store, cfg)));
        // nginx on loopback reports the client in X-Forwarded-For.
        let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let call = |method: &str, path: &str, client: Option<&str>| {
            let mut b = axum::http::Request::builder()
                .method(method)
                .uri(path)
                .extension(ConnectInfo(peer));
            if let Some(c) = client {
                b = b.header("x-forwarded-for", c);
            }
            app.clone().oneshot(b.body(Body::empty()).unwrap())
        };
        for _ in 0..PUBLIC_BURST {
            let r = call("GET", "/api/countries", Some("203.0.113.1"))
                .await
                .unwrap();
            assert_eq!(r.status(), 200);
        }
        let r = call("GET", "/api/countries", Some("203.0.113.1"))
            .await
            .unwrap();
        assert_eq!(r.status(), 429);
        assert!(r.headers().contains_key(axum::http::header::RETRY_AFTER));
        // Security headers still apply to the refusal.
        assert!(r.headers().contains_key("x-content-type-options"));
        let r = call("GET", "/api/countries", Some("203.0.113.2"))
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "another client");
        let r = call("GET", "/assets/js/app.js", Some("203.0.113.1"))
            .await
            .unwrap();
        assert_ne!(r.status(), 429, "assets are not limited");
        // Without X-Forwarded-For all clients look like the proxy: no limit.
        for _ in 0..(PUBLIC_BURST + 5) {
            let r = call("GET", "/api/countries", None).await.unwrap();
            assert_eq!(r.status(), 200);
        }
        // Sign-in ceremonies have a tighter budget.
        for _ in 0..AUTH_BURST {
            let r = call("POST", "/login/start", Some("198.51.100.7"))
                .await
                .unwrap();
            assert_eq!(r.status(), 412, "no keys enrolled");
        }
        let r = call("POST", "/login/start", Some("198.51.100.7"))
            .await
            .unwrap();
        assert_eq!(r.status(), 429);
    }

    #[test]
    fn only_public_pages_and_ceremonies_are_limited() {
        use axum::http::Method;
        assert_eq!(classify(&Method::POST, "/login/start"), Class::Auth);
        assert_eq!(classify(&Method::POST, "/enroll/finish"), Class::Auth);
        assert_eq!(classify(&Method::GET, "/ips"), Class::Public);
        assert_eq!(classify(&Method::GET, "/ip/203.0.113.1"), Class::Public);
        assert_eq!(classify(&Method::GET, "/api/stats"), Class::Public);
        assert_eq!(classify(&Method::GET, "/"), Class::Public);
        assert_eq!(classify(&Method::GET, "/assets/css/app.css"), Class::Free);
        assert_eq!(classify(&Method::GET, "/healthz"), Class::Free);
        assert_eq!(classify(&Method::GET, "/admin"), Class::Free);
        assert_eq!(classify(&Method::GET, "/login"), Class::Free);
    }
}
