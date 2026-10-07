//! Per-client rate limits on the web listener: anonymous traffic to the
//! public pages and the unauthenticated WebAuthn endpoints (each sign-in
//! attempt stores a ceremony). Token buckets in memory, keyed by the client
//! address (an IPv6 client by its /64, or its /48 for the ceremonies),
//! resolved with the same `X-Forwarded-For` logic as the trap. Sign-in
//! starts also share one global bucket, so many sources together cannot
//! churn through the open ceremonies faster than a pending one may be
//! evicted.
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
/// `/login/start` and `/login/password` POSTs from all clients together. Starts within
/// [`MIN_CEREMONY_SECS`](crate::store::auth::MIN_CEREMONY_SECS) stay well
/// under [`MAX_OPEN_CEREMONIES`](crate::store::auth::MAX_OPEN_CEREMONIES), so
/// at the cap an old one is always there to evict.
pub const LOGIN_PER_MINUTE: u32 = 120;
pub const LOGIN_BURST: u32 = 30;
const _: () = assert!(
    (LOGIN_PER_MINUTE as i64) * crate::store::auth::MIN_CEREMONY_SECS / 60 + (LOGIN_BURST as i64)
        < crate::store::auth::MAX_OPEN_CEREMONIES
);
/// Clients tracked at most; past it idle (full) buckets are dropped, then
/// the least recently used.
const MAX_CLIENTS: usize = 20_000;

struct Bucket {
    tokens: f64,
    /// Last refill, which is also the last use.
    at: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            at: now,
        }
    }

    /// Tokens at `now`, not stored.
    fn level(&self, now: Instant, per_sec: f64, burst: f64) -> f64 {
        (self.tokens + now.duration_since(self.at).as_secs_f64() * per_sec).min(burst)
    }

    /// Refill to `now` and take one token; `false` when empty.
    fn take(&mut self, now: Instant, per_sec: f64, burst: f64) -> bool {
        self.tokens = self.level(now, per_sec, burst);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
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
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() >= MAX_CLIENTS && !map.contains_key(&client) {
            map.retain(|_, b| b.level(now, per_sec, burst) < burst);
            if map.len() >= MAX_CLIENTS {
                // Under a flood of distinct sources: drop the least recently
                // used tenth (one pass, then room for many), not everyone.
                let mut ats: Vec<Instant> = map.values().map(|b| b.at).collect();
                let (_, &mut cutoff, _) = ats.select_nth_unstable(MAX_CLIENTS / 10);
                map.retain(|_, b| b.at > cutoff);
            }
        }
        map.entry(client)
            .or_insert_with(|| Bucket::full(burst, now))
            .take(now, per_sec, burst)
    }
}

/// One token bucket shared by all clients.
pub struct GlobalLimiter {
    bucket: Mutex<Bucket>,
    per_sec: f64,
    burst: f64,
}

impl GlobalLimiter {
    pub fn new(per_minute: u32, burst: u32) -> Self {
        let burst = f64::from(burst.max(1));
        Self {
            bucket: Mutex::new(Bucket::full(burst, Instant::now())),
            per_sec: f64::from(per_minute) / 60.0,
            burst,
        }
    }

    /// Take one token; `false` when the bucket is empty.
    pub fn allow(&self) -> bool {
        let mut b = self.bucket.lock().unwrap_or_else(|p| p.into_inner());
        b.take(Instant::now(), self.per_sec, self.burst)
    }
}

/// The limits of one web listener.
pub struct Limits {
    public: RateLimiter,
    auth: RateLimiter,
    login: GlobalLimiter,
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
            login: GlobalLimiter::new(LOGIN_PER_MINUTE, LOGIN_BURST),
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
/// usually holds a whole /64), or by its /48 for the ceremonies (one site
/// usually holds a whole /48; a /64 apiece would give it 65536 budgets).
fn client_key(ip: IpAddr, class: &Class) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let fourth = if *class == Class::Auth { 0 } else { s[3] };
            IpAddr::V6(std::net::Ipv6Addr::new(
                s[0], s[1], s[2], fourth, 0, 0, 0, 0,
            ))
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
    let limits = &state.limits;
    // Sign-in starts from everyone share one budget as well, taken after the
    // client's own so a client over its limit does not spend it.
    let is_login_start =
        class == Class::Auth && matches!(req.uri().path(), "/login/start" | "/login/password");
    let global = || !is_login_start || limits.login.allow();
    // No peer address (in-process callers, tests): nothing to key on.
    let Some(ConnectInfo(peer)) = req.extensions().get::<ConnectInfo<SocketAddr>>().copied() else {
        if !global() {
            return too_many();
        }
        return next.run(req).await;
    };
    let client = crate::trap::client_ip(req.headers(), peer.ip(), &limits.trusted);
    if client.is_loopback() {
        if !limits.warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "web requests arrive from a local proxy without X-Forwarded-For: per-client \
                 rate limits are off. Add `proxy_set_header X-Forwarded-For $remote_addr;` \
                 to the nginx location blocks of the admin site."
            );
        }
        if !global() {
            return too_many();
        }
        return next.run(req).await;
    }
    let key = client_key(client, &class);
    let allowed = match class {
        Class::Auth => limits.auth.allow(key) && global(),
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
    fn ipv6_clients_share_their_64_or_48_for_ceremonies() {
        let key = |ip: &str, class| client_key(ip.parse().unwrap(), &class);
        let a = key("2001:db8:1:2:aaaa::1", Class::Public);
        let b = key("2001:db8:1:2:bbbb::9", Class::Public);
        let c = key("2001:db8:1:3::1", Class::Public);
        assert_eq!(a, b);
        assert_ne!(a, c);
        let a = key("2001:db8:1:2::1", Class::Auth);
        assert_eq!(a, key("2001:db8:1:ffff::1", Class::Auth));
        assert_ne!(a, key("2001:db8:2:2::1", Class::Auth));
        let v4 = key("203.0.113.1", Class::Auth);
        assert_eq!(v4, "203.0.113.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn a_full_table_drops_the_least_recently_used() {
        let l = RateLimiter::new(1, 3); // Slow refill: none turns idle meanwhile.
        let ip = |i: usize| IpAddr::from(std::net::Ipv6Addr::from(i as u128 + 1));
        // Every tracked client has spent a token (none idle).
        for i in 0..MAX_CLIENTS {
            assert!(l.allow(ip(i)));
        }
        // The most recent drains its bucket.
        let hot = ip(MAX_CLIENTS - 1);
        assert!(l.allow(hot) && l.allow(hot));
        assert!(!l.allow(hot));
        assert!(l.allow(ip(MAX_CLIENTS)), "a newcomer gets room");
        let map = l.buckets.lock().unwrap();
        assert!(map.len() < MAX_CLIENTS);
        assert!(!map.contains_key(&ip(0)), "oldest dropped");
        // Not everyone was forgotten: the drained client stays limited.
        assert!(map.contains_key(&hot));
        drop(map);
        assert!(!l.allow(hot));
    }

    #[test]
    fn the_global_bucket_is_shared() {
        let g = GlobalLimiter::new(60, 2);
        assert!(g.allow() && g.allow());
        assert!(!g.allow());
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
        // Many sources together run out of the shared sign-in budget.
        let mut refused = None;
        for i in 0..(LOGIN_BURST * 4) {
            let ip = format!("192.0.2.{i}");
            if call("POST", "/login/start", Some(&ip))
                .await
                .unwrap()
                .status()
                == 429
            {
                refused = Some(i);
                break;
            }
        }
        assert!(
            refused.is_some_and(|i| i >= LOGIN_BURST - AUTH_BURST),
            "{refused:?}"
        );
        // Other ceremony endpoints are not in it.
        let r = call("POST", "/login/finish", Some("192.0.2.250"))
            .await
            .unwrap();
        assert_ne!(r.status(), 429);
    }

    #[test]
    fn only_public_pages_and_ceremonies_are_limited() {
        use axum::http::Method;
        assert_eq!(classify(&Method::POST, "/login/start"), Class::Auth);
        assert_eq!(classify(&Method::POST, "/login/password"), Class::Auth);
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
