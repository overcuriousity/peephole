//! What the providers that ask a third-party API have in common: one request
//! per second, a daily or weekly budget that survives restarts, back-off
//! when the service fails or says "too many requests", and a skip list for
//! addresses that must not or cannot be asked. Each service only builds its
//! request and turns the answer into a compact result (see
//! [`super::abuseipdb`], [`super::shodan`], [`super::greynoise`]).
//!
//! Keys stay in the request: nothing here logs a URL (the Shodan key is a
//! query parameter), and response bodies are never logged or stored raw.
use super::provider::{Finding, Provider};
use crate::store::Store;
use chrono::{DateTime, Datelike, Duration as CDuration, NaiveDate, Utc};
use futures::future::BoxFuture;
use reqwest::StatusCode;
use reqwest::header::HeaderMap;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Largest result a node writes; lists are cut before this is reached.
pub const MAX_DATA_BYTES: usize = 16 * 1024;
/// Largest response body read from a service.
const MAX_BODY: usize = 1 << 20;
/// Gap between two requests to one service.
const PACE: Duration = Duration::from_secs(1);
const TIMEOUT: Duration = Duration::from_secs(20);
/// How long an IP the service refused (400, 422, an unreadable answer) is
/// left alone, so it cannot block the head of the queue.
const SKIP_REJECTED: Duration = Duration::from_secs(24 * 3600);
/// Entries kept on the skip list.
const SKIP_CAP: usize = 10_000;
/// IPs asked per pass: about a minute of requests, so a pass ends before
/// newer IPs have waited long.
const BATCH: i64 = 60;
/// Back-off after failures: 1 min doubling up to 1 h.
const BACKOFF_FIRST: i64 = 60;
const BACKOFF_MAX: i64 = 3600;

/// A third-party lookup service.
pub trait Service: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    /// Whether the service answers for IPv6 addresses.
    fn ipv6(&self) -> bool {
        true
    }
    fn request(&self, client: &reqwest::Client, ip: &str) -> reqwest::RequestBuilder;
    /// The result for a 2xx or 404 answer (a 404 is "nothing known"). None
    /// when the body is not what the service documents.
    fn parse(&self, status: StatusCode, body: &[u8]) -> Option<serde_json::Value>;
    /// Largest response body read; a larger one is treated as a refusal.
    fn max_body(&self) -> usize {
        MAX_BODY
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Period {
    /// UTC day.
    Day,
    /// ISO week (Monday 00:00 UTC).
    Week,
}

impl Period {
    fn start(self, now: DateTime<Utc>) -> NaiveDate {
        let d = now.date_naive();
        match self {
            Self::Day => d,
            Self::Week => d - CDuration::days(d.weekday().num_days_from_monday() as i64),
        }
    }

    fn end(self, now: DateTime<Utc>) -> DateTime<Utc> {
        let days = match self {
            Self::Day => 1,
            Self::Week => 7,
        };
        (self.start(now) + CDuration::days(days))
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
    }

    fn label(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Week => "week",
        }
    }
}

/// At most `max` requests per `period`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    pub period: Period,
    pub max: u64,
}

#[derive(Default)]
struct State {
    /// Requests made per `intel_meta` key (one key per limit and period).
    used: HashMap<String, u64>,
    loaded: bool,
    paused_until: Option<DateTime<Utc>>,
    /// Why it is paused, for the admin page.
    pause_reason: Option<&'static str>,
    key_rejected: bool,
    failures: u32,
    /// None: never asked (not a public address); Some: until then.
    skip: HashMap<String, Option<Instant>>,
    last_request: Option<Instant>,
}

/// A [`Service`] as a [`Provider`].
pub struct ApiProvider<S: Service> {
    svc: S,
    client: reqwest::Client,
    store: Store,
    limits: Vec<Limit>,
    refresh_after_days: f64,
    state: Mutex<State>,
}

/// What a request came back with, before the service reads the body.
enum Answer {
    Result(serde_json::Value),
    /// The service refused this IP; skip it for a day.
    Refused,
    /// Quota or rate limit: pause until then.
    Limited(DateTime<Utc>),
    KeyRejected(StatusCode),
    /// Network trouble or a server error: back off, ask again later.
    Failed(String),
}

impl<S: Service> ApiProvider<S> {
    pub fn new(svc: S, store: Store, limits: Vec<Limit>, refresh_after_days: f64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(concat!("peephole/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client");
        Self {
            svc,
            client,
            store,
            limits,
            refresh_after_days,
            state: Mutex::new(State::default()),
        }
    }

    fn usage_key(&self, l: &Limit, now: DateTime<Utc>) -> String {
        format!(
            "api_used:{}:{}:{}",
            self.svc.name(),
            l.period.label(),
            l.period.start(now)
        )
    }

    async fn load_usage(&self) {
        if self.state.lock().unwrap().loaded {
            return;
        }
        let now = Utc::now();
        let mut used = HashMap::new();
        for l in &self.limits {
            let key = self.usage_key(l, now);
            let n = match self.store.intel_get(&key).await {
                Ok(v) => v.and_then(|v| v.parse().ok()).unwrap_or(0),
                Err(e) => {
                    warn!(provider = self.svc.name(), ?e, "reading api usage failed");
                    0
                }
            };
            used.insert(key, n);
        }
        let mut st = self.state.lock().unwrap();
        st.used.extend(used);
        st.loaded = true;
    }

    /// The end of the first period whose budget is spent, if any.
    fn exhausted_until(&self, st: &State, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.limits
            .iter()
            .filter(|l| st.used.get(&self.usage_key(l, now)).copied().unwrap_or(0) >= l.max)
            .map(|l| l.period.end(now))
            .max()
    }

    /// Count one request against every budget; written through so a
    /// restart does not hand out the same budget twice.
    async fn count_request(&self) {
        let now = Utc::now();
        let updates: Vec<(String, u64)> = {
            let mut st = self.state.lock().unwrap();
            self.limits
                .iter()
                .map(|l| {
                    let key = self.usage_key(l, now);
                    let n = st.used.entry(key.clone()).or_insert(0);
                    *n += 1;
                    (key, *n)
                })
                .collect()
        };
        for (key, n) in updates {
            if let Err(e) = self.store.intel_set(&key, &n.to_string()).await {
                warn!(provider = self.svc.name(), ?e, "recording api usage failed");
            }
        }
    }

    fn pause(&self, until: DateTime<Utc>, reason: &'static str) {
        let mut st = self.state.lock().unwrap();
        if st.paused_until.is_none_or(|t| t < until) {
            st.paused_until = Some(until);
            st.pause_reason = Some(reason);
        }
    }

    fn fail(&self, why: &str) {
        let wait = {
            let mut st = self.state.lock().unwrap();
            st.failures = st.failures.saturating_add(1);
            (BACKOFF_FIRST << (st.failures - 1).min(10)).min(BACKOFF_MAX)
        };
        warn!(
            provider = self.svc.name(),
            error = why,
            retry_in_secs = wait,
            "lookup failed"
        );
        self.pause(Utc::now() + CDuration::seconds(wait), "errors");
    }

    fn skip(&self, ip: &str, until: Option<Instant>) {
        let mut st = self.state.lock().unwrap();
        if st.skip.len() >= SKIP_CAP {
            let now = Instant::now();
            st.skip.retain(|_, t| t.is_none_or(|t| t > now));
        }
        if st.skip.len() < SKIP_CAP {
            st.skip.insert(ip.to_string(), until);
        }
    }

    fn skipped(&self, ip: &str) -> bool {
        let st = self.state.lock().unwrap();
        st.skip
            .get(ip)
            .is_some_and(|t| t.is_none_or(|t| t > Instant::now()))
    }

    /// Whether this IP may be sent to the service at all.
    fn askable(&self, ip: &str) -> bool {
        match ip.parse::<std::net::IpAddr>() {
            Ok(a) => {
                crate::net::is_scannable_target(a)
                    && (self.svc.ipv6() || crate::net::canonical(a).is_ipv4())
            }
            Err(_) => false,
        }
    }

    async fn pace(&self) {
        let wait = {
            let mut st = self.state.lock().unwrap();
            let wait = st
                .last_request
                .map(|t| PACE.saturating_sub(t.elapsed()))
                .unwrap_or_default();
            st.last_request = Some(Instant::now() + wait);
            wait
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }

    async fn ask(&self, ip: &str) -> Answer {
        let resp = match self.svc.request(&self.client, ip).send().await {
            Ok(r) => r,
            // Without the URL: it can hold the key.
            Err(e) => return Answer::Failed(e.without_url().to_string()),
        };
        let status = resp.status();
        let limited_until = rate_limit_until(resp.headers(), Utc::now());
        let body = match read_capped(resp, self.svc.max_body()).await {
            Ok(b) => b,
            Err(Read::TooLarge) => return Answer::Refused,
            Err(Read::Failed(e)) => return Answer::Failed(e),
        };
        match status.as_u16() {
            401 | 403 => Answer::KeyRejected(status),
            429 => Answer::Limited(
                limited_until.unwrap_or_else(|| Utc::now() + CDuration::seconds(BACKOFF_FIRST)),
            ),
            500..=599 => Answer::Failed(format!("HTTP {status}")),
            200..=299 | 404 => match self.svc.parse(status, &body) {
                Some(v) => {
                    // A last good answer before the budget ran out still counts.
                    if let Some(t) = limited_until {
                        self.pause(t, "quota");
                    }
                    Answer::Result(fit(v))
                }
                None => Answer::Refused,
            },
            _ => Answer::Refused,
        }
    }

    /// Requests made in each budget's current period, for the admin page.
    pub fn usage(&self) -> Vec<(Limit, u64)> {
        let now = Utc::now();
        let st = self.state.lock().unwrap();
        self.limits
            .iter()
            .map(|l| {
                (
                    *l,
                    st.used.get(&self.usage_key(l, now)).copied().unwrap_or(0),
                )
            })
            .collect()
    }
}

/// When the service says no more requests are allowed: on a 429, or on a
/// success that used the last one (`X-RateLimit-Remaining: 0`). From
/// `Retry-After` (seconds) or `X-RateLimit-Reset` (epoch seconds).
fn rate_limit_until(h: &HeaderMap, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let num = |k: &str| {
        h.get(k)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<i64>().ok())
    };
    let retry = num("retry-after").map(|s| now + CDuration::seconds(s.clamp(0, 8 * 86400)));
    let reset = num("x-ratelimit-reset")
        .and_then(|t| DateTime::from_timestamp(t, 0))
        .filter(|t| *t > now && *t < now + CDuration::days(8));
    match num("x-ratelimit-remaining") {
        Some(0) => reset
            .or(retry)
            .or(Some(now + CDuration::seconds(BACKOFF_FIRST))),
        _ => retry,
    }
}

enum Read {
    TooLarge,
    Failed(String),
}

async fn read_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>, Read> {
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| Read::Failed(e.without_url().to_string()))?
    {
        out.extend_from_slice(&chunk);
        if out.len() > max {
            return Err(Read::TooLarge);
        }
    }
    Ok(out)
}

/// Strings from a JSON array, at most `max`.
pub(crate) fn strings(v: Option<&serde_json::Value>, max: usize) -> Vec<String> {
    v.and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| match x {
                    serde_json::Value::String(s) => Some(s.clone()),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .take(max)
                .collect()
        })
        .unwrap_or_default()
}

/// Put `v` under `k` unless it is empty (an empty list, string or null).
pub(crate) fn put(
    m: &mut serde_json::Map<String, serde_json::Value>,
    k: &str,
    v: serde_json::Value,
) {
    let empty = match &v {
        serde_json::Value::Null => true,
        serde_json::Value::String(s) => s.is_empty(),
        serde_json::Value::Array(a) => a.is_empty(),
        _ => false,
    };
    if !empty {
        m.insert(k.to_string(), v);
    }
}

/// A result that fits [`MAX_DATA_BYTES`]: list fields are dropped until it
/// does, and `truncated` says so.
fn fit(v: serde_json::Value) -> serde_json::Value {
    let serde_json::Value::Object(mut m) = v else {
        return v;
    };
    let size = |m: &serde_json::Map<_, _>| serde_json::to_string(m).map_or(0, |s| s.len());
    if size(&m) <= MAX_DATA_BYTES {
        return serde_json::Value::Object(m);
    }
    let mut lists: Vec<(String, usize)> = m
        .iter()
        .filter(|(_, v)| v.is_array() || v.is_object())
        .map(|(k, v)| (k.clone(), v.to_string().len()))
        .collect();
    lists.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (k, _) in lists {
        m.remove(&k);
        m.insert("truncated".into(), true.into());
        if size(&m) <= MAX_DATA_BYTES {
            break;
        }
    }
    // Long strings are the only thing left; keep it bounded regardless.
    if size(&m) > MAX_DATA_BYTES {
        m.retain(|_, v| !v.is_string() || v.as_str().is_some_and(|s| s.len() < 256));
    }
    serde_json::Value::Object(m)
}

impl<S: Service> Provider for ApiProvider<S> {
    fn name(&self) -> &'static str {
        self.svc.name()
    }

    fn ready(&self) -> bool {
        let now = Utc::now();
        let st = self.state.lock().unwrap();
        !st.key_rejected
            && st.paused_until.is_none_or(|t| t <= now)
            && self.exhausted_until(&st, now).is_none()
    }

    fn ipv6(&self) -> bool {
        self.svc.ipv6()
    }

    fn batch(&self) -> i64 {
        BATCH
    }

    fn refresh_after_days(&self) -> f64 {
        self.refresh_after_days
    }

    fn skip_list(&self) -> Vec<String> {
        let now = Instant::now();
        self.state
            .lock()
            .unwrap()
            .skip
            .iter()
            .filter(|(_, t)| t.is_none_or(|t| t > now))
            .map(|(ip, _)| ip.clone())
            .collect()
    }

    fn status(&self) -> Option<String> {
        let now = Utc::now();
        let st = self.state.lock().unwrap();
        let mut parts: Vec<String> = self
            .limits
            .iter()
            .map(|l| {
                let n = st.used.get(&self.usage_key(l, now)).copied().unwrap_or(0);
                format!("{n}/{} this {}", l.max, l.period.label())
            })
            .collect();
        if st.key_rejected {
            parts.push("key rejected (fix it and restart)".into());
        } else if let Some(t) = st.paused_until.filter(|t| *t > now) {
            parts.push(format!(
                "paused ({}) until {} UTC",
                st.pause_reason.unwrap_or("limit"),
                t.format("%Y-%m-%d %H:%M")
            ));
        } else if let Some(t) = self.exhausted_until(&st, now) {
            parts.push(format!(
                "budget spent until {} UTC",
                t.format("%Y-%m-%d %H:%M")
            ));
        }
        if parts.is_empty() {
            parts.push("no local limit".into());
        }
        Some(parts.join(" · "))
    }

    fn lookup<'a>(&'a self, ips: &'a [String]) -> BoxFuture<'a, Vec<Finding>> {
        Box::pin(async move {
            self.load_usage().await;
            let mut out = Vec::new();
            for ip in ips {
                if !self.ready() {
                    break;
                }
                if self.skipped(ip) {
                    continue;
                }
                if !self.askable(ip) {
                    self.skip(ip, None);
                    continue;
                }
                self.pace().await;
                self.count_request().await;
                match self.ask(ip).await {
                    Answer::Result(data) => {
                        self.state.lock().unwrap().failures = 0;
                        out.push(Finding {
                            ip: ip.clone(),
                            source_version: None,
                            data,
                        });
                    }
                    Answer::Refused => self.skip(ip, Some(Instant::now() + SKIP_REJECTED)),
                    Answer::Limited(until) => {
                        info!(
                            provider = self.svc.name(),
                            until = %until.format("%Y-%m-%d %H:%M:%S"),
                            "rate limit reached; pausing"
                        );
                        self.pause(until, "rate limit");
                        break;
                    }
                    Answer::KeyRejected(status) => {
                        warn!(
                            provider = self.svc.name(),
                            %status,
                            "API key rejected (or the plan does not include this lookup); provider off until restart"
                        );
                        self.state.lock().unwrap().key_rejected = true;
                        break;
                    }
                    Answer::Failed(why) => {
                        self.fail(&why);
                        break;
                    }
                }
                // The budget may have run out with this request.
                let now = Utc::now();
                let spent = {
                    let st = self.state.lock().unwrap();
                    self.exhausted_until(&st, now)
                };
                if let Some(t) = spent {
                    info!(
                        provider = self.svc.name(),
                        until = %t.format("%Y-%m-%d %H:%M:%S"),
                        "lookup budget spent"
                    );
                    break;
                }
            }
            out
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn periods_start_and_end_in_utc() {
        let t = DateTime::parse_from_rfc3339("2026-10-02T15:00:00Z")
            .unwrap()
            .to_utc();
        assert_eq!(Period::Day.start(t).to_string(), "2026-10-02");
        assert_eq!(Period::Day.end(t).to_rfc3339(), "2026-10-03T00:00:00+00:00");
        // 2026-10-02 is a Friday.
        assert_eq!(Period::Week.start(t).to_string(), "2026-09-28");
        assert_eq!(
            Period::Week.end(t).to_rfc3339(),
            "2026-10-05T00:00:00+00:00"
        );
    }

    #[test]
    fn rate_limit_headers() {
        let now = Utc::now();
        let mut h = HeaderMap::new();
        assert_eq!(rate_limit_until(&h, now), None);
        h.insert("x-ratelimit-remaining", "12".parse().unwrap());
        assert_eq!(rate_limit_until(&h, now), None);
        let reset = (now + CDuration::hours(3)).timestamp();
        h.insert("x-ratelimit-reset", reset.to_string().parse().unwrap());
        h.insert("x-ratelimit-remaining", "0".parse().unwrap());
        assert_eq!(rate_limit_until(&h, now).unwrap().timestamp(), reset);
        let mut h = HeaderMap::new();
        h.insert("retry-after", "120".parse().unwrap());
        assert_eq!(
            rate_limit_until(&h, now),
            Some(now + CDuration::seconds(120))
        );
    }

    struct Mock(String);

    impl Service for Mock {
        fn name(&self) -> &'static str {
            crate::intel::ABUSEIPDB
        }
        fn request(&self, client: &reqwest::Client, ip: &str) -> reqwest::RequestBuilder {
            client.get(format!("{}/{ip}", self.0))
        }
        fn parse(&self, status: StatusCode, body: &[u8]) -> Option<serde_json::Value> {
            match status.as_u16() {
                404 => Some(serde_json::json!({})),
                _ => serde_json::from_slice(body).ok(),
            }
        }
    }

    /// A service that answers by IP: .1 found, .2 unknown, .3 refused,
    /// .4 rate limited for an hour, .5 bad key.
    async fn mock() -> String {
        use axum::http::{HeaderMap as H, StatusCode as S};
        let app = axum::Router::new().route(
            "/{ip}",
            axum::routing::get(
                |axum::extract::Path(ip): axum::extract::Path<String>| async move {
                    let mut h = H::new();
                    let status = match ip.rsplit('.').next() {
                        Some("1") => S::OK,
                        Some("2") => S::NOT_FOUND,
                        Some("3") => S::BAD_REQUEST,
                        Some("4") => {
                            h.insert("retry-after", "3600".parse().unwrap());
                            S::TOO_MANY_REQUESTS
                        }
                        _ => S::UNAUTHORIZED,
                    };
                    (status, h, r#"{"score": 5}"#)
                },
            ),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    async fn store() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        Store::connect(&path).await.unwrap()
    }

    #[tokio::test]
    async fn answers_refusals_and_rate_limits() {
        let base = mock().await;
        let st = store().await;
        let p = ApiProvider::new(Mock(base), st.clone(), vec![], 30.0);
        assert!(p.ready());
        let ips: Vec<String> = [
            "10.0.0.1",
            "198.51.100.1",
            "198.51.100.2",
            "198.51.100.3",
            "198.51.100.4",
            "198.51.100.11",
        ]
        .map(String::from)
        .to_vec();
        let found = p.lookup(&ips).await;
        let got: Vec<_> = found
            .iter()
            .map(|f| (f.ip.as_str(), f.data.clone()))
            .collect();
        assert_eq!(
            got,
            [
                ("198.51.100.1", serde_json::json!({"score": 5})),
                ("198.51.100.2", serde_json::json!({})),
            ]
        );
        assert!(!p.ready(), "paused by the 429");
        assert!(p.status().unwrap().contains("rate limit"));
        let mut skip = p.skip_list();
        skip.sort();
        assert_eq!(skip, ["10.0.0.1", "198.51.100.3"], "private and refused");
    }

    #[tokio::test]
    async fn a_rejected_key_turns_the_provider_off() {
        let p = ApiProvider::new(Mock(mock().await), store().await, vec![], 30.0);
        assert!(p.lookup(&["198.51.100.5".into()]).await.is_empty());
        assert!(!p.ready());
        assert!(p.status().unwrap().contains("key rejected"));
    }

    #[tokio::test]
    async fn the_budget_survives_a_restart() {
        let base = mock().await;
        let st = store().await;
        let limits = vec![Limit {
            period: Period::Day,
            max: 1,
        }];
        let p = ApiProvider::new(Mock(base.clone()), st.clone(), limits.clone(), 30.0);
        let ips = vec!["198.51.100.1".to_string(), "198.51.100.21".to_string()];
        assert_eq!(p.lookup(&ips).await.len(), 1, "one request allowed");
        assert!(!p.ready());
        assert_eq!(p.usage()[0].1, 1);
        // A restarted node: the same budget, already spent.
        let again = ApiProvider::new(Mock(base), st, limits, 30.0);
        assert!(again.lookup(&ips).await.is_empty());
        assert!(!again.ready());
    }

    #[test]
    fn oversized_results_lose_their_lists() {
        let big: Vec<String> = (0..5000).map(|i| format!("CVE-2026-{i:05}")).collect();
        let v = fit(serde_json::json!({"org": "x", "vulns": big}));
        assert_eq!(v["org"], "x");
        assert_eq!(v["truncated"], true);
        assert!(v.get("vulns").is_none());
        let small = serde_json::json!({"ports": [22]});
        assert_eq!(fit(small.clone()), small);
    }
}
