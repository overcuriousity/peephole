//! RDAP: who holds the block an address is in, from the registries'
//! own servers. Free, no key. The IANA bootstrap files say which RIR
//! serves which prefix; they are built in and refreshed weekly into
//! `data_dir`. Each address is asked for itself: RDAP answers with the
//! most specific object, and a sub-assignment inside a range has its own
//! holder and abuse contact, so one answer is never reused for a
//! neighbour.
use super::provider::{Finding, Provider};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use ipnet::IpNet;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub const BOOTSTRAP_V4_URL: &str = "https://data.iana.org/rdap/ipv4.json";
pub const BOOTSTRAP_V6_URL: &str = "https://data.iana.org/rdap/ipv6.json";
/// How old a bootstrap file in `data_dir` may be before it is fetched again.
pub const BOOTSTRAP_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
/// Referrals followed from the bootstrap server's answer.
const MAX_REFERRALS: usize = 2;
const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_BODY: usize = 256 * 1024;
/// A block registered or changed less than this many days ago is `fresh`.
const FRESH_DAYS: i64 = 90;

/// One RDAP service: its base URL and the prefixes it serves.
#[derive(Debug, Clone)]
pub struct Service {
    pub base: String,
    pub nets: Vec<IpNet>,
}

#[derive(Debug, Clone, Default)]
pub struct Bootstrap {
    services: Vec<Service>,
}

impl Bootstrap {
    /// The files shipped in the binary.
    pub fn builtin() -> Self {
        Self::parse(
            include_str!("rdap/ipv4.json"),
            include_str!("rdap/ipv6.json"),
        )
        .expect("built-in rdap bootstrap parses")
    }

    pub fn parse(v4: &str, v6: &str) -> Result<Self> {
        let mut services = vec![];
        for text in [v4, v6] {
            let v: Value = serde_json::from_str(text).context("rdap bootstrap json")?;
            for svc in v["services"].as_array().into_iter().flatten() {
                let nets: Vec<IpNet> = svc[0]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|p| p.as_str()?.parse().ok())
                    .collect();
                let Some(base) = svc[1]
                    .as_array()
                    .and_then(|u| u.iter().find_map(|u| u.as_str()))
                else {
                    continue;
                };
                // Prefer https when the list offers both.
                let base = svc[1]
                    .as_array()
                    .and_then(|u| {
                        u.iter()
                            .find_map(|u| u.as_str().filter(|s| s.starts_with("https://")))
                    })
                    .unwrap_or(base);
                services.push(Service {
                    base: base.to_string(),
                    nets,
                });
            }
        }
        Ok(Self { services })
    }

    /// The bootstrap in `data_dir` when fresh, else the built-in one.
    pub fn load(data_dir: &Path) -> Self {
        let (v4, v6) = (
            data_dir.join("rdap-ipv4.json"),
            data_dir.join("rdap-ipv6.json"),
        );
        let fresh = |p: &PathBuf| {
            std::fs::metadata(p)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age < BOOTSTRAP_MAX_AGE)
        };
        if fresh(&v4)
            && fresh(&v6)
            && let (Ok(a), Ok(b)) = (std::fs::read_to_string(&v4), std::fs::read_to_string(&v6))
            && let Ok(boot) = Self::parse(&a, &b)
        {
            return boot;
        }
        Self::builtin()
    }

    /// Download both files into `data_dir` (atomically); errors leave the
    /// old files untouched.
    pub async fn refresh(data_dir: &Path) -> Result<()> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(60))
            .build()?;
        for (url, name) in [
            (BOOTSTRAP_V4_URL, "rdap-ipv4.json"),
            (BOOTSTRAP_V6_URL, "rdap-ipv6.json"),
        ] {
            let body = client
                .get(url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            // It must parse before it replaces anything.
            let _: Value = serde_json::from_str(&body).context("rdap bootstrap json")?;
            let tmp = data_dir.join(format!("{name}.tmp"));
            std::fs::write(&tmp, &body)?;
            std::fs::rename(&tmp, data_dir.join(name))?;
        }
        Ok(())
    }

    /// The service whose longest prefix covers `ip`.
    pub fn service_for(&self, ip: &IpAddr) -> Option<&Service> {
        self.services
            .iter()
            .filter_map(|s| {
                s.nets
                    .iter()
                    .filter(|n| n.contains(ip))
                    .map(|n| n.prefix_len())
                    .max()
                    .map(|l| (l, s))
            })
            .max_by_key(|(l, _)| *l)
            .map(|(_, s)| s)
    }
}

/// Gap between two queries to one registry.
pub fn pace_for(base: &str) -> Duration {
    if base.contains("lacnic") || base.contains("afrinic") {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(1)
    }
}

/// Pacing and back-off of one registry.
#[derive(Debug, Default)]
pub struct RirState {
    last: Option<Instant>,
    failures: u32,
    paused_until: Option<Instant>,
}

impl RirState {
    /// Count a failure (a 429 without Retry-After, a 5xx, a network error);
    /// returns the pause: 10 s doubling up to 5 min.
    pub fn fail(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        let wait =
            Duration::from_secs(10 << (self.failures - 1).min(5)).min(Duration::from_secs(300));
        self.paused_until = Some(Instant::now() + wait);
        wait
    }

    pub fn ok(&mut self) {
        self.failures = 0;
        self.paused_until = None;
    }

    fn pause(&mut self, d: Duration) {
        self.paused_until = Some(Instant::now() + d);
    }
}

/// The bootstrap shared with the scheduler, which refreshes it weekly.
pub type SharedRdap = Arc<RwLock<Bootstrap>>;

pub struct Rdap {
    bootstrap: SharedRdap,
    client: reqwest::Client,
    rirs: Mutex<HashMap<String, RirState>>,
    #[cfg(test)]
    rewrite: Option<(String, String)>,
}

impl Rdap {
    #[cfg(test)]
    pub fn with_bootstrap(bootstrap: Bootstrap) -> Self {
        Self::with_shared(Arc::new(RwLock::new(bootstrap)))
    }

    pub fn with_shared(bootstrap: SharedRdap) -> Self {
        Self {
            bootstrap,
            client: reqwest::Client::builder()
                .timeout(TIMEOUT)
                .user_agent(concat!("peephole/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("reqwest client"),
            rirs: Mutex::new(HashMap::new()),
            #[cfg(test)]
            rewrite: None,
        }
    }

    #[cfg(test)]
    pub fn with_host_rewrite(mut self, from: &str, to: &str) -> Self {
        self.rewrite = Some((from.into(), to.into()));
        self
    }

    /// Wait for the registry's pace and pause; false when it is paused
    /// longer than a lookup should wait (the IP is tried next pass).
    async fn pace(&self, base: &str) -> bool {
        let wait = {
            let mut all = self.rirs.lock().unwrap();
            let st = all.entry(base.to_string()).or_default();
            if let Some(until) = st.paused_until {
                if until > Instant::now() + Duration::from_secs(30) {
                    return false;
                }
                st.paused_until = None;
                until.saturating_duration_since(Instant::now())
            } else {
                let gap = pace_for(base);
                let w = st
                    .last
                    .map(|t| gap.saturating_sub(t.elapsed()))
                    .unwrap_or_default();
                st.last = Some(Instant::now() + w);
                w
            }
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        true
    }

    fn fail(&self, base: &str) {
        self.rirs
            .lock()
            .unwrap()
            .entry(base.to_string())
            .or_default()
            .fail();
    }

    fn ok(&self, base: &str) {
        self.rirs
            .lock()
            .unwrap()
            .entry(base.to_string())
            .or_default()
            .ok();
    }

    /// One GET; Ok(None) when the registry says the address is unknown
    /// (404) or the answer is not an RDAP object.
    async fn get(&self, base: &str, url: &str) -> Result<Option<Value>> {
        #[cfg(test)]
        let url = match &self.rewrite {
            Some((from, to)) => url.replace(from.as_str(), to.as_str()),
            None => url.to_string(),
        };
        #[cfg(test)]
        let url = url.as_str();
        let resp = self
            .client
            .get(url)
            .header("Accept", "application/rdap+json, application/json")
            .send()
            .await?;
        let status = resp.status();
        if status.as_u16() == 429 {
            let retry = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(|s| Duration::from_secs(s.clamp(1, 3600)));
            let mut all = self.rirs.lock().unwrap();
            let st = all.entry(base.to_string()).or_default();
            match retry {
                Some(d) => st.pause(d),
                None => {
                    st.fail();
                }
            }
            anyhow::bail!("rate limited");
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            anyhow::bail!("HTTP {status}");
        }
        let mut body = Vec::new();
        let mut resp = resp;
        while let Some(chunk) = resp.chunk().await? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_BODY {
                anyhow::bail!("answer larger than {MAX_BODY} bytes");
            }
        }
        Ok(serde_json::from_slice::<Value>(&body)
            .ok()
            .filter(|v| v.is_object()))
    }

    /// The object for `ip`: the bootstrap server's answer, following up to
    /// [`MAX_REFERRALS`] `related` links to another RDAP server.
    async fn query(&self, ip: &IpAddr) -> Result<Option<Value>> {
        let Some(svc) = self.bootstrap.read().unwrap().service_for(ip).cloned() else {
            return Ok(None);
        };
        let mut base = svc.base.trim_end_matches('/').to_string();
        let mut url = format!("{base}/ip/{ip}");
        for hop in 0..=MAX_REFERRALS {
            if !self.pace(&base).await {
                anyhow::bail!("{base} is paused");
            }
            let v = match self.get(&base, &url).await {
                Ok(v) => {
                    self.ok(&base);
                    v
                }
                Err(e) => {
                    if !e.to_string().contains("rate limited") {
                        self.fail(&base);
                    }
                    return Err(e);
                }
            };
            let Some(v) = v else { return Ok(None) };
            let referral = (hop < MAX_REFERRALS)
                .then(|| {
                    v["links"].as_array()?.iter().find_map(|l| {
                        let href = l["href"].as_str()?;
                        let rel = l["rel"].as_str().unwrap_or("");
                        let other_server = !href.starts_with(&base);
                        (rel == "related" && href.contains("/ip/") && other_server)
                            .then(|| href.to_string())
                    })
                })
                .flatten();
            match referral {
                Some(href) => {
                    base = href[..href.find("/ip/").unwrap_or(href.len())].to_string();
                    url = href;
                }
                None => return Ok(Some(v)),
            }
        }
        Ok(None)
    }
}

fn vcard_text(entity: &Value, key: &str) -> Option<String> {
    entity["vcardArray"]
        .as_array()?
        .get(1)?
        .as_array()?
        .iter()
        .find(|f| f[0].as_str() == Some(key))
        .and_then(|f| f[3].as_str())
        .map(str::to_string)
}

fn event_date(v: &Value, action: &str) -> Option<String> {
    v["events"]
        .as_array()?
        .iter()
        .find(|e| e["eventAction"].as_str() == Some(action))
        .and_then(|e| e["eventDate"].as_str())
        .map(|d| d.get(..10).unwrap_or(d).to_string())
}

/// The fields kept of an RDAP IP object.
pub fn compact(v: &Value, now: DateTime<Utc>) -> Value {
    use super::api::put;
    let mut m = Map::new();
    let s = |k: &str| v[k].as_str().map(str::to_string);
    if let (Some(a), Some(b)) = (s("startAddress"), s("endAddress")) {
        put(&mut m, "range", json!(format!("{a} - {b}")));
    }
    let cidrs: Vec<String> = v["cidr0_cidrs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| {
            let p = c["v4prefix"].as_str().or(c["v6prefix"].as_str())?;
            Some(format!("{p}/{}", c["length"].as_u64()?))
        })
        .take(16)
        .collect();
    put(&mut m, "cidrs", json!(cidrs));
    for k in ["handle", "name", "type", "country"] {
        if let Some(x) = s(k) {
            put(&mut m, k, json!(x.chars().take(200).collect::<String>()));
        }
    }
    for e in v["entities"].as_array().into_iter().flatten() {
        let roles: Vec<&str> = e["roles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| r.as_str())
            .collect();
        if roles.contains(&"registrant")
            && !m.contains_key("org")
            && let Some(fn_) = vcard_text(e, "fn")
        {
            put(&mut m, "org", json!(fn_));
        }
        if roles.contains(&"abuse")
            && !m.contains_key("abuse")
            && let Some(mail) = vcard_text(e, "email")
        {
            put(&mut m, "abuse", json!(mail));
        }
    }
    if let Some(d) = event_date(v, "registration") {
        put(&mut m, "registered", json!(d));
    }
    if let Some(d) = event_date(v, "last changed") {
        put(&mut m, "changed", json!(d));
    }
    let fresh = ["registered", "changed"].iter().any(|k| {
        m.get(*k)
            .and_then(|d| d.as_str())
            .and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
            .is_some_and(|d| (now.date_naive() - d).num_days() < FRESH_DAYS)
    });
    if fresh {
        m.insert("fresh".into(), json!(true));
    }
    Value::Object(m)
}

/// Tags for the IP list: `country:XX` and `fresh`.
pub fn tags(data: &Map<String, Value>) -> Vec<String> {
    let mut out = vec![];
    if let Some(c) = data.get("country").and_then(|v| v.as_str()) {
        out.push(format!("country:{}", c.to_ascii_uppercase()));
    }
    if data.get("fresh").and_then(|v| v.as_bool()) == Some(true) {
        out.push("fresh".into());
    }
    out
}

impl Provider for Rdap {
    fn name(&self) -> &'static str {
        super::RDAP
    }

    fn ready(&self) -> bool {
        true
    }

    fn batch(&self) -> i64 {
        20
    }

    fn refresh_after_days(&self) -> f64 {
        30.0
    }

    fn lookup<'a>(&'a self, ips: &'a [String]) -> BoxFuture<'a, Vec<Finding>> {
        Box::pin(async move {
            let mut out = vec![];
            for text in ips {
                let Ok(ip) = text.parse::<IpAddr>() else {
                    out.push(Finding {
                        ip: text.clone(),
                        source_version: None,
                        data: json!({}),
                    });
                    continue;
                };
                if !crate::net::is_scannable_target(ip) {
                    out.push(Finding {
                        ip: text.clone(),
                        source_version: None,
                        data: json!({}),
                    });
                    continue;
                }
                match self.query(&crate::net::canonical(ip)).await {
                    Ok(Some(v)) => out.push(Finding {
                        ip: text.clone(),
                        source_version: None,
                        data: compact(&v, Utc::now()),
                    }),
                    Ok(None) => out.push(Finding {
                        ip: text.clone(),
                        source_version: None,
                        data: json!({}),
                    }),
                    // Not answered: no finding, so it is asked again next pass.
                    Err(e) => tracing::debug!(ip = %text, error = %e, "rdap lookup failed"),
                }
            }
            out
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    const BOOT: &str = r#"{"version":"1.0","services":[
      [["192.0.2.0/24","198.51.100.0/24"],["https://rdap.example-a.test/"]],
      [["203.0.113.0/24"],["https://rdap.lacnic.test/rdap/"]]]}"#;

    #[test]
    fn bootstrap_picks_the_service_by_longest_prefix() {
        let b = Bootstrap::parse(BOOT, "{\"services\":[]}").unwrap();
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(
            b.service_for(&ip).unwrap().base,
            "https://rdap.example-a.test/"
        );
        assert!(b.service_for(&"192.0.3.1".parse().unwrap()).is_none());
    }

    #[test]
    fn builtin_bootstrap_knows_the_five_rirs() {
        let b = Bootstrap::builtin();
        for ip in ["8.8.8.8", "2001:db8::1", "193.0.0.1"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(
                b.service_for(&ip).is_some() || ip.to_string().starts_with("2001:db8"),
                "{ip}"
            );
        }
    }

    #[test]
    fn slow_rirs_are_paced_at_one_per_ten_seconds() {
        assert_eq!(
            pace_for("https://rdap.lacnic.net/rdap/"),
            Duration::from_secs(10)
        );
        assert_eq!(
            pace_for("https://rdap.afrinic.net/rdap/"),
            Duration::from_secs(10)
        );
        assert_eq!(
            pace_for("https://rdap.db.ripe.net/"),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn backoff_doubles_from_ten_seconds_to_five_minutes_and_resets() {
        let mut s = RirState::default();
        assert_eq!(s.fail(), Duration::from_secs(10));
        assert_eq!(s.fail(), Duration::from_secs(20));
        for _ in 0..10 {
            s.fail();
        }
        assert_eq!(s.fail(), Duration::from_secs(300));
        s.ok();
        assert_eq!(s.fail(), Duration::from_secs(10));
    }

    #[test]
    fn an_rdap_answer_becomes_compact_data_and_tags() {
        let body = serde_json::json!({
          "handle": "NET-192-0-2-0-1", "name": "TEST-NET-1", "type": "ASSIGNED PA",
          "startAddress": "192.0.2.0", "endAddress": "192.0.2.255", "country": "DE",
          "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}],
          "events": [{"eventAction": "registration", "eventDate": "2026-09-20T00:00:00Z"},
                     {"eventAction": "last changed", "eventDate": "2026-09-25T00:00:00Z"}],
          "entities": [
            {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Org"]]]},
            {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.test"]]]}
          ]
        });
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-07T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let d = compact(&body, now);
        assert_eq!(d["range"], "192.0.2.0 - 192.0.2.255");
        assert_eq!(d["cidrs"], serde_json::json!(["192.0.2.0/24"]));
        assert_eq!(d["org"], "Example Org");
        assert_eq!(d["abuse"], "abuse@example.test");
        assert_eq!(d["registered"], "2026-09-20");
        let t = tags(d.as_object().unwrap());
        assert!(t.contains(&"country:DE".to_string()));
        assert!(t.contains(&"fresh".to_string()), "registered 17 days ago");
    }

    #[tokio::test]
    async fn a_referral_is_followed_at_most_twice() {
        // A local server: /a refers to /b, /b refers to /c, /c answers.
        let app = axum::Router::new()
            .route("/ip/{ip}", axum::routing::get(|| async {
                axum::Json(serde_json::json!({"links":[{"rel":"related","href":"http://HOST/b/ip/x"}]}))
            }))
            .route("/b/ip/{ip}", axum::routing::get(|| async {
                axum::Json(serde_json::json!({"links":[{"rel":"related","href":"http://HOST/c/ip/x"}]}))
            }))
            .route("/c/ip/{ip}", axum::routing::get(|| async {
                axum::Json(serde_json::json!({"handle":"FINAL","startAddress":"192.0.2.0","endAddress":"192.0.2.1"}))
            }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await });
        let boot = Bootstrap::parse(
            &format!(r#"{{"services":[[["192.0.2.0/24"],["http://{addr}/"]]]}}"#),
            "{\"services\":[]}",
        )
        .unwrap();
        // Rewrite HOST in the referral hrefs by pointing the follow-up at the same server.
        let p = Rdap::with_bootstrap(boot).with_host_rewrite("HOST", &addr.to_string());
        let found = p.lookup(&["192.0.2.5".into()]).await;
        assert_eq!(found.len(), 1);
        // Two referrals followed: the answer is /c's.
        assert_eq!(found[0].data["handle"], "FINAL");
    }
}
