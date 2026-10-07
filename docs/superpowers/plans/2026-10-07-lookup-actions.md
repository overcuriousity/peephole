# Lookup Actions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Admin › Lookup an analyst's page: free RDAP for every address, a paid observational probe of already-open ports (single scanner or N vantages with a diff and a light-speed RTT check), a cheap-first lookup that offers the expensive providers with prices, and domain lookups resolved by several nodes with a per-address majority.

**Architecture:** A probe is an RPC (`/rpc/v1/probe`) paid with the existing `credit_offer`/`credit_receipt` flow; its result is a replicated `probe_result` record applied to local `probes`/`probe_ports` tables, and its hashes and keys land in `host_keys` (with a `probe_id`) so Links needs no second table. A vantage request is N offers to N scanners sharing one `group` uid. A domain lookup is a free RPC (`/rpc/v1/resolve`) asked of up to 5 nodes whose votes are replicated as an `ip_name` record. The peer-observed public address (scan-details spec §1) is carried in the `hello` answer and feeds the safety list, the heartbeat and each probe's `vantage_ip`.

**Tech Stack:** Rust 2024, tokio, axum 0.8, sqlx/SQLite, askama, reqwest (rustls), tokio-rustls/rustls 0.23, x509-parser, aws-lc-rs (X25519, SHA-256), md-5, serde/ciborium (CBOR). No new crates.

**Spec:** `docs/superpowers/specs/2026-10-07-lookup-actions-design.md` (and `docs/superpowers/specs/2026-10-06-scan-details-design.md` §1 for the public address).

## Global Constraints

- No new dependencies. JARM is raw ClientHello bytes; the SSH key exchange uses `aws_lc_rs::agreement::X25519`; MurmurHash3 (favicon `mmh3`) is implemented in-tree (32-bit, seed 0, over the base64 text of the favicon as Shodan does).
- Schema changes are a new migration file only (`src/store/migrations/0018_probes.sql`), appended to `MIGRATIONS`; never edit a shipped one. No `;` inside statements.
- Every record field added to an existing struct is `#[serde(default)]` (and `skip_serializing_if` when optional) so older peers decode and older signed entries rebuild byte for byte.
- Probe touches only ports the address's latest counter-scan found `open`; at most 16 ports; 10 s per connection; 120 s per probe; 256 KiB per response; 100 KiB per favicon; `[probe] max_parallel` (default 2) at once per scanner; one probe per address per scanner per 24 h.
- Redirects: at most 5 hops, one `GET` per hop, every hop target checked against the safety lists and private/loopback/link-local space; a hit is recorded as "skipped (protected)" and ends the chain; the target is never probed further.
- Gating: `Evidence::allowed_level >= 2`, no safety list hit (`never_scan`, members' and own addresses, peer-observed public addresses, Tor exits, verified crawlers), at least one open port in the latest scan.
- Probe price = `price::price("probe", unit, surge)` with `weight_milli("probe") == 4000`; announced as `Heartbeat.probe_price_mc: Option<u32>`; a probe mints nothing, counts toward no pace, is not audited, has no free quota; standalone runs probes without credits.
- Cheap tier = providers with `weight_milli <= 250`; a lookup runs stored results + the cheap tier by itself and offers the rest with prices.
- Domains: ≤ 253 chars, hostname syntax, punycode+lowercase; up to 5 resolvers preferring non-siblings and distinct countries; per-address majority (> half of those that answered); 2 responders → both; 1 → "unverified"; private/loopback/link-local answers dropped; at most 16 agreed addresses followed; only agreed addresses carry the name into the dataset/export.
- Admin-only everywhere: the public IP page renders neither the Actions card nor the Probes section nor disputed names.
- Copy: probes are "observational"; the README rule "escalate by scope, never by speed or aggressiveness" is reworded to say it governs counter-scans.
- Dates in rows are UTC `YYYY-MM-DD HH:MM:SS` (`store::data::now_ts()`); uids are `store::data::new_uid()`.
- Build: `cargo` is on PATH via the `peephole-build-env` memory; run `cargo test <filter>` for focused tests and prune `target/` before a full run (the disk is 43 GB).

## Review Focus

1. **A redirect to a member or to RFC1918 space** — the hop must be recorded as "skipped (protected)" and nothing connects to it. Pinned in Task 6 (`a_hop_to_protected_space_is_skipped`).
2. **A service that never closes the connection** (keeps sending bytes under the cap, or sends nothing) — the per-connection 10 s and per-probe 120 s caps must end it and the port is recorded as `timeout`, the rest of the probe still runs. Pinned in Task 6 (`a_slow_port_times_out_and_the_probe_continues`).
3. **A scanner that accepts an offer and dies** — the asker must show "lapsed, nothing charged" after 15 min, never "running" forever, and the next probe of the same address is allowed. Pinned in Task 8 (`an_accepted_probe_without_a_result_lapses`).
4. **A domain whose resolvers all fail or time out** — the lookup page must say so and store nothing (no `ip_name` record with zero answers). Pinned in Task 12 (`no_answer_at_all_writes_no_record`).
5. **An `ip_name` record from a peer naming a resolver that never answered or an address outside global unicast** — the vote is re-derived locally and such answers are dropped, so a peer cannot inject a name onto an arbitrary address with a forged tally. Pinned in Task 12 (`votes_are_derived_locally_not_trusted`).

---

## File structure

New files:

- `src/intel/rdap.rs` — RDAP provider: bootstrap, per-RIR pacing/backoff, query with ≤ 2 referrals, JSON → compact data, tags.
- `src/intel/rdap/ipv4.json`, `src/intel/rdap/ipv6.json` — built-in IANA bootstrap (fetched once at implementation time).
- `src/intel/dns.rs` — hostname validation, resolver choice, voting, `IpNameRec` building.
- `src/scan/probe/mod.rs` — `ProbeConfig`, port/record types, the runner (`run_probe`), caps, RTT.
- `src/scan/probe/http.rs` — HTTP(S) reads, redirect chain, favicon hashes, mmh3.
- `src/scan/probe/tls.rs` — TLS handshake capture (chain, version, ALPN).
- `src/scan/probe/jarm.rs` — the ten raw ClientHellos and the JARM hash.
- `src/scan/probe/ssh.rs` — banner, KEXINIT/HASSH, host key via X25519 `KEX_ECDH_INIT`.
- `src/scan/probe/gate.rs` — gating (evidence, safety, open ports, 24 h, slots).
- `src/scan/probe/serve.rs` — `/rpc/v1/probe` server side, two-phase answer, result + receipt append; standalone runner.
- `src/scan/probe/ask.rs` — asker: N offers, N calls, group uid.
- `src/store/probes.rs` — apply `probe_result`, read probes per IP, group views, 24 h check.
- `src/store/migrations/0018_probes.sql` — `probes`, `probe_ports`, `host_keys` rebuild with nullable `scan_id` + `probe_id`, `ip_names`.
- `src/admin/probes.rs` — Actions card data, `POST /admin/lookup/probe`, probes section views, diff, RTT verdicts, SSE stream.
- `templates/_actions.html`, `templates/_probes.html`, `templates/_names.html`.

Modified files (by task): `src/intel/mod.rs`, `src/intel/geo.rs`, `src/intel/lookup.rs`, `src/credits/price.rs`, `src/credits/pay.rs`, `src/cluster/record.rs`, `src/cluster/rpc/mod.rs`, `src/cluster/rpc/proto.rs`, `src/cluster/sync.rs`, `src/cluster/status.rs`, `src/cluster/mod.rs`, `src/scan/safety.rs`, `src/scan/mod.rs`, `src/store/mod.rs`, `src/store/data.rs`, `src/store/hostkeys.rs`, `src/store/links.rs`, `src/store/export.rs`, `src/config.rs`, `src/admin/mod.rs`, `src/admin/lookup.rs`, `src/admin/search.rs`, `src/admin/target.rs`, `src/admin/system.rs`, `src/lib.rs`, `templates/admin_lookup.html`, `templates/_admin_nav.html`, `templates/layout.html`, `templates/_target.html`, `templates/_host_keys.html`, `templates/admin_system.html`, `assets/js/app.js`, `README.md`, `docs/cluster.md`, `docs/dataset.md`, `docs/roadmap.md`, `docs/operations.md`.

Task order: 1 RDAP → 2 public address → 3 coordinates → 4 schema + records → 5 probe readers → 6 probe runner → 7 price + gate + serve + ask → 8 links kinds → 9 lookup page → 10 actions + probes UI → 11 vantage diff + RTT → 12 domains → 13 docs. Tasks 1, 2, 3 are independent of each other; everything from 4 on is sequential.

---

### Task 1: RDAP provider

**Files:**
- Create: `src/intel/rdap.rs`, `src/intel/rdap/ipv4.json`, `src/intel/rdap/ipv6.json`
- Modify: `src/intel/mod.rs` (constants, `KNOWN_PROVIDERS`, `tags`, `providers`, scheduler), `src/credits/price.rs:21-27` (`weight_milli`), `src/admin/public.rs` (facts for the card)

**Interfaces:**
- Produces: `intel::RDAP: &str = "rdap"`; `intel::rdap::Rdap` implementing `Provider` (`name() == "rdap"`, `weight_milli == 0`, `refresh_after_days() == 30.0`, `batch() == 20`); `intel::rdap::Bootstrap::{builtin, load(data_dir), refresh(data_dir)}`; `intel::rdap::tags(&Map) -> Vec<String>`; `data_json` keys `range, cidrs, handle, name, type, country, org, abuse, registered, changed`.

- [ ] **Step 1: Fetch the IANA bootstrap files into the tree**

```bash
mkdir -p src/intel/rdap
curl -sSf https://data.iana.org/rdap/ipv4.json -o src/intel/rdap/ipv4.json
curl -sSf https://data.iana.org/rdap/ipv6.json -o src/intel/rdap/ipv6.json
python3 -I -c "import json,sys; [json.load(open(f)) for f in sys.argv[1:]]" src/intel/rdap/ipv4.json src/intel/rdap/ipv6.json && echo ok
```

- [ ] **Step 2: Write the failing tests** (bottom of `src/intel/rdap.rs`; create the file with only the tests module and `use` lines first)

```rust
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
        assert_eq!(b.service_for(&ip).unwrap().base, "https://rdap.example-a.test/");
        assert!(b.service_for(&"192.0.3.1".parse().unwrap()).is_none());
    }

    #[test]
    fn builtin_bootstrap_knows_the_five_rirs() {
        let b = Bootstrap::builtin();
        for ip in ["8.8.8.8", "2001:db8::1", "193.0.0.1"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(b.service_for(&ip).is_some() || ip.to_string().starts_with("2001:db8"), "{ip}");
        }
    }

    #[test]
    fn slow_rirs_are_paced_at_one_per_ten_seconds() {
        assert_eq!(pace_for("https://rdap.lacnic.net/rdap/"), Duration::from_secs(10));
        assert_eq!(pace_for("https://rdap.afrinic.net/rdap/"), Duration::from_secs(10));
        assert_eq!(pace_for("https://rdap.db.ripe.net/"), Duration::from_secs(1));
    }

    #[test]
    fn backoff_doubles_from_ten_seconds_to_five_minutes_and_resets() {
        let mut s = RirState::default();
        assert_eq!(s.fail(), Duration::from_secs(10));
        assert_eq!(s.fail(), Duration::from_secs(20));
        for _ in 0..10 { s.fail(); }
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
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-07T00:00:00Z").unwrap().with_timezone(&chrono::Utc);
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
        tokio::spawn(axum::serve(l, app));
        let boot = Bootstrap::parse(
            &format!(r#"{{"services":[[["192.0.2.0/24"],["http://{addr}/"]]]}}"#),
            "{\"services\":[]}",
        ).unwrap();
        // Rewrite HOST in the referral hrefs by pointing the follow-up at the same server.
        let p = Rdap::with_bootstrap(boot).with_host_rewrite("HOST", &addr.to_string());
        let found = p.lookup(&["192.0.2.5".into()]).await;
        assert_eq!(found.len(), 1);
        // Two referrals followed: the answer is /c's.
        assert_eq!(found[0].data["handle"], "FINAL");
    }
}
```

The `with_host_rewrite` helper is test-only (`#[cfg(test)]`): it replaces `HOST` in referral hrefs with the test server address.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test intel::rdap -- --nocapture`
Expected: compile errors (`Bootstrap`, `Rdap`, `compact`, `tags`, `pace_for`, `RirState` undefined).

- [ ] **Step 4: Implement `src/intel/rdap.rs`**

```rust
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
        Self::parse(include_str!("rdap/ipv4.json"), include_str!("rdap/ipv6.json"))
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
                let Some(base) = svc[1].as_array().and_then(|u| u.iter().find_map(|u| u.as_str()))
                else {
                    continue;
                };
                // Prefer https when the list offers both.
                let base = svc[1]
                    .as_array()
                    .and_then(|u| u.iter().find_map(|u| u.as_str().filter(|s| s.starts_with("https://"))))
                    .unwrap_or(base);
                services.push(Service { base: base.to_string(), nets });
            }
        }
        Ok(Self { services })
    }

    /// The bootstrap in `data_dir` when fresh, else the built-in one.
    pub fn load(data_dir: &Path) -> Self {
        let (v4, v6) = (data_dir.join("rdap-ipv4.json"), data_dir.join("rdap-ipv6.json"));
        let fresh = |p: &PathBuf| {
            std::fs::metadata(p)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age < BOOTSTRAP_MAX_AGE)
        };
        if fresh(&v4) && fresh(&v6)
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
        for (url, name) in [(BOOTSTRAP_V4_URL, "rdap-ipv4.json"), (BOOTSTRAP_V6_URL, "rdap-ipv6.json")] {
            let body = client.get(url).send().await?.error_for_status()?.text().await?;
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
        let wait = Duration::from_secs(10 << (self.failures - 1).min(5)).min(Duration::from_secs(300));
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

pub struct Rdap {
    bootstrap: Arc<RwLock<Bootstrap>>,
    client: reqwest::Client,
    rirs: Mutex<HashMap<String, RirState>>,
    #[cfg(test)]
    rewrite: Option<(String, String)>,
}

impl Rdap {
    pub fn new(data_dir: &Path) -> Self {
        Self::with_bootstrap(Bootstrap::load(data_dir))
    }

    pub fn with_bootstrap(bootstrap: Bootstrap) -> Self {
        Self {
            bootstrap: Arc::new(RwLock::new(bootstrap)),
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

    /// Swap in a refreshed bootstrap (the scheduler calls this weekly).
    pub fn set_bootstrap(&self, b: Bootstrap) {
        *self.bootstrap.write().unwrap() = b;
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
                let w = st.last.map(|t| gap.saturating_sub(t.elapsed())).unwrap_or_default();
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
        self.rirs.lock().unwrap().entry(base.to_string()).or_default().fail();
    }

    fn ok(&self, base: &str) {
        self.rirs.lock().unwrap().entry(base.to_string()).or_default().ok();
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
        Ok(serde_json::from_slice::<Value>(&body).ok().filter(|v| v.is_object()))
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
                        (rel == "related" && href.contains("/ip/") && other_server).then(|| href.to_string())
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
        let roles: Vec<&str> = e["roles"].as_array().into_iter().flatten().filter_map(|r| r.as_str()).collect();
        if roles.contains(&"registrant") && !m.contains_key("org") {
            if let Some(fn_) = vcard_text(e, "fn") {
                put(&mut m, "org", json!(fn_));
            }
        }
        if roles.contains(&"abuse") && !m.contains_key("abuse") {
            if let Some(mail) = vcard_text(e, "email") {
                put(&mut m, "abuse", json!(mail));
            }
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
                    out.push(Finding { ip: text.clone(), source_version: None, data: json!({}) });
                    continue;
                };
                if !crate::net::is_scannable_target(ip) {
                    out.push(Finding { ip: text.clone(), source_version: None, data: json!({}) });
                    continue;
                }
                match self.query(&crate::net::canonical(ip)).await {
                    Ok(Some(v)) => out.push(Finding {
                        ip: text.clone(),
                        source_version: None,
                        data: compact(&v, Utc::now()),
                    }),
                    Ok(None) => out.push(Finding { ip: text.clone(), source_version: None, data: json!({}) }),
                    // Not answered: no finding, so it is asked again next pass.
                    Err(e) => tracing::debug!(ip = %text, error = %e, "rdap lookup failed"),
                }
            }
            out
        })
    }
}
```

- [ ] **Step 5: Register the provider**

In `src/intel/mod.rs`: add `pub mod rdap;`, `pub const RDAP: &str = "rdap";`, a `KNOWN_PROVIDERS` entry `ProviderInfo { name: RDAP, label: "RDAP registry", public: false, api: true, tag_prefix: "rdap", redistributable: false }` (`api: true` so every lookup is recorded and refreshed after 30 days), `RDAP => rdap::tags(data)` in `tags()`, and in `providers()` push `Arc::new(rdap::Rdap::new(&cfg.data_dir))` right after `TorExits` (change the `skip(2)` in the "API providers configured" log to `skip(3)`).

In `src/credits/price.rs` `weight_milli`: `intel::TOR | intel::RDAP => 0`.

In `src/admin/public.rs` where provider facts are labelled (the `facts_of`/match on provider name), add RDAP labels: `range → "Range"`, `cidrs → "CIDRs"`, `handle → "Handle"`, `name → "Name"`, `type → "Type"`, `country → "Country"`, `org → "Registrant"`, `abuse → "Abuse contact"`, `registered → "Registered"`, `changed → "Last changed"`, `fresh → "Fresh block"`. (Unknown keys already fall through to a generic listing; this only prettifies.)

In `run_scheduler` (standalone) and `run_cluster` (cluster): once at startup and then weekly, `rdap::Bootstrap::refresh(&cfg.data_dir)` with the Tor backoff on failure; after a success, find the RDAP provider and `set_bootstrap(Bootstrap::load(&cfg.data_dir))`. The scheduler does not hold the providers; add `pub fn rdap_provider(providers: &Providers) -> Option<Arc<Rdap>>`? Providers are `Arc<dyn Provider>` — instead keep a `SharedRdapBootstrap = Arc<RwLock<Bootstrap>>` created in `lib.rs`, passed to both `providers()` (so `Rdap::with_shared(boot)`) and `run_scheduler`. Add that parameter to `providers()` and `run_scheduler`/`run_cluster` and update their callers in `src/lib.rs` and tests.

- [ ] **Step 6: Run the tests**

Run: `cargo test intel::rdap && cargo test price::`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/intel/rdap.rs src/intel/rdap src/intel/mod.rs src/credits/price.rs src/admin/public.rs src/lib.rs
git commit -m "Intel: RDAP registry provider (free, per-RIR paced, weekly bootstrap)"
```

---

### Task 2: Peer-observed public address (scan-details spec §1)

**Files:**
- Modify: `src/cluster/rpc/proto.rs:15-22` (`Hello`), `src/cluster/rpc/mod.rs:304-313` (`hello` handler), `src/cluster/sync.rs:278` (client), `src/cluster/status.rs` (observations, `Heartbeat.public_addrs`), `src/cluster/mod.rs` (`refresh_heartbeat`, `local_hello`), `src/scan/safety.rs:66-80` (own addresses), `src/admin/system.rs` + `templates/admin_system.html` ("Public address (seen by peers)")

**Interfaces:**
- Produces: `Hello.seen_from: Option<IpAddr>`; `Status::note_seen_from(&self, reporter: NodeId, sibling: bool, ip: IpAddr)`; `Status::public_addresses(&self) -> Vec<IpAddr>` (taken ones, newest confirmation first); `Status::seen_from_report(&self) -> Vec<(IpAddr, Vec<(NodeId, bool)>, bool)>` for the page; `Heartbeat.public_addrs: Vec<IpAddr>`; `Node::public_addrs(&self) -> Vec<IpAddr>`.

**Deviation from the scan-details spec, stated here so nobody "fixes" it:** a node knows its own siblings (`siblings` table) but not which *other* members share an owner. "Two members of different owners" is therefore implemented as **"two distinct reporting members that are not both this node's siblings"** — one sibling alone is enough, two strangers are enough; one stranger is not.

- [ ] **Step 1: Write the failing tests** (in `src/cluster/status.rs` tests)

```rust
#[test]
fn one_stranger_is_not_believed_but_a_sibling_or_two_strangers_are() {
    let st = Status::default();
    let ip: IpAddr = "203.0.113.9".parse().unwrap();
    st.note_seen_from(NodeId([1; 32]), false, ip);
    assert!(st.public_addresses().is_empty(), "one stranger");
    st.note_seen_from(NodeId([2; 32]), false, ip);
    assert_eq!(st.public_addresses(), vec![ip], "two strangers");
    let st = Status::default();
    st.note_seen_from(NodeId([3; 32]), true, ip);
    assert_eq!(st.public_addresses(), vec![ip], "one sibling");
}

#[test]
fn private_and_mapped_reports_are_ignored_and_old_ones_expire() {
    let st = Status::default();
    for bad in ["10.1.2.3", "127.0.0.1", "fe80::1", "::ffff:10.0.0.1"] {
        st.note_seen_from(NodeId([3; 32]), true, bad.parse().unwrap());
    }
    assert!(st.public_addresses().is_empty());
    let ip: IpAddr = "198.51.100.4".parse().unwrap();
    st.note_seen_from(NodeId([3; 32]), true, ip);
    st.age_seen_from(SEEN_FROM_TTL + Duration::from_secs(1)); // test hook: shifts every report back
    assert!(st.public_addresses().is_empty(), "unconfirmed for 7 days");
}
```

And in `src/scan/safety.rs` tests: `taken_public_addresses_are_own_addresses` — build a `Node` is heavy; instead give `Safety::refresh` its public addresses through a new `pub fn add_public(&mut self, addrs: &[IpAddr])` called from `refresh` with `node.status.public_addresses()`, and test `add_public` + `refuses` directly:

```rust
#[tokio::test]
async fn peer_observed_public_addresses_are_refused_like_own_ones() {
    let cfg = config_with(...); // the existing helper of this test module
    let mut s = Safety::new(&cfg);
    s.refresh(&cfg, None).await;
    let ip: IpAddr = "203.0.113.77".parse().unwrap();
    assert!(s.refuses(&ip).is_none());
    s.add_public(&[ip]);
    assert_eq!(s.refuses(&ip).as_deref(), Some("this node's own address"));
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test cluster::status::tests::one_stranger && cargo test scan::safety::tests::peer_observed`
Expected: compile errors.

- [ ] **Step 3: Implement**

`src/cluster/rpc/proto.rs`:
```rust
pub struct Hello {
    pub proto_min: u32,
    pub proto_max: u32,
    pub node_name: String,
    pub version: String,
    pub roles: Vec<String>,
    /// The address the caller's connection came from, as this server saw
    /// it. Older peers send none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_from: Option<std::net::IpAddr>,
}
```
`local_hello()` sets `seen_from: None`. The `hello` handler in `rpc/mod.rs` takes `Extension(server::RemoteAddr(addr)): Extension<server::RemoteAddr>` and answers `Hello { seen_from: Some(addr.ip()), ..ours }` (both arms). `RemoteAddr` already honours `trusted_proxies` where the RPC server sets it; if it does not (check `rpc/server.rs`), leave it: RPC runs mutual TLS end to end and is not proxied.

`src/cluster/status.rs`:
```rust
/// A report no peer repeated for this long is dropped.
pub const SEEN_FROM_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

pub struct Status {
    // ... existing fields ...
    /// Addresses peers saw this node connect from: per address, who
    /// reported it (and whether that peer is a sibling) and when last.
    seen_from: Mutex<HashMap<IpAddr, HashMap<NodeId, (bool, Instant)>>>,
}

impl Status {
    pub fn note_seen_from(&self, reporter: NodeId, sibling: bool, ip: IpAddr) {
        let ip = crate::net::canonical(ip);
        if !crate::net::is_scannable_target(ip) {
            return; // private, loopback, link-local: a LAN or tunnel view
        }
        let mut all = self.seen_from.lock().unwrap();
        all.entry(ip).or_default().insert(reporter, (sibling, Instant::now()));
    }

    fn taken(reports: &HashMap<NodeId, (bool, Instant)>) -> bool {
        let live: Vec<_> = reports.values().filter(|(_, t)| t.elapsed() < SEEN_FROM_TTL).collect();
        live.iter().any(|(s, _)| *s) || live.len() >= 2
    }

    /// This node's public addresses: reported by a sibling, or by two
    /// members. Newest confirmation first.
    pub fn public_addresses(&self) -> Vec<IpAddr> {
        let mut all = self.seen_from.lock().unwrap();
        all.retain(|_, r| {
            r.retain(|_, (_, t)| t.elapsed() < SEEN_FROM_TTL);
            !r.is_empty()
        });
        let mut v: Vec<(Instant, IpAddr)> = all
            .iter()
            .filter(|(_, r)| Self::taken(r))
            .map(|(ip, r)| (r.values().map(|(_, t)| *t).max().unwrap(), *ip))
            .collect();
        v.sort_by(|a, b| b.0.cmp(&a.0));
        v.into_iter().map(|(_, ip)| ip).collect()
    }

    /// Every reported address with its reporters and whether it is taken.
    pub fn seen_from_report(&self) -> Vec<(IpAddr, Vec<(NodeId, bool)>, bool)> { /* map over seen_from */ }

    #[cfg(test)]
    pub fn age_seen_from(&self, by: Duration) {
        for r in self.seen_from.lock().unwrap().values_mut() {
            for (_, t) in r.values_mut() { *t = t.checked_sub(by).unwrap_or(*t); }
        }
    }
}
```
`Heartbeat` gains `#[serde(default)] pub public_addrs: Vec<IpAddr>`; `refresh_heartbeat` fills it from `self.status.public_addresses()`; the two `Heartbeat { .. }` literals in `repl.rs` tests get `public_addrs: vec![]`. Add `Node::public_addrs(&self) -> Vec<IpAddr> { self.status.public_addresses() }`.

`src/cluster/sync.rs` after `let h = node.hello(peer, addr).await?;`:
```rust
if let Some(ip) = h.seen_from {
    let sibling = crate::cluster::owner::fleet::siblings(&node.store)
        .await
        .map(|s| s.contains(&peer))
        .unwrap_or(false);
    node.status.note_seen_from(peer, sibling, ip);
}
```

`src/scan/safety.rs`: `pub fn add_public(&mut self, addrs: &[IpAddr])` extends `self.own` with canonical addresses; `refresh` calls `self.add_public(&node.status.public_addresses())` inside the `if let Some(node)` block **before** the early `return` on "not due" (so a new address protects at once, like `observed`).

`src/admin/system.rs` + `templates/admin_system.html` "This node" card: a line `Public address (seen by peers): 203.0.113.9 (alice, bob)` per taken address, "none reported" otherwise, "reported by one member, not taken" for untaken ones. Data from `node.status.seen_from_report()` with member names from `node.members()`.

`docs/operations.md:72-77` (`own_addresses` paragraph): add "In a cluster, peers report the address they see this node connect from; once a sibling or two members agree, it is protected like `own_addresses`."

- [ ] **Step 4: Run the tests**

Run: `cargo test cluster::status && cargo test scan::safety && cargo test --test cluster members_greet`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A src/cluster src/scan/safety.rs src/admin/system.rs templates/admin_system.html docs/operations.md
git commit -m "Cluster: peers report the public address they see; taken addresses join the safety list"
```

---

### Task 3: Coordinates from GeoLite2-City

**Files:**
- Modify: `src/intel/geo.rs:6-27,62-80`

**Interfaces:**
- Produces: `Geo { country, asn, asn_org, latitude: Option<f64>, longitude: Option<f64>, accuracy_km: Option<u32> }`; `GeoIp::coords(&self, ip: &IpAddr) -> Option<Coords>` with `pub struct Coords { pub lat: f64, pub lon: f64, pub accuracy_km: u32 }`; `pub fn haversine_km(a: (f64, f64), b: (f64, f64)) -> f64`.

- [ ] **Step 1: Write the failing test** (in `src/intel/geo.rs` tests, next to the existing `GB` test that loads `tests/fixtures/GeoLite2-City-Test.mmdb`)

```rust
#[test]
fn coordinates_come_with_the_country_and_distances_are_sane() {
    let dir = fixtures(); // the existing helper that copies the test mmdbs
    let g = GeoIp::load(dir.path()).unwrap();
    let c = g.coords(&"2.125.160.216".parse().unwrap()).expect("the GB test address has a location");
    assert!((c.lat - 51.75).abs() < 1.0 && (c.lon + 1.25).abs() < 1.0, "{c:?}");
    assert!(c.accuracy_km > 0);
    assert!(g.coords(&"203.0.113.1".parse().unwrap()).is_none());
    // Berlin–Paris is about 880 km.
    let d = haversine_km((52.52, 13.40), (48.86, 2.35));
    assert!((d - 878.0).abs() < 10.0, "{d}");
}
```

- [ ] **Step 2: Run it to verify it fails** — `cargo test intel::geo::tests::coordinates` → compile error.

- [ ] **Step 3: Implement**

```rust
#[derive(serde::Deserialize)]
struct CityRecord {
    country: Option<CountryRecord>,
    location: Option<LocationRecord>,
}
#[derive(serde::Deserialize)]
struct LocationRecord {
    latitude: Option<f64>,
    longitude: Option<f64>,
    accuracy_radius: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Coords {
    pub lat: f64,
    pub lon: f64,
    pub accuracy_km: u32,
}

impl GeoIp {
    pub fn coords(&self, ip: &IpAddr) -> Option<Coords> {
        let rec = self.city.lookup(*ip).ok()?.decode::<CityRecord>().ok().flatten()?;
        let l = rec.location?;
        Some(Coords { lat: l.latitude?, lon: l.longitude?, accuracy_km: l.accuracy_radius.unwrap_or(0) })
    }
}

/// Great-circle distance in km between two (lat, lon) points in degrees.
pub fn haversine_km(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (la1, lo1, la2, lo2) = (a.0.to_radians(), a.1.to_radians(), b.0.to_radians(), b.1.to_radians());
    let h = ((la2 - la1) / 2.0).sin().powi(2) + la1.cos() * la2.cos() * ((lo2 - lo1) / 2.0).sin().powi(2);
    2.0 * 6371.0 * h.sqrt().asin()
}
```
`Geo` itself stays as is (`lookup` keeps decoding `CityRecord`; the new field is simply ignored there). Nothing is stored.

- [ ] **Step 4: Run** `cargo test intel::geo` → PASS. **Step 5: Commit** `git commit -am "Geo: coordinates and accuracy radius from GeoLite2-City"`.

---

### Task 4: Schema, records and the probe store

**Files:**
- Create: `src/store/migrations/0018_probes.sql`, `src/store/probes.rs`
- Modify: `src/store/mod.rs:36-55` (`MIGRATIONS`, `pub mod probes;`), `src/cluster/record.rs` (new records), `src/store/data.rs:63-106` (`apply`, `CONTENT_KINDS`, make `ensure_ip`/`erased_by` `pub(crate)`), `src/store/hostkeys.rs` (kinds, nullable `scan_id`, `probe_id`), `src/scan/hostkeys.rs:13-16` (kind constants), `src/config.rs` (`[probe]`)

**Interfaces:**
- `record.rs`:
```rust
pub struct ProbePortRec { pub port: u16, pub protocol: String /* http|https|ssh|tls|banner */, pub outcome: String /* ok|refused|timeout|error */, pub detail_json: String }
pub struct ProbeResultRec {
    pub uid: String, pub group: String, pub ip: String, pub asker: NodeId,
    pub vantage_ip: Option<IpAddr>, pub vantage_ip_source: String /* public|dialled|local */,
    pub started_at: String, pub finished_at: String, pub rtt_min_ms: Option<u32>,
    pub ports: Vec<ProbePortRec>,
    #[serde(default, skip_serializing_if = "String::is_empty")] pub build: String,
}
pub struct IpNameRec {
    pub uid: String, pub name: String, pub at: String,
    pub answers: Vec<(NodeId, Result<Vec<IpAddr>, String>)>,
    #[serde(default, skip_serializing_if = "String::is_empty")] pub build: String,
}
```
  `Record::ProbeResult(ProbeResultRec)` → kind `"probe_result"`, `Record::IpName(IpNameRec)` → kind `"ip_name"`; both return their uid from `uid()` and are in `CONTENT_KINDS` (size 10). All derives as `ScanResultRec`.
- `store/probes.rs`: `apply_probe_result(conn, ctx, &ProbeResultRec) -> Result<Effect>`; `pub fn keys_of(port: u16, detail: &Value) -> Vec<HostKey>`; `Store::probes_for_ip(ip_id) -> Vec<ProbeRow>`; `Store::probe_ports(probe_id) -> Vec<ProbePortRow>`; `Store::probed_recently(ip: &str, origin: &NodeId, hours: i64) -> Result<bool>`. `ProbeRow { id, uid, group_uid, ip_id, origin: Option<Vec<u8>>, asker: Vec<u8>, vantage_ip: Option<String>, vantage_ip_source, started_at, finished_at, rtt_min_ms: Option<i64> }`, `ProbePortRow { port, protocol, outcome, detail_json }`.
- `scan/hostkeys.rs`: `FAVICON = "favicon"`, `JARM = "jarm"`, `HTTP_BODY = "http-body"`, `HTTP_404 = "http-404"`.
- `store/hostkeys.rs`: `insert_probe_keys(conn, probe_id, ip_id, &[HostKey])`; `HostKeyRow` gains `probe_id: Option<i64>`, `probe_at: Option<String>`; `kind_name` covers the four new kinds; `is_identity` unchanged.
- `config.rs`: `pub probe: ProbeConfig { enabled: bool = true, max_parallel: u32 = 2 }` (`#[serde(default)]` on `Config`), `OPTIONAL_KEYS` rows `("probe","enabled","true")`, `("probe","max_parallel","2")`.
- Detail JSON keys the store reads (written by Task 5): `tls.leaf_sha256`, `tls.subject`, `tls.not_after`, `ssh.host_key_type`, `ssh.host_key_sha256`, `ssh.hassh`, `ssh.kex_algorithms`, `jarm`, `favicon_mmh3`, `favicon_sha256`, `body_sha256`, `body_len`, `not_found.status`, `not_found.body_sha256`.

- [ ] **Step 1: Write the migration** `src/store/migrations/0018_probes.sql`

```sql
-- Observational probes (scan::probe), replicated as probe_result records.
CREATE TABLE probes (
  id INTEGER PRIMARY KEY, uid TEXT NOT NULL UNIQUE, group_uid TEXT NOT NULL,
  ip_id INTEGER NOT NULL REFERENCES ips(id), origin BLOB, hlc INTEGER, asker BLOB NOT NULL,
  vantage_ip TEXT, vantage_ip_source TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL, finished_at TEXT NOT NULL, rtt_min_ms INTEGER,
  build TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_probes_ip ON probes(ip_id, id);
CREATE INDEX idx_probes_group ON probes(group_uid);
CREATE INDEX idx_probes_origin_ip ON probes(origin, ip_id, finished_at);
CREATE TABLE probe_ports (
  id INTEGER PRIMARY KEY, probe_id INTEGER NOT NULL REFERENCES probes(id) ON DELETE CASCADE,
  port INTEGER NOT NULL, protocol TEXT NOT NULL, outcome TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_probe_ports_probe ON probe_ports(probe_id, port);
-- host_keys may come from a probe: rebuild with a nullable scan_id.
CREATE TABLE host_keys_new (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
  probe_id INTEGER REFERENCES probes(id) ON DELETE CASCADE,
  ip_id INTEGER NOT NULL REFERENCES ips(id), port INTEGER NOT NULL,
  kind TEXT NOT NULL, fingerprint TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
  CHECK ((scan_id IS NULL) != (probe_id IS NULL))
);
INSERT INTO host_keys_new (id, scan_id, ip_id, port, kind, fingerprint, detail)
  SELECT id, scan_id, ip_id, port, kind, fingerprint, detail FROM host_keys;
DROP TABLE host_keys;
ALTER TABLE host_keys_new RENAME TO host_keys;
CREATE UNIQUE INDEX idx_host_keys_scan ON host_keys(scan_id, port, kind, fingerprint) WHERE scan_id IS NOT NULL;
CREATE UNIQUE INDEX idx_host_keys_probe ON host_keys(probe_id, port, kind, fingerprint) WHERE probe_id IS NOT NULL;
CREATE INDEX idx_host_keys_fp ON host_keys(kind, fingerprint, ip_id);
CREATE INDEX idx_host_keys_ip ON host_keys(ip_id);
-- Names an admin looked up that resolved to the address (intel::dns).
CREATE TABLE ip_names (
  id INTEGER PRIMARY KEY, ip_id INTEGER NOT NULL REFERENCES ips(id),
  name TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'dns',
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  agreed INTEGER NOT NULL DEFAULT 0, asked INTEGER NOT NULL DEFAULT 0,
  answered INTEGER NOT NULL DEFAULT 0, votes INTEGER NOT NULL DEFAULT 0,
  record_uid TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_ip_names_unique ON ip_names(ip_id, name, source);
CREATE INDEX idx_ip_names_name ON ip_names(name)
```
Run `grep -rn "host_keys" src/store/migrations/*.sql` first: any trigger or view on `host_keys` must be recreated after the rename (none as of 0017). Append the file to `MIGRATIONS`.

- [ ] **Step 2: Write the failing tests** (`src/store/probes.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::NodeId;
    use crate::cluster::record::{ProbePortRec, ProbeResultRec, Record};
    use crate::store::Store;
    use crate::store::data::{Ctx, Effect, apply, new_uid, now_ts};

    fn rec(ip: &str, origin: u8) -> ProbeResultRec {
        ProbeResultRec {
            uid: new_uid(), group: new_uid(), ip: ip.into(), asker: NodeId([origin; 32]),
            vantage_ip: Some("198.51.100.1".parse().unwrap()), vantage_ip_source: "public".into(),
            started_at: now_ts(), finished_at: now_ts(), rtt_min_ms: Some(12),
            ports: vec![ProbePortRec {
                port: 443, protocol: "https".into(), outcome: "ok".into(),
                detail_json: serde_json::json!({
                    "status": 200, "server": "nginx", "body_sha256": "ab".repeat(32), "body_len": 1234,
                    "favicon_mmh3": "-1234567", "jarm": "1".repeat(62),
                    "tls": {"leaf_sha256": "cd".repeat(32), "subject": "CN=x", "not_after": "2027-01-01"}
                }).to_string(),
            }],
            build: String::new(),
        }
    }

    #[tokio::test]
    async fn a_probe_result_lands_in_probes_ports_and_host_keys() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
        let r = rec("203.0.113.9", 7);
        let ctx = Ctx { origin: Some(&NodeId([7; 32])), hlc: 5 };
        let mut conn = store.pool.acquire().await.unwrap();
        assert_eq!(apply(&mut conn, ctx, &Record::ProbeResult(r.clone())).await.unwrap(), Effect::Applied);
        apply(&mut conn, ctx, &Record::ProbeResult(r)).await.unwrap(); // twice: no duplicate
        drop(conn);
        let probes = store.probes_for_ip(ip.id).await.unwrap();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].rtt_min_ms, Some(12));
        assert_eq!(store.probe_ports(probes[0].id).await.unwrap()[0].port, 443);
        let keys = store.host_keys_for_ip(ip.id).await.unwrap();
        let kinds: Vec<&str> = keys.iter().map(|k| k.kind.as_str()).collect();
        for k in ["tls-cert", "favicon", "jarm", "http-body"] { assert!(kinds.contains(&k), "{kinds:?}"); }
        assert!(store.probed_recently("203.0.113.9", &NodeId([7; 32]), 24).await.unwrap());
        assert!(!store.probed_recently("203.0.113.9", &NodeId([8; 32]), 24).await.unwrap());
    }

    #[test]
    fn oversized_or_malformed_records_yield_no_keys() {
        let v = serde_json::json!({"jarm": "0".repeat(62), "body_sha256": "zz"});
        let keys = keys_of(80, &v);
        assert!(keys.iter().all(|k| k.kind != "jarm"), "an all-zero JARM is 'no TLS', not a key");
        assert!(keys.iter().all(|k| k.kind != "http-body"), "not a sha256 hex");
    }
}
```
(`host_keys_for_ip` — use the existing per-IP reader's real name from `grep -n "pub async fn" src/store/hostkeys.rs`.)

- [ ] **Step 3: Run** `cargo test store::probes` → compile errors.

- [ ] **Step 4: Implement**

`store/probes.rs` — `apply_probe_result`: reject `uid`/`group` > 64 chars, > 16 ports, or any `detail_json` > 64 KiB (`Effect::Ignored`); `erased_by` → `Effect::Erased`; `ensure_ip` (creates the address like `scan_result` does); `INSERT OR IGNORE INTO probes` binding `origin` = `ctx.origin_bytes()` or, standalone (`None`), the asker's bytes so `probed_recently` works there too; on `rows_affected() == 1` insert the ports and `insert_probe_keys(conn, probe_id, ip_id, &keys_of(port, &detail))`. `keys_of` reads the detail keys listed in Interfaces: TLS leaf → `TLS_CERT` (`fingerprint` = hex sha256, `detail` = `"{subject} · valid until {not_after}"`); SSH key → `SSH_HOSTKEY` (`"SHA256:{host_key_sha256}"`, detail = key type); `hassh` → `HASSH`; `jarm` unless all zeros → `JARM`; `favicon_mmh3` → `FAVICON` (detail = favicon sha256); `body_sha256` when 64 lowercase hex → `HTTP_BODY` (detail `"{body_len} bytes"`); `not_found.body_sha256` → `HTTP_404` (detail `"status {n}"`). Readers: `probes_for_ip` (`ORDER BY id DESC LIMIT 200`, from `self.read`), `probe_ports`, `probed_recently` (`JOIN ips`, `p.origin = ?`, `p.finished_at > datetime('now', '-N hours')`).

`store/hostkeys.rs` — every query that joins `scans s ON s.id = h.scan_id` becomes `LEFT JOIN scans s ON s.id = h.scan_id LEFT JOIN probes p ON p.id = h.probe_id`, times read as `COALESCE(s.finished_at, p.finished_at)`; `derive` still inserts with `scan_id`; add `insert_probe_keys` (same `INSERT OR IGNORE`, `probe_id` column). `templates/_host_keys.html`: when `k.probe_id.is_some()` show "from probe · {{ k.probe_at }}" in the Detail cell prefix.

`store/data.rs` — `Record::ProbeResult(r) => super::probes::apply_probe_result(conn, ctx, r).await`, `Record::IpName(r) => super::probes::apply_ip_name(conn, ctx, r).await` (a stub returning `Ok(Effect::Ignored)` until Task 12), both kinds in `CONTENT_KINDS`. Fix every exhaustive `match` on `Record` the compiler reports (`repl.rs:1407` → `None`).

`config.rs` — `ProbeConfig` with `Default`, `#[serde(default)] pub probe: ProbeConfig` on `Config`, the two `OPTIONAL_KEYS` rows.

- [ ] **Step 5: Run** `cargo test store:: && cargo test config::` → PASS (`fresh_database_reaches_latest_version` now sees 18).
- [ ] **Step 6: Commit** `git add -A src/store src/cluster/record.rs src/scan/hostkeys.rs src/config.rs templates/_host_keys.html && git commit -m "Store: probes, probe_ports, ip_names; host keys may come from probes"`

---

### Task 5: Probe readers — HTTP, TLS, JARM, SSH, banner

**Files:**
- Create: `src/scan/probe/mod.rs`, `src/scan/probe/http.rs`, `src/scan/probe/tls.rs`, `src/scan/probe/jarm.rs`, `src/scan/probe/ssh.rs`
- Modify: `src/scan/mod.rs:2-10` (`pub mod probe;`)

**Interfaces** (every reader takes an absolute `deadline: tokio::time::Instant` and uses `tokio::time::timeout_at`; `mod.rs` holds the caps as constants `MAX_PORTS=16`, `CONNECT_TIMEOUT=10s`, `PROBE_TIMEOUT=120s`, `MAX_RESPONSE=256 KiB`, `MAX_FAVICON=100 KiB`, `MAX_REDIRECTS=5`, `PROBE_COOLDOWN_HOURS=24`, plus `connect(ip, port, deadline)`, `connection_deadline(probe_end)`, `banner(ip, port, deadline) -> io::Result<String>` (≤ 1 KiB, 5 s of silence ends it, control bytes escaped via `printable`), `sha256_hex`):

- `http`: `USER_AGENT` (a current Chrome string); `client(deadline) -> reqwest::Client` (redirects off, invalid certs accepted, connect timeout 10 s); `fetch(client, url, max, deadline) -> anyhow::Result<HttpSeen { status, headers, body, truncated }>`; `title_of(&[u8]) -> Option<String>` (≤ 200 chars, whitespace collapsed); `cookie_names(&HeaderMap) -> Vec<String>` (≤ 20); `mmh3_32(&[u8], seed) -> i32` (MurmurHash3 x86_32); `favicon_mmh3(&[u8]) -> String` (hash of the base64 text with a newline every 76 chars, as Shodan computes it); `probe_http(ip, port, https, guard: &(dyn Fn(&IpAddr) -> Option<String> + Sync), deadline) -> Value` producing `status, server, powered_by, title, cookie_names, body_sha256 (first 4 KiB), body_len, truncated, not_found{status, body_sha256, body_len}, favicon_mmh3, favicon_sha256, redirects[...]`; `follow_redirects(client, first_url, guard, deadline) -> Vec<Value>` where each hop is `{url, status, location, server, powered_by, title, body_sha256, body_len, tls?, jarm?}` or `{url, skipped: "protected"|"loop"|"unresolved"|"limit", why?}`. The favicon URL is the page's `<link rel="icon">` else `/favicon.ico`; the random path is 16 hex chars.
- `tls`: `capture(ip, port, deadline) -> anyhow::Result<TlsSeen { chain_der: Vec<Vec<u8>>, version: String, alpn: Option<String> }>` — one rustls handshake with a `ServerCertVerifier` that accepts and records the chain (the probe records what is presented, trust is not the question), ALPN offered `h2, http/1.1`, SNI = the address; `json(&TlsSeen) -> Value` with `leaf_sha256, subject, issuer, sans (bare names, ≤ 50), not_before, not_after (YYYY-MM-DD), chain_len, version, alpn` via `x509_parser`.
- `jarm`: `fingerprint(ip, port, deadline) -> String` (62 hex chars; all zeros when nothing answered). Implement from the public JARM reference (`salesforce/jarm`, `jarm.py`): the ten ClientHello shapes (`tls1_2_forward … tls1_3_middle_out`), the cipher list, the ServerHello reduction to `cipher|version|alpn|extension-order`, the cipher-index and version-byte tables, and the final `30 fuzzy chars + first 32 hex of SHA-256`. Keep the module structured as `probes(host) -> Vec<Probe>`, `Probe::build() -> Vec<u8>`, `parse_server_hello(&[u8]) -> Option<ServerHelloSeen>`, `hash(&[Option<ServerHelloSeen>]) -> String`, so each piece is unit-testable; the hash is only useful if the bytes match the reference exactly, so diff `build()` against the reference's packet builder before shipping.
- `ssh`: `capture(ip, port, deadline) -> anyhow::Result<SshSeen { banner, kex_algorithms, host_key_algorithms, ciphers, macs, compression, host_key_type: Option<String>, host_key_sha256: Option<String> }>` and `json(&SshSeen) -> Value` (adds `hassh` = MD5 of `kex;enc_s2c;mac_s2c;comp_s2c`, the HASSH-server definition). Protocol per RFC 4253 §4.2 (version exchange), §7.1 (KEXINIT name-lists) and RFC 8731 (curve25519-sha256): send our banner and KEXINIT, read the server's KEXINIT, and — only when it offers `curve25519-sha256` — send `KEX_ECDH_INIT` with an `aws_lc_rs::agreement::X25519` ephemeral public key and read `KEX_ECDH_REPLY`, whose first string is the host-key blob; `host_key_type` is the blob's leading name, `host_key_sha256` the base64 (no padding) SHA-256 of the blob, as OpenSSH prints after `SHA256:`. The connection is closed right after; no secret is derived and nothing is authenticated. Without a shared KEX the banner and HASSH are still returned. Helpers `packet(payload) -> Vec<u8>` and `read_packet(&mut TcpStream) -> io::Result<Vec<u8>>` (RFC 4253 §6 binary packet, unencrypted) are `pub` for the test server.

- [ ] **Step 1: Write the failing tests** — one `#[cfg(test)] mod tests` per file, each against a local server bound on `127.0.0.1:0`:
  - `http`: `mmh3_matches_the_reference_vectors` (`mmh3_32(b"", 0) == 0`, `mmh3_32(b"hello", 0) == 613153351`, `mmh3_32(b"The quick brown fox jumps over the lazy dog", 0) == 776992547`); `titles_and_cookie_names_are_read_and_bounded`; `a_local_server_is_read_with_404_shape_favicon_and_redirects` (an axum app with `/`, `/favicon.ico`, `/go → 302 /landing`, `/landing`, a 404 fallback; asserts `status 200`, `server`, `powered_by`, `title`, `cookie_names`, `not_found.status == 404`, a favicon hash, and a 2-hop chain from `/go`); `a_hop_to_protected_space_is_skipped` (`/` redirects to `http://10.0.0.1/admin`; the guard refuses non-global addresses; asserts hop 2 is `skipped: "protected"` with no `status`); `a_chain_of_six_is_cut_at_five_hops` (`/{n} → /{n+1}`; asserts 5 fetched hops plus a `skipped: "limit"` marker).
  - `tls`: a `pub(crate) async fn tls_server(alpn: &[&str]) -> (SocketAddr, Vec<u8>)` helper (rcgen self-signed `probe.test`, `tokio_rustls::TlsAcceptor`), used by `the_chain_version_and_alpn_are_captured` (leaf DER equals the server's, version `TLSv1_3`, ALPN `h2`, `sans == ["probe.test"]`, `chain_len == 1`) and `a_port_without_tls_errors_quickly` (a listener that writes an SSH banner → `Err`).
  - `jarm`: `the_ten_client_hellos_have_the_reference_names_and_valid_record_framing` (10 probes, names in reference order, each `build()` a TLS record whose length field matches); `a_server_hello_is_reduced_to_cipher_version_and_extensions` (a hand-built ServerHello with cipher `c02f`, version `0303`, ALPN `h2`, extensions `0010`,`0000` → `raw() == "c02f|0303|h2|0010-0000"`); `the_hash_is_62_chars_and_all_zero_without_answers`; `a_real_tls_server_yields_a_non_zero_jarm_and_a_plain_port_yields_zeros` (uses `tls::tests::tls_server`).
  - `ssh`: an `async fn fake_ssh(kex: &str, hostkeys: &str) -> SocketAddr` server that sends a banner `SSH-2.0-OpenSSH_10.2 Debian` and a KEXINIT with the given lists, reads the client's banner, KEXINIT and ECDH init, and answers an ECDH reply whose host-key blob is `ssh-ed25519` + 32 fixed bytes (its signature field is junk: never verified); `banner_hassh_and_host_key_are_read_from_an_openssh_10_style_server` (banner, `kex_algorithms`, `host_key_type == "ssh-ed25519"`, a 43-char unpadded fingerprint, a 32-hex `hassh`); `a_server_without_curve25519_still_gives_banner_and_hassh` (kex `diffie-hellman-group14-sha256` → `host_key_type == None`, no error).
  - `mod`: `banner_reads_what_a_service_sends_and_escapes_control_bytes` (a listener writing `b"220 hi\x01\r\n"` → `"220 hi\\x01\r\n"` with `\r` kept? — decide: keep `\n` and `\t`, escape the rest; assert `"220 hi\\x01\\x0d\n"`).

- [ ] **Step 2: Run** `cargo test scan::probe` → compile errors.
- [ ] **Step 3: Implement `mod.rs`, then `http.rs`** (titles via a case-insensitive `<title>…</title>` scan over the first 64 KiB; `page_json` shared by `/`, the random path and every hop; `target_of(url)` parses the host, resolving a name with the system resolver once (5 s) so the guard sees an address; `origin_of(url)` = `scheme://host[:port]` for relative `Location`s).
- [ ] **Step 4: Implement `tls.rs`** (`ClientConfig::builder_with_provider(aws_lc_rs)…dangerous().with_custom_certificate_verifier(keep)`; `supported_verify_schemes` from the provider; version via `conn.protocol_version()`, ALPN via `conn.alpn_protocol()`).
- [ ] **Step 5: Implement `jarm.rs`** from the reference as described; cipher list and tables copied from `jarm.py`, not from memory.
- [ ] **Step 6: Implement `ssh.rs`** per the RFCs above; the client's own lists: kex `curve25519-sha256,curve25519-sha256@libssh.org`, host keys `ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa`, ciphers `chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr`, MACs `hmac-sha2-256-etm@openssh.com,hmac-sha2-256`, compression `none`.
- [ ] **Step 7: Run** `cargo test scan::probe` → PASS.
- [ ] **Step 8: Commit** `git add src/scan/probe src/scan/mod.rs && git commit -m "Probe: HTTP, TLS, JARM, SSH and banner readers"`

---
### Task 6: The probe runner

**Files:**
- Modify: `src/scan/probe/mod.rs` (add `Target`, `run_probe`, RTT)

**Interfaces:**
- Produces:
```rust
/// What the latest counter-scan found open, as the runner takes it.
pub struct Target { pub ip: IpAddr, pub ports: Vec<(u16, Option<String> /* nmap service name */)> }
pub struct Outcome { pub started_at: String, pub finished_at: String, pub rtt_min_ms: Option<u32>, pub ports: Vec<ProbePortRec> }
pub async fn run_probe(t: &Target, guard: &(dyn Fn(&IpAddr) -> Option<String> + Sync)) -> Outcome;
pub fn protocol_for(port: u16, service: Option<&str>) -> &'static str; // "https" | "http" | "ssh" | "tls" | "banner"
pub async fn rtt_min_ms(ip: IpAddr, port: u16, deadline: Instant) -> Option<u32>;
```
- `protocol_for`: service `ssh` or port 22 → `ssh`; service `https`/`ssl/*` or ports 443, 8443 → `https`; service `http` or ports 80, 8080, 8000, 8008, 8888 → `http`; service containing `ssl`/`tls` → `tls`; anything else → `banner`. For `banner` ports the runner first tries a TLS handshake (3 s) and, when it succeeds, records `tls` + `jarm` instead of a banner.
- Per port the runner records `ProbePortRec { port, protocol, outcome, detail_json }`: `outcome` = `ok` when the reader returned, `refused` on connection refused, `timeout` on the deadline, `error` otherwise (with `detail_json = {"error": "..."}`). `https` ports get `http` detail merged with `tls` and `jarm` keys; `ssh` gets `{"ssh": {...}}`; `tls` gets `{"tls": {...}, "jarm": "..."}`; `banner` gets `{"banner": "..."}`.
- The ports are the lowest-numbered `MAX_PORTS`; the whole probe ends at `started + PROBE_TIMEOUT`; ports after the deadline are recorded `timeout` without connecting. RTT: three TCP connects to the first port (each ≤ 10 s), the minimum in ms.

- [ ] **Step 1: Write the failing tests** (`src/scan/probe/mod.rs` tests)

```rust
#[tokio::test]
async fn a_probe_reads_each_open_port_by_protocol_and_measures_rtt() {
    let (tls_addr, _) = tls::tests::tls_server(&["h2"]).await;            // an HTTPS-like port
    let http = /* axum app with "/" → "<title>t</title>" on 127.0.0.1:0 */;
    let t = Target { ip: "127.0.0.1".parse().unwrap(), ports: vec![(http.port(), Some("http".into())), (tls_addr.port(), None)] };
    let out = run_probe(&t, &|_| None).await;
    assert_eq!(out.ports.len(), 2);
    assert_eq!(out.ports[0].protocol, "http");
    let d0: serde_json::Value = serde_json::from_str(&out.ports[0].detail_json).unwrap();
    assert_eq!(d0["title"], "t");
    // A port nmap did not name that speaks TLS is recorded as tls, with a JARM.
    assert_eq!(out.ports[1].protocol, "tls");
    let d1: serde_json::Value = serde_json::from_str(&out.ports[1].detail_json).unwrap();
    assert_eq!(d1["tls"]["chain_len"], 1);
    assert_eq!(d1["jarm"].as_str().unwrap().len(), 62);
    assert!(out.rtt_min_ms.is_some());
}

#[tokio::test]
async fn a_slow_port_times_out_and_the_probe_continues() {
    // A listener that accepts and never writes.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow = l.local_addr().unwrap().port();
    tokio::spawn(async move { let mut held = vec![]; loop { let Ok((s, _)) = l.accept().await else { break }; held.push(s); } });
    let http = /* axum "/" on 127.0.0.1:0 */;
    let t = Target { ip: "127.0.0.1".parse().unwrap(), ports: vec![(slow, None), (http.port(), Some("http".into()))] };
    let started = std::time::Instant::now();
    let out = run_probe(&t, &|_| None).await;
    assert_eq!(out.ports[0].outcome, "timeout");
    assert_eq!(out.ports[1].outcome, "ok");
    assert!(started.elapsed() < std::time::Duration::from_secs(30), "one slow port costs its own timeout, not the probe's");
}

#[tokio::test]
async fn a_refused_port_is_recorded_as_refused() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let t = Target { ip: "127.0.0.1".parse().unwrap(), ports: vec![(port, None)] };
    let out = run_probe(&t, &|_| None).await;
    assert_eq!(out.ports[0].outcome, "refused");
}

#[test]
fn protocols_follow_nmap_names_then_well_known_ports() {
    assert_eq!(protocol_for(22, None), "ssh");
    assert_eq!(protocol_for(2222, Some("ssh")), "ssh");
    assert_eq!(protocol_for(443, None), "https");
    assert_eq!(protocol_for(8443, Some("ssl/http")), "https");
    assert_eq!(protocol_for(80, None), "http");
    assert_eq!(protocol_for(993, Some("ssl/imap")), "tls");
    assert_eq!(protocol_for(25, Some("smtp")), "banner");
}
```
In the slow-port test, make the banner reader's "5 s of silence" and the TLS try (3 s) the only waits: expect ~8 s for that port.

- [ ] **Step 2: Run** `cargo test scan::probe::tests` → compile errors.

- [ ] **Step 3: Implement** `run_probe`: `started_at = now_ts()`, `probe_end = Instant::now() + PROBE_TIMEOUT`; take `ports.iter().take(MAX_PORTS)` sorted by port; `rtt_min_ms` on the first; then for each port, `let deadline = connection_deadline(probe_end)`; if `Instant::now() >= probe_end` push `timeout`; else match `protocol_for` and call the reader, mapping `io::ErrorKind::ConnectionRefused` → `refused`, `TimedOut` (and `timeout_at` elapsed) → `timeout`, other → `error`. For `banner`: try `tls::capture` with `min(deadline, now + 3 s)`; on `Ok` record protocol `tls` with `tls` json and `jarm::fingerprint(ip, port, deadline)`; on `Err` fall back to `banner()`. For `https`: `http::probe_http(.., true, ..)` merged with `tls::capture` and `jarm`. `finished_at = now_ts()`.

- [ ] **Step 4: Run** `cargo test scan::probe` → PASS. **Step 5: Commit** `git commit -am "Probe: the runner — ports by protocol, caps, RTT"`.

---

### Task 7: Price, gate, server and asker

**Files:**
- Create: `src/scan/probe/gate.rs`, `src/scan/probe/serve.rs`, `src/scan/probe/ask.rs`
- Modify: `src/credits/price.rs` (`weight_milli("probe")`, `Table.probe_mc`, the price loop), `src/cluster/status.rs:41-71` (`Heartbeat.probe_price_mc`), `src/cluster/mod.rs` (`refresh_heartbeat`, `probe_slots`), `src/credits/pay.rs:215-315` (extract `accept_offer`; `make_offer`), `src/cluster/rpc/mod.rs:30-45,205-215` (`/rpc/v1/probe`), `src/scan/mod.rs:149` (`locally_refused` → `pub(crate)`), `src/lib.rs` (wire `probe::serve::Prober` into `Node`/`AdminState`)

**Interfaces:**
- `price.rs`: `pub const PROBE: &str = "probe"; weight_milli(PROBE) == 4000`; `Table.probe_mc: Option<u32>` (None when this node does not probe); computed in the price loop as `price(PROBE, unit, probe_surge)` when `cfg.probe.enabled && roles.scanner`, where `probe_surge = 1 + (busy slots == max_parallel) as u32` (doubles while full). `Table::announced()` unchanged; `Heartbeat.probe_price_mc: Option<u32>` (`#[serde(default)]`) filled from `price_table().probe_mc` in `refresh_heartbeat`.
- `pay.rs`:
```rust
pub struct Accepted { pub offered: Mc, pub covered: Mc, pub book: Arc<Book>, serving: Serving<'_> /* keep the guard alive while served */ }
pub enum Declined { Why(String), TooLow { why: String, price_mc: u32 } }
/// The checks `serve` did on an offer before answering: wait for the entry, is an offer, for me,
/// seal consistent, not already serving, standing, counts, open, time left, amount covers `price`.
pub async fn accept_offer(node: &Arc<Node>, peer: NodeId, offer_seq: u64, price: Mc, what: &str) -> Result<Accepted, Declined>;
/// The asker's side of writing one offer: balance (drawing from the fleet), sealed `CreditOffer`, reconcile so the server holds it.
pub async fn make_offer(node: &Arc<Node>, server: NodeId, total_mc: Mc) -> Result<u64 /* offer seq */, String>;
```
  `serve` and `offer_and_ask` are rewritten on top of these two (existing `pay` tests must pass unchanged). `Declined::TooLow` carries the named price so the probe asker can retry once up to `RETRY_AT_MOST`.
- `gate.rs`:
```rust
pub struct Gate { safety: tokio::sync::Mutex<safety::Safety>, crawlers: Option<crawler::Crawlers>, tor: std::sync::Mutex<guard::TorView>, origins: guard::Origins, classifier: &'static Classifier, cfg: Config }
impl Gate {
    pub fn new(cfg: &Config, me: Option<NodeId>) -> Self;
    /// None: allowed; Some(why): the reason shown to the asker. Checks, in order: enabled; global address;
    /// never_scan; safety lists (members, own, peer-observed public); Tor exit; verified crawler;
    /// evidence allows ≥ 2; latest finished scan has ≥ 1 open port; not probed by this node in 24 h.
    pub async fn check(&self, store: &Store, node: Option<&Node>, ip: &IpAddr) -> Result<Target, String>;
    /// The redirect-hop guard: safety lists + private space (sync, from the last refresh).
    pub fn hop_guard(&self) -> impl Fn(&IpAddr) -> Option<String> + Send + Sync;
}
```
  `Target` comes from `store.scans_for_ip(ip_id)` (first row with `finished_at.is_some()` and `audit_of.is_none()`) + `ports_for_scan(id)` filtered `state == "open"`.
- `serve.rs`:
```rust
#[derive(Serialize, Deserialize)] pub struct ProbeReq { pub ip: String, pub group: String, #[serde(default)] pub offer_seq: Option<u64> }
#[derive(Serialize, Deserialize)] pub enum ProbeResp { Accepted { probe_uid: String }, Declined { why: String, #[serde(default)] price_mc: Option<u32> } }
pub struct Prober { gate: Gate, slots: Arc<tokio::sync::Semaphore>, max: u32 }
impl Prober {
    pub fn new(cfg: &Config, me: Option<NodeId>) -> Self;
    pub fn busy(&self) -> u32;   // max - available permits (for the surge)
    /// Cluster: validate the offer, gate, take a slot, answer at once, then run and append result + receipt in one batch.
    pub async fn serve(self: &Arc<Self>, node: &Arc<Node>, peer: NodeId, req: &ProbeReq) -> ProbeResp;
    /// Standalone: gate, run, write the record through `Recorder::Local`; returns the probe uid.
    pub async fn run_local(self: &Arc<Self>, store: &Store, ip: IpAddr, group: &str) -> Result<String, String>;
}
```
  `vantage_ip`: `node.public_addrs()` with exactly one → (`Some(it)`, `"public"`); else the asker-provided hint is not trusted — use `None`/`"dialled"` and let the asker fill the dialled address on display (it knows what it dialled); standalone → `None`/`"local"`. The result's `asker` is `peer`. Receipt: `CreditReceipt { payer: peer, offer_seq, charged_mc: price, answered: vec!["probe".into()] }` appended together with `Record::ProbeResult` via `repl::append(node, &[result, receipt])`. On a decline before any work: `release()` (receipt of nothing), as `pay::serve` does. A probe that panics or errors after acceptance still writes the receipt with what it has (a result with `error` ports) — the scanner did the work.
- `ask.rs`:
```rust
pub struct Vantage { pub node: NodeId, pub name: String, pub price_mc: u32, pub country: Option<String>, pub dialled: Option<IpAddr> }
/// Live scanners announcing a probe price (this node included when it probes), cheapest first.
pub fn vantages(node: &Node, geo: &SharedGeo) -> Vec<Vantage>;
/// The default pick: up to `n`, spread over distinct countries, padded with the cheapest.
pub fn default_pick(all: &[Vantage], n: usize) -> Vec<NodeId>;
pub struct Asked { pub node: NodeId, pub name: String, pub outcome: Result<String /* probe uid */, String> }
/// One offer and one call per chosen scanner; the group uid ties the results. Retries a too-low decline once at the named price (≤ RETRY_AT_MOST ×).
pub async fn ask(node: &Arc<Node>, prober: &Arc<Prober>, ip: IpAddr, chosen: &[NodeId], group: &str) -> Vec<Asked>;
```
  Asking the own node goes through `make_offer(node, me, price)` + `prober.serve(node, me, &req)` directly (no RPC), so it is paid like any other.
- `rpc/mod.rs`: route `/rpc/v1/probe` (members only) → `node.prober().serve(&node, peer, &req)`; `Node` gains `prober: OnceLock<Arc<Prober>>` with `set_prober`/`prober()` like `lookup_providers`. `lib.rs` creates one `Arc<Prober>` per process (scanner role on, `cfg.probe.enabled`) and hands it to the node and to `AdminState` (`pub prober: Option<Arc<Prober>>`; `public_only` sets `None`).

- [ ] **Step 1: Write the failing tests**

`src/credits/pay.rs` (next to the existing `serve` tests, reusing their two-node setup): `accept_offer_declines_a_too_low_offer_naming_the_price` (offer 10 mc for a 50 mc price → `Declined::TooLow { price_mc: 50 }` and a receipt of nothing is written), `accept_offer_accepts_a_covering_offer` (→ `Accepted { offered: 50, .. }`; a second call for the same seq while the first is alive → `Declined::Why("…being served already")`), and `make_offer_writes_a_sealed_offer_to_the_server` (the entry at the returned seq is `Kind::Offer { to: server, .. }`).

`src/credits/price.rs`: `a_probe_costs_four_units_and_doubles_when_the_slots_are_full` (`price(PROBE, Some(1000), 1) == 4000`, `price(PROBE, Some(1000), 2) == 8000`, `weight_milli(PROBE) == 4000`).

`src/scan/probe/gate.rs`: with a `Store` and the `config_with` helper of `scan::tests`: `a_gate_needs_an_open_port_in_a_finished_scan` (no scan → `Err` mentioning "no counter-scan"; a scan with only closed ports → `Err` "no open port"; a finished scan with 22 open and evidence from 3 requests at level 2 → `Ok(Target { ports: [(22, Some("ssh"))] })`); `a_gate_refuses_thin_evidence_and_protected_addresses` (one request → `Err` "evidence"; `never_scan` covering the IP → `Err` "never_scan"); `a_gate_enforces_the_24_hour_cooldown` (insert a `probes` row by this origin → `Err` "probed … ago").

`src/scan/probe/serve.rs` (standalone, local HTTP server as the target): `run_local_writes_a_probe_result_the_store_reads_back` (seed a finished scan with the server's port open and three level-2 requests; `run_local` → `Ok(uid)`; `probes_for_ip` has it with one `ok` port) and `run_local_declines_when_the_gate_says_no` (no scan → `Err`).

`tests/cluster.rs` (two booted nodes, the existing `boot` harness with `scanner: None`; the target is a local HTTP server): `a_paid_probe_is_accepted_served_and_charged` — node A records the target with evidence and a finished scan (write the `ScanJob`/`ScanResult` records through `rec(&a)`), both nodes replicate, A has credits (use the existing credit-seeding helper of `cluster_e2e.rs` or write `CreditTransfer`/earned scans as those tests do), A calls `probe::ask::ask(&a, &a.prober, ip, &[b.id()], &group)` → `Asked { outcome: Ok(uid) }`; `eventually` A's `probes_for_ip` holds the result with `origin == b.id()`, and A's book shows a receipt of B's price for that offer. `a_probe_of_an_unknown_offer_is_declined_with_a_receipt_of_nothing` — call B's `/rpc/v1/probe` with `offer_seq: Some(99999)` → `Declined`, and A's offer (none) is unaffected.

- [ ] **Step 2: Run** `cargo test credits::pay && cargo test scan::probe::gate && cargo test --test cluster a_paid_probe` → compile errors.

- [ ] **Step 3: Implement `pay::accept_offer` and `make_offer`**, then rewrite `serve` (`let acc = match accept_offer(node, peer, offer_seq, total, "lookup").await { Ok(a) => a, Err(Declined::Why(w)) => return decline(&served, w), Err(Declined::TooLow { why, price_mc }) => { let mut r = decline(&asking, why); r.price_mc = Some(price_mc); return r; } }` — note the lookup computes `total` only after the per-provider share check, so `accept_offer` takes `price` as a closure-free value: compute `asking`/`declined` first, then call it) and `offer_and_ask` (`let seq = make_offer(node, server, total_mc).await.map_err(decline)?;`). Keep every existing log line and reason text so the `pay` tests pass unchanged.

- [ ] **Step 4: Implement price + heartbeat** (`PROBE`, `weight_milli`, `Table.probe_mc`, the loop in `price.rs:280-333` reading `node.prober().map(|p| p.busy() >= p.max)` for the surge, `Heartbeat.probe_price_mc`, `refresh_heartbeat`).

- [ ] **Step 5: Implement `gate.rs`** by lifting the checks of `scan::Source::preflight` (`src/scan/mod.rs:321-383`) and the evidence check (`:651-652`) into `Gate::check`; `locally_refused` becomes `pub(crate)`. Reason strings: "probes are off on this node", "non-global address", "never_scan", the `Safety::refuses` text, "Tor exit", "verified crawler (name)", "the requests held here allow level L, a probe needs 2", "no finished counter-scan of this address here", "the latest counter-scan found no open port", "this node probed the address N h ago".

- [ ] **Step 6: Implement `serve.rs`** (`serve`: `accept_offer(node, peer, seq, price, "probe")` → gate → `try_acquire_owned` on the semaphore (fail → `Declined { why: "all probe slots are busy", price_mc: Some(price) }` + `release`) → `ProbeResp::Accepted { probe_uid }` and `tokio::spawn` the run (holding the permit) that appends `[Record::ProbeResult, Record::CreditReceipt]`; `run_local`: gate → run → `store.local().write(vec![Record::ProbeResult(..)])`). The spawned task logs `tracing::info!(asker, ip, ports, charged, "probe served")`.

- [ ] **Step 7: Implement `ask.rs`** (`vantages` from `node.live_members` + `status.known(id).hb.probe_price_mc` + `dial_address`, country via `geo.read().coords/lookup` of the first `hb.public_addrs`; `default_pick` greedy by unseen country then price; `ask`: for each chosen → `make_offer` → call `/rpc/v1/probe` with `RPC_TIMEOUT` → on `Declined { price_mc: Some(p) }` with `retry_price(offered, Some(p), true)` → one more offer at `p`). Route + `Node::set_prober` + `lib.rs` wiring + `AdminState.prober`.

- [ ] **Step 8: Run** `cargo test credits:: && cargo test scan::probe && cargo test --test cluster probe` → PASS.
- [ ] **Step 9: Commit** `git add -A src/credits src/scan/probe src/cluster src/lib.rs src/admin/mod.rs tests/cluster.rs && git commit -m "Probe: paid over RPC — offer, accept, two-phase answer, result and receipt in one batch"`

---

### Task 8: Soft link kinds

**Files:**
- Modify: `src/store/links.rs:11-170` (`LinkKind`, legs), `src/admin/links.rs` + `templates/admin_links.html` (names/intro copy), `src/admin/search.rs` (nothing: `find_value` is generic over `ALL`)

**Interfaces:**
- `LinkKind::{Favicon, Jarm, HttpBody, Http404}` with keys `favicon`, `jarm`, `http-body`, `http-404`, names "Favicon", "JARM", "Page body", "404 page"; `identity() == false`; `by_node() == false`; `host_kind()` maps to the four `scan::hostkeys` constants; in `ALL` and `LIST`, not in `IDENTITY`. The `host_key` legs become `host_keys h LEFT JOIN scans s ON s.id = h.scan_id LEFT JOIN probes p ON p.id = h.probe_id` with `ts: "COALESCE(s.finished_at, p.finished_at)"`.

- [ ] **Step 1: Write the failing test** (`links.rs` tests, next to the existing kind/leg test)

```rust
#[tokio::test]
async fn probe_hashes_link_addresses_softly() {
    let (store, a, b) = two_ips_with_probe_keys("favicon", "-1234567").await; // helper: two IPs, one host_keys row each via a probes row
    let links = store.links_for(LinkKind::Favicon, "-1234567", 1).await.unwrap(); // the existing per-value reader
    assert_eq!(links.items.len(), 2);
    assert!(!LinkKind::Favicon.identity());
    assert_eq!(LinkKind::parse("http-404"), Some(LinkKind::Http404));
    assert_eq!(LinkKind::of_host_kind("jarm"), Some(LinkKind::Jarm));
    let _ = (a, b);
}
```
(Adapt `links_for` to the real reader name in `links.rs`; the helper inserts a `probes` row and `host_keys(probe_id, …)` rows directly with sqlx.)

- [ ] **Step 2: Run** → compile errors. **Step 3: Implement** the four variants, legs, `ALL` (12) / `LIST` (11), the `kind_name`/intro copy on the Links index ("Favicon, JARM, page and 404 hashes say *same product*, not *same operator*"). **Step 4: Run** `cargo test store::links && cargo test admin::links` → PASS. **Step 5: Commit** `git commit -am "Links: favicon, JARM, page-body and 404 hashes as soft kinds"`.

---
### Task 9: The Lookup page — entry, cheap first, offers after

**Files:**
- Modify: `src/intel/lookup.rs:186-238` (`run` takes the set to ask), `src/admin/lookup.rs` (handlers, `Offer` after the result), `templates/admin_lookup.html`, `templates/_admin_nav.html`, `templates/layout.html:27` (top-bar placeholder), `src/admin/search.rs:40-62,86-96` (hostnames → Lookup)

**Interfaces:**
- `intel::lookup::run(rec, providers, ip, ask: &[String], again: &[String]) -> Outcome`: `ask` names the paid providers to ask now (empty = none); the cheap tier (`weight_milli <= 250`) is always asked when the dataset lacks a fresh result; `again` keeps its meaning (ask although stored). `pub fn cheap() -> Vec<String>` (known providers with `weight_milli <= 250`). `cluster()` passes every known provider as `ask`.
- `admin::lookup::Offer` gains `pub paid: Vec<QuoteView>` (the non-cheap quotes with prices, for the result page) and `pub paid_total: String`; `QuoteView` gains `pub provider: String`. `IpForm` gains `pub ask: Option<Vec<String>>` (multi-value `ask=` fields; `ask=*` means all paid). The form's price line reads "this lookup costs up to {cheap total}"; the result page lists each paid provider with `[Ask]` and one `[Ask all (total)]`.
- `search::classify`: a new `Input::Host(String)` for text that is a valid hostname with at least one dot and no scheme (`intel::dns::valid_name`), routed to `/admin/lookup?ip=<name>` (the Lookup page handles names in Task 12; until then it answers "Not an IP address." — acceptable mid-plan). Placeholder text: "IP, domain, AS…, hash, /path".
- Nav: `("lookup", "/admin/lookup", "Lookup")` after Analytics in `_admin_nav.html`; `admin_lookup.html` already sets `sub = "lookup"`.

- [ ] **Step 1: Write the failing tests**

`src/intel/lookup.rs`: `cheap_tier_is_tor_rdap_geolite_and_internetdb` (`cheap()` equals exactly those four names) and, in `standalone_cluster_lookup_is_the_local_answer_plus_unserved_notes`, keep passing all providers.

`src/admin/lookup.rs` (the existing `app()` harness): `a_lookup_asks_the_cheap_tier_and_offers_the_rest` — POST `ip=203.0.113.9` → the page shows the Tor card (asked now), and in a cluster-less test the paid list is empty; assert the response contains `name="ask"` nowhere (standalone) and that `offer.total` is the cheap total (unit test `Offer::from_quotes` directly with a hand-built quote map: cheap total 0.03, paid list has AbuseIPDB with its price).

`src/admin/search.rs`: extend `classifies_what_was_typed` with `classify("example.com") == Input::Host("example.com")`, `classify("EXAMPLE.COM.") == Input::Host("example.com")`, `classify("not a host") == Input::Value(..)`, `classify("localhost") == Input::Value("localhost")` (no dot).

- [ ] **Step 2: Run** → failures/compile errors.
- [ ] **Step 3: Implement** `run` (`wanted = cheap ∪ ask`, minus stored unless in `again`), `cheap()`, the `Offer` split (`from_quotes(all: &HashMap<String, Vec<Quote>>)` used by both the form and the result), the `ask` form parsing (`serde_urlencoded` with repeated keys → use `axum_extra::extract::Form` or parse the raw body with `form_urlencoded::parse` into `Vec<(String,String)>`; the existing `Form<IpForm>` cannot take repeated keys), the template blocks (result page: a "Ask for more" card listing `offer.paid` rows with a per-row form `ip`+`ask=<provider>` and one `ask=*` form; the pre-lookup quote table is removed), nav entry, placeholder, `Input::Host`.
- [ ] **Step 4: Run** `cargo test intel::lookup && cargo test admin::lookup && cargo test admin::search` → PASS.
- [ ] **Step 5: Commit** `git commit -am "Lookup: nav entry, cheap tier first, paid providers offered with prices"`

---

### Task 10: Actions card, probe request, probes section

**Files:**
- Create: `src/admin/probes.rs`, `templates/_actions.html`, `templates/_probes.html`
- Modify: `src/admin/mod.rs` (`pub mod probes`, routes, `AdminState.geo: SharedGeo`), `src/admin/target.rs` (`Target.actions`, `Target.probes`), `templates/_target.html` (include the two partials, admin only), `src/admin/lookup.rs` (`POST /admin/lookup/probe` lives in `probes.rs`; the lookup result passes through `target`), `assets/js/app.js` (probes SSE), `src/lib.rs` (`AdminState::new` takes `geo`)

**Interfaces:**
- `admin::probes`:
```rust
pub struct ActionsView { pub guard_line: String, pub allowed: bool, pub why_not: Option<String>, pub vantages: Vec<VantageView>, pub default: Vec<String /* node id text */>, pub balance: Option<String>, pub standalone: bool }
pub struct VantageView { pub id: String, pub name: String, pub country: Option<String>, pub price: String }
pub async fn actions_for(state: &AdminState, ip: &IpAddr) -> ActionsView;
pub struct ProbeForm { pub ip: String, pub vantage: Vec<String> }   // repeated `vantage=` fields
/// POST /admin/lookup/probe → writes offers / runs locally, redirects to /ip/{ip}#probes with a notice.
async fn request(..) -> AppResult<Response>;
pub struct GroupView { pub group: String, pub asked_at: String, pub by: String, pub cost: String, pub members: Vec<ProbeView> }
pub struct ProbeView { pub node: String, pub state: &'static str /* queued|running|done|declined|lapsed */, pub why: Option<String>, pub vantage_ip: Option<String>, pub rtt_ms: Option<i64>, pub ports: Vec<PortView> }
pub struct PortView { pub port: i64, pub protocol: String, pub outcome: String, pub facts: Vec<(String, String, bool /* mono */)>, pub links: Vec<(String /* kind key */, String /* value */)>, pub redirects: Vec<HopView> }
pub async fn groups_for(state: &AdminState, ip_id: i64) -> Vec<GroupView>;
/// GET /admin/api/probes?ip=… — SSE: an event `probes` with the states JSON whenever the node's log changes (cluster: `subscribe_changes`; standalone: every 3 s) while any member is not done.
async fn stream(..) -> Sse<..>;
```
- Pending requests (accepted but no result yet) are kept in memory: `AdminState.pending_probes: Mutex<HashMap<String /* group */, Vec<(NodeId, String /* name */, Instant, Result<String, String>)>>>`; a member is `running` while its uid has no row and < 15 min passed, `lapsed` after, `declined` when the ask returned `Err`, `done` when `probes.uid` exists. Restart loses pending state: the page then shows only done rows (acceptable, documented in the template as "requests made before a restart show once their result arrives").
- `Target` gains `pub actions: Option<ActionsView>` and `pub probes: Vec<GroupView>` (both `None`/empty for the public page); `target::load` fills them when `authed`.
- Facts per port, from the detail JSON (`PortView.facts`): HTTP — Status, Server, Powered by, Title, Cookies, Body (sha256 + bytes), 404 (status + sha256), Favicon (mmh3 + sha256); TLS — Subject, Issuer, SANs, Valid, Chain, Version, ALPN, Leaf sha256, JARM; SSH — Banner, Host key (type + fingerprint), HASSH, KEX, Host-key algos, Ciphers, MACs; banner — Banner. `links`: `(favicon, mmh3)`, `(jarm, ..)`, `(http-body, ..)`, `(http-404, ..)`, `(tls, leaf)`, `(ssh, SHA256:..)` rendered as `/admin/links/{kind}/{value}` via `views::link_href`.

- [ ] **Step 1: Write the failing tests** (`src/admin/probes.rs`, the `app()` harness pattern from `admin/lookup.rs` extended with a scan + evidence seed)

`the_actions_card_explains_why_a_probe_is_unavailable` (an IP without a scan → `allowed == false`, `why_not` contains "no finished counter-scan"); `the_actions_card_offers_the_local_probe_standalone` (seed a finished scan with an open port and 3 level-2 requests → `allowed == true`, `standalone == true`, `vantages.is_empty()`); `requesting_a_probe_standalone_redirects_and_a_result_appears` (POST `/admin/lookup/probe` with `ip` + no vantage against a local HTTP target → 303 to `/ip/<ip>#probes`; `eventually` GET `/ip/<ip>` body contains `data-section="probes"` and the port's `Server` fact); `the_public_ip_page_shows_neither_card` (anonymous GET `/ip/<ip>` has no `data-section="probes"` and no `data-section="actions"`); `port_facts_are_built_from_the_detail_json` (unit: `port_view(443, "https", "ok", &json!({...}))` yields the expected labels and link kinds).

- [ ] **Step 2: Run** `cargo test admin::probes` → compile errors.
- [ ] **Step 3: Implement** `probes.rs` (views, `actions_for` using `prober.gate.check` for the reason — expose `Prober::check(&self, store, node, ip) -> Result<Target, String>` — and `ask::vantages`/`default_pick` for the picker; `request` parses repeated `vantage=` keys from the raw body, cluster → `ask::ask`, standalone → `prober.run_local`, stores pending, `redirect_with_notice`; `groups_for` joins `probes_for_ip` grouped by `group_uid` with the pending map; `stream` as described), the two templates (`_actions.html`: guard line, checkbox list with prices, live total via a few lines of JS, Probe button, balance line; `_probes.html`: per group a header and per member a state badge, then port cards with `facts` as a `<dl class="kv">`, `links` as badges, redirect hops as an ordered list with "skipped (protected)" rows), `_target.html` includes (`{% if let Some(a) = t.actions %}…{% endif %}` under Intelligence; `{% if t.admin.is_some() && !t.probes.is_empty() %}` section `probes`), `app.js` (a `[data-probes-src]` element opens an `EventSource` and reloads the page on a `probes` event whose states changed), routes `POST /admin/lookup/probe`, `GET /admin/api/probes`, `AdminState.geo` + `pending_probes`.
- [ ] **Step 4: Run** `cargo test admin::` → PASS. **Step 5: Commit** `git add -A src/admin templates assets/js/app.js src/lib.rs && git commit -m "Admin: actions card, probe requests, probes section on the IP page and lookup result"`

---

### Task 11: Vantage diff and the light-speed check

**Files:**
- Modify: `src/admin/probes.rs` (`DiffView`, RTT verdicts), `templates/_probes.html` (diff table for groups with ≥ 2 members), `src/intel/geo.rs` (nothing new; uses Task 3)

**Interfaces:**
```rust
pub const LIGHT_KM_PER_MS: f64 = 200.0; // ≈ ⅔ c in fibre: the optimistic bound
pub struct RttVerdict { pub vantage: String, pub rtt_ms: i64, pub bound_km: f64, pub distance_km: Option<f64>, pub impossible: bool, pub text: String }
/// None when either side has no coordinates.
pub fn rtt_verdict(name: &str, rtt_ms: i64, vantage: Option<Coords>, target: Option<Coords>) -> RttVerdict;
pub struct DiffRow { pub port: i64, pub field: String, pub values: Vec<Option<String>> /* one per member, None = port not reached */, pub differs: bool }
pub struct DiffView { pub members: Vec<String>, pub rows: Vec<DiffRow>, pub consistent: usize, pub contradicted: usize /* k of N */ }
pub fn diff(members: &[ProbeView]) -> DiffView;
```
- `GroupView` gains `pub diff: Option<DiffView>` (Some when ≥ 2 members are `done`) and `pub verdicts: Vec<RttVerdict>` (one per done member with an RTT; computed with `geo.coords(vantage_ip)` and `geo.coords(target)`; `vantage_ip` None → the dialled address recorded in `pending_probes`, else no verdict).
- Fields compared, per port: `status, server, powered_by, title, body_sha256, not_found.body_sha256, favicon_mmh3, redirects.last.url, tls.leaf_sha256, tls.chain_len, tls.version, tls.alpn, jarm, ssh.host_key_sha256, ssh.hassh, banner`. A member whose port outcome is not `ok` contributes `None` and does not make the row differ. `differs` = at least two `Some` values that are not equal.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn an_impossible_claim_is_flagged_and_a_possible_one_is_not() {
    let berlin = Coords { lat: 52.52, lon: 13.40, accuracy_km: 50 };
    let sydney = Coords { lat: -33.87, lon: 151.21, accuracy_km: 50 };
    let v = rtt_verdict("a", 8, Some(berlin), Some(sydney));
    assert!(v.impossible);
    assert!(v.text.contains("impossible"), "{}", v.text);
    assert!((v.bound_km - 800.0).abs() < 1.0);
    let v = rtt_verdict("a", 200, Some(berlin), Some(sydney));
    assert!(!v.impossible, "20 000 km bound covers 16 000 km");
    let v = rtt_verdict("a", 8, Some(berlin), None);
    assert!(!v.impossible && v.distance_km.is_none());
}

#[test]
fn the_accuracy_radius_is_subtracted_before_judging() {
    let a = Coords { lat: 52.52, lon: 13.40, accuracy_km: 0 };
    let b = Coords { lat: 48.86, lon: 2.35, accuracy_km: 1000 }; // Paris, claimed within 1000 km
    assert!(!rtt_verdict("a", 1, Some(a), Some(b)).impossible, "878 - 1000 < 100");
    let b = Coords { accuracy_km: 0, ..b };
    assert!(rtt_verdict("a", 1, Some(a), Some(b)).impossible, "878 > 100");
}

#[test]
fn the_diff_collapses_equal_rows_and_marks_different_ones() {
    let m = |server: &str, cert: &str| ProbeView { node: server.into(), state: "done", why: None, vantage_ip: None, rtt_ms: Some(1),
        ports: vec![port_view(443, "https", "ok", &serde_json::json!({"status": 200, "server": "nginx", "tls": {"leaf_sha256": cert}}))] };
    let d = diff(&[m("a", "aa"), m("b", "bb")]);
    let server = d.rows.iter().find(|r| r.field == "server").unwrap();
    assert!(!server.differs);
    let leaf = d.rows.iter().find(|r| r.field == "tls.leaf_sha256").unwrap();
    assert!(leaf.differs);
    assert_eq!(leaf.values, vec![Some("aa".into()), Some("bb".into())]);
    assert!(d.consistent >= 2, "status and server");
}

#[test]
fn a_timed_out_port_is_not_a_difference() {
    let ok = ProbeView { /* 443 ok, server nginx */ .. };
    let timeout = ProbeView { /* 443 outcome timeout */ .. };
    let d = diff(&[ok, timeout]);
    assert!(d.rows.iter().all(|r| !r.differs));
}
```
(`PortView` must keep the raw detail for the diff: add `pub detail: serde_json::Value` to it.)

- [ ] **Step 2: Run** `cargo test admin::probes::tests` → compile errors.
- [ ] **Step 3: Implement** `rtt_verdict` (`bound_km = rtt_ms as f64 / 2.0 * LIGHT_KM_PER_MS`; `distance_km = haversine_km(v, t) - t.accuracy_km`; `impossible = distance_km > bound_km`; text "impossible: claimed {d:.0} km away, light-speed bound {b:.0} km" or "plausible: {d:.0} km within {b:.0} km" or "no coordinates"), `diff`, the `GroupView` fields, the template: an RTT table (vantage, RTT, bound, distance, verdict) with the summary line "location claim contradicted by k of N vantages" when `k > 0`, then the diff table (rows with `differs` expanded and marked `class="diff"`, equal rows under a `<details>` "k fields consistent across all vantages").
- [ ] **Step 4: Run** `cargo test admin::probes` → PASS. **Step 5: Commit** `git commit -am "Vantages: field-by-field diff and the light-speed RTT check"`.

---

### Task 12: Domains by consensus

**Files:**
- Create: `src/intel/dns.rs`
- Modify: `src/intel/mod.rs` (`pub mod dns;`), `src/cluster/rpc/mod.rs` (`/rpc/v1/resolve`), `src/cluster/mod.rs` (`take_free_resolve` like `take_free_lookup`), `src/store/probes.rs` (`apply_ip_name`, `names_for_ip`), `src/admin/lookup.rs` (a hostname → resolve → per-address result), `templates/admin_lookup.html` (names block), `templates/_names.html` + `templates/_target.html` (Names on the IP page), `src/store/export.rs` + `docs/dataset.md` (`names` column), `src/admin/search.rs` (already routes hosts)

**Interfaces:**
- `intel::dns`:
```rust
pub const MAX_RESOLVERS: usize = 5;
pub const MAX_FOLLOWED: usize = 16;
/// Lower-cased, dot-trimmed, each label ≤ 63 chars of [a-z0-9-] (non-ASCII labels are
/// IDNA-encoded with a small in-tree punycode encoder, RFC 3492 §6.3), total ≤ 253, at least one dot.
pub fn valid_name(input: &str) -> Option<String>;
#[derive(Serialize, Deserialize)] pub struct ResolveReq { pub name: String }
#[derive(Serialize, Deserialize)] pub struct ResolveResp { pub addrs: Vec<IpAddr>, #[serde(default)] pub error: Option<String> }
/// This node's own answer: the system resolver, 5 s, global unicast only, sorted, deduplicated.
pub async fn resolve_here(name: &str) -> Result<Vec<IpAddr>, String>;
pub struct Resolver { pub id: NodeId, pub name: String, pub sibling: bool, pub country: Option<String> }
/// Up to MAX_RESOLVERS: this node, then random live members preferring non-siblings and unseen countries.
pub fn choose(node: &Node, siblings: &HashSet<NodeId>, geo: &SharedGeo) -> Vec<Resolver>;
pub struct Vote { pub addr: IpAddr, pub votes: usize, pub agreed: bool }
pub struct Tally { pub asked: usize, pub answered: usize, pub votes: Vec<Vote>, pub errors: Vec<(NodeId, String)> }
/// Per address: agreed when votes > answered / 2 (answered ≥ 1). Non-global answers are dropped first.
pub fn tally(answers: &[(NodeId, Result<Vec<IpAddr>, String>)]) -> Tally;
/// Ask the chosen resolvers (RPC `/rpc/v1/resolve`, RPC_TIMEOUT), build the record, write it (cluster: replicated; standalone: local), return the tally.
pub async fn lookup(rec: &Recorder, geo: &SharedGeo, name: &str) -> Result<(Tally, Option<IpNameRec>), String>;
```
- RPC: `POST /rpc/v1/resolve` (members only) → validates the name, `node.take_free_resolve(peer)` (60/h, a second map beside `free_lookups`), `resolve_here`, answers `ResolveResp`. It never scans, probes or stores.
- `store/probes.rs::apply_ip_name`: ignore records with `name` invalid, `> MAX_RESOLVERS` answers, or an answer list longer than 64 addresses; **re-derive** the tally with `dns::tally(&r.answers)` (never trust a tally field — there is none); for every address in the tally, `ensure_ip` and upsert `ip_names` (`first_seen` kept, `last_seen = r.at`, `agreed`, `asked`, `answered`, `votes`, `record_uid`); addresses with zero votes after dropping non-global ones get no row. `Store::names_for_ip(ip_id) -> Vec<NameRow { name, source, first_seen, last_seen, agreed: bool, asked, answered, votes }>`; `Store::ips_named(name) -> Vec<(IpRow, NameRow)>`.
- Admin: the Lookup form accepts a name; the page shows a "Resolved" card: per address a row "203.0.113.5 — agreed by 4 of 5" or "— only from bob (DE), disputed", the resolvers with their countries, errors per resolver; the first `MAX_FOLLOWED` agreed addresses are each looked up (cheap tier) and rendered as today's single-address result stacked; one resolver → "unverified — single resolver"; standalone → "resolved locally, unverified". IP page: a Names line under Intelligence (`_names.html`): `example.com (DNS, agreed 4/5, 2026-10-07)` or `(DNS, disputed 1/5)`; admin-only — the public IP page never renders names (spec: nothing on the public wall).
- Export: `PageContext.names: HashMap<i64, Vec<NameOut>>`, a `names` JSON column `[{"name": "example.com", "source": "dns", "first_seen": "…", "last_seen": "…", "votes": 4, "answered": 5}]` holding agreed names only; documented in `docs/dataset.md` under "Everything else known about the address".

- [ ] **Step 1: Write the failing tests**

`src/intel/dns.rs`:
```rust
#[test]
fn names_are_validated_and_normalised() {
    assert_eq!(valid_name(" Example.COM. ").as_deref(), Some("example.com"));
    assert_eq!(valid_name("bücher.example").as_deref(), Some("xn--bcher-kva.example"));
    assert!(valid_name("localhost").is_none(), "needs a dot");
    assert!(valid_name("-bad.example").is_none());
    assert!(valid_name(&format!("{}.example", "a".repeat(64))).is_none());
    assert!(valid_name("http://example.com").is_none());
    assert!(valid_name("203.0.113.1").is_none(), "an address is not a name");
}

#[test]
fn the_majority_is_per_address_over_those_that_answered() {
    let n = |i: u8| NodeId([i; 32]);
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let t = tally(&[
        (n(1), Ok(vec![ip("203.0.113.1"), ip("203.0.113.2")])),
        (n(2), Ok(vec![ip("203.0.113.1")])),
        (n(3), Ok(vec![ip("203.0.113.1"), ip("10.0.0.1")])),
        (n(4), Err("timed out".into())),
        (n(5), Ok(vec![ip("198.51.100.9")])),
    ]);
    assert_eq!((t.asked, t.answered), (5, 4));
    let v = |a: &str| t.votes.iter().find(|v| v.addr == ip(a)).map(|v| (v.votes, v.agreed));
    assert_eq!(v("203.0.113.1"), Some((3, true)));
    assert_eq!(v("203.0.113.2"), Some((1, false)));
    assert_eq!(v("198.51.100.9"), Some((1, false)), "the odd one out is kept, disputed");
    assert_eq!(v("10.0.0.1"), None, "private answers are dropped");
    assert_eq!(t.errors.len(), 1);
    // Two responders: both must agree. One: unverified (agreed, answered == 1).
    let t2 = tally(&[(n(1), Ok(vec![ip("203.0.113.1")])), (n(2), Ok(vec![ip("203.0.113.3")]))]);
    assert!(t2.votes.iter().all(|v| !v.agreed));
    let t1 = tally(&[(n(1), Ok(vec![ip("203.0.113.1")]))]);
    assert!(t1.votes[0].agreed && t1.answered == 1);
}

#[test]
fn resolvers_prefer_non_siblings_and_new_countries() { /* build a Node-free variant: `pick(candidates: &[Resolver], n)`; assert order and the cap of 5 */ }
```
`src/store/probes.rs`:
```rust
#[tokio::test]
async fn votes_are_derived_locally_not_trusted() {
    // A record whose answers name a private address and an address only one of three returned.
    let r = IpNameRec { uid: new_uid(), name: "example.com".into(), at: now_ts(), answers: vec![
        (NodeId([1;32]), Ok(vec!["203.0.113.1".parse().unwrap(), "10.0.0.1".parse().unwrap()])),
        (NodeId([2;32]), Ok(vec!["203.0.113.1".parse().unwrap()])),
        (NodeId([3;32]), Ok(vec!["203.0.113.7".parse().unwrap()])),
    ], build: String::new() };
    // apply → ip_names has 203.0.113.1 agreed (2/3), 203.0.113.7 disputed, nothing for 10.0.0.1.
}

#[tokio::test]
async fn no_answer_at_all_writes_no_record() {
    // dns::lookup on a standalone Recorder with a name whose resolution fails (use "invalid." TLD → NXDOMAIN or an unresolvable label):
    // returns Ok((tally with answered == 0, None)) and ip_names stays empty.
}
```
`src/admin/lookup.rs`: `a_domain_lookup_shows_votes_and_the_agreed_addresses` (standalone, resolve "localhost.example"? — unresolvable in CI; instead inject: `dns::lookup_with(rec, geo, name, resolve: impl Fn(&str) -> …)`, test-only hook that returns a fixed answer set; assert the page shows "resolved locally, unverified" and the address row). `src/store/export.rs`: `agreed_names_are_exported_disputed_ones_are_not`.

- [ ] **Step 2: Run** → compile errors.
- [ ] **Step 3: Implement** `dns.rs` (validation incl. a ~40-line punycode encoder per RFC 3492; `resolve_here` via `tokio::net::lookup_host((name, 0))` under `timeout(5 s)`, filtered by `net::is_scannable_target`; `choose`/`pick`; `tally`; `lookup` writing `Record::IpName` through `rec.write(..)` only when `answered > 0`), the RPC route and `take_free_resolve`, `apply_ip_name` + readers, the admin flow (`lookup` handler: `valid_name` → `dns::lookup` → per agreed address `run(.., cheap)`; a new `LookupPage.names: Option<NamesView>`), `_names.html`, export column + `docs/dataset.md`.
- [ ] **Step 4: Run** `cargo test intel::dns && cargo test store::probes && cargo test admin::lookup && cargo test store::export` → PASS.
- [ ] **Step 5: Commit** `git add -A src templates docs/dataset.md && git commit -m "Lookup: domains resolved by several nodes, per-address majority, names in the dataset"`

---

### Task 13: Docs and the roadmap

**Files:**
- Modify: `README.md:34-40`, `docs/cluster.md:149-226`, `docs/roadmap.md:134-160,189-190`, `docs/operations.md` (`[probe]` keys), `docs/dataset.md` (done in Task 12; verify), `docs/superpowers/specs/2026-10-06-scan-details-design.md:8` (mark §1 as implemented here)

- [ ] **Step 1: README** — reword the counter-scan bullet: "…four levels that escalate by scope …, never by speed or aggressiveness — that rule governs the automatic counter-scans. On request an admin can also run an *observational probe* of the ports a scan found open (headers, certificates, JARM, SSH host keys), from one scanner or several at once." Add RDAP to the Enrichment bullet.
- [ ] **Step 2: docs/cluster.md** — in "Credits": a "Probes" sub-bullet (price = 4 units × surge, announced per scanner, paid per vantage, half destroyed, the two-phase answer and the 15-minute lapse, nothing minted); in "Known addresses": the cheap tier runs by itself, paid providers are offered with prices; a new "Domains" bullet (5 resolvers, per-address majority, disputed names shown, replicated as `ip_name`); in "What this cannot do": "A majority of colluding resolvers can agree on a wrong address; the per-address votes are shown so a single odd answer stands out."
- [ ] **Step 3: docs/operations.md** — `[probe] enabled`, `max_parallel`; the peer-observed public address sentence (Task 2).
- [ ] **Step 4: docs/roadmap.md** — remove "Peer-observed public address" and the OpenSSH ≥ 10 note (both done; add one line under a "Done in 0.8" note if the file keeps such a section, else delete); reword "Actions on an IP in Lookup" to "**Queue a counter-scan or block from the Lookup page.** S–M, low. The probe and vantage actions exist; the manual scan queue and the block action do not yet." Update the scan-details spec's item list (line 8) with "(implemented by the lookup-actions plan)".
- [ ] **Step 5: Run the whole suite once** — `rm -rf target/debug/deps/*-* 2>/dev/null; cargo test` (prune first: the disk fills with stale test binaries) → PASS. Fix anything the docs or clippy (`cargo clippy --all-targets`) point at.
- [ ] **Step 6: Commit** `git add -A README.md docs && git commit -m "Docs: probes, vantages, RDAP, domains; roadmap items done"`

---

## Self-review notes (done while writing)

- **Spec coverage:** §1 → Task 1; §2 → Tasks 4–7 (output record, tables, host keys, caps, gating, redirects, RTT); §3 → Tasks 2, 3, 7 (`vantage_ip`, `public_addrs`), 11 (diff, light-speed); §4 → Task 7 (`accept_offer`, two-phase, batch append, charge rules, standalone); §5 → Tasks 9, 10; §6 → Task 12; "Tests" list → spread over the tasks' Step 1s; "Not in this spec" → Task 13 roadmap wording.
- **Known gaps accepted:** the SSE `probes` event is driven by the node's change watch rather than a dedicated notifier (same effect, no new plumbing); pending-probe state is in memory and lost on restart (documented in the template).
- **Type consistency:** `ProbeResultRec`/`ProbePortRec`/`IpNameRec` names and fields are identical in Tasks 4, 6, 7, 10, 12; `Prober::{serve, run_local, busy, check}` as used in 7 and 10; `Coords`/`haversine_km` from Task 3 used in 11; `LinkKind` keys from Task 8 used in Task 10's `links`.
- **Review Focus:** items 1–2 pinned in Task 5/6 tests (`a_hop_to_protected_space_is_skipped`, `a_slow_port_times_out_and_the_probe_continues`); item 3 needs a test in Task 7 — add `an_accepted_probe_without_a_result_lapses` to `src/admin/probes.rs` (Task 10): insert a pending entry dated 16 min ago with no `probes` row → state `lapsed`, and `actions_for` still `allowed`; items 4–5 pinned in Task 12 (`no_answer_at_all_writes_no_record`, `votes_are_derived_locally_not_trusted`).
