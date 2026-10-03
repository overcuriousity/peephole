//! What a counter-scan must be backed by, and how much one source can make
//! a node queue.
//!
//! - **Evidence**: the requests (and browser fingerprints) recorded from an
//!   IP justify a scan level. A scanner checks a job against them before it
//!   runs it, so an arbiter cannot have it scan an IP nobody saw, or at a
//!   level nothing asked for. It classifies the requests again with its own
//!   rules, so neither can a node whose rules ask for more than ours.
//! - **Thin evidence**: one request is easily caused by a bystander (a link
//!   preview, a URL scanner or a crawler following a link to the trap), so
//!   it earns at most `scan.single_request_max_level`.
//! - **Queue budgets**: per /24 or /64 network, per autonomous system and in
//!   total, so a flood of sources cannot fill the queue.
use crate::classify::Classifier;
use crate::classify::stored::{History, StoredRequest};
use crate::cluster::identity::NodeId;
use crate::config::ScanSafety;
use crate::intel::tor::{MIN_EXITS, TorExitList};
use anyhow::Result;
use ipnet::IpNet;
use sqlx::SqlitePool;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::SystemTime;

/// What the records about one IP justify.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Evidence {
    /// Highest level a request (or fingerprint) of the IP asked for.
    pub max_level: u8,
    /// Requests recorded from the IP (false-positive claims excluded).
    pub requests: u32,
    /// Distinct rule labels across those requests.
    pub labels: u32,
}

impl Evidence {
    /// Whether the evidence is thin: fewer than `full_scan_min_requests`
    /// requests, and not two requests with different labels.
    pub fn thin(&self, s: &ScanSafety) -> bool {
        self.requests < s.full_scan_min_requests && !(self.requests >= 2 && self.labels >= 2)
    }

    /// Highest level this evidence allows.
    pub fn allowed_level(&self, s: &ScanSafety) -> u8 {
        if self.thin(s) {
            self.max_level.min(s.single_request_max_level)
        } else {
            self.max_level
        }
    }
}

/// Which origins' records count as evidence. Rows without an origin were
/// written standalone (by this node).
#[derive(Debug, Clone)]
pub enum Origins {
    Any,
    /// This node plus the listed ones.
    Only {
        me: Option<NodeId>,
        others: HashSet<NodeId>,
    },
}

impl Origins {
    /// From `scan.trusted_origins` (validated by `Config::load`).
    pub fn from_config(s: &ScanSafety, me: Option<NodeId>) -> Self {
        match &s.trusted_origins {
            None => Origins::Any,
            Some(list) => Origins::Only {
                me,
                others: list.iter().filter_map(|o| NodeId::parse(o).ok()).collect(),
            },
        }
    }

    fn admits(&self, origin: Option<&[u8]>) -> bool {
        match (self, origin) {
            (Origins::Any, _) | (_, None) => true,
            (Origins::Only { me, others }, Some(o)) => {
                let Ok(id) = NodeId::from_slice(o) else {
                    return false;
                };
                *me == Some(id) || others.contains(&id)
            }
        }
    }
}

/// Requests and fingerprints considered per IP (newest first).
const EVIDENCE_ROWS: i64 = 1000;
const FINGERPRINT_ROWS: i64 = 50;
/// Requests classified again per evidence check, at most.
const RECLASSIFY_ROWS: usize = 200;

/// The evidence recorded about `ip` (its text as stored in `ips`).
///
/// With `verify`, each request counts for what this node's rules make of
/// it, not only for what its origin stored: its level is the lower of the
/// stored one and the one `verify` gives it again
/// ([`crate::classify::stored`]), and its labels are those `verify` gives
/// it. So a node with tampered rules cannot make others scan harder than
/// their own rules allow. Rows are examined highest stored level first, and
/// only until no row left can raise the level (its stored level caps it)
/// and two labels are known (all [`Evidence::thin`] asks of them), at most
/// [`RECLASSIFY_ROWS`]; `labels` is then a lower bound.
///
/// Without `verify`, the stored verdicts count as they are: for the trap
/// queueing a scan on what it has just classified itself. A scanner always
/// verifies, with the rules built into its binary.
pub async fn evidence(
    pool: &SqlitePool,
    ip: &str,
    origins: &Origins,
    verify: Option<&Classifier>,
) -> Result<Evidence> {
    type Req = (i64, i64, String, Option<Vec<u8>>);
    let rows: Vec<Req> = sqlx::query_as(
        "SELECT r.id, r.scan_level, r.labels_json, r.origin
         FROM requests r JOIN ips i ON i.id = r.ip_id
         WHERE i.ip = ? AND r.is_fp_claim = 0 ORDER BY r.id DESC LIMIT ?",
    )
    .bind(ip)
    .bind(EVIDENCE_ROWS)
    .fetch_all(pool)
    .await?;
    let mut rows: Vec<Req> = rows
        .into_iter()
        .filter(|r| origins.admits(r.3.as_deref()))
        .collect();
    let mut ev = Evidence {
        requests: rows.len() as u32,
        ..Evidence::default()
    };
    let level = |l: i64| l.clamp(0, 4) as u8;
    let mut labels = HashSet::new();
    match verify {
        None => {
            for (_, stored, labels_json, _) in rows {
                ev.max_level = ev.max_level.max(level(stored));
                if let Ok(l) = serde_json::from_str::<Vec<String>>(&labels_json) {
                    labels.extend(l);
                }
            }
        }
        Some(c) => {
            // Stable: newest first within a level.
            rows.sort_by_key(|r| std::cmp::Reverse(r.1));
            for (n, (id, stored, _, _)) in rows.into_iter().enumerate() {
                let stored = level(stored);
                if n >= RECLASSIFY_ROWS || (stored <= ev.max_level && labels.len() >= 2) {
                    break;
                }
                let Some(row) = StoredRequest::load(pool, id).await? else {
                    continue;
                };
                let local = row.reclassify(pool, c, History::Seen).await?;
                ev.max_level = ev.max_level.max(stored.min(local.scan_level));
                labels.extend(local.labels);
            }
        }
    }
    ev.labels = labels.len() as u32;
    // A browser fingerprint that gives a bot away escalates a scan (trap
    // `/collect`): webdriver to level 2, an inhuman form fill to level 3.
    type Fp = (Option<String>, Option<String>, Option<Vec<u8>>);
    let fps: Vec<Fp> = sqlx::query_as(
        "SELECT f.attributes_json, f.behavior_summary_json, f.origin
         FROM fingerprints f JOIN ips i ON i.id = f.ip_id
         WHERE i.ip = ? ORDER BY f.id DESC LIMIT ?",
    )
    .bind(ip)
    .bind(FINGERPRINT_ROWS)
    .fetch_all(pool)
    .await?;
    for (attrs, behavior, origin) in fps {
        if !origins.admits(origin.as_deref()) {
            continue;
        }
        let parse = |s: Option<String>| {
            s.and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::Value::Null)
        };
        let tells = crate::fingerprint::bot_tells(&parse(attrs), &parse(behavior));
        let level = if tells.inhuman_fill {
            3
        } else if tells.webdriver {
            2
        } else {
            0
        };
        ev.max_level = ev.max_level.max(level);
    }
    Ok(ev)
}

/// The /24 (IPv4) or /64 (IPv6) network of an address.
pub fn network(ip: IpAddr) -> IpNet {
    let ip = crate::net::canonical(ip);
    let len = if ip.is_ipv4() { 24 } else { 64 };
    IpNet::new(ip, len)
        .expect("prefix length fits the family")
        .trunc()
}

/// Other IPs of `ip`'s network with a job queued in the last
/// `window_hours` (refused and superseded jobs excluded). Exact: matched on
/// the indexed `ip_key` range, so every spelling of an address counts once.
pub async fn queued_in_network(pool: &SqlitePool, ip: &str, window_hours: i64) -> Result<usize> {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return Ok(0);
    };
    let net = network(addr);
    let (lo, hi) = crate::store::net_key_range(&net);
    // IPv4 keys live in ::ffff:0:0/96, inside ::/64; an IPv6 network still
    // means IPv6 addresses only.
    let v4_keys = if net.addr().is_ipv6() {
        "00000000000000000000ffff%"
    } else {
        ""
    };
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT i.ip_key) FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
         WHERE j.queued_at > datetime('now', ?) AND j.status NOT IN ('refused','superseded')
           AND i.ip_key BETWEEN ? AND ? AND i.ip_key != ? AND i.ip_key NOT LIKE ?",
    )
    .bind(format!("-{window_hours} hours"))
    .bind(lo)
    .bind(hi)
    .bind(crate::store::ip_key(addr))
    .bind(v4_keys)
    .fetch_one(pool)
    .await?;
    Ok(n as usize)
}

/// Jobs queued in the last hour for IPs of autonomous system `asn`.
pub async fn queued_in_asn_last_hour(pool: &SqlitePool, asn: i64) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
         WHERE i.asn = ? AND j.queued_at > datetime('now', '-1 hour')
           AND j.status NOT IN ('refused','superseded')",
    )
    .bind(asn)
    .fetch_one(pool)
    .await?)
}

/// What enqueuing applies besides the per-IP cooldown.
#[derive(Debug, Clone)]
pub struct EnqueuePolicy {
    pub cooldown_hours: i64,
    /// None: no evidence cap (tests, callers that checked already).
    pub safety: Option<ScanSafety>,
}

impl EnqueuePolicy {
    /// The trap's policy: `[scan]` safety settings and the current cooldown.
    pub fn new(s: &ScanSafety, cooldown_hours: i64) -> Self {
        Self {
            cooldown_hours,
            safety: Some(s.clone()),
        }
    }

    /// Only the per-IP cooldown (what `enqueue_scan` always did).
    pub fn cooldown_only(cooldown_hours: i64) -> Self {
        Self {
            cooldown_hours,
            safety: None,
        }
    }
}

/// Tor exit status of an IP as a scanner sees it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TorStatus {
    Exit,
    NotExit,
    /// No exit list loaded here and no node recorded a result for the IP.
    Unknown,
}

/// The scanner's own view of the exit list file (`<data_dir>/tor-exit.txt`,
/// fetched or copied from the cluster by the intel scheduler), reloaded when
/// the file changes. A list that fails the sanity check counts as none.
pub struct TorView {
    path: PathBuf,
    stamp: Option<(SystemTime, u64)>,
    list: Option<TorExitList>,
}

impl TorView {
    pub fn new(data_dir: &std::path::Path) -> Self {
        Self {
            path: data_dir.join("tor-exit.txt"),
            stamp: None,
            list: None,
        }
    }

    fn refresh(&mut self) {
        let stamp = std::fs::metadata(&self.path)
            .ok()
            .and_then(|m| Some((m.modified().ok()?, m.len())));
        if stamp == self.stamp {
            return;
        }
        self.stamp = stamp;
        self.list = stamp
            .and_then(|_| TorExitList::load(self.path.parent()?).ok())
            .filter(|l| l.len() as u64 > MIN_EXITS);
    }

    /// Whether a sane list is loaded.
    pub fn loaded(&mut self) -> bool {
        self.refresh();
        self.list.is_some()
    }

    /// Local list hit, then any node's recorded result.
    pub fn local(&mut self, ip: &IpAddr) -> Option<bool> {
        self.refresh();
        self.list
            .as_ref()
            .map(|l| l.contains(&crate::net::canonical(*ip)))
    }
}

/// How long a recorded "not an exit" holds. Exit lists change daily; an
/// older verdict counts as unknown (an "exit" always counts).
const NOT_EXIT_MAX_AGE_HOURS: i64 = 72;

/// Tor status of `ip` (its text as stored): this node's list, and the
/// results every node recorded (`ip_intel`). Any "exit" wins; a "not an
/// exit" counts only while fresh.
pub async fn tor_status(pool: &SqlitePool, local: Option<bool>, ip: &str) -> Result<TorStatus> {
    if local == Some(true) {
        return Ok(TorStatus::Exit);
    }
    let rows: Vec<(String, bool)> = sqlx::query_as(
        "SELECT data_json, fetched_at >= datetime('now', ?) FROM ip_intel
         WHERE ip = ? AND provider = ?",
    )
    .bind(format!("-{NOT_EXIT_MAX_AGE_HOURS} hours"))
    .bind(ip)
    .bind(crate::intel::TOR)
    .fetch_all(pool)
    .await?;
    let said: Vec<bool> = rows
        .iter()
        .filter_map(|(r, fresh)| {
            let exit = serde_json::from_str::<serde_json::Value>(r)
                .ok()?
                .get("exit")?
                .as_bool()?;
            (exit || *fresh).then_some(exit)
        })
        .collect();
    Ok(if said.contains(&true) {
        TorStatus::Exit
    } else if local.is_some() || !said.is_empty() {
        TorStatus::NotExit
    } else {
        TorStatus::Unknown
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::store::requests::NewRequest;

    fn req(ip_id: i64, level: i64, labels: &str) -> NewRequest {
        NewRequest {
            ip_id,
            method: "GET".into(),
            path: "/x".into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: labels.into(),
            severity: level,
            scan_level: level,
            is_fp_claim: false,
            page_token: None,
            ..Default::default()
        }
    }

    #[test]
    fn thin_evidence_is_capped() {
        let s = ScanSafety::default();
        let ev = |max_level, requests, labels| Evidence {
            max_level,
            requests,
            labels,
        };
        // One request asking for 4: capped to 2.
        assert_eq!(ev(4, 1, 1).allowed_level(&s), 2);
        assert_eq!(ev(4, 1, 3).allowed_level(&s), 2, "one request, many labels");
        // Two requests, one label: still thin; two labels: not.
        assert_eq!(ev(4, 2, 1).allowed_level(&s), 2);
        assert_eq!(ev(4, 2, 2).allowed_level(&s), 4);
        // Enough requests.
        assert_eq!(ev(4, 3, 1).allowed_level(&s), 4);
        // Never above what was asked for.
        assert_eq!(ev(1, 1, 1).allowed_level(&s), 1);
        assert_eq!(ev(0, 9, 9).allowed_level(&s), 0);
        // Cap off.
        let off = ScanSafety {
            single_request_max_level: 4,
            ..ScanSafety::default()
        };
        assert_eq!(ev(4, 1, 1).allowed_level(&off), 4);
    }

    #[tokio::test]
    async fn evidence_counts_requests_labels_and_origins() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store
            .upsert_ip("198.51.100.4".parse().unwrap())
            .await
            .unwrap();
        let rec = store.local();
        rec.insert_request(&req(ip.id, 3, r#"["sqli"]"#))
            .await
            .unwrap();
        rec.insert_request(&req(ip.id, 1, r#"["probe","sqli"]"#))
            .await
            .unwrap();
        let mut claim = req(ip.id, 0, r#"["fp-claim"]"#);
        claim.is_fp_claim = true;
        rec.insert_request(&claim).await.unwrap();
        let ev = evidence(&store.pool, &ip.ip, &Origins::Any, None)
            .await
            .unwrap();
        assert_eq!(
            ev,
            Evidence {
                max_level: 3,
                requests: 2,
                labels: 2
            }
        );
        // Standalone rows (no origin) are this node's, whatever the list.
        let only = Origins::Only {
            me: None,
            others: HashSet::new(),
        };
        assert_eq!(
            evidence(&store.pool, &ip.ip, &only, None).await.unwrap(),
            ev
        );
        // A row from another node counts only when that node is trusted.
        let other = crate::cluster::identity::Identity::generate().unwrap().id;
        sqlx::query("UPDATE requests SET origin = ? WHERE scan_level = 3")
            .bind(&other.0[..])
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            evidence(&store.pool, &ip.ip, &only, None)
                .await
                .unwrap()
                .max_level,
            1
        );
        let trusting = Origins::Only {
            me: None,
            others: [other].into(),
        };
        assert_eq!(
            evidence(&store.pool, &ip.ip, &trusting, None)
                .await
                .unwrap()
                .max_level,
            3
        );
        // Nothing recorded: nothing justified.
        assert_eq!(
            evidence(&store.pool, "203.0.113.200", &Origins::Any, None)
                .await
                .unwrap(),
            Evidence::default()
        );
    }

    /// Classified again with our rules, a harmless request claiming level 4
    /// backs level 1, and its labels are the ones our rules give; an honest
    /// path scanner's level 2 (from its history) still counts.
    #[tokio::test]
    async fn verified_evidence_counts_what_our_rules_see() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let rules = Classifier::builtin();
        let rec = store.local();
        let ip = store
            .upsert_ip("198.51.100.6".parse().unwrap())
            .await
            .unwrap();
        for _ in 0..3 {
            let mut r = req(ip.id, 4, r#"["rce","sqli"]"#);
            r.path = "/index.html".into();
            rec.insert_request(&r).await.unwrap();
        }
        let other = crate::cluster::identity::Identity::generate().unwrap().id;
        sqlx::query("UPDATE requests SET origin = ?")
            .bind(&other.0[..])
            .execute(&store.pool)
            .await
            .unwrap();
        let s = ScanSafety::default();
        let trusted = evidence(&store.pool, &ip.ip, &Origins::Any, None)
            .await
            .unwrap();
        assert_eq!(trusted.allowed_level(&s), 4);
        let ev = evidence(&store.pool, &ip.ip, &Origins::Any, Some(rules))
            .await
            .unwrap();
        assert_eq!(
            ev,
            Evidence {
                max_level: 1,
                requests: 3,
                labels: 1
            }
        );
        assert_eq!(ev.allowed_level(&s), 1);
        // A stored level below what our rules see caps it.
        let mut r = req(ip.id, 1, r#"["probe"]"#);
        r.path = "/.env".into();
        rec.insert_request(&r).await.unwrap();
        let ev = evidence(&store.pool, &ip.ip, &Origins::Any, Some(rules))
            .await
            .unwrap();
        assert_eq!((ev.max_level, ev.labels), (1, 2), "{ev:?}");

        // Twenty paths in an hour: our rules see the path scanner too.
        let scanner = store
            .upsert_ip("198.51.100.7".parse().unwrap())
            .await
            .unwrap();
        for n in 0..20 {
            let level = if n >= 9 { 2 } else { 1 };
            let mut r = req(scanner.id, level, r#"["probe"]"#);
            r.path = format!("/p{n}");
            rec.insert_request(&r).await.unwrap();
        }
        let ev = evidence(&store.pool, &scanner.ip, &Origins::Any, Some(rules))
            .await
            .unwrap();
        assert_eq!(ev.max_level, 2);
    }

    #[tokio::test]
    async fn fingerprint_tells_are_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store
            .upsert_ip("198.51.100.5".parse().unwrap())
            .await
            .unwrap();
        let rec = store.local();
        rec.insert_request(&req(ip.id, 0, "[]")).await.unwrap();
        rec.insert_fingerprint(
            None,
            ip.id,
            "h",
            None,
            r#"{"webdriver":true}"#,
            r#"{"fill_seconds":0.2,"mouse_events":0}"#,
            b"",
        )
        .await
        .unwrap();
        let ev = evidence(&store.pool, &ip.ip, &Origins::Any, None)
            .await
            .unwrap();
        assert_eq!(ev.max_level, 3);
    }

    use crate::store::scans::EnqueueOutcome;

    async fn level_of(store: &Store, job: i64) -> (i64, String) {
        sqlx::query_as("SELECT level, status FROM scan_jobs WHERE id = ?")
            .bind(job)
            .fetch_one(&store.pool)
            .await
            .unwrap()
    }

    fn queued(o: EnqueueOutcome) -> i64 {
        match o {
            EnqueueOutcome::Queued(id) => id,
            o => panic!("not queued: {o:?}"),
        }
    }

    /// One request asking for level 4 queues level 2; more evidence lifts
    /// the cap (the higher level is the one upgrade the cooldown allows).
    #[tokio::test]
    async fn enqueue_caps_thin_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let rec = store.local();
        let policy = EnqueuePolicy::new(&ScanSafety::default(), 24);
        let ip = store
            .upsert_ip("198.51.100.20".parse().unwrap())
            .await
            .unwrap();
        rec.insert_request(&req(ip.id, 4, r#"["rce"]"#))
            .await
            .unwrap();
        let job = queued(rec.enqueue_scan_with(ip.id, 4, &policy).await.unwrap());
        assert_eq!(level_of(&store, job).await.0, 2);
        rec.insert_request(&req(ip.id, 4, r#"["rce"]"#))
            .await
            .unwrap();
        rec.insert_request(&req(ip.id, 4, r#"["rce"]"#))
            .await
            .unwrap();
        let job = queued(rec.enqueue_scan_with(ip.id, 4, &policy).await.unwrap());
        assert_eq!(level_of(&store, job).await.0, 4);
        // Not a level: not queued.
        for bad in [0, 5, 200] {
            assert_eq!(
                rec.enqueue_scan_with(ip.id, bad, &policy).await.unwrap(),
                EnqueueOutcome::Suppressed
            );
        }
    }

    #[tokio::test]
    async fn enqueue_budgets_per_network_and_asn() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let rec = store.local();
        let s = ScanSafety {
            prefix_max_scans: 2,
            asn_max_per_hour: 3,
            ..ScanSafety::default()
        };
        let policy = EnqueuePolicy::new(&s, 24);
        let add = async |ip: &str, asn: Option<u32>| {
            let row = store.upsert_ip(ip.parse().unwrap()).await.unwrap();
            if asn.is_some() {
                store
                    .set_ip_geo(row.id, Some("DE"), asn, None)
                    .await
                    .unwrap();
            }
            rec.enqueue_scan_with(row.id, 1, &policy).await.unwrap()
        };
        // Two IPs of 198.51.100.0/24, then the network is used up.
        queued(add("198.51.100.1", None).await);
        queued(add("198.51.100.2", None).await);
        assert!(matches!(
            add("198.51.100.3", None).await,
            EnqueueOutcome::Throttled(_)
        ));
        // Same for an IPv6 /64.
        queued(add("2001:db8:0:1::1", None).await);
        queued(add("2001:db8:0:1::2", None).await);
        assert!(matches!(
            add("2001:db8:0:1:ffff::3", None).await,
            EnqueueOutcome::Throttled(_)
        ));
        queued(add("2001:db8:0:2::1", None).await);
        // Three per hour from AS64500, whatever the network.
        queued(add("203.0.113.1", Some(64500)).await);
        queued(add("192.0.2.1", Some(64500)).await);
        queued(add("198.18.5.1", Some(64500)).await);
        assert!(matches!(
            add("198.18.9.1", Some(64500)).await,
            EnqueueOutcome::Throttled(_)
        ));
        queued(add("198.18.9.2", Some(64501)).await);
    }

    /// A full queue makes room for a more urgent job by dropping its oldest
    /// lowest-level one, and otherwise takes no more.
    #[tokio::test]
    async fn a_full_queue_drops_the_least_urgent_job() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let rec = store.local();
        let s = ScanSafety {
            max_queued: 2,
            single_request_max_level: 4,
            ..ScanSafety::default()
        };
        let policy = EnqueuePolicy::new(&s, 24);
        let mut ids = vec![];
        for (ip, level) in [("198.51.100.1", 1), ("198.51.101.1", 2)] {
            let row = store.upsert_ip(ip.parse().unwrap()).await.unwrap();
            ids.push(queued(
                rec.enqueue_scan_with(row.id, level, &policy).await.unwrap(),
            ));
        }
        let row = store
            .upsert_ip("198.51.102.1".parse().unwrap())
            .await
            .unwrap();
        assert!(matches!(
            rec.enqueue_scan_with(row.id, 1, &policy).await.unwrap(),
            EnqueueOutcome::Throttled(_)
        ));
        queued(rec.enqueue_scan_with(row.id, 3, &policy).await.unwrap());
        assert_eq!(
            level_of(&store, ids[0]).await.1,
            "refused",
            "level 1 dropped"
        );
        assert_eq!(level_of(&store, ids[1]).await.1, "queued");
    }

    /// The per-network count is exact: neighbouring networks sharing a
    /// textual prefix (however many) cannot crowd out the network's own
    /// rows, and an IPv4 address counts once whatever its spelling.
    #[tokio::test]
    async fn queued_in_network_is_exact() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut tx = store.pool.begin().await.unwrap();
        let mut add = async |ip: &str| {
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO ips (ip, ip_key, first_seen, last_seen)
                 VALUES (?, ?, datetime('now'), datetime('now')) RETURNING id",
            )
            .bind(ip)
            .bind(crate::store::ip_key_of(ip).unwrap())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO scan_jobs (uid, ip_id, level, status, queued_at)
                 VALUES (?, ?, 1, 'queued', datetime('now'))",
            )
            .bind(format!("job-{id}"))
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
        };
        // Same first 16 bits, other /64s: more than any old prefilter limit.
        for n in 0..10_050u32 {
            add(&format!("2001:{:x}:{:x}::1", n >> 16, n & 0xffff)).await;
        }
        for ip in ["2001:db8:0:1::1", "2001:db8:0:1::2", "2001:db8:0:1:ffff::3"] {
            add(ip).await;
        }
        add("198.51.100.1").await;
        add("::ffff:198.51.100.1").await;
        add("198.51.100.2").await;
        add("198.51.101.1").await;
        tx.commit().await.unwrap();
        let p = &store.pool;
        assert_eq!(
            queued_in_network(p, "2001:db8:0:1::9", 24).await.unwrap(),
            3
        );
        assert_eq!(
            queued_in_network(p, "2001:db8:0:1::1", 24).await.unwrap(),
            2
        );
        assert_eq!(queued_in_network(p, "198.51.100.7", 24).await.unwrap(), 2);
        assert_eq!(
            queued_in_network(p, "::ffff:198.51.100.2", 24)
                .await
                .unwrap(),
            1
        );
        assert_eq!(queued_in_network(p, "::9", 24).await.unwrap(), 0);
    }

    #[test]
    fn networks_and_patterns() {
        let n = network("198.51.100.77".parse().unwrap());
        assert_eq!(n.to_string(), "198.51.100.0/24");
        let n = network("2001:db8:1:2:3::4".parse().unwrap());
        assert_eq!(n.to_string(), "2001:db8:1:2::/64");
        assert_eq!(
            network("::ffff:198.51.100.1".parse().unwrap()).to_string(),
            "198.51.100.0/24"
        );
    }

    #[tokio::test]
    async fn tor_status_combines_local_list_and_results() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let p = &store.pool;
        assert_eq!(
            tor_status(p, None, "198.51.100.9").await.unwrap(),
            TorStatus::Unknown
        );
        assert_eq!(
            tor_status(p, Some(false), "198.51.100.9").await.unwrap(),
            TorStatus::NotExit
        );
        assert_eq!(
            tor_status(p, Some(true), "198.51.100.9").await.unwrap(),
            TorStatus::Exit
        );
        let rec = store.local();
        rec.record_intel(
            "198.51.100.9",
            crate::intel::TOR,
            None,
            serde_json::json!({"exit": false}),
        )
        .await
        .unwrap();
        assert_eq!(
            tor_status(p, None, "198.51.100.9").await.unwrap(),
            TorStatus::NotExit
        );
        rec.record_intel(
            "198.51.100.10",
            crate::intel::TOR,
            None,
            serde_json::json!({"exit": true}),
        )
        .await
        .unwrap();
        // Another node's "exit" beats our list's silence.
        assert_eq!(
            tor_status(p, Some(false), "198.51.100.10").await.unwrap(),
            TorStatus::Exit
        );
        // A stale "not an exit" is unknown again; a stale "exit" still counts.
        sqlx::query("UPDATE ip_intel SET fetched_at = datetime('now', '-73 hours')")
            .execute(p)
            .await
            .unwrap();
        assert_eq!(
            tor_status(p, None, "198.51.100.9").await.unwrap(),
            TorStatus::Unknown
        );
        assert_eq!(
            tor_status(p, None, "198.51.100.10").await.unwrap(),
            TorStatus::Exit
        );
    }

    #[test]
    fn tor_view_needs_a_sane_list_and_follows_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = TorView::new(dir.path());
        assert!(!v.loaded());
        std::fs::write(dir.path().join("tor-exit.txt"), "198.51.100.1\n").unwrap();
        assert!(!v.loaded(), "a one-line list is not a list");
        let list: String = (1..=150).map(|i| format!("198.18.0.{i}\n")).collect();
        std::fs::write(dir.path().join("tor-exit.txt"), list).unwrap();
        assert!(v.loaded());
        assert_eq!(v.local(&"198.18.0.7".parse().unwrap()), Some(true));
        assert_eq!(v.local(&"198.51.100.1".parse().unwrap()), Some(false));
    }
}
