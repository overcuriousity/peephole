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
use crate::intel::tor::{self, MIN_EXITS, TorExitList};
use anyhow::Result;
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::SystemTime;

pub use crate::store::guard::{
    EnqueuePolicy, Evidence, Origins, evidence, network, queued_in_asn_last_hour, queued_in_network,
};

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
/// the file changes. A list that fails the sanity check, or whose file is
/// older than [`tor::MAX_AGE`] (fetching kept failing), counts as none.
pub struct TorView {
    path: PathBuf,
    stamp: Option<(SystemTime, u64)>,
    list: Option<TorExitList>,
    /// The loaded list went stale (warned once).
    stale: bool,
}

impl TorView {
    pub fn new(data_dir: &std::path::Path) -> Self {
        Self {
            path: data_dir.join("tor-exit.txt"),
            stamp: None,
            list: None,
            stale: false,
        }
    }

    fn refresh(&mut self) {
        let stamp = std::fs::metadata(&self.path)
            .ok()
            .and_then(|m| Some((m.modified().ok()?, m.len())));
        if stamp != self.stamp {
            self.stamp = stamp;
            self.list = stamp
                .and_then(|_| TorExitList::load(self.path.parent()?).ok())
                .filter(|l| l.len() as u64 > MIN_EXITS);
        }
        // On every call: an unchanged file still ages.
        let stale = self.list.is_some() && stamp.is_some_and(|(t, _)| tor::too_old(t));
        if stale && !self.stale {
            tracing::warn!(
                file = %self.path.display(),
                "tor exit list older than {} h: the Tor status of IPs is unknown \
                 until a fresh list loads (see scan.tor_unknown)",
                tor::MAX_AGE.as_secs() / 3600
            );
        }
        self.stale = stale;
    }

    /// The list, if a sane and fresh one is loaded.
    fn current(&mut self) -> Option<&TorExitList> {
        self.refresh();
        self.list.as_ref().filter(|_| !self.stale)
    }

    /// Whether a sane, fresh list is loaded.
    pub fn loaded(&mut self) -> bool {
        self.current().is_some()
    }

    /// Whether the loaded list holds `ip`; None without a usable list.
    pub fn local(&mut self, ip: &IpAddr) -> Option<bool> {
        self.current()
            .map(|l| l.contains(&crate::net::canonical(*ip)))
    }
}

/// How long a recorded "not an exit" holds. Exit lists change daily; an
/// older verdict counts as unknown (an "exit" always counts). As old as an
/// exit list may get ([`tor::MAX_AGE`]).
const NOT_EXIT_MAX_AGE_HOURS: i64 = (tor::MAX_AGE.as_secs() / 3600) as i64;

/// Tor status of `ip` (its text as stored): this node's list, and the
/// results recorded by every node (`ip_intel`). Any "exit" wins; a "not an
/// exit" counts only while fresh and only from an origin `origins` admits,
/// as request evidence does (an untrusted node's word could otherwise clear
/// a Tor exit for scanning).
pub async fn tor_status(
    pool: &SqlitePool,
    local: Option<bool>,
    ip: &str,
    origins: &Origins,
) -> Result<TorStatus> {
    if local == Some(true) {
        return Ok(TorStatus::Exit);
    }
    let rows: Vec<(String, bool, Vec<u8>)> = sqlx::query_as(
        "SELECT data_json, fetched_at >= datetime('now', ?), origin FROM ip_intel
         WHERE ip = ? AND provider = ?",
    )
    .bind(format!("-{NOT_EXIT_MAX_AGE_HOURS} hours"))
    .bind(ip)
    .bind(crate::intel::TOR)
    .fetch_all(pool)
    .await?;
    let said: Vec<bool> = rows
        .iter()
        .filter_map(|(r, fresh, origin)| {
            let exit = serde_json::from_str::<serde_json::Value>(r)
                .ok()?
                .get("exit")?
                .as_bool()?;
            // An empty origin is this node's (standalone) result.
            let trusted = || origins.admits((!origin.is_empty()).then_some(&origin[..]));
            (exit || (*fresh && trusted())).then_some(exit)
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
    use crate::classify::Classifier;
    use crate::config::ScanSafety;
    use crate::store::Store;
    use crate::store::requests::NewRequest;
    use std::collections::HashSet;

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
    /// path scanner's history shows, but weak tells alone back level 1, the
    /// same cap the trap applies when it queues the scan.
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

        // Twenty paths in an hour: our rules see the path scanner, and cap
        // its weak-only evidence at level 1, whatever it claimed.
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
        assert_eq!(ev.max_level, 1);
        // A named rule in the mix backs level 2 again.
        let mut r = req(scanner.id, 2, r#"["sensitive-path"]"#);
        r.path = "/.env".into();
        rec.insert_request(&r).await.unwrap();
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
        for bad in [0, 6, 200] {
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
            tor_status(p, None, "198.51.100.9", &Origins::Any)
                .await
                .unwrap(),
            TorStatus::Unknown
        );
        assert_eq!(
            tor_status(p, Some(false), "198.51.100.9", &Origins::Any)
                .await
                .unwrap(),
            TorStatus::NotExit
        );
        assert_eq!(
            tor_status(p, Some(true), "198.51.100.9", &Origins::Any)
                .await
                .unwrap(),
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
            tor_status(p, None, "198.51.100.9", &Origins::Any)
                .await
                .unwrap(),
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
            tor_status(p, Some(false), "198.51.100.10", &Origins::Any)
                .await
                .unwrap(),
            TorStatus::Exit
        );
        // A stale "not an exit" is unknown again; a stale "exit" still counts.
        sqlx::query("UPDATE ip_intel SET fetched_at = datetime('now', '-73 hours')")
            .execute(p)
            .await
            .unwrap();
        assert_eq!(
            tor_status(p, None, "198.51.100.9", &Origins::Any)
                .await
                .unwrap(),
            TorStatus::Unknown
        );
        assert_eq!(
            tor_status(p, None, "198.51.100.10", &Origins::Any)
                .await
                .unwrap(),
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

    /// A list nobody managed to refresh for [`tor::MAX_AGE`] counts as none,
    /// also when the file did not change since it loaded.
    #[test]
    fn tor_view_drops_a_stale_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tor-exit.txt");
        let list: String = (1..=150).map(|i| format!("198.18.0.{i}\n")).collect();
        std::fs::write(&path, list).unwrap();
        let mut v = TorView::new(dir.path());
        assert!(v.loaded());
        // The file ages in place: same stamp as when it loaded.
        let old = SystemTime::now() - tor::MAX_AGE - std::time::Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        v.stamp = Some((old, v.stamp.unwrap().1));
        assert!(!v.loaded());
        assert_eq!(v.local(&"198.18.0.7".parse().unwrap()), None, "unknown");
        // Loaded stale from the start: none either.
        let mut restarted = TorView::new(dir.path());
        assert!(!restarted.loaded());
        // A fresh file counts again.
        let list: String = (1..=150).map(|i| format!("198.18.1.{i}\n")).collect();
        std::fs::write(&path, list).unwrap();
        assert_eq!(v.local(&"198.18.1.7".parse().unwrap()), Some(true));
    }

    /// `scan.trusted_origins`: a "not an exit" counts only from a trusted
    /// node (or this one); an "exit" from anyone.
    #[tokio::test]
    async fn tor_status_trusts_only_admitted_origins_with_not_an_exit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let p = &store.pool;
        let rec = store.local();
        for (ip, exit) in [("198.51.100.20", false), ("198.51.100.21", true)] {
            rec.record_intel(
                ip,
                crate::intel::TOR,
                None,
                serde_json::json!({ "exit": exit }),
            )
            .await
            .unwrap();
        }
        let other = crate::cluster::identity::Identity::generate().unwrap().id;
        sqlx::query("UPDATE ip_intel SET origin = ?")
            .bind(other.0.to_vec())
            .execute(p)
            .await
            .unwrap();
        let only_me = Origins::Only {
            me: None,
            others: HashSet::new(),
        };
        let trusting = Origins::Only {
            me: None,
            others: HashSet::from([other]),
        };
        let cases = [
            ("198.51.100.20", &only_me, TorStatus::Unknown),
            ("198.51.100.20", &trusting, TorStatus::NotExit),
            ("198.51.100.20", &Origins::Any, TorStatus::NotExit),
            ("198.51.100.21", &only_me, TorStatus::Exit),
        ];
        for (ip, origins, want) in cases {
            assert_eq!(
                tor_status(p, None, ip, origins).await.unwrap(),
                want,
                "{ip}"
            );
        }
    }
}
