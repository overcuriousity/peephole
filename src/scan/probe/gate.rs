//! What must hold before this node probes an address: the checks a
//! counter-scan obeys (non-global addresses, `never_scan`, the members'
//! and the operator's lists, Tor exits, verified crawlers, the evidence
//! held here), and three of its own: the evidence allows level 2, the
//! latest finished counter-scan found an open port, and this node did not
//! probe the address in the last 24 hours.
use super::{PROBE_COOLDOWN_HOURS, Target};
use crate::classify::Classifier;
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::config::Config;
use crate::scan::{crawler, guard, locally_refused, safety};
use crate::store::Store;
use std::net::IpAddr;

/// The level of evidence a probe needs: the requests held here must
/// allow at least a level-2 counter-scan.
pub const PROBE_LEVEL: u8 = 2;

/// Who a standalone node's probes are by (it has no key): the asker and
/// origin of its `probe_result` records.
pub const LOCAL: NodeId = NodeId([0; 32]);

pub struct Gate {
    safety: tokio::sync::Mutex<safety::Safety>,
    crawlers: Option<crawler::Crawlers>,
    tor: std::sync::Mutex<guard::TorView>,
    origins: guard::Origins,
    classifier: &'static Classifier,
    cfg: Config,
    /// The origin this node's probes are recorded under.
    me: NodeId,
}

impl Gate {
    pub fn new(cfg: &Config, me: Option<NodeId>) -> Self {
        let s = &cfg.scan.safety;
        Self {
            safety: tokio::sync::Mutex::new(safety::Safety::new(cfg)),
            crawlers: s
                .verify_crawlers
                .then(|| crawler::Crawlers::new(&s.crawler_domains)),
            tor: std::sync::Mutex::new(guard::TorView::new(&cfg.data_dir)),
            origins: guard::Origins::from_config(s, me),
            classifier: Classifier::builtin(),
            cfg: cfg.clone(),
            me: me.unwrap_or(LOCAL),
        }
    }

    /// The address and open ports to probe, or the reason shown to the
    /// asker. Checks, in order: enabled; global address; never_scan;
    /// safety lists (members, own, peer-observed public); Tor exit;
    /// verified crawler; evidence allows ≥ 2; latest finished scan has ≥ 1
    /// open port; not probed by this node in 24 h.
    pub async fn check(
        &self,
        store: &Store,
        node: Option<&Node>,
        ip: &IpAddr,
    ) -> Result<Target, String> {
        let internal = |e: anyhow::Error| format!("this node could not check the address: {e:#}");
        if !self.cfg.probe.enabled {
            return Err("probes are off on this node".into());
        }
        if let Some(r) = locally_refused(ip, &self.cfg.scan.never_scan) {
            return Err(r.reason().to_string());
        }
        {
            let mut s = self.safety.lock().await;
            s.refresh(&self.cfg, node).await;
            if let Some(why) = s.refuses(ip) {
                return Err(why);
            }
            // Fail closed: what the lists cover is not known.
            if let Some(why) = s.unavailable().or_else(|| s.listed(ip)) {
                return Err(why);
            }
        }
        let ip = crate::net::canonical(*ip);
        let ip_text = ip.to_string();
        let local = self.tor.lock().unwrap().local(&ip);
        let tor = guard::tor_status(&store.pool, local, &ip_text, &self.origins)
            .await
            .map_err(internal)?;
        if matches!(tor, guard::TorStatus::Exit) {
            return Err("Tor exit".into());
        }
        if let Some(c) = &self.crawlers
            && let Some(name) = c.confirmed(ip).await
        {
            return Err(format!("verified crawler ({name})"));
        }
        let ev = guard::evidence(&store.pool, &ip_text, &self.origins, Some(self.classifier))
            .await
            .map_err(internal)?;
        let allowed = ev.allowed_level(&self.cfg.scan.safety);
        if allowed < PROBE_LEVEL {
            return Err(format!(
                "the requests held here allow level {allowed}, a probe needs {PROBE_LEVEL}"
            ));
        }
        let no_scan = || "no finished counter-scan of this address here".to_string();
        let Some(row) = store.ip_by_addr(&ip_text).await.map_err(internal)? else {
            return Err(no_scan());
        };
        let scans = store.scans_for_ip(row.id).await.map_err(internal)?;
        let Some(scan) = scans
            .iter()
            .find(|s| s.finished_at.is_some() && s.audit_of.is_none())
        else {
            return Err(no_scan());
        };
        let ports: Vec<(u16, Option<String>)> = store
            .ports_for_scan(scan.id)
            .await
            .map_err(internal)?
            .into_iter()
            .filter(|p| p.state == "open" && p.proto == "tcp")
            .filter_map(|p| Some((u16::try_from(p.port).ok()?, p.service)))
            .collect();
        if ports.is_empty() {
            return Err("the latest counter-scan found no open port".into());
        }
        let ago: Option<i64> = sqlx::query_scalar(
            "SELECT CAST(ROUND((julianday('now') - julianday(MAX(p.finished_at))) * 24) AS INTEGER)
             FROM probes p JOIN ips i ON i.id = p.ip_id
             WHERE i.ip = ? AND p.origin = ? AND p.finished_at > datetime('now', ?)",
        )
        .bind(&ip_text)
        .bind(&self.me.0[..])
        .bind(format!("-{PROBE_COOLDOWN_HOURS} hours"))
        .fetch_one(&store.pool)
        .await
        .map_err(|e| internal(e.into()))?;
        if let Some(h) = ago {
            return Err(format!("this node probed the address {} h ago", h.max(0)));
        }
        Ok(Target { ip, ports })
    }

    /// The redirect-hop guard: non-global addresses and the safety lists
    /// as last refreshed (sync). While the lists are being rebuilt every
    /// hop is refused.
    pub fn hop_guard(&self) -> impl Fn(&IpAddr) -> Option<String> + Send + Sync + '_ {
        move |ip: &IpAddr| {
            if !crate::net::is_scannable_target(*ip) {
                return Some("non-global address".into());
            }
            match self.safety.try_lock() {
                Ok(s) => s.refuses(ip).or_else(|| s.listed(ip)),
                Err(_) => Some("the safety lists are being rebuilt".into()),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::scan::nmap_xml::{PortResult, ScanResult};

    pub(crate) fn config_with(dir: &std::path::Path, scan: &str) -> Config {
        // No Tor list and no DNS in tests: neither check may hold probes back.
        toml::from_str(&format!(
            "database_path = \"{db}\"\ndata_dir = \"{dir}\"\n[scan]\n\
             tor_unknown = \"scan\"\nverify_crawlers = false\n{scan}\n",
            db = dir.join("t.db").display(),
            dir = dir.display()
        ))
        .unwrap()
    }

    /// `n` requests the shipped rules put at level 2 (or 1 below).
    pub(crate) async fn requests(store: &Store, ip_id: i64, n: usize, level: i64) {
        let path = if level >= 2 { "/.env" } else { "/x" };
        for _ in 0..n {
            store
                .local()
                .insert_request(&crate::store::requests::NewRequest {
                    ip_id,
                    method: "GET".into(),
                    path: path.into(),
                    headers_json: "[]".into(),
                    labels_json: "[\"probe\"]".into(),
                    severity: level,
                    scan_level: level,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
    }

    /// A finished counter-scan of `ip` with these `(port, state, service)`.
    pub(crate) async fn scanned(store: &Store, ip: &str, ports: &[(u16, &str, Option<&str>)]) {
        let res = ScanResult {
            os_guess: None,
            raw_xml: b"<nmaprun/>".to_vec(),
            ports: ports
                .iter()
                .map(|(port, state, service)| PortResult {
                    port: *port,
                    proto: "tcp".into(),
                    state: state.to_string(),
                    service: service.map(str::to_string),
                    product: None,
                    version: None,
                })
                .collect(),
        };
        let job = crate::store::data::new_uid();
        sqlx::query(
            "INSERT INTO scan_jobs (ip_id, level, status, queued_at, uid)
             SELECT id, 2, 'done', datetime('now'), ? FROM ips WHERE ip = ?",
        )
        .bind(&job)
        .bind(ip)
        .execute(&store.pool)
        .await
        .unwrap();
        store
            .local()
            .record_scan_result(&job, ip, 2, &crate::store::data::now_ts(), &res)
            .await
            .unwrap();
    }

    async fn store(dir: &std::path::Path) -> Store {
        Store::connect(&dir.join("t.db")).await.unwrap()
    }

    #[tokio::test]
    async fn a_gate_needs_an_open_port_in_a_finished_scan() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let gate = Gate::new(&config_with(dir.path(), ""), None);
        let addr: IpAddr = "203.0.113.20".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        requests(&store, ip.id, 3, 2).await;
        let err = gate.check(&store, None, &addr).await.unwrap_err();
        assert!(err.contains("no finished counter-scan"), "{err}");
        scanned(&store, &ip.ip, &[(22, "closed", Some("ssh"))]).await;
        let err = gate.check(&store, None, &addr).await.unwrap_err();
        assert!(err.contains("no open port"), "{err}");
        scanned(&store, &ip.ip, &[(22, "open", Some("ssh"))]).await;
        let t = gate.check(&store, None, &addr).await.unwrap();
        assert_eq!(t.ports, [(22, Some("ssh".to_string()))]);
    }

    #[tokio::test]
    async fn a_gate_refuses_thin_evidence_and_protected_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let addr: IpAddr = "203.0.113.21".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        scanned(&store, &ip.ip, &[(22, "open", Some("ssh"))]).await;
        requests(&store, ip.id, 1, 1).await;
        let gate = Gate::new(&config_with(dir.path(), ""), None);
        let err = gate.check(&store, None, &addr).await.unwrap_err();
        assert!(err.contains("allow level 1"), "{err}");
        let covered = Gate::new(
            &config_with(dir.path(), "never_scan = [\"203.0.113.0/24\"]"),
            None,
        );
        let err = covered.check(&store, None, &addr).await.unwrap_err();
        assert!(err.contains("never_scan"), "{err}");
    }

    #[tokio::test]
    async fn a_gate_enforces_the_24_hour_cooldown() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let gate = Gate::new(&config_with(dir.path(), ""), None);
        let addr: IpAddr = "203.0.113.22".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        requests(&store, ip.id, 3, 2).await;
        scanned(&store, &ip.ip, &[(22, "open", Some("ssh"))]).await;
        assert!(gate.check(&store, None, &addr).await.is_ok());
        sqlx::query(
            "INSERT INTO probes (uid, group_uid, ip_id, origin, hlc, asker, vantage_ip_source,
               started_at, finished_at, build)
             VALUES ('p1', 'g1', ?, ?, 0, ?, 'local', datetime('now', '-3 hours'),
               datetime('now', '-3 hours'), '')",
        )
        .bind(ip.id)
        .bind(&LOCAL.0[..])
        .bind(&LOCAL.0[..])
        .execute(&store.pool)
        .await
        .unwrap();
        let err = gate.check(&store, None, &addr).await.unwrap_err();
        assert!(err.contains("probed the address 3 h ago"), "{err}");
    }
}
