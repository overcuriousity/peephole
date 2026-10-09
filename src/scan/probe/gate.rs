//! What must hold before this node probes an address: the same checks a
//! counter-scan obeys (non-global addresses, `never_scan`, the members'
//! and the operator's lists, Tor exits, verified crawlers). The ports read
//! are the open ones of the latest finished counter-scan, or the
//! well-known ones when there is none.
use super::Target;
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::config::Config;
use crate::scan::{crawler, guard, locally_refused, safety};
use crate::store::Store;
use std::net::IpAddr;

/// Who a standalone node's probes are by (it has no key): the asker and
/// origin of its `probe_result` records.
pub const LOCAL: NodeId = NodeId([0; 32]);

pub struct Gate {
    safety: tokio::sync::Mutex<safety::Safety>,
    crawlers: Option<crawler::Crawlers>,
    tor: std::sync::Mutex<guard::TorView>,
    origins: guard::Origins,
    cfg: Config,
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
            cfg: cfg.clone(),
        }
    }

    /// The address and ports to probe, or the reason shown to the asker.
    /// Checks, in order: enabled; global address; `never_scan`; safety
    /// lists (members, own, peer-observed public); Tor exit; verified
    /// crawler. The ports are the latest finished scan's open ones, or the
    /// well-known ones.
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
        let known: Vec<(u16, Option<String>)> =
            match store.ip_by_addr(&ip_text).await.map_err(internal)? {
                Some(row) => {
                    let scans = store.scans_for_ip(row.id).await.map_err(internal)?;
                    match scans
                        .iter()
                        .find(|s| s.finished_at.is_some() && s.audit_of.is_none())
                    {
                        Some(scan) => store
                            .ports_for_scan(scan.id)
                            .await
                            .map_err(internal)?
                            .into_iter()
                            .filter(|p| p.state == "open" && p.proto == "tcp")
                            .filter_map(|p| Some((u16::try_from(p.port).ok()?, p.service)))
                            .collect(),
                        None => vec![],
                    }
                }
                None => vec![],
            };
        let ports = match known.is_empty() {
            true => super::WELL_KNOWN_PORTS
                .iter()
                .map(|(p, s)| (*p, Some((*s).to_string())))
                .collect(),
            false => known,
        };
        Ok(Target { ip, ports })
    }

    /// The redirect-hop guard: non-global addresses, `never_scan`, and the
    /// safety lists as last refreshed (sync). While the lists are being
    /// rebuilt every hop is refused.
    pub fn hop_guard(&self) -> impl Fn(&IpAddr) -> Option<String> + Send + Sync + '_ {
        move |ip: &IpAddr| {
            if let Some(r) = locally_refused(ip, &self.cfg.scan.never_scan) {
                return Some(r.reason().to_string());
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

    /// A finished counter-scan of `ip` with these `(port, state, service)`.
    pub(crate) async fn scanned(store: &Store, ip: &str, ports: &[(u16, &str, Option<&str>)]) {
        let res = ScanResult {
            scrubbed: 0,
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

    #[test]
    fn a_redirect_hop_into_never_scan_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with(dir.path(), "never_scan = [\"198.51.100.0/24\"]");
        let gate = Gate::new(&cfg, None);
        let guard = gate.hop_guard();
        assert_eq!(
            guard(&"198.51.100.7".parse().unwrap()).as_deref(),
            Some("never_scan 198.51.100.0/24")
        );
        assert_eq!(
            guard(&"10.0.0.1".parse().unwrap()).as_deref(),
            Some("non-global address")
        );
    }

    #[tokio::test]
    async fn a_gate_reads_the_scans_open_ports_or_the_well_known_ones() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let gate = Gate::new(&config_with(dir.path(), ""), None);
        let addr: IpAddr = "203.0.113.20".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        // Never scanned: the well-known fallback.
        let t = gate.check(&store, None, &addr).await.unwrap();
        assert_eq!(t.ports.len(), crate::scan::probe::WELL_KNOWN_PORTS.len());
        assert_eq!(t.ports[0], (22, Some("ssh".to_string())));
        // A scan with only closed ports: still the fallback.
        scanned(&store, &ip.ip, &[(22, "closed", Some("ssh"))]).await;
        let t = gate.check(&store, None, &addr).await.unwrap();
        assert_eq!(t.ports.len(), crate::scan::probe::WELL_KNOWN_PORTS.len());
        // An open port: the scan's.
        scanned(&store, &ip.ip, &[(22, "open", Some("ssh"))]).await;
        let t = gate.check(&store, None, &addr).await.unwrap();
        assert_eq!(t.ports, [(22, Some("ssh".to_string()))]);
    }

    #[tokio::test]
    async fn a_gate_refuses_protected_addresses_but_not_thin_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let addr: IpAddr = "203.0.113.21".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        scanned(&store, &ip.ip, &[(22, "open", Some("ssh"))]).await;
        // No requests held at all: probed anyway.
        let gate = Gate::new(&config_with(dir.path(), ""), None);
        assert!(gate.check(&store, None, &addr).await.is_ok());
        let covered = Gate::new(
            &config_with(dir.path(), "never_scan = [\"203.0.113.0/24\"]"),
            None,
        );
        let err = covered.check(&store, None, &addr).await.unwrap_err();
        assert!(err.contains("never_scan"), "{err}");
    }

    #[tokio::test]
    async fn a_gate_allows_probing_the_same_address_again() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let gate = Gate::new(&config_with(dir.path(), ""), None);
        let addr: IpAddr = "203.0.113.22".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        scanned(&store, &ip.ip, &[(22, "open", Some("ssh"))]).await;
        // A probe of this address by this node finished a minute ago.
        sqlx::query(
            "INSERT INTO probes (uid, group_uid, ip_id, origin, hlc, asker, vantage_ip_source,
               started_at, finished_at, build)
             VALUES ('p1', 'g1', ?, ?, 0, ?, 'local', datetime('now'),
               datetime('now'), '')",
        )
        .bind(ip.id)
        .bind(&LOCAL.0[..])
        .bind(&LOCAL.0[..])
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(gate.check(&store, None, &addr).await.is_ok());
    }
}
