//! Probing for a member, paid with credits, or for this node's own admin
//! when it runs alone. A member's request names its offer; the scanner
//! checks it like a paid lookup's, runs the gate, takes a slot and answers
//! at once with the probe's uid. The probe runs afterwards; its result
//! and the receipt for the offer are appended in one batch, so a result
//! is never paid twice and a receipt never stands without its result.
use super::gate::{Gate, LOCAL};
use super::{Outcome, Target, run_probe};
use crate::cluster::identity::NodeId;
use crate::cluster::record::{ProbePortRec, ProbeResultRec, Record};
use crate::cluster::{Node, repl};
use crate::config::Config;
use crate::credits::pay::{self, Declined};
use crate::credits::{Mc, price, show};
use crate::store::Store;
use crate::store::data::{new_uid, now_ts};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Longest address text and group uid accepted from a member.
const MAX_TEXT: usize = 64;

/// A member's request for a probe of `ip`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReq {
    pub ip: String,
    /// Ties the probes of one request from several scanners together.
    pub group: String,
    #[serde(default)]
    pub offer_seq: Option<u64>,
    /// The address the asker dialled this scanner at, when that is an IP:
    /// the vantage address recorded when the scanner has no single public
    /// address. The asker's own claim; older askers send none.
    #[serde(default)]
    pub dialled: Option<IpAddr>,
}

/// The answer, given before the probe runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProbeResp {
    Accepted {
        probe_uid: String,
    },
    Declined {
        why: String,
        /// This node's price, when the offer was below it.
        #[serde(default)]
        price_mc: Option<u32>,
    },
}

pub struct Prober {
    gate: Gate,
    slots: Arc<tokio::sync::Semaphore>,
    max: u32,
    /// Addresses being probed now: the gate's cooldown only sees finished
    /// probes.
    running: Mutex<HashSet<IpAddr>>,
    /// Tests only: where the probe connects instead of the probed address.
    connect_to: Option<IpAddr>,
}

/// What an offer must have left to pay for a probe: its longest run and a
/// minute for the result and the receipt.
const PROBE_MARGIN: Duration = super::PROBE_TIMEOUT.saturating_add(Duration::from_secs(60));

/// Marks an address as being probed until dropped.
struct Running(Arc<Prober>, IpAddr);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.running.lock().unwrap().remove(&self.1);
    }
}

fn declined(why: impl Into<String>, price_mc: Option<u32>) -> ProbeResp {
    ProbeResp::Declined {
        why: why.into(),
        price_mc,
    }
}

/// The vantage address a result records and where it came from: this
/// node's one public address; for its own probe its first of several (or
/// none, `local`); otherwise the address the asker says it dialled.
fn vantage(public: &[IpAddr], own: bool, req: &ProbeReq) -> (Option<IpAddr>, &'static str) {
    match (public, own) {
        ([one], _) => (Some(*one), "public"),
        ([first, ..], true) => (Some(*first), "public"),
        ([], true) => (None, "local"),
        (_, false) => (req.dialled, "dialled"),
    }
}

impl Prober {
    pub fn new(cfg: &Config, me: Option<NodeId>) -> Self {
        let max = cfg.probe.max_parallel;
        Self {
            gate: Gate::new(cfg, me),
            slots: Arc::new(tokio::sync::Semaphore::new(max as usize)),
            max,
            running: Mutex::new(HashSet::new()),
            connect_to: None,
        }
    }

    /// The gate's verdict on `ip`, and the address marked as being probed
    /// until the guard is dropped: a second probe of it waits for the
    /// first one's result, which the cooldown then sees.
    async fn admit(
        self: &Arc<Self>,
        store: &Store,
        node: Option<&Node>,
        ip: &IpAddr,
    ) -> Result<(Target, Running), String> {
        let target = self.gate.check(store, node, ip).await?;
        let ip = crate::net::canonical(target.ip);
        if !self.running.lock().unwrap().insert(ip) {
            return Err("a probe of this address is running".into());
        }
        Ok((target, Running(self.clone(), ip)))
    }

    /// Tests only: connect to `ip` (a local server) instead of the probed
    /// address. The gate still judges the probed address, and redirect hops
    /// are still guarded.
    #[doc(hidden)]
    pub fn connecting_to(mut self, ip: IpAddr) -> Self {
        self.connect_to = Some(ip);
        self
    }

    /// Probes running now.
    pub fn busy(&self) -> u32 {
        self.max
            .saturating_sub(self.slots.available_permits().min(u32::MAX as usize) as u32)
    }

    /// Probe slots: probes that can run here at once.
    pub fn slots(&self) -> u32 {
        self.max
    }

    /// What the gate says of `ip` here: the target, or why not.
    pub async fn check(
        &self,
        store: &Store,
        node: Option<&Node>,
        ip: &IpAddr,
    ) -> Result<Target, String> {
        self.gate.check(store, node, ip).await
    }

    /// The counter-scan level the evidence held here allows for `ip`.
    pub async fn allowed_level(&self, store: &Store, ip: &IpAddr) -> Option<u8> {
        self.gate.allowed_level(store, ip).await
    }

    /// What a probe costs here now: `table`'s probe price, or the floor
    /// before the first refresh. Read by the heartbeat and by `serve`, so
    /// the announced price and the price an offer is checked against are
    /// the same.
    pub fn price(&self, table: &price::Table) -> u32 {
        table.probe_mc.unwrap_or(price::PRICE_FLOOR as u32)
    }

    /// Run the probe of `t`; a probe that panicked yields an `error` port
    /// for each port it was to read.
    async fn run(self: &Arc<Self>, t: Target) -> Outcome {
        let started_at = now_ts();
        let me = self.clone();
        let wanted = t.clone();
        let run = tokio::spawn(async move {
            let guard = me.gate.hop_guard();
            let aimed = Target {
                ip: me.connect_to.unwrap_or(t.ip),
                ports: t.ports,
            };
            run_probe(&aimed, &guard).await
        });
        match run.await {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(?e, "probe failed");
                Outcome {
                    started_at,
                    finished_at: now_ts(),
                    rtt_min_ms: None,
                    ports: wanted
                        .ports
                        .iter()
                        .take(super::MAX_PORTS)
                        .map(|(port, service)| ProbePortRec {
                            port: *port,
                            protocol: super::protocol_for(*port, service.as_deref()).into(),
                            outcome: "error".into(),
                            detail_json: serde_json::json!({"error": "the probe failed"})
                                .to_string(),
                        })
                        .collect(),
                }
            }
        }
    }

    /// Cluster: validate the offer, gate, take a slot, answer at once,
    /// then run and append the result and the receipt in one batch. This
    /// node's own request carries no offer: it is free, and has no receipt.
    pub async fn serve(
        self: &Arc<Self>,
        node: &Arc<Node>,
        peer: NodeId,
        req: &ProbeReq,
    ) -> ProbeResp {
        let price_u32 = self.price(&node.price_table());
        let price = price_u32 as Mc;
        let parsed =
            if req.ip.len() > MAX_TEXT || req.group.is_empty() || req.group.len() > MAX_TEXT {
                Err("malformed request")
            } else {
                req.ip
                    .trim()
                    .parse::<IpAddr>()
                    .map_err(|_| "not an IP address")
            };
        let decline = |why: String, price_mc: Option<u32>| {
            tracing::info!(asker = %peer.short(), offer = ?req.offer_seq, ip = %req.ip, %why,
                "probe declined");
            declined(why, price_mc)
        };
        let paid = match req.offer_seq {
            None if peer == node.id() => None,
            None => {
                return match parsed {
                    Err(why) => declined(why, None),
                    Ok(_) => declined(
                        "probes are paid with credits: the request carries no offer",
                        Some(price_u32),
                    ),
                };
            }
            Some(offer_seq) => {
                node.market.note(price::PROBE, 1);
                match pay::accept_offer(
                    node,
                    peer,
                    offer_seq,
                    price,
                    "probe",
                    PROBE_MARGIN.as_millis() as u64,
                )
                .await
                {
                    Ok(a) => Some((offer_seq, a)),
                    Err(Declined::TooLow { why, price_mc }) => {
                        return decline(why, Some(price_mc));
                    }
                    Err(Declined::Why(why) | Declined::NotCovered(why)) => {
                        return decline(why, None);
                    }
                }
            }
        };
        // Every decline of an accepted offer writes a receipt of nothing.
        let release = async || {
            if let Some((offer_seq, _)) = &paid {
                pay::release(node, peer, *offer_seq).await;
            }
        };
        let ip = match parsed {
            Ok(ip) => ip,
            Err(why) => {
                release().await;
                return decline(why.into(), None);
            }
        };
        let (target, running) = match self.admit(&node.store, Some(node), &ip).await {
            Ok(t) => t,
            Err(why) => {
                release().await;
                return decline(why, None);
            }
        };
        let Ok(permit) = self.slots.clone().try_acquire_owned() else {
            release().await;
            return decline("all probe slots are busy".into(), Some(price_u32));
        };
        let charged_mc = if paid.is_some() { price_u32 } else { 0 };
        let uid = format!("{}{}", node.id().uid_prefix(), new_uid());
        let (vantage_ip, vantage_ip_source) = vantage(&node.public_addrs(), peer == node.id(), req);
        let (me, node, group, probe_uid) =
            (self.clone(), node.clone(), req.group.clone(), uid.clone());
        tokio::spawn(async move {
            let (offer_seq, acc) = paid.unzip();
            // The offer stays "being served", and the address "being
            // probed", until the result and the receipt are written.
            let _held = (permit, acc, running);
            let o = me.run(target).await;
            let ports = o.ports.len();
            let mut records = vec![Record::ProbeResult(ProbeResultRec {
                uid: probe_uid,
                group,
                ip: ip.to_string(),
                asker: peer,
                vantage_ip,
                vantage_ip_source: vantage_ip_source.into(),
                started_at: o.started_at,
                finished_at: o.finished_at,
                rtt_min_ms: o.rtt_min_ms,
                ports: o.ports,
                build: crate::COMMIT.into(),
                charged_mc,
            })];
            if let Some(offer_seq) = offer_seq {
                records.push(Record::CreditReceipt {
                    payer: peer,
                    offer_seq,
                    charged_mc,
                    answered: vec![price::PROBE.into()],
                });
            }
            match repl::append(&node, &records).await {
                Ok(_) => tracing::info!(asker = %peer.short(), %ip, ports,
                    charged = %show(charged_mc as Mc), "probe served"),
                Err(e) => tracing::warn!(?e, %ip, "probe result and receipt not written"),
            }
        });
        ProbeResp::Accepted { probe_uid: uid }
    }

    /// Standalone: gate, run, write the record; returns the probe uid.
    pub async fn run_local(
        self: &Arc<Self>,
        store: &Store,
        ip: IpAddr,
        group: &str,
    ) -> Result<String, String> {
        let (target, _running) = self.admit(store, None, &ip).await?;
        let Ok(_permit) = self.slots.clone().try_acquire_owned() else {
            return Err("all probe slots are busy".into());
        };
        let ip = target.ip;
        let o = self.run(target).await;
        let uid = new_uid();
        store
            .local()
            .write(vec![Record::ProbeResult(ProbeResultRec {
                uid: uid.clone(),
                group: group.to_string(),
                ip: ip.to_string(),
                asker: LOCAL,
                vantage_ip: None,
                vantage_ip_source: "local".into(),
                started_at: o.started_at,
                finished_at: o.finished_at,
                rtt_min_ms: o.rtt_min_ms,
                ports: o.ports,
                build: crate::COMMIT.into(),
                charged_mc: 0,
            })])
            .await
            .map_err(|e| format!("the probe result could not be written: {e:#}"))?;
        Ok(uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::probe::gate::tests::{config_with, requests, scanned};

    async fn web() -> std::net::SocketAddr {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async { axum::response::Html("<title>t</title>") }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        addr
    }

    #[tokio::test]
    async fn run_local_writes_a_probe_result_the_store_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let server = web().await;
        let addr: IpAddr = "203.0.113.30".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        requests(&store, ip.id, 3, 2).await;
        scanned(&store, &ip.ip, &[(server.port(), "open", Some("http"))]).await;
        let prober =
            Arc::new(Prober::new(&config_with(dir.path(), ""), None).connecting_to(server.ip()));
        let uid = prober.run_local(&store, addr, "g1").await.unwrap();
        let probes = store.probes_for_ip(ip.id).await.unwrap();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].uid, uid);
        assert_eq!(probes[0].vantage_ip_source, "local");
        let ports = store.probe_ports(probes[0].id).await.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].outcome, "ok");
    }

    #[test]
    fn the_vantage_is_public_own_or_dialled() {
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let b: IpAddr = "198.51.100.2".parse().unwrap();
        let d: IpAddr = "192.0.2.9".parse().unwrap();
        let req = ProbeReq {
            ip: "203.0.113.1".into(),
            group: "g".into(),
            offer_seq: Some(1),
            dialled: Some(d),
        };
        assert_eq!(vantage(&[a], false, &req), (Some(a), "public"));
        assert_eq!(vantage(&[a, b], false, &req), (Some(d), "dialled"));
        assert_eq!(vantage(&[], false, &req), (Some(d), "dialled"));
        assert_eq!(vantage(&[a, b], true, &req), (Some(a), "public"));
        assert_eq!(vantage(&[], true, &req), (None, "local"));
        // An older asker's request carries no dialled address.
        let old: ProbeReq =
            serde_json::from_str(r#"{"ip":"203.0.113.1","group":"g","offer_seq":1}"#).unwrap();
        assert_eq!(old.dialled, None);
        assert_eq!(vantage(&[], false, &old), (None, "dialled"));
    }

    #[test]
    fn the_price_is_the_tables_or_the_floor() {
        let dir = tempfile::tempdir().unwrap();
        let prober = Prober::new(&config_with(dir.path(), ""), None);
        assert_eq!(prober.slots(), prober.max);
        assert_eq!(
            prober.price(&price::Table::default()),
            price::PRICE_FLOOR as u32
        );
        let table = price::Table {
            probe_mc: Some(4000),
            ..Default::default()
        };
        assert_eq!(prober.price(&table), 4000);
    }

    #[tokio::test]
    async fn this_nodes_own_request_needs_no_offer_and_charges_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let node = Node::open(crate::cluster::NodeParams {
            identity: crate::cluster::identity::Identity::generate().unwrap(),
            cluster: crate::config::ClusterConfig {
                node_name: "n".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: None,
                key_path: None,
                takeover_hours: 6.0,
                lease_secs: 120,
                remote_config: false,
                origin_quota_mb: 20 * 1024,
                peers: vec![],
            },
            roles: Default::default(),
            store: store.clone(),
            proto: (1, 1),
            data_dir: dir.path().to_path_buf(),
            retention_days: 0,
        })
        .await
        .unwrap();
        node.bootstrap().await.unwrap();
        let server = web().await;
        let addr: IpAddr = "203.0.113.33".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        requests(&store, ip.id, 3, 2).await;
        scanned(&store, &ip.ip, &[(server.port(), "open", Some("http"))]).await;
        let prober = Arc::new(
            Prober::new(&config_with(dir.path(), ""), Some(node.id())).connecting_to(server.ip()),
        );
        let before = node.own_head.load(std::sync::atomic::Ordering::Relaxed);
        let req = ProbeReq {
            ip: addr.to_string(),
            group: "g".into(),
            offer_seq: None,
            dialled: None,
        };
        let resp = prober.serve(&node, node.id(), &req).await;
        assert!(matches!(resp, ProbeResp::Accepted { .. }), "{resp:?}");
        let mut probes = vec![];
        for _ in 0..100 {
            probes = store.probes_for_ip(ip.id).await.unwrap();
            if !probes.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(probes.len(), 1, "the probe ran");
        assert_eq!(probes[0].charged_mc, 0);
        // The result alone: no receipt.
        assert_eq!(
            node.own_head.load(std::sync::atomic::Ordering::Relaxed),
            before + 1
        );
        // Another node's request without an offer is still declined.
        let other = NodeId([9; 32]);
        let resp = prober.serve(&node, other, &req).await;
        assert!(matches!(resp, ProbeResp::Declined { .. }), "{resp:?}");
    }

    #[tokio::test]
    async fn an_address_being_probed_is_not_probed_again_meanwhile() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let addr: IpAddr = "203.0.113.32".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        requests(&store, ip.id, 3, 2).await;
        scanned(&store, &ip.ip, &[(8080, "open", Some("http"))]).await;
        let prober = Arc::new(Prober::new(&config_with(dir.path(), ""), None));
        let first = prober.admit(&store, None, &addr).await.unwrap();
        let Err(err) = prober.admit(&store, None, &addr).await else {
            panic!("admitted twice");
        };
        assert_eq!(err, "a probe of this address is running");
        drop(first);
        assert!(prober.admit(&store, None, &addr).await.is_ok());
    }

    #[tokio::test]
    async fn run_local_declines_when_the_gate_says_no() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let addr: IpAddr = "203.0.113.31".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        requests(&store, ip.id, 3, 2).await;
        let prober = Arc::new(Prober::new(&config_with(dir.path(), ""), None));
        let err = prober.run_local(&store, addr, "g1").await.unwrap_err();
        assert!(err.contains("no finished counter-scan"), "{err}");
        assert!(store.probes_for_ip(ip.id).await.unwrap().is_empty());
    }
}
