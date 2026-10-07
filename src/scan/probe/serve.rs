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
use std::net::IpAddr;
use std::sync::Arc;

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
    /// Tests only: where the probe connects instead of the probed address.
    connect_to: Option<IpAddr>,
}

fn declined(why: impl Into<String>, price_mc: Option<u32>) -> ProbeResp {
    ProbeResp::Declined {
        why: why.into(),
        price_mc,
    }
}

impl Prober {
    pub fn new(cfg: &Config, me: Option<NodeId>) -> Self {
        let max = cfg.probe.max_parallel;
        Self {
            gate: Gate::new(cfg, me),
            slots: Arc::new(tokio::sync::Semaphore::new(max as usize)),
            max,
            connect_to: None,
        }
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

    /// Every slot is busy (the price doubles).
    pub fn full(&self) -> bool {
        self.busy() >= self.max
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

    /// What a probe costs here now.
    fn price(&self, node: &Node) -> Mc {
        let table = node.price_table();
        table
            .probe_mc
            .unwrap_or_else(|| price::price(price::PROBE, table.unit, 1 + self.full() as u32))
            as Mc
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
    /// then run and append the result and the receipt in one batch.
    pub async fn serve(
        self: &Arc<Self>,
        node: &Arc<Node>,
        peer: NodeId,
        req: &ProbeReq,
    ) -> ProbeResp {
        let price = self.price(node);
        let price_u32 = price.min(u32::MAX as Mc) as u32;
        if req.ip.len() > MAX_TEXT || req.group.is_empty() || req.group.len() > MAX_TEXT {
            return declined("malformed request", None);
        }
        let Ok(ip) = req.ip.trim().parse::<IpAddr>() else {
            return declined("not an IP address", None);
        };
        let Some(offer_seq) = req.offer_seq else {
            return declined(
                "probes are paid with credits: the request carries no offer",
                Some(price_u32),
            );
        };
        let decline = |why: String, price_mc: Option<u32>| {
            tracing::info!(asker = %peer.short(), offer = offer_seq, %ip, %why, "probe declined");
            declined(why, price_mc)
        };
        let acc = match pay::accept_offer(node, peer, offer_seq, price, "probe").await {
            Ok(a) => a,
            Err(Declined::TooLow { why, price_mc }) => return decline(why, Some(price_mc)),
            Err(Declined::Why(why) | Declined::NotCovered(why)) => return decline(why, None),
        };
        let target = match self.gate.check(&node.store, Some(node), &ip).await {
            Ok(t) => t,
            Err(why) => {
                pay::release(node, peer, offer_seq).await;
                return decline(why, None);
            }
        };
        let Ok(permit) = self.slots.clone().try_acquire_owned() else {
            pay::release(node, peer, offer_seq).await;
            return decline("all probe slots are busy".into(), Some(price_u32));
        };
        let uid = format!("{}{}", node.id().uid_prefix(), new_uid());
        let (vantage_ip, vantage_ip_source) = match node.public_addrs()[..] {
            [one] => (Some(one), "public"),
            _ => (None, "dialled"),
        };
        let (me, node, group, probe_uid) =
            (self.clone(), node.clone(), req.group.clone(), uid.clone());
        tokio::spawn(async move {
            // The offer stays "being served" until its receipt is written.
            let _held = (permit, acc);
            let o = me.run(target).await;
            let ports = o.ports.len();
            let result = Record::ProbeResult(ProbeResultRec {
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
            });
            let receipt = Record::CreditReceipt {
                payer: peer,
                offer_seq,
                charged_mc: price_u32,
                answered: vec![price::PROBE.into()],
            };
            match repl::append(&node, &[result, receipt]).await {
                Ok(_) => tracing::info!(asker = %peer.short(), %ip, ports,
                    charged = %show(price), "probe served"),
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
        let target = self.gate.check(store, None, &ip).await?;
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
