//! Ephemeral node status: contacts and signed heartbeats.
//!
//! Every node publishes a heartbeat (who it can talk to, its roles, scan
//! pace and load) every few seconds; heartbeats are gossiped on each sync
//! round, signed by their node so relays cannot forge them. They tell
//! nodes who is alive (scan job takeover), how to route directed messages
//! (the neighbour graph) and what to show on the cluster page. Nothing
//! here is stored in the database.
use super::Node;
use super::identity::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const HB_DOMAIN: &[u8] = b"peephole-hb-v1\0";
/// Contacts this recent make two nodes neighbours.
pub const NEIGHBOUR_WINDOW: Duration = Duration::from_secs(90);
/// How often a node refreshes its own heartbeat.
pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(10);

/// Scan pace as published in heartbeats.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PaceInfo {
    pub max_workers: u32,
    pub max_scans_per_hour: i64,
    pub timeout_secs: u64,
}

/// What this node reports about itself (updated by the scan workers).
#[derive(Debug, Clone, Default)]
pub struct LocalStatus {
    pub pace: Option<PaceInfo>,
    pub active_scans: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub node: NodeId,
    /// Creator's wall clock (ms); strictly increasing per node.
    pub at_ms: u64,
    pub neighbours: Vec<NodeId>,
    pub roles: Vec<String>,
    pub version: String,
    pub pace: Option<PaceInfo>,
    pub active_scans: u32,
    /// Enrichment providers this node can query right now.
    #[serde(default)]
    pub providers: Vec<String>,
    /// Highest sequence in the node's own log (replication lag).
    #[serde(default)]
    pub own_seq: u64,
    /// Days of history the node keeps; 0: all of it.
    #[serde(default)]
    pub retention_days: u32,
    /// Where the node's history of an origin starts, when not at 1. It
    /// serves nothing below.
    #[serde(default)]
    pub floors: Vec<(NodeId, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHeartbeat {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl SignedHeartbeat {
    fn signing(body: &[u8]) -> Vec<u8> {
        [HB_DOMAIN, body].concat()
    }

    /// Decode and check the signature (not membership).
    pub fn open(&self) -> Option<Heartbeat> {
        let hb: Heartbeat = super::rpc::cbor::decode(&self.body).ok()?;
        hb.node
            .verify(&Self::signing(&self.body), &self.sig)
            .then_some(hb)
    }
}

/// A heartbeat as known here, with the local time it last advanced.
#[derive(Debug, Clone)]
pub struct Known {
    pub hb: Heartbeat,
    pub signed: SignedHeartbeat,
    pub advanced: Instant,
}

/// Last successful contact with a peer in either direction.
#[derive(Debug, Clone, Copy, Default)]
pub struct Contact {
    /// We reached them (a sync round succeeded).
    pub outbound: Option<Instant>,
    /// They reached us (an authenticated RPC call).
    pub inbound: Option<Instant>,
}

#[derive(Default)]
pub struct Status {
    pub local: Mutex<LocalStatus>,
    pub contacts: Mutex<HashMap<NodeId, Contact>>,
    pub heartbeats: Mutex<HashMap<NodeId, Known>>,
    last_at: Mutex<u64>,
    /// Source addresses members connected from (newest last), so the
    /// scanners never scan them, outbound-only members included.
    peer_ips: Mutex<HashMap<NodeId, Vec<std::net::IpAddr>>>,
}

/// Connection addresses remembered per member.
const PEER_IPS_KEPT: usize = 8;

impl Status {
    /// A member's authenticated connection came from `ip`.
    pub fn note_peer_ip(&self, peer: NodeId, ip: std::net::IpAddr) {
        let ip = crate::net::canonical(ip);
        let mut all = self.peer_ips.lock().unwrap();
        let ips = all.entry(peer).or_default();
        if ips.last() == Some(&ip) {
            return;
        }
        ips.retain(|i| *i != ip);
        ips.push(ip);
        if ips.len() > PEER_IPS_KEPT {
            ips.remove(0);
        }
    }

    /// Every address a member has connected from since this node started.
    pub fn peer_ips(&self) -> Vec<(NodeId, std::net::IpAddr)> {
        self.peer_ips
            .lock()
            .unwrap()
            .iter()
            .flat_map(|(id, ips)| ips.iter().map(|ip| (*id, *ip)))
            .collect()
    }

    pub fn touch_inbound(&self, peer: NodeId) {
        self.contacts
            .lock()
            .unwrap()
            .entry(peer)
            .or_default()
            .inbound = Some(Instant::now());
    }

    pub fn touch_outbound(&self, peer: NodeId) {
        self.contacts
            .lock()
            .unwrap()
            .entry(peer)
            .or_default()
            .outbound = Some(Instant::now());
    }

    fn recent(t: Option<Instant>) -> bool {
        t.is_some_and(|t| t.elapsed() < NEIGHBOUR_WINDOW)
    }

    /// Peers we exchanged messages with recently, either direction.
    pub fn neighbours(&self) -> Vec<NodeId> {
        let mut v: Vec<_> = self
            .contacts
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, c)| Self::recent(c.outbound) || Self::recent(c.inbound))
            .map(|(id, _)| *id)
            .collect();
        v.sort();
        v
    }

    /// Whether `peer` reached us recently (so it collects its inbox here).
    pub fn polled_recently(&self, peer: &NodeId) -> bool {
        Self::recent(
            self.contacts
                .lock()
                .unwrap()
                .get(peer)
                .and_then(|c| c.inbound),
        )
    }

    /// Whether we reached `peer` recently.
    pub fn reached_recently(&self, peer: &NodeId) -> bool {
        Self::recent(
            self.contacts
                .lock()
                .unwrap()
                .get(peer)
                .and_then(|c| c.outbound),
        )
    }

    /// Store a heartbeat if it is newer than what we have.
    pub fn merge(&self, hb: Heartbeat, signed: SignedHeartbeat) -> bool {
        let mut all = self.heartbeats.lock().unwrap();
        if all.get(&hb.node).is_some_and(|k| k.hb.at_ms >= hb.at_ms) {
            return false;
        }
        all.insert(
            hb.node,
            Known {
                hb,
                signed,
                advanced: Instant::now(),
            },
        );
        true
    }

    pub fn all_signed(&self) -> Vec<SignedHeartbeat> {
        self.heartbeats
            .lock()
            .unwrap()
            .values()
            .map(|k| k.signed.clone())
            .collect()
    }

    pub fn known(&self, id: &NodeId) -> Option<Known> {
        self.heartbeats.lock().unwrap().get(id).cloned()
    }

    fn next_at(&self) -> u64 {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut last = self.last_at.lock().unwrap();
        *last = wall.max(*last + 1);
        *last
    }
}

impl Node {
    /// Build, sign and store this node's current heartbeat.
    pub fn refresh_heartbeat(&self) {
        let local = self.status.local.lock().unwrap().clone();
        let hb = Heartbeat {
            node: self.id(),
            at_ms: self.status.next_at(),
            neighbours: self.status.neighbours(),
            roles: self
                .roles()
                .names()
                .into_iter()
                .map(str::to_string)
                .collect(),
            version: crate::VERSION.to_string(),
            pace: local.pace,
            active_scans: local.active_scans,
            providers: self.providers(),
            own_seq: self.own_head.load(std::sync::atomic::Ordering::Relaxed),
            retention_days: self.retention_days,
            floors: {
                let mut f: Vec<_> = self
                    .own_floors
                    .read()
                    .unwrap()
                    .iter()
                    .map(|(o, s)| (*o, *s))
                    .collect();
                f.sort();
                f
            },
        };
        let Ok(body) = super::rpc::cbor::encode(&hb) else {
            return;
        };
        let sig = self.identity.sign(&SignedHeartbeat::signing(&body));
        self.status.merge(hb, SignedHeartbeat { body, sig });
    }

    /// Publish a status change now instead of with the next idle round.
    pub fn publish_status(&self) {
        self.refresh_heartbeat();
        self.notify_changed();
    }

    /// Merge gossiped heartbeats from members; returns how many were new.
    pub fn merge_heartbeats(&self, incoming: Vec<SignedHeartbeat>) -> usize {
        incoming
            .into_iter()
            .filter_map(|s| s.open().map(|hb| (hb, s)))
            .filter(|(hb, _)| hb.node != self.id() && self.is_member(&hb.node))
            .filter(|(hb, s)| self.status.merge(hb.clone(), s.clone()))
            .count()
    }

    /// Time since `id`'s heartbeat last advanced, as seen here; for nodes
    /// never heard from, the time since this node started.
    pub fn silent_for(&self, id: &NodeId) -> Duration {
        match self.status.known(id) {
            Some(k) => k.advanced.elapsed(),
            None => self.started.elapsed(),
        }
    }

    /// Members whose heartbeat advanced within `window` (this node always).
    pub fn live_members(&self, window: Duration) -> Vec<NodeId> {
        let mut v: Vec<_> = self
            .members()
            .keys()
            .copied()
            .filter(|id| {
                *id == self.id()
                    || self
                        .status
                        .known(id)
                        .is_some_and(|k| k.advanced.elapsed() < window)
            })
            .collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_ips_are_remembered_canonical_and_bounded() {
        let s = Status::default();
        let a = crate::cluster::identity::Identity::generate().unwrap().id;
        s.note_peer_ip(a, "::ffff:203.0.113.1".parse().unwrap());
        s.note_peer_ip(a, "203.0.113.1".parse().unwrap());
        assert_eq!(s.peer_ips(), [(a, "203.0.113.1".parse().unwrap())]);
        for i in 0..20 {
            s.note_peer_ip(a, format!("198.51.100.{i}").parse().unwrap());
        }
        let ips = s.peer_ips();
        assert_eq!(ips.len(), PEER_IPS_KEPT);
        assert!(ips.contains(&(a, "198.51.100.19".parse().unwrap())));
    }

    #[test]
    fn heartbeat_signature_binds_the_node() {
        let a = crate::cluster::identity::Identity::generate().unwrap();
        let hb = Heartbeat {
            node: a.id,
            at_ms: 1,
            neighbours: vec![],
            roles: vec![],
            version: "x".into(),
            pace: None,
            active_scans: 0,
            providers: vec![],
            own_seq: 0,
            retention_days: 0,
            floors: vec![],
        };
        let body = crate::cluster::rpc::cbor::encode(&hb).unwrap();
        let sig = a.sign(&SignedHeartbeat::signing(&body));
        let s = SignedHeartbeat { body, sig };
        assert_eq!(s.open(), Some(hb.clone()));
        let mut forged = s.clone();
        forged.body = crate::cluster::rpc::cbor::encode(&Heartbeat { at_ms: 2, ..hb }).unwrap();
        assert!(forged.open().is_none());
    }
}
