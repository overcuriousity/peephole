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
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const HB_DOMAIN: &[u8] = b"peephole-hb-v1\0";
/// Heartbeats looked at per gossip message beyond one per member (the
/// sender may know a few members this node does not yet).
const GOSSIP_SLACK: usize = 16;
/// Contacts this recent make two nodes neighbours.
pub const NEIGHBOUR_WINDOW: Duration = Duration::from_secs(90);
/// How often a node refreshes its own heartbeat.
pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(10);
/// A report no peer repeated for this long is dropped.
pub const SEEN_FROM_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

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
    /// Creator's wall clock (ms); strictly increasing per node, except
    /// after its clock was set back from beyond the allowed drift.
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
    /// Per provider: paid lookups this node serves a day (see
    /// `credits::share`).
    #[serde(default)]
    pub on_demand: Vec<(String, u32)>,
    /// Per provider this node serves: its current price in mc.
    #[serde(default)]
    pub prices: Vec<(String, u32)>,
    /// The node's public addresses as its peers see them.
    #[serde(default)]
    pub public_addrs: Vec<IpAddr>,
    /// What an observational probe costs at this node, in mc; None when
    /// it does not probe.
    #[serde(default)]
    pub probe_price_mc: Option<u32>,
    /// What this node sells a funded scan job for, in mc; None when it
    /// does not scan.
    #[serde(default)]
    pub scan_price_mc: Option<u32>,
    /// What this node, as arbiter, may still spend on scan jobs now.
    #[serde(default)]
    pub scan_budget_mc: u32,
    /// Its queued scan jobs.
    #[serde(default)]
    pub scan_queued: u32,
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
        self.decode().filter(|hb| self.signed_by(hb))
    }

    /// Decode without checking the signature.
    fn decode(&self) -> Option<Heartbeat> {
        super::rpc::cbor::decode(&self.body).ok()
    }

    /// Whether the node `hb` (decoded from this body) signed it.
    fn signed_by(&self, hb: &Heartbeat) -> bool {
        hb.node.verify(&Self::signing(&self.body), &self.sig)
    }
}

/// Whether `hb` would replace what `all` holds of its node at `now_ms` (see
/// [`Status::merge`]).
fn news(all: &HashMap<NodeId, Known>, hb: &Heartbeat, now_ms: u64) -> bool {
    let limit = now_ms.saturating_add(super::hlc::MAX_DRIFT_MS);
    hb.at_ms <= limit
        && !all
            .get(&hb.node)
            .is_some_and(|k| k.hb.at_ms >= hb.at_ms && k.hb.at_ms <= limit)
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

/// Per reporting peer: whether it is a sibling, and when it last reported.
type SeenBy = HashMap<NodeId, (bool, Instant)>;

/// One reported address: its reporters (and whether each is a sibling),
/// and whether it is taken.
pub type SeenReport = (IpAddr, Vec<(NodeId, bool)>, bool);

#[derive(Default)]
pub struct Status {
    pub local: Mutex<LocalStatus>,
    pub contacts: Mutex<HashMap<NodeId, Contact>>,
    pub heartbeats: Mutex<HashMap<NodeId, Known>>,
    last_at: Mutex<u64>,
    /// Source addresses members connected from (newest last), so the
    /// scanners never scan them, outbound-only members included.
    peer_ips: Mutex<HashMap<NodeId, Vec<std::net::IpAddr>>>,
    /// Addresses peers saw this node connect from: per address, who
    /// reported it (and whether that peer is a sibling) and when last.
    seen_from: Mutex<HashMap<IpAddr, SeenBy>>,
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

    /// `reporter` saw this node connect from `ip`.
    pub fn note_seen_from(&self, reporter: NodeId, sibling: bool, ip: IpAddr) {
        let ip = crate::net::canonical(ip);
        if !crate::net::is_scannable_target(ip) {
            return; // private, loopback, link-local: a LAN or tunnel view
        }
        let mut all = self.seen_from.lock().unwrap();
        all.entry(ip)
            .or_default()
            .insert(reporter, (sibling, Instant::now()));
    }

    /// Whether an address is believed: one sibling or two members say so.
    /// A node does not know which other members share an owner, so two
    /// distinct reporters stand in for "two members of different owners".
    fn taken(reports: &HashMap<NodeId, (bool, Instant)>) -> bool {
        let live: Vec<_> = reports
            .values()
            .filter(|(_, t)| t.elapsed() < SEEN_FROM_TTL)
            .collect();
        live.iter().any(|(s, _)| *s) || live.len() >= 2
    }

    /// Drop reports older than [`SEEN_FROM_TTL`].
    fn expire_seen_from(all: &mut HashMap<IpAddr, HashMap<NodeId, (bool, Instant)>>) {
        all.retain(|_, r| {
            r.retain(|_, (_, t)| t.elapsed() < SEEN_FROM_TTL);
            !r.is_empty()
        });
    }

    /// This node's public addresses: reported by a sibling, or by two
    /// members. Newest confirmation first.
    pub fn public_addresses(&self) -> Vec<IpAddr> {
        let mut all = self.seen_from.lock().unwrap();
        Self::expire_seen_from(&mut all);
        let mut v: Vec<(Instant, IpAddr)> = all
            .iter()
            .filter(|(_, r)| Self::taken(r))
            .map(|(ip, r)| (r.values().map(|(_, t)| *t).max().unwrap(), *ip))
            .collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.0));
        v.into_iter().map(|(_, ip)| ip).collect()
    }

    /// Every reported address with its reporters (and whether each is a
    /// sibling) and whether it is taken; taken ones first.
    pub fn seen_from_report(&self) -> Vec<SeenReport> {
        let mut all = self.seen_from.lock().unwrap();
        Self::expire_seen_from(&mut all);
        let mut v: Vec<_> = all
            .iter()
            .map(|(ip, r)| {
                let mut who: Vec<_> = r.iter().map(|(id, (s, _))| (*id, *s)).collect();
                who.sort();
                (*ip, who, Self::taken(r))
            })
            .collect();
        v.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
        v
    }

    /// Shift every seen-from report back by `by`.
    #[cfg(test)]
    pub fn age_seen_from(&self, by: Duration) {
        for r in self.seen_from.lock().unwrap().values_mut() {
            for (_, t) in r.values_mut() {
                *t = t.checked_sub(by).unwrap_or(*t);
            }
        }
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

    /// Whether [`Self::merge`] would take `hb` (checked before its
    /// signature, which costs more).
    pub fn is_news(&self, hb: &Heartbeat) -> bool {
        news(&self.heartbeats.lock().unwrap(), hb, super::hlc::wall_ms())
    }

    /// Store a heartbeat if it is newer than what we have.
    pub fn merge(&self, hb: Heartbeat, signed: SignedHeartbeat) -> bool {
        self.merge_at(hb, signed, super::hlc::wall_ms())
    }

    /// [`Self::merge`] at local time `now_ms`. A heartbeat dated further
    /// ahead than the allowed drift is refused, and one already held that
    /// is (its node's clock ran ahead, then was corrected) gives way to any
    /// newer-looking one: otherwise it would mute its node until our clock
    /// caught up with it.
    fn merge_at(&self, hb: Heartbeat, signed: SignedHeartbeat, now_ms: u64) -> bool {
        let mut all = self.heartbeats.lock().unwrap();
        if !news(&all, &hb, now_ms) {
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
        let wall = super::hlc::wall_ms();
        let mut last = self.last_at.lock().unwrap();
        // After our clock was set back from far ahead, start again from
        // it: peers refuse heartbeats dated beyond their drift limit.
        *last = if *last > wall.saturating_add(super::hlc::MAX_DRIFT_MS) {
            wall
        } else {
            wall.max(*last + 1)
        };
        *last
    }

    /// Forget the heartbeats of nodes that are no longer members (left,
    /// pruned): they are neither gossiped on nor counted. What a node that
    /// returns is known by comes back with its next heartbeat.
    pub fn retain_heartbeats(&self, keep: impl Fn(&NodeId) -> bool) {
        self.heartbeats.lock().unwrap().retain(|id, _| keep(id));
    }
}

impl Node {
    /// Build, sign and store this node's current heartbeat.
    pub fn refresh_heartbeat(&self) {
        let local = self.status.local.lock().unwrap().clone();
        let table = self.price_table();
        let (on_demand, prices) = table.announced();
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
            on_demand,
            prices,
            public_addrs: self.status.public_addresses(),
            probe_price_mc: self.prober().map(|p| p.price(&table)),
            scan_price_mc: table.price_of(crate::credits::price::SCAN),
            scan_budget_mc: self
                .scan_budget_mc
                .load(std::sync::atomic::Ordering::Relaxed),
            scan_queued: self.scan_queued.load(std::sync::atomic::Ordering::Relaxed),
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
    /// Take the gossiped heartbeats that are news: of members and newer
    /// than what is held. Only those are checked for a signature, and only
    /// so many are looked at per message (one per member, plus a little),
    /// so a peer cannot make this node verify signatures by the thousand.
    pub fn merge_heartbeats(&self, incoming: Vec<SignedHeartbeat>) -> usize {
        let limit = self.members.read().unwrap().len() + GOSSIP_SLACK;
        incoming
            .into_iter()
            .take(limit)
            .filter_map(|s| s.decode().map(|hb| (hb, s)))
            .filter(|(hb, _)| {
                hb.node != self.id() && self.is_member(&hb.node) && self.status.is_news(hb)
            })
            .filter(|(hb, s)| s.signed_by(hb) && self.status.merge(hb.clone(), s.clone()))
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

    fn signed_hb(
        id: &crate::cluster::identity::Identity,
        at_ms: u64,
    ) -> (Heartbeat, SignedHeartbeat) {
        let hb = Heartbeat {
            node: id.id,
            at_ms,
            neighbours: vec![],
            roles: vec![],
            version: "x".into(),
            pace: None,
            active_scans: 0,
            providers: vec![],
            own_seq: 0,
            retention_days: 0,
            floors: vec![],
            on_demand: vec![],
            prices: vec![],
            public_addrs: vec![],
            probe_price_mc: None,
            scan_price_mc: None,
            scan_budget_mc: 0,
            scan_queued: 0,
        };
        let body = crate::cluster::rpc::cbor::encode(&hb).unwrap();
        let sig = id.sign(&SignedHeartbeat::signing(&body));
        (hb, SignedHeartbeat { body, sig })
    }

    /// The scan fields survive the wire, and decode across protocols 4 and 5.
    #[test]
    fn scan_fields_decode_across_protocol_4_and_5() {
        use crate::cluster::rpc::cbor::{decode, encode};
        let a = crate::cluster::identity::Identity::generate().unwrap();
        let (mut hb, _) = signed_hb(&a, 1);
        hb.scan_budget_mc = 5;
        hb.scan_queued = 2;
        let back: Heartbeat = decode(&encode(&hb).unwrap()).unwrap();
        assert_eq!((back.scan_budget_mc, back.scan_queued), (5, 2));
        /// The scan fields of a protocol 4 heartbeat.
        #[derive(serde::Serialize, serde::Deserialize, Default)]
        struct Old {
            #[serde(default)]
            scan_price_mc: Option<u32>,
            #[serde(default)]
            scan_bids: u32,
        }
        #[derive(serde::Serialize, serde::Deserialize, Default, PartialEq, Debug)]
        struct New {
            #[serde(default)]
            scan_price_mc: Option<u32>,
            #[serde(default)]
            scan_budget_mc: u32,
            #[serde(default)]
            scan_queued: u32,
        }
        let new: New = decode(
            &encode(&Old {
                scan_price_mc: Some(7),
                scan_bids: 3,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            new,
            New {
                scan_price_mc: Some(7),
                ..Default::default()
            }
        );
        let old: Old = decode(
            &encode(&New {
                scan_price_mc: None,
                scan_budget_mc: 5,
                scan_queued: 2,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!((old.scan_price_mc, old.scan_bids), (None, 0));
    }

    /// A heartbeat dated far ahead is refused, and one held from before a
    /// clock correction does not mute its node until our clock catches up.
    #[test]
    fn future_heartbeats_do_not_mute_a_node() {
        let s = Status::default();
        let a = crate::cluster::identity::Identity::generate().unwrap();
        let now = 1_000_000_000_000;
        let drift = crate::cluster::hlc::MAX_DRIFT_MS;
        let merge = |at, now| {
            let (hb, signed) = signed_hb(&a, at);
            s.merge_at(hb, signed, now)
        };
        assert!(!merge(now + drift + 1, now), "too far ahead");
        assert!(s.known(&a.id).is_none());
        assert!(merge(now, now));
        assert!(!merge(now, now), "not newer");
        assert!(merge(now + drift, now), "within the drift");
        // Held while it was within the drift; an hour later it is not (our
        // clock was set back, say): a current heartbeat replaces it.
        assert!(merge(now - 3_600_000 + 10, now - 3_600_000));
        assert_eq!(s.known(&a.id).unwrap().hb.at_ms, now - 3_600_000 + 10);
        assert!(!merge(now - 3_600_000, now - 3_600_000), "older again");
    }

    #[test]
    fn own_heartbeat_time_recovers_from_a_clock_set_back() {
        let s = Status::default();
        let wall = crate::cluster::hlc::wall_ms();
        *s.last_at.lock().unwrap() = wall + 3_600_000;
        let at = s.next_at();
        assert!(at <= crate::cluster::hlc::wall_ms(), "{at}");
        assert!(s.next_at() > at);
    }

    /// Gossip takes members' heartbeats that are news, drops strangers' and
    /// forged ones, and looks at no more than one per member (plus a
    /// little) in a message.
    #[tokio::test]
    async fn gossip_takes_members_news_only() {
        use crate::cluster::identity::Identity;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let node = crate::cluster::Node::open(crate::cluster::NodeParams {
            identity: Identity::generate().unwrap(),
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
            store,
            proto: (1, 1),
            data_dir: dir.path().to_path_buf(),
            retention_days: 0,
        })
        .await
        .unwrap();
        node.bootstrap().await.unwrap();
        let (m, stranger) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let info = crate::cluster::record::MemberInfo {
            id: m.id,
            name: "m".into(),
            address: None,
            roles: vec![],
            proto_min: 1,
            proto_max: 1,
            remote_config: false,
        };
        crate::cluster::repl::append(&node, &[crate::cluster::record::Record::MemberAdd(info)])
            .await
            .unwrap();
        let now = crate::cluster::hlc::wall_ms();
        let (_, forged) = {
            let (hb, mut s) = signed_hb(&m, now + 10);
            s.sig[0] ^= 1;
            (hb, s)
        };
        let msg = vec![
            signed_hb(&m, now).1,
            signed_hb(&m, now + 5).1,
            forged,
            signed_hb(&stranger, now).1,
        ];
        assert_eq!(node.merge_heartbeats(msg), 2);
        assert_eq!(node.status.known(&m.id).unwrap().hb.at_ms, now + 5);
        // Past the cap, nothing more is looked at.
        let mut flood: Vec<_> = (0..64).map(|_| signed_hb(&stranger, now).1).collect();
        flood.push(signed_hb(&m, now + 20).1);
        assert_eq!(node.merge_heartbeats(flood), 0);
        assert_eq!(node.status.known(&m.id).unwrap().hb.at_ms, now + 5);
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
            on_demand: vec![],
            prices: vec![],
            public_addrs: vec![],
            probe_price_mc: None,
            scan_price_mc: None,
            scan_budget_mc: 0,
            scan_queued: 0,
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
