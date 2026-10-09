//! Relay leases: an outbound-only member (nobody can dial it) rents an
//! hour of outbox hosting from reachable members, two at a time. A relay
//! holds an outbox only for members it holds a lease from; senders route
//! messages for an outbound-only member through the relays it lists in
//! its heartbeat. A lease is a good like any other (`credits::price`).
use super::Node;
use super::identity::NodeId;
use crate::credits::{Mc, pay, price, show};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One lease: an hour.
pub const LEASE_MS: u64 = 3_600_000;
/// A lessee renews this long before a lease ends.
pub const RENEW_BEFORE_MS: u64 = 5 * 60_000;
/// Relays an outbound-only member holds.
pub const WANTED: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayReq {
    /// Always 1.
    pub hours: u32,
    /// The lessee's offer; None at a zero price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RelayResp {
    /// Leased until this wall-clock time (ms).
    Accepted { until_ms: u64 },
    Declined {
        why: String,
        #[serde(default)]
        price_mc: Option<u32>,
    },
}

/// The leases this node holds as a relay: lessee → end (ms).
#[derive(Default)]
pub struct Leases(Mutex<HashMap<NodeId, u64>>);

impl Leases {
    pub fn holds(&self, id: &NodeId, now_ms: u64) -> bool {
        self.0
            .lock()
            .unwrap()
            .get(id)
            .is_some_and(|until| *until > now_ms)
    }

    /// Leases that have not ended.
    pub fn current(&self, now_ms: u64) -> usize {
        let mut l = self.0.lock().unwrap();
        l.retain(|_, until| *until > now_ms);
        l.len()
    }

    /// End `id`'s lease here at once: messages for it are refused.
    #[doc(hidden)] // For tests: a lease otherwise only runs out.
    pub fn end(&self, id: &NodeId) {
        self.0.lock().unwrap().remove(id);
    }

    /// Lease (or renew) for `id`: an hour from the end of its current
    /// lease, or from now. Returns the new end.
    pub fn grant(&self, id: NodeId, now_ms: u64) -> u64 {
        let mut l = self.0.lock().unwrap();
        let from = l
            .get(&id)
            .copied()
            .filter(|u| *u > now_ms)
            .unwrap_or(now_ms);
        let until = from + LEASE_MS;
        l.insert(id, until);
        until
    }
}

/// The leases this node took as a lessee: relay → end (ms).
#[derive(Default)]
pub struct Leased(Mutex<BTreeMap<NodeId, u64>>, tokio::sync::Notify);

impl Leased {
    /// Its relays now.
    pub fn relays(&self, now_ms: u64) -> Vec<NodeId> {
        let mut l = self.0.lock().unwrap();
        l.retain(|_, until| *until > now_ms);
        l.keys().copied().collect()
    }

    /// Relays not due a renewal.
    pub fn keep(&self, now_ms: u64) -> Vec<NodeId> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, until)| **until > now_ms + RENEW_BEFORE_MS)
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn set(&self, relay: NodeId, until_ms: u64) {
        self.0.lock().unwrap().insert(relay, until_ms);
    }

    /// Drop `relay`, which no longer holds this node's lease (it
    /// restarted): [`lease_once`] replaces it.
    pub fn forget(&self, relay: &NodeId) -> bool {
        let gone = self.0.lock().unwrap().remove(relay).is_some();
        if gone {
            self.1.notify_waiters();
        }
        gone
    }
}

/// What a relay answers, at once, to a message or an inbox poll of a
/// member that lists it but holds no lease there.
pub const NO_LEASE: &str = "no relay lease here";

/// What a lease costs here; None: this node is not advertised (it can
/// relay nothing). 0 before the first price refresh.
pub fn price(node: &Node) -> Option<u32> {
    node.cfg
        .advertise
        .is_some()
        .then(|| node.price_table().relay_mc.unwrap_or(0))
}

/// Lease an hour of outbox hosting to `peer`: free at a zero price, paid
/// with its offer otherwise, charged when accepted.
pub async fn serve(node: &Arc<Node>, peer: NodeId, req: &RelayReq) -> RelayResp {
    let declined = |why: String, price_mc: Option<u32>| RelayResp::Declined { why, price_mc };
    let release = async || {
        if let Some(seq) = req.offer_seq {
            pay::release(node, peer, seq).await;
        }
    };
    let Some(cost) = price(node) else {
        release().await;
        return declined(
            "this node cannot be reached: it relays nothing".into(),
            None,
        );
    };
    if req.hours != 1 {
        release().await;
        return declined("a lease is one hour".into(), None);
    }
    let now = super::hlc::wall_ms();
    if !node.relay_leases.holds(&peer, now)
        && node.relay_leases.current(now) >= node.cfg.relay_slots as usize
    {
        release().await;
        return declined("every relay slot here is leased".into(), Some(cost));
    }
    match req.offer_seq {
        None if cost > 0 => {
            return declined(
                format!(
                    "a lease costs {} credits here now; the request carries no offer",
                    show(cost as Mc)
                ),
                Some(cost),
            );
        }
        None => {}
        Some(seq) => {
            match pay::accept_offer(node, peer, seq, cost as Mc, "relay", pay::SERVE_MARGIN_MS)
                .await
            {
                Ok(_) => {}
                Err(pay::Declined::TooLow { why, price_mc }) => {
                    return declined(why, Some(price_mc));
                }
                Err(pay::Declined::Why(w) | pay::Declined::NotCovered(w)) => {
                    return declined(w, None);
                }
            }
            let receipt = super::record::Record::CreditReceipt {
                payer: peer,
                offer_seq: seq,
                charged_mc: cost,
                answered: vec![price::RELAY.into()],
                economy: super::record::ECONOMY,
            };
            if let Err(e) = super::repl::append(node, &[receipt]).await {
                tracing::warn!(?e, "relay receipt not written");
                return declined("the receipt could not be written".into(), None);
            }
        }
    }
    // A sale: only a lease granted counts as demand (a full house counts
    // as at capacity in `credits::price`).
    node.market.note(price::RELAY, 1);
    let until_ms = node.relay_leases.grant(peer, now);
    tracing::info!(lessee = %peer.short(), charged = %show(cost as Mc), "relay leased");
    RelayResp::Accepted { until_ms }
}

/// One lease request to `relay` at `price`, offered again once at a
/// higher price it names.
async fn ask(node: &Arc<Node>, relay: NodeId, first: u32) -> Option<u64> {
    let once = async |p: Mc| -> Option<RelayResp> {
        let offer_seq = match p {
            0 => None,
            p => Some(pay::make_offer(node, relay, p).await.ok()?),
        };
        let req = RelayReq {
            hours: 1,
            offer_seq,
        };
        node.call_any::<RelayReq, RelayResp>(relay, "/rpc/v1/relay", &req, Duration::from_secs(20))
            .await
            .ok()
    };
    let mut resp = once(first as Mc).await?;
    if let RelayResp::Declined { price_mc, .. } = &resp
        && let Some(p) = pay::retry_price(first as Mc, *price_mc, true)
    {
        resp = once(p).await?;
    }
    match resp {
        RelayResp::Accepted { until_ms } => Some(until_ms),
        RelayResp::Declined { why, .. } => {
            tracing::debug!(relay = %relay.short(), %why, "relay lease declined");
            None
        }
    }
}

/// Lease what is missing of [`WANTED`] relays (renewing those that end
/// within [`RENEW_BEFORE_MS`]) from the cheapest reachable sellers. An
/// advertised node leases nothing. Returns how many leases it took.
pub async fn lease_once(node: &Arc<Node>) -> usize {
    if node.cfg.advertise.is_some() {
        return 0;
    }
    let now = super::hlc::wall_ms();
    let keep = node.leased.keep(now);
    let need = WANTED.saturating_sub(keep.len());
    if need == 0 {
        return 0;
    }
    let me = node.id();
    let mut sellers: Vec<(u32, u32, NodeId)> = node
        .live_members(crate::intel::LIVE_WINDOW)
        .into_iter()
        .filter(|id| *id != me && !keep.contains(id) && !node.is_blocked(id))
        .filter(|id| node.dial_address(id).is_some())
        .filter_map(|id| {
            let p = crate::intel::dns::member_price(node, &id, price::RELAY)?;
            let mut r = [0u8; 4];
            let _ = aws_lc_rs::rand::fill(&mut r);
            Some((p, u32::from_le_bytes(r), id))
        })
        .collect();
    sellers.sort();
    let mut took = 0;
    for (p, _, relay) in sellers {
        if took == need {
            break;
        }
        if let Some(until) = ask(node, relay, p).await {
            node.leased.set(relay, until);
            took += 1;
        }
    }
    if took > 0 {
        node.publish_status();
    }
    took
}

/// Keep this outbound-only node's relays leased, until shutdown.
pub async fn run(node: Arc<Node>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        // Registered before `lease_once`: a relay forgotten meanwhile
        // still wakes this loop.
        let lost = node.leased.1.notified();
        lease_once(&node).await;
        let short = node.leased.relays(super::hlc::wall_ms()).len() < WANTED;
        let wait = Duration::from_secs(if short { 5 } else { 60 });
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = lost => {}
            _ = shutdown.changed() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    #[test]
    fn a_relay_holds_a_lease_for_an_hour_and_a_renewal_extends_it() {
        let l = Leases::default();
        let t = 1_000_000_000u64;
        let until = l.grant(id(1), t);
        assert_eq!(until, t + LEASE_MS);
        assert!(l.holds(&id(1), t + LEASE_MS - 1));
        assert!(!l.holds(&id(1), t + LEASE_MS));
        assert!(!l.holds(&id(2), t));
        // Renewed 5 minutes before the end: an hour more from the end.
        let renewed = l.grant(id(1), until - RENEW_BEFORE_MS);
        assert_eq!(renewed, until + LEASE_MS);
        assert_eq!(l.current(t), 1);
        // After it ran out, a new lease starts now.
        assert_eq!(l.grant(id(1), renewed + 5), renewed + 5 + LEASE_MS);
        l.grant(id(2), t);
        assert_eq!(l.current(renewed + 6), 1, "the other ran out");
        l.end(&id(1));
        assert!(!l.holds(&id(1), renewed + 6));
    }

    async fn relay_node(slots: u32) -> (tempfile::TempDir, Arc<Node>) {
        use crate::cluster::identity::Identity;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let node = Node::open(crate::cluster::NodeParams {
            identity: Identity::generate().unwrap(),
            cluster: crate::config::ClusterConfig {
                node_name: "n".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: Some("127.0.0.1:1".into()),
                key_path: None,
                takeover_hours: 6.0,
                lease_secs: 120,
                remote_config: false,
                origin_quota_mb: 20 * 1024,
                relay_slots: slots,
                peers: vec![],
            },
            roles: Default::default(),
            store,
            proto: (1, 1),
            data_dir: dir.path().to_path_buf(),
            retention_days: 30,
        })
        .await
        .unwrap();
        node.bootstrap().await.unwrap();
        (dir, node)
    }

    /// Only a lease granted is a sale: a declined request moves no price.
    #[tokio::test]
    async fn a_declined_lease_request_is_no_sale() {
        let (_dir, node) = relay_node(1).await;
        let req = RelayReq {
            hours: 1,
            offer_seq: None,
        };
        let sold = || node.market.peek().counts.get(price::RELAY).copied();
        node.relay_leases.grant(id(8), super::super::hlc::wall_ms());
        let full = serve(&node, id(7), &req).await;
        assert!(matches!(full, RelayResp::Declined { .. }), "{full:?}");
        let long = serve(
            &node,
            id(7),
            &RelayReq {
                hours: 2,
                ..req.clone()
            },
        )
        .await;
        assert!(matches!(long, RelayResp::Declined { .. }), "{long:?}");
        assert_eq!(sold(), None, "declined: no demand");
        node.relay_leases.end(&id(8));
        let got = serve(&node, id(7), &req).await;
        assert!(matches!(got, RelayResp::Accepted { .. }), "{got:?}");
        assert_eq!(sold(), Some(1.0));
    }

    #[test]
    fn a_lessee_renews_what_ends_within_five_minutes() {
        let l = Leased::default();
        let t = 1_000_000_000u64;
        l.set(id(1), t + LEASE_MS);
        l.set(id(2), t + RENEW_BEFORE_MS - 1);
        assert_eq!(l.relays(t), [id(1), id(2)]);
        assert_eq!(l.keep(t), [id(1)], "2 is due a renewal");
        assert_eq!(l.relays(t + RENEW_BEFORE_MS), [id(1)], "2 ran out");
        assert!(l.forget(&id(1)) && !l.forget(&id(1)));
        assert!(l.relays(t).is_empty());
    }
}
