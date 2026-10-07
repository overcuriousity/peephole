//! The asking side of a probe: which scanners could probe an address,
//! which of them to pick by default, and one paid request to each. The
//! group uid ties their results together.
use super::serve::{ProbeReq, ProbeResp, Prober};
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::credits::pay::{self, SERVE_WAIT};
use crate::credits::{Mc, price};
use crate::intel::SharedGeo;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

/// A scanner that announces a probe price.
#[derive(Debug, Clone, PartialEq)]
pub struct Vantage {
    pub node: NodeId,
    pub name: String,
    pub price_mc: u32,
    /// Where its public address is, as this node's GeoLite2 places it.
    pub country: Option<String>,
    /// The address this node dials it at, when that is an IP.
    pub dialled: Option<IpAddr>,
}

/// What a probe at `id` costs, as this node knows it.
fn price_at(node: &Node, id: &NodeId) -> Option<u32> {
    if *id == node.id() {
        node.prober()?;
        let table = node.price_table();
        return Some(
            table
                .probe_mc
                .unwrap_or_else(|| price::price(price::PROBE, table.unit, 1)),
        );
    }
    node.status.known(id)?.hb.probe_price_mc
}

/// Live scanners announcing a probe price (this node included when it
/// probes), cheapest first.
pub fn vantages(node: &Node, geo: &SharedGeo) -> Vec<Vantage> {
    let me = node.id();
    let members = node.members();
    let country = |ip: Option<&IpAddr>| {
        let ip = ip?;
        geo.read().ok()?.as_ref()?.lookup(ip).country
    };
    let mut out = vec![];
    for id in node.live_members(crate::intel::LIVE_WINDOW) {
        if id != me && (node.is_blocked(&id) || node.dial_address(&id).is_none()) {
            continue;
        }
        let Some(price_mc) = price_at(node, &id) else {
            continue;
        };
        let (name, publics, dialled) = if id == me {
            ("this node".to_string(), node.public_addrs(), None)
        } else {
            let addr = node.dial_address(&id);
            (
                members
                    .get(&id)
                    .map(|m| m.name.clone())
                    .unwrap_or_else(|| id.short()),
                node.status
                    .known(&id)
                    .map(|k| k.hb.public_addrs.clone())
                    .unwrap_or_default(),
                addr.and_then(|a| a.parse::<std::net::SocketAddr>().ok())
                    .map(|a| a.ip()),
            )
        };
        out.push(Vantage {
            node: id,
            name,
            price_mc,
            country: country(publics.first().or(dialled.as_ref())),
            dialled,
        });
    }
    out.sort_by(|a, b| (a.price_mc, &a.name).cmp(&(b.price_mc, &b.name)));
    out
}

/// The default pick: up to `n`, spread over distinct countries, padded
/// with the cheapest.
pub fn default_pick(all: &[Vantage], n: usize) -> Vec<NodeId> {
    let mut picked: Vec<NodeId> = vec![];
    let mut seen: HashSet<&str> = HashSet::new();
    for v in all {
        if picked.len() == n {
            break;
        }
        if let Some(c) = v.country.as_deref()
            && seen.insert(c)
        {
            picked.push(v.node);
        }
    }
    for v in all {
        if picked.len() == n {
            break;
        }
        if !picked.contains(&v.node) {
            picked.push(v.node);
        }
    }
    picked
}

/// What one scanner said.
#[derive(Debug, Clone, PartialEq)]
pub struct Asked {
    pub node: NodeId,
    pub name: String,
    /// The probe's uid, or why there is none.
    pub outcome: Result<String, String>,
}

/// One offer of `price` to `server` and one request naming it.
async fn offer_once(
    node: &Arc<Node>,
    prober: Option<&Arc<Prober>>,
    server: NodeId,
    ip: IpAddr,
    group: &str,
    price: Mc,
) -> ProbeResp {
    let me = node.id();
    let refused = |why: String| ProbeResp::Declined {
        why,
        price_mc: None,
    };
    let own = match (server == me, prober) {
        (true, None) => return refused("this node does not probe".into()),
        (true, Some(p)) => Some(p),
        (false, _) => None,
    };
    let seq = match pay::make_offer(node, server, price).await {
        Ok(seq) => seq,
        Err(why) => return refused(why),
    };
    let req = ProbeReq {
        ip: ip.to_string(),
        group: group.to_string(),
        offer_seq: Some(seq),
    };
    if let Some(p) = own {
        return p.serve(node, me, &req).await;
    }
    let Some(addr) = node.dial_address(&server) else {
        return refused("the node cannot be dialled from here".into());
    };
    let call = node.call::<ProbeReq, ProbeResp>(server, &addr, "/rpc/v1/probe", &req);
    let resp =
        match tokio::time::timeout(crate::intel::lookup::RPC_TIMEOUT + SERVE_WAIT, call).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return refused(format!("could not be asked: {e:#}")),
            Err(_) => return refused("did not answer in time".into()),
        };
    // A declined offer comes with a receipt of nothing: fetch it, so what
    // the offer held is free for the next one.
    if matches!(resp, ProbeResp::Declined { .. })
        && let Err(e) = crate::cluster::sync::reconcile(node, server, &addr, false).await
    {
        tracing::debug!(?e, "sync after a declined probe offer failed");
    }
    resp
}

/// One offer and one call per chosen scanner; the group uid ties the
/// results. A too-low decline is offered once more at the named price
/// (at most [`pay::RETRY_AT_MOST`] times the first offer).
pub async fn ask(
    node: &Arc<Node>,
    prober: Option<&Arc<Prober>>,
    ip: IpAddr,
    chosen: &[NodeId],
    group: &str,
) -> Vec<Asked> {
    let members = node.members();
    let mut out = vec![];
    for id in chosen {
        let name = if *id == node.id() {
            "this node".to_string()
        } else {
            members
                .get(id)
                .map(|m| m.name.clone())
                .unwrap_or_else(|| id.short())
        };
        let outcome = match price_at(node, id) {
            None => Err("it announces no probe price".to_string()),
            Some(p) => {
                let offered = p as Mc;
                let mut resp = offer_once(node, prober, *id, ip, group, offered).await;
                if let ProbeResp::Declined { price_mc, .. } = &resp
                    && let Some(again) = pay::retry_price(offered, *price_mc, true)
                {
                    // Its price moved since its heartbeat: offer that, once.
                    resp = offer_once(node, prober, *id, ip, group, again).await;
                }
                match resp {
                    ProbeResp::Accepted { probe_uid } => Ok(probe_uid),
                    ProbeResp::Declined { why, .. } => Err(why),
                }
            }
        };
        out.push(Asked {
            node: *id,
            name,
            outcome,
        });
    }
    out
}
