//! The asking side of a probe: which scanners could probe an address,
//! which of them to pick by default, and one paid request to each. The
//! group uid ties their results together.
use super::serve::{ProbeReq, ProbeResp, Prober};
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::credits::Mc;
use crate::credits::pay::{self, SERVE_WAIT};
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
    /// The address this node dials it at, when that is an IP; else the
    /// first public address it announces.
    pub dialled: Option<IpAddr>,
}

/// What a probe at `id` costs, as this node knows it: nothing at this
/// node (when it probes), what the member announces elsewhere.
fn price_at(node: &Node, id: &NodeId) -> Option<u32> {
    if *id == node.id() {
        return node.prober().map(|_| 0);
    }
    // Another node's probe is paid: only a member that counts with the
    // market's rules can be paid.
    if !node
        .members()
        .get(id)
        .is_some_and(|m| pay::pays_with(m.proto_max))
    {
        return None;
    }
    node.status.known(id)?.hb.probe_price_mc
}

/// The address this node dials `id` at, when that is an IP; otherwise
/// (dialled by name, or nobody can dial it) the first public address it
/// announces.
fn dialled_ip(node: &Node, id: &NodeId) -> Option<IpAddr> {
    node.dial_address(id)
        .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
        .map(|a| a.ip())
        .or_else(|| node.status.known(id)?.hb.public_addrs.first().copied())
}

/// Live scanners announcing a probe price (this node included when it
/// probes), cheapest first.
pub fn vantages(node: &Node, geo: &SharedGeo) -> Vec<Vantage> {
    let me = node.id();
    let mut out = vec![];
    for id in node.live_members(crate::intel::LIVE_WINDOW) {
        if id != me && (node.is_blocked(&id) || !node.can_call(&id)) {
            continue;
        }
        let Some(price_mc) = price_at(node, &id) else {
            continue;
        };
        let (name, country) = crate::intel::dns::describe(node, geo, &id);
        let dialled = match id == me {
            true => None,
            false => dialled_ip(node, &id),
        };
        out.push(Vantage {
            node: id,
            name,
            price_mc,
            country,
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

/// One offer of `price` to `server` and one request naming it; this
/// node's own prober is asked without an offer (free).
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
    if server == me {
        let Some(p) = prober else {
            return refused("this node does not probe".into());
        };
        let req = ProbeReq {
            ip: ip.to_string(),
            group: group.to_string(),
            offer_seq: None,
            dialled: None,
        };
        return p.serve(node, me, &req).await;
    }
    let offer_seq = match price {
        0 => None,
        p => match pay::make_offer(node, server, p).await {
            Ok(seq) => Some(seq),
            Err(why) => return refused(why),
        },
    };
    let req = ProbeReq {
        ip: ip.to_string(),
        group: group.to_string(),
        offer_seq,
        // As in its `Vantage`: the scanner records it when it has no
        // single public address of its own.
        dialled: dialled_ip(node, &server),
    };
    let call = node.call_any::<ProbeReq, ProbeResp>(
        server,
        "/rpc/v1/probe",
        &req,
        crate::intel::lookup::RPC_TIMEOUT + SERVE_WAIT,
    );
    let resp = match call.await {
        Ok(r) => r,
        Err(e) if e.downcast_ref::<crate::cluster::msg::NoAnswer>().is_some() => {
            return refused("did not answer in time".into());
        }
        Err(e) => return refused(format!("could not be asked: {e:#}")),
    };
    // A declined offer comes with a receipt of nothing: fetch it, so what
    // the offer held is free for the next one. A scanner nobody can dial
    // pushes its receipt with its own sync.
    if offer_seq.is_some()
        && matches!(resp, ProbeResp::Declined { .. })
        && let Err(e) = node.sync_around_request(server).await
    {
        tracing::debug!(?e, "sync after a declined probe offer failed");
    }
    resp
}

/// Offer `first`; a decline naming a higher price (at most
/// [`pay::RETRY_AT_MOST`] times `first`) is offered that once more.
async fn with_retry<F, Fut>(first: Mc, mut offer: F) -> ProbeResp
where
    F: FnMut(Mc) -> Fut,
    Fut: std::future::Future<Output = ProbeResp>,
{
    let resp = offer(first).await;
    match &resp {
        ProbeResp::Declined { price_mc, .. } => match pay::retry_price(first, *price_mc, true) {
            // Its price moved since its heartbeat: offer that, once.
            Some(again) => offer(again).await,
            None => resp,
        },
        ProbeResp::Accepted { .. } => resp,
    }
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
                let resp = with_retry(p as Mc, |price| {
                    offer_once(node, prober, *id, ip, group, price)
                })
                .await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Offers made to a scanner whose price is `price`; it accepts any
    /// offer that covers it.
    async fn offers_to(price: u32, first: Mc) -> (ProbeResp, Vec<Mc>) {
        let made = Mutex::new(vec![]);
        let resp = with_retry(first, |offer| {
            made.lock().unwrap().push(offer);
            async move {
                match offer >= price as Mc {
                    true => ProbeResp::Accepted {
                        probe_uid: "u".into(),
                    },
                    false => ProbeResp::Declined {
                        why: "too low".into(),
                        price_mc: Some(price),
                    },
                }
            }
        })
        .await;
        (resp, made.into_inner().unwrap())
    }

    #[tokio::test]
    async fn a_too_low_decline_is_offered_once_more_at_the_named_price() {
        let (resp, made) = offers_to(8000, 4000).await;
        assert!(matches!(resp, ProbeResp::Accepted { .. }), "{resp:?}");
        assert_eq!(made, vec![4000, 8000], "the named price, at most twice");
    }

    #[tokio::test]
    async fn a_price_above_twice_the_offer_is_not_chased() {
        let (resp, made) = offers_to(8001, 4000).await;
        assert!(matches!(resp, ProbeResp::Declined { .. }));
        assert_eq!(made, vec![4000]);
    }

    #[tokio::test]
    async fn an_accepted_offer_is_not_repeated() {
        let (resp, made) = offers_to(4000, 4000).await;
        assert!(matches!(resp, ProbeResp::Accepted { .. }));
        assert_eq!(made, vec![4000]);
    }
}
