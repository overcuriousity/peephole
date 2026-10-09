//! Paid requests to a member nobody can dial (outbound-only): the request
//! travels as a directed message, which reaches it through the outbox it
//! long-polls, and is answered by the same code as a direct call.
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::msg::Msg;
use crate::cluster::rpc::cbor;
use crate::scan::probe::serve::{ProbeReq, ProbeResp};
use serde_bytes::ByteBuf;
use std::sync::Arc;

/// The calls that may arrive as messages: paid answers, nothing that syncs.
pub const ROUTED_PATHS: [&str; 4] = [
    "/rpc/v1/lookup",
    "/rpc/v1/resolve",
    "/rpc/v1/probe",
    "/rpc/v1/rdns",
];
/// Largest request or answer body sent as a message (outboxes are in memory).
pub const MAX_ROUTED_BODY: usize = 1 << 20;

pub fn allowed(path: &str) -> bool {
    ROUTED_PATHS.contains(&path)
}

pub fn fits(body: &[u8]) -> bool {
    body.len() <= MAX_ROUTED_BODY
}

fn reply(status: u16, body: Vec<u8>) -> Msg {
    Msg::RpcReply {
        status,
        body: ByteBuf::from(body),
    }
}

/// Answer routed calls the way the RPC handlers answer direct ones.
pub fn serve(node: &Arc<Node>) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |from, msg| {
        let weak = weak.clone();
        Box::pin(async move {
            let Msg::Rpc { path, body } = msg else {
                return None;
            };
            let node = weak.upgrade()?;
            if !allowed(&path) {
                return Some(reply(404, b"not routable".to_vec()));
            }
            if !fits(&body) {
                return Some(reply(413, b"request too large".to_vec()));
            }
            let out = match answer(&node, from, &path, &body).await {
                Ok(bytes) => bytes,
                Err(e) => return Some(reply(400, format!("{e:#}").into_bytes())),
            };
            Some(if fits(&out) {
                reply(200, out)
            } else {
                reply(413, b"answer too large".to_vec())
            })
        })
    }));
}

async fn answer(
    node: &Arc<Node>,
    peer: NodeId,
    path: &str,
    body: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match path {
        "/rpc/v1/lookup" => {
            let req: crate::intel::lookup::LookupReq = cbor::decode(body)?;
            cbor::encode(&crate::intel::lookup::serve(node, peer, &req).await)
        }
        "/rpc/v1/resolve" => {
            let req: crate::intel::dns::ResolveReq = cbor::decode(body)?;
            cbor::encode(&crate::intel::dns::serve_resolve(node, peer, &req).await)
        }
        "/rpc/v1/rdns" => {
            let req: crate::intel::rdns::RdnsReq = cbor::decode(body)?;
            cbor::encode(&crate::intel::rdns::serve_rdns(node, peer, &req).await)
        }
        "/rpc/v1/probe" => {
            let req: ProbeReq = cbor::decode(body)?;
            cbor::encode(&probe_answer(node, peer, &req).await)
        }
        _ => anyhow::bail!("not routable"),
    }
}

/// A probe for a member, direct or routed; declined where nobody probes.
pub(crate) async fn probe_answer(node: &Arc<Node>, peer: NodeId, req: &ProbeReq) -> ProbeResp {
    match node.prober() {
        Some(p) => p.clone().serve(node, peer, req).await,
        None => ProbeResp::Declined {
            why: "this node does not probe".into(),
            price_mc: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_paid_request_paths_are_routed() {
        assert!(
            allowed("/rpc/v1/lookup") && allowed("/rpc/v1/resolve") && allowed("/rpc/v1/probe")
        );
        assert!(allowed("/rpc/v1/rdns"));
        for p in [
            "/rpc/v1/push",
            "/rpc/v1/pull",
            "/rpc/v1/join",
            "/rpc/v1/intel",
            "/rpc/v1/msg",
        ] {
            assert!(!allowed(p), "{p}");
        }
    }

    #[test]
    fn bodies_over_the_cap_are_refused() {
        assert!(fits(&vec![0u8; MAX_ROUTED_BODY]));
        assert!(!fits(&vec![0u8; MAX_ROUTED_BODY + 1]));
    }
}
