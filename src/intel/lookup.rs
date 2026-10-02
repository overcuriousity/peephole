//! On-demand enrichment: an admin asks what the providers say about one
//! address, now. This node's own databases and keys answer first; a
//! provider nobody here serves is asked from a live member that announces
//! it, over the cluster RPC. Nothing is stored: not on this node, not on
//! the answering node, not in the dataset. The automatic enrichment
//! ([`super::enrich_loop`]) keeps recording on its own schedule.
//!
//! API lookups spend the answering node's provider budget, so a member
//! serves at most [`PER_PEER_PER_DAY`] of them per asking node per UTC day;
//! local databases (GeoLite2, the Tor exit list) are free.
use super::{KNOWN_PROVIDERS, Providers, provider_info};
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::store::recorder::Recorder;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// API lookups a member serves per asking node and UTC day.
pub const PER_PEER_PER_DAY: u32 = 50;
/// Longest wait for one member's answer (API providers pace themselves at
/// a request per second and time out after 20 s).
pub const RPC_TIMEOUT: Duration = Duration::from_secs(40);
/// Longest IP text accepted from a peer.
const MAX_IP_LEN: usize = 64;

/// What one node asks another.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LookupReq {
    pub ip: String,
    /// Provider names wanted; empty: every provider the node serves.
    #[serde(default)]
    pub providers: Vec<String>,
}

/// One provider's answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Found {
    pub provider: String,
    pub source_version: Option<String>,
    pub data: serde_json::Value,
}

/// What a node answered.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LookupResp {
    pub findings: Vec<Found>,
    /// `(provider, why)` for every provider asked but not answered.
    #[serde(default)]
    pub declined: Vec<(String, String)>,
}

/// What the providers here say about `ip`: those in `wanted`, or every one
/// this node runs when `wanted` is empty.
pub async fn local(providers: &Providers, ip: &IpAddr, wanted: &[String]) -> LookupResp {
    let mut resp = LookupResp::default();
    let text = crate::net::canonical(*ip).to_string();
    for p in providers {
        let name = p.name();
        if !wanted.is_empty() && !wanted.iter().any(|w| w == name) {
            continue;
        }
        if !p.ready() {
            resp.declined.push((
                name.into(),
                "not available on this node right now (no database, no key, or its budget is spent)"
                    .into(),
            ));
            continue;
        }
        if ip.is_ipv6() && !p.ipv6() {
            resp.declined
                .push((name.into(), "does not answer for IPv6 addresses".into()));
            continue;
        }
        match p
            .lookup(std::slice::from_ref(&text))
            .await
            .into_iter()
            .next()
        {
            Some(f) => resp.findings.push(Found {
                provider: name.into(),
                source_version: f.source_version,
                data: f.data,
            }),
            None => resp.declined.push((
                name.into(),
                "no answer (not a public address, the service refused it, or it failed)".into(),
            )),
        }
    }
    resp
}

/// Serve a member's request with this node's providers, within the
/// member's daily budget for API lookups.
pub async fn serve(node: &Node, peer: NodeId, req: &LookupReq) -> LookupResp {
    let Some(providers) = node.lookup_providers() else {
        return LookupResp {
            declined: vec![("*".into(), "this node runs no enrichment providers".into())],
            ..Default::default()
        };
    };
    if req.ip.len() > MAX_IP_LEN {
        return LookupResp {
            declined: vec![("*".into(), "address too long".into())],
            ..Default::default()
        };
    }
    let Ok(ip) = req.ip.trim().parse::<IpAddr>() else {
        return LookupResp {
            declined: vec![("*".into(), "not an IP address".into())],
            ..Default::default()
        };
    };
    // Only what this node serves is asked; the rest is declined at once.
    let served: Vec<String> = providers
        .iter()
        .map(|p| p.name().to_string())
        .filter(|n| req.providers.is_empty() || req.providers.contains(n))
        .collect();
    let mut declined: Vec<(String, String)> = req
        .providers
        .iter()
        .filter(|n| !served.contains(n))
        .map(|n| (n.clone(), "not served by this node".into()))
        .collect();
    let api_asked = served
        .iter()
        .filter(|n| provider_info(n).is_some_and(|i| i.api))
        .count() as u32;
    let wanted: Vec<String> = if api_asked > 0 && !node.take_lookup_budget(peer, api_asked) {
        for n in served
            .iter()
            .filter(|n| provider_info(n).is_some_and(|i| i.api))
        {
            declined.push((
                n.clone(),
                format!(
                    "your node's on-demand budget here ({PER_PEER_PER_DAY} API lookups a day) is spent"
                ),
            ));
        }
        served
            .into_iter()
            .filter(|n| !provider_info(n).is_some_and(|i| i.api))
            .collect()
    } else {
        served
    };
    let mut resp = if wanted.is_empty() {
        LookupResp::default()
    } else {
        local(providers, &ip, &wanted).await
    };
    resp.declined.append(&mut declined);
    resp
}

/// One node's answer, by the node's name ("this node" for our own).
#[derive(Debug, Clone, PartialEq)]
pub struct NodeAnswer {
    pub node: String,
    pub resp: LookupResp,
}

/// What every reachable node says about `ip`: this node's providers first,
/// then one live member per provider nobody here answered.
pub async fn cluster(rec: &Recorder, providers: &Providers, ip: IpAddr) -> Vec<NodeAnswer> {
    let mine = local(providers, &ip, &[]).await;
    let mut missing: Vec<String> = KNOWN_PROVIDERS
        .iter()
        .map(|p| p.name.to_string())
        .filter(|n| !mine.findings.iter().any(|f| &f.provider == n))
        .collect();
    let mut out = vec![NodeAnswer {
        node: "this node".into(),
        resp: mine,
    }];
    if let Some(node) = rec.node() {
        ask_members(node, ip, &mut missing, &mut out).await;
    }
    for p in missing {
        if !out
            .iter()
            .any(|a| a.resp.declined.iter().any(|(n, _)| *n == p))
        {
            out[0]
                .resp
                .declined
                .push((p, "no reachable node serves this provider".into()));
        }
    }
    out
}

/// Ask one live member per provider in `missing`, removing what they
/// answered; their answers go to `out`.
async fn ask_members(
    node: &Node,
    ip: IpAddr,
    missing: &mut Vec<String>,
    out: &mut Vec<NodeAnswer>,
) {
    let me = node.id();
    let members = node.members();
    let live = node.live_members(super::LIVE_WINDOW);
    // Dialable members first: an outbound-only member cannot be asked.
    let mut candidates: Vec<(NodeId, Vec<String>)> = live
        .into_iter()
        .filter(|id| *id != me && !node.is_blocked(id))
        .filter_map(|id| {
            let serves = node.status.known(&id)?.hb.providers;
            Some((id, serves))
        })
        .collect();
    candidates.sort_by_key(|(id, _)| (members.get(id).is_none_or(|m| m.address.is_none()), *id));
    for (id, serves) in candidates {
        if missing.is_empty() {
            break;
        }
        let ask: Vec<String> = serves.into_iter().filter(|s| missing.contains(s)).collect();
        if ask.is_empty() {
            continue;
        }
        let Some(member) = members.get(&id) else {
            continue;
        };
        let Some(addr) = node.dial_address(&id) else {
            out.push(NodeAnswer {
                node: member.name.clone(),
                resp: LookupResp {
                    declined: ask
                        .iter()
                        .map(|p| {
                            (
                                p.clone(),
                                "serves it, but is outbound-only: it cannot be asked".into(),
                            )
                        })
                        .collect(),
                    ..Default::default()
                },
            });
            continue;
        };
        let req = LookupReq {
            ip: ip.to_string(),
            providers: ask.clone(),
        };
        let answer = tokio::time::timeout(
            RPC_TIMEOUT,
            node.call::<LookupReq, LookupResp>(id, &addr, "/rpc/v1/lookup", &req),
        )
        .await;
        let resp = match answer {
            Ok(Ok(mut resp)) => {
                // Only what was asked for, and only from known providers.
                resp.findings
                    .retain(|f| ask.contains(&f.provider) && provider_info(&f.provider).is_some());
                missing.retain(|m| !resp.findings.iter().any(|f| &f.provider == m));
                resp
            }
            Ok(Err(e)) => LookupResp {
                declined: ask
                    .iter()
                    .map(|p| (p.clone(), format!("could not be asked: {e:#}")))
                    .collect(),
                ..Default::default()
            },
            Err(_) => LookupResp {
                declined: ask
                    .iter()
                    .map(|p| (p.clone(), "did not answer in time".into()))
                    .collect(),
                ..Default::default()
            },
        };
        out.push(NodeAnswer {
            node: member.name.clone(),
            resp,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::provider::{MaxMind, TorExits};
    use std::sync::{Arc, RwLock};

    fn providers() -> Providers {
        let geo: super::super::SharedGeo = Arc::new(RwLock::new(None));
        // A loaded (one-entry) exit list: an empty one is "not ready".
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tor-exit.txt"), "198.51.100.1\n").unwrap();
        let tor: super::super::SharedTor = Arc::new(RwLock::new(
            super::super::tor::TorExitList::load(dir.path()).unwrap(),
        ));
        vec![Arc::new(MaxMind(geo)), Arc::new(TorExits(tor))]
    }

    #[tokio::test]
    async fn local_answers_with_what_is_ready_and_explains_the_rest() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let resp = local(&providers(), &ip, &[]).await;
        // No GeoLite2 database: declined. The (empty) Tor list answers.
        assert_eq!(resp.findings.len(), 1);
        assert_eq!(resp.findings[0].provider, super::super::TOR);
        assert_eq!(resp.findings[0].data["exit"], false);
        assert_eq!(resp.declined.len(), 1);
        assert_eq!(resp.declined[0].0, super::super::MAXMIND);
        // Only what is wanted is asked.
        let only = local(&providers(), &ip, &[super::super::TOR.into()]).await;
        assert_eq!(only.findings.len(), 1);
        assert!(only.declined.is_empty());
    }

    #[tokio::test]
    async fn standalone_cluster_lookup_is_the_local_answer_plus_unserved_notes() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let rec = store.local();
        let out = cluster(&rec, &providers(), "203.0.113.7".parse().unwrap()).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].node, "this node");
        let declined: Vec<&str> = out[0]
            .resp
            .declined
            .iter()
            .map(|(p, _)| p.as_str())
            .collect();
        // Every known provider but the one that answered is accounted for.
        assert_eq!(declined.len(), KNOWN_PROVIDERS.len() - 1);
        assert!(declined.contains(&super::super::SHODAN));
        assert!(!declined.contains(&super::super::TOR));
    }
}
