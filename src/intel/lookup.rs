//! On-demand enrichment: an admin asks what the providers say about one
//! address, now. On a standalone node its own databases and keys answer.
//! In a cluster a lookup is paid with credits (`crate::credits::pay`): per
//! provider the node with the lowest announced price answers, this node's
//! own providers included, and what was paid for is kept in the dataset
//! when the cluster has recorded the address. The automatic enrichment
//! ([`super::enrich_loop`]) keeps recording on its own schedule.
use super::{KNOWN_PROVIDERS, Providers};
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::store::recorder::Recorder;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

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
    /// The asker's `credit_offer` (its sequence number in the asker's log)
    /// that pays for this request. None: free providers only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_seq: Option<u64>,
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
    /// What the receipt charges, in mc.
    #[serde(default)]
    pub charged_mc: u32,
    /// Set when the offer was below this node's price for what was asked:
    /// that price, so the asker may offer again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_mc: Option<u32>,
}

/// What the providers here say about `ip`: those in `wanted`, or every one
/// this node runs when `wanted` is empty.
pub async fn local(providers: &Providers, ip: &IpAddr, wanted: &[String]) -> LookupResp {
    let mut resp = LookupResp::default();
    // Canonical first: an IPv4-mapped address is IPv4 to every provider.
    let ip = crate::net::canonical(*ip);
    let text = ip.to_string();
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

/// Serve a member's request (or this node's own, `peer` being itself)
/// with this node's providers. With an offer the request is paid
/// (`credits::pay::serve`); without one only free providers answer, at
/// most [`crate::credits::pay::FREE_PER_HOUR`] times an hour per asker.
pub async fn serve(node: &Arc<Node>, peer: NodeId, req: &LookupReq) -> LookupResp {
    let all = |why: &str| LookupResp {
        declined: vec![("*".into(), why.into())],
        ..Default::default()
    };
    let Some(providers) = node.lookup_providers() else {
        return all("this node runs no enrichment providers");
    };
    if req.ip.len() > MAX_IP_LEN {
        return all("address too long");
    }
    let Ok(ip) = req.ip.trim().parse::<IpAddr>() else {
        return all("not an IP address");
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
    let mut resp = match req.offer_seq {
        Some(seq) => crate::credits::pay::serve(node, providers, peer, ip, served, seq).await,
        None => {
            let (free, paid): (Vec<String>, Vec<String>) = served
                .into_iter()
                .partition(|n| crate::credits::price::weight_milli(n) == 0);
            declined.extend(paid.into_iter().map(|n| {
                (
                    n,
                    "lookups of this provider are paid with credits: the request carries no offer"
                        .into(),
                )
            }));
            if free.is_empty() {
                LookupResp::default()
            } else if !node.take_free_lookup(peer) {
                LookupResp {
                    declined: free
                        .into_iter()
                        .map(|n| (n, "too many free lookups from your node this hour".into()))
                        .collect(),
                    ..Default::default()
                }
            } else {
                local(providers, &ip, &free).await
            }
        }
    };
    resp.declined.append(&mut declined);
    resp
}

/// One node's answer, by the node's name ("this node" for our own).
#[derive(Debug, Clone, PartialEq)]
pub struct NodeAnswer {
    pub node: String,
    pub resp: LookupResp,
    /// What that node charged for this answer, in mc.
    pub charged_mc: u32,
}

/// What every reachable node says about `ip`. Standalone: this node's
/// providers. In a cluster: per provider the cheapest node, paid with
/// this node's credits (`credits::pay::ask`).
pub async fn cluster(rec: &Recorder, providers: &Providers, ip: IpAddr) -> Vec<NodeAnswer> {
    let known: Vec<String> = KNOWN_PROVIDERS.iter().map(|p| p.name.to_string()).collect();
    let Recorder::Cluster(node) = rec else {
        let mine = local(providers, &ip, &[]).await;
        let mut out = vec![NodeAnswer {
            node: "this node".into(),
            resp: mine,
            charged_mc: 0,
        }];
        note_unserved(&mut out, &known);
        return out;
    };
    let mut out = crate::credits::pay::ask(node, providers, ip, &known).await;
    if out.is_empty() {
        out.push(NodeAnswer {
            node: "this node".into(),
            resp: LookupResp::default(),
            charged_mc: 0,
        });
    }
    note_unserved(&mut out, &known);
    out
}

/// Every provider in `wanted` that nobody answered or declined gets a
/// note on the first answer.
fn note_unserved(out: &mut [NodeAnswer], wanted: &[String]) {
    let missing: Vec<String> = wanted
        .iter()
        .filter(|p| {
            !out.iter().any(|a| {
                a.resp.findings.iter().any(|f| &f.provider == *p)
                    || a.resp.declined.iter().any(|(n, _)| n == *p)
            })
        })
        .cloned()
        .collect();
    for p in missing {
        out[0]
            .resp
            .declined
            .push((p, "no reachable node serves this provider".into()));
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

    /// An IPv4-only provider answers for an IPv4-mapped address.
    #[tokio::test]
    async fn mapped_addresses_count_as_ipv4() {
        struct V4Only;
        impl crate::intel::provider::Provider for V4Only {
            fn name(&self) -> &'static str {
                "v4only"
            }
            fn ready(&self) -> bool {
                true
            }
            fn ipv6(&self) -> bool {
                false
            }
            fn lookup<'a>(
                &'a self,
                ips: &'a [String],
            ) -> futures::future::BoxFuture<'a, Vec<crate::intel::provider::Finding>> {
                Box::pin(async move {
                    ips.iter()
                        .map(|ip| crate::intel::provider::Finding {
                            ip: ip.clone(),
                            source_version: None,
                            data: serde_json::json!({ "asked": ip }),
                        })
                        .collect()
                })
            }
        }
        let providers: Providers = vec![Arc::new(V4Only)];
        let resp = local(&providers, &"::ffff:203.0.113.7".parse().unwrap(), &[]).await;
        assert!(resp.declined.is_empty());
        assert_eq!(resp.findings[0].data["asked"], "203.0.113.7");
        let resp = local(&providers, &"2001:db8::7".parse().unwrap(), &[]).await;
        assert_eq!(resp.declined.len(), 1);
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

    /// A request of a node of an earlier version carries no offer and
    /// still decodes; an answer of one carries no charge.
    #[test]
    fn requests_and_answers_of_an_earlier_version_decode() {
        #[derive(Serialize)]
        struct OldReq {
            ip: String,
            providers: Vec<String>,
        }
        #[derive(Serialize)]
        struct OldResp {
            findings: Vec<Found>,
            declined: Vec<(String, String)>,
        }
        let raw = crate::cluster::rpc::cbor::encode(&OldReq {
            ip: "203.0.113.7".into(),
            providers: vec![],
        })
        .unwrap();
        let req: LookupReq = crate::cluster::rpc::cbor::decode(&raw).unwrap();
        assert_eq!(req.offer_seq, None);
        let raw = crate::cluster::rpc::cbor::encode(&OldResp {
            findings: vec![],
            declined: vec![],
        })
        .unwrap();
        let resp: LookupResp = crate::cluster::rpc::cbor::decode(&raw).unwrap();
        assert_eq!((resp.charged_mc, resp.price_mc), (0, None));
    }
}
