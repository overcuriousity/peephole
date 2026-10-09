//! Reverse DNS of every source: the PTR names of each address that sent
//! requests, kept when they resolve back to it (forward-confirmed), looked
//! up when the source is first seen and again when it returns a day after
//! the last lookup. In a cluster the node that recorded a source buys its
//! names from a quorum (`buy_pass`); a standalone node looks up on its own
//! (`pass`). The names are kept in `ip_names`, source `rdns`; a source's
//! own DNS often names its hoster or a research scanner.
use crate::scan::crawler::{Forward, MAX_NAMES, confirmed_names, system_forward, system_resolver};
use crate::store::Store;
use futures::StreamExt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Sources looked up per pass.
const BATCH: i64 = 50;
/// Lookups at a time.
const PARALLEL: usize = 4;
/// Between passes.
const EVERY: Duration = Duration::from_secs(60);
/// After a full batch: more are likely due (the backlog after an upgrade).
const AGAIN: Duration = Duration::from_secs(1);
/// Longest error text kept in a record.
const MAX_ERROR: usize = 200;

/// How a node finds a source's forward-confirmed reverse names.
pub type RdnsLookup = std::sync::Arc<
    dyn Fn(IpAddr) -> futures::future::BoxFuture<'static, Result<Vec<String>, String>>
        + Send
        + Sync,
>;

/// What one node asks another.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RdnsReq {
    pub ip: String,
    /// The asker's offer; None at a zero price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_seq: Option<u64>,
}

/// Its answer: the names, or why there are none.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RdnsResp {
    pub names: Vec<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub charged_mc: u32,
    /// This node's price, when the request offered less (or nothing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_mc: Option<u32>,
}

impl RdnsResp {
    fn refused(why: &str, price_mc: Option<u32>) -> Self {
        RdnsResp {
            error: Some(why.into()),
            price_mc,
            ..Default::default()
        }
    }
}

/// This node's answer for `ip`: the hook in tests, else the system resolver.
pub async fn lookup_here(node: &crate::cluster::Node, ip: IpAddr) -> Result<Vec<String>, String> {
    if let Some(f) = node.rdns_lookup() {
        return f(ip).await;
    }
    let Some(resolver) = system_resolver() else {
        return Err("no nameserver on this node".into());
    };
    confirmed_names(resolver, &system_forward(), ip)
        .await
        .map_err(|e| format!("{e:#}").chars().take(MAX_ERROR).collect())
}

/// Look up `req.ip`'s reverse names for `peer`: free at a zero price,
/// against the offer it names otherwise; a failure is not charged.
pub async fn serve_rdns(
    node: &std::sync::Arc<crate::cluster::Node>,
    peer: crate::cluster::identity::NodeId,
    req: &RdnsReq,
) -> RdnsResp {
    use crate::credits::{pay, price};
    let release = async || {
        if let Some(seq) = req.offer_seq {
            pay::release(node, peer, seq).await;
        }
    };
    let Some(ip) = req
        .ip
        .trim()
        .parse::<IpAddr>()
        .ok()
        .filter(|a| req.ip.len() <= 64 && crate::net::is_scannable_target(*a))
    else {
        release().await;
        return RdnsResp::refused("not a public address", None);
    };
    let cost = node.price_table().price_of(price::RDNS).unwrap_or(0);
    node.market.note(price::RDNS, 1);
    if req.offer_seq.is_none() && cost > 0 {
        return RdnsResp::refused(
            &format!(
                "reverse names cost {} credits here now; the request carries no offer",
                crate::credits::show(cost as u64)
            ),
            Some(cost),
        );
    }
    if let Some(seq) = req.offer_seq {
        match pay::accept_offer(node, peer, seq, cost as u64, "rdns", pay::SERVE_MARGIN_MS).await {
            Ok(_) => {}
            Err(pay::Declined::TooLow { why, price_mc }) => {
                return RdnsResp::refused(&why, Some(price_mc));
            }
            Err(pay::Declined::Why(w) | pay::Declined::NotCovered(w)) => {
                return RdnsResp::refused(&w, None);
            }
        }
    }
    let taken = match node.lookup_shares() {
        Some(s) => s.take_good(price::RDNS).await.unwrap_or(false),
        None => true,
    };
    if !taken {
        release().await;
        return RdnsResp::refused(
            "this node's reverse lookups for others are used up for today",
            None,
        );
    }
    let answer = lookup_here(node, ip).await;
    let charged = match req.offer_seq {
        Some(seq) => {
            let charged = if answer.is_ok() { cost } else { 0 };
            let receipt = crate::cluster::record::Record::CreditReceipt {
                payer: peer,
                offer_seq: seq,
                charged_mc: charged,
                answered: if charged > 0 {
                    vec![price::RDNS.into()]
                } else {
                    vec![]
                },
                economy: crate::cluster::record::ECONOMY,
            };
            match crate::cluster::repl::append(node, &[receipt]).await {
                Ok(_) => charged,
                Err(e) => {
                    tracing::warn!(?e, "reverse-name receipt not written");
                    0
                }
            }
        }
        None => 0,
    };
    match answer {
        Ok(names) => RdnsResp {
            names,
            charged_mc: charged,
            ..Default::default()
        },
        Err(e) => RdnsResp::refused(&e, None),
    }
}

/// One request to `id`, with an offer of `price` unless it is 0.
async fn ask_once(
    node: &std::sync::Arc<crate::cluster::Node>,
    id: crate::cluster::identity::NodeId,
    ip: IpAddr,
    price: u64,
) -> Result<RdnsResp, String> {
    let offer_seq = match price {
        0 => None,
        p => Some(crate::credits::pay::make_offer(node, id, p).await?),
    };
    let req = RdnsReq {
        ip: ip.to_string(),
        offer_seq,
    };
    let call = node.call_any::<RdnsReq, RdnsResp>(
        id,
        "/rpc/v1/rdns",
        &req,
        crate::intel::lookup::RPC_TIMEOUT,
    );
    match call.await {
        Err(e) if e.downcast_ref::<crate::cluster::msg::NoAnswer>().is_some() => {
            Err("did not answer in time".into())
        }
        Err(e) => Err(format!("could not be asked: {e:#}")),
        Ok(r) => Ok(r),
    }
}

/// One member's answer, with an offer unless its price is 0; a decline
/// naming a higher price is offered that once.
async fn ask_rdns(
    node: &std::sync::Arc<crate::cluster::Node>,
    id: crate::cluster::identity::NodeId,
    ip: IpAddr,
) -> Result<Vec<String>, String> {
    use crate::credits::price;
    let Some(first) = crate::intel::dns::member_price(node, &id, price::RDNS) else {
        return Err("announces no price for reverse names".into());
    };
    let mut resp = ask_once(node, id, ip, first as u64).await;
    if let Ok(r) = &resp
        && r.error.is_some()
        && let Some(p) = crate::credits::pay::retry_price(first as u64, r.price_mc, true)
    {
        // A declined offer comes with a receipt of nothing: fetch it, so
        // what the first offer held is free for the next one.
        if first > 0
            && let Err(e) = node.sync_around_request(id).await
        {
            tracing::debug!(?e, "sync after a declined reverse-name offer failed");
        }
        resp = ask_once(node, id, ip, p).await;
    }
    match resp? {
        RdnsResp { error: Some(e), .. } => Err(e),
        RdnsResp { names, .. } => Ok(names),
    }
}

/// Clip an answer to what a record may hold: names normalised, those that
/// are not valid host names dropped (one would make every node ignore the
/// record), at most `MAX_NAMES`.
fn clip(a: Result<Vec<String>, String>) -> Result<Vec<String>, String> {
    match a {
        Ok(v) => {
            let mut names: Vec<String> = Vec::new();
            for n in v {
                if let Some(n) = crate::intel::dns::valid_name(&n)
                    && !names.contains(&n)
                {
                    names.push(n);
                }
            }
            names.truncate(MAX_NAMES);
            Ok(names)
        }
        Err(e) => Err(e.chars().take(MAX_ERROR).collect()),
    }
}

/// Buy the reverse names of this node's own sources that are due, from
/// itself and the quorum's cheapest other members, and replicate the
/// answers. Returns how many sources were handled.
pub async fn buy_pass(
    node: &std::sync::Arc<crate::cluster::Node>,
    geo: &crate::intel::SharedGeo,
) -> anyhow::Result<usize> {
    use crate::cluster::record::{RdnsRec, Record};
    let me = node.id();
    let due = node.store.rdns_due_own(BATCH, &me).await?;
    let n = due.len();
    let siblings: std::collections::HashSet<_> =
        crate::cluster::owner::fleet::siblings(&node.store)
            .await
            .inspect_err(|e| tracing::debug!(?e, "reverse DNS: siblings not read"))
            .unwrap_or_default()
            .into_iter()
            .collect();
    let rec = crate::store::recorder::Recorder::Cluster(node.clone());
    for (ip_id, text) in due {
        let ip = match text.parse::<IpAddr>() {
            Ok(ip) if crate::net::is_scannable_target(ip) => ip,
            _ => {
                node.store.mark_rdns(ip_id).await?;
                continue;
            }
        };
        let chosen = crate::intel::dns::choose(node, &siblings, geo, crate::credits::price::RDNS);
        let others = futures::future::join_all(
            chosen
                .iter()
                .filter(|r| r.id != me)
                .map(|r| async { (r.id, ask_rdns(node, r.id, ip).await) }),
        );
        let (own, mut answers) = futures::join!(lookup_here(node, ip), others);
        answers.insert(0, (me, own));
        let answers = answers.into_iter().map(|(id, a)| (id, clip(a))).collect();
        let r = RdnsRec {
            uid: rec.uid(),
            ip: crate::net::canonical(ip).to_string(),
            at: crate::store::data::now_ts(),
            answers,
            build: crate::COMMIT.into(),
        };
        // Only a written record counts as looked up; else the next pass retries.
        match rec.write(vec![Record::RdnsName(r)]).await {
            Ok(()) => node.store.mark_rdns(ip_id).await?,
            Err(e) => tracing::warn!(%ip, ?e, "reverse names not written"),
        }
    }
    Ok(n)
}

/// Look up the sources that are due, `BATCH` at a time, until shutdown: in
/// a cluster the node's own sources are bought from a quorum, standalone
/// they are looked up here. Off when `enabled` is false, or standalone
/// without a resolver.
pub async fn run(
    store: Store,
    node: Option<std::sync::Arc<crate::cluster::Node>>,
    geo: crate::intel::SharedGeo,
    enabled: bool,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    if !enabled {
        return;
    }
    let standalone = match node {
        Some(_) => None,
        None => {
            let Some(resolver) = system_resolver() else {
                tracing::info!("reverse DNS: no nameserver in /etc/resolv.conf, off");
                return;
            };
            Some((resolver, system_forward()))
        }
    };
    loop {
        let done = match (&node, &standalone) {
            (Some(node), _) => buy_pass(node, &geo).await,
            (None, Some((resolver, forward))) => pass(&store, *resolver, forward).await,
            (None, None) => return,
        };
        let wait = match done {
            Ok(n) if n as i64 == BATCH => AGAIN,
            Ok(0) => EVERY,
            Ok(n) => {
                tracing::debug!(sources = n, "reverse DNS: looked up");
                EVERY
            }
            Err(e) => {
                tracing::warn!(error = %e, "reverse DNS: pass failed");
                EVERY
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            r = shutdown.changed() => if r.is_err() { return },
        }
        if *shutdown.borrow() {
            return;
        }
    }
}

/// One batch: every due source is marked looked up, whatever the
/// resolver answered (a broken resolver costs one try a day per source).
/// Returns how many sources were handled.
pub(crate) async fn pass(
    store: &Store,
    resolver: SocketAddr,
    forward: &Forward,
) -> anyhow::Result<usize> {
    let due = store.rdns_due(BATCH).await?;
    let n = due.len();
    let found: Vec<(i64, Vec<String>)> = futures::stream::iter(due)
        .map(|(id, ip)| async move {
            let names = match ip.parse::<IpAddr>() {
                Ok(addr) if crate::net::is_scannable_target(addr) => {
                    confirmed_names(resolver, forward, addr)
                        .await
                        .unwrap_or_else(|e| {
                            tracing::debug!(%ip, error = %e, "reverse DNS failed");
                            vec![]
                        })
                }
                _ => vec![],
            };
            (id, names)
        })
        .buffer_unordered(PARALLEL)
        .collect()
        .await;
    // One source's failure does not lose the rest of the batch.
    for (id, names) in found {
        if let Err(e) = store.record_rdns(id, &names).await {
            tracing::warn!(ip_id = id, error = %e, "reverse DNS: not stored");
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_cleaned_before_they_are_recorded() {
        let got = clip(Ok(vec![
            "Host.Example.NET.".into(),
            "BAD_NAME.".into(),
            "192.0.2.1".into(),
            "host.example.net".into(),
        ]));
        assert_eq!(got, Ok(vec!["host.example.net".to_string()]));
        assert_eq!(clip(Ok(vec!["_x".into()])), Ok(vec![]));
        assert_eq!(clip(Err("e".repeat(300))).unwrap_err().len(), MAX_ERROR);
    }
    use crate::scan::crawler::testing::fake_resolver;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn a_pass_stores_confirmed_names_and_marks_every_source() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut ids = vec![];
        for ip in ["198.51.100.7", "198.51.100.8"] {
            let row = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
            s.insert_request(&crate::store::requests::NewRequest {
                ip_id: row.id,
                method: "GET".into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                ..Default::default()
            })
            .await
            .unwrap();
            ids.push(row.id);
        }
        let resolver = fake_resolver(Arc::new(Mutex::new(Some("host-7.example.net".into())))).await;
        let forward: Forward = Arc::new(|name: String| {
            Box::pin(async move {
                if name.trim_end_matches('.') == "host-7.example.net" {
                    Ok(vec!["198.51.100.7".parse().unwrap()])
                } else {
                    Err(std::io::Error::other("no such host"))
                }
            })
        });
        assert_eq!(pass(&s, resolver, &forward).await.unwrap(), 2);
        let n7 = s.names_for_ip(ids[0]).await.unwrap();
        assert_eq!(n7.len(), 1);
        assert_eq!(n7[0].source, "rdns");
        assert!(
            s.names_for_ip(ids[1]).await.unwrap().is_empty(),
            "the name points elsewhere"
        );
        assert_eq!(
            pass(&s, resolver, &forward).await.unwrap(),
            0,
            "both marked"
        );
    }
}
