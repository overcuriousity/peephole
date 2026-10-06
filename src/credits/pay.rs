//! Paying for a lookup. The asking node sets credits aside with a
//! `credit_offer` to the server it chose and names that entry in its
//! request; the server checks the offer against its own book, asks its
//! providers and writes a `credit_receipt` for what it answered. Half of
//! what is charged goes to the server, half is destroyed. A node's own
//! providers cost the same as anyone else's.
use super::entries::{self, Kind, SealState};
use super::ledger::OfferState;
use super::{Mc, price, show};
use crate::cluster::identity::NodeId;
use crate::cluster::record::Record;
use crate::cluster::{Node, repl};
use crate::intel::lookup::{LookupReq, LookupResp, NodeAnswer};
use crate::intel::{Providers, provider_info};
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// How long a server waits for the asker's offer to arrive.
pub const SERVE_WAIT: Duration = Duration::from_secs(10);
/// Free lookups (no offer) a member gets an hour.
pub const FREE_PER_HOUR: usize = 60;
/// Servers tried for one provider before giving up.
const MAX_ROUNDS: usize = 3;

/// A node that could answer for a provider, and what it asks.
#[derive(Debug, Clone, PartialEq)]
pub struct Quote {
    pub provider: String,
    pub server: NodeId,
    pub server_name: String,
    pub price_mc: u32,
}

/// Sort by price; equal prices in random order, so no node is preferred.
fn cheapest_first(list: &mut [Quote]) {
    let mut keyed: Vec<(u32, u32, Quote)> = list
        .iter()
        .map(|q| {
            let mut r = [0u8; 4];
            let _ = aws_lc_rs::rand::fill(&mut r);
            (q.price_mc, u32::from_le_bytes(r), q.clone())
        })
        .collect();
    keyed.sort_by_key(|(price, r, _)| (*price, *r));
    for (slot, (_, _, q)) in list.iter_mut().zip(keyed) {
        *slot = q;
    }
}

/// Who could be asked for each provider, cheapest first: this node, if it
/// serves the provider, and every live member that announces a price for
/// it and can be asked. Neither this node nor its fleet is preferred.
pub fn quotes(node: &Node, own: &Providers) -> HashMap<String, Vec<Quote>> {
    let me = node.id();
    let mut out: HashMap<String, Vec<Quote>> = HashMap::new();
    let table = node.price_table();
    for p in own.iter().filter(|p| p.ready()) {
        let name = p.name();
        out.entry(name.to_string()).or_default().push(Quote {
            provider: name.to_string(),
            server: me,
            server_name: "this node".into(),
            price_mc: table
                .price_of(name)
                .unwrap_or_else(|| price::price(name, table.unit, 1)),
        });
    }
    let members = node.members();
    for id in node.live_members(crate::intel::LIVE_WINDOW) {
        let Some(m) = members.get(&id) else { continue };
        if id == me
            || node.is_blocked(&id)
            || m.proto_max < crate::cluster::rpc::proto::OWNER_PROTO
            || node.dial_address(&id).is_none()
        {
            continue;
        }
        let Some(k) = node.status.known(&id) else {
            continue;
        };
        for (provider, price_mc) in &k.hb.prices {
            if provider_info(provider).is_none() {
                continue;
            }
            out.entry(provider.clone()).or_default().push(Quote {
                provider: provider.clone(),
                server: id,
                server_name: m.name.clone(),
                price_mc: *price_mc,
            });
        }
    }
    for list in out.values_mut() {
        cheapest_first(list);
    }
    out
}

/// The asker's entry `seq`, once it is held here (as a payment row).
async fn wait_for(node: &Node, peer: &NodeId, seq: u64) -> Option<entries::Entry> {
    let until = tokio::time::Instant::now() + SERVE_WAIT;
    loop {
        if let Ok(Some(e)) = entries::get(&node.store.pool, peer, seq).await {
            return Some(e);
        }
        if tokio::time::Instant::now() >= until {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Removes an offer from the ones being served when the request ends.
struct Serving<'a>(&'a Node, (NodeId, u64));

impl Drop for Serving<'_> {
    fn drop(&mut self) {
        self.0.serving_offers.lock().unwrap().remove(&self.1);
    }
}

/// A provider result the dataset holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Stored {
    pub provider: String,
    pub fetched_at: String,
    pub age_secs: i64,
    /// The node that fetched it.
    pub node: Option<String>,
    pub source_version: Option<String>,
    pub data: serde_json::Value,
}

/// Per provider, the newest result for `ip` any node fetched less than 24
/// hours ago. Shown instead of asking again: it costs nothing.
pub async fn stored(pool: &SqlitePool, ip: &IpAddr) -> anyhow::Result<Vec<Stored>> {
    type Row = (String, String, Option<String>, String, Option<String>, i64);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT t.provider, t.fetched_at, t.source_version, t.data_json,
                (SELECT name FROM members m WHERE m.id = t.origin),
                CAST((julianday('now') - julianday(t.fetched_at)) * 86400 AS INTEGER)
         FROM ip_intel_log t
         WHERE t.ip = ? AND t.fetched_at > datetime('now', '-1 day')
         ORDER BY t.hlc DESC, t.origin DESC",
    )
    .bind(crate::net::canonical(*ip).to_string())
    .fetch_all(pool)
    .await?;
    let mut out: Vec<Stored> = vec![];
    for (provider, fetched_at, source_version, data_json, node, age_secs) in rows {
        if provider_info(&provider).is_none() || out.iter().any(|s| s.provider == provider) {
            continue;
        }
        out.push(Stored {
            provider,
            fetched_at,
            age_secs: age_secs.max(0),
            node,
            source_version,
            data: serde_json::from_str(&data_json).unwrap_or(serde_json::Value::Null),
        });
    }
    Ok(out)
}

/// Whether the dataset here holds a recorded request from `ip` (a
/// false-positive claim alone does not count).
pub async fn recorded(pool: &SqlitePool, ip: &IpAddr) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM requests r JOIN ips i ON i.id = r.ip_id
                       WHERE i.ip = ? AND r.is_fp_claim = 0)",
    )
    .bind(crate::net::canonical(*ip).to_string())
    .fetch_one(pool)
    .await
    .is_ok_and(|n| n > 0)
}

/// The serving side: check the offer `offer_seq` of `peer` in this node's
/// own book, ask the providers in `served`, write the receipt. Whatever is
/// declined says why.
pub async fn serve(
    node: &Arc<Node>,
    providers: &Providers,
    peer: NodeId,
    ip: IpAddr,
    served: Vec<String>,
    offer_seq: u64,
) -> LookupResp {
    let decline = |names: &[String], why: String| LookupResp {
        declined: names.iter().map(|n| (n.clone(), why.clone())).collect(),
        ..Default::default()
    };
    let Some(entry) = wait_for(node, &peer, offer_seq).await else {
        return decline(
            &served,
            format!("the offer (entry {offer_seq} of your node's log) did not arrive here"),
        );
    };
    match &entry.kind {
        Kind::Offer { to, .. } if *to == node.id() => {}
        Kind::Offer { .. } => return decline(&served, "the offer is made to another node".into()),
        _ => {
            return decline(
                &served,
                format!("entry {offer_seq} of your node's log is no offer"),
            );
        }
    }
    // Unchecked is not enough: the asker's next offer seals a range that
    // starts at this one, so one declined offer is the cost.
    match entry.seal {
        SealState::Consistent => {}
        SealState::Inconsistent => {
            return decline(
                &served,
                "the offer's seal does not match your node's log here".into(),
            );
        }
        _ => {
            return decline(
                &served,
                "the offer's seal could not be checked here yet; offer again".into(),
            );
        }
    }
    if !node
        .serving_offers
        .lock()
        .unwrap()
        .insert((peer, offer_seq))
    {
        return decline(&served, "this offer is being served already".into());
    }
    let _serving = Serving(node, (peer, offer_seq));
    let book = match super::book_fresh(node).await {
        Ok(b) => b,
        Err(e) => {
            return decline(
                &served,
                format!("this node could not read its books: {e:#}"),
            );
        }
    };
    let standing = book.standing(&peer);
    if standing.left_out() {
        return decline(
            &served,
            format!(
                "your node's credits are not accepted here: {}",
                standing.reasons().join("; ")
            ),
        );
    }
    let Some(offer) = book.ledger.offer(&peer, offer_seq) else {
        return decline(&served, "the offer does not count here".into());
    };
    if offer.state != OfferState::Open {
        return decline(
            &served,
            "the offer is used up, or older than 15 minutes".into(),
        );
    }
    let (offered, covered) = (offer.offered, offer.covered);

    let table = node.price_table();
    let price_of = |name: &str| -> Mc {
        table
            .price_of(name)
            .unwrap_or_else(|| price::price(name, table.unit, 1)) as Mc
    };
    let shares = node.lookup_shares();
    let provider = |name: &str| providers.iter().find(|p| p.name() == name);
    // Providers whose on-demand share is spent are declined one by one;
    // the rest is served.
    let (mut asking, mut declined) = (vec![], vec![]);
    for name in served {
        let spent = match (shares, provider(&name)) {
            (Some(s), Some(p)) => s.spent(p.as_ref()).await.unwrap_or(true),
            _ => false,
        };
        if spent {
            declined.push((
                name,
                "this node's on-demand share of that provider is spent for today".to_string(),
            ));
        } else {
            asking.push(name);
        }
    }
    let total: Mc = asking.iter().map(|n| price_of(n)).sum();
    let refuse = |why: String, price_mc: Option<u32>| async move {
        // A receipt of nothing frees the asker's credits at once.
        let receipt = Record::CreditReceipt {
            payer: peer,
            offer_seq,
            charged_mc: 0,
            answered: vec![],
        };
        if let Err(e) = repl::append(node, &[receipt]).await {
            tracing::debug!(?e, "receipt not written");
        }
        tracing::info!(asker = %peer.short(), %why, "paid lookup declined");
        (why, price_mc)
    };
    let refused = if total > offered {
        Some(
            refuse(
                format!(
                    "this costs {} credits here now; the offer is {}",
                    show(total),
                    show(offered)
                ),
                Some(total.min(u32::MAX as Mc) as u32),
            )
            .await,
        )
    } else if covered < total {
        Some(
            refuse(
                format!(
                    "not covered here: this node counts {} of the {} credits offered",
                    show(covered),
                    show(offered)
                ),
                None,
            )
            .await,
        )
    } else {
        None
    };
    if let Some((why, price_mc)) = refused {
        let mut resp = decline(&asking, why);
        resp.price_mc = price_mc;
        resp.declined.append(&mut declined);
        return resp;
    }
    // Count the share before asking: a failed request used the budget too.
    let mut ask_now = vec![];
    for name in asking {
        let taken = match (shares, provider(&name)) {
            (Some(s), Some(p)) => s.take(p.as_ref()).await.unwrap_or(false),
            _ => true,
        };
        if taken {
            ask_now.push(name);
        } else {
            declined.push((
                name,
                "this node's on-demand share of that provider is spent for today".to_string(),
            ));
        }
    }
    let mut resp = if ask_now.is_empty() {
        LookupResp::default()
    } else {
        crate::intel::lookup::local(providers, &ip, &ask_now).await
    };
    let answered: Vec<String> = resp.findings.iter().map(|f| f.provider.clone()).collect();
    let charged = answered
        .iter()
        .map(|n| price_of(n))
        .sum::<Mc>()
        .min(covered);
    let receipt = Record::CreditReceipt {
        payer: peer,
        offer_seq,
        charged_mc: charged.min(u32::MAX as Mc) as u32,
        answered: answered.clone(),
    };
    match repl::append(node, &[receipt]).await {
        Ok(_) => resp.charged_mc = charged.min(u32::MAX as Mc) as u32,
        // Answered all the same: this node goes unpaid, the asker's
        // credits return after 15 minutes.
        Err(e) => tracing::warn!(?e, "credit receipt not written"),
    }
    tracing::info!(asker = %peer.short(), providers = %answered.join(","),
        charged = %show(charged), "paid lookup served");
    // What was paid for is kept for everyone when the cluster has
    // recorded the address, exactly as the automatic enrichment would
    // write it; for an address nobody recorded nothing is written.
    if !resp.findings.is_empty() && recorded(&node.store.pool, &ip).await {
        let rec = crate::store::recorder::Recorder::Cluster(node.clone());
        let text = crate::net::canonical(ip).to_string();
        let mut all = true;
        for f in &resp.findings {
            let version = f.source_version.as_deref();
            let written = if provider_info(&f.provider).is_some_and(|i| i.api) {
                rec.record_lookup(&text, &f.provider, version, f.data.clone())
                    .await
            } else {
                rec.record_intel(&text, &f.provider, version, f.data.clone())
                    .await
            };
            if let Err(e) = written {
                tracing::warn!(provider = %f.provider, ?e, "paid lookup result not kept");
                all = false;
            }
        }
        resp.kept = all;
    }
    resp.declined.append(&mut declined);
    resp
}

/// Offer `total_mc` to `server` for `providers` and ask it once. The
/// answer carries what it charged; a refusal says why.
pub async fn offer_and_ask(
    node: &Arc<Node>,
    own: &Providers,
    ip: IpAddr,
    server: NodeId,
    providers: &[String],
    total_mc: Mc,
) -> LookupResp {
    let decline = |why: String| LookupResp {
        declined: providers.iter().map(|p| (p.clone(), why.clone())).collect(),
        ..Default::default()
    };
    let me = node.id();
    let book = match super::book_fresh(node).await {
        Ok(b) => b,
        Err(e) => return decline(format!("this node could not read its books: {e:#}")),
    };
    let mut book = book;
    if book.ledger.spendable_parts(&me, total_mc).is_none() {
        // The fleet's balance sits at its collecting node: draw what is
        // missing, then look again.
        let missing = total_mc.saturating_sub(book.balance(&me));
        if super::fleet::draw(node, missing).await
            && let Ok(b) = super::book_fresh(node).await
        {
            book = b;
        }
    }
    let Some(parts) = book.ledger.spendable_parts(&me, total_mc) else {
        let have = book.balance(&me);
        return decline(format!(
            "this node holds {} credits; the lookup costs {} ({} missing)",
            show(have),
            show(total_mc),
            show(total_mc.saturating_sub(have))
        ));
    };
    let offer = match repl::append_sealing(node, |seal| Record::CreditOffer {
        to: server,
        parts,
        seal,
    })
    .await
    {
        Ok(e) => e,
        Err(e) => return decline(format!("the offer could not be written: {e:#}")),
    };
    let req = LookupReq {
        ip: ip.to_string(),
        providers: providers.to_vec(),
        offer_seq: Some(offer.seq),
    };
    let mut resp = if server == me {
        let _ = own;
        crate::intel::lookup::serve(node, me, &req).await
    } else {
        let Some(addr) = node.dial_address(&server) else {
            return decline("the node cannot be dialled from here".into());
        };
        // So the offer is there before the request.
        if let Err(e) = crate::cluster::sync::reconcile(node, server, &addr, false).await {
            tracing::debug!(
                ?e,
                "sync before a paid lookup failed; the server waits for the offer"
            );
        }
        let call = node.call::<LookupReq, LookupResp>(server, &addr, "/rpc/v1/lookup", &req);
        match tokio::time::timeout(crate::intel::lookup::RPC_TIMEOUT + SERVE_WAIT, call).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return decline(format!("could not be asked: {e:#}")),
            Err(_) => return decline("did not answer in time".into()),
        }
    };
    // Only what was asked for, and only from providers this build knows.
    resp.findings
        .retain(|f| providers.contains(&f.provider) && provider_info(&f.provider).is_some());
    resp
}

/// Ask the cheapest server of each quote group once more at its named
/// price when it turned the first offer down for being too low.
async fn ask_server(
    node: &Arc<Node>,
    own: &Providers,
    ip: IpAddr,
    server: NodeId,
    quotes: &[Quote],
) -> LookupResp {
    let names: Vec<String> = quotes.iter().map(|q| q.provider.clone()).collect();
    let total: Mc = quotes.iter().map(|q| q.price_mc as Mc).sum();
    let me = node.id();
    if total == 0 {
        // Free providers need no offer.
        let req = LookupReq {
            ip: ip.to_string(),
            providers: names.clone(),
            offer_seq: None,
        };
        if server == me {
            return crate::intel::lookup::local(own, &ip, &names).await;
        }
        let Some(addr) = node.dial_address(&server) else {
            return LookupResp::default();
        };
        let call = node.call::<LookupReq, LookupResp>(server, &addr, "/rpc/v1/lookup", &req);
        return match tokio::time::timeout(crate::intel::lookup::RPC_TIMEOUT, call).await {
            Ok(Ok(mut r)) => {
                r.findings.retain(|f| {
                    names.contains(&f.provider) && provider_info(&f.provider).is_some()
                });
                r
            }
            _ => LookupResp {
                declined: names
                    .iter()
                    .map(|n| (n.clone(), "could not be asked".into()))
                    .collect(),
                ..Default::default()
            },
        };
    }
    let first = offer_and_ask(node, own, ip, server, &names, total).await;
    match first.price_mc {
        // Its price moved since its heartbeat: offer that, once.
        Some(p) if first.findings.is_empty() && p as Mc > total => {
            offer_and_ask(node, own, ip, server, &names, p as Mc).await
        }
        _ => first,
    }
}

/// The asking side: for each provider in `wanted` that somebody serves,
/// ask the cheapest server (and the next cheapest when it declines), and
/// pay what each asks. One answer per server asked.
pub async fn ask(
    node: &Arc<Node>,
    own: &Providers,
    ip: IpAddr,
    wanted: &[String],
) -> Vec<NodeAnswer> {
    let me = node.id();
    let mut remaining: Vec<String> = wanted.to_vec();
    let mut tried: HashMap<String, HashSet<NodeId>> = HashMap::new();
    let mut out: Vec<NodeAnswer> = vec![];
    for _ in 0..MAX_ROUNDS {
        let all = quotes(node, own);
        // The cheapest server not yet tried, per provider still open.
        let mut by_server: Vec<(NodeId, String, Vec<Quote>)> = vec![];
        for p in &remaining {
            let seen = tried.entry(p.clone()).or_default();
            let Some(q) = all
                .get(p)
                .and_then(|list| list.iter().find(|q| !seen.contains(&q.server)))
            else {
                continue;
            };
            seen.insert(q.server);
            match by_server.iter_mut().find(|(s, _, _)| *s == q.server) {
                Some((_, _, list)) => list.push(q.clone()),
                None => by_server.push((q.server, q.server_name.clone(), vec![q.clone()])),
            }
        }
        if by_server.is_empty() {
            break;
        }
        // This node first, then by name: a stable order on the page.
        by_server.sort_by_key(|(s, name, _)| (*s != me, name.clone()));
        for (server, name, quotes) in by_server {
            let resp = ask_server(node, own, ip, server, &quotes).await;
            remaining.retain(|p| !resp.findings.iter().any(|f| &f.provider == p));
            out.push(NodeAnswer {
                node: name,
                charged_mc: resp.charged_mc,
                resp,
            });
        }
        if remaining.is_empty() {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(provider: &str, server: u8, price_mc: u32) -> Quote {
        Quote {
            provider: provider.into(),
            server: NodeId([server; 32]),
            server_name: format!("n{server}"),
            price_mc,
        }
    }

    #[test]
    fn the_cheapest_server_is_asked_first_and_no_node_is_preferred() {
        let mut list = vec![
            q("abuseipdb", 3, 300),
            q("abuseipdb", 1, 200),
            q("abuseipdb", 2, 250),
        ];
        cheapest_first(&mut list);
        let order: Vec<u32> = list.iter().map(|x| x.price_mc).collect();
        assert_eq!(order, [200, 250, 300]);
        // Equal prices: one of them at random, not always the same one.
        let mut first = HashSet::new();
        for _ in 0..200 {
            let mut same = vec![q("abuseipdb", 1, 200), q("abuseipdb", 2, 200)];
            cheapest_first(&mut same);
            first.insert(same[0].server);
        }
        assert_eq!(first.len(), 2);
    }
}
