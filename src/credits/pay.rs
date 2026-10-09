//! Paying for a lookup. The asking node sets credits aside with a
//! `credit_offer` to the server it chose and names that entry in its
//! request; the server checks the offer against its own book, asks its
//! providers and writes a `credit_receipt` for what it answered. The
//! server keeps what it charges. What a node answers itself is free; what
//! another node answers is paid, whoever owns it.
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
/// Servers tried for one provider before giving up.
const MAX_ROUNDS: usize = 3;
/// A server that turns an offer down names its price; the asker offers it
/// once more only up to this many times what the server announced. A
/// price can move between heartbeats, but the server
/// names it alone: without a bound it could ask for the asker's whole
/// balance, and the fleet's behind it.
pub(crate) const RETRY_AT_MOST: Mc = 2;

/// Whether a member announcing `proto_max` sells scan jobs at its own price.
pub fn sells_scans(proto_max: u32) -> bool {
    proto_max >= crate::cluster::rpc::proto::SCAN_PRICE_PROTO
}

/// Whether a member announcing `proto_max` counts balances as this node does.
pub fn pays_with(proto_max: u32) -> bool {
    proto_max >= crate::cluster::rpc::proto::MARKET_PROTO
}

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

/// Why a provider whose on-demand share is used up is declined.
const SHARE_SPENT: &str = "this node's on-demand share of that provider is spent for today";

/// Who could be asked for each provider, cheapest first: this node, if it
/// serves the provider (for nothing: it answers itself), and every live
/// member that announces a price for it and can be asked (at the price it
/// announces, which may be 0).
pub fn quotes(node: &Node, own: &Providers) -> HashMap<String, Vec<Quote>> {
    let me = node.id();
    let mut out: HashMap<String, Vec<Quote>> = HashMap::new();
    for p in own.iter().filter(|p| p.ready()) {
        let name = p.name();
        out.entry(name.to_string()).or_default().push(Quote {
            provider: name.to_string(),
            server: me,
            server_name: "this node".into(),
            price_mc: 0,
        });
    }
    let members = node.members();
    for id in node.live_members(crate::intel::LIVE_WINDOW) {
        let Some(m) = members.get(&id) else { continue };
        if id == me || node.is_blocked(&id) || !pays_with(m.proto_max) || !node.can_call(&id) {
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

/// What an offer must have left of its 15 minutes to be served: the
/// providers' time and some slack. A receipt written after the offer
/// lapsed counts nowhere, so the server would answer unpaid. A paid
/// request that takes longer passes its own margin to [`accept_offer`].
pub const SERVE_MARGIN_MS: u64 = 2 * 60 * 1000;

/// Whether an offer dated `hlc` can still be charged when served `now_ms`
/// by a request that takes up to `margin_ms`.
fn time_left(hlc: u64, now_ms: u64, margin_ms: u64) -> bool {
    now_ms + margin_ms <= crate::cluster::hlc::physical_ms(hlc) + super::OFFER_TTL_MS
}

/// Write a receipt of nothing for `peer`'s offer `offer_seq`: it frees
/// what the offer held at once, on every node.
pub(crate) async fn release(node: &Arc<Node>, peer: NodeId, offer_seq: u64) {
    let receipt = Record::CreditReceipt {
        payer: peer,
        offer_seq,
        charged_mc: 0,
        answered: vec![],
    };
    if let Err(e) = repl::append(node, &[receipt]).await {
        tracing::debug!(?e, "receipt not written");
    }
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
struct Serving(Arc<Node>, (NodeId, u64));

impl Drop for Serving {
    fn drop(&mut self) {
        self.0.serving_offers.lock().unwrap().remove(&self.1);
    }
}

/// An offer that passed every check of [`accept_offer`]. While it lives
/// the offer counts as being served: a second request naming it is
/// declined.
pub struct Accepted {
    pub offered: Mc,
    pub covered: Mc,
    pub book: Arc<super::Book>,
    _serving: Serving,
}

/// Why an offer was turned down. Every decline that [`accept_offer`] can
/// settle at once comes with a receipt of nothing.
#[derive(Debug, Clone, PartialEq)]
pub enum Declined {
    Why(String),
    /// The offer is less than the price, which it names.
    TooLow {
        why: String,
        price_mc: u32,
    },
    /// The offer is enough, but this node counts less of it.
    NotCovered(String),
}

/// Whether a request whose offer was looked at is demand for the good:
/// the offer was found (accepted, or declined only for its amount). A
/// missing offer, a bad request or any other decline never counts.
pub fn counts_as_demand<T>(accepted: &Result<T, Declined>) -> bool {
    !matches!(accepted, Err(Declined::Why(_)))
}

/// The checks `serve` does on an offer before answering: the asker is of
/// the market ([`pays_with`]), wait for the entry, is an offer, for me,
/// seal consistent, not already serving, standing, counts, open,
/// `margin_ms` left (see [`SERVE_MARGIN_MS`]), amount covers `price`.
pub async fn accept_offer(
    node: &Arc<Node>,
    peer: NodeId,
    offer_seq: u64,
    price: Mc,
    what: &str,
    margin_ms: u64,
) -> Result<Accepted, Declined> {
    let why = |w: String| Err(Declined::Why(w));
    if !node
        .members()
        .get(&peer)
        .is_some_and(|m| pays_with(m.proto_max))
    {
        release(node, peer, offer_seq).await;
        return why("your node predates the market (protocol 4): upgrade it to pay here".into());
    }
    let Some(entry) = wait_for(node, &peer, offer_seq).await else {
        return why(format!(
            "the offer (entry {offer_seq} of your node's log) did not arrive here"
        ));
    };
    match &entry.kind {
        Kind::Offer { to, .. } if *to == node.id() => {}
        Kind::Offer { .. } => return why("the offer is made to another node".into()),
        _ => return why(format!("entry {offer_seq} of your node's log is no offer")),
    }
    // Unchecked is not enough: the asker's next offer seals a range that
    // starts at this one, so one declined offer is the cost.
    match entry.seal {
        SealState::Consistent => {}
        SealState::Inconsistent => {
            release(node, peer, offer_seq).await;
            return why("the offer's seal does not match your node's log here".into());
        }
        _ => {
            release(node, peer, offer_seq).await;
            return why("the offer's seal could not be checked here yet; offer again".into());
        }
    }
    if !node
        .serving_offers
        .lock()
        .unwrap()
        .insert((peer, offer_seq))
    {
        return why("this offer is being served already".into());
    }
    let serving = Serving(node.clone(), (peer, offer_seq));
    let book = match super::book_fresh(node).await {
        Ok(b) => b,
        Err(e) => {
            release(node, peer, offer_seq).await;
            return why(format!("this node could not read its books: {e:#}"));
        }
    };
    let standing = book.standing(&peer);
    if standing.left_out() {
        release(node, peer, offer_seq).await;
        return why(format!(
            "your node's credits are not accepted here: {}",
            standing.reasons().join("; ")
        ));
    }
    let Some(offer) = book.ledger.offer(&peer, offer_seq) else {
        return why("the offer does not count here".into());
    };
    if offer.state != OfferState::Open {
        return why("the offer is used up, or older than 15 minutes".into());
    }
    if !time_left(offer.hlc, book.now_ms, margin_ms) {
        release(node, peer, offer_seq).await;
        return why("the offer lapses before it could be charged; offer again".into());
    }
    let (offered, covered) = (offer.offered, offer.covered);
    if price > offered {
        release(node, peer, offer_seq).await;
        return Err(Declined::TooLow {
            why: format!(
                "this costs {} credits here now; the offer is {}",
                show(price),
                show(offered)
            ),
            price_mc: price.min(u32::MAX as Mc) as u32,
        });
    }
    if covered < price {
        release(node, peer, offer_seq).await;
        return Err(Declined::NotCovered(format!(
            "not covered here: this node counts {} of the {} credits offered",
            show(covered),
            show(offered)
        )));
    }
    tracing::debug!(asker = %peer.short(), offer = offer_seq, what, "offer accepted");
    Ok(Accepted {
        offered,
        covered,
        book,
        _serving: serving,
    })
}

/// The asker's side of writing one offer: the balance (drawing from the
/// fleet), a sealed `CreditOffer` of `total_mc` to `server`, and a sync so
/// the server holds it before it is named. Returns the offer's sequence
/// number.
pub async fn make_offer(node: &Arc<Node>, server: NodeId, total_mc: Mc) -> Result<u64, String> {
    let me = node.id();
    // Checked before the offer is written: an offer nobody can be asked
    // to serve would stay held for 15 minutes.
    if server != me && !node.can_call(&server) {
        return Err("the node cannot be reached from here".into());
    }
    let mut book = super::book_fresh(node)
        .await
        .map_err(|e| format!("this node could not read its books: {e:#}"))?;
    if book.ledger.spendable_parts(&me, total_mc).is_none() {
        // Draw what is missing from the siblings, the richest first.
        let missing = total_mc.saturating_sub(book.balance(&me));
        if super::fleet::draw(node, missing).await
            && let Ok(b) = super::book_fresh(node).await
        {
            book = b;
        }
    }
    let Some(parts) = book.ledger.spendable_parts(&me, total_mc) else {
        let have = book.balance(&me);
        return Err(format!(
            "this node holds {} credits; this costs {} ({} missing)",
            show(have),
            show(total_mc),
            show(total_mc.saturating_sub(have))
        ));
    };
    let offer = repl::append_sealing(node, |seal| Record::CreditOffer {
        to: server,
        parts,
        seal,
        job: None,
    })
    .await
    .map_err(|e| format!("the offer could not be written: {e:#}"))?;
    // So the offer is there before the request. A server nobody can dial
    // pulls it with its own long-poll.
    if server != me
        && let Err(e) = node.sync_around_request(server).await
    {
        tracing::debug!(
            ?e,
            "sync before a paid request failed; the server waits for the offer"
        );
    }
    Ok(offer.seq)
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
    // Every offer leaves one line in the journal: declined here, or
    // served below.
    let decline = |names: &[String], why: String| {
        tracing::info!(asker = %peer.short(), offer = offer_seq,
            providers = %names.join(","), %why, "paid lookup declined");
        LookupResp {
            declined: names.iter().map(|n| (n.clone(), why.clone())).collect(),
            ..Default::default()
        }
    };
    let table = node.price_table();
    let price_of =
        |name: &str| -> Mc { table.price_of(name).unwrap_or(price::PRICE_FLOOR as u32) as Mc };
    let shares = node.lookup_shares();
    let provider = |name: &str| providers.iter().find(|p| p.name() == name);
    // Providers whose on-demand share is spent are declined one by one;
    // the rest is served.
    let (mut asking, mut declined) = (vec![], vec![]);
    let all = served.clone();
    for name in served {
        let spent = match (shares, provider(&name)) {
            (Some(s), Some(p)) => s.spent(p.as_ref()).await.unwrap_or(true),
            _ => false,
        };
        if spent {
            declined.push((name, SHARE_SPENT.to_string()));
        } else {
            asking.push(name);
        }
    }
    let total: Mc = asking.iter().map(|n| price_of(n)).sum();
    let accepted = accept_offer(node, peer, offer_seq, total, "lookup", SERVE_MARGIN_MS).await;
    if counts_as_demand(&accepted) {
        for name in &all {
            node.market.note(name, 1);
        }
    }
    let acc = match accepted {
        Ok(a) => a,
        Err(Declined::Why(why)) => {
            // Not about the amount: every provider asked for hears it.
            return decline(&all, why);
        }
        Err(Declined::TooLow { why, price_mc }) => {
            let mut resp = decline(&asking, why);
            resp.price_mc = Some(price_mc);
            resp.declined.append(&mut declined);
            return resp;
        }
        Err(Declined::NotCovered(why)) => {
            let mut resp = decline(&asking, why);
            resp.declined.append(&mut declined);
            return resp;
        }
    };
    let covered = acc.covered;
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
            declined.push((name, SHARE_SPENT.to_string()));
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
    let not_served: Vec<String> = declined.iter().map(|(n, _)| n.clone()).collect();
    tracing::info!(asker = %peer.short(), offer = offer_seq,
        providers = %answered.join(","), declined = %not_served.join(","),
        charged = %show(charged), "paid lookup served");
    // What was paid for is kept for everyone when the cluster has
    // recorded the address, exactly as the automatic enrichment would
    // write it; for an address nobody recorded nothing is written.
    keep_if_recorded(node, ip, &mut resp).await;
    resp.declined.append(&mut declined);
    resp
}

/// Keep `resp`'s answers in the dataset when the cluster recorded `ip`.
async fn keep_if_recorded(node: &Arc<Node>, ip: IpAddr, resp: &mut LookupResp) {
    if resp.findings.is_empty() || !recorded(&node.store.pool, &ip).await {
        return;
    }
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
            tracing::warn!(provider = %f.provider, ?e, "lookup result not kept");
            all = false;
        }
    }
    resp.kept = all;
}

/// The serving side of a request without an offer: what this node prices
/// at zero now is answered free (it still takes the on-demand share and
/// counts as demand); the rest is declined naming its price, so the asker
/// may offer it.
pub async fn serve_free(
    node: &Arc<Node>,
    providers: &Providers,
    peer: NodeId,
    ip: IpAddr,
    served: Vec<String>,
) -> LookupResp {
    let table = node.price_table();
    let shares = node.lookup_shares();
    let provider = |name: &str| providers.iter().find(|p| p.name() == name);
    let (mut free, mut declined, mut priced) = (vec![], vec![], 0 as Mc);
    for name in served {
        node.market.note(&name, 1);
        let price = table.price_of(&name).unwrap_or(0);
        if price > 0 {
            priced += price as Mc;
            declined.push((
                name,
                format!(
                    "this costs {} credits here now; the request carries no offer",
                    show(price as Mc)
                ),
            ));
            continue;
        }
        let taken = match (shares, provider(&name)) {
            (Some(s), Some(p)) => s.take(p.as_ref()).await.unwrap_or(false),
            _ => true,
        };
        match taken {
            true => free.push(name),
            false => declined.push((name, SHARE_SPENT.to_string())),
        }
    }
    let mut resp = if free.is_empty() {
        LookupResp::default()
    } else {
        crate::intel::lookup::local(providers, &ip, &free).await
    };
    if priced > 0 {
        resp.price_mc = Some(priced.min(u32::MAX as Mc) as u32);
    }
    tracing::info!(asker = %peer.short(), providers = %free.join(","), "free lookup served");
    keep_if_recorded(node, ip, &mut resp).await;
    resp.declined.append(&mut declined);
    resp
}

/// Offer `total_mc` to `server` (another node) for `providers` and ask it
/// once. The answer carries what it charged; a refusal says why.
pub async fn offer_and_ask(
    node: &Arc<Node>,
    ip: IpAddr,
    server: NodeId,
    providers: &[String],
    total_mc: Mc,
) -> LookupResp {
    let decline = |why: String| LookupResp {
        declined: providers.iter().map(|p| (p.clone(), why.clone())).collect(),
        ..Default::default()
    };
    // A zero price is asked without an offer.
    let offer_seq = match total_mc {
        0 => None,
        mc => match make_offer(node, server, mc).await {
            Ok(seq) => Some(seq),
            Err(why) => return decline(why),
        },
    };
    let req = LookupReq {
        ip: ip.to_string(),
        providers: providers.to_vec(),
        offer_seq,
    };
    let mut resp = {
        let call = node.call_any::<LookupReq, LookupResp>(
            server,
            "/rpc/v1/lookup",
            &req,
            crate::intel::lookup::RPC_TIMEOUT + SERVE_WAIT,
        );
        let r = match call.await {
            Ok(r) => r,
            Err(e) if e.downcast_ref::<crate::cluster::msg::NoAnswer>().is_some() => {
                return decline("did not answer in time".into());
            }
            Err(e) => return decline(format!("could not be asked: {e:#}")),
        };
        // A declined offer comes with a receipt of nothing: fetch it, so
        // what the offer held is free for the next one. A server nobody can
        // dial pushes its receipt with its own sync.
        if offer_seq.is_some()
            && r.findings.is_empty()
            && r.charged_mc == 0
            && let Err(e) = node.sync_around_request(server).await
        {
            tracing::debug!(?e, "sync after a declined offer failed");
        }
        r
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
    if server == node.id() {
        // What this node answers itself is free: no offer.
        return crate::intel::lookup::local(own, &ip, &names).await;
    }
    let first = offer_and_ask(node, ip, server, &names, total).await;
    match retry_price(total, first.price_mc, first.findings.is_empty()) {
        // Its price moved since its heartbeat: offer that, once.
        Some(p) => offer_and_ask(node, ip, server, &names, p).await,
        None => first,
    }
}

/// What to offer a server that turned down `offered` naming `named`: its
/// price when that is higher, but at most [`RETRY_AT_MOST`] times the
/// offer (one mc for a request without an offer). None: do not offer again (the next server is asked instead).
pub(crate) fn retry_price(offered: Mc, named: Option<u32>, nothing_answered: bool) -> Option<Mc> {
    let p = named? as Mc;
    let bound = offered.max(1).saturating_mul(RETRY_AT_MOST);
    (nothing_answered && p > offered && p <= bound).then_some(p)
}

/// The next server to ask for a provider: the cheapest in `list` not yet
/// `seen`; another node only when the provider is `picked` to be paid for.
fn next_server<'a>(
    list: &'a [Quote],
    seen: &HashSet<NodeId>,
    me: NodeId,
    picked: bool,
) -> Option<&'a Quote> {
    list.iter()
        .find(|q| !seen.contains(&q.server))
        .filter(|q| q.server == me || picked)
}

/// The asking side: for each provider in `wanted` that somebody serves,
/// ask the cheapest server (and the next cheapest when it declines), and
/// pay what each asks. Servers other than this node are asked only for
/// the providers in `paid`. One answer per server asked.
pub async fn ask(
    node: &Arc<Node>,
    own: &Providers,
    ip: IpAddr,
    wanted: &[String],
    paid: &[String],
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
                .and_then(|list| next_server(list, seen, me, paid.contains(p)))
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

    #[test]
    fn only_a_found_offer_counts_as_demand() {
        assert!(counts_as_demand(&Ok::<(), _>(())));
        assert!(counts_as_demand(&Err::<(), _>(Declined::TooLow {
            why: "x".into(),
            price_mc: 5
        })));
        assert!(counts_as_demand(&Err::<(), _>(Declined::NotCovered(
            "x".into()
        ))));
        assert!(!counts_as_demand(&Err::<(), _>(Declined::Why(
            "no such offer".into()
        ))));
    }

    #[test]
    fn only_market_nodes_are_paid() {
        assert_eq!(crate::cluster::rpc::proto::MARKET_PROTO, 4);
        const {
            assert!(
                crate::cluster::rpc::proto::PROTO_VERSION
                    >= crate::cluster::rpc::proto::MARKET_PROTO
            )
        };
        assert_eq!(crate::cluster::rpc::proto::SCAN_PRICE_PROTO, 5);
        assert_eq!(crate::cluster::rpc::proto::ROUTED_PROTO, 6);
        const {
            assert!(
                crate::cluster::rpc::proto::PROTO_VERSION
                    >= crate::cluster::rpc::proto::ROUTED_PROTO
            )
        };
        assert!(!pays_with(3));
        assert!(pays_with(4));
    }

    #[test]
    fn an_offer_is_served_only_with_time_left_to_be_charged() {
        let min = 60 * 1000;
        let now = 1_000 * min;
        let made = |ago: u64| (now - ago) << 16;
        let m = SERVE_MARGIN_MS;
        assert!(time_left(made(0), now, m));
        assert!(time_left(made(10 * min), now, m));
        // Its receipt would be written after the offer lapsed: ignored
        // everywhere, the server unpaid.
        assert!(!time_left(made(14 * min), now, m));
        assert!(!time_left(made(20 * min), now, m));
        // A longer request needs more of the offer left.
        assert!(time_left(made(12 * min), now, m));
        assert!(!time_left(made(12 * min), now, 3 * min + 1));
    }

    #[test]
    fn a_named_price_is_offered_again_only_within_bounds() {
        assert_eq!(retry_price(500, Some(800), true), Some(800));
        assert_eq!(
            retry_price(500, Some(1000), true),
            Some(1000),
            "twice is the most"
        );
        assert_eq!(
            retry_price(500, Some(1001), true),
            None,
            "beyond: ask the next server"
        );
        assert_eq!(
            retry_price(1, Some(10_000_000), true),
            None,
            "a balance named as price"
        );
        assert_eq!(
            retry_price(500, Some(400), true),
            None,
            "lower: it declined for another reason"
        );
        assert_eq!(
            retry_price(500, Some(800), false),
            None,
            "something was answered"
        );
        assert_eq!(retry_price(500, None, true), None);
    }

    #[test]
    fn a_zero_offer_is_retried_at_a_small_named_price_only() {
        assert_eq!(retry_price(0, Some(1), true), Some(1));
        assert_eq!(retry_price(0, Some(2), true), Some(2), "twice of one mc");
        assert_eq!(retry_price(0, Some(3), true), None);
        assert_eq!(retry_price(0, None, true), None);
        assert_eq!(
            retry_price(0, Some(1), false),
            None,
            "something was answered"
        );
    }

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

    #[test]
    fn a_provider_not_picked_is_asked_only_at_this_node() {
        let me = NodeId([1; 32]);
        let list = vec![q("rdap", 1, 0), q("rdap", 2, 300)];
        let none = HashSet::new();
        let tried: HashSet<NodeId> = [me].into();
        // Not picked: this node, and no fallback when it gave no answer.
        assert_eq!(
            next_server(&list, &none, me, false).map(|q| q.server),
            Some(me)
        );
        assert_eq!(next_server(&list, &tried, me, false), None);
        // Picked: the member is the fallback.
        assert_eq!(
            next_server(&list, &none, me, true).map(|q| q.server),
            Some(me)
        );
        assert_eq!(
            next_server(&list, &tried, me, true).map(|q| q.server),
            Some(NodeId([2; 32]))
        );
    }
}
