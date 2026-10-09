//! Lookup credits: a fixed pool a day for the verified listeners, earned
//! by selling goods, spent on goods. Every node computes every balance for
//! itself, from its own copy of the log; see "Credits" in docs/cluster.md.
pub mod audit;
pub mod cli;
pub mod entries;
pub mod fleet;
pub mod gates;
pub mod history;
pub mod jobs;
pub mod ledger;
pub mod pay;
pub mod pool;
pub mod price;
pub mod reach;
pub mod share;

/// Millicredits: 1 credit = 1000 mc. Sums are `u64`, amounts on the wire
/// `u32`.
pub type Mc = u64;
pub const CREDIT: Mc = 1000;

pub const DAY_MS: u64 = 86_400_000;
/// A credit can be used on the day it was earned and the 6 after.
pub const LOT_DAYS: u32 = 7;
/// An offer without a receipt lapses after this long.
pub const OFFER_TTL_MS: u64 = 15 * 60 * 1000;

/// A scan offer (`credits::jobs`) lapses after the longest scan and the
/// margin a server keeps for writing its receipt.
pub const JOB_OFFER_TTL_MS: u64 = crate::scan::pace::MAX_RUN_SECS * 1000 + pay::SERVE_MARGIN_MS;

/// The UTC day an entry belongs to, from its HLC.
pub fn day_of(hlc: u64) -> u32 {
    (crate::cluster::hlc::physical_ms(hlc) / DAY_MS) as u32
}

/// An amount in credits with two decimals ("0.25").
pub fn show(mc: Mc) -> String {
    let cents = (mc + 5) / 10;
    format!("{}.{:02}", cents / 100, cents % 100)
}

/// An amount typed by an operator ("1", "0.25"): more than nothing, at
/// most three decimals.
pub fn parse_amount(s: &str) -> Option<Mc> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty()
        || frac.len() > 3
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole: Mc = whole.parse().ok()?;
    let frac: Mc = format!("{frac:0<3}").parse().ok()?;
    let mc = whole.checked_mul(CREDIT)?.checked_add(frac)?;
    (mc > 0).then_some(mc)
}

use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

/// Everything this node knows about credits at one moment: who was up
/// when, whose pool shares it credits, and where every credit is.
pub struct Book {
    pub ledger: ledger::Ledger,
    /// The pool shares this node credits (members that earn here).
    pub pool: Vec<ledger::Earned>,
    /// The verified listeners of each day the window reads.
    pub listeners: BTreeMap<u32, BTreeSet<NodeId>>,
    pub uptime: reach::Uptime,
    /// The members that do not earn in full here.
    pub standings: gates::Standings,
    pub now_ms: u64,
}

impl Book {
    pub fn balance(&self, node: &NodeId) -> Mc {
        self.ledger.balance(node)
    }

    pub fn standing(&self, node: &NodeId) -> gates::Standing {
        self.standings.get(node).cloned().unwrap_or_default()
    }

    /// What the pool credited here a day over the last 7 days.
    pub fn pool_per_day(&self) -> Mc {
        let from = self.now_ms.saturating_sub(7 * DAY_MS);
        let week: Mc = self
            .pool
            .iter()
            .filter(|e| crate::cluster::hlc::physical_ms(e.hlc) >= from)
            .map(|e| e.mc)
            .sum();
        week / 7
    }

    /// `node`'s up hours on `day`, as reported.
    pub fn up_hours(&self, node: &NodeId, day: u32) -> u32 {
        self.uptime.get(&(*node, day)).copied().unwrap_or(0)
    }
}

/// The HLC from which payments and reports are read at `now_ms`: the 7
/// days lots live, and one more.
pub fn window_start(now_ms: u64) -> u64 {
    now_ms.saturating_sub((LOT_DAYS as u64 + 1) * DAY_MS) << 16
}

/// Compute this node's book from what it holds now.
pub async fn compute(node: &Node) -> anyhow::Result<Book> {
    let now_ms = crate::cluster::hlc::wall_ms();
    let since = window_start(now_ms);
    let (first, today) = (day_of(since), (now_ms / DAY_MS) as u32);
    let standings = gates::standings(node).await?;
    let set = |f: &dyn Fn(&gates::Standing) -> bool| -> HashSet<NodeId> {
        standings
            .iter()
            .filter(|(_, s)| f(s))
            .map(|(id, _)| *id)
            .collect()
    };
    let gates = ledger::Gates {
        left_out: set(&|s| s.left_out()),
        no_sales: set(&|s| !s.earns()),
        no_scan_sales: set(&|s| !s.earns_as_scanner()),
    };
    let members: Vec<crate::cluster::members::MemberRow> =
        crate::cluster::members::all(&node.store)
            .await?
            .into_iter()
            .filter(|m| m.active)
            .collect();
    let ids: Vec<NodeId> = members.iter().map(|m| m.id).collect();
    let reports = reach::since(&node.store.pool, first * 24).await?;
    let uptime = reach::uptime(&reports, &ids, &reach::ignored(&members, &gates.left_out));
    let listeners: BTreeMap<u32, BTreeSet<NodeId>> = (first..=today)
        .map(|d| (d, reach::verified(&members, &uptime, d)))
        .collect();
    // A member that does not earn here is not credited here, and its
    // share is not given to anyone else.
    let pool: Vec<ledger::Earned> = pool::credited(&listeners, now_ms)
        .into_iter()
        .filter(|e| !gates.no_sales.contains(&e.node))
        .collect();
    let entries = entries::since(&node.store.pool, since).await?;
    let ledger = ledger::run(&pool, &entries, &gates, now_ms);
    Ok(Book {
        ledger,
        pool,
        listeners,
        uptime,
        standings,
        now_ms,
    })
}

/// How old a book the pages and the heartbeat may use.
const BOOK_TTL: std::time::Duration = std::time::Duration::from_secs(10);

/// This node's book, at most [`BOOK_TTL`] old.
pub async fn book(node: &Node) -> anyhow::Result<Arc<Book>> {
    if let Some((at, b)) = node.credits_book.lock().unwrap().as_ref()
        && at.elapsed() < BOOK_TTL
    {
        return Ok(b.clone());
    }
    book_fresh(node).await
}

/// This node's book, computed now (before money moves: an offer is made,
/// or served).
pub async fn book_fresh(node: &Node) -> anyhow::Result<Arc<Book>> {
    let b = Arc::new(compute(node).await?);
    *node.credits_book.lock().unwrap() = Some((std::time::Instant::now(), b.clone()));
    Ok(b)
}

/// How often the loop runs.
const TICK: std::time::Duration = std::time::Duration::from_secs(60);
/// Ticks between price refreshes: 10 minutes. Each step is scaled by the
/// time since the last one, so prices move as fast per hour as with an
/// hourly refresh, in smaller steps.
const PRICE_TICKS: u64 = 10;

/// Report the hours that ended, settle audits, say in the journal when a
/// member's standing changes, refresh prices and drop what is older than
/// the ledger reads.
pub async fn run(node: Arc<Node>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut known: gates::Standings = Default::default();
    let mut ticks = 0u64;
    loop {
        // The hours that ended since the last tick, once each.
        if let Err(e) = reach::report_due(&node, crate::cluster::hlc::wall_ms()).await {
            tracing::debug!(?e, "credits: reach report not written");
        }
        if let Err(e) = audit::settle(&node.store.pool).await {
            tracing::debug!(?e, "credits: comparing audits failed");
        }
        match gates::standings(&node).await {
            Ok(now) => {
                let names = node.members();
                let name =
                    |id: &NodeId| names.get(id).map_or_else(|| id.short(), |m| m.name.clone());
                for (id, s) in &now {
                    if known.get(id) != Some(s) {
                        tracing::info!(member = %name(id), reasons = %s.reasons().join("; "),
                            "credits: member does not earn in full here");
                    }
                }
                for id in known.keys().filter(|id| !now.contains_key(*id)) {
                    tracing::info!(member = %name(id), "credits: member earns here again");
                }
                known = now;
            }
            Err(e) => tracing::debug!(?e, "credits: standings not evaluated"),
        }
        if ticks.is_multiple_of(60) {
            let before = window_start(crate::cluster::hlc::wall_ms());
            let pool = &node.store.pool;
            if let Err(e) = async {
                entries::prune(pool, before).await?;
                let hours = (LOT_DAYS + 1) * 24;
                reach::prune(
                    pool,
                    reach::hour_of(crate::cluster::hlc::wall_ms()).saturating_sub(hours),
                )
                .await
            }
            .await
            {
                tracing::debug!(?e, "credits: pruning failed");
            }
        }
        // The scanner weights' hourly snapshot, taken as soon as it is due
        // (five minutes after the hour) rather than on first use, so every
        // node takes it at about the same time.
        if let Err(e) = node.weights.get(&node.store.pool).await {
            tracing::debug!(?e, "credits: scanner weights not measured");
        }
        // Every tick (one count and the cached book), for the heartbeat.
        if let Err(e) = jobs::announce_budget(&node).await {
            tracing::debug!(?e, "credits: scan budget not computed");
        }
        // At the start (once the first heartbeats are in) and every
        // PRICE_TICKS.
        if ticks % PRICE_TICKS == 1
            && let Err(e) = price::refresh(&node).await
        {
            tracing::debug!(?e, "credits: prices not computed");
        }
        ticks += 1;
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = shutdown.changed() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prices_refresh_every_ten_minutes() {
        assert_eq!(
            TICK * PRICE_TICKS as u32,
            std::time::Duration::from_secs(600)
        );
    }

    #[test]
    fn days_and_amounts() {
        let hlc = |ms: u64| ms << 16;
        assert_eq!(day_of(hlc(0)), 0);
        assert_eq!(day_of(hlc(DAY_MS - 1)), 0);
        assert_eq!(day_of(hlc(DAY_MS)), 1);
        assert_eq!(day_of(hlc(20_000 * DAY_MS + 5) | 7), 20_000);
        assert_eq!(show(0), "0.00");
        assert_eq!(show(250), "0.25");
        assert_eq!(show(1000), "1.00");
        assert_eq!(show(12_345), "12.35", "rounded to cents");
        assert_eq!(show(4), "0.00");
        assert_eq!(parse_amount("1"), Some(1000));
        assert_eq!(parse_amount("0.25"), Some(250));
        assert_eq!(parse_amount(" 12.5 "), Some(12_500));
        assert_eq!(parse_amount("0.001"), Some(1));
        for bad in ["", "-1", "1.2345", "abc", "1e3", "0", "0.0"] {
            assert_eq!(parse_amount(bad), None, "{bad}");
        }
    }
}
