//! Lookup credits: earned by completed counter-scans, spent on lookups.
//! Every node computes every balance for itself, from its own copy of the
//! log; see docs/superpowers/specs/2026-10-06-lookup-credits-design.md.
pub mod audit;
pub mod earn;
pub mod entries;
pub mod fleet;
pub mod gates;
pub mod ledger;
pub mod pay;
pub mod price;
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
use std::collections::HashSet;
use std::sync::Arc;

/// Everything this node knows about credits at one moment: who earns
/// here, what every judged scan paid, and where every credit is.
pub struct Book {
    pub ledger: ledger::Ledger,
    pub paid: Vec<earn::Paid>,
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

    /// What all members earned a day over the last 168 hours (the `E` of
    /// the price formula).
    pub fn earned_per_day(&self) -> Mc {
        let from = self.now_ms.saturating_sub(7 * DAY_MS);
        let week: Mc = self
            .paid
            .iter()
            .filter(|p| crate::cluster::hlc::physical_ms(p.scan.hlc) >= from)
            .map(|p| p.scanner_mc + p.trap_mc)
            .sum();
        week / 7
    }
}

/// The HLC from which scans and payments are read at `now_ms`: the 7 days
/// lots live, and one more for the 24-hour window of each IP.
pub fn window_start(now_ms: u64) -> u64 {
    now_ms.saturating_sub((LOT_DAYS as u64 + 1) * DAY_MS) << 16
}

/// Compute this node's book from what it holds now.
pub async fn compute(node: &Node) -> anyhow::Result<Book> {
    let now_ms = crate::cluster::hlc::wall_ms();
    let since = window_start(now_ms);
    let standings = gates::standings(node).await?;
    let judged = earn::judged_since(&node.store.pool, since).await?;
    let paid = earn::pay(&judged, &gates::to_gates(&standings));
    let entries = entries::since(&node.store.pool, since).await?;
    let left_out: HashSet<NodeId> = standings
        .iter()
        .filter(|(_, s)| s.left_out())
        .map(|(id, _)| *id)
        .collect();
    let ledger = ledger::run(&earn::earned(&paid), &entries, &left_out, now_ms);
    Ok(Book {
        ledger,
        paid,
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

/// How often the loop judges scans.
const TICK: std::time::Duration = std::time::Duration::from_secs(60);

/// Judge scans as they become due, say in the journal when a member's
/// standing changes, and drop what is older than the ledger reads.
pub async fn run(
    node: Arc<Node>,
    cfg: crate::config::Config,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let origins = crate::scan::guard::Origins::from_config(&cfg.scan.safety, Some(node.id()));
    let mut known: gates::Standings = Default::default();
    let mut ticks = 0u64;
    loop {
        let judge = earn::Judge {
            pool: &node.store.pool,
            origins: &origins,
            classifier: crate::classify::Classifier::builtin(),
        };
        match earn::judge(&judge, earn::JUDGE_AFTER_SECS).await {
            Ok(0) => {}
            Ok(n) => tracing::debug!(scans = n, "credits: scans judged"),
            Err(e) => tracing::warn!(?e, "credits: judging scans failed"),
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
        if ticks % 60 == 0 {
            let before = window_start(crate::cluster::hlc::wall_ms());
            let pool = &node.store.pool;
            if let Err(e) = async {
                entries::prune(pool, before).await?;
                earn::prune(pool, before).await
            }
            .await
            {
                tracing::debug!(?e, "credits: pruning failed");
            }
        }
        // At the start (once the first heartbeats are in) and every hour.
        if ticks % 60 == 1 {
            if let Err(e) = price::refresh(&node).await {
                tracing::debug!(?e, "credits: prices not computed");
            }
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
