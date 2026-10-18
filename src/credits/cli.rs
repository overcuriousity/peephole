//! `peephole credits …`: this node's credits from the shell. Like
//! `peephole cluster`, it works on the node's database, also while the
//! daemon runs; every figure is this node's own count.
use super::{Book, Mc, date_of, day_of, show, when};
use crate::cluster::cli::{open, resolve};
use crate::cluster::identity::NodeId;
use crate::cluster::members;
use crate::credits::ledger::OfferState;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};

pub const USAGE: &str = "usage: peephole credits [CONFIG]                     balance, by day
       peephole credits log [--days N] [CONFIG]     pool shares, spent, sold, sent, received
       peephole credits members [CONFIG]            every member's balance and standing
       peephole credits uptime [CONFIG]             each member's reported hours up, 7 days
       peephole credits market [CONFIG]             per good: own ask and bid, sold, bought, refused over bid;
                                                    per member: RDAP rows checked, disputed
       peephole credits send NODE AMOUNT [CONFIG]   NODE: name, fingerprint or key";

fn config_path(arg: &str) -> bool {
    arg.contains('/') || arg.ends_with(".toml") || std::path::Path::new(arg).is_file()
}

pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let mut days = 7u64;
    let mut pos: Vec<&str> = vec![];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(());
            }
            "--days" => {
                days = it
                    .next()
                    .and_then(|d| d.parse().ok())
                    .filter(|d| (1..=7).contains(d))
                    .context("--days takes a number from 1 to 7")?;
            }
            f if f.starts_with("--") => bail!("unknown flag {f}\n\n{USAGE}"),
            p => pos.push(p),
        }
    }
    // A trailing path is the config file.
    let config = match pos.last() {
        Some(p) if config_path(p) => pos.pop().unwrap_or(default_config),
        _ => default_config,
    };
    let (_, node) = open(config).await?;
    let me = node.id();
    let names = node.members();
    let name = |id: &crate::cluster::identity::NodeId| {
        names.get(id).map_or_else(|| id.short(), |m| m.name.clone())
    };
    match pos.as_slice() {
        [] => {
            let book: Book = super::compute(&node).await?;
            println!(
                "balance {} credits ({} set aside in open lookups)",
                show(book.balance(&me)),
                show(book.ledger.held(&me))
            );
            for (day, mc) in book.ledger.by_day(&me) {
                let left = (day + super::LOT_DAYS - 1).saturating_sub(book.ledger.today);
                println!(
                    "  {}  {:>10}  expires in {left} day(s)",
                    date_of(day),
                    show(mc)
                );
            }
        }
        ["uptime"] => {
            let book = super::compute(&node).await?;
            let today = (book.now_ms / super::DAY_MS) as u32;
            let days: Vec<u32> = (today.saturating_sub(6)..=today).collect();
            let all: Vec<members::MemberRow> = members::all(&node.store)
                .await?
                .into_iter()
                .filter(|m| m.active)
                .collect();
            let names: Vec<_> = all.iter().map(|m| (m.id, m.name.clone())).collect();
            for line in super::reach::uptime_lines(&names, &book.uptime, &book.listeners, &days) {
                println!("{line}");
            }
            println!(
                "hours up a day (UTC); * a verified listener: advertised, listener role, protocol 7, up 12 hours or more"
            );
        }
        ["log"] => {
            let book = super::compute(&node).await?;
            let from = book.now_ms.saturating_sub(days * super::DAY_MS);
            let lines = log_lines(&book, &me, from, name);
            if lines.is_empty() {
                println!("nothing earned, spent or sent in the last {days} day(s)");
            }
            for (hlc, line) in lines {
                println!("{}  {line}", when(hlc));
            }
        }
        ["members"] => {
            let book = super::compute(&node).await?;
            for m in members::all(&node.store).await?.iter().filter(|m| m.active) {
                let reasons = book.standing(&m.id).reasons();
                println!(
                    "{:<24} {:>10}  {}",
                    m.name,
                    show(book.balance(&m.id)),
                    if reasons.is_empty() {
                        "earns here".to_string()
                    } else {
                        format!("not earning here: {}", reasons.join("; "))
                    }
                );
            }
        }
        ["market"] => {
            let book = super::compute(&node).await?;
            for line in market_lines(&super::price::market(&node, &book).await?) {
                println!("{line}");
            }
            let mut checks: Vec<(String, i64, i64)> =
                crate::intel::rdap_check::counts(&node.store.pool)
                    .await?
                    .into_iter()
                    .filter_map(|(origin, (c, d))| {
                        let id = crate::cluster::identity::NodeId::from_slice(&origin).ok()?;
                        Some((name(&id), c, d))
                    })
                    .collect();
            checks.sort();
            for line in rdap_lines(&checks) {
                println!("{line}");
            }
        }
        ["send", who, amount] => {
            let mc = super::parse_amount(amount)
                .with_context(|| format!("`{amount}` is not an amount (like 1 or 0.25)"))?;
            let to = resolve(&members::all(&node.store).await?, who)?;
            let sent = super::fleet::send(&node, to, mc).await?;
            println!("sent {} credits to {}", show(sent), name(&to));
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}

/// `peephole credits log` since `from` (ms), oldest first: pool shares,
/// offers `me` made, transfers, and its sales per UTC day and good (the
/// goods a charged offer's receipt names) at the day's last sale.
pub fn log_lines(
    book: &Book,
    me: &NodeId,
    from: u64,
    name: impl Fn(&NodeId) -> String,
) -> Vec<(u64, String)> {
    let recent = |hlc: u64| crate::cluster::hlc::physical_ms(hlc) >= from;
    let mut lines: Vec<(u64, String)> = vec![];
    for e in book.pool.iter().filter(|e| e.node == *me && recent(e.hlc)) {
        lines.push((
            e.hlc,
            format!("pool     {:>8}  this node's share of the day", show(e.mc)),
        ));
    }
    for o in book
        .ledger
        .offers
        .iter()
        .filter(|o| o.payer == *me && recent(o.hlc))
    {
        let what = match &o.state {
            OfferState::Open => "open".to_string(),
            OfferState::Lapsed => "lapsed, nothing charged".to_string(),
            OfferState::Charged { charged, .. } => {
                format!("charged {} for {}", show(*charged), o.answered.join(", "))
            }
        };
        lines.push((
            o.hlc,
            format!(
                "offered  {:>8}  to {}: {what}",
                show(o.offered),
                name(&o.to)
            ),
        ));
    }
    // Per (UTC day, good).
    #[derive(Default)]
    struct Sold {
        last: u64,
        total: Mc,
        n: u64,
        payers: BTreeSet<NodeId>,
    }
    let mut sold: BTreeMap<(u32, String), Sold> = BTreeMap::new();
    for o in book
        .ledger
        .offers
        .iter()
        .filter(|o| o.to == *me && o.payer != *me && recent(o.hlc))
    {
        let OfferState::Charged { charged } = o.state else {
            continue;
        };
        if charged == 0 {
            continue;
        }
        let s = sold
            .entry((day_of(o.hlc), o.answered.join(", ")))
            .or_default();
        s.last = s.last.max(o.hlc);
        s.total += charged;
        s.n += 1;
        s.payers.insert(o.payer);
    }
    for ((_, good), s) in sold {
        lines.push((
            s.last,
            format!(
                "sold     {:>8}  {} × {good} to {} member(s)",
                show(s.total),
                s.n,
                s.payers.len()
            ),
        ));
    }
    for t in book.ledger.transfers.iter().filter(|t| recent(t.hlc)) {
        if t.from == *me {
            lines.push((
                t.hlc,
                format!("sent     {:>8}  to {}", show(t.moved), name(&t.to)),
            ));
        } else if t.to == *me {
            lines.push((
                t.hlc,
                format!("received {:>8}  from {}", show(t.moved), name(&t.from)),
            ));
        }
    }
    lines.sort_by_key(|(hlc, _)| *hlc);
    lines
}

/// `peephole credits market`, after the goods: per member, its RDAP rows
/// this node spot-checked and the disputes among them (`intel::rdap_check`).
/// A dispute blocks nobody: `peephole cluster block` stays the operator's.
pub fn rdap_lines(rows: &[(String, i64, i64)]) -> Vec<String> {
    let mut out = vec![format!(
        "{:<24} {:>12} {:>13}",
        "member", "rdap_checked", "rdap_disputes"
    )];
    for (name, checked, disputes) in rows {
        out.push(format!("{name:<24} {checked:>12} {disputes:>13}"));
    }
    if rows.is_empty() {
        out.push("no RDAP rows of other members checked yet".into());
    }
    out
}

/// `peephole credits market`: one row per traded good (the free goods,
/// `price::FREE_GOODS`, are no market and not listed). Sold and bought count the book's window
/// (`LOT_DAYS`); ask and bid are as of the last hourly price refresh.
pub fn market_lines(rows: &[super::price::MarketRow]) -> Vec<String> {
    let mut out = vec![format!(
        "{:<18} {:>10} {:>10} {:>6} {:>6} {:>8}",
        "good", "ask", "bid", "sold", "bought", "over bid"
    )];
    for r in rows {
        out.push(format!(
            "{:<18} {:>10} {:>10} {:>6} {:>6} {:>8}",
            r.good,
            r.ask_mc.map_or_else(|| "-".to_string(), show),
            show(r.bid_mc),
            r.tally.sold,
            r.tally.bought,
            r.tally.over_bid
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn market_lists_each_members_rdap_checks_and_disputes() {
        let lines = rdap_lines(&[("node-a".into(), 12, 0), ("node-b".into(), 7, 2)]);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("rdap_checked") && lines[0].contains("rdap_disputes"));
        let cols = |l: &str| l.split_whitespace().map(str::to_string).collect::<Vec<_>>();
        assert_eq!(cols(&lines[1]), ["node-a", "12", "0"]);
        assert_eq!(cols(&lines[2]), ["node-b", "7", "2"]);
        assert_eq!(rdap_lines(&[]).len(), 2, "says none were checked");
    }

    fn offer(
        payer: u8,
        to: u8,
        hlc: u64,
        charged: Mc,
        good: &str,
    ) -> crate::credits::ledger::Offer {
        crate::credits::ledger::Offer {
            payer: NodeId([payer; 32]),
            seq: hlc,
            hlc,
            to: NodeId([to; 32]),
            offered: charged,
            covered: charged,
            held: vec![],
            state: OfferState::Charged { charged },
            answered: vec![good.into()],
            job: None,
            audit: None,
        }
    }

    #[test]
    fn log_sums_sales_per_day_and_good() {
        const DAY: u64 = 20_000;
        let at = |day: u64, min: u64| (day * super::super::DAY_MS + min * 60_000) << 16;
        let ledger = crate::credits::ledger::Ledger {
            offers: vec![
                offer(2, 1, at(DAY, 10), 100, "rdns"),
                offer(3, 1, at(DAY, 20), 100, "rdns"),
                offer(2, 1, at(DAY, 30), 150, "rdns"),
                offer(2, 1, at(DAY + 1, 5), 4000, "scan"),
                offer(1, 4, at(DAY + 1, 6), 300, "abuseipdb"),
                offer(1, 1, at(DAY + 1, 7), 500, "scan"),
            ],
            ..Default::default()
        };
        let book = Book {
            ledger,
            pool: vec![],
            listeners: Default::default(),
            uptime: Default::default(),
            standings: Default::default(),
            now_ms: (DAY + 2) * super::super::DAY_MS,
            own_head: 0,
        };
        let lines = log_lines(&book, &NodeId([1; 32]), 0, |id| id.short());
        let text: Vec<&str> = lines.iter().map(|(_, l)| l.as_str()).collect();
        let sold: Vec<_> = text.iter().filter(|l| l.starts_with("sold")).collect();
        assert_eq!(sold.len(), 2, "{text:?}");
        assert_eq!(*sold[0], "sold         0.35  3 × rdns to 2 member(s)");
        assert_eq!(*sold[1], "sold         4.00  1 × scan to 1 member(s)");
        assert_eq!(lines[0].0, at(DAY, 30), "at the day's last sale");
        assert!(
            text.iter()
                .any(|l| l.starts_with("offered") && l.contains("abuseipdb"))
        );
        assert!(
            text.iter().filter(|l| l.starts_with("offered")).count() == 2,
            "the self-payment is an offer, not a sale: {text:?}"
        );
    }
}
