//! `peephole credits …`: this node's credits from the shell. Like
//! `peephole cluster`, it works on the node's database, also while the
//! daemon runs; every figure is this node's own count.
use super::{Book, show};
use crate::admin::credits::{date_of, when};
use crate::cluster::cli::{open, resolve};
use crate::cluster::members;
use crate::credits::ledger::OfferState;
use anyhow::{Context, Result, bail};

pub const USAGE: &str = "usage: peephole credits [CONFIG]                     balance, by day
       peephole credits log [--days N] [CONFIG]     pool shares, spent, sent, received
       peephole credits members [CONFIG]            every member's balance and standing
       peephole credits uptime [CONFIG]             each member's reported hours up, 7 days
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
                "hours up a day (UTC); * a verified listener: advertised, up 12 hours or more"
            );
        }
        ["log"] => {
            let book = super::compute(&node).await?;
            let from = book.now_ms.saturating_sub(days * super::DAY_MS);
            let recent = |hlc: u64| crate::cluster::hlc::physical_ms(hlc) >= from;
            let mut lines: Vec<(u64, String)> = vec![];
            for e in book.pool.iter().filter(|e| e.node == me && recent(e.hlc)) {
                lines.push((
                    e.hlc,
                    format!("pool     {:>8}  this node's share of the day", show(e.mc)),
                ));
            }
            for o in book
                .ledger
                .offers
                .iter()
                .filter(|o| o.payer == me && recent(o.hlc))
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
            for t in book.ledger.transfers.iter().filter(|t| recent(t.hlc)) {
                if t.from == me {
                    lines.push((
                        t.hlc,
                        format!("sent     {:>8}  to {}", show(t.moved), name(&t.to)),
                    ));
                } else if t.to == me {
                    lines.push((
                        t.hlc,
                        format!("received {:>8}  from {}", show(t.moved), name(&t.from)),
                    ));
                }
            }
            if lines.is_empty() {
                println!("nothing earned, spent or sent in the last {days} day(s)");
            }
            lines.sort_by_key(|(hlc, _)| *hlc);
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
