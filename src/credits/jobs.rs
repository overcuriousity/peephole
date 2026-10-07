//! Paying for scan jobs. An arbiter funds a job it grants with an offer to
//! the scanner that names the job; the scanner charges the offered price
//! when it delivers the result, and nothing otherwise. What an arbiter
//! commits to its own jobs is bounded by `[credits] scan_share`.
use super::ledger::{Ledger, OfferState};
use super::{Mc, day_of, price};
use crate::cluster::identity::NodeId;
use crate::cluster::record::Record;
use crate::cluster::{Node, repl};
use anyhow::Result;
use std::sync::Arc;

/// What `me` may still hold in or pay for its scan jobs today: `share` of
/// its balance plus what its scan offers hold and were charged today,
/// minus those two.
pub fn budget(l: &Ledger, me: &NodeId, share: f64) -> Mc {
    let (mut held, mut charged) = (0, 0);
    for o in l
        .offers
        .iter()
        .filter(|o| o.payer == *me && o.job.is_some())
    {
        match o.state {
            OfferState::Open => held += o.held_now(),
            OfferState::Charged { charged: c } if day_of(o.hlc) == l.today => charged += c,
            _ => {}
        }
    }
    let committed = held + charged;
    let cap = ((l.balance(me) + committed) as f64 * share.clamp(0.0, 1.0)).floor() as Mc;
    cap.saturating_sub(committed)
}

/// Queued jobs `budget` funds at `price`.
pub fn bids(queued: u32, budget: Mc, price: Mc) -> u32 {
    if price == 0 {
        return 0;
    }
    (budget / price).min(queued as Mc) as u32
}

/// Fund the grant of `job_uid` to `scanner` at this node's scan price:
/// `(offer_seq, price)` once the offer is written. None: its own scanner,
/// a scanner that predates the market, a price under `min_mc`, or no
/// budget; the job is granted unfunded.
pub async fn fund(
    node: &Arc<Node>,
    scanner: NodeId,
    job_uid: &str,
    min_mc: u32,
) -> Option<(u64, u32)> {
    let me = node.id();
    if scanner == me
        || !node
            .members()
            .get(&scanner)
            .is_some_and(|m| super::pay::pays_with(m.proto_max))
    {
        return None;
    }
    let price = node.price_table().price_of(price::SCAN)?;
    if price < min_mc {
        return None;
    }
    let book = super::book_fresh(node).await.ok()?;
    if budget(&book.ledger, &me, node.scan_share()) < price as Mc {
        return None;
    }
    let parts = book.ledger.spendable_parts(&me, price as Mc)?;
    let job = Some(job_uid.to_string());
    match repl::append_sealing(node, |seal| Record::CreditOffer {
        to: scanner,
        parts,
        seal,
        job,
    })
    .await
    {
        Ok(e) => Some((e.seq, price)),
        Err(e) => {
            tracing::debug!(?e, job = %job_uid, "scan offer not written; granted unfunded");
            None
        }
    }
}

/// The scanner's receipt for a funded job: the price for a delivered
/// result, nothing for anything else (it frees the offer at once).
pub async fn settle(node: &Arc<Node>, arbiter: NodeId, offer_seq: u64, charged_mc: u32) {
    let receipt = Record::CreditReceipt {
        payer: arbiter,
        offer_seq,
        charged_mc,
        answered: vec![price::SCAN.into()],
    };
    if let Err(e) = repl::append(node, &[receipt]).await {
        tracing::warn!(?e, "scan receipt not written");
    }
}

/// Compute and keep the funded jobs this node would grant now, for the
/// heartbeat and the scan price.
pub async fn announce_bids(node: &Arc<Node>) -> Result<u32> {
    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued' AND arbiter = ?",
    )
    .bind(&node.id().0[..])
    .fetch_one(&node.store.pool)
    .await?;
    let book = super::book(node).await?;
    let price = node.price_table().price_of(price::SCAN).unwrap_or(0) as Mc;
    let n = bids(
        queued.clamp(0, u32::MAX as i64) as u32,
        budget(&book.ledger, &node.id(), node.scan_share()),
        price,
    );
    node.scan_bids
        .store(n, std::sync::atomic::Ordering::Relaxed);
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credits::DAY_MS;
    use crate::credits::entries::{Entry, Kind, SealState};
    use crate::credits::ledger::{Earned, run};

    const DAY: u32 = 20_000;
    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }
    fn at(day: u32, min: u64) -> u64 {
        (day as u64 * DAY_MS + min * 60_000) << 16
    }
    fn e(origin: u8, seq: u64, hlc: u64, kind: Kind) -> Entry {
        Entry {
            origin: id(origin),
            seq,
            hlc,
            kind,
            seal: SealState::Consistent,
        }
    }

    #[test]
    fn the_budget_is_a_share_of_what_was_there_today() {
        let earned = [Earned {
            node: id(1),
            hlc: at(DAY, 0),
            mc: 1000,
        }];
        let entries = [
            e(
                1,
                1,
                at(DAY, 1),
                Kind::Offer {
                    to: id(2),
                    parts: vec![(DAY, 200)],
                    job: Some("a".into()),
                },
            ),
            e(
                2,
                1,
                at(DAY, 2),
                Kind::Receipt {
                    payer: id(1),
                    offer_seq: 1,
                    charged_mc: 200,
                    answered: vec!["scan".into()],
                },
            ),
            e(
                1,
                2,
                at(DAY, 3),
                Kind::Offer {
                    to: id(2),
                    parts: vec![(DAY, 100)],
                    job: Some("b".into()),
                },
            ),
            // A lookup offer is not a scan offer.
            e(
                1,
                3,
                at(DAY, 4),
                Kind::Offer {
                    to: id(3),
                    parts: vec![(DAY, 50)],
                    job: None,
                },
            ),
        ];
        let l = run(
            &earned,
            &entries,
            &Default::default(),
            (DAY as u64 * DAY_MS) + 5 * 60_000,
        );
        // balance 650, committed 300: half of 950 is 475, 175 left.
        assert_eq!(budget(&l, &id(1), 0.5), 175);
        assert_eq!(budget(&l, &id(1), 0.0), 0);
        assert_eq!(budget(&l, &id(1), 1.0), 650);
    }

    #[test]
    fn bids_are_what_the_budget_buys_of_the_queue() {
        assert_eq!(bids(10, 175, 50), 3);
        assert_eq!(bids(2, 175, 50), 2);
        assert_eq!(bids(10, 0, 50), 0);
        assert_eq!(bids(10, 175, 0), 0, "no price, no bid");
    }
}
