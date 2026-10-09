//! Paying for scan jobs. An arbiter funds a job it grants with an offer to
//! the scanner that names the job; the scanner charges the offered price
//! when it delivers the result, and nothing otherwise. What an arbiter
//! commits to its own jobs is bounded by `[credits] scan_share`. Every
//! grant is funded: at the scanner's price, which may be 0 (then without
//! an offer).
use super::ledger::{self, Ledger, OfferState};
use super::{Mc, day_of, price};
use crate::cluster::identity::NodeId;
use crate::cluster::record::Record;
use crate::cluster::{Node, repl};
use anyhow::Result;
use std::sync::Arc;

/// What `me` may still hold in or pay for its scan jobs today: `share` of
/// its balance plus what its scan offers hold and were charged today,
/// minus those and what its own jobs (`self_mc`) hold. Paying oneself
/// leaves the balance as it is, so `self_mc` is not added back.
pub fn budget(l: &Ledger, me: &NodeId, share: f64, self_mc: Mc) -> Mc {
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
    let offered = held + charged;
    let cap = ((l.balance(me) + offered) as f64 * share.clamp(0.0, 1.0)).floor() as Mc;
    cap.saturating_sub(offered + self_mc)
}

/// What this node's own jobs granted to its own scanner hold (running) or
/// were charged today (done): they count against the budget like offers.
/// A job requeued, failed or refused no longer counts, and a regrant
/// clears the old reservation (see [`hold_self`]).
pub async fn self_committed(pool: &sqlx::SqlitePool, me: &NodeId) -> Result<Mc> {
    let n: Option<i64> = sqlx::query_scalar(
        "SELECT SUM(self_mc) FROM scan_jobs
         WHERE arbiter = ? AND scanner = arbiter AND self_mc > 0
           AND (status = 'running' OR (status = 'done' AND finished_at >= date('now')))",
    )
    .bind(&me.0[..])
    .fetch_one(pool)
    .await?;
    Ok(n.unwrap_or(0).max(0) as Mc)
}

/// What the grant of `job_uid` holds as an own job: `mc`, or nothing
/// (0). Every grant writes it, so a reservation of an earlier grant of a
/// requeued job never counts again.
pub async fn hold_self(pool: &sqlx::SqlitePool, job_uid: &str, mc: u32) -> Result<()> {
    sqlx::query("UPDATE scan_jobs SET self_mc = NULLIF(?, 0) WHERE uid = ?")
        .bind(mc as i64)
        .bind(job_uid)
        .execute(pool)
        .await?;
    Ok(())
}

/// What this node, as arbiter, would pay `scanner` for a job now: its own
/// scanner its selling price (0 before the first refresh); another
/// scanner what it announces, at most [`price::PRICE_TOLERANCE`] times
/// this node's copy, or an announced 0 while there is no copy yet. None:
/// not a scanner of the market, or a price that cannot be capped yet; it
/// cannot be granted the job.
pub fn price_for(node: &Node, scanner: &NodeId) -> Option<u32> {
    let table = node.price_table();
    if *scanner == node.id() {
        return price::own_scan_price(node, &table);
    }
    let k = node.status.known(scanner)?;
    if !node
        .members()
        .get(scanner)
        .is_some_and(|m| super::pay::sells_scans(m.proto_max))
    {
        return None;
    }
    match table.reference(scanner) {
        Some(r) => price::offer_price(k.hb.scan_price_mc, Some(r)),
        None => k.hb.scan_price_mc.filter(|p| *p == 0),
    }
}

/// The factor a bought (manual) job's level scales its funding price by:
/// 4^(level-1) — level 1 at the scanner's price, level 4 at 64 times it.
pub fn level_factor(level: i64) -> u32 {
    1u32.checked_shl(2 * level.clamp(1, 4) as u32 - 2)
        .unwrap_or(u32::MAX)
}

/// The oldest lot day a scan offer written at `now_ms` may draw from: a
/// lot that dies before the offer can be charged (within
/// [`JOB_OFFER_TTL_MS`](super::JOB_OFFER_TTL_MS)) is left out.
pub fn first_day_for_job(now_ms: u64) -> u32 {
    let last = ((now_ms + super::JOB_OFFER_TTL_MS) / super::DAY_MS) as u32;
    last.saturating_sub(super::LOT_DAYS - 1)
}

/// What one round of handing out jobs funds from: one book, computed at
/// the first grant that needs it, and what the offers written since took.
#[derive(Default)]
pub struct Funding {
    book: Option<Arc<super::Book>>,
    /// This node's lots as the book has them, less what was drawn since.
    lots: Vec<(u32, Mc)>,
    /// What the offers written in this round set aside.
    committed: Mc,
    /// What this node's own running and done-today jobs hold, read once.
    self_mc: Option<Mc>,
}

/// Whether this round's book can fund a grant at `price` to a scanner
/// taking no less than `min_mc`: a price of 0 always (it needs no book).
/// Reads the book and the own-job tally into `funding` the first time;
/// writes nothing.
pub async fn affordable(node: &Arc<Node>, funding: &mut Funding, min_mc: u32, price: u32) -> bool {
    if price < min_mc {
        return false;
    }
    if price == 0 {
        return true;
    }
    let me = node.id();
    if funding.book.is_none() {
        let Ok(b) = super::book_fresh(node).await else {
            return false;
        };
        funding.lots = b.ledger.by_day(&me);
        funding.book = Some(b);
    }
    let self_mc = match funding.self_mc {
        Some(s) => s,
        None => {
            let Ok(s) = self_committed(&node.store.pool, &me).await else {
                return false;
            };
            funding.self_mc = Some(s);
            s
        }
    };
    let Some(book) = &funding.book else {
        return false;
    };
    let left =
        budget(&book.ledger, &me, node.scan_share(), self_mc).saturating_sub(funding.committed);
    left >= price as Mc
}

/// Fund the grant of `job_uid` to `scanner` at `price` (see [`price_for`]):
/// `Some((Some(seq), price))` once the offer is written, `Some((None,
/// price))` for an own job, which the self tally holds against the budget,
/// and `Some((None, 0))` at a zero price: granted free, without an offer.
/// None: a price under `min_mc`, no budget, or the offer could not be
/// written; the job is not granted. `funding` carries the book and what
/// was committed across the grants of one round.
pub async fn fund(
    node: &Arc<Node>,
    funding: &mut Funding,
    scanner: NodeId,
    job_uid: &str,
    min_mc: u32,
    price: u32,
) -> Option<(Option<u64>, u32)> {
    let me = node.id();
    // Whatever an earlier grant of this job reserved is gone; a funded
    // own grant below writes its own.
    if let Err(e) = hold_self(&node.store.pool, job_uid, 0).await {
        tracing::warn!(?e, job = %job_uid, "old own-job reservation not cleared");
        return None;
    }
    if price < min_mc {
        return None;
    }
    if price == 0 {
        return Some((None, 0));
    }
    if !affordable(node, funding, min_mc, price).await {
        return None;
    }
    if scanner == me {
        // Paying oneself moves nothing: the job holds the price against
        // the budget instead of an offer.
        hold_self(&node.store.pool, job_uid, price).await.ok()?;
        funding.committed += price as Mc;
        return Some((None, price));
    }
    let first_day = first_day_for_job(crate::cluster::hlc::wall_ms());
    let parts = ledger::parts_from(&funding.lots, price as Mc, first_day)?;
    let job = Some(job_uid.to_string());
    match repl::append_sealing(node, |seal| Record::CreditOffer {
        to: scanner,
        parts: parts.clone(),
        seal,
        job,
        economy: crate::cluster::record::ECONOMY,
    })
    .await
    {
        Ok(e) => {
            funding.committed += price as Mc;
            for (day, mc) in parts {
                if let Some(lot) = funding.lots.iter_mut().find(|(d, _)| *d == day) {
                    lot.1 = lot.1.saturating_sub(mc as Mc);
                }
            }
            Some((Some(e.seq), price))
        }
        Err(e) => {
            tracing::debug!(?e, job = %job_uid, "scan offer not written; job not granted");
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
        economy: crate::cluster::record::ECONOMY,
    };
    if let Err(e) = repl::append(node, &[receipt]).await {
        tracing::warn!(?e, "scan receipt not written");
    }
}

/// Compute and keep this node's scan budget left and queued jobs, for
/// the heartbeat.
pub async fn announce_budget(node: &Arc<Node>) -> Result<()> {
    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued' AND arbiter = ?",
    )
    .bind(&node.id().0[..])
    .fetch_one(&node.store.pool)
    .await?;
    let book = super::book(node).await?;
    let self_mc = self_committed(&node.store.pool, &node.id()).await?;
    let left = budget(&book.ledger, &node.id(), node.scan_share(), self_mc);
    node.scan_budget_mc.store(
        left.min(u32::MAX as Mc) as u32,
        std::sync::atomic::Ordering::Relaxed,
    );
    node.scan_queued.store(
        queued.clamp(0, u32::MAX as i64) as u32,
        std::sync::atomic::Ordering::Relaxed,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credits::DAY_MS;
    use crate::credits::entries::{Entry, Kind, SealState};
    use crate::credits::ledger::{Earned, run};

    #[test]
    fn the_level_factor_is_four_to_the_level_minus_one() {
        assert_eq!(level_factor(1), 1);
        assert_eq!(level_factor(2), 4);
        assert_eq!(level_factor(3), 16);
        assert_eq!(level_factor(4), 64);
    }

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
        assert_eq!(budget(&l, &id(1), 0.5, 0), 175);
        assert_eq!(budget(&l, &id(1), 0.0, 0), 0);
        assert_eq!(budget(&l, &id(1), 1.0, 0), 650);
    }

    #[test]
    fn the_budget_counts_own_jobs() {
        // A balance of 1000 at share 0.5: 500. Own jobs holding 200 leave
        // the balance as it is: 1000 x 0.5 - 200 = 300 left, as after
        // paying 200 to another scanner ((800 + 200) x 0.5 - 200).
        let l = ledger_with_balance(id(1), 1000);
        assert_eq!(budget(&l, &id(1), 0.5, 0), 500);
        assert_eq!(budget(&l, &id(1), 0.5, 200), 300);
        // At share 1 own jobs use up the balance too.
        assert_eq!(budget(&l, &id(1), 1.0, 1000), 0);
    }

    #[tokio::test]
    async fn own_job_reservations_count_while_running_and_when_done_today() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let pool = &store.pool;
        let me = id(1);
        sqlx::query(
            "INSERT INTO ips (id, ip, first_seen, last_seen) VALUES (1, '192.0.2.1', '', '')",
        )
        .execute(pool)
        .await
        .unwrap();
        let other = id(2);
        for (n, status, finished, scanner, mc) in [
            (1, "running", None, me, 30),
            (2, "done", Some("datetime('now')"), me, 20),
            (3, "done", Some("datetime('now','-2 days')"), me, 50),
            (4, "queued", None, me, 70), // requeued after its reservation: no longer counts
            (5, "failed", Some("datetime('now')"), me, 90),
            (6, "running", None, other, 40), // a stale reservation, regranted elsewhere
        ] {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "INSERT INTO scan_jobs (id, ip_id, level, status, queued_at, finished_at, uid, arbiter, scanner, self_mc)
                 VALUES (?, 1, 1, ?, datetime('now'), {}, ?, ?, ?, ?)",
                finished.unwrap_or("NULL")
            )))
            .bind(n)
            .bind(status)
            .bind(format!("j{n}"))
            .bind(&me.0[..])
            .bind(&scanner.0[..])
            .bind(mc)
            .execute(pool)
            .await
            .unwrap();
        }
        assert_eq!(self_committed(pool, &me).await.unwrap(), 50);
        // The requeued job runs here again: its grant writes what it holds.
        sqlx::query("UPDATE scan_jobs SET status = 'running' WHERE uid = 'j4'")
            .execute(pool)
            .await
            .unwrap();
        hold_self(pool, "j4", 0).await.unwrap();
        assert_eq!(
            self_committed(pool, &me).await.unwrap(),
            50,
            "reservation cleared"
        );
        hold_self(pool, "j4", 25).await.unwrap();
        assert_eq!(self_committed(pool, &me).await.unwrap(), 75, "funded anew");
    }

    #[tokio::test]
    async fn a_zero_price_is_affordable_without_credits_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let node = crate::cluster::Node::open(crate::cluster::NodeParams {
            identity: crate::cluster::identity::Identity::generate().unwrap(),
            cluster: crate::config::ClusterConfig {
                node_name: "n".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: None,
                key_path: None,
                takeover_hours: 6.0,
                lease_secs: 120,
                remote_config: false,
                origin_quota_mb: 20 * 1024,
                peers: vec![],
            },
            roles: Default::default(),
            store: store.clone(),
            proto: (2, 2),
            data_dir: dir.path().to_path_buf(),
            retention_days: 0,
        })
        .await
        .unwrap();
        node.bootstrap().await.unwrap();
        node.set_scan_share(0.0);
        let mut f = Funding::default();
        assert!(
            affordable(&node, &mut f, 0, 0).await,
            "free, even with a share of 0"
        );
        assert!(!affordable(&node, &mut f, 0, 1).await, "no credits");
        assert!(
            !affordable(&node, &mut f, 5, 0).await,
            "under the scanner's least"
        );
        let other = crate::cluster::identity::Identity::generate().unwrap().id;
        assert_eq!(
            fund(&node, &mut f, other, "job-1", 0, 0).await,
            Some((None, 0))
        );
        assert_eq!(
            fund(&node, &mut f, node.id(), "job-2", 0, 0).await,
            Some((None, 0))
        );
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credit_entries")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "no offer written");
        assert_eq!(self_committed(&store.pool, &node.id()).await.unwrap(), 0);
    }

    fn ledger_with_balance(node: NodeId, mc: Mc) -> Ledger {
        let earned = [Earned {
            node,
            hlc: at(DAY, 0),
            mc,
        }];
        run(
            &earned,
            &[],
            &Default::default(),
            (DAY as u64 * DAY_MS) + 5 * 60_000,
        )
    }

    #[test]
    fn a_scan_offer_is_not_funded_from_a_lot_that_dies_before_the_scan_ends() {
        use crate::credits::{JOB_OFFER_TTL_MS, LOT_DAYS};
        // Early in the day: every live lot outlives the offer.
        let early = DAY as u64 * DAY_MS + 60_000;
        assert_eq!(first_day_for_job(early), DAY - (LOT_DAYS - 1));
        // Close to midnight: the oldest live lot dies within the offer's
        // lifetime, so it is left out.
        let late = (DAY as u64 + 1) * DAY_MS - JOB_OFFER_TTL_MS / 2;
        assert_eq!(first_day_for_job(late), DAY + 1 - (LOT_DAYS - 1));
        let earned = [
            Earned {
                node: id(1),
                hlc: at(DAY - (LOT_DAYS - 1), 0),
                mc: 100,
            },
            Earned {
                node: id(1),
                hlc: at(DAY, 0),
                mc: 50,
            },
        ];
        let l = run(&earned, &[], &Default::default(), late);
        let lots = l.by_day(&id(1));
        assert_eq!(lots, [(DAY - (LOT_DAYS - 1), 100), (DAY, 50)]);
        assert_eq!(
            ledger::parts_from(&lots, 120, first_day_for_job(early)),
            Some(vec![(DAY - (LOT_DAYS - 1), 100), (DAY, 20)])
        );
        assert_eq!(
            ledger::parts_from(&lots, 50, first_day_for_job(late)),
            Some(vec![(DAY, 50)])
        );
        assert_eq!(
            ledger::parts_from(&lots, 120, first_day_for_job(late)),
            None
        );
    }
}
