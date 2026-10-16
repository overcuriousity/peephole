//! Paying for scan jobs. An arbiter funds a job it grants with an offer to
//! the scanner that names the job; the scanner charges the offered price
//! when it delivers the result, and nothing otherwise. What an arbiter
//! commits to its own jobs is bounded by its balance. Every
//! grant is funded: at the scanner's price, which may be 0 (then without
//! an offer).
use super::ledger::{self, Ledger, OfferState};
use super::{Mc, price};
use crate::cluster::identity::NodeId;
use crate::cluster::record::Record;
use crate::cluster::{Node, repl};
use crate::lock::MutexExt;
use anyhow::Result;
use std::sync::Arc;

/// What `me` may still hold in or pay for its scan jobs: its whole
/// balance (open offers are held out of it already) minus what its own
/// jobs (`self_mc`) hold. Paying oneself leaves the balance as it is, so
/// `self_mc` is held against it here. No daily share (MIK-249).
pub fn budget(l: &Ledger, me: &NodeId, self_mc: Mc) -> Mc {
    l.balance(me).saturating_sub(self_mc)
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
/// scanner what it announces. Between two members of the free market
/// (protocol 9, [`super::pay::trades_market`]) that is the ask as it
/// stands: the buyer's bid decides ([`affordable`]). A scanner below 9
/// is paid at most [`price::PRICE_TOLERANCE`] times this node's copy, or
/// an announced 0 while there is no copy yet. None: not a scanner of the
/// market, or a price that cannot be capped yet; it cannot be granted the
/// job.
pub fn price_for(node: &Node, scanner: &NodeId) -> Option<u32> {
    let table = node.price_table();
    if *scanner == node.id() {
        return price::own_scan_price(node, &table);
    }
    let k = node.status.known(scanner)?;
    let proto = node.members().get(scanner).map(|m| m.proto_max)?;
    scan_offer(
        node.proto.1,
        proto,
        k.hb.scan_price_mc,
        table.reference(scanner),
    )
}

/// [`price_for`] another scanner: this node announcing `my_proto`, the
/// scanner `proto`, its `announced` price and this node's copy of it.
pub fn scan_offer(
    my_proto: u32,
    proto: u32,
    announced: Option<u32>,
    reference: Option<u32>,
) -> Option<u32> {
    if !super::pay::sells_scans(proto) {
        return None;
    }
    if under_bid(my_proto, proto) {
        return announced;
    }
    match reference {
        Some(r) => price::offer_price(announced, Some(r)),
        None => announced.filter(|p| *p == 0),
    }
}

/// Whether this node (announcing `my_proto`) buys a scan from a scanner
/// announcing `proto` at the scanner's ask, bounded by its own bid instead
/// of a cap on its copy of the price: both are in the free market.
pub fn under_bid(my_proto: u32, proto: u32) -> bool {
    super::pay::trades_market(my_proto) && super::pay::trades_market(proto)
}

/// The factor a bought (manual) job's level scales its funding price by:
/// 4^(level-1) — level 1 at the scanner's price, level 4 at 64 and level 5
/// at 256 times it.
pub fn level_factor(level: i64) -> u32 {
    1u32.checked_shl(2 * level.clamp(1, 5) as u32 - 2)
        .unwrap_or(u32::MAX)
}

/// The oldest lot day a scan offer written at `now_ms` may draw from: a
/// lot that dies before the offer can be charged (within
/// [`JOB_OFFER_TTL_MS`](super::JOB_OFFER_TTL_MS)) is left out.
pub fn first_day_for_job(now_ms: u64) -> u32 {
    ledger::first_day_for(now_ms, super::JOB_OFFER_TTL_MS)
}

/// What one round of handing out jobs funds from: one book, computed at
/// the first grant that needs it. What every offer or transfer of this
/// node written since took from its lots, in this round or not, is left
/// out of them ([`super::pay::Spending`]).
#[derive(Default)]
pub struct Funding {
    book: Option<Arc<super::Book>>,
    /// What the offers written in this round set aside.
    committed: Mc,
    /// What this node's own running and done-today jobs hold, read once.
    self_mc: Option<Mc>,
    /// This node's bid for a scan job ([`super::bid`]), read once.
    bid: Option<Mc>,
}

/// Whether a round can fund a grant ([`affordable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Afford {
    Yes,
    /// Under the scanner's least price, or no budget for it.
    No,
    /// The scanner's ask is above this node's bid for a scan job: the
    /// job waits for a lower ask or a higher bid.
    OverBid {
        bid: Mc,
    },
}

/// Whether a grant at `price` to `scanner` is bounded by this node's bid
/// rather than only by its balance: an automatic job (not `manual`, which
/// an operator bought) for another scanner of the free market. Paying
/// oneself moves nothing; a scanner below protocol 9 is capped instead
/// ([`price_for`]).
fn bid_bounds(node: &Node, scanner: &NodeId, manual: bool) -> bool {
    !manual
        && *scanner != node.id()
        && node
            .members()
            .get(scanner)
            .is_some_and(|m| under_bid(node.proto.1, m.proto_max))
}

/// Whether this round's book can fund a grant at `price` to `scanner`
/// taking no less than `min_mc`: a price of 0 always (it needs no book).
/// An automatic job for a scanner of the free market also needs `price`
/// at most this node's bid ([`bid_bounds`]). Reads the book, the own-job
/// tally and the bid into `funding` the first time; writes nothing.
pub async fn affordable(
    node: &Arc<Node>,
    funding: &mut Funding,
    scanner: &NodeId,
    manual: bool,
    min_mc: u32,
    price: u32,
) -> Afford {
    if price < min_mc {
        return Afford::No;
    }
    if price == 0 {
        return Afford::Yes;
    }
    let me = node.id();
    if funding.book.is_none() {
        let Ok(b) = super::book_fresh(node).await else {
            return Afford::No;
        };
        funding.book = Some(b);
    }
    let self_mc = match funding.self_mc {
        Some(s) => s,
        None => {
            let Ok(s) = self_committed(&node.store.pool, &me).await else {
                return Afford::No;
            };
            funding.self_mc = Some(s);
            s
        }
    };
    let Some(book) = &funding.book else {
        return Afford::No;
    };
    let left = budget(&book.ledger, &me, self_mc).saturating_sub(funding.committed);
    if left < price as Mc {
        return Afford::No;
    }
    if bid_bounds(node, scanner, manual) {
        let bid = match funding.bid {
            Some(b) => b,
            None => {
                let b = price::own_bid_in(node, book, price::SCAN).await;
                funding.bid = Some(b);
                b
            }
        };
        if price as Mc > bid {
            return Afford::OverBid { bid };
        }
    }
    Afford::Yes
}

/// Fund the grant of `job_uid` to `scanner` at `price` (see [`price_for`]):
/// `Some((Some(seq), price))` once the offer is written, `Some((None,
/// price))` for an own job, which the self tally holds against the budget,
/// and `Some((None, 0))` at a zero price: granted free, without an offer.
/// None: a price under `min_mc`, no budget, above the bid
/// ([`affordable`]), or the offer could not be written; the job is not
/// granted. `funding` carries the book and what was committed across the
/// grants of one round.
pub async fn fund(
    node: &Arc<Node>,
    funding: &mut Funding,
    scanner: NodeId,
    job_uid: &str,
    manual: bool,
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
    if affordable(node, funding, &scanner, manual, min_mc, price).await != Afford::Yes {
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
    let mut spending = node.credits.spending.lock().await;
    let lots = spending.lots(funding.book.as_ref()?, &me);
    let parts = ledger::parts_from(&lots, price as Mc, first_day)?;
    let job = Some(job_uid.to_string());
    match repl::append_sealing(node, |seal| Record::CreditOffer {
        to: scanner,
        parts: parts.clone(),
        seal,
        job,
        audit: None,
        economy: crate::cluster::record::ECONOMY,
    })
    .await
    {
        Ok(e) => {
            funding.committed += price as Mc;
            spending.wrote(e.seq, &parts);
            Some((Some(e.seq), price))
        }
        Err(e) => {
            tracing::debug!(?e, job = %job_uid, "scan offer not written; job not granted");
            None
        }
    }
}

/// The scanner's side of a funded job before it runs: whether `arbiter`'s
/// offer `seq` is held here, made to this node for `job_uid`, open, and
/// covers `price` in this node's book. A scanner that charged an offer the
/// arbiter's lots do not hold would be paid less than it charged. An
/// offer not held yet is fetched from the arbiter and waited for up to
/// [`super::pay::SERVE_WAIT`].
pub async fn offer_covers(
    node: &Arc<Node>,
    arbiter: NodeId,
    seq: u64,
    job_uid: &str,
    price: u32,
) -> bool {
    let pool = &node.store.pool;
    if !matches!(super::entries::get(pool, &arbiter, seq).await, Ok(Some(_))) {
        if let Err(e) = node.sync_around_request(arbiter).await {
            tracing::debug!(?e, "sync for a scan offer failed; waiting for it");
        }
        let until = tokio::time::Instant::now() + super::pay::SERVE_WAIT;
        while !matches!(super::entries::get(pool, &arbiter, seq).await, Ok(Some(_))) {
            if tokio::time::Instant::now() >= until {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
    let Ok(book) = super::book_fresh(node).await else {
        return false;
    };
    book.ledger.offer(&arbiter, seq).is_some_and(|o| {
        o.to == node.id()
            && o.job.as_deref() == Some(job_uid)
            && o.state == OfferState::Open
            && o.covered >= price as Mc
    })
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
/// the heartbeat; and the scan jobs it wants bought in the coming hour,
/// for its bid ([`scan_wants`]).
pub async fn announce_budget(node: &Arc<Node>) -> Result<()> {
    let (queued, grantable): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*),
                COALESCE(SUM(NOT manual AND (retry_at IS NULL OR retry_at <= datetime('now'))), 0)
         FROM scan_jobs WHERE status = 'queued' AND arbiter = ?",
    )
    .bind(&node.id().0[..])
    .fetch_one(&node.store.pool)
    .await?;
    let can_do: f64 = node
        .price_table()
        .capacity
        .scanners
        .iter()
        .map(|s| s.can_do)
        .sum();
    node.credits
        .wants
        .lock_or_recover()
        .set(price::SCAN, scan_wants(grantable.max(0) as u64, can_do));
    let book = super::book(node).await?;
    let self_mc = self_committed(&node.store.pool, &node.id()).await?;
    let left = budget(&book.ledger, &node.id(), self_mc);
    node.credits.scan_budget_mc.store(
        left.min(u32::MAX as Mc) as u32,
        std::sync::atomic::Ordering::Relaxed,
    );
    node.credits.scan_queued.store(
        queued.clamp(0, u32::MAX as i64) as u32,
        std::sync::atomic::Ordering::Relaxed,
    );
    Ok(())
}

/// The scan jobs this node wants bought in the coming hour: its
/// `grantable` queued jobs (automatic and due; an operator's bought job
/// is no part of the bid), at most what the scanners `can_do` in an hour
/// together, when that is known.
pub fn scan_wants(grantable: u64, can_do: f64) -> u32 {
    let units = match can_do > 0.0 {
        true => grantable.min(can_do.ceil() as u64),
        false => grantable,
    };
    units.min(u32::MAX as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credits::DAY_MS;
    use crate::credits::entries::{Entry, Kind, SealState};
    use crate::credits::ledger::{Earned, run};

    #[test]
    fn a_v9_arbiter_pays_a_v9_scanner_its_ask_and_caps_older_ones() {
        // Copy 100, ask 200.
        assert_eq!(scan_offer(9, 9, Some(200), Some(100)), Some(200));
        assert_eq!(
            scan_offer(9, 9, Some(200), None),
            Some(200),
            "no copy needed"
        );
        assert_eq!(scan_offer(9, 8, Some(200), Some(100)), Some(125));
        assert_eq!(
            scan_offer(8, 9, Some(200), Some(100)),
            Some(125),
            "below 9 here"
        );
        assert_eq!(scan_offer(9, 8, Some(200), None), None, "no copy to cap by");
        assert_eq!(scan_offer(9, 8, Some(0), None), Some(0));
        assert_eq!(
            scan_offer(9, 6, Some(200), Some(100)),
            None,
            "sells no scans"
        );
        assert_eq!(
            scan_offer(9, 9, None, Some(100)),
            None,
            "announces no price"
        );
    }

    #[test]
    fn the_scan_jobs_wanted_are_the_grantable_ones_an_hour_can_take() {
        assert_eq!(scan_wants(0, 40.0), 0);
        assert_eq!(scan_wants(12, 40.0), 12);
        assert_eq!(scan_wants(500, 40.0), 40, "what the scanners do in an hour");
        assert_eq!(scan_wants(500, 0.5), 1);
        assert_eq!(scan_wants(500, 0.0), 500, "capacity unknown");
    }

    #[test]
    fn the_level_factor_is_four_to_the_level_minus_one() {
        assert_eq!(level_factor(1), 1);
        assert_eq!(level_factor(2), 4);
        assert_eq!(level_factor(3), 16);
        assert_eq!(level_factor(4), 64);
        assert_eq!(level_factor(5), 256);
        assert_eq!(level_factor(9), 256, "clamped at the highest level");
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
    fn the_budget_is_the_whole_balance() {
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
                    audit: None,
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
                    audit: None,
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
                    audit: None,
                },
            ),
        ];
        let l = run(
            &earned,
            &entries,
            &Default::default(),
            (DAY as u64 * DAY_MS) + 5 * 60_000,
        );
        // 1000 earned, 200 charged, 150 held by open offers: 650, all of
        // it for scan jobs (no daily half, MIK-249).
        assert_eq!(budget(&l, &id(1), 0), 650);
    }

    #[test]
    fn the_budget_counts_own_jobs() {
        // A balance of 1000 funds jobs up to 1000. Own jobs holding 200
        // leave the balance as it is: 800 left, as after paying 200 to
        // another scanner.
        let l = ledger_with_balance(id(1), 1000);
        assert_eq!(budget(&l, &id(1), 0), 1000);
        assert_eq!(budget(&l, &id(1), 200), 800);
        assert_eq!(budget(&l, &id(1), 1000), 0);
        assert_eq!(budget(&l, &id(1), 1500), 0);
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
                relay_slots: 16,
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
        let mut f = Funding::default();
        let other = crate::cluster::identity::Identity::generate().unwrap().id;
        assert_eq!(
            affordable(&node, &mut f, &other, false, 0, 0).await,
            Afford::Yes,
            "free, even with no credits"
        );
        assert_eq!(
            affordable(&node, &mut f, &other, false, 0, 1).await,
            Afford::No,
            "no credits"
        );
        assert_eq!(
            affordable(&node, &mut f, &other, false, 5, 0).await,
            Afford::No,
            "under the scanner's least"
        );
        assert_eq!(
            fund(&node, &mut f, other, "job-1", false, 0, 0).await,
            Some((None, 0))
        );
        assert_eq!(
            fund(&node, &mut f, node.id(), "job-2", false, 0, 0).await,
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
