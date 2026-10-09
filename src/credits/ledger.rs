//! The ledger: every balance, from the pool credited to the verified
//! listeners (`credits::pool`) and what the log says about payments. A
//! pure function of its input, so every node that holds the same entries
//! and counts the same reach reports arrives at the same balances, in
//! whatever order the entries reached it.
//!
//! A credit belongs to a lot: a node and the UTC day of the pool it came
//! from. It keeps its lot when it changes hands and is gone 7 days after
//! that day.
use super::entries::{Entry, Kind, parts_ok};
use super::{DAY_MS, LOT_DAYS, Mc, OFFER_TTL_MS, day_of};
use crate::cluster::hlc::physical_ms;
use crate::cluster::identity::NodeId;
use std::collections::{BTreeMap, HashMap, HashSet};

/// A pool share credited to a node; its HLC dates the lot.
#[derive(Debug, Clone, PartialEq)]
pub struct Earned {
    pub node: NodeId,
    /// The last instant of the pool's day (`pool::end_of`).
    pub hlc: u64,
    pub mc: Mc,
}

/// Who this node does not pay in full: the gates, as the ledger applies
/// them.
#[derive(Debug, Clone, Default)]
pub struct Gates {
    /// Blocked here, or shown to have two histories: hold nothing, and
    /// their entries move nothing.
    pub left_out: HashSet<NodeId>,
    /// Members that do not earn here (failing the rules gate, or left
    /// out): their receipts move nothing.
    pub no_sales: HashSet<NodeId>,
    /// Scanners failing the audit gates here: their receipts for scan jobs
    /// move nothing.
    pub no_scan_sales: HashSet<NodeId>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OfferState {
    /// Written, no receipt yet, not past its lifetime ([`Offer::ttl_ms`]).
    Open,
    Charged {
        charged: Mc,
    },
    /// Its lifetime passed without a receipt: everything went back.
    Lapsed,
}

/// An offer as the ledger sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Offer {
    pub payer: NodeId,
    pub seq: u64,
    pub hlc: u64,
    pub to: NodeId,
    /// What the offer names.
    pub offered: Mc,
    /// What the payer's lots held of that when it was written: the most a
    /// receipt can take.
    pub covered: Mc,
    /// Still set aside, by lot day; empty once charged or lapsed.
    pub held: Vec<(u32, Mc)>,
    pub state: OfferState,
    /// The providers its receipt names.
    pub answered: Vec<String>,
    /// The scan job it funds; None: a lookup or probe.
    pub job: Option<String>,
    /// The scan an audit it buys checks (`credits::audit`).
    pub audit: Option<String>,
}

impl Offer {
    /// How long it may wait for its receipt.
    pub fn ttl_ms(&self) -> u64 {
        if self.audit.is_some() {
            super::AUDIT_OFFER_TTL_MS
        } else if self.job.is_some() {
            super::JOB_OFFER_TTL_MS
        } else {
            OFFER_TTL_MS
        }
    }

    pub fn held_now(&self) -> Mc {
        self.held.iter().map(|(_, mc)| mc).sum()
    }
}

/// A transfer and what it really moved.
#[derive(Debug, Clone, PartialEq)]
pub struct Moved {
    pub hlc: u64,
    pub from: NodeId,
    pub to: NodeId,
    pub named: Mc,
    pub moved: Mc,
}

/// What a node earned and paid over the entries walked.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Tally {
    pub earned: Mc,
    /// Charged to it for lookups.
    pub spent: Mc,
    /// What it charged others.
    pub served: Mc,
    pub sent: Mc,
    pub received: Mc,
}

#[derive(Debug, Clone, Default)]
pub struct Ledger {
    /// Balance per lot `(node, day)`.
    pub lots: BTreeMap<(NodeId, u32), Mc>,
    /// Every offer walked, in the order of the walk.
    pub offers: Vec<Offer>,
    pub transfers: Vec<Moved>,
    pub tallies: HashMap<NodeId, Tally>,
    /// The same, counting only the last 7 days (the walk covers 8: a lot's
    /// life and one).
    pub week: HashMap<NodeId, Tally>,
    /// The UTC day balances are read for.
    pub today: u32,
}

/// The parts of `mc` drawn from `lots` (`(day, mc)`, oldest first as
/// [`Ledger::by_day`] gives them), oldest first, leaving out the lots of
/// days before `first_day`; None when they do not hold that much (or
/// `mc` is nothing).
pub fn parts_from(lots: &[(u32, Mc)], mc: Mc, first_day: u32) -> Option<Vec<(u32, u32)>> {
    if mc == 0 {
        return None;
    }
    let mut left = mc;
    let mut parts = vec![];
    for &(day, have) in lots
        .iter()
        .filter(|(day, have)| *day >= first_day && *have > 0)
    {
        let take = have.min(left).min(u32::MAX as Mc);
        parts.push((day, take as u32));
        left -= take;
        if left == 0 {
            return Some(parts);
        }
    }
    None
}

impl Ledger {
    fn first_live_day(&self) -> u32 {
        self.today.saturating_sub(LOT_DAYS - 1)
    }

    /// What `node` can spend now: its lots that are still alive.
    pub fn balance(&self, node: &NodeId) -> Mc {
        self.by_day(node).iter().map(|(_, mc)| mc).sum()
    }

    /// `node`'s live lots that hold something, oldest first.
    pub fn by_day(&self, node: &NodeId) -> Vec<(u32, Mc)> {
        self.lots
            .range((*node, self.first_live_day())..=(*node, self.today))
            .filter(|(_, mc)| **mc > 0)
            .map(|((_, day), mc)| (*day, *mc))
            .collect()
    }

    /// What `node` has set aside in open offers.
    pub fn held(&self, node: &NodeId) -> Mc {
        self.offers
            .iter()
            .filter(|o| o.payer == *node && o.state == OfferState::Open)
            .map(Offer::held_now)
            .sum()
    }

    /// The parts of an offer or transfer of `mc` by `node`, oldest lots
    /// first; None when it does not hold that much (or `mc` is nothing).
    pub fn spendable_parts(&self, node: &NodeId, mc: Mc) -> Option<Vec<(u32, u32)>> {
        parts_from(&self.by_day(node), mc, 0)
    }

    pub fn offer(&self, payer: &NodeId, seq: u64) -> Option<&Offer> {
        self.offers
            .iter()
            .find(|o| o.payer == *payer && o.seq == seq)
    }

    /// Every live credit, held ones included.
    pub fn circulating(&self) -> Mc {
        let first = self.first_live_day();
        let in_lots: Mc = self
            .lots
            .iter()
            .filter(|((_, day), _)| (first..=self.today).contains(day))
            .map(|(_, mc)| mc)
            .sum();
        let held: Mc = self
            .offers
            .iter()
            .filter(|o| o.state == OfferState::Open)
            .flat_map(|o| o.held.iter())
            .filter(|(day, _)| (first..=self.today).contains(day))
            .map(|(_, mc)| mc)
            .sum();
        in_lots + held
    }

    /// What `node` holds in the lot that is on its last day.
    pub fn expiring_today(&self, node: &NodeId) -> Mc {
        if self.today < LOT_DAYS - 1 {
            return 0;
        }
        self.lots
            .get(&(*node, self.first_live_day()))
            .copied()
            .unwrap_or(0)
    }

    pub fn tally(&self, node: &NodeId) -> Tally {
        self.tallies.get(node).copied().unwrap_or_default()
    }

    /// [`Ledger::tally`] of the last 7 days.
    pub fn week_tally(&self, node: &NodeId) -> Tally {
        self.week.get(node).copied().unwrap_or_default()
    }
}

enum Step<'a> {
    Earn(&'a Earned),
    Entry(&'a Entry),
}

impl Step<'_> {
    /// The order of the walk: by HLC, then origin, then sequence number;
    /// what a scan earned comes before an entry of the same instant.
    fn key(&self) -> (u64, NodeId, u8, u64) {
        match self {
            Step::Earn(e) => (e.hlc, e.node, 0, 0),
            Step::Entry(e) => (e.hlc, e.origin, 1, e.seq),
        }
    }
}

struct Walk<'a> {
    l: Ledger,
    gates: &'a Gates,
    /// The HLC the last 7 days start at.
    week_from: u64,
}

impl Walk<'_> {
    fn lot(&mut self, node: NodeId, day: u32) -> &mut Mc {
        self.l.lots.entry((node, day)).or_insert(0)
    }

    /// Count `f` for `node` in the tallies, and in the week's when `hlc`
    /// lies in the last 7 days.
    fn tally(&mut self, node: NodeId, hlc: u64, f: impl Fn(&mut Tally)) {
        f(self.l.tallies.entry(node).or_default());
        if hlc >= self.week_from {
            f(self.l.week.entry(node).or_default());
        }
    }

    /// Give back what offers past their lifetime still hold.
    fn lapse(&mut self, now_ms: u64) {
        for i in 0..self.l.offers.len() {
            let o = &self.l.offers[i];
            if o.state != OfferState::Open || now_ms <= physical_ms(o.hlc) + o.ttl_ms() {
                continue;
            }
            let (payer, held) = (o.payer, std::mem::take(&mut self.l.offers[i].held));
            self.l.offers[i].state = OfferState::Lapsed;
            for (day, mc) in held {
                *self.lot(payer, day) += mc;
            }
        }
    }

    fn offer(
        &mut self,
        e: &Entry,
        to: NodeId,
        parts: &[(u32, u32)],
        job: &Option<String>,
        audit: &Option<String>,
    ) {
        let mut held = vec![];
        for (day, mc) in parts {
            let lot = self.lot(e.origin, *day);
            let take = (*lot).min(*mc as Mc);
            *lot -= take;
            if take > 0 {
                held.push((*day, take));
            }
        }
        held.sort();
        self.l.offers.push(Offer {
            payer: e.origin,
            seq: e.seq,
            hlc: e.hlc,
            to,
            offered: parts.iter().map(|(_, mc)| *mc as Mc).sum(),
            covered: held.iter().map(|(_, mc)| mc).sum(),
            held,
            state: OfferState::Open,
            answered: vec![],
            job: job.clone(),
            audit: audit.clone(),
        });
    }

    fn receipt(
        &mut self,
        e: &Entry,
        payer: NodeId,
        offer_seq: u64,
        charged: Mc,
        answered: &[String],
    ) {
        if self.gates.no_sales.contains(&e.origin) {
            return;
        }
        let Some(i) = self.l.offers.iter().position(|o| {
            o.payer == payer
                && o.seq == offer_seq
                && o.to == e.origin
                && o.state == OfferState::Open
                && e.hlc > o.hlc
                && physical_ms(e.hlc) <= physical_ms(o.hlc) + o.ttl_ms()
        }) else {
            return;
        };
        // A scanner failing the audit gates here is not paid for scans.
        if self.l.offers[i].job.is_some() && self.gates.no_scan_sales.contains(&e.origin) {
            return;
        }
        let held = std::mem::take(&mut self.l.offers[i].held);
        let mut left = charged.min(held.iter().map(|(_, mc)| mc).sum());
        let paid = left;
        for (day, mc) in held {
            let take = mc.min(left);
            left -= take;
            *self.lot(e.origin, day) += take;
            *self.lot(payer, day) += mc - take;
        }
        let o = &mut self.l.offers[i];
        o.answered = answered.to_vec();
        o.state = OfferState::Charged { charged: paid };
        self.tally(payer, e.hlc, |t| t.spent += paid);
        self.tally(e.origin, e.hlc, |t| t.served += paid);
    }

    fn transfer(&mut self, e: &Entry, to: NodeId, parts: &[(u32, u32)]) {
        let mut moved = 0;
        for (day, mc) in parts {
            let lot = self.lot(e.origin, *day);
            let take = (*lot).min(*mc as Mc);
            *lot -= take;
            *self.lot(to, *day) += take;
            moved += take;
        }
        self.l.transfers.push(Moved {
            hlc: e.hlc,
            from: e.origin,
            to,
            named: parts.iter().map(|(_, mc)| *mc as Mc).sum(),
            moved,
        });
        self.tally(e.origin, e.hlc, |t| t.sent += moved);
        self.tally(to, e.hlc, |t| t.received += moved);
    }
}

/// Walk the pool shares and every payment in order, and return where
/// every credit is at `now_ms`. Members in `gates.left_out` hold nothing
/// and their entries move nothing (what others sent them is lost); the
/// receipts of those in `no_sales`, and the scan receipts of those in
/// `no_scan_sales`, move nothing (their offers lapse back).
pub fn run(earned: &[Earned], entries: &[Entry], gates: &Gates, now_ms: u64) -> Ledger {
    let mut steps: Vec<Step> = earned
        .iter()
        .map(Step::Earn)
        .chain(entries.iter().map(Step::Entry))
        .collect();
    steps.sort_by_key(Step::key);
    let mut w = Walk {
        l: Ledger {
            today: (now_ms / DAY_MS) as u32,
            ..Default::default()
        },
        gates,
        week_from: now_ms.saturating_sub(7 * DAY_MS) << 16,
    };
    for step in steps {
        match step {
            Step::Earn(e) => {
                w.lapse(physical_ms(e.hlc));
                if w.gates.left_out.contains(&e.node) {
                    continue;
                }
                *w.lot(e.node, day_of(e.hlc)) += e.mc;
                w.tally(e.node, e.hlc, |t| t.earned += e.mc);
            }
            Step::Entry(e) => {
                w.lapse(physical_ms(e.hlc));
                if w.gates.left_out.contains(&e.origin) {
                    continue;
                }
                match &e.kind {
                    Kind::Offer {
                        to,
                        parts,
                        job,
                        audit,
                    } if parts_ok(parts, day_of(e.hlc)) => w.offer(e, *to, parts, job, audit),
                    Kind::Transfer { to, parts }
                        if *to != e.origin && parts_ok(parts, day_of(e.hlc)) =>
                    {
                        w.transfer(e, *to, parts)
                    }
                    Kind::Receipt {
                        payer,
                        offer_seq,
                        charged_mc,
                        answered,
                    } => w.receipt(e, *payer, *offer_seq, *charged_mc as Mc, answered),
                    // Breaks a shape rule: ignored whole.
                    _ => {}
                }
            }
        }
    }
    w.lapse(now_ms);
    // A node left out shows no balance, whatever was sent to it.
    w.l.lots
        .retain(|(node, _), _| !gates.left_out.contains(node));
    w.l
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credits::entries::SealState;

    const DAY: u32 = 20_000;

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    /// An HLC `min` minutes into day `day`.
    fn at(day: u32, min: u64) -> u64 {
        (day as u64 * DAY_MS + min * 60_000) << 16
    }

    fn earn(node: u8, day: u32, min: u64, mc: Mc) -> Earned {
        Earned {
            node: id(node),
            hlc: at(day, min),
            mc,
        }
    }

    fn entry(origin: u8, seq: u64, hlc: u64, kind: Kind) -> Entry {
        Entry {
            origin: id(origin),
            seq,
            hlc,
            kind,
            seal: SealState::Consistent,
        }
    }

    fn offer(origin: u8, seq: u64, hlc: u64, to: u8, parts: &[(u32, u32)]) -> Entry {
        entry(
            origin,
            seq,
            hlc,
            Kind::Offer {
                to: id(to),
                parts: parts.to_vec(),
                job: None,
                audit: None,
            },
        )
    }

    fn job_offer(origin: u8, seq: u64, hlc: u64, to: u8, parts: &[(u32, u32)]) -> Entry {
        entry(
            origin,
            seq,
            hlc,
            Kind::Offer {
                to: id(to),
                parts: parts.to_vec(),
                job: Some(format!("job{seq}")),
                audit: None,
            },
        )
    }

    fn receipt(origin: u8, seq: u64, hlc: u64, payer: u8, offer_seq: u64, charged: u32) -> Entry {
        entry(
            origin,
            seq,
            hlc,
            Kind::Receipt {
                payer: id(payer),
                offer_seq,
                charged_mc: charged,
                answered: vec!["abuseipdb".into()],
            },
        )
    }

    fn transfer(origin: u8, seq: u64, hlc: u64, to: u8, parts: &[(u32, u32)]) -> Entry {
        entry(
            origin,
            seq,
            hlc,
            Kind::Transfer {
                to: id(to),
                parts: parts.to_vec(),
            },
        )
    }

    fn now(day: u32, min: u64) -> u64 {
        day as u64 * DAY_MS + min * 60_000
    }

    fn ledger(earned: &[Earned], entries: &[Entry], now_ms: u64) -> Ledger {
        run(earned, entries, &Gates::default(), now_ms)
    }

    /// The walk covers 8 days; the week's tallies count only the last 7.
    #[test]
    fn the_week_tallies_leave_out_the_eighth_day() {
        let l = ledger(
            &[earn(1, DAY, 0, 1000), earn(1, DAY + 7, 0, 300)],
            &[
                offer(1, 1, at(DAY, 10), 2, &[(DAY, 400)]),
                receipt(2, 1, at(DAY, 11), 1, 1, 400),
                offer(1, 2, at(DAY + 7, 10), 2, &[(DAY + 7, 100)]),
                receipt(2, 2, at(DAY + 7, 11), 1, 2, 100),
            ],
            now(DAY + 7, 60),
        );
        let (all, week) = (l.tally(&id(1)), l.week_tally(&id(1)));
        assert_eq!((all.earned, all.spent), (1300, 500));
        assert_eq!((week.earned, week.spent), (300, 100));
        assert_eq!(l.week_tally(&id(2)).served, 100);
    }

    #[test]
    fn earn_then_spend() {
        let l = ledger(
            &[earn(1, DAY, 0, 1000)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY, 400)]),
                receipt(2, 9, at(DAY, 11), 1, 5, 400),
            ],
            now(DAY, 60),
        );
        assert_eq!(l.balance(&id(1)), 600);
        assert_eq!(l.balance(&id(2)), 400, "the server gets what is charged");
        assert_eq!(l.held(&id(1)), 0);
        let o = l.offer(&id(1), 5).unwrap();
        assert_eq!(o.state, OfferState::Charged { charged: 400 });
        assert_eq!(o.answered, vec!["abuseipdb".to_string()]);
        let (t1, t2) = (l.tally(&id(1)), l.tally(&id(2)));
        assert_eq!((t1.earned, t1.spent), (1000, 400));
        assert_eq!(t2.served, 400);
        assert_eq!(l.circulating(), 1000);
        // What the server got is of the same day's lot as what was paid.
        assert_eq!(l.by_day(&id(2)), vec![(DAY, 400)]);
    }

    #[test]
    fn an_offer_larger_than_the_lot_holds_what_is_there() {
        let l = ledger(
            &[earn(1, DAY, 0, 300)],
            &[offer(1, 5, at(DAY, 10), 2, &[(DAY, 1000)])],
            now(DAY, 12),
        );
        let o = l.offer(&id(1), 5).unwrap();
        assert_eq!((o.offered, o.covered), (1000, 300));
        assert_eq!((l.balance(&id(1)), l.held(&id(1))), (0, 300));
        // A receipt takes at most what was held.
        let l = ledger(
            &[earn(1, DAY, 0, 300)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY, 1000)]),
                receipt(2, 1, at(DAY, 11), 1, 5, 1000),
            ],
            now(DAY, 12),
        );
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (0, 300));
        // An offer on nothing holds nothing, and nothing goes below zero.
        let l = ledger(
            &[],
            &[offer(1, 5, at(DAY, 10), 2, &[(DAY, 50)])],
            now(DAY, 12),
        );
        assert_eq!(l.offer(&id(1), 5).unwrap().covered, 0);
        assert_eq!(l.balance(&id(1)), 0);
    }

    #[test]
    fn a_receipt_lower_than_the_offer_returns_the_rest() {
        let l = ledger(
            &[earn(1, DAY - 1, 0, 100), earn(1, DAY, 0, 500)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY - 1, 100), (DAY, 300)]),
                receipt(2, 1, at(DAY, 11), 1, 5, 150),
            ],
            now(DAY, 12),
        );
        // Oldest lot first: all 100 of yesterday, 50 of today.
        assert_eq!(l.by_day(&id(1)), vec![(DAY, 450)]);
        assert_eq!(l.by_day(&id(2)), vec![(DAY - 1, 100), (DAY, 50)]);
        // A receipt of nothing frees everything at once.
        let l = ledger(
            &[earn(1, DAY, 0, 500)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY, 300)]),
                receipt(2, 1, at(DAY, 11), 1, 5, 0),
            ],
            now(DAY, 12),
        );
        assert_eq!(
            (l.balance(&id(1)), l.held(&id(1)), l.balance(&id(2))),
            (500, 0, 0)
        );
    }

    #[test]
    fn an_offer_lapses_after_fifteen_minutes_and_a_late_receipt_is_ignored() {
        let es = [
            offer(1, 5, at(DAY, 10), 2, &[(DAY, 300)]),
            receipt(2, 1, at(DAY, 26), 1, 5, 300),
        ];
        let earned = [earn(1, DAY, 0, 500)];
        // Still open a minute before the limit.
        let open = ledger(&earned, &es[..1], now(DAY, 24));
        assert_eq!((open.balance(&id(1)), open.held(&id(1))), (200, 300));
        assert_eq!(open.offer(&id(1), 5).unwrap().state, OfferState::Open);
        let late = ledger(&earned, &es, now(DAY, 30));
        assert_eq!((late.balance(&id(1)), late.balance(&id(2))), (500, 0));
        assert_eq!(late.offer(&id(1), 5).unwrap().state, OfferState::Lapsed);
        // Exactly at the limit it still counts.
        let on_time = ledger(
            &earned,
            &[es[0].clone(), receipt(2, 1, at(DAY, 25), 1, 5, 300)],
            now(DAY, 30),
        );
        assert_eq!(on_time.balance(&id(2)), 300);
        // A receipt dated before its offer does not.
        let early = ledger(
            &earned,
            &[es[0].clone(), receipt(2, 1, at(DAY, 9), 1, 5, 300)],
            now(DAY, 12),
        );
        assert_eq!(early.balance(&id(2)), 0);
        // What lapsed can be offered again.
        let again = ledger(
            &earned,
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY, 500)]),
                offer(1, 6, at(DAY, 40), 3, &[(DAY, 500)]),
            ],
            now(DAY, 41),
        );
        assert_eq!(again.offer(&id(1), 6).unwrap().covered, 500);
    }

    #[test]
    fn only_the_first_receipt_from_the_node_offered_to_counts() {
        let earned = [earn(1, DAY, 0, 500)];
        let o = offer(1, 5, at(DAY, 10), 2, &[(DAY, 300)]);
        let l = ledger(
            &earned,
            &[
                o.clone(),
                receipt(3, 1, at(DAY, 11), 1, 5, 300),
                receipt(2, 1, at(DAY, 12), 1, 5, 100),
                receipt(2, 2, at(DAY, 13), 1, 5, 300),
            ],
            now(DAY, 14),
        );
        assert_eq!(l.balance(&id(3)), 0, "not the node the offer was made to");
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (400, 100));
        // A receipt that names no offer does nothing.
        let l = ledger(
            &earned,
            &[receipt(2, 1, at(DAY, 12), 1, 99, 100)],
            now(DAY, 14),
        );
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (500, 0));
    }

    #[test]
    fn an_offer_to_oneself_costs_nothing() {
        let l = ledger(
            &[earn(1, DAY, 0, 500)],
            &[
                offer(1, 5, at(DAY, 10), 1, &[(DAY, 200)]),
                receipt(1, 6, at(DAY, 11), 1, 5, 200),
            ],
            now(DAY, 12),
        );
        assert_eq!(l.balance(&id(1)), 500);
    }

    #[test]
    fn a_transfer_moves_what_is_there_and_keeps_the_day() {
        let l = ledger(
            &[earn(1, DAY - 2, 0, 100), earn(1, DAY, 0, 50)],
            &[transfer(1, 5, at(DAY, 10), 2, &[(DAY - 2, 500), (DAY, 20)])],
            now(DAY, 12),
        );
        assert_eq!(l.by_day(&id(1)), vec![(DAY, 30)]);
        assert_eq!(l.by_day(&id(2)), vec![(DAY - 2, 100), (DAY, 20)]);
        assert_eq!(
            l.transfers,
            vec![Moved {
                hlc: at(DAY, 10),
                from: id(1),
                to: id(2),
                named: 520,
                moved: 120
            }]
        );
        let (t1, t2) = (l.tally(&id(1)), l.tally(&id(2)));
        assert_eq!((t1.sent, t2.received), (120, 120));
        // What is held for an offer cannot be sent meanwhile.
        let l = ledger(
            &[earn(1, DAY, 0, 100)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY, 80)]),
                transfer(1, 6, at(DAY, 11), 3, &[(DAY, 100)]),
            ],
            now(DAY, 12),
        );
        assert_eq!(l.balance(&id(3)), 20);
    }

    #[test]
    fn a_credit_is_gone_seven_days_after_its_scan_however_often_it_moved() {
        let earned = [earn(1, DAY, 0, 1000)];
        let moved = [transfer(1, 5, at(DAY + 3, 0), 2, &[(DAY, 1000)])];
        let l = ledger(&earned, &moved, now(DAY + 6, 0));
        assert_eq!(l.balance(&id(2)), 1000);
        assert_eq!(l.expiring_today(&id(2)), 1000);
        assert_eq!(l.expiring_today(&id(1)), 0);
        let l = ledger(&earned, &moved, now(DAY + 7, 0));
        assert_eq!(l.balance(&id(2)), 0);
        assert_eq!(l.circulating(), 0);
        // An entry that names a lot on its eighth day is ignored whole.
        let stale = [transfer(
            1,
            5,
            at(DAY + 7, 0),
            2,
            &[(DAY, 500), (DAY + 7, 1)],
        )];
        let l = ledger(
            &[earn(1, DAY, 0, 1000), earn(1, DAY + 7, 0, 10)],
            &stale,
            now(DAY + 7, 1),
        );
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (10, 0));
        // So is a transfer to oneself.
        let own = [transfer(1, 5, at(DAY, 5), 1, &[(DAY, 500)])];
        assert!(ledger(&earned, &own, now(DAY, 6)).transfers.is_empty());
    }

    #[test]
    fn a_receipt_moves_the_full_amount() {
        let l = ledger(
            &[earn(1, DAY - 1, 0, 3), earn(1, DAY, 0, 10)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY - 1, 3), (DAY, 4)]),
                receipt(2, 1, at(DAY, 11), 1, 5, 7),
            ],
            now(DAY, 12),
        );
        assert_eq!(l.by_day(&id(2)), vec![(DAY - 1, 3), (DAY, 4)]);
        assert_eq!(
            l.offer(&id(1), 5).unwrap().state,
            OfferState::Charged { charged: 7 }
        );
        assert_eq!((l.tally(&id(1)).spent, l.tally(&id(2)).served), (7, 7));
    }

    #[test]
    fn a_job_offer_lapses_after_the_longest_run() {
        let earned = [earn(1, DAY, 0, 500)];
        // Charged four hours later: still open, so it counts.
        let l = ledger(
            &earned,
            &[
                job_offer(1, 5, at(DAY, 10), 2, &[(DAY, 200)]),
                receipt(2, 1, at(DAY, 250), 1, 5, 200),
            ],
            now(DAY, 260),
        );
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (300, 200));
        assert_eq!(l.offer(&id(1), 5).unwrap().job.as_deref(), Some("job5"));
        // Never charged: held until MAX_RUN_SECS + margin, then returned.
        let lapse_min = 10 + crate::credits::JOB_OFFER_TTL_MS / 60_000;
        let open = ledger(
            &earned,
            &[job_offer(1, 5, at(DAY, 10), 2, &[(DAY, 200)])],
            now(DAY, lapse_min),
        );
        assert_eq!(open.balance(&id(1)), 300);
        assert_eq!(open.offer(&id(1), 5).unwrap().state, OfferState::Open);
        let gone = ledger(
            &earned,
            &[job_offer(1, 5, at(DAY, 10), 2, &[(DAY, 200)])],
            now(DAY, lapse_min + 1),
        );
        assert_eq!(gone.balance(&id(1)), 500);
        // A receipt after the lapse is ignored.
        let late = ledger(
            &earned,
            &[
                job_offer(1, 5, at(DAY, 10), 2, &[(DAY, 200)]),
                receipt(2, 1, at(DAY, lapse_min + 2), 1, 5, 200),
            ],
            now(DAY, lapse_min + 3),
        );
        assert_eq!((late.balance(&id(1)), late.balance(&id(2))), (500, 0));
    }

    #[test]
    fn entries_and_earnings_of_a_node_left_out_do_not_count() {
        let earned = [earn(1, DAY, 0, 1000), earn(2, DAY, 0, 1000)];
        let entries = [
            transfer(2, 1, at(DAY, 5), 3, &[(DAY, 400)]),
            offer(1, 5, at(DAY, 10), 2, &[(DAY, 300)]),
            receipt(2, 2, at(DAY, 11), 1, 5, 300),
        ];
        let out = Gates {
            left_out: [id(2)].into(),
            ..Default::default()
        };
        let l = run(&earned, &entries, &out, now(DAY, 30));
        assert_eq!(l.balance(&id(2)), 0, "blocked or forked: nothing");
        assert_eq!(l.balance(&id(3)), 0, "its transfers move nothing");
        // Its receipt does not count either: the offer lapses.
        assert_eq!(l.balance(&id(1)), 1000);
        assert_eq!(l.offer(&id(1), 5).unwrap().state, OfferState::Lapsed);
        // Credits sent to it are lost to everyone.
        let sent = [transfer(1, 6, at(DAY, 12), 2, &[(DAY, 100)])];
        let l = run(&earned, &sent, &out, now(DAY, 30));
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (900, 0));
    }

    #[test]
    fn the_receipts_of_a_member_that_does_not_earn_here_move_nothing() {
        // 1 pays 2 for a lookup; 2 fails the rules gate here.
        let earned = [earn(1, DAY, 0, 1000)];
        let entries = [
            offer(1, 1, at(DAY, 1), 2, &[(DAY, 300)]),
            receipt(2, 1, at(DAY, 2), 1, 1, 300),
        ];
        let gates = Gates {
            no_sales: [id(2)].into(),
            ..Default::default()
        };
        let l = run(&earned, &entries, &gates, now(DAY, 3));
        assert_eq!(
            (l.balance(&id(1)), l.balance(&id(2))),
            (700, 0),
            "held, not paid"
        );
        let l = run(&earned, &entries, &gates, now(DAY, 20));
        assert_eq!(l.balance(&id(1)), 1000, "lapsed back to the payer");
        assert_eq!(l.offers[0].state, OfferState::Lapsed);
    }

    #[test]
    fn a_scanner_failing_the_audit_gates_is_not_paid_for_scans_but_for_lookups() {
        let earned = [earn(1, DAY, 0, 1000)];
        let entries = [
            job_offer(1, 1, at(DAY, 1), 2, &[(DAY, 100)]),
            receipt(2, 1, at(DAY, 2), 1, 1, 100),
            offer(1, 2, at(DAY, 3), 2, &[(DAY, 50)]),
            receipt(2, 2, at(DAY, 4), 1, 2, 50),
        ];
        let gates = Gates {
            no_scan_sales: [id(2)].into(),
            ..Default::default()
        };
        let l = run(&earned, &entries, &gates, now(DAY, 5));
        assert_eq!(l.balance(&id(2)), 50, "the lookup only");
        assert_eq!(
            l.offers[0].state,
            OfferState::Open,
            "the scan offer waits to lapse"
        );
    }

    /// Review focus: entries reach nodes in different orders.
    #[test]
    fn the_same_entries_in_any_arrival_order_give_the_same_balances() {
        let earned = vec![
            earn(1, DAY - 1, 30, 1000),
            earn(2, DAY, 1, 250),
            earn(1, DAY, 2, 2000),
            earn(3, DAY, 2, 500),
        ];
        let entries = vec![
            offer(1, 5, at(DAY, 10), 2, &[(DAY - 1, 800), (DAY, 300)]),
            transfer(3, 1, at(DAY, 10), 1, &[(DAY, 500)]),
            receipt(2, 4, at(DAY, 11), 1, 5, 900),
            transfer(1, 6, at(DAY, 12), 3, &[(DAY - 1, 1000), (DAY, 100)]),
            offer(2, 5, at(DAY, 13), 3, &[(DAY, 600), (DAY - 1, 600)]),
            receipt(3, 2, at(DAY, 40), 2, 5, 600),
            transfer(2, 6, at(DAY, 41), 1, &[(DAY - 1, 5000), (DAY, 5000)]),
        ];
        let want = ledger(&earned, &entries, now(DAY, 50));
        let mut e2 = entries.clone();
        let mut g2 = earned.clone();
        for round in 0..6 {
            e2.rotate_left(round % entries.len() + 1);
            if round % 2 == 0 {
                e2.reverse();
                g2.reverse();
            }
            let got = ledger(&g2, &e2, now(DAY, 50));
            assert_eq!(got.lots, want.lots, "round {round}");
            assert_eq!(got.offers, want.offers, "round {round}");
        }
        // And it is what the entries say: nothing appears from nowhere.
        let total: Mc = earned.iter().map(|e| e.mc).sum();
        let all: Mc =
            want.lots.values().sum::<Mc>() + want.offers.iter().map(Offer::held_now).sum::<Mc>();
        assert_eq!(all, total);
    }

    #[test]
    fn what_can_be_spent_is_drawn_from_the_oldest_lots() {
        let l = ledger(
            &[
                earn(1, DAY - 6, 0, 100),
                earn(1, DAY - 1, 0, 50),
                earn(1, DAY, 0, 500),
            ],
            &[],
            now(DAY, 10),
        );
        assert_eq!(
            l.spendable_parts(&id(1), 180),
            Some(vec![(DAY - 6, 100), (DAY - 1, 50), (DAY, 30)])
        );
        assert_eq!(
            l.spendable_parts(&id(1), 650),
            Some(vec![(DAY - 6, 100), (DAY - 1, 50), (DAY, 500)])
        );
        assert_eq!(l.spendable_parts(&id(1), 651), None);
        assert_eq!(l.spendable_parts(&id(1), 0), None);
        assert_eq!(l.spendable_parts(&id(2), 1), None);
        // Lots before a first day are left out.
        let lots = l.by_day(&id(1));
        assert_eq!(
            parts_from(&lots, 180, DAY - 1),
            Some(vec![(DAY - 1, 50), (DAY, 130)])
        );
        assert_eq!(parts_from(&lots, 551, DAY - 1), None);
    }
}
