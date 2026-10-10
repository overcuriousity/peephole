//! The ledger: every balance, from the pool credited to the verified
//! listeners (`credits::pool`) and what the log says about payments. A
//! pure function of its input, so every node that holds the same entries
//! and counts the same reach reports arrives at the same balances, in
//! whatever order the entries reached it.
//!
//! A credit belongs to a lot: a node and the UTC day of the pool it came
//! from. It keeps its lot when it changes hands and is gone 7 days after
//! that day.
//!
//! The gates (who does not earn here) are read as they stand now and
//! applied to the whole walk, but only at its end: a gated member's sales
//! and pool shares settle like anyone's, so whoever it paid keeps that.
//! What it still holds of that income at the end goes back to the payers
//! of those sales, by what each paid, and the pool's part is burned
//! ([`Walk::claw_back`]).
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
    /// out): they keep none of what their receipts and pool shares
    /// brought them ([`Walk::claw_back`]).
    pub no_sales: HashSet<NodeId>,
    /// Scanners failing the audit gates here: they keep none of what their
    /// receipts for scan jobs brought them.
    pub no_scan_sales: HashSet<NodeId>,
    /// The HLC of each scan job's done status as the log holds it, by job
    /// uid: a receipt for the job's offer dated at or after it moves
    /// nothing ([`charged_in_time`]).
    pub done: HashMap<String, u64>,
}

/// Whether a scan receipt dated `receipt_hlc` counts against its job's
/// done status `done_hlc` (None: none held yet): only one written before
/// it. The done status designates the scan for an audit
/// (`credits::audit::seed`), so a scanner charging after it could charge
/// only the scans it sees are not designated. `credits::audit::job_paid`
/// applies the same rule.
pub fn charged_in_time(receipt_hlc: u64, done_hlc: Option<u64>) -> bool {
    done_hlc.is_none_or(|d| receipt_hlc < d)
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
    /// Taken back at the end of the walk: what it held of the income a
    /// gate denies it ([`Gates`]).
    pub withheld: Mc,
    /// Given back to it as the payer of a gated member's sales.
    pub refunded: Mc,
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
    /// What gated members still held of their pool shares at the end of
    /// the walk: gone, given to nobody.
    pub burned: Mc,
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

/// The oldest lot day an offer written at `now_ms` that lives `ttl_ms`
/// may draw from: a lot that dies before the offer can be charged is left
/// out (a receipt would hand the server credits already gone).
pub fn first_day_for(now_ms: u64, ttl_ms: u64) -> u32 {
    let last = ((now_ms + ttl_ms) / DAY_MS) as u32;
    last.saturating_sub(LOT_DAYS - 1)
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

/// The income a gate denies one member, as the walk settled it.
#[derive(Default)]
struct Gated {
    /// Its pool shares.
    pool: Mc,
    /// What its gated receipts moved to it, by payer.
    paid_by: BTreeMap<NodeId, Mc>,
}

struct Walk<'a> {
    l: Ledger,
    gates: &'a Gates,
    /// The HLC the last 7 days start at.
    week_from: u64,
    gated: BTreeMap<NodeId, Gated>,
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
        // A scan receipt written after the job's done status pays nothing;
        // the offer lapses back.
        if let Some(job) = &self.l.offers[i].job
            && !charged_in_time(e.hlc, self.gates.done.get(job).copied())
        {
            return;
        }
        // A member failing a gate here keeps none of this sale: noted, and
        // settled at the end of the walk.
        let gated = self.gates.no_sales.contains(&e.origin)
            || (self.l.offers[i].job.is_some() && self.gates.no_scan_sales.contains(&e.origin));
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
        if gated && paid > 0 && payer != e.origin {
            let g = self.gated.entry(e.origin).or_default();
            *g.paid_by.entry(payer).or_default() += paid;
        }
    }

    /// At the end of the walk, take from each gated member, in key order,
    /// what it still holds of the income its gates deny it: the least of
    /// its balance and that income, from its oldest lots. Of that, the
    /// receipts' share of the income goes back to their payers, split by
    /// what each paid (the odd millicredits to the lowest keys), and the
    /// pool's share is burned. Whatever it spent stays spent. A refund to a
    /// gated payer counts in that payer's balance when its turn comes.
    fn claw_back(&mut self, now_ms: u64) {
        let hlc = now_ms << 16;
        for (node, g) in std::mem::take(&mut self.gated) {
            if self.gates.left_out.contains(&node) {
                continue;
            }
            let receipts: Mc = g.paid_by.values().sum();
            let income = receipts + g.pool;
            let take = self.l.balance(&node).min(income);
            if take == 0 {
                continue;
            }
            let part = |of: Mc, n: Mc, d: Mc| (of as u128 * n as u128 / d as u128) as Mc;
            let refund = part(take, receipts, income);
            // Each payer's part (the odd millicredits to the lowest keys),
            // then the burn (None).
            let mut out: Vec<(Option<NodeId>, Mc)> = g
                .paid_by
                .iter()
                .map(|(p, mc)| (Some(*p), part(refund, *mc, receipts)))
                .collect();
            let odd = refund - out.iter().map(|(_, mc)| mc).sum::<Mc>();
            for (_, mc) in out.iter_mut().take(odd as usize) {
                *mc += 1;
            }
            out.push((None, take - refund));
            // From the oldest lots, keeping their days.
            let mut lots = self.l.by_day(&node);
            let mut i = 0;
            for (to, mut mc) in out {
                if let Some(p) = to {
                    self.tally(p, hlc, |t| t.refunded += mc);
                }
                while mc > 0 && i < lots.len() {
                    let day = lots[i].0;
                    let t = lots[i].1.min(mc);
                    lots[i].1 -= t;
                    mc -= t;
                    *self.lot(node, day) -= t;
                    match to {
                        Some(p) => *self.lot(p, day) += t,
                        None => self.l.burned += t,
                    }
                    if lots[i].1 == 0 {
                        i += 1;
                    }
                }
            }
            self.tally(node, hlc, |t| t.withheld += take);
        }
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
/// and their entries move nothing (what others sent them is lost); those
/// in `no_sales` keep none of their receipts and pool shares, those in
/// `no_scan_sales` none of their scan receipts, as far as they still hold
/// them at the end ([`Walk::claw_back`]).
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
        gated: BTreeMap::new(),
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
                if w.gates.no_sales.contains(&e.node) {
                    w.gated.entry(e.node).or_default().pool += e.mc;
                }
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
    w.claw_back(now_ms);
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

    /// A scan receipt dated at or after its job's done status moves
    /// nothing: the done status designates the scan for an audit, and a
    /// scanner charging after it could charge only the scans it sees are
    /// not designated. The offer lapses back to the arbiter.
    #[test]
    fn a_scan_receipt_after_the_jobs_done_status_pays_nothing() {
        let earned = [earn(1, DAY, 0, 1000)];
        // job1, offered at minute 1, charged at minute 5.
        let entries = [
            job_offer(1, 1, at(DAY, 1), 2, &[(DAY, 100)]),
            receipt(2, 1, at(DAY, 5), 1, 1, 100),
        ];
        let done_at = |min: u64| Gates {
            done: [("job1".to_string(), at(DAY, min))].into(),
            ..Default::default()
        };
        // Done before the receipt, or at its instant: unpaid, held until
        // the offer lapses, then the arbiter's again.
        for done in [
            done_at(4),
            Gates {
                done: [("job1".to_string(), at(DAY, 5))].into(),
                ..Default::default()
            },
        ] {
            let l = run(&earned, &entries, &done, now(DAY, 6));
            assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (900, 0));
            assert_eq!(l.offers[0].state, OfferState::Open);
            let lapsed = now(DAY, 2 + crate::credits::JOB_OFFER_TTL_MS / 60_000);
            let l = run(&earned, &entries, &done, lapsed);
            assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (1000, 0));
            assert_eq!(l.offers[0].state, OfferState::Lapsed);
            conserved(&l, &earned);
        }
        // Charged before the done status: paid.
        let l = run(&earned, &entries, &done_at(6), now(DAY, 7));
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (900, 100));
        assert_eq!(l.offers[0].state, OfferState::Charged { charged: 100 });
        // No done status held yet: paid; once one dated earlier arrives,
        // the count says unpaid.
        let l = run(&earned, &entries, &Gates::default(), now(DAY, 7));
        assert_eq!(l.balance(&id(2)), 100);
        let l = run(&earned, &entries, &done_at(3), now(DAY, 7));
        assert_eq!(l.balance(&id(2)), 0);
        // A lookup receipt is no scan receipt, whatever is done.
        let lookup = [
            offer(1, 1, at(DAY, 1), 2, &[(DAY, 100)]),
            receipt(2, 1, at(DAY, 5), 1, 1, 100),
        ];
        let l = run(&earned, &lookup, &done_at(3), now(DAY, 7));
        assert_eq!(l.balance(&id(2)), 100);
        assert!(charged_in_time(at(DAY, 5), Some(at(DAY, 6))));
        assert!(!charged_in_time(at(DAY, 5), Some(at(DAY, 5))));
        assert!(charged_in_time(at(DAY, 5), None));
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

    /// Every credit the pool made is in a lot, held by an open offer,
    /// burned, or of an expired lot: nothing appears or vanishes otherwise.
    fn conserved(l: &Ledger, earned: &[Earned]) {
        let total: Mc = earned.iter().map(|e| e.mc).sum();
        let all: Mc = l.lots.values().sum::<Mc>()
            + l.offers.iter().map(Offer::held_now).sum::<Mc>()
            + l.burned;
        assert_eq!(all, total, "conserved");
    }

    /// The gate applies to the whole walk: a gated seller's sales settle as
    /// they were made, so whoever it paid keeps that; what it still holds
    /// of them at the end goes back to its payers.
    #[test]
    fn a_gated_sellers_unspent_income_goes_back_to_its_payers() {
        // 1 pays 2 500 for a lookup; 2 pays 3 300; 2 fails the rules gate.
        let earned = [earn(1, DAY, 0, 1000)];
        let entries = [
            offer(1, 1, at(DAY, 1), 2, &[(DAY, 500)]),
            receipt(2, 1, at(DAY, 2), 1, 1, 500),
            offer(2, 2, at(DAY, 3), 3, &[(DAY, 300)]),
            receipt(3, 1, at(DAY, 4), 2, 2, 300),
        ];
        let gates = Gates {
            no_sales: [id(2)].into(),
            ..Default::default()
        };
        let l = run(&earned, &entries, &gates, now(DAY, 5));
        assert_eq!(l.balance(&id(3)), 300, "the one it paid keeps it");
        assert_eq!(l.balance(&id(1)), 700, "the payer gets back the rest");
        assert_eq!(l.balance(&id(2)), 0, "the gated seller keeps none");
        assert_eq!(l.offers[0].state, OfferState::Charged { charged: 500 });
        assert_eq!(
            (l.tally(&id(1)).refunded, l.tally(&id(2)).withheld),
            (200, 200)
        );
        assert_eq!(l.burned, 0);
        conserved(&l, &earned);
        // It spent nothing: the payer has it all back.
        let l = run(&earned, &entries[..2], &gates, now(DAY, 5));
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (1000, 0));
        conserved(&l, &earned);
        // While its offer is open what it holds stays with it; once the
        // offer lapses back, the walk takes that too.
        let l = run(&earned, &entries[..3], &gates, now(DAY, 5));
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (700, 0));
        assert_eq!(l.held(&id(2)), 300);
        let l = run(&earned, &entries[..3], &gates, now(DAY, 30));
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (1000, 0));
        conserved(&l, &earned);
    }

    /// Several payers share what is given back by what each paid; the
    /// odd millicredits go to the lowest keys.
    #[test]
    fn what_goes_back_is_shared_by_what_each_payer_paid() {
        let earned = [earn(1, DAY, 0, 1000), earn(4, DAY, 0, 1000)];
        let entries = [
            offer(1, 1, at(DAY, 1), 2, &[(DAY, 300)]),
            receipt(2, 1, at(DAY, 2), 1, 1, 300),
            offer(4, 1, at(DAY, 3), 2, &[(DAY, 100)]),
            receipt(2, 2, at(DAY, 4), 4, 1, 100),
            transfer(2, 3, at(DAY, 5), 3, &[(DAY, 200)]),
        ];
        let gates = Gates {
            no_sales: [id(2)].into(),
            ..Default::default()
        };
        let l = run(&earned, &entries, &gates, now(DAY, 6));
        assert_eq!(l.balance(&id(1)), 700 + 150);
        assert_eq!(l.balance(&id(4)), 900 + 50);
        assert_eq!((l.balance(&id(2)), l.balance(&id(3))), (0, 200));
        conserved(&l, &earned);
        // 2 mc back to three payers of 1 mc each: the two lowest keys.
        let earned = [
            earn(1, DAY, 0, 10),
            earn(4, DAY, 0, 10),
            earn(5, DAY, 0, 10),
        ];
        let mut entries = vec![];
        for (n, payer) in [1u8, 4, 5].into_iter().enumerate() {
            let at_min = 1 + 2 * n as u64;
            entries.push(offer(payer, 1, at(DAY, at_min), 2, &[(DAY, 1)]));
            entries.push(receipt(2, n as u64 + 1, at(DAY, at_min + 1), payer, 1, 1));
        }
        entries.push(transfer(2, 9, at(DAY, 10), 3, &[(DAY, 1)]));
        let l = run(&earned, &entries, &gates, now(DAY, 11));
        assert_eq!(
            (l.balance(&id(1)), l.balance(&id(4)), l.balance(&id(5))),
            (10, 10, 9)
        );
        conserved(&l, &earned);
    }

    /// A gated member's pool share is credited, so what it paid stays paid;
    /// what it still holds of it at the end is burned, given to nobody.
    #[test]
    fn a_gated_members_unspent_pool_share_is_burned() {
        let earned = [earn(2, DAY, 0, 400)];
        let entries = [transfer(2, 1, at(DAY, 1), 3, &[(DAY, 100)])];
        let gates = Gates {
            no_sales: [id(2)].into(),
            ..Default::default()
        };
        let l = run(&earned, &entries, &gates, now(DAY, 2));
        assert_eq!((l.balance(&id(2)), l.balance(&id(3))), (0, 100));
        assert_eq!(l.burned, 300);
        conserved(&l, &earned);
        // Pool and sales both gated: what is left is split by their shares
        // of the gated income, the sales' part back to the payer.
        let earned = [earn(2, DAY, 0, 400), earn(1, DAY, 0, 1000)];
        let entries = [
            offer(1, 1, at(DAY, 1), 2, &[(DAY, 500)]),
            receipt(2, 1, at(DAY, 2), 1, 1, 500),
            transfer(2, 2, at(DAY, 3), 3, &[(DAY, 300)]),
        ];
        let l = run(&earned, &entries, &gates, now(DAY, 4));
        // Left 600 of 900 gated: 500/900 of it (333) back, the rest burned.
        assert_eq!(l.balance(&id(1)), 500 + 333);
        assert_eq!((l.balance(&id(2)), l.balance(&id(3))), (0, 300));
        assert_eq!(l.burned, 267);
        conserved(&l, &earned);
    }

    #[test]
    fn a_scanner_failing_the_audit_gates_keeps_its_lookup_sales_only() {
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
        assert_eq!(l.balance(&id(1)), 950, "the scan's price back");
        assert_eq!(l.offers[0].state, OfferState::Charged { charged: 100 });
        conserved(&l, &earned);
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
        // With a gated seller: the same in any order, and still conserved.
        let gates = Gates {
            no_sales: [id(2)].into(),
            ..Default::default()
        };
        let want = run(&earned, &entries, &gates, now(DAY, 50));
        let (mut e2, mut g2) = (entries.clone(), earned.clone());
        e2.reverse();
        g2.reverse();
        let got = run(&g2, &e2, &gates, now(DAY, 50));
        assert_eq!((got.lots, got.burned), (want.lots.clone(), want.burned));
        conserved(&want, &earned);
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
