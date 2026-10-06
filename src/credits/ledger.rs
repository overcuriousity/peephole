//! The ledger: every balance, from what scans earned and what the log
//! says about payments. A pure function of its input, so every node that
//! holds the same entries and judges the same scans arrives at the same
//! balances, in whatever order the entries reached it.
//!
//! A credit belongs to a lot: a node and the UTC day it was earned. It
//! keeps its lot when it changes hands and is gone 7 days after the scan
//! that created it.
use super::entries::{Entry, Kind, parts_ok};
use super::{DAY_MS, LOT_DAYS, Mc, OFFER_TTL_MS, day_of};
use crate::cluster::hlc::physical_ms;
use crate::cluster::identity::NodeId;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Credits a completed scan gave a node (`earn::pay` decides how many).
#[derive(Debug, Clone, PartialEq)]
pub struct Earned {
    pub node: NodeId,
    /// The HLC of the scan result: it dates the lot.
    pub hlc: u64,
    pub mc: Mc,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OfferState {
    /// Written, no receipt yet, not 15 minutes old.
    Open,
    Charged {
        charged: Mc,
        to_server: Mc,
        destroyed: Mc,
    },
    /// 15 minutes passed without a receipt: everything went back.
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
}

impl Offer {
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
    /// Its half of what it charged others.
    pub served: Mc,
    /// The half of its payments that went to nobody.
    pub destroyed: Mc,
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
    /// The UTC day balances are read for.
    pub today: u32,
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
        if mc == 0 {
            return None;
        }
        let mut left = mc;
        let mut parts = vec![];
        for (day, have) in self.by_day(node) {
            let take = have.min(left).min(u32::MAX as Mc);
            parts.push((day, take as u32));
            left -= take;
            if left == 0 {
                return Some(parts);
            }
        }
        None
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
    left_out: &'a HashSet<NodeId>,
}

impl Walk<'_> {
    fn lot(&mut self, node: NodeId, day: u32) -> &mut Mc {
        self.l.lots.entry((node, day)).or_insert(0)
    }

    fn tally(&mut self, node: NodeId) -> &mut Tally {
        self.l.tallies.entry(node).or_default()
    }

    /// Give back what offers older than 15 minutes still hold.
    fn lapse(&mut self, now_ms: u64) {
        for i in 0..self.l.offers.len() {
            let o = &self.l.offers[i];
            if o.state != OfferState::Open || now_ms <= physical_ms(o.hlc) + OFFER_TTL_MS {
                continue;
            }
            let (payer, held) = (o.payer, std::mem::take(&mut self.l.offers[i].held));
            self.l.offers[i].state = OfferState::Lapsed;
            for (day, mc) in held {
                *self.lot(payer, day) += mc;
            }
        }
    }

    fn offer(&mut self, e: &Entry, to: NodeId, parts: &[(u32, u32)]) {
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
                && physical_ms(e.hlc) <= physical_ms(o.hlc) + OFFER_TTL_MS
        }) else {
            return;
        };
        let held = std::mem::take(&mut self.l.offers[i].held);
        let mut left = charged.min(held.iter().map(|(_, mc)| mc).sum());
        let (paid, mut to_server) = (left, 0);
        for (day, mc) in held {
            let take = mc.min(left);
            left -= take;
            let half = take / 2;
            to_server += half;
            *self.lot(e.origin, day) += half;
            *self.lot(payer, day) += mc - take;
        }
        let destroyed = paid - to_server;
        let o = &mut self.l.offers[i];
        o.answered = answered.to_vec();
        o.state = OfferState::Charged {
            charged: paid,
            to_server,
            destroyed,
        };
        let t = self.tally(payer);
        t.spent += paid;
        t.destroyed += destroyed;
        self.tally(e.origin).served += to_server;
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
        self.tally(e.origin).sent += moved;
        self.tally(to).received += moved;
    }
}

/// Walk what was earned and every payment in order, and return where
/// every credit is at `now_ms`. Nodes in `left_out` (blocked here, or
/// shown to have two histories) earn nothing and their entries move
/// nothing; what others sent them is lost.
pub fn run(
    earned: &[Earned],
    entries: &[Entry],
    left_out: &HashSet<NodeId>,
    now_ms: u64,
) -> Ledger {
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
        left_out,
    };
    for step in steps {
        match step {
            Step::Earn(e) => {
                w.lapse(physical_ms(e.hlc));
                if w.left_out.contains(&e.node) {
                    continue;
                }
                *w.lot(e.node, day_of(e.hlc)) += e.mc;
                w.tally(e.node).earned += e.mc;
            }
            Step::Entry(e) => {
                w.lapse(physical_ms(e.hlc));
                if w.left_out.contains(&e.origin) {
                    continue;
                }
                match &e.kind {
                    Kind::Offer { to, parts } if parts_ok(parts, day_of(e.hlc)) => {
                        w.offer(e, *to, parts)
                    }
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
    w.l.lots.retain(|(node, _), _| !left_out.contains(node));
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
        run(earned, entries, &HashSet::new(), now_ms)
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
        assert_eq!(l.balance(&id(2)), 200, "half goes to the server");
        assert_eq!(l.held(&id(1)), 0);
        let o = l.offer(&id(1), 5).unwrap();
        assert_eq!(
            o.state,
            OfferState::Charged {
                charged: 400,
                to_server: 200,
                destroyed: 200
            }
        );
        assert_eq!(o.answered, vec!["abuseipdb".to_string()]);
        let (t1, t2) = (l.tally(&id(1)), l.tally(&id(2)));
        assert_eq!((t1.earned, t1.spent, t1.destroyed), (1000, 400, 200));
        assert_eq!(t2.served, 200);
        assert_eq!(l.circulating(), 800);
        // The server's half is of the same day's lot as what was paid.
        assert_eq!(l.by_day(&id(2)), vec![(DAY, 200)]);
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
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (0, 150));
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
        assert_eq!(l.by_day(&id(2)), vec![(DAY - 1, 50), (DAY, 25)]);
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
        assert_eq!(on_time.balance(&id(2)), 150);
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
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (400, 50));
        // A receipt that names no offer does nothing.
        let l = ledger(
            &earned,
            &[receipt(2, 1, at(DAY, 12), 1, 99, 100)],
            now(DAY, 14),
        );
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (500, 0));
    }

    #[test]
    fn an_offer_to_oneself_costs_half() {
        let l = ledger(
            &[earn(1, DAY, 0, 500)],
            &[
                offer(1, 5, at(DAY, 10), 1, &[(DAY, 200)]),
                receipt(1, 6, at(DAY, 11), 1, 5, 200),
            ],
            now(DAY, 12),
        );
        assert_eq!(l.balance(&id(1)), 400);
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
    fn halves_round_down_and_the_remainder_is_destroyed() {
        let l = ledger(
            &[earn(1, DAY - 1, 0, 3), earn(1, DAY, 0, 10)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY - 1, 3), (DAY, 4)]),
                receipt(2, 1, at(DAY, 11), 1, 5, 7),
            ],
            now(DAY, 12),
        );
        // 3 → 1 to the server, 2 destroyed; 4 → 2 and 2.
        assert_eq!(l.by_day(&id(2)), vec![(DAY - 1, 1), (DAY, 2)]);
        assert_eq!(
            l.offer(&id(1), 5).unwrap().state,
            OfferState::Charged {
                charged: 7,
                to_server: 3,
                destroyed: 4
            }
        );
    }

    #[test]
    fn entries_and_earnings_of_a_node_left_out_do_not_count() {
        let earned = [earn(1, DAY, 0, 1000), earn(2, DAY, 0, 1000)];
        let entries = [
            transfer(2, 1, at(DAY, 5), 3, &[(DAY, 400)]),
            offer(1, 5, at(DAY, 10), 2, &[(DAY, 300)]),
            receipt(2, 2, at(DAY, 11), 1, 5, 300),
        ];
        let out: HashSet<NodeId> = [id(2)].into();
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
        let destroyed: Mc = want.tallies.values().map(|t| t.destroyed).sum();
        let all: Mc =
            want.lots.values().sum::<Mc>() + want.offers.iter().map(Offer::held_now).sum::<Mc>();
        assert_eq!(all + destroyed, total);
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
    }
}
