//! What an automatic buyer pays at most for one unit of a good (protocol
//! 9, "free market"). Credits expire [`LOT_DAYS`] after their day, so
//! keeping them gains nothing: each lot is spread evenly over the hours it
//! has left, the hour's budget split equally across the goods some buyer
//! loop wants, and each good's share across the units wanted. The bid
//! comes only from this node's own book and its own buyer loops; nothing
//! a peer says can raise it.
use super::{LOT_DAYS, Mc};
use std::collections::HashMap;

const HOUR_MS: u64 = 3_600_000;

/// What this node can spend in the coming hour: each of `lots` (`(day,
/// mc)`, as [`super::pay::Spending::lots`] has them) over the hours it has
/// left until `day + LOT_DAYS`, at least one. Lots that expired by `today`
/// count nothing.
pub fn hourly_budget(lots: &[(u32, Mc)], today: u32, now_ms: u64) -> Mc {
    lots.iter()
        .filter(|(day, _)| day + LOT_DAYS > today)
        .map(|(day, mc)| {
            let end_ms = (*day + LOT_DAYS) as u64 * super::DAY_MS;
            let left_ms = end_ms.saturating_sub(now_ms).max(HOUR_MS);
            (*mc as u128 * HOUR_MS as u128 / left_ms as u128) as Mc
        })
        .sum()
}

/// Units of each good this node's buyer loops want in the coming hour:
/// each loop sets its own good (its backlog, capped at what it can buy in
/// an hour).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Wants(HashMap<String, u32>);

impl Wants {
    pub fn set(&mut self, good: &str, units: u32) {
        if units == 0 {
            self.0.remove(good);
        } else {
            self.0.insert(good.to_string(), units);
        }
    }

    pub fn get(&self, good: &str) -> u32 {
        self.0.get(good).copied().unwrap_or(0)
    }

    /// Goods with at least one wanted unit.
    pub fn goods(&self) -> usize {
        self.0.len()
    }
}

/// The most this node pays for one unit of `good`: `budget` split equally
/// over the goods with wants, that share over the units of `good` wanted.
/// 0 when `good` is not wanted (or nothing is to spend): then the node
/// buys only what is free.
pub fn bid(budget: Mc, wants: &Wants, good: &str) -> Mc {
    match wants.get(good) {
        0 => 0,
        units => budget / wants.goods() as Mc / units as Mc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credits::{CREDIT, DAY_MS};

    const TODAY: u32 = 20_000;
    /// The start of `TODAY`: a lot of `TODAY - 6` has 24 h left, one of
    /// `TODAY` has 168 h.
    const NOW: u64 = TODAY as u64 * DAY_MS;

    fn wants(list: &[(&str, u32)]) -> Wants {
        let mut w = Wants::default();
        for (g, n) in list {
            w.set(g, *n);
        }
        w
    }

    #[test]
    fn no_balance_bids_nothing() {
        let budget = hourly_budget(&[], TODAY, NOW);
        assert_eq!(budget, 0);
        assert_eq!(bid(budget, &wants(&[("rdns", 5)]), "rdns"), 0);
    }

    #[test]
    fn a_week_old_lot_of_168_credits_bids_one_credit_an_hour() {
        let budget = hourly_budget(&[(TODAY, 168 * CREDIT)], TODAY, NOW);
        assert_eq!(budget, CREDIT);
        assert_eq!(bid(budget, &wants(&[("rdns", 1)]), "rdns"), CREDIT);
    }

    #[test]
    fn two_goods_bid_half_each() {
        let budget = hourly_budget(&[(TODAY, 168 * CREDIT)], TODAY, NOW);
        let w = wants(&[("rdns", 1), ("shodan", 1)]);
        assert_eq!(bid(budget, &w, "rdns"), CREDIT / 2);
        assert_eq!(bid(budget, &w, "shodan"), CREDIT / 2);
        // And within a good, the units share it.
        let w = wants(&[("rdns", 4), ("shodan", 1)]);
        assert_eq!(bid(budget, &w, "rdns"), CREDIT / 8);
    }

    #[test]
    fn an_expiring_lot_weighs_more_an_hour_than_a_fresh_one() {
        let fresh = hourly_budget(&[(TODAY, 168 * CREDIT)], TODAY, NOW);
        let expiring = hourly_budget(&[(TODAY - 6, 168 * CREDIT)], TODAY, NOW);
        assert!(expiring > fresh, "{expiring} vs {fresh}");
        assert_eq!(expiring, 7 * CREDIT);
        // Both together: their hours add up.
        let both = hourly_budget(
            &[(TODAY - 6, 168 * CREDIT), (TODAY, 168 * CREDIT)],
            TODAY,
            NOW,
        );
        assert_eq!(both, 8 * CREDIT);
        // In its last hour a lot is spent whole; an expired one counts nothing.
        let last = NOW + DAY_MS - HOUR_MS / 2;
        assert_eq!(hourly_budget(&[(TODAY - 6, CREDIT)], TODAY, last), CREDIT);
        assert_eq!(hourly_budget(&[(TODAY - 7, CREDIT)], TODAY, NOW), 0);
    }

    #[test]
    fn no_wants_no_bid() {
        let budget = hourly_budget(&[(TODAY, 168 * CREDIT)], TODAY, NOW);
        assert_eq!(bid(budget, &Wants::default(), "rdns"), 0);
        assert_eq!(bid(budget, &wants(&[("shodan", 1)]), "rdns"), 0);
        // Setting 0 withdraws a want.
        let mut w = wants(&[("rdns", 3)]);
        w.set("rdns", 0);
        assert_eq!(w.goods(), 0);
    }
}
