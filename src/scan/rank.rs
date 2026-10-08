//! Ranking scanners for a scan job by what one delivered result costs: a
//! failed scan is not paid, so a scanner's price buys a result only as
//! often as it delivers, its `weight` at the job's level (see `weight`).
//! A paid job waits for a cheaper live scanner (the reserve) for up to
//! [`OVERRIDE_WAIT_MINS`]: the buyer's patience.
use super::weight::{MIN_SAMPLE, MIN_WEIGHT, OVERRIDE_WAIT_MINS};
use crate::cluster::identity::NodeId;

/// `price / weight` in millicredits. No price: after every priced scanner.
pub fn effective(price: Option<u32>, weight: f64) -> u32 {
    match price {
        Some(p) => (p as f64 / weight.max(MIN_WEIGHT))
            .round()
            .min(u32::MAX as f64) as u32,
        None => u32::MAX,
    }
}

/// A claimant of a round, as it stands for one job.
#[derive(Debug, Clone)]
pub struct Bid {
    pub id: NodeId,
    /// What this arbiter would pay it (`credits::jobs::price_for`).
    pub price: Option<u32>,
    /// Its weight at the job's level.
    pub weight: f64,
    /// Over its hourly capacity, or not delivering enough grants here.
    pub demoted: bool,
    /// Its scans of the last hour, cluster-wide.
    pub load: i64,
}

impl Bid {
    pub fn effective(&self) -> u32 {
        effective(self.price, self.weight)
    }
}

/// Not demoted first, then cheapest per delivered result, then fewest
/// recent scans, then key.
pub fn rank(bids: &mut [Bid]) {
    bids.sort_by_key(|b| (b.demoted, b.effective(), b.load, b.id));
}

/// A live scanner, not demoted and under its capacity, that could take
/// the job but may not be asking right now.
#[derive(Debug, Clone)]
pub struct Standby {
    pub id: NodeId,
    pub price: Option<u32>,
    pub weight: f64,
    /// Its finished scans at the job's level in the weight snapshot.
    pub sample: i64,
}

/// The reserve of a level: the cheapest per delivered result among the
/// standby scanners with a record there ([`MIN_SAMPLE`]), so one that
/// never runs the level does not hold its jobs back.
pub fn reserve(standby: &[Standby]) -> Option<u32> {
    standby
        .iter()
        .filter(|s| s.sample >= MIN_SAMPLE && s.price.is_some())
        .map(|s| effective(s.price, s.weight))
        .min()
}

/// Whether a paid job goes to its best claimant now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    /// Nobody live is cheaper per delivered result.
    Go,
    /// A cheaper scanner is live: wait for it.
    Hold,
    /// A cheaper scanner is live, but the job has waited long enough.
    Override,
}

/// [`Wait`] for a job whose best claimant costs `best` per delivered
/// result, queued for `waited_secs`.
pub fn waits(best: u32, reserve: Option<u32>, waited_secs: i64) -> Wait {
    match reserve {
        Some(r) if r < best && waited_secs >= OVERRIDE_WAIT_MINS * 60 => Wait::Override,
        Some(r) if r < best => Wait::Hold,
        _ => Wait::Go,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        NodeId([b; 32])
    }

    fn bid(b: u8, price: u32, weight: f64, demoted: bool, load: i64) -> Bid {
        Bid {
            id: id(b),
            price: Some(price),
            weight,
            demoted,
            load,
        }
    }

    #[test]
    fn the_cheapest_per_delivered_result_wins() {
        // Fast asks 30 and delivers everything; Flaky asks 20 and fails
        // half its L4 scans but none at L1.
        let mut l4 = vec![bid(2, 20, 0.5, false, 0), bid(1, 30, 1.0, false, 9)];
        rank(&mut l4);
        assert_eq!(l4[0].id, id(1));
        let mut l1 = vec![bid(2, 20, 1.0, false, 0), bid(1, 30, 1.0, false, 0)];
        rank(&mut l1);
        assert_eq!(l1[0].id, id(2));
    }

    #[test]
    fn demoted_last_then_load_then_key() {
        let mut v = vec![
            bid(1, 5, 1.0, true, 0),
            bid(2, 40, 1.0, false, 3),
            bid(3, 40, 1.0, false, 1),
            Bid {
                id: id(4),
                price: None,
                weight: 1.0,
                demoted: false,
                load: 0,
            },
        ];
        rank(&mut v);
        let order: Vec<NodeId> = v.iter().map(|b| b.id).collect();
        assert_eq!(order, vec![id(3), id(2), id(4), id(1)]);
    }

    #[test]
    fn effective_saturates() {
        assert_eq!(effective(Some(u32::MAX), 0.1), u32::MAX);
        assert_eq!(effective(None, 1.0), u32::MAX);
        assert_eq!(effective(Some(20), 0.5), 40);
    }

    #[test]
    fn the_reserve_needs_a_record_at_the_level() {
        let s = |b: u8, price: u32, weight: f64, sample: i64| Standby {
            id: id(b),
            price: Some(price),
            weight,
            sample,
        };
        assert_eq!(reserve(&[s(1, 30, 1.0, 10), s(2, 10, 1.0, 4)]), Some(30));
        assert_eq!(reserve(&[s(2, 10, 1.0, MIN_SAMPLE - 1)]), None);
        assert_eq!(reserve(&[]), None);
    }

    #[test]
    fn a_paid_job_waits_for_a_cheaper_scanner_until_the_override() {
        assert_eq!(waits(40, Some(30), 0), Wait::Hold);
        assert_eq!(waits(40, Some(30), OVERRIDE_WAIT_MINS * 60), Wait::Override);
        assert_eq!(waits(30, Some(30), 0), Wait::Go);
        assert_eq!(waits(40, None, 0), Wait::Go);
    }
}
