//! What a good costs here: one rule for every good with limited supply.
//! Excess demand raises the price, excess supply lowers it, by a bounded
//! step an hour. A good without a supply limit costs nothing.
use super::Mc;
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::intel;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub const PRICE_FLOOR: Mc = 1;
pub const PRICE_STEP: f64 = 0.15;
/// A funded scan job (`credits::jobs`).
pub const SCAN: &str = "scan";
/// An observational probe (`scan::probe`).
pub const PROBE: &str = "probe";
/// A name resolved for another member (`intel::dns`).
pub const RESOLVE: &str = "resolve";
/// A probe slot serves this many probes an hour (`PROBE_TIMEOUT` is 2 minutes).
pub const PROBES_PER_SLOT_HOUR: f64 = 30.0;

/// One step of a price from the demand and the supply of a period. A
/// price moves by at least 1 mc when they differ, so rounding does not
/// hold a small price where it is.
pub fn step(price: Mc, demand: f64, supply: f64) -> Mc {
    scaled_step(price, demand, supply, 1.0)
}

/// A step of a flow good (demand and supply counted over `hours`): a
/// period shorter than an hour moves the price by that share of a full
/// step, so the first refresh after a start does not take a whole one.
pub fn flow_step(price: Mc, demand: f64, supply: f64, hours: f64) -> Mc {
    scaled_step(price, demand, supply, hours.clamp(0.0, 1.0))
}

fn scaled_step(price: Mc, demand: f64, supply: f64, scale: f64) -> Mc {
    let price = price.max(PRICE_FLOOR);
    let x = ((demand - supply) / supply.max(1.0)).clamp(-3.0, 3.0);
    let p = (price as f64 * (PRICE_STEP * scale * x).exp()).round();
    let p = (p.min(u32::MAX as f64) as Mc).max(PRICE_FLOOR);
    match p == price {
        true if x > 0.0 => price.saturating_add(1).min(u32::MAX as Mc),
        true if x < 0.0 => (price - 1).max(PRICE_FLOOR),
        _ => p,
    }
}

/// Where a good's price starts here: the lower median of what members
/// announce for it, or the floor.
pub fn start(announced: &[u32]) -> Mc {
    let mut v: Vec<u32> = announced.iter().copied().filter(|p| *p > 0).collect();
    if v.is_empty() {
        return PRICE_FLOOR;
    }
    v.sort_unstable();
    v[(v.len() - 1) / 2] as Mc
}

/// A provider's next price here: a step from `current` (or the floor)
/// with `per_day` spread over `hours` as supply.
pub fn provider_price(per_day: u32, current: Option<Mc>, demand: f64, hours: f64) -> Mc {
    flow_step(
        current.unwrap_or(PRICE_FLOOR),
        demand,
        per_day as f64 / 24.0 * hours,
        hours,
    )
}

/// Paid requests this node received since the last refresh, per good.
pub struct Demand {
    inner: std::sync::Mutex<(std::time::Instant, HashMap<String, f64>)>,
}

impl Default for Demand {
    fn default() -> Self {
        Self {
            inner: std::sync::Mutex::new((std::time::Instant::now(), HashMap::new())),
        }
    }
}

impl Demand {
    pub fn note(&self, good: &str, n: u32) {
        *self
            .inner
            .lock()
            .unwrap()
            .1
            .entry(good.to_string())
            .or_default() += n as f64;
    }

    /// The counts and the hours they cover; starts a new period.
    pub fn take(&self) -> (HashMap<String, f64>, f64) {
        let mut g = self.inner.lock().unwrap();
        let hours = (g.0.elapsed().as_secs_f64() / 3600.0).max(1e-6);
        g.0 = std::time::Instant::now();
        (std::mem::take(&mut g.1), hours)
    }
}

/// What is known of one scanner: its pace as its heartbeat announces it,
/// and its finished jobs as the replicated queue holds them.
#[derive(Debug, Clone, PartialEq)]
pub struct Scanner {
    pub node: NodeId,
    pub max_workers: u32,
    pub max_scans_per_hour: i64,
    /// Mean worker time of the jobs it ended (done or failed) in the last
    /// 7 days; None without one.
    pub mean_secs: Option<f64>,
    pub jobs_7d: u32,
    /// Jobs and audits it ended in the last 24 hours.
    pub ended_24h: u32,
}

/// Which of its two settings binds a scanner.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Limit {
    Workers,
    PerHour,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScannerCapacity {
    pub node: NodeId,
    /// Scans an hour it can do, and did over the last 24 hours.
    pub can_do: f64,
    pub did: f64,
    pub limited_by: Limit,
}

/// The cluster's scan capacity, in scans a day.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Capacity {
    pub scanners: Vec<ScannerCapacity>,
    pub per_day: f64,
    pub used_per_day: f64,
    /// Used over capacity, at most 1; 1 with no capacity at all.
    pub utilization: f64,
}

pub fn capacity(scanners: &[Scanner]) -> Capacity {
    let (secs, jobs) = scanners
        .iter()
        .filter_map(|s| Some((s.mean_secs? * s.jobs_7d as f64, s.jobs_7d)))
        .fold((0.0, 0u32), |a, b| (a.0 + b.0, a.1 + b.1));
    let cluster_mean = if jobs > 0 {
        secs / jobs as f64
    } else {
        crate::scan::pace::DEFAULT_SCAN_SECS
    };
    let per_scanner: Vec<ScannerCapacity> = scanners
        .iter()
        .map(|s| {
            let d = match s.mean_secs {
                Some(m) if s.jobs_7d >= 5 => m,
                _ => cluster_mean,
            }
            .max(1.0);
            let by_workers = s.max_workers as f64 * 3600.0 / d;
            let per_hour = s.max_scans_per_hour.max(0) as f64;
            let (can_do, limited_by) = if by_workers <= per_hour {
                (by_workers, Limit::Workers)
            } else {
                (per_hour, Limit::PerHour)
            };
            ScannerCapacity {
                node: s.node,
                can_do,
                did: s.ended_24h as f64 / 24.0,
                limited_by,
            }
        })
        .collect();
    let per_day: f64 = per_scanner.iter().map(|s| s.can_do).sum::<f64>() * 24.0;
    let used_per_day: f64 = per_scanner.iter().map(|s| s.did).sum::<f64>() * 24.0;
    Capacity {
        utilization: if per_day <= 0.0 {
            1.0
        } else {
            (used_per_day / per_day).min(1.0)
        },
        scanners: per_scanner,
        per_day,
        used_per_day,
    }
}

/// One provider as this node serves it.
#[derive(Debug, Clone, PartialEq)]
pub struct Offer {
    pub provider: String,
    pub price_mc: u32,
    /// Paid lookups a day it serves (`share::Shares::allowance`).
    pub on_demand: u32,
}

/// This node's prices and what they were computed from.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Table {
    pub at_ms: u64,
    pub capacity: Capacity,
    /// Funded scan jobs waiting in the cluster, as arbiters announce them.
    pub scan_bids: u32,
    pub scan_mc: u32,
    /// None: this node does not probe.
    pub probe_mc: Option<u32>,
    /// What resolving a name for another member costs here.
    pub resolve_mc: u32,
    pub offers: Vec<Offer>,
}

/// `(provider, millicredits)` pairs as a heartbeat carries them.
pub type Announced = Vec<(String, u32)>;

impl Table {
    pub fn price_of(&self, good: &str) -> Option<u32> {
        match good {
            SCAN => Some(self.scan_mc).filter(|p| *p > 0),
            PROBE => self.probe_mc,
            RESOLVE => Some(self.resolve_mc).filter(|p| *p > 0),
            _ => self
                .offers
                .iter()
                .find(|o| o.provider == good)
                .map(|o| o.price_mc),
        }
    }

    /// What the heartbeat carries: `(on_demand, prices)`.
    pub fn announced(&self) -> (Announced, Announced) {
        let mut prices: Announced = self
            .offers
            .iter()
            .map(|o| (o.provider.clone(), o.price_mc))
            .collect();
        if self.resolve_mc > 0 {
            prices.push((RESOLVE.to_string(), self.resolve_mc));
        }
        (
            self.offers
                .iter()
                .map(|o| (o.provider.clone(), o.on_demand))
                .collect(),
            prices,
        )
    }
}

/// The scanners this node counts: live members with the scanner role
/// (this node included) that are not in `left_out` (blocked or forked
/// here), with their announced pace and their finished jobs.
pub async fn scanners(node: &Node, left_out: &HashSet<NodeId>) -> Result<Vec<Scanner>> {
    let stats: Vec<(Vec<u8>, Option<f64>, i64, i64)> = sqlx::query_as(
        "SELECT scanner,
                AVG((julianday(finished_at) - julianday(started_at)) * 86400.0),
                COUNT(*),
                COALESCE(SUM(finished_at > datetime('now', '-1 day')), 0)
         FROM scan_jobs
         WHERE scanner IS NOT NULL AND status IN ('done', 'failed')
           AND started_at IS NOT NULL AND finished_at IS NOT NULL
           AND finished_at > datetime('now', '-7 days')
         GROUP BY scanner",
    )
    .fetch_all(&node.store.pool)
    .await?;
    let audits: Vec<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT origin, COUNT(*) FROM scans
         WHERE audit_of IS NOT NULL AND origin IS NOT NULL
           AND finished_at > datetime('now', '-1 day')
         GROUP BY origin",
    )
    .fetch_all(&node.store.pool)
    .await?;
    let mut jobs: HashMap<NodeId, (Option<f64>, u32, u32)> = HashMap::new();
    for (id, mean, n, day) in stats {
        if let Ok(id) = NodeId::from_slice(&id) {
            jobs.insert(
                id,
                (mean.map(|m| m.max(0.0)), n.max(0) as u32, day.max(0) as u32),
            );
        }
    }
    for (id, n) in audits {
        if let Ok(id) = NodeId::from_slice(&id) {
            jobs.entry(id).or_default().2 += n.max(0) as u32;
        }
    }
    let me = node.id();
    let mut out = vec![];
    for id in node.live_members(crate::scan::arbiter::LIVE_WINDOW) {
        if left_out.contains(&id) {
            continue;
        }
        let pace = if id == me {
            node.roles()
                .scanner
                .then(|| node.status.local.lock().unwrap().pace)
                .flatten()
        } else {
            node.status
                .known(&id)
                .filter(|k| k.hb.roles.iter().any(|r| r == "scanner"))
                .and_then(|k| k.hb.pace)
        };
        let Some(pace) = pace else { continue };
        let (mean_secs, jobs_7d, ended_24h) = jobs.get(&id).copied().unwrap_or_default();
        out.push(Scanner {
            node: id,
            max_workers: pace.max_workers,
            max_scans_per_hour: pace.max_scans_per_hour,
            mean_secs,
            jobs_7d,
            ended_24h,
        });
    }
    Ok(out)
}

/// Kept across restarts.
fn price_key(good: &str) -> String {
    format!("price:{good}")
}

/// Where `good`'s next step starts: the last price here, the kept one,
/// or what members announce.
async fn current(node: &Node, old: &Table, good: &str, announced: &[u32]) -> Result<Mc> {
    if let Some(p) = old.price_of(good).filter(|p| *p > 0) {
        return Ok(p as Mc);
    }
    if let Some(p) = node
        .store
        .intel_get(&price_key(good))
        .await?
        .and_then(|v| v.parse::<Mc>().ok())
    {
        return Ok(p.max(PRICE_FLOOR));
    }
    Ok(start(announced))
}

fn as_mc(p: Mc) -> u32 {
    p.min(u32::MAX as Mc) as u32
}

/// Step this node's prices from the demand it counted and the supply it
/// has, keep them, and announce them with the next heartbeat.
pub async fn refresh(node: &Node) -> Result<Arc<Table>> {
    let book = super::book_fresh(node).await?;
    let left_out: HashSet<NodeId> = book
        .standings
        .iter()
        .filter(|(_, s)| s.left_out())
        .map(|(id, _)| *id)
        .collect();
    let capacity = capacity(&scanners(node, &left_out).await?);
    let (demand, hours) = node.market.take();
    let old = node.price_table();
    // What live members announce, per good (for the start price), and
    // their scan bids.
    let me = node.id();
    let members = node.members();
    let mut announced: HashMap<String, Vec<u32>> = HashMap::new();
    let mut bids: u64 = node.scan_bids.load(std::sync::atomic::Ordering::Relaxed) as u64;
    for id in node.live_members(intel::LIVE_WINDOW) {
        if id == me
            || left_out.contains(&id)
            || node.is_blocked(&id)
            || !members
                .get(&id)
                .is_some_and(|m| super::pay::pays_with(m.proto_max))
        {
            continue;
        }
        let Some(k) = node.status.known(&id) else {
            continue;
        };
        for (p, mc) in &k.hb.prices {
            announced.entry(p.clone()).or_default().push(*mc);
        }
        if let Some(mc) = k.hb.scan_price_mc {
            announced.entry(SCAN.into()).or_default().push(mc);
        }
        if let Some(mc) = k.hb.probe_price_mc {
            announced.entry(PROBE.into()).or_default().push(mc);
        }
        bids += k.hb.scan_bids as u64;
    }
    let none = vec![];
    let ann = |g: &str| announced.get(g).unwrap_or(&none).clone();
    let got = |g: &str| demand.get(g).copied().unwrap_or(0.0);
    let empty = vec![];
    let providers = node.lookup_providers().unwrap_or(&empty);
    let offer_per_day = node
        .lookup_shares()
        .map_or(crate::config::DEFAULT_OFFER_PER_DAY, |s| s.offer_per_day());
    let mut offers = vec![];
    for p in providers.iter().filter(|p| p.ready()) {
        let on_demand = node
            .lookup_shares()
            .map_or(offer_per_day, |s| s.allowance(p.as_ref()));
        let cur = current(node, &old, p.name(), &ann(p.name())).await?;
        offers.push(Offer {
            provider: p.name().to_string(),
            price_mc: as_mc(provider_price(on_demand, Some(cur), got(p.name()), hours)),
            on_demand,
        });
    }
    let resolve_cur = current(node, &old, RESOLVE, &ann(RESOLVE)).await?;
    let resolve_mc = as_mc(flow_step(
        resolve_cur,
        got(RESOLVE),
        offer_per_day as f64 / 24.0 * hours,
        hours,
    ));
    let probe_mc = match node.prober() {
        Some(pr) => {
            let cur = current(node, &old, PROBE, &ann(PROBE)).await?;
            Some(as_mc(flow_step(
                cur,
                got(PROBE),
                pr.slots() as f64 * PROBES_PER_SLOT_HOUR * hours,
                hours,
            )))
        }
        None => None,
    };
    // Funded jobs waiting now (a stock, not a flow over `hours`) against
    // what the scanners do in an hour: a full step.
    let scan_cur = current(node, &old, SCAN, &ann(SCAN)).await?;
    let scan_mc = as_mc(step(scan_cur, bids as f64, capacity.per_day / 24.0));
    for (good, mc) in offers
        .iter()
        .map(|o| (o.provider.as_str(), o.price_mc))
        .chain(probe_mc.map(|m| (PROBE, m)))
        .chain([(SCAN, scan_mc), (RESOLVE, resolve_mc)])
    {
        node.store
            .intel_set(&price_key(good), &mc.to_string())
            .await?;
    }
    let table = Arc::new(Table {
        at_ms: crate::cluster::hlc::wall_ms(),
        capacity,
        scan_bids: bids.min(u32::MAX as u64) as u32,
        scan_mc,
        probe_mc,
        resolve_mc,
        offers,
    });
    node.set_price_table(table.clone());
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn scanner(
        n: u8,
        workers: u32,
        per_hour: i64,
        mean: Option<f64>,
        jobs: u32,
        day: u32,
    ) -> Scanner {
        Scanner {
            node: id(n),
            max_workers: workers,
            max_scans_per_hour: per_hour,
            mean_secs: mean,
            jobs_7d: jobs,
            ended_24h: day,
        }
    }

    #[test]
    fn scan_capacity_is_bound_by_workers_or_by_the_hourly_limit() {
        // 2 workers at 360 s a scan do 20 an hour; the limit is 30.
        let by_workers = scanner(1, 2, 30, Some(360.0), 10, 48);
        // 4 workers at 60 s could do 240 an hour; the limit is 30.
        let by_limit = scanner(2, 4, 30, Some(60.0), 50, 240);
        let c = capacity(&[by_workers.clone(), by_limit.clone()]);
        assert_eq!(
            (c.scanners[0].can_do, c.scanners[0].limited_by),
            (20.0, Limit::Workers)
        );
        assert_eq!(
            (c.scanners[1].can_do, c.scanners[1].limited_by),
            (30.0, Limit::PerHour)
        );
        assert_eq!((c.scanners[0].did, c.scanners[1].did), (2.0, 10.0));
        assert_eq!((c.per_day, c.used_per_day), (1200.0, 288.0));
        assert_eq!(c.utilization, 0.24);

        // Fewer than 5 jobs: the cluster's mean scan time (here 120 s over
        // 2 + 58 jobs: 2×600 + 58×(6000/58)).
        let new = scanner(3, 1, 3600, Some(600.0), 2, 0);
        let old = scanner(4, 1, 3600, Some(6000.0 / 58.0), 58, 0);
        let c = capacity(&[new, old]);
        assert_eq!(c.scanners[0].can_do, 30.0);
        // No job anywhere: the default scan time.
        let c = capacity(&[scanner(5, 1, 3600, None, 0, 0)]);
        assert_eq!(
            c.scanners[0].can_do,
            3600.0 / crate::scan::pace::DEFAULT_SCAN_SECS
        );
        // A paused scanner can do nothing; with no capacity at all the
        // cluster counts as saturated.
        let c = capacity(&[
            scanner(6, 0, 30, Some(60.0), 9, 3),
            scanner(7, 2, 0, None, 0, 0),
        ]);
        assert_eq!((c.per_day, c.utilization), (0.0, 1.0));
        assert_eq!(capacity(&[]).utilization, 1.0);
        // More done than the current pace allows: at most 1.
        let c = capacity(&[scanner(8, 1, 1, Some(60.0), 99, 99)]);
        assert_eq!(c.utilization, 1.0);
    }

    #[test]
    fn a_price_follows_the_imbalance_within_a_bounded_step() {
        assert_eq!(step(1000, 10.0, 10.0), 1000, "balanced");
        assert!(step(1000, 20.0, 10.0) > 1000);
        assert!(step(1000, 5.0, 10.0) < 1000);
        // Up by at most e^(0.15 × 3); down by at most e^(−0.15), as no
        // demand at all is one supply's worth below it.
        assert_eq!(
            step(1000, 1e9, 10.0),
            (1000.0 * (0.45f64).exp()).round() as Mc
        );
        assert_eq!(
            step(1000, 0.0, 1e9),
            (1000.0 * (-0.15f64).exp()).round() as Mc
        );
        // Excess supply ends at the floor, never below; no supply counts as 1.
        let mut p = 1000;
        for _ in 0..200 {
            p = step(p, 0.0, 50.0);
        }
        assert_eq!(p, PRICE_FLOOR);
        assert_eq!(step(3, 0.0, 50.0), 2, "rounding does not hold it");
        assert!(step(PRICE_FLOOR, 5.0, 0.0) > PRICE_FLOOR);
    }

    #[test]
    fn a_short_period_moves_a_flow_price_by_its_share_of_a_step() {
        // One minute with no demand at all: at most e^(−0.15/60) down,
        // where a full step would take e^(−0.15).
        let minute = 1.0 / 60.0;
        let p = provider_price(240, Some(100_000), 0.0, minute);
        let bound = (100_000.0 * (-0.15f64 / 60.0).exp()).round() as Mc;
        assert!(p < 100_000, "it still moves: {p}");
        assert!(p >= bound, "{p} moved past {bound}");
        assert!(step(100_000, 0.0, 10.0) < bound - 10_000, "a full step");
        // An hour or longer: one full step, never more.
        assert_eq!(
            flow_step(100_000, 0.0, 10.0, 1.0),
            step(100_000, 0.0, 10.0)
        );
        assert_eq!(
            flow_step(100_000, 0.0, 10.0, 5.0),
            step(100_000, 0.0, 10.0)
        );
        // A small price still moves by the 1 mc minimum.
        assert_eq!(flow_step(5, 0.0, 4.0, minute), 4);
    }

    #[test]
    fn a_new_good_starts_at_the_median_announced_or_the_floor() {
        assert_eq!(start(&[]), PRICE_FLOOR);
        assert_eq!(start(&[300, 100, 200]), 200);
        assert_eq!(start(&[100, 400]), 100, "lower median");
        assert_eq!(start(&[0, 0]), PRICE_FLOOR);
    }

    #[test]
    fn demand_is_counted_and_taken() {
        let d = Demand::default();
        d.note("abuseipdb", 2);
        d.note("abuseipdb", 1);
        d.note(PROBE, 1);
        let (got, hours) = d.take();
        assert_eq!(got.get("abuseipdb"), Some(&3.0));
        assert_eq!(got.get(PROBE), Some(&1.0));
        assert!(hours > 0.0 && hours < 0.01);
        assert!(d.take().0.is_empty(), "taken");
    }

    #[test]
    fn every_provider_follows_its_supply() {
        assert_eq!(
            provider_price(240, None, 3.0, 1.0),
            step(PRICE_FLOOR, 3.0, 10.0)
        );
        assert_eq!(provider_price(240, Some(500), 10.0, 1.0), 500);
        assert_eq!(provider_price(0, Some(500), 1.0, 1.0), step(500, 1.0, 0.0));
        assert!(
            provider_price(240, Some(1), 0.0, 1.0) >= PRICE_FLOOR,
            "never free"
        );
        // A generous node (high offer_per_day) gets cheaper under the same demand.
        assert!(
            provider_price(24_000, Some(500), 50.0, 1.0)
                < provider_price(240, Some(500), 50.0, 1.0)
        );
    }

    #[test]
    fn a_table_knows_what_it_offers() {
        let t = Table {
            offers: vec![
                Offer {
                    provider: intel::ABUSEIPDB.into(),
                    price_mc: 200,
                    on_demand: 200,
                },
                Offer {
                    provider: intel::MAXMIND.into(),
                    price_mc: 50,
                    on_demand: 1000,
                },
            ],
            ..Default::default()
        };
        assert_eq!(t.price_of(intel::ABUSEIPDB), Some(200));
        assert_eq!(t.price_of(intel::SHODAN), None);
        let (on_demand, prices) = t.announced();
        assert_eq!(
            on_demand,
            [
                (intel::ABUSEIPDB.to_string(), 200),
                (intel::MAXMIND.to_string(), 1000)
            ]
        );
        assert_eq!(prices.len(), 2);
    }
}
