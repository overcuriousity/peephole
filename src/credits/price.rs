//! What a lookup costs. A fixed price fits one cluster size only, so the
//! price follows the two things that set the balance: what the cluster
//! earns (credits a day, read from the log) and what it can serve
//! (on-demand lookups a day, announced in heartbeats). The scanners' load
//! moves it by at most a factor of 2 either way, and each server corrects
//! for what the formula cannot know with its own surge.
use super::Mc;
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::intel;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// The unit price stays within 0.01 and 100 credits.
pub const UNIT_MIN: Mc = 10;
pub const UNIT_MAX: Mc = 100_000;

/// What an observational probe (`scan::probe`) is priced as.
pub const PROBE: &str = "probe";

/// The weight of a provider in thousandths: a keyed API 1, Shodan
/// InternetDB and GeoLite2 a quarter, the Tor exit list and RDAP nothing
/// (free). A probe costs four: a scanner's time and its address.
pub fn weight_milli(provider: &str) -> u32 {
    match provider {
        intel::TOR | intel::RDAP => 0,
        intel::MAXMIND | intel::INTERNETDB => 250,
        PROBE => 4000,
        _ => 1000,
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

/// Half price while the scanners idle, double when they are saturated.
pub fn load(utilization: f64) -> f64 {
    2f64.powf(2.0 * utilization.clamp(0.0, 1.0) - 1.0)
}

/// The unit price in mc: the price at which what the cluster earns in a
/// day buys what it can serve in a day (half of every payment survives,
/// so an earned credit is spent twice on average), moved by the scanners'
/// load. None: nobody announces lookup capacity.
pub fn unit(earned_per_day: Mc, lookups_per_day: f64, utilization: f64) -> Option<Mc> {
    if lookups_per_day <= 0.0 {
        return None;
    }
    let u = earned_per_day as f64 / (0.5 * lookups_per_day) * load(utilization);
    Some((u.round().clamp(0.0, UNIT_MAX as f64) as Mc).clamp(UNIT_MIN, UNIT_MAX))
}

/// What one lookup of `provider` costs here, in mc: its weight times the
/// unit times this node's surge for it, at least 1 mc; nothing for a free
/// provider. Without a unit, what is served is priced from the floor.
pub fn price(provider: &str, unit: Option<Mc>, surge: u32) -> u32 {
    let w = weight_milli(provider) as u64;
    if w == 0 {
        return 0;
    }
    let p = w * unit.unwrap_or(UNIT_MIN) * surge.max(1) as u64 / 1000;
    p.clamp(1, u32::MAX as u64) as u32
}

/// One provider as this node serves it.
#[derive(Debug, Clone, PartialEq)]
pub struct Offer {
    pub provider: String,
    pub price_mc: u32,
    pub surge: u32,
    /// On-demand lookups a day; None: no budget, no limit.
    pub on_demand: Option<u32>,
}

/// This node's prices and what they were computed from.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Table {
    pub at_ms: u64,
    /// What all members earned a day over the last 7 days (E).
    pub earned_per_day: Mc,
    /// Weighted on-demand lookups a day the cluster announces (C).
    pub lookups_per_day: f64,
    pub capacity: Capacity,
    pub load: f64,
    pub unit: Option<Mc>,
    pub offers: Vec<Offer>,
    /// What a probe costs here; None when this node does not probe.
    pub probe_mc: Option<u32>,
}

/// `(provider, millicredits)` pairs as a heartbeat carries them.
pub type Announced = Vec<(String, u32)>;

impl Table {
    pub fn price_of(&self, provider: &str) -> Option<u32> {
        self.offers
            .iter()
            .find(|o| o.provider == provider)
            .map(|o| o.price_mc)
    }

    /// What the heartbeat carries: `(on_demand, prices)`.
    pub fn announced(&self) -> (Announced, Announced) {
        (
            self.offers
                .iter()
                .filter_map(|o| Some((o.provider.clone(), o.on_demand?)))
                .collect(),
            self.offers
                .iter()
                .map(|o| (o.provider.clone(), o.price_mc))
                .collect(),
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

/// Compute this node's prices from what it holds and hears now, keep
/// them, and announce them with the next heartbeat.
pub async fn refresh(node: &Node) -> Result<Arc<Table>> {
    let book = super::book_fresh(node).await?;
    let left_out: HashSet<NodeId> = book
        .standings
        .iter()
        .filter(|(_, s)| s.left_out())
        .map(|(id, _)| *id)
        .collect();
    let capacity = capacity(&scanners(node, &left_out).await?);
    let empty = vec![];
    let providers = node.lookup_providers().unwrap_or(&empty);
    let shares = node.lookup_shares();
    // What this node serves, and what it adds to the cluster's capacity.
    let mut own: Vec<(String, u32, Option<u32>)> = vec![];
    let mut weighted: u64 = 0;
    for p in providers.iter().filter(|p| p.ready()) {
        let (on_demand, surge) = match shares {
            Some(s) => (s.allowance(p.as_ref()), s.surge(p.as_ref()).await?),
            None => (None, 1),
        };
        weighted += weight_milli(p.name()) as u64 * on_demand.unwrap_or(0) as u64;
        own.push((p.name().to_string(), surge, on_demand));
    }
    // And every live member that can be asked and is not left out here.
    let me = node.id();
    let members = node.members();
    for id in node.live_members(intel::LIVE_WINDOW) {
        let askable = id != me
            && !left_out.contains(&id)
            && !node.is_blocked(&id)
            && node.dial_address(&id).is_some()
            && members
                .get(&id)
                .is_some_and(|m| m.proto_max >= crate::cluster::rpc::proto::OWNER_PROTO);
        if !askable {
            continue;
        }
        if let Some(k) = node.status.known(&id) {
            for (provider, n) in &k.hb.on_demand {
                if intel::provider_info(provider).is_some() {
                    weighted += weight_milli(provider) as u64 * *n as u64;
                }
            }
        }
    }
    let lookups_per_day = weighted as f64 / 1000.0;
    let earned_per_day = book.earned_per_day();
    let unit = unit(earned_per_day, lookups_per_day, capacity.utilization);
    let table = Arc::new(Table {
        at_ms: crate::cluster::hlc::wall_ms(),
        earned_per_day,
        lookups_per_day,
        load: load(capacity.utilization),
        capacity,
        unit,
        offers: own
            .into_iter()
            .map(|(provider, surge, on_demand)| Offer {
                price_mc: price(&provider, unit, surge),
                provider,
                surge,
                on_demand,
            })
            .collect(),
        // Doubles while every probe slot is busy.
        probe_mc: node
            .prober()
            .map(|p| price(PROBE, unit, 1 + p.full() as u32)),
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
    fn the_load_factor_runs_from_a_half_to_double() {
        assert_eq!(load(0.0), 0.5);
        assert_eq!(load(0.5), 1.0);
        assert_eq!(load(1.0), 2.0);
        assert_eq!(load(7.0), 2.0, "bounded");
        assert_eq!(load(-1.0), 0.5);
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
    fn the_unit_price_is_what_the_days_earnings_buy_of_the_days_capacity() {
        // The spec's example: 20 credits a day, 200 weighted lookups a day.
        assert_eq!(unit(20_000, 200.0, 0.5), Some(200));
        assert_eq!(unit(20_000, 200.0, 0.0), Some(100), "idle scanners: half");
        assert_eq!(unit(20_000, 200.0, 1.0), Some(400), "saturated: double");
        assert_eq!(price(intel::ABUSEIPDB, Some(200), 1), 200);
        assert_eq!(price(intel::SHODAN, Some(200), 1), 200);
        assert_eq!(price(intel::GREYNOISE, Some(200), 1), 200);
        assert_eq!(price(intel::INTERNETDB, Some(200), 1), 50);
        assert_eq!(price(intel::MAXMIND, Some(200), 1), 50);
        assert_eq!(price(intel::TOR, Some(200), 8), 0, "free");
        assert_eq!(price(intel::ABUSEIPDB, Some(200), 4), 800, "surge");
        // Doubling the earnings doubles the price; doubling the capacity
        // halves it.
        assert_eq!(unit(40_000, 200.0, 0.5), Some(400));
        assert_eq!(unit(20_000, 400.0, 0.5), Some(100));
        // No earnings yet: the floor. Far too many: the ceiling.
        assert_eq!(unit(0, 200.0, 0.5), Some(UNIT_MIN));
        assert_eq!(unit(u64::MAX / 4, 1.0, 1.0), Some(UNIT_MAX));
        // Nobody announces capacity: no unit; what has no budget is priced
        // from the floor, and a price is never less than 1 mc.
        assert_eq!(unit(20_000, 0.0, 0.5), None);
        assert_eq!(price(intel::MAXMIND, None, 1), 2);
        assert_eq!(price(intel::MAXMIND, Some(1), 1), 1);
    }

    #[test]
    fn a_probe_costs_four_units_and_doubles_when_the_slots_are_full() {
        assert_eq!(weight_milli(PROBE), 4000);
        assert_eq!(price(PROBE, Some(1000), 1), 4000);
        assert_eq!(price(PROBE, Some(1000), 2), 8000);
    }

    #[test]
    fn a_table_knows_what_it_offers() {
        let t = Table {
            offers: vec![
                Offer {
                    provider: intel::ABUSEIPDB.into(),
                    price_mc: 200,
                    surge: 1,
                    on_demand: Some(200),
                },
                Offer {
                    provider: intel::MAXMIND.into(),
                    price_mc: 50,
                    surge: 1,
                    on_demand: None,
                },
            ],
            ..Default::default()
        };
        assert_eq!(t.price_of(intel::ABUSEIPDB), Some(200));
        assert_eq!(t.price_of(intel::SHODAN), None);
        let (on_demand, prices) = t.announced();
        assert_eq!(on_demand, [(intel::ABUSEIPDB.to_string(), 200)]);
        assert_eq!(prices.len(), 2);
    }
}
