//! What a good costs here: one rule for every good. A good that sold in
//! the last period gets dearer, one that sold nothing cheaper, by a
//! bounded step an hour, down to nothing.
use super::Mc;
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::intel;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// A funded scan job (`credits::jobs`).
pub const SCAN: &str = "scan";
/// An observational probe (`scan::probe`).
pub const PROBE: &str = "probe";
/// A name resolved for another member (`intel::dns`).
pub const RESOLVE: &str = "resolve";
/// A probe slot serves this many probes an hour (`PROBE_TIMEOUT` is 2 minutes).
pub const PROBES_PER_SLOT_HOUR: f64 = 30.0;

/// Share of a scanner's capacity at which it counts as at capacity: its
/// price rises whatever it sold.
pub const PAID_TARGET: f64 = 0.9;
/// An arbiter offers a scanner at most this times its own copy of the
/// scanner's price; a scanner takes no less than its price divided by it.
pub const PRICE_TOLERANCE: f64 = 1.25;

/// What an arbiter offers a scanner: what it announces, at most
/// [`PRICE_TOLERANCE`] times this node's own copy. None: not a scanner,
/// or no copy here yet; the job is granted unpaid.
pub fn offer_price(announced: Option<u32>, reference: Option<u32>) -> Option<u32> {
    let cap = (reference? as f64 * PRICE_TOLERANCE).floor() as u32;
    Some(announced?.min(cap))
}

/// The least a scanner selling at `sell_mc` takes for a funded job.
pub fn min_take(sell_mc: u32) -> u32 {
    (sell_mc as f64 / PRICE_TOLERANCE).floor() as u32
}

/// Per hour a price rises at most by e^0.45 and falls by e^-0.15 (the
/// sizes of the market before the sales rule).
pub const RAISE_PER_HOUR: f64 = 0.45;
pub const LOWER_PER_HOUR: f64 = 0.15;
/// Reverse names of a source looked up for another member (`intel::rdns`).
pub const RDNS: &str = "rdns";

/// One step of a price `hours` after the last: up when the good sold in
/// that period (or is at capacity), down when it sold nothing. A period
/// shorter than an hour takes that share of the hour's step, a longer one
/// a full step. The price moves by at least 1 mc, which is what lifts a
/// used good off zero; it never goes below zero. No floor.
pub fn sales_step(price: Mc, raise: bool, hours: f64) -> Mc {
    let scale = hours.clamp(0.0, 1.0);
    let rate = if raise {
        RAISE_PER_HOUR
    } else {
        -LOWER_PER_HOUR
    };
    let p = (price as f64 * (rate * scale).exp())
        .round()
        .min(u32::MAX as f64) as Mc;
    match (raise, p == price) {
        (true, true) => price.saturating_add(1).min(u32::MAX as Mc),
        (false, true) => price.saturating_sub(1),
        _ => p,
    }
}

/// Where a good's price starts here: the lower median of what members
/// announce for it, free ones included; 0 when nobody does.
pub fn start(announced: &[u32]) -> Mc {
    let mut v = announced.to_vec();
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[(v.len() - 1) / 2] as Mc
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

    /// The counts so far and the hours they cover, left in place: the
    /// period ends with [`Demand::consume`] once they were used, so a
    /// refresh that fails loses none of them.
    pub fn peek(&self) -> Counted {
        let g = self.inner.lock().unwrap();
        let now = std::time::Instant::now();
        Counted {
            hours: ((now - g.0).as_secs_f64() / 3600.0).max(1e-6),
            counts: g.1.clone(),
            at: now,
        }
    }

    /// End the period `c` covers; what was noted since stays for the next.
    pub fn consume(&self, c: &Counted) {
        let mut g = self.inner.lock().unwrap();
        for (good, n) in &c.counts {
            if let Some(v) = g.1.get_mut(good) {
                *v -= n;
                if *v <= 0.0 {
                    g.1.remove(good);
                }
            }
        }
        g.0 = g.0.max(c.at);
    }
}

/// What [`Demand::peek`] saw.
pub struct Counted {
    pub counts: HashMap<String, f64>,
    pub hours: f64,
    at: std::time::Instant,
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

/// One scanner's price as this node computes it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScannerPrice {
    pub node: NodeId,
    pub price_mc: u32,
    /// Its paid scans of the past hour, and [`PAID_TARGET`] of its capacity.
    pub paid: f64,
    pub supply: f64,
}

/// This node's prices and what they were computed from.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Table {
    pub at_ms: u64,
    pub capacity: Capacity,
    /// This node's own selling price; None: it does not scan.
    pub sell_mc: Option<u32>,
    /// Every scanner this node counts (itself included), with this node's
    /// copy of its price: the reference an arbiter offers against.
    pub scanners: Vec<ScannerPrice>,
    /// None: this node does not probe.
    pub probe_mc: Option<u32>,
    /// What resolving a name for another member costs here.
    pub resolve_mc: u32,
    /// What looking up a source's reverse names for another member costs here.
    pub rdns_mc: u32,
    pub offers: Vec<Offer>,
}

/// `(provider, millicredits)` pairs as a heartbeat carries them.
pub type Announced = Vec<(String, u32)>;

impl Table {
    /// This node's copy of `node`'s scan price.
    pub fn reference(&self, node: &NodeId) -> Option<u32> {
        self.scanners
            .iter()
            .find(|s| s.node == *node)
            .map(|s| s.price_mc)
    }

    /// Scans an hour `node` can do, as this node counts its capacity.
    pub fn can_do(&self, node: &NodeId) -> Option<f64> {
        self.capacity
            .scanners
            .iter()
            .find(|s| s.node == *node)
            .map(|s| s.can_do)
    }

    pub fn price_of(&self, good: &str) -> Option<u32> {
        match good {
            SCAN => self.sell_mc,
            PROBE => self.probe_mc,
            RESOLVE => Some(self.resolve_mc),
            RDNS => Some(self.rdns_mc),
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
        prices.push((RESOLVE.to_string(), self.resolve_mc));
        prices.push((RDNS.to_string(), self.rdns_mc));
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
    if let Some(p) = old.price_of(good) {
        return Ok(p as Mc);
    }
    if let Some(p) = node
        .store
        .intel_get(&price_key(good))
        .await?
        .and_then(|v| v.parse::<Mc>().ok())
    {
        return Ok(p);
    }
    Ok(start(announced))
}

/// The scans of jobs granted to each scanner by another arbiter that
/// finished in the past hour, as wall-clock ms by the scan's own
/// `finished_at`: one per job (its scanner's first record), none dated in
/// the future. Granted at any price, zero included: a sale. A scanner's
/// own jobs are no sale and do not fill its capacity, or it could raise
/// its own price by queuing work for itself.
pub async fn granted_scans(pool: &sqlx::SqlitePool) -> Result<HashMap<NodeId, Vec<u64>>> {
    let rows: Vec<(Vec<u8>, String)> = sqlx::query_as(
        "SELECT s.origin, MIN(s.finished_at) FROM scans s
         JOIN scan_jobs j ON j.uid = s.job_uid AND j.scanner = s.origin
         WHERE s.audit_of IS NULL AND s.origin IS NOT NULL AND s.job_uid IS NOT NULL
           AND j.arbiter IS NOT s.origin
           AND s.finished_at > datetime('now', '-1 hour')
           AND s.finished_at <= datetime('now')
         GROUP BY s.origin, s.job_uid",
    )
    .fetch_all(pool)
    .await?;
    let mut out: HashMap<NodeId, Vec<u64>> = HashMap::new();
    for (scanner, finished) in rows {
        let (Ok(scanner), Ok(t)) = (
            NodeId::from_slice(&scanner),
            chrono::NaiveDateTime::parse_from_str(&finished, "%Y-%m-%d %H:%M:%S"),
        ) else {
            continue;
        };
        out.entry(scanner)
            .or_default()
            .push(t.and_utc().timestamp_millis().max(0) as u64);
    }
    Ok(out)
}

/// Whether a scanner's price rises: a scan of a job granted to it ended
/// in the last `period_ms`, or its granted scans of the past hour reach
/// [`PAID_TARGET`] of what it can do (at capacity).
pub fn scanner_raises(finished: &[u64], now_ms: u64, period_ms: u64, can_do: f64) -> bool {
    let sold = finished
        .iter()
        .any(|t| t.saturating_add(period_ms) >= now_ms);
    let full = can_do > 0.0 && finished.len() as f64 >= PAID_TARGET * can_do;
    sold || full
}

/// Kept across restarts: this node's copy of `scanner`'s price, as
/// `mc@ms` with the time of its last step.
fn scanner_key(scanner: &NodeId) -> String {
    format!("price:scan:{scanner}")
}

/// A kept copy: its price and, unless it predates them, when it was stepped.
fn parse_kept(v: &str) -> Option<(Mc, Option<u64>)> {
    match v.split_once('@') {
        Some((mc, ms)) => Some((mc.parse().ok()?, ms.parse().ok())),
        None => Some((v.parse().ok()?, None)),
    }
}

/// Hours from `since_ms` to `now_ms` (a full step without a time).
fn hours_since(since_ms: Option<u64>, now_ms: u64) -> f64 {
    since_ms.map_or(1.0, |t| now_ms.saturating_sub(t) as f64 / 3_600_000.0)
}

/// Where a scanner's next step starts, and the hours since its last step:
/// the last copy here, the kept copy, `legacy` (on upgrade, the
/// cluster-wide scan price of the market before scanner prices; only for
/// the scanners counted at the first refresh after it), the lower median
/// of what scanners announce, 0.
async fn scanner_current(
    node: &Node,
    old: &Table,
    scanner: &NodeId,
    legacy: Option<Mc>,
    announced: &[u32],
    now_ms: u64,
) -> Result<(Mc, f64)> {
    if let Some(p) = old.reference(scanner) {
        return Ok((p as Mc, hours_since(Some(old.at_ms), now_ms)));
    }
    if let Some((p, at)) = node
        .store
        .intel_get(&scanner_key(scanner))
        .await?
        .and_then(|v| parse_kept(&v))
    {
        return Ok((p, hours_since(at, now_ms)));
    }
    Ok((legacy.unwrap_or_else(|| start(announced)), 1.0))
}

fn as_mc(p: Mc) -> u32 {
    p.min(u32::MAX as Mc) as u32
}

/// Seed this node's table from the prices it kept, so a restart serves
/// at them until the first refresh steps them.
pub async fn load_kept(node: &Node) -> Result<()> {
    let kept = |good: &str| {
        let store = node.store.clone();
        let key = price_key(good);
        async move {
            store
                .intel_get(&key)
                .await
                .ok()
                .flatten()
                .and_then(|v| v.parse::<Mc>().ok())
        }
    };
    let mut t = Table {
        resolve_mc: kept(RESOLVE).await.map_or(0, as_mc),
        rdns_mc: kept(RDNS).await.map_or(0, as_mc),
        ..Default::default()
    };
    if node.prober().is_some() {
        t.probe_mc = kept(PROBE).await.map(as_mc);
    }
    for p in node
        .lookup_providers()
        .into_iter()
        .flatten()
        .filter(|p| p.ready())
    {
        if let Some(mc) = kept(p.name()).await {
            t.offers.push(Offer {
                provider: p.name().to_string(),
                price_mc: as_mc(mc),
                on_demand: node
                    .lookup_shares()
                    .map_or(crate::config::DEFAULT_OFFER_PER_DAY, |s| {
                        s.allowance(p.as_ref())
                    }),
            });
        }
    }
    let me = node.id();
    if let Some((mc, _)) = node
        .store
        .intel_get(&scanner_key(&me))
        .await?
        .and_then(|v| parse_kept(&v))
    {
        t.sell_mc = Some(as_mc(mc));
    }
    node.set_price_table(Arc::new(t));
    Ok(())
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
    let counted = node.market.peek();
    let (demand, hours) = (&counted.counts, counted.hours);
    let old = node.price_table();
    // What live members announce, per good (for the start price).
    let me = node.id();
    let members = node.members();
    let mut announced: HashMap<String, Vec<u32>> = HashMap::new();
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
        // A protocol-4 node's scan price is the old cluster-wide one.
        if let Some(mc) = k.hb.scan_price_mc.filter(|_| {
            members
                .get(&id)
                .is_some_and(|m| super::pay::sells_scans(m.proto_max))
        }) {
            announced.entry(SCAN.into()).or_default().push(mc);
        }
        if let Some(mc) = k.hb.probe_price_mc {
            announced.entry(PROBE.into()).or_default().push(mc);
        }
    }
    let none = vec![];
    let ann = |g: &str| announced.get(g).unwrap_or(&none).clone();
    let got = |g: &str| demand.get(g).copied().unwrap_or(0.0);
    // A good that was asked for sold (a request beyond the supply is a
    // sale too), so it rises; one nobody asked for falls.
    let next = |cur: Mc, good: &str| as_mc(sales_step(cur, got(good) > 0.0, hours));
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
            price_mc: next(cur, p.name()),
            on_demand,
        });
    }
    let resolve_mc = next(current(node, &old, RESOLVE, &ann(RESOLVE)).await?, RESOLVE);
    let rdns_mc = next(current(node, &old, RDNS, &ann(RDNS)).await?, RDNS);
    let probe_mc = match node.prober() {
        Some(_) => Some(next(current(node, &old, PROBE, &ann(PROBE)).await?, PROBE)),
        None => None,
    };
    // Every scanner's price, from the scans of jobs other arbiters granted it: the
    // same public inputs on every node.
    let granted = granted_scans(&node.store.pool).await?;
    // The cluster-wide scan price of the market before scanner prices
    // seeds the scanners counted now, once: later ones start from what
    // scanners announce, like on every node that never had it.
    let legacy_key = price_key(SCAN);
    let legacy = node
        .store
        .intel_get(&legacy_key)
        .await?
        .and_then(|v| v.parse::<Mc>().ok());
    let now_ms = crate::cluster::hlc::wall_ms();
    let mut scanner_prices = vec![];
    for s in &capacity.scanners {
        let (cur, hours) = scanner_current(node, &old, &s.node, legacy, &ann(SCAN), now_ms).await?;
        let finished = granted.get(&s.node).map(Vec::as_slice).unwrap_or(&[]);
        let period_ms = (hours.clamp(0.0, 1.0) * 3_600_000.0) as u64;
        let raise = scanner_raises(finished, now_ms, period_ms, s.can_do);
        let price_mc = as_mc(sales_step(cur, raise, hours));
        node.store
            .intel_set(&scanner_key(&s.node), &format!("{price_mc}@{now_ms}"))
            .await?;
        scanner_prices.push(ScannerPrice {
            node: s.node,
            price_mc,
            paid: (finished.len() as f64).min(s.can_do),
            supply: PAID_TARGET * s.can_do,
        });
    }
    if legacy.is_some() {
        node.store.intel_delete(&legacy_key).await?;
    }
    let sell_mc = scanner_prices
        .iter()
        .find(|s| s.node == me)
        .map(|s| s.price_mc);
    for (good, mc) in offers
        .iter()
        .map(|o| (o.provider.as_str(), o.price_mc))
        .chain(probe_mc.map(|m| (PROBE, m)))
        .chain([(RESOLVE, resolve_mc), (RDNS, rdns_mc)])
    {
        node.store
            .intel_set(&price_key(good), &mc.to_string())
            .await?;
    }
    // The hour's snapshot for the Credits page: demand and supply per hour.
    let per_hour = |n: f64| if hours > 0.0 { n / hours } else { 0.0 };
    let mut goods: Vec<(&str, Option<u32>, f64, f64)> = offers
        .iter()
        .map(|o| {
            (
                o.provider.as_str(),
                Some(o.price_mc),
                per_hour(got(&o.provider)),
                o.on_demand as f64 / 24.0,
            )
        })
        .collect();
    let mine = scanner_prices.iter().find(|s| s.node == me);
    goods.push((
        SCAN,
        sell_mc,
        mine.map_or(0.0, |s| s.paid),
        mine.map_or(0.0, |s| s.supply),
    ));
    goods.push((
        RESOLVE,
        Some(resolve_mc),
        per_hour(got(RESOLVE)),
        offer_per_day as f64 / 24.0,
    ));
    goods.push((
        RDNS,
        Some(rdns_mc),
        per_hour(got(RDNS)),
        offer_per_day as f64 / 24.0,
    ));
    if let Some(pr) = node.prober() {
        goods.push((
            PROBE,
            probe_mc,
            per_hour(got(PROBE)),
            pr.slots() as f64 * PROBES_PER_SLOT_HOUR,
        ));
    }
    // Goods only members announce (a provider this node does not serve).
    for g in announced.keys() {
        if !goods.iter().any(|(x, ..)| x == g) {
            goods.push((g.as_str(), None, 0.0, 0.0));
        }
    }
    let hour = super::history::hour_of(crate::cluster::hlc::wall_ms());
    let points: Vec<super::history::Point> = goods
        .into_iter()
        .map(|(good, own, demand, supply)| {
            let (lo_mc, median_mc, hi_mc) = super::history::spread(&ann(good));
            super::history::Point {
                hour,
                good: good.to_string(),
                own_mc: own.map(i64::from),
                lo_mc,
                median_mc,
                hi_mc,
                demand,
                supply,
            }
        })
        .collect();
    if let Err(e) = super::history::record(&node.store.pool, &points).await {
        tracing::debug!(?e, "credits: price history not written");
    }
    let table = Arc::new(Table {
        at_ms: crate::cluster::hlc::wall_ms(),
        capacity,
        sell_mc,
        scanners: scanner_prices,
        probe_mc,
        resolve_mc,
        rdns_mc,
        offers,
    });
    node.set_price_table(table.clone());
    node.market.consume(&counted);
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
    fn a_price_rises_when_it_sold_and_falls_when_it_did_not() {
        let up = |h: f64| (1000.0 * (RAISE_PER_HOUR * h).exp()).round() as Mc;
        let down = |h: f64| (1000.0 * (-LOWER_PER_HOUR * h).exp()).round() as Mc;
        assert_eq!(sales_step(1000, true, 1.0), up(1.0));
        assert_eq!(sales_step(1000, false, 1.0), down(1.0));
        assert_eq!(
            sales_step(1000, true, 1.0 / 6.0),
            up(1.0 / 6.0),
            "ten minutes"
        );
        assert_eq!(
            sales_step(1000, false, 5.0),
            down(1.0),
            "never more than a full step"
        );
    }

    #[test]
    fn a_price_has_no_floor_and_a_used_good_leaves_zero() {
        let mut p: Mc = 1000;
        for _ in 0..1000 {
            p = sales_step(p, false, 1.0 / 6.0);
        }
        assert_eq!(p, 0, "unsold for long enough: free");
        assert_eq!(sales_step(0, false, 1.0), 0, "never below 0");
        assert_eq!(
            sales_step(0, true, 1.0 / 6.0),
            1,
            "sold at 0: up by at least 1 mc"
        );
        assert_eq!(
            sales_step(3, false, 1.0 / 6.0),
            2,
            "rounding does not hold it"
        );
        assert_eq!(sales_step(u32::MAX as Mc, true, 1.0), u32::MAX as Mc);
    }

    #[test]
    fn six_ten_minute_steps_move_a_price_like_one_hourly_step() {
        for raise in [true, false] {
            let hourly = sales_step(1_000_000, raise, 1.0);
            let mut p = 1_000_000;
            for _ in 0..6 {
                p = sales_step(p, raise, 1.0 / 6.0);
            }
            let diff = (p as f64 - hourly as f64).abs() / hourly as f64;
            assert!(diff < 0.002, "raise {raise}: {p} vs {hourly}");
        }
    }

    #[test]
    fn a_scanner_rises_when_a_granted_scan_ended_in_the_period_or_at_capacity() {
        let (now, min) = (10 * 3_600_000u64, 60_000u64);
        assert!(
            scanner_raises(&[now - 5 * min], now, 10 * min, 10.0),
            "sold in the period"
        );
        assert!(
            !scanner_raises(&[now - 30 * min], now, 10 * min, 10.0),
            "sold before it"
        );
        let nine: Vec<u64> = (0..9).map(|i| now - (20 + i) * min).collect();
        assert!(
            scanner_raises(&nine, now, 10 * min, 10.0),
            "90 % of capacity in the hour"
        );
        assert!(!scanner_raises(&nine[..8], now, 10 * min, 10.0));
        assert!(
            !scanner_raises(&[], now, 10 * min, 0.0),
            "a paused scanner sells nothing"
        );
    }

    #[tokio::test]
    async fn granted_scans_count_each_job_once_by_finish_time() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let pool = &store.pool;
        let (s, a) = (id(1), id(2));
        sqlx::query(
            "INSERT INTO ips (id, ip, first_seen, last_seen) VALUES (1, '192.0.2.1', '', '')",
        )
        .execute(pool)
        .await
        .unwrap();
        // (job uid, queued by, its scanner, finished minutes ago)
        for (n, (uid, origin, by, ago)) in [
            ("paid", a, s, 10),     // granted to s by a: counts
            ("free", a, s, 10),     // granted at zero: counts too
            ("own", s, s, 20),      // the scanner's own job: no sale
            ("old", a, s, 90),      // finished over an hour ago
            ("other", s, a, 10),    // granted to a, but s wrote the scan
            ("future", s, s, -600), // dated ahead: never counts
        ]
        .into_iter()
        .enumerate()
        {
            sqlx::query(
                "INSERT INTO scan_jobs (id, ip_id, level, status, queued_at, uid, origin, arbiter, scanner)
                 VALUES (?, 1, 1, 'done', datetime('now','-2 hours'), ?, ?, ?, ?)",
            )
            .bind(n as i64 + 1).bind(uid).bind(&origin.0[..]).bind(&origin.0[..]).bind(&by.0[..])
            .execute(pool).await.unwrap();
            sqlx::query(
                "INSERT INTO scans (job_id, ip_id, level, started_at, finished_at, uid, origin, job_uid)
                 VALUES (?, 1, 1, datetime('now', ?), datetime('now', ?), ?, ?, ?)",
            )
            .bind(n as i64 + 1)
            .bind(format!("{} minutes", -(ago + 5)))
            .bind(format!("{} minutes", -ago))
            .bind(format!("scan-{uid}")).bind(&s.0[..]).bind(uid)
            .execute(pool).await.unwrap();
        }
        // More scan records of one job count once.
        for k in 0..3 {
            sqlx::query(
                "INSERT INTO scans (job_id, ip_id, level, started_at, finished_at, uid, origin, job_uid)
                 VALUES (3, 1, 1, datetime('now','-9 minutes'), datetime('now','-8 minutes'), ?, ?, 'own')",
            )
            .bind(format!("again-{k}")).bind(&s.0[..])
            .execute(pool).await.unwrap();
        }
        let got = granted_scans(pool).await.unwrap();
        assert_eq!(got.get(&s).map(Vec::len), Some(2), "{got:?}");
        assert_eq!(got.get(&a), None, "{got:?}");
        let now = crate::cluster::hlc::wall_ms();
        assert!(got[&s].iter().all(|t| *t <= now && *t + 3_600_000 >= now));
    }

    #[test]
    fn a_new_good_starts_at_the_lower_median_announced_or_zero() {
        assert_eq!(start(&[]), 0);
        assert_eq!(start(&[300, 100, 200]), 200);
        assert_eq!(start(&[100, 400]), 100, "lower median");
        assert_eq!(start(&[0, 0]), 0);
        assert_eq!(start(&[0, 400]), 0, "a free announcement counts");
    }

    #[tokio::test]
    async fn a_restart_seeds_the_table_from_kept_prices() {
        let (_dir, node) = test_node().await;
        node.store
            .intel_set(&price_key(RESOLVE), "40")
            .await
            .unwrap();
        node.store.intel_set(&price_key(RDNS), "7").await.unwrap();
        load_kept(&node).await.unwrap();
        let t = node.price_table();
        assert_eq!(t.price_of(RESOLVE), Some(40));
        assert_eq!(t.price_of(RDNS), Some(7));
    }

    #[test]
    fn demand_is_counted_and_taken() {
        let d = Demand::default();
        d.note("abuseipdb", 2);
        d.note("abuseipdb", 1);
        d.note(PROBE, 1);
        let c = d.peek();
        assert_eq!(c.counts.get("abuseipdb"), Some(&3.0));
        assert_eq!(c.counts.get(PROBE), Some(&1.0));
        assert!(c.hours > 0.0 && c.hours < 0.01);
        // Not used (a refresh failed): still there.
        assert_eq!(d.peek().counts.get(PROBE), Some(&1.0));
        // Used: gone, but what was noted meanwhile stays.
        d.note(PROBE, 2);
        d.consume(&c);
        let left = d.peek().counts;
        assert_eq!(left.get(PROBE), Some(&2.0));
        assert_eq!(left.get("abuseipdb"), None);
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
        // The resolution price is always announced, also at 0.
        assert_eq!(prices.len(), 4);
        assert!(prices.contains(&(RESOLVE.to_string(), 0)));
        assert!(prices.contains(&(RDNS.to_string(), 0)));
        assert_eq!(t.price_of(RDNS), Some(0));
        assert_eq!(t.price_of(RESOLVE), Some(0));
    }

    #[test]
    fn a_kept_copy_carries_the_time_of_its_last_step() {
        assert_eq!(parse_kept("120@5000"), Some((120, Some(5000))));
        assert_eq!(parse_kept("120"), Some((120, None)));
        assert_eq!(parse_kept("x@5000"), None);
        assert_eq!(hours_since(Some(0), 1_800_000), 0.5);
        assert_eq!(hours_since(None, 1_800_000), 1.0, "no time: a full step");
        assert_eq!(hours_since(Some(9), 5), 0.0, "never negative");
    }

    async fn test_node() -> (tempfile::TempDir, Arc<Node>) {
        use crate::cluster::identity::Identity;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let node = Node::open(crate::cluster::NodeParams {
            identity: Identity::generate().unwrap(),
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
            store,
            proto: (1, 1),
            data_dir: dir.path().to_path_buf(),
            retention_days: 30,
        })
        .await
        .unwrap();
        node.bootstrap().await.unwrap();
        (dir, node)
    }

    #[tokio::test]
    async fn a_scanner_copy_starts_from_the_kept_one_the_legacy_price_or_the_median() {
        let (_dir, node) = test_node().await;
        let (kept, legacy, new) = (id(1), id(2), id(3));
        let old = Table::default();
        let now = 10 * 3_600_000;
        node.store
            .intel_set(&scanner_key(&kept), &format!("70@{}", now - 900_000))
            .await
            .unwrap();
        assert_eq!(
            scanner_current(&node, &old, &kept, Some(500), &[40], now)
                .await
                .unwrap(),
            (70, 0.25),
            "the kept copy and its time win"
        );
        assert_eq!(
            scanner_current(&node, &old, &legacy, Some(500), &[40], now)
                .await
                .unwrap(),
            (500, 1.0),
            "on upgrade: the legacy price"
        );
        assert_eq!(
            scanner_current(&node, &old, &new, None, &[40, 90, 10], now)
                .await
                .unwrap(),
            (40, 1.0),
            "later: the lower median announced"
        );
        let old = Table {
            at_ms: now - 3_600_000,
            scanners: vec![ScannerPrice {
                node: kept,
                price_mc: 66,
                paid: 0.0,
                supply: 0.0,
            }],
            ..Default::default()
        };
        assert_eq!(
            scanner_current(&node, &old, &kept, None, &[], now)
                .await
                .unwrap(),
            (66, 1.0),
            "the last copy here, an hour ago"
        );
    }

    #[tokio::test]
    async fn the_legacy_scan_price_is_used_at_one_refresh_only() {
        let (_dir, node) = test_node().await;
        node.store.intel_set(&price_key(SCAN), "500").await.unwrap();
        refresh(&node).await.unwrap();
        assert_eq!(node.store.intel_get(&price_key(SCAN)).await.unwrap(), None);
    }

    #[test]
    fn an_offer_is_the_announced_price_capped_by_the_reference() {
        assert_eq!(offer_price(Some(100), Some(100)), Some(100));
        assert_eq!(
            offer_price(Some(80), Some(100)),
            Some(80),
            "undercutting is fine"
        );
        assert_eq!(
            offer_price(Some(500), Some(100)),
            Some(125),
            "capped at 1.25×"
        );
        assert_eq!(offer_price(None, Some(100)), None, "not a scanner");
        assert_eq!(
            offer_price(Some(100), None),
            None,
            "no reference yet: unpaid"
        );
        assert_eq!(min_take(125), 100);
        assert_eq!(min_take(1), 0);
    }

    #[test]
    fn the_table_answers_for_each_scanner() {
        let t = Table {
            sell_mc: Some(40),
            scanners: vec![ScannerPrice {
                node: id(7),
                price_mc: 55,
                paid: 3.0,
                supply: 9.0,
            }],
            ..Default::default()
        };
        assert_eq!(t.price_of(SCAN), Some(40));
        assert_eq!(t.reference(&id(7)), Some(55));
        assert_eq!(t.reference(&id(8)), None);
        assert_eq!(
            Table::default().price_of(SCAN),
            None,
            "not a scanner: no selling price"
        );
    }
}
