pub mod abuseipdb;
pub mod api;
pub mod dns;
pub mod geo;
pub mod hosting;
pub mod lookup;
pub mod provider;
pub mod rdap;
pub mod rdap_check;
pub mod rdns;
pub mod relays;
pub mod share;
pub mod shodan;
pub mod tor;

/// Provider names in `ip_intel` records.
pub const MAXMIND: &str = "maxmind-geolite2";
pub const TOR: &str = "tor-exits";
/// The Onionoo relay index (GH #138); `TOR` keeps meaning "exit".
pub const TOR_RELAYS: &str = "tor-relays";
pub const ABUSEIPDB: &str = "abuseipdb";
pub const SHODAN: &str = "shodan";
pub const INTERNETDB: &str = "shodan-internetdb";
pub const RDAP: &str = "rdap";

/// A provider this version knows: results from others are not accepted.
pub struct ProviderInfo {
    pub name: &'static str,
    /// Shown on the IP page.
    pub label: &'static str,
    /// Whether anonymous visitors see its results. Only for facts the public
    /// pages already show (country, ASN, Tor flag); a provider that reports
    /// open ports or abuse reports stays admin-only.
    pub public: bool,
    /// Looked up through a third-party API: every lookup is recorded (no
    /// "same as last time" skip), and results come back on refresh.
    pub api: bool,
    /// Prefix of this provider's tags in `ip_intel_tags`.
    pub tag_prefix: &'static str,
    /// Whether its terms allow passing its results on: only these stay in
    /// a redistributable export.
    pub redistributable: bool,
    /// Whether it answers for IPv6 addresses.
    pub ipv6: bool,
}

pub const KNOWN_PROVIDERS: &[ProviderInfo] = &[
    ProviderInfo {
        name: TOR,
        label: "Tor exit list",
        public: true,
        api: false,
        tag_prefix: "tor",
        redistributable: true,
        ipv6: true,
    },
    // Public: anonymous visitors see "Tor exit" / "Tor relay (roles)" only;
    // nickname, fingerprint and the rest are admin-only (`intel_facts`).
    ProviderInfo {
        name: TOR_RELAYS,
        label: "Tor relays (Onionoo)",
        public: true,
        api: false,
        tag_prefix: "tor-relay",
        redistributable: true,
        ipv6: true,
    },
    ProviderInfo {
        name: MAXMIND,
        label: "MaxMind GeoLite2",
        public: true,
        api: false,
        tag_prefix: "maxmind",
        redistributable: false,
        ipv6: true,
    },
    ProviderInfo {
        name: ABUSEIPDB,
        label: "AbuseIPDB",
        public: false,
        api: true,
        tag_prefix: "abuseipdb",
        redistributable: false,
        ipv6: true,
    },
    ProviderInfo {
        name: RDAP,
        label: "RDAP registry",
        public: false,
        api: true,
        tag_prefix: "rdap",
        redistributable: false,
        ipv6: true,
    },
    ProviderInfo {
        name: SHODAN,
        label: "Shodan",
        public: false,
        api: true,
        tag_prefix: "shodan",
        redistributable: false,
        ipv6: true,
    },
    ProviderInfo {
        name: INTERNETDB,
        label: "Shodan InternetDB",
        public: false,
        api: true,
        tag_prefix: "internetdb",
        redistributable: false,
        ipv6: false,
    },
];

/// Largest `data_json` accepted from a peer; a node writes at most
/// [`api::MAX_DATA_BYTES`].
pub const MAX_PEER_DATA_BYTES: usize = 32 * 1024;

pub fn provider_info(name: &str) -> Option<&'static ProviderInfo> {
    KNOWN_PROVIDERS.iter().find(|p| p.name == name)
}

/// Whether `name` is asked about IPv6 addresses ([`ProviderInfo::ipv6`];
/// a provider this version does not know is).
pub fn asks_ipv6(name: &str) -> bool {
    provider_info(name).is_none_or(|i| i.ipv6)
}

/// Tags of one result, for filtering the admin IP list (stored with the
/// provider's [`ProviderInfo::tag_prefix`]).
pub fn tags(provider: &str, data: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    match provider {
        ABUSEIPDB => abuseipdb::tags(data),
        SHODAN | INTERNETDB => shodan::tags(data),
        RDAP => rdap::tags(data),
        TOR_RELAYS => relays::tags(data),
        _ => vec![],
    }
}

use crate::config::Config;
use crate::lock::{MutexExt, RwLockExt};
use crate::store::Store;
use crate::store::recorder::Recorder;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, info, warn};

/// GeoIP readers shared with the trap; None until the MaxMind DBs exist.
pub type SharedGeo = Arc<RwLock<Option<geo::GeoIp>>>;
/// Tor exit list shared with the trap.
pub type SharedTor = Arc<RwLock<tor::TorExitList>>;
/// RDAP bootstrap shared with the scheduler that refreshes it.
pub use rdap::SharedRdap;

/// The providers a node was started with.
pub type Providers = Vec<Arc<dyn provider::Provider>>;

/// The providers this node can run: the local databases always, the API
/// providers that have a config section (and, for InternetDB, `enabled`).
pub fn providers(
    cfg: &Config,
    store: &Store,
    geo: &SharedGeo,
    tor: &SharedTor,
    rdap: &SharedRdap,
) -> Providers {
    use api::{ApiProvider, Limit, Period};
    let daily = |max: u64| -> Vec<Limit> {
        (max > 0)
            .then_some(Limit {
                period: Period::Day,
                max,
            })
            .into_iter()
            .collect()
    };
    let refresh = cfg.enrichment.refresh_after_days;
    let mut out: Providers = vec![
        Arc::new(provider::MaxMind(geo.clone())),
        Arc::new(provider::TorExits(tor.clone())),
        Arc::new(provider::TorRelays(tor.clone())),
        Arc::new(rdap::Rdap::with_shared(rdap.clone())),
    ];
    if let Some(a) = &cfg.abuseipdb {
        out.push(Arc::new(ApiProvider::new(
            abuseipdb::AbuseIpDb {
                base: abuseipdb::BASE.into(),
                key: a.api_key.expose().trim().into(),
                max_age_days: a.max_age_days,
            },
            store.clone(),
            daily(a.daily_limit),
            refresh,
        )));
    }
    if let Some(s) = &cfg.shodan {
        out.push(Arc::new(ApiProvider::new(
            shodan::ShodanHost {
                base: shodan::HOST_BASE.into(),
                key: s.api_key.expose().trim().into(),
            },
            store.clone(),
            daily(s.daily_limit),
            refresh,
        )));
    }
    if let Some(i) = cfg.internetdb.as_ref().filter(|i| i.enabled) {
        out.push(Arc::new(ApiProvider::new(
            shodan::InternetDb {
                base: shodan::INTERNETDB_BASE.into(),
            },
            store.clone(),
            daily(i.daily_limit),
            refresh,
        )));
    }
    let api: Vec<&str> = out.iter().skip(4).map(|p| p.name()).collect();
    if !api.is_empty() {
        info!(providers = ?api, "API enrichment providers configured");
    }
    out
}

/// How often the enrichment loop runs.
const ENRICH_TICK: Duration = Duration::from_secs(60);

/// One pass: for every provider this node can serve, look up IPs that have
/// no result from it yet (or, for API providers, are due again) and record
/// what it says. In a cluster the able nodes take turns by rank (see
/// [`provider::step_in_secs`]). Returns how many results were written.
pub async fn enrich_once(rec: &Recorder, providers: &Providers) -> anyhow::Result<usize> {
    announce(rec, providers);
    let mut written = 0;
    for p in providers.iter().filter(|p| p.ready()) {
        written += enrich_provider(rec, p.as_ref(), providers).await?;
    }
    Ok(written)
}

/// Announce the providers this node can serve right now (heartbeats).
fn announce(rec: &Recorder, providers: &Providers) {
    if let Some(node) = rec.node() {
        node.set_providers(
            providers
                .iter()
                .filter(|p| p.ready())
                .map(|p| p.name().to_string())
                .collect(),
        );
    }
}

/// Whether a live, unblocked member (this node included) serves `name`.
fn served_in_cluster(rec: &Recorder, providers: &Providers, name: &str) -> bool {
    if providers.iter().any(|p| p.name() == name && p.ready()) {
        return true;
    }
    rec.node().is_some_and(|node| {
        let me = node.id();
        node.live_members(LIVE_WINDOW).into_iter().any(|id| {
            id != me
                && !node.is_blocked(&id)
                && node
                    .status
                    .known(&id)
                    .is_some_and(|k| k.hb.providers.iter().any(|n| n == name))
        })
    })
}

/// This node's place among the live members that serve `name` (0 standalone).
fn rank_for(rec: &Recorder, name: &str) -> usize {
    let Some(node) = rec.node() else { return 0 };
    let me = node.id();
    let members = node.members();
    let able: Vec<_> = node
        .live_members(LIVE_WINDOW)
        .into_iter()
        .filter(|id| *id == me || !node.is_blocked(id))
        .filter(|id| {
            *id == me
                || node
                    .status
                    .known(id)
                    .is_some_and(|k| k.hb.providers.iter().any(|n| n == name))
        })
        .map(|id| (id, members.get(&id).is_some_and(|m| m.address.is_some())))
        .collect();
    share::rank(me, &able).unwrap_or(0)
}

/// Extra wait before InternetDB takes an IP while Shodan is served, so the
/// full host lookup gets it first.
const INTERNETDB_DEFER_SECS: i64 = 900;

/// One batch for one provider; returns how many results were written.
async fn enrich_provider(
    rec: &Recorder,
    p: &dyn provider::Provider,
    all: &Providers,
) -> anyhow::Result<usize> {
    let step = provider::step_in_secs(rank_for(rec, p.name()));
    let info = provider_info(p.name());
    // Protocol 9: a provider the recorder buys is given away except for the
    // sources of the other market members, who buy it.
    let others: Vec<_> = rec
        .node()
        .filter(|n| bought_by_recorder(p.name()) && crate::credits::pay::trades_market(n.proto.1))
        .map(|n| {
            let me = n.id();
            n.members()
                .iter()
                .filter(|(id, m)| **id != me && crate::credits::pay::trades_market(m.proto_max))
                .map(|(id, _)| *id)
                .collect()
        })
        .unwrap_or_default();
    let recorded_by = crate::store::requests::RecordedBy::NotBy(&others);
    let ips = if info.is_some_and(|i| i.api) {
        let mut step = step;
        let covered_by = (p.name() == INTERNETDB).then_some(SHODAN);
        if covered_by.is_some() && served_in_cluster(rec, all, SHODAN) {
            step += INTERNETDB_DEFER_SECS;
        }
        let skip = p.skip_list();
        rec.store()
            .intel_candidates(&crate::store::requests::IntelCandidates {
                provider: p.name(),
                step_secs: step,
                refresh_after_days: p.refresh_after_days(),
                ipv6: p.ipv6(),
                skip: &skip,
                covered_by,
                recorded_by,
                limit: p.batch(),
            })
            .await?
    } else {
        rec.store()
            .ips_missing_intel(p.name(), step, recorded_by, p.batch())
            .await?
    };
    if ips.is_empty() {
        return Ok(0);
    }
    let api = info.is_some_and(|i| i.api);
    let mut written = 0;
    for f in p.lookup(&ips).await {
        if api {
            rec.record_lookup(&f.ip, p.name(), f.source_version.as_deref(), f.data)
                .await?;
        } else {
            rec.record_intel(&f.ip, p.name(), f.source_version.as_deref(), f.data)
                .await?;
        }
        written += 1;
    }
    Ok(written)
}

/// How often the announced provider list is refreshed.
const ANNOUNCE_TICK: Duration = Duration::from_secs(10);

/// Keep filling in results for IPs that lack them, until shutdown: one task
/// per provider, so a slow API never holds up the others.
pub async fn enrich_loop(
    rec: Recorder,
    providers: Providers,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    for p in &providers {
        tokio::spawn(provider_loop(
            rec.clone(),
            p.clone(),
            providers.clone(),
            shutdown.clone(),
        ));
    }
    if let (Some(node), Some(rdap)) = (rec.node(), providers.iter().find(|p| p.name() == RDAP)) {
        tokio::spawn(check_loop(
            rec.clone(),
            rdap.clone(),
            node.identity.derive_key(rdap_check::KEY_LABEL),
            shutdown.clone(),
        ));
    }
    let mut shutdown = shutdown;
    loop {
        announce(&rec, &providers);
        tokio::select! {
            _ = tokio::time::sleep(ANNOUNCE_TICK) => {}
            _ = shutdown.changed() => break,
        }
    }
}

async fn provider_loop(
    rec: Recorder,
    p: Arc<dyn provider::Provider>,
    all: Providers,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut wait = Duration::from_secs(5);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => break,
        }
        wait = ENRICH_TICK;
        if !p.ready() {
            continue;
        }
        match enrich_provider(&rec, p.as_ref(), &all).await {
            Ok(0) => {}
            Ok(n) => {
                info!(provider = p.name(), n, "enrichment: results recorded");
                // A full batch: more are probably waiting.
                if n as i64 >= p.batch() {
                    wait = Duration::from_secs(1);
                }
            }
            Err(e) => warn!(provider = p.name(), ?e, "enrichment pass failed"),
        }
    }
}

/// Whether the recorder of a source buys `name`'s answer about it
/// (protocol 9): a provider traded in the market. RDAP and the rest are
/// fetched by the able nodes in turns and shared for free.
pub fn bought_by_recorder(name: &str) -> bool {
    use crate::credits::price::{MARKET_GOODS, is_free};
    provider_info(name).is_some() && MARKET_GOODS.contains(&name) && !is_free(name)
}

/// How often the recorder's buyer runs.
const BUY_TICK: Duration = Duration::from_secs(60);
/// Buyer passes an hour.
const BUYS_PER_HOUR: i64 = 3600 / BUY_TICK.as_secs() as i64;
/// How long a source asked for is not asked again: a bought answer reaches
/// this node by replication, a declined one waits its turn.
const BUY_PAUSE: Duration = Duration::from_secs(3600);

/// Sources the buyer asked for lately, by provider and address.
#[derive(Debug, Default)]
pub struct Asked(std::collections::HashMap<(String, String), std::time::Instant>);

impl Asked {
    fn skip(&mut self, provider: &str) -> Vec<String> {
        self.0.retain(|_, at| at.elapsed() < BUY_PAUSE);
        self.0
            .keys()
            .filter(|(p, _)| p == provider)
            .map(|(_, ip)| ip.clone())
            .collect()
    }
}

/// One pass of the recorder's buyer (protocol 9): for each provider of
/// [`bought_by_recorder`] that `own` does not serve, the node's own
/// sources that lack its answer (or are due again after
/// `refresh_after_days`) are wanted, capped at what a provider asks in an
/// hour; up to a batch of them is bought, each at most at this node's bid
/// and only from members of the free market. The serving node writes the
/// answer into the dataset (`pay::serve`), so data its terms keep from
/// redistribution goes nowhere else. An ask above the bid is not offered
/// and counted. Returns how many answers were bought.
pub async fn buy_pass(
    node: &Arc<crate::cluster::Node>,
    own: &Providers,
    refresh_after_days: f64,
    asked: &mut Asked,
) -> anyhow::Result<usize> {
    use crate::credits::{pay, price};
    if !pay::trades_market(node.proto.1) {
        return Ok(0);
    }
    let me = node.id();
    let mut bought = 0;
    for info in KNOWN_PROVIDERS
        .iter()
        .filter(|i| bought_by_recorder(i.name))
    {
        let name = info.name;
        if own.iter().any(|p| p.name() == name && p.ready()) {
            node.credits.wants.lock_or_recover().set(name, 0);
            continue;
        }
        let members = node.members();
        let Some(ask) = pay::quotes(node, own)
            .get(name)
            .into_iter()
            .flatten()
            .filter(|q| {
                members
                    .get(&q.server)
                    .is_some_and(|m| pay::trades_market(m.proto_max))
            })
            .map(|q| q.price_mc as crate::credits::Mc)
            .min()
        else {
            // No member of the market sells it: it takes no share of the
            // budget from goods that can be bought.
            node.credits.wants.lock_or_recover().set(name, 0);
            continue;
        };
        let skip = asked.skip(name);
        let due = node
            .store
            .intel_candidates(&crate::store::requests::IntelCandidates {
                provider: name,
                step_secs: 0,
                // A dataset like MaxMind's is looked up once, not refreshed.
                refresh_after_days: if info.api { refresh_after_days } else { 0.0 },
                ipv6: info.ipv6,
                skip: &skip,
                covered_by: None,
                recorded_by: crate::store::requests::RecordedBy::Own(&me),
                limit: api::BATCH * BUYS_PER_HOUR,
            })
            .await?;
        node.credits
            .wants
            .lock_or_recover()
            .set(name, due.len() as u32);
        if due.is_empty() {
            continue;
        }
        let bid = match price::own_bid(node, name).await {
            Ok(bid) => bid,
            Err(e) => {
                // Not a refusal: nothing is counted against the ask.
                warn!(?e, provider = name, "market: no bid, nothing bought");
                continue;
            }
        };
        if ask > bid {
            node.credits.market.over_bid(name);
            info!(good = name, ask, bid, "market: ask above bid, not bought");
            continue;
        }
        let wanted = [name.to_string()];
        for ip in due.into_iter().take(api::BATCH as usize) {
            let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
                continue;
            };
            asked
                .0
                .insert((name.to_string(), ip), std::time::Instant::now());
            let answers = pay::ask(node, own, addr, &wanted, &wanted, Some(bid)).await;
            if answers
                .iter()
                .any(|a| a.resp.findings.iter().any(|f| f.provider == name))
            {
                bought += 1;
            }
        }
    }
    Ok(bought)
}

/// Buy the answers of keyed providers about this node's own sources
/// ([`buy_pass`]) until shutdown.
pub async fn buy_loop(
    node: Arc<crate::cluster::Node>,
    providers: Providers,
    refresh_after_days: f64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut asked = Asked::default();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(BUY_TICK) => {}
            _ = shutdown.changed() => break,
        }
        match buy_pass(&node, &providers, refresh_after_days, &mut asked).await {
            Ok(0) => {}
            Ok(n) => info!(n, "enrichment: answers bought"),
            Err(e) => warn!(?e, "enrichment buyer pass failed"),
        }
    }
}

/// How often the RDAP spot-check runs.
const CHECK_TICK: Duration = Duration::from_secs(120);

/// Spot-check other origins' RDAP rows until shutdown ([`check_pass`]).
async fn check_loop(
    rec: Recorder,
    rdap: Arc<dyn provider::Provider>,
    key: [u8; 32],
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(CHECK_TICK) => {}
            _ = shutdown.changed() => break,
        }
        if !rdap.ready() {
            continue;
        }
        match check_pass(&rec, rdap.as_ref(), &key, rdap_check::RECHECK_AFTER).await {
            Ok(c) if c.disputed > 0 => {
                warn!(
                    ?c,
                    "rdap spot-check: a member's registry answers differ from ours"
                )
            }
            Ok(c) if c != Checked::default() => debug!(?c, "rdap spot-check"),
            Ok(_) => {}
            Err(e) => warn!(?e, "rdap spot-check failed"),
        }
    }
}

/// What one [`check_pass`] did.
#[derive(Debug, Default, PartialEq)]
pub struct Checked {
    /// Same tags as this node's own query.
    pub agreed: usize,
    /// Different once: asked again after [`rdap_check::RECHECK_AFTER`].
    pub pending: usize,
    /// Different twice: this node wrote its own row, a dispute counted.
    pub disputed: usize,
}

/// One RDAP spot-check pass: up to [`rdap_check::CHECK_BATCH`] RDAP rows
/// that another origin wrote in the last [`rdap_check::CHECK_WINDOW_DAYS`]
/// days, are [`rdap_check::designated`] for this node and are not checked
/// yet, asked again through `rdap` (the provider the enrichment uses, so
/// the same rate limits apply). Same tags: checked. Different: asked once
/// more after `recheck_after`; still different, this node records its own
/// row and the origin gets a dispute (`rdap_checks`, local). A dispute is
/// only counted: blocking a member stays the operator's decision.
pub async fn check_pass(
    rec: &Recorder,
    rdap: &dyn provider::Provider,
    me_key: &[u8; 32],
    recheck_after: Duration,
) -> anyhow::Result<Checked> {
    let me = rec.node_id().map(|id| id.0.to_vec()).unwrap_or_default();
    let pool = &rec.store().pool;
    // First mismatches that waited long enough, then new rows.
    let mut todo: Vec<(String, Vec<u8>, bool)> = sqlx::query_as::<_, (String, Vec<u8>)>(
        "SELECT ip, origin FROM rdap_checks
         WHERE agreed IS NULL AND checked_at <= datetime('now', ?)
         ORDER BY checked_at LIMIT ?",
    )
    .bind(format!("-{} seconds", recheck_after.as_secs()))
    .bind(rdap_check::CHECK_BATCH)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|(ip, origin)| (ip, origin, true))
    .collect();
    let fresh: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT i.ip, i.origin FROM ip_intel i
         WHERE i.provider = ? AND i.origin != ? AND length(i.origin) > 0
           AND i.fetched_at >= datetime('now', ?)
           AND NOT EXISTS (SELECT 1 FROM rdap_checks c WHERE c.ip = i.ip AND c.origin = i.origin
                             AND (c.agreed IS NOT 1 OR c.checked_at >= i.fetched_at))
         ORDER BY i.fetched_at DESC",
    )
    .bind(RDAP)
    .bind(&me)
    .bind(format!("-{} days", rdap_check::CHECK_WINDOW_DAYS))
    .fetch_all(pool)
    .await?;
    let room = (rdap_check::CHECK_BATCH as usize).saturating_sub(todo.len());
    todo.extend(
        fresh
            .into_iter()
            .filter(|(ip, _)| rdap_check::designated(me_key, ip))
            .take(room)
            .map(|(ip, origin)| (ip, origin, false)),
    );
    let mut out = Checked::default();
    for (ip, origin, second) in todo {
        let theirs: Option<String> = sqlx::query_scalar(
            "SELECT data_json FROM ip_intel WHERE ip = ? AND provider = ? AND origin = ?",
        )
        .bind(&ip)
        .bind(RDAP)
        .bind(&origin)
        .fetch_optional(pool)
        .await?;
        let Some(theirs) = theirs else { continue };
        // Not answered now: asked again next pass.
        let Some(own) = rdap
            .lookup(std::slice::from_ref(&ip))
            .await
            .into_iter()
            .next()
        else {
            continue;
        };
        let as_map = |v: serde_json::Value| v.as_object().cloned().unwrap_or_default();
        let theirs = as_map(serde_json::from_str(&theirs).unwrap_or_default());
        let agreed = rdap::tags(&as_map(own.data.clone())) == rdap::tags(&theirs);
        let state = match (agreed, second) {
            (true, _) => {
                out.agreed += 1;
                Some(true)
            }
            (false, false) => {
                out.pending += 1;
                None
            }
            (false, true) => {
                rec.record_lookup(&ip, RDAP, own.source_version.as_deref(), own.data)
                    .await?;
                out.disputed += 1;
                Some(false)
            }
        };
        sqlx::query(
            "INSERT INTO rdap_checks (ip, origin, checked_at, agreed) VALUES (?, ?, ?, ?)
             ON CONFLICT(ip, origin) DO UPDATE SET
               checked_at = excluded.checked_at, agreed = excluded.agreed",
        )
        .bind(&ip)
        .bind(&origin)
        .bind(crate::store::data::now_ts())
        .bind(state)
        .execute(pool)
        .await?;
    }
    Ok(out)
}

fn is_stale_at(value: Option<&str>) -> bool {
    match value {
        // Stale once ~23h old. The scheduler sleeps 24h + up to 1h of jitter,
        // so a `> 24h` test (with truncating num_hours) would read 24 and skip
        // the refresh every other cycle, stretching "daily" to ~48h.
        Some(v) => chrono::DateTime::parse_from_rfc3339(v)
            .map(|t| chrono::Utc::now().signed_duration_since(t) >= chrono::Duration::hours(23))
            .unwrap_or(true),
        None => true,
    }
}

/// Retry delays after failed fetches: doubling from `first` up to `max`.
#[derive(Debug, Clone, Copy)]
struct Backoff {
    first: Duration,
    max: Duration,
    failures: u32,
}

impl Backoff {
    const fn new(first: Duration, max: Duration) -> Self {
        Self {
            first,
            max,
            failures: 0,
        }
    }

    /// Count a failure; returns how long to wait before the next attempt.
    fn fail(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        let factor = 1u32 << (self.failures - 1).min(16);
        self.first.saturating_mul(factor).min(self.max)
    }

    fn reset(&mut self) {
        self.failures = 0;
    }
}

/// Tor exit list: retried from 1 min, doubling up to 1 h, until it loads.
const TOR_BACKOFF: Backoff = Backoff::new(Duration::from_secs(60), Duration::from_secs(3600));
/// GeoLite2: from 5 min up to 2 h, so a failing download stays well under
/// MaxMind's daily download limit.
const MAXMIND_BACKOFF: Backoff =
    Backoff::new(Duration::from_secs(300), Duration::from_secs(2 * 3600));
/// How often a node checks whether its GeoLite2 databases are stale.
const MAXMIND_CHECK: Duration = Duration::from_secs(3600);

/// RDAP bootstrap: refreshed weekly, retried like the Tor list.
const RDAP_BACKOFF: Backoff = Backoff::new(Duration::from_secs(60), Duration::from_secs(3600));

/// Fetch the RDAP bootstrap files and swap them into the shared state;
/// returns when to ask again.
async fn refresh_rdap(cfg: &Config, rdap: &SharedRdap, backoff: &mut Backoff) -> Duration {
    match rdap::Bootstrap::refresh(&cfg.data_dir).await {
        Ok(()) => {
            // Reads and parses both files: off the async workers.
            let dir = cfg.data_dir.clone();
            match tokio::task::spawn_blocking(move || rdap::Bootstrap::load(&dir)).await {
                Ok(b) => *rdap.write_or_recover() = b,
                Err(e) => warn!(?e, "loading the rdap bootstrap failed"),
            }
            info!("rdap bootstrap refreshed");
            backoff.reset();
            rdap::BOOTSTRAP_MAX_AGE
        }
        Err(e) => {
            let wait = backoff.fail();
            warn!(error = %format!("{e:#}"), retry_in_secs = wait.as_secs(), "rdap bootstrap refresh failed; keeping previous");
            wait
        }
    }
}

/// `intel_meta` key recording one edition's last successful download.
fn edition_key(edition: &str) -> String {
    format!("maxmind_last_fetch:{edition}")
}

/// Download the GeoLite2 databases that are missing or stale (needs
/// `[maxmind]` credentials) and load them; they stay on this node. Each
/// database keeps its own fetch time, so when one download fails the other
/// is not fetched again (MaxMind counts every download against a daily
/// limit). Errors when a download or the reload failed.
async fn refresh_maxmind(store: &Store, cfg: &Config, geo: &SharedGeo) -> anyhow::Result<()> {
    let Some(mm) = &cfg.maxmind else {
        return Ok(());
    };
    let mut fetched = 0;
    let mut failed = None;
    for edition in geo::EDITIONS {
        let file = cfg.data_dir.join(format!("{edition}.mmdb"));
        let last = store.intel_get(&edition_key(edition)).await?;
        if file.exists() && !is_stale_at(last.as_deref()) {
            continue;
        }
        match geo::download_edition(
            &cfg.data_dir,
            edition,
            &mm.account_id,
            mm.license_key.expose(),
        )
        .await
        {
            Ok(()) => {
                fetched += 1;
                store
                    .intel_set(&edition_key(edition), &chrono::Utc::now().to_rfc3339())
                    .await?;
            }
            Err(e) => {
                warn!(edition, error = %format!("{e:#}"), "maxmind download failed; keeping previous");
                failed = Some(e);
            }
        }
    }
    let loaded = geo.read_or_recover().is_some();
    if fetched > 0 || !loaded {
        match geo::GeoIp::load_blocking(&cfg.data_dir).await {
            Ok(g) => {
                *geo.write_or_recover() = Some(g);
                if fetched > 0 {
                    info!(databases = fetched, "maxmind databases refreshed");
                }
            }
            // Both files are needed; a first install whose ASN download
            // failed has nothing to load yet.
            Err(e) if failed.is_some() => debug!(?e, "maxmind databases not loadable yet"),
            Err(e) => return Err(e.context("maxmind reload")),
        }
    }
    if let Some(e) = failed {
        return Err(e);
    }
    if fetched > 0 {
        // Both databases are current: what the admin pages show.
        if let Err(e) = store
            .intel_set("maxmind_last_fetch", &chrono::Utc::now().to_rfc3339())
            .await
        {
            warn!(?e, "recording the MaxMind fetch time failed");
        }
    }
    Ok(())
}

/// Unload the exit list once its file is older than [`tor::MAX_AGE`]
/// (fetching or copying it kept failing): from a stale list the trap would
/// record "not an exit" for exits that appeared since, and scanners believe
/// that. Without a list their Tor status is unknown (`scan.tor_unknown`);
/// IPs already recorded as exits stay exits.
fn drop_stale_tor(tor: &SharedTor, cfg: &Config) {
    if !tor.read_or_recover().has_bulk() || !tor::stale(&cfg.data_dir) {
        return;
    }
    warn!(
        "tor exit list older than {} h: unloaded until a fresh one is fetched",
        tor::MAX_AGE.as_secs() / 3600
    );
    // The relay index stays: it ages on its own (`TorExitList::relays`).
    let kept = tor.read_or_recover().without_bulk();
    *tor.write_or_recover() = kept;
}

/// Warn, at most hourly, while no Tor exit list is loaded: Tor exits cannot
/// be told apart from scanners then (see `scan.tor_unknown`).
fn warn_without_tor_list(tor: &SharedTor, cfg: &Config, last: &mut Option<std::time::Instant>) {
    if !tor.read_or_recover().is_empty() {
        return;
    }
    if last.is_some_and(|t| t.elapsed() < Duration::from_secs(3600)) {
        return;
    }
    *last = Some(std::time::Instant::now());
    let effect = match cfg.scan.safety.tor_unknown {
        crate::config::TorUnknown::Defer => "scans of IPs with an unknown Tor status are deferred",
        crate::config::TorUnknown::Scan => {
            "Tor exits may be counter-scanned (scan.tor_unknown = \"scan\")"
        }
    };
    warn!("no Tor exit list loaded yet: {effect}");
}

/// Daily intel refresh (spec §9): at startup (Tor always, MaxMind when stale
/// or not loaded, to spare its download quota), then every 24h ± jitter.
/// Failed fetches are retried with backoff until they succeed. Each
/// successful fetch is loaded into the shared state the trap reads.
pub async fn run_scheduler(
    rec: Recorder,
    cfg: Config,
    geo: SharedGeo,
    tor: SharedTor,
    rdap: SharedRdap,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let store = rec.store().clone();
    tokio::spawn(hosting_loop(store.clone(), cfg.clone(), shutdown.clone()));
    tokio::spawn(relays_loop(
        rec.clone(),
        cfg.clone(),
        tor.clone(),
        shutdown.clone(),
    ));
    if let Recorder::Cluster(node) = &rec {
        return run_cluster(node.clone(), cfg, geo, tor, rdap, shutdown).await;
    }
    if cfg.maxmind.is_none() && geo.read_or_recover().is_none() {
        warn!("no [maxmind] credentials and no GeoLite2 databases: GeoIP enrichment is off");
    }
    let now = tokio::time::Instant::now();
    let (mut tor_next, mut mm_next) = (now, now);
    // Fresh files from the last run are not downloaded again.
    let mut rdap_next = now + rdap::Bootstrap::due_in(&cfg.data_dir);
    let (mut tor_backoff, mut mm_backoff) = (TOR_BACKOFF, MAXMIND_BACKOFF);
    let mut rdap_backoff = RDAP_BACKOFF;
    let mut warned = None;
    loop {
        let now = tokio::time::Instant::now();
        if now >= tor_next {
            match tor::TorExitList::refresh(&cfg.data_dir).await {
                Ok(n) => {
                    info!(n, "tor exit list refreshed");
                    match tor::TorExitList::load(&cfg.data_dir) {
                        Ok(l) => *tor.write_or_recover() = l,
                        Err(e) => warn!(?e, "tor exit list reload failed"),
                    }
                    if let Err(e) = store
                        .intel_set("tor_last_fetch", &chrono::Utc::now().to_rfc3339())
                        .await
                    {
                        warn!(?e, "recording the tor exit list fetch time failed");
                    }
                    tor_backoff.reset();
                    // 24h ± up to 1h deterministic-ish jitter from nanos.
                    let jitter = Duration::from_secs(
                        (chrono::Utc::now().timestamp_subsec_nanos() as u64) % 3600,
                    );
                    tor_next = now + Duration::from_secs(24 * 3600) + jitter;
                }
                Err(e) => {
                    let wait = tor_backoff.fail();
                    warn!(error = %format!("{e:#}"), retry_in_secs = wait.as_secs(), "tor exit list refresh failed; keeping previous");
                    tor_next = now + wait;
                }
            }
            drop_stale_tor(&tor, &cfg);
            warn_without_tor_list(&tor, &cfg, &mut warned);
        }
        if now >= mm_next {
            match refresh_maxmind(&store, &cfg, &geo).await {
                Ok(()) => {
                    mm_backoff.reset();
                    mm_next = now + MAXMIND_CHECK;
                }
                Err(e) => {
                    let wait = mm_backoff.fail();
                    warn!(error = %format!("{e:#}"), retry_in_secs = wait.as_secs(), "maxmind refresh failed");
                    mm_next = now + wait;
                }
            }
        }
        if now >= rdap_next {
            rdap_next = now + refresh_rdap(&cfg, &rdap, &mut rdap_backoff).await;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(tor_next.min(mm_next).min(rdap_next)) => {}
            _ = shutdown.changed() => { break; }
        }
    }
}

/// The X4BNet datacenter ASN list (`hosting`): fetched at startup, then
/// daily with the Tor exit list's jitter and backoff, on every node (35 KB
/// from GitHub). A fetched copy replaces the evidence catalogue's list; a
/// failed fetch keeps the one loaded.
async fn hosting_loop(store: Store, cfg: Config, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut backoff = TOR_BACKOFF;
    loop {
        let wait = match hosting::refresh(&cfg.data_dir).await {
            Ok(n) => {
                info!(n, "datacenter ASN list refreshed");
                let dir = cfg.data_dir.clone();
                if let Err(e) = tokio::task::spawn_blocking(move || hosting::install(&dir)).await {
                    warn!(?e, "loading the datacenter ASN list failed");
                }
                if let Err(e) = store
                    .intel_set(hosting::FETCHED_KEY, &chrono::Utc::now().to_rfc3339())
                    .await
                {
                    warn!(?e, "recording the datacenter ASN list fetch time failed");
                }
                backoff.reset();
                Duration::from_secs(
                    24 * 3600 + (chrono::Utc::now().timestamp_subsec_nanos() as u64) % 3600,
                )
            }
            Err(e) => {
                let wait = backoff.fail();
                warn!(error = %format!("{e:#}"), retry_in_secs = wait.as_secs(), "datacenter ASN list refresh failed; keeping previous");
                wait
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => { break; }
        }
    }
}

/// The Onionoo relay index (GH #138), in a task of its own: the answer is
/// tens of megabytes, and a slow fetch must not hold up the exit list or
/// the MaxMind refresh. Standalone it is fetched daily like the exit list;
/// in a cluster when it is this node's turn ([`share::due`]), and members
/// copy it in the main loop. A 304 from Onionoo counts as a fetch.
async fn relays_loop(
    rec: Recorder,
    cfg: Config,
    tor: SharedTor,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut backoff = TOR_BACKOFF;
    let mut next = tokio::time::Instant::now();
    loop {
        let now = tokio::time::Instant::now();
        let due = match &rec {
            Recorder::Cluster(node) => {
                let age = share::manifests(&node.store)
                    .await
                    .ok()
                    .and_then(|m| m.get(share::RELAYS).map(share::Manifest::age_hours))
                    .unwrap_or(f64::INFINITY);
                let members = node.members();
                let all: Vec<_> = node
                    .live_members(LIVE_WINDOW)
                    .iter()
                    .map(|id| (*id, members.get(id).is_some_and(|m| m.address.is_some())))
                    .collect();
                (node.started.elapsed() > ELECTION_GRACE || members.len() <= 1)
                    && share::rank(node.id(), &all).is_some_and(|r| share::due(r, age))
            }
            _ => true,
        };
        if due && now >= next {
            match relays::Relays::refresh(&cfg.data_dir).await {
                Ok(r) => {
                    if let relays::Refreshed::Updated(n) = r {
                        info!(n, "tor relay index refreshed");
                        reload(&[share::RELAYS.to_string()], &cfg, &tor);
                    }
                    backoff.reset();
                    next = now + Duration::from_secs(24 * 3600);
                    if let Recorder::Cluster(node) = &rec
                        && relays::file(&cfg.data_dir).exists()
                        && let Err(e) = share::publish(node, &cfg.data_dir, &[share::RELAYS]).await
                    {
                        let wait = backoff.fail();
                        warn!(
                            ?e,
                            retry_in_secs = wait.as_secs(),
                            "announcing tor relay index failed"
                        );
                        next = now + wait;
                    }
                }
                Err(e) => {
                    let wait = backoff.fail();
                    warn!(error = %format!("{e:#}"), retry_in_secs = wait.as_secs(), "tor relay index refresh failed; keeping previous");
                    next = now + wait;
                }
            }
        }
        // In a cluster the turn can come any time; standalone only `next`.
        let wake = match &rec {
            Recorder::Cluster(_) => now + INTEL_TICK,
            _ => next,
        };
        tokio::select! {
            _ = tokio::time::sleep_until(wake) => {}
            _ = shutdown.changed() => { break; }
        }
    }
}

/// How often the cluster intel loop runs without news.
const INTEL_TICK: Duration = Duration::from_secs(60);
/// Minimum gap between two passes (log growth wakes the loop).
const INTEL_MIN_GAP: Duration = Duration::from_secs(5);
/// Wait for heartbeats before deciding who fetches.
const ELECTION_GRACE: Duration = Duration::from_secs(90);
/// Heartbeats this recent count a member as alive for the fetch order.
pub(crate) const LIVE_WINDOW: Duration = Duration::from_secs(45);

/// Refresh `maxmind_cluster_seen` at most this often while it holds.
const CLUSTER_SEEN_EVERY: Duration = Duration::from_secs(600);

/// Record, for the stale-intel warning, what a cluster node actually has:
/// the fetch time of the Tor exit list version it holds (the elected
/// fetcher's, not the time it was copied), and, on a node without its own
/// `[maxmind]`, when a live member last offered GeoIP lookups, whose results
/// reach this node as records.
pub async fn note_cluster_intel(
    node: &crate::cluster::Node,
    data_dir: &std::path::Path,
    own_maxmind: bool,
    manifests: &std::collections::HashMap<String, share::Manifest>,
) -> anyhow::Result<()> {
    let store = &node.store;
    if let Some(m) = manifests.get(share::TOR)
        && let Some(at) = m.fetched_rfc3339()
        && let Some(name) = share::file_name(share::TOR)
        && let path = data_dir.join(name)
        && path.exists()
        && share::file_hash(&path)?.0 == m.sha256
        && store.intel_get("tor_last_fetch").await?.as_deref() != Some(at.as_str())
    {
        store.intel_set("tor_last_fetch", &at).await?;
    }
    if !own_maxmind {
        let me = node.id();
        let offered = node.live_members(LIVE_WINDOW).into_iter().any(|id| {
            id != me
                && !node.is_blocked(&id)
                && node
                    .status
                    .known(&id)
                    .is_some_and(|k| k.hb.providers.iter().any(|n| n == MAXMIND))
        });
        let due = match store.intel_get(MAXMIND_CLUSTER_SEEN).await? {
            Some(v) => chrono::DateTime::parse_from_rfc3339(&v).map_or(true, |t| {
                chrono::Utc::now().signed_duration_since(t)
                    >= chrono::Duration::from_std(CLUSTER_SEEN_EVERY).unwrap()
            }),
            None => true,
        };
        if offered && due {
            store
                .intel_set(MAXMIND_CLUSTER_SEEN, &chrono::Utc::now().to_rfc3339())
                .await?;
        }
    }
    Ok(())
}

/// `intel_meta` key: when a member last offered GeoIP lookups to this node.
pub const MAXMIND_CLUSTER_SEEN: &str = "maxmind_cluster_seen";

fn reload(kinds: &[String], cfg: &Config, tor: &SharedTor) {
    if kinds.iter().any(|k| k == share::TOR || k == share::RELAYS) {
        match tor::TorExitList::load(&cfg.data_dir) {
            Ok(l) => *tor.write_or_recover() = l,
            Err(e) => warn!(?e, "tor exit list reload failed"),
        }
    }
}

/// Distributed mode: copy the newer Tor exit list from the cluster, fetch it
/// ourselves when it is our turn (see [`share`]), and keep this node's own
/// GeoLite2 databases fresh.
async fn run_cluster(
    node: std::sync::Arc<crate::cluster::Node>,
    cfg: Config,
    geo: SharedGeo,
    tor: SharedTor,
    rdap: SharedRdap,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let me = node.id();
    let mut changes = node.subscribe_changes();
    let now = std::time::Instant::now();
    let (mut tor_next, mut mm_next) = (now, now);
    // Fresh files from the last run are not downloaded again.
    let mut rdap_next = now + rdap::Bootstrap::due_in(&cfg.data_dir);
    let (mut tor_backoff, mut mm_backoff) = (TOR_BACKOFF, MAXMIND_BACKOFF);
    let mut rdap_backoff = RDAP_BACKOFF;
    let mut warned = None;
    loop {
        changes.borrow_and_update();
        match share::sync_files(&node, &cfg.data_dir).await {
            Ok(kinds) if !kinds.is_empty() => {
                reload(&kinds, &cfg, &tor);
            }
            Ok(_) => {}
            Err(e) => warn!(?e, "intel sync failed"),
        }
        let manifests = share::manifests(&node.store).await.unwrap_or_default();
        let age = |k: &str| manifests.get(k).map_or(f64::INFINITY, |m| m.age_hours());
        if node.started.elapsed() > ELECTION_GRACE || node.members().len() <= 1 {
            let members = node.members();
            let live = node.live_members(LIVE_WINDOW);
            let dialable = |id: &crate::cluster::identity::NodeId| {
                members.get(id).is_some_and(|m| m.address.is_some())
            };
            let all: Vec<_> = live.iter().map(|id| (*id, dialable(id))).collect();
            if share::rank(me, &all).is_some_and(|r| share::due(r, age(share::TOR)))
                && std::time::Instant::now() >= tor_next
            {
                match tor::TorExitList::refresh(&cfg.data_dir).await {
                    Ok(n) => {
                        info!(n, "tor exit list refreshed for the cluster");
                        tor_backoff.reset();
                        reload(&[share::TOR.to_string()], &cfg, &tor);
                        // A published list makes it not due; an unpublished
                        // one would be fetched again every pass.
                        if let Err(e) = share::publish(&node, &cfg.data_dir, &[share::TOR]).await {
                            let wait = tor_backoff.fail();
                            warn!(
                                ?e,
                                retry_in_secs = wait.as_secs(),
                                "announcing tor exit list failed"
                            );
                            tor_next = std::time::Instant::now() + wait;
                        }
                    }
                    Err(e) => {
                        let wait = tor_backoff.fail();
                        warn!(error = %format!("{e:#}"), retry_in_secs = wait.as_secs(), "tor exit list refresh failed");
                        tor_next = std::time::Instant::now() + wait;
                    }
                }
            }
        }
        drop_stale_tor(&tor, &cfg);
        warn_without_tor_list(&tor, &cfg, &mut warned);
        // Every node with credentials keeps its own databases fresh.
        if std::time::Instant::now() >= mm_next {
            match refresh_maxmind(&node.store, &cfg, &geo).await {
                Ok(()) => {
                    mm_backoff.reset();
                    mm_next = std::time::Instant::now() + MAXMIND_CHECK;
                }
                Err(e) => {
                    let wait = mm_backoff.fail();
                    warn!(error = %format!("{e:#}"), retry_in_secs = wait.as_secs(), "maxmind refresh failed");
                    mm_next = std::time::Instant::now() + wait;
                }
            }
        }
        // Every node keeps its own bootstrap fresh; it is small and public.
        if std::time::Instant::now() >= rdap_next {
            rdap_next =
                std::time::Instant::now() + refresh_rdap(&cfg, &rdap, &mut rdap_backoff).await;
        }
        if let Err(e) =
            note_cluster_intel(&node, &cfg.data_dir, cfg.maxmind.is_some(), &manifests).await
        {
            warn!(?e, "recording intel freshness failed");
        }
        tokio::select! {
            _ = tokio::time::sleep(INTEL_TICK) => {}
            _ = changes.changed() => tokio::time::sleep(INTEL_MIN_GAP).await,
            _ = shutdown.changed() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An RDAP provider that answers every IP with `data`.
    struct FixedRdap(serde_json::Value);

    impl provider::Provider for FixedRdap {
        fn name(&self) -> &'static str {
            RDAP
        }
        fn ready(&self) -> bool {
            true
        }
        fn lookup<'a>(
            &'a self,
            ips: &'a [String],
        ) -> futures::future::BoxFuture<'a, Vec<provider::Finding>> {
            Box::pin(async move {
                ips.iter()
                    .map(|ip| provider::Finding {
                        ip: ip.clone(),
                        source_version: None,
                        data: self.0.clone(),
                    })
                    .collect()
            })
        }
    }

    /// A store holding one RDAP row of another origin, for an IP `key`
    /// designates; returns the IP and that origin.
    async fn peer_rdap_row(key: &[u8; 32], data: &str) -> (Store, String, Vec<u8>) {
        use crate::cluster::record::{IpIntelRec, Record};
        use crate::store::data::{Ctx, apply};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let store = Store::connect(&path).await.unwrap();
        let ip = (0..255u8)
            .map(|i| format!("198.51.100.{i}"))
            .find(|ip| rdap_check::designated(key, ip))
            .expect("one of 255 is designated");
        let peer = crate::cluster::identity::Identity::generate().unwrap().id;
        let rec = Record::IpIntel(IpIntelRec {
            build: String::new(),
            ip: ip.clone(),
            provider: RDAP.into(),
            fetched_at: crate::store::data::now_ts(),
            source_version: None,
            data_json: data.into(),
        });
        let mut conn = store.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: Some(&peer),
            hlc: crate::cluster::hlc::Hlc::new().now(),
        };
        apply(&mut conn, ctx, &rec).await.unwrap();
        (store, ip, peer.0.to_vec())
    }

    async fn rdap_rows(store: &Store) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM ip_intel WHERE provider = 'rdap'")
            .fetch_one(&store.pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_wrong_country_is_disputed_after_a_second_query() {
        let key = [7u8; 32];
        let (store, ip, peer) = peer_rdap_row(&key, r#"{"country":"US"}"#).await;
        let rec = store.local();
        let own = FixedRdap(serde_json::json!({"country": "DE"}));
        let first = check_pass(&rec, &own, &key, Duration::ZERO).await.unwrap();
        assert_eq!(first.pending, 1, "{first:?}");
        assert_eq!(
            rdap_rows(&store).await,
            1,
            "nothing written after one query"
        );
        // Not due again before the wait is over.
        let early = check_pass(&rec, &own, &key, Duration::from_secs(600))
            .await
            .unwrap();
        assert_eq!(early, Checked::default());
        let second = check_pass(&rec, &own, &key, Duration::ZERO).await.unwrap();
        assert_eq!(second.disputed, 1, "{second:?}");
        assert_eq!(rdap_rows(&store).await, 2, "this node's own row");
        let counts = rdap_check::counts(&store.pool).await.unwrap();
        assert_eq!(counts.get(&peer), Some(&(1, 1)), "disputes[origin] = 1");
        let own_row: String = sqlx::query_scalar(
            "SELECT data_json FROM ip_intel WHERE ip = ? AND provider = 'rdap' AND origin = x''",
        )
        .bind(&ip)
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert!(own_row.contains("DE"), "{own_row}");
        // Checked for good: not asked again.
        let again = check_pass(&rec, &own, &key, Duration::ZERO).await.unwrap();
        assert_eq!(again, Checked::default());
    }

    #[tokio::test]
    async fn matching_tags_are_checked_and_write_nothing() {
        let key = [9u8; 32];
        let (store, _ip, peer) = peer_rdap_row(&key, r#"{"country":"de","fresh":false}"#).await;
        let rec = store.local();
        // Other fields may differ: only the tags count.
        let own = FixedRdap(serde_json::json!({"country": "DE", "name": "X"}));
        let c = check_pass(&rec, &own, &key, Duration::ZERO).await.unwrap();
        assert_eq!(c.agreed, 1, "{c:?}");
        assert_eq!(rdap_rows(&store).await, 1);
        let counts = rdap_check::counts(&store.pool).await.unwrap();
        assert_eq!(counts.get(&peer), Some(&(1, 0)));
        let again = check_pass(&rec, &own, &key, Duration::ZERO).await.unwrap();
        assert_eq!(again, Checked::default(), "checked once per row");
    }

    #[tokio::test]
    async fn rows_not_designated_are_not_checked() {
        let key = [7u8; 32];
        let (store, _ip, _peer) = peer_rdap_row(&key, r#"{"country":"US"}"#).await;
        let other = (0u8..)
            .map(|i| [i; 32])
            .find(|k| {
                (0..255u8)
                    .map(|i| format!("198.51.100.{i}"))
                    .find(|ip| rdap_check::designated(&key, ip))
                    .is_some_and(|ip| !rdap_check::designated(k, &ip))
            })
            .unwrap();
        let own = FixedRdap(serde_json::json!({"country": "DE"}));
        let c = check_pass(&store.local(), &own, &other, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(c, Checked::default());
    }

    #[test]
    fn a_removed_provider_is_unknown() {
        assert!(provider_info("greynoise-community").is_none());
    }

    #[test]
    fn backoff_doubles_up_to_its_cap_and_resets() {
        let mut b = TOR_BACKOFF;
        let waits: Vec<u64> = (0..9).map(|_| b.fail().as_secs()).collect();
        assert_eq!(waits, [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600]);
        b.reset();
        assert_eq!(b.fail().as_secs(), 60);
        let mut m = MAXMIND_BACKOFF;
        let waits: Vec<u64> = (0..6).map(|_| m.fail().as_secs()).collect();
        assert_eq!(waits, [300, 600, 1200, 2400, 4800, 7200]);
        // Far past the cap nothing overflows.
        for _ in 0..100 {
            m.fail();
        }
        assert_eq!(m.fail().as_secs(), 7200);
    }

    /// A list whose file went stale is unloaded, so the trap stops
    /// recording "not an exit" from it.
    #[test]
    fn a_stale_tor_list_is_unloaded() {
        let dir = tempfile::tempdir().unwrap();
        let cfg: Config = toml::from_str(&format!(
            "database_path = \"{d}/t.db\"\ndata_dir = \"{d}\"\n",
            d = dir.path().display()
        ))
        .unwrap();
        let path = dir.path().join("tor-exit.txt");
        std::fs::write(&path, "198.51.100.1\n").unwrap();
        let shared: SharedTor =
            Arc::new(RwLock::new(tor::TorExitList::load(&cfg.data_dir).unwrap()));
        drop_stale_tor(&shared, &cfg);
        assert!(!shared.read_or_recover().is_empty(), "fresh: kept");
        let old = std::time::SystemTime::now() - tor::MAX_AGE - Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        drop_stale_tor(&shared, &cfg);
        assert!(shared.read_or_recover().is_empty());
    }

    #[test]
    fn staleness_is_per_timestamp() {
        assert!(is_stale_at(None));
        assert!(is_stale_at(Some("garbage")));
        let fresh = chrono::Utc::now().to_rfc3339();
        assert!(!is_stale_at(Some(&fresh)));
        let old = (chrono::Utc::now() - chrono::Duration::hours(30)).to_rfc3339();
        assert!(is_stale_at(Some(&old)));
    }
}
