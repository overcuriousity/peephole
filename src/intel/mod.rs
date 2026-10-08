pub mod abuseipdb;
pub mod api;
pub mod dns;
pub mod geo;
pub mod lookup;
pub mod provider;
pub mod rdap;
pub mod rdns;
pub mod share;
pub mod shodan;
pub mod tor;

/// Provider names in `ip_intel` records.
pub const MAXMIND: &str = "maxmind-geolite2";
pub const TOR: &str = "tor-exits";
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
}

pub const KNOWN_PROVIDERS: &[ProviderInfo] = &[
    ProviderInfo {
        name: TOR,
        label: "Tor exit list",
        public: true,
        api: false,
        tag_prefix: "tor",
        redistributable: true,
    },
    ProviderInfo {
        name: MAXMIND,
        label: "MaxMind GeoLite2",
        public: true,
        api: false,
        tag_prefix: "maxmind",
        redistributable: false,
    },
    ProviderInfo {
        name: ABUSEIPDB,
        label: "AbuseIPDB",
        public: false,
        api: true,
        tag_prefix: "abuseipdb",
        redistributable: false,
    },
    ProviderInfo {
        name: RDAP,
        label: "RDAP registry",
        public: false,
        api: true,
        tag_prefix: "rdap",
        redistributable: false,
    },
    ProviderInfo {
        name: SHODAN,
        label: "Shodan",
        public: false,
        api: true,
        tag_prefix: "shodan",
        redistributable: false,
    },
    ProviderInfo {
        name: INTERNETDB,
        label: "Shodan InternetDB",
        public: false,
        api: true,
        tag_prefix: "internetdb",
        redistributable: false,
    },
];

/// Largest `data_json` accepted from a peer; a node writes at most
/// [`api::MAX_DATA_BYTES`].
pub const MAX_PEER_DATA_BYTES: usize = 32 * 1024;

pub fn provider_info(name: &str) -> Option<&'static ProviderInfo> {
    KNOWN_PROVIDERS.iter().find(|p| p.name == name)
}

/// Tags of one result, for filtering the admin IP list (stored with the
/// provider's [`ProviderInfo::tag_prefix`]).
pub fn tags(provider: &str, data: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    match provider {
        ABUSEIPDB => abuseipdb::tags(data),
        SHODAN | INTERNETDB => shodan::tags(data),
        RDAP => rdap::tags(data),
        _ => vec![],
    }
}

use crate::config::Config;
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
        Arc::new(rdap::Rdap::with_shared(rdap.clone())),
    ];
    if let Some(a) = &cfg.abuseipdb {
        out.push(Arc::new(ApiProvider::new(
            abuseipdb::AbuseIpDb {
                base: abuseipdb::BASE.into(),
                key: a.api_key.trim().into(),
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
                key: s.api_key.trim().into(),
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
    let api: Vec<&str> = out.iter().skip(3).map(|p| p.name()).collect();
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
                limit: p.batch(),
            })
            .await?
    } else {
        rec.store()
            .ips_missing_intel(p.name(), step, p.batch())
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
            *rdap.write().unwrap() = rdap::Bootstrap::load(&cfg.data_dir);
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
        match geo::download_edition(&cfg.data_dir, edition, &mm.account_id, &mm.license_key).await {
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
    let loaded = geo.read().unwrap().is_some();
    if fetched > 0 || !loaded {
        match geo::GeoIp::load_blocking(&cfg.data_dir).await {
            Ok(g) => {
                *geo.write().unwrap() = Some(g);
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
        let _ = store
            .intel_set("maxmind_last_fetch", &chrono::Utc::now().to_rfc3339())
            .await;
    }
    Ok(())
}

/// Unload the exit list once its file is older than [`tor::MAX_AGE`]
/// (fetching or copying it kept failing): from a stale list the trap would
/// record "not an exit" for exits that appeared since, and scanners believe
/// that. Without a list their Tor status is unknown (`scan.tor_unknown`);
/// IPs already recorded as exits stay exits.
fn drop_stale_tor(tor: &SharedTor, cfg: &Config) {
    if tor.read().unwrap().is_empty() || !tor::stale(&cfg.data_dir) {
        return;
    }
    warn!(
        "tor exit list older than {} h: unloaded until a fresh one is fetched",
        tor::MAX_AGE.as_secs() / 3600
    );
    *tor.write().unwrap() = tor::TorExitList::default();
}

/// Warn, at most hourly, while no Tor exit list is loaded: Tor exits cannot
/// be told apart from scanners then (see `scan.tor_unknown`).
fn warn_without_tor_list(tor: &SharedTor, cfg: &Config, last: &mut Option<std::time::Instant>) {
    if !tor.read().unwrap().is_empty() {
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
    if let Recorder::Cluster(node) = &rec {
        return run_cluster(node.clone(), cfg, geo, tor, rdap, shutdown).await;
    }
    if cfg.maxmind.is_none() && geo.read().unwrap().is_none() {
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
                        Ok(l) => *tor.write().unwrap() = l,
                        Err(e) => warn!(?e, "tor exit list reload failed"),
                    }
                    let _ = store
                        .intel_set("tor_last_fetch", &chrono::Utc::now().to_rfc3339())
                        .await;
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
    if kinds.iter().any(|k| k == share::TOR) {
        match tor::TorExitList::load(&cfg.data_dir) {
            Ok(l) => *tor.write().unwrap() = l,
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
        assert!(!shared.read().unwrap().is_empty(), "fresh: kept");
        let old = std::time::SystemTime::now() - tor::MAX_AGE - Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        drop_stale_tor(&shared, &cfg);
        assert!(shared.read().unwrap().is_empty());
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
