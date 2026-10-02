pub mod geo;
pub mod provider;
pub mod share;
pub mod tor;

/// Provider names in `ip_intel` records.
pub const MAXMIND: &str = "maxmind-geolite2";
pub const TOR: &str = "tor-exits";

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

/// Rewrite country names left by older builds to ISO codes (needs the MaxMind DBs).
pub async fn backfill_geo(rec: &Recorder, geo: &RwLock<Option<geo::GeoIp>>) {
    let store = rec.store();
    let rows = match store.ips_with_legacy_country().await {
        Ok(r) if !r.is_empty() => r,
        Ok(_) => return,
        Err(e) => return warn!(?e, "geo backfill: query failed"),
    };
    let (updates, version) = {
        let guard = geo.read().unwrap();
        match guard.as_ref() {
            Some(g) => (g.relookup(&rows), g.build_date()),
            None => return,
        }
    };
    match geo::backfill_iso_codes(rec, updates, version.as_deref()).await {
        Ok(n) => info!(
            fixed = n,
            pending = rows.len(),
            "geo backfill: country names -> ISO codes"
        ),
        Err(e) => warn!(?e, "geo backfill failed"),
    }
}

/// The providers a node was started with.
pub type Providers = Vec<Arc<dyn provider::Provider>>;

/// IPs looked up per provider and pass.
const ENRICH_BATCH: i64 = 500;
/// How often the enrichment loop runs.
const ENRICH_TICK: Duration = Duration::from_secs(60);

/// One pass: for every provider this node can serve, look up IPs that have
/// no result from it yet and record what it says. In a cluster the able
/// nodes take turns by rank (see [`provider::step_in_secs`]). Returns how
/// many results were written.
pub async fn enrich_once(rec: &Recorder, providers: &Providers) -> anyhow::Result<usize> {
    let ready: Vec<_> = providers.iter().filter(|p| p.ready()).collect();
    if let Some(node) = rec.node() {
        node.set_providers(ready.iter().map(|p| p.name().to_string()).collect());
    }
    let mut written = 0;
    for p in ready {
        let rank = match rec.node() {
            None => 0,
            Some(node) => {
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
                                .is_some_and(|k| k.hb.providers.iter().any(|n| n == p.name()))
                    })
                    .map(|id| (id, members.get(&id).is_some_and(|m| m.address.is_some())))
                    .collect();
                share::rank(me, &able).unwrap_or(0)
            }
        };
        let ips = rec
            .store()
            .ips_missing_intel(p.name(), provider::step_in_secs(rank), ENRICH_BATCH)
            .await?;
        if ips.is_empty() {
            continue;
        }
        for f in p.lookup(&ips).await {
            rec.record_intel(&f.ip, p.name(), f.source_version.as_deref(), f.data)
                .await?;
            written += 1;
        }
    }
    Ok(written)
}

/// Keep filling in results for IPs that lack them, until shutdown.
pub async fn enrich_loop(
    rec: Recorder,
    providers: Providers,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut wait = Duration::from_secs(5);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => break,
        }
        wait = ENRICH_TICK;
        match enrich_once(&rec, &providers).await {
            Ok(0) => {}
            Ok(n) => info!(n, "enrichment: results recorded"),
            Err(e) => warn!(?e, "enrichment pass failed"),
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

/// `intel_meta` key recording one edition's last successful download.
fn edition_key(edition: &str) -> String {
    format!("maxmind_last_fetch:{edition}")
}

/// Download the GeoLite2 databases that are missing or stale (needs
/// `[maxmind]` credentials) and load them; they stay on this node. Each
/// database keeps its own fetch time, so when one download fails the other
/// is not fetched again (MaxMind counts every download against a daily
/// limit). Errors when a download or the reload failed.
async fn refresh_maxmind(
    store: &Store,
    rec: &Recorder,
    cfg: &Config,
    geo: &SharedGeo,
) -> anyhow::Result<()> {
    let Some(mm) = &cfg.maxmind else {
        return Ok(());
    };
    // Builds before per-database keys recorded one time for both.
    let legacy = store.intel_get("maxmind_last_fetch").await?;
    let mut fetched = 0;
    let mut failed = None;
    for edition in geo::EDITIONS {
        let file = cfg.data_dir.join(format!("{edition}.mmdb"));
        let last = store
            .intel_get(&edition_key(edition))
            .await?
            .or(legacy.clone());
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
                backfill_geo(rec, geo).await;
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
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let store = rec.store().clone();
    backfill_geo(&rec, &geo).await;
    if let Recorder::Cluster(node) = &rec {
        return run_cluster(node.clone(), rec.clone(), cfg, geo, tor, shutdown).await;
    }
    if cfg.maxmind.is_none() && geo.read().unwrap().is_none() {
        warn!("no [maxmind] credentials and no GeoLite2 databases: GeoIP enrichment is off");
    }
    let now = tokio::time::Instant::now();
    let (mut tor_next, mut mm_next) = (now, now);
    let (mut tor_backoff, mut mm_backoff) = (TOR_BACKOFF, MAXMIND_BACKOFF);
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
            warn_without_tor_list(&tor, &cfg, &mut warned);
        }
        if now >= mm_next {
            match refresh_maxmind(&store, &rec, &cfg, &geo).await {
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
        tokio::select! {
            _ = tokio::time::sleep_until(tor_next.min(mm_next)) => {}
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
const LIVE_WINDOW: Duration = Duration::from_secs(45);

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
    rec: Recorder,
    cfg: Config,
    geo: SharedGeo,
    tor: SharedTor,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let me = node.id();
    let mut changes = node.subscribe_changes();
    let now = std::time::Instant::now();
    let (mut tor_next, mut mm_next) = (now, now);
    let (mut tor_backoff, mut mm_backoff) = (TOR_BACKOFF, MAXMIND_BACKOFF);
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
                        if let Err(e) = share::publish(&node, &cfg.data_dir, &[share::TOR]).await {
                            warn!(?e, "announcing tor exit list failed");
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
        warn_without_tor_list(&tor, &cfg, &mut warned);
        // Every node with credentials keeps its own databases fresh.
        if std::time::Instant::now() >= mm_next {
            match refresh_maxmind(&node.store, &rec, &cfg, &geo).await {
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
