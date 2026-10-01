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
use tracing::{info, warn};

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

async fn is_stale(store: &Store, key: &str) -> bool {
    match store.intel_get(key).await {
        // Stale once ~23h old. The scheduler sleeps 24h + up to 1h of jitter,
        // so a `> 24h` test (with truncating num_hours) would read 24 and skip
        // the refresh every other cycle, stretching "daily" to ~48h.
        Ok(Some(v)) => chrono::DateTime::parse_from_rfc3339(&v)
            .map(|t| chrono::Utc::now().signed_duration_since(t) >= chrono::Duration::hours(23))
            .unwrap_or(true),
        _ => true,
    }
}

/// Download the GeoLite2 databases when they are missing or stale (needs
/// `[maxmind]` credentials) and load them. They stay on this node.
async fn refresh_maxmind(store: &Store, rec: &Recorder, cfg: &Config, geo: &SharedGeo) {
    let geo_missing = geo.read().unwrap().is_none();
    if let Some(mm) = &cfg.maxmind
        && (geo_missing || is_stale(store, "maxmind_last_fetch").await)
    {
        match geo::download(&cfg.data_dir, &mm.account_id, &mm.license_key).await {
            Ok(()) => {
                info!("maxmind databases refreshed");
                match geo::GeoIp::load(&cfg.data_dir) {
                    Ok(g) => {
                        *geo.write().unwrap() = Some(g);
                        backfill_geo(rec, geo).await;
                        // Record success only after the new databases load,
                        // so a bad download is retried on the next tick
                        // rather than waiting out the full day.
                        let _ = store
                            .intel_set("maxmind_last_fetch", &chrono::Utc::now().to_rfc3339())
                            .await;
                    }
                    Err(e) => warn!(?e, "maxmind reload failed; will retry"),
                }
            }
            Err(e) => warn!(?e, "maxmind download failed; keeping previous"),
        }
    }
}

/// Daily intel refresh (spec §9): at startup (Tor always, MaxMind when stale
/// or not loaded, to spare its download quota), then every 24h ± jitter.
/// Each successful fetch is loaded into the shared state the trap reads.
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
    let mut first = true;
    loop {
        if first || is_stale(&store, "tor_last_fetch").await {
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
                }
                Err(e) => warn!(?e, "tor exit list refresh failed; keeping previous"),
            }
        }
        refresh_maxmind(&store, &rec, &cfg, &geo).await;
        first = false;
        // 24h ± up to 1h deterministic-ish jitter from nanos.
        let jitter =
            Duration::from_secs((chrono::Utc::now().timestamp_subsec_nanos() as u64) % 3600);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(24 * 3600) + jitter) => {}
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
/// After a failed download, leave the quota alone this long.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(3600);
/// Heartbeats this recent count a member as alive for the fetch order.
const LIVE_WINDOW: Duration = Duration::from_secs(45);
/// How often a cluster node checks whether its GeoLite2 databases are stale.
const MAXMIND_CHECK: Duration = Duration::from_secs(3600);

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
    let mut failed: std::collections::HashMap<&'static str, std::time::Instant> =
        Default::default();
    let mut last_maxmind: Option<std::time::Instant> = None;
    let recently_failed = |f: &std::collections::HashMap<&str, std::time::Instant>, k: &str| {
        f.get(k).is_some_and(|t| t.elapsed() < RETRY_AFTER_FAILURE)
    };
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
                && !recently_failed(&failed, share::TOR)
            {
                match tor::TorExitList::refresh(&cfg.data_dir).await {
                    Ok(n) => {
                        info!(n, "tor exit list refreshed for the cluster");
                        reload(&[share::TOR.to_string()], &cfg, &tor);
                        if let Err(e) = share::publish(&node, &cfg.data_dir, &[share::TOR]).await {
                            warn!(?e, "announcing tor exit list failed");
                        }
                    }
                    Err(e) => {
                        warn!(?e, "tor exit list refresh failed");
                        failed.insert(share::TOR, std::time::Instant::now());
                    }
                }
            }
        }
        // Every node with credentials keeps its own databases fresh.
        if last_maxmind.is_none_or(|t| t.elapsed() > MAXMIND_CHECK) {
            last_maxmind = Some(std::time::Instant::now());
            refresh_maxmind(&node.store, &rec, &cfg, &geo).await;
        }
        tokio::select! {
            _ = tokio::time::sleep(INTEL_TICK) => {}
            _ = changes.changed() => tokio::time::sleep(INTEL_MIN_GAP).await,
            _ = shutdown.changed() => break,
        }
    }
}
