pub mod geo;
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
        let geo_missing = geo.read().unwrap().is_none();
        if let Some(mm) = &cfg.maxmind
            && (geo_missing || is_stale(&store, "maxmind_last_fetch").await)
        {
            match geo::download(&cfg.data_dir, &mm.account_id, &mm.license_key).await {
                Ok(()) => {
                    info!("maxmind databases refreshed");
                    match geo::GeoIp::load(&cfg.data_dir) {
                        Ok(g) => {
                            *geo.write().unwrap() = Some(g);
                            backfill_geo(&rec, &geo).await;
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

fn reload(kinds: &[String], cfg: &Config, geo: &SharedGeo, tor: &SharedTor) {
    if kinds.iter().any(|k| k == share::CITY || k == share::ASN) {
        match geo::GeoIp::load(&cfg.data_dir) {
            Ok(g) => *geo.write().unwrap() = Some(g),
            Err(e) => warn!(?e, "maxmind reload failed"),
        }
    }
    if kinds.iter().any(|k| k == share::TOR) {
        match tor::TorExitList::load(&cfg.data_dir) {
            Ok(l) => *tor.write().unwrap() = l,
            Err(e) => warn!(?e, "tor exit list reload failed"),
        }
    }
}

/// Distributed mode: copy newer intel from the cluster, fetch it ourselves
/// when it is our turn (see [`share`]), and fill in missing GeoIP data.
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
    let recently_failed = |f: &std::collections::HashMap<&str, std::time::Instant>, k: &str| {
        f.get(k).is_some_and(|t| t.elapsed() < RETRY_AFTER_FAILURE)
    };
    loop {
        changes.borrow_and_update();
        match share::sync_files(&node, &cfg.data_dir).await {
            Ok(kinds) if !kinds.is_empty() => {
                reload(&kinds, &cfg, &geo, &tor);
                backfill_geo(&rec, &geo).await;
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
                        reload(&[share::TOR.to_string()], &cfg, &geo, &tor);
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
            if let Some(mm) = &cfg.maxmind {
                let key_holders: Vec<_> = all
                    .iter()
                    .copied()
                    .filter(|(id, _)| {
                        *id == me || node.status.known(id).is_some_and(|k| k.hb.has_maxmind)
                    })
                    .collect();
                let geo_age = age(share::CITY).max(age(share::ASN));
                if share::rank(me, &key_holders).is_some_and(|r| share::due(r, geo_age))
                    && !recently_failed(&failed, share::CITY)
                {
                    match geo::download(&cfg.data_dir, &mm.account_id, &mm.license_key).await {
                        Ok(()) => {
                            info!("maxmind databases refreshed for the cluster");
                            reload(&[share::CITY.to_string()], &cfg, &geo, &tor);
                            if let Err(e) =
                                share::publish(&node, &cfg.data_dir, &[share::CITY, share::ASN])
                                    .await
                            {
                                warn!(?e, "announcing maxmind databases failed");
                            }
                            backfill_geo(&rec, &geo).await;
                        }
                        Err(e) => {
                            warn!(?e, "maxmind download failed");
                            failed.insert(share::CITY, std::time::Instant::now());
                        }
                    }
                }
            }
        }
        // The fetcher of the current databases fills in IPs recorded
        // without GeoIP data, once for the whole cluster.
        if manifests.get(share::CITY).and_then(|m| m.origin) == Some(me) {
            match share::backfill_missing_geo(&rec, &geo).await {
                Ok(0) => {}
                Ok(n) => info!(n, "geo backfill: enriched IPs recorded without GeoIP"),
                Err(e) => warn!(?e, "geo backfill failed"),
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(INTEL_TICK) => {}
            _ = changes.changed() => tokio::time::sleep(INTEL_MIN_GAP).await,
            _ = shutdown.changed() => break,
        }
    }
}
