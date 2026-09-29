pub mod geo;
pub mod tor;

use crate::config::Config;
use crate::store::Store;
use std::time::Duration;
use tracing::{info, warn};

async fn is_stale(store: &Store, key: &str) -> bool {
    match store.intel_get(key).await {
        Ok(Some(v)) => chrono::DateTime::parse_from_rfc3339(&v)
            .map(|t| chrono::Utc::now().signed_duration_since(t).num_hours() > 24)
            .unwrap_or(true),
        _ => true,
    }
}

/// Daily intel refresh (spec §9): startup-if-stale, then every 24h ± jitter.
pub async fn run_scheduler(
    store: Store,
    cfg: Config,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        if is_stale(&store, "tor_last_fetch").await {
            match tor::TorExitList::refresh(&cfg.data_dir).await {
                Ok(n) => {
                    info!(n, "tor exit list refreshed");
                    let _ = store
                        .intel_set("tor_last_fetch", &chrono::Utc::now().to_rfc3339())
                        .await;
                }
                Err(e) => warn!(?e, "tor exit list refresh failed; keeping previous"),
            }
        }
        if is_stale(&store, "maxmind_last_fetch").await {
            match geo::download(
                &cfg.data_dir,
                &cfg.maxmind.account_id,
                &cfg.maxmind.license_key,
            )
            .await
            {
                Ok(()) => {
                    info!("maxmind databases refreshed");
                    let _ = store
                        .intel_set("maxmind_last_fetch", &chrono::Utc::now().to_rfc3339())
                        .await;
                }
                Err(e) => warn!(?e, "maxmind download failed; keeping previous"),
            }
        }
        // 24h ± up to 1h deterministic-ish jitter from nanos.
        let jitter =
            Duration::from_secs((chrono::Utc::now().timestamp_subsec_nanos() as u64) % 3600);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(24 * 3600) + jitter) => {}
            _ = shutdown.changed() => { break; }
        }
    }
}
