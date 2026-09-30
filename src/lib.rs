pub mod admin;
pub mod classify;
pub mod config;
pub mod events;
pub mod export;
pub mod fingerprint;
pub mod intel;
pub mod scan;
pub mod store;
pub mod trap;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

pub async fn run(config_path: PathBuf) -> Result<()> {
    let cfg = config::Config::load(&config_path)?;
    std::fs::create_dir_all(&cfg.data_dir)?;

    // Startup validation (spec §12).
    let nmap_path = std::env::var("PEEPHOLE_NMAP_PATH").unwrap_or_else(|_| "nmap".into());
    let nmap_out = tokio::process::Command::new(&nmap_path)
        .arg("--version")
        .output()
        .await
        .context("nmap not found — install nmap")?;
    anyhow::ensure!(nmap_out.status.success(), "nmap --version failed");
    let classifier = classify::Classifier::from_dir(&cfg.rules_dir).context("loading rules")?;
    let store = store::Store::connect(&cfg.database_path).await?;

    let geo = Arc::new(RwLock::new(
        intel::geo::GeoIp::load(&cfg.data_dir)
            .map(Some)
            .unwrap_or_else(|e| {
                warn!(
                    ?e,
                    "maxmind dbs not loaded yet; geo enrichment deferred to scheduler"
                );
                None
            }),
    ));
    let tor = Arc::new(RwLock::new(
        intel::tor::TorExitList::load(&cfg.data_dir).unwrap_or_default(),
    ));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Daily intel; refresh shared state after each successful fetch.
    {
        let store = store.clone();
        let cfg2 = cfg.clone();
        let geo = geo.clone();
        let tor = tor.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            // One immediate pass when stale, then delegate to the scheduler loop.
            if intel::tor::TorExitList::refresh(&cfg2.data_dir)
                .await
                .is_ok()
            {
                if let Ok(l) = intel::tor::TorExitList::load(&cfg2.data_dir) {
                    *tor.write().unwrap() = l;
                }
                let _ = store
                    .intel_set("tor_last_fetch", &chrono::Utc::now().to_rfc3339())
                    .await;
            }
            if intel::geo::download(
                &cfg2.data_dir,
                &cfg2.maxmind.account_id,
                &cfg2.maxmind.license_key,
            )
            .await
            .is_ok()
            {
                if let Ok(g) = intel::geo::GeoIp::load(&cfg2.data_dir) {
                    *geo.write().unwrap() = Some(g);
                }
                let _ = store
                    .intel_set("maxmind_last_fetch", &chrono::Utc::now().to_rfc3339())
                    .await;
            }
            intel::run_scheduler(store, cfg2, rx.clone()).await;
            let _ = &mut rx;
        });
    }

    // Queue change notifications: trap + workers publish, admin SSE subscribes.
    let notifier = events::Notifier::new();

    // Scan worker pool.
    {
        let store = store.clone();
        let cfg2 = cfg.clone();
        tokio::spawn(scan::run_workers(
            store,
            cfg2,
            PathBuf::from(nmap_path),
            shutdown_rx.clone(),
            notifier.clone(),
        ));
    }

    // First-run admin setup token (spec §8.4).
    let _ = admin::auth::ensure_setup_token(&store, &cfg.data_dir).await;

    // Listeners.
    let trap_state = Arc::new(trap::TrapState {
        store: store.clone(),
        cfg: cfg.clone(),
        classifier,
        geo: geo.clone(),
        tor: tor.clone(),
        notifier: notifier.clone(),
    });
    let trap_app = trap::router(trap_state);
    let admin_app = admin::full_router(Arc::new(admin::AdminState::new(
        store.clone(),
        cfg.clone(),
        notifier,
    )));

    let trap_listener = tokio::net::TcpListener::bind(cfg.trap_listen)
        .await
        .with_context(|| format!("binding trap listener {}", cfg.trap_listen))?;
    let admin_listener = tokio::net::TcpListener::bind(cfg.admin_listen)
        .await
        .with_context(|| format!("binding admin listener {}", cfg.admin_listen))?;
    info!(trap = %cfg.trap_listen, admin = %cfg.admin_listen, "peephole up");

    tokio::select! {
        r = axum::serve(trap_listener, trap_app.into_make_service_with_connect_info::<std::net::SocketAddr>()) => { r?; }
        r = axum::serve(admin_listener, admin_app) => { r?; }
        _ = tokio::signal::ctrl_c() => { info!("shutting down"); }
    }
    let _ = shutdown_tx.send(true);
    Ok(())
}
