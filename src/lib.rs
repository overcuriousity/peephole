pub mod admin;
pub mod classify;
pub mod cluster;
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

/// Build version, baked in by `build.rs` from `PEEPHOLE_VERSION` ("dev" locally).
pub const VERSION: &str = env!("PEEPHOLE_VERSION");

fn nmap_path() -> String {
    std::env::var("PEEPHOLE_NMAP_PATH").unwrap_or_else(|_| "nmap".into())
}

/// Startup validation shared by `run` and `check-config`: config parses and
/// is sane, rules load (listener), nmap is executable (scanner). Returns the
/// classifier when the listener role is on, and a one-line summary.
pub async fn check_config(
    config_path: &std::path::Path,
) -> Result<(config::Config, Option<classify::Classifier>, String)> {
    let cfg = config::Config::load(config_path).context("config")?;
    let notes = config::optional_key_notes(config_path);
    let mut summary = format!("ok: config (roles: {})", cfg.roles.names().join(", "));
    let classifier = match (&cfg.rules_dir, cfg.roles.listener) {
        (Some(dir), true) => {
            let c = classify::Classifier::from_dir(dir).context("loading rules")?;
            summary.push_str(&format!(", rules ({})", c.rule_count()));
            Some(c)
        }
        _ => None,
    };
    if cfg.roles.scanner {
        let nmap = nmap_path();
        let out = tokio::process::Command::new(&nmap)
            .arg("--version")
            .output()
            .await
            .with_context(|| format!("nmap not found at {nmap} — install nmap"))?;
        anyhow::ensure!(out.status.success(), "nmap --version failed");
        let nmap_line = String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("nmap")
            .to_string();
        summary.push_str(&format!(", {nmap_line}"));
    }
    if cfg.cluster.is_some() {
        let path = cfg.node_key_path();
        match cluster::identity::Identity::load(&path) {
            Ok(id) => summary.push_str(&format!("\nnode key {}", id.id)),
            Err(_) if !path.exists() => summary.push_str(&format!(
                "\nnote: node key {} will be created on first start",
                path.display()
            )),
            Err(e) => return Err(e.context("node key")),
        }
    }
    for n in notes {
        summary.push('\n');
        summary.push_str(&n);
    }
    Ok((cfg, classifier, summary))
}

pub async fn run(config_path: PathBuf) -> Result<()> {
    // Startup validation (spec §12).
    let (cfg, classifier, summary) = check_config(&config_path).await?;
    info!(version = VERSION, "{summary}");
    std::fs::create_dir_all(&cfg.data_dir)?;
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

    // Daily intel: the scheduler refreshes the files and swaps the shared
    // state after each successful fetch, so the trap sees fresh data.
    tokio::spawn(intel::run_scheduler(
        store.clone(),
        cfg.clone(),
        geo.clone(),
        tor.clone(),
        shutdown_rx.clone(),
    ));

    // Queue change notifications: trap + workers publish, admin SSE subscribes.
    let notifier = events::Notifier::new();

    // Scan pace: config defaults, overridden from the admin queue page.
    let pace = scan::pace::SharedPace::load(&store, &cfg.scan).await?;

    // Distributed mode: RPC listener and peer loops.
    if cfg.cluster.is_some() {
        let node = cluster::Node::from_config(&cfg)?;
        cluster::start(node, shutdown_rx.clone()).await?;
    }

    // Scan worker pool.
    if cfg.roles.scanner {
        tokio::spawn(scan::run_workers(
            store.clone(),
            cfg.clone(),
            pace.clone(),
            PathBuf::from(nmap_path()),
            shutdown_rx.clone(),
            notifier.clone(),
        ));
    }

    let mut servers = tokio::task::JoinSet::new();
    if let (true, Some(addr), Some(classifier)) = (cfg.roles.listener, cfg.trap_listen, classifier)
    {
        let trap_app = trap::router(Arc::new(trap::TrapState {
            store: store.clone(),
            cfg: cfg.clone(),
            classifier,
            geo: geo.clone(),
            tor: tor.clone(),
            notifier: notifier.clone(),
        }));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding trap listener {addr}"))?;
        info!(%addr, "trap listener up");
        servers.spawn(async move {
            axum::serve(
                listener,
                trap_app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
        });
    }
    if let (true, Some(addr)) = (cfg.roles.web, cfg.admin_listen) {
        // First-run admin setup token (spec §8.4).
        let _ = admin::auth::ensure_setup_token(&store, &cfg.data_dir).await;
        let admin_app = admin::full_router(Arc::new(admin::AdminState::new(
            store.clone(),
            cfg.clone(),
            notifier,
            pace,
        )));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding admin listener {addr}"))?;
        info!(%addr, "admin listener up");
        servers.spawn(async move { axum::serve(listener, admin_app).await });
    }
    info!(roles = %cfg.roles.names().join(","), "peephole up");

    // A scanner-only node serves nothing; it runs until interrupted.
    let served = async {
        match servers.join_next().await {
            Some(r) => r.map_err(anyhow::Error::from)?.map_err(anyhow::Error::from),
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        r = served => { r?; }
        _ = tokio::signal::ctrl_c() => { info!("shutting down"); }
    }
    let _ = shutdown_tx.send(true);
    Ok(())
}
