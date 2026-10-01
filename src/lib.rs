pub mod admin;
pub mod classify;
pub mod cluster;
pub mod config;
pub mod events;
pub mod export;
pub mod fingerprint;
pub mod intel;
pub mod net;
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

    // Distributed mode: open the node (adopting standalone history into the
    // log) before anything writes, so every write is replicated.
    let node = match cfg.cluster {
        Some(_) => {
            let node =
                cluster::Node::open(cluster::NodeParams::from_config(&cfg, store.clone())?).await?;
            cluster::adopt::adopt_history(&node).await?;
            Some(node)
        }
        None => None,
    };
    let recorder = match &node {
        Some(n) => store::recorder::Recorder::Cluster(n.clone()),
        None => store.local(),
    };

    // Daily intel: the scheduler refreshes the files and swaps the shared
    // state after each successful fetch, so the trap sees fresh data.
    tokio::spawn(intel::run_scheduler(
        recorder.clone(),
        cfg.clone(),
        geo.clone(),
        tor.clone(),
        shutdown_rx.clone(),
    ));

    // Queue change notifications: trap + workers publish, admin SSE subscribes.
    let notifier = events::Notifier::new();

    // Scan pace: config defaults, overridden from the admin queue page.
    let pace = scan::pace::SharedPace::load(&store, &cfg.scan).await?;

    // Distributed mode: job arbiter (answers scanners' claims), remote pace
    // changes and takeover of silent arbiters' queues (scanners), then the
    // RPC listener and sync loops.
    if let Some(node) = &node {
        scan::arbiter::Arbiter::start(node.clone(), shutdown_rx.clone()).await?;
        if cfg.roles.scanner {
            scan::pace::serve_remote(node, pace.clone());
            tokio::spawn(scan::arbiter::takeover_loop(
                node.clone(),
                shutdown_rx.clone(),
            ));
        }
        cluster::start(node.clone(), shutdown_rx.clone()).await?;
        tokio::spawn(forward_job_events(
            node.clone(),
            notifier.clone(),
            shutdown_rx.clone(),
        ));
    }

    // Scan worker pool.
    if cfg.roles.scanner {
        tokio::spawn(scan::run_workers(
            recorder.clone(),
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
            recorder: recorder.clone(),
            cfg: cfg.clone(),
            classifier,
            geo: geo.clone(),
            tor: tor.clone(),
            notifier: notifier.clone(),
            helper_rate: Default::default(),
        }));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding trap listener {addr}"))?;
        info!(%addr, "trap listener up");
        let trap_shutdown = shutdown_rx.clone();
        servers.spawn(async move {
            serve_trap(listener, trap_app, trap_shutdown).await;
            Ok::<(), std::io::Error>(())
        });
    }
    if let (true, Some(addr)) = (cfg.roles.web, cfg.admin_listen) {
        // First-run admin setup token (spec §8.4).
        let _ = admin::auth::ensure_setup_token(&store, &cfg.data_dir).await;
        let admin_app = admin::full_router(Arc::new(
            admin::AdminState::new(store.clone(), cfg.clone(), notifier, pace)
                .with_recorder(recorder.clone()),
        ));
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

/// Serve the public trap listener with slowloris protection: a per-connection
/// header-read timeout and overall deadline (hyper on its own disables its
/// default header timeout when no timer is installed), plus a cap on concurrent
/// connections that sheds load rather than exhausting file descriptors/tasks.
/// The direct peer address is injected as `ConnectInfo` for the handlers.
async fn serve_trap(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto;
    use std::time::Duration;
    use tower::ServiceExt;

    // Bound simultaneous connections; excess are dropped (load shedding).
    const MAX_CONNS: usize = 2048;
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONNS));
    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => { warn!(?e, "trap accept failed"); continue; }
            },
            _ = shutdown.changed() => break,
        };
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            // At the connection cap: drop this one instead of piling up.
            continue;
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    async move {
                        let (mut parts, body) = req.into_parts();
                        parts.extensions.insert(axum::extract::ConnectInfo(peer));
                        let req = hyper::Request::from_parts(parts, axum::body::Body::new(body));
                        app.oneshot(req).await
                    }
                });
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(15));
            let io = TokioIo::new(stream);
            // Overall per-connection deadline bounds slow bodies and keep-alive
            // trickling as well as slow headers.
            let _ = tokio::time::timeout(
                Duration::from_secs(120),
                builder.serve_connection_with_upgrades(io, service),
            )
            .await;
        });
    }
}

/// Push scan jobs changed anywhere in the cluster to the live queue.
async fn forward_job_events(
    node: Arc<cluster::Node>,
    notifier: events::Notifier,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut rx = node.job_events.subscribe();
    loop {
        let uid = tokio::select! {
            r = rx.recv() => match r {
                Ok(u) => u,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            },
            _ = shutdown.changed() => break,
        };
        // Remote batches announce before they commit: wait a moment, and
        // take everything else that arrived meanwhile in the same pass.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut uids = std::collections::BTreeSet::from([uid]);
        while let Ok(u) = rx.try_recv() {
            uids.insert(u);
        }
        for uid in uids {
            let id: Option<i64> = sqlx::query_scalar("SELECT id FROM scan_jobs WHERE uid = ?")
                .bind(&uid)
                .fetch_optional(&node.store.pool)
                .await
                .ok()
                .flatten();
            if let Some(id) = id
                && let Ok(Some(j)) = node.store.queue_job(id).await
            {
                notifier.publish(j);
            }
        }
    }
}
