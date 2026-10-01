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
pub mod settings;
pub mod settings_cli;
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
        summary.push_str(if cfg.cluster.as_ref().is_some_and(|c| c.remote_config) {
            "\nremote config: on (config key holders may change runtime settings)"
        } else {
            "\nremote config: off"
        });
        if cfg.scan.retention_days > 0 {
            summary.push_str(
                "\nnote: scan.retention_days is ignored in a cluster (the shared dataset is persistent)",
            );
        }
    }
    for n in notes {
        summary.push('\n');
        summary.push_str(&n);
    }
    Ok((cfg, classifier, summary))
}

/// Whether old records are deleted by age. Only on a standalone node: a
/// cluster's dataset is persistent, and nothing in it is erased by age.
pub fn retention_applies(cfg: &config::Config) -> bool {
    cfg.cluster.is_none() && cfg.scan.retention_days > 0
}

pub async fn run(config_path: PathBuf) -> Result<()> {
    // Startup validation (spec §12).
    let (cfg, _, summary) = check_config(&config_path).await?;
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

    // Retention (standalone only): prune requests and scan results older
    // than the configured window so the database does not grow without bound.
    if retention_applies(&cfg) {
        tokio::spawn(run_retention(
            recorder.clone(),
            cfg.scan.retention_days,
            shutdown_rx.clone(),
        ));
    }

    // Queue change notifications: trap + workers publish, admin SSE subscribes.
    let notifier = events::Notifier::new();

    // Runtime settings: config defaults, overridden from the admin UI, the
    // CLI or a config key holder.
    let nmap_ok = tokio::process::Command::new(nmap_path())
        .arg("--version")
        .output()
        .await
        .is_ok_and(|o| o.status.success());
    let settings =
        settings::Settings::load(&store, &cfg, settings::Prereqs::from_config(&cfg, nmap_ok))
            .await?;

    // Distributed mode: job arbiter (answers scanners' claims), remote pace
    // changes and takeover of silent arbiters' queues (scanners), then the
    // RPC listener and sync loops.
    if let Some(node) = &node {
        scan::arbiter::Arbiter::start(node.clone(), shutdown_rx.clone()).await?;
        if cfg.cluster.as_ref().is_some_and(|c| c.remote_config) {
            cluster::confkey::ensure(&store, node.id()).await?;
        }
        cluster::confkey::serve(node, settings.clone());
        // Does nothing unless this node currently scans.
        tokio::spawn(scan::arbiter::takeover_loop(
            node.clone(),
            shutdown_rx.clone(),
        ));
        cluster::start(node.clone(), shutdown_rx.clone()).await?;
        tokio::spawn(forward_job_events(
            node.clone(),
            notifier.clone(),
            shutdown_rx.clone(),
        ));
    }

    // Roles run under a supervisor that starts and stops them when the
    // effective roles change (admin UI, CLI, or a config key holder).
    let roles = RoleRunner {
        cfg: cfg.clone(),
        store: store.clone(),
        recorder: recorder.clone(),
        geo,
        tor,
        notifier,
        settings: settings.clone(),
        node: node.clone(),
    };
    // At startup a role that cannot start is fatal, as it always was (the
    // installer's health check relies on it); later changes are retried.
    let mut running = Running3::default();
    roles.reconcile(&mut running, true).await?;
    info!(roles = %settings.roles().names().join(","), "peephole up");
    let supervisor = tokio::spawn(roles.supervise(running, shutdown_rx.clone()));
    shutdown_signal().await;
    info!("shutting down");
    let _ = shutdown_tx.send(true);
    let _ = supervisor.await;
    Ok(())
}

/// How often the daemon re-reads settings another process (the CLI) may
/// have written, and retries a role that failed to start.
pub const SETTINGS_TICK: std::time::Duration = std::time::Duration::from_secs(2);

/// A running role: stop it by sending `true`, then wait for the task.
struct Running {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

/// The three roles' tasks, where running.
#[derive(Default)]
struct Running3 {
    trap: Option<Running>,
    scanner: Option<Running>,
    web: Option<Running>,
}

/// Everything needed to start any role.
struct RoleRunner {
    cfg: config::Config,
    store: store::Store,
    recorder: store::recorder::Recorder,
    geo: intel::SharedGeo,
    tor: intel::SharedTor,
    notifier: events::Notifier,
    settings: settings::Settings,
    node: Option<Arc<cluster::Node>>,
}

impl RoleRunner {
    /// Make the running roles equal to the effective ones. `strict`: a role
    /// that cannot start is an error; otherwise it is logged and tried
    /// again on the next pass.
    async fn reconcile(&self, r: &mut Running3, strict: bool) -> Result<()> {
        let want = self.settings.roles();
        // A task that ended by itself (listener error) is started afresh.
        for slot in [&mut r.trap, &mut r.scanner, &mut r.web] {
            if slot.as_ref().is_some_and(|x| x.task.is_finished()) {
                *slot = None;
            }
        }
        for (slot, want, name) in [
            (&mut r.trap, want.listener, "trap"),
            (&mut r.scanner, want.scanner, "scanner"),
            (&mut r.web, want.web, "web"),
        ] {
            match (want, slot.is_some()) {
                (true, false) => {
                    let started = match name {
                        "trap" => self.start_trap().await,
                        "scanner" => self.start_scanner().await,
                        _ => self.start_web().await,
                    };
                    match started {
                        Ok(x) => {
                            info!(role = name, "role started");
                            *slot = Some(x);
                        }
                        Err(e) if strict => return Err(e.context(format!("starting {name}"))),
                        Err(e) => {
                            warn!(role = name, error = %format!("{e:#}"), "role could not start; retrying")
                        }
                    }
                }
                (false, true) => {
                    if let Some(x) = slot.take() {
                        x.stop().await;
                        info!(role = name, "role stopped");
                    }
                }
                _ => {}
            }
        }
        if let Some(node) = &self.node
            && let Err(e) = node.set_roles(want).await
        {
            warn!(?e, "publishing the new roles failed");
        }
        Ok(())
    }

    /// Keep the running roles equal to the effective ones until shutdown.
    async fn supervise(
        self,
        mut running: Running3,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut changes = self.settings.subscribe();
        loop {
            tokio::select! {
                _ = changes.changed() => {}
                _ = tokio::time::sleep(SETTINGS_TICK) => {
                    if let Err(e) = self.settings.reload().await {
                        warn!(?e, "reloading settings failed");
                    }
                }
                _ = shutdown.changed() => break,
            }
            let _ = self.reconcile(&mut running, false).await;
        }
        for r in [running.trap, running.scanner, running.web]
            .into_iter()
            .flatten()
        {
            r.stop().await;
        }
    }

    async fn start_trap(&self) -> Result<Running> {
        let (Some(addr), Some(dir)) = (self.cfg.trap_listen, &self.cfg.rules_dir) else {
            anyhow::bail!("trap_listen and rules_dir are required");
        };
        // Loaded on every start, so edited rules apply when the role is
        // switched off and on.
        let classifier = classify::Classifier::from_dir(dir).context("loading rules")?;
        let app = trap::router(Arc::new(trap::TrapState {
            store: self.store.clone(),
            recorder: self.recorder.clone(),
            cfg: self.cfg.clone(),
            classifier,
            geo: self.geo.clone(),
            tor: self.tor.clone(),
            notifier: self.notifier.clone(),
            helper_rate: Default::default(),
            pace: self.settings.pace.clone(),
        }));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding trap listener {addr}"))?;
        info!(%addr, "trap listener up");
        let (stop, rx) = tokio::sync::watch::channel(false);
        Ok(Running {
            stop,
            task: tokio::spawn(serve_trap(listener, app, rx)),
        })
    }

    async fn start_scanner(&self) -> Result<Running> {
        let (stop, rx) = tokio::sync::watch::channel(false);
        Ok(Running {
            stop,
            task: tokio::spawn(scan::run_workers(
                self.recorder.clone(),
                self.cfg.clone(),
                self.settings.pace.clone(),
                PathBuf::from(nmap_path()),
                rx,
                self.notifier.clone(),
            )),
        })
    }

    async fn start_web(&self) -> Result<Running> {
        let Some(addr) = self.cfg.admin_listen else {
            anyhow::bail!("admin_listen is required");
        };
        // First-run admin setup token (spec §8.4).
        let _ = admin::auth::ensure_setup_token(&self.store, &self.cfg.data_dir).await;
        let app = admin::full_router(Arc::new(
            admin::AdminState::new(
                self.store.clone(),
                self.cfg.clone(),
                self.notifier.clone(),
                self.settings.pace.clone(),
            )
            .with_recorder(self.recorder.clone())
            .with_settings(self.settings.clone()),
        ));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding admin listener {addr}"))?;
        info!(%addr, "admin listener up");
        let (stop, mut rx) = tokio::sync::watch::channel(false);
        Ok(Running {
            stop,
            task: tokio::spawn(async move {
                let served = axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = rx.changed().await;
                    })
                    .await;
                if let Err(e) = served {
                    warn!(?e, "admin listener stopped");
                }
            }),
        })
    }
}

/// Resolve on Ctrl-C or SIGTERM. systemd stops the service with SIGTERM, so
/// without this the graceful path (watch channel → task shutdown) never ran.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Daily retention sweep. Runs an initial pass shortly after start, then once
/// a day, draining any backlog in bounded batches. `days == 0` disables it.
async fn run_retention(
    recorder: store::recorder::Recorder,
    days: u32,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    if days == 0 {
        return;
    }
    // Small initial delay so startup is not competing with the first sweep.
    let mut first = std::time::Duration::from_secs(300);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(first) => {}
            _ = shutdown.changed() => break,
        }
        first = std::time::Duration::from_secs(24 * 3600);
        // Drain in batches until a pass removes nothing.
        loop {
            match recorder.prune_older_than(days).await {
                Ok((0, 0)) => break,
                Ok((r, s)) => {
                    info!(requests = r, scans = s, "retention: pruned old records");
                    if r == 0 && s == 0 {
                        break;
                    }
                }
                Err(e) => {
                    warn!(?e, "retention sweep failed");
                    break;
                }
            }
            if *shutdown.borrow() {
                break;
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(extra: &str) -> config::Config {
        toml::from_str(&format!(
            "database_path = \"/x\"\ndata_dir = \"/x\"\n[roles]\nlistener = false\nweb = false\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn retention_only_applies_to_standalone_nodes() {
        assert!(retention_applies(&cfg("")));
        assert!(!retention_applies(&cfg("[scan]\nretention_days = 0\n")));
        assert!(!retention_applies(&cfg(
            "[cluster]\nnode_name = \"n\"\nlisten = \"127.0.0.1:7443\"\n"
        )));
    }
}
