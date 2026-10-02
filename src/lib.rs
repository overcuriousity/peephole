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

/// Whether this node loads the GeoLite2 databases in its data dir. A cluster
/// node needs its own `[maxmind]` credentials: files copied from peers by
/// older builds are not used, so nobody serves a frozen copy.
pub fn geolite_loads(cfg: &config::Config) -> bool {
    cfg.cluster.is_none() || cfg.maxmind.is_some()
}

pub async fn run(config_path: PathBuf) -> Result<()> {
    // Startup validation (spec §12).
    let (cfg, _, summary) = check_config(&config_path).await?;
    info!(version = VERSION, "{summary}");
    std::fs::create_dir_all(&cfg.data_dir)?;
    let store = store::Store::connect(&cfg.database_path).await?;

    let geo = Arc::new(RwLock::new(if geolite_loads(&cfg) {
        intel::geo::GeoIp::load(&cfg.data_dir)
            .map(Some)
            .unwrap_or_else(|e| {
                warn!(
                    ?e,
                    "maxmind dbs not loaded yet; geo enrichment deferred to scheduler"
                );
                None
            })
    } else {
        info!(
            "GeoLite2 databases are not shared any more; configure [maxmind] to look up \
             GeoIP data on this node"
        );
        None
    }));
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

    // Results for IPs this or other nodes recorded without them.
    tokio::spawn(intel::enrich_loop(
        recorder.clone(),
        vec![Arc::new(intel::provider::MaxMind(geo.clone()))],
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

/// How long a stopping web interface may finish open requests before its
/// listener task is dropped.
const WEB_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
/// How long shutdown waits for the roles to stop (scans to finish) before it
/// abandons them; interrupted scans are requeued as after a crash.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);
/// Longest wait between attempts to start a role that keeps failing.
const RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(300);

/// A running role: send `true` to make it stop; the task ends by itself.
struct Running {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Ask the role to stop, without waiting for it.
    fn signal(self) -> tokio::task::JoinHandle<()> {
        let _ = self.stop.send(true);
        self.task
    }
}

/// One role's state in the supervisor.
#[derive(Default)]
struct Slot {
    running: Option<Running>,
    /// The previous instance, asked to stop and still finishing (a scanner
    /// lets its scans end). The role is not started again until it is gone:
    /// a fresh scanner would requeue the jobs it is still running.
    stopping: Option<tokio::task::JoinHandle<()>>,
    /// Failed starts in a row, and when to try again.
    failures: u32,
    next_try: Option<tokio::time::Instant>,
}

/// The three roles: trap, scanner, web.
#[derive(Default)]
struct Running3 {
    trap: Slot,
    scanner: Slot,
    web: Slot,
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
    /// Make the running roles equal to the effective ones. Never waits for a
    /// role to stop. `startup`: a role the config file enables that cannot
    /// start is an error (the installer's health check relies on it); every
    /// other failure is logged and retried with a growing delay.
    async fn reconcile(&self, r: &mut Running3, startup: bool) -> Result<()> {
        let want = self.settings.roles();
        let now = tokio::time::Instant::now();
        for (slot, want, from_file, name, key) in [
            (
                &mut r.trap,
                want.listener,
                self.cfg.roles.listener,
                "trap",
                "roles.listener",
            ),
            (
                &mut r.scanner,
                want.scanner,
                self.cfg.roles.scanner,
                "scanner",
                "roles.scanner",
            ),
            (&mut r.web, want.web, self.cfg.roles.web, "web", "roles.web"),
        ] {
            if slot.stopping.as_ref().is_some_and(|t| t.is_finished()) {
                slot.stopping = None;
                info!(role = name, "role stopped");
            }
            // A task that ended by itself (listener error) is started afresh.
            if slot.running.as_ref().is_some_and(|x| x.task.is_finished()) {
                slot.running = None;
            }
            if !want {
                slot.failures = 0;
                slot.next_try = None;
                if let Some(x) = slot.running.take() {
                    info!(role = name, "role stopping");
                    slot.stopping = Some(x.signal());
                }
                continue;
            }
            if slot.running.is_some()
                || slot.stopping.is_some()
                || slot.next_try.is_some_and(|t| t > now)
            {
                continue;
            }
            let started = match name {
                "trap" => self.start_trap().await,
                "scanner" => self.start_scanner().await,
                _ => self.start_web().await,
            };
            match started {
                Ok(x) => {
                    info!(role = name, "role started");
                    slot.running = Some(x);
                    slot.failures = 0;
                    slot.next_try = None;
                }
                Err(e) if startup && from_file => {
                    return Err(e.context(format!("starting {name}")));
                }
                Err(e) => {
                    slot.failures += 1;
                    let wait =
                        (SETTINGS_TICK * 2u32.saturating_pow(slot.failures - 1)).min(RETRY_MAX);
                    slot.next_try = Some(now + wait);
                    let why = if from_file {
                        String::new()
                    } else {
                        format!(
                            " (switched on by a runtime setting; `peephole settings reset {key}` undoes that)"
                        )
                    };
                    warn!(
                        role = name,
                        error = %format!("{e:#}"),
                        retry_in_secs = wait.as_secs(),
                        "role could not start{why}"
                    );
                }
            }
        }
        // Tell the cluster what this node actually runs.
        if let Some(node) = &self.node {
            let running = config::Roles {
                listener: r.trap.running.is_some(),
                scanner: r.scanner.running.is_some(),
                web: r.web.running.is_some(),
            };
            if let Err(e) = node.set_roles(running).await {
                warn!(?e, "publishing the new roles failed");
            }
        }
        Ok(())
    }

    /// Keep the running roles equal to the effective ones until shutdown,
    /// then stop them all, waiting at most [`SHUTDOWN_GRACE`].
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
        let mut tasks = vec![];
        for slot in [running.trap, running.scanner, running.web] {
            tasks.extend(slot.running.map(Running::signal));
            tasks.extend(slot.stopping);
        }
        let aborts: Vec<_> = tasks.iter().map(|t| t.abort_handle()).collect();
        if tokio::time::timeout(SHUTDOWN_GRACE, futures::future::join_all(tasks))
            .await
            .is_err()
        {
            warn!("roles did not stop in time; running scans are interrupted and requeued");
            for a in aborts {
                a.abort();
            }
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
        let (stop, mut rx) = tokio::sync::watch::channel(false);
        let app = admin::full_router(Arc::new(
            admin::AdminState::new(
                self.store.clone(),
                self.cfg.clone(),
                self.notifier.clone(),
                self.settings.pace.clone(),
            )
            .with_recorder(self.recorder.clone())
            .with_settings(self.settings.clone())
            .with_closing(rx.clone()),
        ));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding admin listener {addr}"))?;
        info!(%addr, "admin listener up");
        Ok(Running {
            stop,
            task: tokio::spawn(async move {
                let mut grace = rx.clone();
                // The peer address feeds the per-client rate limits.
                let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
                let served = axum::serve(listener, app).with_graceful_shutdown(async move {
                    let _ = rx.wait_for(|v| *v).await;
                });
                tokio::select! {
                    r = served => if let Err(e) = r {
                        warn!(?e, "admin listener stopped");
                    },
                    _ = async {
                        let _ = grace.wait_for(|v| *v).await;
                        tokio::time::sleep(WEB_GRACE).await;
                    } => warn!("admin listener stopped with requests still open"),
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

    #[test]
    fn a_cluster_node_loads_geolite2_only_with_its_own_credentials() {
        let cluster = "[cluster]\nnode_name = \"n\"\nlisten = \"127.0.0.1:7443\"\n";
        let maxmind = "[maxmind]\naccount_id = \"1\"\nlicense_key = \"k\"\n";
        assert!(geolite_loads(&cfg("")));
        assert!(!geolite_loads(&cfg(cluster)));
        assert!(geolite_loads(&cfg(&format!("{maxmind}{cluster}"))));
    }
}
