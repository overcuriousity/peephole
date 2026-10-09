// The export row's `json!` (export::ExportRow::to_json) has more keys than
// the default limit expands.
#![recursion_limit = "256"]

pub mod admin;
pub mod canary;
pub mod classify;
pub mod cluster;
pub mod config;
pub mod credits;
pub mod events;
pub mod export;
pub mod fingerprint;
pub mod intel;
pub mod net;
pub mod scan;
pub mod sd_notify;
pub mod settings;
pub mod settings_cli;
pub mod store;
pub mod trap;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{error, info, warn};

/// Build version, baked in by `build.rs` from `PEEPHOLE_VERSION` ("dev" locally).
pub const VERSION: &str = env!("PEEPHOLE_VERSION");
/// Commit the binary was built from (12 hex digits, or "unknown"), from `build.rs`.
pub const COMMIT: &str = env!("PEEPHOLE_COMMIT");

/// Startup validation shared by `run` and `check-config`: config parses and
/// is sane, nmap is executable (scanner). Returns the config and a summary:
/// one line, then notes (the built-in rules, keys that do nothing).
pub async fn check_config(config_path: &std::path::Path) -> Result<(config::Config, String)> {
    let cfg = config::Config::load(config_path).context("config")?;
    let mut notes = config_warnings(&cfg, config_path);
    notes.extend(config::optional_key_notes(config_path));
    let mut summary = format!("ok: config (roles: {})", cfg.roles.names().join(", "));
    // Built into the binary: the same on every start and every node of
    // this build.
    let rules = classify::Classifier::builtin();
    summary.push_str(&format!(
        ", rules built in ({}, {})",
        rules.rule_count(),
        &rules.fingerprint()[..12]
    ));
    if cfg.roles.scanner {
        summary.push_str(&format!(", {}", cfg.scan.nmap_version().await?));
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
    if cfg.retention_days > 0 {
        summary.push_str(&format!(
            "\nretention: this node keeps the last {} days of records and history \
             (other nodes keep theirs)",
            cfg.retention_days
        ));
    }
    for n in notes {
        summary.push('\n');
        summary.push_str(&n);
    }
    Ok((cfg, summary))
}

/// What the config sets that loads but deserves a warning: unknown keys,
/// keys that do nothing any more, wide trusted proxies. `check-config`
/// prints them; the daemon logs them as warnings.
fn config_warnings(cfg: &config::Config, config_path: &std::path::Path) -> Vec<String> {
    let mut warnings = config::unknown_key_notes(config_path);
    warnings.extend(cfg.obsolete_notes());
    warnings.extend(cfg.trusted_proxy_notes());
    warnings
}

/// Whether this node loads the GeoLite2 databases in its data dir. A cluster
/// node needs its own `[maxmind]` credentials: files copied from peers by
/// older builds are not used, so nobody serves a frozen copy.
pub fn geolite_loads(cfg: &config::Config) -> bool {
    cfg.cluster.is_none() || cfg.maxmind.is_some()
}

pub async fn run(config_path: PathBuf) -> Result<()> {
    // Startup validation (spec §12).
    let (cfg, summary) = check_config(&config_path).await?;
    // Config warnings are logged as such; the summary has them too (for
    // check-config), so they are left out of its log line.
    let warned = config_warnings(&cfg, &config_path);
    let summary: Vec<&str> = summary
        .lines()
        .filter(|l| !warned.iter().any(|n| n == l))
        .collect();
    info!(version = VERSION, "{}", summary.join("\n"));
    for note in &warned {
        warn!("{note}");
    }
    std::fs::create_dir_all(&cfg.data_dir)?;
    let store = store::Store::connect(&cfg.database_path).await?;
    // Public pages show a request only after this delay (spec 2026-10-05).
    let minutes = |m: u32| std::time::Duration::from_secs(u64::from(m) * 60);
    store
        .set_publish_delay(
            minutes(cfg.public.delay_minutes),
            minutes(cfg.public.jitter_minutes),
        )
        .await?;
    if cfg.public.delay_minutes + cfg.public.jitter_minutes == 0 {
        warn!(
            "[public] delay_minutes and jitter_minutes are 0: public pages show requests at once"
        );
    }

    let geo = Arc::new(RwLock::new(if geolite_loads(&cfg) {
        intel::geo::GeoIp::load_blocking(&cfg.data_dir)
            .await
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
    let rdap: intel::SharedRdap =
        Arc::new(RwLock::new(intel::rdap::Bootstrap::load(&cfg.data_dir)));

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

    // Tasks beside the roles; one that panics stops the node (below).
    let mut background = Background::default();

    // Daily intel: the scheduler refreshes the files and swaps the shared
    // state after each successful fetch, so the trap sees fresh data.
    background.spawn(
        "intel scheduler",
        intel::run_scheduler(
            recorder.clone(),
            cfg.clone(),
            geo.clone(),
            tor.clone(),
            rdap.clone(),
            shutdown_rx.clone(),
        ),
    );

    // Results for IPs this or other nodes recorded without them.
    let providers = intel::providers(&cfg, &store, &geo, &tor, &rdap);
    if let Some(n) = &node {
        n.set_lookup_providers(providers.clone());
        n.set_lookup_shares(credits::share::Shares::new(
            store.clone(),
            cfg.enrichment.on_demand_share,
            cfg.enrichment.offer_per_day,
        ));
    }
    background.spawn(
        "enrichment",
        intel::enrich_loop(recorder.clone(), providers.clone(), shutdown_rx.clone()),
    );
    // Reverse DNS of the sources, forward-confirmed, kept on this node.
    background.spawn(
        "reverse dns",
        intel::rdns::run(
            store.clone(),
            node.clone(),
            geo.clone(),
            cfg.enrichment.reverse_dns,
            shutdown_rx.clone(),
        ),
    );

    // Observational probes, for members (paid) and this node's admin.
    let prober = (cfg.roles.scanner && cfg.probe.enabled).then(|| {
        Arc::new(scan::probe::serve::Prober::new(
            &cfg,
            node.as_ref().map(|n| n.id()),
        ))
    });
    if let (Some(n), Some(p)) = (&node, &prober) {
        n.set_prober(p.clone());
    }

    // Retention on a standalone node: delete records older than the window.
    // A cluster node lowers its history floor instead (`cluster::history`).
    if cfg.cluster.is_none() && cfg.retention_days > 0 {
        background.spawn(
            "retention",
            run_retention(recorder.clone(), cfg.retention_days, shutdown_rx.clone()),
        );
    }

    // Housekeeping on every node: expired sessions and ceremonies, planner
    // statistics, freed pages; local tombstones on a standalone node.
    background.spawn(
        "maintenance",
        store::maintenance::run(store.clone(), cfg.cluster.is_none(), shutdown_rx.clone()),
    );

    // Release delayed requests to the public pages.
    background.spawn(
        "publisher",
        store::publish::run(store.clone(), shutdown_rx.clone()),
    );

    // What rows and scans stored before this build lack; new ones get it
    // as written. Canaries and tokens (or by an older tokenizer), host keys
    // and facts of scans read by an older parser (HOSTKEYS_V, FACTS_V),
    // JA4H, User-Agent.
    background.backfill("canaries", "parsed stored rows", {
        let pool = store.pool.clone();
        async move { store::canaries::backfill(&pool).await }
    });
    background.backfill("host keys", "read stored scans again", {
        let pool = store.pool.clone();
        async move { store::hostkeys::backfill(&pool, scan::hostkeys::HOSTKEYS_V).await }
    });
    background.backfill("scan facts", "read stored scans", {
        let pool = store.pool.clone();
        async move { store::facts::backfill(&pool, scan::facts::FACTS_V).await }
    });
    background.backfill("ja4h", "derived stored rows", {
        let pool = store.pool.clone();
        async move { store::ja4h::backfill(&pool).await }
    });
    background.backfill("user-agent", "derived stored rows", {
        let pool = store.pool.clone();
        async move { store::useragent::backfill(&pool).await }
    });

    // Queue change notifications: trap + workers publish, admin SSE subscribes.
    let notifier = events::Notifier::new();

    // Runtime settings: config defaults, overridden from the admin UI, the
    // CLI or the owner.
    let nmap_ok = cfg.scan.nmap_version().await.is_ok();
    let settings =
        settings::Settings::load(&store, &cfg, settings::Prereqs::from_config(&cfg, nmap_ok))
            .await?;

    // Distributed mode: job arbiter (answers scanners' claims), remote pace
    // changes and takeover of silent arbiters' queues (scanners), then the
    // RPC listener and sync loops.
    if let Some(node) = &node {
        node.set_scan_share(cfg.credits.scan_share);
        scan::arbiter::Arbiter::start(node.clone(), shutdown_rx.clone()).await?;
        cluster::remote::serve(node, settings.clone());
        cluster::owner::fleet::serve(node);
        cluster::owner::cmd::serve(node, settings.clone());
        background.spawn(
            "fleet",
            cluster::owner::fleet::run(node.clone(), shutdown_rx.clone()),
        );
        background.spawn(
            "seal",
            cluster::seal::run(node.clone(), shutdown_rx.clone()),
        );
        background.spawn("credits", credits::run(node.clone(), shutdown_rx.clone()));
        // Does nothing unless this node is outbound-only.
        background.spawn(
            "relay",
            cluster::relay::run(node.clone(), shutdown_rx.clone()),
        );
        credits::fleet::serve(node);
        credits::audit::serve(node);
        // Does nothing unless this node currently scans.
        background.spawn(
            "takeover",
            scan::arbiter::takeover_loop(node.clone(), shutdown_rx.clone()),
        );
        // Serve at the kept prices until the first refresh steps them.
        credits::price::load_kept(node).await?;
        cluster::start(node.clone(), shutdown_rx.clone()).await?;
        background.spawn(
            "job events",
            forward_job_events(node.clone(), notifier.clone(), shutdown_rx.clone()),
        );
    }

    // Roles run under a supervisor that starts and stops them when the
    // effective roles change (admin UI, CLI, or the owner).
    let roles = RoleRunner {
        cfg: cfg.clone(),
        store: store.clone(),
        recorder: recorder.clone(),
        geo,
        tor,
        notifier,
        settings: settings.clone(),
        node: node.clone(),
        providers,
        prober,
        tarpit: Arc::new(trap::tarpit::Tarpit::of(&cfg)),
        sse: Arc::new(trap::decoy::sse::SseHub::new(&cfg.trap)),
    };
    // At startup a role that cannot start is fatal, as it always was (the
    // installer's health check relies on it); later changes are retried.
    let mut running = Running3::default();
    roles.reconcile(&mut running, true).await?;
    info!(roles = %settings.roles().names().join(","), "peephole up");
    // Listeners are bound: `systemctl start` (Type=notify) returns now.
    sd_notify::ready();
    let supervisor = tokio::spawn(roles.supervise(running, shutdown_rx.clone()));
    // A task that panicked stops the node with an error: systemd starts it
    // again (Restart=on-failure), where it would otherwise go on reporting
    // healthy without, say, its publisher.
    let failed = tokio::select! {
        _ = shutdown_signal() => None,
        e = background.panicked() => Some(e),
    };
    match &failed {
        None => info!("shutting down"),
        Some(e) => error!("{e}; shutting down"),
    }
    let _ = shutdown_tx.send(true);
    let _ = supervisor.await;
    failed.map_or(Ok(()), Err)
}

/// Tasks beside the roles, kept so that one that panics is noticed.
#[derive(Default)]
struct Background {
    tasks: tokio::task::JoinSet<()>,
    /// Each task's name, and whether its panic stops the node.
    names: std::collections::HashMap<tokio::task::Id, (&'static str, bool)>,
}

impl Background {
    /// A task that runs until shutdown, or ends by itself when it has
    /// nothing to do (switched off). If it panics, the node stops.
    fn spawn(&mut self, name: &'static str, task: impl Future<Output = ()> + Send + 'static) {
        let id = self.tasks.spawn(task).id();
        self.names.insert(id, (name, true));
    }

    /// A pass over stored rows that ends when done, logged as `name: done`.
    /// A failure or panic is logged only: the node works without it, and
    /// the next start tries again.
    fn backfill(
        &mut self,
        name: &'static str,
        done: &'static str,
        pass: impl Future<Output = Result<u64>> + Send + 'static,
    ) {
        let id = self
            .tasks
            .spawn(async move {
                match pass.await {
                    Ok(0) => {}
                    Ok(n) => info!(count = n, "{name}: {done}"),
                    Err(e) => warn!(error = %e, "{name}: backfill failed"),
                }
            })
            .id();
        self.names.insert(id, (name, false));
    }

    /// The first panic that stops the node; never returns without one.
    async fn panicked(&mut self) -> anyhow::Error {
        while let Some(ended) = self.tasks.join_next_with_id().await {
            let (id, panic) = match ended {
                Ok((id, ())) => (id, None),
                Err(e) => (e.id(), e.is_panic().then_some(e)),
            };
            let (name, fatal) = self.names.remove(&id).unwrap_or(("?", true));
            match panic {
                Some(e) if fatal => return anyhow::anyhow!("background task {name} panicked: {e}"),
                Some(e) => error!(task = name, error = %e, "backfill panicked"),
                None => {}
            }
        }
        std::future::pending().await
    }
}

/// How often the daemon re-reads settings another process (the CLI) may
/// have written, and retries a role that failed to start.
pub const SETTINGS_TICK: std::time::Duration = std::time::Duration::from_secs(2);

/// How long a stopping web interface may finish open requests before its
/// listener task is dropped.
const WEB_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
/// How long shutdown waits for the roles to stop (scans to finish) before it
/// abandons them; interrupted scans are requeued as after a crash.
pub(crate) const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);
/// Longest wait between attempts to start a role that keeps failing.
const RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(300);
/// A role that ran this long before its task ended is not crash-looping:
/// its restart starts the backoff afresh.
const RUN_STABLE: std::time::Duration = std::time::Duration::from_secs(60);

/// The wait before the next attempt after `failures` failures in a row.
fn retry_delay(failures: u32) -> std::time::Duration {
    (SETTINGS_TICK * 2u32.saturating_pow(failures.saturating_sub(1))).min(RETRY_MAX)
}

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
    /// Failed starts (or quick exits) in a row, and when to try again.
    failures: u32,
    next_try: Option<tokio::time::Instant>,
    /// When the running instance started.
    since: Option<tokio::time::Instant>,
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
    providers: intel::Providers,
    /// Observational probes (scanner role with `probe.enabled`).
    prober: Option<Arc<scan::probe::serve::Prober>>,
    /// The trap's tarpit: outlives a listener restart, read by the admin.
    tarpit: Arc<trap::tarpit::Tarpit>,
    /// The trap's legacy MCP SSE streams: outlive a listener restart.
    sse: Arc<trap::decoy::sse::SseHub>,
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
            // A task that ended by itself (listener error) is started afresh,
            // after a growing delay unless it had run for a while.
            if slot.running.as_ref().is_some_and(|x| x.task.is_finished()) {
                slot.running = None;
                if slot.since.is_some_and(|t| now - t >= RUN_STABLE) {
                    slot.failures = 0;
                }
                slot.failures += 1;
                let wait = retry_delay(slot.failures);
                slot.next_try = Some(now + wait);
                if slot.failures >= 3 {
                    error!(
                        role = name,
                        failures = slot.failures,
                        retry_in_secs = wait.as_secs(),
                        "role keeps exiting"
                    );
                } else {
                    warn!(role = name, retry_in_secs = wait.as_secs(), "role exited");
                }
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
                    // Failures are forgotten once it has run a while (above).
                    slot.since = Some(now);
                    slot.next_try = None;
                }
                Err(e) if startup && from_file => {
                    return Err(e.context(format!("starting {name}")));
                }
                Err(e) => {
                    slot.failures += 1;
                    let wait = retry_delay(slot.failures);
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
        let Some(addr) = self.cfg.trap_listen else {
            anyhow::bail!("trap_listen is required");
        };
        // The rules built into the binary; every request carries their
        // fingerprint.
        let classifier = classify::Classifier::builtin();
        let state = Arc::new(trap::TrapState {
            store: self.store.clone(),
            recorder: self.recorder.clone(),
            cfg: self.cfg.clone(),
            classifier,
            geo: self.geo.clone(),
            tor: self.tor.clone(),
            notifier: self.notifier.clone(),
            helper_rate: Default::default(),
            panel_rate: Default::default(),
            pace: self.settings.pace.clone(),
            guards: Default::default(),
            tarpit: self.tarpit.clone(),
            sse: self.sse.clone(),
        });
        let app = trap::router(state.clone());
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding trap listener {addr}"))?;
        info!(%addr, "trap listener up");
        let trusted = Arc::new(self.cfg.trusted_proxies.clone());
        let (tls_listener, tls) = match self.cfg.trap_tls_listen {
            Some(a) => {
                let tls = trap::listen::trap_tls_config(
                    self.cfg.trap_tls_cert.as_deref(),
                    self.cfg.trap_tls_key.as_deref(),
                )
                .context("trap TLS certificate")?;
                let l = tokio::net::TcpListener::bind(a)
                    .await
                    .with_context(|| format!("binding trap TLS listener {a}"))?;
                info!(addr = %a, "trap TLS listener up");
                (Some(l), Some(tls))
            }
            None => (None, None),
        };
        let (stop, rx) = tokio::sync::watch::channel(false);
        Ok(Running {
            stop,
            task: tokio::spawn(async move {
                let rx_tls = rx.clone();
                tokio::join!(
                    trap::listen::serve_trap(
                        listener,
                        app.clone(),
                        None,
                        trusted.clone(),
                        rx.clone()
                    ),
                    async move {
                        if let Some(l) = tls_listener {
                            trap::listen::serve_trap(l, app, tls, trusted, rx_tls).await;
                        }
                    },
                    trap::flush_skips(state, rx)
                );
            }),
        })
    }

    async fn start_scanner(&self) -> Result<Running> {
        // Grants are checked against the rules built into this binary.
        let classifier = classify::Classifier::builtin();
        let (stop, rx) = tokio::sync::watch::channel(false);
        Ok(Running {
            stop,
            task: tokio::spawn(scan::run_workers(
                self.recorder.clone(),
                self.cfg.clone(),
                self.settings.pace.clone(),
                PathBuf::from(self.cfg.scan.nmap()),
                rx,
                self.notifier.clone(),
                classifier,
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
                self.geo.clone(),
            )
            .with_recorder(self.recorder.clone())
            .with_settings(self.settings.clone())
            .with_providers(self.providers.clone())
            .with_prober(self.prober.clone())
            .with_tarpit(self.tarpit.clone())
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
                Ok(p) if p.is_empty() => break,
                Ok(p) => info!(
                    requests = p.requests,
                    scans = p.scans,
                    skipped_batches = p.skipped_batches,
                    fingerprints = p.fingerprints,
                    jobs = p.jobs,
                    "retention: pruned old records"
                ),
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
    fn a_cluster_node_loads_geolite2_only_with_its_own_credentials() {
        let cluster = "[cluster]\nnode_name = \"n\"\nlisten = \"127.0.0.1:7443\"\n";
        let maxmind = "[maxmind]\naccount_id = \"1\"\nlicense_key = \"k\"\n";
        assert!(geolite_loads(&cfg("")));
        assert!(!geolite_loads(&cfg(cluster)));
        assert!(geolite_loads(&cfg(&format!("{maxmind}{cluster}"))));
    }

    /// A background task that panics is named and stops the node; one that
    /// ends by itself (switched off) does not, nor does a failed backfill.
    #[tokio::test]
    async fn a_panicking_background_task_is_fatal() {
        let soon = std::time::Duration::from_millis(300);
        let mut bg = Background::default();
        bg.spawn("reverse dns", async {});
        bg.backfill("canaries", "parsed stored rows", async {
            panic!("backfill bug")
        });
        bg.backfill("ja4h", "derived stored rows", async {
            anyhow::bail!("no table")
        });
        assert!(tokio::time::timeout(soon, bg.panicked()).await.is_err());
        bg.spawn("publisher", async { panic!("publisher bug") });
        let e = tokio::time::timeout(soon, bg.panicked())
            .await
            .expect("the panic is noticed");
        assert!(e.to_string().contains("publisher"), "{e}");
    }

    #[test]
    fn retries_back_off_up_to_a_ceiling() {
        assert_eq!(retry_delay(1), SETTINGS_TICK);
        assert_eq!(retry_delay(2), SETTINGS_TICK * 2);
        assert_eq!(retry_delay(4), SETTINGS_TICK * 8);
        assert_eq!(retry_delay(40), RETRY_MAX);
    }
}
