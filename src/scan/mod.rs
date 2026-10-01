pub mod arbiter;
pub mod nmap_xml;
pub mod pace;

use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::msg::Msg;
use crate::config::Config;
use crate::store::recorder::Recorder;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// nmap argv (after the binary name) for a level and target (spec §5).
pub fn nmap_argv(level: u8, target: &IpAddr, cfg: &Config) -> Vec<String> {
    // Collapse IPv4-mapped IPv6 to IPv4 so a `::ffff:a.b.c.d` target is scanned
    // as the v4 address (and matched by v4 guards) rather than handed to nmap
    // as an IPv6 literal.
    let target = crate::net::canonical(*target);
    let mut argv = cfg.default_level_argv(level);
    // nmap treats a bare IPv6 literal as a hostname unless -6 is given, so
    // every IPv6 scan would otherwise fail with "host down".
    if target.is_ipv6() {
        argv.push("-6".into());
    }
    argv.push("-oX".into());
    argv.push("-".into());
    argv.push(target.to_string());
    argv
}

/// Why this scanner will not run a job.
#[derive(Debug, PartialEq)]
enum Refusal {
    /// Nobody may scan it (non-global address, a cluster member's address).
    Never(String),
    /// This scanner's own `never_scan` covers it; another scanner may take it.
    Mine(String),
}

impl Refusal {
    fn reason(&self) -> &str {
        match self {
            Refusal::Never(w) | Refusal::Mine(w) => w,
        }
    }
}

/// Config-only refusal applied before nmap runs: never scan a non-global
/// address, and leave anything in this node's `never_scan` to others.
/// Catches jobs that were queued before an operator edited `never_scan`,
/// requeued orphans, and admin-requeued failed jobs.
fn locally_refused(ip: &IpAddr, never: &[ipnet::IpNet]) -> Option<Refusal> {
    if !crate::net::is_scannable_target(*ip) {
        return Some(Refusal::Never("non-global address".into()));
    }
    let canon = crate::net::canonical(*ip);
    never
        .iter()
        .find(|n| n.contains(&canon))
        .map(|n| Refusal::Mine(format!("never_scan {n}")))
}

/// A scan to run, and who to report it to.
#[derive(Clone)]
enum Job {
    /// Standalone: a row in our own queue.
    Local { id: i64, ip: IpAddr, level: u8 },
    /// Cluster: granted by `arbiter` under a lease.
    Granted {
        arbiter: NodeId,
        uid: String,
        ip: IpAddr,
        level: u8,
        lease: Duration,
        started_at: String,
    },
}

impl Job {
    fn ip(&self) -> IpAddr {
        match self {
            Job::Local { ip, .. } | Job::Granted { ip, .. } => *ip,
        }
    }
    fn level(&self) -> u8 {
        match self {
            Job::Local { level, .. } | Job::Granted { level, .. } => *level,
        }
    }
}

/// How a scan ended.
enum Outcome {
    Done(nmap_xml::ScanResult),
    Failed(String),
    /// The arbiter gave the job to someone else (lease lost).
    Abandoned,
}

/// How long to wait for an arbiter's answer to a claim.
const CLAIM_TIMEOUT: Duration = Duration::from_secs(15);
/// Skip an arbiter that did not answer for this long.
const ARBITER_BACKOFF: Duration = Duration::from_secs(30);
/// Rebuild the member-address set this often (member list, DNS).
const SAFETY_REFRESH: Duration = Duration::from_secs(300);

/// Targets no scanner touches: the addresses of all cluster members.
struct Safety {
    addrs: std::collections::HashSet<IpAddr>,
    built: Option<std::time::Instant>,
}

impl Safety {
    fn new() -> Self {
        Self {
            addrs: Default::default(),
            built: None,
        }
    }

    async fn refresh(&mut self, node: &Node) {
        if self.built.is_some_and(|t| t.elapsed() < SAFETY_REFRESH) {
            return;
        }
        let mut addrs = std::collections::HashSet::new();
        let mut hosts: Vec<String> = node.dial_targets().into_iter().map(|t| t.2).collect();
        if let Ok(rows) = crate::cluster::members::all(&node.store).await {
            hosts.extend(rows.into_iter().filter_map(|m| m.address));
        }
        hosts.extend(node.cfg.advertise.clone());
        for h in hosts {
            if let Ok(Ok(it)) =
                tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host(h)).await
            {
                addrs.extend(it.map(|sa| sa.ip()));
            }
        }
        self.addrs = addrs;
        self.built = Some(std::time::Instant::now());
    }

    fn refuses(&self, ip: &IpAddr) -> Option<String> {
        self.addrs
            .contains(ip)
            .then(|| "cluster member address".to_string())
    }
}

/// Where jobs come from and where outcomes go.
struct Source {
    rec: Recorder,
    cfg: Config,
    pace: pace::SharedPace,
    safety: tokio::sync::Mutex<Safety>,
    unreachable: std::sync::Mutex<std::collections::HashMap<NodeId, std::time::Instant>>,
}

impl Source {
    fn node(&self) -> Option<&Arc<Node>> {
        match &self.rec {
            Recorder::Cluster(n) => Some(n),
            Recorder::Local(_) => None,
        }
    }

    /// Next job to run, or None when there is nothing for us.
    async fn acquire(&self) -> anyhow::Result<Option<Job>> {
        let Some(node) = self.node() else {
            let Some(job) = self.rec.next_queued_job().await? else {
                return Ok(None);
            };
            // Distinguish "IP row gone" (fail the job) from a transient DB
            // error (leave the job for a later pass instead of failing it).
            let ip: Option<String> = sqlx::query_scalar("SELECT ip FROM ips WHERE id=?")
                .bind(job.ip_id)
                .fetch_optional(&self.rec.store().pool)
                .await?;
            let parsed = ip.as_deref().and_then(|s| s.parse::<IpAddr>().ok());
            let Some(ip) = parsed else {
                let _ = self
                    .rec
                    .finish_job(job.id, None, Some("invalid target"))
                    .await;
                return Box::pin(self.acquire()).await;
            };
            // Re-check never_scan / non-global here too: the job may have been
            // queued before an operator edited never_scan, or requeued on
            // restart (standalone has no cluster Safety pre-flight otherwise).
            if let Some(r) = locally_refused(&ip, &self.cfg.scan.never_scan) {
                info!(target = %ip, why = r.reason(), "scan refused");
                let _ = self.rec.finish_job(job.id, None, Some(r.reason())).await;
                return Box::pin(self.acquire()).await;
            }
            return Ok(Some(Job::Local {
                id: job.id,
                ip,
                level: job.level as u8,
            }));
        };
        // Arbiters with queued work, most urgent first.
        let arbiters: Vec<(Vec<u8>, i64, String)> = sqlx::query_as(
            "SELECT arbiter, MAX(level) AS l, MIN(queued_at) AS q FROM scan_jobs
             WHERE status = 'queued' AND arbiter IS NOT NULL
             GROUP BY arbiter ORDER BY l DESC, q ASC",
        )
        .fetch_all(&node.store.pool)
        .await?;
        for (a, _, _) in arbiters {
            let Ok(arbiter) = NodeId::from_slice(&a) else {
                continue;
            };
            // No scan work for or from a peer this node blocked.
            if node.is_blocked(&arbiter) {
                continue;
            }
            if self
                .unreachable
                .lock()
                .unwrap()
                .get(&arbiter)
                .is_some_and(|t| t.elapsed() < ARBITER_BACKOFF)
            {
                continue;
            }
            let grant = match node.request(arbiter, Msg::Claim, CLAIM_TIMEOUT).await {
                Ok(Msg::ClaimReply { grant }) => grant,
                Ok(_) => None,
                Err(e) => {
                    debug!(arbiter = %arbiter.short(), ?e, "claim failed");
                    self.unreachable
                        .lock()
                        .unwrap()
                        .insert(arbiter, std::time::Instant::now());
                    None
                }
            };
            let Some(g) = grant else { continue };
            let Ok(ip) = g.ip.parse::<IpAddr>() else {
                self.report(
                    node,
                    arbiter,
                    &g.job_uid,
                    "failed",
                    Some("invalid target".into()),
                )
                .await;
                continue;
            };
            // Pre-flight: refused targets and duplicates never reach nmap.
            let refused = match locally_refused(&ip, &self.cfg.scan.never_scan) {
                some @ Some(_) => some,
                None => {
                    let mut s = self.safety.lock().await;
                    s.refresh(node).await;
                    s.refuses(&ip).map(Refusal::Never)
                }
            };
            match refused {
                Some(Refusal::Never(why)) => {
                    info!(target = %ip, %why, "scan refused");
                    self.report(node, arbiter, &g.job_uid, "refused", Some(why))
                        .await;
                    continue;
                }
                // Our own never_scan: hand the job back for another scanner.
                Some(Refusal::Mine(why)) => {
                    info!(target = %ip, %why, "scan declined");
                    self.report(node, arbiter, &g.job_uid, "declined", Some(why))
                        .await;
                    continue;
                }
                None => {}
            }
            if self.duplicate(&g.job_uid, &g.ip, g.level).await? {
                self.report(node, arbiter, &g.job_uid, "superseded", None)
                    .await;
                continue;
            }
            return Ok(Some(Job::Granted {
                arbiter,
                uid: g.job_uid,
                ip,
                level: g.level as u8,
                lease: Duration::from_secs(g.lease_secs),
                started_at: crate::store::data::now_ts(),
            }));
        }
        Ok(None)
    }

    /// A scan of this IP at this level or higher is running, or finished
    /// within the cooldown.
    async fn duplicate(&self, uid: &str, ip: &str, level: i64) -> anyhow::Result<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
             WHERE i.ip = ? AND j.uid != ? AND j.level >= ?
               AND (j.status = 'running'
                    OR (j.status = 'done' AND j.finished_at > datetime('now', ?)))",
        )
        .bind(ip)
        .bind(uid)
        .bind(level)
        .bind(format!("-{} hours", self.pace.cooldown_hours()))
        .fetch_one(&self.rec.store().pool)
        .await?;
        Ok(n > 0)
    }

    /// Tell the arbiter how a job ended, retrying for about two minutes; if
    /// it never hears, its lease sweep finds our result (or requeues).
    async fn report(
        &self,
        node: &Arc<Node>,
        arbiter: NodeId,
        uid: &str,
        status: &str,
        error: Option<String>,
    ) {
        let msg = Msg::Complete {
            job_uid: uid.to_string(),
            status: status.to_string(),
            error,
        };
        let mut wait = Duration::from_secs(2);
        for _ in 0..6 {
            match node.request(arbiter, msg.clone(), CLAIM_TIMEOUT).await {
                Ok(Msg::CompleteReply { ok: true }) => return,
                Ok(_) => {
                    warn!(job = %uid, arbiter = %arbiter.short(), "arbiter refused the outcome");
                    return;
                }
                Err(e) => debug!(job = %uid, ?e, "reporting outcome failed; retrying"),
            }
            tokio::time::sleep(wait).await;
            wait *= 2;
        }
        warn!(job = %uid, arbiter = %arbiter.short(), "arbiter unreachable; outcome not reported");
    }

    /// Record a finished job.
    async fn finish(&self, job: &Job, outcome: Outcome) {
        match (job, self.node()) {
            (Job::Local { id, .. }, _) => {
                let r = match &outcome {
                    Outcome::Done(res) => self.rec.finish_job(*id, Some(res), None).await,
                    Outcome::Failed(e) => self.rec.finish_job(*id, None, Some(e)).await,
                    Outcome::Abandoned => Ok(()),
                };
                if let Err(e) = r {
                    warn!(job = id, ?e, "could not record scan outcome (job deleted?)");
                }
            }
            (
                Job::Granted {
                    arbiter,
                    uid,
                    ip,
                    level,
                    started_at,
                    ..
                },
                Some(node),
            ) => match outcome {
                Outcome::Done(res) => {
                    if let Err(e) = self
                        .rec
                        .record_scan_result(uid, &ip.to_string(), *level as i64, started_at, &res)
                        .await
                    {
                        warn!(job = %uid, ?e, "could not record scan result");
                        self.report(node, *arbiter, uid, "failed", Some(e.to_string()))
                            .await;
                        return;
                    }
                    self.report(node, *arbiter, uid, "done", None).await;
                }
                Outcome::Failed(e) => self.report(node, *arbiter, uid, "failed", Some(e)).await,
                Outcome::Abandoned => {}
            },
            _ => {}
        }
    }

    /// Queue row for the live queue view, if we have it.
    async fn queue_row(&self, job: &Job) -> Option<crate::events::QueueJob> {
        let store = self.rec.store();
        let id = match job {
            Job::Local { id, .. } => *id,
            Job::Granted { uid, .. } => {
                sqlx::query_scalar("SELECT id FROM scan_jobs WHERE uid = ?")
                    .bind(uid)
                    .fetch_optional(&store.pool)
                    .await
                    .ok()??
            }
        };
        store.queue_job(id).await.ok()?
    }
}

/// Run nmap for `job`; in a cluster, renew the lease meanwhile and give up
/// if the arbiter says it is no longer ours.
async fn run_scan(
    source: &Source,
    job: &Job,
    argv: Vec<String>,
    nmap: PathBuf,
    timeout: Duration,
) -> Outcome {
    // kill_on_drop: when the timeout (or a lost lease) drops this future,
    // nmap must die with it, not linger behind a freed worker slot.
    let run = async {
        let out = tokio::process::Command::new(nmap)
            .args(&argv)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::piped())
            // Capture stderr so a failure says *why* ("requires root privileges",
            // "Failed to resolve", …) instead of a bare exit code.
            .stderr(std::process::Stdio::piped())
            .output();
        match tokio::time::timeout(timeout, out).await {
            Ok(Ok(out)) if out.status.success() => match nmap_xml::parse_nmap_xml(&out.stdout) {
                Ok(res) => Outcome::Done(res),
                Err(e) => Outcome::Failed(e.to_string()),
            },
            Ok(Ok(out)) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let detail = stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
                Outcome::Failed(if detail.is_empty() {
                    format!("exit {:?}", out.status.code())
                } else {
                    format!("exit {:?}: {}", out.status.code(), detail.trim())
                })
            }
            Ok(Err(e)) => Outcome::Failed(e.to_string()),
            Err(_) => Outcome::Failed("timeout".into()),
        }
    };
    let (
        Job::Granted {
            arbiter,
            uid,
            lease,
            ..
        },
        Some(node),
    ) = (job, source.node())
    else {
        return run.await;
    };
    let renew = async {
        let every = (*lease / 3).max(Duration::from_millis(200));
        loop {
            tokio::time::sleep(every).await;
            let renewed = node
                .request(
                    *arbiter,
                    Msg::Renew {
                        job_uid: uid.clone(),
                    },
                    every,
                )
                .await;
            // An unreachable arbiter is not a refusal: keep scanning; it
            // requeues the job if the lease runs out.
            if let Ok(Msg::RenewReply { ok: false }) = renewed {
                return;
            }
        }
    };
    tokio::select! {
        o = run => o,
        _ = renew => {
            warn!(job = %uid, "scan lease lost; nmap stopped");
            Outcome::Abandoned
        }
    }
}

pub async fn run_workers(
    rec: Recorder,
    cfg: Config,
    pace: pace::SharedPace,
    nmap_path: PathBuf,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    notifier: crate::events::Notifier,
) {
    if matches!(rec, Recorder::Local(_)) {
        // In a cluster the arbiters recover their own jobs.
        match rec.requeue_orphaned_jobs().await {
            Ok(0) => {}
            Ok(n) => info!(jobs = n, "requeued scans interrupted by the last shutdown"),
            Err(e) => warn!(?e, "could not requeue interrupted scans"),
        }
    }
    let source = Arc::new(Source {
        rec: rec.clone(),
        cfg: cfg.clone(),
        pace: pace.clone(),
        safety: tokio::sync::Mutex::new(Safety::new()),
        unreachable: Default::default(),
    });
    let mut joinset = tokio::task::JoinSet::new();
    let mut last_start: Option<tokio::time::Instant> = None;
    loop {
        if *shutdown.borrow() {
            break;
        }
        // Reap finished scans: JoinSet::len() counts them until joined.
        while joinset.try_join_next().is_some() {}
        // Re-read every pass so admin changes apply without a restart.
        let p = pace.get();
        if let Some(node) = source.node() {
            *node.status.local.lock().unwrap() = crate::cluster::status::LocalStatus {
                pace: Some(crate::cluster::status::PaceInfo {
                    max_workers: p.max_workers as u32,
                    max_scans_per_hour: p.max_scans_per_hour,
                    timeout_secs: p.timeout_secs,
                }),
                active_scans: joinset.len() as u32,
            };
        }
        while joinset.len() < p.max_workers {
            // Cadence: space starts evenly instead of bursting up to the cap.
            let Some(interval) = p.interval() else { break };
            if last_start.is_some_and(|t| t.elapsed() < interval) {
                break;
            }
            // Rate cap (spec §5), also across restarts; per scanner.
            match rec.jobs_started_last_hour().await {
                Ok(n) if n >= p.max_scans_per_hour => break,
                Err(e) => {
                    warn!(?e, "rate cap check failed");
                    break;
                }
                _ => {}
            }
            let job = match source.acquire().await {
                Ok(Some(job)) => job,
                Ok(None) => break,
                Err(e) => {
                    warn!(?e, "queue poll failed");
                    break;
                }
            };
            if let Some(j) = source.queue_row(&job).await {
                notifier.publish(j);
            }
            last_start = Some(tokio::time::Instant::now());
            let argv = nmap_argv(job.level(), &job.ip(), &cfg);
            let source2 = source.clone();
            let notifier2 = notifier.clone();
            let nmap = nmap_path.clone();
            let timeout = Duration::from_secs(p.timeout_secs);
            joinset.spawn(async move {
                let outcome = run_scan(&source2, &job, argv, nmap, timeout).await;
                if let Outcome::Done(_) = &outcome {
                    info!(target = %job.ip(), level = job.level(), "scan done");
                }
                source2.finish(&job, outcome).await;
                if let Some(j) = source2.queue_row(&job).await {
                    notifier2.publish(j);
                }
            });
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            _ = shutdown.changed() => {}
        }
    }
    while joinset.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::store::Store;
    use std::io::Write;
    use std::net::IpAddr;

    fn test_config(dir: &std::path::Path) -> Config {
        let toml = format!(
            r#"
trap_listen = "0.0.0.0:8080"
admin_listen = "127.0.0.1:8443"
database_path = "{db}"
data_dir = "{dir}"
rules_dir = "rules"
[webauthn]
rp_id = "x.example"
origin = "https://x.example"
rp_name = "x"
[maxmind]
account_id = "1"
license_key = "k"
"#,
            db = dir.join("t.db").display(),
            dir = dir.display()
        );
        let path = dir.join("c.toml");
        std::fs::write(&path, toml).unwrap();
        Config::load(&path).unwrap()
    }

    #[test]
    fn argv_contains_target_last_and_xml_flag() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let argv = nmap_argv(2, &ip, &cfg);
        assert_eq!(argv.last().unwrap(), "203.0.113.9");
        assert!(argv.windows(2).any(|w| w == ["-oX", "-"]));
        assert!(argv.contains(&"-sV".to_string()));
    }

    #[test]
    fn ipv6_target_gets_dash6_and_mapped_v4_is_canonicalised() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());
        let v6: IpAddr = "2001:db8::5".parse().unwrap();
        let argv = nmap_argv(2, &v6, &cfg);
        assert!(argv.contains(&"-6".to_string()), "{argv:?}");
        assert_eq!(argv.last().unwrap(), "2001:db8::5");
        // IPv4-mapped IPv6 is scanned as the v4 address, with no -6.
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        let argv = nmap_argv(2, &mapped, &cfg);
        assert!(!argv.contains(&"-6".to_string()), "{argv:?}");
        assert_eq!(argv.last().unwrap(), "203.0.113.9");
    }

    #[test]
    fn own_never_scan_is_a_refusal_for_this_scanner_only() {
        let never: Vec<ipnet::IpNet> = vec!["203.0.113.0/24".parse().unwrap()];
        assert_eq!(
            locally_refused(&"203.0.113.9".parse().unwrap(), &never),
            Some(Refusal::Mine("never_scan 203.0.113.0/24".into()))
        );
        assert_eq!(
            locally_refused(&"10.0.0.1".parse().unwrap(), &never),
            Some(Refusal::Never("non-global address".into()))
        );
    }

    #[test]
    fn non_global_targets_are_locally_refused() {
        let never: Vec<ipnet::IpNet> = vec![];
        assert!(locally_refused(&"127.0.0.1".parse().unwrap(), &never).is_some());
        assert!(locally_refused(&"10.0.0.1".parse().unwrap(), &never).is_some());
        assert!(locally_refused(&"169.254.169.254".parse().unwrap(), &never).is_some());
        assert!(locally_refused(&"203.0.113.9".parse().unwrap(), &never).is_none());
        let never = vec!["203.0.113.0/24".parse().unwrap()];
        assert!(locally_refused(&"203.0.113.9".parse().unwrap(), &never).is_some());
    }

    #[tokio::test]
    async fn pending_lower_level_job_is_upgraded_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store
            .upsert_ip("198.51.100.2".parse().unwrap())
            .await
            .unwrap();
        // A level-1 probe queues a job; a level-4 exploit arrives before it runs.
        assert!(matches!(
            store.enqueue_scan(ip.id, 1, 24).await.unwrap(),
            crate::store::scans::EnqueueOutcome::Queued(_)
        ));
        assert!(matches!(
            store.enqueue_scan(ip.id, 4, 24).await.unwrap(),
            crate::store::scans::EnqueueOutcome::Queued(_)
        ));
        // Still one queued job, now at the higher level.
        let (n, level): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), MAX(level) FROM scan_jobs WHERE ip_id = ? AND status='queued'",
        )
        .bind(ip.id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(n, 1, "no duplicate job");
        assert_eq!(level, 4, "level raised to the higher request");
        // A later equal-or-lower request is still suppressed.
        assert!(matches!(
            store.enqueue_scan(ip.id, 2, 24).await.unwrap(),
            crate::store::scans::EnqueueOutcome::Cooldown
        ));
    }

    #[tokio::test]
    async fn cooldown_suppresses_rescan_but_allows_upgrade_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store
            .upsert_ip("198.51.100.1".parse().unwrap())
            .await
            .unwrap();
        // Pretend a level-1 scan finished just now.
        let job = match store.enqueue_scan(ip.id, 1, 24).await.unwrap() {
            crate::store::scans::EnqueueOutcome::Queued(id) => id,
            other => panic!("expected queued, got {other:?}"),
        };
        store.finish_job(job, None, None).await.unwrap();
        // Same level within cooldown → suppressed.
        assert!(matches!(
            store.enqueue_scan(ip.id, 1, 24).await.unwrap(),
            crate::store::scans::EnqueueOutcome::Cooldown
        ));
        // Higher level → one upgrade allowed.
        assert!(matches!(
            store.enqueue_scan(ip.id, 3, 24).await.unwrap(),
            crate::store::scans::EnqueueOutcome::Queued(_)
        ));
    }

    #[tokio::test]
    async fn finish_job_on_deleted_ip_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = s.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
        let job = match s.enqueue_scan(ip.id, 1, 24).await.unwrap() {
            crate::store::scans::EnqueueOutcome::Queued(j) => j,
            o => panic!("{o:?}"),
        };
        s.next_queued_job().await.unwrap();
        assert!(s.delete_ip(ip.id).await.unwrap());
        assert!(s.finish_job(job, None, Some("timeout")).await.is_err());
        assert!(s.queue_job(job).await.unwrap().is_none());
    }

    fn fake_nmap(dir: &std::path::Path) -> PathBuf {
        let fake = dir.join("fake-nmap");
        std::fs::write(&fake, "#!/bin/sh\ncat \"$(dirname \"$0\")/nmap.xml\"\n").unwrap();
        std::fs::copy("tests/fixtures/nmap-basic.xml", dir.join("nmap.xml")).unwrap();
        let mut perms = std::fs::metadata(&fake).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&fake, perms).unwrap();
        fake
    }

    async fn wait_for_scans(store: &Store, n: i64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let done: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans")
                .fetch_one(&store.pool)
                .await
                .unwrap();
            if done >= n {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "only {done} of {n} scans finished"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Regression: finished tasks were never reaped from the JoinSet, so the
    /// pool stalled for good after `max_workers` scans.
    #[tokio::test]
    async fn worker_keeps_draining_after_first_batch() {
        let dir = tempfile::tempdir().unwrap();
        let fake = fake_nmap(dir.path());
        let cfg = test_config(dir.path());
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let jobs = cfg.scan.max_workers as i64 * 2 + 1;
        for i in 0..jobs {
            let ip = store
                .upsert_ip(format!("198.51.100.{}", 30 + i).parse().unwrap())
                .await
                .unwrap();
            store.enqueue_scan(ip.id, 2, 24).await.unwrap();
        }
        let (tx, rx) = tokio::sync::watch::channel(false);
        let p = pace::SharedPace::new(pace::Pace {
            max_workers: cfg.scan.max_workers,
            max_scans_per_hour: 3600,
            timeout_secs: 60,
        });
        let pool = tokio::spawn(run_workers(
            store.local(),
            cfg,
            p,
            fake,
            rx,
            crate::events::Notifier::new(),
        ));
        wait_for_scans(&store, jobs).await;
        tx.send(true).unwrap();
        pool.await.unwrap();
    }

    /// Regression: on timeout the output future was dropped but the nmap
    /// child kept running, so orphans piled up behind freed worker slots.
    #[tokio::test]
    async fn timed_out_nmap_is_killed_and_job_fails() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let fake = dir.path().join("slow-nmap");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\necho $$ > {}\nexec sleep 30\n",
                pidfile.display()
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&fake).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&fake, perms).unwrap();

        let cfg = test_config(dir.path());
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store
            .upsert_ip("198.51.100.99".parse().unwrap())
            .await
            .unwrap();
        store.enqueue_scan(ip.id, 1, 24).await.unwrap();
        let p = pace::SharedPace::new(pace::Pace {
            max_workers: 1,
            max_scans_per_hour: 3600,
            timeout_secs: 1,
        });
        let (tx, rx) = tokio::sync::watch::channel(false);
        let pool = tokio::spawn(run_workers(
            store.local(),
            cfg,
            p,
            fake,
            rx,
            crate::events::Notifier::new(),
        ));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let err = loop {
            let e: Option<String> =
                sqlx::query_scalar("SELECT error FROM scan_jobs WHERE status = 'failed'")
                    .fetch_optional(&store.pool)
                    .await
                    .unwrap()
                    .flatten();
            if let Some(e) = e {
                break e;
            }
            assert!(std::time::Instant::now() < deadline, "job never timed out");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        };
        assert!(err.contains("timeout"), "{err}");
        tx.send(true).unwrap();
        pool.await.unwrap();
        let pid = std::fs::read_to_string(&pidfile).unwrap();
        let proc = std::path::PathBuf::from(format!("/proc/{}", pid.trim()));
        for _ in 0..20 {
            // A killed child may linger as a zombie until reaped; check state.
            let alive = std::fs::read_to_string(proc.join("stat"))
                .map(|s| s.split_whitespace().nth(2).is_none_or(|st| st != "Z"))
                .unwrap_or(false);
            if !alive {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("nmap child {} still running after timeout", pid.trim());
    }

    #[tokio::test]
    async fn worker_runs_fake_nmap_and_stores_ports() {
        let dir = tempfile::tempdir().unwrap();
        // Fake nmap: copies the fixture to stdout, ignores argv.
        let fake = dir.path().join("fake-nmap");
        std::fs::write(&fake, "#!/bin/sh\ncat \"$(dirname \"$0\")/nmap.xml\"\n").unwrap();
        std::fs::copy("tests/fixtures/nmap-basic.xml", dir.path().join("nmap.xml")).unwrap();
        let mut perms = std::fs::metadata(&fake).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&fake, perms).unwrap();

        let cfg = test_config(dir.path());
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store
            .upsert_ip("198.51.100.23".parse().unwrap())
            .await
            .unwrap();
        store.enqueue_scan(ip.id, 2, 24).await.unwrap();

        let (tx, rx) = tokio::sync::watch::channel(false);
        let p = pace::SharedPace::new(pace::Pace::from_config(&cfg.scan));
        let pool = tokio::spawn(run_workers(
            store.local(),
            cfg,
            p,
            fake.clone(),
            rx,
            crate::events::Notifier::new(),
        ));
        // Wait until the job is done (poll DB, max 5s).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let done: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans")
                .fetch_one(&store.pool)
                .await
                .unwrap();
            if done == 1 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "worker did not finish"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        tx.send(true).unwrap();
        pool.await.unwrap();
        let ports: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ports")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(ports, 3);
        let mut f = std::fs::File::create("/dev/null").unwrap();
        f.write_all(b"").unwrap(); // keeps Write import used
    }
}
