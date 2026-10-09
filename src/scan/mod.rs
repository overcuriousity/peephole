pub mod arbiter;
pub mod crawler;
pub mod facts;
pub mod guard;
pub mod handout;
pub mod hostkeys;
pub mod nmap_xml;
pub mod order;
pub mod pace;
pub mod probe;
pub mod profiles;
pub mod rank;
pub mod retry;
pub mod safety;
pub mod scrub;
pub mod weight;

use crate::classify::Classifier;
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::msg::{Grant, Msg};
use crate::config::{Config, TorUnknown};
use crate::store::recorder::Recorder;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Largest nmap XML kept; beyond it nmap is killed and the job fails. A
/// full-range scan of a busy host is well under 1 MB.
pub const MAX_STDOUT: usize = 16 * 1024 * 1024;
/// Start of nmap's stderr kept for the error message (the rest is drained).
const MAX_STDERR: usize = 64 * 1024;

/// A scan level as stored or granted, if it is one (1..=4). Anything else is
/// refused rather than truncated: `5 as u8`, or 260 truncated to 4, must
/// not pick a preset.
pub fn valid_level(level: i64) -> Option<u8> {
    u8::try_from(level).ok().filter(|l| (1..=4).contains(l))
}

/// nmap's own per-host limit, just under the job timeout so nmap reports
/// what it found before the worker kills it.
fn host_timeout_secs(timeout_secs: u64) -> u64 {
    timeout_secs
        .saturating_sub((timeout_secs / 20).max(15))
        .max(30)
}

/// `argv` (a level's list) with what every run adds: the timeouts, the
/// rate floor of level 4, `-6`, XML on standard output and the target.
fn complete(
    mut argv: Vec<String>,
    level: u8,
    target: IpAddr,
    cfg: &Config,
    timeout_secs: u64,
) -> Vec<String> {
    let host_timeout = host_timeout_secs(timeout_secs);
    if !argv.iter().any(|a| a.starts_with("--host-timeout")) {
        argv.push("--host-timeout".into());
        argv.push(format!("{host_timeout}s"));
    }
    let scripts = argv
        .iter()
        .any(|a| a == "--script" || a.starts_with("--script=") || a == "-sC" || a == "-A");
    if scripts && !argv.iter().any(|a| a.starts_with("--script-timeout")) {
        argv.push("--script-timeout".into());
        argv.push(format!("{}s", (host_timeout / 3).clamp(30, 600)));
    }
    // Level 4 scans every port: a floor on the send rate keeps hosts that
    // drop probes from slowing nmap's adaptive timing to a crawl.
    if level == 4
        && !argv
            .iter()
            .any(|a| a == "--min-rate" || a.starts_with("--min-rate="))
    {
        argv.push("--min-rate".into());
        argv.push(cfg.scan.min_rate.to_string());
    }
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

/// nmap argv (after the binary name) for a level and target (spec §5).
/// None for a level outside 1..=4.
pub fn nmap_argv(
    level: u8,
    target: &IpAddr,
    cfg: &Config,
    timeout_secs: u64,
) -> Option<Vec<String>> {
    // Collapse IPv4-mapped IPv6 to IPv4 so a `::ffff:a.b.c.d` target is scanned
    // as the v4 address (and matched by v4 guards) rather than handed to nmap
    // as an IPv6 literal.
    let target = crate::net::canonical(*target);
    let argv = cfg.default_level_argv(level)?;
    Some(complete(argv, level, target, cfg, timeout_secs))
}

/// The arguments of an audit: the built-in list of the level, whatever
/// `scan.level_argv` says, so the audit is comparable.
pub fn audit_argv(
    level: u8,
    target: &IpAddr,
    cfg: &Config,
    timeout_secs: u64,
) -> Option<Vec<String>> {
    let target = crate::net::canonical(*target);
    let argv = profiles::builtin(level, cfg.scan.level4_udp)?;
    Some(complete(argv, level, target, cfg, timeout_secs))
}

/// Why this scanner will not run a job (now).
#[derive(Debug, PartialEq)]
pub(crate) enum Refusal {
    /// Nobody may scan it (non-global address, a cluster member's address,
    /// a Tor exit, a verified crawler).
    Never(String),
    /// This scanner's own `never_scan` covers it; another scanner may take it.
    Mine(String),
    /// Not now (Tor status unknown, never-scan lists not loaded):
    /// standalone the job waits, in a cluster it is handed back for another
    /// scanner.
    Defer(String),
}

impl Refusal {
    pub(crate) fn reason(&self) -> &str {
        match self {
            Refusal::Never(w) | Refusal::Mine(w) | Refusal::Defer(w) => w,
        }
    }
}

/// A grant handed back "later" for these reasons is no fault of the
/// scanner: the arbiter does not count it as undelivered.
pub(crate) const NOT_REPLICATED: &str = "job not replicated here yet";
pub(crate) const TOR_UNKNOWN: &str = "Tor exit status unknown (no exit list loaded)";

/// What a scanner knows of an arbiter with queued work, for [`can_pay`].
#[derive(Clone, Copy)]
struct Payer {
    /// This node itself: its own jobs pay from its own scan budget.
    own: bool,
    /// It sells and buys scans at scanner prices (`pay::sells_scans`).
    sells_scans: bool,
    /// `(scan_queued, scan_budget_mc)` as its heartbeat announces them.
    announced: Option<(u32, u32)>,
    /// Its balance in this node's book; None without a book.
    balance: Option<u64>,
}

/// Whether an arbiter can pay `sell` (this scanner's price; None: it does
/// not sell): this node's own jobs from `own_left`, another arbiter from
/// the budget it announces, at most its balance here.
fn can_pay(sell: Option<u32>, own_left: u64, a: &Payer) -> bool {
    let Some(price) = sell.map(u64::from) else {
        return false;
    };
    if a.own {
        return own_left >= price;
    }
    if !a.sells_scans {
        return false;
    }
    match (a.announced, a.balance) {
        (Some((queued, budget)), Some(balance)) => {
            queued > 0 && (budget as u64).min(balance) >= price
        }
        _ => false,
    }
}

/// `arbiters` (in urgency order) with those that can pay this scanner's
/// price first; each group keeps its order. Price differences between
/// arbiters do not reorder anything: the scanner names the price.
fn can_pay_first(arbiters: Vec<NodeId>, can_pay: impl Fn(&NodeId) -> bool) -> Vec<NodeId> {
    let (mut first, rest): (Vec<_>, Vec<_>) = arbiters.into_iter().partition(|a| can_pay(a));
    first.extend(rest);
    first
}

/// A grant at a level this scanner excluded from its claim: an arbiter
/// older than `exclude_levels` ignored it. Handed back "later".
fn over_share(level: i64, exclude: &[u8]) -> bool {
    u8::try_from(level).is_ok_and(|l| exclude.contains(&l))
}

/// Config-only refusal applied before nmap runs: never scan a non-global
/// address, and leave anything in this node's `never_scan` to others.
/// Catches jobs that were queued before an operator edited `never_scan`,
/// requeued orphans, and admin-requeued failed jobs.
pub(crate) fn locally_refused(ip: &IpAddr, never: &[ipnet::IpNet]) -> Option<Refusal> {
    if !crate::net::is_scannable_target(*ip) {
        return Some(Refusal::Never("non-global address".into()));
    }
    let canon = crate::net::canonical(*ip);
    never
        .iter()
        .find(|n| n.contains(&canon))
        .map(|n| Refusal::Mine(format!("never_scan {n}")))
}

/// The job that job `uid` gives way to, if any: a scan of the same IP at
/// its level or higher that is running, or a queued job of another arbiter
/// that ranks first (higher level, then earlier `queued_at`, then lower
/// uid). Decided from replicated rows only, so when two arbiters queued
/// the same IP, every arbiter and scanner that holds both jobs lets the
/// same one run and supersedes the other. Adoption keeps a job's uid and
/// `queued_at`, so its rank survives a takeover.
pub(crate) async fn outranked_by(
    pool: &sqlx::SqlitePool,
    uid: &str,
) -> anyhow::Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT o.uid FROM scan_jobs j JOIN scan_jobs o ON o.ip_id = j.ip_id AND o.uid != j.uid
         WHERE j.uid = ?
           AND ((o.status = 'running' AND o.level >= j.level
                 AND o.started_at > datetime('now', ?)
                 AND o.started_at <= datetime('now', '+10 minutes'))
             OR (o.status = 'queued' AND o.arbiter IS NOT NULL AND o.arbiter IS NOT j.arbiter
                 AND (o.level > j.level OR (o.level = j.level
                      AND (o.queued_at < j.queued_at
                           OR (o.queued_at = j.queued_at AND o.uid < j.uid))))))
         LIMIT 1",
    )
    .bind(uid)
    .bind(format!("-{} hours", pace::STALE_RUNNING_HOURS))
    .fetch_optional(pool)
    .await?)
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
        /// The arbiter's offer funding it and its price (`credits::jobs`).
        offer: Option<(u64, u32)>,
    },
    /// Another node's scan, run again here to check it (`credits::audit`).
    /// No arbiter and no lease: nobody waits for it.
    Audit {
        /// The uid of the audited scan, and its job's.
        of: String,
        job_uid: String,
        ip: IpAddr,
        level: u8,
        started_at: String,
        /// Who bought it, its offer and what it offered; None: an unpaid
        /// pick.
        offer: Option<(NodeId, u64, u32)>,
    },
}

impl Job {
    fn ip(&self) -> IpAddr {
        match self {
            Job::Local { ip, .. } | Job::Granted { ip, .. } | Job::Audit { ip, .. } => *ip,
        }
    }
    fn level(&self) -> u8 {
        match self {
            Job::Local { level, .. } | Job::Granted { level, .. } | Job::Audit { level, .. } => {
                *level
            }
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
/// Standalone: a deferred job is looked at again after this long.
const DEFER_RETRY: Duration = Duration::from_secs(60);
/// `scan.tor_unknown = "scan"`: how often that is warned about.
const TOR_WARN_EVERY: Duration = Duration::from_secs(600);

/// A grant this scanner turns down: the status reported to the arbiter and
/// why.
type Turndown = (&'static str, Option<String>);

/// Where jobs come from and where outcomes go.
struct Source {
    rec: Recorder,
    cfg: Config,
    pace: pace::SharedPace,
    safety: tokio::sync::Mutex<safety::Safety>,
    crawlers: Option<crawler::Crawlers>,
    tor: std::sync::Mutex<guard::TorView>,
    origins: guard::Origins,
    /// This node's rules (built in), to classify the requests behind a
    /// grant again (`guard::evidence`).
    classifier: &'static Classifier,
    /// Standalone jobs waiting (Tor status unknown), until when.
    deferred: std::sync::Mutex<HashMap<i64, Instant>>,
    tor_warned: std::sync::Mutex<Option<Instant>>,
    unreachable: std::sync::Mutex<HashMap<NodeId, Instant>>,
    /// Granted jobs this scanner runs now: IP (canonical) and level. Known
    /// before the job's state replicates anywhere.
    active: std::sync::Mutex<HashMap<IpAddr, u8>>,
    /// Per-level duration estimates for the response-ratio order.
    order: order::Cached,
    /// The scans of other nodes this scanner audits.
    audits: tokio::sync::Mutex<crate::credits::audit::Picker>,
}

/// Hours since a `YYYY-MM-DD HH:MM:SS` (UTC) time; unparsable: infinite.
fn hours_since(ts: &str) -> f64 {
    chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S")
        .map(|t| (chrono::Utc::now().naive_utc() - t).num_seconds() as f64 / 3600.0)
        .unwrap_or(f64::INFINITY)
}

impl Source {
    fn new(
        rec: Recorder,
        cfg: Config,
        pace: pace::SharedPace,
        classifier: &'static Classifier,
    ) -> Self {
        let s = &cfg.scan.safety;
        Self {
            classifier,
            safety: tokio::sync::Mutex::new(safety::Safety::new(&cfg)),
            crawlers: s
                .verify_crawlers
                .then(|| crawler::Crawlers::new(&s.crawler_domains)),
            tor: std::sync::Mutex::new(guard::TorView::new(&cfg.data_dir)),
            origins: guard::Origins::from_config(s, rec.node_id()),
            deferred: Default::default(),
            tor_warned: Default::default(),
            unreachable: Default::default(),
            active: Default::default(),
            order: order::Cached::new(),
            audits: tokio::sync::Mutex::new(crate::credits::audit::Picker::new(
                cfg.credits.audit_share,
            )),
            rec,
            cfg,
            pace,
        }
    }

    fn node(&self) -> Option<&Arc<Node>> {
        match &self.rec {
            Recorder::Cluster(n) => Some(n),
            Recorder::Local(_) => None,
        }
    }

    /// Everything that stops this scanner from scanning `ip` (stored as
    /// `ip_text`, queued at `queued_at`) apart from the grant itself.
    async fn preflight(
        &self,
        ip: &IpAddr,
        ip_text: &str,
        queued_at: &str,
    ) -> anyhow::Result<Option<Refusal>> {
        if let Some(r) = locally_refused(ip, &self.cfg.scan.never_scan) {
            return Ok(Some(r));
        }
        {
            let mut s = self.safety.lock().await;
            s.refresh(&self.cfg, self.node().map(|n| &**n)).await;
            if let Some(why) = s.refuses(ip) {
                return Ok(Some(Refusal::Never(why)));
            }
            // Fail closed: what the lists cover is not known.
            if let Some(why) = s.unavailable() {
                return Ok(Some(Refusal::Defer(why)));
            }
            if let Some(why) = s.listed(ip) {
                return Ok(Some(Refusal::Mine(why)));
            }
        }
        let local = self.tor.lock().unwrap().local(ip);
        match guard::tor_status(&self.rec.store().pool, local, ip_text, &self.origins).await? {
            guard::TorStatus::Exit => return Ok(Some(Refusal::Never("Tor exit".into()))),
            guard::TorStatus::NotExit => {}
            guard::TorStatus::Unknown => {
                let s = &self.cfg.scan.safety;
                match s.tor_unknown {
                    TorUnknown::Defer if hours_since(queued_at) < s.tor_wait_hours as f64 => {
                        return Ok(Some(Refusal::Defer(TOR_UNKNOWN.into())));
                    }
                    TorUnknown::Defer => {
                        return Ok(Some(Refusal::Never(format!(
                            "Tor exit status still unknown after {} h (no exit list loaded)",
                            s.tor_wait_hours
                        ))));
                    }
                    TorUnknown::Scan => {
                        let mut w = self.tor_warned.lock().unwrap();
                        if w.is_none_or(|t| t.elapsed() > TOR_WARN_EVERY) {
                            *w = Some(Instant::now());
                            warn!(
                                "scanning without a Tor exit list: Tor exits may be \
                                 counter-scanned (scan.tor_unknown = \"scan\")"
                            );
                        }
                    }
                }
            }
        }
        if let Some(c) = &self.crawlers
            && let Some(name) = c.confirmed(*ip).await
        {
            return Ok(Some(Refusal::Never(format!("verified crawler ({name})"))));
        }
        Ok(None)
    }

    /// Next job to run, or None when there is nothing for us.
    async fn acquire(&self, exclude: &[u8]) -> anyhow::Result<Option<Job>> {
        match self.node() {
            None => self.acquire_local(exclude).await,
            Some(node) => self.acquire_granted(node, exclude).await,
        }
    }

    /// Why this scanner would not run an audit of `ip` (stored as
    /// `ip_text`) at `level` now, if it would not: an audit obeys
    /// everything a scan does (never_scan, members' addresses, Tor exits,
    /// crawlers, the evidence held here) except the rescan cooldown. An
    /// auditor asks this before it accepts a bought audit.
    async fn audit_refusal(
        &self,
        ip: &IpAddr,
        ip_text: &str,
        level: u8,
    ) -> anyhow::Result<Option<String>> {
        let now = crate::store::data::now_ts();
        if let Some(r) = self.preflight(ip, ip_text, &now).await? {
            return Ok(Some(r.reason().to_string()));
        }
        let pool = &self.rec.store().pool;
        let ev = guard::evidence(pool, ip_text, &self.origins, Some(self.classifier)).await?;
        if ev.allowed_level(&self.cfg.scan.safety) < level {
            return Ok(Some(
                "the requests held here do not back a scan at this level".into(),
            ));
        }
        Ok(None)
    }

    /// The next audit this scanner can start, a bought one before an
    /// unpaid pick, that [`Source::audit_refusal`] lets through. A bought
    /// audit of an address scanned here now waits its turn; one refused
    /// writes nothing: its offer is released by `credits::audit`.
    async fn next_audit(&self, exclude: &[u8]) -> anyhow::Result<Option<Job>> {
        let Some(node) = self.node() else {
            return Ok(None);
        };
        let mut picker = self.audits.lock().await;
        picker.poll(&node.store.pool, &node.id()).await?;
        let (mut busy, mut found, mut failed) = (vec![], None, None);
        loop {
            let bought = node.audit_queue.lock().unwrap().take(exclude);
            let Some(t) = bought.or_else(|| picker.take(exclude)) else {
                break;
            };
            let end = |t: &crate::credits::audit::Task| {
                if let Some((p, q, _)) = t.offer {
                    node.audit_queue.lock().unwrap().end((p, q));
                }
            };
            let Ok(ip) = t.ip.parse::<IpAddr>() else {
                end(&t);
                continue;
            };
            let key = crate::net::canonical(ip);
            if self.active.lock().unwrap().contains_key(&key) {
                if t.offer.is_some() {
                    busy.push(t);
                }
                continue;
            }
            match self.audit_refusal(&ip, &t.ip, t.level).await {
                Ok(None) => {}
                Ok(Some(why)) => {
                    debug!(target = %ip, %why, "audit not run");
                    end(&t);
                    continue;
                }
                Err(e) => {
                    end(&t);
                    failed = Some(e);
                    break;
                }
            }
            self.active.lock().unwrap().insert(key, t.level);
            found = Some(Job::Audit {
                of: t.scan_uid,
                job_uid: t.job_uid,
                ip,
                level: t.level,
                started_at: crate::store::data::now_ts(),
                offer: t.offer,
            });
            break;
        }
        {
            let mut q = node.audit_queue.lock().unwrap();
            for t in busy.into_iter().rev() {
                q.put_back(t);
            }
        }
        match failed {
            Some(e) => Err(e),
            None => Ok(found),
        }
    }

    /// Standalone: our queue's next job that passes the pre-flight checks.
    /// Refused jobs never start (they do not count against the hourly
    /// rate); deferred ones stay queued and are looked at again later.
    async fn acquire_local(&self, exclude: &[u8]) -> anyhow::Result<Option<Job>> {
        let pool = &self.rec.store().pool;
        let est = self.order.get(pool).await;
        let mut seen: HashSet<i64> = HashSet::new();
        loop {
            let skip: Vec<i64> = {
                let mut d = self.deferred.lock().unwrap();
                let now = Instant::now();
                d.retain(|_, until| *until > now);
                d.keys().copied().chain(seen.iter().copied()).collect()
            };
            let row: Option<(i64, Option<String>, i64, String)> =
                sqlx::query_as(sqlx::AssertSqlSafe(format!(
                    "SELECT j.id, i.ip, j.level, j.queued_at FROM scan_jobs j
                 LEFT JOIN ips i ON i.id = j.ip_id
                 WHERE j.status = 'queued' AND j.arbiter IS NULL
                   AND j.id NOT IN (SELECT value FROM json_each(?))
                   AND j.level NOT IN (SELECT value FROM json_each(?))
                 ORDER BY {} LIMIT 1",
                    est.order_by("j", "j.id")
                )))
                .bind(serde_json::to_string(&skip)?)
                .bind(serde_json::to_string(exclude)?)
                .fetch_optional(pool)
                .await?;
            let Some((id, ip_text, level, queued_at)) = row else {
                return Ok(None);
            };
            seen.insert(id);
            let target = ip_text
                .as_deref()
                .and_then(|t| Some((t, t.parse::<IpAddr>().ok()?)));
            let Some((ip_text, ip)) = target else {
                self.rec.refuse_job(id, "invalid target").await?;
                continue;
            };
            let Some(level) = valid_level(level) else {
                warn!(job = id, level, "scan level out of range; job refused");
                self.rec.refuse_job(id, "invalid scan level").await?;
                continue;
            };
            // Re-check here: the job may have been queued before an
            // operator edited never_scan, or before the exit list loaded.
            match self.preflight(&ip, ip_text, &queued_at).await? {
                Some(Refusal::Defer(why)) => {
                    debug!(target = %ip, %why, "scan deferred");
                    self.deferred
                        .lock()
                        .unwrap()
                        .insert(id, Instant::now() + DEFER_RETRY);
                    continue;
                }
                Some(r) => {
                    info!(target = %ip, why = r.reason(), "scan refused");
                    self.rec.refuse_job(id, r.reason()).await?;
                    continue;
                }
                None => {}
            }
            if self.rec.start_job(id).await? {
                return Ok(Some(Job::Local { id, ip, level }));
            }
        }
    }

    /// Cluster: ask the arbiters with queued work, most urgent first.
    async fn acquire_granted(
        &self,
        node: &Arc<Node>,
        exclude: &[u8],
    ) -> anyhow::Result<Option<Job>> {
        let est = self.order.get(&node.store.pool).await;
        let arbiters: Vec<(Vec<u8>, f64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT j.arbiter, MAX({}) AS r FROM scan_jobs j
             WHERE j.status = 'queued' AND j.arbiter IS NOT NULL
               AND j.level NOT IN (SELECT value FROM json_each(?))
             GROUP BY j.arbiter ORDER BY r DESC, MIN(j.queued_at) ASC",
            est.ratio_sql("j")
        )))
        .bind(serde_json::to_string(exclude)?)
        .fetch_all(&node.store.pool)
        .await?;
        let arbiters: Vec<NodeId> = arbiters
            .into_iter()
            .filter_map(|(a, _)| NodeId::from_slice(&a).ok())
            .collect();
        // Arbiters that can pay this scanner's price first; this node's
        // own jobs pay from its own scan budget.
        let me = node.id();
        // Before its first refresh it sells at 0, as its heartbeat says.
        let sell = crate::credits::price::own_scan_price(node, &node.price_table());
        // Without a book (or the self tally) no arbiter counts as able to
        // pay; claiming goes on in urgency order.
        let book = match crate::credits::book(node).await {
            Ok(b) => Some(b),
            Err(e) => {
                debug!(?e, "no book: no arbiter counts as paying");
                None
            }
        };
        let own_left = match (sell, &book) {
            (Some(_), Some(book)) => {
                match crate::credits::jobs::self_committed(&node.store.pool, &me).await {
                    Ok(self_mc) => {
                        crate::credits::jobs::budget(&book.ledger, &me, node.scan_share(), self_mc)
                    }
                    Err(e) => {
                        debug!(?e, "own scan reservations not read");
                        0
                    }
                }
            }
            _ => 0,
        };
        let members = node.members();
        let can_pay = |a: &NodeId| -> bool {
            let payer = Payer {
                own: *a == me,
                sells_scans: members
                    .get(a)
                    .is_some_and(|m| crate::credits::pay::sells_scans(m.proto_max)),
                announced: node
                    .status
                    .known(a)
                    .map(|k| (k.hb.scan_queued, k.hb.scan_budget_mc)),
                balance: book.as_ref().map(|b| b.balance(a)),
            };
            can_pay(sell, own_left, &payer)
        };
        let arbiters = can_pay_first(arbiters, can_pay);
        let min_mc = sell.map_or(0, crate::credits::price::min_take);
        for arbiter in arbiters {
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
            let grant = match node
                .request(
                    arbiter,
                    Msg::Claim {
                        exclude_levels: exclude.to_vec(),
                        min_mc,
                    },
                    CLAIM_TIMEOUT,
                )
                .await
            {
                Ok(Msg::ClaimReply { grant }) => grant,
                Ok(_) => None,
                Err(e) => {
                    debug!(arbiter = %arbiter.short(), ?e, "claim failed");
                    self.unreachable
                        .lock()
                        .unwrap()
                        .insert(arbiter, Instant::now());
                    None
                }
            };
            let Some(g) = grant else { continue };
            if over_share(g.level, exclude) {
                info!(job = %g.job_uid, target = %g.ip, "scan grant turned down: at the level-4 share");
                let (node, uid, offer) = (node.clone(), g.job_uid, g.offer_seq);
                tokio::spawn(async move {
                    Self::report(
                        &node,
                        arbiter,
                        &uid,
                        "later",
                        Some("at the level-4 share".into()),
                    )
                    .await;
                    if let Some(seq) = offer {
                        crate::credits::jobs::settle(&node, arbiter, seq, 0).await;
                    }
                });
                continue;
            }
            match self.check_grant(arbiter, &g).await? {
                Ok(job) => {
                    self.active
                        .lock()
                        .unwrap()
                        .insert(crate::net::canonical(job.ip()), job.level());
                    return Ok(Some(job));
                }
                Err((status, why)) => {
                    info!(job = %g.job_uid, target = %g.ip, status, why = why.as_deref().unwrap_or(""), "scan grant turned down");
                    // In the background: the retries must not stall the
                    // worker loop (finish reports run in a worker task too).
                    let (node, uid, offer) = (node.clone(), g.job_uid, g.offer_seq);
                    tokio::spawn(async move {
                        Self::report(&node, arbiter, &uid, status, why).await;
                        if let Some(seq) = offer {
                            crate::credits::jobs::settle(&node, arbiter, seq, 0).await;
                        }
                    });
                }
            }
        }
        Ok(None)
    }

    /// A grant is the arbiter's word only: check it against this node's own
    /// replicated copy of the job and the evidence behind it before nmap
    /// runs. Not yet replicated, not backed well enough yet, or Tor status
    /// unknown: handed back for now ("later"); never scanned here: handed
    /// back for good ("declined") for another scanner; contradicting our
    /// copy: refused.
    async fn check_grant(
        &self,
        arbiter: NodeId,
        g: &Grant,
    ) -> anyhow::Result<Result<Job, Turndown>> {
        let checked = self.check_grant_here(arbiter, g).await;
        // An internal error ends the grant too: a funded offer goes back
        // at once instead of lapsing.
        if checked.is_err()
            && let Some(seq) = g.offer_seq
            && let Some(node) = self.node()
        {
            crate::credits::jobs::settle(node, arbiter, seq, 0).await;
        }
        checked
    }

    /// [`Self::check_grant`] without giving a funded offer back on error.
    async fn check_grant_here(
        &self,
        arbiter: NodeId,
        g: &Grant,
    ) -> anyhow::Result<Result<Job, Turndown>> {
        let pool = &self.rec.store().pool;
        let Some(level) = valid_level(g.level) else {
            return Ok(Err(("refused", Some("invalid scan level".into()))));
        };
        let Ok(ip) = g.ip.parse::<IpAddr>() else {
            return Ok(Err(("failed", Some("invalid target".into()))));
        };
        // (ip, level, arbiter, queued_at, manual) — a type alias so clippy's
        // type_complexity lint stays happy now that the row carries `manual`.
        type GrantRow = (String, i64, Option<Vec<u8>>, String, i64);
        let row: Option<GrantRow> = sqlx::query_as(
            "SELECT i.ip, j.level, j.arbiter, j.queued_at, j.manual FROM scan_jobs j
             JOIN ips i ON i.id = j.ip_id WHERE j.uid = ?",
        )
        .bind(&g.job_uid)
        .fetch_optional(pool)
        .await?;
        let Some((ip_text, job_level, job_arbiter, queued_at, manual)) = row else {
            return Ok(Err(("later", Some(NOT_REPLICATED.into()))));
        };
        if job_arbiter.as_deref() != Some(&arbiter.0[..]) {
            return Ok(Err((
                "declined",
                Some("job arbitrated by another node here".into()),
            )));
        }
        let same_ip = ip_text
            .parse::<IpAddr>()
            .is_ok_and(|a| crate::net::canonical(a) == crate::net::canonical(ip));
        if !same_ip || job_level != g.level {
            warn!(job = %g.job_uid, arbiter = %arbiter.short(), granted_ip = %g.ip, granted_level = g.level,
                  ip = %ip_text, level = job_level, "grant contradicts the replicated job");
            return Ok(Err((
                "refused",
                Some("grant does not match the job".into()),
            )));
        }
        // Already scanning it here (another arbiter's job for the same IP
        // whose state has not replicated yet): covered, or not now.
        let running = self
            .active
            .lock()
            .unwrap()
            .get(&crate::net::canonical(ip))
            .copied();
        if let Some(l) = running {
            let why = Some(format!("this scanner is scanning the IP at level {l}"));
            return Ok(Err((if l >= level { "superseded" } else { "later" }, why)));
        }
        // A bought (manual) job skips the evidence rule; the preflight's
        // safety checks below apply to it all the same.
        if manual == 0 {
            let ev = guard::evidence(pool, &ip_text, &self.origins, Some(self.classifier)).await?;
            let allowed = ev.allowed_level(&self.cfg.scan.safety);
            if allowed < level {
                if ev.max_level < level {
                    let why = format!(
                        "no request here asks for level {level} (highest: {})",
                        ev.max_level
                    );
                    return Ok(Err(("declined", Some(why))));
                }
                // More requests may still arrive or replicate here.
                let why = format!(
                    "level {level} needs more evidence ({} request(s); thin evidence allows {allowed})",
                    ev.requests
                );
                return Ok(Err(("later", Some(why))));
            }
        }
        match self.preflight(&ip, &ip_text, &queued_at).await? {
            Some(Refusal::Never(why)) => return Ok(Err(("refused", Some(why)))),
            // Our own never_scan: hand it back for another scanner.
            Some(Refusal::Mine(why)) => return Ok(Err(("declined", Some(why)))),
            // Not now: hand it back, to be offered here again later.
            Some(Refusal::Defer(why)) => return Ok(Err(("later", Some(why)))),
            None => {}
        }
        // Our stored spelling: the arbiter's may differ (same_ip allows it).
        if self.duplicate(&g.job_uid, &ip_text, g.level).await? {
            return Ok(Err(("superseded", None)));
        }
        // Arbiters older than this check grant a job that lost the tie-break.
        if let Some(other) = outranked_by(pool, &g.job_uid).await? {
            let why = format!("job {other} for this IP ranks first");
            return Ok(Err(("superseded", Some(why))));
        }
        Ok(Ok(Job::Granted {
            arbiter,
            uid: g.job_uid.clone(),
            ip,
            level,
            lease: Duration::from_secs(g.lease_secs),
            started_at: crate::store::data::now_ts(),
            offer: g.offer_seq.zip(Some(g.price_mc)),
        }))
    }

    /// A scan of this IP at this level or higher is running, or finished
    /// within the cooldown.
    async fn duplicate(&self, uid: &str, ip: &str, level: i64) -> anyhow::Result<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
             WHERE i.ip = ? AND j.uid != ? AND j.level >= ?
               AND ((j.status = 'running' AND j.started_at > datetime('now', ?)
                     AND j.started_at <= datetime('now', '+10 minutes'))
                    OR (j.status = 'done' AND j.finished_at > datetime('now', ?)))",
        )
        .bind(ip)
        .bind(uid)
        .bind(level)
        .bind(format!("-{} hours", pace::STALE_RUNNING_HOURS))
        .bind(format!("-{} hours", self.pace.cooldown_hours()))
        .fetch_one(&self.rec.store().pool)
        .await?;
        Ok(n > 0)
    }

    /// Tell the arbiter how a job ended, retrying for about two minutes; if
    /// it never hears, its lease sweep finds our result (or requeues).
    async fn report(
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
                // An arbiter older than "later" rejects it; the job goes
                // back to its queue when our lease expires.
                Ok(_) if status == "later" => {
                    debug!(job = %uid, arbiter = %arbiter.short(), "arbiter does not take \"later\"; its lease expiry requeues the job");
                    return;
                }
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
        if let Job::Granted { ip, .. } | Job::Audit { ip, .. } = job {
            self.active
                .lock()
                .unwrap()
                .remove(&crate::net::canonical(*ip));
        }
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
                Job::Audit {
                    of,
                    job_uid,
                    ip,
                    level,
                    started_at,
                    offer,
                },
                node,
            ) => {
                match outcome {
                    Outcome::Done(res) => {
                        if let Err(e) = self
                            .rec
                            .record_scan_audit(
                                of,
                                job_uid,
                                &ip.to_string(),
                                *level as i64,
                                started_at,
                                &res,
                            )
                            .await
                        {
                            warn!(audit_of = %of, ?e, "could not record audit");
                        } else if let (Some((payer, seq, price)), Some(node)) = (offer, node) {
                            // A bought audit, published: charge its offer.
                            let receipt = crate::cluster::record::Record::CreditReceipt {
                                payer: *payer,
                                offer_seq: *seq,
                                charged_mc: *price,
                                answered: vec![crate::credits::price::AUDIT.into()],
                                economy: crate::cluster::record::ECONOMY,
                            };
                            if let Err(e) = crate::cluster::repl::append(node, &[receipt]).await {
                                warn!(audit_of = %of, ?e, "audit receipt not written");
                            }
                        }
                    }
                    // A failed audit says nothing: it is not published.
                    Outcome::Failed(e) => debug!(audit_of = %of, error = %e, "audit scan failed"),
                    Outcome::Abandoned => {}
                }
                // Charged, or (failed, abandoned) left for `credits::audit`
                // to release.
                if let (Some((payer, seq, _)), Some(node)) = (offer, node) {
                    node.audit_queue.lock().unwrap().end((*payer, *seq));
                }
            }
            (
                Job::Granted {
                    arbiter,
                    uid,
                    ip,
                    level,
                    started_at,
                    offer,
                    ..
                },
                Some(node),
            ) => {
                let delivered = match outcome {
                    Outcome::Done(res) => {
                        if let Err(e) = self
                            .rec
                            .record_scan_result(
                                uid,
                                &ip.to_string(),
                                *level as i64,
                                started_at,
                                &res,
                            )
                            .await
                        {
                            warn!(job = %uid, ?e, "could not record scan result");
                            Self::report(node, *arbiter, uid, "failed", Some(e.to_string())).await;
                            false
                        } else {
                            Self::report(node, *arbiter, uid, "done", None).await;
                            true
                        }
                    }
                    Outcome::Failed(e) => {
                        Self::report(node, *arbiter, uid, "failed", Some(e)).await;
                        false
                    }
                    // The lease is lost: nothing delivered, the offer freed.
                    Outcome::Abandoned => false,
                };
                if let Some((seq, price)) = offer {
                    let charged = if delivered { *price } else { 0 };
                    crate::credits::jobs::settle(node, *arbiter, *seq, charged).await;
                }
            }
            _ => {}
        }
    }

    /// Queue row for the live queue view, if we have it.
    async fn queue_row(&self, job: &Job) -> Option<crate::events::QueueJob> {
        let store = self.rec.store();
        let id = match job {
            Job::Local { id, .. } => *id,
            Job::Audit { .. } => return None,
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

/// Run nmap and collect its output, holding at most [`MAX_STDOUT`] bytes
/// of XML: beyond that nmap is killed and the scan fails. stderr is drained
/// in the background, keeping only its start.
async fn run_nmap(nmap: PathBuf, argv: &[String]) -> Outcome {
    use tokio::io::AsyncReadExt;
    // kill_on_drop: when the timeout (or a lost lease) drops this future,
    // nmap must die with it, not linger behind a freed worker slot.
    let spawned = tokio::process::Command::new(nmap)
        .args(argv)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        // Capture stderr so a failure says *why* ("requires root privileges",
        // "Failed to resolve", …) instead of a bare exit code.
        .stderr(std::process::Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    let (Some(stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return Outcome::Failed("nmap pipes unavailable".into());
    };
    let errors = tokio::spawn(async move {
        let mut kept = Vec::new();
        let mut buf = [0u8; 8192];
        while let Ok(n) = stderr.read(&mut buf).await {
            if n == 0 {
                break;
            }
            let room = MAX_STDERR.saturating_sub(kept.len());
            kept.extend_from_slice(&buf[..n.min(room)]);
        }
        kept
    });
    let mut out = Vec::new();
    if let Err(e) = stdout
        .take(MAX_STDOUT as u64 + 1)
        .read_to_end(&mut out)
        .await
    {
        return Outcome::Failed(format!("reading nmap output: {e}"));
    }
    if out.len() > MAX_STDOUT {
        let _ = child.kill().await;
        errors.abort();
        return Outcome::Failed(format!(
            "nmap output exceeds {} MiB; scan stopped",
            MAX_STDOUT / (1024 * 1024)
        ));
    }
    let status = match child.wait().await {
        Ok(s) => s,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    let stderr = errors.await.unwrap_or_default();
    if status.success() {
        return match nmap_xml::parse_nmap_xml(&out) {
            Ok(res) => Outcome::Done(res),
            Err(e) => Outcome::Failed(e.to_string()),
        };
    }
    let stderr = String::from_utf8_lossy(&stderr);
    let detail = stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let detail: String = detail.chars().take(500).collect();
    let how = describe_exit(&status);
    Outcome::Failed(if detail.is_empty() {
        how
    } else {
        format!("{how}: {}", detail.trim())
    })
}

/// Why a finished nmap process ended, for the failure message. A normal
/// non-zero exit keeps its code. A process killed by a signal has no exit
/// code (`None` on Unix), and a bare "exit None" tells an operator nothing;
/// naming the signal does, since the common cases need different fixes: the
/// OOM killer (SIGKILL) means too little memory, a crash (SIGSEGV/SIGABRT)
/// is an nmap bug or bad input, and SIGTERM/SIGINT is an external stop.
fn describe_exit(status: &std::process::ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("exit {code}");
    }
    #[cfg(unix)]
    if let Some(sig) = std::os::unix::process::ExitStatusExt::signal(status) {
        let (name, hint) = signal_desc(sig);
        return match hint {
            Some(h) => format!("killed by {name} ({h})"),
            None => format!("killed by {name}"),
        };
    }
    "exited abnormally".into()
}

/// Name and, where it points at a likely cause, a short hint for the signals
/// that end an nmap scan. Unknown signals fall back to their number.
fn signal_desc(sig: i32) -> (String, Option<&'static str>) {
    match sig {
        2 => ("SIGINT".into(), Some("interrupted")),
        6 => ("SIGABRT".into(), Some("nmap aborted")),
        9 => ("SIGKILL".into(), Some("forced kill, often out of memory")),
        11 => ("SIGSEGV".into(), Some("nmap crashed")),
        15 => ("SIGTERM".into(), Some("terminated externally")),
        other => (format!("signal {other}"), None),
    }
}

/// Run nmap for `job` (`run_leased`), then keep this node's own addresses
/// and names out of the result's XML before it is signed.
async fn run_scan(
    source: &Source,
    job: &Job,
    argv: Vec<String>,
    nmap: PathBuf,
    timeout: Duration,
) -> Outcome {
    let mut outcome = run_leased(source, job, argv, nmap, timeout).await;
    if let Outcome::Done(res) = &mut outcome {
        source.scrub(&job.ip(), res).await;
    }
    outcome
}

impl Source {
    /// Replace this node's own global addresses and names in the scan's
    /// XML (`scan::scrub`), unless the target is one of them: that scan is
    /// about this node. The safety lock is held only to read the lists;
    /// the pass over the XML (up to `MAX_RAW_XML`) runs on a blocking
    /// thread, so other workers' preflights and the probe gate do not wait
    /// for it.
    async fn scrub(&self, target: &IpAddr, res: &mut nmap_xml::ScanResult) {
        let (addrs, names) = {
            let s = self.safety.lock().await;
            if s.is_own(target) {
                return;
            }
            (s.own_global(), s.own_names())
        };
        let raw = std::mem::take(&mut res.raw_xml);
        match tokio::task::spawn_blocking(move || scrub::scrub(&raw, &addrs, &names)).await {
            Ok((xml, n)) => {
                res.raw_xml = xml;
                res.scrubbed = n;
            }
            // `scrub` does not panic; if it ever did, fail as loudly as the
            // inline call would have.
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            // Cancelled, which happens only when the runtime shuts down
            // before the task starts: the XML is left empty rather than
            // unscrubbed.
            Err(_) => {}
        }
    }
}

/// Run nmap for `job`; in a cluster, renew the lease meanwhile and give up
/// if the arbiter says it is no longer ours.
async fn run_leased(
    source: &Source,
    job: &Job,
    argv: Vec<String>,
    nmap: PathBuf,
    timeout: Duration,
) -> Outcome {
    let run = async {
        match tokio::time::timeout(timeout, run_nmap(nmap, &argv)).await {
            Ok(o) => o,
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
        let (every, wait, retry) = renew_timing(*lease);
        let mut next = every;
        loop {
            tokio::time::sleep(next).await;
            let renewed = node
                .request(
                    *arbiter,
                    Msg::Renew {
                        job_uid: uid.clone(),
                    },
                    wait,
                )
                .await;
            next = match renewed {
                Ok(Msg::RenewReply { ok: false }) => return,
                Ok(Msg::RenewReply { ok: true }) => every,
                // An unreachable arbiter is not a refusal: keep scanning and
                // try again soon, several times before the lease runs out;
                // the arbiter requeues the job only once it has.
                _ => retry,
            };
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

/// How a scanner renews a lease of `lease`: every quarter of it, each
/// attempt waiting at most an eighth, a failed one retried after a
/// sixteenth. A renewal that fails once leaves several more tries before
/// the lease runs out (three quarters of it after the last success).
fn renew_timing(lease: Duration) -> (Duration, Duration, Duration) {
    let floor = Duration::from_millis(100);
    (
        (lease / 4).max(floor),
        (lease / 8).max(floor),
        (lease / 16).max(floor),
    )
}

/// One running level-4 scan, counted while it lives.
struct L4Slot(Arc<std::sync::atomic::AtomicUsize>);

impl L4Slot {
    fn take(n: &Arc<std::sync::atomic::AtomicUsize>) -> Self {
        n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(n.clone())
    }
}

impl Drop for L4Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

pub async fn run_workers(
    rec: Recorder,
    cfg: Config,
    pace: pace::SharedPace,
    nmap_path: PathBuf,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    notifier: crate::events::Notifier,
    classifier: &'static Classifier,
) {
    if matches!(rec, Recorder::Local(_)) {
        // In a cluster the arbiters recover their own jobs.
        match rec.requeue_orphaned_jobs().await {
            Ok(0) => {}
            Ok(n) => info!(jobs = n, "requeued scans interrupted by the last shutdown"),
            Err(e) => warn!(?e, "could not requeue interrupted scans"),
        }
    }
    let source = Arc::new(Source::new(
        rec.clone(),
        cfg.clone(),
        pace.clone(),
        classifier,
    ));
    // An auditor asks before it accepts a bought audit (`credits::audit`).
    if let Some(node) = source.node() {
        let weak = Arc::downgrade(&source);
        let check: crate::credits::audit::Check = Arc::new(move |ip, ip_text, level| {
            let weak = weak.clone();
            Box::pin(async move {
                let Some(source) = weak.upgrade() else {
                    return Some("this node's scan workers stopped".to_string());
                };
                match source.audit_refusal(&ip, &ip_text, level).await {
                    Ok(why) => why,
                    Err(e) => Some(format!("{e:#}")),
                }
            })
        });
        *node.audit_check.lock().unwrap() = Some(check);
    }
    // Level-4 scans running now (see `L4Slot`).
    let running_l4 = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut joinset = tokio::task::JoinSet::new();
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
                    // Read by nodes of earlier versions only.
                    max_scans_per_hour: pace::ANNOUNCED_PER_HOUR,
                    timeout_secs: p.timeout_secs,
                }),
                active_scans: joinset.len() as u32,
            };
        }
        while joinset.len() < p.max_workers {
            let cap = pace::level4_cap(p.max_workers, cfg.scan.level4_max_share);
            let exclude: Vec<u8> = if running_l4.load(std::sync::atomic::Ordering::SeqCst) >= cap {
                vec![4]
            } else {
                vec![]
            };
            let audit = match source.next_audit(&exclude).await {
                Ok(a) => a,
                Err(e) => {
                    warn!(?e, "audit poll failed");
                    None
                }
            };
            let job = match audit {
                Some(job) => job,
                None => match source.acquire(&exclude).await {
                    Ok(Some(job)) => job,
                    Ok(None) => break,
                    Err(e) => {
                        warn!(?e, "queue poll failed");
                        break;
                    }
                },
            };
            let l4 = (job.level() == 4).then(|| L4Slot::take(&running_l4));
            if let Some(j) = source.queue_row(&job).await {
                notifier.publish(j);
            }
            let limit = pace::level_timeout_secs(p.timeout_secs, job.level());
            let argv = match &job {
                Job::Audit { .. } => audit_argv(job.level(), &job.ip(), &cfg, limit),
                _ => nmap_argv(job.level(), &job.ip(), &cfg, limit),
            };
            let source2 = source.clone();
            let notifier2 = notifier.clone();
            let nmap = nmap_path.clone();
            let timeout = Duration::from_secs(limit);
            joinset.spawn(async move {
                let _l4 = l4;
                let outcome = match argv {
                    Some(argv) => run_scan(&source2, &job, argv, nmap, timeout).await,
                    // Unreachable: acquire only hands out levels 1..=4.
                    None => Outcome::Failed("invalid scan level".into()),
                };
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

    /// Scanner config for tests: no Tor list and no DNS here, so neither
    /// check holds jobs back unless a test turns it on (`extra_scan`).
    fn test_config(dir: &std::path::Path) -> Config {
        config_with(dir, "tor_unknown = \"scan\"\nverify_crawlers = false\n")
    }

    fn config_with(dir: &std::path::Path, scan: &str) -> Config {
        let toml = format!(
            r#"
trap_listen = "0.0.0.0:8080"
admin_listen = "127.0.0.1:8443"
database_path = "{db}"
data_dir = "{dir}"
[webauthn]
rp_id = "x.example"
origin = "https://x.example"
rp_name = "x"
[maxmind]
account_id = "1"
license_key = "k"
[scan]
{scan}
"#,
            db = dir.join("t.db").display(),
            dir = dir.display()
        );
        let path = dir.join("c.toml");
        std::fs::write(&path, toml).unwrap();
        Config::load(&path).unwrap()
    }

    /// After one good renewal, an arbiter that stops answering is asked at
    /// least three more times before the lease it granted runs out.
    #[test]
    fn a_failed_renewal_is_retried_before_the_lease_expires() {
        for lease in [Duration::from_secs(10), Duration::from_secs(120)] {
            let (every, wait, retry) = renew_timing(lease);
            let (mut t, mut tries) = (every, 0);
            while t + wait < lease {
                tries += 1;
                t += wait + retry;
            }
            assert!(tries >= 3, "{lease:?}: {tries} tries");
        }
    }

    #[test]
    fn argv_contains_target_last_and_xml_flag() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let argv = nmap_argv(2, &ip, &cfg, 1800).unwrap();
        assert_eq!(argv.last().unwrap(), "203.0.113.9");
        assert!(argv.windows(2).any(|w| w == ["-oX", "-"]));
        assert!(argv.contains(&"-sV".to_string()));
    }

    #[test]
    fn ipv6_target_gets_dash6_and_mapped_v4_is_canonicalised() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());
        let v6: IpAddr = "2001:db8::5".parse().unwrap();
        let argv = nmap_argv(2, &v6, &cfg, 1800).unwrap();
        assert!(argv.contains(&"-6".to_string()), "{argv:?}");
        assert_eq!(argv.last().unwrap(), "2001:db8::5");
        // IPv4-mapped IPv6 is scanned as the v4 address, with no -6.
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        let argv = nmap_argv(2, &mapped, &cfg, 1800).unwrap();
        assert!(!argv.contains(&"-6".to_string()), "{argv:?}");
        assert_eq!(argv.last().unwrap(), "203.0.113.9");
    }

    /// nmap gives up on the host just before the worker would kill it, and
    /// scripts get their own limit.
    #[test]
    fn argv_carries_nmap_timeouts_under_the_job_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let after = |argv: &[String], flag: &str| {
            argv.iter()
                .position(|a| a == flag)
                .map(|i| argv[i + 1].clone())
        };
        let argv = nmap_argv(4, &ip, &cfg, 1800).unwrap();
        assert_eq!(after(&argv, "--host-timeout").as_deref(), Some("1710s"));
        assert_eq!(after(&argv, "--script-timeout").as_deref(), Some("570s"));
        let argv = nmap_argv(1, &ip, &cfg, 60).unwrap();
        assert_eq!(after(&argv, "--host-timeout").as_deref(), Some("45s"));
        assert_eq!(
            after(&argv, "--script-timeout"),
            None,
            "no scripts at level 1"
        );
        // An operator's own --host-timeout is kept.
        let cfg = config_with(
            dir.path(),
            "[scan.level_argv]\n2 = [\"-sT\", \"--host-timeout\", \"5m\"]\n",
        );
        let argv = nmap_argv(2, &ip, &cfg, 1800).unwrap();
        assert_eq!(argv.iter().filter(|a| *a == "--host-timeout").count(), 1);
    }

    /// --min-rate at level 4 only, from the config, and an
    /// operator's own value is kept.
    #[test]
    fn min_rate_is_added_at_level_4_only() {
        let dir = tempfile::tempdir().unwrap();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let cfg = config_with(dir.path(), "min_rate = 120\n");
        let after = |argv: &[String], flag: &str| {
            argv.iter()
                .position(|a| a == flag)
                .map(|i| argv[i + 1].clone())
        };
        let a4 = nmap_argv(4, &ip, &cfg, 3600).unwrap();
        assert_eq!(after(&a4, "--min-rate").as_deref(), Some("120"));
        for l in 1..=3 {
            assert!(
                !nmap_argv(l, &ip, &cfg, 1800)
                    .unwrap()
                    .iter()
                    .any(|a| a == "--min-rate")
            );
        }
        let cfg = config_with(
            dir.path(),
            "[scan.level_argv]\n4 = [\"-sS\", \"-p-\", \"--min-rate\", \"999\"]\n",
        );
        let a4 = nmap_argv(4, &ip, &cfg, 3600).unwrap();
        assert_eq!(a4.iter().filter(|a| *a == "--min-rate").count(), 1);
        assert_eq!(after(&a4, "--min-rate").as_deref(), Some("999"));
    }

    /// A signal-killed nmap names the signal instead of "exit None", and a
    /// normal non-zero exit keeps its code.
    #[cfg(unix)]
    #[test]
    fn describe_exit_names_the_signal() {
        use std::os::unix::process::ExitStatusExt;
        // Low 7 bits hold the terminating signal; a plain exit code is <<8.
        let killed = std::process::ExitStatus::from_raw(9);
        assert_eq!(
            describe_exit(&killed),
            "killed by SIGKILL (forced kill, often out of memory)"
        );
        let crashed = std::process::ExitStatus::from_raw(11);
        assert_eq!(describe_exit(&crashed), "killed by SIGSEGV (nmap crashed)");
        let odd = std::process::ExitStatus::from_raw(31);
        assert_eq!(describe_exit(&odd), "killed by signal 31");
        let exited = std::process::ExitStatus::from_raw(1 << 8);
        assert_eq!(describe_exit(&exited), "exit 1");
    }

    /// Levels are 1..=4: nothing else gets an argv, nothing is truncated.
    #[test]
    fn levels_outside_1_to_4_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        for l in [0u8, 5, 255] {
            assert!(nmap_argv(l, &ip, &cfg, 1800).is_none(), "level {l}");
        }
        for (l, ok) in [
            (0, None),
            (1, Some(1)),
            (4, Some(4)),
            (5, None),
            (260, None),
            (-1, None),
        ] {
            assert_eq!(valid_level(l), ok, "level {l}");
        }
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
            timeout_secs: 60,
        });
        let pool = tokio::spawn(run_workers(
            store.local(),
            cfg,
            p,
            fake,
            rx,
            crate::events::Notifier::new(),
            Classifier::builtin(),
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
            Classifier::builtin(),
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
            Classifier::builtin(),
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

    #[tokio::test]
    async fn worker_scrubs_its_own_address_from_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        let fake = fake_nmap(dir.path());
        // The fixture, with a greeting that names the scanner.
        let xml = std::fs::read_to_string("tests/fixtures/nmap-basic.xml").unwrap().replacen(
            "</port>",
            r#"<script id="smtp-commands" output="mail Hello scanner-5.example.net [198.51.100.5], 198.51.100.50 pleased"/></port>"#,
            1,
        );
        std::fs::write(dir.path().join("nmap.xml"), xml).unwrap();
        let cfg = config_with(
            dir.path(),
            "tor_unknown = \"scan\"\nverify_crawlers = false\nown_addresses = [\"198.51.100.5\"]\n",
        );
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
            fake,
            rx,
            crate::events::Notifier::new(),
            Classifier::builtin(),
        ));
        wait_for_scans(&store, 1).await;
        tx.send(true).unwrap();
        pool.await.unwrap();
        let (scrubbed, raw): (i64, Vec<u8>) = sqlx::query_as("SELECT scrubbed, raw_xml FROM scans")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(scrubbed, 1);
        let xml = String::from_utf8(zstd::decode_all(raw.as_slice()).unwrap()).unwrap();
        assert!(
            xml.contains("Hello scanner-5.example.net [[scanner]], 198.51.100.50"),
            "{xml}"
        );
        assert!(!xml.contains("[198.51.100.5]"));
        assert!(xml.contains("198.51.100.23"), "the target stays");
        assert!(
            xml.contains("args=\"nmap -sS -sV -oX - 198.51.100.23\""),
            "the args line stays"
        );
        let ports: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ports")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(ports, 3, "ports as before");
        let s = store.scan_by_id(1).await.unwrap().unwrap();
        assert_eq!(s.scrubbed, 1);
    }

    #[tokio::test]
    async fn a_scan_of_an_own_address_is_not_scrubbed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with(
            dir.path(),
            "tor_unknown = \"scan\"\nverify_crawlers = false\nown_addresses = [\"198.51.100.5\"]\n",
        );
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let p = pace::SharedPace::new(pace::Pace::from_config(&cfg.scan));
        let source = Source::new(store.local(), cfg.clone(), p, Classifier::builtin());
        source.safety.lock().await.refresh(&cfg, None).await;
        let xml = b"<nmaprun><host><ports><port protocol=\"tcp\" portid=\"25\"><state state=\"open\"/><script id=\"banner\" output=\"hi 198.51.100.5\"/></port></ports></host></nmaprun>";
        let mut res = nmap_xml::parse_nmap_xml(xml).unwrap();
        source
            .scrub(&"198.51.100.5".parse().unwrap(), &mut res)
            .await;
        assert_eq!(
            (res.scrubbed, res.raw_xml.as_slice()),
            (0, &xml[..]),
            "about this node"
        );
        source
            .scrub(&"198.51.100.23".parse().unwrap(), &mut res)
            .await;
        assert_eq!(res.scrubbed, 1);
        assert!(String::from_utf8_lossy(&res.raw_xml).contains("hi [scanner]"));
    }

    async fn status_of(store: &Store, ip: &str) -> (String, Option<String>, Option<String>) {
        sqlx::query_as(
            "SELECT j.status, j.started_at, j.error FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
             WHERE i.ip = ?",
        )
        .bind(ip)
        .fetch_one(&store.pool)
        .await
        .unwrap()
    }

    /// Regression: each refused job recursed once (Box::pin) and kept its
    /// start time, so a run of refusals could exhaust the stack and used
    /// up the hourly rate without a single nmap run.
    #[tokio::test]
    async fn refused_jobs_never_start_and_do_not_use_the_rate() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with(
            dir.path(),
            "tor_unknown = \"scan\"\nverify_crawlers = false\nnever_scan = [\"198.51.0.0/16\"]\n",
        );
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        for i in 0..300 {
            let ip = store
                .upsert_ip(
                    format!("198.51.{}.{}", i / 200, i % 200 + 1)
                        .parse()
                        .unwrap(),
                )
                .await
                .unwrap();
            store.enqueue_scan(ip.id, 3, 24).await.unwrap();
        }
        let ok = store
            .upsert_ip("203.0.113.50".parse().unwrap())
            .await
            .unwrap();
        store.enqueue_scan(ok.id, 1, 24).await.unwrap();
        let p = pace::SharedPace::new(pace::Pace::from_config(&cfg.scan));
        let source = Source::new(store.local(), cfg, p, Classifier::builtin());
        let job = source.acquire(&[]).await.unwrap().expect("the valid job");
        assert_eq!(job.ip().to_string(), "203.0.113.50");
        let (status, started, error) = status_of(&store, "198.51.0.1").await;
        assert_eq!(status, "refused");
        assert!(started.is_none());
        assert!(error.unwrap().contains("never_scan"));
        assert_eq!(store.local().jobs_started_last_hour().await.unwrap(), 1);
        assert!(source.acquire(&[]).await.unwrap().is_none());
    }

    fn write_tor_list(dir: &std::path::Path, extra: &str) {
        let mut list: String = (1..=150).map(|i| format!("198.18.0.{i}\n")).collect();
        list.push_str(extra);
        std::fs::write(dir.join("tor-exit.txt"), list).unwrap();
    }

    /// Without an exit list a job waits (default `tor_unknown = "defer"`);
    /// once a list is there it runs, unless the IP is an exit; and after
    /// `tor_wait_hours` without a list it is refused.
    #[tokio::test]
    async fn unknown_tor_status_defers_scans() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with(dir.path(), "verify_crawlers = false\n");
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let p = || pace::SharedPace::new(pace::Pace::from_config(&cfg.scan));
        let a = store
            .upsert_ip("203.0.113.60".parse().unwrap())
            .await
            .unwrap();
        store.enqueue_scan(a.id, 2, 24).await.unwrap();
        let source = Source::new(store.local(), cfg.clone(), p(), Classifier::builtin());
        assert!(source.acquire(&[]).await.unwrap().is_none(), "deferred");
        assert_eq!(status_of(&store, "203.0.113.60").await.0, "queued");
        assert!(
            source.acquire(&[]).await.unwrap().is_none(),
            "still waiting"
        );
        // The list loads (a fresh scanner, so the retry delay is not waited out).
        write_tor_list(dir.path(), "203.0.113.61\n");
        let source = Source::new(store.local(), cfg.clone(), p(), Classifier::builtin());
        let job = source
            .acquire(&[])
            .await
            .unwrap()
            .expect("runs once the list is there");
        assert_eq!(job.ip().to_string(), "203.0.113.60");
        // A listed exit is refused.
        let b = store
            .upsert_ip("203.0.113.61".parse().unwrap())
            .await
            .unwrap();
        store.enqueue_scan(b.id, 2, 24).await.unwrap();
        assert!(source.acquire(&[]).await.unwrap().is_none());
        let (status, _, error) = status_of(&store, "203.0.113.61").await;
        assert_eq!(
            (status.as_str(), error.as_deref()),
            ("refused", Some("Tor exit"))
        );
        // No list, and the job has waited long enough: refused.
        std::fs::remove_file(dir.path().join("tor-exit.txt")).unwrap();
        let c = store
            .upsert_ip("203.0.113.62".parse().unwrap())
            .await
            .unwrap();
        store.enqueue_scan(c.id, 2, 24).await.unwrap();
        sqlx::query("UPDATE scan_jobs SET queued_at = datetime('now', '-7 hours') WHERE ip_id = ?")
            .bind(c.id)
            .execute(&store.pool)
            .await
            .unwrap();
        let source = Source::new(store.local(), cfg.clone(), p(), Classifier::builtin());
        assert!(source.acquire(&[]).await.unwrap().is_none());
        let (status, _, error) = status_of(&store, "203.0.113.62").await;
        assert_eq!(status, "refused");
        assert!(error.unwrap().contains("still unknown"));
    }

    /// nmap output is bounded: past the cap nmap is killed and the job
    /// fails instead of the worker buffering without limit.
    #[tokio::test]
    async fn oversized_nmap_output_fails_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("chatty-nmap");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\nhead -c {} /dev/zero\nhead -c 200000 /dev/zero >&2\n",
                MAX_STDOUT + 4096
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&fake).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&fake, perms).unwrap();
        match run_nmap(fake, &[]).await {
            Outcome::Failed(e) => assert!(e.contains("exceeds"), "{e}"),
            _ => panic!("oversized output accepted"),
        }
        // A loud stderr alone is drained, not fatal.
        let fake = dir.path().join("noisy-nmap");
        std::fs::write(
            &fake,
            "#!/bin/sh\nhead -c 2000000 /dev/zero >&2\necho 'oops' >&2\nexit 3\n",
        )
        .unwrap();
        let mut perms = std::fs::metadata(&fake).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&fake, perms).unwrap();
        match run_nmap(fake, &[]).await {
            Outcome::Failed(e) => assert!(e.starts_with("exit 3:"), "{e}"),
            _ => panic!("failed nmap accepted"),
        }
    }

    /// A single-node cluster whose scanner checks grants of its own jobs.
    async fn cluster_source(dir: &std::path::Path, scan: &str) -> (Arc<Node>, Source, Store) {
        let store = Store::connect(&dir.join("t.db")).await.unwrap();
        let node = Node::open(crate::cluster::NodeParams {
            identity: crate::cluster::identity::Identity::generate().unwrap(),
            cluster: crate::config::ClusterConfig {
                node_name: "n".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: None,
                key_path: None,
                takeover_hours: 6.0,
                lease_secs: 120,
                remote_config: false,
                peers: vec![],
                origin_quota_mb: 20 * 1024,
            },
            roles: Default::default(),
            store: store.clone(),
            proto: (2, 2),
            data_dir: dir.to_path_buf(),
            retention_days: 0,
        })
        .await
        .unwrap();
        node.bootstrap().await.unwrap();
        let cfg = config_with(
            dir,
            &format!("tor_unknown = \"scan\"\nverify_crawlers = false\n{scan}"),
        );
        let p = pace::SharedPace::new(pace::Pace::from_config(&cfg.scan));
        let source = Source::new(
            Recorder::Cluster(node.clone()),
            cfg,
            p,
            Classifier::builtin(),
        );
        (node, source, store)
    }

    /// A request that the shipped rules put at `level`, as stored with that
    /// level and `label` (the scanner classifies it again).
    fn request(ip_id: i64, level: i64, label: &str) -> crate::store::requests::NewRequest {
        let (method, path, query, body): (&str, &str, Option<&str>, Option<&[u8]>) = match level {
            1 => ("GET", "/x", None, None),
            2 => ("GET", "/.env", None, None),
            3 => ("POST", "/login", None, Some(b"username=a&password=b")),
            _ => ("GET", "/login", Some("user=admin'%20OR%20'1'='1"), None),
        };
        crate::store::requests::NewRequest {
            ip_id,
            method: method.into(),
            path: path.into(),
            query: query.map(str::to_string),
            headers_json: "[]".into(),
            body: body.map(<[u8]>::to_vec),
            labels_json: format!("[\"{label}\"]"),
            severity: level,
            scan_level: level,
            is_fp_claim: false,
            page_token: None,
            ..Default::default()
        }
    }

    async fn job_uid(store: &Store, ip_id: i64) -> String {
        sqlx::query_scalar("SELECT uid FROM scan_jobs WHERE ip_id = ? ORDER BY id DESC LIMIT 1")
            .bind(ip_id)
            .fetch_one(&store.pool)
            .await
            .unwrap()
    }

    fn grant(uid: &str, ip: &str, level: i64) -> Grant {
        Grant {
            job_uid: uid.into(),
            ip: ip.into(),
            level,
            lease_secs: 60,
            offer_seq: None,
            price_mc: 0,
        }
    }

    /// A grant is checked against the scanner's own copy of the job and
    /// against the evidence for its level.
    #[tokio::test]
    async fn grants_are_checked_against_the_replicated_job_and_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let (node, source, store) = cluster_source(dir.path(), "").await;
        let me = node.id();
        let rec = Recorder::Cluster(node.clone());
        let ip = store
            .upsert_ip("203.0.113.70".parse().unwrap())
            .await
            .unwrap();
        rec.enqueue_scan(ip.id, 3, 24).await.unwrap();
        let uid = job_uid(&store, ip.id).await;
        let turned = |r: Result<Job, Turndown>| r.err().map(|(s, _)| s);
        // No request asks for any scan of this IP: handed back.
        let r = source
            .check_grant(me, &grant(&uid, &ip.ip, 3))
            .await
            .unwrap();
        assert_eq!(turned(r), Some("declined"));
        // One request at level 3: thin evidence allows level 2 only, for now.
        rec.insert_request(&request(ip.id, 3, "sqli"))
            .await
            .unwrap();
        let r = source
            .check_grant(me, &grant(&uid, &ip.ip, 3))
            .await
            .unwrap();
        assert_eq!(turned(r), Some("later"));
        // A second request with another label: enough.
        rec.insert_request(&request(ip.id, 1, "probe"))
            .await
            .unwrap();
        let r = source
            .check_grant(me, &grant(&uid, &ip.ip, 3))
            .await
            .unwrap();
        assert!(r.is_ok(), "backed grant runs");
        // Grants that contradict the job, or are not levels.
        for (g, want) in [
            (grant(&uid, &ip.ip, 4), "refused"),
            (grant(&uid, "203.0.113.71", 3), "refused"),
            (grant(&uid, &ip.ip, 9), "refused"),
            (grant(&uid, &ip.ip, 259), "refused"),
            (grant(&uid, "not-an-ip", 3), "failed"),
            (grant("unknown-job", &ip.ip, 3), "later"),
        ] {
            let r = source.check_grant(me, &g).await.unwrap();
            assert_eq!(turned(r), Some(want), "{g:?}");
        }
        // Granted by a node that does not arbitrate the job here.
        let other = crate::cluster::identity::Identity::generate().unwrap().id;
        let r = source
            .check_grant(other, &grant(&uid, &ip.ip, 3))
            .await
            .unwrap();
        assert_eq!(turned(r), Some("declined"));
    }

    /// A node whose rules put a harmless request at level 4 cannot make
    /// this scanner scan at 4: its rules see a probe.
    #[tokio::test]
    async fn grants_need_requests_our_rules_put_at_the_level() {
        let dir = tempfile::tempdir().unwrap();
        let (node, source, store) = cluster_source(dir.path(), "").await;
        let rec = Recorder::Cluster(node.clone());
        let ip = store
            .upsert_ip("203.0.113.74".parse().unwrap())
            .await
            .unwrap();
        for _ in 0..3 {
            let mut r = request(ip.id, 1, "rce");
            r.scan_level = 4;
            r.severity = 4;
            rec.insert_request(&r).await.unwrap();
        }
        let other = crate::cluster::identity::Identity::generate().unwrap().id;
        sqlx::query("UPDATE requests SET origin = ?")
            .bind(&other.0[..])
            .execute(&store.pool)
            .await
            .unwrap();
        rec.enqueue_scan(ip.id, 4, 24).await.unwrap();
        let uid = job_uid(&store, ip.id).await;
        let r = source
            .check_grant(node.id(), &grant(&uid, &ip.ip, 4))
            .await
            .unwrap();
        let (status, why) = r.err().unwrap();
        assert_eq!(status, "declined");
        assert!(why.unwrap().contains("highest: 1"));
    }

    /// A bought (manual) job needs no evidence: the scanner's own rules
    /// never enter into it; the safety preflight still applies.
    #[tokio::test]
    async fn a_manual_grant_runs_without_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let (node, source, store) = cluster_source(dir.path(), "").await;
        let rec = Recorder::Cluster(node.clone());
        let ip = store
            .upsert_ip("203.0.113.75".parse().unwrap())
            .await
            .unwrap();
        rec.enqueue_manual(ip.id, 4).await.unwrap();
        let uid = job_uid(&store, ip.id).await;
        let r = source
            .check_grant(node.id(), &grant(&uid, &ip.ip, 4))
            .await
            .unwrap();
        assert!(r.is_ok(), "a bought scan runs with no requests held");
    }

    /// A grant for an IP this scanner is scanning now, or for a job that
    /// loses the tie-break against another arbiter's job for the same IP,
    /// does not run (whatever the arbiter's version).
    #[tokio::test]
    async fn grants_for_an_ip_already_taken_do_not_run() {
        let dir = tempfile::tempdir().unwrap();
        let (node, source, store) = cluster_source(dir.path(), "").await;
        let me = node.id();
        let rec = Recorder::Cluster(node.clone());
        let ip = store
            .upsert_ip("203.0.113.73".parse().unwrap())
            .await
            .unwrap();
        for label in ["a", "b", "c"] {
            rec.insert_request(&request(ip.id, 2, label)).await.unwrap();
        }
        rec.enqueue_scan(ip.id, 2, 24).await.unwrap();
        let uid = job_uid(&store, ip.id).await;
        let turned = |r: Result<Job, Turndown>| r.err().map(|(s, _)| s);
        // Scanning it here already: at this level it is covered; at a lower
        // one the grant comes back later.
        let addr: IpAddr = ip.ip.parse().unwrap();
        for (active, want) in [(2, "superseded"), (1, "later")] {
            source.active.lock().unwrap().insert(addr, active);
            let r = source.check_grant(me, &grant(&uid, &ip.ip, 2)).await;
            assert_eq!(turned(r.unwrap()), Some(want));
        }
        source.active.lock().unwrap().clear();
        assert!(
            source
                .check_grant(me, &grant(&uid, &ip.ip, 2))
                .await
                .unwrap()
                .is_ok()
        );
        // Another arbiter queued the IP earlier: its job runs, not ours.
        let other = crate::cluster::identity::Identity::generate().unwrap().id;
        sqlx::query(
            "INSERT INTO scan_jobs (uid, origin, arbiter, hlc, ip_id, level, status, queued_at)
             VALUES ('other-job', ?1, ?1, 1, ?2, 2, 'queued', '2000-01-01 00:00:00')",
        )
        .bind(&other.0[..])
        .bind(ip.id)
        .execute(&store.pool)
        .await
        .unwrap();
        let r = source
            .check_grant(me, &grant(&uid, &ip.ip, 2))
            .await
            .unwrap();
        let (status, why) = r.err().unwrap();
        assert_eq!(status, "superseded");
        assert!(why.unwrap().contains("other-job"));
        // ... and the other way round, that job is the one that runs.
        assert_eq!(outranked_by(&store.pool, "other-job").await.unwrap(), None);
    }

    /// An outbound-only member has no published address; the address it
    /// connects from is protected all the same.
    #[tokio::test]
    async fn addresses_members_connect_from_are_never_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let (node, source, store) = cluster_source(dir.path(), "").await;
        let rec = Recorder::Cluster(node.clone());
        let ip = store
            .upsert_ip("203.0.113.99".parse().unwrap())
            .await
            .unwrap();
        for label in ["a", "b", "c"] {
            rec.insert_request(&request(ip.id, 2, label)).await.unwrap();
        }
        rec.enqueue_scan(ip.id, 2, 24).await.unwrap();
        let uid = job_uid(&store, ip.id).await;
        let member = crate::cluster::identity::Identity::generate().unwrap().id;
        node.status
            .note_peer_ip(member, "203.0.113.99".parse().unwrap());
        let r = source
            .check_grant(node.id(), &grant(&uid, &ip.ip, 2))
            .await
            .unwrap();
        let (status, why) = r.err().unwrap();
        assert_eq!(status, "refused");
        assert!(why.unwrap().contains("cluster member address"));
    }

    /// `trusted_origins = []`: only requests this node recorded back a scan.
    #[tokio::test]
    async fn trusted_origins_limit_whose_requests_count() {
        let dir = tempfile::tempdir().unwrap();
        let (node, source, store) = cluster_source(dir.path(), "trusted_origins = []\n").await;
        let me = node.id();
        let rec = Recorder::Cluster(node.clone());
        let ip = store
            .upsert_ip("203.0.113.72".parse().unwrap())
            .await
            .unwrap();
        for label in ["a", "b", "c"] {
            rec.insert_request(&request(ip.id, 2, label)).await.unwrap();
        }
        rec.enqueue_scan(ip.id, 2, 24).await.unwrap();
        let uid = job_uid(&store, ip.id).await;
        assert!(
            source
                .check_grant(me, &grant(&uid, &ip.ip, 2))
                .await
                .unwrap()
                .is_ok()
        );
        // The same requests, as if another node had recorded them.
        let other = crate::cluster::identity::Identity::generate().unwrap().id;
        sqlx::query("UPDATE requests SET origin = ?")
            .bind(&other.0[..])
            .execute(&store.pool)
            .await
            .unwrap();
        let r = source
            .check_grant(me, &grant(&uid, &ip.ip, 2))
            .await
            .unwrap();
        assert_eq!(r.err().map(|(s, _)| s), Some("declined"));
    }

    #[test]
    fn arbiters_that_can_pay_are_asked_first_in_urgency_order() {
        let (a, b, c, d) = (
            NodeId([1; 32]),
            NodeId([2; 32]),
            NodeId([3; 32]),
            NodeId([4; 32]),
        );
        // Urgency order a, b, c, d; b and d can pay.
        let order = can_pay_first(vec![a, b, c, d], |n| *n == b || *n == d);
        assert_eq!(order, vec![b, d, a, c]);
    }

    #[test]
    fn an_arbiter_can_pay_from_its_budget_and_balance_or_its_own_budget() {
        let other = Payer {
            own: false,
            sells_scans: true,
            announced: Some((3, 500)),
            balance: Some(800),
        };
        assert!(can_pay(Some(500), 0, &other));
        assert!(!can_pay(Some(501), 0, &other), "over its budget");
        assert!(!can_pay(None, 0, &other), "this node does not sell");
        // The budget it announces counts only up to its balance here.
        let poor = Payer {
            balance: Some(100),
            ..other
        };
        assert!(!can_pay(Some(200), 0, &poor));
        let cases = [
            Payer {
                announced: Some((0, 500)),
                ..other
            }, // nothing queued
            Payer {
                sells_scans: false,
                ..other
            },
            Payer {
                announced: None,
                ..other
            }, // no heartbeat yet
            Payer {
                balance: None,
                ..other
            }, // no book
        ];
        for p in &cases {
            assert!(!can_pay(Some(100), 0, p));
        }
        // This node's own jobs: its own scan budget left, nothing else.
        let own = Payer {
            own: true,
            sells_scans: false,
            announced: None,
            balance: None,
        };
        assert!(can_pay(Some(300), 300, &own));
        assert!(!can_pay(Some(300), 299, &own));
    }

    #[test]
    fn an_arbiter_can_pay_a_zero_price_from_nothing() {
        let other = Payer {
            own: false,
            sells_scans: true,
            announced: Some((1, 0)),
            balance: Some(0),
        };
        assert!(can_pay(Some(0), 0, &other));
        let idle = Payer {
            announced: Some((0, 0)),
            ..other
        };
        assert!(!can_pay(Some(0), 0, &idle), "nothing queued");
    }

    #[test]
    fn a_grant_at_an_excluded_level_is_over_the_share() {
        assert!(over_share(4, &[4]));
        assert!(!over_share(2, &[4]));
        assert!(!over_share(4, &[]));
    }

    #[tokio::test]
    async fn standalone_pick_skips_excluded_levels() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        for (ip, level) in [("203.0.113.70", 4), ("203.0.113.71", 2)] {
            let ip = store.upsert_ip(ip.parse().unwrap()).await.unwrap();
            store.enqueue_scan(ip.id, level, 24).await.unwrap();
        }
        let p = pace::SharedPace::new(pace::Pace::from_config(&cfg.scan));
        let source = Source::new(store.local(), cfg, p, Classifier::builtin());
        let job = source.acquire(&[4]).await.unwrap().unwrap();
        assert_eq!(job.level(), 2);
        assert!(source.acquire(&[4]).await.unwrap().is_none());
        assert_eq!(source.acquire(&[]).await.unwrap().unwrap().level(), 4);
    }

    /// A fake nmap that records how many level-4 scans (argv has -p-) run
    /// at once, holding each for `secs`.
    fn counting_nmap(dir: &std::path::Path, secs: &str) -> PathBuf {
        let fake = fake_nmap(dir); // writes nmap.xml next to it
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\nd=\"$(dirname \"$0\")\"\n\
                 case \" $* \" in *\" -p- \"*) mkdir -p \"$d/l4\"; touch \"$d/l4/$$\"; \
                 ls \"$d/l4\" | wc -l >> \"$d/l4-seen\"; sleep {secs}; rm \"$d/l4/$$\";; esac\n\
                 cat \"$d/nmap.xml\"\n"
            ),
        )
        .unwrap();
        fake
    }

    /// With 2 workers at most one level-4 scan runs, the other worker keeps
    /// the shorter levels moving, and a queue of only level-4 jobs still
    /// drains.
    #[tokio::test]
    async fn level4_never_takes_more_than_its_share() {
        let dir = tempfile::tempdir().unwrap();
        let fake = counting_nmap(dir.path(), "1.5");
        let cfg = test_config(dir.path());
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        for (i, level) in [4, 4, 2, 2].into_iter().enumerate() {
            let ip = store
                .upsert_ip(format!("198.51.100.{}", 80 + i).parse().unwrap())
                .await
                .unwrap();
            store.enqueue_scan(ip.id, level, 24).await.unwrap();
        }
        let (tx, rx) = tokio::sync::watch::channel(false);
        let p = pace::SharedPace::new(pace::Pace {
            max_workers: 2,
            timeout_secs: 60,
        });
        let pool = tokio::spawn(run_workers(
            store.local(),
            cfg,
            p,
            fake,
            rx,
            crate::events::Notifier::new(),
            Classifier::builtin(),
        ));
        wait_for_scans(&store, 4).await;
        tx.send(true).unwrap();
        pool.await.unwrap();
        let seen = std::fs::read_to_string(dir.path().join("l4-seen")).unwrap();
        let max: u32 = seen
            .split_whitespace()
            .map(|n| n.parse::<u32>().unwrap())
            .max()
            .unwrap();
        assert_eq!(max, 1, "two level-4 scans ran at once: {seen:?}");
    }
}
