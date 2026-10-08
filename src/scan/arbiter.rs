//! The scan-job arbiter (distributed mode). Every node arbitrates the
//! jobs it enqueued (or adopted): scanners anywhere in the cluster ask it
//! for work, it hands each job to exactly one of them under a lease that
//! the scanner renews while nmap runs, and it alone records the job's state.
//!
//! Fairness: claims are collected for a short window and the jobs go to
//! the claimants that ran the fewest scans in the last hour, so equally
//! paced scanners share the queue equally wherever the job came from.
//! A scanner that fails a level more than the others is weighted down at
//! that level (see `weight`). Among an arbiter's jobs, the highest
//! response ratio goes first (see `order`).
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::msg::{Grant, Msg};
use crate::cluster::record::{JobStatusRec, Record};
use crate::store::data::now_ts;
use crate::store::recorder::Recorder;
use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{info, warn};

/// How long claims are collected before jobs are handed out.
pub const CLAIM_WINDOW: Duration = Duration::from_secs(2);

/// How long a job handed back "later" (not replicated there yet, thin
/// evidence, Tor status unknown) is not offered to that scanner again.
const LATER_BACKOFF: Duration = Duration::from_secs(180);

struct Lease {
    scanner: NodeId,
    expires: Instant,
    /// Whether this arbiter funded the grant (an offer or a self tally):
    /// only then does a turn-down count against the scanner.
    funded: bool,
}

/// A claimant that delivered less than this share of at least
/// [`DELIVERY_MIN_GRANTS`] grants of this arbiter in the past 24 hours
/// goes after all others.
const DELIVERY_MIN: f64 = 0.5;
const DELIVERY_MIN_GRANTS: usize = 5;
const DELIVERY_WINDOW: Duration = Duration::from_secs(24 * 3600);

/// Whether a scanner's recent grants of this arbiter came back delivered
/// often enough (`(when, delivered)` outcomes).
fn delivers(outcomes: &VecDeque<(Instant, bool)>, now: Instant) -> bool {
    let recent: Vec<bool> = outcomes
        .iter()
        .filter(|(t, _)| now.saturating_duration_since(*t) < DELIVERY_WINDOW)
        .map(|(_, ok)| *ok)
        .collect();
    if recent.len() < DELIVERY_MIN_GRANTS {
        return true;
    }
    recent.iter().filter(|ok| **ok).count() as f64 >= DELIVERY_MIN * recent.len() as f64
}

/// Whether a scanner already got what it can do in an hour from this
/// arbiter. Unknown capacity never gates.
fn over_capacity(granted_last_hour: i64, can_do: Option<f64>) -> bool {
    can_do.is_some_and(|c| granted_last_hour as f64 >= c.max(1.0))
}

/// Sort key of a claimant: not demoted first, then the price this
/// arbiter would pay (unpaid after every price), fewest recent scans
/// cluster-wide, key. Demoted claimants go by load alone.
fn claim_order(
    price: Option<u32>,
    demoted: bool,
    load: i64,
    id: NodeId,
) -> (bool, u32, i64, NodeId) {
    let price = if demoted {
        0
    } else {
        price.unwrap_or(u32::MAX)
    };
    (demoted, price, load, id)
}

/// Whether a funded grant handed back with `status` and `why` counts as
/// not delivered: every turn-down, except "later" for a reason that is no
/// fault of the scanner (the job has not replicated there yet, or its
/// Tor exit list is not loaded).
fn undelivered(status: &str, why: Option<&str>) -> bool {
    match status {
        "later" => !matches!(why, Some(super::NOT_REPLICATED | super::TOR_UNKNOWN)),
        _ => status == "declined",
    }
}

type Waiter = (NodeId, Vec<u8>, u32, oneshot::Sender<Option<Grant>>);

pub struct Arbiter {
    node: Arc<Node>,
    rec: Recorder,
    lease: Duration,
    leases: Mutex<HashMap<String, Lease>>,
    waiting: Mutex<Vec<Waiter>>,
    /// Estimated job durations for the response-ratio order.
    order: super::order::Cached,
    /// Scanners that handed a job back because their own never_scan covers it.
    declined: Mutex<HashMap<String, std::collections::HashSet<NodeId>>>,
    /// Scanners that handed a job back for now, until when they are skipped.
    later: Mutex<HashMap<String, HashMap<NodeId, Instant>>>,
    /// How recent grants to each scanner ended, for [`delivers`].
    outcomes: Mutex<HashMap<NodeId, VecDeque<(Instant, bool)>>>,
    /// Serializes hand-outs and state writes.
    assign: tokio::sync::Mutex<()>,
}

/// `(status, attempts, started_at, scanner)` of a job we arbitrate.
type JobRow = (String, i64, Option<String>, Option<Vec<u8>>);

impl Arbiter {
    /// Start arbitrating this node's jobs and answer scanners' messages.
    pub async fn start(
        node: Arc<Node>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Arc<Self>> {
        let a = Arc::new(Self {
            rec: Recorder::Cluster(node.clone()),
            lease: Duration::from_secs(node.cfg.lease_secs),
            node: node.clone(),
            leases: Mutex::new(HashMap::new()),
            outcomes: Mutex::new(HashMap::new()),
            waiting: Mutex::new(vec![]),
            order: super::order::Cached::new(),
            declined: Mutex::new(HashMap::new()),
            later: Mutex::new(HashMap::new()),
            assign: tokio::sync::Mutex::new(()),
        });
        a.recover().await?;
        let h = a.clone();
        node.on_message(Arc::new(move |from, msg| {
            let a = h.clone();
            Box::pin(async move { a.handle(from, msg).await })
        }));
        let sweeper = a.clone();
        let tick = (a.lease / 4).clamp(Duration::from_millis(250), Duration::from_secs(5));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(tick) => {}
                    _ = shutdown.changed() => break,
                }
                if let Err(e) = sweeper.sweep().await {
                    warn!(?e, "lease sweep failed");
                }
            }
        });
        Ok(a)
    }

    /// After a restart: jobs we scanned ourselves died with the process and
    /// go back to the queue; jobs remote scanners run get one lease period
    /// to renew.
    async fn recover(&self) -> Result<()> {
        let me = self.node.id();
        let rows: Vec<(String, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT uid, scanner FROM scan_jobs WHERE status = 'running' AND arbiter = ?",
        )
        .bind(&me.0[..])
        .fetch_all(&self.node.store.pool)
        .await?;
        let mut requeue = vec![];
        for (uid, scanner) in rows {
            match scanner.and_then(|s| NodeId::from_slice(&s).ok()) {
                Some(s) if s != me => {
                    self.leases.lock().unwrap().insert(
                        uid,
                        Lease {
                            scanner: s,
                            expires: Instant::now() + self.lease,
                            funded: false,
                        },
                    );
                }
                _ => requeue.push(uid),
            }
        }
        for uid in requeue {
            self.set_state(&uid, "queued", None, None).await?;
        }
        Ok(())
    }

    async fn handle(self: Arc<Self>, from: NodeId, msg: Msg) -> Option<Msg> {
        match msg {
            Msg::Claim {
                exclude_levels,
                min_mc,
            } => Some(Msg::ClaimReply {
                grant: self.claim(from, exclude_levels, min_mc).await,
            }),
            Msg::Renew { job_uid } => Some(Msg::RenewReply {
                ok: self.renew(from, &job_uid),
            }),
            Msg::Complete {
                job_uid,
                status,
                error,
            } => Some(Msg::CompleteReply {
                ok: self.complete(from, &job_uid, &status, error).await,
            }),
            _ => None,
        }
    }

    /// Wait for the claim window, then get a job or nothing.
    async fn claim(
        self: &Arc<Self>,
        scanner: NodeId,
        exclude: Vec<u8>,
        min_mc: u32,
    ) -> Option<Grant> {
        let (tx, rx) = oneshot::channel();
        let first = {
            let mut w = self.waiting.lock().unwrap();
            w.push((scanner, exclude, min_mc, tx));
            w.len() == 1
        };
        if first {
            let a = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(CLAIM_WINDOW).await;
                if let Err(e) = a.hand_out().await {
                    warn!(?e, "handing out scan jobs failed");
                }
            });
        }
        rx.await.ok().flatten()
    }

    /// `scanner`'s scans started in the last hour: `(of any arbiter, of
    /// this one)`. The first breaks ties between equal prices, so load
    /// spreads across the cluster; the second is what the capacity gate
    /// counts.
    async fn scans_last_hour(&self, scanner: &NodeId) -> (i64, i64) {
        sqlx::query_as(
            // Like the scanners' own rate count: a grant turned down ran nothing.
            "SELECT COUNT(*), COALESCE(SUM(arbiter = ?), 0) FROM scan_jobs
             WHERE scanner = ? AND started_at > datetime('now','-1 hour')
               AND status NOT IN ('refused','superseded')",
        )
        .bind(&self.node.id().0[..])
        .bind(&scanner.0[..])
        .fetch_one(&self.node.store.pool)
        .await
        .unwrap_or((0, 0))
    }

    /// Remember how a grant to `scanner` ended, for [`delivers`].
    fn note_outcome(&self, scanner: NodeId, delivered: bool) {
        let now = Instant::now();
        let mut o = self.outcomes.lock().unwrap();
        let q = o.entry(scanner).or_default();
        q.push_back((now, delivered));
        while q
            .front()
            .is_some_and(|(t, _)| now.saturating_duration_since(*t) >= DELIVERY_WINDOW)
        {
            q.pop_front();
        }
    }

    async fn hand_out(&self) -> Result<()> {
        let _g = self.assign.lock().await;
        let waiters = std::mem::take(&mut *self.waiting.lock().unwrap());
        let mut load = HashMap::new();
        for (s, _, _, _) in &waiters {
            if !load.contains_key(s) {
                load.insert(*s, self.scans_last_hour(s).await);
            }
        }
        // Cheapest first, hoarding and non-delivering scanners last, then
        // fewest recent scans; ties broken by key so it is stable.
        let table = self.node.price_table();
        let now = Instant::now();
        let mut keyed = vec![];
        for w in waiters {
            let s = w.0;
            let price = crate::credits::jobs::price_for(&self.node, &s);
            let (all, here) = load[&s];
            let demoted = over_capacity(here, table.can_do(&s))
                || !self
                    .outcomes
                    .lock()
                    .unwrap()
                    .get(&s)
                    .is_none_or(|o| delivers(o, now));
            keyed.push((claim_order(price, demoted, all, s), w));
        }
        keyed.sort_by_key(|k| k.0);
        let waiters: Vec<Waiter> = keyed.into_iter().map(|(_, w)| w).collect();
        // One book for the round; what each funded grant commits is
        // carried to the next, so the budget is never overspent.
        let mut funding = crate::credits::jobs::Funding::default();
        for (scanner, exclude, min_mc, tx) in waiters {
            let grant = self
                .next_job_for(&mut funding, scanner, &exclude, min_mc)
                .await?;
            if let Some(g) = &grant {
                let l = load.get_mut(&scanner).unwrap();
                l.0 += 1;
                l.1 += 1;
                info!(job = %g.job_uid, ip = %g.ip, scanner = %scanner.short(), "scan job granted");
            }
            let _ = tx.send(grant);
        }
        Ok(())
    }

    /// [`Self::next_job`], funded with an offer to `scanner` when this
    /// node's scan budget and `min_mc` allow (`credits::jobs::fund`).
    async fn next_job_for(
        &self,
        funding: &mut crate::credits::jobs::Funding,
        scanner: NodeId,
        exclude: &[u8],
        min_mc: u32,
    ) -> Result<Option<Grant>> {
        let Some(mut g) = self.next_job(scanner, exclude).await? else {
            return Ok(None);
        };
        let price = crate::credits::jobs::price_for(&self.node, &scanner);
        if let Some((seq, price)) = crate::credits::jobs::fund(
            &self.node,
            funding,
            scanner,
            &g.job_uid,
            min_mc,
            price.unwrap_or(0),
        )
        .await
        {
            g.offer_seq = seq;
            g.price_mc = price;
            if let Some(l) = self.leases.lock().unwrap().get_mut(&g.job_uid) {
                l.funded = g.offer_seq.is_some() || g.price_mc > 0;
            }
            info!(job = %g.job_uid, scanner = %scanner.short(),
                price = %crate::credits::show(price as u64), "scan job funded");
        }
        Ok(Some(g))
    }

    /// Take our next queued job for `scanner` and mark it running.
    async fn next_job(&self, scanner: NodeId, exclude: &[u8]) -> Result<Option<Grant>> {
        // Not a job this scanner already handed back (for now or for good).
        let declined: Vec<String> = {
            let d = self.declined.lock().unwrap();
            let l = self.later.lock().unwrap();
            let now = Instant::now();
            d.iter()
                .filter(|(_, by)| by.contains(&scanner))
                .map(|(uid, _)| uid.clone())
                .chain(
                    l.iter()
                        .filter(|(_, by)| by.get(&scanner).is_some_and(|t| *t > now))
                        .map(|(uid, _)| uid.clone()),
                )
                .collect()
        };
        let skipped = self.skipped_levels(scanner).await?;
        self.next_job_skipping(scanner, declined, &skipped, exclude)
            .await
    }

    /// Levels `scanner` fails more than the other live scanners and sits
    /// out for now (see `weight`). None when it is the only scanner.
    async fn skipped_levels(&self, scanner: NodeId) -> Result<Vec<i64>> {
        let scanners = self.scanners();
        if scanners.len() < 2 {
            return Ok(vec![]);
        }
        let t = super::weight::tallies(&self.node.store.pool).await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(super::weight::skipped_levels(&t, scanner, &scanners, now))
    }

    /// [`Self::next_job`] past the jobs `scanner` handed back, the jobs of
    /// the levels it sits out (unless they have waited
    /// [`super::weight::OVERRIDE_WAIT_MINS`]) or excludes (always). Highest
    /// response ratio first (`order`).
    async fn next_job_skipping(
        &self,
        scanner: NodeId,
        declined: Vec<String>,
        skipped: &[i64],
        exclude: &[u8],
    ) -> Result<Option<Grant>> {
        let me = self.node.id();
        let est = self.order.get(&self.node.store.pool).await;
        let (uid, ip, level, attempts) = loop {
            let row: Option<(String, String, i64, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT j.uid, i.ip, j.level, j.attempts FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
                 WHERE j.status = 'queued' AND j.arbiter = ?
                   AND j.uid NOT IN (SELECT value FROM json_each(?))
                   AND (j.level NOT IN (SELECT value FROM json_each(?))
                        OR j.queued_at < datetime('now', '-{} minutes'))
                   AND j.level NOT IN (SELECT value FROM json_each(?))
                   AND (j.retry_at IS NULL
                        OR (j.retry_at <= datetime('now')
                            AND (j.failed_by IS NULL OR j.failed_by != ?
                                 OR j.retry_at <= datetime('now', '-{} minutes'))))
                 ORDER BY {} LIMIT 1",
                super::weight::OVERRIDE_WAIT_MINS,
                super::retry::LAST_FAILER_WAIT,
                est.order_by("j", "j.uid"),
            )))
            .bind(&me.0[..])
            .bind(serde_json::to_string(&declined)?)
            .bind(serde_json::to_string(skipped)?)
            .bind(serde_json::to_string(exclude)?)
            .bind(&scanner.0[..])
            .fetch_optional(&self.node.store.pool)
            .await?;
            let Some(row) = row else {
                return Ok(None);
            };
            // Another arbiter queued the same IP and its job ranks first, or
            // a scan of it is running: the scanners would turn this one down.
            let Some(other) = super::outranked_by(&self.node.store.pool, &row.0).await? else {
                break row;
            };
            info!(job = %row.0, ip = %row.1, by = %other, "scan job superseded by another job for the same IP");
            let why = format!("job {other} for this IP ranks first");
            self.set_state(&row.0, "superseded", Some(why), Some(now_ts()))
                .await?;
        };
        self.rec
            .write(vec![Record::JobStatus(JobStatusRec {
                job_uid: uid.clone(),
                status: "running".into(),
                started_at: Some(now_ts()),
                finished_at: None,
                error: None,
                attempts: attempts + 1,
                scanner: Some(scanner),
            })])
            .await?;
        self.leases.lock().unwrap().insert(
            uid.clone(),
            Lease {
                scanner,
                expires: Instant::now() + self.lease,
                funded: false,
            },
        );
        Ok(Some(Grant {
            job_uid: uid,
            ip,
            level,
            lease_secs: self.lease.as_secs().max(1),
            offer_seq: None,
            price_mc: 0,
        }))
    }

    fn renew(&self, scanner: NodeId, job_uid: &str) -> bool {
        let mut leases = self.leases.lock().unwrap();
        match leases.get_mut(job_uid) {
            Some(l) if l.scanner == scanner => {
                l.expires = Instant::now() + self.lease;
                true
            }
            _ => false,
        }
    }

    async fn job(&self, uid: &str) -> Result<Option<JobRow>> {
        Ok(sqlx::query_as(
            "SELECT status, attempts, started_at, scanner FROM scan_jobs
             WHERE uid = ? AND arbiter = ?",
        )
        .bind(uid)
        .bind(&self.node.id().0[..])
        .fetch_optional(&self.node.store.pool)
        .await?)
    }

    /// Record a job's new state, keeping its start time, attempts and scanner.
    async fn set_state(
        &self,
        uid: &str,
        status: &str,
        error: Option<String>,
        finished: Option<String>,
    ) -> Result<()> {
        let Some((_, attempts, started_at, scanner)) = self.job(uid).await? else {
            return Ok(());
        };
        let queued = status == "queued";
        self.rec
            .write(vec![Record::JobStatus(JobStatusRec {
                job_uid: uid.to_string(),
                status: status.into(),
                started_at: if queued { None } else { started_at },
                finished_at: finished,
                error,
                attempts,
                scanner: if queued {
                    None
                } else {
                    scanner.and_then(|s| NodeId::from_slice(&s).ok())
                },
            })])
            .await
    }

    async fn complete(
        &self,
        scanner: NodeId,
        uid: &str,
        status: &str,
        error: Option<String>,
    ) -> bool {
        if ![
            "done",
            "failed",
            "superseded",
            "refused",
            "declined",
            "later",
        ]
        .contains(&status)
        {
            return false;
        }
        let _g = self.assign.lock().await;
        let (holder, funded) = {
            let leases = self.leases.lock().unwrap();
            let l = leases.get(uid);
            (l.map(|l| l.scanner), l.is_some_and(|l| l.funded))
        };
        // After an arbiter restart the lease may be gone; the replicated
        // scanner column still says who ran it.
        let ok = match holder {
            Some(h) => h == scanner,
            None => matches!(self.job(uid).await, Ok(Some((st, _, _, Some(s))))
                if st == "running" && s == scanner.0.to_vec()),
        };
        if !ok {
            return false;
        }
        self.leases.lock().unwrap().remove(uid);
        match status {
            "done" => self.note_outcome(scanner, true),
            "failed" => self.note_outcome(scanner, false),
            "later" | "declined" if funded && undelivered(status, error.as_deref()) => {
                self.note_outcome(scanner, false)
            }
            _ => {}
        }
        if status == "declined" {
            return self.decline(scanner, uid, error).await;
        }
        if status == "later" {
            return self.later(scanner, uid).await;
        }
        self.declined.lock().unwrap().remove(uid);
        self.later.lock().unwrap().remove(uid);
        if let Err(e) = self.set_state(uid, status, error, Some(now_ts())).await {
            warn!(?e, job = %uid, "recording job outcome failed");
            return false;
        }
        if status == "failed" {
            match self.rec.retry_failed(uid, Some(scanner)).await {
                Ok(Some(retry)) => info!(job = %uid, %retry, "failed scan queued for a retry"),
                Ok(None) => {}
                Err(e) => warn!(?e, job = %uid, "queueing a retry failed"),
            }
        }
        true
    }

    fn scanners(&self) -> Vec<NodeId> {
        scanners(&self.node)
    }

    /// Whether every scanner that could take `uid` has declined it.
    fn all_declined(&self, uid: &str) -> bool {
        let d = self.declined.lock().unwrap();
        d.get(uid)
            .is_some_and(|by| self.scanners().iter().all(|s| by.contains(s)))
    }

    /// Declined jobs wait for another scanner. When the scanners that have
    /// not declined a job are gone, nobody is left to take it: refuse it.
    /// Entries of jobs that are no longer queued here are dropped, and so
    /// are "later" turndowns once they have expired.
    async fn recheck_declined(&self) -> Result<()> {
        {
            let now = Instant::now();
            let mut l = self.later.lock().unwrap();
            l.retain(|_, by| {
                by.retain(|_, until| *until > now);
                !by.is_empty()
            });
        }
        let uids: Vec<String> = self.declined.lock().unwrap().keys().cloned().collect();
        for uid in uids {
            let queued = matches!(self.job(&uid).await?, Some((st, ..)) if st == "queued");
            if !queued {
                self.declined.lock().unwrap().remove(&uid);
            } else if self.all_declined(&uid) {
                self.declined.lock().unwrap().remove(&uid);
                self.set_state(
                    &uid,
                    "refused",
                    Some("declined by every scanner (never_scan)".into()),
                    Some(now_ts()),
                )
                .await?;
            }
        }
        Ok(())
    }

    /// A scanner handed the job back. It returns to the queue for the other
    /// scanners; once every scanner has declined, it is refused for good.
    async fn decline(&self, scanner: NodeId, uid: &str, why: Option<String>) -> bool {
        self.declined
            .lock()
            .unwrap()
            .entry(uid.to_string())
            .or_default()
            .insert(scanner);
        let everyone = self.all_declined(uid);
        if everyone {
            self.declined.lock().unwrap().remove(uid);
        }
        let r = if everyone {
            let why = format!(
                "declined by every scanner ({})",
                why.unwrap_or_else(|| "never_scan".into())
            );
            self.set_state(uid, "refused", Some(why), Some(now_ts()))
                .await
        } else {
            self.set_state(uid, "queued", None, None).await
        };
        if let Err(e) = r {
            warn!(?e, job = %uid, "recording a declined job failed");
            return false;
        }
        true
    }

    /// A scanner handed the job back for now: it returns to the queue and
    /// this scanner is skipped for it for a while. Never refuses the job.
    async fn later(&self, scanner: NodeId, uid: &str) -> bool {
        self.later
            .lock()
            .unwrap()
            .entry(uid.to_string())
            .or_default()
            .insert(scanner, Instant::now() + LATER_BACKOFF);
        if let Err(e) = self.set_state(uid, "queued", None, None).await {
            warn!(?e, job = %uid, "recording a job handed back for now failed");
            return false;
        }
        true
    }

    /// Expired leases: done if the scanner's result already arrived,
    /// otherwise back to the queue.
    async fn sweep(&self) -> Result<()> {
        let expired: Vec<(String, NodeId)> = {
            let mut leases = self.leases.lock().unwrap();
            let now = Instant::now();
            let gone: Vec<_> = leases
                .iter()
                .filter(|(_, l)| l.expires <= now)
                .map(|(u, l)| (u.clone(), l.scanner))
                .collect();
            for (u, _) in &gone {
                leases.remove(u);
            }
            gone
        };
        self.recheck_declined().await?;
        if expired.is_empty() {
            return Ok(());
        }
        let _g = self.assign.lock().await;
        for (uid, scanner) in expired {
            let has_result: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM scans WHERE job_uid = ? AND audit_of IS NULL",
            )
            .bind(&uid)
            .fetch_one(&self.node.store.pool)
            .await?;
            self.note_outcome(scanner, has_result > 0);
            if has_result > 0 {
                self.set_state(&uid, "done", None, Some(now_ts())).await?;
            } else {
                warn!(job = %uid, scanner = %scanner.short(), "scan lease expired; job requeued");
                self.set_state(&uid, "queued", None, None).await?;
            }
        }
        Ok(())
    }
}

/// A scanner silent for longer than this no longer counts as someone who
/// could still take a declined job.
const SCANNER_PRESENT: Duration = Duration::from_secs(300);

/// Scanners that could still take a job: members with the scanner role
/// that this node does not block and has heard from recently (or has not
/// had the chance to hear from yet), this node included.
pub fn scanners(node: &Node) -> Vec<NodeId> {
    let me = node.id();
    let mut v: Vec<NodeId> = node
        .members()
        .values()
        .filter(|m| m.roles.iter().any(|r| r == "scanner"))
        .map(|m| m.id)
        .filter(|id| *id == me || (!node.is_blocked(id) && node.silent_for(id) < SCANNER_PRESENT))
        .collect();
    if node.roles().scanner && !v.contains(&me) {
        v.push(me);
    }
    v
}

/// Heartbeats this recent count a scanner as alive for takeover decisions.
pub(crate) const LIVE_WINDOW: Duration = Duration::from_secs(45);

/// Adopt queued jobs of arbiters silent for `cluster.takeover_hours`.
/// Only the lowest-keyed live scanner adopts, so takeovers rarely collide.
/// Every other node applies an adoption only once it, too, sees the arbiter
/// silent (or the job unchanged) for that long (see `cluster::repl`).
pub async fn takeover_loop(node: Arc<Node>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let window = Duration::from_secs_f64(node.cfg.takeover_hours * 3600.0);
    let tick = (window / 4).clamp(Duration::from_millis(250), Duration::from_secs(60));
    let rec = Recorder::Cluster(node.clone());
    loop {
        tokio::select! {
            _ = tokio::time::sleep(tick) => {}
            _ = shutdown.changed() => break,
        }
        if let Err(e) = takeover_once(&node, &rec, window).await {
            warn!(?e, "job takeover check failed");
        }
    }
}

/// One takeover pass. Jobs move to this node when their arbiter
/// - is blocked here (scanners here skip it, so its jobs would be stranded;
///   any scanner node that blocked it adopts, whatever its rank),
/// - has been silent for `window` (lowest live scanner only), or
/// - keeps running but has not touched a job for `window` while this
///   node's scanner has idle workers (lowest live scanner only): an
///   arbiter that never hands its jobs out.
async fn takeover_once(node: &Arc<Node>, rec: &Recorder, window: Duration) -> Result<()> {
    let me = node.id();
    if !node.roles().scanner {
        return Ok(());
    }
    let members = node.members();
    let scanner = |id: &NodeId| {
        node.status
            .known(id)
            .map(|k| k.hb.roles.iter().any(|r| r == "scanner"))
            .or_else(|| {
                members
                    .get(id)
                    .map(|m| m.roles.iter().any(|r| r == "scanner"))
            })
            .unwrap_or(false)
    };
    let lowest = node
        .live_members(LIVE_WINDOW)
        .into_iter()
        .filter(|id| !node.is_blocked(id) && (*id == me || scanner(id)))
        .min()
        == Some(me);
    let idle = {
        let local = node.status.local.lock().unwrap();
        local
            .pace
            .is_some_and(|p| local.active_scans < p.max_workers)
    };
    let arbiters: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT DISTINCT arbiter FROM scan_jobs
         WHERE status IN ('queued','running') AND arbiter IS NOT NULL AND arbiter != ?",
    )
    .bind(&me.0[..])
    .fetch_all(&node.store.pool)
    .await?;
    // Jobs unchanged since this HLC are stale.
    let stale_before = crate::cluster::hlc::to_db(
        crate::cluster::hlc::wall_ms().saturating_sub(window.as_millis() as u64) << 16,
    );
    for a in arbiters {
        let Ok(from) = NodeId::from_slice(&a) else {
            continue;
        };
        let gone = node.is_blocked(&from) || (lowest && node.silent_for(&from) >= window);
        // Include 'running' jobs: after takeover_hours any lease is long
        // expired, so a job still marked running is stale and would
        // otherwise block its IP cluster-wide forever.
        let uids: Vec<String> = if gone {
            sqlx::query_scalar(
                "SELECT uid FROM scan_jobs WHERE status IN ('queued','running') AND arbiter = ?
                 LIMIT 500",
            )
            .bind(&a)
            .fetch_all(&node.store.pool)
            .await?
        } else if lowest && idle {
            // A running job of a live arbiter may be a long level-4 scan
            // whose lease is renewed without touching the job row: take it
            // only once no scan can still be running.
            sqlx::query_scalar(
                "SELECT uid FROM scan_jobs WHERE arbiter = ?
                   AND MAX(COALESCE(hlc, 0), status_hlc) < ?
                   AND (status = 'queued' OR (status = 'running'
                        AND (started_at IS NULL OR started_at < datetime('now', ?))))
                 LIMIT 500",
            )
            .bind(&a)
            .bind(stale_before)
            .bind(format!("-{} hours", crate::scan::pace::STALE_RUNNING_HOURS))
            .fetch_all(&node.store.pool)
            .await?
        } else {
            continue;
        };
        if uids.is_empty() {
            continue;
        }
        info!(from = %from.short(), jobs = uids.len(), "adopting scans of an unreachable, blocked or stalling node");
        rec.write(vec![Record::JobAdopt(
            crate::cluster::record::JobAdoptRec {
                from,
                job_uids: uids,
            },
        )])
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;

    #[test]
    fn a_scanner_delivers_unless_it_failed_half_of_five_recent_grants() {
        let now = Instant::now();
        let mut o = VecDeque::new();
        for ok in [false, false, false, false] {
            o.push_back((now, ok));
        }
        assert!(delivers(&o, now), "fewer than 5 grants: no judgement");
        o.push_back((now, true));
        assert!(!delivers(&o, now), "1 of 5 delivered");
        for _ in 0..4 {
            o.push_back((now, true));
        }
        assert!(delivers(&o, now), "5 of 9 delivered");
        let old = VecDeque::from(vec![(now - Duration::from_secs(25 * 3600), false); 9]);
        assert!(delivers(&old, now), "only the past 24 hours count");
    }

    #[test]
    fn capacity_gate_needs_a_known_capacity() {
        assert!(!over_capacity(100, None), "unknown capacity never gates");
        assert!(!over_capacity(9, Some(10.0)));
        assert!(over_capacity(10, Some(10.0)));
    }

    #[test]
    fn claimants_go_cheapest_first_and_demoted_ones_last() {
        let (a, b, c, d) = (
            NodeId([1; 32]),
            NodeId([2; 32]),
            NodeId([3; 32]),
            NodeId([4; 32]),
        );
        let e = NodeId([5; 32]);
        let mut v = vec![
            claim_order(Some(50), false, 0, a),
            claim_order(Some(20), false, 9, b),
            claim_order(Some(5), true, 3, c), // cheapest but hoarding
            claim_order(None, false, 0, d),   // no price: after the priced ones
            claim_order(Some(90), true, 1, e), // demoted: by load, not price
        ];
        v.sort();
        let order: Vec<NodeId> = v.into_iter().map(|k| k.3).collect();
        assert_eq!(order, vec![b, a, d, e, c]);
    }

    #[test]
    fn hand_backs_for_reasons_outside_the_scanner_are_not_undelivered() {
        assert!(!undelivered("later", Some(super::super::NOT_REPLICATED)));
        assert!(!undelivered("later", Some(super::super::TOR_UNKNOWN)));
        assert!(undelivered("later", Some("level 2 needs more evidence")));
        assert!(undelivered("later", None));
        assert!(undelivered("declined", Some(super::super::NOT_REPLICATED)));
    }

    type Setup = (
        Arc<Node>,
        Arc<Arbiter>,
        crate::store::Store,
        tokio::sync::watch::Sender<bool>,
    );

    /// A bootstrapped node (a scanner too) with its arbiter running.
    async fn setup(dir: &std::path::Path) -> Setup {
        let store = crate::store::Store::connect(&dir.join("t.db"))
            .await
            .unwrap();
        let node = Node::open(crate::cluster::NodeParams {
            identity: Identity::generate().unwrap(),
            cluster: crate::config::ClusterConfig {
                node_name: "n".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: None,
                key_path: None,
                takeover_hours: 6.0,
                lease_secs: 120,
                remote_config: false,
                origin_quota_mb: 20 * 1024,
                peers: vec![],
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
        let (tx, rx) = tokio::sync::watch::channel(false);
        let arbiter = Arbiter::start(node.clone(), rx).await.unwrap();
        (node, arbiter, store, tx)
    }

    #[tokio::test]
    async fn no_budget_grants_without_an_offer() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        node.set_scan_share(1.0);
        let rec = Recorder::Cluster(node.clone());
        let ip = store
            .upsert_ip("203.0.113.94".parse().unwrap())
            .await
            .unwrap();
        rec.enqueue_scan(ip.id, 2, 24).await.unwrap();
        let scanner = Identity::generate().unwrap().id;
        let g = arbiter
            .next_job_for(&mut Default::default(), scanner, &[], 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((g.offer_seq, g.price_mc), (None, 0));
    }

    /// Credits for `node`: the whole mint of a day two days back.
    async fn give_credits(store: &crate::store::Store, node: NodeId) {
        use crate::credits::DAY_MS;
        let day = crate::cluster::hlc::wall_ms() / DAY_MS - 2;
        sqlx::query(
            "INSERT INTO credit_scans
               (scan_uid, job_uid, ip, scanner, trap, hlc, level, job_level, args_ok, judged_at)
             VALUES ('given', 'given-job', '100.64.0.1', ?, ?, ?, 1, 1, 1, datetime('now'))",
        )
        .bind(&node.0[..])
        .bind(&[0xEE; 32][..])
        .bind(((day * DAY_MS + 3_600_000) << 16) as i64)
        .execute(&store.pool)
        .await
        .unwrap();
    }

    /// This node as a scanner selling at `sell_mc`.
    fn selling(node: &Node, sell_mc: u32) {
        node.set_price_table(Arc::new(crate::credits::price::Table {
            sell_mc: Some(sell_mc),
            ..Default::default()
        }));
    }

    async fn self_mc(store: &crate::store::Store, uid: &str) -> Option<i64> {
        sqlx::query_scalar("SELECT self_mc FROM scan_jobs WHERE uid = ?")
            .bind(uid)
            .fetch_one(&store.pool)
            .await
            .unwrap()
    }

    /// An own job granted to the own scanner writes no offer: it holds
    /// the price against the scan budget as `self_mc`.
    #[tokio::test]
    async fn an_own_job_is_funded_by_a_reservation_not_an_offer() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        give_credits(&store, node.id()).await;
        node.set_scan_share(0.5);
        selling(&node, 300);
        let ip = store
            .upsert_ip("203.0.113.95".parse().unwrap())
            .await
            .unwrap();
        Recorder::Cluster(node.clone())
            .enqueue_scan(ip.id, 2, 24)
            .await
            .unwrap();
        let g = arbiter
            .next_job_for(&mut Default::default(), node.id(), &[], 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((g.offer_seq, g.price_mc), (None, 300));
        assert_eq!(self_mc(&store, &g.job_uid).await, Some(300));
        let offers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credit_entries")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(offers, 0, "no offer written");
        assert_eq!(
            crate::credits::jobs::self_committed(&store.pool, &node.id())
                .await
                .unwrap(),
            300
        );
    }

    /// A requeued own job's reservation never counts again: not when it
    /// is granted to another scanner, not when it is granted to this one
    /// unpaid.
    #[tokio::test]
    async fn a_regranted_job_drops_its_old_reservation() {
        use crate::credits::jobs::self_committed;
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        give_credits(&store, node.id()).await;
        node.set_scan_share(0.5);
        selling(&node, 300);
        let me = node.id();
        let rec = Recorder::Cluster(node.clone());
        for i in [96, 97] {
            let ip = store
                .upsert_ip(format!("203.0.113.{i}").parse().unwrap())
                .await
                .unwrap();
            rec.enqueue_scan(ip.id, 2, 24).await.unwrap();
        }
        let mut funding = Default::default();
        let a = arbiter
            .next_job_for(&mut funding, me, &[], 0)
            .await
            .unwrap()
            .unwrap();
        let b = arbiter
            .next_job_for(&mut funding, me, &[], 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self_committed(&store.pool, &me).await.unwrap(), 600);
        // Both go back to the queue (a restart, a lease expiry, a hand-back).
        for uid in [&a.job_uid, &b.job_uid] {
            arbiter.set_state(uid, "queued", None, None).await.unwrap();
        }
        assert_eq!(self_committed(&store.pool, &me).await.unwrap(), 0);
        // Regranted to another scanner (unpaid: no reference here) ...
        let other = Identity::generate().unwrap().id;
        let g = arbiter
            .next_job_for(&mut Default::default(), other, &[], 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status(&store, &g.job_uid).await, "running");
        assert_eq!(self_mc(&store, &g.job_uid).await, None);
        // ... and to this scanner at a price over its budget.
        selling(&node, u32::MAX);
        let g = arbiter
            .next_job_for(&mut Default::default(), me, &[], 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((g.offer_seq, g.price_mc), (None, 0));
        assert_eq!(status(&store, &g.job_uid).await, "running");
        assert_eq!(self_committed(&store.pool, &me).await.unwrap(), 0);
    }

    /// A claimant without a reference price here is granted unpaid and
    /// goes after one with a price.
    #[tokio::test]
    async fn a_scanner_without_a_reference_goes_after_a_priced_one() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        give_credits(&store, node.id()).await;
        node.set_scan_share(0.5);
        selling(&node, 300);
        let ip = store
            .upsert_ip("203.0.113.98".parse().unwrap())
            .await
            .unwrap();
        Recorder::Cluster(node.clone())
            .enqueue_scan(ip.id, 2, 24)
            .await
            .unwrap();
        let other = Identity::generate().unwrap().id;
        // The unpriced one asks first; the one job still goes to the other.
        let (theirs, mine) = tokio::join!(arbiter.claim(other, vec![], 0), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            arbiter.claim(node.id(), vec![], 0).await
        });
        assert!(theirs.is_none());
        assert_eq!(mine.map(|g| g.price_mc), Some(300));
        // Alone, it is granted unpaid.
        Recorder::Cluster(node.clone())
            .enqueue_scan(
                store
                    .upsert_ip("203.0.113.99".parse().unwrap())
                    .await
                    .unwrap()
                    .id,
                2,
                24,
            )
            .await
            .unwrap();
        let g = arbiter.claim(other, vec![], 0).await.unwrap();
        assert_eq!((g.offer_seq, g.price_mc), (None, 0));
    }

    async fn status(store: &crate::store::Store, uid: &str) -> String {
        sqlx::query_scalar("SELECT status FROM scan_jobs WHERE uid = ?")
            .bind(uid)
            .fetch_one(&store.pool)
            .await
            .unwrap()
    }

    /// A queued job of another arbiter, as if it had replicated here.
    async fn foreign_job(store: &crate::store::Store, ip_id: i64, level: i64, queued_at: &str) {
        let other = Identity::generate().unwrap().id;
        sqlx::query(
            "INSERT INTO scan_jobs (uid, origin, arbiter, hlc, ip_id, level, status, queued_at)
             VALUES (lower(hex(randomblob(16))), ?1, ?1, 1, ?2, ?3, 'queued', ?4)",
        )
        .bind(&other.0[..])
        .bind(ip_id)
        .bind(level)
        .bind(queued_at)
        .execute(&store.pool)
        .await
        .unwrap();
    }

    /// Two arbiters queued the same IP: only the job that ranks first
    /// (level, then queued_at, then uid) is granted; the other is
    /// superseded for good.
    #[tokio::test]
    async fn the_same_ip_queued_by_two_arbiters_is_granted_once() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let rec = Recorder::Cluster(node.clone());
        let scanner = Identity::generate().unwrap().id;
        let ip = store
            .upsert_ip("203.0.113.82".parse().unwrap())
            .await
            .unwrap();
        rec.enqueue_scan(ip.id, 2, 24).await.unwrap();
        let ours: String = sqlx::query_scalar("SELECT uid FROM scan_jobs WHERE ip_id = ?")
            .bind(ip.id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        // Queued later elsewhere, or at a lower level: ours runs.
        foreign_job(&store, ip.id, 2, "2999-01-01 00:00:00").await;
        foreign_job(&store, ip.id, 1, "2000-01-01 00:00:00").await;
        let g = arbiter.next_job(scanner, &[]).await.unwrap().unwrap();
        assert_eq!(g.job_uid, ours);
        assert!(arbiter.complete(scanner, &ours, "later", None).await);
        // Queued earlier elsewhere at the same level: that one runs, ours
        // is superseded and nothing else is granted here.
        foreign_job(&store, ip.id, 2, "2000-01-01 00:00:00").await;
        assert!(arbiter.next_job(node.id(), &[]).await.unwrap().is_none());
        assert_eq!(status(&store, &ours).await, "superseded");
    }

    /// A level a scanner sits out is passed over for the next one down,
    /// unless its job has waited long enough.
    #[tokio::test]
    async fn sat_out_levels_are_skipped_until_the_job_has_waited() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let rec = Recorder::Cluster(node.clone());
        for (i, level) in [(1u8, 4), (2, 2)] {
            let ip = store
                .upsert_ip(format!("203.0.113.{i}").parse().unwrap())
                .await
                .unwrap();
            rec.enqueue_scan(ip.id, level, 24).await.unwrap();
        }
        let scanner = Identity::generate().unwrap().id;
        let g = arbiter
            .next_job_skipping(scanner, vec![], &[4], &[])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(g.level, 2);
        assert!(
            arbiter
                .next_job_skipping(scanner, vec![], &[4], &[])
                .await
                .unwrap()
                .is_none()
        );
        // Waited past the override: anyone takes it.
        sqlx::query(
            "UPDATE scan_jobs SET queued_at = datetime('now', '-31 minutes') WHERE level = 4",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        let g = arbiter
            .next_job_skipping(scanner, vec![], &[4], &[])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(g.level, 4);
        // A lone scanner sits nothing out.
        assert!(arbiter.skipped_levels(scanner).await.unwrap().is_empty());
    }

    /// Jobs a scanner handed back must not hide the jobs behind them.
    #[tokio::test]
    async fn declined_jobs_do_not_starve_a_scanner() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let rec = Recorder::Cluster(node.clone());
        // 60 urgent jobs the scanner declined, then one it can run.
        for i in 0..61u8 {
            let ip = store
                .upsert_ip(format!("203.0.113.{}", i + 1).parse().unwrap())
                .await
                .unwrap();
            rec.enqueue_scan(ip.id, if i < 60 { 3 } else { 1 }, 24)
                .await
                .unwrap();
        }
        let scanner = Identity::generate().unwrap().id;
        let urgent: Vec<String> = sqlx::query_scalar("SELECT uid FROM scan_jobs WHERE level = 3")
            .fetch_all(&store.pool)
            .await
            .unwrap();
        assert_eq!(urgent.len(), 60);
        {
            let mut d = arbiter.declined.lock().unwrap();
            for uid in urgent {
                d.entry(uid).or_default().insert(scanner);
            }
        }
        let grant = arbiter.next_job(scanner, &[]).await.unwrap();
        assert_eq!(grant.map(|g| g.level), Some(1));
    }

    /// A failure reported by a scanner stays failed and queues a retry:
    /// nobody gets it before its time, then another scanner first; the
    /// one that failed only after a further wait.
    #[tokio::test]
    async fn failed_scans_are_retried_by_another_scanner_first() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let ip = store
            .upsert_ip("203.0.113.81".parse().unwrap())
            .await
            .unwrap();
        Recorder::Cluster(node.clone())
            .enqueue_scan(ip.id, 3, 24)
            .await
            .unwrap();
        let (a, b) = (node.id(), Identity::generate().unwrap().id);
        let g = arbiter.next_job(a, &[]).await.unwrap().unwrap();
        assert!(
            arbiter
                .complete(a, &g.job_uid, "failed", Some("nmap exited 1".into()))
                .await
        );
        assert_eq!(status(&store, &g.job_uid).await, "failed");
        let (retry, retry_of, failed_by): (String, Option<String>, Option<Vec<u8>>) =
            sqlx::query_as(
                "SELECT uid, retry_of, failed_by FROM scan_jobs WHERE status = 'queued'",
            )
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(retry_of.as_deref(), Some(g.job_uid.as_str()));
        assert_eq!(failed_by.as_deref(), Some(&a.0[..]));
        assert!(arbiter.next_job(b, &[]).await.unwrap().is_none(), "not yet");
        let due = |ago: &'static str| {
            let store = store.clone();
            async move {
                sqlx::query(
                    "UPDATE scan_jobs SET retry_at = datetime('now', ?) WHERE retry_of IS NOT NULL",
                )
                .bind(ago)
                .execute(&store.pool)
                .await
                .unwrap();
            }
        };
        due("-1 minute").await;
        assert!(
            arbiter.next_job(a, &[]).await.unwrap().is_none(),
            "the failer waits"
        );
        let g = arbiter.next_job(b, &[]).await.unwrap().unwrap();
        assert_eq!(g.job_uid, retry);
        assert!(arbiter.complete(b, &retry, "later", None).await);
        assert!(
            arbiter.next_job(a, &[]).await.unwrap().is_none(),
            "still waiting"
        );
        due("-31 minutes").await;
        let g = arbiter.next_job(a, &[]).await.unwrap().unwrap();
        assert_eq!((g.job_uid.as_str(), g.level), (retry.as_str(), 3));
    }

    /// "later" requeues the job and skips that scanner for it for a while
    /// only; it never makes the job refused.
    #[tokio::test]
    async fn later_turndowns_are_temporary() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let ip = store
            .upsert_ip("203.0.113.80".parse().unwrap())
            .await
            .unwrap();
        Recorder::Cluster(node.clone())
            .enqueue_scan(ip.id, 2, 24)
            .await
            .unwrap();
        let (a, b) = (node.id(), Identity::generate().unwrap().id);
        let g = arbiter.next_job(a, &[]).await.unwrap().unwrap();
        let why = Some("Tor exit status unknown (no exit list loaded)".into());
        assert!(arbiter.complete(a, &g.job_uid, "later", why).await);
        assert_eq!(status(&store, &g.job_uid).await, "queued");
        // `a` is the only scanner present; the job still is not refused.
        arbiter.recheck_declined().await.unwrap();
        assert_eq!(status(&store, &g.job_uid).await, "queued");
        // Not offered to `a` again yet, but to anyone else.
        assert!(arbiter.next_job(a, &[]).await.unwrap().is_none());
        let g = arbiter.next_job(b, &[]).await.unwrap().unwrap();
        assert!(arbiter.complete(b, &g.job_uid, "later", None).await);
        // Once the backoff is over, `a` gets it again.
        arbiter
            .later
            .lock()
            .unwrap()
            .get_mut(&g.job_uid)
            .unwrap()
            .insert(a, Instant::now());
        assert_eq!(
            arbiter.next_job(a, &[]).await.unwrap().map(|g| g.job_uid),
            Some(g.job_uid.clone())
        );
        assert_eq!(status(&store, &g.job_uid).await, "running");
    }

    /// "declined" (also from scanners older than "later") still hands the
    /// job back for good: with nobody left to take it, it is refused.
    #[tokio::test]
    async fn declined_turndowns_stay_permanent() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let ip = store
            .upsert_ip("203.0.113.81".parse().unwrap())
            .await
            .unwrap();
        Recorder::Cluster(node.clone())
            .enqueue_scan(ip.id, 2, 24)
            .await
            .unwrap();
        let a = Identity::generate().unwrap().id;
        let g = arbiter.next_job(a, &[]).await.unwrap().unwrap();
        let why = Some("never_scan 203.0.113.0/24".into());
        assert!(arbiter.complete(a, &g.job_uid, "declined", why).await);
        // This node's scanner may still take it, and then hands it back too.
        assert_eq!(status(&store, &g.job_uid).await, "queued");
        assert!(arbiter.next_job(a, &[]).await.unwrap().is_none());
        let g = arbiter.next_job(node.id(), &[]).await.unwrap().unwrap();
        assert!(
            arbiter
                .complete(node.id(), &g.job_uid, "declined", None)
                .await
        );
        assert_eq!(status(&store, &g.job_uid).await, "refused");
    }

    /// A scanner at its level-4 share is offered no level-4 job, however
    /// long it has waited (unlike the weight skips).
    #[tokio::test]
    async fn excluded_levels_are_never_granted() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let rec = Recorder::Cluster(node.clone());
        let scanner = Identity::generate().unwrap().id;
        let a = store
            .upsert_ip("203.0.113.90".parse().unwrap())
            .await
            .unwrap();
        let b = store
            .upsert_ip("203.0.113.91".parse().unwrap())
            .await
            .unwrap();
        rec.enqueue_scan(a.id, 4, 24).await.unwrap();
        rec.enqueue_scan(b.id, 2, 24).await.unwrap();
        sqlx::query("UPDATE scan_jobs SET queued_at = datetime('now', '-3 hours') WHERE level = 4")
            .execute(&store.pool)
            .await
            .unwrap();
        let g = arbiter.next_job(scanner, &[4]).await.unwrap().unwrap();
        assert_eq!(g.level, 2);
        assert!(arbiter.next_job(scanner, &[4]).await.unwrap().is_none());
        assert_eq!(
            arbiter.next_job(scanner, &[]).await.unwrap().unwrap().level,
            4
        );
    }

    /// Highest response ratio first: a fresher short job beats a younger
    /// long one; a long job that has waited long enough goes first.
    #[tokio::test]
    async fn jobs_are_granted_by_response_ratio() {
        // (minutes the L4 has waited, minutes the L2 has waited, level granted)
        for (l4_mins, l2_mins, first) in [(10, 5, 2), (120, 5, 4)] {
            let dir = tempfile::tempdir().unwrap();
            let (node, arbiter, store, _tx) = setup(dir.path()).await;
            let rec = Recorder::Cluster(node.clone());
            let scanner = Identity::generate().unwrap().id;
            let a = store
                .upsert_ip("203.0.113.92".parse().unwrap())
                .await
                .unwrap();
            let b = store
                .upsert_ip("203.0.113.93".parse().unwrap())
                .await
                .unwrap();
            rec.enqueue_scan(a.id, 4, 24).await.unwrap();
            rec.enqueue_scan(b.id, 2, 24).await.unwrap();
            for (level, mins) in [(4, l4_mins), (2, l2_mins)] {
                // ratio 1.5 / 2.0 with the default 20-min estimate at 10 / 5 min
                sqlx::query("UPDATE scan_jobs SET queued_at = datetime('now', ?) WHERE level = ?")
                    .bind(format!("-{mins} minutes"))
                    .bind(level)
                    .execute(&store.pool)
                    .await
                    .unwrap();
            }
            let g = arbiter.next_job(scanner, &[]).await.unwrap().unwrap();
            assert_eq!(g.level, first, "L4 waited {l4_mins} min, L2 {l2_mins} min");
        }
    }
}
