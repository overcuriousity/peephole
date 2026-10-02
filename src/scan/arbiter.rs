//! The scan-job arbiter (distributed mode). Every node arbitrates the
//! jobs it enqueued (or adopted): scanners anywhere in the cluster ask it
//! for work, it hands each job to exactly one of them under a lease that
//! the scanner renews while nmap runs, and it alone records the job's state.
//!
//! Fairness: claims are collected for a short window and the jobs go to
//! the claimants that ran the fewest scans in the last hour, so equally
//! paced scanners share the queue equally wherever the job came from.
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::msg::{Grant, Msg};
use crate::cluster::record::{JobStatusRec, Record};
use crate::store::data::now_ts;
use crate::store::recorder::Recorder;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{info, warn};

/// How long claims are collected before jobs are handed out.
pub const CLAIM_WINDOW: Duration = Duration::from_secs(2);

struct Lease {
    scanner: NodeId,
    expires: Instant,
}

type Waiter = (NodeId, oneshot::Sender<Option<Grant>>);

pub struct Arbiter {
    node: Arc<Node>,
    rec: Recorder,
    lease: Duration,
    leases: Mutex<HashMap<String, Lease>>,
    waiting: Mutex<Vec<Waiter>>,
    /// Scanners that handed a job back because their own never_scan covers it.
    declined: Mutex<HashMap<String, std::collections::HashSet<NodeId>>>,
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
            waiting: Mutex::new(vec![]),
            declined: Mutex::new(HashMap::new()),
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
            Msg::Claim => Some(Msg::ClaimReply {
                grant: self.claim(from).await,
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
            Msg::RequeueFailed { days } => Some(Msg::RequeueReply {
                n: self.rec.requeue_failed_jobs(days).await.unwrap_or(0),
            }),
            _ => None,
        }
    }

    /// Wait for the claim window, then get a job or nothing.
    async fn claim(self: &Arc<Self>, scanner: NodeId) -> Option<Grant> {
        let (tx, rx) = oneshot::channel();
        let first = {
            let mut w = self.waiting.lock().unwrap();
            w.push((scanner, tx));
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

    async fn scans_last_hour(&self, scanner: &NodeId) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_jobs WHERE scanner = ? AND started_at > datetime('now','-1 hour')",
        )
        .bind(&scanner.0[..])
        .fetch_one(&self.node.store.pool)
        .await
        .unwrap_or(0)
    }

    async fn hand_out(&self) -> Result<()> {
        let _g = self.assign.lock().await;
        let mut waiters = std::mem::take(&mut *self.waiting.lock().unwrap());
        let mut load = HashMap::new();
        for (s, _) in &waiters {
            if !load.contains_key(s) {
                load.insert(*s, self.scans_last_hour(s).await);
            }
        }
        // Fewest recent scans first; ties broken by key so it is stable.
        waiters.sort_by_key(|(s, _)| (load[s], *s));
        for (scanner, tx) in waiters {
            let grant = self.next_job(scanner).await?;
            if let Some(g) = &grant {
                *load.get_mut(&scanner).unwrap() += 1;
                info!(job = %g.job_uid, ip = %g.ip, scanner = %scanner.short(), "scan job granted");
            }
            let _ = tx.send(grant);
        }
        Ok(())
    }

    /// Take our next queued job for `scanner` and mark it running.
    async fn next_job(&self, scanner: NodeId) -> Result<Option<Grant>> {
        let me = self.node.id();
        // Not a job this scanner already handed back.
        let declined: Vec<String> = {
            let d = self.declined.lock().unwrap();
            d.iter()
                .filter(|(_, by)| by.contains(&scanner))
                .map(|(uid, _)| uid.clone())
                .collect()
        };
        let row: Option<(String, String, i64, i64)> = sqlx::query_as(
            "SELECT j.uid, i.ip, j.level, j.attempts FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
             WHERE j.status = 'queued' AND j.arbiter = ?
               AND j.uid NOT IN (SELECT value FROM json_each(?))
             ORDER BY j.level DESC, j.queued_at ASC LIMIT 1",
        )
        .bind(&me.0[..])
        .bind(serde_json::to_string(&declined)?)
        .fetch_optional(&self.node.store.pool)
        .await?;
        let Some((uid, ip, level, attempts)) = row else {
            return Ok(None);
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
            },
        );
        Ok(Some(Grant {
            job_uid: uid,
            ip,
            level,
            lease_secs: self.lease.as_secs().max(1),
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
        if !["done", "failed", "superseded", "refused", "declined"].contains(&status) {
            return false;
        }
        let _g = self.assign.lock().await;
        let holder = self.leases.lock().unwrap().get(uid).map(|l| l.scanner);
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
        if status == "declined" {
            return self.decline(scanner, uid, error).await;
        }
        self.declined.lock().unwrap().remove(uid);
        if let Err(e) = self.set_state(uid, status, error, Some(now_ts())).await {
            warn!(?e, job = %uid, "recording job outcome failed");
            return false;
        }
        true
    }

    /// Scanners that could still take a job: members with the scanner role
    /// that this node does not block and has heard from recently (or has not
    /// had the chance to hear from yet), this node included.
    fn scanners(&self) -> Vec<NodeId> {
        let me = self.node.id();
        let mut v: Vec<NodeId> = self
            .node
            .members()
            .values()
            .filter(|m| m.roles.iter().any(|r| r == "scanner"))
            .map(|m| m.id)
            .filter(|id| {
                *id == me
                    || (!self.node.is_blocked(id) && self.node.silent_for(id) < SCANNER_PRESENT)
            })
            .collect();
        if self.node.roles().scanner && !v.contains(&me) {
            v.push(me);
        }
        v
    }

    /// Whether every scanner that could take `uid` has declined it.
    fn all_declined(&self, uid: &str) -> bool {
        let d = self.declined.lock().unwrap();
        d.get(uid)
            .is_some_and(|by| self.scanners().iter().all(|s| by.contains(s)))
    }

    /// Declined jobs wait for another scanner. When the scanners that have
    /// not declined a job are gone, nobody is left to take it: refuse it.
    /// Entries of jobs that are no longer queued here are dropped.
    async fn recheck_declined(&self) -> Result<()> {
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
            let has_result: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM scans WHERE job_uid = ?")
                    .bind(&uid)
                    .fetch_one(&self.node.store.pool)
                    .await?;
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

/// Heartbeats this recent count a scanner as alive for takeover decisions.
const LIVE_WINDOW: Duration = Duration::from_secs(45);

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
            sqlx::query_scalar(
                "SELECT uid FROM scan_jobs WHERE status IN ('queued','running') AND arbiter = ?
                   AND MAX(COALESCE(hlc, 0), status_hlc) < ? LIMIT 500",
            )
            .bind(&a)
            .bind(stale_before)
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

    /// Jobs a scanner handed back must not hide the jobs behind them.
    #[tokio::test]
    async fn declined_jobs_do_not_starve_a_scanner() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
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
                retention_days: 0,
                peers: vec![],
            },
            roles: Default::default(),
            store: store.clone(),
            proto: (2, 2),
            data_dir: dir.path().to_path_buf(),
        })
        .await
        .unwrap();
        node.bootstrap().await.unwrap();
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let arbiter = Arbiter::start(node.clone(), rx).await.unwrap();
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
        let grant = arbiter.next_job(scanner).await.unwrap();
        assert_eq!(grant.map(|g| g.level), Some(1));
    }
}
