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
        let row: Option<(String, String, i64, i64)> = sqlx::query_as(
            "SELECT j.uid, i.ip, j.level, j.attempts FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
             WHERE j.status = 'queued' AND j.arbiter = ?
             ORDER BY j.level DESC, j.queued_at ASC LIMIT 1",
        )
        .bind(&me.0[..])
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
        if !["done", "failed", "superseded", "refused"].contains(&status) {
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
        if let Err(e) = self.set_state(uid, status, error, Some(now_ts())).await {
            warn!(?e, job = %uid, "recording job outcome failed");
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

/// Heartbeats this recent count a scanner as alive for takeover decisions.
const LIVE_WINDOW: Duration = Duration::from_secs(45);

/// Adopt queued jobs of arbiters silent for `cluster.takeover_hours`.
/// Only the lowest-keyed live scanner adopts, so takeovers rarely collide.
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

async fn takeover_once(node: &Arc<Node>, rec: &Recorder, window: Duration) -> Result<()> {
    let me = node.id();
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
    let lowest_live_scanner = node
        .live_members(LIVE_WINDOW)
        .into_iter()
        .filter(|id| *id == me || scanner(id))
        .min();
    if lowest_live_scanner != Some(me) || !node.roles.scanner {
        return Ok(());
    }
    let arbiters: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT DISTINCT arbiter FROM scan_jobs
         WHERE status = 'queued' AND arbiter IS NOT NULL AND arbiter != ?",
    )
    .bind(&me.0[..])
    .fetch_all(&node.store.pool)
    .await?;
    for a in arbiters {
        let Ok(from) = NodeId::from_slice(&a) else {
            continue;
        };
        if node.silent_for(&from) < window {
            continue;
        }
        let uids: Vec<String> = sqlx::query_scalar(
            "SELECT uid FROM scan_jobs WHERE status = 'queued' AND arbiter = ? LIMIT 500",
        )
        .bind(&a)
        .fetch_all(&node.store.pool)
        .await?;
        if uids.is_empty() {
            continue;
        }
        info!(from = %from.short(), jobs = uids.len(), "adopting queued scans of an unreachable node");
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
