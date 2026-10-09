//! The scan-job arbiter (distributed mode). Every node arbitrates the
//! jobs it enqueued (or adopted): scanners anywhere in the cluster ask it
//! for work, it hands each job to exactly one of them under a lease that
//! the scanner renews while nmap runs, and it alone records the job's state.
//!
//! Claims are collected for a short window, then the jobs are walked in
//! order (highest response ratio first, see `order`) and each goes to the
//! claimant that is cheapest per delivered result at its level (see
//! `rank`): its price over its success rate there (see `weight`). Equal
//! prices go to the claimant that ran the fewest scans in the last hour.
//! Every grant is funded, at zero or above; a job no claimant can be paid
//! for waits. A job waits for a cheaper live scanner up to
//! `weight::OVERRIDE_WAIT_MINS`. Why each job went where is kept in
//! `handout`.
use super::handout::{Handout, Reason};
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::msg::{Grant, Msg};
use crate::cluster::record::{JobStatusRec, Record};
use crate::store::data::now_ts;
use crate::store::recorder::Recorder;
use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};
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

/// Whether a grant handed back with `status` and `why` counts as
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

/// Queued jobs a round reads at most, a page of [`ROUND_PAGE`] at a time
/// until every claim has a job. Jobs every claimant handed back, or whose
/// level every claimant excludes, are not read at all; jobs held for a
/// cheaper scanner are, so a long held backlog does not hide the work
/// behind it.
const ROUND_JOBS: i64 = 5000;
const ROUND_PAGE: i64 = 200;

/// One claim of a round: who asks, the levels it takes none of, and the
/// least it takes for a funded job.
pub(crate) struct Claimant {
    pub id: NodeId,
    pub exclude: Vec<u8>,
    pub min_mc: u32,
}

/// How a scanner stands with this arbiter at the start of a round.
struct Stand {
    /// What this arbiter would pay it; None: it cannot be granted (unpaid
    /// here, or a scanner that does not earn as one, because it owes
    /// audits or its audits differ: it is not funded).
    price: Option<u32>,
    /// Over its hourly capacity here, or not delivering enough grants.
    demoted: bool,
    /// Its scans of the last hour, cluster-wide.
    load: i64,
}

/// `(uid, ip, level, attempts, failed_by, manual, failer_may, waited_secs)`.
type QueuedRow = (String, String, i64, i64, Option<Vec<u8>>, bool, bool, i64);

/// A queued job as a round sees it.
struct Queued {
    uid: String,
    ip: String,
    level: i64,
    attempts: i64,
    /// The scanner that failed its last try, if it is a retry.
    failed_by: Option<NodeId>,
    /// Whether it was bought (a manual job), not queued by the sweep.
    manual: bool,
    /// Whether that scanner may have it again.
    failer_may: bool,
    /// Seconds since it was queued.
    waited_secs: i64,
}

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
    /// Each scanner's last claim here: `(levels excluded, least price)`.
    last_claim: Mutex<HashMap<NodeId, (Vec<u8>, u32)>>,
    /// Paid jobs waiting for a cheaper scanner (the reserve), since when.
    held: Mutex<HashMap<String, Instant>>,
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
            held: Mutex::new(HashMap::new()),
            last_claim: Mutex::new(HashMap::new()),
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
        let waiters = std::mem::take(&mut *self.waiting.lock().unwrap());
        let claims: Vec<Claimant> = waiters
            .iter()
            .map(|(id, exclude, min_mc, _)| Claimant {
                id: *id,
                exclude: exclude.clone(),
                min_mc: *min_mc,
            })
            .collect();
        let grants = self.round(&claims).await?;
        for ((.., tx), grant) in waiters.into_iter().zip(grants) {
            let _ = tx.send(grant);
        }
        Ok(())
    }

    /// How `scanner` stands with this arbiter now.
    async fn stand(
        &self,
        scanner: &NodeId,
        table: &crate::credits::price::Table,
        book: Option<&crate::credits::Book>,
    ) -> Stand {
        let (all, here) = self.scans_last_hour(scanner).await;
        let delivering = self
            .outcomes
            .lock()
            .unwrap()
            .get(scanner)
            .is_none_or(|o| delivers(o, Instant::now()));
        Stand {
            // This node's own scanner sells nothing to it: no audits owed.
            price: if *scanner != self.node.id()
                && book.is_some_and(|b| !b.standing(scanner).earns_as_scanner())
            {
                None
            } else {
                crate::credits::jobs::price_for(&self.node, scanner)
            },
            demoted: over_capacity(here, table.can_do(scanner)) || !delivering,
            load: all,
        }
    }

    /// Jobs handed back by a scanner, for now or for good: by whom.
    fn handed_back(&self) -> HashMap<String, HashSet<NodeId>> {
        let now = Instant::now();
        let mut out: HashMap<String, HashSet<NodeId>> = self.declined.lock().unwrap().clone();
        for (uid, by) in self.later.lock().unwrap().iter() {
            out.entry(uid.clone())
                .or_default()
                .extend(by.iter().filter(|(_, t)| **t > now).map(|(s, _)| *s));
        }
        out
    }

    /// One round: the queued jobs in order (highest response ratio first),
    /// each to the eligible claim cheapest per delivered result at its
    /// level (see `rank`) that this round's book can pay; a job nobody can
    /// be paid for waits. A job waits for a cheaper live scanner up to
    /// `weight::OVERRIDE_WAIT_MINS`. One job per claim; the result is in
    /// claim order.
    async fn round(&self, claims: &[Claimant]) -> Result<Vec<Option<Grant>>> {
        use super::rank::{self, Bid, Standby, Wait};
        use super::weight;
        let _g = self.assign.lock().await;
        let mut out: Vec<Option<Grant>> = claims.iter().map(|_| None).collect();
        if claims.is_empty() {
            return Ok(out);
        }
        let pool = &self.node.store.pool;
        let table = self.node.price_table();
        let snap = self.node.weights.get(pool).await?;
        let scanners = self.scanners();
        let book = crate::credits::book(&self.node).await.ok();
        let mut stands: HashMap<NodeId, Stand> = HashMap::new();
        for s in claims.iter().map(|c| c.id).chain(scanners.iter().copied()) {
            if let std::collections::hash_map::Entry::Vacant(e) = stands.entry(s) {
                e.insert(self.stand(&s, &table, book.as_deref()).await);
            }
        }
        // What each scanner asked for last: a scanner not asking now keeps
        // its level exclusions and least price for the reserve.
        let last = {
            let mut l = self.last_claim.lock().unwrap();
            for c in claims {
                l.insert(c.id, (c.exclude.clone(), c.min_mc));
            }
            l.clone()
        };
        let back = self.handed_back();
        // What no claimant would take stays in the queue unread.
        let nobody: Vec<&String> = back
            .iter()
            .filter(|(_, by)| claims.iter().all(|c| by.contains(&c.id)))
            .map(|(uid, _)| uid)
            .collect();
        let excluded: Vec<u8> = (1..=5u8)
            .filter(|l| claims.iter().all(|c| c.exclude.contains(l)))
            .collect();
        let mut funding = crate::credits::jobs::Funding::default();
        let mut offset = 0;
        'pages: while offset < ROUND_JOBS && !out.iter().all(Option::is_some) {
            let jobs = match self.queued(&nobody, &excluded, offset).await {
                Ok(j) => j,
                Err(e) => {
                    warn!(?e, "handing out scan jobs stopped");
                    break;
                }
            };
            let read = jobs.len() as i64;
            // Jobs granted or superseded leave the queue: the next page starts
            // that many earlier.
            let mut gone = 0;
            for job in jobs {
                if out.iter().all(Option::is_some) {
                    break 'pages;
                }
                let level = job.level;
                // A bought job pays every scanner 4^(level-1) times its
                // price: the ranking and the reserve are unchanged by it.
                let factor = match job.manual {
                    true => crate::credits::jobs::level_factor(level),
                    false => 1,
                };
                let takes = |id: &NodeId| {
                    !back.get(&job.uid).is_some_and(|by| by.contains(id))
                        && !(job.failed_by == Some(*id) && !job.failer_may)
                };
                let excludes = |c: &Claimant| c.exclude.contains(&(level as u8));
                let mut bids: Vec<(usize, Bid)> = claims
                    .iter()
                    .enumerate()
                    .filter(|(i, c)| out[*i].is_none() && !excludes(c) && takes(&c.id))
                    .map(|(i, c)| {
                        let st = &stands[&c.id];
                        let bid = Bid {
                            id: c.id,
                            price: st.price,
                            weight: weight::weight(&snap.tallies, c.id, &scanners, level),
                            demoted: st.demoted,
                            load: st.load,
                        };
                        (i, bid)
                    })
                    .collect();
                if bids.is_empty() {
                    continue;
                }
                bids.sort_by_key(|(_, b)| rank::order(b));
                // The best claimant this round's book can pay; with none,
                // the job waits for the next round.
                let mut payee = None;
                for (k, (ci, b)) in bids.iter().enumerate() {
                    if let Some(p) = b.price
                        && crate::credits::jobs::affordable(
                            &self.node,
                            &mut funding,
                            claims[*ci].min_mc,
                            p.saturating_mul(factor),
                        )
                        .await
                    {
                        payee = Some(k);
                        break;
                    }
                }
                let Some(pick) = payee else { continue };
                let top = bids[pick].1.clone();
                let standby: Vec<Standby> = scanners
                    .iter()
                    .filter(|s| {
                        !stands[*s].demoted
                            && !table.can_do(s).is_some_and(|c| c < 1.0)
                            && takes(s)
                            && !last.get(*s).is_some_and(|(x, min_mc)| {
                                x.contains(&(level as u8))
                                    || stands[*s].price.is_some_and(|p| p < *min_mc)
                            })
                    })
                    .map(|s| {
                        let t = snap.tallies.get(&(*s, level)).copied().unwrap_or_default();
                        Standby {
                            id: *s,
                            price: stands[s].price,
                            weight: weight::weight(&snap.tallies, *s, &scanners, level),
                            sample: t.ok + t.failed,
                        }
                    })
                    .collect();
                let (reason, waited) =
                    match rank::waits(top.effective(), rank::reserve(&standby), job.waited_secs) {
                        Wait::Hold => {
                            self.held
                                .lock()
                                .unwrap()
                                .entry(job.uid.clone())
                                .or_insert_with(Instant::now);
                            continue;
                        }
                        Wait::Go => {
                            let held = self.held.lock().unwrap().get(&job.uid).copied();
                            (
                                Reason::Cheapest,
                                held.map_or(0, |t| t.elapsed().as_secs() as i64),
                            )
                        }
                        Wait::Override => (Reason::Override, job.waited_secs),
                    };
                // Another arbiter queued the same IP and its job ranks first, or
                // a scan of it is running: the scanners would turn this one down.
                let other = match super::outranked_by(pool, &job.uid).await {
                    Ok(o) => o,
                    Err(e) => {
                        warn!(?e, job = %job.uid, "handing out scan jobs stopped");
                        break 'pages;
                    }
                };
                if let Some(other) = other {
                    info!(job = %job.uid, ip = %job.ip, by = %other, "scan job superseded by another job for the same IP");
                    let why = format!("job {other} for this IP ranks first");
                    if let Err(e) = self
                        .set_state(&job.uid, "superseded", Some(why), Some(now_ts()))
                        .await
                    {
                        warn!(?e, job = %job.uid, "handing out scan jobs stopped");
                        break 'pages;
                    }
                    gone += 1;
                    continue;
                }
                let (i, bid) = bids[pick].clone();
                let next = bids
                    .iter()
                    .find(|(_, b)| b.id != bid.id)
                    .map(|(_, b)| (b.id, b.effective()));
                let c = &claims[i];
                let price = bid.price.unwrap_or(0).saturating_mul(factor);
                let g = match self.grant(&mut funding, c, &job, price).await {
                    Ok(Some(g)) => g,
                    // The offer could not be written: the job stays queued.
                    Ok(None) => continue,
                    Err(e) => {
                        // The grants made so far still go out.
                        warn!(?e, job = %job.uid, "handing out scan jobs stopped");
                        break 'pages;
                    }
                };
                gone += 1;
                self.held.lock().unwrap().remove(&job.uid);
                if let Some(st) = stands.get_mut(&c.id) {
                    st.load += 1;
                }
                info!(job = %g.job_uid, ip = %g.ip, scanner = %c.id.short(), "scan job granted");
                let h = Handout {
                    job_uid: g.job_uid.clone(),
                    scanner: c.id,
                    level,
                    price_mc: bid.price,
                    rate: bid.weight,
                    effective_mc: bid.effective(),
                    next,
                    waited_secs: waited,
                    reason,
                };
                if let Err(e) = super::handout::record(pool, &h).await {
                    tracing::debug!(?e, job = %h.job_uid, "hand-out not recorded");
                }
                out[i] = Some(g);
            }
            if read < ROUND_PAGE {
                break;
            }
            offset += read - gone;
        }
        Ok(out)
    }

    /// A page of this arbiter's queued jobs that are due, highest response
    /// ratio first, from `offset`, past `nobody` (uids every claimant
    /// handed back) and the `excluded` levels (every claimant's).
    async fn queued(
        &self,
        nobody: &[&String],
        excluded: &[u8],
        offset: i64,
    ) -> Result<Vec<Queued>> {
        let est = self.order.get(&self.node.store.pool).await;
        let rows: Vec<QueuedRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT j.uid, i.ip, j.level, j.attempts, j.failed_by, j.manual,
                        j.retry_at IS NULL OR j.retry_at <= datetime('now', '-{} minutes'),
                        CAST((julianday('now') - julianday(j.queued_at)) * 86400 AS INTEGER)
                 FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
                 WHERE j.status = 'queued' AND j.arbiter = ?
                   AND j.uid NOT IN (SELECT value FROM json_each(?))
                   AND j.level NOT IN (SELECT value FROM json_each(?))
                   AND (j.retry_at IS NULL OR j.retry_at <= datetime('now'))
                 ORDER BY {} LIMIT {ROUND_PAGE} OFFSET {offset}",
            super::retry::LAST_FAILER_WAIT,
            est.order_by("j", "j.uid"),
        )))
        .bind(&self.node.id().0[..])
        .bind(serde_json::to_string(nobody)?)
        .bind(serde_json::to_string(excluded)?)
        .fetch_all(&self.node.store.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(uid, ip, level, attempts, failed_by, manual, failer_may, waited_secs)| Queued {
                    uid,
                    ip,
                    level,
                    attempts,
                    failed_by: failed_by.and_then(|f| NodeId::from_slice(&f).ok()),
                    manual,
                    failer_may,
                    waited_secs,
                },
            )
            .collect())
    }

    /// Fund `job` for `claim`'s scanner at `price` and mark it running
    /// under a lease. None: the offer could not be written; the job stays
    /// queued. (If the state write fails after an offer was written, the
    /// offer lapses unanswered: nothing is charged.)
    async fn grant(
        &self,
        funding: &mut crate::credits::jobs::Funding,
        claim: &Claimant,
        job: &Queued,
        price: u32,
    ) -> Result<Option<Grant>> {
        let Some((offer_seq, price)) = crate::credits::jobs::fund(
            &self.node,
            funding,
            claim.id,
            &job.uid,
            claim.min_mc,
            price,
        )
        .await
        else {
            return Ok(None);
        };
        self.rec
            .write(vec![Record::JobStatus(JobStatusRec {
                job_uid: job.uid.clone(),
                status: "running".into(),
                started_at: Some(now_ts()),
                finished_at: None,
                error: None,
                attempts: job.attempts + 1,
                scanner: Some(claim.id),
            })])
            .await?;
        self.leases.lock().unwrap().insert(
            job.uid.clone(),
            Lease {
                scanner: claim.id,
                expires: Instant::now() + self.lease,
            },
        );
        if price > 0 {
            info!(job = %job.uid, scanner = %claim.id.short(),
                price = %crate::credits::show(price as u64), "scan job funded");
        }
        Ok(Some(Grant {
            job_uid: job.uid.clone(),
            ip: job.ip.clone(),
            level: job.level,
            lease_secs: self.lease.as_secs().max(1),
            offer_seq,
            price_mc: price,
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
        match status {
            "done" => self.note_outcome(scanner, true),
            "failed" => self.note_outcome(scanner, false),
            // Every grant is funded: a turn-down counts against the scanner.
            "later" | "declined" if undelivered(status, error.as_deref()) => {
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
        // A job held for a cheaper scanner is granted within the override
        // wait, or was handed out elsewhere.
        let hold = Duration::from_secs(2 * super::weight::OVERRIDE_WAIT_MINS as u64 * 60);
        self.held.lock().unwrap().retain(|_, t| t.elapsed() < hold);
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
/// - keeps running but has left a job marked running for `window` while
///   this node's scanner has idle workers (lowest live scanner only): a
///   grant whose scan cannot still be running. A live arbiter's queued
///   jobs stay with it: one that no claimant can be paid for waits for
///   its arbiter's funds, not for another node's.
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
            // Only stale running jobs of a live arbiter: its queued jobs
            // wait for its own funding (adopting them would have this node
            // pay for them). A running job may be a long level-4 scan whose
            // lease is renewed without touching the job row: take it only
            // once no scan can still be running.
            sqlx::query_scalar(
                "SELECT uid FROM scan_jobs WHERE arbiter = ?
                   AND MAX(COALESCE(hlc, 0), status_hlc) < ?
                   AND status = 'running'
                   AND (started_at IS NULL OR started_at < datetime('now', ?))
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
                relay_slots: 16,
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
        // Its scanner runs (it sells at 0 before its first refresh).
        node.status.local.lock().unwrap().pace = Some(crate::cluster::status::PaceInfo {
            max_workers: 2,
            max_scans_per_hour: 60,
            timeout_secs: 600,
        });
        let (tx, rx) = tokio::sync::watch::channel(false);
        let arbiter = Arbiter::start(node.clone(), rx).await.unwrap();
        (node, arbiter, store, tx)
    }

    /// Credits for `node`: the whole pool of the day two days back.
    async fn give_credits(store: &crate::store::Store, node: NodeId) {
        let day = (crate::cluster::hlc::wall_ms() / crate::credits::DAY_MS) as u32 - 2;
        sqlx::query(
            "UPDATE members SET address = '198.51.100.1:7443', proto_max = ?,
               roles_json = '[\"listener\",\"scanner\"]' WHERE id = ?",
        )
        .bind(crate::cluster::rpc::proto::ECONOMY_PROTO as i64)
        .bind(&node.0[..])
        .execute(&store.pool)
        .await
        .unwrap();
        crate::credits::pool::testing::report_all_day(&store.pool, day, &[node])
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
        let g = arbiter.next_job(node.id(), &[], 0).await.unwrap();
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

    /// A bought (manual) job is funded at the scanner's price times
    /// 4^(level-1) — level 3 at 16 times.
    #[tokio::test]
    async fn a_manual_job_is_funded_at_the_level_scaled_price() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        give_credits(&store, node.id()).await;
        node.set_scan_share(1.0);
        selling(&node, 300);
        let ip = store
            .upsert_ip("203.0.113.98".parse().unwrap())
            .await
            .unwrap();
        Recorder::Cluster(node.clone())
            .enqueue_manual(ip.id, 3)
            .await
            .unwrap();
        let g = arbiter.next_job(node.id(), &[], 0).await.unwrap();
        assert_eq!((g.offer_seq, g.price_mc), (None, 300 * 16));
        assert_eq!(self_mc(&store, &g.job_uid).await, Some(300 * 16));
    }

    /// A requeued own job's reservation never counts again: not when it
    /// is granted to another scanner, not when this one is over its budget
    /// (the job waits).
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
        let a = arbiter.next_job(me, &[], 0).await.unwrap();
        let b = arbiter.next_job(me, &[], 0).await.unwrap();
        assert_eq!(self_committed(&store.pool, &me).await.unwrap(), 600);
        // Both go back to the queue (a restart, a lease expiry, a hand-back).
        for uid in [&a.job_uid, &b.job_uid] {
            arbiter.set_state(uid, "queued", None, None).await.unwrap();
        }
        assert_eq!(self_committed(&store.pool, &me).await.unwrap(), 0);
        // Regranted to another scanner (priced at 0 here) ...
        let other = zero_scanner(&node).await;
        let g = arbiter.next_job(other, &[], 0).await.unwrap();
        assert_eq!((g.offer_seq, g.price_mc), (None, 0));
        assert_eq!(status(&store, &g.job_uid).await, "running");
        assert_eq!(self_mc(&store, &g.job_uid).await, None);
        // ... and not to this scanner at a price over its budget: the
        // other job waits, and its old reservation still counts for nothing.
        selling(&node, u32::MAX);
        assert!(arbiter.next_job(me, &[], 0).await.is_none());
        assert_eq!(self_committed(&store.pool, &me).await.unwrap(), 0);
    }

    /// A claimant without a reference price here is not granted: the
    /// job goes to one with a price, or waits.
    #[tokio::test]
    async fn a_scanner_without_a_reference_is_not_granted() {
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
        // Alone, it is not granted: the job waits.
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
        assert!(arbiter.claim(other, vec![], 0).await.is_none());
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
        let scanner = zero_scanner(&node).await;
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
        let g = arbiter.next_job(scanner, &[], 0).await.unwrap();
        assert_eq!(g.job_uid, ours);
        assert!(arbiter.complete(scanner, &ours, "later", None).await);
        // Queued earlier elsewhere at the same level: that one runs, ours
        // is superseded and nothing else is granted here.
        foreign_job(&store, ip.id, 2, "2000-01-01 00:00:00").await;
        assert!(arbiter.next_job(node.id(), &[], 0).await.is_none());
        assert_eq!(status(&store, &ours).await, "superseded");
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
        let scanner = zero_scanner(&node).await;
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
        let grant = arbiter.next_job(scanner, &[], 0).await;
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
        let (a, b) = (node.id(), zero_scanner(&node).await);
        let g = arbiter.next_job(a, &[], 0).await.unwrap();
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
        assert!(arbiter.next_job(b, &[], 0).await.is_none(), "not yet");
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
            arbiter.next_job(a, &[], 0).await.is_none(),
            "the failer waits"
        );
        let g = arbiter.next_job(b, &[], 0).await.unwrap();
        assert_eq!(g.job_uid, retry);
        assert!(arbiter.complete(b, &retry, "later", None).await);
        assert!(arbiter.next_job(a, &[], 0).await.is_none(), "still waiting");
        due("-31 minutes").await;
        let g = arbiter.next_job(a, &[], 0).await.unwrap();
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
        let (a, b) = (node.id(), zero_scanner(&node).await);
        let g = arbiter.next_job(a, &[], 0).await.unwrap();
        let why = Some("Tor exit status unknown (no exit list loaded)".into());
        assert!(arbiter.complete(a, &g.job_uid, "later", why).await);
        assert_eq!(status(&store, &g.job_uid).await, "queued");
        // `a` is the only scanner present; the job still is not refused.
        arbiter.recheck_declined().await.unwrap();
        assert_eq!(status(&store, &g.job_uid).await, "queued");
        // Not offered to `a` again yet, but to anyone else.
        assert!(arbiter.next_job(a, &[], 0).await.is_none());
        let g = arbiter.next_job(b, &[], 0).await.unwrap();
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
            arbiter.next_job(a, &[], 0).await.map(|g| g.job_uid),
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
        let a = zero_scanner(&node).await;
        let g = arbiter.next_job(a, &[], 0).await.unwrap();
        let why = Some("never_scan 203.0.113.0/24".into());
        assert!(arbiter.complete(a, &g.job_uid, "declined", why).await);
        // This node's scanner may still take it, and then hands it back too.
        assert_eq!(status(&store, &g.job_uid).await, "queued");
        assert!(arbiter.next_job(a, &[], 0).await.is_none());
        let g = arbiter.next_job(node.id(), &[], 0).await.unwrap();
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
        let scanner = zero_scanner(&node).await;
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
        let g = arbiter.next_job(scanner, &[4], 0).await.unwrap();
        assert_eq!(g.level, 2);
        assert!(arbiter.next_job(scanner, &[4], 0).await.is_none());
        assert_eq!(arbiter.next_job(scanner, &[], 0).await.unwrap().level, 4);
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
            let scanner = zero_scanner(&node).await;
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
            let g = arbiter.next_job(scanner, &[], 0).await.unwrap();
            assert_eq!(g.level, first, "L4 waited {l4_mins} min, L2 {l2_mins} min");
        }
    }

    impl Arbiter {
        /// One round with one claim.
        async fn next_job(&self, scanner: NodeId, exclude: &[u8], min_mc: u32) -> Option<Grant> {
            let c = Claimant {
                min_mc,
                ..claim_of(scanner, exclude)
            };
            self.round(&[c]).await.unwrap().pop().flatten()
        }
    }

    fn claim_of(id: NodeId, exclude: &[u8]) -> Claimant {
        Claimant {
            id,
            exclude: exclude.to_vec(),
            min_mc: 0,
        }
    }

    /// A member with the scanner role, heard from just now, announcing
    /// `price_mc` for a scan job.
    async fn remote_scanner(node: &Node, price_mc: u32) -> NodeId {
        remote_member(node, "scanner", price_mc).await
    }

    /// A member with `role`, heard from just now, announcing `price_mc`
    /// for a scan job.
    async fn remote_member(node: &Node, role: &str, price_mc: u32) -> NodeId {
        let id = Identity::generate().unwrap().id;
        let now = crate::cluster::hlc::wall_ms() << 16;
        sqlx::query(
            "INSERT INTO members (id, name, roles_json, proto_min, proto_max, sponsor,
                                  info_hlc, admitted_hlc)
             VALUES (?1, ?2, json_array(?5), 1, ?3, ?1, ?4, ?4)",
        )
        .bind(&id.0[..])
        .bind(format!("s-{price_mc}"))
        .bind(crate::cluster::rpc::proto::ECONOMY_PROTO as i64)
        .bind(now as i64)
        .bind(role)
        .execute(&node.store.pool)
        .await
        .unwrap();
        node.reload_members().await.unwrap();
        let hb = crate::cluster::status::Heartbeat {
            node: id,
            at_ms: crate::cluster::hlc::wall_ms(),
            neighbours: vec![],
            roles: vec![role.into()],
            version: String::new(),
            pace: None,
            active_scans: 0,
            providers: vec![],
            own_seq: 0,
            retention_days: 0,
            floors: vec![],
            on_demand: vec![],
            prices: vec![],
            public_addrs: vec![],
            probe_price_mc: None,
            scan_price_mc: Some(price_mc),
            scan_budget_mc: 0,
            scan_queued: 0,
            relays: vec![],
        };
        let signed = crate::cluster::status::SignedHeartbeat {
            body: vec![],
            sig: vec![],
        };
        assert!(node.status.merge(hb, signed));
        id
    }

    /// This node's copy of the scanners' prices, and their capacity.
    fn references(node: &Node, refs: &[(NodeId, u32, f64)]) {
        use crate::credits::price::{Capacity, Limit, ScannerCapacity, ScannerPrice, Table};
        node.set_price_table(Arc::new(Table {
            scanners: refs
                .iter()
                .map(|(n, p, _)| ScannerPrice {
                    node: *n,
                    price_mc: *p,
                    paid: 0.0,
                    supply: 0.0,
                })
                .collect(),
            capacity: Capacity {
                scanners: refs
                    .iter()
                    .map(|(n, _, c)| ScannerCapacity {
                        node: *n,
                        can_do: *c,
                        did: 0.0,
                        limited_by: Limit::PerHour,
                    })
                    .collect(),
                ..Default::default()
            },
            ..Default::default()
        }));
    }

    /// `who` finished `ok` and `failed` scans at `level` two hours ago:
    /// inside the weight snapshot's window.
    async fn history(
        store: &crate::store::Store,
        who: NodeId,
        level: i64,
        ok: usize,
        failed: usize,
    ) {
        let ip = store
            .upsert_ip("198.51.100.1".parse().unwrap())
            .await
            .unwrap();
        for status in std::iter::repeat_n("done", ok).chain(std::iter::repeat_n("failed", failed)) {
            sqlx::query(
                "INSERT INTO scan_jobs (uid, origin, arbiter, hlc, ip_id, level, status, queued_at,
                                        started_at, finished_at, scanner, error)
                 VALUES (lower(hex(randomblob(16))), ?1, ?1, 1, ?2, ?3, ?4,
                         datetime('now', '-3 hours'), datetime('now', '-3 hours'),
                         datetime('now', '-2 hours'), ?1, 'nmap exited 1')",
            )
            .bind(&who.0[..])
            .bind(ip.id)
            .bind(level)
            .bind(status)
            .execute(&store.pool)
            .await
            .unwrap();
        }
    }

    async fn queue(node: &Arc<Node>, store: &crate::store::Store, last: u8, level: u8) -> String {
        let ip = store
            .upsert_ip(format!("203.0.113.{last}").parse().unwrap())
            .await
            .unwrap();
        Recorder::Cluster(node.clone())
            .enqueue_scan(ip.id, level, 24)
            .await
            .unwrap();
        sqlx::query_scalar("SELECT uid FROM scan_jobs WHERE ip_id = ? ORDER BY id DESC LIMIT 1")
            .bind(ip.id)
            .fetch_one(&store.pool)
            .await
            .unwrap()
    }

    async fn handout_of(store: &crate::store::Store, uid: &str) -> crate::scan::handout::Handout {
        crate::scan::handout::latest(&store.pool, &[uid.to_string()])
            .await
            .unwrap()
            .remove(uid)
            .expect("a record of the grant")
    }

    /// Fast asks 30 and delivers every scan; Flaky asks 20, fails most
    /// level-4 scans and none at level 1. This node pays both.
    async fn fast_and_flaky(node: &Arc<Node>, store: &crate::store::Store) -> (NodeId, NodeId) {
        give_credits(store, node.id()).await;
        node.set_scan_share(0.5);
        let fast = remote_scanner(node, 30).await;
        let flaky = remote_scanner(node, 20).await;
        references(node, &[(fast, 30, 100.0), (flaky, 20, 100.0)]);
        history(store, fast, 4, 10, 0).await;
        history(store, flaky, 4, 2, 10).await;
        history(store, fast, 1, 10, 0).await;
        history(store, flaky, 1, 10, 0).await;
        (fast, flaky)
    }

    #[tokio::test]
    async fn a_paid_job_goes_to_the_cheapest_per_delivered_result() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let (fast, flaky) = fast_and_flaky(&node, &store).await;
        let l4 = queue(&node, &store, 4, 4).await;
        let l1 = queue(&node, &store, 1, 1).await;
        // The level-4 job goes first, so both claimants bid for it.
        sqlx::query(
            "UPDATE scan_jobs SET queued_at = datetime('now', '-25 minutes') WHERE uid = ?",
        )
        .bind(&l4)
        .execute(&store.pool)
        .await
        .unwrap();
        let got = arbiter
            .round(&[claim_of(flaky, &[]), claim_of(fast, &[])])
            .await
            .unwrap();
        let uid = |g: &Option<Grant>| g.as_ref().map(|g| g.job_uid.clone());
        assert_eq!(uid(&got[0]), Some(l1.clone()), "Flaky gets level 1");
        assert_eq!(uid(&got[1]), Some(l4.clone()), "Fast gets level 4");
        assert_eq!(
            got[1].as_ref().unwrap().price_mc,
            30,
            "paid at Fast's price"
        );
        let h = handout_of(&store, &l4).await;
        assert_eq!(
            (h.scanner, h.reason),
            (fast, crate::scan::handout::Reason::Cheapest)
        );
        assert_eq!(h.next.map(|n| n.0), Some(flaky));
        assert!(h.next.unwrap().1 > h.effective_mc);
        assert_eq!(handout_of(&store, &l1).await.scanner, flaky);
    }

    #[tokio::test]
    async fn a_paid_job_waits_for_a_cheaper_live_scanner_until_the_override() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let (_fast, flaky) = fast_and_flaky(&node, &store).await;
        // More level-4 jobs ahead than four per claimant: they must not
        // hide the level-1 job behind them.
        for i in 10..16 {
            queue(&node, &store, i, 4).await;
        }
        sqlx::query("UPDATE scan_jobs SET queued_at = datetime('now', '-20 minutes') WHERE level = 4 AND status = 'queued'")
            .execute(&store.pool)
            .await
            .unwrap();
        let l1 = queue(&node, &store, 1, 1).await;
        let g = arbiter.next_job(flaky, &[], 0).await.unwrap();
        assert_eq!(
            g.job_uid, l1,
            "Fast is cheaper per result at level 4: those wait"
        );
        assert!(arbiter.next_job(flaky, &[], 0).await.is_none());
        // Waited past the override: Flaky gets one.
        sqlx::query("UPDATE scan_jobs SET queued_at = datetime('now', '-31 minutes') WHERE level = 4 AND status = 'queued'")
            .execute(&store.pool)
            .await
            .unwrap();
        let g = arbiter.next_job(flaky, &[], 0).await.unwrap();
        assert_eq!(g.level, 4);
        assert!(g.price_mc > 0, "still paid");
        let h = handout_of(&store, &g.job_uid).await;
        assert_eq!(h.reason, crate::scan::handout::Reason::Override);
        assert!(h.waited_secs >= 31 * 60);
    }

    #[tokio::test]
    async fn a_scanner_that_cannot_take_the_job_sets_no_reserve() {
        for case in [
            "declined",
            "last failer",
            "no record",
            "over capacity",
            "excludes",
            "paused",
            "excluded before",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (node, arbiter, store, _tx) = setup(dir.path()).await;
            give_credits(&store, node.id()).await;
            node.set_scan_share(0.5);
            let fast = remote_scanner(&node, 30).await;
            let flaky = remote_scanner(&node, 20).await;
            let fast_can_do = match case {
                "over capacity" => 1.0,
                "paused" => 0.0,
                _ => 100.0,
            };
            references(&node, &[(fast, 30, fast_can_do), (flaky, 20, 100.0)]);
            history(&store, fast, 4, if case == "no record" { 4 } else { 10 }, 0).await;
            history(&store, flaky, 4, 2, 10).await;
            let uid = queue(&node, &store, 4, 4).await;
            let mut claims = vec![claim_of(flaky, &[])];
            match case {
                "declined" => {
                    arbiter
                        .declined
                        .lock()
                        .unwrap()
                        .entry(uid.clone())
                        .or_default()
                        .insert(fast);
                }
                "last failer" => {
                    sqlx::query("UPDATE scan_jobs SET failed_by = ?, retry_at = datetime('now', '-1 minute') WHERE uid = ?")
                        .bind(&fast.0[..])
                        .bind(&uid)
                        .execute(&store.pool)
                        .await
                        .unwrap();
                }
                "over capacity" => {
                    // One scan started for this arbiter in the last hour.
                    let me = node.id();
                    sqlx::query(
                        "INSERT INTO scan_jobs (uid, origin, arbiter, hlc, ip_id, level, status, queued_at, started_at, scanner)
                         VALUES ('busy', ?1, ?1, 1, (SELECT MIN(id) FROM ips), 2, 'running', datetime('now'), datetime('now'), ?2)",
                    )
                    .bind(&me.0[..])
                    .bind(&fast.0[..])
                    .execute(&store.pool)
                    .await
                    .unwrap();
                }
                "excludes" => claims.push(claim_of(fast, &[4])),
                "excluded before" => {
                    // Fast last asked without level 4; it is busy now.
                    assert!(arbiter.round(&[claim_of(fast, &[4])]).await.unwrap()[0].is_none());
                }
                _ => {}
            }
            let got = arbiter.round(&claims).await.unwrap();
            assert_eq!(
                got[0].as_ref().map(|g| g.job_uid.clone()),
                Some(uid),
                "{case}: Flaky gets it at once"
            );
        }
    }

    #[tokio::test]
    async fn two_claims_of_one_scanner_get_two_jobs() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let a = queue(&node, &store, 1, 2).await;
        let b = queue(&node, &store, 2, 2).await;
        let other = zero_scanner(&node).await;
        let got = arbiter
            .round(&[claim_of(other, &[]), claim_of(other, &[])])
            .await
            .unwrap();
        let mut uids: Vec<String> = got.into_iter().map(|g| g.unwrap().job_uid).collect();
        uids.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(uids, want);
    }

    /// A held job that went elsewhere (or away) is forgotten in time.
    #[tokio::test]
    async fn old_holds_are_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let (_node, arbiter, _store, _tx) = setup(dir.path()).await;
        let long = Duration::from_secs(61 * 60);
        if let Some(old) = Instant::now().checked_sub(long) {
            arbiter.held.lock().unwrap().insert("gone".into(), old);
        }
        arbiter
            .held
            .lock()
            .unwrap()
            .insert("fresh".into(), Instant::now());
        arbiter.recheck_declined().await.unwrap();
        let held = arbiter.held.lock().unwrap();
        assert!(!held.contains_key("gone"));
        assert!(held.contains_key("fresh"));
    }

    /// A failure late in a round does not lose the grants made before it.
    #[tokio::test]
    async fn grants_made_before_an_error_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let first = queue(&node, &store, 1, 2).await;
        let second = queue(&node, &store, 2, 2).await;
        sqlx::query("UPDATE scan_jobs SET queued_at = datetime('now', '-5 minutes') WHERE uid = ?")
            .bind(&first)
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE TRIGGER boom BEFORE UPDATE ON scan_jobs WHEN NEW.uid = '{second}'
             BEGIN SELECT RAISE(ABORT, 'boom'); END"
        )))
        .execute(&store.pool)
        .await
        .unwrap();
        let other = zero_scanner(&node).await;
        let got = arbiter
            .round(&[claim_of(other, &[]), claim_of(other, &[])])
            .await
            .unwrap();
        assert_eq!(got[0].as_ref().map(|g| g.job_uid.clone()), Some(first));
        assert!(got[1].is_none());
    }

    /// A backlog of held jobs longer than a page does not hide the work
    /// behind it.
    #[tokio::test]
    async fn a_long_held_backlog_does_not_hide_cheaper_work() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let (_fast, flaky) = fast_and_flaky(&node, &store).await;
        let ip = store
            .upsert_ip("198.51.100.200".parse().unwrap())
            .await
            .unwrap();
        for _ in 0..(ROUND_PAGE + 50) {
            sqlx::query(
                "INSERT INTO scan_jobs (uid, origin, arbiter, hlc, ip_id, level, status, queued_at)
                 VALUES (lower(hex(randomblob(16))), ?1, ?1, 1, ?2, 4, 'queued',
                         datetime('now', '-20 minutes'))",
            )
            .bind(&node.id().0[..])
            .bind(ip.id)
            .execute(&store.pool)
            .await
            .unwrap();
        }
        let l1 = queue(&node, &store, 1, 1).await;
        let g = arbiter.next_job(flaky, &[], 0).await.unwrap();
        assert_eq!(g.job_uid, l1);
    }

    /// When the best claimant cannot be paid (it takes no less than more
    /// than its price here), the next one that can is paid.
    #[tokio::test]
    async fn a_fundable_claimant_is_paid_when_the_best_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let (fast, flaky) = fast_and_flaky(&node, &store).await;
        let uid = queue(&node, &store, 4, 4).await;
        let picky = Claimant {
            min_mc: 1000,
            ..claim_of(fast, &[])
        };
        let got = arbiter.round(&[picky, claim_of(flaky, &[])]).await.unwrap();
        assert!(got[0].is_none());
        let g = got[1].as_ref().unwrap();
        assert_eq!((g.job_uid.as_str(), g.price_mc), (uid.as_str(), 20));
        let h = handout_of(&store, &uid).await;
        assert_eq!(h.reason, crate::scan::handout::Reason::Cheapest);
    }

    /// The next best is another scanner, not a second claim of the same.
    #[tokio::test]
    async fn the_next_best_is_another_scanner() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let (fast, flaky) = fast_and_flaky(&node, &store).await;
        let uid = queue(&node, &store, 4, 4).await;
        arbiter
            .round(&[
                claim_of(fast, &[]),
                claim_of(fast, &[]),
                claim_of(flaky, &[]),
            ])
            .await
            .unwrap();
        let h = handout_of(&store, &uid).await;
        assert_eq!((h.scanner, h.next.map(|n| n.0)), (fast, Some(flaky)));
    }

    /// A member scanner priced at 0, with this node's copy of its price:
    /// granted at zero, without credits.
    async fn zero_scanner(node: &Node) -> NodeId {
        use crate::credits::price::{Limit, ScannerCapacity, ScannerPrice};
        let id = remote_scanner(node, 0).await;
        let mut t = (*node.price_table()).clone();
        t.scanners.push(ScannerPrice {
            node: id,
            price_mc: 0,
            paid: 0.0,
            supply: 0.0,
        });
        t.capacity.scanners.push(ScannerCapacity {
            node: id,
            can_do: 100.0,
            did: 0.0,
            limited_by: Limit::PerHour,
        });
        node.set_price_table(Arc::new(t));
        id
    }

    #[tokio::test]
    async fn a_zero_priced_scanner_is_granted_without_an_offer() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let free = zero_scanner(&node).await;
        let uid = queue(&node, &store, 2, 2).await;
        let g = arbiter.next_job(free, &[], 0).await.unwrap();
        assert_eq!(
            (g.job_uid.as_str(), g.offer_seq, g.price_mc),
            (uid.as_str(), None, 0)
        );
        let h = handout_of(&store, &uid).await;
        assert_eq!(h.reason, crate::scan::handout::Reason::Cheapest);
    }

    #[tokio::test]
    async fn a_scanner_announcing_zero_is_granted_before_this_node_has_a_copy() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        // No `references`: this node has no copy of its price yet.
        let fresh = remote_scanner(&node, 0).await;
        let pricey = remote_scanner(&node, 40).await;
        let uid = queue(&node, &store, 2, 2).await;
        assert!(
            arbiter.next_job(pricey, &[], 0).await.is_none(),
            "40 cannot be capped yet"
        );
        let g = arbiter.next_job(fresh, &[], 0).await.unwrap();
        assert_eq!((g.job_uid.as_str(), g.price_mc), (uid.as_str(), 0));
    }

    #[tokio::test]
    async fn a_job_nobody_can_be_paid_for_waits() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        // Priced, but this node holds no credits; and one without a price here.
        let priced = remote_scanner(&node, 30).await;
        references(&node, &[(priced, 30, 100.0)]);
        let unknown = Identity::generate().unwrap().id;
        let uid = queue(&node, &store, 2, 2).await;
        let got = arbiter
            .round(&[claim_of(priced, &[]), claim_of(unknown, &[])])
            .await
            .unwrap();
        assert!(got.iter().all(Option::is_none), "{got:?}");
        assert_eq!(status(&store, &uid).await, "queued");
    }

    /// The lowest idle scanner adopts a live arbiter's stale running job,
    /// whose scan cannot still be running, but not its stale queued job:
    /// that waits for its arbiter's funding.
    #[tokio::test]
    async fn a_live_arbiters_queued_jobs_are_not_adopted() {
        let dir = tempfile::tempdir().unwrap();
        let (node, _arbiter, store, _tx) = setup(dir.path()).await;
        let live = remote_member(&node, "listener", 0).await;
        let ip = store
            .upsert_ip("198.51.100.77".parse().unwrap())
            .await
            .unwrap();
        let old = format!("-{} hours", crate::scan::pace::STALE_RUNNING_HOURS + 1);
        for (uid, status, started) in [("q", "queued", None), ("r", "running", Some(&old))] {
            sqlx::query(
                "INSERT INTO scan_jobs (uid, origin, arbiter, hlc, ip_id, level, status, queued_at,
                                        started_at, scanner)
                 VALUES (?1, ?2, ?2, 1, ?3, 2, ?4, datetime('now', '-1 day'),
                         datetime('now', ?5), CASE WHEN ?5 IS NULL THEN NULL ELSE ?2 END)",
            )
            .bind(uid)
            .bind(&live.0[..])
            .bind(ip.id)
            .bind(status)
            .bind(started)
            .execute(&store.pool)
            .await
            .unwrap();
        }
        takeover_once(
            &node,
            &Recorder::Cluster(node.clone()),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let arbiter_of = |uid: &'static str| {
            let store = store.clone();
            async move {
                let a: Vec<u8> = sqlx::query_scalar("SELECT arbiter FROM scan_jobs WHERE uid = ?")
                    .bind(uid)
                    .fetch_one(&store.pool)
                    .await
                    .unwrap();
                NodeId::from_slice(&a).unwrap()
            }
        };
        assert_eq!(arbiter_of("q").await, live, "queued: waits for its arbiter");
        assert_eq!(arbiter_of("r").await, node.id(), "stale running: adopted");
    }
}
