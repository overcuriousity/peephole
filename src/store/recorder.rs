//! Writes to replicated tables. A [`Recorder`] turns each change into
//! records: applied directly on a standalone node, appended to the signed
//! log (and so replicated) in a cluster. Reads go to the [`Store`].
use super::Store;
use super::data::{self, Ctx, new_uid, now_ts};
use super::requests::NewRequest;
use super::scans::{EnqueueOutcome, ScanJobRow};
use crate::cluster::Node;
use crate::cluster::hlc::Hlc;
use crate::cluster::record::{
    FingerprintRec, FpClaimRec, IpEnrichRec, JobStatusRec, PortRec, Record, RequestRec, ScanJobRec,
    ScanResultRec, TombTarget, TombstoneRec,
};
use crate::scan::nmap_xml::ScanResult;
use anyhow::{Context, Result};
use std::sync::Arc;

/// Clock for standalone writes (LWW columns need an HLC there too).
static LOCAL_HLC: Hlc = Hlc::new();

#[derive(Clone)]
pub enum Recorder {
    Local(Store),
    Cluster(Arc<Node>),
}

/// Rows per tombstone record in bulk deletes.
const TOMB_CHUNK: usize = 500;

impl Recorder {
    pub fn store(&self) -> &Store {
        match self {
            Recorder::Local(s) => s,
            Recorder::Cluster(n) => &n.store,
        }
    }

    /// The cluster node, in distributed mode.
    pub fn node(&self) -> Option<&Arc<Node>> {
        match self {
            Recorder::Local(_) => None,
            Recorder::Cluster(n) => Some(n),
        }
    }

    /// This node's key in a cluster.
    pub fn node_id(&self) -> Option<crate::cluster::identity::NodeId> {
        match self {
            Recorder::Local(_) => None,
            Recorder::Cluster(n) => Some(n.id()),
        }
    }

    /// SQL condition selecting jobs this node arbitrates, plus its bind.
    fn own_jobs(&self) -> (&'static str, Option<Vec<u8>>) {
        match self {
            Recorder::Local(_) => ("arbiter IS NULL", None),
            Recorder::Cluster(n) => ("arbiter = ?", Some(n.id().0.to_vec())),
        }
    }

    /// Apply (standalone) or append (cluster) records atomically.
    pub async fn write(&self, records: Vec<Record>) -> Result<()> {
        match self {
            Recorder::Local(s) => {
                let mut tx = s.pool.begin_with("BEGIN IMMEDIATE").await?;
                for r in &records {
                    let ctx = Ctx {
                        origin: None,
                        hlc: LOCAL_HLC.now(),
                    };
                    data::apply(&mut tx, ctx, r).await?;
                }
                tx.commit().await?;
            }
            Recorder::Cluster(n) => {
                crate::cluster::repl::append(n, &records).await?;
            }
        }
        Ok(())
    }

    async fn ip_of(&self, ip_id: i64) -> Result<String> {
        sqlx::query_scalar("SELECT ip FROM ips WHERE id = ?")
            .bind(ip_id)
            .fetch_optional(&self.store().pool)
            .await?
            .with_context(|| format!("ip {ip_id} not found"))
    }

    async fn id_by_uid(&self, table: &'static str, uid: &str) -> Result<i64> {
        let sql = format!("SELECT id FROM {table} WHERE uid = ?");
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(uid)
            .fetch_optional(&self.store().pool)
            .await?
            .with_context(|| format!("{table} {uid} was not stored"))
    }

    async fn uid_by_id(&self, table: &'static str, id: i64) -> Result<Option<String>> {
        let sql = format!("SELECT uid FROM {table} WHERE id = ?");
        Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(id)
            .fetch_optional(&self.store().pool)
            .await?
            .flatten())
    }

    /// Record a request from the IP `n.ip_id`. Returns the request id.
    pub async fn insert_request(&self, n: &NewRequest) -> Result<i64> {
        let uid = new_uid();
        self.write(vec![Record::Request(RequestRec {
            uid: uid.clone(),
            ts: now_ts(),
            ip: self.ip_of(n.ip_id).await?,
            method: n.method.clone(),
            path: n.path.clone(),
            query: n.query.clone(),
            headers_json: n.headers_json.clone(),
            body: n.body.clone(),
            labels_json: n.labels_json.clone(),
            severity: n.severity,
            scan_level: n.scan_level,
            is_fp_claim: n.is_fp_claim,
            page_token: n.page_token.clone(),
        })])
        .await?;
        self.id_by_uid("requests", &uid).await
    }

    /// Set GeoIP / Tor facts for an IP, writing only if they changed.
    pub async fn enrich_ip(
        &self,
        ip_id: i64,
        country: Option<&str>,
        asn: Option<u32>,
        asn_org: Option<&str>,
        tor: bool,
    ) -> Result<()> {
        let cur: Option<data::IpFacts<String>> =
            sqlx::query_as("SELECT ip, country, asn, asn_org, is_tor_exit FROM ips WHERE id = ?")
                .bind(ip_id)
                .fetch_optional(&self.store().pool)
                .await?;
        let Some((ip, c, a, o, t)) = cur else {
            return Ok(());
        };
        let asn = asn.map(i64::from);
        if c.as_deref() == country && a == asn && o.as_deref() == asn_org && t == tor {
            return Ok(());
        }
        self.write(vec![Record::IpEnrich(IpEnrichRec {
            ip,
            country: country.map(str::to_string),
            asn,
            asn_org: asn_org.map(str::to_string),
            tor,
        })])
        .await
    }

    pub async fn insert_fp_claim(
        &self,
        ip_id: i64,
        request_id: i64,
        email: Option<&str>,
        ua: &str,
    ) -> Result<()> {
        let request_uid = self
            .uid_by_id("requests", request_id)
            .await?
            .context("claim for an unknown request")?;
        self.write(vec![Record::FpClaim(FpClaimRec {
            uid: new_uid(),
            request_uid,
            ip: self.ip_of(ip_id).await?,
            ts: now_ts(),
            contact_email: email.map(str::to_string),
            user_agent: Some(ua.to_string()),
        })])
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_fingerprint(
        &self,
        request_id: Option<i64>,
        ip_id: i64,
        fp_hash: &str,
        visitor_id: Option<&str>,
        attributes_json: &str,
        behavior_summary_json: &str,
        event_blob: &[u8],
    ) -> Result<i64> {
        let request_uid = match request_id {
            Some(id) => self.uid_by_id("requests", id).await?,
            None => None,
        };
        let uid = new_uid();
        self.write(vec![Record::Fingerprint(FingerprintRec {
            uid: uid.clone(),
            request_uid,
            ip: self.ip_of(ip_id).await?,
            ts: now_ts(),
            fp_hash: Some(fp_hash.to_string()),
            visitor_id: visitor_id.map(str::to_string),
            attributes_json: Some(attributes_json.to_string()),
            behavior_summary_json: Some(behavior_summary_json.to_string()),
            event_blob: Some(zstd::encode_all(event_blob, 3)?),
        })])
        .await?;
        self.id_by_uid("fingerprints", &uid).await
    }

    /// Cooldown (spec §5): a finished scan of level >= requested within the
    /// window suppresses; a higher requested level upgrades exactly once.
    /// Checked against every job in the (replicated) database.
    pub async fn enqueue_scan(
        &self,
        ip_id: i64,
        level: u8,
        cooldown_hours: i64,
    ) -> Result<EnqueueOutcome> {
        if level == 0 {
            return Ok(EnqueueOutcome::Suppressed);
        }
        let pool = &self.store().pool;
        let recent: Option<(i64,)> = sqlx::query_as(
            "SELECT level FROM scan_jobs WHERE ip_id = ? AND status IN ('done','failed')
             AND finished_at > datetime('now', ?) ORDER BY level DESC LIMIT 1",
        )
        .bind(ip_id)
        .bind(format!("-{cooldown_hours} hours"))
        .fetch_optional(pool)
        .await?;
        if let Some((last_level,)) = recent
            && (level as i64) <= last_level
        {
            return Ok(EnqueueOutcome::Cooldown);
        }
        // A job for this IP is already queued or running. Rather than drop a
        // higher-severity request (which would leave the IP under-scanned until
        // the cooldown lapses), raise the level it will be scanned at.
        let max_pending: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(level) FROM scan_jobs WHERE ip_id = ? AND status IN ('queued','running')",
        )
        .bind(ip_id)
        .fetch_one(pool)
        .await?;
        if let Some(max_pending) = max_pending {
            if (level as i64) <= max_pending {
                // An equal or higher-scope scan is already pending.
                return Ok(EnqueueOutcome::Cooldown);
            }
            match self {
                Recorder::Local(_) => {
                    // Upgrade the queued job in place.
                    let r = sqlx::query(
                        "UPDATE scan_jobs SET level = ?
                         WHERE ip_id = ? AND status = 'queued' AND level < ?",
                    )
                    .bind(level as i64)
                    .bind(ip_id)
                    .bind(level as i64)
                    .execute(pool)
                    .await?;
                    if r.rows_affected() > 0 {
                        let id: i64 = sqlx::query_scalar(
                            "SELECT id FROM scan_jobs WHERE ip_id = ? AND status = 'queued'
                             ORDER BY level DESC LIMIT 1",
                        )
                        .bind(ip_id)
                        .fetch_one(pool)
                        .await?;
                        return Ok(EnqueueOutcome::Queued(id));
                    }
                    // Only a running job covers it; let it finish, then cooldown.
                    return Ok(EnqueueOutcome::Cooldown);
                }
                Recorder::Cluster(_) => {
                    // Queue a fresh higher-level job; the arbiter runs it first
                    // (ORDER BY level DESC) and the lower one is superseded by
                    // the scanner's duplicate check once the higher completes.
                }
            }
        }
        let uid = new_uid();
        self.write(vec![Record::ScanJob(ScanJobRec {
            uid: uid.clone(),
            ip: self.ip_of(ip_id).await?,
            level: level as i64,
            queued_at: now_ts(),
        })])
        .await?;
        Ok(EnqueueOutcome::Queued(
            self.id_by_uid("scan_jobs", &uid).await?,
        ))
    }

    /// Jobs this node started in the last hour, whatever their outcome: the
    /// rate cap limits nmap launches, so failed and running scans count too.
    pub async fn jobs_started_last_hour(&self) -> Result<i64> {
        let (cond, bind) = match self {
            Recorder::Local(_) => ("arbiter IS NULL", None),
            Recorder::Cluster(n) => ("scanner = ?", Some(n.id().0.to_vec())),
        };
        let sql = format!(
            "SELECT COUNT(*) FROM scan_jobs WHERE started_at > datetime('now','-1 hour') AND {cond}"
        );
        let mut q = sqlx::query_scalar(sqlx::AssertSqlSafe(sql));
        if let Some(b) = bind {
            q = q.bind(b);
        }
        Ok(q.fetch_one(&self.store().pool).await?)
    }

    async fn status(&self, job_uid: &str, f: JobStatusRec) -> Result<()> {
        debug_assert_eq!(job_uid, f.job_uid);
        self.write(vec![Record::JobStatus(f)]).await
    }

    /// Take the next queued job this node arbitrates and mark it running.
    pub async fn next_queued_job(&self) -> Result<Option<ScanJobRow>> {
        let (cond, bind) = self.own_jobs();
        let sql = format!(
            "SELECT id, ip_id, level, status, queued_at, started_at, finished_at, attempts, error
             FROM scan_jobs WHERE status = 'queued' AND {cond}
             ORDER BY level DESC, queued_at ASC LIMIT 1"
        );
        let mut q = sqlx::query_as::<_, ScanJobRow>(sqlx::AssertSqlSafe(sql));
        if let Some(b) = bind {
            q = q.bind(b);
        }
        let Some(job) = q.fetch_optional(&self.store().pool).await? else {
            return Ok(None);
        };
        let uid = self
            .uid_by_id("scan_jobs", job.id)
            .await?
            .context("job without uid")?;
        self.status(
            &uid,
            JobStatusRec {
                job_uid: uid.clone(),
                status: "running".into(),
                started_at: Some(now_ts()),
                finished_at: None,
                error: None,
                attempts: job.attempts + 1,
                scanner: self.node_id(),
            },
        )
        .await?;
        Ok(Some(job))
    }

    /// Record a scan's outcome. Errors if the job no longer exists.
    pub async fn finish_job(
        &self,
        job_id: i64,
        result: Option<&ScanResult>,
        error: Option<&str>,
    ) -> Result<()> {
        type Job = (Option<String>, String, i64, Option<String>, i64);
        let job: Job = sqlx::query_as(
            "SELECT j.uid, i.ip, j.level, j.started_at, j.attempts
             FROM scan_jobs j JOIN ips i ON i.id = j.ip_id WHERE j.id = ?",
        )
        .bind(job_id)
        .fetch_optional(&self.store().pool)
        .await?
        .with_context(|| format!("job {job_id} not found"))?;
        let (uid, ip, level, started_at, attempts) = job;
        let uid = uid.context("job without uid")?;
        let now = now_ts();
        let mut records = vec![];
        if let Some(res) = result {
            records.push(Record::ScanResult(ScanResultRec {
                uid: new_uid(),
                job_uid: uid.clone(),
                ip,
                level,
                started_at: started_at.clone().unwrap_or_else(|| now.clone()),
                finished_at: Some(now.clone()),
                os_guess: res.os_guess.clone(),
                raw_xml: Some(zstd::encode_all(res.raw_xml.as_slice(), 3)?),
                ports: res
                    .ports
                    .iter()
                    .map(|p| PortRec {
                        port: p.port as i64,
                        proto: p.proto.clone(),
                        state: p.state.clone(),
                        service: p.service.clone(),
                        product: p.product.clone(),
                        version: p.version.clone(),
                    })
                    .collect(),
            }));
        }
        records.push(Record::JobStatus(JobStatusRec {
            job_uid: uid,
            status: if result.is_some() { "done" } else { "failed" }.into(),
            started_at,
            finished_at: Some(now),
            error: if result.is_some() {
                None
            } else {
                error.map(str::to_string)
            },
            attempts,
            scanner: self.node_id(),
        }));
        self.write(records).await
    }

    /// Store the result of a scan this node ran for another arbiter's job
    /// (the arbiter records the job's state).
    pub async fn record_scan_result(
        &self,
        job_uid: &str,
        ip: &str,
        level: i64,
        started_at: &str,
        res: &ScanResult,
    ) -> Result<()> {
        self.write(vec![Record::ScanResult(ScanResultRec {
            uid: new_uid(),
            job_uid: job_uid.to_string(),
            ip: ip.to_string(),
            level,
            started_at: started_at.to_string(),
            finished_at: Some(now_ts()),
            os_guess: res.os_guess.clone(),
            raw_xml: Some(zstd::encode_all(res.raw_xml.as_slice(), 3)?),
            ports: res
                .ports
                .iter()
                .map(|p| PortRec {
                    port: p.port as i64,
                    proto: p.proto.clone(),
                    state: p.state.clone(),
                    service: p.service.clone(),
                    product: p.product.clone(),
                    version: p.version.clone(),
                })
                .collect(),
        })])
        .await
    }

    /// Requeue failed jobs on every arbiter: ours directly, the others'
    /// by asking them. Returns how many were requeued (as far as known).
    pub async fn requeue_failed_everywhere(&self, days: i64) -> Result<u64> {
        let mut n = self.requeue_failed_jobs(days).await?;
        if let Recorder::Cluster(node) = self {
            let others: Vec<_> = node
                .members()
                .keys()
                .copied()
                .filter(|id| *id != node.id())
                .collect();
            let asks = others.into_iter().map(|id| {
                let node = node.clone();
                async move {
                    node.request(
                        id,
                        crate::cluster::msg::Msg::RequeueFailed { days },
                        std::time::Duration::from_secs(10),
                    )
                    .await
                }
            });
            for r in futures::future::join_all(asks).await {
                if let Ok(crate::cluster::msg::Msg::RequeueReply { n: m }) = r {
                    n += m;
                }
            }
        }
        Ok(n)
    }

    /// Requeue the jobs selected by `sql` (uid, started_at kept or not).
    async fn requeue(&self, sql: String, bind_days: Option<String>, clear: bool) -> Result<u64> {
        let (_, own) = self.own_jobs();
        type Row = (String, Option<String>, Option<String>, i64);
        let mut q = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql));
        if let Some(d) = bind_days {
            q = q.bind(d);
        }
        if let Some(b) = own {
            q = q.bind(b);
        }
        let rows = q.fetch_all(&self.store().pool).await?;
        let n = rows.len() as u64;
        let records = rows
            .into_iter()
            .map(|(uid, finished_at, error, attempts)| {
                Record::JobStatus(JobStatusRec {
                    job_uid: uid,
                    status: "queued".into(),
                    started_at: None,
                    finished_at: if clear { None } else { finished_at },
                    error: if clear { None } else { error },
                    attempts,
                    scanner: None,
                })
            })
            .collect::<Vec<_>>();
        if !records.is_empty() {
            self.write(records).await?;
        }
        Ok(n)
    }

    /// Jobs left `running` by a crash or restart go back to the queue;
    /// otherwise they block their IP from ever being scanned again.
    pub async fn requeue_orphaned_jobs(&self) -> Result<u64> {
        let (cond, _) = self.own_jobs();
        self.requeue(
            format!(
                "SELECT uid, finished_at, error, attempts FROM scan_jobs
                 WHERE status = 'running' AND uid IS NOT NULL AND {cond}"
            ),
            None,
            false,
        )
        .await
    }

    /// Put jobs that failed in the last `days` back in the queue, unless
    /// their IP already has a pending job. Returns how many were requeued.
    pub async fn requeue_failed_jobs(&self, days: i64) -> Result<u64> {
        let (cond, _) = self.own_jobs();
        self.requeue(
            format!(
                "SELECT uid, finished_at, error, attempts FROM scan_jobs
                 WHERE status = 'failed' AND finished_at > datetime('now', ?) AND uid IS NOT NULL
                   AND NOT EXISTS (SELECT 1 FROM scan_jobs p WHERE p.ip_id = scan_jobs.ip_id
                                   AND p.status IN ('queued','running'))
                   AND id = (SELECT MAX(f.id) FROM scan_jobs f
                             WHERE f.ip_id = scan_jobs.ip_id AND f.status = 'failed')
                   AND {cond}"
            ),
            Some(format!("-{days} days")),
            true,
        )
        .await
    }

    fn tomb(target: TombTarget) -> Record {
        Record::Tombstone(TombstoneRec {
            uid: new_uid(),
            target,
        })
    }

    pub async fn delete_request(&self, id: i64) -> Result<bool> {
        let Some(uid) = self.uid_by_id("requests", id).await? else {
            return Ok(false);
        };
        self.write(vec![Self::tomb(TombTarget::Requests { uids: vec![uid] })])
            .await?;
        Ok(true)
    }

    /// Delete many requests (and their claims/fingerprints) atomically.
    pub async fn delete_requests(&self, ids: &[i64]) -> Result<u64> {
        let mut uids = vec![];
        for id in ids {
            if let Some(u) = self.uid_by_id("requests", *id).await? {
                uids.push(u);
            }
        }
        let n = uids.len() as u64;
        let records: Vec<_> = uids
            .chunks(TOMB_CHUNK)
            .map(|c| Self::tomb(TombTarget::Requests { uids: c.to_vec() }))
            .collect();
        if !records.is_empty() {
            self.write(records).await?;
        }
        Ok(n)
    }

    pub async fn delete_ip(&self, ip_id: i64) -> Result<bool> {
        Ok(self.delete_ips(&[ip_id]).await? == 1)
    }

    /// Delete IPs with everything hanging off them, atomically.
    pub async fn delete_ips(&self, ids: &[i64]) -> Result<u64> {
        let mut records = vec![];
        for id in ids {
            if let Ok(ip) = self.ip_of(*id).await {
                records.push(Self::tomb(TombTarget::Ip { ip }));
            }
        }
        let n = records.len() as u64;
        if n > 0 {
            self.write(records).await?;
        }
        Ok(n)
    }

    pub async fn delete_scan(&self, id: i64) -> Result<bool> {
        let Some(uid) = self.uid_by_id("scans", id).await? else {
            return Ok(false);
        };
        self.write(vec![Self::tomb(TombTarget::Scan { uid })])
            .await?;
        Ok(true)
    }

    pub async fn delete_claim(&self, id: i64) -> Result<bool> {
        let Some(uid) = self.uid_by_id("fp_claims", id).await? else {
            return Ok(false);
        };
        self.write(vec![Self::tomb(TombTarget::Claim { uid })])
            .await?;
        Ok(true)
    }
}
