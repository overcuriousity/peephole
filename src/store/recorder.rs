//! Writes to replicated tables. A [`Recorder`] turns each change into
//! records: applied directly on a standalone node, appended to the signed
//! log (and so replicated) in a cluster. Reads go to the [`Store`].
use super::Store;
use super::data::{self, Ctx, new_uid, now_ts};
use super::requests::NewRequest;
use super::scans::{EnqueueOutcome, ScanJobRow};
use crate::cluster::Node;
use crate::cluster::hlc::Hlc;
use crate::cluster::identity::NodeId;
use crate::cluster::record::{
    FingerprintRec, FpClaimRec, IpIntelRec, JobStatusRec, PortRec, Record, RequestRec, ScanJobRec,
    ScanResultRec, TombstoneRec,
};
use crate::scan::guard::{self, EnqueuePolicy};
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
/// Retention deletes this many requests (with their claims and
/// fingerprints), or rows of another table, per write transaction ...
const PRUNE_CHUNK: usize = 500;
/// ... and pauses this long between two, so the trap's writes waiting for
/// the lock get in (a whole batch at once outlasted their busy timeout).
const PRUNE_PAUSE: std::time::Duration = std::time::Duration::from_millis(50);

/// `v` with the null-valued keys of an object removed.
fn without_nulls(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(m) = v.as_object_mut() {
        m.retain(|_, x| !x.is_null());
    }
    v
}

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

    /// A fresh uid. In a cluster it carries this node's prefix, which binds
    /// the record to its origin (see `NodeId::uid_prefix`).
    pub(crate) fn uid(&self) -> String {
        match self {
            Recorder::Local(_) => new_uid(),
            Recorder::Cluster(n) => format!("{}{}", n.id().uid_prefix(), new_uid()),
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
        let ip = self.ip_of(n.ip_id).await?;
        Ok(self.insert_request_from(&ip, n).await?.0)
    }

    /// Record a request from `ip`, creating the IP's row if it has none
    /// (the trap's path: one write transaction, no separate IP upsert).
    /// `n.ip_id` is not used. Returns the request's and the IP's row ids.
    pub async fn insert_request_from(&self, ip: &str, n: &NewRequest) -> Result<(i64, i64)> {
        let uid = self.uid();
        self.write(vec![Record::Request(Box::new(RequestRec {
            build: crate::COMMIT.into(),
            uid: uid.clone(),
            ts: n.ts.clone().unwrap_or_else(now_ts),
            ip: ip.to_string(),
            method: n.method.clone(),
            path: n.path.clone(),
            query: n.query.clone(),
            headers_json: n.headers_json.clone(),
            body: n.body.clone(),
            labels_json: n.labels_json.clone(),
            // `[]` and absent are one stored value; sign the absent form so
            // the record rebuilds from its row byte for byte.
            owasp_json: n.owasp_json.clone().filter(|j| j != "[]"),
            severity: n.severity,
            scan_level: n.scan_level,
            is_fp_claim: n.is_fp_claim,
            page_token: n.page_token.clone(),
            answer: n.answer.clone(),
            status: n.status,
            unrecorded: n.unrecorded,
            transport: n.transport.clone(),
            via_proxy: n.via_proxy,
            raw_head: n.raw_head.clone(),
            tls_client_hello: n.tls_client_hello.clone(),
            ja4: n.ja4.clone(),
            rules: n.rules.clone(),
            decoy_v: n.decoy_v,
            decoy_site: n.decoy_site.clone(),
            held_ms: n.held_ms,
            decoy_in: n.decoy_in.clone(),
        }))])
        .await?;
        sqlx::query_as("SELECT id, ip_id FROM requests WHERE uid = ?")
            .bind(&uid)
            .fetch_optional(&self.store().pool)
            .await?
            .with_context(|| format!("requests {uid} was not stored"))
    }

    /// Record requests from `ip` that the flood gate answered without
    /// recording them in full, as one batch.
    pub async fn insert_skip_batch(
        &self,
        ip: &str,
        dropped: i64,
        rows: Vec<crate::cluster::record::SkipRow>,
    ) -> Result<()> {
        self.write(vec![Record::SkipBatch(
            crate::cluster::record::SkipBatchRec {
                build: crate::COMMIT.into(),
                uid: self.uid(),
                ip: ip.to_string(),
                dropped,
                rows,
            },
        )])
        .await
    }

    /// Record one provider's result for an IP. Nothing is written when this
    /// node's last result for it says the same, so a cluster does not
    /// replicate one record per request.
    pub async fn record_intel(
        &self,
        ip: &str,
        provider: &str,
        source_version: Option<&str>,
        data: serde_json::Value,
    ) -> Result<()> {
        let mine = self.node_id().map(|id| id.0.to_vec()).unwrap_or_default();
        let last: Option<String> = sqlx::query_scalar(
            "SELECT data_json FROM ip_intel WHERE ip = ? AND provider = ? AND origin = ?",
        )
        .bind(ip)
        .bind(provider)
        .bind(mine)
        .fetch_optional(&self.store().pool)
        .await?;
        // Compared as JSON without null fields: rows from the migration
        // differ in key order and carry explicit nulls for unknown fields.
        let same = last
            .and_then(|l| serde_json::from_str::<serde_json::Value>(&l).ok())
            .is_some_and(|l| without_nulls(l) == without_nulls(data.clone()));
        if same {
            return Ok(());
        }
        self.record_lookup(ip, provider, source_version, data).await
    }

    /// Record one lookup's result, also when it says the same as the last
    /// one: API lookups are the history of the research dataset.
    pub async fn record_lookup(
        &self,
        ip: &str,
        provider: &str,
        source_version: Option<&str>,
        data: serde_json::Value,
    ) -> Result<()> {
        self.write(vec![Record::IpIntel(IpIntelRec {
            build: crate::COMMIT.into(),
            ip: ip.to_string(),
            provider: provider.to_string(),
            fetched_at: now_ts(),
            source_version: source_version.map(str::to_string),
            data_json: data.to_string(),
        })])
        .await
    }

    /// GeoIP facts as a MaxMind result (fields that are unknown are left out).
    pub fn geo_data(
        country: Option<&str>,
        asn: Option<u32>,
        asn_org: Option<&str>,
    ) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        if let Some(c) = country {
            m.insert("country".into(), c.into());
        }
        if let Some(a) = asn {
            m.insert("asn".into(), a.into());
        }
        if let Some(o) = asn_org {
            m.insert("asn_org".into(), o.into());
        }
        serde_json::Value::Object(m)
    }

    /// Record this node's MaxMind result for an IP. Only the provider that
    /// was consulted is written; other providers' results are not touched.
    pub async fn record_geo(
        &self,
        ip_id: i64,
        source_version: Option<&str>,
        country: Option<&str>,
        asn: Option<u32>,
        asn_org: Option<&str>,
    ) -> Result<()> {
        let Some(ip) = self.find_ip(ip_id).await? else {
            return Ok(());
        };
        self.record_intel(
            &ip,
            crate::intel::MAXMIND,
            source_version,
            Self::geo_data(country, asn, asn_org),
        )
        .await
    }

    /// Record this node's Tor exit list result for an IP.
    pub async fn record_tor(&self, ip_id: i64, exit: bool) -> Result<()> {
        let Some(ip) = self.find_ip(ip_id).await? else {
            return Ok(());
        };
        self.record_intel(
            &ip,
            crate::intel::TOR,
            None,
            serde_json::json!({ "exit": exit }),
        )
        .await
    }

    /// The IP's text, None when the row does not exist.
    async fn find_ip(&self, ip_id: i64) -> Result<Option<String>> {
        Ok(sqlx::query_scalar("SELECT ip FROM ips WHERE id = ?")
            .bind(ip_id)
            .fetch_optional(&self.store().pool)
            .await?)
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
            build: crate::COMMIT.into(),
            uid: self.uid(),
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
        let ip = self.ip_of(ip_id).await?;
        self.insert_fingerprint_from(
            &ip,
            request_id,
            fp_hash,
            visitor_id,
            attributes_json,
            behavior_summary_json,
            event_blob,
        )
        .await
    }

    /// [`Recorder::insert_fingerprint`] from `ip`, creating the IP's row if
    /// it has none (as [`Recorder::insert_request_from`]).
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_fingerprint_from(
        &self,
        ip: &str,
        request_id: Option<i64>,
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
        let uid = self.uid();
        self.write(vec![Record::Fingerprint(FingerprintRec {
            build: crate::COMMIT.into(),
            uid: uid.clone(),
            request_uid,
            ip: ip.to_string(),
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

    /// [`Recorder::enqueue_scan_with`] with only the per-IP cooldown.
    pub async fn enqueue_scan(
        &self,
        ip_id: i64,
        level: u8,
        cooldown_hours: i64,
    ) -> Result<EnqueueOutcome> {
        self.enqueue_scan_with(ip_id, level, &EnqueuePolicy::cooldown_only(cooldown_hours))
            .await
    }

    /// Cooldown (spec §5): a finished or refused scan of level >= requested
    /// within the window suppresses; a higher requested level upgrades
    /// exactly once.
    /// Checked against every job in the (replicated) database.
    ///
    /// With `policy.safety` (the trap's policy, see [`crate::scan::guard`]):
    /// thin evidence caps the level; a new job must fit the /24-/64 and ASN
    /// budgets; a full queue drops its oldest lowest-level job for a
    /// higher-level one, and otherwise refuses the new one.
    pub async fn enqueue_scan_with(
        &self,
        ip_id: i64,
        level: u8,
        policy: &EnqueuePolicy,
    ) -> Result<EnqueueOutcome> {
        if !(1..=4).contains(&level) {
            if level != 0 {
                tracing::warn!(level, "scan level out of range; not queued");
            }
            return Ok(EnqueueOutcome::Suppressed);
        }
        let cooldown_hours = policy.cooldown_hours;
        let pool = &self.store().pool;
        let ip_text = self.ip_of(ip_id).await?;
        let mut level = level;
        // Stored verdicts as they are: the scanner that takes the job
        // classifies the requests again before it runs it.
        if let Some(s) = &policy.safety
            && level > s.single_request_max_level
            && guard::evidence(pool, &ip_text, &guard::Origins::Any, None)
                .await?
                .thin(s)
        {
            level = s.single_request_max_level;
        }
        // A refusal (crawler, member, never_scan, Tor exit, ...) holds as
        // long as a scan would, or every request would queue the IP again;
        // a job dropped from a full queue says nothing about the IP.
        let recent: Option<(i64,)> = sqlx::query_as(
            "SELECT level FROM scan_jobs WHERE ip_id = ?
             AND (status IN ('done','failed')
                  OR (status = 'refused' AND COALESCE(error, '') NOT LIKE 'dropped:%'))
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
        // A job "running" for longer than any scan may take is dead (its
        // arbiter is gone or never finishes it) and shields nothing.
        let max_pending: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(level) FROM scan_jobs WHERE ip_id = ? AND (status = 'queued'
               OR (status = 'running' AND started_at > datetime('now', ?)
                   AND started_at <= datetime('now', '+10 minutes')))",
        )
        .bind(ip_id)
        .bind(format!("-{} hours", crate::scan::pace::STALE_RUNNING_HOURS))
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
        if let Some(s) = &policy.safety
            && let Some(why) = self
                .over_budget(ip_id, &ip_text, level, s, cooldown_hours)
                .await?
        {
            tracing::debug!(ip = %ip_text, why, "scan not queued");
            return Ok(EnqueueOutcome::Throttled(why));
        }
        let uid = self.uid();
        self.write(vec![Record::ScanJob(ScanJobRec {
            uid: uid.clone(),
            ip: ip_text,
            level: level as i64,
            queued_at: now_ts(),
            retry_of: None,
            retry_at: None,
            failed_by: None,
            manual: false,
        })])
        .await?;
        Ok(EnqueueOutcome::Queued(
            self.id_by_uid("scan_jobs", &uid).await?,
        ))
    }

    /// A scan an admin bought on the Actions card: queued without the
    /// cooldown, evidence or budget checks (those are the automatic
    /// queue's); the marker lets every scanner skip its evidence
    /// re-check and the arbiter fund it at the level-scaled price.
    pub async fn enqueue_manual(&self, ip_id: i64, level: u8) -> Result<EnqueueOutcome> {
        if !(1..=4).contains(&level) {
            return Ok(EnqueueOutcome::Suppressed);
        }
        let ip_text = self.ip_of(ip_id).await?;
        let uid = self.uid();
        self.write(vec![Record::ScanJob(ScanJobRec {
            uid: uid.clone(),
            ip: ip_text,
            level: level as i64,
            queued_at: now_ts(),
            retry_of: None,
            retry_at: None,
            failed_by: None,
            manual: true,
        })])
        .await?;
        Ok(EnqueueOutcome::Queued(
            self.id_by_uid("scan_jobs", &uid).await?,
        ))
    }

    /// Why a new job for this IP does not fit the queue budgets, if it does
    /// not. A full queue makes room by refusing its oldest lowest-level job
    /// when that is below `level`.
    async fn over_budget(
        &self,
        ip_id: i64,
        ip: &str,
        level: u8,
        s: &crate::config::ScanSafety,
        cooldown_hours: i64,
    ) -> Result<Option<&'static str>> {
        let pool = &self.store().pool;
        if s.prefix_max_scans > 0
            && cooldown_hours > 0
            && guard::queued_in_network(pool, ip, cooldown_hours).await?
                >= s.prefix_max_scans as usize
        {
            return Ok(Some("network budget (/24 or /64) used up"));
        }
        if s.asn_max_per_hour > 0 {
            let asn: Option<i64> = sqlx::query_scalar("SELECT asn FROM ips WHERE id = ?")
                .bind(ip_id)
                .fetch_optional(pool)
                .await?
                .flatten();
            if let Some(asn) = asn
                && guard::queued_in_asn_last_hour(pool, asn).await? >= s.asn_max_per_hour as i64
            {
                return Ok(Some("hourly ASN budget used up"));
            }
        }
        if s.max_queued > 0 {
            let (cond, own) = self.own_jobs();
            let sql = format!("SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued' AND {cond}");
            let mut q = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql));
            if let Some(b) = &own {
                q = q.bind(b.clone());
            }
            if q.fetch_one(pool).await? >= s.max_queued as i64 {
                let sql = format!(
                    "SELECT uid, attempts FROM scan_jobs WHERE status = 'queued' AND {cond}
                       AND level < ? ORDER BY level ASC, queued_at ASC LIMIT 1"
                );
                let mut q = sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(sql));
                if let Some(b) = own {
                    q = q.bind(b);
                }
                let Some((uid, attempts)) = q.bind(level as i64).fetch_optional(pool).await? else {
                    return Ok(Some("scan queue full"));
                };
                self.write(vec![Record::JobStatus(JobStatusRec {
                    job_uid: uid,
                    status: "refused".into(),
                    started_at: None,
                    finished_at: Some(now_ts()),
                    error: Some("dropped: scan queue full".into()),
                    attempts,
                    scanner: None,
                })])
                .await?;
            }
        }
        Ok(None)
    }

    /// Mark a queued job this node arbitrates as running (standalone
    /// scanner). False when it is no longer queued.
    pub async fn start_job(&self, job_id: i64) -> Result<bool> {
        let row: Option<(Option<String>, String, i64)> =
            sqlx::query_as("SELECT uid, status, attempts FROM scan_jobs WHERE id = ?")
                .bind(job_id)
                .fetch_optional(&self.store().pool)
                .await?;
        let Some((Some(uid), status, attempts)) = row else {
            return Ok(false);
        };
        if status != "queued" {
            return Ok(false);
        }
        self.status(
            &uid.clone(),
            JobStatusRec {
                job_uid: uid,
                status: "running".into(),
                started_at: Some(now_ts()),
                finished_at: None,
                error: None,
                attempts: attempts + 1,
                scanner: self.node_id(),
            },
        )
        .await?;
        Ok(true)
    }

    /// Refuse a job before it ran (standalone scanner): it never started,
    /// so it does not count against the hourly rate.
    pub async fn refuse_job(&self, job_id: i64, why: &str) -> Result<()> {
        let row: Option<(Option<String>, i64)> =
            sqlx::query_as("SELECT uid, attempts FROM scan_jobs WHERE id = ?")
                .bind(job_id)
                .fetch_optional(&self.store().pool)
                .await?;
        let Some((Some(uid), attempts)) = row else {
            return Ok(());
        };
        self.status(
            &uid.clone(),
            JobStatusRec {
                job_uid: uid,
                status: "refused".into(),
                started_at: None,
                finished_at: Some(now_ts()),
                error: Some(why.to_string()),
                attempts,
                scanner: None,
            },
        )
        .await
    }

    /// Jobs this node started in the last hour: the rate cap limits nmap
    /// launches, so failed and running scans count too. Jobs refused or
    /// superseded before nmap ran do not (in a cluster the arbiter stamps a
    /// start time when it grants a job the scanner then turns down).
    pub async fn jobs_started_last_hour(&self) -> Result<i64> {
        let (cond, bind) = match self {
            Recorder::Local(_) => ("arbiter IS NULL", None),
            Recorder::Cluster(n) => ("scanner = ?", Some(n.id().0.to_vec())),
        };
        let sql = format!(
            "SELECT COUNT(*) FROM scan_jobs WHERE started_at > datetime('now','-1 hour')
               AND status NOT IN ('refused','superseded') AND {cond}"
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
               AND (retry_at IS NULL OR retry_at <= datetime('now'))
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
                build: crate::COMMIT.into(),
                uid: self.uid(),
                job_uid: uid.clone(),
                ip,
                level,
                started_at: started_at.clone().unwrap_or_else(|| now.clone()),
                finished_at: Some(now.clone()),
                os_guess: res.os_guess.clone(),
                raw_xml: Some(zstd::encode_all(res.raw_xml.as_slice(), 3)?),
                scrubbed: res.scrubbed,
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
            job_uid: uid.clone(),
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
        self.write(records).await?;
        if result.is_none() {
            self.retry_failed(&uid, self.node_id()).await?;
        }
        Ok(())
    }

    /// Queue a retry of the failed job `job_uid` this node arbitrates (see
    /// [`crate::scan::retry`]), `failed_by` the scanner that ran it. Returns
    /// the retry's uid; None when the failure is not retried: the error rules
    /// it out, the window is over, or a pending job or a scan done since the
    /// first failure covers the IP at this level.
    pub async fn retry_failed(
        &self,
        job_uid: &str,
        failed_by: Option<NodeId>,
    ) -> Result<Option<String>> {
        use crate::scan::retry;
        let pool = &self.store().pool;
        type Job = (
            i64,
            String,
            i64,
            String,
            Option<String>,
            Option<String>,
            i64,
        );
        let job: Option<Job> = sqlx::query_as(
            "SELECT j.ip_id, i.ip, j.level, j.status, j.error, j.retry_of, j.manual
             FROM scan_jobs j JOIN ips i ON i.id = j.ip_id WHERE j.uid = ?",
        )
        .bind(job_uid)
        .fetch_optional(pool)
        .await?;
        let Some((ip_id, ip, level, status, error, retry_of, manual)) = job else {
            return Ok(None);
        };
        if status != "failed" || !retry::retryable(error.as_deref()) {
            return Ok(None);
        }
        let root = retry_of.unwrap_or_else(|| job_uid.to_string());
        let (first, failures): (Option<String>, i64) = sqlx::query_as(
            "SELECT MIN(finished_at), COUNT(*) FROM scan_jobs
             WHERE (uid = ?1 OR retry_of = ?1) AND status = 'failed'",
        )
        .bind(&root)
        .fetch_one(pool)
        .await?;
        let Some(retry_at) = first
            .as_deref()
            .and_then(|f| retry::next_at(f, failures, chrono::Utc::now()))
        else {
            return Ok(None);
        };
        let covered: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_jobs WHERE ip_id = ? AND level >= ?
               AND (status IN ('queued','running') OR (status = 'done' AND finished_at >= ?))",
        )
        .bind(ip_id)
        .bind(level)
        .bind(&first)
        .fetch_one(pool)
        .await?;
        if covered > 0 {
            return Ok(None);
        }
        let uid = self.uid();
        self.write(vec![Record::ScanJob(ScanJobRec {
            uid: uid.clone(),
            ip,
            level,
            queued_at: now_ts(),
            retry_of: Some(root),
            retry_at: Some(retry_at),
            failed_by,
            manual: manual != 0,
        })])
        .await?;
        Ok(Some(uid))
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
            build: crate::COMMIT.into(),
            uid: self.uid(),
            job_uid: job_uid.to_string(),
            ip: ip.to_string(),
            level,
            started_at: started_at.to_string(),
            finished_at: Some(now_ts()),
            os_guess: res.os_guess.clone(),
            raw_xml: Some(zstd::encode_all(res.raw_xml.as_slice(), 3)?),
            scrubbed: res.scrubbed,
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

    /// Publish an audit: this node's own scan of `ip`, run to check the
    /// scan `audit_of` of another node (whose job is `job_uid`).
    pub async fn record_scan_audit(
        &self,
        audit_of: &str,
        job_uid: &str,
        ip: &str,
        level: i64,
        started_at: &str,
        res: &ScanResult,
    ) -> Result<()> {
        self.write(vec![Record::ScanAudit(Box::new(
            crate::cluster::record::ScanAuditRec {
                audit_of: audit_of.to_string(),
                scan: ScanResultRec {
                    build: crate::COMMIT.into(),
                    uid: self.uid(),
                    job_uid: job_uid.to_string(),
                    ip: ip.to_string(),
                    level,
                    started_at: started_at.to_string(),
                    finished_at: Some(now_ts()),
                    os_guess: res.os_guess.clone(),
                    raw_xml: Some(zstd::encode_all(res.raw_xml.as_slice(), 3)?),
                    scrubbed: res.scrubbed,
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
                },
            },
        ))])
        .await
    }

    /// Requeue the jobs selected by `sql` (uid, finished_at, error, attempts).
    async fn requeue(&self, sql: String) -> Result<u64> {
        let (_, own) = self.own_jobs();
        type Row = (String, Option<String>, Option<String>, i64);
        let mut q = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql));
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
                    finished_at,
                    error,
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
        self.requeue(format!(
            "SELECT uid, finished_at, error, attempts FROM scan_jobs
                 WHERE status = 'running' AND uid IS NOT NULL AND {cond}"
        ))
        .await
    }

    /// Uids of `table` rows whose `col` is one of `keys`, split into what
    /// this node originated and what other nodes did. Only the former can be
    /// deleted cluster-wide. A standalone node deletes everything it holds,
    /// rows it got while it was in a cluster included.
    async fn split(
        &self,
        table: &'static str,
        col: &'static str,
        keys: Keys<'_>,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let me = self.node_id().map(|id| id.0.to_vec());
        let local = me.is_none();
        let n = match keys {
            Keys::Ids(k) => k.len(),
            Keys::Uids(k) => k.len(),
        };
        let (mut own, mut other) = (vec![], vec![]);
        for start in (0..n).step_by(400) {
            let end = (start + 400).min(n);
            let sql = format!(
                "SELECT uid, origin FROM {table} WHERE uid IS NOT NULL AND {col} IN ({})",
                vec!["?"; end - start].join(",")
            );
            let mut q = sqlx::query_as::<_, (String, Option<Vec<u8>>)>(sqlx::AssertSqlSafe(sql));
            match keys {
                Keys::Ids(k) => {
                    for v in &k[start..end] {
                        q = q.bind(*v);
                    }
                }
                Keys::Uids(k) => {
                    for v in &k[start..end] {
                        q = q.bind(v.as_str());
                    }
                }
            }
            for (uid, origin) in q.fetch_all(&self.store().pool).await? {
                if local || origin == me {
                    own.push(uid);
                } else {
                    other.push(uid);
                }
            }
        }
        Ok((own, other))
    }

    /// Delete records this node originated, everywhere.
    async fn bury(&self, uids: Vec<String>) -> Result<()> {
        let mut records = vec![];
        for c in uids.chunks(TOMB_CHUNK) {
            let (uids, seqs) = match self {
                Recorder::Local(_) => (c.to_vec(), vec![]),
                // Where each record sits in our log: receivers accept an
                // erased entry only at a position its tombstone names.
                Recorder::Cluster(n) => {
                    let sql = format!(
                        "SELECT uid, seq FROM repl_log
                         WHERE +origin = ? AND kind != 'tombstone' AND uid IN ({})",
                        vec!["?"; c.len()].join(",")
                    );
                    let mut q = sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(sql))
                        .bind(n.id().0.to_vec());
                    for u in c {
                        q = q.bind(u.as_str());
                    }
                    q.fetch_all(&n.store.pool)
                        .await?
                        .into_iter()
                        .map(|(uid, seq)| (uid, seq as u64))
                        .unzip()
                }
            };
            if uids.is_empty() {
                continue;
            }
            records.push(Record::Tombstone(TombstoneRec {
                uid: self.uid(),
                uids,
                seqs,
            }));
        }
        if !records.is_empty() {
            self.write(records).await?;
        }
        Ok(())
    }

    /// Records other nodes originated cannot be deleted from here: they are
    /// hidden on this node only.
    async fn hide(&self, uids: Vec<String>) -> Result<u64> {
        let Recorder::Cluster(n) = self else {
            return Ok(0);
        };
        if uids.is_empty() {
            return Ok(0);
        }
        let _g = n.apply_lock.lock().await;
        let mut tx = n.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let hidden = data::hide(&mut tx, &uids).await?;
        tx.commit().await?;
        Ok(hidden)
    }

    pub async fn delete_request(&self, id: i64) -> Result<Deleted> {
        self.delete_requests(&[id]).await
    }

    /// Delete requests. Ours go cluster-wide, together with our claims and
    /// fingerprints on them.
    pub async fn delete_requests(&self, ids: &[i64]) -> Result<Deleted> {
        let (reqs, foreign) = self.split("requests", "id", Keys::Ids(ids)).await?;
        // Claims and fingerprints go with their request: ours are deleted
        // cluster-wide, other nodes' are hidden here.
        let all: Vec<String> = [&reqs[..], &foreign[..]].concat();
        let (claims, their_claims) = self
            .split("fp_claims", "request_uid", Keys::Uids(&all))
            .await?;
        let (fps, their_fps) = self
            .split("fingerprints", "request_uid", Keys::Uids(&all))
            .await?;
        let (deleted, hidden) = (reqs.len() as u64, foreign.len() as u64);
        self.bury([reqs, claims, fps].concat()).await?;
        // Children first: hiding a request unlinks its fingerprints.
        self.hide([their_fps, their_claims, foreign].concat())
            .await?;
        Ok(Deleted { deleted, hidden })
    }

    /// Whether the IP existed. Everything this node recorded about it is
    /// deleted cluster-wide.
    pub async fn delete_ip(&self, ip_id: i64) -> Result<bool> {
        let existed = self.ip_of(ip_id).await.is_ok();
        self.delete_ips(&[ip_id]).await?;
        Ok(existed)
    }

    /// Delete everything about these IPs, as far as this node recorded it.
    pub async fn delete_ips(&self, ids: &[i64]) -> Result<Deleted> {
        let (mut own, mut foreign) = (vec![], vec![]);
        for table in [
            "requests",
            "fp_claims",
            "fingerprints",
            "scan_jobs",
            "scans",
            "skipped_batches",
            "probes",
        ] {
            let (o, f) = self.split(table, "ip_id", Keys::Ids(ids)).await?;
            own.extend(o);
            foreign.extend(f);
        }
        let deleted = own.len() as u64;
        self.bury(own).await?;
        let hidden = self.hide(foreign).await?;
        // An IP without any record left (or that never had one) goes too;
        // the names that resolved to it are its own rows here and go first,
        // or they alone would keep it.
        let mut conn = self.store().pool.acquire().await?;
        for id in ids {
            sqlx::query("DELETE FROM ip_names WHERE ip_id = ?")
                .bind(id)
                .execute(&mut *conn)
                .await?;
            data::drop_orphan_ip(&mut conn, *id).await?;
        }
        Ok(Deleted { deleted, hidden })
    }

    pub async fn delete_scan(&self, id: i64) -> Result<Deleted> {
        let (own, foreign) = self.split("scans", "id", Keys::Ids(&[id])).await?;
        let deleted = own.len() as u64;
        self.bury(own).await?;
        Ok(Deleted {
            deleted,
            hidden: self.hide(foreign).await?,
        })
    }

    pub async fn delete_claim(&self, id: i64) -> Result<Deleted> {
        let (own, foreign) = self.split("fp_claims", "id", Keys::Ids(&[id])).await?;
        let deleted = own.len() as u64;
        self.bury(own).await?;
        Ok(Deleted {
            deleted,
            hidden: self.hide(foreign).await?,
        })
    }

    /// Retention (standalone nodes): delete requests, with their claims and
    /// fingerprints, scan results, skipped batches, finished jobs and
    /// fingerprints without a request, older than `days`. Bounded per call
    /// so a huge backlog drains over several runs: call again until the
    /// result [`Pruned::is_empty`]. Written in transactions of
    /// [`PRUNE_CHUNK`] rows, [`PRUNE_PAUSE`] apart.
    pub async fn prune_older_than(&self, days: u32) -> Result<Pruned> {
        if days == 0 {
            return Ok(Pruned::default());
        }
        const BATCH: i64 = 20_000;
        let pool = &self.store().pool;
        let cutoff = format!("-{days} days");
        let req_ids: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM requests WHERE ts < datetime('now', ?) ORDER BY id LIMIT ?",
        )
        .bind(&cutoff)
        .bind(BATCH)
        .fetch_all(pool)
        .await?;
        let mut wrote = false;
        let mut pause = async || {
            if std::mem::replace(&mut wrote, true) {
                tokio::time::sleep(PRUNE_PAUSE).await;
            }
        };
        let mut requests = 0;
        for c in req_ids.chunks(PRUNE_CHUNK) {
            pause().await;
            requests += self.delete_requests(c).await?.deleted;
        }
        let mut counts = [0u64; 4];
        for (n, sql) in counts.iter_mut().zip([
            "SELECT uid FROM scans
             WHERE COALESCE(finished_at, started_at) < datetime('now', ?)
             ORDER BY id LIMIT ?",
            "SELECT uid FROM skipped_batches
             WHERE last_ms < CAST(strftime('%s', 'now', ?) AS INTEGER) * 1000
             ORDER BY last_ms LIMIT ?",
            // Fingerprints that never had a request (a /collect with an
            // unknown token): nothing else deletes them, and they keep
            // their IP alive.
            "SELECT uid FROM fingerprints
             WHERE request_id IS NULL AND request_uid IS NULL AND uid IS NOT NULL
               AND ts < datetime('now', ?)
             ORDER BY id LIMIT ?",
            // Finished jobs without a scan left: otherwise they (and their
            // IP rows, which a job keeps alive) would stay forever. After
            // the scans above, so a job whose scan just went follows it.
            "SELECT j.uid FROM scan_jobs j
             WHERE j.status IN ('done', 'failed', 'superseded', 'refused')
               AND COALESCE(j.finished_at, j.queued_at) < datetime('now', ?)
               AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.job_id = j.id)
             ORDER BY j.id LIMIT ?",
        ]) {
            let uids: Vec<String> = sqlx::query_scalar(sql)
                .bind(&cutoff)
                .bind(BATCH)
                .fetch_all(pool)
                .await?;
            *n = uids.len() as u64;
            for c in uids.chunks(PRUNE_CHUNK) {
                pause().await;
                self.bury(c.to_vec()).await?;
            }
        }
        let [scans, skipped_batches, fingerprints, jobs] = counts;
        Ok(Pruned {
            requests,
            scans,
            skipped_batches,
            fingerprints,
            jobs,
        })
    }
}

/// What one [`Recorder::prune_older_than`] pass deleted, per table.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Pruned {
    pub requests: u64,
    pub scans: u64,
    pub skipped_batches: u64,
    pub fingerprints: u64,
    pub jobs: u64,
}

impl Pruned {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Row keys for [`Recorder::split`].
#[derive(Clone, Copy)]
enum Keys<'a> {
    Ids(&'a [i64]),
    Uids(&'a [String]),
}

/// What a delete did, counted in the records that were asked for.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Deleted {
    /// Records this node originated: deleted on every node.
    pub deleted: u64,
    /// Records other nodes originated: hidden on this node only.
    pub hidden: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_manual_job_ignores_the_cooldown_and_is_marked() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let rec = store.local();
        let ip = store
            .upsert_ip("203.0.113.60".parse().unwrap())
            .await
            .unwrap();
        let first = rec.enqueue_manual(ip.id, 2).await.unwrap();
        assert!(matches!(first, EnqueueOutcome::Queued(_)));
        let second = rec.enqueue_manual(ip.id, 2).await.unwrap();
        assert!(matches!(second, EnqueueOutcome::Queued(_)));
        let manual: i64 = sqlx::query_scalar("SELECT manual FROM scan_jobs WHERE ip_id = ?")
            .bind(ip.id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(manual, 1);
    }

    fn req(ip_id: i64) -> NewRequest {
        NewRequest {
            ip_id,
            method: "GET".into(),
            path: "/x".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            severity: 1,
            scan_level: 1,
            ..Default::default()
        }
    }

    /// A refused job holds the cooldown like a scan, so a crawler or a
    /// member is not queued again on every request; a job dropped from a
    /// full queue does not.
    #[tokio::test]
    async fn refused_jobs_hold_the_cooldown() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let rec = store.local();
        let ip = store
            .upsert_ip("198.51.100.30".parse().unwrap())
            .await
            .unwrap();
        let EnqueueOutcome::Queued(job) = rec.enqueue_scan(ip.id, 2, 24).await.unwrap() else {
            panic!("not queued");
        };
        rec.refuse_job(job, "verified crawler (googlebot.com)")
            .await
            .unwrap();
        assert_eq!(
            rec.enqueue_scan(ip.id, 2, 24).await.unwrap(),
            EnqueueOutcome::Cooldown
        );
        assert!(
            matches!(
                rec.enqueue_scan(ip.id, 3, 24).await.unwrap(),
                EnqueueOutcome::Queued(_)
            ),
            "a higher level still queues"
        );
        let other = store
            .upsert_ip("198.51.100.31".parse().unwrap())
            .await
            .unwrap();
        let EnqueueOutcome::Queued(job) = rec.enqueue_scan(other.id, 2, 24).await.unwrap() else {
            panic!("not queued");
        };
        sqlx::query(
            "UPDATE scan_jobs SET status = 'refused', finished_at = datetime('now'),
               error = 'dropped: scan queue full' WHERE id = ?",
        )
        .bind(job)
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(matches!(
            rec.enqueue_scan(other.id, 2, 24).await.unwrap(),
            EnqueueOutcome::Queued(_)
        ));
    }

    /// Retention spans several short transactions; the trap writes in
    /// between, and what it writes stays.
    #[tokio::test]
    async fn retention_deletes_in_short_transactions() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let rec = store.local();
        let ip = store
            .upsert_ip("198.51.100.40".parse().unwrap())
            .await
            .unwrap();
        let old = PRUNE_CHUNK * 2 + 1;
        for _ in 0..old {
            rec.insert_request(&req(ip.id)).await.unwrap();
        }
        sqlx::query("UPDATE requests SET ts = datetime('now', '-100 days')")
            .execute(&store.pool)
            .await
            .unwrap();
        let (pruned, new) = tokio::join!(rec.prune_older_than(90), async {
            tokio::time::sleep(PRUNE_PAUSE / 2).await;
            rec.insert_request(&req(ip.id)).await
        });
        assert_eq!(pruned.unwrap().requests, old as u64);
        let left: Vec<i64> = sqlx::query_scalar("SELECT id FROM requests")
            .fetch_all(&store.pool)
            .await
            .unwrap();
        assert_eq!(left, [new.unwrap()]);
        assert!(rec.prune_older_than(90).await.unwrap().is_empty());
    }
}
