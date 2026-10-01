//! The only writer of replicated rows. Every change to requests, IPs,
//! claims, fingerprints, scan jobs and scans is a [`Record`] applied here —
//! directly on a standalone node, through the replication log in a cluster
//! — so both modes share one set of semantics.
//!
//! Deletes are tombstones: they list the uids to remove, affect only records
//! of the tombstone's own origin, and remember the deleted uids so a record
//! that arrives later is dropped instead of resurrecting.
use crate::cluster::identity::NodeId;
use crate::cluster::record::{
    FingerprintRec, FpClaimRec, IntelManifestRec, IpEnrichRec, JobAdoptRec, JobStatusRec, PortRec,
    ROW_BACKED, Record, RequestRec, ScanJobRec, ScanResultRec, TombstoneRec,
};
use anyhow::Result;
use sqlx::SqliteConnection;

/// Who created the record being applied, and when (HLC).
#[derive(Clone, Copy, Debug)]
pub struct Ctx<'a> {
    /// None on a standalone node.
    pub origin: Option<&'a NodeId>,
    pub hlc: u64,
}

impl Ctx<'_> {
    fn origin_bytes(&self) -> Option<Vec<u8>> {
        self.origin.map(|o| o.0.to_vec())
    }
}

#[derive(Debug, PartialEq)]
pub enum Effect {
    Applied,
    /// Not applied: a tombstone (this uid) already deleted it.
    Erased(String),
    /// Not applied, nothing to remember (stale, or its parent is gone).
    Ignored,
    /// Not applied yet: a parent row (e.g. the scan job for a scan result) has
    /// not replicated here. Kept unapplied so a later pass retries it once the
    /// parent arrives, rather than dropping it permanently.
    Deferred,
}

/// Whether `uid` has been deleted (so a missing parent is gone for good, not
/// merely not-yet-replicated).
async fn is_tombstoned(conn: &mut SqliteConnection, uid: &str) -> Result<bool> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tombstoned WHERE uid = ?")
        .bind(uid)
        .fetch_one(&mut *conn)
        .await?;
    Ok(n > 0)
}

/// UTC timestamp in the rows' format.
pub fn now_ts() -> String {
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn new_uid() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

pub async fn apply(conn: &mut SqliteConnection, ctx: Ctx<'_>, r: &Record) -> Result<Effect> {
    // Hides and blocks only exist in a cluster.
    if ctx.origin.is_some() && CONTENT_KINDS.contains(&r.kind()) {
        if origin_blocked(conn, ctx.origin).await? {
            return Ok(Effect::Ignored);
        }
        if let Some(uid) = r.uid()
            && suppressed(conn, &uid).await?
        {
            return Ok(Effect::Ignored);
        }
    }
    match r {
        Record::Request(r) => request(conn, ctx, r).await,
        Record::IpEnrich(r) => ip_enrich(conn, ctx, r).await,
        Record::FpClaim(r) => fp_claim(conn, ctx, r).await,
        Record::Fingerprint(r) => fingerprint(conn, ctx, r).await,
        Record::ScanJob(r) => scan_job(conn, ctx, r).await,
        Record::JobStatus(r) => job_status(conn, ctx, r).await,
        Record::JobAdopt(r) => job_adopt(conn, ctx, r).await,
        Record::ScanResult(r) => scan_result(conn, ctx, r).await,
        Record::Tombstone(t) => tombstone(conn, ctx, t).await,
        Record::IntelManifest(m) => intel_manifest(conn, ctx, m).await,
        Record::MemberAdd(_) | Record::MemberUpdate(_) | Record::MemberRevoke { .. } => {
            Ok(Effect::Ignored)
        }
    }
}

/// Record kinds a local hide or block keeps out of the tables. Membership,
/// tombstones and scan-job state still apply, so the cluster stays in step.
const CONTENT_KINDS: [&str; 6] = [
    "request",
    "fingerprint",
    "fp_claim",
    "scan_job",
    "scan_result",
    "ip_enrich",
];

async fn origin_blocked(conn: &mut SqliteConnection, origin: Option<&NodeId>) -> Result<bool> {
    let Some(o) = origin else { return Ok(false) };
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocked_peers WHERE id = ?")
        .bind(&o.0[..])
        .fetch_one(&mut *conn)
        .await?;
    Ok(n > 0)
}

/// Whether `uid` is kept out of the tables locally: hidden by an admin, or
/// created by a blocked node.
async fn suppressed(conn: &mut SqliteConnection, uid: &str) -> Result<bool> {
    let n: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM hidden WHERE uid = ?1)
             OR EXISTS(SELECT 1 FROM repl_log l JOIN blocked_peers b ON b.id = l.origin
                       WHERE l.uid = ?1)",
    )
    .bind(uid)
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

/// Whether a parent row that is missing is gone for good (deleted, hidden or
/// blocked) rather than not replicated yet.
async fn gone(conn: &mut SqliteConnection, uid: &str) -> Result<bool> {
    Ok(is_tombstoned(conn, uid).await? || suppressed(conn, uid).await?)
}

/// Local delete of records other nodes created: they leave this node's
/// tables for good and stay in its log. Returns how many were hidden.
pub async fn hide(conn: &mut SqliteConnection, uids: &[String]) -> Result<u64> {
    let mut n = 0;
    for uid in uids {
        let kind: Option<String> = sqlx::query_scalar(
            "SELECT kind FROM repl_log WHERE uid = ? AND kind != 'tombstone' LIMIT 1",
        )
        .bind(uid)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(kind) = kind else { continue };
        sqlx::query("INSERT OR IGNORE INTO hidden (uid, hidden_at) VALUES (?, datetime('now'))")
            .bind(uid)
            .execute(&mut *conn)
            .await?;
        if let Some(ip_id) = unmaterialize(conn, &kind, uid).await? {
            drop_orphan_ip(conn, ip_id).await?;
            n += 1;
        }
    }
    Ok(n)
}

/// The tombstone that already deleted this record, if any.
async fn erased_by(conn: &mut SqliteConnection, uid: &str) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT tombstone_uid FROM tombstoned WHERE uid = ?")
            .bind(uid)
            .fetch_optional(&mut *conn)
            .await?,
    )
}

/// `(hlc or id, country, asn, asn_org, tor)`: an IP's GeoIP / Tor facts.
pub type IpFacts<K> = (K, Option<String>, Option<i64>, Option<String>, bool);
/// `(port, proto, state, service, product, version)`.
type PortRow = (
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The IP's row id, creating the row if needed. `seen` widens the
/// first/last-seen window; scan records pass None (a scan is not a visit).
async fn ensure_ip(conn: &mut SqliteConnection, ip: &str, seen: Option<&str>) -> Result<i64> {
    let ts = seen.map(str::to_string).unwrap_or_else(now_ts);
    let id: Option<i64> = sqlx::query_scalar("SELECT id FROM ips WHERE ip = ?")
        .bind(ip)
        .fetch_optional(&mut *conn)
        .await?;
    let id = match id {
        Some(id) => {
            if let Some(ts) = seen {
                sqlx::query(
                    "UPDATE ips SET first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?)
                     WHERE id = ?",
                )
                .bind(ts)
                .bind(ts)
                .bind(id)
                .execute(&mut *conn)
                .await?;
            }
            return Ok(id);
        }
        None => sqlx::query("INSERT INTO ips (ip, first_seen, last_seen) VALUES (?, ?, ?)")
            .bind(ip)
            .bind(&ts)
            .bind(&ts)
            .execute(&mut *conn)
            .await?
            .last_insert_rowid(),
    };
    // Enrichment that arrived before the IP's first record.
    let pending: Option<IpFacts<i64>> = sqlx::query_as(
        "SELECT hlc, country, asn, asn_org, tor FROM ip_enrich_pending WHERE ip = ?",
    )
    .bind(ip)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some((hlc, country, asn, asn_org, tor)) = pending {
        sqlx::query(
            "UPDATE ips SET country = ?, asn = ?, asn_org = ?, is_tor_exit = ?, geo_hlc = ?
             WHERE id = ?",
        )
        .bind(country)
        .bind(asn)
        .bind(asn_org)
        .bind(tor)
        .bind(hlc)
        .bind(id)
        .execute(&mut *conn)
        .await?;
        sqlx::query("DELETE FROM ip_enrich_pending WHERE ip = ?")
            .bind(ip)
            .execute(&mut *conn)
            .await?;
    }
    Ok(id)
}

async fn request(conn: &mut SqliteConnection, ctx: Ctx<'_>, r: &RequestRec) -> Result<Effect> {
    if let Some(t) = erased_by(conn, &r.uid).await? {
        return Ok(Effect::Erased(t));
    }
    let ip_id = ensure_ip(conn, &r.ip, Some(&r.ts)).await?;
    sqlx::query(
        "INSERT OR IGNORE INTO requests (uid, origin, hlc, ts, ip_id, method, path, query,
           headers_json, body, labels_json, severity, scan_level, is_fp_claim, page_token)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&r.uid)
    .bind(ctx.origin_bytes())
    .bind(ctx.hlc as i64)
    .bind(&r.ts)
    .bind(ip_id)
    .bind(&r.method)
    .bind(&r.path)
    .bind(&r.query)
    .bind(&r.headers_json)
    .bind(&r.body)
    .bind(&r.labels_json)
    .bind(r.severity)
    .bind(r.scan_level)
    .bind(r.is_fp_claim)
    .bind(&r.page_token)
    .execute(&mut *conn)
    .await?;
    Ok(Effect::Applied)
}

async fn ip_enrich(conn: &mut SqliteConnection, ctx: Ctx<'_>, r: &IpEnrichRec) -> Result<Effect> {
    let n = sqlx::query(
        "UPDATE ips SET country = ?, asn = ?, asn_org = ?, is_tor_exit = ?, geo_hlc = ?
         WHERE ip = ? AND geo_hlc < ?",
    )
    .bind(&r.country)
    .bind(r.asn)
    .bind(&r.asn_org)
    .bind(r.tor)
    .bind(ctx.hlc as i64)
    .bind(&r.ip)
    .bind(ctx.hlc as i64)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if n == 0 {
        let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM ips WHERE ip = ?")
            .bind(&r.ip)
            .fetch_optional(&mut *conn)
            .await?;
        if exists.is_none() {
            sqlx::query(
                "INSERT INTO ip_enrich_pending (ip, hlc, country, asn, asn_org, tor)
                 VALUES (?,?,?,?,?,?)
                 ON CONFLICT(ip) DO UPDATE SET hlc = excluded.hlc, country = excluded.country,
                   asn = excluded.asn, asn_org = excluded.asn_org, tor = excluded.tor
                 WHERE excluded.hlc > ip_enrich_pending.hlc",
            )
            .bind(&r.ip)
            .bind(ctx.hlc as i64)
            .bind(&r.country)
            .bind(r.asn)
            .bind(&r.asn_org)
            .bind(r.tor)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(Effect::Applied)
}

async fn request_id(conn: &mut SqliteConnection, uid: &str) -> Result<Option<i64>> {
    Ok(sqlx::query_scalar("SELECT id FROM requests WHERE uid = ?")
        .bind(uid)
        .fetch_optional(&mut *conn)
        .await?)
}

async fn fp_claim(conn: &mut SqliteConnection, ctx: Ctx<'_>, r: &FpClaimRec) -> Result<Effect> {
    if let Some(t) = erased_by(conn, &r.uid).await? {
        return Ok(Effect::Erased(t));
    }
    // A claim on a request that is gone is not applied; it stays in the log.
    let Some(rid) = request_id(conn, &r.request_uid).await? else {
        return Ok(Effect::Ignored);
    };
    let ip_id = ensure_ip(conn, &r.ip, Some(&r.ts)).await?;
    sqlx::query(
        "INSERT OR IGNORE INTO fp_claims (uid, origin, hlc, ip_id, request_id, request_uid, ts,
           contact_email, user_agent)
         VALUES (?,?,?,?,?,?,?,?,?)",
    )
    .bind(&r.uid)
    .bind(ctx.origin_bytes())
    .bind(ctx.hlc as i64)
    .bind(ip_id)
    .bind(rid)
    .bind(&r.request_uid)
    .bind(&r.ts)
    .bind(&r.contact_email)
    .bind(&r.user_agent)
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE ips SET fp_claimed = 1 WHERE id = ?")
        .bind(ip_id)
        .execute(&mut *conn)
        .await?;
    Ok(Effect::Applied)
}

async fn fingerprint(
    conn: &mut SqliteConnection,
    ctx: Ctx<'_>,
    r: &FingerprintRec,
) -> Result<Effect> {
    if let Some(t) = erased_by(conn, &r.uid).await? {
        return Ok(Effect::Erased(t));
    }
    let rid = match &r.request_uid {
        Some(u) => request_id(conn, u).await?,
        None => None,
    };
    let ip_id = ensure_ip(conn, &r.ip, Some(&r.ts)).await?;
    sqlx::query(
        "INSERT OR IGNORE INTO fingerprints (uid, origin, hlc, request_id, request_uid, ip_id, ts,
           fp_hash, visitor_id, attributes_json, behavior_summary_json, event_blob)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&r.uid)
    .bind(ctx.origin_bytes())
    .bind(ctx.hlc as i64)
    .bind(rid)
    .bind(&r.request_uid)
    .bind(ip_id)
    .bind(&r.ts)
    .bind(&r.fp_hash)
    .bind(&r.visitor_id)
    .bind(&r.attributes_json)
    .bind(&r.behavior_summary_json)
    .bind(&r.event_blob)
    .execute(&mut *conn)
    .await?;
    Ok(Effect::Applied)
}

async fn scan_job(conn: &mut SqliteConnection, ctx: Ctx<'_>, r: &ScanJobRec) -> Result<Effect> {
    if let Some(t) = erased_by(conn, &r.uid).await? {
        return Ok(Effect::Erased(t));
    }
    let ip_id = ensure_ip(conn, &r.ip, None).await?;
    sqlx::query(
        "INSERT OR IGNORE INTO scan_jobs (uid, origin, arbiter, hlc, ip_id, level, status, queued_at)
         VALUES (?,?,?,?,?,?,'queued',?)",
    )
    .bind(&r.uid)
    .bind(ctx.origin_bytes())
    .bind(ctx.origin_bytes())
    .bind(ctx.hlc as i64)
    .bind(ip_id)
    .bind(r.level)
    .bind(&r.queued_at)
    .execute(&mut *conn)
    .await?;
    Ok(Effect::Applied)
}

async fn job_status(conn: &mut SqliteConnection, ctx: Ctx<'_>, r: &JobStatusRec) -> Result<Effect> {
    let arbiter: Option<Option<Vec<u8>>> =
        sqlx::query_scalar("SELECT arbiter FROM scan_jobs WHERE uid = ?")
            .bind(&r.job_uid)
            .fetch_optional(&mut *conn)
            .await?;
    let Some(arbiter) = arbiter else {
        // No such job: deleted, hidden or blocked → drop; otherwise it has
        // not replicated here yet → defer so the status is applied once the
        // job arrives.
        return Ok(if gone(conn, &r.job_uid).await? {
            Effect::Ignored
        } else {
            Effect::Deferred
        });
    };
    // Only the job's arbiter changes its state.
    if let Some(o) = ctx.origin
        && arbiter.as_deref() != Some(&o.0[..])
    {
        tracing::debug!(job = %r.job_uid, by = %o.short(), "job status from a non-arbiter ignored");
        return Ok(Effect::Ignored);
    }
    sqlx::query(
        "UPDATE scan_jobs SET status = ?, started_at = ?, finished_at = ?, error = ?, attempts = ?,
           scanner = ?, status_hlc = ?
         WHERE uid = ? AND status_hlc < ?",
    )
    .bind(&r.status)
    .bind(&r.started_at)
    .bind(&r.finished_at)
    .bind(&r.error)
    .bind(r.attempts)
    .bind(r.scanner.map(|s| s.0.to_vec()))
    .bind(ctx.hlc as i64)
    .bind(&r.job_uid)
    .bind(ctx.hlc as i64)
    .execute(&mut *conn)
    .await?;
    Ok(Effect::Applied)
}

/// Take over queued jobs from `r.from`. Order-independent: a job moves to
/// the adopter if `from` still arbitrates it, or if another node adopted it
/// from `from` but has a higher key than this adopter.
async fn job_adopt(conn: &mut SqliteConnection, ctx: Ctx<'_>, r: &JobAdoptRec) -> Result<Effect> {
    let Some(adopter) = ctx.origin else {
        return Ok(Effect::Ignored);
    };
    let (from, me) = (r.from.0.to_vec(), adopter.0.to_vec());
    for uid in &r.job_uids {
        // Adopt queued jobs, and requeue a job still marked 'running' under
        // the (silent) origin — its lease is long gone, so the adopter reruns
        // it. The CASE reads the pre-update status. Taking over does not alter
        // a job already done/failed.
        sqlx::query(
            "UPDATE scan_jobs
               SET arbiter = ?1, adopted_from = ?2,
                   status = CASE WHEN status = 'running' THEN 'queued' ELSE status END,
                   started_at = CASE WHEN status = 'running' THEN NULL ELSE started_at END,
                   scanner = CASE WHEN status = 'running' THEN NULL ELSE scanner END
             WHERE uid = ?3 AND status IN ('queued','running')
               AND (arbiter = ?2 OR (adopted_from = ?2 AND arbiter > ?1))",
        )
        .bind(&me)
        .bind(&from)
        .bind(uid)
        .execute(&mut *conn)
        .await?;
    }
    Ok(Effect::Applied)
}

async fn scan_result(
    conn: &mut SqliteConnection,
    ctx: Ctx<'_>,
    r: &ScanResultRec,
) -> Result<Effect> {
    if let Some(t) = erased_by(conn, &r.uid).await? {
        return Ok(Effect::Erased(t));
    }
    let job_id: Option<i64> = sqlx::query_scalar("SELECT id FROM scan_jobs WHERE uid = ?")
        .bind(&r.job_uid)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(job_id) = job_id else {
        // The scan job has not replicated here yet (cross-origin ordering):
        // defer so the result is stored once it does, unless the job is gone
        // for good (deleted, hidden or blocked).
        return Ok(if gone(conn, &r.job_uid).await? {
            Effect::Ignored
        } else {
            Effect::Deferred
        });
    };
    let ip_id = ensure_ip(conn, &r.ip, None).await?;
    let res = sqlx::query(
        "INSERT OR IGNORE INTO scans (uid, origin, hlc, job_id, job_uid, ip_id, level, started_at,
           finished_at, os_guess, raw_xml)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&r.uid)
    .bind(ctx.origin_bytes())
    .bind(ctx.hlc as i64)
    .bind(job_id)
    .bind(&r.job_uid)
    .bind(ip_id)
    .bind(r.level)
    .bind(&r.started_at)
    .bind(&r.finished_at)
    .bind(&r.os_guess)
    .bind(&r.raw_xml)
    .execute(&mut *conn)
    .await?;
    if res.rows_affected() == 1 {
        let scan_id = res.last_insert_rowid();
        for p in &r.ports {
            sqlx::query(
                "INSERT INTO ports (scan_id, port, proto, state, service, product, version)
                 VALUES (?,?,?,?,?,?,?)",
            )
            .bind(scan_id)
            .bind(p.port)
            .bind(&p.proto)
            .bind(&p.state)
            .bind(&p.service)
            .bind(&p.product)
            .bind(&p.version)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(Effect::Applied)
}

/// The newest announced version of an intel file wins (by HLC).
async fn intel_manifest(
    conn: &mut SqliteConnection,
    ctx: Ctx<'_>,
    m: &IntelManifestRec,
) -> Result<Effect> {
    sqlx::query(
        "INSERT INTO intel_files (kind, sha256, size, fetched_at, origin, hlc) VALUES (?,?,?,?,?,?)
         ON CONFLICT(kind) DO UPDATE SET sha256 = excluded.sha256, size = excluded.size,
           fetched_at = excluded.fetched_at, origin = excluded.origin, hlc = excluded.hlc
         WHERE excluded.hlc > intel_files.hlc",
    )
    .bind(&m.kind)
    .bind(&m.sha256)
    .bind(m.size as i64)
    .bind(&m.fetched_at)
    .bind(ctx.origin_bytes())
    .bind(ctx.hlc as i64)
    .execute(&mut *conn)
    .await?;
    Ok(Effect::Applied)
}

/// `?,?,…` for `n` binds.
fn placeholders(n: usize) -> String {
    std::iter::repeat_n("?", n).collect::<Vec<_>>().join(",")
}

/// Remember `uids` as deleted and drop their payloads from the log.
async fn bury(conn: &mut SqliteConnection, uids: &[String], tomb: &str) -> Result<()> {
    for chunk in uids.chunks(400) {
        for uid in chunk {
            sqlx::query("INSERT OR IGNORE INTO tombstoned (uid, tombstone_uid) VALUES (?, ?)")
                .bind(uid)
                .bind(tomb)
                .execute(&mut *conn)
                .await?;
        }
        let sql = format!(
            "UPDATE repl_log SET payload = NULL, sig = NULL, erased_by = ?
             WHERE uid IN ({}) AND kind != 'tombstone'",
            placeholders(chunk.len())
        );
        let mut q = sqlx::query(sqlx::AssertSqlSafe(sql.as_str())).bind(tomb);
        for uid in chunk {
            q = q.bind(uid);
        }
        q.execute(&mut *conn).await?;
    }
    Ok(())
}

/// Run `sql` (one `IN (…)` list of uids) over `uids` in chunks.
async fn for_uids(conn: &mut SqliteConnection, sql: &str, uids: &[String]) -> Result<()> {
    for chunk in uids.chunks(400) {
        let sql = sql.replace("{}", &placeholders(chunk.len()));
        let mut q = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
        for uid in chunk {
            q = q.bind(uid);
        }
        q.execute(&mut *conn).await?;
    }
    Ok(())
}

async fn uids_where(
    conn: &mut SqliteConnection,
    sql: &str,
    bind: &[String],
) -> Result<Vec<String>> {
    let mut out = vec![];
    for chunk in bind.chunks(400) {
        let sql = sql.replace("{}", &placeholders(chunk.len()));
        let mut q = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in chunk {
            q = q.bind(b);
        }
        out.extend(q.fetch_all(&mut *conn).await?);
    }
    Ok(out)
}

/// Delete the listed records, as far as the tombstone's origin created
/// them. Records of other nodes that hang off a deleted one (a claim on a
/// deleted request, a scan of a deleted job) are not this origin's to erase:
/// they leave the tables, because their parent is gone, and stay in the log.
async fn tombstone(conn: &mut SqliteConnection, ctx: Ctx<'_>, t: &TombstoneRec) -> Result<Effect> {
    // Uids carry their origin's prefix, so a tombstone can only name
    // records its own origin created. A standalone node created everything.
    let own: Vec<String> = match ctx.origin {
        Some(o) => {
            let prefix = o.uid_prefix();
            t.uids
                .iter()
                .filter(|u| u.starts_with(&prefix))
                .cloned()
                .collect()
        }
        None => t.uids.clone(),
    };
    if own.is_empty() {
        return Ok(Effect::Applied);
    }
    let mine: std::collections::HashSet<&str> = own.iter().map(String::as_str).collect();
    let mut ips = std::collections::BTreeSet::new();
    for table in [
        "requests",
        "fp_claims",
        "fingerprints",
        "scan_jobs",
        "scans",
    ] {
        let sql = format!("SELECT DISTINCT ip_id FROM {table} WHERE uid IN ({{}})");
        for chunk in own.chunks(400) {
            let sql = sql.replace("{}", &placeholders(chunk.len()));
            let mut q = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql));
            for uid in chunk {
                q = q.bind(uid);
            }
            ips.extend(q.fetch_all(&mut *conn).await?);
        }
    }
    // Dependents that are not part of this delete.
    let claims = uids_where(
        conn,
        "SELECT uid FROM fp_claims WHERE request_uid IN ({})",
        &own,
    )
    .await?;
    for uid in claims.iter().filter(|u| !mine.contains(u.as_str())) {
        unmaterialize(conn, "fp_claim", uid).await?;
    }
    let scans = uids_where(conn, "SELECT uid FROM scans WHERE job_uid IN ({})", &own).await?;
    for uid in scans.iter().filter(|u| !mine.contains(u.as_str())) {
        unmaterialize(conn, "scan_result", uid).await?;
    }
    for_uids(
        conn,
        "UPDATE fingerprints SET request_id = NULL WHERE request_uid IN ({})",
        &own,
    )
    .await?;
    bury(conn, &own, &t.uid).await?;
    // Children before parents.
    for_uids(
        conn,
        "DELETE FROM ports WHERE scan_id IN (SELECT id FROM scans WHERE uid IN ({}))",
        &own,
    )
    .await?;
    for table in [
        "scans",
        "fp_claims",
        "fingerprints",
        "scan_jobs",
        "requests",
    ] {
        let sql = format!("DELETE FROM {table} WHERE uid IN ({{}})");
        for_uids(conn, &sql, &own).await?;
    }
    for ip_id in ips {
        drop_orphan_ip(conn, ip_id).await?;
    }
    Ok(Effect::Applied)
}

/// Remove an IP row once nothing refers to it any more.
pub(crate) async fn drop_orphan_ip(conn: &mut SqliteConnection, ip_id: i64) -> Result<()> {
    sqlx::query(
        "DELETE FROM ips WHERE id = ?1
           AND NOT EXISTS (SELECT 1 FROM requests WHERE ip_id = ?1)
           AND NOT EXISTS (SELECT 1 FROM scan_jobs WHERE ip_id = ?1)
           AND NOT EXISTS (SELECT 1 FROM scans WHERE ip_id = ?1)
           AND NOT EXISTS (SELECT 1 FROM fingerprints WHERE ip_id = ?1)
           AND NOT EXISTS (SELECT 1 FROM fp_claims WHERE ip_id = ?1)",
    )
    .bind(ip_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Put a row-backed record's payload back into its log entry, so the entry
/// can be relayed without the row.
async fn keep_payload(conn: &mut SqliteConnection, kind: &str, uid: &str) -> Result<()> {
    if !ROW_BACKED.contains(&kind) {
        return Ok(());
    }
    if let Some(rec) = rebuild(conn, kind, uid).await? {
        sqlx::query(
            "UPDATE repl_log SET payload = ?
             WHERE uid = ? AND kind = ? AND payload IS NULL AND erased_by IS NULL",
        )
        .bind(crate::cluster::rpc::cbor::encode(&rec)?)
        .bind(uid)
        .bind(kind)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Take a record out of the tables but keep it in the log with its payload,
/// so this node still relays it. Children that cannot exist without it leave
/// the tables the same way. Returns the row's IP id if there was a row.
pub(crate) async fn unmaterialize(
    conn: &mut SqliteConnection,
    kind: &str,
    uid: &str,
) -> Result<Option<i64>> {
    let table = match kind {
        "request" => "requests",
        "fp_claim" => "fp_claims",
        "fingerprint" => "fingerprints",
        "scan_job" => "scan_jobs",
        "scan_result" => "scans",
        _ => return Ok(None),
    };
    let sql = format!("SELECT ip_id FROM {table} WHERE uid = ?");
    let ip_id: Option<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(uid)
        .fetch_optional(&mut *conn)
        .await?;
    if ip_id.is_none() {
        return Ok(None);
    }
    keep_payload(conn, kind, uid).await?;
    match kind {
        "request" => {
            sqlx::query("DELETE FROM fp_claims WHERE request_uid = ?")
                .bind(uid)
                .execute(&mut *conn)
                .await?;
            sqlx::query("UPDATE fingerprints SET request_id = NULL WHERE request_uid = ?")
                .bind(uid)
                .execute(&mut *conn)
                .await?;
        }
        "scan_job" => {
            let scans: Vec<String> = sqlx::query_scalar("SELECT uid FROM scans WHERE job_uid = ?")
                .bind(uid)
                .fetch_all(&mut *conn)
                .await?;
            for s in scans {
                keep_payload(conn, "scan_result", &s).await?;
                sqlx::query(
                    "DELETE FROM ports WHERE scan_id IN (SELECT id FROM scans WHERE uid = ?)",
                )
                .bind(&s)
                .execute(&mut *conn)
                .await?;
                sqlx::query("DELETE FROM scans WHERE uid = ?")
                    .bind(&s)
                    .execute(&mut *conn)
                    .await?;
            }
        }
        "scan_result" => {
            sqlx::query("DELETE FROM ports WHERE scan_id IN (SELECT id FROM scans WHERE uid = ?)")
                .bind(uid)
                .execute(&mut *conn)
                .await?;
        }
        _ => {}
    }
    let sql = format!("DELETE FROM {table} WHERE uid = ?");
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(uid)
        .execute(&mut *conn)
        .await?;
    Ok(ip_id)
}

/// Rebuild a row-backed record from its row, byte-for-byte as it was
/// signed. None if the row is gone.
pub async fn rebuild(conn: &mut SqliteConnection, kind: &str, uid: &str) -> Result<Option<Record>> {
    type Req = (
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        Option<Vec<u8>>,
        String,
        i64,
        i64,
        bool,
        Option<String>,
    );
    type Fp = (
        String,
        Option<String>,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<Vec<u8>>,
    );
    type Scan = (
        i64,
        String,
        String,
        String,
        i64,
        String,
        Option<String>,
        Option<String>,
        Option<Vec<u8>>,
    );
    Ok(match kind {
        "request" => {
            let r: Option<Req> = sqlx::query_as(
                "SELECT r.uid, r.ts, i.ip, r.method, r.path, r.query, r.headers_json, r.body,
                        r.labels_json, r.severity, r.scan_level, r.is_fp_claim, r.page_token
                 FROM requests r JOIN ips i ON i.id = r.ip_id WHERE r.uid = ?",
            )
            .bind(uid)
            .fetch_optional(&mut *conn)
            .await?;
            r.map(|r| {
                Record::Request(RequestRec {
                    uid: r.0,
                    ts: r.1,
                    ip: r.2,
                    method: r.3,
                    path: r.4,
                    query: r.5,
                    headers_json: r.6,
                    body: r.7,
                    labels_json: r.8,
                    severity: r.9,
                    scan_level: r.10,
                    is_fp_claim: r.11,
                    page_token: r.12,
                })
            })
        }
        "fingerprint" => {
            let r: Option<Fp> = sqlx::query_as(
                "SELECT f.uid, f.request_uid, i.ip, f.ts, f.fp_hash, f.visitor_id,
                        f.attributes_json, f.behavior_summary_json, f.event_blob
                 FROM fingerprints f JOIN ips i ON i.id = f.ip_id WHERE f.uid = ?",
            )
            .bind(uid)
            .fetch_optional(&mut *conn)
            .await?;
            r.map(|r| {
                Record::Fingerprint(FingerprintRec {
                    uid: r.0,
                    request_uid: r.1,
                    ip: r.2,
                    ts: r.3,
                    fp_hash: r.4,
                    visitor_id: r.5,
                    attributes_json: r.6,
                    behavior_summary_json: r.7,
                    event_blob: r.8,
                })
            })
        }
        "scan_result" => {
            let r: Option<Scan> = sqlx::query_as(
                "SELECT s.id, s.uid, s.job_uid, i.ip, s.level, s.started_at, s.finished_at,
                        s.os_guess, s.raw_xml
                 FROM scans s JOIN ips i ON i.id = s.ip_id WHERE s.uid = ?",
            )
            .bind(uid)
            .fetch_optional(&mut *conn)
            .await?;
            match r {
                None => None,
                Some(r) => {
                    let ports: Vec<PortRow> = sqlx::query_as(
                        "SELECT port, proto, state, service, product, version FROM ports
                             WHERE scan_id = ? ORDER BY id",
                    )
                    .bind(r.0)
                    .fetch_all(&mut *conn)
                    .await?;
                    Some(Record::ScanResult(ScanResultRec {
                        uid: r.1,
                        job_uid: r.2,
                        ip: r.3,
                        level: r.4,
                        started_at: r.5,
                        finished_at: r.6,
                        os_guess: r.7,
                        raw_xml: r.8,
                        ports: ports
                            .into_iter()
                            .map(|p| PortRec {
                                port: p.0,
                                proto: p.1,
                                state: p.2,
                                service: p.3,
                                product: p.4,
                                version: p.5,
                            })
                            .collect(),
                    }))
                }
            }
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::record::{Record, ScanResultRec};
    use crate::store::Store;

    use crate::cluster::identity::Identity;
    use crate::cluster::record::{RequestRec, ScanJobRec, TombstoneRec};

    fn request(uid: &str, path: &str) -> Record {
        Record::Request(RequestRec {
            uid: uid.into(),
            ts: now_ts(),
            ip: "203.0.113.7".into(),
            method: "GET".into(),
            path: path.into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: "[]".into(),
            severity: 1,
            scan_level: 1,
            is_fp_claim: false,
            page_token: None,
        })
    }

    /// A log row as the replication layer would hold it for an applied,
    /// row-backed record (payload dropped).
    async fn log_row(
        conn: &mut SqliteConnection,
        origin: &NodeId,
        seq: i64,
        kind: &str,
        uid: &str,
    ) {
        sqlx::query(
            "INSERT INTO repl_log (origin, seq, hlc, kind, uid, payload, sig, applied, received_at)
             VALUES (?, ?, ?, ?, ?, NULL, x'00', 1, datetime('now'))",
        )
        .bind(&origin.0[..])
        .bind(seq)
        .bind(seq)
        .bind(kind)
        .bind(uid)
        .execute(&mut *conn)
        .await
        .unwrap();
    }

    async fn count(conn: &mut SqliteConnection, sql: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_string()))
            .fetch_one(&mut *conn)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_tombstone_only_deletes_its_own_origins_records() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = store.pool.acquire().await.unwrap();
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let (ua, ub) = (
            format!("{}req", a.uid_prefix()),
            format!("{}req", b.uid_prefix()),
        );
        for (origin, uid, seq) in [(&a, ua.as_str(), 1), (&b, ub.as_str(), 1)] {
            let ctx = Ctx {
                origin: Some(origin),
                hlc: 10,
            };
            assert_eq!(
                apply(&mut conn, ctx, &request(uid, "/x")).await.unwrap(),
                Effect::Applied
            );
            log_row(&mut conn, origin, seq, "request", uid).await;
        }
        // B lists both; only its own goes.
        let t = Record::Tombstone(TombstoneRec {
            uid: "tomb-1".into(),
            uids: vec![ua.clone(), ub.clone()],
            seqs: vec![],
        });
        let ctx = Ctx {
            origin: Some(&b),
            hlc: 20,
        };
        apply(&mut conn, ctx, &t).await.unwrap();
        let left: Vec<String> = sqlx::query_scalar("SELECT uid FROM requests")
            .fetch_all(&mut *conn)
            .await
            .unwrap();
        assert_eq!(left, std::slice::from_ref(&ua));
        assert_eq!(
            count(
                &mut conn,
                &format!("SELECT COUNT(*) FROM tombstoned WHERE uid = '{ua}'")
            )
            .await,
            0
        );
        assert_eq!(
            count(
                &mut conn,
                &format!(
                    "SELECT COUNT(*) FROM repl_log WHERE uid = '{ua}' AND erased_by IS NOT NULL"
                )
            )
            .await,
            0
        );
        assert_eq!(
            count(
                &mut conn,
                &format!(
                    "SELECT COUNT(*) FROM repl_log WHERE uid = '{ub}' AND erased_by = 'tomb-1'"
                )
            )
            .await,
            1
        );
        assert_eq!(
            count(&mut conn, "SELECT COUNT(*) FROM ips").await,
            1,
            "a's request keeps the ip"
        );
    }

    /// A tombstone that names a parent but not its children must not trip a
    /// foreign key and stall the origin's stream.
    #[tokio::test]
    async fn children_left_out_of_a_tombstone_leave_the_tables() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = store.pool.acquire().await.unwrap();
        let ctx = |hlc| Ctx { origin: None, hlc };
        apply(&mut conn, ctx(1), &request("req", "/x"))
            .await
            .unwrap();
        apply(
            &mut conn,
            ctx(2),
            &Record::FpClaim(crate::cluster::record::FpClaimRec {
                uid: "claim".into(),
                request_uid: "req".into(),
                ip: "203.0.113.7".into(),
                ts: now_ts(),
                contact_email: None,
                user_agent: None,
            }),
        )
        .await
        .unwrap();
        apply(
            &mut conn,
            ctx(3),
            &Record::ScanJob(ScanJobRec {
                uid: "job".into(),
                ip: "203.0.113.7".into(),
                level: 2,
                queued_at: now_ts(),
            }),
        )
        .await
        .unwrap();
        apply(
            &mut conn,
            ctx(4),
            &Record::ScanResult(ScanResultRec {
                uid: "scan".into(),
                job_uid: "job".into(),
                ip: "203.0.113.7".into(),
                level: 2,
                started_at: now_ts(),
                finished_at: Some(now_ts()),
                os_guess: None,
                raw_xml: None,
                ports: vec![],
            }),
        )
        .await
        .unwrap();
        let t = Record::Tombstone(TombstoneRec {
            uid: "tomb".into(),
            uids: vec!["req".into(), "job".into()],
            seqs: vec![],
        });
        assert_eq!(apply(&mut conn, ctx(5), &t).await.unwrap(), Effect::Applied);
        for table in ["requests", "fp_claims", "scan_jobs", "scans", "ips"] {
            let sql = format!("SELECT COUNT(*) FROM {table}");
            assert_eq!(count(&mut conn, &sql).await, 0, "{table}");
        }
    }

    #[tokio::test]
    async fn scan_result_defers_until_its_job_exists() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store
            .upsert_ip("203.0.113.9".parse().unwrap())
            .await
            .unwrap();
        let mut conn = store.pool.acquire().await.unwrap();
        let res = ScanResultRec {
            uid: new_uid(),
            job_uid: "job-not-here-yet".into(),
            ip: "203.0.113.9".into(),
            level: 2,
            started_at: now_ts(),
            finished_at: Some(now_ts()),
            os_guess: None,
            raw_xml: None,
            ports: vec![],
        };
        // The parent job has not replicated yet → deferred, not dropped.
        let eff = apply(
            &mut conn,
            Ctx {
                origin: None,
                hlc: 1,
            },
            &Record::ScanResult(res.clone()),
        )
        .await
        .unwrap();
        assert_eq!(eff, Effect::Deferred);
        // Once the job arrives, the same record applies.
        sqlx::query(
            "INSERT INTO scan_jobs (uid, ip_id, level, status, queued_at) VALUES (?,?,2,'running',?)",
        )
        .bind("job-not-here-yet")
        .bind(ip.id)
        .bind(now_ts())
        .execute(&mut *conn)
        .await
        .unwrap();
        let eff = apply(
            &mut conn,
            Ctx {
                origin: None,
                hlc: 2,
            },
            &Record::ScanResult(res),
        )
        .await
        .unwrap();
        assert_eq!(eff, Effect::Applied);
    }
}
