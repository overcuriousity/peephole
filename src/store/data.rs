//! The only writer of replicated rows. Every change to requests, IPs,
//! claims, fingerprints, scan jobs and scans is a [`Record`] applied here —
//! directly on a standalone node, through the replication log in a cluster
//! — so both modes share one set of semantics.
//!
//! Deletes are tombstones: they remove the rows, remember the deleted uids
//! (and per-IP cut-offs), and records that arrive later for something
//! already deleted are dropped instead of resurrecting it.
use crate::cluster::identity::NodeId;
use crate::cluster::record::{
    FingerprintRec, FpClaimRec, IpEnrichRec, JobStatusRec, PortRec, Record, RequestRec, ScanJobRec,
    ScanResultRec, TombTarget, TombstoneRec,
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
}

/// UTC timestamp in the rows' format.
pub fn now_ts() -> String {
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn new_uid() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

pub async fn apply(conn: &mut SqliteConnection, ctx: Ctx<'_>, r: &Record) -> Result<Effect> {
    match r {
        Record::Request(r) => request(conn, ctx, r).await,
        Record::IpEnrich(r) => ip_enrich(conn, ctx, r).await,
        Record::FpClaim(r) => fp_claim(conn, ctx, r).await,
        Record::Fingerprint(r) => fingerprint(conn, ctx, r).await,
        Record::ScanJob(r) => scan_job(conn, ctx, r).await,
        Record::JobStatus(r) => job_status(conn, ctx, r).await,
        Record::ScanResult(r) => scan_result(conn, ctx, r).await,
        Record::Tombstone(t) => tombstone(conn, ctx, t).await,
        Record::MemberAdd(_) | Record::MemberUpdate(_) | Record::MemberRevoke { .. } => {
            Ok(Effect::Ignored)
        }
    }
}

/// The tombstone that already deleted this record, if any.
async fn erased_by(
    conn: &mut SqliteConnection,
    uids: &[Option<&str>],
    ip: &str,
    hlc: u64,
) -> Result<Option<String>> {
    for uid in uids.iter().flatten() {
        let t: Option<String> =
            sqlx::query_scalar("SELECT tombstone_uid FROM tombstoned WHERE uid = ?")
                .bind(uid)
                .fetch_optional(&mut *conn)
                .await?;
        if t.is_some() {
            return Ok(t);
        }
    }
    Ok(
        sqlx::query_scalar("SELECT tombstone_uid FROM ip_tombstones WHERE ip = ? AND hlc >= ?")
            .bind(ip)
            .bind(hlc as i64)
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
    if let Some(t) = erased_by(conn, &[Some(&r.uid)], &r.ip, ctx.hlc).await? {
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
    if erased_by(conn, &[], &r.ip, ctx.hlc).await?.is_some() {
        return Ok(Effect::Ignored);
    }
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
    if let Some(t) = erased_by(conn, &[Some(&r.uid), Some(&r.request_uid)], &r.ip, ctx.hlc).await? {
        return Ok(Effect::Erased(t));
    }
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
    if let Some(t) = erased_by(
        conn,
        &[Some(&r.uid), r.request_uid.as_deref()],
        &r.ip,
        ctx.hlc,
    )
    .await?
    {
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
    if let Some(t) = erased_by(conn, &[Some(&r.uid)], &r.ip, ctx.hlc).await? {
        return Ok(Effect::Erased(t));
    }
    let ip_id = ensure_ip(conn, &r.ip, None).await?;
    sqlx::query(
        "INSERT OR IGNORE INTO scan_jobs (uid, origin, hlc, ip_id, level, status, queued_at)
         VALUES (?,?,?,?,?,'queued',?)",
    )
    .bind(&r.uid)
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
        sqlx::query_scalar("SELECT origin FROM scan_jobs WHERE uid = ?")
            .bind(&r.job_uid)
            .fetch_optional(&mut *conn)
            .await?;
    let Some(arbiter) = arbiter else {
        return Ok(Effect::Ignored); // job deleted
    };
    // Only the job's arbiter changes its state.
    if let Some(o) = ctx.origin
        && arbiter.as_deref() != Some(&o.0[..])
    {
        tracing::warn!(job = %r.job_uid, by = %o.short(), "job status from a non-arbiter ignored");
        return Ok(Effect::Ignored);
    }
    sqlx::query(
        "UPDATE scan_jobs SET status = ?, started_at = ?, finished_at = ?, error = ?, attempts = ?,
           status_hlc = ?
         WHERE uid = ? AND status_hlc < ?",
    )
    .bind(&r.status)
    .bind(&r.started_at)
    .bind(&r.finished_at)
    .bind(&r.error)
    .bind(r.attempts)
    .bind(ctx.hlc as i64)
    .bind(&r.job_uid)
    .bind(ctx.hlc as i64)
    .execute(&mut *conn)
    .await?;
    Ok(Effect::Applied)
}

async fn scan_result(
    conn: &mut SqliteConnection,
    ctx: Ctx<'_>,
    r: &ScanResultRec,
) -> Result<Effect> {
    if let Some(t) = erased_by(conn, &[Some(&r.uid)], &r.ip, ctx.hlc).await? {
        return Ok(Effect::Erased(t));
    }
    let job_id: Option<i64> = sqlx::query_scalar("SELECT id FROM scan_jobs WHERE uid = ?")
        .bind(&r.job_uid)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(job_id) = job_id else {
        return Ok(Effect::Ignored);
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

async fn tombstone(conn: &mut SqliteConnection, ctx: Ctx<'_>, t: &TombstoneRec) -> Result<Effect> {
    match &t.target {
        TombTarget::Requests { uids } => {
            let claims = uids_where(
                conn,
                "SELECT uid FROM fp_claims WHERE request_uid IN ({})",
                uids,
            )
            .await?;
            let fps = uids_where(
                conn,
                "SELECT uid FROM fingerprints WHERE request_uid IN ({})",
                uids,
            )
            .await?;
            let all: Vec<String> = uids.iter().chain(&claims).chain(&fps).cloned().collect();
            bury(conn, &all, &t.uid).await?;
            for_uids(
                conn,
                "DELETE FROM fp_claims WHERE request_uid IN ({})",
                uids,
            )
            .await?;
            for_uids(
                conn,
                "DELETE FROM fingerprints WHERE request_uid IN ({})",
                uids,
            )
            .await?;
            for_uids(conn, "DELETE FROM requests WHERE uid IN ({})", uids).await?;
        }
        TombTarget::Scan { uid } => {
            bury(conn, std::slice::from_ref(uid), &t.uid).await?;
            sqlx::query("DELETE FROM ports WHERE scan_id IN (SELECT id FROM scans WHERE uid = ?)")
                .bind(uid)
                .execute(&mut *conn)
                .await?;
            sqlx::query("DELETE FROM scans WHERE uid = ?")
                .bind(uid)
                .execute(&mut *conn)
                .await?;
        }
        TombTarget::Claim { uid } => {
            bury(conn, std::slice::from_ref(uid), &t.uid).await?;
            sqlx::query("DELETE FROM fp_claims WHERE uid = ?")
                .bind(uid)
                .execute(&mut *conn)
                .await?;
        }
        TombTarget::Ip { ip } => tombstone_ip(conn, ctx, ip, &t.uid).await?,
    }
    Ok(Effect::Applied)
}

/// Uids of `table` rows for an IP recorded at or before `cut`.
async fn uids_for_ip(
    conn: &mut SqliteConnection,
    table: &'static str,
    ip_id: i64,
    cut: i64,
) -> Result<Vec<String>> {
    let sql = format!("SELECT uid FROM {table} WHERE ip_id = ? AND COALESCE(hlc, 0) <= ?");
    Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
        .bind(ip_id)
        .bind(cut)
        .fetch_all(&mut *conn)
        .await?)
}

/// Delete everything about `ip` recorded up to the tombstone's HLC. Rows
/// that depend on deleted rows go too, whatever their HLC.
async fn tombstone_ip(
    conn: &mut SqliteConnection,
    ctx: Ctx<'_>,
    ip: &str,
    tomb: &str,
) -> Result<()> {
    let cut = ctx.hlc as i64;
    sqlx::query(
        "INSERT INTO ip_tombstones (ip, hlc, tombstone_uid) VALUES (?,?,?)
         ON CONFLICT(ip) DO UPDATE SET hlc = excluded.hlc, tombstone_uid = excluded.tombstone_uid
         WHERE excluded.hlc > ip_tombstones.hlc",
    )
    .bind(ip)
    .bind(cut)
    .bind(tomb)
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM ip_enrich_pending WHERE ip = ? AND hlc <= ?")
        .bind(ip)
        .bind(cut)
        .execute(&mut *conn)
        .await?;
    let ip_id: Option<i64> = sqlx::query_scalar("SELECT id FROM ips WHERE ip = ?")
        .bind(ip)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(ip_id) = ip_id else { return Ok(()) };
    let reqs = uids_for_ip(conn, "requests", ip_id, cut).await?;
    let jobs = uids_for_ip(conn, "scan_jobs", ip_id, cut).await?;
    let mut claims = uids_for_ip(conn, "fp_claims", ip_id, cut).await?;
    let mut fps = uids_for_ip(conn, "fingerprints", ip_id, cut).await?;
    let mut scans = uids_for_ip(conn, "scans", ip_id, cut).await?;
    claims.extend(
        uids_where(
            conn,
            "SELECT uid FROM fp_claims WHERE request_uid IN ({})",
            &reqs,
        )
        .await?,
    );
    fps.extend(
        uids_where(
            conn,
            "SELECT uid FROM fingerprints WHERE request_uid IN ({})",
            &reqs,
        )
        .await?,
    );
    scans.extend(uids_where(conn, "SELECT uid FROM scans WHERE job_uid IN ({})", &jobs).await?);
    let all: Vec<String> = [&reqs, &jobs, &claims, &fps, &scans]
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    bury(conn, &all, tomb).await?;
    for_uids(
        conn,
        "DELETE FROM ports WHERE scan_id IN (SELECT id FROM scans WHERE uid IN ({}))",
        &scans,
    )
    .await?;
    for_uids(conn, "DELETE FROM scans WHERE uid IN ({})", &scans).await?;
    for_uids(conn, "DELETE FROM scan_jobs WHERE uid IN ({})", &jobs).await?;
    for_uids(conn, "DELETE FROM fp_claims WHERE uid IN ({})", &claims).await?;
    for_uids(conn, "DELETE FROM fingerprints WHERE uid IN ({})", &fps).await?;
    for_uids(conn, "DELETE FROM requests WHERE uid IN ({})", &reqs).await?;
    // The IP itself goes once nothing refers to it any more.
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
