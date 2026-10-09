//! History adoption: rows a node recorded while standalone (origin NULL)
//! are signed into its log on the first start in distributed mode, so the
//! cluster backfills them like any other data.
use super::Node;
use super::identity::NodeId;
use super::record::{FpClaimRec, IpIntelRec, JobStatusRec, Record, ScanJobRec};
use super::repl;
use crate::store::data;
use anyhow::Result;
use sqlx::SqliteConnection;
use tracing::info;

const BATCH: i64 = 500;

/// The record a standalone row would have been written as.
async fn record_for(conn: &mut SqliteConnection, kind: &str, uid: &str) -> Result<Option<Record>> {
    Ok(match kind {
        "request" | "fingerprint" | "scan_result" | "skip_batch" => {
            data::rebuild(conn, kind, uid).await?
        }
        "fp_claim" => {
            type Row = (
                Option<String>,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
            );
            let r: Option<Row> = sqlx::query_as(
                "SELECT c.request_uid, i.ip, c.ts, c.contact_email, c.user_agent, c.build
                 FROM fp_claims c JOIN ips i ON i.id = c.ip_id WHERE c.uid = ?",
            )
            .bind(uid)
            .fetch_optional(&mut *conn)
            .await?;
            r.and_then(|r| {
                Some(Record::FpClaim(FpClaimRec {
                    uid: uid.to_string(),
                    request_uid: r.0?,
                    ip: r.1,
                    ts: r.2,
                    contact_email: r.3,
                    user_agent: r.4,
                    build: r.5,
                }))
            })
        }
        "scan_job" => {
            type Row = (
                String,
                i64,
                String,
                Option<String>,
                Option<String>,
                Option<Vec<u8>>,
                i64,
            );
            let r: Option<Row> = sqlx::query_as(
                "SELECT i.ip, j.level, j.queued_at, j.retry_of, j.retry_at, j.failed_by, j.manual
                 FROM scan_jobs j JOIN ips i ON i.id = j.ip_id WHERE j.uid = ?",
            )
            .bind(uid)
            .fetch_optional(&mut *conn)
            .await?;
            r.map(|(ip, level, queued_at, retry_of, retry_at, failed_by, manual)| {
                Record::ScanJob(ScanJobRec {
                    uid: uid.to_string(),
                    ip,
                    level,
                    queued_at,
                    retry_of,
                    retry_at,
                    failed_by: failed_by.and_then(|b| NodeId::from_slice(&b).ok()),
                    manual: manual != 0,
                })
            })
        }
        _ => None,
    })
}

/// A job's current state as a record, if it ever left the queue.
async fn job_status_for(conn: &mut SqliteConnection, uid: &str) -> Result<Option<Record>> {
    type Row = (String, Option<String>, Option<String>, Option<String>, i64);
    let r: Row = sqlx::query_as(
        "SELECT status, started_at, finished_at, error, attempts FROM scan_jobs WHERE uid = ?",
    )
    .bind(uid)
    .fetch_one(&mut *conn)
    .await?;
    if r.0 == "queued" && r.4 == 0 {
        return Ok(None);
    }
    Ok(Some(Record::JobStatus(JobStatusRec {
        job_uid: uid.to_string(),
        status: r.0,
        started_at: r.1,
        finished_at: r.2,
        error: r.3,
        attempts: r.4,
        scanner: None,
    })))
}

/// Give standalone rows uids that carry this node's prefix, as every record
/// in a cluster must (see `NodeId::uid_prefix`). References between rows
/// follow. Idempotent: rows that were already renamed are left alone.
async fn bind_uids(node: &Node) -> Result<()> {
    let p = node.id().uid_prefix();
    let _g = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    // References first, while the parents still carry their old uids.
    for (child, col, parent) in [
        ("fp_claims", "request_uid", "requests"),
        ("fingerprints", "request_uid", "requests"),
        ("scans", "job_uid", "scan_jobs"),
    ] {
        let sql = format!(
            "UPDATE {child} SET {col} = ?1 || {col} WHERE {col} IN
               (SELECT uid FROM {parent} WHERE origin IS NULL AND uid NOT LIKE ?1 || '%')"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(&p)
            .execute(&mut *tx)
            .await?;
    }
    for table in [
        "requests",
        "fp_claims",
        "fingerprints",
        "scan_jobs",
        "scans",
        "skipped_batches",
    ] {
        let sql = format!(
            "UPDATE {table} SET uid = ?1 || uid
             WHERE origin IS NULL AND uid IS NOT NULL AND uid NOT LIKE ?1 || '%'"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(&p)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Adopt all standalone rows; returns how many records were logged.
pub async fn adopt_history(node: &Node) -> Result<u64> {
    let me = node.id().0.to_vec();
    let mut total = 0u64;
    bind_uids(node).await?;
    // Parents before children, so receivers can link them.
    for (table, kind) in [
        ("requests", "request"),
        ("fp_claims", "fp_claim"),
        ("fingerprints", "fingerprint"),
        ("scan_jobs", "scan_job"),
        ("scans", "scan_result"),
        ("skipped_batches", "skip_batch"),
    ] {
        loop {
            let _g = node.apply_lock.lock().await;
            let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
            let sql = format!(
                "SELECT uid FROM {table} WHERE origin IS NULL AND uid IS NOT NULL ORDER BY id LIMIT ?"
            );
            let uids: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
                .bind(BATCH)
                .fetch_all(&mut *tx)
                .await?;
            if uids.is_empty() {
                break;
            }
            for uid in &uids {
                let hlc = match record_for(&mut tx, kind, uid).await? {
                    Some(rec) => {
                        total += 1;
                        repl::append_existing(node, &mut tx, &rec).await?.hlc
                    }
                    // Unlinkable (e.g. a claim whose request lost its uid):
                    // keep it local, but do not look at it again.
                    None => 0,
                };
                let sql = if table == "scan_jobs" {
                    "UPDATE scan_jobs SET origin = ?1, arbiter = ?1, hlc = ?2 WHERE uid = ?3"
                        .to_string()
                } else {
                    format!("UPDATE {table} SET origin = ?1, hlc = ?2 WHERE uid = ?3")
                };
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(&me)
                    .bind(hlc as i64)
                    .bind(uid)
                    .execute(&mut *tx)
                    .await?;
                if kind == "scan_job"
                    && let Some(st) = job_status_for(&mut tx, uid).await?
                {
                    let e = repl::append_existing(node, &mut tx, &st).await?;
                    sqlx::query("UPDATE scan_jobs SET status_hlc = ? WHERE uid = ?")
                        .bind(e.hlc as i64)
                        .bind(uid)
                        .execute(&mut *tx)
                        .await?;
                    total += 1;
                }
            }
            tx.commit().await?;
        }
    }
    total += adopt_intel(node).await?;
    if total > 0 {
        info!(
            records = total,
            "standalone history adopted into the cluster log"
        );
        node.notify_changed();
    }
    Ok(total)
}

/// Enrichment results recorded while standalone (origin empty) become this
/// node's results in the log: the whole lookup history, oldest first, so
/// the cluster gets every lookup and not only the newest.
async fn adopt_intel(node: &Node) -> Result<u64> {
    let me = node.id().0.to_vec();
    let mut total = 0;
    loop {
        let _g = node.apply_lock.lock().await;
        let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        type Row = (String, String, i64, String, Option<String>, String, String);
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT ip, provider, hlc, fetched_at, source_version, data_json, build
             FROM ip_intel_log
             WHERE origin = x'' ORDER BY hlc, ip, provider LIMIT ?",
        )
        .bind(BATCH)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            break;
        }
        for (ip, provider, hlc, fetched_at, source_version, data_json, build) in rows {
            let e = repl::append_existing(
                node,
                &mut tx,
                &Record::IpIntel(IpIntelRec {
                    ip: ip.clone(),
                    provider: provider.clone(),
                    fetched_at,
                    source_version,
                    data_json,
                    build,
                }),
            )
            .await?;
            sqlx::query(
                "UPDATE ip_intel_log SET origin = ?, hlc = ?
                 WHERE ip = ? AND provider = ? AND origin = x'' AND hlc = ?",
            )
            .bind(&me)
            .bind(e.hlc as i64)
            .bind(&ip)
            .bind(&provider)
            .bind(hlc)
            .execute(&mut *tx)
            .await?;
            total += 1;
        }
        tx.commit().await?;
    }
    // The newest standalone result per (ip, provider) is now ours, at the
    // HLC its log entry got; a result of ours recorded since joining is newer.
    let _g = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query(
        "DELETE FROM ip_intel WHERE origin = x'' AND EXISTS (
           SELECT 1 FROM ip_intel m WHERE m.ip = ip_intel.ip
             AND m.provider = ip_intel.provider AND m.origin = ?1)",
    )
    .bind(&me)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE ip_intel SET origin = ?1, hlc = COALESCE((
           SELECT MAX(l.hlc) FROM ip_intel_log l WHERE l.ip = ip_intel.ip
             AND l.provider = ip_intel.provider AND l.origin = ?1), hlc)
         WHERE origin = x''",
    )
    .bind(&me)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(total)
}
