//! History floors: a node may keep only the last `retention_days` of the
//! replicated history, like a pruned Bitcoin node. It drops old records and
//! their log entries *locally* (no tombstones; other nodes keep theirs),
//! holds every entry of an origin from its floor on, and serves only that.
//! Members that keep everything serve the older history.
//!
//! Membership entries are kept below the floor: they are few and small, and
//! a node joining with a window needs the admissions to trust anyone. So a
//! floor means "everything from here on is held; below, membership only".
//! The newest entry of an origin is never dropped: several parts of the log
//! read it (this node's next sequence, liveness, the clock).
use super::Node;
use super::identity::NodeId;
use crate::store::data;
use anyhow::Result;
use sqlx::SqliteConnection;
use std::collections::{BTreeSet, HashMap};
use tracing::info;

/// Kinds kept below the floor.
pub const MEMBERSHIP: [&str; 3] = ["member_add", "member_update", "member_revoke"];
/// SQL list of [`MEMBERSHIP`].
pub(crate) const MEMBERSHIP_SQL: &str = "('member_add','member_update','member_revoke')";

/// Floors above 1, per origin.
pub type Floors = HashMap<NodeId, u64>;

/// Entries dropped per transaction, so the write lock is never held long.
const BATCH: i64 = 500;

/// Every floor above 1.
pub async fn floors(conn: &mut SqliteConnection) -> Result<Floors> {
    let rows: Vec<(Vec<u8>, i64)> = sqlx::query_as("SELECT origin, seq FROM repl_floors")
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(o, s)| Some((NodeId::from_slice(&o).ok()?, s.max(1) as u64)))
        .filter(|(_, s)| *s > 1)
        .collect())
}

/// The first sequence of `origin` held in full (1: the whole history).
pub async fn floor_of(conn: &mut SqliteConnection, origin: &NodeId) -> Result<u64> {
    let s: Option<i64> = sqlx::query_scalar("SELECT seq FROM repl_floors WHERE origin = ?")
        .bind(&origin.0[..])
        .fetch_optional(&mut *conn)
        .await?;
    Ok(s.unwrap_or(1).max(1) as u64)
}

/// Raise the floor of `origin` to `seq` (floors never go down here).
pub(crate) async fn raise_floor(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    seq: u64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO repl_floors (origin, seq) VALUES (?, ?)
         ON CONFLICT(origin) DO UPDATE SET seq = MAX(seq, excluded.seq)",
    )
    .bind(&origin.0[..])
    .bind(seq.min(i64::MAX as u64) as i64)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The HLC from which a window of `days` starts at `now_ms`.
pub fn window_hlc(days: u32, now_ms: u64) -> u64 {
    now_ms.saturating_sub(days as u64 * 86_400_000) << 16
}

/// Where the window starts in `origin`'s log: the lowest sequence from
/// `from` on whose entry is not older than `since_hlc`; the newest entry
/// when all are older (it always stays). 0 for an origin without a log.
pub async fn cut(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    from: u64,
    since_hlc: u64,
) -> Result<u64> {
    let (head, first): (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT (SELECT MAX(seq) FROM repl_log WHERE origin = ?1),
                (SELECT MIN(seq) FROM repl_log WHERE origin = ?1 AND seq >= ?2 AND hlc >= ?3)",
    )
    .bind(&origin.0[..])
    .bind(from.min(i64::MAX as u64) as i64)
    .bind(since_hlc.min(i64::MAX as u64) as i64)
    .fetch_one(&mut *conn)
    .await?;
    let head = head.unwrap_or(0).max(0) as u64;
    Ok(first.map_or(head, |f| (f.max(0) as u64).min(head)))
}

/// Drop what lies outside this node's window, for every origin. Returns how
/// many log entries went. Does nothing on a node that keeps everything.
pub async fn prune(node: &Node) -> Result<u64> {
    if node.retention_days == 0 {
        return Ok(0);
    }
    let since = window_hlc(node.retention_days, super::hlc::wall_ms());
    let origins: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT origin FROM repl_heads WHERE origin NOT IN (SELECT id FROM purged_origins)",
    )
    .fetch_all(&node.store.pool)
    .await?;
    let mut total = 0;
    for o in origins {
        let origin = NodeId::from_slice(&o)?;
        total += prune_origin(node, &origin, since).await?;
    }
    if total > 0 {
        info!(
            entries = total,
            days = node.retention_days,
            "history outside the window dropped"
        );
    }
    Ok(total)
}

async fn prune_origin(node: &Node, origin: &NodeId, since: u64) -> Result<u64> {
    let mut conn = node.store.pool.acquire().await?;
    let floor = floor_of(&mut conn, origin).await?;
    let new_floor = cut(&mut conn, origin, floor, since).await?.max(floor);
    drop(conn);
    let mut n = 0;
    loop {
        let _g = node.apply_lock.lock().await;
        let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        type Row = (i64, String, Option<String>, i64);
        let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT seq, kind, uid, accounted FROM repl_log
             WHERE origin = ? AND seq < ? AND kind NOT IN {MEMBERSHIP_SQL}
             ORDER BY seq LIMIT ?"
        )))
        .bind(&origin.0[..])
        .bind(new_floor.min(i64::MAX as u64) as i64)
        .bind(BATCH)
        .fetch_all(&mut *tx)
        .await?;
        let Some(last) = rows.last().map(|r| r.0 as u64) else {
            raise_floor(&mut tx, origin, new_floor).await?;
            tx.commit().await?;
            break;
        };
        let mut ips = BTreeSet::new();
        let mut bytes = 0;
        for (seq, kind, uid, accounted) in &rows {
            bytes += accounted;
            if let Some(uid) = uid {
                if kind == "tombstone" {
                    sqlx::query("DELETE FROM tomb_proofs WHERE origin = ? AND tomb_uid = ?")
                        .bind(&origin.0[..])
                        .bind(uid)
                        .execute(&mut *tx)
                        .await?;
                } else if !(kind == "scan_job" && job_active(&mut tx, uid).await?) {
                    // A job still queued or running keeps its row: the
                    // queue needs it, and its state is not history yet.
                    ips.extend(data::drop_row(&mut tx, kind, uid).await?);
                }
            }
            sqlx::query("DELETE FROM repl_log WHERE origin = ? AND seq = ?")
                .bind(&origin.0[..])
                .bind(seq)
                .execute(&mut *tx)
                .await?;
        }
        for ip in ips {
            data::drop_orphan_ip(&mut tx, ip).await?;
        }
        sqlx::query(
            "UPDATE origin_usage SET bytes = MAX(bytes - ?, 0), entries = MAX(entries - ?, 0)
             WHERE origin = ?",
        )
        .bind(bytes)
        .bind(rows.len() as i64)
        .bind(&origin.0[..])
        .execute(&mut *tx)
        .await?;
        // Everything from here on is held (membership below it too).
        raise_floor(&mut tx, origin, (last + 1).min(new_floor)).await?;
        tx.commit().await?;
        n += rows.len() as u64;
    }
    if new_floor > floor {
        drop_old_intel(node, origin, new_floor).await?;
    }
    Ok(n)
}

async fn job_active(conn: &mut SqliteConnection, uid: &str) -> Result<bool> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_jobs WHERE uid = ? AND status IN ('queued', 'running')",
    )
    .bind(uid)
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

/// Enrichment results of `origin` older than its entry at `floor`: the
/// lookup history and the newest result per IP alike (the IPs fall back to
/// other nodes' results).
async fn drop_old_intel(node: &Node, origin: &NodeId, floor: u64) -> Result<()> {
    let cut_hlc: Option<i64> =
        sqlx::query_scalar("SELECT hlc FROM repl_log WHERE origin = ? AND seq = ?")
            .bind(&origin.0[..])
            .bind(floor.min(i64::MAX as u64) as i64)
            .fetch_optional(&node.store.pool)
            .await?;
    let Some(cut_hlc) = cut_hlc else {
        return Ok(());
    };
    loop {
        let _g = node.apply_lock.lock().await;
        let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let ips: Vec<String> = sqlx::query_scalar(
            "SELECT ip FROM ip_intel_log WHERE origin = ?1 AND hlc < ?2
             UNION SELECT ip FROM ip_intel WHERE origin = ?1 AND hlc < ?2 LIMIT ?3",
        )
        .bind(&origin.0[..])
        .bind(cut_hlc)
        .bind(BATCH)
        .fetch_all(&mut *tx)
        .await?;
        if ips.is_empty() {
            return Ok(());
        }
        for ip in &ips {
            for sql in [
                "DELETE FROM ip_intel_log WHERE origin = ? AND ip = ? AND hlc < ?",
                "DELETE FROM ip_intel WHERE origin = ? AND ip = ? AND hlc < ?",
            ] {
                sqlx::query(sql)
                    .bind(&origin.0[..])
                    .bind(ip)
                    .bind(cut_hlc)
                    .execute(&mut *tx)
                    .await?;
            }
            data::refresh_ip_view(&mut tx, ip).await?;
        }
        tx.commit().await?;
    }
}
