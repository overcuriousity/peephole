//! The local block list. Blocking a peer is this node's own decision and
//! is never replicated: the node stops talking to the peer and keeps its
//! records out of its tables, but still stores and relays them, so nobody
//! else is affected. Purging a blocked peer goes further: its entries are
//! deleted here and neither accepted nor relayed any more.
use super::Node;
use super::identity::NodeId;
use super::repl;
use crate::store::data;
use anyhow::{Result, bail};

pub async fn list(store: &crate::store::Store) -> Result<Vec<NodeId>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT id FROM blocked_peers")
        .fetch_all(&store.pool)
        .await?;
    rows.iter().map(|r| NodeId::from_slice(r)).collect()
}

/// Nodes this node purged.
pub async fn purged(store: &crate::store::Store) -> Result<Vec<NodeId>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT id FROM purged_origins")
        .fetch_all(&store.pool)
        .await?;
    rows.iter().map(|r| NodeId::from_slice(r)).collect()
}

/// Rows taken out of the tables per transaction, so the write lock is
/// never held for long (blocking a flooding peer is exactly when this is
/// large).
const BATCH: usize = 500;

/// Block `id`. Returns how many of its records left the tables.
pub async fn block(node: &Node, id: NodeId) -> Result<u64> {
    if id == node.id() {
        bail!("a node cannot block itself");
    }
    // From here on its new records stay out of the tables.
    sqlx::query("INSERT OR IGNORE INTO blocked_peers (id, blocked_at) VALUES (?, datetime('now'))")
        .bind(&id.0[..])
        .execute(&node.store.pool)
        .await?;
    node.reload_members().await?;
    let mut n = 0;
    // Children before parents, so each row is counted once.
    for (table, kind) in [
        ("scans", "scan_result"),
        ("fp_claims", "fp_claim"),
        ("fingerprints", "fingerprint"),
        ("scan_jobs", "scan_job"),
        ("requests", "request"),
        ("skipped_batches", "skip_batch"),
    ] {
        let sql = format!("SELECT uid FROM {table} WHERE origin = ? AND uid IS NOT NULL");
        let uids: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(&id.0[..])
            .fetch_all(&node.store.pool)
            .await?;
        for chunk in uids.chunks(BATCH) {
            let _g = node.apply_lock.lock().await;
            let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
            let mut ips = std::collections::BTreeSet::new();
            for uid in chunk {
                if let Some(ip) = data::unmaterialize(&mut tx, kind, uid).await? {
                    ips.insert(ip);
                    n += 1;
                }
            }
            for ip in ips {
                data::drop_orphan_ip(&mut tx, ip).await?;
            }
            tx.commit().await?;
        }
    }
    // Its enrichment results go too; the IPs fall back to other nodes' results.
    loop {
        let _g = node.apply_lock.lock().await;
        let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let ips: Vec<String> =
            sqlx::query_scalar("SELECT DISTINCT ip FROM ip_intel_log WHERE origin = ? LIMIT ?")
                .bind(&id.0[..])
                .bind(BATCH as i64)
                .fetch_all(&mut *tx)
                .await?;
        if ips.is_empty() {
            break;
        }
        for ip in &ips {
            for sql in [
                "DELETE FROM ip_intel WHERE origin = ? AND ip = ?",
                "DELETE FROM ip_intel_log WHERE origin = ? AND ip = ?",
            ] {
                sqlx::query(sql)
                    .bind(&id.0[..])
                    .bind(ip)
                    .execute(&mut *tx)
                    .await?;
            }
            data::refresh_ip_view(&mut tx, ip).await?;
        }
        tx.commit().await?;
    }
    tracing::info!(id = %id.short(), records = n, "peer blocked");
    Ok(n)
}

/// Block `id` and every node it admitted, transitively (a sponsor that
/// brought in a swarm of keys). This node is never included. Returns the
/// nodes blocked and how many records left the tables.
pub async fn block_subtree(node: &Node, id: NodeId) -> Result<(Vec<NodeId>, u64)> {
    let mut ids = vec![id];
    ids.extend(super::members::subtree(&node.store, id, node.id()).await?);
    let mut n = 0;
    for i in &ids {
        n += block(node, *i).await?;
    }
    Ok((ids, n))
}

/// Entries deleted per transaction by [`purge`].
const PURGE_BATCH: i64 = 5000;

/// Delete everything this node holds from a blocked node: its log entries
/// (a block keeps them for relaying), parked entries, proofs, intel
/// announcements and results. From now on its entries are refused and not
/// relayed. Unblocking fetches them again. Returns how many log entries
/// went.
pub async fn purge(node: &Node, id: NodeId) -> Result<u64> {
    if !node.is_blocked(&id) && !list(&node.store).await?.contains(&id) {
        bail!("block {} before purging it", id.short());
    }
    // First refuse new entries, then delete what is held.
    sqlx::query("INSERT OR IGNORE INTO purged_origins (id, purged_at) VALUES (?, datetime('now'))")
        .bind(&id.0[..])
        .execute(&node.store.pool)
        .await?;
    let mut n = 0;
    loop {
        let _g = node.apply_lock.lock().await;
        let gone = sqlx::query(
            "DELETE FROM repl_log WHERE origin = ?1
               AND seq IN (SELECT seq FROM repl_log WHERE origin = ?1 LIMIT ?2)",
        )
        .bind(&id.0[..])
        .bind(PURGE_BATCH)
        .execute(&node.store.pool)
        .await?
        .rows_affected();
        n += gone;
        if gone == 0 {
            break;
        }
    }
    let _g = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    for sql in [
        "DELETE FROM repl_pending WHERE origin = ?",
        "DELETE FROM tomb_proofs WHERE origin = ?",
        "DELETE FROM intel_files WHERE origin = ?",
        "DELETE FROM origin_usage WHERE origin = ?",
        "DELETE FROM repl_floors WHERE origin = ?",
    ] {
        sqlx::query(sql).bind(&id.0[..]).execute(&mut *tx).await?;
    }
    let ips: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT ip FROM ip_intel_log WHERE origin = ?")
            .bind(&id.0[..])
            .fetch_all(&mut *tx)
            .await?;
    for sql in [
        "DELETE FROM ip_intel WHERE origin = ?",
        "DELETE FROM ip_intel_log WHERE origin = ?",
    ] {
        sqlx::query(sql).bind(&id.0[..]).execute(&mut *tx).await?;
    }
    for ip in &ips {
        data::refresh_ip_view(&mut tx, ip).await?;
    }
    tx.commit().await?;
    tracing::info!(id = %id.short(), entries = n, "blocked peer purged");
    Ok(n)
}

/// Unblock `id` and bring its records back. False if it was not blocked.
/// A purged node's entries are fetched again from the other members.
pub async fn unblock(node: &Node, id: NodeId) -> Result<bool> {
    let n = sqlx::query("DELETE FROM blocked_peers WHERE id = ?")
        .bind(&id.0[..])
        .execute(&node.store.pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Ok(false);
    }
    let purged = sqlx::query("DELETE FROM purged_origins WHERE id = ?")
        .bind(&id.0[..])
        .execute(&node.store.pool)
        .await?
        .rows_affected();
    if purged > 0 {
        let _g = node.apply_lock.lock().await;
        let mut conn = node.store.pool.acquire().await?;
        repl::reset_head(&mut conn, &id).await?;
    }
    repl::rematerialize(node).await?;
    node.reload_members().await?;
    tracing::info!(id = %id.short(), "peer unblocked");
    Ok(true)
}
