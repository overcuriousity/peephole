//! The local block list. Blocking a peer is this node's own decision and
//! is never replicated: the node stops talking to the peer and keeps its
//! records out of its tables, but still stores and relays them, so nobody
//! else is affected.
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
    tracing::info!(id = %id.short(), records = n, "peer blocked");
    Ok(n)
}

/// Unblock `id` and bring its records back. False if it was not blocked.
pub async fn unblock(node: &Node, id: NodeId) -> Result<bool> {
    let n = sqlx::query("DELETE FROM blocked_peers WHERE id = ?")
        .bind(&id.0[..])
        .execute(&node.store.pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Ok(false);
    }
    repl::rematerialize(node).await?;
    node.reload_members().await?;
    tracing::info!(id = %id.short(), "peer unblocked");
    Ok(true)
}
