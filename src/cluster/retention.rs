//! Opt-in retention in a cluster (`cluster.retention_days`, off by
//! default). The shared dataset is persistent and nobody can delete another
//! node's records, so a cluster can only be bounded cooperatively: a node
//! that opts in deletes its *own* requests, claims, fingerprints and scan
//! results older than N days, cluster-wide, with the ordinary signed
//! tombstones of its origin. Records of other nodes are never touched.
use super::Node;
use crate::store::recorder::Recorder;
use anyhow::Result;
use std::sync::Arc;

/// Records looked at per table and round, so the write lock is short.
const BATCH: i64 = 5000;

/// Delete this node's records older than `days`; returns how many.
pub async fn run(node: &Arc<Node>, days: u32) -> Result<u64> {
    if days == 0 {
        return Ok(0);
    }
    let rec = Recorder::Cluster(node.clone());
    let me = node.id().0.to_vec();
    let cutoff = format!("-{days} days");
    let mut total = 0;
    // Bounded: the rest waits for the next daily run.
    for _ in 0..20 {
        let mut uids: Vec<String> = vec![];
        for sql in [
            "SELECT uid FROM requests WHERE origin = ? AND ts < datetime('now', ?)
             AND uid IS NOT NULL ORDER BY id LIMIT ?",
            "SELECT uid FROM fp_claims WHERE origin = ? AND ts < datetime('now', ?)
             AND uid IS NOT NULL ORDER BY id LIMIT ?",
            "SELECT uid FROM fingerprints WHERE origin = ? AND ts < datetime('now', ?)
             AND uid IS NOT NULL ORDER BY id LIMIT ?",
            "SELECT uid FROM scans WHERE origin = ?
             AND COALESCE(finished_at, started_at) < datetime('now', ?)
             AND uid IS NOT NULL ORDER BY id LIMIT ?",
        ] {
            let found: Vec<String> = sqlx::query_scalar(sql)
                .bind(&me)
                .bind(&cutoff)
                .bind(BATCH)
                .fetch_all(&node.store.pool)
                .await?;
            uids.extend(found);
        }
        if uids.is_empty() {
            break;
        }
        let n = uids.len() as u64;
        rec.delete_own(uids).await?;
        total += n;
        if n < BATCH as u64 {
            break;
        }
    }
    Ok(total)
}
