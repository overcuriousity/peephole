//! The replication log: local appends, version vectors, serving entries to
//! peers and applying theirs.
//!
//! Invariant: for every origin the entries held (applied log + parked) are
//! exactly `1..=head`, so a version vector of heads describes a node's state.
//! Entries arrive in order; anything that would leave a gap is rejected and
//! simply re-sent by a later sync round.
use super::Node;
use super::identity::NodeId;
use super::record::{ROW_BACKED, Record, WireEntry};
use crate::store::data::{self, Ctx, Effect};
use anyhow::Result;
use sqlx::SqliteConnection;
use tracing::warn;

/// Highest held sequence per origin.
pub type Heads = Vec<(NodeId, u64)>;

/// What [`apply_batch`] did with a batch.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Applied {
    pub applied: usize,
    pub parked: usize,
    pub duplicate: usize,
    pub rejected: usize,
    pub membership_changed: bool,
}

pub async fn heads(store: &crate::store::Store) -> Result<Heads> {
    let rows: Vec<(Vec<u8>, i64)> = sqlx::query_as("SELECT origin, seq FROM repl_heads")
        .fetch_all(&store.pool)
        .await?;
    rows.into_iter()
        .map(|(o, s)| Ok((NodeId::from_slice(&o)?, s as u64)))
        .collect()
}

/// True if `ours` holds anything `theirs` does not.
pub fn ahead_of(ours: &Heads, theirs: &Heads) -> bool {
    ours.iter().any(|(o, s)| head_in(theirs, o) < *s)
}

pub fn head_in(h: &Heads, origin: &NodeId) -> u64 {
    h.iter()
        .find(|(o, _)| o == origin)
        .map(|(_, s)| *s)
        .unwrap_or(0)
}

async fn log_head(conn: &mut SqliteConnection, origin: &NodeId) -> Result<u64> {
    let s: Option<i64> = sqlx::query_scalar("SELECT MAX(seq) FROM repl_log WHERE origin = ?")
        .bind(&origin.0[..])
        .fetch_one(&mut *conn)
        .await?;
    Ok(s.unwrap_or(0) as u64)
}

async fn pending_head(conn: &mut SqliteConnection, origin: &NodeId) -> Result<u64> {
    let s: Option<i64> = sqlx::query_scalar("SELECT MAX(seq) FROM repl_pending WHERE origin = ?")
        .bind(&origin.0[..])
        .fetch_one(&mut *conn)
        .await?;
    Ok(s.unwrap_or(0) as u64)
}

type LogRow = (
    Vec<u8>,
    i64,
    i64,
    String,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
);

fn from_row(r: LogRow) -> Result<WireEntry> {
    Ok(WireEntry {
        origin: NodeId::from_slice(&r.0)?,
        seq: r.1 as u64,
        hlc: r.2 as u64,
        kind: r.3,
        uid: r.4,
        payload: r.5,
        sig: r.6,
        erased_by: r.7,
    })
}

/// Entries after each `(origin, seq)`, in order, within the given budget.
/// Always returns at least one entry when one is available.
pub async fn entries_after(
    store: &crate::store::Store,
    wants: &[(NodeId, u64)],
    max_entries: usize,
    max_bytes: usize,
) -> Result<Vec<WireEntry>> {
    let mut conn = store.pool.acquire().await?;
    let mut out: Vec<WireEntry> = vec![];
    let mut bytes = 0usize;
    let full = |out: &Vec<WireEntry>, bytes: usize| {
        out.len() >= max_entries || (bytes >= max_bytes && !out.is_empty())
    };
    for (origin, after) in wants {
        if full(&out, bytes) {
            break;
        }
        let mut next = *after + 1;
        let rows: Vec<LogRow> = sqlx::query_as(
            "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by FROM repl_log
             WHERE origin = ? AND seq > ? ORDER BY seq LIMIT ?",
        )
        .bind(&origin.0[..])
        .bind(*after as i64)
        .bind((max_entries - out.len()) as i64)
        .fetch_all(&mut *conn)
        .await?;
        let mut parked = vec![];
        if rows.len() < max_entries - out.len() {
            // Parked entries (origin not trusted here yet) are relayed too;
            // every receiver verifies signatures and trust itself.
            let blobs: Vec<Vec<u8>> = sqlx::query_scalar(
                "SELECT entry FROM repl_pending WHERE origin = ? AND seq > ? ORDER BY seq LIMIT ?",
            )
            .bind(&origin.0[..])
            .bind(*after as i64)
            .bind((max_entries - out.len()) as i64)
            .fetch_all(&mut *conn)
            .await?;
            for b in blobs {
                parked.push(super::rpc::cbor::decode::<WireEntry>(&b)?);
            }
        }
        let candidates = rows
            .into_iter()
            .map(from_row)
            .chain(parked.into_iter().map(Ok));
        for e in candidates {
            let mut e = e?;
            if e.payload.is_none() && e.erased_by.is_none() {
                // Row-backed: rebuild the signed payload from the row.
                let rebuilt = match &e.uid {
                    Some(uid) => data::rebuild(&mut conn, &e.kind, uid).await?,
                    None => None,
                };
                let Some(r) = rebuilt else {
                    warn!(origin = %e.origin.short(), seq = e.seq, kind = %e.kind,
                          "log entry has neither payload nor row; serving stops here");
                    break;
                };
                e.payload = Some(super::rpc::cbor::encode(&r)?);
            }
            if e.seq < next {
                continue;
            }
            if e.seq != next || full(&out, bytes) {
                break;
            }
            bytes += e.payload.as_ref().map_or(0, Vec::len) + 128;
            next += 1;
            out.push(e);
        }
    }
    Ok(out)
}

/// Raise the held head of `origin` to `seq` (entries never go away, so
/// heads only grow).
async fn bump_head(conn: &mut SqliteConnection, origin: &NodeId, seq: u64) -> Result<()> {
    sqlx::query(
        "INSERT INTO repl_heads (origin, seq) VALUES (?, ?)
         ON CONFLICT(origin) DO UPDATE SET seq = MAX(seq, excluded.seq)",
    )
    .bind(&origin.0[..])
    .bind(seq as i64)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn insert_log(conn: &mut SqliteConnection, e: &WireEntry, applied: bool) -> Result<()> {
    bump_head(conn, &e.origin, e.seq).await?;
    sqlx::query(
        "INSERT INTO repl_log (origin, seq, hlc, kind, uid, payload, sig, erased_by, applied, received_at)
         VALUES (?,?,?,?,?,?,?,?,?,datetime('now'))",
    )
    .bind(&e.origin.0[..])
    .bind(e.seq as i64)
    .bind(e.hlc as i64)
    .bind(&e.kind)
    .bind(&e.uid)
    .bind(&e.payload)
    .bind(&e.sig)
    .bind(&e.erased_by)
    .bind(applied)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Whether records from `origin` are accepted: this node, or any node that
/// was ever admitted. Leaving or being pruned ends a node's access, not the
/// validity of what it recorded.
pub async fn trusted(node: &Node, conn: &mut SqliteConnection, origin: &NodeId) -> Result<bool> {
    if *origin == node.id() {
        return Ok(true);
    }
    let n: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM members WHERE id = ? AND admitted_hlc > 0")
            .bind(&origin.0[..])
            .fetch_one(&mut *conn)
            .await?;
    Ok(n > 0)
}

/// Append a record created by this node, applying it in the same
/// transaction. Callers hold `node.apply_lock` (see [`append`]).
pub async fn append_in_tx(
    node: &Node,
    conn: &mut SqliteConnection,
    record: &Record,
) -> Result<(WireEntry, bool)> {
    let me = node.id();
    let seq = log_head(conn, &me)
        .await?
        .max(pending_head(conn, &me).await?)
        + 1;
    let e = WireEntry::sign(&node.identity, seq, node.hlc.now(), record)?;
    insert_log(conn, &e, true).await?;
    let settled = apply_record(node, conn, &e, record).await?;
    Ok((e, settled.membership))
}

/// Log a record whose rows already exist (history adoption): sign and
/// store it without applying it again. Row-backed kinds keep no payload.
pub async fn append_existing(
    node: &Node,
    conn: &mut SqliteConnection,
    record: &Record,
) -> Result<WireEntry> {
    let me = node.id();
    let seq = log_head(conn, &me)
        .await?
        .max(pending_head(conn, &me).await?)
        + 1;
    let mut e = WireEntry::sign(&node.identity, seq, node.hlc.now(), record)?;
    let stored_payload = e.payload.take();
    if !ROW_BACKED.contains(&e.kind.as_str()) {
        e.payload = stored_payload.clone();
    }
    insert_log(conn, &e, true).await?;
    e.payload = stored_payload;
    Ok(e)
}

/// Append records created by this node, atomically.
pub async fn append(node: &Node, records: &[Record]) -> Result<Vec<WireEntry>> {
    let _g = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let mut out = vec![];
    let mut members = false;
    for r in records {
        let (e, changed) = append_in_tx(node, &mut tx, r).await?;
        members |= changed;
        out.push(e);
    }
    tx.commit().await?;
    drop(_g);
    if let Some(last) = out.last() {
        node.own_head
            .fetch_max(last.seq, std::sync::atomic::Ordering::Relaxed);
    }
    for (e, r) in out.iter().zip(records) {
        announce_job(node, &e.kind, r);
    }
    if members {
        node.reload_members().await?;
    }
    node.notify_changed();
    Ok(out)
}

/// Apply entries received from a peer (any origin).
pub async fn apply_batch(node: &Node, entries: Vec<WireEntry>) -> Result<Applied> {
    let mut st = Applied::default();
    if entries.is_empty() {
        return Ok(st);
    }
    let guard = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    for e in entries {
        apply_one(node, &mut tx, e, &mut st).await?;
    }
    if st.applied > 0 {
        drain_pending(node, &mut tx, &mut st).await?;
        // Newly-applied entries may be the parent of earlier deferred ones.
        retry_deferred(node, &mut tx, &mut st).await?;
    }
    tx.commit().await?;
    drop(guard);
    if st.membership_changed {
        node.reload_members().await?;
    }
    if st.applied + st.parked > 0 {
        node.notify_changed();
    }
    Ok(st)
}

async fn apply_one(
    node: &Node,
    conn: &mut SqliteConnection,
    e: WireEntry,
    st: &mut Applied,
) -> Result<()> {
    let have = log_head(conn, &e.origin).await?;
    let held = have.max(pending_head(conn, &e.origin).await?);
    if e.seq <= held {
        st.duplicate += 1;
        return Ok(());
    }
    if e.seq != held + 1 {
        st.rejected += 1;
        return Ok(());
    }
    if e.payload.is_none() {
        return apply_stub(node, conn, e, held > have, st).await;
    }
    // Verify before parking too, so junk never takes up space or blocks
    // the real entry at that position.
    if !e.verify() {
        warn!(origin = %e.origin.short(), seq = e.seq, "entry with bad signature dropped");
        st.rejected += 1;
        return Ok(());
    }
    if held > have || !trusted(node, conn, &e.origin).await? {
        park(conn, &e).await?;
        st.parked += 1;
        return Ok(());
    }
    apply_verified(node, conn, e, st).await
}

/// Store an entry we cannot apply yet (a gap ahead, or its origin not trusted
/// here yet) and advance the held head so the stream can continue; a later
/// [`drain_pending`] applies it once the obstacle clears.
async fn park(conn: &mut SqliteConnection, e: &WireEntry) -> Result<()> {
    sqlx::query(
        "INSERT INTO repl_pending (origin, seq, entry, received_at) VALUES (?,?,?,datetime('now'))",
    )
    .bind(&e.origin.0[..])
    .bind(e.seq as i64)
    .bind(super::rpc::cbor::encode(e)?)
    .execute(&mut *conn)
    .await?;
    bump_head(conn, &e.origin, e.seq).await?;
    Ok(())
}

/// An entry its origin deleted (payload erased, `erased_by` naming the
/// tombstone). The tombstone sits *later* in the same origin's in-order
/// stream, so requiring it first would stall the origin forever; instead a
/// stub from a trusted origin is applied immediately (remembering the uid as
/// deleted), and one from an untrusted/not-yet-trusted origin — or behind a
/// gap — is parked for a later drain. NOTE: erased stubs carry no signature
/// (the payload, and thus the signature, were dropped on erasure), so a
/// trusted relaying member could forge one; this matches the existing threat
/// model (any member may delete anything) but a future protocol revision
/// should sign stubs at the origin.
async fn apply_stub(
    node: &Node,
    conn: &mut SqliteConnection,
    e: WireEntry,
    blocked: bool,
    st: &mut Applied,
) -> Result<()> {
    if e.erased_by.is_none() {
        // A payload-less entry that is not an erased stub is malformed.
        st.rejected += 1;
        return Ok(());
    }
    if blocked || !trusted(node, conn, &e.origin).await? {
        park(conn, &e).await?;
        st.parked += 1;
        return Ok(());
    }
    apply_stub_now(node, conn, &e, st).await
}

/// Record an erased stub whose origin is trusted and whose position is next.
async fn apply_stub_now(
    node: &Node,
    conn: &mut SqliteConnection,
    e: &WireEntry,
    st: &mut Applied,
) -> Result<()> {
    insert_log(conn, e, true).await?;
    if let (Some(uid), Some(tomb)) = (&e.uid, &e.erased_by) {
        sqlx::query("INSERT OR IGNORE INTO tombstoned (uid, tombstone_uid) VALUES (?, ?)")
            .bind(uid)
            .bind(tomb)
            .execute(&mut *conn)
            .await?;
    }
    node.hlc.observe(e.hlc);
    st.applied += 1;
    Ok(())
}

/// Tell the live queue about scan jobs a record touched.
fn announce_job(node: &Node, _kind: &str, r: &Record) {
    let uids: Vec<&String> = match r {
        Record::ScanJob(j) => vec![&j.uid],
        Record::JobStatus(s) => vec![&s.job_uid],
        Record::JobAdopt(a) => a.job_uids.iter().collect(),
        _ => return,
    };
    for u in uids {
        let _ = node.job_events.send(u.clone());
    }
}

async fn apply_verified(
    node: &Node,
    conn: &mut SqliteConnection,
    e: WireEntry,
    st: &mut Applied,
) -> Result<()> {
    let record = e.record();
    insert_log(conn, &e, record.is_some()).await?;
    if let Some(r) = &record {
        let settled = apply_record(node, conn, &e, r).await?;
        st.membership_changed |= settled.membership;
        if settled.deferred {
            // Parent not here yet: keep it unapplied for retry_deferred.
            sqlx::query("UPDATE repl_log SET applied = 0 WHERE origin = ? AND seq = ?")
                .bind(&e.origin.0[..])
                .bind(e.seq as i64)
                .execute(&mut *conn)
                .await?;
        }
        // Sent before commit; listeners re-read the row after a moment.
        announce_job(node, &e.kind, r);
    }
    node.hlc.observe(e.hlc);
    st.applied += 1;
    Ok(())
}

/// Apply parked entries whose origin became trusted, until nothing moves.
async fn drain_pending(node: &Node, conn: &mut SqliteConnection, st: &mut Applied) -> Result<()> {
    loop {
        let origins: Vec<Vec<u8>> = sqlx::query_scalar("SELECT DISTINCT origin FROM repl_pending")
            .fetch_all(&mut *conn)
            .await?;
        let mut progress = false;
        for o in origins {
            let origin = NodeId::from_slice(&o)?;
            if !trusted(node, conn, &origin).await? {
                continue;
            }
            let blobs: Vec<(i64, Vec<u8>)> =
                sqlx::query_as("SELECT seq, entry FROM repl_pending WHERE origin = ? ORDER BY seq")
                    .bind(&o)
                    .fetch_all(&mut *conn)
                    .await?;
            for (seq, blob) in blobs {
                sqlx::query("DELETE FROM repl_pending WHERE origin = ? AND seq = ?")
                    .bind(&o)
                    .bind(seq)
                    .execute(&mut *conn)
                    .await?;
                if seq as u64 != log_head(conn, &origin).await? + 1 {
                    continue; // already applied via another path
                }
                let e: WireEntry = super::rpc::cbor::decode(&blob)?;
                // A parked erased stub records the deletion; everything else
                // carries a signed payload to apply.
                if e.payload.is_none() {
                    apply_stub_now(node, conn, &e, st).await?;
                } else {
                    apply_verified(node, conn, e, st).await?;
                }
                progress = true;
            }
        }
        if !progress {
            return Ok(());
        }
    }
}

/// Re-apply entries a previous build stored without understanding them.
pub async fn apply_unknown_kinds(node: &Node) -> Result<usize> {
    let _g = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let rows: Vec<LogRow> = sqlx::query_as(
        "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by FROM repl_log
         WHERE applied = 0 ORDER BY hlc",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut n = 0;
    for r in rows {
        let e = from_row(r)?;
        if let Some(rec) = e.record() {
            let settled = apply_record(node, &mut tx, &e, &rec).await?;
            // A still-deferred entry (parent absent) stays unapplied for a
            // later retry; do not mark it applied.
            if !settled.deferred {
                sqlx::query("UPDATE repl_log SET applied = 1 WHERE origin = ? AND seq = ?")
                    .bind(&e.origin.0[..])
                    .bind(e.seq as i64)
                    .execute(&mut *tx)
                    .await?;
                n += 1;
            }
        }
    }
    tx.commit().await?;
    Ok(n)
}

/// Re-apply entries that were deferred because their parent row was missing,
/// now that newly-applied entries may have supplied it. Loops until no entry
/// moves. Runs inside the batch transaction.
async fn retry_deferred(node: &Node, conn: &mut SqliteConnection, st: &mut Applied) -> Result<()> {
    loop {
        let rows: Vec<LogRow> = sqlx::query_as(
            "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by FROM repl_log
             WHERE applied = 0 AND payload IS NOT NULL ORDER BY hlc",
        )
        .fetch_all(&mut *conn)
        .await?;
        let mut progress = false;
        for r in rows {
            let e = from_row(r)?;
            let Some(rec) = e.record() else { continue };
            let settled = apply_record(node, conn, &e, &rec).await?;
            st.membership_changed |= settled.membership;
            if !settled.deferred {
                sqlx::query("UPDATE repl_log SET applied = 1 WHERE origin = ? AND seq = ?")
                    .bind(&e.origin.0[..])
                    .bind(e.seq as i64)
                    .execute(&mut *conn)
                    .await?;
                announce_job(node, &e.kind, &rec);
                progress = true;
            }
        }
        if !progress {
            return Ok(());
        }
    }
}

/// What applying a record did, beyond its table effects.
#[derive(Default, Clone, Copy)]
struct Settled {
    membership: bool,
    /// The record's parent row is not here yet; keep the entry unapplied.
    deferred: bool,
}

/// Effects of one record on the materialized tables, then settle its log
/// entry: erased if a tombstone already deleted it, payload dropped if it
/// can be rebuilt from its row.
async fn apply_record(
    node: &Node,
    conn: &mut SqliteConnection,
    e: &WireEntry,
    r: &Record,
) -> Result<Settled> {
    if super::members::apply(node, conn, e, r).await? {
        return Ok(Settled {
            membership: true,
            deferred: false,
        });
    }
    let ctx = Ctx {
        origin: Some(&e.origin),
        hlc: e.hlc,
    };
    match data::apply(conn, ctx, r).await? {
        Effect::Deferred => {
            return Ok(Settled {
                membership: false,
                deferred: true,
            });
        }
        Effect::Erased(t) => {
            sqlx::query(
                "UPDATE repl_log SET payload = NULL, sig = NULL, erased_by = ?
                 WHERE origin = ? AND seq = ?",
            )
            .bind(&t)
            .bind(&e.origin.0[..])
            .bind(e.seq as i64)
            .execute(&mut *conn)
            .await?;
        }
        Effect::Applied if ROW_BACKED.contains(&e.kind.as_str()) => {
            // Keep the payload unless the row reproduces it exactly.
            if let (Some(uid), Some(payload)) = (&e.uid, &e.payload)
                && let Some(rebuilt) = data::rebuild(conn, &e.kind, uid).await?
                && super::rpc::cbor::encode(&rebuilt)? == *payload
            {
                sqlx::query("UPDATE repl_log SET payload = NULL WHERE origin = ? AND seq = ?")
                    .bind(&e.origin.0[..])
                    .bind(e.seq as i64)
                    .execute(&mut *conn)
                    .await?;
            } else {
                warn!(kind = %e.kind, uid = ?e.uid, "row does not reproduce its record; payload kept");
            }
        }
        _ => {}
    }
    Ok(Settled::default())
}

#[cfg(test)]
mod tests {
    /// The heads table must agree with what the log and parked entries hold.
    #[tokio::test]
    async fn heads_table_matches_held_entries() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let node = super::super::Node::open(super::super::NodeParams {
            identity: super::super::identity::Identity::generate().unwrap(),
            cluster: crate::config::ClusterConfig {
                node_name: "n".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: None,
                key_path: None,
                takeover_hours: 6.0,
                lease_secs: 120,
                peers: vec![],
            },
            roles: Default::default(),
            store: store.clone(),
            proto: (1, 1),
            has_maxmind: false,
            data_dir: dir.path().to_path_buf(),
        })
        .await
        .unwrap();
        node.bootstrap().await.unwrap();
        let other = super::super::identity::Identity::generate().unwrap();
        let rec = |id: &super::super::identity::Identity| {
            super::Record::MemberUpdate(super::super::record::MemberInfo {
                id: id.id,
                name: "o".into(),
                address: None,
                roles: vec![],
                proto_min: 1,
                proto_max: 1,
            })
        };
        // A parked entry from an unknown origin counts as held.
        let e = super::WireEntry::sign(&other, 1, 5, &rec(&other)).unwrap();
        super::apply_batch(&node, vec![e]).await.unwrap();
        let h = super::heads(&store).await.unwrap();
        assert_eq!(super::head_in(&h, &other.id), 1);
        assert_eq!(super::head_in(&h, &node.id()), 1);
        let scanned: Vec<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT origin, MAX(seq) FROM (SELECT origin, seq FROM repl_log
             UNION ALL SELECT origin, seq FROM repl_pending) GROUP BY origin ORDER BY origin",
        )
        .fetch_all(&store.pool)
        .await
        .unwrap();
        let table: Vec<(Vec<u8>, i64)> =
            sqlx::query_as("SELECT origin, seq FROM repl_heads ORDER BY origin")
                .fetch_all(&store.pool)
                .await
                .unwrap();
        assert_eq!(scanned, table);
    }
}
