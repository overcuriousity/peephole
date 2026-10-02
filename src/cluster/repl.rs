//! The replication log: local appends, version vectors, serving entries to
//! peers and applying theirs.
//!
//! Invariant: for every origin the entries held (applied log + parked) are
//! exactly `floor..=head` (plus, below the floor, its membership entries),
//! so a version vector of heads describes a node's state. The floor is 1 —
//! the whole history — unless this node keeps only a window (see
//! [`super::history`]). Entries arrive in order; anything that would leave
//! a gap is rejected and simply re-sent by a later sync round. Local
//! decisions bend this: parked entries of a node nobody admitted expire (its
//! head goes back down, so they are fetched again later), a purged origin
//! keeps its head while its entries are gone (they are neither served nor
//! accepted), and a windowed node drops entries below its floor.
//!
//! Nothing else is ever removed from the log: a node that joins later
//! fetches the history from members that keep it. Erased entries shrink to
//! stubs without payload; `tombstoned` must stay too, because records of
//! other nodes that hang off a deleted one can arrive at any time.
use super::Node;
use super::hlc;
use super::identity::NodeId;
use super::record::{JobAdoptRec, ROW_BACKED, Record, WireEntry};
use super::sync::Batch;
use crate::store::data::{self, Ctx, Effect};
use anyhow::Result;
use sqlx::SqliteConnection;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

/// Highest held sequence per origin (the wire form).
pub type Heads = Vec<(NodeId, u64)>;
/// [`Heads`] for lookups.
pub type HeadMap = HashMap<NodeId, u64>;

/// `repl_log.applied` states (see migration 0018).
const APPLIED: i64 = 1;
const DEFERRED: i64 = 0;
const UNKNOWN_KIND: i64 = 2;

/// Entries of a node nobody admitted (yet) are parked and relayed only up
/// to these limits per origin; the rest is fetched again once it is
/// admitted.
pub const PARK_UNTRUSTED_ENTRIES: i64 = 100;
pub const PARK_UNTRUSTED_BYTES: i64 = 1024 * 1024;
/// Distinct origins with parked entries (bounds sybil keys).
const PARK_ORIGINS: i64 = 64;
/// Parked entries of a node nobody admitted are dropped after this.
const PARK_TTL: &str = "-7 days";
/// A deferred entry (parent never arrived, adoption never became due) is
/// given up after this; it stays in the log and is still relayed.
const DEFER_MAX_AGE: &str = "-7 days";
/// Deferred entries retried per query and per call.
const RETRY_BATCH: i64 = 100;
const RETRY_MAX_PER_CALL: usize = 500;
/// Job uids one adoption entry may move.
const MAX_ADOPT: usize = 500;

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

pub fn head_map(h: &Heads) -> HeadMap {
    h.iter().copied().collect()
}

/// True if `ours` holds anything `theirs` does not.
pub fn ahead_of(ours: &Heads, theirs: &Heads) -> bool {
    ahead_of_map(ours, &head_map(theirs))
}

pub fn ahead_of_map(ours: &Heads, theirs: &HeadMap) -> bool {
    ours.iter()
        .any(|(o, s)| theirs.get(o).copied().unwrap_or(0) < *s)
}

/// One origin's head (a single lookup; use [`head_map`] for many).
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

/// A log row with the time it was received (unix ms).
type TimedRow = (
    Vec<u8>,
    i64,
    i64,
    String,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<i64>,
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

fn from_timed(r: TimedRow) -> Result<(WireEntry, u64)> {
    let received = r.8.unwrap_or(0).max(0) as u64;
    Ok((
        from_row((r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7))?,
        received,
    ))
}

/// Origins this node purged (`cluster purge`).
async fn purged_set(conn: &mut SqliteConnection) -> Result<HashSet<NodeId>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT id FROM purged_origins")
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| NodeId::from_slice(r).ok())
        .collect())
}

pub async fn is_purged(conn: &mut SqliteConnection, origin: &NodeId) -> Result<bool> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM purged_origins WHERE id = ?")
        .bind(&origin.0[..])
        .fetch_one(&mut *conn)
        .await?;
    Ok(n > 0)
}

/// Whether `origin` has used up its storage quota here (see
/// `cluster.origin_quota_mb`). This node's own entries never are.
async fn over_quota(node: &Node, conn: &mut SqliteConnection, origin: &NodeId) -> Result<bool> {
    if *origin == node.id() || node.cfg.origin_quota_mb == 0 {
        return Ok(false);
    }
    let used: Option<i64> = sqlx::query_scalar("SELECT bytes FROM origin_usage WHERE origin = ?")
        .bind(&origin.0[..])
        .fetch_optional(&mut *conn)
        .await?;
    let quota = node.cfg.origin_quota_mb.saturating_mul(1024 * 1024);
    Ok(used.unwrap_or(0).max(0) as u64 >= quota)
}

/// Origins whose entries this node does not take right now: purged ones,
/// ones over their quota, and nodes nobody admitted whose parking space is
/// full. A sync round does not ask for them, so they cannot crowd out
/// entries this node does take.
pub async fn refused_origins(node: &Node) -> Result<HashSet<NodeId>> {
    let mut conn = node.store.pool.acquire().await?;
    let mut out = purged_set(&mut conn).await?;
    if node.cfg.origin_quota_mb > 0 {
        let quota = node.cfg.origin_quota_mb.saturating_mul(1024 * 1024);
        let over: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT origin FROM origin_usage WHERE bytes >= ?")
                .bind(quota.min(i64::MAX as u64) as i64)
                .fetch_all(&mut *conn)
                .await?;
        out.extend(over.iter().filter_map(|o| NodeId::from_slice(o).ok()));
    }
    let full: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT origin FROM repl_pending GROUP BY origin
         HAVING COUNT(*) >= ? OR SUM(length(entry)) >= ?",
    )
    .bind(PARK_UNTRUSTED_ENTRIES)
    .bind(PARK_UNTRUSTED_BYTES)
    .fetch_all(&mut *conn)
    .await?;
    for o in full {
        let Ok(id) = NodeId::from_slice(&o) else {
            continue;
        };
        if !trusted(node, &mut conn, &id).await? {
            out.insert(id);
        }
    }
    out.remove(&node.id());
    Ok(out)
}

/// Entries after each `(origin, seq)`, in order, within the given budget.
/// Always returns at least one entry when one is available. Each origin
/// gets a share of the budget, so one origin the receiver refuses cannot
/// fill every batch.
pub async fn entries_after(
    store: &crate::store::Store,
    wants: &[(NodeId, u64)],
    max_entries: usize,
    max_bytes: usize,
) -> Result<Batch> {
    let mut conn = store.pool.acquire().await?;
    let purged = purged_set(&mut conn).await?;
    let share = (max_entries / wants.len().max(1)).max(100).min(max_entries);
    let mut out: Vec<WireEntry> = vec![];
    let mut bytes = 0usize;
    let full = |out: &Vec<WireEntry>, bytes: usize| {
        out.len() >= max_entries || (bytes >= max_bytes && !out.is_empty())
    };
    for (origin, after) in wants {
        if full(&out, bytes) {
            break;
        }
        // Purged here: not ours to relay any more.
        if purged.contains(origin) {
            continue;
        }
        let limit = share.min(max_entries - out.len());
        let mut taken = 0;
        let mut next = *after + 1;
        let rows: Vec<LogRow> = sqlx::query_as(
            "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by FROM repl_log
             WHERE origin = ? AND seq > ? ORDER BY seq LIMIT ?",
        )
        .bind(&origin.0[..])
        .bind(*after as i64)
        .bind(limit as i64)
        .fetch_all(&mut *conn)
        .await?;
        let mut parked = vec![];
        if rows.len() < limit {
            // Parked entries (origin not trusted here yet) are relayed too,
            // within the parking limits; every receiver verifies signatures
            // and trust itself.
            let blobs: Vec<Vec<u8>> = sqlx::query_scalar(
                "SELECT entry FROM repl_pending WHERE origin = ? AND seq > ? ORDER BY seq LIMIT ?",
            )
            .bind(&origin.0[..])
            .bind(*after as i64)
            .bind(limit as i64)
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
            if e.seq != next || full(&out, bytes) || taken >= limit {
                break;
            }
            bytes += e.payload.as_ref().map_or(0, Vec::len) + 128;
            next += 1;
            taken += 1;
            out.push(e);
        }
    }
    // Erased entries travel with the tombstone that erased them.
    let mut proofs = vec![];
    let mut seen = HashSet::new();
    for e in &out {
        if e.payload.is_some() {
            continue;
        }
        let Some(tomb) = &e.erased_by else { continue };
        if seen.insert((e.origin, tomb.clone()))
            && let Some(p) = held_proof(&mut conn, &e.origin, tomb).await?
        {
            proofs.push(p);
        }
    }
    Ok(Batch {
        entries: out,
        proofs,
    })
}

/// The tombstone `tomb_uid` of `origin` as we hold it: in the log, or
/// stored as a proof ahead of its arrival there.
async fn held_proof(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    tomb_uid: &str,
) -> Result<Option<WireEntry>> {
    let row: Option<LogRow> = sqlx::query_as(
        "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by FROM repl_log
         WHERE origin = ? AND kind = 'tombstone' AND uid = ? AND payload IS NOT NULL",
    )
    .bind(&origin.0[..])
    .bind(tomb_uid)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(r) = row {
        return Ok(Some(from_row(r)?));
    }
    let blob: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT entry FROM tomb_proofs WHERE origin = ? AND tomb_uid = ?")
            .bind(&origin.0[..])
            .bind(tomb_uid)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(match blob {
        Some(b) => Some(super::rpc::cbor::decode(&b)?),
        None => None,
    })
}

/// Whether `proof` is a tombstone, signed by the stub's origin, that names
/// exactly this entry: its uid at its position in the origin's log. The
/// stub itself is unsigned, so nothing else in it is taken on trust.
fn proves(proof: &WireEntry, e: &WireEntry) -> bool {
    let (Some(uid), Some(tomb)) = (&e.uid, &e.erased_by) else {
        return false;
    };
    proof.origin == e.origin
        && proof.kind == "tombstone"
        && proof.uid.as_deref() == Some(tomb.as_str())
        && e.seq < proof.seq
        && uid.starts_with(&e.origin.uid_prefix())
        && proof.verify()
        && matches!(proof.record(), Some(Record::Tombstone(t))
            if t.uids.len() == t.seqs.len()
                && t.uids.iter().zip(&t.seqs).any(|(u, s)| u == uid && *s == e.seq))
}

/// Check an erased stub against the batch's proofs and the tombstones we
/// hold. A proof that is new to us is stored so we can relay the erasure.
async fn erasure_proven(
    conn: &mut SqliteConnection,
    proofs: &[WireEntry],
    e: &WireEntry,
) -> Result<bool> {
    let Some(tomb) = &e.erased_by else {
        return Ok(false);
    };
    if let Some(held) = held_proof(conn, &e.origin, tomb).await? {
        return Ok(proves(&held, e));
    }
    let Some(p) = proofs.iter().find(|p| proves(p, e)) else {
        return Ok(false);
    };
    sqlx::query("INSERT OR IGNORE INTO tomb_proofs (origin, tomb_uid, entry) VALUES (?, ?, ?)")
        .bind(&e.origin.0[..])
        .bind(tomb)
        .bind(super::rpc::cbor::encode(p)?)
        .execute(&mut *conn)
        .await?;
    Ok(true)
}

/// Raise the held head of `origin` to `seq` (heads only grow, except when
/// [`expire_parked`] drops parked entries).
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

/// Store a log entry. `state` is one of the `repl_log.applied` states.
async fn insert_log(conn: &mut SqliteConnection, e: &WireEntry, state: i64) -> Result<()> {
    bump_head(conn, &e.origin, e.seq).await?;
    let accounted = (e.payload.as_ref().map_or(0, Vec::len) + 128) as i64;
    sqlx::query(
        "INSERT INTO repl_log (origin, seq, hlc, kind, uid, payload, sig, erased_by, applied,
                               received_at, accounted)
         VALUES (?,?,?,?,?,?,?,?,?,datetime('now'),?)",
    )
    .bind(&e.origin.0[..])
    .bind(e.seq as i64)
    .bind(e.hlc as i64)
    .bind(&e.kind)
    .bind(&e.uid)
    .bind(&e.payload)
    .bind(&e.sig)
    .bind(&e.erased_by)
    .bind(state)
    .bind(accounted)
    .execute(&mut *conn)
    .await?;
    // What the origin costs this node (its quota); row-backed payloads are
    // counted at arrival, which is about what their rows take.
    sqlx::query(
        "INSERT INTO origin_usage (origin, bytes, entries) VALUES (?, ?, 1)
         ON CONFLICT(origin) DO UPDATE SET bytes = bytes + excluded.bytes, entries = entries + 1",
    )
    .bind(&e.origin.0[..])
    .bind(accounted)
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
    // Peers drop an entry whose uid is not bound to its origin, and with it
    // everything after it in our log: never write one.
    if let Some(uid) = &e.uid
        && !uid.starts_with(&me.uid_prefix())
    {
        anyhow::bail!("record uid `{uid}` does not carry this node's prefix");
    }
    insert_log(conn, &e, APPLIED).await?;
    let settled = apply_record(node, conn, &e, record, hlc::wall_ms()).await?;
    if settled.deferred {
        mark_deferred(conn, &e.origin, e.seq, settled.wait_uid.as_deref()).await?;
    }
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
    insert_log(conn, &e, APPLIED).await?;
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
pub async fn apply_batch(node: &Node, batch: impl Into<Batch>) -> Result<Applied> {
    let Batch { entries, proofs } = batch.into();
    let mut st = Applied::default();
    if entries.is_empty() {
        return Ok(st);
    }
    let guard = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    for e in entries {
        apply_one(node, &mut tx, e, &proofs, &mut st).await?;
    }
    if st.applied > 0 {
        drain_pending(node, &mut tx, &mut st).await?;
        // Newly-applied entries may be the parent of earlier deferred ones
        // (those waiting for them were made due).
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
    proofs: &[WireEntry],
    st: &mut Applied,
) -> Result<()> {
    // Purged here: neither stored nor relayed any more.
    if is_purged(conn, &e.origin).await? {
        st.rejected += 1;
        return Ok(());
    }
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
    // Over its quota: the origin's stream stops here (no gap is left; the
    // rest is offered again and refused).
    if over_quota(node, conn, &e.origin).await? {
        debug!(origin = %e.origin.short(), "entry over the origin's storage quota refused");
        st.rejected += 1;
        return Ok(());
    }
    if e.payload.is_none() {
        return apply_stub(node, conn, e, held > have, proofs, st).await;
    }
    // A uid must carry its origin's prefix: otherwise a node could create a
    // record under another node's uid and shadow or delete the original.
    if let Some(uid) = &e.uid
        && !uid.starts_with(&e.origin.uid_prefix())
    {
        warn!(origin = %e.origin.short(), seq = e.seq, "entry whose uid is not bound to its origin dropped");
        st.rejected += 1;
        return Ok(());
    }
    // Verify before parking too, so junk never takes up space or blocks
    // the real entry at that position.
    if !e.verify() {
        warn!(origin = %e.origin.short(), seq = e.seq, "entry with bad signature dropped");
        st.rejected += 1;
        return Ok(());
    }
    let untrusted = !trusted(node, conn, &e.origin).await?;
    if held > have || untrusted {
        return park_or_refuse(conn, &e, untrusted, st).await;
    }
    apply_verified(node, conn, e, st).await
}

/// Park an entry, unless it comes from a node nobody admitted and that
/// node's parking space (or the room for such nodes) is used up.
async fn park_or_refuse(
    conn: &mut SqliteConnection,
    e: &WireEntry,
    untrusted: bool,
    st: &mut Applied,
) -> Result<()> {
    let blob = super::rpc::cbor::encode(e)?;
    if untrusted {
        let (n, bytes): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(length(entry)), 0) FROM repl_pending WHERE origin = ?",
        )
        .bind(&e.origin.0[..])
        .fetch_one(&mut *conn)
        .await?;
        let room = if n == 0 {
            let origins: i64 =
                sqlx::query_scalar("SELECT COUNT(DISTINCT origin) FROM repl_pending")
                    .fetch_one(&mut *conn)
                    .await?;
            origins < PARK_ORIGINS
        } else {
            true
        };
        if !room || n >= PARK_UNTRUSTED_ENTRIES || bytes + blob.len() as i64 > PARK_UNTRUSTED_BYTES
        {
            debug!(origin = %e.origin.short(), seq = e.seq, "parking space of an unknown node full");
            st.rejected += 1;
            return Ok(());
        }
    }
    park(conn, e, blob).await?;
    st.parked += 1;
    Ok(())
}

/// Store an entry we cannot apply yet (a gap ahead, or its origin not trusted
/// here yet) and advance the held head so the stream can continue; a later
/// [`drain_pending`] applies it once the obstacle clears.
async fn park(conn: &mut SqliteConnection, e: &WireEntry, blob: Vec<u8>) -> Result<()> {
    sqlx::query(
        "INSERT INTO repl_pending (origin, seq, entry, received_at) VALUES (?,?,?,datetime('now'))",
    )
    .bind(&e.origin.0[..])
    .bind(e.seq as i64)
    .bind(blob)
    .execute(&mut *conn)
    .await?;
    bump_head(conn, &e.origin, e.seq).await?;
    Ok(())
}

/// An entry its origin deleted (payload erased, `erased_by` naming the
/// tombstone). The tombstone sits *later* in the same origin's in-order
/// stream, so the stub cannot wait for it; instead it must come with that
/// tombstone as proof: signed by the stub's origin and listing its uid. A
/// stub without one is rejected, so a relay cannot make this node drop
/// records their origin never deleted.
async fn apply_stub(
    node: &Node,
    conn: &mut SqliteConnection,
    e: WireEntry,
    blocked: bool,
    proofs: &[WireEntry],
    st: &mut Applied,
) -> Result<()> {
    if !erasure_proven(conn, proofs, &e).await? {
        warn!(origin = %e.origin.short(), seq = e.seq, "erased entry without a valid tombstone dropped");
        st.rejected += 1;
        return Ok(());
    }
    let untrusted = !trusted(node, conn, &e.origin).await?;
    if blocked || untrusted {
        return park_or_refuse(conn, &e, untrusted, st).await;
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
    insert_log(conn, e, APPLIED).await?;
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
        Record::JobAdopt(a) => a.job_uids.iter().take(MAX_ADOPT).collect(),
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
    // A kind this build does not know is kept (and relayed) and applied
    // after an upgrade, never retried before.
    let state = if record.is_some() {
        APPLIED
    } else {
        UNKNOWN_KIND
    };
    insert_log(conn, &e, state).await?;
    if let Some(r) = &record {
        let settled = apply_record(node, conn, &e, r, hlc::wall_ms()).await?;
        st.membership_changed |= settled.membership;
        if settled.deferred {
            // Not applicable yet: kept for retry_deferred.
            mark_deferred(conn, &e.origin, e.seq, settled.wait_uid.as_deref()).await?;
        }
        // Sent before commit; listeners re-read the row after a moment.
        announce_job(node, &e.kind, r);
    }
    node.hlc.observe(e.hlc);
    st.applied += 1;
    Ok(())
}

/// Keep an entry unapplied for a later retry: due again after a backoff
/// that doubles from 30 s to an hour, or as soon as `wait_uid` (the row it
/// waits for) arrives. After [`DEFER_MAX_AGE`] it is given up.
async fn mark_deferred(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    seq: u64,
    wait_uid: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE repl_log SET
           applied = CASE WHEN received_at < datetime('now', ?) THEN 3 ELSE 0 END,
           wait_uid = ?, retry_attempts = retry_attempts + 1,
           retry_after = ? + MIN(30000 << MIN(retry_attempts, 7), 3600000)
         WHERE origin = ? AND seq = ?",
    )
    .bind(DEFER_MAX_AGE)
    .bind(wait_uid)
    .bind(hlc::wall_ms() as i64)
    .bind(&origin.0[..])
    .bind(seq as i64)
    .execute(&mut *conn)
    .await?;
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
    let rows: Vec<TimedRow> = sqlx::query_as(
        "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by,
                CAST(strftime('%s', received_at) AS INTEGER) * 1000
         FROM repl_log WHERE applied = 2 ORDER BY hlc",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut n = 0;
    for r in rows {
        let (e, received) = from_timed(r)?;
        let Some(rec) = e.record() else { continue };
        let settled = apply_record(node, &mut tx, &e, &rec, received).await?;
        if settled.deferred {
            mark_deferred(&mut tx, &e.origin, e.seq, settled.wait_uid.as_deref()).await?;
        } else {
            set_applied(&mut tx, &e).await?;
            n += 1;
        }
    }
    tx.commit().await?;
    Ok(n)
}

async fn set_applied(conn: &mut SqliteConnection, e: &WireEntry) -> Result<()> {
    sqlx::query("UPDATE repl_log SET applied = 1, wait_uid = NULL WHERE origin = ? AND seq = ?")
        .bind(&e.origin.0[..])
        .bind(e.seq as i64)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Re-apply deferred entries that are due: their backoff passed, or the row
/// they wait for arrived. Bounded per call, so a pile of entries that never
/// resolve cannot make every batch slow; the rest waits for the next call.
/// Runs inside the caller's transaction.
async fn retry_deferred(node: &Node, conn: &mut SqliteConnection, st: &mut Applied) -> Result<()> {
    let mut done = 0;
    while done < RETRY_MAX_PER_CALL {
        // `applied != 1` lets SQLite use the partial index.
        let rows: Vec<TimedRow> = sqlx::query_as(
            "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by,
                    CAST(strftime('%s', received_at) AS INTEGER) * 1000
             FROM repl_log
             WHERE applied != 1 AND applied = ? AND retry_after <= ? AND payload IS NOT NULL
             ORDER BY hlc LIMIT ?",
        )
        .bind(DEFERRED)
        .bind(hlc::wall_ms() as i64)
        .bind(RETRY_BATCH)
        .fetch_all(&mut *conn)
        .await?;
        if rows.is_empty() {
            break;
        }
        done += rows.len();
        for r in rows {
            let (e, received) = from_timed(r)?;
            let Some(rec) = e.record() else {
                sqlx::query("UPDATE repl_log SET applied = ? WHERE origin = ? AND seq = ?")
                    .bind(UNKNOWN_KIND)
                    .bind(&e.origin.0[..])
                    .bind(e.seq as i64)
                    .execute(&mut *conn)
                    .await?;
                continue;
            };
            let settled = apply_record(node, conn, &e, &rec, received).await?;
            st.membership_changed |= settled.membership;
            if settled.deferred {
                // Pushes its retry time out, so this call does not see it again.
                mark_deferred(conn, &e.origin, e.seq, settled.wait_uid.as_deref()).await?;
            } else {
                set_applied(conn, &e).await?;
                announce_job(node, &e.kind, &rec);
            }
        }
    }
    Ok(())
}

/// Retry deferred entries whose time has come (periodically, so a deferral
/// that waits for time, like an adoption, resolves without new entries).
pub async fn retry_due(node: &Node) -> Result<()> {
    let guard = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let mut st = Applied::default();
    retry_deferred(node, &mut tx, &mut st).await?;
    tx.commit().await?;
    drop(guard);
    if st.membership_changed {
        node.reload_members().await?;
    }
    Ok(())
}

/// Drop the parked entries of nodes nobody admitted once the oldest is past
/// [`PARK_TTL`]; their held head goes back down, so if the node is admitted
/// later its entries are simply fetched again. Returns how many origins
/// were dropped.
pub async fn expire_parked(node: &Node) -> Result<usize> {
    let guard = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let origins: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT DISTINCT origin FROM repl_pending WHERE received_at < datetime('now', ?)",
    )
    .bind(PARK_TTL)
    .fetch_all(&mut *tx)
    .await?;
    let mut n = 0;
    for o in origins {
        let id = NodeId::from_slice(&o)?;
        if trusted(node, &mut tx, &id).await? {
            continue;
        }
        sqlx::query("DELETE FROM repl_pending WHERE origin = ?")
            .bind(&o)
            .execute(&mut *tx)
            .await?;
        reset_head(&mut tx, &id).await?;
        n += 1;
    }
    tx.commit().await?;
    drop(guard);
    if n > 0 {
        info!(origins = n, "parked entries of unknown nodes expired");
    }
    Ok(n)
}

/// Set the held head of `origin` back to what its log holds.
pub(crate) async fn reset_head(conn: &mut SqliteConnection, origin: &NodeId) -> Result<()> {
    let held = log_head(conn, origin)
        .await?
        .max(pending_head(conn, origin).await?);
    if held == 0 {
        sqlx::query("DELETE FROM repl_heads WHERE origin = ?")
            .bind(&origin.0[..])
            .execute(&mut *conn)
            .await?;
    } else {
        sqlx::query("UPDATE repl_heads SET seq = ? WHERE origin = ?")
            .bind(held as i64)
            .bind(&origin.0[..])
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Drop what is safe to drop: tombstones held as proofs that have since
/// arrived in their origin's log (the log copy serves as proof). Returns
/// how many rows went.
pub async fn compact(node: &Node) -> Result<u64> {
    let _g = node.apply_lock.lock().await;
    Ok(sqlx::query(
        "DELETE FROM tomb_proofs WHERE EXISTS (
           SELECT 1 FROM repl_log l WHERE l.origin = tomb_proofs.origin
             AND l.kind = 'tombstone' AND l.uid = tomb_proofs.tomb_uid AND l.payload IS NOT NULL)",
    )
    .execute(&node.store.pool)
    .await?
    .rows_affected())
}

/// Entries replayed per transaction by [`rematerialize`], so the write lock
/// is never held for long.
const REPLAY_BATCH: usize = 1000;

/// Apply log entries that are held with their payload but have no row:
/// after an unblock, everything the block kept out of the tables. Records an
/// admin hid stay hidden. Returns how many entries were looked at.
pub async fn rematerialize(node: &Node) -> Result<usize> {
    // Parents first; job state after the jobs it refers to. Only the keys
    // are collected up front; the entries are loaded batch by batch.
    let keys: Vec<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT origin, seq FROM repl_log
         WHERE payload IS NOT NULL
           AND kind IN ('request','scan_job','job_adopt','job_status','fp_claim',
                        'fingerprint','scan_result','ip_intel','skip_batch')
         ORDER BY CASE kind WHEN 'request' THEN 0 WHEN 'scan_job' THEN 1
                            WHEN 'job_adopt' THEN 2 WHEN 'job_status' THEN 3 ELSE 4 END, hlc",
    )
    .fetch_all(&node.store.pool)
    .await?;
    for batch in keys.chunks(REPLAY_BATCH) {
        let _g = node.apply_lock.lock().await;
        let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        for (origin, seq) in batch {
            let row: Option<TimedRow> = sqlx::query_as(
                "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by,
                        CAST(strftime('%s', received_at) AS INTEGER) * 1000
                 FROM repl_log WHERE origin = ? AND seq = ?",
            )
            .bind(origin)
            .bind(seq)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((e, received)) = row.map(from_timed).transpose()? else {
                continue;
            };
            if let Some(rec) = e.record() {
                apply_record(node, &mut tx, &e, &rec, received).await?;
            }
        }
        tx.commit().await?;
    }
    node.notify_changed();
    Ok(keys.len())
}

/// What applying a record did, beyond its table effects.
#[derive(Default, Clone)]
struct Settled {
    membership: bool,
    /// The record cannot apply yet (a parent row is missing, or an adoption
    /// is not due here yet); keep the entry unapplied.
    deferred: bool,
    /// The uid whose arrival makes a deferred entry due at once.
    wait_uid: Option<String>,
}

/// The parent a record may wait for.
fn waits_for(r: &Record) -> Option<String> {
    match r {
        Record::JobStatus(s) => Some(s.job_uid.clone()),
        Record::ScanResult(s) => Some(s.job_uid.clone()),
        _ => None,
    }
}

/// Effects of one record on the materialized tables, then settle its log
/// entry: erased if a tombstone already deleted it, payload dropped if it
/// can be rebuilt from its row. `received_ms` is when the entry reached this
/// node: what the record is ordered by never lies further ahead than that
/// (see [`hlc::effective`]).
async fn apply_record(
    node: &Node,
    conn: &mut SqliteConnection,
    e: &WireEntry,
    r: &Record,
    received_ms: u64,
) -> Result<Settled> {
    let at = hlc::effective(e.hlc, received_ms);
    if super::members::apply(node, conn, e, r, at).await? {
        return Ok(Settled {
            membership: true,
            ..Default::default()
        });
    }
    if let Record::JobAdopt(a) = r {
        return adopt(node, conn, e, a, at).await;
    }
    let ctx = Ctx {
        origin: Some(&e.origin),
        hlc: at,
    };
    match data::apply(conn, ctx, r).await? {
        Effect::Deferred => {
            return Ok(Settled {
                deferred: true,
                wait_uid: waits_for(r),
                ..Default::default()
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
        Effect::Applied => {
            // Entries waiting for this job are due now.
            if let Record::ScanJob(j) = r {
                sqlx::query(
                    "UPDATE repl_log SET retry_after = 0 WHERE wait_uid = ? AND applied = 0",
                )
                .bind(&j.uid)
                .execute(&mut *conn)
                .await?;
            }
            if ROW_BACKED.contains(&e.kind.as_str()) {
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
        }
        Effect::Ignored => {}
    }
    Ok(Settled::default())
}

/// A takeover of scan jobs. Every node decides for itself whether it is
/// due, from what it observed, not from what the adopter claims: a job
/// moves once its arbiter has been silent here for `takeover_hours` (or is
/// blocked here), or once the job itself has not changed for that long (an
/// arbiter that keeps running but never hands it out). Until then the
/// entry is deferred and retried. Adoptions by nodes blocked here are
/// ignored.
async fn adopt(
    node: &Node,
    conn: &mut SqliteConnection,
    e: &WireEntry,
    a: &JobAdoptRec,
    at: u64,
) -> Result<Settled> {
    if node.is_blocked(&e.origin) {
        return Ok(Settled::default());
    }
    let window_ms = (node.cfg.takeover_hours * 3_600_000.0) as u64;
    let from_gone = a.from != node.id()
        && (node.is_blocked(&a.from) || node.silent_for(&a.from).as_millis() as u64 >= window_ms);
    let now = hlc::wall_ms();
    let mut waiting = false;
    for uid in a.job_uids.iter().take(MAX_ADOPT) {
        let Some(row) = data::adopt_row(conn, uid).await? else {
            // Not replicated here yet, unless it is gone for good.
            waiting |= !data::gone(conn, uid).await?;
            continue;
        };
        if !["queued", "running"].contains(&row.status.as_str())
            || (row.arbiter != Some(a.from) && row.adopted_from != Some(a.from))
        {
            continue;
        }
        // Already taken over from `from` here by another node: this node
        // judged it due then, so only the rank decides between adopters.
        let contested = row.arbiter != Some(a.from);
        let stale = now.saturating_sub(hlc::physical_ms(row.changed_hlc)) >= window_ms;
        if contested || from_gone || stale {
            data::adopt_one(conn, &e.origin, &a.from, uid, at).await?;
        } else {
            waiting = true;
        }
    }
    Ok(Settled {
        deferred: waiting,
        ..Default::default()
    })
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
                remote_config: false,
                origin_quota_mb: 20 * 1024,
                peers: vec![],
            },
            roles: Default::default(),
            store: store.clone(),
            proto: (1, 1),
            data_dir: dir.path().to_path_buf(),
            retention_days: 0,
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
                remote_config: false,
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
