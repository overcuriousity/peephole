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
use super::record::{JobAdoptRec, ROW_BACKED, Record, Seal, WireEntry};
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
/// Dated no later than its origin's previous entry: kept and relayed, never
/// applied (see [`in_order`]).
const OUT_OF_ORDER: i64 = 4;

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

/// Heads as reported to a peer holding `theirs`: a purged origin at what
/// the peer holds (absent if it holds none), so the peer neither pulls what
/// is no longer served here nor pushes what is no longer accepted.
pub fn advertised(ours: Heads, purged: &HashSet<NodeId>, theirs: &HeadMap) -> Heads {
    ours.into_iter()
        .filter_map(|(o, s)| {
            if purged.contains(&o) {
                theirs.get(&o).map(|t| (o, *t))
            } else {
                Some((o, s))
            }
        })
        .collect()
}

/// What of a peer's `wants` this node can serve: each origin once, and only
/// origins it holds past what is asked for. A request names any number of
/// origins; this keeps it to at most one per head held here, and an
/// unknown origin costs no query.
pub fn servable_wants(wants: Vec<(NodeId, u64)>, ours: &HeadMap) -> Vec<(NodeId, u64)> {
    let mut seen = HashSet::new();
    wants
        .into_iter()
        .filter(|(o, after)| ours.get(o).is_some_and(|h| h > after) && seen.insert(*o))
        .collect()
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
///
/// The history sent starts at this node's floor, or for a receiver that
/// keeps a window (`since_hlc > 0`) at the first entry inside it, whichever
/// is later. When that is past what was asked for, the membership entries
/// before it go along and `floors` says where the full history starts.
///
/// `old_peer`: an older member: each origin stops at its first entry only
/// protocol 7 knows (`WireEntry::needs_economy_proto`), so it never sees a
/// gap; it catches up once it upgrades.
pub async fn entries_after(
    store: &crate::store::Store,
    wants: &[(NodeId, u64)],
    since_hlc: u64,
    max_entries: usize,
    max_bytes: usize,
    old_peer: bool,
) -> Result<Batch> {
    let mut conn = store.pool.acquire().await?;
    let purged = purged_set(&mut conn).await?;
    let floors = super::history::floors(&mut conn).await?;
    let mut declared = vec![];
    let mut bounds = vec![];
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
        // `after` comes from the peer: no overflow, no negative bind.
        let after = (*after).min(i64::MAX as u64);
        let mut start = (after + 1).max(floors.get(origin).copied().unwrap_or(1));
        if since_hlc > 0 {
            start = start.max(super::history::cut(&mut conn, origin, start, since_hlc).await?);
        }
        if start > after + 1 {
            let bound = signed_entry(&mut conn, origin, start - 1).await?;
            // An older member could not verify a bound only protocol 7
            // knows: this origin waits until it upgrades.
            if old_peer && bound.as_ref().is_some_and(|b| b.needs_economy_proto()) {
                continue;
            }
            declared.push((*origin, start));
            if let Some(b) = bound {
                bounds.push(b);
            }
        }
        let mut next = start;
        let rows: Vec<LogRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by FROM repl_log
             WHERE origin = ? AND seq > ? AND (seq >= ? OR kind IN {})
             ORDER BY seq LIMIT ?",
            super::history::MEMBERSHIP_SQL
        )))
        .bind(&origin.0[..])
        .bind(after as i64)
        .bind(start.min(i64::MAX as u64) as i64)
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
            .bind((start - 1).min(i64::MAX as u64) as i64)
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
            if old_peer && e.needs_economy_proto() {
                break;
            }
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
            // Membership below the start of the full history.
            if e.seq < start {
                if full(&out, bytes) || taken >= limit {
                    break;
                }
                bytes += e.payload.as_ref().map_or(0, Vec::len) + 128;
                taken += 1;
                out.push(e);
                continue;
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
    // Membership ahead of the data: a few small entries per origin, so the
    // receiver trusts the members it would otherwise only learn about once
    // the whole history in front of their admissions has arrived.
    let mut membership = vec![];
    for (origin, after) in wants {
        if purged.contains(origin) || membership.len() >= MEMBERSHIP_AHEAD {
            continue;
        }
        let sent = out
            .iter()
            .filter(|e| e.origin == *origin)
            .map(|e| e.seq)
            .max()
            .unwrap_or(0)
            .max(*after)
            .min(i64::MAX as u64);
        let rows: Vec<LogRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by FROM repl_log
             WHERE origin = ? AND seq > ? AND kind IN {} AND payload IS NOT NULL
             ORDER BY seq LIMIT ?",
            super::history::MEMBERSHIP_SQL
        )))
        .bind(&origin.0[..])
        .bind(sent as i64)
        .bind((MEMBERSHIP_AHEAD - membership.len()) as i64)
        .fetch_all(&mut *conn)
        .await?;
        for r in rows {
            membership.push(from_row(r)?);
        }
    }
    Ok(Batch {
        entries: out,
        proofs,
        floors: declared,
        bounds,
        membership,
    })
}

/// Most membership entries sent ahead in one batch.
const MEMBERSHIP_AHEAD: usize = 2000;

/// Every membership entry this node holds with its payload, oldest first:
/// the cluster's membership for a node that is just joining.
pub async fn membership_entries(store: &crate::store::Store) -> Result<Vec<WireEntry>> {
    let rows: Vec<LogRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by FROM repl_log
         WHERE kind IN {} AND payload IS NOT NULL ORDER BY hlc LIMIT ?",
        super::history::MEMBERSHIP_SQL
    )))
    .bind(MEMBERSHIP_AHEAD as i64)
    .fetch_all(&store.pool)
    .await?;
    rows.into_iter().map(from_row).collect()
}

/// Apply membership entries before the log in front of them arrives: only
/// their effect on the member list (`members::apply`, which takes them
/// again harmlessly when they arrive in order), not the log entry, so each
/// origin's log stays gap-free. Each must be signed by its origin, and its
/// origin trusted here, perhaps through an admission earlier in the same
/// list, and keep its origin's order like an entry of the log would (see
/// [`ahead_in_order`]). Returns how many were taken.
pub async fn apply_membership_ahead(node: &Node, entries: &[WireEntry]) -> Result<usize> {
    let me = node.id();
    let mut todo: Vec<&WireEntry> = entries
        .iter()
        .filter(|e| {
            e.origin != me
                && e.payload.is_some()
                && super::history::MEMBERSHIP.contains(&e.kind.as_str())
        })
        .collect();
    if todo.is_empty() {
        return Ok(0);
    }
    todo.sort_by_key(|e| (e.hlc, e.seq));
    let guard = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let mut taken = 0;
    // The last entry taken of each origin: (seq, hlc).
    let mut last: HashMap<NodeId, (u64, u64)> = HashMap::new();
    loop {
        let mut rest = vec![];
        let before = taken;
        for e in todo {
            if is_purged(&mut tx, &e.origin).await? || hlc::ahead(e.hlc, hlc::wall_ms()) {
                continue;
            }
            if !trusted(node, &mut tx, &e.origin).await? {
                rest.push(e);
                continue;
            }
            if !ahead_in_order(&mut tx, e, last.get(&e.origin).copied()).await? {
                continue;
            }
            let Some(r) = e.record().filter(|_| e.verify()) else {
                continue;
            };
            super::members::apply(node, &mut tx, e, &r, hlc::to_db(e.hlc) as u64).await?;
            last.insert(e.origin, (e.seq, e.hlc));
            taken += 1;
        }
        todo = rest;
        if taken == before || todo.is_empty() {
            break;
        }
    }
    tx.commit().await?;
    drop(guard);
    if taken > 0 {
        node.reload_members().await?;
        node.notify_changed();
    }
    Ok(taken)
}

/// Whether a membership entry sent ahead keeps its origin's order: past
/// the log held of it, dated after the latest entry held in order (as
/// [`in_order`] judges entries of the log), after its admissions taken
/// ahead before, and after `last`, the entry of it taken just before in
/// the same list, in sequence too. Otherwise a member could sign entries
/// at made-up sequences, dated back past what is held, and admit more than
/// [`super::members::ADMISSIONS_PER_DAY`]: the daily count holds every
/// earlier admission only while each sponsor's admissions rise.
async fn ahead_in_order(
    conn: &mut SqliteConnection,
    e: &WireEntry,
    last: Option<(u64, u64)>,
) -> Result<bool> {
    if last.is_some_and(|(seq, at)| e.seq <= seq || e.hlc <= at) {
        return Ok(false);
    }
    if e.seq <= log_head(conn, &e.origin).await? || !in_order(conn, e).await? {
        return Ok(false);
    }
    let admitted: Option<i64> =
        sqlx::query_scalar("SELECT MAX(hlc) FROM sponsorships WHERE sponsor = ?")
            .bind(&e.origin.0[..])
            .fetch_one(&mut *conn)
            .await?;
    Ok(admitted.is_none_or(|a| hlc::to_db(e.hlc) > a))
}

/// `origin`'s entry `seq` with its signed payload (rebuilt from its row if
/// need be); None if it is not held or erased.
pub(crate) async fn signed_entry(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    seq: u64,
) -> Result<Option<WireEntry>> {
    let row: Option<LogRow> = sqlx::query_as(
        "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by FROM repl_log
         WHERE origin = ? AND seq = ? AND sig IS NOT NULL",
    )
    .bind(&origin.0[..])
    .bind(seq.min(i64::MAX as u64) as i64)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(mut e) = row.map(from_row).transpose()? else {
        return Ok(None);
    };
    if e.payload.is_none() {
        let rebuilt = match &e.uid {
            Some(uid) => data::rebuild(conn, &e.kind, uid).await?,
            None => None,
        };
        let Some(r) = rebuilt else { return Ok(None) };
        e.payload = Some(super::rpc::cbor::encode(&r)?);
    }
    Ok(Some(e))
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
                               received_at, accounted, digest)
         VALUES (?,?,?,?,?,?,?,?,?,datetime('now'),?,?)",
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
    // While the payload is here: a row-backed entry gives it up below.
    .bind(e.digest().map(|d| d.to_vec()))
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
    let settled = apply_record(node, conn, &e, record).await?;
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
    // A local admission (an invite redeemed, a join) can make parked
    // entries of the admitted node applicable.
    if members {
        let mut st = Applied::default();
        drain_pending(node, &mut tx, &mut st).await?;
        if st.applied > 0 {
            retry_deferred(node, &mut tx, &mut st).await?;
        }
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

/// Append one sealing record created by this node (an offer, a transfer,
/// a `log_seal`). `make` gets the seal for the position the entry takes,
/// computed in the same transaction that writes it.
pub async fn append_sealing(node: &Node, make: impl FnOnce(Seal) -> Record) -> Result<WireEntry> {
    let guard = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let me = node.id();
    let seq = log_head(&mut tx, &me)
        .await?
        .max(pending_head(&mut tx, &me).await?)
        + 1;
    let seal = super::seal::next(&mut tx, &me, seq).await?;
    let record = make(seal);
    let (e, _) = append_in_tx(node, &mut tx, &record).await?;
    tx.commit().await?;
    drop(guard);
    node.own_head
        .fetch_max(e.seq, std::sync::atomic::Ordering::Relaxed);
    node.notify_changed();
    Ok(e)
}

/// Apply entries received from a peer (any origin). A windowed node skips
/// history only with proof (see [`apply_batch_with`]).
pub async fn apply_batch(node: &Node, batch: impl Into<Batch>) -> Result<Applied> {
    apply_batch_with(node, batch, |_| false).await
}

/// Apply entries received from a peer. `skip_ok(origin)`: this node's own
/// sync round found no reachable peer that holds more of that origin than
/// the sender, so a windowed node may start it at the sender's floor
/// without proof that what it skips is older than its window.
pub async fn apply_batch_with(
    node: &Node,
    batch: impl Into<Batch>,
    skip_ok: impl Fn(&NodeId) -> bool,
) -> Result<Applied> {
    let Batch {
        entries,
        proofs,
        floors,
        bounds,
        membership,
    } = batch.into();
    // Members first, so their entries in this batch apply instead of
    // waiting (parked, or refused once their parking space is full).
    apply_membership_ahead(node, &membership).await?;
    // Where each origin may start here, if past what is held. Each bound is
    // looked up by the start it proves and verified at most once.
    let since = node.since_hlc();
    let declared: HashSet<(NodeId, u64)> = floors.iter().copied().collect();
    let mut proven: HashSet<(NodeId, u64)> = HashSet::new();
    for b in &bounds {
        let Some(start) = b.seq.checked_add(1) else {
            continue;
        };
        let key = (b.origin, start);
        if !skip_ok(&b.origin)
            && b.hlc < since
            && declared.contains(&key)
            && !proven.contains(&key)
            && b.verify()
        {
            proven.insert(key);
        }
    }
    let floors: HeadMap = floors
        .into_iter()
        .filter(|f| skip_ok(&f.0) || proven.contains(f))
        .collect();
    let mut st = Applied::default();
    if entries.is_empty() {
        return Ok(st);
    }
    let guard = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    // Each entry in a savepoint: one that cannot be stored is rolled back
    // alone instead of failing the batch, and with it every origin's sync,
    // round after round. Its origin stops there for this batch (its log
    // must stay gap-free); the others go on.
    let mut failed: HashSet<NodeId> = HashSet::new();
    for e in entries {
        if failed.contains(&e.origin) {
            st.rejected += 1;
            continue;
        }
        let (origin, seq) = (e.origin, e.seq);
        let start = floors.get(&e.origin).copied();
        let before = st;
        let mut sp = sqlx::Connection::begin(&mut *tx).await?;
        match apply_one(node, &mut sp, e, &proofs, start, &mut st).await {
            Ok(()) => sp.commit().await?,
            Err(err) => {
                sp.rollback().await?;
                warn!(origin = %origin.short(), seq, error = %format!("{err:#}"),
                      "log entry could not be stored; its origin waits for a later round");
                st = before;
                st.rejected += 1;
                failed.insert(origin);
            }
        }
    }
    // Parked entries may wait for an origin trusted since they were parked
    // (also through a local append), so parking alone is reason to look.
    if st.applied + st.parked > 0 {
        drain_pending(node, &mut tx, &mut st).await?;
    }
    if st.applied > 0 {
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

/// The highest sequence of `origin` below which nothing is missing here:
/// the log head, or just below the floor when the floor lies past it.
async fn complete_to(conn: &mut SqliteConnection, origin: &NodeId) -> Result<u64> {
    let floor = super::history::floor_of(conn, origin).await?;
    Ok(log_head(conn, origin).await?.max(floor - 1))
}

/// `start`: where the sender's full history of this origin begins, when it
/// begins past what was asked for (see [`entries_after`]).
async fn apply_one(
    node: &Node,
    conn: &mut SqliteConnection,
    e: WireEntry,
    proofs: &[WireEntry],
    start: Option<u64>,
    st: &mut Applied,
) -> Result<()> {
    // Purged here: neither stored nor relayed any more.
    if is_purged(conn, &e.origin).await? {
        st.rejected += 1;
        return Ok(());
    }
    // Dated too far ahead: not taken until its time comes (see
    // [`hlc::ahead`]). The origin's stream stops here like at a gap; peers
    // offer the entry again on every round, and other origins go on.
    if hlc::ahead(e.hlc, hlc::wall_ms()) {
        debug!(origin = %e.origin.short(), seq = e.seq, "entry dated too far ahead waits");
        st.rejected += 1;
        return Ok(());
    }
    let mut have = complete_to(conn, &e.origin).await?;
    let mut held = have.max(pending_head(conn, &e.origin).await?);
    // The sender's history starts past ours: a node that keeps only a window
    // takes the membership before that start and moves its floor up to it.
    // A node keeping everything never skips history (the gap is rejected).
    if node.retention_days > 0
        && let Some(start) = start.filter(|s| *s > held + 1)
    {
        let valid = if e.seq < start {
            super::history::MEMBERSHIP.contains(&e.kind.as_str())
                && e.payload.is_some()
                && e.verify()
        } else {
            e.seq == start && acceptable(conn, &e, proofs).await?
        };
        if !valid || !trusted(node, conn, &e.origin).await? {
            st.rejected += 1;
            return Ok(());
        }
        // The floor moves first, so whatever arrives next connects at the
        // start, also when this batch ends before it. The head stays at what
        // is held: membership entries a cut-short batch did not carry are
        // asked for again.
        super::history::raise_floor(conn, &e.origin, start).await?;
        // Parked entries before the new floor will never connect.
        sqlx::query("DELETE FROM repl_pending WHERE origin = ? AND seq < ?")
            .bind(&e.origin.0[..])
            .bind(start.min(i64::MAX as u64) as i64)
            .execute(&mut *conn)
            .await?;
        if e.seq < start {
            return apply_membership_below(node, conn, e, st).await;
        }
        have = start - 1;
        held = have;
    } else if node.retention_days > 0 && start.is_some_and(|s| e.seq < s) {
        // Membership below a start this node already moved to.
        return apply_membership_below(node, conn, e, st).await;
    }
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

/// A membership entry below a sender's floor (see [`apply_one`]): taken
/// once, signed by its origin, in log order among what is held, and only
/// from a trusted origin (a node nobody admitted could otherwise describe
/// itself and then sponsor others past the parking of its entries).
async fn apply_membership_below(
    node: &Node,
    conn: &mut SqliteConnection,
    e: WireEntry,
    st: &mut Applied,
) -> Result<()> {
    if !super::history::MEMBERSHIP.contains(&e.kind.as_str())
        || e.payload.is_none()
        || !e.verify()
        || !trusted(node, conn, &e.origin).await?
    {
        st.rejected += 1;
        return Ok(());
    }
    if e.seq <= log_head(conn, &e.origin).await? {
        st.duplicate += 1;
        return Ok(());
    }
    apply_verified(node, conn, e, st).await
}

/// Whether an entry would pass the checks of the normal path: an erased stub
/// with its proof, or a signed entry whose uid carries its origin's prefix.
async fn acceptable(
    conn: &mut SqliteConnection,
    e: &WireEntry,
    proofs: &[WireEntry],
) -> Result<bool> {
    if e.payload.is_none() {
        return erasure_proven(conn, proofs, e).await;
    }
    Ok(e.uid
        .as_ref()
        .is_none_or(|uid| uid.starts_with(&e.origin.uid_prefix()))
        && e.verify())
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

/// Whether `e` is dated later than the entry its origin signed before it.
/// HLCs rise with the sequence in an honest log (see `Hlc::now`); without
/// this, a member could backdate entries past the windows its limits are
/// judged in (admissions per day, scan jobs per hour).
///
/// The entry before is the latest held with its signature that was itself
/// in order, so neither an out-of-order entry nor an erased stub (whose HLC
/// nobody signed, and which a relay could set to anything) moves the bar.
/// The verdict is the same on every node that holds the same entries. One
/// case is not: an origin that breaks the order right after an entry it
/// later erases is judged against that entry by nodes that got it before
/// the erasure, and against the one before by nodes that only got a stub.
async fn in_order(conn: &mut SqliteConnection, e: &WireEntry) -> Result<bool> {
    let prev: Option<i64> = sqlx::query_scalar(
        "SELECT hlc FROM repl_log
         WHERE origin = ? AND seq < ? AND sig IS NOT NULL AND applied != ?
         ORDER BY seq DESC LIMIT 1",
    )
    .bind(&e.origin.0[..])
    .bind(e.seq.min(i64::MAX as u64) as i64)
    .bind(OUT_OF_ORDER)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(prev.is_none_or(|p| hlc::to_db(e.hlc) > p))
}

async fn apply_verified(
    node: &Node,
    conn: &mut SqliteConnection,
    e: WireEntry,
    st: &mut Applied,
) -> Result<()> {
    // Out of order: kept (the log stays gap-free, and it is relayed like
    // any entry) but never applied, here or on any other node.
    if !in_order(conn, &e).await? {
        warn!(origin = %e.origin.short(), seq = e.seq, kind = %e.kind,
              "entry dated before its origin's previous one ignored");
        insert_log(conn, &e, OUT_OF_ORDER).await?;
        st.applied += 1;
        return Ok(());
    }
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
        let settled = apply_isolated(node, conn, &e, r).await?;
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
                if seq as u64 != complete_to(conn, &origin).await? + 1 {
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
        "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by
         FROM repl_log WHERE applied = 2 ORDER BY hlc",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut n = 0;
    for r in rows {
        let e = from_row(r)?;
        let Some(rec) = e.record() else { continue };
        let settled = apply_isolated(node, &mut tx, &e, &rec).await?;
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
        let rows: Vec<LogRow> = sqlx::query_as(
            "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by
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
            let e = from_row(r)?;
            let Some(rec) = e.record() else {
                sqlx::query("UPDATE repl_log SET applied = ? WHERE origin = ? AND seq = ?")
                    .bind(UNKNOWN_KIND)
                    .bind(&e.origin.0[..])
                    .bind(e.seq as i64)
                    .execute(&mut *conn)
                    .await?;
                continue;
            };
            let settled = apply_isolated(node, conn, &e, &rec).await?;
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

/// Setting that remembers the last [`write_off_lost`] that found anything:
/// `"<count> <unix seconds>"`, for the Cluster page.
pub const LOST_ROWS_KEY: &str = "repl.lost_rows";

/// Records written off per tombstone.
const LOST_CHUNK: usize = 500;

/// This node's own row-backed entries whose row is gone although the entry
/// gave up its payload for it: rows deleted outside peephole (by hand in the
/// database). Nobody can serve such an entry any more, so every node that
/// fetches this log from the start would stop at the first one for good.
/// They are written off with a tombstone of their own, and served from then
/// on like any deleted record (stub plus proof). Returns how many.
pub async fn write_off_lost(node: &Node) -> Result<usize> {
    let me = node.id();
    // Candidates by a cheap anti-join; `rebuild` has the final word.
    let mut candidates: Vec<(i64, String, String)> = vec![];
    for (kind, table) in [
        ("request", "requests"),
        ("fingerprint", "fingerprints"),
        ("scan_result", "scans"),
        ("skip_batch", "skipped_batches"),
    ] {
        debug_assert!(ROW_BACKED.contains(&kind));
        let sql = format!(
            "SELECT l.seq, l.kind, l.uid FROM repl_log l
             WHERE l.origin = ? AND l.kind = ? AND l.uid IS NOT NULL
               AND l.payload IS NULL AND l.erased_by IS NULL
               AND NOT EXISTS (SELECT 1 FROM {table} t JOIN ips i ON i.id = t.ip_id
                               WHERE t.uid = l.uid)"
        );
        candidates.extend(
            sqlx::query_as::<_, (i64, String, String)>(sqlx::AssertSqlSafe(sql))
                .bind(&me.0[..])
                .bind(kind)
                .fetch_all(&node.store.pool)
                .await?,
        );
    }
    candidates.sort();
    let mut lost: Vec<(String, u64)> = vec![];
    {
        let mut conn = node.store.pool.acquire().await?;
        for (seq, kind, uid) in candidates {
            if data::rebuild(&mut conn, &kind, &uid).await?.is_none() {
                lost.push((uid, seq as u64));
            }
        }
    }
    if lost.is_empty() {
        return Ok(0);
    }
    let records: Vec<Record> = lost
        .chunks(LOST_CHUNK)
        .map(|c| {
            let (uids, seqs) = c.iter().cloned().unzip();
            Record::Tombstone(super::record::TombstoneRec {
                uid: format!("{}{}", me.uid_prefix(), data::new_uid()),
                uids,
                seqs,
            })
        })
        .collect();
    append(node, &records).await?;
    warn!(
        records = lost.len(),
        first_seq = lost[0].1,
        "own log entries had lost their rows (deleted outside peephole); written off as deleted so new members can sync"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    node.store
        .setting_set(LOST_ROWS_KEY, &format!("{} {now}", lost.len()))
        .await?;
    Ok(lost.len())
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
/// admin hid stay hidden, entries out of order stay unapplied. Returns how
/// many entries were looked at.
pub async fn rematerialize(node: &Node) -> Result<usize> {
    // Parents first; job state after the jobs it refers to. Only the keys
    // are collected up front; the entries are loaded batch by batch.
    let keys: Vec<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT origin, seq FROM repl_log
         WHERE payload IS NOT NULL AND applied != 4
           AND kind IN ('request','scan_job','job_adopt','job_status','fp_claim',
                        'fingerprint','scan_result','scan_audit','ip_intel','skip_batch')
         ORDER BY CASE kind WHEN 'request' THEN 0 WHEN 'scan_job' THEN 1
                            WHEN 'job_adopt' THEN 2 WHEN 'job_status' THEN 3 ELSE 4 END, hlc",
    )
    .fetch_all(&node.store.pool)
    .await?;
    for batch in keys.chunks(REPLAY_BATCH) {
        let _g = node.apply_lock.lock().await;
        let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        for (origin, seq) in batch {
            let row: Option<LogRow> = sqlx::query_as(
                "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by
                 FROM repl_log WHERE origin = ? AND seq = ?",
            )
            .bind(origin)
            .bind(seq)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(e) = row.map(from_row).transpose()? else {
                continue;
            };
            if let Some(rec) = e.record() {
                apply_isolated(node, &mut tx, &e, &rec).await?;
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

/// [`apply_record`] in a savepoint, for entries of the log (received, or
/// replayed). A record that fails to apply (a constraint, a row this build
/// cannot take) is rolled back alone and deferred: the entry stays in the
/// log, so its origin's later entries still connect, and it is retried
/// with backoff like one waiting for its parent, then given up after
/// [`DEFER_MAX_AGE`]. Local appends use [`apply_record`] and fail instead.
async fn apply_isolated(
    node: &Node,
    conn: &mut SqliteConnection,
    e: &WireEntry,
    r: &Record,
) -> Result<Settled> {
    let mut sp = sqlx::Connection::begin(&mut *conn).await?;
    match apply_record(node, &mut sp, e, r).await {
        Ok(settled) => {
            sp.commit().await?;
            Ok(settled)
        }
        Err(err) => {
            sp.rollback().await?;
            warn!(origin = %e.origin.short(), seq = e.seq, kind = %e.kind,
                  error = %format!("{err:#}"), "log entry failed to apply; deferred");
            Ok(Settled {
                deferred: true,
                ..Default::default()
            })
        }
    }
}

/// The parent a record may wait for.
fn waits_for(r: &Record) -> Option<String> {
    match r {
        Record::JobStatus(s) => Some(s.job_uid.clone()),
        Record::ScanResult(s) => Some(s.job_uid.clone()),
        Record::ScanAudit(a) => Some(a.scan.job_uid.clone()),
        _ => None,
    }
}

/// Effects of one record on the materialized tables, then settle its log
/// entry: erased if a tombstone already deleted it, payload dropped if it
/// can be rebuilt from its row. The record is ordered by its own HLC, the
/// same on every node whenever it arrived: entries dated too far ahead are
/// only taken once their time comes (see [`hlc::ahead`]). Only entries a
/// build before that stored may still lie beyond the signed range.
async fn apply_record(
    node: &Node,
    conn: &mut SqliteConnection,
    e: &WireEntry,
    r: &Record,
) -> Result<Settled> {
    let at = hlc::to_db(e.hlc) as u64;
    if super::members::apply(node, conn, e, r, at).await? {
        return Ok(Settled {
            membership: true,
            ..Default::default()
        });
    }
    if let Record::JobAdopt(a) = r {
        return adopt(node, conn, e, a, at).await;
    }
    if matches!(
        r,
        Record::CreditOffer { .. }
            | Record::CreditReceipt { .. }
            | Record::CreditTransfer { .. }
            | Record::LogSeal { .. }
            | Record::ForkProof { .. }
    ) {
        super::seal::on_apply(node, conn, e, r).await?;
        return Ok(Settled::default());
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
                relay_slots: 16,
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

    use super::super::identity::{Identity, NodeId};
    use super::super::record::MemberInfo;
    use super::super::sync::Batch;
    use super::{Record, WireEntry};

    async fn test_node(retention_days: u32) -> (tempfile::TempDir, std::sync::Arc<super::Node>) {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let node = super::Node::open(super::super::NodeParams {
            identity: Identity::generate().unwrap(),
            cluster: crate::config::ClusterConfig {
                node_name: "n".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: None,
                key_path: None,
                takeover_hours: 6.0,
                lease_secs: 120,
                remote_config: false,
                origin_quota_mb: 20 * 1024,
                relay_slots: 16,
                peers: vec![],
            },
            roles: Default::default(),
            store,
            proto: (1, 1),
            data_dir: dir.path().to_path_buf(),
            retention_days,
        })
        .await
        .unwrap();
        node.bootstrap().await.unwrap();
        (dir, node)
    }

    fn info(id: NodeId, name: &str) -> MemberInfo {
        MemberInfo {
            id,
            name: name.into(),
            address: None,
            roles: vec![],
            proto_min: 1,
            proto_max: 1,
            remote_config: false,
        }
    }

    /// A CLI process opening the node keeps the roles the daemon announced
    /// (here: the scanner switched off at runtime), not the config file's.
    #[tokio::test]
    async fn a_cli_bootstrap_keeps_the_announced_roles() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("node.key");
        let open = || async {
            let store = crate::store::Store::connect(&dir.path().join("t.db"))
                .await
                .unwrap();
            super::Node::open(super::super::NodeParams {
                identity: Identity::load_or_create(&key).unwrap(),
                cluster: crate::config::ClusterConfig {
                    node_name: "n".into(),
                    listen: "127.0.0.1:0".parse().unwrap(),
                    advertise: None,
                    key_path: None,
                    takeover_hours: 6.0,
                    lease_secs: 120,
                    remote_config: false,
                    origin_quota_mb: 20 * 1024,
                    relay_slots: 16,
                    peers: vec![],
                },
                roles: Default::default(),
                store,
                proto: (1, 1),
                data_dir: dir.path().to_path_buf(),
                retention_days: 0,
            })
            .await
            .unwrap()
        };
        let daemon = open().await;
        daemon.bootstrap().await.unwrap();
        let running = crate::config::Roles {
            scanner: false,
            ..Default::default()
        };
        daemon.set_roles(running).await.unwrap();

        let cli = open().await;
        cli.bootstrap_keeping_roles().await.unwrap();
        let me = super::super::members::all(&cli.store)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.id == cli.id())
            .unwrap();
        assert_eq!(me.roles, ["listener", "web"]);
    }

    #[tokio::test]
    async fn a_member_whose_dial_fails_is_asked_through_its_outbox() {
        let (_d, node) = test_node(0).await;
        let x = Identity::generate().unwrap();
        let mut m = info(x.id, "x");
        m.address = Some("x.example.net:7443".into());
        m.proto_max = super::super::rpc::proto::ROUTED_PROTO;
        super::append(&node, &[Record::MemberAdd(m)]).await.unwrap();
        assert!(node.can_call(&x.id));

        node.record_status(x.id, "x", Err("connection refused".into()))
            .await;
        // Not polling: the dial is tried anyway (it may be back).
        assert!(node.can_call(&x.id) && !node.routed_callable(&x.id));
        // It polls its outbox here: `call_any` asks it that way, and a
        // sync around a request gives up on the dial quickly.
        node.status.touch_inbound(x.id);
        assert!(node.routed_callable(&x.id));
        let t = std::time::Instant::now();
        let _ = node.sync_around_request(x.id).await;
        assert!(t.elapsed() <= super::super::QUICK_SYNC + std::time::Duration::from_secs(1));
    }

    fn now_hlc(n: u64) -> u64 {
        (super::hlc::wall_ms() << 16) + n
    }

    async fn trusted(node: &super::Node, id: &NodeId) -> bool {
        let mut conn = node.store.pool.acquire().await.unwrap();
        super::trusted(node, &mut conn, id).await.unwrap()
    }

    async fn logged(node: &super::Node, id: &NodeId) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM repl_log WHERE origin = ?")
            .bind(&id.0[..])
            .fetch_one(&node.store.pool)
            .await
            .unwrap()
    }

    /// Membership below a declared floor is taken only from a trusted
    /// origin. Before, a node nobody admitted, with entries parked here,
    /// could declare a floor at its parked head and have its own
    /// description and then an admission of another key applied.
    #[tokio::test]
    async fn membership_below_a_floor_needs_a_trusted_origin() {
        let (_d, node) = test_node(7).await;
        let x = Identity::generate().unwrap();
        let y = Identity::generate().unwrap();
        let parked: Vec<_> = (1..=2)
            .map(|s| {
                WireEntry::sign(&x, s, now_hlc(s), &Record::MemberUpdate(info(x.id, "x"))).unwrap()
            })
            .collect();
        let st = super::apply_batch(&node, parked).await.unwrap();
        assert_eq!(st.parked, 2, "{st:?}");
        let batch = Batch {
            entries: vec![
                WireEntry::sign(&x, 1, now_hlc(10), &Record::MemberUpdate(info(x.id, "x")))
                    .unwrap(),
                WireEntry::sign(&x, 2, now_hlc(11), &Record::MemberAdd(info(y.id, "y"))).unwrap(),
            ],
            floors: vec![(x.id, 3)],
            ..Default::default()
        };
        let st = super::apply_batch_with(&node, batch, |_| true)
            .await
            .unwrap();
        assert_eq!((st.applied, st.rejected), (0, 2), "{st:?}");
        assert_eq!(logged(&node, &x.id).await, 0);
        assert!(!trusted(&node, &y.id).await);
        assert!(!trusted(&node, &x.id).await);
    }

    /// Parked entries of a node admitted by a local append (an invite
    /// redeemed here) apply at once, and heartbeats of nodes that are no
    /// longer members are forgotten.
    #[tokio::test]
    async fn a_local_admission_drains_parked_entries() {
        let (_d, node) = test_node(0).await;
        let x = Identity::generate().unwrap();
        let e = WireEntry::sign(&x, 1, now_hlc(1), &Record::MemberUpdate(info(x.id, "x"))).unwrap();
        assert_eq!(super::apply_batch(&node, vec![e]).await.unwrap().parked, 1);
        super::append(&node, &[Record::MemberAdd(info(x.id, "x-by-n"))])
            .await
            .unwrap();
        assert_eq!(logged(&node, &x.id).await, 1);
        let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM repl_pending")
            .fetch_one(&node.store.pool)
            .await
            .unwrap();
        assert_eq!(pending, 0);
        // The next entry of x applies directly instead of parking.
        let e =
            WireEntry::sign(&x, 2, now_hlc(2), &Record::MemberUpdate(info(x.id, "x2"))).unwrap();
        assert_eq!(super::apply_batch(&node, vec![e]).await.unwrap().applied, 1);

        // Heartbeats: a member's stays, a stranger's goes on reload.
        let z = Identity::generate().unwrap();
        for id in [&x, &z] {
            let hb = super::super::status::Heartbeat {
                node: id.id,
                at_ms: super::hlc::wall_ms(),
                neighbours: vec![],
                roles: vec![],
                version: "x".into(),
                pace: None,
                active_scans: 0,
                providers: vec![],
                own_seq: 0,
                retention_days: 0,
                floors: vec![],
                on_demand: vec![],
                prices: vec![],
                public_addrs: vec![],
                probe_price_mc: None,
                scan_price_mc: None,
                scan_budget_mc: 0,
                scan_queued: 0,
                relays: vec![],
            };
            let body = super::super::rpc::cbor::encode(&hb).unwrap();
            let signed = super::super::status::SignedHeartbeat { body, sig: vec![] };
            assert!(node.status.merge(hb, signed));
        }
        node.reload_members().await.unwrap();
        assert!(node.status.known(&x.id).is_some());
        assert!(node.status.known(&z.id).is_none());
    }

    /// A floor is taken with a valid bound among bogus ones (each checked
    /// once); without one, the gap is refused.
    #[tokio::test]
    async fn floors_need_a_valid_bound() {
        let (_d, node) = test_node(7).await;
        let o = Identity::generate().unwrap();
        super::append(&node, &[Record::MemberAdd(info(o.id, "o"))])
            .await
            .unwrap();
        let old = (super::hlc::wall_ms() - 30 * 86_400_000) << 16;
        let rec = Record::MemberUpdate(info(o.id, "o"));
        let bound = WireEntry::sign(&o, 2, old, &rec).unwrap();
        let mut forged = bound.clone();
        forged.hlc -= 1;
        let mut huge = bound.clone();
        huge.seq = u64::MAX;
        let entry = WireEntry::sign(&o, 3, now_hlc(3), &rec).unwrap();
        let batch = |bounds: Vec<WireEntry>| Batch {
            entries: vec![entry.clone()],
            floors: vec![(o.id, 3)],
            bounds,
            ..Default::default()
        };
        let st =
            super::apply_batch_with(&node, batch(vec![forged.clone(), huge.clone()]), |_| false)
                .await
                .unwrap();
        assert_eq!((st.applied, st.rejected), (0, 1), "{st:?}");
        let st = super::apply_batch_with(&node, batch(vec![forged, huge, bound]), |_| false)
            .await
            .unwrap();
        assert_eq!(st.applied, 1, "{st:?}");
        let mut conn = node.store.pool.acquire().await.unwrap();
        assert_eq!(
            super::super::history::floor_of(&mut conn, &o.id)
                .await
                .unwrap(),
            3
        );
    }

    /// An entry dated further ahead than the allowed drift is not taken:
    /// its origin's stream waits there (the rest of it is a gap), other
    /// origins go on, and what is taken counts at its own HLC. Before, such
    /// entries were taken at once and capped to their receipt, so nodes that
    /// received them at different times ordered them differently.
    #[tokio::test]
    async fn entries_dated_too_far_ahead_wait_for_their_time() {
        let (_d, node) = test_node(0).await;
        let (x, y) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        super::append(
            &node,
            &[
                Record::MemberAdd(info(x.id, "x")),
                Record::MemberAdd(info(y.id, "y")),
            ],
        )
        .await
        .unwrap();
        let soon = now_hlc(0) + ((super::hlc::MAX_DRIFT_MS - 60_000) << 16);
        let later = now_hlc(0) + (86_400_000 << 16);
        let update = |id: &Identity, seq, hlc, name: &str| {
            WireEntry::sign(id, seq, hlc, &Record::MemberUpdate(info(id.id, name))).unwrap()
        };
        let far = update(&x, 2, later, "x-far");
        let batch = vec![
            update(&x, 1, soon, "x-soon"),
            far.clone(),
            update(&x, 3, later + 1, "x-after"),
            update(&y, 1, now_hlc(1), "y"),
        ];
        let st = super::apply_batch(&node, batch).await.unwrap();
        assert_eq!((st.applied, st.rejected), (2, 2), "{st:?}");
        let h = super::heads(&node.store).await.unwrap();
        assert_eq!(
            (super::head_in(&h, &x.id), super::head_in(&h, &y.id)),
            (1, 1)
        );
        let all = super::super::members::all(&node.store).await.unwrap();
        let row = all.iter().find(|m| m.id == x.id).unwrap();
        assert_eq!((row.name.as_str(), row.info_hlc), ("x-soon", soon));
        // Offered again before its time: still waits.
        let st = super::apply_batch(&node, vec![far]).await.unwrap();
        assert_eq!((st.applied, st.rejected), (0, 1), "{st:?}");
    }

    fn request(o: &Identity, seq: u64, path: &str) -> WireEntry {
        let r = Record::Request(Box::new(super::super::record::RequestRec {
            uid: format!("{}{seq}", o.id.uid_prefix()),
            ts: "2026-10-01 00:00:00".into(),
            ip: "203.0.113.20".into(),
            method: "GET".into(),
            path: path.into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        }));
        WireEntry::sign(o, seq, now_hlc(seq), &r).unwrap()
    }

    async fn paths(node: &super::Node) -> Vec<String> {
        sqlx::query_scalar("SELECT path FROM requests ORDER BY path")
            .fetch_all(&node.store.pool)
            .await
            .unwrap()
    }

    /// A node of an earlier version meets a record kind it does not know
    /// (as the credit kinds are to a node before them): it keeps the entry,
    /// does not apply it, and relays it unchanged, so the nodes behind it
    /// receive it as their origin signed it.
    #[tokio::test]
    async fn a_kind_this_build_does_not_know_is_kept_and_relayed_unchanged() {
        let (_d, node) = test_node(0).await;
        let a = Identity::generate().unwrap();
        super::append(&node, &[Record::MemberAdd(info(a.id, "a"))])
            .await
            .unwrap();
        let payload = super::super::rpc::cbor::encode(&serde_json::json!({
            "payer": "x", "offer_seq": 7, "charged_mc": 1500, "answered": ["abuseipdb"]
        }))
        .unwrap();
        let later = WireEntry::sign_kind(&a, 1, now_hlc(1), "credit_receipt_v9", payload);
        assert!(later.record().is_none(), "unknown here");
        let after = request(&a, 2, "/after");
        let st = super::apply_batch(&node, vec![later.clone(), after])
            .await
            .unwrap();
        assert_eq!((st.applied, st.rejected), (2, 0), "{st:?}");
        let state: i64 =
            sqlx::query_scalar("SELECT applied FROM repl_log WHERE origin = ? AND seq = 1")
                .bind(&a.id.0[..])
                .fetch_one(&node.store.pool)
                .await
                .unwrap();
        assert_eq!(state, super::UNKNOWN_KIND);
        assert_eq!(paths(&node).await, ["/after"], "the origin's log goes on");
        // Still unknown after a restart's retry.
        super::apply_unknown_kinds(&node).await.unwrap();

        let batch = super::entries_after(&node.store, &[(a.id, 0)], 0, 100, 1 << 20, false)
            .await
            .unwrap();
        let sent = batch
            .entries
            .iter()
            .find(|e| e.origin == a.id && e.seq == 1)
            .expect("relayed");
        assert_eq!(sent, &later, "byte for byte");
        assert!(sent.verify(), "the origin's signature still holds");
    }

    /// One entry that fails stops neither the batch nor the other origins.
    /// Before, any error rolled back the whole batch; peers sent it again
    /// and again and sync stalled for every origin.
    #[tokio::test]
    async fn a_failing_entry_does_not_stall_the_batch() {
        let (_d, node) = test_node(0).await;
        let (a, b) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        super::append(
            &node,
            &[
                Record::MemberAdd(info(a.id, "a")),
                Record::MemberAdd(info(b.id, "b")),
            ],
        )
        .await
        .unwrap();
        let sql = |s: &'static str| sqlx::query(s).execute(&node.store.pool);
        // A row the tables refuse (as a constraint would).
        sql(
            "CREATE TRIGGER fail_boom BEFORE INSERT ON requests WHEN NEW.path = '/boom'
             BEGIN SELECT RAISE(ABORT, 'boom'); END",
        )
        .await
        .unwrap();
        let batch = vec![
            request(&a, 1, "/boom"),
            request(&a, 2, "/a"),
            request(&b, 1, "/b"),
        ];
        let st = super::apply_batch(&node, batch).await.unwrap();
        assert_eq!((st.applied, st.rejected), (3, 0), "{st:?}");
        assert_eq!(paths(&node).await, ["/a", "/b"]);
        // The failed one is held, deferred, and applies on a later retry.
        let state: i64 =
            sqlx::query_scalar("SELECT applied FROM repl_log WHERE origin = ? AND seq = 1")
                .bind(&a.id.0[..])
                .fetch_one(&node.store.pool)
                .await
                .unwrap();
        assert_eq!(state, super::DEFERRED);
        sql("DROP TRIGGER fail_boom").await.unwrap();
        sql("UPDATE repl_log SET retry_after = 0").await.unwrap();
        super::retry_due(&node).await.unwrap();
        assert_eq!(paths(&node).await, ["/a", "/b", "/boom"]);

        // An entry that cannot even be stored: its origin stops there (no
        // gap), the others go on.
        sql(
            "CREATE TRIGGER fail_log BEFORE INSERT ON repl_log WHEN NEW.seq = 3
             BEGIN SELECT RAISE(ABORT, 'no room'); END",
        )
        .await
        .unwrap();
        let batch = vec![
            request(&a, 3, "/a3"),
            request(&a, 4, "/a4"),
            request(&b, 2, "/b2"),
        ];
        let st = super::apply_batch(&node, batch).await.unwrap();
        assert_eq!((st.applied, st.rejected), (1, 2), "{st:?}");
        assert_eq!(paths(&node).await, ["/a", "/b", "/b2", "/boom"]);
        let h = super::heads(&node.store).await.unwrap();
        assert_eq!(
            (super::head_in(&h, &a.id), super::head_in(&h, &b.id)),
            (2, 2)
        );
    }

    /// A heartbeat of `id`, as gossiped, keeping `retention_days` from
    /// `floors` on.
    fn heartbeat(node: &super::Node, id: NodeId, retention_days: u32, floors: Vec<(NodeId, u64)>) {
        let hb = super::super::status::Heartbeat {
            node: id,
            at_ms: super::hlc::wall_ms(),
            neighbours: vec![],
            roles: vec![],
            version: "x".into(),
            pace: None,
            active_scans: 0,
            providers: vec![],
            own_seq: 0,
            retention_days,
            floors,
            on_demand: vec![],
            prices: vec![],
            public_addrs: vec![],
            probe_price_mc: None,
            scan_price_mc: None,
            scan_budget_mc: 0,
            scan_queued: 0,
            relays: vec![],
        };
        let body = super::super::rpc::cbor::encode(&hb).unwrap();
        let signed = super::super::status::SignedHeartbeat { body, sig: vec![] };
        assert!(node.status.merge(hb, signed));
    }

    /// A windowed node waits for another member only for origins that
    /// member holds from right after its own head. Before, any member with
    /// an equal window counted, so with three windowed members each one
    /// waited for another and none ever started at a floor.
    #[tokio::test]
    async fn waits_only_for_a_member_that_holds_more_of_the_origin() {
        let (_d, node) = test_node(7).await;
        let (p, m) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        super::append(
            &node,
            &[
                Record::MemberAdd(info(p.id, "p")),
                Record::MemberAdd(info(m.id, "m")),
            ],
        )
        .await
        .unwrap();
        let (o, other) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        // No word from m: nothing to wait for.
        assert!(!node.keeps_more_elsewhere(&p.id, &o, 0));
        // m keeps the same window and its history of o starts at 50.
        heartbeat(&node, m.id, 7, vec![(o, 50)]);
        assert!(!node.keeps_more_elsewhere(&p.id, &o, 0));
        assert!(node.keeps_more_elsewhere(&p.id, &o, 49));
        assert!(node.keeps_more_elsewhere(&p.id, &other, 0));
        // The peer itself never counts.
        assert!(!node.keeps_more_elsewhere(&m.id, &other, 0));
    }

    /// An older member is served each origin up to its first entry only
    /// protocol 7 knows, never past it (no gap); a protocol-7 member gets all.
    #[tokio::test]
    async fn an_older_member_is_not_served_entries_of_protocol_seven() {
        use crate::cluster::record::{ReachReportRec, Record};
        let (_d, node) = test_node(0).await;
        let first = super::append(
            &node,
            &[Record::LogSeal {
                seal: Default::default(),
            }],
        )
        .await
        .unwrap();
        super::append(
            &node,
            &[Record::ReachReport(ReachReportRec {
                hour: crate::credits::reach::hour_of(crate::cluster::hlc::wall_ms()),
                reached: vec![],
            })],
        )
        .await
        .unwrap();
        let wants = [(node.id(), first[0].seq - 1)];
        let old = super::entries_after(&node.store, &wants, 0, 100, 1 << 20, true)
            .await
            .unwrap();
        assert_eq!(
            old.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [first[0].seq]
        );
        let new = super::entries_after(&node.store, &wants, 0, 100, 1 << 20, false)
            .await
            .unwrap();
        assert_eq!(new.entries.len(), 2);
    }

    /// Payments of the economy before are served to an older member; the
    /// first payment of protocol 7's economy cuts its stream like a reach
    /// report, and what follows either cut (of any kind) waits.
    #[tokio::test]
    async fn an_older_member_gets_old_payments_up_to_the_first_new_one() {
        use crate::cluster::record::{ECONOMY, ReachReportRec, Record};
        let (_d, node) = test_node(0).await;
        let day = crate::credits::day_of(crate::cluster::hlc::wall_ms() << 16);
        let to = NodeId([7; 32]);
        let transfer = |economy: u8| {
            move |seal| Record::CreditTransfer {
                to,
                parts: vec![(day, 5)],
                seal,
                economy,
            }
        };
        async fn seal(node: &super::Node) -> u64 {
            let bare = [Record::LogSeal {
                seal: Default::default(),
            }];
            super::append(node, &bare).await.unwrap()[0].seq
        }
        let s1 = seal(&node).await;
        let old = super::append_sealing(&node, transfer(0)).await.unwrap().seq;
        let report = super::append(
            &node,
            &[Record::ReachReport(ReachReportRec {
                hour: crate::credits::reach::hour_of(crate::cluster::hlc::wall_ms()),
                reached: vec![],
            })],
        )
        .await
        .unwrap()[0]
            .seq;
        let s2 = seal(&node).await;
        let new = super::append_sealing(&node, transfer(ECONOMY))
            .await
            .unwrap()
            .seq;
        let s3 = seal(&node).await;
        async fn served(node: &super::Node, after: u64, old_peer: bool) -> Vec<u64> {
            super::entries_after(
                &node.store,
                &[(node.id(), after)],
                0,
                100,
                1 << 20,
                old_peer,
            )
            .await
            .unwrap()
            .entries
            .iter()
            .map(|e| e.seq)
            .collect()
        }
        assert_eq!(
            served(&node, s1 - 1, true).await,
            [s1, old],
            "up to the report"
        );
        assert_eq!(
            served(&node, report, true).await,
            [s2],
            "up to the new payment"
        );
        assert_eq!(served(&node, new, true).await, [s3]);
        assert_eq!(
            served(&node, s1 - 1, false).await,
            [s1, old, report, s2, new, s3],
            "a protocol-7 member gets everything"
        );
    }

    /// A peer asking from the very end of the range gets nothing, not a
    /// panic or a wrapped query.
    #[tokio::test]
    async fn entries_after_the_last_sequence_are_none() {
        let (_d, node) = test_node(0).await;
        let b = super::entries_after(&node.store, &[(node.id(), u64::MAX)], 0, 10, 1 << 20, false)
            .await
            .unwrap();
        assert!(b.entries.is_empty() && b.floors.is_empty());
    }

    /// A pull serves each origin once and only what is held here past the
    /// want; a list of unknown origins (any number fits in a body) costs
    /// nothing. Before, each one cost queries on a held connection.
    #[test]
    fn wants_are_deduplicated_and_bounded_by_our_heads() {
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let ours = super::head_map(&vec![(a, 5), (b, 3)]);
        let mut wants = vec![(a, 2), (a, 0), (b, 3)];
        wants.extend((0..1000).map(|_| (Identity::generate().unwrap().id, 0)));
        assert_eq!(super::servable_wants(wants, &ours), vec![(a, 2)]);
    }

    /// A purged origin is reported at what the peer holds, or not at all.
    #[test]
    fn purged_origins_are_advertised_at_the_peers_head() {
        let (a, p) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let ours = vec![(a, 5), (p, 9)];
        let purged = std::collections::HashSet::from([p]);
        let theirs = super::head_map(&vec![(p, 3)]);
        assert_eq!(
            super::advertised(ours.clone(), &purged, &theirs),
            vec![(a, 5), (p, 3)]
        );
        assert_eq!(
            super::advertised(ours, &purged, &Default::default()),
            vec![(a, 5)]
        );
    }

    /// A request row deleted by hand in the database (not through a
    /// tombstone) left its entry with neither payload nor row: this node
    /// stopped serving its own log there, and every member that joined
    /// later stalled at it for good. The entry is written off as deleted
    /// and the log behind it reaches a new member.
    #[tokio::test]
    async fn an_own_entry_whose_row_was_deleted_by_hand_is_written_off() {
        let (_d, node) = test_node(0).await;
        let own = |n: u32, path: &str| {
            Record::Request(Box::new(super::super::record::RequestRec {
                uid: format!("{}{n}", node.id().uid_prefix()),
                ts: "2026-10-01 00:00:00".into(),
                ip: "203.0.113.20".into(),
                method: "GET".into(),
                path: path.into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                ..Default::default()
            }))
        };
        super::append(&node, &[own(1, "/lost"), own(2, "/after")])
            .await
            .unwrap();
        let (lost_seq, no_payload): (i64, bool) = sqlx::query_as(
            "SELECT seq, payload IS NULL FROM repl_log WHERE uid = ? AND kind = 'request'",
        )
        .bind(format!("{}1", node.id().uid_prefix()))
        .fetch_one(&node.store.pool)
        .await
        .unwrap();
        assert!(no_payload, "the row carries it");
        sqlx::query("DELETE FROM requests WHERE path = '/lost'")
            .execute(&node.store.pool)
            .await
            .unwrap();
        let served = |node: std::sync::Arc<super::Node>| async move {
            super::entries_after(&node.store, &[(node.id(), 0)], 0, 100, 1 << 20, false)
                .await
                .unwrap()
        };
        let before = served(node.clone()).await;
        assert!(
            before.entries.iter().all(|e| (e.seq as i64) < lost_seq),
            "serving stops at the lost entry"
        );

        assert_eq!(super::write_off_lost(&node).await.unwrap(), 1);
        assert_eq!(super::write_off_lost(&node).await.unwrap(), 0, "once");
        assert!(
            node.store
                .setting_get(super::LOST_ROWS_KEY)
                .await
                .unwrap()
                .is_some_and(|v| v.starts_with("1 "))
        );

        let batch = served(node.clone()).await;
        let stub = batch
            .entries
            .iter()
            .find(|e| e.seq as i64 == lost_seq)
            .expect("served now");
        assert!(stub.payload.is_none() && stub.erased_by.is_some());
        assert_eq!(batch.proofs.len(), 1, "with its tombstone");

        // A member joining now takes the whole log.
        let (_d2, joiner) = test_node(0).await;
        super::append(&joiner, &[Record::MemberAdd(info(node.id(), "n"))])
            .await
            .unwrap();
        let st = super::apply_batch(&joiner, batch).await.unwrap();
        assert_eq!(st.rejected, 0, "{st:?}");
        assert_eq!(paths(&joiner).await, ["/after"]);
        let head = super::heads(&joiner.store).await.unwrap();
        let ours = super::heads(&node.store).await.unwrap();
        assert_eq!(
            head.iter().find(|h| h.0 == node.id()),
            ours.iter().find(|h| h.0 == node.id()),
            "caught up"
        );
    }

    /// A node that joined through `a` knew only `a` until `a`'s whole
    /// history in front of its admission of `b` had arrived; `b`'s entries
    /// were parked meanwhile and, past the parking limit, refused. Now the
    /// first batch carries `a`'s membership entries ahead of the data, and
    /// `b` is a member at once.
    #[tokio::test]
    async fn members_arrive_ahead_of_the_history_in_front_of_them() {
        let (_da, a) = test_node(0).await;
        let b = Identity::generate().unwrap();
        let reqs: Vec<Record> = (0..5)
            .map(|n| {
                Record::Request(Box::new(super::super::record::RequestRec {
                    uid: format!("{}{n}", a.id().uid_prefix()),
                    ts: "2026-10-01 00:00:00".into(),
                    ip: "203.0.113.20".into(),
                    method: "GET".into(),
                    path: format!("/{n}"),
                    headers_json: "[]".into(),
                    labels_json: "[]".into(),
                    ..Default::default()
                }))
            })
            .collect();
        super::append(&a, &reqs).await.unwrap();
        super::append(&a, &[Record::MemberAdd(info(b.id, "b"))])
            .await
            .unwrap();
        let b_says =
            WireEntry::sign(&b, 1, now_hlc(1), &Record::MemberUpdate(info(b.id, "b"))).unwrap();

        let (_dj, joiner) = test_node(0).await;
        super::append(&joiner, &[Record::MemberAdd(info(a.id(), "a"))])
            .await
            .unwrap();
        let admitted = |node: std::sync::Arc<super::Node>, id: NodeId| async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM members WHERE id = ? AND admitted_hlc > 0",
            )
            .bind(&id.0[..])
            .fetch_one(&node.store.pool)
            .await
            .unwrap()
                == 1
        };

        // Two entries of a's log: the admission of b is far behind them.
        let mut batch = super::entries_after(&a.store, &[(a.id(), 0)], 0, 2, 1 << 20, false)
            .await
            .unwrap();
        assert!(batch.entries.iter().all(|e| e.kind != "member_add"));
        assert!(batch.membership.iter().any(|e| e.kind == "member_add"));
        batch.entries.push(b_says);
        let st = super::apply_batch(&joiner, batch).await.unwrap();
        assert!(admitted(joiner.clone(), b.id).await, "b is known at once");
        assert_eq!(st.parked, 0, "b's own entry applies: {st:?}");
        assert!(joiner.members().contains_key(&b.id));

        // The rest of a's log still arrives in order, admission included.
        let rest = super::entries_after(&a.store, &[(a.id(), 0)], 0, 100, 1 << 20, false)
            .await
            .unwrap();
        let st = super::apply_batch(&joiner, rest).await.unwrap();
        assert_eq!(st.rejected, 0, "{st:?}");
        assert!(admitted(joiner.clone(), b.id).await);
        let held: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM repl_log WHERE origin = ? AND kind = 'member_add'",
        )
        .bind(&a.id().0[..])
        .fetch_one(&joiner.store.pool)
        .await
        .unwrap();
        assert_eq!(held, 1, "the admission is in the log, in its place");

        // The join reply carries the same.
        let all = super::membership_entries(&a.store).await.unwrap();
        assert!(
            all.iter()
                .any(|e| e.kind == "member_add" && e.origin == a.id())
        );
    }

    /// Membership sent ahead is taken only from trusted, signed origins: a
    /// stranger cannot admit itself, nor be admitted by another stranger.
    #[tokio::test]
    async fn membership_ahead_needs_a_trusted_signer() {
        let (_d, node) = test_node(0).await;
        let (x, y) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let x_adds_y =
            WireEntry::sign(&x, 1, now_hlc(1), &Record::MemberAdd(info(y.id, "y"))).unwrap();
        let mut forged = x_adds_y.clone();
        forged.origin = node.id();
        assert_eq!(
            super::apply_membership_ahead(&node, &[x_adds_y, forged])
                .await
                .unwrap(),
            0
        );
        assert!(!node.members().contains_key(&y.id));
    }

    /// Membership sent ahead keeps its origin's order: a member cannot sign
    /// admissions at made-up sequences dated before what is held of it (or
    /// before what it admitted ahead earlier), which would escape the daily
    /// admission limit.
    #[tokio::test]
    async fn membership_ahead_keeps_its_origin_in_order() {
        let (_d, node) = test_node(0).await;
        let m = Identity::generate().unwrap();
        super::append(&node, &[Record::MemberAdd(info(m.id, "m"))])
            .await
            .unwrap();
        let base = super::hlc::wall_ms() - 2 * 3_600_000;
        let at = |minutes: u64| (base + minutes * 60_000) << 16;
        let alive = WireEntry::sign(&m, 1, at(60), &Record::MemberUpdate(info(m.id, "m"))).unwrap();
        let st = super::apply_batch(&node, vec![alive]).await.unwrap();
        assert_eq!(st.applied, 1, "{st:?}");
        let far = 1_000_000_000_000u64;
        let sybils: Vec<Identity> = (0..5).map(|_| Identity::generate().unwrap()).collect();
        let add = |seq: u64, hlc: u64, s: &Identity| {
            WireEntry::sign(&m, seq, hlc, &Record::MemberAdd(info(s.id, "s"))).unwrap()
        };
        // Dated before m's latest held entry.
        let early = add(far, at(30), &sybils[0]);
        // In order: taken.
        let fine = add(far + 2, at(70), &sybils[1]);
        // A lower sequence dated after it, in the same list.
        let swapped = add(far + 1, at(75), &sybils[3]);
        // Its own sequence again.
        let again = add(far + 2, at(80), &sybils[2]);
        let taken = super::apply_membership_ahead(&node, &[early, fine, swapped, again])
            .await
            .unwrap();
        assert_eq!(taken, 1);
        // Dated before the admission taken ahead earlier.
        let later = add(far + 4, at(68), &sybils[4]);
        assert_eq!(
            super::apply_membership_ahead(&node, &[later])
                .await
                .unwrap(),
            0
        );
        let members = node.members();
        let admitted: Vec<usize> = (0..5)
            .filter(|i| members.contains_key(&sybils[*i].id))
            .collect();
        assert_eq!(admitted, [1]);
    }
}
