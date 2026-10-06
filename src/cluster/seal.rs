//! Seals: how a node's payments commit to the rest of its log.
//!
//! Every log entry has a digest, the SHA-256 of what its origin signed. A
//! sealing entry (an offer, a transfer, a `log_seal`) names the origin's
//! previous sealing entry and carries the SHA-256 over the digests of the
//! entries from there up to itself. The ranges overlap in one entry, so
//! the seals of a node chain over its whole log. A node that showed two
//! members different entries at one position must, with its next payment,
//! commit to one of them, and every member holding the other then holds
//! two signed statements that contradict each other.
use super::Node;
use super::identity::NodeId;
use super::record::{Record, Seal, WireEntry};
use crate::credits::entries::SealState;
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;

/// The kinds of entry that carry a seal.
pub const SEALING: [&str; 3] = ["credit_offer", "credit_transfer", "log_seal"];
/// Longest range one seal is checked over here; a longer one stays
/// unchecked (an honest node seals at least every 500 entries).
const MAX_RANGE: u64 = 50_000;

/// The digest of an empty range: what a node's first sealing entry carries.
pub fn empty() -> [u8; 32] {
    Sha256::digest([]).into()
}

/// The seal a record carries, if it is of a sealing kind.
pub fn seal_in(r: &Record) -> Option<&Seal> {
    match r {
        Record::CreditOffer { seal, .. }
        | Record::CreditTransfer { seal, .. }
        | Record::LogSeal { seal } => Some(seal),
        _ => None,
    }
}

/// `origin`'s last sealing entry applied here.
pub async fn head(conn: &mut SqliteConnection, origin: &NodeId) -> Result<Option<u64>> {
    let s: Option<i64> = sqlx::query_scalar("SELECT seq FROM seal_heads WHERE origin = ?")
        .bind(&origin.0[..])
        .fetch_optional(&mut *conn)
        .await?;
    Ok(s.map(|s| s.max(0) as u64))
}

async fn note(conn: &mut SqliteConnection, origin: &NodeId, seq: u64) -> Result<()> {
    sqlx::query(
        "INSERT INTO seal_heads (origin, seq) VALUES (?, ?)
         ON CONFLICT(origin) DO UPDATE SET seq = MAX(seq, excluded.seq)",
    )
    .bind(&origin.0[..])
    .bind(seq.min(i64::MAX as u64) as i64)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The digest of `origin`'s entry `seq` as held here: the stored one, or
/// (for an entry a build before seals stored) computed from the entry and
/// kept. None: not held, or only ever seen erased.
pub(crate) async fn digest_of(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    seq: u64,
) -> Result<Option<[u8; 32]>> {
    type Row = (
        i64,
        String,
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT hlc, kind, uid, payload, sig, digest FROM repl_log WHERE origin = ? AND seq = ?",
    )
    .bind(&origin.0[..])
    .bind(seq.min(i64::MAX as u64) as i64)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((hlc, kind, uid, payload, sig, digest)) = row else {
        return Ok(None);
    };
    if let Some(d) = digest.and_then(|d| <[u8; 32]>::try_from(d).ok()) {
        return Ok(Some(d));
    }
    // Erased before it had a digest: nothing signed is left to hash.
    if sig.is_none() {
        return Ok(None);
    }
    let payload = match (payload, &uid) {
        (Some(p), _) => p,
        // Row-backed: the row reproduces the signed payload.
        (None, Some(uid)) => match crate::store::data::rebuild(conn, &kind, uid).await? {
            Some(r) => super::rpc::cbor::encode(&r)?,
            None => return Ok(None),
        },
        (None, None) => return Ok(None),
    };
    let e = WireEntry {
        origin: *origin,
        seq,
        hlc: super::hlc::from_db(hlc),
        kind,
        uid,
        payload: Some(payload),
        sig,
        erased_by: None,
    };
    // Only what the origin really signed counts.
    if !e.verify() {
        return Ok(None);
    }
    let d = e.digest();
    if let Some(d) = d {
        sqlx::query("UPDATE repl_log SET digest = ? WHERE origin = ? AND seq = ?")
            .bind(&d[..])
            .bind(&origin.0[..])
            .bind(seq as i64)
            .execute(&mut *conn)
            .await?;
    }
    Ok(d)
}

/// SHA-256 over the digests of `origin`'s entries `from .. to` (`to`
/// excluded). None: one of them is not held with a digest, or the range
/// is longer than this node checks.
pub(crate) async fn range_digest(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    from: u64,
    to: u64,
) -> Result<Option<[u8; 32]>> {
    if to < from || to - from > MAX_RANGE {
        return Ok(None);
    }
    let mut h = Sha256::new();
    for seq in from..to {
        match digest_of(conn, origin, seq).await? {
            Some(d) => h.update(d),
            None => return Ok(None),
        }
    }
    Ok(Some(h.finalize().into()))
}

/// The seal for the entry `origin` (this node) is about to write at `seq`.
pub(crate) async fn next(conn: &mut SqliteConnection, origin: &NodeId, seq: u64) -> Result<Seal> {
    let Some(prev) = head(conn, origin).await?.filter(|p| *p < seq) else {
        return Ok(Seal {
            from: seq,
            digest: empty().to_vec(),
        });
    };
    match range_digest(conn, origin, prev, seq).await? {
        Some(d) => Ok(Seal {
            from: prev,
            digest: d.to_vec(),
        }),
        // A wrong seal would mark this node as having shown two histories.
        None => bail!(
            "this node's log entries {prev}..{seq} cannot be sealed (one of them has no digest)"
        ),
    }
}

async fn kind_of(conn: &mut SqliteConnection, origin: &NodeId, seq: u64) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT kind FROM repl_log WHERE origin = ? AND seq = ?")
            .bind(&origin.0[..])
            .bind(seq.min(i64::MAX as u64) as i64)
            .fetch_optional(&mut *conn)
            .await?,
    )
}

/// How the seal of `e` (a sealing entry that is being applied; its row is
/// in the log) checks out against what this node holds of its origin.
pub(crate) async fn check(
    conn: &mut SqliteConnection,
    e: &WireEntry,
    seal: &Seal,
) -> Result<SealState> {
    if seal.digest.len() != 32 || seal.from > e.seq {
        return Ok(SealState::Inconsistent);
    }
    let prev = head(conn, &e.origin).await?.filter(|p| *p < e.seq);
    if seal.from == e.seq {
        // "My first sealing entry."
        if prev.is_some() {
            return Ok(SealState::Inconsistent);
        }
        // An earlier one may lie below what this node holds.
        if super::history::floor_of(conn, &e.origin).await? > 1 {
            return Ok(SealState::Unchecked);
        }
        return Ok(if seal.digest == empty() {
            SealState::Consistent
        } else {
            SealState::Inconsistent
        });
    }
    match prev {
        Some(p) if p != seal.from => return Ok(SealState::Inconsistent),
        Some(_) => {}
        // No sealing entry of this origin was applied here: the one it
        // names is below this node's floor, or is no sealing entry.
        None => match kind_of(conn, &e.origin, seal.from).await? {
            None => return Ok(SealState::Unchecked),
            Some(k) if !SEALING.contains(&k.as_str()) => return Ok(SealState::Inconsistent),
            Some(_) => {}
        },
    }
    Ok(
        match range_digest(conn, &e.origin, seal.from, e.seq).await? {
            None => SealState::Unchecked,
            Some(d) if d[..] == seal.digest[..] => SealState::Consistent,
            Some(_) => SealState::Inconsistent,
        },
    )
}

/// A credit entry is being applied: check its seal, remember where the
/// origin's seals stand, and keep a payment as a row.
pub(crate) async fn on_apply(
    _node: &Node,
    conn: &mut SqliteConnection,
    e: &WireEntry,
    r: &Record,
) -> Result<()> {
    let state = match seal_in(r) {
        None => SealState::None,
        Some(seal) => {
            let state = check(conn, e, seal).await?;
            note(conn, &e.origin, e.seq).await?;
            if state == SealState::Inconsistent {
                tracing::warn!(origin = %e.origin.short(), seq = e.seq,
                    "a seal does not match the log held here: its origin showed two histories");
            }
            state
        }
    };
    crate::credits::entries::apply(conn, e, r, state).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;
    use crate::store::Store;

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (store, dir)
    }

    fn filler(id: &Identity, seq: u64) -> WireEntry {
        let r = Record::CreditReceipt {
            payer: id.id,
            offer_seq: seq,
            charged_mc: 0,
            answered: vec![],
        };
        WireEntry::sign(id, seq, (1_000 + seq) << 16, &r).unwrap()
    }

    fn sealing(id: &Identity, seq: u64, seal: Seal) -> WireEntry {
        WireEntry::sign(id, seq, (1_000 + seq) << 16, &Record::LogSeal { seal }).unwrap()
    }

    /// Store an entry as the log holds it. `digest`: as this build stores
    /// it; without, as a build before seals did.
    async fn put(conn: &mut SqliteConnection, e: &WireEntry, digest: bool) {
        sqlx::query(
            "INSERT INTO repl_log (origin, seq, hlc, kind, uid, payload, sig, erased_by, applied,
                                   received_at, digest)
             VALUES (?,?,?,?,?,?,?,?,1,datetime('now'),?)",
        )
        .bind(&e.origin.0[..])
        .bind(e.seq as i64)
        .bind(e.hlc as i64)
        .bind(&e.kind)
        .bind(&e.uid)
        .bind(&e.payload)
        .bind(&e.sig)
        .bind(&e.erased_by)
        .bind(digest.then(|| e.digest().unwrap().to_vec()))
        .execute(&mut *conn)
        .await
        .unwrap();
    }

    /// Store `e` and, like `on_apply`, note it as its origin's newest
    /// sealing entry.
    async fn put_sealing(conn: &mut SqliteConnection, e: &WireEntry) {
        put(conn, e, true).await;
        note(conn, &e.origin, e.seq).await.unwrap();
    }

    #[tokio::test]
    async fn a_seal_covers_the_entries_since_the_previous_one() {
        let (store, _dir) = store().await;
        let mut conn = store.pool.acquire().await.unwrap();
        let id = Identity::generate().unwrap();
        for seq in 1..=3 {
            put(&mut conn, &filler(&id, seq), true).await;
        }
        // The first sealing entry names itself and covers nothing.
        let first = next(&mut conn, &id.id, 4).await.unwrap();
        assert_eq!((first.from, first.digest.as_slice()), (4, &empty()[..]));
        let e4 = sealing(&id, 4, first.clone());
        assert_eq!(
            check(&mut conn, &e4, &first).await.unwrap(),
            SealState::Consistent
        );
        put_sealing(&mut conn, &e4).await;
        assert_eq!(head(&mut conn, &id.id).await.unwrap(), Some(4));
        for seq in 5..=6 {
            put(&mut conn, &filler(&id, seq), true).await;
        }
        // The next one starts at the previous sealing entry.
        let second = next(&mut conn, &id.id, 7).await.unwrap();
        assert_eq!(second.from, 4);
        let mut h = Sha256::new();
        for e in [e4.clone(), filler(&id, 5), filler(&id, 6)] {
            h.update(e.digest().unwrap());
        }
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(second.digest, want);
        let e7 = sealing(&id, 7, second.clone());
        assert_eq!(
            check(&mut conn, &e7, &second).await.unwrap(),
            SealState::Consistent
        );

        // Another digest, another start, or "the first" after a first one:
        // the origin signed two histories.
        let wrong = |from: u64, digest: Vec<u8>| Seal { from, digest };
        for bad in [
            wrong(4, vec![9; 32]),
            wrong(5, second.digest.clone()),
            wrong(7, empty().to_vec()),
            wrong(8, second.digest.clone()),
            wrong(4, vec![1, 2, 3]),
        ] {
            let e = sealing(&id, 7, bad.clone());
            assert_eq!(
                check(&mut conn, &e, &bad).await.unwrap(),
                SealState::Inconsistent,
                "{bad:?}"
            );
        }
    }

    /// A node that upgraded later holds entries without stored digests:
    /// the seal is checked from the entries themselves.
    #[tokio::test]
    async fn a_seal_over_entries_without_stored_digests_is_checked_from_the_entries() {
        let (store, _dir) = store().await;
        let mut conn = store.pool.acquire().await.unwrap();
        let id = Identity::generate().unwrap();
        let e1 = sealing(
            &id,
            1,
            Seal {
                from: 1,
                digest: empty().to_vec(),
            },
        );
        put(&mut conn, &e1, false).await;
        note(&mut conn, &id.id, 1).await.unwrap();
        put(&mut conn, &filler(&id, 2), false).await;
        let seal = next(&mut conn, &id.id, 3).await.unwrap();
        let e3 = sealing(&id, 3, seal.clone());
        assert_eq!(
            check(&mut conn, &e3, &seal).await.unwrap(),
            SealState::Consistent
        );
        // Computed once, then kept.
        let kept: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT digest FROM repl_log WHERE origin = ? AND seq = 2")
                .bind(&id.id.0[..])
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        assert_eq!(kept, Some(filler(&id, 2).digest().unwrap().to_vec()));
    }

    /// An entry this node only ever saw erased has no digest here: the
    /// seal says nothing. One erased after it arrived keeps its digest.
    #[tokio::test]
    async fn a_stub_in_the_range_leaves_the_seal_unchecked() {
        let (store, _dir) = store().await;
        let mut conn = store.pool.acquire().await.unwrap();
        let id = Identity::generate().unwrap();
        let e1 = sealing(
            &id,
            1,
            Seal {
                from: 1,
                digest: empty().to_vec(),
            },
        );
        put_sealing(&mut conn, &e1).await;
        let e2 = filler(&id, 2);
        // What the origin sealed: its real entry 2.
        let mut h = Sha256::new();
        h.update(e1.digest().unwrap());
        h.update(e2.digest().unwrap());
        let seal = Seal {
            from: 1,
            digest: h.finalize().to_vec(),
        };
        let e3 = sealing(&id, 3, seal.clone());

        // Held as a stub that arrived erased: no payload, no signature.
        let stub = WireEntry {
            payload: None,
            sig: None,
            erased_by: Some("t".into()),
            ..e2.clone()
        };
        put(&mut conn, &stub, false).await;
        assert_eq!(
            check(&mut conn, &e3, &seal).await.unwrap(),
            SealState::Unchecked
        );

        // Erased after it arrived: the digest stayed.
        sqlx::query("UPDATE repl_log SET digest = ? WHERE origin = ? AND seq = 2")
            .bind(e2.digest().unwrap().to_vec())
            .bind(&id.id.0[..])
            .execute(&mut *conn)
            .await
            .unwrap();
        assert_eq!(
            check(&mut conn, &e3, &seal).await.unwrap(),
            SealState::Consistent
        );
    }

    /// A node that keeps only a window: a range that starts below what it
    /// holds, and a "first" seal it cannot know to be the first.
    #[tokio::test]
    async fn a_range_below_the_floor_leaves_the_seal_unchecked() {
        let (store, _dir) = store().await;
        let mut conn = store.pool.acquire().await.unwrap();
        let id = Identity::generate().unwrap();
        crate::cluster::history::raise_floor(&mut conn, &id.id, 10)
            .await
            .unwrap();
        put(&mut conn, &filler(&id, 10), true).await;
        let from_below = Seal {
            from: 7,
            digest: vec![5; 32],
        };
        let e = sealing(&id, 11, from_below.clone());
        assert_eq!(
            check(&mut conn, &e, &from_below).await.unwrap(),
            SealState::Unchecked
        );
        let first = Seal {
            from: 11,
            digest: empty().to_vec(),
        };
        let e = sealing(&id, 11, first.clone());
        assert_eq!(
            check(&mut conn, &e, &first).await.unwrap(),
            SealState::Unchecked
        );
    }
}
