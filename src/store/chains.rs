//! Chains: groups of joiner pieces ([`super::pieces`]) one operator is
//! behind. A sighting with the role `stager`, `key` or `file` is a joiner
//! (the role, not the kind: every URL piece has the kind `stager`). Two
//! joiners connect only when they appear together in sources from at least
//! two addresses, so one forged body naming two stagers fuses nothing, and a
//! shared recipe or one address using both connects nothing. A joiner that
//! connects to none is a chain of its own.
//!
//! A chain's sources are the sources holding one of its joiners, and its
//! describers the ones sighted in those sources. What came after an upload
//! is tied through the file ([`follow_ups`], [`dead_ends`]), never through
//! the address, so a noisy scanner cannot fill a chain.
//!
//! Derived on each node from its sightings, rebuilt in the campaign pass
//! ([`rebuild`]), never replicated, never exported.
use super::campaigns::HARD_FANOUT_MAX;
use super::uploads::{self, TimelineRow, UPLOAD_COLS, UploadRow};
use crate::trap::decoy::keeps_its_own_answer;
use anyhow::Result;
use sqlx::SqliteConnection;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Stored with each chain; a new version rebuilds them.
pub const CHAIN_V: i64 = 1;

const REQUEST: u8 = 0;
const UPLOAD: u8 = 1;

/// The roles that join, for a `role IN` clause.
const JOINER_ROLES: &str = "('stager', 'key', 'file')";
/// The kinds that describe.
const DESCRIBER_KINDS: &str = "('exploit', 'recipe', 'tag', 'shell-profile')";

/// Most uploads of a chain [`follow_ups`] and [`dead_ends`] read, newest
/// first: each is a query, and a botnet's chain can hold thousands.
const UPLOADS_MAX: i64 = 64;
/// A dead end: asked for within this long after the upload.
const DEAD_END_SECS: i64 = 60;

/// A joiner in a source. `source` is the kind ([`REQUEST`] or [`UPLOAD`])
/// and the row's id.
pub struct JoinerSighting {
    piece: i64,
    source: (u8, i64),
    ip: i64,
    ts: String,
}

/// A chain as [`connect`] finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainOut {
    /// The oldest joiner's hash, as 16 lowercase hex digits.
    key: String,
    first_seen: String,
    last_seen: String,
    ips: i64,
    /// Every source holding one of its joiners, in order.
    sources: Vec<(u8, i64)>,
    /// In order.
    joiners: Vec<i64>,
}

/// The root of `x`'s group. A root has no entry in `parent`.
fn find(parent: &mut HashMap<i64, i64>, x: i64) -> i64 {
    let mut root = x;
    while let Some(&up) = parent.get(&root) {
        root = up;
    }
    let mut at = x;
    while at != root {
        at = parent.insert(at, root).unwrap_or(root);
    }
    root
}

/// The joiner pairs that appear together in sources from at least two
/// addresses, as a union of everything each joins: `piece -> parent`.
fn unions(sightings: &[JoinerSighting]) -> HashMap<i64, i64> {
    let mut sources: HashMap<(u8, i64), (i64, BTreeSet<i64>)> = HashMap::new();
    let mut addresses: HashMap<i64, HashSet<i64>> = HashMap::new();
    for s in sightings {
        let (_, joiners) = sources
            .entry(s.source)
            .or_insert_with(|| (s.ip, BTreeSet::new()));
        joiners.insert(s.piece);
        addresses.entry(s.piece).or_default().insert(s.ip);
    }
    let mut parent = HashMap::new();
    // A body names up to 256 pieces, so 32,640 pairs. A joiner on one address
    // cannot connect, and an address sending the same list again says
    // nothing new: neither costs a pair.
    let mut read: HashSet<(i64, Vec<i64>)> = HashSet::new();
    // The first address of each pair: a second one connects it.
    let mut pairs: HashMap<(i64, i64), i64> = HashMap::new();
    for (ip, joiners) in sources.into_values() {
        let shared: Vec<i64> = joiners
            .into_iter()
            .filter(|j| addresses[j].len() >= 2)
            .collect();
        if shared.len() < 2 || !read.insert((ip, shared.clone())) {
            continue;
        }
        for (i, &a) in shared.iter().enumerate() {
            for &b in &shared[i + 1..] {
                if *pairs.entry((a, b)).or_insert(ip) != ip {
                    let (ra, rb) = (find(&mut parent, a), find(&mut parent, b));
                    if ra != rb {
                        parent.insert(ra, rb);
                    }
                }
            }
        }
    }
    parent
}

/// The chains these joiners form, by key.
pub(crate) fn connect(sightings: &[JoinerSighting]) -> Vec<ChainOut> {
    #[derive(Default)]
    struct Group<'a> {
        /// Each joiner's oldest sighting.
        joiners: BTreeMap<i64, &'a str>,
        ips: HashSet<i64>,
        sources: BTreeSet<(u8, i64)>,
        first: &'a str,
        last: &'a str,
    }
    let mut parent = unions(sightings);
    let mut groups: HashMap<i64, Group> = HashMap::new();
    for s in sightings {
        let g = groups.entry(find(&mut parent, s.piece)).or_default();
        let oldest = g.joiners.entry(s.piece).or_insert(&s.ts);
        *oldest = (*oldest).min(&s.ts);
        g.ips.insert(s.ip);
        g.sources.insert(s.source);
        if g.first.is_empty() || s.ts.as_str() < g.first {
            g.first = &s.ts;
        }
        g.last = g.last.max(&s.ts);
    }
    let mut out: Vec<ChainOut> = groups
        .into_values()
        .map(|g| {
            let oldest = g
                .joiners
                .iter()
                .min_by_key(|&(hash, ts)| (*ts, *hash))
                .map_or(0, |(hash, _)| *hash);
            ChainOut {
                key: format!("{:016x}", oldest as u64),
                first_seen: g.first.to_string(),
                last_seen: g.last.to_string(),
                ips: g.ips.len() as i64,
                sources: g.sources.into_iter().collect(),
                joiners: g.joiners.into_keys().collect(),
            }
        })
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

fn source_of(kind: &str, id: i64) -> (u8, i64) {
    (if kind == "upload" { UPLOAD } else { REQUEST }, id)
}

/// The joiner sightings chains are built from. A file on more than
/// [`HARD_FANOUT_MAX`] addresses is left out: it is a public webshell, not
/// an operator. Counted from the sightings, as `pieces.ips` can lag.
async fn joiner_sightings(tx: &mut SqliteConnection) -> Result<Vec<JoinerSighting>> {
    let rows: Vec<(i64, String, i64, i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT piece, source_kind, source_id, ip_id, ts FROM piece_sightings
             WHERE role IN {JOINER_ROLES} AND piece NOT IN
               (SELECT piece FROM piece_sightings WHERE role = 'file'
                GROUP BY piece HAVING COUNT(DISTINCT ip_id) > ?)"
    )))
    .bind(HARD_FANOUT_MAX as i64)
    .fetch_all(&mut *tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(piece, kind, id, ip, ts)| JoinerSighting {
            piece,
            source: source_of(&kind, id),
            ip,
            ts,
        })
        .collect())
}

/// Replace every chain with what the sightings say now. Runs in the
/// transaction that rebuilds the campaigns.
pub async fn rebuild(tx: &mut SqliteConnection) -> Result<()> {
    let chains = connect(&joiner_sightings(tx).await?);
    let mut holders: HashMap<(u8, i64), Vec<&str>> = HashMap::new();
    let mut members: BTreeSet<(&str, i64)> = BTreeSet::new();
    for c in &chains {
        for &source in &c.sources {
            holders.entry(source).or_default().push(&c.key);
        }
        members.extend(c.joiners.iter().map(|&j| (c.key.as_str(), j)));
    }
    let describers: Vec<(i64, String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT DISTINCT g.piece, g.source_kind, g.source_id
         FROM piece_sightings g JOIN pieces p ON p.hash = g.piece
         WHERE p.kind IN {DESCRIBER_KINDS} AND EXISTS
           (SELECT 1 FROM piece_sightings j
            WHERE j.source_kind = g.source_kind AND j.source_id = g.source_id
              AND j.role IN {JOINER_ROLES})"
    )))
    .fetch_all(&mut *tx)
    .await?;
    for (piece, kind, id) in describers {
        for &key in holders.get(&source_of(&kind, id)).into_iter().flatten() {
            members.insert((key, piece));
        }
    }
    for sql in ["DELETE FROM chain_pieces", "DELETE FROM chains"] {
        sqlx::query(sql).execute(&mut *tx).await?;
    }
    for c in &chains {
        sqlx::query(
            "INSERT INTO chains (key, first_seen, last_seen, ips, sources, v)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&c.key)
        .bind(&c.first_seen)
        .bind(&c.last_seen)
        .bind(c.ips)
        .bind(c.sources.len() as i64)
        .bind(CHAIN_V)
        .execute(&mut *tx)
        .await?;
    }
    for (chain, piece) in members {
        sqlx::query("INSERT INTO chain_pieces (chain, piece) VALUES (?, ?)")
            .bind(chain)
            .bind(piece)
            .execute(&mut *tx)
            .await?;
    }
    Ok(())
}

/// The uploads holding one of the chain's joiners, newest first, at most
/// [`UPLOADS_MAX`].
pub async fn uploads_of(conn: &mut SqliteConnection, chain: &str) -> Result<Vec<UploadRow>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {UPLOAD_COLS} WHERE u.id IN
           (SELECT g.source_id FROM chain_pieces c JOIN piece_sightings g ON g.piece = c.piece
            WHERE c.chain = ? AND g.source_kind = 'upload' AND g.role IN {JOINER_ROLES})
         ORDER BY u.id DESC LIMIT ?"
    )))
    .bind(chain)
    .bind(UPLOADS_MAX)
    .fetch_all(&mut *conn)
    .await?)
}

/// What was sent to the chain's files, oldest first, at most
/// [`uploads::TIMELINE_MAX`]: the uploads' timelines, from any address,
/// without the requests to a path the trap answers itself. Until `411e2a6`
/// a `PUT /` or `PUT /.env` made that path answer as a webshell for everyone,
/// so those rows, `webshell` or not, are ordinary traffic and stay out.
pub async fn follow_ups(conn: &mut SqliteConnection, chain: &str) -> Result<Vec<TimelineRow>> {
    let mut rows = BTreeMap::new();
    for u in uploads_of(conn, chain).await? {
        for r in uploads::timeline(conn, &u).await? {
            if !keeps_its_own_answer(&r.method, &r.path, r.query.as_deref()) {
                rows.insert((r.ts.clone(), r.id), r);
            }
        }
    }
    let rows = rows.into_values();
    Ok(rows.take(uploads::TIMELINE_MAX as usize).collect())
}

/// The name a client would ask for the file by: the one it sent, without
/// directories, or for a `PUT`, which sends none, the end of the path.
fn file_name(u: &UploadRow) -> Option<&str> {
    let sent = u.filename.as_deref().filter(|f| !f.is_empty());
    let name = sent.unwrap_or(&u.answered_path);
    name.rsplit(['/', '\\']).next().filter(|n| !n.is_empty())
}

/// The requests that found nothing where an upload was expected: the same
/// address, within [`DEAD_END_SECS`] after the upload, asks the same origin
/// for a path ending in the file's name and gets a 404. `substr`, not
/// `LIKE`: a `_` or `%` in the name is no wildcard.
async fn dead_ends_of(conn: &mut SqliteConnection, u: &UploadRow) -> Result<Vec<TimelineRow>> {
    let Some(name) = file_name(u) else {
        return Ok(vec![]);
    };
    Ok(sqlx::query_as(
        "SELECT r.id, r.ts, i.ip, r.method, r.path, r.query, r.status, r.answer
         FROM requests r JOIN ips i ON i.id = r.ip_id
         WHERE i.ip = ?1 AND r.origin IS ?2 AND r.status = 404
           AND substr(r.path, -length(?3)) = ?3
           AND r.ts <= datetime(?4, ?6)
           AND (r.ts > ?4 OR (r.ts = ?4 AND r.id > ?5))
         ORDER BY r.ts, r.id LIMIT ?7",
    )
    .bind(&u.ip)
    .bind(&u.origin)
    .bind(format!("/{name}"))
    .bind(&u.ts)
    .bind(u.request_id.unwrap_or(i64::MAX))
    .bind(format!("+{DEAD_END_SECS} seconds"))
    .bind(uploads::TIMELINE_MAX)
    .fetch_all(&mut *conn)
    .await?)
}

/// The dead ends of the chain's files, oldest first, at most
/// [`uploads::TIMELINE_MAX`].
pub async fn dead_ends(conn: &mut SqliteConnection, chain: &str) -> Result<Vec<TimelineRow>> {
    let mut rows = BTreeMap::new();
    for u in uploads_of(conn, chain).await? {
        for r in dead_ends_of(conn, &u).await? {
            rows.insert((r.ts.clone(), r.id), r);
        }
    }
    let rows = rows.into_values();
    Ok(rows.take(uploads::TIMELINE_MAX as usize).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::store::campaigns::HARD_FANOUT_MAX;
    use crate::store::pieces::{extract, piece_hash};
    use crate::store::requests::NewRequest;
    use crate::store::uploads::seed_upload;

    const T0: &str = "2026-10-01 00:00:00";
    const T1: &str = "2026-10-02 00:00:00";
    /// More than the 32 bytes a `file` piece needs.
    const FILE: &[u8] = b"<?php echo 'a file of at least thirty-two bytes'; ?>";

    fn at(piece: i64, source: (u8, i64), ip: i64, ts: &str) -> JoinerSighting {
        JoinerSighting {
            piece,
            source,
            ip,
            ts: ts.into(),
        }
    }

    fn joiners(chains: &[ChainOut]) -> Vec<Vec<i64>> {
        chains.iter().map(|c| c.joiners.clone()).collect()
    }

    fn the<'a>(chains: &'a [ChainOut], piece: i64) -> &'a ChainOut {
        chains.iter().find(|c| c.joiners.contains(&piece)).unwrap()
    }

    #[test]
    fn one_forged_body_fuses_nothing() {
        let forged = connect(&[at(1, (REQUEST, 1), 10, T0), at(2, (REQUEST, 1), 10, T0)]);
        assert_eq!(joiners(&forged), [[1], [2]]);
        // Sent again from the same address, it still is one address.
        let again = connect(&[
            at(1, (REQUEST, 1), 10, T0),
            at(2, (REQUEST, 1), 10, T0),
            at(1, (REQUEST, 2), 10, T1),
            at(2, (REQUEST, 2), 10, T1),
            at(1, (UPLOAD, 2), 10, T1),
            at(2, (UPLOAD, 2), 10, T1),
        ]);
        assert_eq!(joiners(&again), [[1], [2]]);
    }

    #[test]
    fn two_addresses_connect_joiners() {
        let c = connect(&[
            at(1, (REQUEST, 1), 10, T0),
            at(2, (REQUEST, 1), 10, T0),
            at(1, (UPLOAD, 1), 11, T1),
            at(2, (UPLOAD, 1), 11, T1),
        ]);
        assert_eq!(joiners(&c), [[1, 2]]);
        assert_eq!((c[0].ips, c[0].sources.len()), (2, 2));
        assert_eq!(
            (c[0].first_seen.as_str(), c[0].last_seen.as_str()),
            (T0, T1)
        );
    }

    #[test]
    fn connection_runs_through_a_shared_joiner() {
        let c = connect(&[
            at(1, (REQUEST, 1), 10, T0),
            at(2, (REQUEST, 1), 10, T0),
            at(1, (REQUEST, 2), 11, T0),
            at(2, (REQUEST, 2), 11, T0),
            at(2, (REQUEST, 3), 12, T0),
            at(3, (REQUEST, 3), 12, T0),
            at(2, (REQUEST, 4), 13, T0),
            at(3, (REQUEST, 4), 13, T0),
        ]);
        assert_eq!(joiners(&c), [[1, 2, 3]]);
    }

    #[test]
    fn one_address_using_two_stagers_connects_nothing() {
        // Both on both addresses, but never in one source.
        let c = connect(&[
            at(1, (REQUEST, 1), 10, T0),
            at(2, (REQUEST, 2), 10, T0),
            at(1, (REQUEST, 3), 11, T0),
            at(2, (REQUEST, 4), 11, T0),
        ]);
        assert_eq!(joiners(&c), [[1], [2]]);
    }

    #[test]
    fn chain_key_is_its_oldest_joiner() {
        let pair = |a, b, s: i64, ts: &str| {
            [
                at(a, (REQUEST, s), s + 100, ts),
                at(b, (REQUEST, s), s + 100, ts),
            ]
        };
        let mut rows: Vec<JoinerSighting> = [pair(0x20, 0x10, 1, T1), pair(0x20, 0x10, 2, T1)]
            .into_iter()
            .flatten()
            .collect();
        rows.push(at(0x20, (REQUEST, 3), 200, T0));
        let c = connect(&rows);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].key, "0000000000000020", "older than the lower hash");
        // A newer joiner grows the chain and leaves the key.
        rows.extend(pair(0x10, 0x05, 4, T1));
        rows.extend(pair(0x10, 0x05, 5, T1));
        let grown = connect(&rows);
        assert_eq!(grown.len(), 1);
        assert_eq!(grown[0].joiners, [0x05, 0x10, 0x20]);
        assert_eq!(grown[0].key, "0000000000000020");
        // Ties break by hash. A negative hash is its 64 bits.
        assert_eq!(
            connect(&[at(7, (REQUEST, 1), 1, T0)])[0].key,
            "0000000000000007"
        );
        let tie = connect(&[
            at(9, (REQUEST, 1), 1, T0),
            at(-1, (REQUEST, 1), 1, T0),
            at(9, (REQUEST, 2), 2, T0),
            at(-1, (REQUEST, 2), 2, T0),
        ]);
        assert_eq!(tie[0].key, "ffffffffffffffff");
    }

    #[test]
    fn source_with_two_unconnected_joiners_counts_in_both() {
        let c = connect(&[
            at(1, (REQUEST, 1), 10, T0),
            at(2, (REQUEST, 1), 10, T0),
            at(1, (REQUEST, 2), 10, T1),
        ]);
        assert_eq!(joiners(&c), [[1], [2]]);
        assert_eq!(the(&c, 1).sources, [(REQUEST, 1), (REQUEST, 2)]);
        assert_eq!(the(&c, 2).sources, [(REQUEST, 1)]);
    }

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (s, dir)
    }

    /// A sighting as extraction stores it.
    async fn sight(
        s: &Store,
        (kind, value, role): (&str, &str, &str),
        (source_kind, source_id): (&str, i64),
        ip: i64,
    ) -> i64 {
        let hash = piece_hash(kind, value);
        sqlx::query(
            "INSERT OR IGNORE INTO pieces (hash, kind, value, first_seen, last_seen, ips, sources)
             VALUES (?, ?, ?, ?, ?, 0, 0)",
        )
        .bind(hash)
        .bind(kind)
        .bind(value)
        .bind(T0)
        .bind(T0)
        .execute(&s.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO piece_sightings VALUES (?, ?, ?, ?, ?, 'claimed', ?)")
            .bind(hash)
            .bind(source_kind)
            .bind(source_id)
            .bind(ip)
            .bind(role)
            .bind(T0)
            .execute(&s.pool)
            .await
            .unwrap();
        hash
    }

    async fn run(s: &Store) {
        let mut tx = s.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        rebuild(&mut tx).await.unwrap();
        tx.commit().await.unwrap();
    }

    fn key_of(piece: i64) -> String {
        format!("{:016x}", piece as u64)
    }

    /// The pieces of the chain `key`, in order.
    async fn pieces_of(s: &Store, key: &str) -> Vec<i64> {
        sqlx::query_scalar("SELECT piece FROM chain_pieces WHERE chain = ? ORDER BY piece")
            .bind(key)
            .fetch_all(&s.pool)
            .await
            .unwrap()
    }

    async fn chains(s: &Store) -> Vec<(String, String, String, i64, i64, i64)> {
        sqlx::query_as("SELECT key, first_seen, last_seen, ips, sources, v FROM chains")
            .fetch_all(&s.pool)
            .await
            .unwrap()
    }

    fn sorted(mut v: Vec<i64>) -> Vec<i64> {
        v.sort_unstable();
        v
    }

    const STAGER_A: (&str, &str, &str) = ("stager", "a.example.org", "stager");
    const STAGER_B: (&str, &str, &str) = ("stager", "b.example.org", "stager");
    const RECIPE: (&str, &str, &str) = ("recipe", "curl|sh", "recipe");

    #[tokio::test]
    async fn sharing_a_recipe_connects_nothing() {
        let (s, _d) = store().await;
        let a = sight(&s, STAGER_A, ("request", 1), 10).await;
        let b = sight(&s, STAGER_B, ("request", 2), 11).await;
        let r = sight(&s, RECIPE, ("request", 1), 10).await;
        sight(&s, RECIPE, ("request", 2), 11).await;
        run(&s).await;
        assert_eq!(chains(&s).await.len(), 2);
        assert_eq!(pieces_of(&s, &key_of(a)).await, sorted(vec![a, r]));
        assert_eq!(pieces_of(&s, &key_of(b)).await, sorted(vec![b, r]));
    }

    #[tokio::test]
    async fn rebuild_replaces_the_last_pass_and_stamps_the_version() {
        let (s, _d) = store().await;
        let a = sight(&s, STAGER_A, ("request", 1), 10).await;
        run(&s).await;
        assert_eq!(
            chains(&s).await,
            [(key_of(a), T0.into(), T0.into(), 1, 1, CHAIN_V)]
        );
        sqlx::query("DELETE FROM piece_sightings")
            .execute(&s.pool)
            .await
            .unwrap();
        let b = sight(&s, STAGER_B, ("request", 2), 11).await;
        run(&s).await;
        assert_eq!(chains(&s).await.len(), 1);
        assert_eq!(chains(&s).await[0].0, key_of(b));
        assert_eq!(pieces_of(&s, &key_of(a)).await, Vec::<i64>::new());
    }

    #[tokio::test]
    async fn file_over_the_cap_is_left_out() {
        let (s, _d) = store().await;
        assert_eq!(HARD_FANOUT_MAX, 50);
        let (over, at_cap) = (("file", "11", "file"), ("file", "22", "file"));
        // Were the file a joiner, it would fuse the two stagers.
        let (mut a, mut b, mut left_out) = (0, 0, 0);
        for i in 0..=HARD_FANOUT_MAX as i64 {
            left_out = sight(&s, over, ("upload", i), i).await;
            match i % 4 {
                0 | 1 => a = sight(&s, STAGER_A, ("upload", i), i).await,
                _ => b = sight(&s, STAGER_B, ("upload", i), i).await,
            }
        }
        let mut kept = 0;
        for i in 0..HARD_FANOUT_MAX as i64 {
            kept = sight(&s, at_cap, ("upload", 1000 + i), i).await;
        }
        run(&s).await;
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chain_pieces WHERE piece = ?")
            .bind(left_out)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "over the cap");
        assert_eq!(pieces_of(&s, &key_of(a)).await, [a]);
        assert_eq!(pieces_of(&s, &key_of(b)).await, [b]);
        assert_eq!(pieces_of(&s, &key_of(kept)).await, [kept], "at the cap");
    }

    #[tokio::test]
    async fn other_roles_of_a_stager_piece_join_nothing() {
        let (s, _d) = store().await;
        // A URL piece is `stager` by kind whatever its role.
        sight(
            &s,
            ("stager", "x.example.org", "queried"),
            ("request", 1),
            10,
        )
        .await;
        sight(
            &s,
            ("stager", "y.example.org", "self-hosted"),
            ("request", 1),
            10,
        )
        .await;
        run(&s).await;
        assert!(chains(&s).await.is_empty());
        // In a chain's source they are no describers either.
        let a = sight(&s, STAGER_A, ("request", 1), 10).await;
        run(&s).await;
        assert_eq!(pieces_of(&s, &key_of(a)).await, [a]);
    }

    #[tokio::test]
    async fn describers_attach_by_source_not_by_address() {
        let (s, _d) = store().await;
        let a = sight(&s, STAGER_A, ("request", 1), 10).await;
        let r = sight(&s, RECIPE, ("request", 1), 10).await;
        let t = sight(&s, ("tag", "cve_2024_4577", "tag"), ("request", 1), 10).await;
        let e = sight(&s, ("exploit", "POST /x", "exploit"), ("request", 1), 10).await;
        let p = sight(&s, ("shell-profile", "c99", "opaque"), ("request", 1), 10).await;
        // The same address, another request.
        sight(&s, ("recipe", "wget|sh", "recipe"), ("request", 2), 10).await;
        run(&s).await;
        assert_eq!(pieces_of(&s, &key_of(a)).await, sorted(vec![a, r, t, e, p]));
        assert_eq!(chains(&s).await[0].4, 1, "one source");
    }

    /// A later request, stored as the trap stores it.
    async fn request(
        s: &Store,
        ip: &str,
        (method, path): (&str, &str),
        status: i64,
        answer: &str,
        ts: &str,
    ) -> i64 {
        let ip_id = s.upsert_ip(ip.parse().unwrap()).await.unwrap().id;
        s.insert_request(&NewRequest {
            ip_id,
            method: method.into(),
            path: path.into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            answer: Some(answer.into()),
            status: Some(status),
            ts: Some(ts.into()),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    /// Pieces and chains from what is stored.
    async fn pass(s: &Store) -> String {
        extract(&s.pool).await.unwrap();
        run(s).await;
        use sha2::Digest;
        let hex = data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(FILE));
        key_of(piece_hash("file", &hex))
    }

    fn ids(rows: Vec<TimelineRow>) -> Vec<i64> {
        rows.into_iter().map(|r| r.id).collect()
    }

    const UPLOADER: &str = "203.0.113.5";
    const OTHER: &str = "203.0.113.6";
    const LATER: &str = "2999-01-01 00:00:00";
    const SHELL: i64 = 200;

    #[tokio::test]
    async fn follow_ups_attach_through_the_file() {
        let (s, _d) = store().await;
        seed_upload(&s, UPLOADER, "/up/a.php", FILE).await;
        // From another address, and to the file: it counts.
        let r = request(&s, OTHER, ("GET", "/up/a.php"), SHELL, "webshell", LATER).await;
        // From the uploader, and not to the file: it does not.
        request(&s, UPLOADER, ("GET", "/noise.php"), 404, "default", LATER).await;
        let key = pass(&s).await;
        let mut c = s.pool.acquire().await.unwrap();
        assert_eq!(ids(follow_ups(&mut c, &key).await.unwrap()), [r]);
    }

    #[tokio::test]
    async fn two_uploads_at_one_path_show_a_follow_up_once() {
        let (s, _d) = store().await;
        seed_upload(&s, UPLOADER, "/up/a.php", FILE).await;
        seed_upload(&s, OTHER, "/up/a.php", FILE).await;
        let r = request(&s, OTHER, ("GET", "/up/a.php"), SHELL, "webshell", LATER).await;
        let key = pass(&s).await;
        let mut c = s.pool.acquire().await.unwrap();
        assert_eq!(uploads_of(&mut c, &key).await.unwrap().len(), 2);
        // The second upload was itself sent to the first one's path.
        let got = ids(follow_ups(&mut c, &key).await.unwrap());
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[1], r);
    }

    #[tokio::test]
    async fn root_webshell_rows_are_not_follow_ups() {
        let (s, _d) = store().await;
        for path in ["/", "/.env", "/up/a.php"] {
            seed_upload(&s, UPLOADER, path, FILE).await;
        }
        request(&s, OTHER, ("GET", "/"), SHELL, "webshell", LATER).await;
        request(&s, OTHER, ("GET", "/.env"), SHELL, "webshell", LATER).await;
        // A POST is not what the decoy answers: this one is a real use.
        let post = request(&s, OTHER, ("POST", "/.env"), SHELL, "webshell", LATER).await;
        let real = request(&s, OTHER, ("GET", "/up/a.php"), SHELL, "webshell", LATER).await;
        let key = pass(&s).await;
        let mut c = s.pool.acquire().await.unwrap();
        assert_eq!(uploads_of(&mut c, &key).await.unwrap().len(), 3);
        assert_eq!(ids(follow_ups(&mut c, &key).await.unwrap()), [post, real]);
    }

    #[tokio::test]
    async fn dead_end_is_a_404_for_the_file_within_60_seconds() {
        let (s, _d) = store().await;
        seed_upload(&s, UPLOADER, "/up/s.php", FILE).await;
        sqlx::query("UPDATE uploads SET ts = ?")
            .bind(T0)
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE requests SET ts = ?")
            .bind(T0)
            .execute(&s.pool)
            .await
            .unwrap();
        let get = |path| ("GET", path);
        let at_60 = "2026-10-01 00:01:00";
        let at_61 = "2026-10-01 00:01:01";
        let at_30 = "2026-10-01 00:00:30";
        let hit = request(&s, UPLOADER, get("/other/s.php"), 404, "default", at_60).await;
        let near = request(&s, UPLOADER, get("/s.php"), 404, "default", at_30).await;
        // Too late, someone else, found, not the name, before the upload.
        request(&s, UPLOADER, get("/other/s.php"), 404, "default", at_61).await;
        request(&s, OTHER, get("/other/s.php"), 404, "default", at_30).await;
        request(&s, UPLOADER, get("/other/s.php"), 200, "default", at_30).await;
        request(&s, UPLOADER, get("/other/xs.php"), 404, "default", at_30).await;
        request(
            &s,
            UPLOADER,
            get("/other/s.php"),
            404,
            "default",
            "2026-09-30 23:59:59",
        )
        .await;
        let key = pass(&s).await;
        let mut c = s.pool.acquire().await.unwrap();
        assert_eq!(ids(dead_ends(&mut c, &key).await.unwrap()), [near, hit]);
    }

    #[tokio::test]
    async fn a_put_has_the_name_of_its_path() {
        let (s, _d) = store().await;
        seed_upload(&s, UPLOADER, "/up/put.php", FILE).await;
        sqlx::query("UPDATE uploads SET filename = NULL, ts = ?")
            .bind(T0)
            .execute(&s.pool)
            .await
            .unwrap();
        let at_30 = "2026-10-01 00:00:30";
        let hit = request(&s, UPLOADER, ("GET", "/x/put.php"), 404, "default", at_30).await;
        let key = pass(&s).await;
        let mut c = s.pool.acquire().await.unwrap();
        assert_eq!(ids(dead_ends(&mut c, &key).await.unwrap()), [hit]);
    }
}
