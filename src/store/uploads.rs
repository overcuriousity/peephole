//! Files dropped on the trap (MIK-121): their metadata (`uploads`) and
//! their content, once per SHA-256 (`upload_blobs`). Content is hostile:
//! nothing here serves, executes, renders or unpacks it.
//!
//! New content is stored only within five bounds, on the node that
//! collected it and on every node it replicates to alike: dedup by hash,
//! the trap's per-source rate (decided before the record exists), a daily
//! byte budget per origin keyed on this node's UTC day of apply (never on
//! the record's own `ts`), a ceiling on all stored content, and a floor of
//! free disk. Past a bound the row is still written, with why the content
//! is not held.
use super::data::{Ctx, Effect, ensure_ip, erased_by, gone, row_ts};
use crate::cluster::record::UploadRec;
use anyhow::Result;
use sha2::Digest;
use sqlx::SqliteConnection;

/// Most bytes of one upload that are kept.
pub const MAX_CONTENT: usize = 1 << 20;
const MIB: u64 = 1 << 20;

/// What became of an upload's content on this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentState {
    Held,
    /// The source sent more than the trap keeps per hour.
    DroppedRate,
    /// The origin's daily budget here is spent.
    DroppedBudget,
    /// The store holds its ceiling of content.
    DroppedCeiling,
    /// Free disk is below the floor.
    DroppedDisk,
    /// The bytes did not hash to the record's `sha256`.
    DroppedMismatch,
    /// Larger than [`MAX_CONTENT`].
    TooBig,
    /// The origin held it but did not send it here (it already held the
    /// hash when it recorded the upload, or a relay did not have it).
    NotReceived,
}

impl ContentState {
    pub const ALL: [ContentState; 8] = [
        Self::Held,
        Self::DroppedRate,
        Self::DroppedBudget,
        Self::DroppedCeiling,
        Self::DroppedDisk,
        Self::DroppedMismatch,
        Self::TooBig,
        Self::NotReceived,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::DroppedRate => "dropped_rate",
            Self::DroppedBudget => "dropped_budget",
            Self::DroppedCeiling => "dropped_ceiling",
            Self::DroppedDisk => "dropped_disk",
            Self::DroppedMismatch => "dropped_mismatch",
            Self::TooBig => "too_big",
            Self::NotReceived => "not_received",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// Upload kinds the trap records (`kind` column).
pub const KINDS: [&str; 5] = ["put", "wp_plugin", "wp_theme", "wp_media", "script"];

/// Runtime settings keys of the bounds (see `crate::settings`).
pub const KEY_ENABLED: &str = "uploads.enabled";
pub const KEY_PER_SOURCE: &str = "uploads.per_source";
pub const KEY_DAILY_MB: &str = "uploads.daily_mb";
pub const KEY_STORE_MAX_MB: &str = "uploads.store_max_mb";
pub const KEY_MIN_FREE_MB: &str = "uploads.min_free_mb";

/// The bounds on stored content. Byte sizes are in MiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The trap's upload sink is on.
    pub enabled: bool,
    /// Content-bearing uploads per source (IPv6 by /64) per hour.
    pub per_source: u32,
    /// New content per origin per UTC day of apply.
    pub daily_mb: u32,
    /// All content in `upload_blobs`.
    pub store_max_mb: u32,
    /// No new content below this much free disk.
    pub min_free_mb: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            enabled: true,
            per_source: 6,
            daily_mb: 32,
            store_max_mb: 1024,
            min_free_mb: 2048,
        }
    }
}

impl Limits {
    /// The defaults with the stored runtime overrides applied.
    pub async fn load(conn: &mut SqliteConnection) -> Result<Self> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM settings WHERE key LIKE 'uploads.%'")
                .fetch_all(&mut *conn)
                .await?;
        let mut l = Self::default();
        for (k, v) in &rows {
            if let Ok(c) = crate::settings::Changes::from_key_value(k, v) {
                l = l.with(&c);
            }
        }
        Ok(l)
    }

    /// These limits with the fields `c` sets.
    pub fn with(self, c: &crate::settings::Changes) -> Self {
        Self {
            enabled: c.uploads_enabled.unwrap_or(self.enabled),
            per_source: c.upload_per_source.unwrap_or(self.per_source),
            daily_mb: c.upload_daily_mb.unwrap_or(self.daily_mb),
            store_max_mb: c.upload_store_max_mb.unwrap_or(self.store_max_mb),
            min_free_mb: c.upload_min_free_mb.unwrap_or(self.min_free_mb),
        }
    }
}

/// Free bytes for an unprivileged writer on the filesystem holding the
/// database; None for an in-memory database.
pub async fn free_bytes(conn: &mut SqliteConnection) -> Result<Option<u64>> {
    let rows: Vec<(i64, String, String)> = sqlx::query_as("PRAGMA database_list")
        .fetch_all(&mut *conn)
        .await?;
    let Some((_, _, file)) = rows.into_iter().find(|r| r.1 == "main") else {
        return Ok(None);
    };
    if file.is_empty() {
        return Ok(None);
    }
    let st = rustix::fs::statvfs(file.as_str())?;
    Ok(Some(st.f_bavail.saturating_mul(st.f_frsize)))
}

/// UTC day of now, as the budget is keyed.
fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

pub async fn has_blob(conn: &mut SqliteConnection, sha256: &[u8]) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM upload_blobs WHERE sha256 = ?)")
            .bind(sha256)
            .fetch_one(&mut *conn)
            .await?,
    )
}

/// Bytes of content held.
pub async fn blob_bytes(conn: &mut SqliteConnection) -> Result<u64> {
    let n: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(size), 0) FROM upload_blobs")
        .fetch_one(&mut *conn)
        .await?;
    Ok(n.max(0) as u64)
}

/// Store `content` under `sha256` if every bound allows it. `origin` keys
/// the daily budget (empty on a standalone node); `day` is this node's UTC
/// day of apply; `free` the free disk, if known. Held when the blob is
/// present afterwards, whether stored now or before.
pub async fn put_blob_bounded(
    conn: &mut SqliteConnection,
    origin: &[u8],
    sha256: &[u8],
    content: &[u8],
    limits: &Limits,
    day: &str,
    free: Option<u64>,
) -> Result<ContentState> {
    // The cap, then the hash, before anything else looks at the bytes.
    if content.len() > MAX_CONTENT {
        tracing::warn!(
            sha256 = %data_encoding::HEXLOWER.encode(sha256),
            len = content.len(),
            "upload content over the cap; not stored"
        );
        return Ok(ContentState::TooBig);
    }
    if sha2::Sha256::digest(content).as_slice() != sha256 {
        tracing::warn!(
            sha256 = %data_encoding::HEXLOWER.encode(sha256),
            "upload content does not match its hash; not stored"
        );
        return Ok(ContentState::DroppedMismatch);
    }
    if has_blob(conn, sha256).await? {
        return Ok(ContentState::Held);
    }
    let len = content.len() as u64;
    if free.is_some_and(|f| f < u64::from(limits.min_free_mb) * MIB + len) {
        return Ok(ContentState::DroppedDisk);
    }
    if blob_bytes(conn).await? + len > u64::from(limits.store_max_mb) * MIB {
        return Ok(ContentState::DroppedCeiling);
    }
    let spent: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(bytes), 0) FROM upload_budget WHERE origin = ? AND day = ?",
    )
    .bind(origin)
    .bind(day)
    .fetch_one(&mut *conn)
    .await?;
    if spent.max(0) as u64 + len > u64::from(limits.daily_mb) * MIB {
        return Ok(ContentState::DroppedBudget);
    }
    sqlx::query("INSERT INTO upload_blobs (sha256, size, content) VALUES (?, ?, ?)")
        .bind(sha256)
        .bind(len as i64)
        .bind(content)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO upload_budget (origin, day, bytes) VALUES (?, ?, ?)
         ON CONFLICT(origin, day) DO UPDATE SET bytes = bytes + excluded.bytes",
    )
    .bind(origin)
    .bind(day)
    .bind(len as i64)
    .execute(&mut *conn)
    .await?;
    Ok(ContentState::Held)
}

/// The origin's side of a new upload: store `content` within the bounds
/// (`rate_ok`: the trap's per-source rate allows it), then set the record's
/// `sha256`, `content_state` and `carries_content`. The bytes ride with the
/// record only when this upload newly stored them; a hash held before needs
/// no second copy. The record itself is written by the caller.
pub async fn insert_upload(
    conn: &mut SqliteConnection,
    origin: &[u8],
    r: &mut UploadRec,
    content: &[u8],
    rate_ok: bool,
) -> Result<ContentState> {
    let limits = Limits::load(conn).await?;
    let free = free_bytes(conn).await?;
    insert_upload_at(conn, origin, r, content, rate_ok, &limits, &today(), free).await
}

/// [`insert_upload`] with the bounds, the day and the free disk given.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_upload_at(
    conn: &mut SqliteConnection,
    origin: &[u8],
    r: &mut UploadRec,
    content: &[u8],
    rate_ok: bool,
    limits: &Limits,
    day: &str,
    free: Option<u64>,
) -> Result<ContentState> {
    let kept = &content[..content.len().min(MAX_CONTENT)];
    r.sha256 = sha2::Sha256::digest(kept).to_vec();
    let had = has_blob(conn, &r.sha256).await?;
    let state = if had {
        ContentState::Held
    } else if !rate_ok {
        ContentState::DroppedRate
    } else {
        put_blob_bounded(conn, origin, &r.sha256, kept, limits, day, free).await?
    };
    r.content_state = state.as_str().into();
    r.carries_content = state == ContentState::Held && !had;
    Ok(state)
}

/// The bytes a relayed `upload` entry carries: those of a record that
/// `carries_content`, if held here. Replication only; nothing here serves
/// them to anyone but a peer, which verifies them against the signed hash.
pub(crate) async fn content_for_relay(
    conn: &mut SqliteConnection,
    r: &UploadRec,
) -> Result<Option<Vec<u8>>> {
    if !r.carries_content {
        return Ok(None);
    }
    Ok(
        sqlx::query_scalar("SELECT content FROM upload_blobs WHERE sha256 = ?")
            .bind(&r.sha256)
            .fetch_optional(&mut *conn)
            .await?,
    )
}

/// Whether a record is well-formed enough to store: anything else from a
/// peer is ignored.
fn valid(r: &UploadRec) -> bool {
    r.sha256.len() == 32
        && KINDS.contains(&r.kind.as_str())
        && r.size >= 0
        && !r.request_uid.is_empty()
        && r.request_uid.len() <= 128
        && !r.answered_path.is_empty()
        && r.answered_path.len() <= 2048
        && r.filename.as_ref().is_none_or(|f| f.len() <= 255)
        && !r.sniffed_type.is_empty()
        && r.sniffed_type.len() <= 16
        && ContentState::parse(&r.content_state).is_some()
}

/// Apply an upload record: its row, and its content within the bounds.
/// `content` is the bytes that came with the record, if any.
pub(crate) async fn apply(
    conn: &mut SqliteConnection,
    ctx: Ctx<'_>,
    r: &UploadRec,
    content: Option<&[u8]>,
) -> Result<Effect> {
    let limits = Limits::load(conn).await?;
    let free = match content {
        Some(_) => free_bytes(conn).await?,
        None => None,
    };
    apply_at(conn, ctx, r, content, &limits, &today(), free).await
}

/// [`apply`] with the bounds, the day and the free disk given (tests).
pub(crate) async fn apply_at(
    conn: &mut SqliteConnection,
    ctx: Ctx<'_>,
    r: &UploadRec,
    content: Option<&[u8]>,
    limits: &Limits,
    day: &str,
    free: Option<u64>,
) -> Result<Effect> {
    // Bytes are taken only with a record whose origin newly stored them.
    let content = content.filter(|_| r.carries_content);
    if let Some(t) = erased_by(conn, &r.uid).await? {
        return Ok(Effect::Erased(t));
    }
    if !valid(r) || gone(conn, &r.request_uid).await? {
        return Ok(Effect::Ignored);
    }
    let Some(ts) = row_ts(&r.ts) else {
        return Ok(Effect::Ignored);
    };
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM uploads WHERE uid = ?)")
        .bind(&r.uid)
        .fetch_one(&mut *conn)
        .await?;
    if exists {
        return Ok(Effect::Applied);
    }
    let Some(ip_id) = ensure_ip(conn, &r.ip, Some(&ts)).await? else {
        return Ok(Effect::Ignored);
    };
    let origin = ctx.origin_bytes().unwrap_or_default();
    let why = match content {
        Some(c) => put_blob_bounded(conn, &origin, &r.sha256, c, limits, day, free).await?,
        // The origin's own word on why it has none, or that it kept it.
        None => match ContentState::parse(&r.content_state) {
            Some(ContentState::Held) | None => ContentState::NotReceived,
            Some(s) => s,
        },
    };
    // Held exactly when the blob is here after apply.
    let state = if has_blob(conn, &r.sha256).await? {
        ContentState::Held
    } else if why == ContentState::Held {
        ContentState::NotReceived
    } else {
        why
    };
    sqlx::query(
        "INSERT INTO uploads (uid, request_uid, origin, hlc, ts, ip_id, kind, filename,
           sniffed_type, size, truncated, sha256, answered_path, path_is_prefix, content_state)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&r.uid)
    .bind(&r.request_uid)
    .bind(ctx.origin_bytes())
    .bind(ctx.hlc as i64)
    .bind(&ts)
    .bind(ip_id)
    .bind(&r.kind)
    .bind(&r.filename)
    .bind(&r.sniffed_type)
    .bind(r.size)
    .bind(r.truncated)
    .bind(&r.sha256)
    .bind(&r.answered_path)
    .bind(r.path_is_prefix)
    .bind(state.as_str())
    .execute(&mut *conn)
    .await?;
    Ok(Effect::Applied)
}

/// The paths this node answered its own latest `limit` uploads at, oldest
/// first: `(answered_path, path_is_prefix, uid)`. `origin` is this node's
/// id; None on a standalone node, whose uploads carry none.
pub async fn answered_paths(
    conn: &mut SqliteConnection,
    origin: Option<&[u8]>,
    limit: usize,
) -> Result<Vec<(String, bool, String)>> {
    let mut rows: Vec<(String, bool, String)> = sqlx::query_as(
        "SELECT answered_path, path_is_prefix, uid FROM uploads
         WHERE origin IS ? ORDER BY id DESC LIMIT ?",
    )
    .bind(origin)
    .bind(limit as i64)
    .fetch_all(&mut *conn)
    .await?;
    rows.reverse();
    Ok(rows)
}

/// One upload's metadata, as `/api/v1` and the Parquet export give it out.
/// It has no content field: no query here reads `content`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UploadMeta {
    pub id: i64,
    pub uid: String,
    pub request_uid: String,
    /// The node that collected it (`origin`); None on a standalone node.
    pub node_id: Option<Vec<u8>>,
    pub ts: String,
    pub ip: String,
    pub kind: String,
    /// The client's file name, as sent: attacker text.
    pub filename: Option<String>,
    pub sniffed_type: String,
    pub size: i64,
    pub truncated: bool,
    pub sha256: Vec<u8>,
    pub answered_path: String,
    pub path_is_prefix: bool,
    pub content_state: String,
}

/// Which uploads [`super::Store::uploads_meta`] reads. With `after`, the
/// page runs oldest first from that id (the export); otherwise newest
/// first, below `before` if given (the API).
#[derive(Debug, Default, Clone, Copy)]
pub struct UploadQuery<'a> {
    pub before: Option<i64>,
    pub after: Option<i64>,
    pub sha256: Option<&'a [u8]>,
    /// `ts` bounds, inclusive, in the stored `YYYY-MM-DD HH:MM:SS` form.
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub ip: Option<&'a str>,
}

impl super::Store {
    /// Up to `limit` uploads' metadata matching `q`.
    pub async fn uploads_meta(&self, q: &UploadQuery<'_>, limit: i64) -> Result<Vec<UploadMeta>> {
        let mut w = String::new();
        let (order, cursor) = match (q.after, q.before) {
            (Some(a), _) => {
                w.push_str(" AND u.id > ?");
                ("ASC", Some(a))
            }
            (None, Some(b)) => {
                w.push_str(" AND u.id < ?");
                ("DESC", Some(b))
            }
            (None, None) => ("DESC", None),
        };
        for (on, clause) in [
            (q.sha256.is_some(), " AND u.sha256 = ?"),
            (q.from.is_some(), " AND u.ts >= ?"),
            (q.to.is_some(), " AND u.ts <= ?"),
            (q.ip.is_some(), " AND i.ip = ?"),
        ] {
            if on {
                w.push_str(clause);
            }
        }
        let sql = format!(
            "SELECT u.id, u.uid, u.request_uid, u.origin AS node_id, u.ts, i.ip, u.kind,
                    u.filename, u.sniffed_type, u.size, u.truncated, u.sha256,
                    u.answered_path, u.path_is_prefix, u.content_state
             FROM uploads u JOIN ips i ON i.id = u.ip_id
             WHERE 1=1{w} ORDER BY u.id {order} LIMIT ?"
        );
        let mut query = sqlx::query_as::<_, UploadMeta>(sqlx::AssertSqlSafe(sql));
        if let Some(c) = cursor {
            query = query.bind(c);
        }
        if let Some(h) = q.sha256 {
            query = query.bind(h);
        }
        for v in [q.from, q.to, q.ip].into_iter().flatten() {
            query = query.bind(v);
        }
        Ok(query.bind(limit).fetch_all(&self.read).await?)
    }
}

/// Daily maintenance: drop content no upload refers to any more, and
/// budget days that are over. Returns how many blobs went.
pub async fn gc_blobs(conn: &mut SqliteConnection) -> Result<u64> {
    let n = sqlx::query(
        "DELETE FROM upload_blobs
         WHERE NOT EXISTS (SELECT 1 FROM uploads u WHERE u.sha256 = upload_blobs.sha256)",
    )
    .execute(&mut *conn)
    .await?
    .rows_affected();
    sqlx::query("DELETE FROM upload_budget WHERE day < ?")
        .bind(
            (chrono::Utc::now() - chrono::Duration::days(2))
                .format("%Y-%m-%d")
                .to_string(),
        )
        .execute(&mut *conn)
        .await?;
    Ok(n)
}

/// An upload as the admin lists it: metadata only, never the content.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UploadRow {
    pub uid: String,
    pub ts: String,
    pub ip: String,
    pub kind: String,
    /// The client's file name, as sent (escaped wherever it is shown).
    pub filename: Option<String>,
    pub sniffed_type: String,
    pub size: i64,
    pub truncated: bool,
    pub sha256: Vec<u8>,
    pub answered_path: String,
    pub path_is_prefix: bool,
    pub content_state: String,
    /// The content is in the store here, and can be exported.
    pub held: bool,
    /// The request that carried it, when this node holds it.
    pub request_id: Option<i64>,
    pub origin: Option<Vec<u8>>,
}

impl UploadRow {
    pub fn hash(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.sha256)
    }
}

/// A later request to where an upload was told it landed.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TimelineRow {
    pub id: i64,
    pub ts: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub status: Option<i64>,
    pub answer: Option<String>,
}

/// Most requests an upload's timeline shows.
pub const TIMELINE_MAX: i64 = 500;

const UPLOAD_COLS: &str = "u.uid, u.ts, i.ip, u.kind, u.filename, u.sniffed_type, u.size,
    u.truncated, u.sha256, u.answered_path, u.path_is_prefix, u.content_state,
    EXISTS(SELECT 1 FROM upload_blobs b WHERE b.sha256 = u.sha256) AS held,
    (SELECT r.id FROM requests r WHERE r.uid = u.request_uid) AS request_id, u.origin
    FROM uploads u JOIN ips i ON i.id = u.ip_id";

/// One page of uploads, newest first; with `ip`, only that address's.
pub async fn list(
    conn: &mut SqliteConnection,
    page: u32,
    ip: Option<&str>,
) -> Result<super::browse::Page<UploadRow>> {
    use super::browse::{PAGE_SIZE, Page, offset};
    let page = page.max(1);
    let rows = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {UPLOAD_COLS} WHERE ?1 IS NULL OR i.ip = ?1 ORDER BY u.id DESC LIMIT ?2 OFFSET ?3"
    )))
    .bind(ip)
    .bind(PAGE_SIZE + 1)
    .bind(offset(page))
    .fetch_all(&mut *conn)
    .await?;
    Ok(Page::from_rows(rows, page))
}

impl super::Store {
    /// Up to `limit` of an address's uploads, newest first.
    pub async fn uploads_for_ip(&self, ip_id: i64, limit: i64) -> Result<Vec<UploadRow>> {
        Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {UPLOAD_COLS} WHERE u.ip_id = ? ORDER BY u.id DESC LIMIT ?"
        )))
        .bind(ip_id)
        .bind(limit)
        .fetch_all(&self.read)
        .await?)
    }

    /// The uploads a request carried (a form can send several).
    pub async fn uploads_of_request(&self, request_id: i64) -> Result<Vec<UploadRow>> {
        Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {UPLOAD_COLS}
             WHERE u.request_uid = (SELECT uid FROM requests WHERE id = ?) ORDER BY u.id"
        )))
        .bind(request_id)
        .fetch_all(&self.read)
        .await?)
    }
}

pub async fn get(conn: &mut SqliteConnection, uid: &str) -> Result<Option<UploadRow>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {UPLOAD_COLS} WHERE u.uid = ?"
    )))
    .bind(uid)
    .fetch_optional(&mut *conn)
    .await?)
}

/// The requests the origin answered at the upload's path after it, oldest
/// first: the same path, or (for a folder) any path under it. A query-time
/// join, as the trap's own lookup: `substr`, not `LIKE`, so a `_` or `%`
/// in the path is no wildcard (A2). Requests in the upload's own second
/// count if they came after its request.
pub async fn timeline(conn: &mut SqliteConnection, u: &UploadRow) -> Result<Vec<TimelineRow>> {
    Ok(sqlx::query_as(
        "SELECT r.id, r.ts, i.ip, r.method, r.path, r.query, r.status, r.answer
         FROM requests r JOIN ips i ON i.id = r.ip_id
         WHERE r.origin IS ?1 AND r.path >= ?2
           AND (r.path = ?2 OR (?3 AND substr(r.path, 1, length(?2)) = ?2))
           AND (r.ts > ?4 OR (r.ts = ?4 AND r.id > ?5))
         ORDER BY r.ts, r.id LIMIT ?6",
    )
    .bind(&u.origin)
    .bind(&u.answered_path)
    .bind(u.path_is_prefix)
    .bind(&u.ts)
    .bind(u.request_id.unwrap_or(i64::MAX))
    .bind(TIMELINE_MAX)
    .fetch_all(&mut *conn)
    .await?)
}

/// An upload's held content, with its SHA-256, for the admin's encrypted
/// download. The only reader of stored content besides replication
/// ([`content_for_relay`]); nothing serves it on the trap.
pub async fn content_for_export(
    conn: &mut SqliteConnection,
    uid: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    Ok(sqlx::query_as(
        "SELECT b.sha256, b.content FROM uploads u JOIN upload_blobs b ON b.sha256 = u.sha256
         WHERE u.uid = ?",
    )
    .bind(uid)
    .fetch_optional(&mut *conn)
    .await?)
}

/// Test fixture: a `PUT` of `content` to `path` from `ip` (a fixture
/// address), recorded as a request and its upload. Returns the upload's uid.
#[cfg(test)]
pub(crate) async fn seed_upload(
    store: &super::Store,
    ip: &str,
    path: &str,
    content: &[u8],
) -> String {
    let ip_id = store.upsert_ip(ip.parse().unwrap()).await.unwrap().id;
    let id = store
        .insert_request(&super::requests::NewRequest {
            ip_id,
            method: "PUT".into(),
            path: path.into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let (request_uid, ts): (String, String) =
        sqlx::query_as("SELECT uid, ts FROM requests WHERE id = ?")
            .bind(id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    let r = UploadRec {
        request_uid,
        ts,
        ip: ip.into(),
        kind: "put".into(),
        filename: Some("s.php".into()),
        sniffed_type: "php".into(),
        size: content.len() as i64,
        answered_path: path.into(),
        ..Default::default()
    };
    let (_, _, uid) = store.local().record_upload(r, content, true).await.unwrap();
    uid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::{Identity, NodeId};
    use crate::store::Store;

    const DAY: &str = "2026-10-11";

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (s, dir)
    }

    fn rec(uid: &str, content: &[u8]) -> UploadRec {
        UploadRec {
            uid: uid.into(),
            request_uid: format!("r-{uid}"),
            ts: "2026-10-01 00:00:00".into(),
            ip: "203.0.113.21".into(),
            kind: "put".into(),
            sniffed_type: "php".into(),
            size: content.len() as i64,
            sha256: sha2::Sha256::digest(content).to_vec(),
            answered_path: "/s.php".into(),
            content_state: "held".into(),
            carries_content: true,
            ..Default::default()
        }
    }

    /// 1 MiB that no other `n` repeats.
    fn mib(n: u32) -> Vec<u8> {
        let mut v = vec![0u8; MAX_CONTENT];
        v[..4].copy_from_slice(&n.to_le_bytes());
        v
    }

    async fn receive(
        conn: &mut SqliteConnection,
        origin: &NodeId,
        r: &UploadRec,
        content: Option<&[u8]>,
        limits: &Limits,
        day: &str,
        free: Option<u64>,
    ) -> String {
        let ctx = Ctx {
            origin: Some(origin),
            hlc: 1,
        };
        assert_eq!(
            apply_at(conn, ctx, r, content, limits, day, free)
                .await
                .unwrap(),
            Effect::Applied
        );
        sqlx::query_scalar("SELECT content_state FROM uploads WHERE uid = ?")
            .bind(&r.uid)
            .fetch_one(&mut *conn)
            .await
            .unwrap()
    }

    async fn blobs(conn: &mut SqliteConnection) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM upload_blobs")
            .fetch_one(&mut *conn)
            .await
            .unwrap()
    }

    fn origin() -> NodeId {
        Identity::generate().unwrap().id
    }

    /// (a) The same file twice is one blob; on the origin only the first
    /// upload carries the bytes (A3).
    #[tokio::test]
    async fn a_duplicate_hash_stores_one_blob() {
        let (s, _d) = store().await;
        let mut c = s.pool.acquire().await.unwrap();
        let l = Limits::default();
        let body = b"<?php system($_GET['c']); ?>";
        let mut first = rec("u1", b"");
        let mut second = rec("u2", b"");
        for r in [&mut first, &mut second] {
            let st = insert_upload_at(&mut c, b"", r, body, true, &l, DAY, None)
                .await
                .unwrap();
            assert_eq!(st, ContentState::Held);
        }
        assert!(first.carries_content, "newly stored");
        assert!(!second.carries_content, "already held: hash only");
        assert_eq!(first.sha256, sha2::Sha256::digest(body).to_vec());
        assert_eq!(blobs(&mut c).await, 1);
        // A receiver given the same bytes twice keeps one blob too.
        let (s2, _d2) = store().await;
        let mut c2 = s2.pool.acquire().await.unwrap();
        let o = origin();
        for uid in ["x1", "x2"] {
            let st = receive(&mut c2, &o, &rec(uid, body), Some(body), &l, DAY, None).await;
            assert_eq!(st, "held");
        }
        assert_eq!(blobs(&mut c2).await, 1);
    }

    /// (b) Bytes that do not hash to the signed `sha256` are not stored;
    /// the row is (C1).
    #[tokio::test]
    async fn a_hash_mismatch_stores_metadata_only() {
        let (s, _d) = store().await;
        let mut c = s.pool.acquire().await.unwrap();
        let r = rec("u1", b"what was signed");
        let st = receive(
            &mut c,
            &origin(),
            &r,
            Some(b"tampered"),
            &Limits::default(),
            DAY,
            None,
        )
        .await;
        assert_eq!(st, "dropped_mismatch");
        assert_eq!(blobs(&mut c).await, 0);
        assert!(
            !has_blob(&mut c, &sha2::Sha256::digest(b"tampered"))
                .await
                .unwrap()
        );
    }

    /// (c) More than 1 MiB is refused before it is even hashed.
    #[tokio::test]
    async fn content_over_the_cap_is_rejected() {
        let (s, _d) = store().await;
        let mut c = s.pool.acquire().await.unwrap();
        let big = vec![1u8; MAX_CONTENT + 1];
        let st = receive(
            &mut c,
            &origin(),
            &rec("u1", &big),
            Some(&big),
            &Limits::default(),
            DAY,
            None,
        )
        .await;
        assert_eq!(st, "too_big");
        assert_eq!(blobs(&mut c).await, 0);
    }

    /// (d) The 33rd MiB from one origin in a day is over its budget; another
    /// origin is not affected. The budget is keyed on the receiver's day of
    /// apply: a record back-dated into an empty day does not escape it (A1),
    /// and the next day of apply has room again.
    #[tokio::test]
    async fn the_daily_budget_is_per_origin_and_day_of_apply() {
        let (s, _d) = store().await;
        let mut c = s.pool.acquire().await.unwrap();
        let l = Limits::default();
        let (a, b) = (origin(), origin());
        for n in 0..32 {
            let body = mib(n);
            let st = receive(
                &mut c,
                &a,
                &rec(&format!("a{n}"), &body),
                Some(&body),
                &l,
                DAY,
                None,
            )
            .await;
            assert_eq!(st, "held", "MiB {n}");
        }
        let body = mib(32);
        let st = receive(&mut c, &a, &rec("a32", &body), Some(&body), &l, DAY, None).await;
        assert_eq!(st, "dropped_budget");
        let mut old = rec("a33", &mib(33));
        old.ts = "2026-01-01 00:00:00".into();
        let st = receive(&mut c, &a, &old, Some(&mib(33)), &l, DAY, None).await;
        assert_eq!(
            st, "dropped_budget",
            "a back-dated ts counts on the day of apply"
        );
        let st = receive(
            &mut c,
            &b,
            &rec("b0", &mib(34)),
            Some(&mib(34)),
            &l,
            DAY,
            None,
        )
        .await;
        assert_eq!(st, "held", "another origin has its own budget");
        let st = receive(
            &mut c,
            &a,
            &rec("a35", &mib(35)),
            Some(&mib(35)),
            &l,
            "2026-10-12",
            None,
        )
        .await;
        assert_eq!(st, "held", "a new day of apply");
    }

    /// (e) Past the ceiling on all stored content.
    #[tokio::test]
    async fn past_the_ceiling_content_is_dropped() {
        let (s, _d) = store().await;
        let mut c = s.pool.acquire().await.unwrap();
        let l = Limits {
            store_max_mb: 1,
            ..Default::default()
        };
        let o = origin();
        let st = receive(
            &mut c,
            &o,
            &rec("u1", &mib(1)),
            Some(&mib(1)),
            &l,
            DAY,
            None,
        )
        .await;
        assert_eq!(st, "held");
        let st = receive(
            &mut c,
            &o,
            &rec("u2", b"one more"),
            Some(b"one more"),
            &l,
            DAY,
            None,
        )
        .await;
        assert_eq!(st, "dropped_ceiling");
        // The origin itself is held to it alike.
        let mut r = rec("u3", b"");
        let st = insert_upload_at(&mut c, b"", &mut r, b"local", true, &l, DAY, None)
            .await
            .unwrap();
        assert_eq!(st, ContentState::DroppedCeiling);
        assert!(!r.carries_content);
        assert_eq!(blobs(&mut c).await, 1);
    }

    /// (f) Below the free-disk floor nothing new is stored.
    #[tokio::test]
    async fn below_the_disk_floor_content_is_dropped() {
        let (s, _d) = store().await;
        let mut c = s.pool.acquire().await.unwrap();
        let l = Limits::default();
        let free = Some(u64::from(l.min_free_mb) * MIB);
        let st = receive(
            &mut c,
            &origin(),
            &rec("u1", b"x"),
            Some(b"x"),
            &l,
            DAY,
            free,
        )
        .await;
        assert_eq!(st, "dropped_disk");
        assert_eq!(blobs(&mut c).await, 0);
        // The real probe answers for the test's own file system.
        assert!(free_bytes(&mut c).await.unwrap().is_some());
    }

    /// Over the source's hourly rate, the origin keeps the hash only and
    /// sends no bytes.
    #[tokio::test]
    async fn over_the_rate_the_origin_keeps_the_hash_only() {
        let (s, _d) = store().await;
        let mut c = s.pool.acquire().await.unwrap();
        let mut r = rec("u1", b"");
        let st = insert_upload_at(
            &mut c,
            b"",
            &mut r,
            b"x",
            false,
            &Limits::default(),
            DAY,
            None,
        )
        .await
        .unwrap();
        assert_eq!(st, ContentState::DroppedRate);
        assert_eq!(
            (r.content_state.as_str(), r.carries_content),
            ("dropped_rate", false)
        );
        assert_eq!(r.sha256, sha2::Sha256::digest(b"x").to_vec());
        assert_eq!(blobs(&mut c).await, 0);
    }

    /// A3: a receiver's state is `held` exactly when the blob is present
    /// after apply, whatever the origin's word. C2: bytes attached to a
    /// record that does not carry content are ignored.
    #[tokio::test]
    async fn held_means_the_blob_is_here() {
        let (s, _d) = store().await;
        let mut c = s.pool.acquire().await.unwrap();
        let (l, o) = (Limits::default(), origin());
        // Held at the origin, but no bytes came: not received.
        let st = receive(&mut c, &o, &rec("u1", b"a"), None, &l, DAY, None).await;
        assert_eq!(st, "not_received");
        // Bytes attached against the signed flag are not taken.
        let mut no = rec("u2", b"a");
        no.carries_content = false;
        let st = receive(&mut c, &o, &no, Some(b"a"), &l, DAY, None).await;
        assert_eq!(st, "not_received");
        assert_eq!(blobs(&mut c).await, 0);
        // The origin's reason for having none is kept.
        let mut rate = rec("u3", b"a");
        (rate.content_state, rate.carries_content) = ("dropped_rate".into(), false);
        assert_eq!(
            receive(&mut c, &o, &rate, None, &l, DAY, None).await,
            "dropped_rate"
        );
        // Once the blob is here (another upload brought it), a hash-only
        // record of it is held.
        assert_eq!(
            receive(&mut c, &o, &rec("u4", b"a"), Some(b"a"), &l, DAY, None).await,
            "held"
        );
        assert_eq!(
            receive(&mut c, &o, &rec("u5", b"a"), None, &l, DAY, None).await,
            "held"
        );
    }

    /// The origin's path: the content is stored, the record written, and a
    /// delete of the request or the IP takes the upload with it.
    #[tokio::test]
    async fn a_recorded_upload_goes_with_its_request_and_ip() {
        let (s, _d) = store().await;
        let rec_ = s.local();
        let mut ip_id = 0;
        for n in 0..2 {
            let id;
            (id, ip_id) = rec_
                .insert_request_from(
                    "203.0.113.21",
                    &crate::store::requests::NewRequest {
                        method: "PUT".into(),
                        path: "/s.php".into(),
                        headers_json: "[]".into(),
                        labels_json: "[]".into(),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let request_uid: String = sqlx::query_scalar("SELECT uid FROM requests WHERE id = ?")
                .bind(id)
                .fetch_one(&s.pool)
                .await
                .unwrap();
            let r = UploadRec {
                request_uid,
                ..rec("", b"")
            };
            let (st, _, _) = rec_.record_upload(r, b"<?php", true).await.unwrap();
            assert_eq!(st, ContentState::Held);
            if n == 0 {
                rec_.delete_request(id).await.unwrap();
            }
        }
        let rows: Vec<(String, bool)> =
            sqlx::query_as("SELECT content_state, uid != '' FROM uploads")
                .fetch_all(&s.pool)
                .await
                .unwrap();
        assert_eq!(
            rows,
            [("held".to_string(), true)],
            "the first went with its request"
        );
        assert!(rec_.delete_ip(ip_id).await.unwrap());
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM uploads")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "and the second with its IP");
    }

    /// Uploads at the edge of the daily budget at once: the check and the
    /// store are one unit, so no more get in than the budget holds.
    #[tokio::test]
    async fn concurrent_uploads_stay_within_the_budget() {
        let (s, _d) = store().await;
        sqlx::query("INSERT INTO settings (key, value) VALUES (?, '1')")
            .bind(KEY_DAILY_MB)
            .execute(&s.pool)
            .await
            .unwrap();
        let rec_ = s.local();
        let mut rs = vec![];
        for n in 0..8u8 {
            let (id, _) = rec_
                .insert_request_from(
                    "203.0.113.22",
                    &crate::store::requests::NewRequest {
                        method: "PUT".into(),
                        path: "/s.php".into(),
                        headers_json: "[]".into(),
                        labels_json: "[]".into(),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let request_uid: String = sqlx::query_scalar("SELECT uid FROM requests WHERE id = ?")
                .bind(id)
                .fetch_one(&s.pool)
                .await
                .unwrap();
            // 300 KiB each: three fit in the 1 MiB budget, a fourth does not.
            let body = vec![n; 300 * 1024];
            rs.push((
                UploadRec {
                    request_uid,
                    ..rec("", b"")
                },
                body,
            ));
        }
        // Every upload starts on an open connection, so they run in step.
        let mut warm = vec![];
        for _ in 0..8 {
            warm.push(s.pool.acquire().await.unwrap());
        }
        drop(warm);
        let got = futures::future::join_all(
            rs.iter()
                .map(|(r, body)| rec_.record_upload(r.clone(), body, true)),
        )
        .await;
        let held = got
            .into_iter()
            .filter(|c| c.as_ref().unwrap().0 == ContentState::Held)
            .count();
        assert_eq!(held, 3, "the budget check and the store are one unit");
        let mut c = s.pool.acquire().await.unwrap();
        assert_eq!(blobs(&mut c).await, 3);
    }

    /// Daily maintenance drops content nothing refers to any more.
    #[tokio::test]
    async fn gc_drops_orphan_blobs() {
        let (s, _d) = store().await;
        let mut c = s.pool.acquire().await.unwrap();
        let o = origin();
        let l = Limits::default();
        receive(&mut c, &o, &rec("u1", b"a"), Some(b"a"), &l, DAY, None).await;
        receive(&mut c, &o, &rec("u2", b"b"), Some(b"b"), &l, DAY, None).await;
        sqlx::query("DELETE FROM uploads WHERE uid = 'u1'")
            .execute(&mut *c)
            .await
            .unwrap();
        assert_eq!(gc_blobs(&mut c).await.unwrap(), 1);
        assert!(!has_blob(&mut c, &sha2::Sha256::digest(b"a")).await.unwrap());
        assert!(has_blob(&mut c, &sha2::Sha256::digest(b"b")).await.unwrap());
    }

    /// The trap's answered paths are its own node's uploads only, oldest
    /// first, and a standalone node's are those without an origin.
    #[tokio::test]
    async fn answered_paths_are_this_origins() {
        let (s, _d) = store().await;
        let mut c = s.pool.acquire().await.unwrap();
        let l = Limits::default();
        let (mine, other) = (origin(), origin());
        let mut a = rec("a", b"x");
        a.answered_path = "/wp-content/plugins/hello/".into();
        a.path_is_prefix = true;
        let mut b = rec("b", b"x");
        b.answered_path = "/theirs.php".into();
        let c_ = rec("c", b"x");
        receive(&mut c, &mine, &a, None, &l, DAY, None).await;
        receive(&mut c, &other, &b, None, &l, DAY, None).await;
        receive(&mut c, &mine, &c_, None, &l, DAY, None).await;
        let ctx = Ctx {
            origin: None,
            hlc: 1,
        };
        let mut d = rec("d", b"x");
        d.answered_path = "/standalone.php".into();
        apply_at(&mut c, ctx, &d, None, &l, DAY, None)
            .await
            .unwrap();
        let got = answered_paths(&mut c, Some(&mine.0[..]), 10).await.unwrap();
        assert_eq!(
            got,
            vec![
                ("/wp-content/plugins/hello/".into(), true, "a".into()),
                ("/s.php".into(), false, "c".into()),
            ]
        );
        let last = answered_paths(&mut c, Some(&mine.0[..]), 1).await.unwrap();
        assert_eq!(last, vec![("/s.php".into(), false, "c".into())]);
        let alone = answered_paths(&mut c, None, 10).await.unwrap();
        assert_eq!(alone, vec![("/standalone.php".into(), false, "d".into())]);
    }

    /// The timeline is the origin's later requests at the path, and under
    /// it for a folder; a `_` in the slug matches only itself (A2).
    #[tokio::test]
    async fn the_timeline_is_later_requests_at_the_answered_path() {
        let (s, _d) = store().await;
        let mut c = s.pool.acquire().await.unwrap();
        let l = Limits::default();
        let (mine, other) = (origin(), origin());
        let a = rec("a", b"x");
        let mut b = rec("b", b"y");
        b.answered_path = "/wp-content/plugins/wp_shell/".into();
        b.path_is_prefix = true;
        receive(&mut c, &mine, &a, None, &l, DAY, None).await;
        receive(&mut c, &mine, &b, None, &l, DAY, None).await;
        let t0 = "2026-10-01 00:00:00";
        for (uid, ts, path, o) in [
            ("early", "2026-09-30 23:59:59", "/s.php", &mine),
            ("r-a", t0, "/s.php", &mine),
            ("same-second", t0, "/s.php", &mine),
            ("later", "2026-10-01 00:00:05", "/s.php", &mine),
            ("theirs", "2026-10-01 00:00:06", "/s.php", &other),
            ("longer", "2026-10-01 00:00:07", "/s.phpx", &mine),
            (
                "under",
                "2026-10-01 00:00:08",
                "/wp-content/plugins/wp_shell/x.php",
                &mine,
            ),
            (
                "wildcard",
                "2026-10-01 00:00:09",
                "/wp-content/plugins/wpXshell/x.php",
                &mine,
            ),
            (
                "no-slash",
                "2026-10-01 00:00:10",
                "/wp-content/plugins/wp_shell",
                &mine,
            ),
        ] {
            sqlx::query(
                "INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, origin)
                 VALUES (?, ?, (SELECT id FROM ips LIMIT 1), 'GET', ?, '[]', ?)",
            )
            .bind(uid)
            .bind(ts)
            .bind(path)
            .bind(&o.0[..])
            .execute(&mut *c)
            .await
            .unwrap();
        }
        let paths = |rows: Vec<TimelineRow>| rows.into_iter().map(|r| r.path).collect::<Vec<_>>();
        let a = get(&mut c, "a").await.unwrap().unwrap();
        assert!(a.request_id.is_some());
        assert_eq!(
            paths(timeline(&mut c, &a).await.unwrap()),
            ["/s.php", "/s.php"]
        );
        let b = get(&mut c, "b").await.unwrap().unwrap();
        assert_eq!(
            paths(timeline(&mut c, &b).await.unwrap()),
            ["/wp-content/plugins/wp_shell/x.php"]
        );
    }

    /// Only held content is exported, with its hash; the list says which.
    #[tokio::test]
    async fn only_held_content_is_exported() {
        let (s, _d) = store().await;
        let mut c = s.pool.acquire().await.unwrap();
        let l = Limits::default();
        let o = origin();
        let held = rec("h", b"kept");
        let gone = rec("g", b"not kept");
        receive(&mut c, &o, &held, Some(b"kept"), &l, DAY, None).await;
        receive(&mut c, &o, &gone, None, &l, DAY, None).await;
        let (sha, bytes) = content_for_export(&mut c, "h").await.unwrap().unwrap();
        assert_eq!((sha, bytes), (held.sha256.clone(), b"kept".to_vec()));
        assert!(content_for_export(&mut c, "g").await.unwrap().is_none());
        assert!(content_for_export(&mut c, "nope").await.unwrap().is_none());
        let page = list(&mut c, 1, None).await.unwrap();
        let got: Vec<_> = page
            .items
            .iter()
            .map(|u| (u.uid.as_str(), u.held))
            .collect();
        assert_eq!(got, [("g", false), ("h", true)]);
    }
}
