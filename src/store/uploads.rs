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
            let (st, _) = rec_.record_upload(r, b"<?php", true).await.unwrap();
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
}
