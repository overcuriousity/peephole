//! Path shapes ([`crate::model::shape`]) of every request and light row,
//! and the `shapes` table (each shape's text, first and last time seen, and
//! how many IPs asked for it, and how many of its requests hit a rule).
//! Derived on each node from replicated rows, never replicated, as the
//! canaries are ([`super::canaries`]).
use crate::classify::{UNMATCHED_LABELS, is_unmatched};
use crate::model::shape::{SHAPE_V, shape};
use anyhow::Result;
use sqlx::SqliteConnection;
use std::collections::BTreeMap;

/// Derive a stored request's shape, unless it has this version's already.
pub(crate) async fn derive_request(conn: &mut SqliteConnection, request_id: i64) -> Result<()> {
    let Some((ts, ip_id, path, v, labels_json)): Option<(String, i64, String, i64, String)> =
        sqlx::query_as("SELECT ts, ip_id, path, shape_v, labels_json FROM requests WHERE id = ?")
            .bind(request_id)
            .fetch_optional(&mut *conn)
            .await?
    else {
        return Ok(());
    };
    if v == SHAPE_V {
        return Ok(());
    }
    let (hash, text) = shape(&path);
    let known = asked_before(conn, hash, ip_id, request_id, 0).await?;
    sqlx::query("UPDATE requests SET shape = ?, shape_v = ? WHERE id = ?")
        .bind(hash)
        .bind(SHAPE_V)
        .bind(request_id)
        .execute(&mut *conn)
        .await?;
    let labels: Vec<String> = serde_json::from_str(&labels_json).unwrap_or_default();
    seen(conn, hash, &text, &ts, &ts, !known, !is_unmatched(&labels)).await
}

/// Derive the shapes of a light-row batch's rows, unless it has this
/// version's already.
pub(crate) async fn derive_batch(conn: &mut SqliteConnection, batch_id: i64) -> Result<()> {
    let Some((ip_id, v)): Option<(i64, i64)> =
        sqlx::query_as("SELECT ip_id, shape_v FROM skipped_batches WHERE id = ?")
            .bind(batch_id)
            .fetch_optional(&mut *conn)
            .await?
    else {
        return Ok(());
    };
    if v == SHAPE_V {
        return Ok(());
    }
    let rows: Vec<(i64, i64, String)> =
        sqlx::query_as("SELECT rowid, ts_ms, path FROM skipped_requests WHERE batch_id = ?")
            .bind(batch_id)
            .fetch_all(&mut *conn)
            .await?;
    // Per shape: its text and the batch's first and last row asking for it.
    let mut shapes: BTreeMap<i64, (String, i64, i64)> = BTreeMap::new();
    for (rowid, ts_ms, path) in rows {
        let (hash, text) = shape(&path);
        sqlx::query("UPDATE skipped_requests SET shape = ? WHERE rowid = ?")
            .bind(hash)
            .bind(rowid)
            .execute(&mut *conn)
            .await?;
        let e = shapes.entry(hash).or_insert((text, ts_ms, ts_ms));
        e.1 = e.1.min(ts_ms);
        e.2 = e.2.max(ts_ms);
    }
    for (hash, (text, first, last)) in shapes {
        let known = asked_before(conn, hash, ip_id, 0, batch_id).await?;
        // Light rows carry no labels: never a rule hit.
        seen(
            conn,
            hash,
            &text,
            &ts_text(first),
            &ts_text(last),
            !known,
            false,
        )
        .await?;
    }
    sqlx::query("UPDATE skipped_batches SET shape_v = ? WHERE id = ?")
        .bind(SHAPE_V)
        .bind(batch_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// A light row's millisecond time as `requests.ts` holds times.
pub(crate) fn ts_text(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

/// Whether the IP asked for the shape in a row other than the request or
/// batch being derived (0: none).
async fn asked_before(
    conn: &mut SqliteConnection,
    hash: i64,
    ip_id: i64,
    request_id: i64,
    batch_id: i64,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM requests WHERE shape = ?1 AND ip_id = ?2 AND id <> ?3)
             OR EXISTS(SELECT 1 FROM skipped_batches b
                       JOIN skipped_requests s ON s.batch_id = b.id AND s.shape = ?1
                       WHERE b.ip_id = ?2 AND b.id <> ?4)",
    )
    .bind(hash)
    .bind(ip_id)
    .bind(request_id)
    .bind(batch_id)
    .fetch_one(&mut *conn)
    .await?)
}

/// Record that a shape was asked for between `first` and `last`, by an IP
/// new to it or not, in a request that hit a rule or not. A new shape
/// starts counting rule hits at once; one from before migration 0045
/// (`rule_hits` NULL) only learns that a rule hit it, and [`backfill`]
/// counts the rest.
async fn seen(
    conn: &mut SqliteConnection,
    hash: i64,
    text: &str,
    first: &str,
    last: &str,
    new_ip: bool,
    hit: bool,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO shapes (hash, text, first_seen, last_seen, ips, rule_hits)
         VALUES (?1,?2,?3,?4,1,?6)
         ON CONFLICT (hash) DO UPDATE SET
           first_seen = MIN(first_seen, excluded.first_seen),
           last_seen = MAX(last_seen, excluded.last_seen),
           ips = ips + ?5,
           rule_hits = CASE WHEN ?6 = 1 THEN COALESCE(rule_hits, 0) + 1 ELSE rule_hits END",
    )
    .bind(hash)
    .bind(text)
    .bind(first)
    .bind(last)
    .bind(new_ip as i64)
    .bind(hit as i64)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Requests derived per write transaction by [`backfill`].
const BACKFILL_REQUESTS: i64 = 500;
/// Light-row batches derived per write transaction (up to
/// [`super::data::SKIP_BATCH_MAX`] rows each).
const BACKFILL_BATCHES: i64 = 20;
/// Shapes whose rule hits are counted per write transaction by [`backfill`].
const BACKFILL_SHAPES: i64 = 200;
/// Pause between [`backfill`]'s transactions, so the trap's and
/// replication's writes get the lock in between.
const BACKFILL_PAUSE: std::time::Duration = std::time::Duration::from_millis(25);

/// Derive the shapes of the rows stored before this build, a page at a
/// time, each page its own short write transaction. When the rules changed
/// ([`SHAPE_V`]), every row and the `shapes` table are cleared first (one
/// transaction), so no count mixes two versions. Then counts the rule hits
/// of the shapes from before migration 0045, again a page at a time.
/// Returns how many requests and batches were derived.
pub async fn backfill(pool: &sqlx::SqlitePool) -> Result<u64> {
    let other: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM requests WHERE shape_v NOT IN (0, ?1))
             OR EXISTS(SELECT 1 FROM skipped_batches WHERE shape_v NOT IN (0, ?1))",
    )
    .bind(SHAPE_V)
    .fetch_one(pool)
    .await?;
    if other {
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        for sql in [
            // Waves name shapes by hash, which the new rules change.
            "DELETE FROM waves",
            "DELETE FROM shapes",
            "UPDATE requests SET shape = NULL, shape_v = 0 WHERE shape_v <> 0",
            "UPDATE skipped_requests SET shape = NULL WHERE shape IS NOT NULL",
            "UPDATE skipped_batches SET shape_v = 0 WHERE shape_v <> 0",
        ] {
            sqlx::query(sql).execute(&mut *tx).await?;
        }
        tx.commit().await?;
    }
    let mut done = 0;
    let (mut after_req, mut after_batch) = (0i64, 0i64);
    loop {
        let ids: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM requests WHERE shape_v < ? AND id > ? ORDER BY id LIMIT ?",
        )
        .bind(SHAPE_V)
        .bind(after_req)
        .bind(BACKFILL_REQUESTS)
        .fetch_all(pool)
        .await?;
        let batches: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM skipped_batches WHERE shape_v < ? AND id > ? ORDER BY id LIMIT ?",
        )
        .bind(SHAPE_V)
        .bind(after_batch)
        .bind(BACKFILL_BATCHES)
        .fetch_all(pool)
        .await?;
        if ids.is_empty() && batches.is_empty() {
            break;
        }
        after_req = ids.last().copied().unwrap_or(after_req);
        after_batch = batches.last().copied().unwrap_or(after_batch);
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        for id in &ids {
            derive_request(&mut tx, *id).await?;
        }
        for id in &batches {
            derive_batch(&mut tx, *id).await?;
        }
        tx.commit().await?;
        done += (ids.len() + batches.len()) as u64;
        tokio::time::sleep(BACKFILL_PAUSE).await;
    }
    let unmatched = serde_json::to_string(&UNMATCHED_LABELS)?;
    loop {
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        let counted = sqlx::query(
            "UPDATE shapes SET rule_hits = (
               SELECT COUNT(*) FROM requests r
               WHERE r.shape = shapes.hash
                 AND EXISTS(SELECT 1 FROM json_each(r.labels_json)
                            WHERE value NOT IN (SELECT value FROM json_each(?1))))
             WHERE hash IN (SELECT hash FROM shapes WHERE rule_hits IS NULL LIMIT ?2)",
        )
        .bind(&unmatched)
        .bind(BACKFILL_SHAPES)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if counted == 0 {
            return Ok(done);
        }
        tokio::time::sleep(BACKFILL_PAUSE).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::record::{Record, RequestRec, SkipBatchRec, SkipRow};
    use crate::store::data::{Ctx, apply};

    const CTX: Ctx<'static> = Ctx {
        origin: None,
        hlc: 1,
    };

    fn req(uid: &str, ts: &str, ip: &str, path: &str) -> Record {
        labeled(uid, ts, ip, path, "[]")
    }

    fn labeled(uid: &str, ts: &str, ip: &str, path: &str, labels: &str) -> Record {
        Record::Request(Box::new(RequestRec {
            uid: uid.into(),
            ts: ts.into(),
            ip: ip.into(),
            method: "GET".into(),
            path: path.into(),
            headers_json: "[]".into(),
            labels_json: labels.into(),
            ..Default::default()
        }))
    }

    fn batch(uid: &str, ip: &str, rows: &[(i64, &str)]) -> Record {
        Record::SkipBatch(SkipBatchRec {
            uid: uid.into(),
            ip: ip.into(),
            dropped: 0,
            rows: rows
                .iter()
                .map(|(ts_ms, path)| SkipRow {
                    ts_ms: *ts_ms,
                    method: "GET".into(),
                    path: (*path).into(),
                    page_token: None,
                    host: None,
                    answer: None,
                    decoy_v: None,
                    decoy_site: None,
                    held_ms: None,
                    decoy_in: None,
                })
                .collect(),
            build: String::new(),
        })
    }

    /// 2026-10-04 12:00:00 UTC and later, in ms.
    const NOON: i64 = 1_791_115_200_000;

    async fn store() -> (crate::store::Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        (s, dir)
    }

    async fn fill(pool: &sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        for r in [
            req("a1", "2026-10-04 12:30:00", "198.51.100.1", "/a8f3c2d1.php"),
            req(
                "a2",
                "2026-10-04 14:00:00",
                "198.51.100.1",
                "/b7e2a9c0.php?x=1",
            ),
            req("b1", "2026-10-04 12:10:00", "198.51.100.2", "/0c1d2e3f.PHP"),
            labeled(
                "b2",
                "2026-10-04 12:20:00",
                "198.51.100.2",
                "/.env",
                r#"["path-scanner","sensitive-path"]"#,
            ),
            // Light rows: a third IP, twice in one batch; the first IP
            // again, earlier than all of its requests.
            batch(
                "l1",
                "198.51.100.3",
                &[
                    (NOON + 3_600_000, "/ffee0011.php"),
                    (NOON + 7_200_000, "/1234abcd.php"),
                ],
            ),
            batch("l2", "198.51.100.1", &[(NOON - 60_000, "/aabbccdd.php")]),
            batch("l3", "198.51.100.3", &[(NOON, "//.env/")]),
        ] {
            apply(&mut conn, CTX, &r).await.unwrap();
        }
    }

    type Shape = (i64, String, String, String, i64, Option<i64>);

    async fn shapes(pool: &sqlx::SqlitePool) -> Vec<Shape> {
        sqlx::query_as("SELECT * FROM shapes ORDER BY text")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    /// Every row's derived columns and its shape's rule hits, to compare a
    /// backfill with the insert path.
    async fn rows(pool: &sqlx::SqlitePool) -> Vec<(String, Option<i64>, i64, Option<i64>)> {
        sqlx::query_as(
            "SELECT uid, shape, shape_v,
                    (SELECT rule_hits FROM shapes WHERE hash = requests.shape) FROM requests
             UNION ALL
             SELECT b.uid || ':' || s.rowid, s.shape, b.shape_v,
                    (SELECT rule_hits FROM shapes WHERE hash = s.shape)
             FROM skipped_requests s JOIN skipped_batches b ON b.id = s.batch_id
             ORDER BY 1",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    fn want() -> Vec<Shape> {
        let (hex, env) = (shape("/{hex}.php"), shape("/.env"));
        vec![
            (
                env.0,
                env.1,
                "2026-10-04 12:00:00".into(),
                "2026-10-04 12:20:00".into(),
                2,
                Some(1),
            ),
            (
                hex.0,
                hex.1,
                "2026-10-04 11:59:00".into(),
                "2026-10-04 14:00:00".into(),
                3,
                Some(0),
            ),
        ]
    }

    #[tokio::test]
    async fn inserting_rows_derives_shapes() {
        let (s, _dir) = store().await;
        fill(&s.pool).await;
        let rows = rows(&s.pool).await;
        assert_eq!(rows.len(), 8);
        let hex = shape("/{hex}.php").0;
        for (uid, h, v, _) in &rows {
            assert_eq!(*v, SHAPE_V, "{uid}");
            assert!(h.is_some(), "{uid}");
        }
        assert_eq!(rows.iter().filter(|r| r.1 == Some(hex)).count(), 6);
        assert_eq!(shapes(&s.pool).await, want());
    }

    #[tokio::test]
    async fn backfill_derives_what_the_insert_path_would_and_is_idempotent() {
        let (s, _dir) = store().await;
        fill(&s.pool).await;
        let derived = rows(&s.pool).await;
        // As stored before this build.
        for sql in [
            "DELETE FROM shapes",
            "UPDATE requests SET shape = NULL, shape_v = 0",
            "UPDATE skipped_requests SET shape = NULL",
            "UPDATE skipped_batches SET shape_v = 0",
        ] {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&s.pool)
                .await
                .unwrap();
        }
        assert_eq!(backfill(&s.pool).await.unwrap(), 4 + 3);
        assert_eq!(rows(&s.pool).await, derived);
        assert_eq!(shapes(&s.pool).await, want());
        assert_eq!(backfill(&s.pool).await.unwrap(), 0);
        assert_eq!(rows(&s.pool).await, derived);
        assert_eq!(shapes(&s.pool).await, want());
    }

    #[tokio::test]
    async fn backfill_starts_over_on_rows_of_other_rules() {
        let (s, _dir) = store().await;
        fill(&s.pool).await;
        let derived = rows(&s.pool).await;
        // One row derived by other rules, and counts that are now wrong.
        for sql in [
            "UPDATE requests SET shape = 7, shape_v = 99 WHERE uid = 'a1'",
            "UPDATE shapes SET ips = 42",
        ] {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&s.pool)
                .await
                .unwrap();
        }
        assert_eq!(backfill(&s.pool).await.unwrap(), 4 + 3);
        assert_eq!(rows(&s.pool).await, derived);
        assert_eq!(shapes(&s.pool).await, want());
    }

    #[tokio::test]
    async fn backfill_counts_rule_hits_of_shapes_from_before_0045() {
        let (s, _dir) = store().await;
        fill(&s.pool).await;
        let derived = rows(&s.pool).await;
        // As migration 0045 leaves them.
        sqlx::query("UPDATE shapes SET rule_hits = NULL")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(backfill(&s.pool).await.unwrap(), 0);
        assert_eq!(rows(&s.pool).await, derived);
        assert_eq!(shapes(&s.pool).await, want());
    }

    async fn rule_hits(pool: &sqlx::SqlitePool, path: &str) -> Option<i64> {
        sqlx::query_scalar("SELECT rule_hits FROM shapes WHERE hash = ?")
            .bind(shape(path).0)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn weak_and_behaviour_labels_are_no_rule_hit() {
        let (s, _dir) = store().await;
        let mut conn = s.pool.acquire().await.unwrap();
        let r = labeled(
            "w1",
            "2026-10-04 12:00:00",
            "198.51.100.9",
            "/wp-admin/x.php",
            r#"["form-interaction","php-probe","probe"]"#,
        );
        apply(&mut conn, CTX, &r).await.unwrap();
        drop(conn);
        assert_eq!(rule_hits(&s.pool, "/wp-admin/x.php").await, Some(0));
        sqlx::query("UPDATE shapes SET rule_hits = NULL")
            .execute(&s.pool)
            .await
            .unwrap();
        backfill(&s.pool).await.unwrap();
        assert_eq!(rule_hits(&s.pool, "/wp-admin/x.php").await, Some(0));
    }

    #[tokio::test]
    async fn an_unmatched_insert_leaves_a_shape_from_before_0045_uncounted() {
        let (s, _dir) = store().await;
        fill(&s.pool).await;
        sqlx::query("UPDATE shapes SET rule_hits = NULL")
            .execute(&s.pool)
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let miss = req("c1", "2026-10-04 15:00:00", "198.51.100.4", "/0a0b0c0d.php");
        apply(&mut conn, CTX, &miss).await.unwrap();
        assert_eq!(rule_hits(&s.pool, "/{hex}.php").await, None);
        let hit = labeled(
            "c2",
            "2026-10-04 15:01:00",
            "198.51.100.4",
            "/0a0b0c0e.php",
            r#"["rce"]"#,
        );
        apply(&mut conn, CTX, &hit).await.unwrap();
        assert_eq!(rule_hits(&s.pool, "/{hex}.php").await, Some(1));
    }
}
