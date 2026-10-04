//! The canaries this node knows were served and the tokens of every
//! request, both derived from replicated rows (never replicated
//! themselves), so every node finds the same reuses: a reuse is a token
//! whose hash is a served canary's ([`crate::canary`]).
use super::Store;
use crate::canary::tokens::{TOKENS_V, of_request};
use anyhow::Result;
use sqlx::SqliteConnection;
use std::collections::HashSet;

/// Derive a stored request's served canaries and tokens (again: old ones
/// are replaced) and mark it parsed with [`TOKENS_V`].
pub(crate) async fn derive_request(conn: &mut SqliteConnection, request_id: i64) -> Result<()> {
    type Row = (
        String,
        i64,
        String,
        Option<String>,
        String,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<String>,
        Option<String>,
        Option<i64>,
    );
    let Some(r): Option<Row> = sqlx::query_as(
        "SELECT ts, ip_id, path, query, headers_json, body, raw_head, page_token, answer, decoy_v
         FROM requests WHERE id = ?",
    )
    .bind(request_id)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(());
    };
    let (ts, ip_id, path, query, headers_json, body, raw_head, page_token, answer, decoy_v) = r;
    sqlx::query("DELETE FROM canaries WHERE request_id = ?")
        .bind(request_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM request_tokens WHERE request_id = ?")
        .bind(request_id)
        .execute(&mut *conn)
        .await?;
    if let (Some(tok), Some(name)) = (
        page_token.as_deref(),
        answer.as_deref().and_then(|a| a.strip_prefix("decoy:")),
    ) {
        for (kind, value) in crate::canary::served(decoy_v, tok, name) {
            sqlx::query(
                "INSERT INTO canaries (value_hash, kind, request_id, ts, ip_id) VALUES (?,?,?,?,?)",
            )
            .bind(crate::canary::hash(&value))
            .bind(kind.name())
            .bind(request_id)
            .bind(&ts)
            .bind(ip_id)
            .execute(&mut *conn)
            .await?;
        }
    }
    let headers: Vec<(String, String)> = serde_json::from_str(&headers_json).unwrap_or_default();
    let tokens = of_request(
        &headers,
        raw_head.as_deref(),
        &path,
        query.as_deref(),
        body.as_deref().unwrap_or_default(),
    );
    for (place, h) in tokens {
        sqlx::query(
            "INSERT OR IGNORE INTO request_tokens (request_id, value_hash, place) VALUES (?,?,?)",
        )
        .bind(request_id)
        .bind(h)
        .bind(place)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query("UPDATE requests SET canary_parsed = ? WHERE id = ?")
        .bind(TOKENS_V)
        .bind(request_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Derive a light-row batch's served canaries and mark it parsed.
pub(crate) async fn derive_batch(conn: &mut SqliteConnection, batch_id: i64) -> Result<()> {
    sqlx::query("DELETE FROM canaries WHERE batch_id = ?")
        .bind(batch_id)
        .execute(&mut *conn)
        .await?;
    let rows: Vec<(i64, i64, String, String, Option<i64>, i64)> = sqlx::query_as(
        "SELECT s.rowid, s.ts_ms, s.page_token, s.answer, s.decoy_v, b.ip_id
         FROM skipped_requests s JOIN skipped_batches b ON b.id = s.batch_id
         WHERE s.batch_id = ? AND s.page_token IS NOT NULL AND s.answer LIKE 'decoy:%'",
    )
    .bind(batch_id)
    .fetch_all(&mut *conn)
    .await?;
    for (rowid, ts_ms, tok, answer, decoy_v, ip_id) in rows {
        let ts = chrono::DateTime::from_timestamp_millis(ts_ms)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        let name = answer.trim_start_matches("decoy:");
        for (kind, value) in crate::canary::served(decoy_v, &tok, name) {
            sqlx::query(
                "INSERT INTO canaries (value_hash, kind, batch_id, skip_rowid, ts, ip_id)
                 VALUES (?,?,?,?,?,?)",
            )
            .bind(crate::canary::hash(&value))
            .bind(kind.name())
            .bind(batch_id)
            .bind(rowid)
            .bind(&ts)
            .bind(ip_id)
            .execute(&mut *conn)
            .await?;
        }
    }
    sqlx::query("UPDATE skipped_batches SET canary_parsed = ? WHERE id = ?")
        .bind(TOKENS_V)
        .bind(batch_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Parse the rows stored before this build (or by an older tokenizer), a
/// batch at a time, each batch its own short write transaction so the trap
/// is not held up. Returns how many rows were parsed.
pub async fn backfill(pool: &sqlx::SqlitePool) -> Result<u64> {
    let mut done = 0;
    loop {
        let ids: Vec<i64> =
            sqlx::query_scalar("SELECT id FROM requests WHERE canary_parsed < ? LIMIT 200")
                .bind(TOKENS_V)
                .fetch_all(pool)
                .await?;
        let batches: Vec<i64> =
            sqlx::query_scalar("SELECT id FROM skipped_batches WHERE canary_parsed < ? LIMIT 200")
                .bind(TOKENS_V)
                .fetch_all(pool)
                .await?;
        if ids.is_empty() && batches.is_empty() {
            return Ok(done);
        }
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        for id in &ids {
            derive_request(&mut tx, *id).await?;
        }
        for id in &batches {
            derive_batch(&mut tx, *id).await?;
        }
        tx.commit().await?;
        done += (ids.len() + batches.len()) as u64;
    }
}

/// One use of a served canary by another request.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Reuse {
    pub kind: String,
    pub place: String,
    /// The serving request (None: a light row).
    pub served_request_id: Option<i64>,
    pub served_ip: String,
    pub served_node: Option<String>,
    pub served_ts: String,
    pub served_answer: Option<String>,
    pub used_request_id: i64,
    pub used_ip: String,
    pub used_node: Option<String>,
    pub used_ts: String,
    pub delta_s: i64,
    pub same_source: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ReuseFilter {
    pub kind: Option<String>,
    /// Node name, either side.
    pub node: Option<String>,
    pub same_source: Option<bool>,
    pub range: crate::store::stats::Range,
    /// Either side is this request.
    pub request: Option<i64>,
    /// Either side is this IP.
    pub ip_id: Option<i64>,
    pub limit: i64,
}

const REUSE_SELECT: &str = "
    SELECT c.kind, t.place,
           c.request_id AS served_request_id,
           ci.ip AS served_ip,
           (SELECT name FROM members m WHERE m.id = COALESCE(sr.origin, sb.origin)) AS served_node,
           c.ts AS served_ts,
           sr.answer AS served_answer,
           u.id AS used_request_id,
           ui.ip AS used_ip,
           (SELECT name FROM members m WHERE m.id = u.origin) AS used_node,
           u.ts AS used_ts,
           CAST(strftime('%s', u.ts) AS INTEGER) - CAST(strftime('%s', c.ts) AS INTEGER) AS delta_s,
           c.ip_id = u.ip_id AS same_source
    FROM request_tokens t
    JOIN canaries c ON c.value_hash = t.value_hash
    JOIN requests u ON u.id = t.request_id
    JOIN ips ui ON ui.id = u.ip_id
    JOIN ips ci ON ci.id = c.ip_id
    LEFT JOIN requests sr ON sr.id = c.request_id
    LEFT JOIN skipped_batches sb ON sb.id = c.batch_id
    WHERE (c.request_id IS NULL OR c.request_id != t.request_id)";

impl Store {
    /// Reuses matching `f`, newest use first, one row per (use, canary).
    pub async fn reuses(&self, f: &ReuseFilter) -> Result<Vec<Reuse>> {
        let mut sql = REUSE_SELECT.to_string();
        if f.kind.is_some() {
            sql.push_str(" AND c.kind = ?");
        }
        if f.node.is_some() {
            sql.push_str(" AND ? IN ((SELECT name FROM members m WHERE m.id = COALESCE(sr.origin, sb.origin)), (SELECT name FROM members m WHERE m.id = u.origin))");
        }
        if let Some(same) = f.same_source {
            sql.push_str(if same {
                " AND c.ip_id = u.ip_id"
            } else {
                " AND c.ip_id != u.ip_id"
            });
        }
        if f.request.is_some() {
            sql.push_str(" AND ? IN (c.request_id, u.id)");
        }
        if f.ip_id.is_some() {
            sql.push_str(" AND ? IN (c.ip_id, u.ip_id)");
        }
        if f.range.since().is_some() {
            sql.push_str(" AND u.ts >= datetime('now', ?)");
        }
        sql.push_str(" GROUP BY u.id, c.value_hash ORDER BY u.ts DESC, u.id DESC LIMIT ?");
        let mut q = sqlx::query_as::<_, Reuse>(sqlx::AssertSqlSafe(sql));
        if let Some(k) = &f.kind {
            q = q.bind(k);
        }
        if let Some(n) = &f.node {
            q = q.bind(n);
        }
        if let Some(r) = f.request {
            q = q.bind(r);
        }
        if let Some(i) = f.ip_id {
            q = q.bind(i);
        }
        if let Some(m) = f.range.since() {
            q = q.bind(m);
        }
        Ok(q.bind(f.limit.clamp(1, 1000)).fetch_all(&self.read).await?)
    }

    pub async fn canary_links_for_ip(&self, ip_id: i64) -> Result<(i64, i64)> {
        Ok(sqlx::query_as(
            "SELECT
               (SELECT COUNT(DISTINCT u.ip_id) FROM canaries c
                  JOIN request_tokens t ON t.value_hash = c.value_hash
                  JOIN requests u ON u.id = t.request_id
                WHERE c.ip_id = ?1 AND u.ip_id != ?1),
               (SELECT COUNT(DISTINCT c.ip_id) FROM requests u
                  JOIN request_tokens t ON t.request_id = u.id
                  JOIN canaries c ON c.value_hash = t.value_hash
                WHERE u.ip_id = ?1 AND c.ip_id != ?1)",
        )
        .bind(ip_id)
        .fetch_one(&self.read)
        .await?)
    }
}

impl Store {
    /// Which of these hashes are canaries this node knows were served.
    pub async fn known_canaries(&self, hashes: &[i64]) -> Result<HashSet<i64>> {
        if hashes.is_empty() {
            return Ok(HashSet::new());
        }
        let found: Vec<i64> = sqlx::query_scalar(
            "SELECT DISTINCT value_hash FROM canaries
             WHERE value_hash IN (SELECT value FROM json_each(?))",
        )
        .bind(serde_json::to_string(hashes)?)
        .fetch_all(&self.read)
        .await?;
        Ok(found.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::record::{Record, RequestRec, SkipBatchRec, SkipRow};
    use crate::store::data::{Ctx, apply};

    const TOK: &str = "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a";

    fn req(
        uid: &str,
        ts: &str,
        ip: &str,
        path: &str,
        headers: &str,
        answer: &str,
        decoy_v: Option<i64>,
    ) -> Record {
        Record::Request(Box::new(RequestRec {
            uid: uid.into(),
            ts: ts.into(),
            ip: ip.into(),
            method: "GET".into(),
            path: path.into(),
            headers_json: headers.into(),
            labels_json: "[]".into(),
            page_token: Some(format!("{TOK}-{uid}")),
            answer: Some(answer.into()),
            decoy_v,
            ..Default::default()
        }))
    }

    fn git_token(uid: &str) -> String {
        crate::canary::value(&format!("{TOK}-{uid}"), crate::canary::Kind::GitToken)
    }

    fn basic(user: &str, pass: &str) -> String {
        let b = data_encoding::BASE64.encode(format!("{user}:{pass}").as_bytes());
        format!(r#"[["authorization","Basic {b}"]]"#)
    }

    async fn reuses(pool: &sqlx::SqlitePool) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT s.uid, u.uid FROM request_tokens t
             JOIN canaries c ON c.value_hash = t.value_hash
             JOIN requests u ON u.id = t.request_id
             JOIN requests s ON s.id = c.request_id
             WHERE c.request_id != t.request_id ORDER BY 1, 2",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_reuse_is_found_in_either_arrival_order() {
        for serve_first in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let s = crate::store::Store::connect(&dir.path().join("t.db"))
                .await
                .unwrap();
            let serve = req(
                "srv",
                "2026-10-04 10:00:00",
                "198.51.100.1",
                "/.git/config",
                "[]",
                "decoy:git-config",
                Some(1),
            );
            let using = req(
                "use",
                "2026-10-04 13:00:00",
                "198.51.100.2",
                "/git/shop.git/info/refs",
                &basic("deploy", &git_token("srv")),
                "decoy:git-refs",
                Some(1),
            );
            let mut conn = s.pool.acquire().await.unwrap();
            let ctx = Ctx {
                origin: None,
                hlc: 1,
            };
            let order = if serve_first {
                [&serve, &using]
            } else {
                [&using, &serve]
            };
            for r in order {
                apply(&mut conn, ctx, r).await.unwrap();
            }
            assert_eq!(
                reuses(&s.pool).await,
                vec![("srv".into(), "use".into())],
                "serve_first={serve_first}"
            );
        }
    }

    #[tokio::test]
    async fn a_light_row_decoy_is_traceable() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: None,
            hlc: 1,
        };
        let tok = "light-token";
        apply(
            &mut conn,
            ctx,
            &Record::SkipBatch(SkipBatchRec {
                uid: "b1".into(),
                ip: "198.51.100.3".into(),
                dropped: 0,
                rows: vec![SkipRow {
                    ts_ms: 1_791_000_000_000,
                    method: "GET".into(),
                    path: "/.git/config".into(),
                    page_token: Some(tok.into()),
                    host: Some("203.0.113.7".into()),
                    answer: Some("decoy:git-config".into()),
                    decoy_v: Some(1),
                }],
                build: String::new(),
            }),
        )
        .await
        .unwrap();
        let token = crate::canary::value(tok, crate::canary::Kind::GitToken);
        apply(
            &mut conn,
            ctx,
            &req(
                "use",
                "2026-10-04 13:00:00",
                "198.51.100.4",
                "/x",
                &basic("deploy", &token),
                "not-found",
                None,
            ),
        )
        .await
        .unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM request_tokens t JOIN canaries c ON c.value_hash = t.value_hash WHERE c.batch_id IS NOT NULL",
        ).fetch_one(&s.pool).await.unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn version_zero_rows_are_canaries_too() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: None,
            hlc: 1,
        };
        apply(
            &mut conn,
            ctx,
            &req(
                "old",
                "2026-10-01 10:00:00",
                "198.51.100.1",
                "/.env",
                "[]",
                "decoy:dotenv",
                None,
            ),
        )
        .await
        .unwrap();
        let r = crate::canary::v0_ref(&format!("{TOK}-old"));
        apply(
            &mut conn,
            ctx,
            &req(
                "use",
                "2026-10-04 13:00:00",
                "198.51.100.2",
                "/x",
                &basic("app", &format!("canary-{r}")),
                "not-found",
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(reuses(&s.pool).await, vec![("old".into(), "use".into())]);
    }

    #[tokio::test]
    async fn backfill_derives_history_and_reparses_old_versions() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: None,
            hlc: 1,
        };
        apply(
            &mut conn,
            ctx,
            &req(
                "srv",
                "2026-10-04 10:00:00",
                "198.51.100.1",
                "/.git/config",
                "[]",
                "decoy:git-config",
                Some(1),
            ),
        )
        .await
        .unwrap();
        apply(
            &mut conn,
            ctx,
            &req(
                "use",
                "2026-10-04 13:00:00",
                "198.51.100.2",
                "/x",
                &basic("deploy", &git_token("srv")),
                "not-found",
                None,
            ),
        )
        .await
        .unwrap();
        // As an older build would have left it.
        for sql in [
            "DELETE FROM canaries",
            "DELETE FROM request_tokens",
            "UPDATE requests SET canary_parsed = 0",
        ] {
            sqlx::query(sql).execute(&s.pool).await.unwrap();
        }
        drop(conn);
        assert_eq!(backfill(&s.pool).await.unwrap(), 2);
        assert_eq!(reuses(&s.pool).await.len(), 1);
        assert_eq!(backfill(&s.pool).await.unwrap(), 0, "each row once");
        sqlx::query("UPDATE requests SET canary_parsed = 0 WHERE uid = 'use'")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(backfill(&s.pool).await.unwrap(), 1);
        assert_eq!(
            reuses(&s.pool).await.len(),
            1,
            "re-parsing does not duplicate"
        );
    }

    #[tokio::test]
    async fn derived_rows_follow_their_request() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: None,
            hlc: 1,
        };
        apply(
            &mut conn,
            ctx,
            &req(
                "srv",
                "2026-10-04 10:00:00",
                "198.51.100.1",
                "/.git/config",
                "[]",
                "decoy:git-config",
                Some(1),
            ),
        )
        .await
        .unwrap();
        apply(
            &mut conn,
            ctx,
            &req(
                "use",
                "2026-10-04 13:00:00",
                "198.51.100.2",
                "/x",
                &basic("deploy", &git_token("srv")),
                "not-found",
                None,
            ),
        )
        .await
        .unwrap();
        drop(conn);
        let use_id: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE uid = 'use'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        s.local().delete_request(use_id).await.unwrap();
        let srv_id: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE uid = 'srv'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        s.local().delete_request(srv_id).await.unwrap();
        for t in ["canaries", "request_tokens"] {
            let n: i64 =
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {t}")))
                    .fetch_one(&s.pool)
                    .await
                    .unwrap();
            assert_eq!(n, 0, "{t}");
        }
    }

    #[tokio::test]
    async fn known_canaries_answers_by_hash() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        apply(
            &mut conn,
            Ctx {
                origin: None,
                hlc: 1,
            },
            &req(
                "srv",
                "2026-10-04 10:00:00",
                "198.51.100.1",
                "/.git/config",
                "[]",
                "decoy:git-config",
                Some(1),
            ),
        )
        .await
        .unwrap();
        drop(conn);
        let h = crate::canary::hash(&git_token("srv"));
        let k = s.known_canaries(&[h, 42]).await.unwrap();
        assert!(k.contains(&h) && !k.contains(&42));
        assert!(s.known_canaries(&[]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn reuses_name_both_sides_and_filter() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: None,
            hlc: 1,
        };
        apply(
            &mut conn,
            ctx,
            &req(
                "srv",
                "2026-10-04 10:00:00",
                "198.51.100.1",
                "/.git/config",
                "[]",
                "decoy:git-config",
                Some(1),
            ),
        )
        .await
        .unwrap();
        apply(
            &mut conn,
            ctx,
            &req(
                "use",
                "2026-10-04 13:00:00",
                "198.51.100.2",
                "/x",
                &basic("deploy", &git_token("srv")),
                "not-found",
                None,
            ),
        )
        .await
        .unwrap();
        apply(
            &mut conn,
            ctx,
            &req(
                "self",
                "2026-10-04 14:00:00",
                "198.51.100.1",
                "/y",
                &basic("deploy", &git_token("srv")),
                "not-found",
                None,
            ),
        )
        .await
        .unwrap();
        drop(conn);
        let all = ReuseFilter {
            range: crate::store::stats::Range::All,
            limit: 100,
            ..Default::default()
        };
        let r = s.reuses(&all).await.unwrap();
        assert_eq!(r.len(), 2);
        let other = r.iter().find(|x| x.used_ip == "198.51.100.2").unwrap();
        assert_eq!(
            (other.kind.as_str(), other.place.as_str()),
            ("git-token", "header:authorization")
        );
        assert_eq!(other.delta_s, 3 * 3600);
        assert!(!other.same_source);
        assert!(r.iter().any(|x| x.same_source));
        let diff = s
            .reuses(&ReuseFilter {
                same_source: Some(false),
                ..all.clone()
            })
            .await
            .unwrap();
        assert_eq!(diff.len(), 1);
        let srv_ip: i64 = sqlx::query_scalar("SELECT id FROM ips WHERE ip = '198.51.100.1'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(s.canary_links_for_ip(srv_ip).await.unwrap(), (1, 0));
        let use_ip: i64 = sqlx::query_scalar("SELECT id FROM ips WHERE ip = '198.51.100.2'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(s.canary_links_for_ip(use_ip).await.unwrap(), (0, 1));
    }
}
