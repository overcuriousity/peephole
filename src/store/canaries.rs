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
    // Every row, in batch order: a row is named by its position (from 1),
    // which is the same on every node.
    type Row = (i64, Option<String>, Option<String>, Option<i64>, i64);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT s.ts_ms, s.page_token, s.answer, s.decoy_v, b.ip_id
         FROM skipped_requests s JOIN skipped_batches b ON b.id = s.batch_id
         WHERE s.batch_id = ? ORDER BY s.rowid",
    )
    .bind(batch_id)
    .fetch_all(&mut *conn)
    .await?;
    for (pos, (ts_ms, tok, answer, decoy_v, ip_id)) in rows.into_iter().enumerate() {
        let (Some(tok), Some(name)) = (
            tok,
            answer.as_deref().and_then(|a| a.strip_prefix("decoy:")),
        ) else {
            continue;
        };
        let ts = chrono::DateTime::from_timestamp_millis(ts_ms)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        for (kind, value) in crate::canary::served(decoy_v, &tok, name) {
            sqlx::query(
                "INSERT INTO canaries (value_hash, kind, batch_id, skip_row, ts, ip_id)
                 VALUES (?,?,?,?,?,?)",
            )
            .bind(crate::canary::hash(&value))
            .bind(kind.name())
            .bind(batch_id)
            .bind(pos as i64 + 1)
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

/// Rows parsed per write transaction by [`backfill`].
const BACKFILL_BATCH: i64 = 50;
/// Pause between [`backfill`]'s transactions, so the trap's and
/// replication's writes get the lock in between.
const BACKFILL_PAUSE: std::time::Duration = std::time::Duration::from_millis(25);

/// Parse the rows stored before this build (or by an older tokenizer), a
/// small batch at a time, each batch its own short write transaction with a
/// pause after it, so the trap and replication are not held up on a large
/// database. Walks each table once by id. Returns how many rows were
/// parsed.
pub async fn backfill(pool: &sqlx::SqlitePool) -> Result<u64> {
    let mut done = 0;
    let (mut after_req, mut after_batch) = (0i64, 0i64);
    loop {
        let ids: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM requests WHERE canary_parsed < ? AND id > ? ORDER BY id LIMIT ?",
        )
        .bind(TOKENS_V)
        .bind(after_req)
        .bind(BACKFILL_BATCH)
        .fetch_all(pool)
        .await?;
        let batches: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM skipped_batches WHERE canary_parsed < ? AND id > ? ORDER BY id LIMIT ?",
        )
        .bind(TOKENS_V)
        .bind(after_batch)
        .bind(BACKFILL_BATCH)
        .fetch_all(pool)
        .await?;
        if ids.is_empty() && batches.is_empty() {
            return Ok(done);
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
            // The period is when the canary was served, as in the summary.
            sql.push_str(" AND c.ts >= datetime('now', ?)");
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

/// Served canaries of one kind.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct KindStat {
    pub kind: String,
    pub served: i64,
    pub reused: i64,
}
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CanarySummary {
    pub served: i64,
    /// Served canaries used at least once by any request but their own.
    pub reused: i64,
    /// Median and maximum time from harvest to first use, seconds.
    pub median_s: Option<i64>,
    pub max_s: Option<i64>,
    pub per_kind: Vec<KindStat>,
    /// Decoy answers that served canaries (one harvest each, however many
    /// values it carried), and how many of them were used again.
    pub harvests: i64,
    pub harvests_reused: i64,
    /// Median time from a harvest to the first use of any of its values.
    pub harvest_median_s: Option<i64>,
}

/// A serving row: (request id, light-row batch id, light-row position).
type Harvest = (Option<i64>, Option<i64>, Option<i64>);

impl CanarySummary {
    pub fn share_pct(&self) -> i64 {
        if self.served == 0 {
            0
        } else {
            (self.reused * 100 + self.served / 2) / self.served
        }
    }

    /// Harvests used again, in percent of harvests.
    pub fn harvest_share_pct(&self) -> i64 {
        if self.harvests == 0 {
            0
        } else {
            (self.harvests_reused * 100 + self.harvests / 2) / self.harvests
        }
    }
}

impl Store {
    /// Canary reuse as an admin sees it.
    pub async fn canary_summary(&self, range: crate::store::stats::Range) -> Result<CanarySummary> {
        self.canary_summary_as(range, crate::store::browse::Audience::Admin)
            .await
    }

    pub async fn canary_summary_as(
        &self,
        range: crate::store::stats::Range,
        a: crate::store::browse::Audience,
    ) -> Result<CanarySummary> {
        let rel = a.released("u");
        let since = range.since();
        let mut window = String::from(if since.is_some() {
            " AND c.ts >= datetime('now', ?)"
        } else {
            ""
        });
        if a == crate::store::browse::Audience::Public {
            // Only canaries whose serving request is released; light rows
            // (no request, never delayed) once the delay has elapsed, so a
            // probe cannot move the public share live.
            window.push_str(
                " AND ((c.request_id IS NOT NULL AND EXISTS (SELECT 1 FROM requests sr
                        WHERE sr.id = c.request_id AND sr.public_at IS NULL))
                    OR (c.request_id IS NULL AND c.ts <= datetime('now', '-' ||
                        (SELECT delay_s FROM publish_cfg WHERE id = 1) || ' seconds')))",
            );
        }
        // Per served canary: its kind and its first use by another request.
        type Row = (Option<i64>, Option<i64>, Option<i64>, String, Option<i64>);
        let mut q = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(format!(
            "SELECT c.request_id, c.batch_id, c.skip_row, c.kind,
                    (SELECT MIN(CAST(strftime('%s', u.ts) AS INTEGER) - CAST(strftime('%s', c.ts) AS INTEGER))
                     FROM request_tokens t JOIN requests u ON u.id = t.request_id
                     WHERE t.value_hash = c.value_hash
                       AND (c.request_id IS NULL OR t.request_id != c.request_id){rel})
             FROM canaries c WHERE 1 = 1{window}"
        )));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let rows = q.fetch_all(&self.read).await?;
        let mut per: std::collections::BTreeMap<String, (i64, i64)> = Default::default();
        let mut firsts: Vec<i64> = vec![];
        // Per harvest (serving row): the first use of any of its values.
        let mut harvests: std::collections::BTreeMap<Harvest, Option<i64>> = Default::default();
        for (req, batch, rowid, kind, first) in &rows {
            let h = harvests.entry((*req, *batch, *rowid)).or_default();
            if let Some(f) = first {
                *h = Some(h.map_or(*f, |x| x.min(*f)));
            }
            let e = per.entry(kind.clone()).or_default();
            e.0 += 1;
            if let Some(f) = first {
                e.1 += 1;
                firsts.push((*f).max(0));
            }
        }
        firsts.sort_unstable();
        let mut harvest_firsts: Vec<i64> =
            harvests.values().flatten().map(|f| (*f).max(0)).collect();
        harvest_firsts.sort_unstable();
        Ok(CanarySummary {
            harvests: harvests.len() as i64,
            harvests_reused: harvest_firsts.len() as i64,
            harvest_median_s: (!harvest_firsts.is_empty())
                .then(|| harvest_firsts[harvest_firsts.len() / 2]),
            served: rows.len() as i64,
            reused: firsts.len() as i64,
            median_s: (!firsts.is_empty()).then(|| firsts[firsts.len() / 2]),
            max_s: firsts.last().copied(),
            per_kind: per
                .into_iter()
                .map(|(kind, (served, reused))| KindStat {
                    kind,
                    served,
                    reused,
                })
                .collect(),
        })
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
                    decoy_site: Some("shop".into()),
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

    #[tokio::test]
    async fn summary_counts_first_use() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: None,
            hlc: 1,
        };
        let now = chrono::Utc::now();
        let at = |h: i64| {
            (now - chrono::Duration::hours(h))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        };
        apply(
            &mut conn,
            ctx,
            &req(
                "srv",
                &at(10),
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
                "env",
                &at(10),
                "198.51.100.1",
                "/.env",
                "[]",
                "decoy:dotenv",
                Some(1),
            ),
        )
        .await
        .unwrap();
        apply(
            &mut conn,
            ctx,
            &req(
                "u1",
                &at(8),
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
                "u2",
                &at(2),
                "198.51.100.3",
                "/x",
                &basic("deploy", &git_token("srv")),
                "not-found",
                None,
            ),
        )
        .await
        .unwrap();
        drop(conn);
        let sum = s
            .canary_summary(crate::store::stats::Range::H24)
            .await
            .unwrap();
        assert_eq!(sum.served, 8); // 1 git token + 7 in the .env
        assert_eq!(sum.reused, 1);
        assert_eq!(sum.median_s, Some(2 * 3600), "first use only");
        assert_eq!(
            sum.per_kind
                .iter()
                .find(|k| k.kind == "git-token")
                .map(|k| (k.served, k.reused)),
            Some((1, 1))
        );
        assert_eq!(sum.share_pct(), 13); // 1 of 8, rounded
    }

    #[tokio::test]
    async fn public_summary_ignores_canaries_of_pending_requests() {
        use crate::store::browse::Audience;
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        s.set_publish_delay(
            std::time::Duration::from_secs(300),
            std::time::Duration::ZERO,
        )
        .await
        .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: None,
            hlc: 1,
        };
        let at = |h: i64| {
            (chrono::Utc::now() - chrono::Duration::hours(h))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        };
        apply(
            &mut conn,
            ctx,
            &req(
                "srv",
                &at(3),
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
                &at(1),
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
        let r = crate::store::stats::Range::H24;
        let public = s.canary_summary_as(r, Audience::Public).await.unwrap();
        assert_eq!((public.served, public.harvests, public.reused), (0, 0, 0));
        let admin = s.canary_summary_as(r, Audience::Admin).await.unwrap();
        assert_eq!((admin.served, admin.harvests, admin.reused), (1, 1, 1));
        sqlx::query("UPDATE requests SET public_at = datetime('now', '-1 seconds') WHERE public_at IS NOT NULL")
            .execute(&s.pool)
            .await
            .unwrap();
        s.release_due().await.unwrap();
        let public = s.canary_summary_as(r, Audience::Public).await.unwrap();
        assert_eq!((public.served, public.harvests, public.reused), (1, 1, 1));
    }

    #[tokio::test]
    async fn summary_and_table_share_the_serve_time_window() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: None,
            hlc: 1,
        };
        let now = chrono::Utc::now();
        let at = |d: i64| {
            (now - chrono::Duration::days(d))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        };
        apply(
            &mut conn,
            ctx,
            &req(
                "srv",
                &at(40),
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
                &at(1),
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
        let d30 = crate::store::stats::Range::D30;
        assert_eq!(s.canary_summary(d30).await.unwrap().reused, 0);
        let f = ReuseFilter {
            range: d30,
            limit: 10,
            ..Default::default()
        };
        assert!(
            s.reuses(&f).await.unwrap().is_empty(),
            "harvested before the period"
        );
    }

    async fn derived(pool: &sqlx::SqlitePool) -> (i64, i64) {
        let n = |t: &'static str| async move {
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {t}")))
                .fetch_one(pool)
                .await
                .unwrap()
        };
        (n("canaries").await, n("request_tokens").await)
    }

    #[tokio::test]
    async fn hiding_a_request_drops_its_derived_rows() {
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
        assert!(derived(&s.pool).await.0 > 0 && derived(&s.pool).await.1 > 0);
        for uid in ["srv", "use"] {
            crate::store::data::unmaterialize(&mut conn, "request", uid)
                .await
                .unwrap();
        }
        drop(conn);
        assert_eq!(derived(&s.pool).await, (0, 0));
    }

    #[tokio::test]
    async fn pruning_drops_derived_rows_of_requests_and_light_rows() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: None,
            hlc: 1,
        };
        let old = chrono::Utc::now() - chrono::Duration::days(40);
        let ts = old.format("%Y-%m-%d %H:%M:%S").to_string();
        apply(
            &mut conn,
            ctx,
            &req(
                "srv",
                &ts,
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
                &ts,
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
            &Record::SkipBatch(SkipBatchRec {
                uid: "b1".into(),
                ip: "198.51.100.3".into(),
                dropped: 0,
                rows: vec![SkipRow {
                    ts_ms: old.timestamp_millis(),
                    method: "GET".into(),
                    path: "/.env".into(),
                    page_token: Some("t".into()),
                    host: None,
                    answer: Some("decoy:dotenv".into()),
                    decoy_v: Some(1),
                    decoy_site: Some("shop".into()),
                }],
                build: String::new(),
            }),
        )
        .await
        .unwrap();
        drop(conn);
        s.local().prune_older_than(30).await.unwrap();
        assert_eq!(derived(&s.pool).await, (0, 0));
    }

    #[tokio::test]
    async fn deleting_an_ip_drops_its_light_rows_canaries() {
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
            &Record::SkipBatch(SkipBatchRec {
                uid: "b1".into(),
                ip: "198.51.100.3".into(),
                dropped: 0,
                rows: vec![SkipRow {
                    ts_ms: 1_791_000_000_000,
                    method: "GET".into(),
                    path: "/.env".into(),
                    page_token: Some("t".into()),
                    host: None,
                    answer: Some("decoy:dotenv".into()),
                    decoy_v: Some(1),
                    decoy_site: Some("shop".into()),
                }],
                build: String::new(),
            }),
        )
        .await
        .unwrap();
        drop(conn);
        assert_eq!(derived(&s.pool).await.0, 7);
        let ip = s.ip_by_addr("198.51.100.3").await.unwrap().unwrap();
        assert!(s.local().delete_ip(ip.id).await.unwrap());
        assert_eq!(derived(&s.pool).await, (0, 0));
    }
}
