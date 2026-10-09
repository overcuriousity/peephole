//! The User-Agent of stored requests, kept in a column of its own so the
//! admin requests search can filter by it through an index. Derived from
//! `headers_json` on each node, so not replicated itself: a row gets it as
//! it is written, and rows stored before this build get it from
//! [`backfill`].

use anyhow::Result;

/// Version of the derivation a row was read with (0: not yet).
pub const UA_V: i64 = 1;

/// What a row without a User-Agent header stores (as Analytics names it).
pub const NONE: &str = "(none)";

/// The first `User-Agent` of a stored `headers_json` (`[[name, value], …]`),
/// name in any case, as Analytics' ranking reads it; [`NONE`] without one.
pub(crate) fn derive(headers_json: &str) -> String {
    let Ok(serde_json::Value::Array(headers)) = serde_json::from_str(headers_json) else {
        return NONE.into();
    };
    headers
        .iter()
        .find(|h| {
            h.get(0)
                .and_then(|n| n.as_str())
                .is_some_and(|n| n.eq_ignore_ascii_case("user-agent"))
        })
        .and_then(|h| h.get(1))
        .map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_else(|| NONE.into())
}

/// Rows read per write transaction by [`backfill`].
const BACKFILL_BATCH: i64 = 500;

/// The rows [`backfill`] has left, through `idx_requests_ua_pending`.
const PENDING: &str =
    "SELECT id, headers_json FROM requests WHERE ua_v = 0 AND id > ? ORDER BY id LIMIT ?";

fn write_pending<'c>(
    conn: &'c mut sqlx::SqliteConnection,
    r: &'c (i64, String),
    ua: String,
) -> super::backfill::WriteFut<'c> {
    Box::pin(async move {
        sqlx::query("UPDATE requests SET user_agent = ?, ua_v = ? WHERE id = ?")
            .bind(ua)
            .bind(UA_V)
            .bind(r.0)
            .execute(&mut *conn)
            .await?;
        Ok(())
    })
}

/// Derive the User-Agent of the rows stored before this build,
/// [`BACKFILL_BATCH`] at a time (see [`super::backfill`]). Returns how many
/// rows were read.
pub async fn backfill(pool: &sqlx::SqlitePool) -> Result<u64> {
    super::backfill::run(
        pool,
        super::backfill::Walk {
            pending: PENDING,
            below: None,
            batch: BACKFILL_BATCH,
            id: |r: &(i64, String)| r.0,
            derive: |r: &(i64, String)| derive(&r.1),
            write: write_pending,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::store::browse::{Audience, RequestFilter};
    use crate::store::requests::NewRequest;

    async fn store() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        Store::connect(&path).await.unwrap()
    }

    async fn insert(s: &Store, headers: &str) -> i64 {
        let ip = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: "/".into(),
            headers_json: headers.into(),
            labels_json: "[]".into(),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    async fn ua_of(s: &Store, id: i64) -> Option<String> {
        sqlx::query_scalar("SELECT user_agent FROM requests WHERE id = ?")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    #[test]
    fn derives_the_first_user_agent_in_any_case() {
        assert_eq!(
            derive(r#"[["Host","x"],["user-AGENT","curl/8"],["User-Agent","b"]]"#),
            "curl/8"
        );
        assert_eq!(derive(r#"[["Host","x"]]"#), NONE);
        assert_eq!(derive("not json"), NONE);
        assert_eq!(derive("[]"), NONE);
    }

    /// The same value Analytics' ranking shows (its `UA_SQL`), so a row
    /// links to exactly the requests it counts.
    #[tokio::test]
    async fn matches_the_analytics_expression() {
        let s = store().await;
        for h in [
            r#"[["Host","x"],["user-agent","zgrab/0.x"]]"#,
            r#"[["Host","x"]]"#,
            "garbage",
        ] {
            let id = insert(&s, h).await;
            let sql: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT {} FROM requests r WHERE r.id = ?",
                crate::store::analytics::UA_SQL
            )))
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
            assert_eq!(ua_of(&s, id).await.as_deref(), Some(sql.as_str()), "{h}");
        }
    }

    #[tokio::test]
    async fn backfill_derives_rows_stored_before() {
        let s = store().await;
        let id = insert(&s, r#"[["User-Agent","old/1"]]"#).await;
        sqlx::query("UPDATE requests SET user_agent = NULL, ua_v = 0")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(backfill(&s.pool).await.unwrap(), 1);
        assert_eq!(ua_of(&s, id).await.as_deref(), Some("old/1"));
        assert_eq!(backfill(&s.pool).await.unwrap(), 0, "nothing left");
    }

    #[tokio::test]
    async fn requests_are_found_by_user_agent_for_the_admin_only() {
        let s = store().await;
        insert(&s, r#"[["User-Agent","zgrab/0.x"]]"#).await;
        insert(&s, r#"[["User-Agent","curl/8"]]"#).await;
        insert(&s, "[]").await;
        let f = |ua: &str| RequestFilter {
            ua: Some(ua.into()),
            ..Default::default()
        };
        assert_eq!(s.count_requests(&f("zgrab/0.x")).await.unwrap().n, 1);
        assert_eq!(s.count_requests(&f(NONE)).await.unwrap().n, 1);
        let public = s
            .search_requests(&f("zgrab/0.x"), Audience::Public)
            .await
            .unwrap()
            .items
            .len();
        assert_eq!(public, 3, "admin-only filter");
        let plan: Vec<(i64, i64, i64, String)> =
            sqlx::query_as("EXPLAIN QUERY PLAN SELECT id FROM requests r WHERE r.user_agent = ?")
                .bind("zgrab/0.x")
                .fetch_all(&s.pool)
                .await
                .unwrap();
        assert!(
            plan.iter().any(|p| p.3.contains("idx_requests_ua")),
            "{plan:?}"
        );
    }
}
