//! The command a request sent a dropped webshell, kept in a column of its
//! own so the admin requests search, pivots and campaign views can find it
//! through an index. Derived from `query`/`body` on each node, so not
//! replicated itself: a row gets it as it is written, and rows stored
//! before this build get it from [`backfill`].

use anyhow::Result;

/// Version of the derivation a row was read with (0: not yet).
pub const CMD_V: i64 = 1;

/// The command of a stored request: the webshell's command
/// ([`crate::model::webshell::extract_command`], at most
/// [`crate::model::webshell::MAX_CMD`] bytes) trimmed, for a row the trap
/// answered as a webshell; `None` for any other row or without a command.
pub(crate) fn derive(
    answer: Option<&str>,
    query: Option<&str>,
    body: Option<&[u8]>,
) -> Option<String> {
    if answer != Some("webshell") {
        return None;
    }
    let cmd = crate::model::webshell::extract_command(query, body)?;
    let cmd = cmd.trim();
    (!cmd.is_empty()).then(|| cmd.to_string())
}

/// Rows read per write transaction by [`backfill`].
const BACKFILL_BATCH: i64 = 500;

type Row = (i64, Option<String>, Option<Vec<u8>>);

/// The webshell rows [`backfill`] has left, through
/// `idx_requests_cmd_pending`.
const PENDING: &str = "SELECT id, query, body FROM requests
     WHERE cmd_v = 0 AND answer = 'webshell' AND id > ? ORDER BY id LIMIT ?";

fn write_pending<'c>(
    conn: &'c mut sqlx::SqliteConnection,
    r: &'c Row,
    cmd: Option<String>,
) -> super::backfill::WriteFut<'c> {
    Box::pin(async move {
        sqlx::query("UPDATE requests SET cmd = ?, cmd_v = ? WHERE id = ?")
            .bind(cmd)
            .bind(CMD_V)
            .bind(r.0)
            .execute(&mut *conn)
            .await?;
        Ok(())
    })
}

/// Derive the command of the webshell rows stored before this build,
/// [`BACKFILL_BATCH`] at a time (see [`super::backfill`]). Returns how many
/// rows were read.
pub async fn backfill(pool: &sqlx::SqlitePool) -> Result<u64> {
    super::backfill::run(
        pool,
        super::backfill::Walk {
            pending: PENDING,
            below: None,
            batch: BACKFILL_BATCH,
            id: |r: &Row| r.0,
            derive: |r: &Row| derive(Some("webshell"), r.1.as_deref(), r.2.as_deref()),
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

    async fn insert(s: &Store, answer: &str, query: &str) -> i64 {
        let ip = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: "/shell.php".into(),
            query: Some(query.into()),
            answer: Some(answer.into()),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    async fn cmd_of(s: &Store, id: i64) -> (Option<String>, i64) {
        sqlx::query_as("SELECT cmd, cmd_v FROM requests WHERE id = ?")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    #[test]
    fn derives_the_trimmed_command_of_webshell_rows_only() {
        let w = Some("webshell");
        assert_eq!(
            derive(w, Some("cmd=ls+-la"), None).as_deref(),
            Some("ls -la")
        );
        assert_eq!(derive(w, None, Some(b"c=+id+")).as_deref(), Some("id"));
        assert_eq!(derive(w, Some("cmd=+"), None), None, "blank");
        assert_eq!(derive(w, Some("q=1"), None), None);
        assert_eq!(derive(Some("not-found"), Some("cmd=id"), None), None);
        assert_eq!(derive(None, Some("cmd=id"), None), None);
    }

    #[tokio::test]
    async fn is_set_at_insert() {
        let s = store().await;
        let id = insert(&s, "webshell", "cmd=whoami").await;
        assert_eq!(cmd_of(&s, id).await, (Some("whoami".into()), CMD_V));
        let id = insert(&s, "not-found", "cmd=whoami").await;
        assert_eq!(cmd_of(&s, id).await, (None, CMD_V));
    }

    #[tokio::test]
    async fn backfill_derives_rows_stored_before() {
        let s = store().await;
        let ls = insert(&s, "webshell", "cmd=ls+-la").await;
        let long = insert(&s, "webshell", &format!("cmd={}", "é".repeat(150))).await;
        let other = insert(&s, "not-found", "cmd=id").await;
        sqlx::query("UPDATE requests SET cmd = NULL, cmd_v = 0")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(backfill(&s.pool).await.unwrap(), 2, "webshell rows only");
        assert_eq!(cmd_of(&s, ls).await, (Some("ls -la".into()), CMD_V));
        let (long, _) = cmd_of(&s, long).await;
        let long = long.unwrap();
        assert!(
            long.len() <= 256 && long.chars().all(|c| c == 'é'),
            "{}",
            long.len()
        );
        assert_eq!(cmd_of(&s, other).await, (None, 0));
        assert_eq!(backfill(&s.pool).await.unwrap(), 0, "nothing left");
    }

    #[tokio::test]
    async fn requests_are_found_by_command_for_the_admin_only() {
        let s = store().await;
        insert(&s, "webshell", "cmd=ls+-la").await;
        insert(&s, "webshell", "cmd=id").await;
        insert(&s, "not-found", "cmd=ls+-la").await;
        let f = RequestFilter {
            cmd: Some("ls -la".into()),
            ..Default::default()
        };
        assert_eq!(s.count_requests(&f).await.unwrap().n, 1);
        let public = s
            .search_requests(&f, Audience::Public)
            .await
            .unwrap()
            .items
            .len();
        assert_eq!(public, 3, "admin-only filter");
        let plan: Vec<(i64, i64, i64, String)> =
            sqlx::query_as("EXPLAIN QUERY PLAN SELECT id FROM requests r WHERE r.cmd = ?")
                .bind("ls -la")
                .fetch_all(&s.pool)
                .await
                .unwrap();
        assert!(
            plan.iter()
                .any(|p| p.3.contains("INDEX idx_requests_cmd (")),
            "{plan:?}"
        );
    }
}
