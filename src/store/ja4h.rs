//! JA4H of stored requests (`trap::ja4h`), derived from `raw_head` on each
//! node, so not replicated itself: a row gets it as it is written, and rows
//! stored before this build get it from [`backfill`].

use anyhow::Result;

/// Version of the JA4H derivation a row was read with (0: not yet). A
/// change to the derivation bumps it, and its migration sets `ja4h_v = 0`
/// on the rows to derive again (`WHERE raw_head IS NOT NULL`: only those
/// can have one).
pub const JA4H_V: i64 = 1;

/// The JA4H of a request as stored. None for plain HTTP from a trusted
/// proxy: the head is the proxy's request (nginx sends HTTP/1.1 and its own
/// Host and X-Forwarded-For), not the client's. HTTPS through one is the
/// client's own bytes behind a PROXY header.
pub(crate) fn derive(
    raw_head: Option<&[u8]>,
    transport: Option<&str>,
    via_proxy: Option<bool>,
) -> Option<String> {
    if transport == Some("http") && via_proxy == Some(true) {
        return None;
    }
    raw_head.and_then(crate::trap::ja4h::ja4h)
}

/// Rows read per write transaction by [`backfill`] (heads are up to 64 KiB).
const BACKFILL_BATCH: i64 = 100;

/// The rows [`backfill`] has left, through `idx_requests_ja4h_pending`
/// (which holds only those).
const PENDING: &str = "SELECT id, raw_head, transport, via_proxy FROM requests
     WHERE raw_head IS NOT NULL AND ja4h_v = 0 AND id > ? ORDER BY id LIMIT ?";

/// A pending row: id, head, transport, via proxy.
type Pending = (i64, Vec<u8>, Option<String>, Option<bool>);

fn write_pending<'c>(
    conn: &'c mut sqlx::SqliteConnection,
    r: &'c Pending,
    ja4h: Option<String>,
) -> super::backfill::WriteFut<'c> {
    Box::pin(async move {
        sqlx::query("UPDATE requests SET ja4h = ?, ja4h_v = ? WHERE id = ?")
            .bind(ja4h)
            .bind(JA4H_V)
            .bind(r.0)
            .execute(&mut *conn)
            .await?;
        Ok(())
    })
}

/// Derive the JA4H of the rows stored before this build (or marked for a
/// new derivation), [`BACKFILL_BATCH`] at a time (see
/// [`super::backfill`]). Returns how many rows were read.
pub async fn backfill(pool: &sqlx::SqlitePool) -> Result<u64> {
    super::backfill::run(
        pool,
        super::backfill::Walk {
            pending: PENDING,
            below: None,
            batch: BACKFILL_BATCH,
            id: |r: &Pending| r.0,
            derive: |(_, head, transport, via_proxy): &Pending| {
                derive(Some(head), transport.as_deref(), *via_proxy)
            },
            write: write_pending,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::store::requests::NewRequest;

    const HEAD: &[u8] = b"GET /.env HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n";

    async fn store() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        Store::connect(&path).await.unwrap()
    }

    async fn insert(s: &Store, raw_head: Option<&[u8]>) -> i64 {
        insert_via(s, raw_head, "http", false).await
    }

    async fn insert_via(s: &Store, raw_head: Option<&[u8]>, transport: &str, proxy: bool) -> i64 {
        let ip = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: "/.env".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            raw_head: raw_head.map(<[u8]>::to_vec),
            transport: Some(transport.into()),
            via_proxy: Some(proxy),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    async fn ja4h_of(s: &Store, id: i64) -> Option<String> {
        s.request_by_id(id).await.unwrap().unwrap().ja4h
    }

    #[tokio::test]
    async fn a_request_gets_its_ja4h_as_it_is_written() {
        let s = store().await;
        let with = insert(&s, Some(HEAD)).await;
        let without = insert(&s, None).await;
        assert_eq!(ja4h_of(&s, with).await, crate::trap::ja4h::ja4h(HEAD));
        assert!(ja4h_of(&s, with).await.is_some());
        assert_eq!(ja4h_of(&s, without).await, None);
    }

    #[tokio::test]
    async fn backfill_derives_rows_stored_before() {
        let s = store().await;
        let id = insert(&s, Some(HEAD)).await;
        insert(&s, Some(b"\x16\x03\x01junk\r\n\r\n")).await;
        insert(&s, None).await;
        sqlx::query("UPDATE requests SET ja4h = NULL, ja4h_v = 0")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(backfill(&s.pool).await.unwrap(), 2);
        assert_eq!(ja4h_of(&s, id).await, crate::trap::ja4h::ja4h(HEAD));
        assert_eq!(backfill(&s.pool).await.unwrap(), 0, "each row once");
    }

    /// Plain HTTP from a trusted proxy is the proxy's request (nginx sends
    /// HTTP/1.1 and its own Host and X-Forwarded-For), not the client's.
    /// HTTPS through one is the client's bytes behind a PROXY header.
    #[tokio::test]
    async fn a_head_an_http_proxy_rewrote_has_none() {
        let s = store().await;
        let proxied = insert_via(&s, Some(HEAD), "http", true).await;
        let tls = insert_via(&s, Some(HEAD), "https", true).await;
        let direct = insert_via(&s, Some(HEAD), "http", false).await;
        assert_eq!(ja4h_of(&s, proxied).await, None);
        assert!(ja4h_of(&s, tls).await.is_some());
        assert!(ja4h_of(&s, direct).await.is_some());
        sqlx::query("UPDATE requests SET ja4h = NULL, ja4h_v = 0")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(backfill(&s.pool).await.unwrap(), 3);
        assert_eq!(ja4h_of(&s, proxied).await, None, "nor from the backfill");
        assert!(ja4h_of(&s, tls).await.is_some());
    }

    /// The backfill finds what is left through an index of only those
    /// rows, not by walking the table at every start.
    #[tokio::test]
    async fn the_backfill_reads_only_pending_rows() {
        let s = store().await;
        let plan: Vec<(i64, i64, i64, String)> =
            sqlx::query_as(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {PENDING}")))
                .bind(0)
                .bind(BACKFILL_BATCH)
                .fetch_all(&s.pool)
                .await
                .unwrap();
        assert!(
            plan.iter()
                .any(|p| p.3.contains("idx_requests_ja4h_pending")),
            "{plan:?}"
        );
    }
}
