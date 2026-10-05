//! JA4H of stored requests (`trap::ja4h`), derived from `raw_head` on each
//! node, so not replicated itself: a row gets it as it is written, and rows
//! stored before this build get it from [`backfill`].

use anyhow::Result;

/// Version of the JA4H derivation; rows derived by an older one are derived
/// again by [`backfill`].
pub const JA4H_V: i64 = 1;

/// Rows read per write transaction by [`backfill`].
const BACKFILL_BATCH: i64 = 500;
/// Pause between [`backfill`]'s transactions, so the trap's and
/// replication's writes get the lock in between.
const BACKFILL_PAUSE: std::time::Duration = std::time::Duration::from_millis(25);

/// Derive the JA4H of the rows stored before this build (or by an older
/// derivation), a batch at a time, each batch its own short write
/// transaction with a pause after it. Walks the table once by id. Returns
/// how many rows were read.
pub async fn backfill(pool: &sqlx::SqlitePool) -> Result<u64> {
    let (mut done, mut after) = (0, 0i64);
    loop {
        let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT id, raw_head FROM requests
             WHERE raw_head IS NOT NULL AND ja4h_v < ? AND id > ? ORDER BY id LIMIT ?",
        )
        .bind(JA4H_V)
        .bind(after)
        .bind(BACKFILL_BATCH)
        .fetch_all(pool)
        .await?;
        let Some(&(last, _)) = rows.last() else {
            return Ok(done);
        };
        after = last;
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        for (id, head) in &rows {
            sqlx::query("UPDATE requests SET ja4h = ?, ja4h_v = ? WHERE id = ?")
                .bind(crate::trap::ja4h::ja4h(head))
                .bind(JA4H_V)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        done += rows.len() as u64;
        tokio::time::sleep(BACKFILL_PAUSE).await;
    }
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
        let ip = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: "/.env".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            raw_head: raw_head.map(<[u8]>::to_vec),
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
}
