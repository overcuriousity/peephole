//! The walk the derived columns' backfills share (`hostkeys`, `facts`,
//! `ja4h`, `useragent`): the rows a derivation has left, by id, a batch at
//! a time. A batch is read and derived outside any transaction (a scan's
//! XML takes a decompression and a parse), then written in one short
//! write transaction with a pause after it, so the trap's and
//! replication's writes get the lock in between.
use anyhow::Result;
use sqlx::SqliteConnection;
use sqlx::sqlite::SqliteRow;

/// Pause between two batches' write transactions.
const PAUSE: std::time::Duration = std::time::Duration::from_millis(25);

/// What [`Walk::write`] returns.
pub(crate) type WriteFut<'c> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'c>>;

/// One backfill: which rows, how to derive them, how to store the result.
pub(crate) struct Walk<R, D> {
    /// The pending rows after an id (`id > ?`), by id, `LIMIT ?`; with
    /// [`Walk::below`], a first `?` takes it.
    pub pending: &'static str,
    pub below: Option<i64>,
    /// Rows per batch.
    pub batch: i64,
    pub id: fn(&R) -> i64,
    /// Runs outside the transaction.
    pub derive: fn(&R) -> D,
    /// Runs inside it; must store nothing for a row deleted since it was
    /// read.
    pub write: for<'c> fn(&'c mut SqliteConnection, &'c R, D) -> WriteFut<'c>,
}

/// Walk the pending rows once by id. Returns how many were read.
pub(crate) async fn run<R, D>(pool: &sqlx::SqlitePool, w: Walk<R, D>) -> Result<u64>
where
    R: for<'r> sqlx::FromRow<'r, SqliteRow> + Send + Unpin,
{
    let (mut done, mut after) = (0, 0i64);
    loop {
        let mut q = sqlx::query_as::<_, R>(w.pending);
        if let Some(b) = w.below {
            q = q.bind(b);
        }
        let rows = q.bind(after).bind(w.batch).fetch_all(pool).await?;
        let Some(last) = rows.last() else {
            return Ok(done);
        };
        after = (w.id)(last);
        let derived: Vec<D> = rows.iter().map(w.derive).collect();
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        for (r, d) in rows.iter().zip(derived) {
            (w.write)(&mut tx, r, d).await?;
        }
        tx.commit().await?;
        done += rows.len() as u64;
        tokio::time::sleep(PAUSE).await;
    }
}
