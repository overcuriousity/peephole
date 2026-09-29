use crate::admin::AdminState;
use axum::{extract::State, response::sse::{Event, Sse}};
use futures::stream::{self, Stream};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

pub async fn queue_stream(
    State(state): State<Arc<AdminState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = stream::unfold((state, String::new()), |(state, last)| async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let rows: Vec<(i64, i64, String, Option<String>)> = sqlx::query_as(
            "SELECT j.id, j.level, j.status, i.ip FROM scan_jobs j JOIN ips i ON j.ip_id = i.id
             ORDER BY j.queued_at DESC LIMIT 50",
        ).fetch_all(&state.store.pool).await.unwrap_or_default();
        let snapshot = serde_json::to_string(&rows.iter().map(|(id, level, status, ip)|
            serde_json::json!({"id": id, "level": level, "status": status, "ip": ip})
        ).collect::<Vec<_>>()).unwrap_or_default();
        if snapshot == last {
            // No change: emit a comment heartbeat to keep proxies alive.
            Some((Ok(Event::default().comment("tick")), (state, last)))
        } else {
            let ev = Event::default().event("queue").data(snapshot.clone());
            Some((Ok(ev), (state, snapshot)))
        }
    });
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}
