//! Live scan queue for the admin area. Snapshot on connect, then one event
//! per job transition from the broadcast notifier; a periodic snapshot and
//! a lag-triggered snapshot keep long-lived clients honest.
use crate::admin::{AdminState, auth::SessionUser};
use crate::events::QueueJob;
use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

const SNAPSHOT_ROWS: i64 = 100;

fn snapshot_event(jobs: &[QueueJob]) -> Event {
    Event::default()
        .event("snapshot")
        .data(serde_json::to_string(jobs).unwrap_or_else(|_| "[]".into()))
}

pub async fn queue_stream(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.notifier.subscribe();
    Sse::new(async_stream(state, rx)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}

fn async_stream(
    state: Arc<AdminState>,
    rx: tokio::sync::broadcast::Receiver<QueueJob>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    struct St {
        state: Arc<AdminState>,
        rx: tokio::sync::broadcast::Receiver<QueueJob>,
        first: bool,
    }
    futures::stream::unfold(
        St {
            state,
            rx,
            first: true,
        },
        |mut st| async move {
            if st.first {
                st.first = false;
                let jobs = st
                    .state
                    .store
                    .queue_snapshot(SNAPSHOT_ROWS)
                    .await
                    .unwrap_or_default();
                return Some((Ok(snapshot_event(&jobs)), st));
            }
            let ev = tokio::select! {
                msg = st.rx.recv() => match msg {
                    Ok(job) => Event::default()
                        .event("job")
                        .data(serde_json::to_string(&job).unwrap_or_default()),
                    Err(RecvError::Lagged(_)) => {
                        let jobs = st.state.store.queue_snapshot(SNAPSHOT_ROWS).await.unwrap_or_default();
                        snapshot_event(&jobs)
                    }
                    Err(RecvError::Closed) => return None,
                },
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    let jobs = st.state.store.queue_snapshot(SNAPSHOT_ROWS).await.unwrap_or_default();
                    snapshot_event(&jobs)
                }
            };
            Some((Ok(ev), st))
        },
    )
}
