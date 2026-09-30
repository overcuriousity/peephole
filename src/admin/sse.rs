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

/// Matches the queue page's server-rendered rows, so a resync never shrinks it.
const SNAPSHOT_ROWS: i64 = 500;

fn snapshot_event(jobs: &[QueueJob]) -> Event {
    Event::default()
        .event("snapshot")
        .data(serde_json::to_string(jobs).unwrap_or_else(|_| "[]".into()))
}

/// A snapshot, or — when the store fails — a comment the client ignores, so a
/// transient DB error never renders as "Queue empty".
async fn snapshot_or_comment(state: &AdminState) -> Event {
    match state.store.queue_snapshot(SNAPSHOT_ROWS).await {
        Ok(jobs) => snapshot_event(&jobs),
        Err(e) => {
            tracing::warn!(error = ?e, "queue snapshot unavailable");
            Event::default().comment("snapshot unavailable")
        }
    }
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
                return Some((Ok(snapshot_or_comment(&st.state).await), st));
            }
            let ev = tokio::select! {
                msg = st.rx.recv() => match msg {
                    Ok(job) => Event::default()
                        .event("job")
                        .data(serde_json::to_string(&job).unwrap_or_default()),
                    Err(RecvError::Lagged(_)) => snapshot_or_comment(&st.state).await,
                    Err(RecvError::Closed) => return None,
                },
                _ = tokio::time::sleep(Duration::from_secs(30)) => snapshot_or_comment(&st.state).await,
            };
            Some((Ok(ev), st))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test]
    async fn store_error_yields_comment_not_empty_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_text = format!(
            r#"
trap_listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"
database_path = "{d}/t.db"
data_dir = "{d}"
rules_dir = "rules"
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
[maxmind]
account_id = "1"
license_key = "k"
"#,
            d = dir.path().display()
        );
        let cfg_path = dir.path().join("c.toml");
        std::fs::write(&cfg_path, cfg_text).unwrap();
        let cfg = crate::config::Config::load(&cfg_path).unwrap();
        let store = crate::store::Store::connect(&cfg.database_path)
            .await
            .unwrap();
        store.pool.close().await; // every query now fails
        let state = Arc::new(AdminState::public_only(store, cfg));
        let rx = state.notifier.subscribe();
        let mut stream = Box::pin(async_stream(state, rx));
        let first = stream.next().await.unwrap().unwrap();
        let dbg = format!("{first:?}");
        assert!(!dbg.contains("event: snapshot"), "{dbg}");
        assert!(dbg.contains(": snapshot unavailable"), "{dbg}");
    }
}
