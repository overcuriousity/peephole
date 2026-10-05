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

/// Matches the Scans page's live card, so a resync never shrinks it.
const SNAPSHOT_ROWS: i64 = crate::admin::scans::LIVE_ROWS;

/// The live card's rows and how many jobs are active in all (more than the
/// rows when over [`SNAPSHOT_ROWS`]).
fn snapshot_event(jobs: &[QueueJob], active: i64) -> Event {
    Event::default().event("snapshot").data(
        serde_json::to_string(&serde_json::json!({ "jobs": jobs, "active": active }))
            .unwrap_or_else(|_| r#"{"jobs":[],"active":0}"#.into()),
    )
}

/// A snapshot, or — when the store fails — a comment the client ignores, so a
/// transient DB error never renders as "Queue empty".
async fn snapshot_or_comment(state: &AdminState) -> Event {
    let snap = async {
        let jobs = state.store.active_jobs(SNAPSHOT_ROWS).await?;
        let q = state.store.queue_summary(&state.recorder).await?;
        anyhow::Ok((jobs, q.queued + q.running))
    };
    match snap.await {
        Ok((jobs, active)) => snapshot_event(&jobs, active),
        Err(e) => {
            tracing::warn!(error = ?e, "queue snapshot unavailable");
            Event::default().comment("snapshot unavailable")
        }
    }
}

/// Resolves once the web role is told to stop (never without a signal).
async fn closing(state: &AdminState) {
    match state.closing.clone() {
        Some(mut rx) => {
            let _ = rx.wait_for(|v| *v).await;
        }
        None => std::future::pending().await,
    }
}

/// Forced-resync / session-recheck cadence.
const SNAPSHOT_EVERY: Duration = Duration::from_secs(30);

pub async fn queue_stream(
    _u: SessionUser,
    jar: axum_extra::extract::CookieJar,
    State(state): State<Arc<AdminState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.notifier.subscribe();
    // The session id, so the long-lived stream can notice logout/expiry.
    let session = crate::admin::auth::session_token(&state, &jar);
    Sse::new(async_stream(state, rx, session)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}

fn async_stream(
    state: Arc<AdminState>,
    rx: tokio::sync::broadcast::Receiver<QueueJob>,
    session: Option<String>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    struct St {
        state: Arc<AdminState>,
        rx: tokio::sync::broadcast::Receiver<QueueJob>,
        session: Option<String>,
        first: bool,
        // Next forced snapshot, independent of job traffic (a steady stream of
        // jobs must not keep resetting it, or a client never resyncs).
        next_snapshot: tokio::time::Instant,
    }
    futures::stream::unfold(
        St {
            state,
            rx,
            session,
            first: true,
            next_snapshot: tokio::time::Instant::now() + SNAPSHOT_EVERY,
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
                // The web role is being switched off.
                _ = closing(&st.state) => return None,
                _ = tokio::time::sleep_until(st.next_snapshot) => {
                    st.next_snapshot = tokio::time::Instant::now() + SNAPSHOT_EVERY;
                    // Re-check the session so a logout or expiry ends the stream
                    // instead of streaming queue data to a dead session.
                    if let Some(id) = &st.session
                        && !st.state.store.validate_session(id).await.unwrap_or(false)
                    {
                        return None;
                    }
                    snapshot_or_comment(&st.state).await
                }
            };
            Some((Ok(ev), st))
        },
    )
}

/// How often the live request feed looks for new rows.
const RECENT_POLL: Duration = Duration::from_secs(3);

/// Rows per live batch: the wall's table keeps as many.
const RECENT_BATCH: i64 = 50;

#[derive(serde::Deserialize)]
pub struct RecentQuery {
    /// The newest request id the page already shows.
    #[serde(default, deserialize_with = "crate::store::browse::lenient_i64")]
    after: Option<i64>,
}

/// Live request feed for the wall's admin-only "Recent activity": a batch
/// of the requests recorded since the last one, every few seconds. Polls
/// the database rather than the trap, so rows replicated from cluster
/// members show up as well.
pub async fn recent_stream(
    _u: SessionUser,
    jar: axum_extra::extract::CookieJar,
    State(state): State<Arc<AdminState>>,
    axum::extract::Query(q): axum::extract::Query<RecentQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let session = crate::admin::auth::session_token(&state, &jar);
    let after = match q.after {
        Some(a) => a,
        None => state.store.max_request_id().await.unwrap_or(0),
    };
    Sse::new(recent_events(state, after, session)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}

fn recent_events(
    state: Arc<AdminState>,
    after: i64,
    session: Option<String>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    struct St {
        state: Arc<AdminState>,
        after: i64,
        session: Option<String>,
        next_check: tokio::time::Instant,
    }
    futures::stream::unfold(
        St {
            state,
            after,
            session,
            next_check: tokio::time::Instant::now() + SNAPSHOT_EVERY,
        },
        |mut st| async move {
            loop {
                tokio::select! {
                    _ = closing(&st.state) => return None,
                    _ = tokio::time::sleep(RECENT_POLL) => {}
                }
                if tokio::time::Instant::now() >= st.next_check {
                    st.next_check = tokio::time::Instant::now() + SNAPSHOT_EVERY;
                    // A logout or expiry ends the stream, as for the queue.
                    if let Some(id) = &st.session
                        && !st.state.store.validate_session(id).await.unwrap_or(false)
                    {
                        return None;
                    }
                }
                match st.state.store.requests_after(st.after, RECENT_BATCH).await {
                    Ok(rows) if !rows.is_empty() => {
                        st.after = rows.last().map(|r| r.id).unwrap_or(st.after);
                        let ev = Event::default()
                            .event("requests")
                            .data(serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into()));
                        return Some((Ok(ev), st));
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = ?e, "live request feed unavailable"),
                }
            }
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
        let mut stream = Box::pin(async_stream(state, rx, None));
        let first = stream.next().await.unwrap().unwrap();
        let dbg = format!("{first:?}");
        assert!(!dbg.contains("event: snapshot"), "{dbg}");
        assert!(dbg.contains(": snapshot unavailable"), "{dbg}");
    }
}
