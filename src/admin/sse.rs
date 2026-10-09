//! Live scan queue for the admin area. Snapshot on connect, then one event
//! per job transition from the broadcast notifier; a periodic snapshot and
//! a lag-triggered snapshot keep long-lived clients honest. Also the other
//! admin streams: the wall's request feed and [`watch`], which the Actions
//! card's probe and scan-job states use.
use crate::admin::{AdminState, auth::SessionUser};
use crate::events::QueueJob;
use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, KeepAliveStream, Sse},
};
use futures::stream::Stream;
use std::convert::Infallible;
use std::future::Future;
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

/// Whether the stream's session (if it had one) has ended: a logout or
/// expiry ends the stream instead of streaming admin data to a dead
/// session.
async fn session_ended(state: &AdminState, session: &Option<String>) -> bool {
    match session {
        Some(id) => !state.store.validate_session(id).await.unwrap_or(false),
        None => false,
    }
}

/// [`session_ended`], asked at most every [`SNAPSHOT_EVERY`].
struct SessionCheck {
    session: Option<String>,
    next: tokio::time::Instant,
}

impl SessionCheck {
    fn new(session: Option<String>) -> Self {
        Self {
            session,
            next: tokio::time::Instant::now() + SNAPSHOT_EVERY,
        }
    }

    async fn ended(&mut self, state: &AdminState) -> bool {
        if tokio::time::Instant::now() < self.next {
            return false;
        }
        self.next = tokio::time::Instant::now() + SNAPSHOT_EVERY;
        session_ended(state, &self.session).await
    }
}

/// The SSE response for an admin stream, kept alive through proxies.
fn sse<S>(stream: S) -> Sse<KeepAliveStream<S>>
where
    S: Stream<Item = Result<Event, Infallible>> + Send + 'static,
{
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}

/// How often [`watch`] looks again without a log change.
const WATCH_POLL: Duration = Duration::from_secs(3);

/// A stream of `event`s carrying what `load` returns, `(states, waiting)`:
/// the states whenever they change, looked at again on each cluster-log
/// change or every [`WATCH_POLL`]. The last event goes out once nothing is
/// `waiting`: the page reloads and opens no new stream.
pub fn watch<F, Fut>(
    state: Arc<AdminState>,
    session: Option<String>,
    event: &'static str,
    load: F,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>>
where
    F: Fn(Arc<AdminState>) -> Fut + Send + 'static,
    Fut: Future<Output = (String, bool)> + Send,
{
    struct St<F> {
        state: Arc<AdminState>,
        check: SessionCheck,
        changes: Option<tokio::sync::watch::Receiver<u64>>,
        load: F,
        last: Option<String>,
        done: bool,
    }
    let changes = state.recorder.node().map(|n| n.subscribe_changes());
    sse(futures::stream::unfold(
        St {
            state,
            check: SessionCheck::new(session),
            changes,
            load,
            last: None,
            done: false,
        },
        move |mut st| async move {
            if st.done {
                return None;
            }
            loop {
                if st.last.is_some() {
                    let changed = async {
                        match st.changes.as_mut() {
                            Some(rx) => {
                                if rx.changed().await.is_err() {
                                    std::future::pending::<()>().await;
                                }
                            }
                            None => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        _ = closing(&st.state) => return None,
                        _ = changed => {}
                        _ = tokio::time::sleep(WATCH_POLL) => {}
                    }
                }
                if st.check.ended(&st.state).await {
                    return None;
                }
                let (states, waiting) = (st.load)(st.state.clone()).await;
                st.done = !waiting;
                if st.last.as_deref() != Some(&states) || st.done {
                    st.last = Some(states.clone());
                    let ev = Event::default().event(event).data(states);
                    return Some((Ok(ev), st));
                }
            }
        },
    ))
}

pub async fn queue_stream(
    _u: SessionUser,
    jar: axum_extra::extract::CookieJar,
    State(state): State<Arc<AdminState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.notifier.subscribe();
    // The session id, so the long-lived stream can notice logout/expiry.
    let session = crate::admin::auth::session_token(&state, &jar);
    sse(async_stream(state, rx, session))
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
                    if session_ended(&st.state, &st.session).await {
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
    sse(recent_events(state, after, session))
}

fn recent_events(
    state: Arc<AdminState>,
    after: i64,
    session: Option<String>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    struct St {
        state: Arc<AdminState>,
        after: i64,
        check: SessionCheck,
    }
    futures::stream::unfold(
        St {
            state,
            after,
            check: SessionCheck::new(session),
        },
        |mut st| async move {
            loop {
                tokio::select! {
                    _ = closing(&st.state) => return None,
                    _ = tokio::time::sleep(RECENT_POLL) => {}
                }
                if st.check.ended(&st.state).await {
                    return None;
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

    /// A standalone admin on a fresh database in `dir`.
    async fn admin(dir: &tempfile::TempDir) -> (crate::config::Config, crate::store::Store) {
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
        (cfg, store)
    }

    #[tokio::test]
    async fn store_error_yields_comment_not_empty_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, store) = admin(&dir).await;
        store.pool.close().await; // every query now fails
        let state = Arc::new(AdminState::public_only(store, cfg));
        let rx = state.notifier.subscribe();
        let mut stream = Box::pin(async_stream(state, rx, None));
        let first = stream.next().await.unwrap().unwrap();
        let dbg = format!("{first:?}");
        assert!(!dbg.contains("event: snapshot"), "{dbg}");
        assert!(dbg.contains(": snapshot unavailable"), "{dbg}");
    }

    #[tokio::test]
    async fn watch_sends_changes_and_ends_once_nothing_waits() {
        use axum::response::IntoResponse;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let (cfg, store) = admin(&dir).await;
        let state = Arc::new(AdminState::public_only(store, cfg));
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        // Waiting, unchanged (no event), then settled.
        let sse = watch(state, None, "states", move |_| {
            let n = seen.fetch_add(1, Ordering::SeqCst);
            async move {
                match n {
                    0 | 1 => ("[1]".to_string(), true),
                    _ => ("[2]".to_string(), false),
                }
            }
        });
        let body = sse.into_response().into_body();
        let all = tokio::time::timeout(
            Duration::from_secs(20),
            axum::body::to_bytes(body, usize::MAX),
        )
        .await
        .expect("the stream ends")
        .unwrap();
        let all = String::from_utf8_lossy(&all);
        assert_eq!(all.matches("event: states").count(), 2, "{all}");
        assert!(
            all.contains("data: [1]") && all.contains("data: [2]"),
            "{all}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
