//! Legacy MCP HTTP+SSE: `GET /sse` holds a stream whose first event names
//! the endpoint to POST to; the answers to those POSTs go down the stream.
//! Streams live on this node only, in a pool of their own (as the
//! tarpit's), and end after the hold cap or two idle minutes.
use crate::trap::TrapConfig;
use axum::body::Bytes;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::Instant;

pub const PING_EVERY: Duration = Duration::from_secs(15);
pub const IDLE: Duration = Duration::from_secs(120);
const QUEUE: usize = 16;

pub struct SseHub {
    pool: Arc<Semaphore>,
    per_source: usize,
    hold: Duration,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    sessions: HashMap<String, mpsc::Sender<String>>,
    sources: HashMap<IpAddr, usize>,
}

/// Gives a stream's place back when the stream is dropped, and says how
/// long it held the client.
struct Guard {
    hub: Arc<SseHub>,
    _permit: OwnedSemaphorePermit,
    ip: IpAddr,
    session: String,
    start: Instant,
    done: Option<oneshot::Sender<u64>>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let mut g = self.hub.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.sessions.remove(&self.session);
        if let Some(n) = g.sources.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.sources.remove(&self.ip);
            }
        }
        if let Some(tx) = self.done.take() {
            let _ = tx.send(u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX));
        }
    }
}

struct Held {
    _guard: Guard,
    rx: mpsc::Receiver<String>,
    first: Option<String>,
    end: Instant,
    idle_until: Instant,
    ping: tokio::time::Interval,
}

impl SseHub {
    pub fn new(cfg: &TrapConfig) -> Self {
        Self {
            pool: Arc::new(Semaphore::new(cfg.mcp_sse_pool)),
            per_source: cfg.mcp_sse_per_source,
            hold: Duration::from_secs(cfg.mcp_sse_hold_secs),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The longest a stream lasts.
    pub fn hold(&self) -> Duration {
        self.hold
    }

    /// Streams open now.
    pub fn open_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .len()
    }

    /// A stream for `session` from `ip`, opened with `first`, and where the
    /// time it held the client arrives once it ends. None: the pool or the
    /// source's share is full.
    #[allow(clippy::type_complexity)]
    pub fn open(
        self: &Arc<Self>,
        ip: IpAddr,
        session: String,
        first: String,
    ) -> Option<(
        impl futures::Stream<Item = Result<Bytes, Infallible>> + Send + 'static,
        oneshot::Receiver<u64>,
    )> {
        let key = crate::net::source_key(ip);
        let permit = self.pool.clone().try_acquire_owned().ok()?;
        let (tx, rx) = mpsc::channel(QUEUE);
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if g.sessions.contains_key(&session)
                || g.sources.get(&key).copied().unwrap_or(0) >= self.per_source
            {
                return None;
            }
            *g.sources.entry(key).or_default() += 1;
            g.sessions.insert(session.clone(), tx);
        }
        let (done, held) = oneshot::channel();
        let start = Instant::now();
        let mut ping = tokio::time::interval_at(start + PING_EVERY, PING_EVERY);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let state = Held {
            _guard: Guard {
                hub: self.clone(),
                _permit: permit,
                ip: key,
                session,
                start,
                done: Some(done),
            },
            rx,
            first: Some(first),
            end: start + self.hold,
            idle_until: start + IDLE,
            ping,
        };
        let stream = futures::stream::unfold(state, |mut h| async move {
            if let Some(f) = h.first.take() {
                return Some((Ok(Bytes::from(f)), h));
            }
            let deadline = h.end.min(h.idle_until);
            // Biased: a message first, then the end, then the ping, so a
            // ping due at the very deadline does not outlive it.
            tokio::select! {
                biased;
                m = h.rx.recv() => {
                    let f = m?;
                    h.idle_until = Instant::now() + IDLE;
                    Some((Ok(Bytes::from(f)), h))
                }
                _ = tokio::time::sleep_until(deadline) => None,
                _ = h.ping.tick() => Some((Ok(Bytes::from_static(b": ping\n\n")), h)),
            }
        });
        Some((stream, held))
    }

    /// Push `frame` down the stream of `session` (None: only ask whether
    /// it is open).
    pub fn deliver(&self, session: &str, frame: Option<String>) -> Delivery {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(tx) = g.sessions.get(session) else {
            return Delivery::NoSession;
        };
        match frame {
            None if tx.is_closed() => Delivery::NoSession,
            None => Delivery::Sent,
            Some(f) => match tx.try_send(f) {
                Ok(()) => Delivery::Sent,
                Err(mpsc::error::TrySendError::Full(_)) => Delivery::Full,
                Err(mpsc::error::TrySendError::Closed(_)) => Delivery::NoSession,
            },
        }
    }
}

/// What became of a frame pushed to a legacy stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    Sent,
    /// No such stream on this node.
    NoSession,
    /// The stream exists but its queue is full: the frame was dropped.
    Full,
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn hub(pool: usize, per: usize, hold: u64) -> Arc<SseHub> {
        Arc::new(SseHub::new(&crate::trap::TrapConfig {
            mcp_sse_pool: pool,
            mcp_sse_per_source: per,
            mcp_sse_hold_secs: hold,
            ..Default::default()
        }))
    }
    const IP: &str = "198.51.100.7";

    #[tokio::test(start_paused = true)]
    async fn first_event_then_pushed_messages_then_pings() {
        let h = hub(4, 2, 300);
        let (s, _held) = h
            .open(
                IP.parse().unwrap(),
                "sid".into(),
                "event: endpoint\n\n".into(),
            )
            .unwrap();
        tokio::pin!(s);
        assert_eq!(s.next().await.unwrap().unwrap(), "event: endpoint\n\n");
        assert_eq!(
            h.deliver("sid", Some("event: message\ndata: {}\n\n".into())),
            Delivery::Sent
        );
        assert_eq!(
            s.next().await.unwrap().unwrap(),
            "event: message\ndata: {}\n\n"
        );
        assert_eq!(
            h.deliver("sid", None),
            Delivery::Sent,
            "open: a notification needs no frame"
        );
        assert_eq!(h.deliver("other", Some("x".into())), Delivery::NoSession);
        assert_eq!(s.next().await.unwrap().unwrap(), ": ping\n\n");
    }

    #[tokio::test(start_paused = true)]
    async fn ends_idle_or_at_the_hold_and_reports_the_time_held() {
        let h = hub(4, 2, 300);
        let (s, held) = h
            .open(IP.parse().unwrap(), "sid".into(), "e\n\n".into())
            .unwrap();
        let n = s.count().await; // runs to the idle end (120 s), pinging every 15 s
        assert_eq!(n, 1 + 7);
        assert_eq!(held.await.unwrap(), 120_000);
        assert_eq!(h.open_count(), 0);
        assert_eq!(
            h.deliver("sid", None),
            Delivery::NoSession,
            "gone once ended"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn pool_and_per_source_caps() {
        let h = hub(2, 1, 300);
        let a = h.open(IP.parse().unwrap(), "a".into(), String::new());
        assert!(a.is_some());
        assert!(
            h.open(IP.parse().unwrap(), "b".into(), String::new())
                .is_none(),
            "per source"
        );
        let c = h.open("203.0.113.9".parse().unwrap(), "c".into(), String::new());
        assert!(c.is_some());
        assert!(
            h.open("192.0.2.1".parse().unwrap(), "d".into(), String::new())
                .is_none(),
            "pool"
        );
        drop(a);
        assert!(
            h.open("192.0.2.1".parse().unwrap(), "d".into(), String::new())
                .is_some(),
            "freed on drop"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_queue_is_told_apart_from_no_session() {
        let h = hub(4, 2, 300);
        let _s = h
            .open(IP.parse().unwrap(), "sid".into(), String::new())
            .unwrap();
        for _ in 0..QUEUE {
            assert_eq!(h.deliver("sid", Some("x".into())), Delivery::Sent);
        }
        assert_eq!(h.deliver("sid", Some("x".into())), Delivery::Full);
        assert_eq!(h.deliver("nope", Some("x".into())), Delivery::NoSession);
    }
}
