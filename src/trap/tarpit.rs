//! The tarpit: sources whose requests reached severity 4 get, for an hour
//! after, a `200` whose body drips a few bytes at a time until the hold cap
//! or until they give up. It has a pool of its own; a held connection gives
//! back its listener's slots (see [`super::listen::Handover`]), and when the
//! pool is full the request gets the normal answer. The time a connection
//! was held is recorded with the request (`held_ms`).
//!
//! Never marked, so never tarpitted: addresses that are not global, and
//! those in `scan.never_scan` or `scan.never_scan_dir` (crawlers and other
//! bystanders the operator listed). Marks are this node's own.
use super::TrapConfig;
use super::listen::{SourceSlot, Sources};
use axum::body::Bytes;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::{Instant, Sleep};

/// How long a source stays marked after its last severity-4 request.
const MARK_TTL: Duration = Duration::from_secs(3600);
/// Most sources marked at once; past it the oldest marks go first.
const MAX_MARKS: usize = 64 * 1024;
/// The first bytes of every tarpit answer: the start of a page.
const PREFIX: &[u8] = b"<!DOCTYPE html>\n<html><head>\n";

/// Sources marked for the tarpit, keyed by [`crate::net::source_key`],
/// with when the mark runs out.
struct Marks {
    until: HashMap<IpAddr, Instant>,
    cap: usize,
}

impl Marks {
    fn new(cap: usize) -> Self {
        Self {
            until: HashMap::new(),
            cap,
        }
    }

    fn mark(&mut self, ip: IpAddr, now: Instant) {
        let key = crate::net::source_key(ip);
        if self.until.len() >= self.cap && !self.until.contains_key(&key) {
            self.until.retain(|_, t| *t > now);
            if self.until.len() >= self.cap {
                // The older half goes: one sort per cap/2 new marks.
                let mut ends: Vec<Instant> = self.until.values().copied().collect();
                ends.sort_unstable();
                let cut = ends[ends.len() / 2];
                self.until.retain(|_, t| *t > cut);
            }
        }
        self.until.insert(key, now + MARK_TTL);
    }

    fn marked(&self, ip: IpAddr, now: Instant) -> bool {
        self.until
            .get(&crate::net::source_key(ip))
            .is_some_and(|t| *t > now)
    }
}

/// The tarpit's marks and pool.
pub struct Tarpit {
    cfg: TrapConfig,
    never: Vec<IpNet>,
    lists: Mutex<crate::scan::safety::Lists>,
    marks: Mutex<Marks>,
    pool: Arc<Semaphore>,
    sources: Arc<Sources>,
}

impl Tarpit {
    /// With `cfg`'s pool and drip; never marking `never` nor what the
    /// lists in `never_dir` cover.
    pub fn new(cfg: &TrapConfig, never: Vec<IpNet>, never_dir: Option<PathBuf>) -> Self {
        Self {
            cfg: cfg.clone(),
            never,
            lists: Mutex::new(crate::scan::safety::Lists::new(never_dir)),
            marks: Mutex::new(Marks::new(MAX_MARKS)),
            pool: Arc::new(Semaphore::new(cfg.tarpit_pool)),
            sources: Arc::default(),
        }
    }

    /// The tarpit as `cfg` sets it, with the scanner's never-scan lists.
    pub fn of(cfg: &crate::config::Config) -> Self {
        Self::new(
            &cfg.trap,
            cfg.scan.never_scan.clone(),
            cfg.scan.safety.never_scan_dir.clone(),
        )
    }

    /// A tarpit that marks and holds nothing.
    pub fn off() -> Self {
        let cfg = TrapConfig {
            tarpit_pool: 0,
            ..Default::default()
        };
        Self::new(&cfg, vec![], None)
    }

    /// Mark `ip`'s source after a severity-4 request, unless it is exempt.
    pub fn mark(&self, ip: IpAddr) {
        if self.cfg.tarpit_pool == 0 || self.exempt(ip) {
            return;
        }
        let mut m = self.marks.lock().unwrap_or_else(|p| p.into_inner());
        m.mark(ip, Instant::now());
    }

    fn exempt(&self, ip: IpAddr) -> bool {
        let canon = crate::net::canonical(ip);
        if !crate::net::is_scannable_target(canon) || self.never.iter().any(|n| n.contains(&canon))
        {
            return true;
        }
        let mut lists = self.lists.lock().unwrap_or_else(|p| p.into_inner());
        lists.refresh();
        // Lists configured but never loaded: protect everyone.
        lists.unavailable().is_some() || lists.covering(&canon).is_some()
    }

    /// A place in the pool for a request from `ip`: None unless its source
    /// is marked and both the pool and the source's share have room.
    pub fn take(&self, ip: IpAddr) -> Option<Hold> {
        let marked = {
            let m = self.marks.lock().unwrap_or_else(|p| p.into_inner());
            m.marked(ip, Instant::now())
        };
        if !marked {
            return None;
        }
        let permit = self.pool.clone().try_acquire_owned().ok()?;
        let slot = self.sources.take(ip, self.cfg.tarpit_per_source)?;
        Some(Hold {
            _permit: permit,
            _slot: slot,
            hold: Duration::from_secs(self.cfg.tarpit_hold_secs),
            every: Duration::from_secs(self.cfg.tarpit_drip_every_secs),
            bytes: self.cfg.tarpit_drip_bytes,
        })
    }

    /// How full the tarpit is right now.
    pub fn status(&self) -> Status {
        let now = Instant::now();
        let m = self.marks.lock().unwrap_or_else(|p| p.into_inner());
        Status {
            held: self.cfg.tarpit_pool - self.pool.available_permits(),
            pool: self.cfg.tarpit_pool,
            marked: m.until.values().filter(|t| **t > now).count(),
        }
    }

    #[cfg(test)]
    fn free(&self) -> usize {
        self.pool.available_permits()
    }
}

/// How full the tarpit is (System › Status).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    /// Connections held now.
    pub held: usize,
    /// Of at most this many; 0: the tarpit is off.
    pub pool: usize,
    /// Sources marked now.
    pub marked: usize,
}

/// A place in the tarpit's pool, given back when dropped.
pub struct Hold {
    _permit: OwnedSemaphorePermit,
    _slot: SourceSlot,
    hold: Duration,
    every: Duration,
    bytes: usize,
}

impl Hold {
    /// The longest this hold lasts.
    pub fn cap(&self) -> Duration {
        self.hold
    }

    /// The dripping body, and where the time it held the client arrives
    /// (in milliseconds) once it ends or is dropped.
    pub fn drip(self) -> (Drip, oneshot::Receiver<u64>) {
        let (tx, rx) = oneshot::channel();
        let start = Instant::now();
        let drip = Drip {
            end: start + self.hold,
            next: Box::pin(tokio::time::sleep_until(start + self.every.min(self.hold))),
            start,
            confirmed: start,
            emitted: None,
            started: false,
            done: false,
            tx: Some(tx),
            hold: self,
        };
        (drip, rx)
    }
}

/// The tarpit's answer body: [`PREFIX`] at once, then `bytes` spaces every
/// `every`, until the hold cap. The time held is up to the last chunk the
/// connection took: one asked for after it, which hyper does once it wrote
/// it out. A client that left is noticed at the next write, so it is never
/// counted for the time after it left. At the cap the time held is the cap.
pub struct Drip {
    hold: Hold,
    start: Instant,
    end: Instant,
    next: Pin<Box<Sleep>>,
    /// When the chunk not yet taken was handed out.
    emitted: Option<Instant>,
    /// Up to when the client is known to have been there.
    confirmed: Instant,
    started: bool,
    done: bool,
    tx: Option<oneshot::Sender<u64>>,
}

impl futures::Stream for Drip {
    type Item = Result<Bytes, std::convert::Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if let Some(t) = this.emitted.take() {
            this.confirmed = t;
        }
        if this.done {
            return Poll::Ready(None);
        }
        if !this.started {
            this.started = true;
            this.emitted = Some(Instant::now());
            return Poll::Ready(Some(Ok(Bytes::from_static(PREFIX))));
        }
        if this.next.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        let now = Instant::now();
        if now >= this.end {
            this.done = true;
            this.confirmed = this.end;
            this.report();
            return Poll::Ready(None);
        }
        let at = (now + this.hold.every).min(this.end);
        this.next.as_mut().reset(at);
        this.emitted = Some(now);
        Poll::Ready(Some(Ok(Bytes::from(vec![b' '; this.hold.bytes]))))
    }
}

impl Drip {
    fn report(&mut self) {
        if let Some(tx) = self.tx.take() {
            let ms = self.confirmed.duration_since(self.start).as_millis();
            let _ = tx.send(u64::try_from(ms).unwrap_or(u64::MAX));
        }
    }
}

impl Drop for Drip {
    fn drop(&mut self) {
        self.report();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn cfg(pool: usize, per_source: usize) -> TrapConfig {
        TrapConfig {
            tarpit_pool: pool,
            tarpit_per_source: per_source,
            tarpit_hold_secs: 60,
            tarpit_drip_bytes: 3,
            tarpit_drip_every_secs: 10,
            ..Default::default()
        }
    }

    const SCANNER: &str = "8.8.4.4";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn marks_run_out_and_cover_the_source() {
        let mut m = Marks::new(10);
        let t0 = Instant::now();
        m.mark(ip("2001:db8:1:2::1"), t0);
        assert!(m.marked(ip("2001:db8:1:2::ffff"), t0), "the same /64");
        assert!(!m.marked(ip("2001:db8:1:3::1"), t0));
        assert!(m.marked(
            ip("2001:db8:1:2::1"),
            t0 + MARK_TTL - Duration::from_secs(1)
        ));
        assert!(!m.marked(ip("2001:db8:1:2::1"), t0 + MARK_TTL));
    }

    #[tokio::test(start_paused = true)]
    async fn marks_are_capped_and_keep_the_newest() {
        let mut m = Marks::new(8);
        let t0 = Instant::now();
        for i in 0..100u32 {
            m.mark(
                IpAddr::from((0xCB00_7100 + i).to_be_bytes()),
                t0 + Duration::from_millis(i.into()),
            );
            assert!(m.until.len() <= 8);
        }
        let last = IpAddr::from((0xCB00_7100u32 + 99).to_be_bytes());
        assert!(m.marked(last, t0 + Duration::from_secs(1)));
    }

    #[tokio::test(start_paused = true)]
    async fn only_marked_global_unlisted_sources_are_taken() {
        let t = Tarpit::new(&cfg(4, 2), vec!["198.51.100.0/24".parse().unwrap()], None);
        assert!(t.take(ip(SCANNER)).is_none(), "not marked");
        for exempt in ["10.0.0.1", "127.0.0.1", "198.51.100.7"] {
            t.mark(ip(exempt));
            assert!(t.take(ip(exempt)).is_none(), "{exempt}");
        }
        t.mark(ip(SCANNER));
        assert!(t.take(ip(SCANNER)).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn unloaded_never_scan_lists_protect_everyone() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let t = Tarpit::new(&cfg(4, 2), vec![], Some(missing));
        t.mark(ip(SCANNER));
        assert!(t.take(ip(SCANNER)).is_none());
        std::fs::write(dir.path().join("crawlers.txt"), "8.8.4.0/24\n").unwrap();
        let t = Tarpit::new(&cfg(4, 2), vec![], Some(dir.path().to_path_buf()));
        t.mark(ip(SCANNER));
        assert!(t.take(ip(SCANNER)).is_none(), "listed");
        t.mark(ip("8.8.8.8"));
        assert!(t.take(ip("8.8.8.8")).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn the_pool_and_each_source_are_capped_and_given_back() {
        let t = Tarpit::new(&cfg(3, 2), vec![], None);
        let (a, b) = (ip("8.8.8.8"), ip("1.1.1.1"));
        t.mark(a);
        t.mark(b);
        let a1 = t.take(a).unwrap();
        let a2 = t.take(a).unwrap();
        assert!(t.take(a).is_none(), "the source's share");
        let b1 = t.take(b).unwrap();
        assert!(t.take(b).is_none(), "the pool");
        assert_eq!(t.free(), 0);
        drop((a1, a2, b1));
        assert_eq!(t.free(), 3);
        assert!(t.take(a).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn status_counts_holds_and_live_marks() {
        let t = Tarpit::new(&cfg(3, 2), vec![], None);
        assert_eq!(
            t.status(),
            Status {
                held: 0,
                pool: 3,
                marked: 0
            }
        );
        t.mark(ip("8.8.8.8"));
        t.mark(ip("1.1.1.1"));
        let h = t.take(ip("8.8.8.8")).unwrap();
        assert_eq!(
            t.status(),
            Status {
                held: 1,
                pool: 3,
                marked: 2
            }
        );
        drop(h);
        tokio::time::advance(MARK_TTL).await;
        assert_eq!(
            t.status(),
            Status {
                held: 0,
                pool: 3,
                marked: 0
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn off_marks_and_takes_nothing() {
        for t in [Tarpit::new(&cfg(0, 2), vec![], None), Tarpit::off()] {
            t.mark(ip("8.8.8.8"));
            assert!(t.take(ip("8.8.8.8")).is_none());
            assert_eq!(
                t.status(),
                Status {
                    held: 0,
                    pool: 0,
                    marked: 0
                }
            );
        }
    }

    fn hold() -> Hold {
        let t = Tarpit::new(&cfg(1, 1), vec![], None);
        t.mark(ip("8.8.8.8"));
        t.take(ip("8.8.8.8")).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn drips_slowly_and_ends_at_the_cap() {
        let (mut drip, held) = hold().drip();
        let t0 = Instant::now();
        assert_eq!(&drip.next().await.unwrap().unwrap()[..], PREFIX);
        assert_eq!(Instant::now(), t0, "the prefix at once");
        let chunk = drip.next().await.unwrap().unwrap();
        assert_eq!(&chunk[..], b"   ");
        assert_eq!(Instant::now() - t0, Duration::from_secs(10));
        let mut chunks = 2;
        while drip.next().await.is_some() {
            chunks += 1;
        }
        assert_eq!(Instant::now() - t0, Duration::from_secs(60));
        assert_eq!(chunks, 6, "the prefix and one every 10 s before the cap");
        assert_eq!(held.await.unwrap(), 60_000);
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_leaves_is_held_until_its_last_taken_chunk() {
        let (mut drip, held) = hold().drip();
        drip.next().await.unwrap().unwrap();
        drip.next().await.unwrap().unwrap(); // at 10 s, then asked again:
        let again = tokio::time::timeout(Duration::from_secs(3), drip.next()).await;
        assert!(again.is_err(), "nothing before 20 s");
        drop(drip); // gone at 13 s; hyper had taken the 10 s chunk
        assert_eq!(held.await.unwrap(), 10_000);
    }

    #[tokio::test(start_paused = true)]
    async fn a_chunk_handed_out_but_never_taken_does_not_count() {
        let (mut drip, held) = hold().drip();
        drip.next().await.unwrap().unwrap();
        drip.next().await.unwrap().unwrap(); // the 10 s chunk, never asked past
        drop(drip);
        assert_eq!(held.await.unwrap(), 0);
    }
}
