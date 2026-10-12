//! What replication moves between this node and each peer, for the journal:
//! one summary line per active peer a minute (`cluster traffic`), each sync
//! round at debug level.

use super::identity::NodeId;
use super::record::WireEntry;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::info;

/// A summary covers this long.
pub const SUMMARY_EVERY: Duration = Duration::from_secs(60);

/// Entries by kind (`request`, `scan_job`, ...).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Kinds(BTreeMap<String, u64>);

impl Kinds {
    pub fn of<'a>(entries: impl IntoIterator<Item = &'a WireEntry>) -> Self {
        let mut k = Self::default();
        for e in entries {
            k.add(&e.kind, 1);
        }
        k
    }

    fn add(&mut self, kind: &str, n: u64) {
        if n > 0 {
            *self.0.entry(kind.to_string()).or_default() += n;
        }
    }

    fn merge(&mut self, other: &Kinds) {
        for (k, n) in &other.0 {
            self.add(k, *n);
        }
    }

    pub fn total(&self) -> u64 {
        self.0.values().sum()
    }
}

/// `12 (request 10, scan_job 2)`, or `0`.
impl std::fmt::Display for Kinds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.total())?;
        if !self.0.is_empty() {
            let mut parts = String::new();
            for (k, n) in &self.0 {
                if !parts.is_empty() {
                    parts.push_str(", ");
                }
                let _ = write!(parts, "{k} {n}");
            }
            write!(f, " ({parts})")?;
        }
        Ok(())
    }
}

/// One peer's counts since the last summary.
#[derive(Debug, Default)]
struct Peer {
    name: String,
    /// Sync rounds this node ran with the peer, and how many failed.
    rounds: u64,
    failed: u64,
    /// Entries taken from the peer: pulled by us or pushed by it.
    received: Kinds,
    /// Of those, applied (the rest were parked, duplicates or refused).
    applied: u64,
    /// Entries the peer took from us: pushed by us or pulled by it.
    sent: Kinds,
}

impl Peer {
    fn active(&self) -> bool {
        self.rounds + self.failed + self.received.total() + self.sent.total() > 0
    }
}

#[derive(Debug)]
pub struct Traffic {
    peers: Mutex<HashMap<NodeId, Peer>>,
    since: Mutex<Instant>,
}

impl Default for Traffic {
    fn default() -> Self {
        Self {
            peers: Default::default(),
            since: Mutex::new(Instant::now()),
        }
    }
}

impl Traffic {
    fn with(&self, peer: NodeId, name: &str, f: impl FnOnce(&mut Peer)) {
        let mut peers = self.peers.lock().unwrap();
        let p = peers.entry(peer).or_default();
        if !name.is_empty() {
            p.name = name.to_string();
        }
        f(p);
    }

    /// A sync round with `peer` finished (`ok`) or failed.
    pub fn round(&self, peer: NodeId, name: &str, ok: bool) {
        self.with(peer, name, |p| {
            p.rounds += 1;
            p.failed += u64::from(!ok);
        });
    }

    /// Entries taken from `peer`, `applied` of them.
    pub fn received(&self, peer: NodeId, name: &str, kinds: &Kinds, applied: usize) {
        self.with(peer, name, |p| {
            p.received.merge(kinds);
            p.applied += applied as u64;
        });
    }

    /// Entries `peer` took from us.
    pub fn sent(&self, peer: NodeId, name: &str, kinds: &Kinds) {
        self.with(peer, name, |p| p.sent.merge(kinds));
    }

    /// Log and reset the counts once [`SUMMARY_EVERY`] has passed; a peer
    /// with nothing to report gets no line.
    pub fn summarize_if_due(&self) {
        {
            let mut since = self.since.lock().unwrap();
            if since.elapsed() < SUMMARY_EVERY {
                return;
            }
            *since = Instant::now();
        }
        let peers = std::mem::take(&mut *self.peers.lock().unwrap());
        let mut active: Vec<_> = peers.into_iter().filter(|(_, p)| p.active()).collect();
        active.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        for (id, p) in active {
            info!(
                peer = %p.name,
                id = %id.short(),
                rounds = p.rounds,
                failed = p.failed,
                received = %p.received,
                applied = p.applied,
                sent = %p.sent,
                "cluster traffic in the last minute"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: &str) -> WireEntry {
        WireEntry {
            origin: NodeId([1; 32]),
            seq: 1,
            hlc: 1,
            kind: kind.into(),
            uid: None,
            payload: None,
            sig: None,
            erased_by: None,
        }
    }

    #[test]
    fn kinds_count_and_print() {
        let e = [entry("request"), entry("scan_job"), entry("request")];
        let k = Kinds::of(&e);
        assert_eq!(k.total(), 3);
        assert_eq!(k.to_string(), "3 (request 2, scan_job 1)");
        assert_eq!(Kinds::default().to_string(), "0");
    }

    #[test]
    fn counts_add_up_per_peer_and_reset_after_a_summary() {
        let t = Traffic::default();
        let a = NodeId([2; 32]);
        let k = Kinds::of(&[entry("request")]);
        t.round(a, "a", true);
        t.round(a, "", false);
        t.received(a, "a", &k, 1);
        t.sent(a, "a", &k);
        t.sent(a, "a", &k);
        {
            let peers = t.peers.lock().unwrap();
            let p = &peers[&a];
            assert_eq!((p.name.as_str(), p.rounds, p.failed), ("a", 2, 1));
            assert_eq!((p.received.total(), p.applied, p.sent.total()), (1, 1, 2));
        }
        // Not due yet: nothing is reset.
        t.summarize_if_due();
        assert!(t.peers.lock().unwrap().contains_key(&a));
        *t.since.lock().unwrap() -= SUMMARY_EVERY;
        t.summarize_if_due();
        assert!(t.peers.lock().unwrap().is_empty());
    }
}
