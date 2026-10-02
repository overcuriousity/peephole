//! Per-peer sync loops. For every member we can dial: exchange version
//! vectors, pull what we lack, push what they lack, then sleep until our
//! log grows, theirs does (long-poll), or a timer fires.
use super::Node;
use super::history;
use super::identity::NodeId;
use super::record::WireEntry;
use super::repl::{self, Heads};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Reconcile at least this often, even without news (plus up to
/// [`IDLE_JITTER`], so a full mesh does not sync in lockstep).
const IDLE_ROUND: Duration = Duration::from_secs(30);
const IDLE_JITTER: Duration = Duration::from_secs(10);
/// Sync exchanges running at once, over all peers: in a full mesh every
/// member has its own loop, and the database serializes their writes anyway.
pub(crate) const MAX_CONCURRENT_SYNCS: usize = 8;
/// Longest wait between attempts to reach an unreachable peer.
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// Gather bursts of local writes into one round.
const DEBOUNCE: Duration = Duration::from_millis(200);
/// How long a peer holds our long-poll open.
pub const WAIT_SECS: u64 = 25;
/// Re-check the member list (picks up CLI changes) this often.
const SUPERVISE_TICK: Duration = Duration::from_secs(5);
/// Re-greet a reachable peer this often.
const HELLO_EVERY: Duration = Duration::from_secs(60);
pub const BATCH_ENTRIES: usize = 2000;
pub const BATCH_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct PullReq {
    pub wants: Vec<(NodeId, u64)>,
    /// The receiver keeps only history from this HLC on (0: everything).
    #[serde(default)]
    pub since_hlc: u64,
    pub max_entries: usize,
    pub max_bytes: usize,
}

/// Log entries, plus the signed tombstones that justify the erased ones
/// among them. A receiver accepts an erased entry only with such a proof.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Batch {
    pub entries: Vec<WireEntry>,
    pub proofs: Vec<WireEntry>,
    /// Origins whose entries here start past what was asked for (the
    /// sender's floor or the receiver's window), and where. Entries before
    /// that start are membership entries.
    #[serde(default)]
    pub floors: Vec<(NodeId, u64)>,
}

impl From<Vec<WireEntry>> for Batch {
    fn from(entries: Vec<WireEntry>) -> Self {
        Self {
            entries,
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WaitReq {
    pub heads: Heads,
    /// Origins the caller does not take right now (purged, over quota, …).
    #[serde(default)]
    pub refused: Vec<NodeId>,
    /// The caller keeps only a window and may start an origin at a floor.
    #[serde(default)]
    pub windowed: bool,
}

/// Run one loop per dialable member; restart on address change, stop for
/// members that were revoked.
pub async fn supervise(node: Arc<Node>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut loops: HashMap<NodeId, (String, tokio::task::JoinHandle<()>)> = HashMap::new();
    let mut last_heads: Option<Heads> = None;
    loop {
        // Another process (the CLI) may have written members or entries.
        if let Err(e) = node.reload_members().await {
            debug!(?e, "member reload failed");
        }
        if let Ok(h) = repl::heads(&node.store).await {
            if last_heads.as_ref().is_some_and(|l| repl::ahead_of(&h, l)) {
                node.notify_changed();
            }
            last_heads = Some(h);
        }
        let targets = node.dial_targets();
        loops.retain(|id, (addr, h)| {
            let keep = !h.is_finished() && targets.iter().any(|t| t.0 == *id && t.2 == *addr);
            if !keep {
                h.abort();
            }
            keep
        });
        for (id, name, addr) in targets {
            loops.entry(id).or_insert_with(|| {
                let sync = peer_loop(node.clone(), id, name, addr.clone(), shutdown.clone());
                let inbox = super::msg::inbox_loop(node.clone(), id, addr.clone());
                let h = tokio::spawn(async move {
                    tokio::select! {
                        _ = sync => {}
                        _ = inbox => {}
                    }
                });
                (addr, h)
            });
        }
        tokio::select! {
            _ = tokio::time::sleep(SUPERVISE_TICK) => {}
            _ = node.members_changed.notified() => {}
            _ = shutdown.changed() => break,
        }
    }
    for (_, (_, h)) in loops {
        h.abort();
    }
}

async fn peer_loop(
    node: Arc<Node>,
    peer: NodeId,
    name: String,
    addr: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut backoff = Duration::from_secs(1);
    // Separate, growing backoff for the "stuck" case (peer offers entries we
    // cannot apply): without it the loop would re-poll /wait — which answers
    // at once while the peer is ahead — and busy-spin at full CPU.
    let mut stuck_backoff = Duration::from_secs(1);
    let mut last_hello: Option<tokio::time::Instant> = None;
    let mut changes = node.subscribe_changes();
    loop {
        changes.borrow_and_update();
        let hello_due = last_hello.is_none_or(|t| t.elapsed() > HELLO_EVERY);
        let round = {
            let _slot = node.sync_slots.acquire().await;
            reconcile(&node, peer, &addr, hello_due).await
        };
        match round {
            Ok(stuck) => {
                if hello_due {
                    last_hello = Some(tokio::time::Instant::now());
                }
                backoff = Duration::from_secs(1);
                if stuck {
                    tokio::select! {
                        _ = tokio::time::sleep(stuck_backoff) => {}
                        _ = changes.changed() => {}
                        _ = shutdown.changed() => return,
                    }
                    stuck_backoff = (stuck_backoff * 2).min(Duration::from_secs(60));
                    continue;
                }
                stuck_backoff = Duration::from_secs(1);
            }
            Err(e) => {
                let msg = format!("{e:#}");
                // We thought everyone else was gone; a peer says it is us.
                if node.isolated() && msg.contains("pruned: no sign of life") {
                    tracing::warn!(peer = %name, "the cluster pruned this node; rejoin with an invite");
                    if super::set_detached(&node.store, Some(super::Detached::Pruned))
                        .await
                        .is_ok()
                    {
                        let _ = node.reload_members().await;
                    }
                    return;
                }
                node.record_status(peer, &name, Err(msg)).await;
                last_hello = None;
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.changed() => return,
                }
                // A peer whose published address keeps failing is dialled
                // less and less often.
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        }
        let wait = WaitReq {
            heads: repl::heads(&node.store).await.unwrap_or_default(),
            refused: repl::refused_origins(&node)
                .await
                .unwrap_or_default()
                .into_iter()
                .collect(),
            windowed: node.windowed(),
        };
        let long_poll = node.call::<_, Heads>(peer, &addr, "/rpc/v1/wait", &wait);
        tokio::select! {
            _ = changes.changed() => tokio::time::sleep(DEBOUNCE).await,
            // News on their side, or the poll timed out; an error here
            // surfaces in the next reconcile.
            _ = long_poll => {}
            _ = tokio::time::sleep(IDLE_ROUND + jitter(IDLE_JITTER)) => {}
            _ = shutdown.changed() => return,
        }
    }
}

/// A random duration below `max`.
fn jitter(max: Duration) -> Duration {
    let mut b = [0u8; 4];
    let _ = aws_lc_rs::rand::fill(&mut b);
    max.mul_f64(u32::from_le_bytes(b) as f64 / u32::MAX as f64)
}

/// One full exchange with a peer. Returns `true` when it is "stuck": the peer
/// offered entries but none could be applied or parked (and we are still
/// behind), so the caller must back off instead of immediately re-polling
/// `/wait` (which answers at once while the peer is ahead) and busy-spinning.
pub async fn reconcile(node: &Node, peer: NodeId, addr: &str, hello: bool) -> Result<bool> {
    node.sync_rounds
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = node
        .members()
        .get(&peer)
        .map(|m| m.name.clone())
        .unwrap_or_default();
    if hello {
        let h = node.hello(peer, addr).await?;
        node.record_status(peer, &name, Ok(Some(h))).await;
    }
    let ours = repl::heads(&node.store).await?;
    let theirs: Heads = node.call(peer, addr, "/rpc/v1/heads", &ours).await?;
    let gossip: Vec<super::status::SignedHeartbeat> = node
        .call(peer, addr, "/rpc/v1/gossip", &node.status.all_signed())
        .await?;
    node.merge_heartbeats(gossip);
    // Pull what we lack, except from origins we would refuse anyway (they
    // must not crowd out the rest) and what the peer cannot serve us (its
    // history starts past ours).
    let refused = repl::refused_origins(node).await?;
    let mut stuck = false;
    loop {
        let ours = repl::head_map(&repl::heads(&node.store).await?);
        let wants: Vec<_> = theirs
            .iter()
            .filter(|(o, _)| !refused.contains(o))
            .map(|(o, s)| (*o, *s, ours.get(o).copied().unwrap_or(0)))
            .filter(|(o, s, mine)| {
                mine < s && history::servable(node.peer_floor(&peer, o), *mine, node.windowed())
            })
            .map(|(o, _, mine)| (o, mine))
            .collect();
        if wants.is_empty() {
            break;
        }
        let batch: Batch = node
            .call(
                peer,
                addr,
                "/rpc/v1/pull",
                &PullReq {
                    wants,
                    since_hlc: node.since_hlc(),
                    max_entries: BATCH_ENTRIES,
                    max_bytes: BATCH_BYTES,
                },
            )
            .await?;
        if batch.entries.is_empty() {
            // Advertised but not served (e.g. a floor not gossiped yet): back
            // off like for entries we cannot apply.
            stuck = true;
            break;
        }
        let st = repl::apply_batch(node, batch).await?;
        if st.applied + st.parked == 0 {
            // The peer has entries we cannot make progress on; stop pulling and
            // signal the caller to back off rather than spin.
            stuck = true;
            break;
        }
    }
    // Push what they lack and can take from us.
    let mut theirs = repl::head_map(&theirs);
    let floors = {
        let mut conn = node.store.pool.acquire().await?;
        history::floors(&mut conn).await?
    };
    let peer_windowed = node.peer_since_hlc(&peer) > 0;
    loop {
        let ours = repl::heads(&node.store).await?;
        let wants: Vec<_> = ours
            .iter()
            .map(|(o, s)| (*o, *s, theirs.get(o).copied().unwrap_or(0)))
            .filter(|(o, s, t)| {
                t < s && history::servable(floors.get(o).copied().unwrap_or(1), *t, peer_windowed)
            })
            .map(|(o, _, t)| (o, t))
            .collect();
        if wants.is_empty() {
            break;
        }
        let batch = repl::entries_after(
            &node.store,
            &wants,
            node.peer_since_hlc(&peer),
            BATCH_ENTRIES,
            BATCH_BYTES,
        )
        .await?;
        if batch.entries.is_empty() {
            break;
        }
        let after: Heads = node.call(peer, addr, "/rpc/v1/push", &batch).await?;
        if !repl::ahead_of_map(&after, &theirs) {
            break; // they accepted nothing (e.g. a gap on their side)
        }
        theirs = repl::head_map(&after);
    }
    node.record_status(peer, &name, Ok(None)).await;
    Ok(stuck)
}
