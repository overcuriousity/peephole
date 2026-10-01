//! Per-peer sync loops. For every member we can dial: exchange version
//! vectors, pull what we lack, push what they lack, then sleep until our
//! log grows, theirs does (long-poll), or a timer fires.
use super::Node;
use super::identity::NodeId;
use super::record::WireEntry;
use super::repl::{self, Heads};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Reconcile at least this often, even without news.
const IDLE_ROUND: Duration = Duration::from_secs(30);
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
    pub max_entries: usize,
    pub max_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PushReq {
    pub entries: Vec<WireEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WaitReq {
    pub heads: Heads,
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
                let h = tokio::spawn(peer_loop(
                    node.clone(),
                    id,
                    name,
                    addr.clone(),
                    shutdown.clone(),
                ));
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
    let mut last_hello: Option<tokio::time::Instant> = None;
    let mut changes = node.subscribe_changes();
    loop {
        changes.borrow_and_update();
        let hello_due = last_hello.is_none_or(|t| t.elapsed() > HELLO_EVERY);
        match reconcile(&node, peer, &addr, hello_due).await {
            Ok(()) => {
                if hello_due {
                    last_hello = Some(tokio::time::Instant::now());
                }
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                node.record_status(peer, &name, Err(format!("{e:#}"))).await;
                last_hello = None;
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.changed() => return,
                }
                backoff = (backoff * 2).min(Duration::from_secs(60));
                continue;
            }
        }
        let wait = WaitReq {
            heads: repl::heads(&node.store).await.unwrap_or_default(),
        };
        let long_poll = node.call::<_, Heads>(peer, &addr, "/rpc/v1/wait", &wait);
        tokio::select! {
            _ = changes.changed() => tokio::time::sleep(DEBOUNCE).await,
            // News on their side, or the poll timed out; an error here
            // surfaces in the next reconcile.
            _ = long_poll => {}
            _ = tokio::time::sleep(IDLE_ROUND) => {}
            _ = shutdown.changed() => return,
        }
    }
}

/// One full exchange with a peer.
pub async fn reconcile(node: &Node, peer: NodeId, addr: &str, hello: bool) -> Result<()> {
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
    // Pull what we lack.
    loop {
        let ours = repl::heads(&node.store).await?;
        let wants: Vec<_> = theirs
            .iter()
            .filter(|(o, s)| repl::head_in(&ours, o) < *s)
            .map(|(o, _)| (*o, repl::head_in(&ours, o)))
            .collect();
        if wants.is_empty() {
            break;
        }
        let entries: Vec<WireEntry> = node
            .call(
                peer,
                addr,
                "/rpc/v1/pull",
                &PullReq {
                    wants,
                    max_entries: BATCH_ENTRIES,
                    max_bytes: BATCH_BYTES,
                },
            )
            .await?;
        if entries.is_empty() {
            break;
        }
        let st = repl::apply_batch(node, entries).await?;
        if st.applied + st.parked == 0 {
            break;
        }
    }
    // Push what they lack.
    let mut theirs = theirs;
    loop {
        let ours = repl::heads(&node.store).await?;
        let wants: Vec<_> = ours
            .iter()
            .filter(|(o, s)| repl::head_in(&theirs, o) < *s)
            .map(|(o, _)| (*o, repl::head_in(&theirs, o)))
            .collect();
        if wants.is_empty() {
            break;
        }
        let entries = repl::entries_after(&node.store, &wants, BATCH_ENTRIES, BATCH_BYTES).await?;
        if entries.is_empty() {
            break;
        }
        let after: Heads = node
            .call(peer, addr, "/rpc/v1/push", &PushReq { entries })
            .await?;
        if !repl::ahead_of(&after, &theirs) {
            break; // they accepted nothing (e.g. a gap on their side)
        }
        theirs = after;
    }
    node.record_status(peer, &name, Ok(None)).await;
    Ok(())
}
