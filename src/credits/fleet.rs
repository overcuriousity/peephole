//! A fleet's one balance. The ledger has node accounts only; a fleet
//! becomes one entity through two movements between its nodes, both
//! ordinary transfers: every node forwards what it earns to the fleet's
//! collecting node, and a node that needs credits draws them from there.
//! To the rest of the cluster these are transfers like any other.
use super::{CREDIT, Mc, show};
use crate::cluster::identity::NodeId;
use crate::cluster::msg::Msg;
use crate::cluster::record::Record;
use crate::cluster::{Node, repl};
use crate::settings::Settings;
use anyhow::{Result, bail};
use std::sync::Arc;
use std::time::Duration;

/// How often a node forwards what it holds.
pub const COLLECT_EVERY: Duration = Duration::from_secs(600);
/// How long a node waits for its collecting node, and then for the
/// transfer to arrive.
pub const DRAW_WAIT: Duration = Duration::from_secs(10);

/// Whether credits can be sent to `to` from here: an active member that
/// is neither blocked nor shown to have two histories.
async fn receivable(node: &Node, to: &NodeId) -> Result<bool> {
    if *to == node.id() || node.is_blocked(to) {
        return Ok(false);
    }
    if !node.members().get(to).is_some_and(|m| m.active) {
        return Ok(false);
    }
    Ok(!crate::cluster::seal::forked_set(&node.store.pool)
        .await?
        .contains(to))
}

async fn transfer(node: &Node, to: NodeId, parts: Vec<(u32, u32)>) -> Result<()> {
    repl::append_sealing(node, |seal| Record::CreditTransfer { to, parts, seal }).await?;
    Ok(())
}

/// Send `mc` to `to`, oldest lots first. No fee. Refused when this node
/// does not hold that much, or `to` cannot receive.
pub async fn send(node: &Node, to: NodeId, mc: Mc) -> Result<Mc> {
    if !receivable(node, &to).await? {
        bail!(
            "{} is not a member credits can be sent to from here",
            to.short()
        );
    }
    let book = super::book_fresh(node).await?;
    let Some(parts) = book.ledger.spendable_parts(&node.id(), mc) else {
        bail!(
            "this node holds {} credits, not {}",
            show(book.balance(&node.id())),
            show(mc)
        );
    };
    transfer(node, to, parts).await?;
    tracing::info!(to = %to.short(), credits = %show(mc), "credits sent");
    Ok(mc)
}

/// Forward everything this node holds to `to`, when it holds at least a
/// credit or a lot is on its last day. Returns what was sent.
pub async fn collect(node: &Node, to: NodeId) -> Result<Mc> {
    if !receivable(node, &to).await? {
        return Ok(0);
    }
    let me = node.id();
    let book = super::book_fresh(node).await?;
    let have = book.balance(&me);
    if have == 0 || (have < CREDIT && book.ledger.expiring_today(&me) == 0) {
        return Ok(0);
    }
    let Some(parts) = book.ledger.spendable_parts(&me, have) else {
        return Ok(0);
    };
    transfer(node, to, parts).await?;
    tracing::info!(to = %to.short(), credits = %show(have), "credits forwarded to the collecting node");
    Ok(have)
}

/// Answer draws: a sibling gets what it asks for, as far as this node's
/// balance goes. Anyone else gets no answer.
pub fn serve(node: &Arc<Node>) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |from, msg| {
        let weak = weak.clone();
        Box::pin(async move {
            let Msg::CreditDraw { mc } = msg else {
                return None;
            };
            let node = weak.upgrade()?;
            let siblings = crate::cluster::owner::fleet::siblings(&node.store)
                .await
                .ok()?;
            if !siblings.contains(&from) {
                tracing::debug!(by = %from.short(), "credit draw by a node that is not ours: not answered");
                return None;
            }
            let have = super::book_fresh(&node).await.ok()?.balance(&node.id());
            let give = mc.min(have);
            let sent_mc = match give {
                0 => 0,
                _ => send(&node, from, give).await.unwrap_or(0),
            };
            Some(Msg::CreditDrawReply { sent_mc })
        })
    }));
}

/// Draw `mc` from this node's collecting node and wait for the transfer
/// to arrive. False: no collecting node, it did not answer, or it sent
/// nothing.
pub async fn draw(node: &Arc<Node>, mc: Mc) -> bool {
    let me = node.id();
    let Some(from) = (*node.collect_to.read().unwrap()).filter(|c| *c != me) else {
        return false;
    };
    let before = match super::book_fresh(node).await {
        Ok(b) => b.balance(&me),
        Err(_) => return false,
    };
    let avoid = crate::cluster::owner::cmd::old_relays(node, &from);
    let sent = match node
        .request_avoiding(from, Msg::CreditDraw { mc }, DRAW_WAIT, avoid)
        .await
    {
        Ok(Msg::CreditDrawReply { sent_mc }) => sent_mc,
        _ => 0,
    };
    if sent == 0 {
        return false;
    }
    // The transfer is an entry of the collecting node's log: fetch it.
    if let Some(addr) = node.dial_address(&from) {
        let _ = crate::cluster::sync::reconcile(node, from, &addr, false).await;
    }
    let until = tokio::time::Instant::now() + DRAW_WAIT;
    loop {
        if let Ok(b) = super::book_fresh(node).await
            && b.balance(&me) > before
        {
            return true;
        }
        if tokio::time::Instant::now() >= until {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Keep the node's collecting node in step with its settings, and forward
/// what it holds every [`COLLECT_EVERY`].
pub async fn run(
    node: Arc<Node>,
    settings: Settings,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut changed = settings.subscribe();
    let mut next = tokio::time::Instant::now() + COLLECT_EVERY;
    loop {
        let to = settings.snapshot().collect_to;
        *node.collect_to.write().unwrap() = to;
        if tokio::time::Instant::now() >= next {
            next = tokio::time::Instant::now() + COLLECT_EVERY;
            if let Some(to) = to
                && let Err(e) = collect(&node, to).await
            {
                tracing::debug!(?e, "credits not forwarded");
            }
        }
        tokio::select! {
            _ = tokio::time::sleep_until(next) => {}
            _ = changed.changed() => {}
            _ = shutdown.changed() => break,
        }
    }
}
