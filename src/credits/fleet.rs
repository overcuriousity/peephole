//! A fleet (the nodes of one owner) proves ownership. Its one economic
//! effect: a node whose lookup needs more than it holds draws the missing
//! credits from its siblings, the richest first. Every node keeps what it
//! earns; scans are paid from the node's own balance only.
use super::{Mc, show};
use crate::cluster::identity::NodeId;
use crate::cluster::msg::Msg;
use crate::cluster::record::Record;
use crate::cluster::{Node, repl};
use anyhow::{Result, bail};
use std::sync::Arc;
use std::time::Duration;

/// How long a node waits for a sibling, and then for the transfers to
/// arrive.
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

/// Siblings to draw from: those holding anything, the richest first
/// (ties by key, so the order is stable).
pub fn draw_order(siblings: &[NodeId], balance: impl Fn(&NodeId) -> Mc) -> Vec<NodeId> {
    let mut v: Vec<(Mc, NodeId)> = siblings
        .iter()
        .map(|s| (balance(s), *s))
        .filter(|(b, _)| *b > 0)
        .collect();
    v.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    v.into_iter().map(|(_, s)| s).collect()
}

/// Draw `mc` from this node's siblings, the richest first, until it is
/// covered, and wait for the transfers to arrive. False: no sibling gave
/// enough.
pub async fn draw(node: &Arc<Node>, mc: Mc) -> bool {
    let me = node.id();
    let Ok(book) = super::book_fresh(node).await else {
        return false;
    };
    let start = book.balance(&me);
    let siblings = crate::cluster::owner::fleet::siblings(&node.store)
        .await
        .unwrap_or_default();
    let siblings: Vec<NodeId> = siblings
        .into_iter()
        .filter(|s| *s != me && !node.is_blocked(s))
        .collect();
    let mut missing = mc;
    for from in draw_order(&siblings, |s| book.balance(s)) {
        let ask = missing.min(book.balance(&from));
        let avoid = crate::cluster::owner::cmd::old_relays(
            node,
            &from,
            crate::cluster::rpc::proto::OWNER_PROTO,
        );
        let sent = match node
            .request_avoiding(from, Msg::CreditDraw { mc: ask }, DRAW_WAIT, avoid)
            .await
        {
            Ok(Msg::CreditDrawReply { sent_mc }) => sent_mc,
            _ => 0,
        };
        if sent == 0 {
            continue;
        }
        // The transfer is an entry of the sibling's log: fetch it.
        if let Some(addr) = node.working_dial_address(&from) {
            let _ = crate::cluster::sync::reconcile(node, from, &addr, false).await;
        }
        missing = missing.saturating_sub(sent);
        if missing == 0 {
            break;
        }
    }
    // Wait until the book holds what arrived.
    let until = tokio::time::Instant::now() + DRAW_WAIT;
    loop {
        if let Ok(b) = super::book_fresh(node).await
            && b.balance(&me) >= start + mc.saturating_sub(missing)
        {
            return missing == 0;
        }
        if tokio::time::Instant::now() >= until {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lookup_draws_from_the_richest_sibling_first() {
        let (a, b, c) = (NodeId([1; 32]), NodeId([2; 32]), NodeId([3; 32]));
        let bal = |n: &NodeId| match n.0[0] {
            1 => 50,
            2 => 900,
            _ => 0,
        };
        assert_eq!(
            draw_order(&[a, b, c], bal),
            vec![b, a],
            "richest first; nothing to give: not asked"
        );
        assert!(draw_order(&[], bal).is_empty());
    }
}
