//! The fleet: the members that share this node's owner. They are found
//! with a directed hello and kept in the `siblings` table. The rest of
//! the cluster takes no part: a hello does not carry the owner id, and a
//! node of another owner (or of none) only answers that it is no sibling.
use super::{OwnerId, cert_valid, load};
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::msg::Msg;
use crate::cluster::rpc::proto::OWNER_PROTO;
use crate::store::Store;
use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};

const HELLO_DOMAIN: &[u8] = b"peephole-owner-hello-v1\0";
/// How long a member has to answer a hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Greet every reachable member at least this often.
const ROUND: Duration = Duration::from_secs(600);
/// How often the loop looks whether the owner or the live members changed.
const TICK: Duration = Duration::from_secs(60);
/// A member heard from within this time is greeted.
const LIVE: Duration = Duration::from_secs(45);

/// What a hello carries instead of the owner id: only a node that holds
/// the same owner id can recompute it.
pub fn hello_tag(owner: &OwnerId, from: &NodeId, to: &NodeId) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(HELLO_DOMAIN);
    h.update(owner.0);
    h.update(from.0);
    h.update(to.0);
    h.finalize().into()
}

/// This node's siblings, by node id.
pub async fn siblings(store: &Store) -> Result<Vec<NodeId>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT node FROM siblings ORDER BY node")
        .fetch_all(&store.pool)
        .await?;
    rows.iter().map(|r| NodeId::from_slice(r)).collect()
}

pub(crate) async fn remember(store: &Store, node: &NodeId, cert: &[u8]) -> Result<()> {
    sqlx::query(
        "INSERT INTO siblings (node, cert, seen_at) VALUES (?, ?, datetime('now'))
         ON CONFLICT(node) DO UPDATE SET cert = excluded.cert, seen_at = excluded.seen_at",
    )
    .bind(&node.0[..])
    .bind(cert)
    .execute(&store.pool)
    .await?;
    Ok(())
}

pub(crate) async fn forget(store: &Store, node: &NodeId) -> Result<()> {
    sqlx::query("DELETE FROM siblings WHERE node = ?")
        .bind(&node.0[..])
        .execute(&store.pool)
        .await?;
    Ok(())
}

/// Answer hellos: a sibling gets this node's certificate, anyone else an
/// empty one.
pub fn serve(node: &Arc<Node>) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |from, msg| {
        let weak = weak.clone();
        Box::pin(async move {
            let Msg::OwnerHello { tag, cert } = msg else {
                return None;
            };
            let node = weak.upgrade()?;
            let no = Some(Msg::OwnerHelloReply {
                cert: serde_bytes::ByteBuf::new(),
            });
            let Ok(Some(owned)) = load(&node.store, node.id()).await else {
                return no;
            };
            let ours = hello_tag(&owned.id, &from, &node.id());
            if aws_lc_rs::constant_time::verify_slices_are_equal(tag.as_slice(), &ours).is_err()
                || !cert_valid(&owned.id, &from, &cert)
            {
                return no;
            }
            if let Err(e) = remember(&node.store, &from, &cert).await {
                tracing::debug!(?e, "sibling not stored");
            }
            Some(Msg::OwnerHelloReply {
                cert: serde_bytes::ByteBuf::from(owned.cert),
            })
        })
    }));
}

/// One round: forget siblings that are no longer members, greet every
/// live member, and return the siblings afterwards. A member that answers
/// with its certificate is a sibling; one that answers without is not
/// (any more); one that does not answer stays what it was.
///
/// A sibling this node blocked stays a sibling: whose node it is does not
/// depend on whether this node talks to it, and a rotation must still list
/// it as not moved.
pub async fn discover(node: &Arc<Node>) -> Result<Vec<NodeId>> {
    greet(node, None).await
}

/// [`discover`], greeting only the members in `only` when it is given.
async fn greet(node: &Arc<Node>, only: Option<&[NodeId]>) -> Result<Vec<NodeId>> {
    let me = node.id();
    let Some(owned) = load(&node.store, me).await? else {
        return Ok(vec![]);
    };
    let members = node.members();
    let stored: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as("SELECT node, cert FROM siblings")
        .fetch_all(&node.store.pool)
        .await?;
    for (id, cert) in stored {
        let id = NodeId::from_slice(&id)?;
        let member = members.get(&id).is_some_and(|m| m.active);
        if !member || !cert_valid(&owned.id, &id, &cert) {
            forget(&node.store, &id).await?;
        }
    }
    let targets: Vec<NodeId> = node
        .live_members(LIVE)
        .into_iter()
        .filter(|id| *id != me && !node.is_blocked(id))
        .filter(|id| only.is_none_or(|o| o.contains(id)))
        .filter(|id| {
            members
                .get(id)
                .is_some_and(|m| m.active && m.proto_max >= OWNER_PROTO)
        })
        .collect();
    let asks = targets.iter().map(|to| {
        let hello = Msg::OwnerHello {
            tag: serde_bytes::ByteBuf::from(hello_tag(&owned.id, &me, to).to_vec()),
            cert: serde_bytes::ByteBuf::from(owned.cert.clone()),
        };
        let avoid = super::cmd::old_relays(node, to);
        async move {
            let answer = node
                .request_avoiding(*to, hello, HELLO_TIMEOUT, avoid)
                .await;
            (*to, answer)
        }
    });
    for (to, answer) in futures::future::join_all(asks).await {
        match answer {
            Ok(Msg::OwnerHelloReply { cert }) if cert_valid(&owned.id, &to, &cert) => {
                remember(&node.store, &to, &cert).await?;
            }
            Ok(_) => forget(&node.store, &to).await?,
            // Unreachable: it stays what it was.
            Err(_) => {}
        }
    }
    siblings(&node.store).await
}

/// What the loop does at a tick.
#[derive(Debug, PartialEq)]
enum Round {
    Nothing,
    /// Every live member: the owner changed, or [`ROUND`] has passed.
    Full,
    /// Only the members that came online since the last look.
    Only(Vec<NodeId>),
}

/// The owner and the live members as last greeted, and as they are now.
type View = (Option<OwnerId>, Vec<NodeId>);

fn plan(seen: Option<&View>, now: &View, due: bool) -> Round {
    match seen {
        Some(seen) if seen.0 == now.0 && !due => {
            let new: Vec<NodeId> = now
                .1
                .iter()
                .filter(|id| !seen.1.contains(id))
                .copied()
                .collect();
            if new.is_empty() {
                Round::Nothing
            } else {
                Round::Only(new)
            }
        }
        _ => Round::Full,
    }
}

/// Keep the siblings current: a full round when the owner changed and at
/// least every [`ROUND`], and a greeting for each member that comes online
/// in between.
pub async fn run(node: Arc<Node>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut seen: Option<View> = None;
    let mut last = Instant::now();
    loop {
        let owner = load(&node.store, node.id())
            .await
            .ok()
            .flatten()
            .map(|o| o.id);
        let mut live = node.live_members(LIVE);
        live.sort();
        let now = (owner, live);
        let round = plan(seen.as_ref(), &now, last.elapsed() >= ROUND);
        let done = match &round {
            Round::Nothing => None,
            Round::Full => Some(greet(&node, None).await),
            Round::Only(new) => Some(greet(&node, Some(new)).await),
        };
        match done {
            // A round that failed is made again at the next tick.
            Some(Err(e)) => tracing::debug!(?e, "sibling discovery failed"),
            Some(Ok(_)) => {
                if round == Round::Full {
                    last = Instant::now();
                }
                seen = Some(now);
            }
            None => seen = Some(now),
        }
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = shutdown.changed() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;
    use crate::cluster::owner::OwnerKey;

    #[test]
    fn the_hello_tag_binds_owner_and_both_nodes() {
        let (o1, o2) = (
            OwnerKey::generate().unwrap().id,
            OwnerKey::generate().unwrap().id,
        );
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let t = hello_tag(&o1, &a, &b);
        assert_eq!(t, hello_tag(&o1, &a, &b));
        assert_ne!(t, hello_tag(&o2, &a, &b), "another owner");
        assert_ne!(t, hello_tag(&o1, &b, &a), "direction");
    }

    #[test]
    fn a_round_greets_everyone_only_when_the_owner_changed_or_it_is_due() {
        let o = OwnerKey::generate().unwrap().id;
        let (a, b, c) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let was: View = (Some(o), vec![a, b]);
        assert_eq!(plan(None, &was, false), Round::Full, "the first look");
        assert_eq!(plan(Some(&was), &was, false), Round::Nothing);
        assert_eq!(plan(Some(&was), &was, true), Round::Full, "due");
        let more: View = (Some(o), vec![a, b, c]);
        assert_eq!(plan(Some(&was), &more, false), Round::Only(vec![c]));
        let fewer: View = (Some(o), vec![a]);
        assert_eq!(plan(Some(&was), &fewer, false), Round::Nothing);
        let other: View = (Some(OwnerKey::generate().unwrap().id), vec![a, b]);
        assert_eq!(
            plan(Some(&was), &other, false),
            Round::Full,
            "another owner"
        );
        let none: View = (None, vec![a, b]);
        assert_eq!(plan(Some(&was), &none, false), Round::Full, "released");
    }

    #[tokio::test]
    async fn siblings_are_remembered_and_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        remember(&store, &a, b"c1").await.unwrap();
        remember(&store, &a, b"c2").await.unwrap();
        remember(&store, &b, b"c3").await.unwrap();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(siblings(&store).await.unwrap(), want);
        forget(&store, &a).await.unwrap();
        assert_eq!(siblings(&store).await.unwrap(), vec![b]);
    }
}
