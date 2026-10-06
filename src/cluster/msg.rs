//! Directed messages between nodes (scan claims, leases, pace changes).
//!
//! Messages are signed by their sender and routed hop by hop: straight to
//! the destination if we can dial it, into an outbox the destination
//! collects with a long-poll if it dials us (outbound-only nodes), or
//! towards it over the neighbour graph learned from heartbeats.
//! Requests carry an id; the answer comes back as a separate message.
use super::Node;
use super::identity::NodeId;
use anyhow::{Context, Result, bail};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::debug;

const MSG_DOMAIN: &[u8] = b"peephole-msg-v1\0";
/// Hops after which a message is dropped (loops, stale routes).
const MAX_HOPS: u8 = 8;
/// Messages older than this are refused (replay window).
const MAX_AGE: Duration = Duration::from_secs(600);
/// Messages dated further ahead than this are refused: they would outlive
/// the duplicate filter and could be replayed after it forgot them.
const MAX_AHEAD: Duration = Duration::from_secs(300);
/// Undelivered outbox messages are dropped after this.
const OUTBOX_TTL: Duration = Duration::from_secs(120);
/// Messages waiting in one peer's outbox; older ones are dropped first.
const MAX_OUTBOX: usize = 256;
/// Messages being routed at once; more are refused (the sender retries).
pub const MAX_ROUTING: usize = 256;
/// A heartbeat listing more neighbours than this contributes none.
const MAX_NEIGHBOURS: usize = 256;
/// How long a peer's inbox long-poll is held open.
pub const INBOX_WAIT: Duration = Duration::from_secs(25);

/// A job granted to a scanner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub job_uid: String,
    pub ip: String,
    pub level: i64,
    pub lease_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "m", rename_all = "snake_case")]
pub enum Msg {
    /// Scanner → arbiter: give me a job, but none of these levels (a
    /// scanner at its level-4 share excludes 4). Empty encodes exactly like
    /// the claim of nodes that predate the field; such nodes ignore it.
    Claim {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        exclude_levels: Vec<u8>,
    },
    ClaimReply {
        grant: Option<Grant>,
    },
    /// Scanner → arbiter: still scanning this job.
    Renew {
        job_uid: String,
    },
    RenewReply {
        ok: bool,
    },
    /// Scanner → arbiter: the job ended. Status: done, failed, superseded
    /// or refused; or handed back: declined (for good) or later (for now).
    Complete {
        job_uid: String,
        status: String,
        error: Option<String>,
    },
    CompleteReply {
        ok: bool,
    },
    /// Admin → every arbiter: requeue jobs that failed in the last `days`.
    RequeueFailed {
        days: i64,
    },
    RequeueReply {
        n: u64,
    },
    /// Any member → node: what are your runtime settings?
    ConfigGet,
    ConfigState(super::remote::State),
    /// A config key request of an earlier version. Still decoded; always
    /// answered with a refusal that names the ownership key.
    ConfigSet {
        base_version: u64,
        changes: crate::settings::Changes,
        mac: serde_bytes::ByteBuf,
    },
    /// The refusal.
    ConfigSetReply {
        version: Option<u64>,
        error: Option<String>,
    },
    /// Owned node → member: are you a node of my owner? `tag` is a hash
    /// that only a node with the same owner id can recompute, `cert` the
    /// sender's certificate.
    OwnerHello {
        tag: serde_bytes::ByteBuf,
        cert: serde_bytes::ByteBuf,
    },
    /// The answerer's certificate; empty when it is no sibling.
    OwnerHelloReply {
        cert: serde_bytes::ByteBuf,
    },
    /// Managing node → sibling: do this. `sig` is the owner key's
    /// signature over sender, target, `counter` and the command.
    OwnerCmd {
        counter: u64,
        cmd: super::owner::cmd::OwnerCmd,
        sig: serde_bytes::ByteBuf,
    },
    /// `counter` is the node's counter after the command.
    OwnerReply {
        counter: u64,
        error: Option<String>,
        data: Option<super::owner::cmd::OwnerData>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    pub id: String,
    pub from: NodeId,
    pub to: NodeId,
    pub created_ms: u64,
    pub in_reply_to: Option<String>,
    pub msg: Msg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    /// Incremented by each relay; not signed.
    pub hops: u8,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Envelope {
    fn seal(
        node: &Node,
        to: NodeId,
        in_reply_to: Option<String>,
        msg: Msg,
    ) -> Result<(String, Self)> {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let body = super::rpc::cbor::encode(&Body {
            id: id.clone(),
            from: node.id(),
            to,
            created_ms: now_ms(),
            in_reply_to,
            msg,
        })?;
        let sig = node.identity.sign(&[MSG_DOMAIN, &body].concat());
        Ok((id, Self { body, sig, hops: 0 }))
    }

    /// Decode and verify the sender's signature.
    pub fn open(&self) -> Result<Body> {
        let b: Body = super::rpc::cbor::decode(&self.body).context("message body")?;
        if !b.from.verify(&[MSG_DOMAIN, &self.body].concat(), &self.sig) {
            bail!("bad message signature");
        }
        Ok(b)
    }
}

impl Body {
    /// Within the replay window: not older than [`MAX_AGE`], not dated
    /// more than [`MAX_AHEAD`] into the future.
    pub fn fresh(&self) -> bool {
        let now = now_ms();
        self.created_ms <= now + MAX_AHEAD.as_millis() as u64
            && now.saturating_sub(self.created_ms) <= MAX_AGE.as_millis() as u64
    }
}

/// Handles requests addressed to this node; the answer goes back to the
/// sender. Registered once by the subsystems (arbiter, pace).
pub type Handler = Arc<dyn Fn(NodeId, Msg) -> BoxFuture<'static, Option<Msg>> + Send + Sync>;

#[derive(Default)]
pub struct Messaging {
    seen: Mutex<HashMap<String, Instant>>,
    outbox: Mutex<HashMap<NodeId, VecDeque<(Envelope, Instant)>>>,
    pub outbox_changed: tokio::sync::Notify,
    /// request id -> (expected responder, reply channel). The responder is
    /// checked so a relaying member that merely saw the id cannot forge the
    /// answer in the real destination's place.
    replies: Mutex<HashMap<String, (NodeId, tokio::sync::oneshot::Sender<Msg>)>>,
    handlers: Mutex<Vec<Handler>>,
}

enum Hop {
    Dial(NodeId, String),
    Outbox(NodeId),
}

impl Node {
    /// Register a handler; each request goes to the handlers in order
    /// until one answers.
    pub fn on_message(&self, h: Handler) {
        self.msg.handlers.lock().unwrap().push(h);
    }

    /// Ask `to` and wait for its answer.
    pub async fn request(self: &Arc<Self>, to: NodeId, msg: Msg, timeout: Duration) -> Result<Msg> {
        let (id, env) = Envelope::seal(self, to, None, msg)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.msg
            .replies
            .lock()
            .unwrap()
            .insert(id.clone(), (to, tx));
        let mut rx = rx;
        let no_answer = || anyhow::anyhow!("no answer from {} within {timeout:?}", to.short());
        let out = match self.route_avoiding(env.clone(), vec![]).await {
            Ok(hop) => match tokio::time::timeout(timeout / 2, &mut rx).await {
                Ok(r) => r.map_err(|_| anyhow::anyhow!("request dropped")),
                Err(_) => {
                    // No answer yet: send it once more around the first hop
                    // used, in case that relay drops it. The id stays the
                    // same, so the destination handles it only once.
                    if let Some(h) = hop {
                        let _ = self.route_avoiding(env, vec![h]).await;
                    }
                    tokio::time::timeout(timeout - timeout / 2, rx)
                        .await
                        .map_err(|_| no_answer())
                        .and_then(|r| r.map_err(|_| anyhow::anyhow!("request dropped")))
                }
            },
            Err(e) => Err(e),
        };
        self.msg.replies.lock().unwrap().remove(&id);
        out
    }

    /// Send or forward a message one step towards its destination.
    pub fn route(self: &Arc<Self>, env: Envelope) -> BoxFuture<'static, Result<()>> {
        let node = self.clone();
        Box::pin(async move { node.route_avoiding(env, vec![]).await.map(|_| ()) })
    }

    /// Like [`Node::route`], never via the first hops in `avoid`. Returns the
    /// first hop used (None: delivered here).
    pub fn route_avoiding(
        self: &Arc<Self>,
        env: Envelope,
        avoid: Vec<NodeId>,
    ) -> BoxFuture<'static, Result<Option<NodeId>>> {
        let node = self.clone();
        Box::pin(async move {
            let body = env.open()?;
            if body.to == node.id() {
                node.deliver(body).await;
                return Ok(None);
            }
            if env.hops >= MAX_HOPS {
                bail!("message to {} exceeded {MAX_HOPS} hops", body.to.short());
            }
            match node.next_hop(&body.to, &avoid) {
                Some(Hop::Dial(peer, addr)) => {
                    let _: bool = node.call(peer, &addr, "/rpc/v1/msg", &env).await?;
                    Ok(Some(peer))
                }
                Some(Hop::Outbox(peer)) => {
                    let mut all = node.msg.outbox.lock().unwrap();
                    // Peers that stopped polling must not pile up messages.
                    for q in all.values_mut() {
                        q.retain(|(_, t)| t.elapsed() < OUTBOX_TTL);
                    }
                    all.retain(|_, q| !q.is_empty());
                    let q = all.entry(peer).or_default();
                    while q.len() >= MAX_OUTBOX {
                        q.pop_front();
                    }
                    q.push_back((env, Instant::now()));
                    drop(all);
                    node.msg.outbox_changed.notify_waiters();
                    Ok(Some(peer))
                }
                None => bail!("no route to {}", body.to.short()),
            }
        })
    }

    /// Whether dialling `id` failed last time (it is retried by its sync
    /// loop with backoff, not by every message).
    fn dial_failing(&self, id: &NodeId) -> bool {
        self.peer_status
            .read()
            .unwrap()
            .get(id)
            .is_some_and(|s| s.last_error.is_some())
    }

    fn next_hop(&self, to: &NodeId, avoid: &[NodeId]) -> Option<Hop> {
        let dial: HashMap<NodeId, String> = self
            .dial_targets()
            .into_iter()
            .filter(|(id, _, _)| !avoid.contains(id))
            .map(|(id, _, addr)| (id, addr))
            .collect();
        let via = |id: &NodeId, fresh_only: bool| -> Option<Hop> {
            if avoid.contains(id) {
                return None;
            }
            if let Some(addr) = dial.get(id)
                && (if fresh_only {
                    self.status.reached_recently(id)
                } else {
                    !self.dial_failing(id)
                })
            {
                return Some(Hop::Dial(*id, addr.clone()));
            }
            self.status.polled_recently(id).then_some(Hop::Outbox(*id))
        };
        // Direct delivery first.
        if let Some(h) = via(to, true) {
            return Some(h);
        }
        // Shortest path over the neighbour graph; first hop must be ours.
        // Heartbeats are self-asserted: only members count, a node listing
        // too many neighbours contributes none, and an edge between two
        // other nodes counts only if both list it, so no node can make
        // itself everybody's relay by claiming to be.
        let members = self.members();
        let mut claimed: HashSet<(NodeId, NodeId)> = HashSet::new();
        for k in self.status.heartbeats.lock().unwrap().values() {
            if k.hb.neighbours.len() > MAX_NEIGHBOURS || !members.contains_key(&k.hb.node) {
                continue;
            }
            for n in &k.hb.neighbours {
                if members.contains_key(n) {
                    claimed.insert((k.hb.node, *n));
                }
            }
        }
        let mut adj: HashMap<NodeId, HashSet<NodeId>> = HashMap::new();
        let mut link = |a: NodeId, b: NodeId| {
            adj.entry(a).or_default().insert(b);
            adj.entry(b).or_default().insert(a);
        };
        for n in self.status.neighbours() {
            if !avoid.contains(&n) {
                link(self.id(), n);
            }
        }
        for (a, b) in &claimed {
            if *a != self.id() && *b != self.id() && claimed.contains(&(*b, *a)) {
                link(*a, *b);
            }
        }
        let mut prev: HashMap<NodeId, NodeId> = HashMap::new();
        let mut queue = VecDeque::from([self.id()]);
        let mut seen = HashSet::from([self.id()]);
        while let Some(cur) = queue.pop_front() {
            if cur == *to {
                break;
            }
            for n in adj.get(&cur).into_iter().flatten() {
                if seen.insert(*n) {
                    prev.insert(*n, cur);
                    queue.push_back(*n);
                }
            }
        }
        if prev.contains_key(to) {
            let mut hop = *to;
            while prev.get(&hop) != Some(&self.id()) {
                hop = prev[&hop];
            }
            if let Some(h) = via(&hop, false) {
                return Some(h);
            }
        }
        // Last resort: dial the destination even without recent contact.
        via(to, false)
    }

    async fn deliver(self: &Arc<Self>, b: Body) {
        if self.is_blocked(&b.from) {
            return debug!(from = %b.from.short(), "message from a blocked peer dropped");
        }
        if !self.is_member(&b.from) {
            return debug!(from = %b.from.short(), "message from non-member dropped");
        }
        if !b.fresh() {
            return debug!(from = %b.from.short(), "stale or future-dated message dropped");
        }
        {
            let mut seen = self.msg.seen.lock().unwrap();
            seen.retain(|_, t| t.elapsed() < MAX_AGE * 2);
            if seen.insert(b.id.clone(), Instant::now()).is_some() {
                return; // duplicate
            }
        }
        if let Some(rid) = &b.in_reply_to {
            let mut replies = self.msg.replies.lock().unwrap();
            // Only accept the reply from the node we actually asked; a relay
            // that saw the id must not be able to answer in its place.
            if let Some((expected, _)) = replies.get(rid) {
                if *expected == b.from {
                    if let Some((_, tx)) = replies.remove(rid) {
                        let _ = tx.send(b.msg);
                    }
                } else {
                    debug!(from = %b.from.short(), "reply from unexpected responder dropped");
                }
            }
            return;
        }
        let handlers = self.msg.handlers.lock().unwrap().clone();
        let node = self.clone();
        // Handlers may wait (claim window); never block the caller.
        tokio::spawn(async move {
            for h in handlers {
                if let Some(answer) = h(b.from, b.msg.clone()).await {
                    match Envelope::seal(&node, b.from, Some(b.id.clone()), answer) {
                        Ok((_, env)) => {
                            if let Err(e) = node.route(env).await {
                                debug!(to = %b.from.short(), ?e, "reply not delivered");
                            }
                        }
                        Err(e) => debug!(?e, "reply not sealed"),
                    }
                    return;
                }
            }
        });
    }

    /// Messages waiting for `peer` (it long-polls us); waits up to
    /// [`INBOX_WAIT`] for one to arrive.
    pub async fn take_inbox(&self, peer: NodeId) -> Vec<Envelope> {
        let deadline = tokio::time::Instant::now() + INBOX_WAIT;
        loop {
            let notified = self.msg.outbox_changed.notified();
            {
                let mut all = self.msg.outbox.lock().unwrap();
                if let Some(q) = all.get_mut(&peer) {
                    q.retain(|(_, t)| t.elapsed() < OUTBOX_TTL);
                    if !q.is_empty() {
                        return q.drain(..).map(|(e, _)| e).collect();
                    }
                }
            }
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => return vec![],
            }
        }
    }
}

/// Collect messages a dialable peer holds for us, and route each.
pub async fn inbox_loop(node: Arc<Node>, peer: NodeId, addr: String) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match node
            .call::<_, Vec<Envelope>>(peer, &addr, "/rpc/v1/inbox", &true)
            .await
        {
            Ok(envs) => {
                backoff = Duration::from_secs(1);
                for mut env in envs.into_iter().take(MAX_OUTBOX) {
                    env.hops = env.hops.saturating_add(1);
                    let Ok(permit) = node.route_slots.clone().try_acquire_owned() else {
                        debug!("too many messages in flight; inbox message dropped");
                        continue;
                    };
                    let n = node.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = n.route(env).await {
                            debug!(?e, "inbox message not routed");
                        }
                    });
                }
            }
            Err(_) => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim as nodes before `exclude_levels` know it.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(tag = "m", rename_all = "snake_case")]
    enum OldMsg {
        Claim,
    }

    /// Mixed versions: an empty exclusion encodes exactly like the old
    /// unit claim, each side decodes the other's claim, and an old node
    /// decodes a claim that carries exclusions.
    #[test]
    fn claims_stay_compatible_across_versions() {
        use crate::cluster::rpc::cbor::{decode, encode};
        let new_empty = Msg::Claim {
            exclude_levels: vec![],
        };
        assert_eq!(encode(&new_empty).unwrap(), encode(&OldMsg::Claim).unwrap());
        assert_eq!(
            decode::<Msg>(&encode(&OldMsg::Claim).unwrap()).unwrap(),
            new_empty
        );
        let excl = Msg::Claim {
            exclude_levels: vec![4],
        };
        assert_eq!(decode::<Msg>(&encode(&excl).unwrap()).unwrap(), excl);
        assert_eq!(
            decode::<OldMsg>(&encode(&excl).unwrap()).unwrap(),
            OldMsg::Claim
        );
    }

    #[test]
    fn messages_from_the_future_are_not_fresh() {
        let id = crate::cluster::identity::Identity::generate().unwrap().id;
        let at = |created_ms| Body {
            id: "x".into(),
            from: id,
            to: id,
            created_ms,
            in_reply_to: None,
            msg: Msg::Claim {
                exclude_levels: vec![],
            },
        };
        let now = now_ms();
        assert!(at(now).fresh());
        assert!(at(now + 60_000).fresh(), "small clock skew is fine");
        assert!(
            !at(now + 3_600_000).fresh(),
            "would outlive the replay filter"
        );
        assert!(!at(now - 3_600_000).fresh());
    }
}
