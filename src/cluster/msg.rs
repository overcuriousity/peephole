//! Directed messages between nodes (scan claims, leases, pace changes).
//!
//! Messages are signed by their sender and routed hop by hop: straight to
//! the destination if we can dial it, into an outbox the destination
//! collects with a long-poll if it dials us (outbound-only nodes), or
//! towards it over the neighbour graph learned from heartbeats.
//! Requests carry an id; the answer comes back as a separate message.
use super::Node;
use super::identity::NodeId;
use super::rpc::proto::ROUTED_PROTO;
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
/// Bytes of messages waiting in one peer's outbox; older ones are dropped
/// first.
const MAX_OUTBOX_BYTES: usize = 32 << 20;
/// Bytes of messages handed over by one inbox poll; the rest wait for the
/// next.
const MAX_INBOX_BYTES: usize = 16 << 20;
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
    /// The arbiter's offer that funds this job (`credits::jobs`). A grant
    /// at 0 has none and encodes exactly like those of nodes that predate
    /// the market.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_seq: Option<u64>,
    /// What the scanner charges for delivering the result.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub price_mc: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
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
        /// The least a funded job may pay: half the scanner's own scan price.
        #[serde(default, skip_serializing_if = "is_zero")]
        min_mc: u32,
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
    /// Managing node → sibling: do this. `cmd` is the encoded command
    /// (`owner::cmd::OwnerCmd`), `sig` the owner key's signature over
    /// sender, target, `counter` and those bytes.
    OwnerCmd {
        counter: u64,
        cmd: serde_bytes::ByteBuf,
        sig: serde_bytes::ByteBuf,
    },
    /// `counter` is the node's counter after the command.
    OwnerReply {
        counter: u64,
        error: Option<String>,
        data: Option<super::owner::cmd::OwnerData>,
    },
    /// A sibling → a sibling: send me this much (`credits::fleet`).
    CreditDraw {
        mc: u64,
    },
    /// What the sibling sent.
    CreditDrawReply {
        sent_mc: u64,
    },
    /// A paid call to a member nobody can dial (`rpc::routed`); `body` is
    /// the CBOR request a direct call would POST to `path`.
    Rpc {
        path: String,
        body: serde_bytes::ByteBuf,
    },
    /// Its answer: the HTTP status a direct call would get, and the body.
    RpcReply {
        status: u16,
        body: serde_bytes::ByteBuf,
    },
    /// Scanner → its auditor: audit my designated scan `scan_uid`, paid
    /// with my offer `offer_seq` (`credits::audit`). The auditor reads the
    /// scan from its own copy of the log.
    AuditReq {
        scan_uid: String,
        offer_seq: u64,
    },
    AuditReply {
        accepted: bool,
        why: Option<String>,
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
    /// Wakes an outbound-only node's inbox polls when it asks something:
    /// it collects the answer also where it holds no relay lease.
    asking: tokio::sync::Notify,
    handlers: Mutex<Vec<Handler>>,
}

/// No answer came back in time.
#[derive(Debug)]
pub struct NoAnswer(pub Duration);

impl std::fmt::Display for NoAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no answer within {:?}", self.0)
    }
}

impl std::error::Error for NoAnswer {}

#[derive(Debug, PartialEq)]
pub(crate) enum Hop {
    Dial(NodeId, String),
    Outbox(NodeId),
}

/// The first hop of a message for `to`, an outbound-only member leasing
/// `relays`: this node's outbox when it is one of them and `holds` its
/// lease (else none: it refuses), otherwise the first listed relay this
/// node can dial that is not in `avoid`.
pub(crate) fn relay_hop(
    me: &NodeId,
    to: &NodeId,
    relays: &[NodeId],
    dial: &HashMap<NodeId, String>,
    avoid: &[NodeId],
    holds: bool,
) -> Option<Hop> {
    if relays.contains(me) {
        return holds.then_some(Hop::Outbox(*to));
    }
    relays
        .iter()
        .filter(|r| !avoid.contains(r))
        .find_map(|r| dial.get(r).map(|a| Hop::Dial(*r, a.clone())))
}

impl Node {
    /// Register a handler; each request goes to the handlers in order
    /// until one answers.
    pub fn on_message(&self, h: Handler) {
        self.msg.handlers.lock().unwrap().push(h);
    }

    /// Ask `to` and wait for its answer.
    pub async fn request(self: &Arc<Self>, to: NodeId, msg: Msg, timeout: Duration) -> Result<Msg> {
        self.request_avoiding(to, msg, timeout, vec![]).await
    }

    /// Like [`Node::request`], never sent through the first hops in
    /// `avoid`: members that could not relay this kind of message.
    pub async fn request_avoiding(
        self: &Arc<Self>,
        to: NodeId,
        msg: Msg,
        timeout: Duration,
        avoid: Vec<NodeId>,
    ) -> Result<Msg> {
        let (id, env) = Envelope::seal(self, to, None, msg)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.msg
            .replies
            .lock()
            .unwrap()
            .insert(id.clone(), (to, tx));
        self.msg.asking.notify_waiters();
        let mut rx = rx;
        let no_answer =
            || anyhow::Error::new(NoAnswer(timeout)).context(format!("asked {}", to.short()));
        let out = match self.route_avoiding(env.clone(), avoid.clone()).await {
            Ok(hop) => match tokio::time::timeout(timeout / 2, &mut rx).await {
                Ok(r) => r.map_err(|_| anyhow::anyhow!("request dropped")),
                Err(_) => {
                    // No answer yet: send it once more around the first hop
                    // used, in case that relay drops it. The id stays the
                    // same, so the destination handles it only once.
                    if let Some(h) = hop {
                        let mut avoid = avoid;
                        avoid.push(h);
                        let _ = self.route_avoiding(env, avoid).await;
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
            match node.next_hop(&body.to, &avoid, body.in_reply_to.is_some()) {
                Some(Hop::Dial(peer, addr)) => {
                    match node.call::<_, bool>(peer, &addr, "/rpc/v1/msg", &env).await {
                        Ok(_) => Ok(Some(peer)),
                        // A relay that fails or refuses: the next one.
                        Err(e)
                            if node
                                .status
                                .known(&body.to)
                                .is_some_and(|k| k.hb.relays.contains(&peer)) =>
                        {
                            debug!(relay = %peer.short(), ?e, "relay failed; trying the next");
                            let mut avoid = avoid;
                            avoid.push(peer);
                            node.route_avoiding(env, avoid).await
                        }
                        Err(e) => Err(e),
                    }
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
                    let mut bytes: usize = q.iter().map(|(e, _)| e.body.len()).sum();
                    while bytes > MAX_OUTBOX_BYTES
                        && let Some((e, _)) = q.pop_front()
                    {
                        bytes -= e.body.len();
                    }
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
    pub(crate) fn dial_failing(&self, id: &NodeId) -> bool {
        self.peer_status
            .read()
            .unwrap()
            .get(id)
            .is_some_and(|s| s.last_error.is_some())
    }

    /// Whether a message to `id` has a first hop, none of them in `avoid`.
    pub(crate) fn routable(&self, id: &NodeId, avoid: &[NodeId]) -> bool {
        self.next_hop(id, avoid, false).is_some()
    }

    /// The first hop towards `to`. A `reply` (an answer to a request of
    /// `to`) may wait in an outbox here for a member that polls it without
    /// a lease; only requests need one.
    fn next_hop(&self, to: &NodeId, avoid: &[NodeId], reply: bool) -> Option<Hop> {
        let dial: HashMap<NodeId, String> = self
            .dial_targets()
            .into_iter()
            .filter(|(id, _, _)| !avoid.contains(id))
            .map(|(id, _, addr)| (id, addr))
            .collect();
        // An outbound-only member is reached through the relays it leases.
        let relays = self
            .status
            .known(to)
            .map(|k| k.hb.relays)
            .unwrap_or_default();
        if !relays.is_empty() && !dial.contains_key(to) {
            let now = super::hlc::wall_ms();
            let holds = self.relay_leases.holds(to, now) && self.status.polled_recently(to);
            let hop = relay_hop(&self.id(), to, &relays, &dial, avoid, holds);
            if hop.is_some() || !reply {
                return hop;
            }
        }
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
            (self.status.polled_recently(id) && (reply && id == to || self.holds_outbox_for(id)))
                .then_some(Hop::Outbox(*id))
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

    /// Whether this node keeps an outbox for `id`: it has an address
    /// (it collects here when its dial fails), or leased this node.
    fn holds_outbox_for(&self, id: &NodeId) -> bool {
        self.members().get(id).is_some_and(|m| m.address.is_some())
            || self.relay_leases.holds(id, super::hlc::wall_ms())
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
                    // An RPC answer must not pass members too old to relay it.
                    let avoid = if matches!(answer, Msg::RpcReply { .. }) {
                        super::owner::cmd::old_relays(&node, &b.from, ROUTED_PROTO)
                    } else {
                        vec![]
                    };
                    match Envelope::seal(&node, b.from, Some(b.id.clone()), answer) {
                        Ok((_, env)) => {
                            if let Err(e) = node.route_avoiding(env, avoid).await {
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

    /// Whether messages wait here for `peer`.
    pub fn has_queued(&self, peer: &NodeId) -> bool {
        self.msg
            .outbox
            .lock()
            .unwrap()
            .get_mut(peer)
            .is_some_and(|q| {
                q.retain(|(_, t)| t.elapsed() < OUTBOX_TTL);
                !q.is_empty()
            })
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
                        return drain_budget(q, MAX_INBOX_BYTES);
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

/// Takes messages from the front of `q` up to `budget` bytes of bodies
/// (always at least one); the rest stay queued.
fn drain_budget(q: &mut VecDeque<(Envelope, Instant)>, budget: usize) -> Vec<Envelope> {
    let mut out = vec![];
    let mut bytes = 0;
    while let Some((e, _)) = q.front() {
        if !out.is_empty() && bytes + e.body.len() > budget {
            break;
        }
        bytes += e.body.len();
        out.extend(q.pop_front().map(|(e, _)| e));
    }
    out
}

/// Collect messages a dialable peer holds for us, and route each.
pub async fn inbox_loop(node: Arc<Node>, peer: NodeId, addr: String) {
    let mut backoff = Duration::from_secs(1);
    loop {
        // Registered before the check: a request made meanwhile still
        // wakes it.
        let asking = node.msg.asking.notified();
        // An outbound-only node collects at the relays it leases, and
        // anywhere while it waits for answers to its own requests.
        if node.cfg.advertise.is_none()
            && !node.leased.relays(super::hlc::wall_ms()).contains(&peer)
            && node.msg.replies.lock().unwrap().is_empty()
        {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                _ = asking => {}
            }
            continue;
        }
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
            Err(e) => {
                // The relay lost this node's lease (it restarted): lease
                // another.
                if format!("{e:#}").contains(super::relay::NO_LEASE) && node.leased.forget(&peer) {
                    debug!(relay = %peer.short(), "relay holds no lease of ours; dropped");
                    node.publish_status();
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_inbox_poll_takes_at_most_its_budget() {
        let env = |n: usize| {
            (
                Envelope {
                    body: vec![0; n],
                    sig: vec![],
                    hops: 0,
                },
                Instant::now(),
            )
        };
        let mut q: VecDeque<_> = [env(6), env(4), env(3)].into();
        assert_eq!(drain_budget(&mut q, 10).len(), 2);
        assert_eq!(q.len(), 1);
        // One message larger than the budget still goes, alone.
        let mut q: VecDeque<_> = [env(20), env(1)].into();
        assert_eq!(drain_budget(&mut q, 10).len(), 1);
        assert_eq!(q.len(), 1);
    }

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
            min_mc: 0,
        };
        assert_eq!(encode(&new_empty).unwrap(), encode(&OldMsg::Claim).unwrap());
        assert_eq!(
            decode::<Msg>(&encode(&OldMsg::Claim).unwrap()).unwrap(),
            new_empty
        );
        let excl = Msg::Claim {
            exclude_levels: vec![4],
            min_mc: 25,
        };
        assert_eq!(decode::<Msg>(&encode(&excl).unwrap()).unwrap(), excl);
        assert_eq!(
            decode::<OldMsg>(&encode(&excl).unwrap()).unwrap(),
            OldMsg::Claim
        );
    }

    /// The grant as nodes before paid scan jobs know it.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct OldGrant {
        job_uid: String,
        ip: String,
        level: i64,
        lease_secs: u64,
    }

    /// A grant at 0 encodes exactly like the old one; each side
    /// decodes the other's.
    #[test]
    fn grants_stay_compatible_across_versions() {
        use crate::cluster::rpc::cbor::{decode, encode};
        let old = OldGrant {
            job_uid: "j".into(),
            ip: "203.0.113.1".into(),
            level: 2,
            lease_secs: 120,
        };
        let free = Grant {
            job_uid: "j".into(),
            ip: "203.0.113.1".into(),
            level: 2,
            lease_secs: 120,
            offer_seq: None,
            price_mc: 0,
        };
        assert_eq!(encode(&free).unwrap(), encode(&old).unwrap());
        assert_eq!(decode::<Grant>(&encode(&old).unwrap()).unwrap(), free);
        let funded = Grant {
            offer_seq: Some(7),
            price_mc: 40,
            ..free
        };
        assert_eq!(decode::<Grant>(&encode(&funded).unwrap()).unwrap(), funded);
        assert_eq!(decode::<OldGrant>(&encode(&funded).unwrap()).unwrap(), old);
    }

    #[test]
    fn an_outbound_only_member_is_reached_through_its_relays_in_turn() {
        let id = |n: u8| NodeId([n; 32]);
        let (me, to) = (id(1), id(9));
        let dial: HashMap<NodeId, String> =
            [(id(2), "a:1".to_string()), (id(3), "b:1".to_string())].into();
        let hop = |relays: &[NodeId], avoid: &[NodeId], holds: bool| {
            relay_hop(&me, &to, relays, &dial, avoid, holds)
        };
        assert_eq!(
            hop(&[id(2), id(3)], &[], false),
            Some(Hop::Dial(id(2), "a:1".into()))
        );
        assert_eq!(
            hop(&[id(2), id(3)], &[id(2)], false),
            Some(Hop::Dial(id(3), "b:1".into())),
            "the first refused"
        );
        assert_eq!(
            hop(&[id(2), id(3)], &[id(2), id(3)], false),
            None,
            "both refused: no route"
        );
        assert_eq!(
            hop(&[id(4)], &[], false),
            None,
            "a relay this node cannot dial"
        );
        // This node is one of its relays: its outbox, while the lease holds.
        assert_eq!(hop(&[me, id(2)], &[], true), Some(Hop::Outbox(to)));
        assert_eq!(
            hop(&[me, id(2)], &[], false),
            None,
            "no lease from it: refused"
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
                min_mc: 0,
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
