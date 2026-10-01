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
/// Undelivered outbox messages are dropped after this.
const OUTBOX_TTL: Duration = Duration::from_secs(120);
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
    /// Scanner → arbiter: give me a job.
    Claim,
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
    /// or refused.
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
    /// Admin → scanner: change its scan pace (persisted there).
    SetPace {
        pace: super::status::PaceInfo,
    },
    /// `error` is None on success.
    SetPaceReply {
        error: Option<String>,
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

/// Handles requests addressed to this node; the answer goes back to the
/// sender. Registered once by the subsystems (arbiter, pace).
pub type Handler = Arc<dyn Fn(NodeId, Msg) -> BoxFuture<'static, Option<Msg>> + Send + Sync>;

#[derive(Default)]
pub struct Messaging {
    seen: Mutex<HashMap<String, Instant>>,
    outbox: Mutex<HashMap<NodeId, VecDeque<(Envelope, Instant)>>>,
    pub outbox_changed: tokio::sync::Notify,
    replies: Mutex<HashMap<String, tokio::sync::oneshot::Sender<Msg>>>,
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
        self.msg.replies.lock().unwrap().insert(id.clone(), tx);
        let sent = self.route(env).await;
        let out = match sent {
            Ok(()) => tokio::time::timeout(timeout, rx)
                .await
                .map_err(|_| anyhow::anyhow!("no answer from {} within {timeout:?}", to.short()))
                .and_then(|r| r.map_err(|_| anyhow::anyhow!("request dropped"))),
            Err(e) => Err(e),
        };
        self.msg.replies.lock().unwrap().remove(&id);
        out
    }

    /// Send or forward a message one step towards its destination.
    pub fn route(self: &Arc<Self>, env: Envelope) -> BoxFuture<'static, Result<()>> {
        let node = self.clone();
        Box::pin(async move {
            let body = env.open()?;
            if body.to == node.id() {
                node.deliver(body).await;
                return Ok(());
            }
            if env.hops >= MAX_HOPS {
                bail!("message to {} exceeded {MAX_HOPS} hops", body.to.short());
            }
            match node.next_hop(&body.to) {
                Some(Hop::Dial(peer, addr)) => {
                    let _: bool = node.call(peer, &addr, "/rpc/v1/msg", &env).await?;
                    Ok(())
                }
                Some(Hop::Outbox(peer)) => {
                    let mut all = node.msg.outbox.lock().unwrap();
                    // Peers that stopped polling must not pile up messages.
                    for q in all.values_mut() {
                        q.retain(|(_, t)| t.elapsed() < OUTBOX_TTL);
                    }
                    all.retain(|_, q| !q.is_empty());
                    all.entry(peer)
                        .or_default()
                        .push_back((env, Instant::now()));
                    drop(all);
                    node.msg.outbox_changed.notify_waiters();
                    Ok(())
                }
                None => bail!("no route to {}", body.to.short()),
            }
        })
    }

    fn next_hop(&self, to: &NodeId) -> Option<Hop> {
        let dial: HashMap<NodeId, String> = self
            .dial_targets()
            .into_iter()
            .map(|(id, _, addr)| (id, addr))
            .collect();
        let via = |id: &NodeId, fresh_only: bool| -> Option<Hop> {
            if let Some(addr) = dial.get(id)
                && (!fresh_only || self.status.reached_recently(id))
            {
                return Some(Hop::Dial(*id, addr.clone()));
            }
            self.status.polled_recently(id).then_some(Hop::Outbox(*id))
        };
        if let Some(h) = via(to, true) {
            return Some(h);
        }
        // Shortest path over the neighbour graph; first hop must be ours.
        let mut adj: HashMap<NodeId, HashSet<NodeId>> = HashMap::new();
        let mut link = |a: NodeId, b: NodeId| {
            adj.entry(a).or_default().insert(b);
            adj.entry(b).or_default().insert(a);
        };
        for n in self.status.neighbours() {
            link(self.id(), n);
        }
        for k in self.status.heartbeats.lock().unwrap().values() {
            for n in &k.hb.neighbours {
                link(k.hb.node, *n);
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
        if !self.is_member(&b.from) {
            return debug!(from = %b.from.short(), "message from non-member dropped");
        }
        let age = now_ms().saturating_sub(b.created_ms);
        if age > MAX_AGE.as_millis() as u64 {
            return debug!(from = %b.from.short(), "stale message dropped");
        }
        {
            let mut seen = self.msg.seen.lock().unwrap();
            seen.retain(|_, t| t.elapsed() < MAX_AGE * 2);
            if seen.insert(b.id.clone(), Instant::now()).is_some() {
                return; // duplicate
            }
        }
        if let Some(rid) = &b.in_reply_to {
            if let Some(tx) = self.msg.replies.lock().unwrap().remove(rid) {
                let _ = tx.send(b.msg);
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
                for mut env in envs {
                    env.hops = env.hops.saturating_add(1);
                    let n = node.clone();
                    tokio::spawn(async move {
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
