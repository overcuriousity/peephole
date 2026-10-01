//! Distributed mode: node identity, pinned-key mTLS RPC, replicated log,
//! membership.
pub mod adopt;
pub mod block;
pub mod cli;
pub mod confkey;
pub mod hlc;
pub mod identity;
pub mod invite;
pub mod members;
pub mod msg;
pub mod record;
pub mod repl;
pub mod rpc;
pub mod status;
pub mod sync;
pub mod tls;

use crate::config::{ClusterConfig, Config, Roles};
use crate::store::Store;
use anyhow::{Context, Result, bail};
use identity::{Identity, NodeId};
use members::MemberRow;
use record::{MemberInfo, Record};
use rpc::proto::{self, Hello};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::{info, warn};

/// Everything a [`Node`] is built from.
pub struct NodeParams {
    pub identity: Identity,
    pub cluster: ClusterConfig,
    pub roles: Roles,
    pub store: Store,
    /// Supported protocol range; constants except in interop tests.
    pub proto: (u32, u32),
    /// This node has MaxMind credentials (published in heartbeats).
    pub has_maxmind: bool,
    /// Where shared intel files live (served to peers).
    pub data_dir: std::path::PathBuf,
}

impl NodeParams {
    /// Parameters for `cfg` (which must have `[cluster]`), creating the node
    /// key on first start.
    pub fn from_config(cfg: &Config, store: Store) -> Result<Self> {
        let Some(cluster) = cfg.cluster.clone() else {
            bail!("no [cluster] section");
        };
        Ok(Self {
            identity: Identity::load_or_create(&cfg.node_key_path())?,
            cluster,
            roles: cfg.roles,
            store,
            proto: (proto::PROTO_MIN, proto::PROTO_VERSION),
            has_maxmind: cfg.maxmind.is_some(),
            data_dir: cfg.data_dir.clone(),
        })
    }
}

/// Why this node no longer takes part in its cluster. It keeps its copy of
/// the data and what it contributed stays in the cluster.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Detached {
    /// It left (`peephole cluster leave`).
    Left,
    /// It was offline for longer than the prune window.
    Pruned,
}

const DETACHED_KEY: &str = "cluster.detached";

impl Detached {
    fn as_str(&self) -> &'static str {
        match self {
            Detached::Left => "left",
            Detached::Pruned => "pruned",
        }
    }

    /// What the admin UI and CLI say about it.
    pub fn label(&self) -> &'static str {
        match self {
            Detached::Left => {
                "This node left its cluster and no longer syncs. Rejoin with an invite."
            }
            Detached::Pruned => {
                "This node was silent for more than 30 days and has been pruned from its cluster. Rejoin with an invite."
            }
        }
    }
}

impl Detached {
    /// The persisted state (CLI; the daemon caches it in [`Node::detached`]).
    pub async fn read(store: &Store) -> Result<Option<Detached>> {
        read_detached(store).await
    }
}

async fn read_detached(store: &Store) -> Result<Option<Detached>> {
    let v: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
        .bind(DETACHED_KEY)
        .fetch_optional(&store.pool)
        .await?;
    Ok(match v.as_deref() {
        Some("left") => Some(Detached::Left),
        Some("pruned") => Some(Detached::Pruned),
        _ => None,
    })
}

/// Persist (or clear) the detached state; the daemon picks it up within
/// seconds, also when the CLI wrote it.
pub async fn set_detached(store: &Store, d: Option<Detached>) -> Result<()> {
    match d {
        Some(d) => {
            sqlx::query(
                "INSERT INTO settings (key, value) VALUES (?, ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            )
            .bind(DETACHED_KEY)
            .bind(d.as_str())
            .execute(&store.pool)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM settings WHERE key = ?")
                .bind(DETACHED_KEY)
                .execute(&store.pool)
                .await?;
        }
    }
    Ok(())
}

/// Leave the cluster: announce it, hand the announcement to every peer we
/// can reach, then stop syncing. Returns how many peers were told.
pub async fn leave(node: &Node) -> Result<usize> {
    repl::append(node, &[Record::MemberRevoke { id: node.id() }]).await?;
    let mut told = 0;
    for (peer, _, addr) in node.dial_targets() {
        if sync::reconcile(node, peer, &addr, false).await.is_ok() {
            told += 1;
        }
    }
    if told == 0 {
        warn!("left the cluster without reaching a peer; it will prune this node after 30 days");
    }
    set_detached(&node.store, Some(Detached::Left)).await?;
    node.reload_members().await?;
    Ok(told)
}

/// Last contact with a peer, for logs and the admin UI.
#[derive(Debug, Clone, Default)]
pub struct PeerStatus {
    pub last_ok: Option<chrono::DateTime<chrono::Utc>>,
    pub last_error: Option<String>,
    pub hello: Option<Hello>,
}

pub struct Node {
    pub identity: Identity,
    pub cert: tls::NodeCert,
    pub cfg: ClusterConfig,
    roles: RwLock<Roles>,
    pub proto: (u32, u32),
    pub store: Store,
    pub hlc: hlc::Hlc,
    /// Active members (including this node), refreshed from the database.
    members: RwLock<Arc<HashMap<NodeId, MemberRow>>>,
    /// Set while this node is out of its cluster (left or pruned).
    detached: RwLock<Option<Detached>>,
    /// Every other member looks pruned to us: more likely we are the one
    /// that was cut off. They are then still dialled, to find out.
    isolated: std::sync::atomic::AtomicBool,
    /// Peers this node blocked (a local decision, see [`block`]).
    blocked: RwLock<Arc<std::collections::HashSet<NodeId>>>,
    /// The standing of every known node, members or not.
    standings: RwLock<Arc<HashMap<NodeId, members::Standing>>>,
    /// Addresses from `[[cluster.peers]]`, preferred over published ones.
    address_override: HashMap<NodeId, String>,
    clients: Mutex<HashMap<NodeId, reqwest::Client>>,
    pub peer_status: RwLock<HashMap<NodeId, PeerStatus>>,
    /// Serializes log writes (local appends and remote batches).
    pub apply_lock: tokio::sync::Mutex<()>,
    /// Bumped whenever the log grows; wakes sync loops and long-polls.
    changed: tokio::sync::watch::Sender<u64>,
    join_attempts: Mutex<std::collections::VecDeque<std::time::Instant>>,
    /// Wakes the sync supervisor when the set of dialable members changes.
    pub members_changed: tokio::sync::Notify,
    pub has_maxmind: bool,
    pub data_dir: std::path::PathBuf,
    /// Contacts and heartbeats (ephemeral).
    pub status: status::Status,
    pub msg: msg::Messaging,
    pub started: std::time::Instant,
    /// Uids of scan jobs whose row changed (any origin), for the live queue.
    pub job_events: tokio::sync::broadcast::Sender<String>,
    /// Highest sequence this node has written to its own log.
    pub own_head: std::sync::atomic::AtomicU64,
}

impl Node {
    pub async fn open(p: NodeParams) -> Result<Arc<Self>> {
        let cert = tls::NodeCert::new(&p.identity)?;
        let mut address_override = HashMap::new();
        for peer in &p.cluster.peers {
            address_override.insert(NodeId::parse(&peer.public_key)?, peer.address.clone());
        }
        let node = Arc::new(Self {
            identity: p.identity,
            cert,
            cfg: p.cluster,
            roles: RwLock::new(p.roles),
            proto: p.proto,
            store: p.store,
            hlc: hlc::Hlc::new(),
            members: RwLock::new(Arc::new(HashMap::new())),
            detached: RwLock::new(None),
            isolated: Default::default(),
            blocked: RwLock::new(Arc::new(Default::default())),
            standings: RwLock::new(Arc::new(HashMap::new())),
            address_override,
            clients: Mutex::new(HashMap::new()),
            peer_status: RwLock::new(HashMap::new()),
            apply_lock: tokio::sync::Mutex::new(()),
            changed: tokio::sync::watch::channel(0).0,
            join_attempts: Mutex::new(Default::default()),
            members_changed: tokio::sync::Notify::new(),
            has_maxmind: p.has_maxmind,
            data_dir: p.data_dir,
            status: Default::default(),
            msg: Default::default(),
            started: std::time::Instant::now(),
            job_events: tokio::sync::broadcast::channel(256).0,
            own_head: Default::default(),
        });
        // Our clock must not run behind anything already in the log.
        let max_hlc: Option<i64> = sqlx::query_scalar("SELECT MAX(hlc) FROM repl_log")
            .fetch_one(&node.store.pool)
            .await?;
        node.hlc.observe(max_hlc.unwrap_or(0) as u64);
        node.reload_members().await?;
        // Offline for longer than the prune window: the cluster dropped us,
        // and our log is too old to judge anyone else by.
        if node.detached().is_none()
            && let Some(last) = node.own_last_hlc().await?
            && hlc::wall_ms().saturating_sub(hlc::physical_ms(last)) > members::PRUNE_AFTER_MS
            && node.standings.read().unwrap().len() > 1
        {
            warn!(
                "no entry of our own for over 30 days: pruned from the cluster; rejoin with an invite"
            );
            set_detached(&node.store, Some(Detached::Pruned)).await?;
            node.reload_members().await?;
        }
        let n = repl::apply_unknown_kinds(&node).await?;
        if n > 0 {
            info!(n, "applied log entries from a newer protocol");
        }
        Ok(node)
    }

    pub fn id(&self) -> NodeId {
        self.identity.id
    }

    /// The roles this node runs right now.
    pub fn roles(&self) -> Roles {
        *self.roles.read().unwrap()
    }

    /// Adopt new roles and tell the cluster (member info and heartbeat).
    pub async fn set_roles(&self, r: Roles) -> Result<()> {
        if self.roles() == r {
            return Ok(());
        }
        let before = std::mem::replace(&mut *self.roles.write().unwrap(), r);
        if let Err(e) = repl::append(self, &[Record::MemberUpdate(self.self_info())]).await {
            // Not announced: try again on the next call.
            *self.roles.write().unwrap() = before;
            return Err(e);
        }
        self.publish_status();
        Ok(())
    }

    /// How this node describes itself to the cluster.
    pub fn self_info(&self) -> MemberInfo {
        MemberInfo {
            id: self.id(),
            name: self.cfg.node_name.clone(),
            address: self.cfg.advertise.clone(),
            roles: self
                .roles()
                .names()
                .into_iter()
                .map(str::to_string)
                .collect(),
            proto_min: self.proto.0,
            proto_max: self.proto.1,
            remote_config: self.cfg.remote_config,
        }
    }

    /// Publish our own description and vouch for configured peers.
    /// Configured peers are only added when never seen before, so a
    /// revocation is not undone by a config that still lists the peer.
    pub async fn bootstrap(&self) -> Result<()> {
        let all = members::all(&self.store).await?;
        let mine = self.self_info();
        let current = all.iter().find(|m| m.id == self.id());
        let up_to_date = current.is_some_and(|m| {
            m.info_hlc > 0
                && m.name == mine.name
                && m.address == mine.address
                && m.roles == mine.roles
                && m.remote_config == mine.remote_config
                && (m.proto_min, m.proto_max) == (mine.proto_min, mine.proto_max)
        });
        let mut records = vec![];
        if !up_to_date {
            records.push(Record::MemberUpdate(mine));
        }
        for p in &self.cfg.peers {
            let id = NodeId::parse(&p.public_key)?;
            match all.iter().find(|m| m.id == id) {
                None => records.push(Record::MemberAdd(MemberInfo {
                    id,
                    name: p.name.clone(),
                    address: Some(p.address.clone()),
                    roles: vec![],
                    proto_min: 0,
                    proto_max: 0,
                    remote_config: false,
                })),
                Some(m) if !m.active => warn!(
                    peer = %p.name,
                    "configured peer is revoked; remove it from [[cluster.peers]]"
                ),
                Some(_) => {}
            }
        }
        if !records.is_empty() {
            repl::append(self, &records).await?;
        }
        Ok(())
    }

    pub fn detached(&self) -> Option<Detached> {
        *self.detached.read().unwrap()
    }

    /// Whether every other member looks pruned from here (see `isolated`).
    pub fn isolated(&self) -> bool {
        self.isolated.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether this node blocked `id` (a local decision, see [`block`]).
    pub fn is_blocked(&self, id: &NodeId) -> bool {
        self.blocked.read().unwrap().contains(id)
    }

    /// The standing of any known node, member or not.
    pub fn standing_of(&self, id: &NodeId) -> Option<members::Standing> {
        self.standings.read().unwrap().get(id).copied()
    }

    /// HLC of the newest entry this node wrote, if any.
    async fn own_last_hlc(&self) -> Result<Option<u64>> {
        let h: Option<i64> = sqlx::query_scalar(
            "SELECT hlc FROM repl_log WHERE origin = ? ORDER BY seq DESC LIMIT 1",
        )
        .bind(&self.id().0[..])
        .fetch_optional(&self.store.pool)
        .await?;
        Ok(h.map(|h| h as u64))
    }

    /// Write a sign of life when this node has been quiet for a day, so the
    /// cluster does not prune a node that merely has nothing to record.
    /// Returns whether an entry was written.
    pub async fn keepalive(&self) -> Result<bool> {
        if self.detached().is_some() {
            return Ok(false);
        }
        let last = self.own_last_hlc().await?.map_or(0, hlc::physical_ms);
        if hlc::wall_ms().saturating_sub(last) < members::KEEPALIVE_MS {
            return Ok(false);
        }
        repl::append(self, &[Record::MemberUpdate(self.self_info())]).await?;
        Ok(true)
    }

    pub async fn reload_members(&self) -> Result<()> {
        let rows = members::all(&self.store).await?;
        let detached = read_detached(&self.store).await?;
        let blocked: std::collections::HashSet<NodeId> =
            block::list(&self.store).await?.into_iter().collect();
        let standings: HashMap<_, _> = rows.iter().map(|m| (m.id, m.standing)).collect();
        // When nobody else is active but some were pruned, we were probably
        // the one out of touch: keep treating them as members, so contact
        // can resume or they can tell us that we were pruned.
        let me = self.identity.id;
        let others = |s: members::Standing| {
            rows.iter()
                .filter(|m| m.id != me && m.standing == s)
                .count()
        };
        let isolated =
            others(members::Standing::Active) == 0 && others(members::Standing::Pruned) > 0;
        self.isolated
            .store(isolated, std::sync::atomic::Ordering::Relaxed);
        let map: HashMap<_, _> = rows
            .into_iter()
            .filter(|m| {
                m.active || m.id == me || (isolated && m.standing == members::Standing::Pruned)
            })
            .map(|m| (m.id, m))
            .collect();
        let before = self.dial_targets();
        *self.members.write().unwrap() = Arc::new(map);
        *self.detached.write().unwrap() = detached;
        *self.blocked.write().unwrap() = Arc::new(blocked);
        *self.standings.write().unwrap() = Arc::new(standings);
        if self.dial_targets() != before {
            self.members_changed.notify_one();
        }
        Ok(())
    }

    /// Whether `id` may use the RPC API (an active member, or this node).
    pub fn is_member(&self, id: &NodeId) -> bool {
        *id == self.id() || self.members.read().unwrap().contains_key(id)
    }

    pub fn members(&self) -> Arc<HashMap<NodeId, MemberRow>> {
        self.members.read().unwrap().clone()
    }

    /// Active members we can dial: `(id, name, address)`. None while this
    /// node is detached from its cluster.
    pub fn dial_targets(&self) -> Vec<(NodeId, String, String)> {
        if self.detached().is_some() {
            return vec![];
        }
        let mut v: Vec<_> = self
            .members()
            .values()
            .filter(|m| m.id != self.id() && !self.is_blocked(&m.id))
            .filter_map(|m| {
                let addr = self
                    .address_override
                    .get(&m.id)
                    .cloned()
                    .or_else(|| m.address.clone())?;
                Some((m.id, m.name.clone(), addr))
            })
            .collect();
        v.sort_by_key(|t| t.0);
        v
    }

    pub fn notify_changed(&self) {
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub fn subscribe_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// Allow at most 10 join attempts per minute (invite secrets are 256-bit,
    /// this only keeps junk traffic cheap).
    pub fn join_allowed(&self) -> bool {
        let mut q = self.join_attempts.lock().unwrap();
        let now = std::time::Instant::now();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            q.pop_front();
        }
        if q.len() >= 10 {
            return false;
        }
        q.push_back(now);
        true
    }

    pub fn local_hello(&self) -> Hello {
        Hello {
            proto_min: self.proto.0,
            proto_max: self.proto.1,
            node_name: self.cfg.node_name.clone(),
            version: crate::VERSION.to_string(),
            roles: self
                .roles()
                .names()
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }

    /// HTTP client that only talks to `peer` (its key is pinned in TLS).
    pub fn client_for(&self, peer: NodeId) -> Result<reqwest::Client> {
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients.get(&peer) {
            return Ok(c.clone());
        }
        let c = reqwest::Client::builder()
            .tls_backend_preconfigured(tls::client_config(&self.cert, peer)?)
            // Node traffic goes direct; an HTTP proxy cannot carry pinned mTLS.
            .no_proxy()
            .https_only(true)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .build()
            .context("rpc client")?;
        clients.insert(peer, c.clone());
        Ok(c)
    }

    /// POST a CBOR body; returns the status and raw reply.
    pub async fn call_raw<Req: serde::Serialize>(
        &self,
        peer: NodeId,
        address: &str,
        path: &str,
        body: &Req,
    ) -> Result<(reqwest::StatusCode, Vec<u8>)> {
        let resp = self
            .client_for(peer)?
            .post(format!("https://{address}{path}"))
            .header(reqwest::header::CONTENT_TYPE, rpc::cbor::CONTENT_TYPE)
            .body(rpc::cbor::encode(body)?)
            .send()
            .await?;
        let status = resp.status();
        Ok((status, resp.bytes().await?.to_vec()))
    }

    /// POST a CBOR body and decode a successful reply; errors carry the
    /// peer's message otherwise.
    pub async fn call<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        peer: NodeId,
        address: &str,
        path: &str,
        body: &Req,
    ) -> Result<Resp> {
        let (status, bytes) = self.call_raw(peer, address, path, body).await?;
        if !status.is_success() {
            bail!(
                "{path}: HTTP {status}: {}",
                String::from_utf8_lossy(&bytes[..bytes.len().min(300)])
            );
        }
        rpc::cbor::decode(&bytes).with_context(|| format!("{path}: undecodable reply"))
    }

    /// Exchange `hello` with a peer; errors on protocol mismatch.
    pub async fn hello(&self, peer: NodeId, address: &str) -> Result<Hello> {
        let (status, bytes) = self
            .call_raw(peer, address, "/rpc/v1/hello", &self.local_hello())
            .await?;
        if !status.is_success() && status != reqwest::StatusCode::UPGRADE_REQUIRED {
            bail!(
                "hello: HTTP {status}: {}",
                String::from_utf8_lossy(&bytes[..bytes.len().min(300)])
            );
        }
        let theirs: Hello = rpc::cbor::decode(&bytes).context("hello: undecodable reply")?;
        if proto::negotiate(self.proto, (theirs.proto_min, theirs.proto_max)).is_none() {
            bail!(
                "incompatible protocol: we speak {}..={}, peer `{}` ({}) speaks {}..={}",
                self.proto.0,
                self.proto.1,
                theirs.node_name,
                theirs.version,
                theirs.proto_min,
                theirs.proto_max
            );
        }
        Ok(theirs)
    }

    /// Remember the outcome of contacting a peer (memory + database).
    pub async fn record_status(&self, peer: NodeId, name: &str, r: Result<Option<Hello>, String>) {
        let changed = {
            if r.is_ok() {
                self.status.touch_outbound(peer);
            }
            let mut all = self.peer_status.write().unwrap();
            let st = all.entry(peer).or_default();
            match r {
                Ok(h) => {
                    let was_down = st.last_ok.is_none() || st.last_error.is_some();
                    if was_down {
                        info!(peer = %name, id = %peer.short(), "peer reachable");
                    }
                    let stale = st
                        .last_ok
                        .is_none_or(|t| chrono::Utc::now() - t > chrono::Duration::seconds(60));
                    st.last_ok = Some(chrono::Utc::now());
                    st.last_error = None;
                    if h.is_some() {
                        st.hello = h;
                    }
                    was_down || stale
                }
                Err(msg) => {
                    let new = st.last_error.as_deref() != Some(&msg);
                    if new {
                        warn!(peer = %name, id = %peer.short(), error = %msg, "peer unreachable");
                    }
                    st.last_error = Some(msg);
                    new
                }
            }
        };
        if changed {
            let st = self
                .peer_status
                .read()
                .unwrap()
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            let _ = sqlx::query(
                "INSERT INTO peer_contact (id, last_ok, last_error, error_at, version)
                 VALUES (?, ?, ?, CASE WHEN ? IS NULL THEN NULL ELSE datetime('now') END, ?)
                 ON CONFLICT(id) DO UPDATE SET
                   last_ok = COALESCE(excluded.last_ok, peer_contact.last_ok),
                   last_error = excluded.last_error,
                   error_at = COALESCE(excluded.error_at, peer_contact.error_at),
                   version = COALESCE(excluded.version, peer_contact.version)",
            )
            .bind(&peer.0[..])
            .bind(st.last_ok.map(|t| t.to_rfc3339()))
            .bind(&st.last_error)
            .bind(&st.last_error)
            .bind(st.hello.as_ref().map(|h| h.version.clone()))
            .execute(&self.store.pool)
            .await;
        }
    }
}

/// Bind the RPC listener and start the sync loops. Returns the bound address.
pub async fn start(
    node: Arc<Node>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<std::net::SocketAddr> {
    node.bootstrap().await?;
    let listener = tokio::net::TcpListener::bind(node.cfg.listen)
        .await
        .with_context(|| format!("binding cluster listener {}", node.cfg.listen))?;
    let addr = listener.local_addr()?;
    info!(
        %addr,
        node = %node.cfg.node_name,
        id = %node.id(),
        "cluster rpc listener up"
    );
    let tls = tls::server_config(&node.cert)?;
    tokio::spawn(rpc::server::serve(
        listener,
        tls,
        rpc::router(node.clone()),
        shutdown.clone(),
    ));
    tokio::spawn(heartbeat_loop(node.clone(), shutdown.clone()));
    tokio::spawn(sync::supervise(node, shutdown));
    Ok(addr)
}

/// Refresh our heartbeat periodically; gossip carries it to the cluster.
async fn heartbeat_loop(node: Arc<Node>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        if let Ok(h) = repl::heads(&node.store).await {
            node.own_head.store(
                repl::head_in(&h, &node.id()),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        node.refresh_heartbeat();
        if let Err(e) = node.keepalive().await {
            warn!(?e, "keepalive failed");
        }
        tokio::select! {
            _ = tokio::time::sleep(status::HEARTBEAT_EVERY) => {}
            _ = shutdown.changed() => break,
        }
    }
}
