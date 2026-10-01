//! Distributed mode: node identity, pinned-key mTLS RPC, replicated log,
//! membership.
pub mod adopt;
pub mod cli;
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
    /// This node's `scan.never_scan`, published to the cluster.
    pub never_scan: Vec<String>,
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
            never_scan: cfg.scan.never_scan.iter().map(|n| n.to_string()).collect(),
            store,
            proto: (proto::PROTO_MIN, proto::PROTO_VERSION),
            has_maxmind: cfg.maxmind.is_some(),
            data_dir: cfg.data_dir.clone(),
        })
    }
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
    pub roles: Roles,
    pub never_scan: Vec<String>,
    pub proto: (u32, u32),
    pub store: Store,
    pub hlc: hlc::Hlc,
    /// Active members (including this node), refreshed from the database.
    members: RwLock<Arc<HashMap<NodeId, MemberRow>>>,
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
            roles: p.roles,
            never_scan: p.never_scan,
            proto: p.proto,
            store: p.store,
            hlc: hlc::Hlc::new(),
            members: RwLock::new(Arc::new(HashMap::new())),
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
        let n = repl::apply_unknown_kinds(&node).await?;
        if n > 0 {
            info!(n, "applied log entries from a newer protocol");
        }
        Ok(node)
    }

    pub fn id(&self) -> NodeId {
        self.identity.id
    }

    /// How this node describes itself to the cluster.
    pub fn self_info(&self) -> MemberInfo {
        MemberInfo {
            id: self.id(),
            name: self.cfg.node_name.clone(),
            address: self.cfg.advertise.clone(),
            roles: self.roles.names().into_iter().map(str::to_string).collect(),
            never_scan: self.never_scan.clone(),
            proto_min: self.proto.0,
            proto_max: self.proto.1,
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
                && m.never_scan == mine.never_scan
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
                    never_scan: vec![],
                    proto_min: 0,
                    proto_max: 0,
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

    pub async fn reload_members(&self) -> Result<()> {
        let rows = members::all(&self.store).await?;
        let map: HashMap<_, _> = rows
            .into_iter()
            .filter(|m| m.active || m.id == self.identity.id)
            .map(|m| (m.id, m))
            .collect();
        let before = self.dial_targets();
        *self.members.write().unwrap() = Arc::new(map);
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

    /// Active members we can dial: `(id, name, address)`.
    pub fn dial_targets(&self) -> Vec<(NodeId, String, String)> {
        let mut v: Vec<_> = self
            .members()
            .values()
            .filter(|m| m.id != self.id())
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
            roles: self.roles.names().into_iter().map(str::to_string).collect(),
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
        tokio::select! {
            _ = tokio::time::sleep(status::HEARTBEAT_EVERY) => {}
            _ = shutdown.changed() => break,
        }
    }
}
