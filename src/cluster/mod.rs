//! Distributed mode: node identity, pinned-key mTLS RPC, peers.
pub mod cli;
pub mod identity;
pub mod rpc;
pub mod tls;

use crate::config::{ClusterConfig, Config, Roles};
use anyhow::{Context, Result, bail};
use identity::{Identity, NodeId};
use rpc::proto::{self, Hello};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::{info, warn};

/// How often configured peers are greeted.
const HELLO_INTERVAL: Duration = Duration::from_secs(30);

/// A known node and how to reach it.
#[derive(Debug, Clone)]
pub struct Member {
    pub id: NodeId,
    pub name: String,
    /// `host:port`; None for outbound-only nodes.
    pub address: Option<String>,
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
    /// Supported protocol range; constants except in tests.
    pub proto: (u32, u32),
    members: RwLock<Arc<HashMap<NodeId, Member>>>,
    clients: Mutex<HashMap<NodeId, reqwest::Client>>,
    pub status: RwLock<HashMap<NodeId, PeerStatus>>,
}

impl Node {
    /// Node for `cfg` (which must have a `[cluster]` section), creating the
    /// node key on first start.
    pub fn from_config(cfg: &Config) -> Result<Arc<Self>> {
        let Some(cc) = cfg.cluster.clone() else {
            bail!("no [cluster] section");
        };
        let identity = Identity::load_or_create(&cfg.node_key_path())?;
        Self::new(identity, cc, cfg.roles)
    }

    pub fn new(identity: Identity, cc: ClusterConfig, roles: Roles) -> Result<Arc<Self>> {
        Self::with_proto(
            identity,
            cc,
            roles,
            (proto::PROTO_MIN, proto::PROTO_VERSION),
        )
    }

    /// Like [`Node::new`] with an explicit protocol range (interop tests).
    pub fn with_proto(
        identity: Identity,
        cc: ClusterConfig,
        roles: Roles,
        proto: (u32, u32),
    ) -> Result<Arc<Self>> {
        let cert = tls::NodeCert::new(&identity)?;
        let mut members = HashMap::new();
        members.insert(
            identity.id,
            Member {
                id: identity.id,
                name: cc.node_name.clone(),
                address: cc.advertise.clone(),
            },
        );
        for p in &cc.peers {
            let id = NodeId::parse(&p.public_key)?;
            members.insert(
                id,
                Member {
                    id,
                    name: p.name.clone(),
                    address: Some(p.address.clone()),
                },
            );
        }
        Ok(Arc::new(Self {
            identity,
            cert,
            cfg: cc,
            roles,
            proto,
            members: RwLock::new(Arc::new(members)),
            clients: Mutex::new(HashMap::new()),
            status: RwLock::new(HashMap::new()),
        }))
    }

    pub fn id(&self) -> NodeId {
        self.identity.id
    }

    pub fn is_member(&self, id: &NodeId) -> bool {
        self.members.read().unwrap().contains_key(id)
    }

    pub fn members(&self) -> Arc<HashMap<NodeId, Member>> {
        self.members.read().unwrap().clone()
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

    /// POST a CBOR body to `peer` at `address` and decode the reply.
    pub async fn call<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        peer: NodeId,
        address: &str,
        path: &str,
        body: &Req,
    ) -> Result<(reqwest::StatusCode, Resp)> {
        let resp = self
            .client_for(peer)?
            .post(format!("https://{address}{path}"))
            .header(reqwest::header::CONTENT_TYPE, rpc::cbor::CONTENT_TYPE)
            .body(rpc::cbor::encode(body)?)
            .send()
            .await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if status == reqwest::StatusCode::FORBIDDEN {
            bail!("peer refused us: not a member on its side");
        }
        let decoded = rpc::cbor::decode(&bytes)
            .with_context(|| format!("{path}: HTTP {status}, undecodable body"))?;
        Ok((status, decoded))
    }

    /// Exchange `hello` with a peer; errors on protocol mismatch.
    pub async fn hello(&self, peer: NodeId, address: &str) -> Result<Hello> {
        let (status, theirs): (_, Hello) = self
            .call(peer, address, "/rpc/v1/hello", &self.local_hello())
            .await?;
        if status == reqwest::StatusCode::UPGRADE_REQUIRED
            || proto::negotiate(self.proto, (theirs.proto_min, theirs.proto_max)).is_none()
        {
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

    fn record_status(&self, peer: &Member, r: Result<Hello>) {
        let mut all = self.status.write().unwrap();
        let st = all.entry(peer.id).or_default();
        match r {
            Ok(h) => {
                if st.last_ok.is_none() || st.last_error.is_some() {
                    info!(peer = %peer.name, id = %peer.id.short(), version = %h.version, "peer reachable");
                }
                st.last_ok = Some(chrono::Utc::now());
                st.last_error = None;
                st.hello = Some(h);
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if st.last_error.as_deref() != Some(&msg) {
                    warn!(peer = %peer.name, id = %peer.id.short(), error = %msg, "peer unreachable");
                }
                st.last_error = Some(msg);
            }
        }
    }
}

/// Bind the RPC listener and start the peer loops. Returns the bound address.
pub async fn start(
    node: Arc<Node>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<std::net::SocketAddr> {
    let listener = tokio::net::TcpListener::bind(node.cfg.listen)
        .await
        .with_context(|| format!("binding cluster listener {}", node.cfg.listen))?;
    info!(
        addr = %node.cfg.listen,
        node = %node.cfg.node_name,
        id = %node.id(),
        "cluster rpc listener up"
    );
    let tls = tls::server_config(&node.cert)?;
    let addr = listener.local_addr()?;
    tokio::spawn(rpc::server::serve(
        listener,
        tls,
        rpc::router(node.clone()),
        shutdown.clone(),
    ));
    tokio::spawn(greet_peers(node, shutdown));
    Ok(addr)
}

/// Periodically greet every member with a known address.
async fn greet_peers(node: Arc<Node>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        let members = node.members();
        for m in members.values().filter(|m| m.id != node.id()) {
            if let Some(addr) = &m.address {
                let r = node.hello(m.id, addr).await;
                node.record_status(m, r);
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(HELLO_INTERVAL) => {}
            _ = shutdown.changed() => break,
        }
    }
}
