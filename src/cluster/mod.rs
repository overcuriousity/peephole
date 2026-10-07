//! Distributed mode: node identity, pinned-key mTLS RPC, replicated log,
//! membership.
pub mod adopt;
pub mod block;
pub mod cli;
pub mod history;
pub mod hlc;
pub mod identity;
pub mod invite;
pub mod members;
pub mod msg;
pub mod owner;
pub mod record;
pub mod remote;
pub mod repl;
pub mod rpc;
pub mod seal;
pub mod status;
pub mod sync;
pub mod tls;
pub mod traffic;

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
    /// Where shared intel files live (served to peers).
    pub data_dir: std::path::PathBuf,
    /// Days of history this node keeps (top-level `retention_days`); 0: all.
    pub retention_days: u32,
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
            data_dir: cfg.data_dir.clone(),
            retention_days: cfg.retention_days,
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

/// Leave the cluster: revoke our invites, announce it, hand the
/// announcement to every peer we can reach, then stop syncing. Returns how
/// many peers were told.
pub async fn leave(node: &Node) -> Result<usize> {
    // A node that left admits nobody: an invite given out before must not
    // let anyone in on its word afterwards.
    invite::revoke_all(&node.store).await?;
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

/// Largest RPC reply this node reads (the server's body limit plus room for
/// a batch at its byte budget).
pub const MAX_REPLY: usize = 80 * 1024 * 1024;

/// Join attempts in the last minute, per source.
#[derive(Default)]
pub struct JoinAttempts {
    all: std::collections::VecDeque<std::time::Instant>,
    by_source: HashMap<String, std::collections::VecDeque<std::time::Instant>>,
}

impl JoinAttempts {
    /// Per address (IPv6: per /64) and per key a few attempts a minute; 60
    /// a minute in total.
    const PER_ADDRESS: usize = 10;
    const PER_KEY: usize = 5;
    const TOTAL: usize = 60;

    fn allow(&mut self, peer: NodeId, ip: std::net::IpAddr, now: std::time::Instant) -> bool {
        let fresh = |q: &mut std::collections::VecDeque<std::time::Instant>| {
            while q
                .front()
                .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
            {
                q.pop_front();
            }
        };
        fresh(&mut self.all);
        self.by_source.retain(|_, q| {
            fresh(q);
            !q.is_empty()
        });
        let net = match crate::net::canonical(ip) {
            std::net::IpAddr::V6(v6) => {
                let s = v6.segments();
                format!("ip:{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
            v4 => format!("ip:{v4}"),
        };
        let sources = [
            (net, Self::PER_ADDRESS),
            (format!("key:{peer}"), Self::PER_KEY),
        ];
        if self.all.len() >= Self::TOTAL
            || sources
                .iter()
                .any(|(k, limit)| self.by_source.get(k).is_some_and(|q| q.len() >= *limit))
        {
            return false;
        }
        self.all.push_back(now);
        for (k, _) in sources {
            self.by_source.entry(k).or_default().push_back(now);
        }
        true
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
    /// Owner commands and key rotations, each one at a time.
    pub owner_locks: owner::Locks,
    /// How members' requests compare with this node's rules (the credits
    /// gate and the cluster pages).
    pub rules_check: crate::store::stats::SwrCache<(), crate::credits::gates::RulesCheck>,
    /// This node's book of credits, as last computed.
    pub credits_book: Mutex<Option<(std::time::Instant, Arc<crate::credits::Book>)>>,
    /// Bumped whenever the log grows; wakes sync loops and long-polls.
    changed: tokio::sync::watch::Sender<u64>,
    join_attempts: Mutex<JoinAttempts>,
    /// Sync exchanges running at once (see `sync::MAX_CONCURRENT_SYNCS`).
    pub sync_slots: tokio::sync::Semaphore,
    /// Directed messages being routed at once (see `msg`).
    pub route_slots: Arc<tokio::sync::Semaphore>,
    /// Wakes the sync supervisor when the set of dialable members changes.
    pub members_changed: tokio::sync::Notify,
    /// Enrichment providers this node can query right now (heartbeats).
    providers: RwLock<Vec<String>>,
    /// This node's provider objects, for on-demand lookups members ask for.
    lookup_providers: std::sync::OnceLock<crate::intel::Providers>,
    /// The on-demand share of each provider budget (see `credits::share`).
    lookup_shares: std::sync::OnceLock<crate::credits::share::Shares>,
    /// This node's lookup prices, as last computed (`credits::price`).
    price_table: RwLock<Arc<crate::credits::price::Table>>,
    /// The fleet node this node forwards its credits to and draws from
    /// (the runtime setting `credits.collect_to`).
    pub collect_to: RwLock<Option<NodeId>>,
    /// Free lookups served per asking member in the last hour.
    free_lookups: Mutex<HashMap<NodeId, std::collections::VecDeque<std::time::Instant>>>,
    /// Offers a paid lookup is being served for right now: `(payer,
    /// sequence number)`. An offer is served once.
    pub(crate) serving_offers: Mutex<std::collections::HashSet<(NodeId, u64)>>,
    pub data_dir: std::path::PathBuf,
    /// Contacts and heartbeats (ephemeral).
    pub status: status::Status,
    pub msg: msg::Messaging,
    pub started: std::time::Instant,
    /// Uids of scan jobs whose row changed (any origin), for the live queue.
    pub job_events: tokio::sync::broadcast::Sender<String>,
    /// Highest sequence this node has written to its own log.
    pub own_head: std::sync::atomic::AtomicU64,
    /// Days of history this node keeps; 0: everything (see [`history`]).
    pub retention_days: u32,
    /// This node's floors above 1, as last read (for heartbeats).
    pub own_floors: RwLock<history::Floors>,
    /// Sync rounds run, with any peer (status and tests).
    pub sync_rounds: std::sync::atomic::AtomicU64,
    /// What replication moved per peer, for the journal.
    pub traffic: traffic::Traffic,
    /// The furthest any peer is known to hold this node's own log (from
    /// sync rounds since start). A windowed node never drops its own
    /// entries beyond it: they may be the only copy.
    pub own_acked: std::sync::atomic::AtomicU64,
    /// Per peer: origins we lack that its history does not reach back to,
    /// as of the last round (a full node waits for a full member).
    pub unserved: Mutex<HashMap<NodeId, Vec<NodeId>>>,
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
            owner_locks: Default::default(),
            rules_check: crate::store::stats::SwrCache::new(1),
            credits_book: Mutex::new(None),
            changed: tokio::sync::watch::channel(0).0,
            join_attempts: Mutex::new(Default::default()),
            sync_slots: tokio::sync::Semaphore::new(sync::MAX_CONCURRENT_SYNCS),
            route_slots: Arc::new(tokio::sync::Semaphore::new(msg::MAX_ROUTING)),
            members_changed: tokio::sync::Notify::new(),
            providers: RwLock::new(vec![]),
            lookup_providers: Default::default(),
            lookup_shares: Default::default(),
            price_table: Default::default(),
            collect_to: RwLock::new(None),
            free_lookups: Mutex::new(HashMap::new()),
            serving_offers: Mutex::new(Default::default()),
            data_dir: p.data_dir,
            status: Default::default(),
            msg: Default::default(),
            started: std::time::Instant::now(),
            job_events: tokio::sync::broadcast::channel(256).0,
            own_head: Default::default(),
            retention_days: p.retention_days,
            own_floors: Default::default(),
            sync_rounds: Default::default(),
            traffic: Default::default(),
            unserved: Default::default(),
            own_acked: Default::default(),
        });
        // Our clock must not run behind anything already in the log, and
        // never behind our own entries: peers ignore an entry of ours that
        // is not later than the one before (see `repl`), also after the
        // wall clock was set back.
        let max_hlc: Option<i64> = sqlx::query_scalar("SELECT MAX(hlc) FROM repl_log")
            .fetch_one(&node.store.pool)
            .await?;
        node.hlc.observe(hlc::from_db(max_hlc.unwrap_or(0)));
        if let Some(own) = node.own_last_hlc().await? {
            if hlc::ahead(own, hlc::wall_ms()) {
                warn!("our last log entry is dated ahead of the clock; ours stay later than it");
            }
            node.hlc.observe_own(own);
        }
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
            // Config keys are gone; the field stays for records of earlier versions.
            remote_config: false,
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

    /// The provider objects on-demand lookups from members are served
    /// with; set once at startup.
    pub fn set_lookup_providers(&self, p: crate::intel::Providers) {
        let _ = self.lookup_providers.set(p);
    }

    pub fn lookup_providers(&self) -> Option<&crate::intel::Providers> {
        self.lookup_providers.get()
    }

    pub fn set_lookup_shares(&self, s: crate::credits::share::Shares) {
        let _ = self.lookup_shares.set(s);
    }

    pub fn lookup_shares(&self) -> Option<&crate::credits::share::Shares> {
        self.lookup_shares.get()
    }

    pub fn price_table(&self) -> Arc<crate::credits::price::Table> {
        self.price_table.read().unwrap().clone()
    }

    /// Adopt new prices and announce them with the next heartbeat.
    pub fn set_price_table(&self, t: Arc<crate::credits::price::Table>) {
        *self.price_table.write().unwrap() = t;
        self.publish_status();
    }

    /// Count one free lookup for `peer`; false when it had
    /// [`crate::credits::pay::FREE_PER_HOUR`] in the last hour.
    pub fn take_free_lookup(&self, peer: NodeId) -> bool {
        let hour = Duration::from_secs(3600);
        let mut all = self.free_lookups.lock().unwrap();
        all.retain(|_, q| q.back().is_some_and(|t| t.elapsed() < hour));
        let q = all.entry(peer).or_default();
        while q.front().is_some_and(|t| t.elapsed() >= hour) {
            q.pop_front();
        }
        if q.len() >= crate::credits::pay::FREE_PER_HOUR {
            return false;
        }
        q.push_back(std::time::Instant::now());
        true
    }

    /// The address this node would dial `id` at, if it has one.
    pub fn dial_address(&self, id: &NodeId) -> Option<String> {
        self.dial_targets()
            .into_iter()
            .find(|(peer, _, _)| peer == id)
            .map(|(_, _, addr)| addr)
    }

    /// Enrichment providers this node can query right now.
    pub fn providers(&self) -> Vec<String> {
        self.providers.read().unwrap().clone()
    }

    pub fn set_providers(&self, p: Vec<String>) {
        if *self.providers.read().unwrap() != p {
            *self.providers.write().unwrap() = p;
            self.publish_status();
        }
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

    /// Whether this node keeps only a window of the history.
    pub fn windowed(&self) -> bool {
        self.retention_days > 0
    }

    /// Where this node's window starts (HLC); 0 when it keeps everything.
    pub fn since_hlc(&self) -> u64 {
        match self.retention_days {
            0 => 0,
            d => history::window_hlc(d, hlc::wall_ms()),
        }
    }

    /// Where `peer`'s history of `origin` starts, as its heartbeat says
    /// (1 when it has not said otherwise).
    pub fn peer_floor(&self, peer: &NodeId, origin: &NodeId) -> u64 {
        self.status
            .known(peer)
            .and_then(|k| k.hb.floors.iter().find(|(o, _)| o == origin).map(|f| f.1))
            .unwrap_or(1)
    }

    /// Where `peer`'s window starts (HLC); 0 when it keeps everything or has
    /// not said.
    pub fn peer_since_hlc(&self, peer: &NodeId) -> u64 {
        match self.status.known(peer).map_or(0, |k| k.hb.retention_days) {
            0 => 0,
            d => history::window_hlc(d, hlc::wall_ms()),
        }
    }

    /// Origins this node lacks history of that no peer it reached could
    /// serve (a node keeping everything, or a windowed one waiting for a
    /// member that holds more of it).
    pub fn unserved_origins(&self) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self
            .unserved
            .lock()
            .unwrap()
            .values()
            .flatten()
            .copied()
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// The origins `peer` could not serve this node in the last round.
    pub fn unserved_from(&self, peer: &NodeId) -> Vec<NodeId> {
        self.unserved
            .lock()
            .unwrap()
            .get(peer)
            .cloned()
            .unwrap_or_default()
    }

    /// Whether a member other than `peer` that keeps at least this node's
    /// window (or everything) was heard from recently and, by its heartbeat,
    /// holds `origin` from right after `head` (what this node holds) on: a
    /// windowed node then fetches that origin from it rather than start at
    /// `peer`'s floor. A member whose floor lies past `head` too (equal
    /// windows) would only make it wait forever.
    pub fn keeps_more_elsewhere(&self, peer: &NodeId, origin: &NodeId, head: u64) -> bool {
        let mine = self.retention_days;
        self.members().keys().any(|id| {
            *id != self.id()
                && id != peer
                && self.status.known(id).is_some_and(|k| {
                    k.advanced.elapsed() < status::NEIGHBOUR_WINDOW
                        && (k.hb.retention_days == 0 || k.hb.retention_days >= mine)
                })
                && history::servable(self.peer_floor(id, origin), head, false)
        })
    }

    /// Re-read this node's floors (after a prune, for the heartbeat).
    pub async fn reload_floors(&self) -> Result<()> {
        let mut conn = self.store.pool.acquire().await?;
        let f = history::floors(&mut conn).await?;
        *self.own_floors.write().unwrap() = f;
        Ok(())
    }

    /// HLC of the newest entry this node wrote, if any.
    async fn own_last_hlc(&self) -> Result<Option<u64>> {
        let h: Option<i64> = sqlx::query_scalar(
            "SELECT hlc FROM repl_log WHERE origin = ? ORDER BY seq DESC LIMIT 1",
        )
        .bind(&self.id().0[..])
        .fetch_optional(&self.store.pool)
        .await?;
        Ok(h.map(hlc::from_db))
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
        self.status.retain_heartbeats(|id| self.is_member(id));
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

    /// Whether a join attempt from `peer` at `ip` may proceed. Invite
    /// secrets are 256-bit; the limits only keep junk traffic cheap. They
    /// apply per address (an IPv6 /64 counts as one) and per key, plus a
    /// generous global cap, so one source cannot use up everybody's
    /// attempts.
    pub fn join_allowed(&self, peer: NodeId, ip: std::net::IpAddr) -> bool {
        self.join_attempts
            .lock()
            .unwrap()
            .allow(peer, ip, std::time::Instant::now())
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
            seen_from: None,
        }
    }

    /// This node's public addresses as its peers see them (see
    /// [`status::Status::public_addresses`]).
    pub fn public_addrs(&self) -> Vec<std::net::IpAddr> {
        self.status.public_addresses()
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

    /// POST a CBOR body; returns the status and raw reply. Replies larger
    /// than [`MAX_REPLY`] are refused, whatever the peer sends.
    pub async fn call_raw<Req: serde::Serialize>(
        &self,
        peer: NodeId,
        address: &str,
        path: &str,
        body: &Req,
    ) -> Result<(reqwest::StatusCode, Vec<u8>)> {
        let mut resp = self
            .client_for(peer)?
            .post(format!("https://{address}{path}"))
            .header(reqwest::header::CONTENT_TYPE, rpc::cbor::CONTENT_TYPE)
            .body(rpc::cbor::encode(body)?)
            .send()
            .await?;
        let status = resp.status();
        if resp.content_length().is_some_and(|n| n > MAX_REPLY as u64) {
            bail!("{path}: reply larger than {MAX_REPLY} bytes");
        }
        let mut out = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if out.len() + chunk.len() > MAX_REPLY {
                bail!("{path}: reply larger than {MAX_REPLY} bytes");
            }
            out.extend_from_slice(&chunk);
        }
        Ok((status, out))
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
        node.clone(),
        shutdown.clone(),
    ));
    tokio::spawn(heartbeat_loop(node.clone(), shutdown.clone()));
    tokio::spawn(maintenance_loop(node.clone(), shutdown.clone()));
    tokio::spawn(sync::supervise(node, shutdown));
    Ok(addr)
}

/// Housekeeping: retry deferred entries whose time has come (every
/// minute), expire parked entries of unknown nodes and compact (hourly),
/// drop history outside this node's window (daily).
async fn maintenance_loop(node: Arc<Node>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut tick: u64 = 0;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            _ = shutdown.changed() => break,
        }
        tick += 1;
        if let Err(e) = repl::retry_due(&node).await {
            warn!(?e, "retrying deferred entries failed");
        }
        if tick % 60 == 1 {
            if let Err(e) = repl::expire_parked(&node).await {
                warn!(?e, "expiring parked entries failed");
            }
            if let Err(e) = repl::compact(&node).await {
                warn!(?e, "log compaction failed");
            }
        }
        // Five minutes after start, then daily: drop history outside this
        // node's window (a no-op when it keeps everything).
        if node.windowed() && tick % (24 * 60) == 5 {
            if let Err(e) = history::prune(&node).await {
                warn!(?e, "dropping old history failed");
            }
            if let Err(e) = node.reload_floors().await {
                warn!(?e, "reading history floors failed");
            }
        }
    }
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
        if let Err(e) = node.reload_floors().await {
            warn!(?e, "reading history floors failed");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_attempts_are_limited_per_source_not_globally_first() {
        let mut j = JoinAttempts::default();
        let now = std::time::Instant::now();
        let key = |_| identity::Identity::generate().unwrap().id;
        let ip: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        // One address, fresh keys each time: limited per address.
        for i in 0..JoinAttempts::PER_ADDRESS {
            assert!(j.allow(key(i), ip, now));
        }
        assert!(!j.allow(key(0), ip, now));
        // Another address is unaffected; one key is limited on its own.
        let k = key(0);
        for i in 0..JoinAttempts::PER_KEY {
            let other: std::net::IpAddr = format!("203.0.113.{}", i + 1).parse().unwrap();
            assert!(j.allow(k, other, now));
        }
        assert!(!j.allow(k, "192.0.2.1".parse().unwrap(), now));
        // A whole IPv6 /64 counts as one address.
        let a: std::net::IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: std::net::IpAddr = "2001:db8:1:2::ffff".parse().unwrap();
        for _ in 0..JoinAttempts::PER_ADDRESS {
            assert!(j.allow(key(0), a, now));
        }
        assert!(!j.allow(key(0), b, now));
        // A minute later all is forgotten.
        assert!(j.allow(key(0), ip, now + Duration::from_secs(61)));
    }
}
