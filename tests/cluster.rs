//! Multi-node tests: several in-process nodes on localhost.
use peephole::cluster::record::{Record, WireEntry};
use peephole::cluster::{self, Node, NodeParams, identity::Identity, identity::NodeId};
use peephole::cluster::{invite, members, repl};
use peephole::config::{ClusterConfig, PeerConfig, Roles};
use peephole::store::Store;
use std::sync::Arc;
use std::time::Duration;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Public facts about a test node: what its peers put in their config.
#[derive(Clone)]
struct Addr {
    name: &'static str,
    id: NodeId,
    port: u16,
}

impl Addr {
    fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

fn new_node(name: &'static str) -> (Identity, Addr) {
    let identity = Identity::generate().unwrap();
    let addr = Addr {
        name,
        id: identity.id,
        port: free_port(),
    };
    (identity, addr)
}

struct TestNode {
    node: Arc<Node>,
    _dir: tempfile::TempDir,
    _stop: tokio::sync::watch::Sender<bool>,
}

impl std::ops::Deref for TestNode {
    type Target = Node;
    fn deref(&self) -> &Node {
        &self.node
    }
}

struct Opts {
    proto: Option<(u32, u32)>,
    /// false: outbound-only (no advertise address).
    advertise: bool,
}

const DEFAULT: Opts = Opts {
    proto: None,
    advertise: true,
};

async fn boot(identity: Identity, me: &Addr, peers: &[&Addr], o: Opts) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let cluster = ClusterConfig {
        node_name: me.name.into(),
        listen: me.address().parse().unwrap(),
        advertise: o.advertise.then(|| me.address()),
        key_path: None,
        takeover_hours: 6,
        lease_secs: 120,
        peers: peers
            .iter()
            .map(|p| PeerConfig {
                name: p.name.into(),
                address: p.address(),
                public_key: p.id.to_string(),
            })
            .collect(),
    };
    let node = Node::open(NodeParams {
        identity,
        cluster,
        roles: Roles::default(),
        never_scan: vec![],
        store,
        proto: o.proto.unwrap_or((
            cluster::rpc::proto::PROTO_MIN,
            cluster::rpc::proto::PROTO_VERSION,
        )),
    })
    .await
    .unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    cluster::start(node.clone(), rx).await.unwrap();
    TestNode {
        node,
        _dir: dir,
        _stop: tx,
    }
}

/// Poll `f` until it holds or 15 s pass.
async fn eventually<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !f().await {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn knows(n: &Node, id: NodeId, active: bool) -> bool {
    members::all(&n.store)
        .await
        .unwrap()
        .iter()
        .any(|m| m.id == id && m.active == active)
}

#[tokio::test]
async fn members_greet_each_other_over_pinned_mtls() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    assert_eq!(na.hello(b.id, &b.address()).await.unwrap().node_name, "b");
    assert_eq!(nb.hello(a.id, &a.address()).await.unwrap().node_name, "a");
    // Each learns the other's self-description (roles, never_scan, ...).
    eventually("a sees b's self-description", || async {
        members::all(&na.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == b.id && m.info_hlc > 0 && m.roles.len() == 3)
    })
    .await;
}

#[tokio::test]
async fn non_member_key_is_refused() {
    let (ia, a) = new_node("a");
    let (ix, x) = new_node("x");
    let _na = boot(ia, &a, &[], DEFAULT).await;
    // x pins a's key, but a does not know x.
    let nx = boot(ix, &x, &[&a], DEFAULT).await;
    let e = nx.hello(a.id, &a.address()).await.unwrap_err();
    assert!(format!("{e:#}").contains("not a cluster member"), "{e:#}");
}

#[tokio::test]
async fn client_refuses_a_server_with_another_key() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let impostor = Identity::generate().unwrap().id;
    let _na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    // Dial a's address while pinning a different key: TLS must fail
    // before any request is sent.
    let e = nb.hello(impostor, &a.address()).await.unwrap_err();
    let msg = format!("{e:#}");
    assert!(msg.contains("invalid peer certificate"), "{msg}");
}

#[tokio::test]
async fn incompatible_protocol_ranges_are_reported() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(
        ia,
        &a,
        &[&b],
        Opts {
            proto: Some((1, 1)),
            ..DEFAULT
        },
    )
    .await;
    let _nb = boot(
        ib,
        &b,
        &[&a],
        Opts {
            proto: Some((2, 3)),
            ..DEFAULT
        },
    )
    .await;
    let e = na.hello(b.id, &b.address()).await.unwrap_err();
    let msg = format!("{e:#}");
    assert!(msg.contains("incompatible protocol"), "{msg}");
    assert!(msg.contains("2..=3"), "{msg}");
}

/// A–B configured; C joins through B's invite. A learns C (and C learns
/// A) without anyone touching A.
#[tokio::test]
async fn invited_member_propagates_cluster_wide() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let nc = boot(ic, &c, &[], DEFAULT).await;
    let token = invite::create(&nb, 1).await.unwrap();
    let inviter = invite::join(&nc, &token).await.unwrap();
    assert_eq!(inviter.id, b.id);
    eventually("a admits c", || knows(&na, c.id, true)).await;
    eventually("c admits a", || knows(&nc, a.id, true)).await;
    // And A accepts C's RPC calls now.
    eventually("c greets a", || async {
        nc.hello(a.id, &a.address()).await.is_ok()
    })
    .await;
}

/// C has no advertise address: nobody can dial it, yet its records reach
/// A (via B or by C pushing), and A's reach C.
#[tokio::test]
async fn outbound_only_member_syncs_both_ways() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let nc = boot(
        ic,
        &c,
        &[],
        Opts {
            advertise: false,
            ..DEFAULT
        },
    )
    .await;
    let token = invite::create(&nb, 1).await.unwrap();
    invite::join(&nc, &token).await.unwrap();
    eventually("a has c's self-description", || async {
        members::all(&na.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == c.id && m.info_hlc > 0 && m.address.is_none())
    })
    .await;
    // A new record on A reaches outbound-only C promptly (long-poll).
    let (_, d) = new_node("d");
    let rec = Record::MemberRevoke { id: d.id };
    repl::append(&na, &[rec]).await.unwrap();
    eventually("c sees a's newest record", || async {
        members::all(&nc.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == d.id)
    })
    .await;
}

#[tokio::test]
async fn invites_are_single_use_and_expire() {
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let (id_, d) = new_node("d");
    let nb = boot(ib, &b, &[], DEFAULT).await;
    let nc = boot(ic, &c, &[], DEFAULT).await;
    let nd = boot(id_, &d, &[], DEFAULT).await;
    let token = invite::create(&nb, 1).await.unwrap();
    invite::join(&nc, &token).await.unwrap();
    let e = invite::join(&nd, &token).await.unwrap_err();
    assert!(
        format!("{e:#}").contains("invalid, used or expired"),
        "{e:#}"
    );

    let token = invite::create(&nb, 1).await.unwrap();
    sqlx::query(
        "UPDATE invites SET expires_at = datetime('now','-1 minute') WHERE used_at IS NULL",
    )
    .execute(&nb.store.pool)
    .await
    .unwrap();
    let e = invite::join(&nd, &token).await.unwrap_err();
    assert!(
        format!("{e:#}").contains("invalid, used or expired"),
        "{e:#}"
    );
    assert!(!knows(&nb, d.id, true).await);
    // A node that already joined a cluster refuses a second one.
    let token = invite::create(&nd, 1).await.unwrap();
    let e = invite::join(&nc, &token).await.unwrap_err();
    assert!(format!("{e:#}").contains("already belongs"), "{e:#}");
}

#[tokio::test]
async fn revocation_spreads_and_locks_the_node_out() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let nc = boot(ic, &c, &[], DEFAULT).await;
    let token = invite::create(&nb, 1).await.unwrap();
    invite::join(&nc, &token).await.unwrap();
    eventually("a admits c", || knows(&na, c.id, true)).await;
    repl::append(&nb, &[Record::MemberRevoke { id: c.id }])
        .await
        .unwrap();
    eventually("a revokes c", || knows(&na, c.id, false)).await;
    assert!(!na.is_member(&c.id));
    let e = nc.hello(a.id, &a.address()).await.unwrap_err();
    assert!(format!("{e:#}").contains("not a cluster member"), "{e:#}");
    // C cannot re-admit itself.
    repl::append(
        &nc,
        &[Record::MemberUpdate(
            peephole::cluster::record::MemberInfo {
                name: "c-again".into(),
                ..nc.self_info()
            },
        )],
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(knows(&na, c.id, false).await);
}

/// Entries are applied only with a valid origin signature, and entries
/// from a not-yet-trusted origin wait until it is admitted.
#[tokio::test]
async fn forged_entries_are_rejected_and_unknown_origins_parked() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let me = Identity::generate().unwrap();
    let (a_id, b_id) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let node = Node::open(NodeParams {
        identity: me,
        cluster: ClusterConfig {
            node_name: "me".into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            advertise: None,
            key_path: None,
            takeover_hours: 6,
            lease_secs: 120,
            peers: vec![PeerConfig {
                name: "a".into(),
                address: "127.0.0.1:1".into(),
                public_key: a_id.id.to_string(),
            }],
        },
        roles: Roles::default(),
        never_scan: vec![],
        store,
        proto: (1, 1),
    })
    .await
    .unwrap();
    node.bootstrap().await.unwrap();

    let info = |id: &Identity, name: &str| peephole::cluster::record::MemberInfo {
        id: id.id,
        name: name.into(),
        address: None,
        roles: vec![],
        never_scan: vec![],
        proto_min: 1,
        proto_max: 1,
    };
    // Forgery: b signs an entry claiming to come from a.
    let mut forged =
        WireEntry::sign(&b_id, 1, 1, &Record::MemberUpdate(info(&a_id, "evil"))).unwrap();
    forged.origin = a_id.id;
    let st = repl::apply_batch(&node, vec![forged]).await.unwrap();
    assert_eq!((st.applied, st.rejected), (0, 1));

    // b is unknown: its own (valid) entry is parked...
    let b1 = WireEntry::sign(&b_id, 1, 10, &Record::MemberUpdate(info(&b_id, "b"))).unwrap();
    let st = repl::apply_batch(&node, vec![b1]).await.unwrap();
    assert_eq!((st.applied, st.parked), (0, 1));
    // ...a gap is rejected...
    let b3 = WireEntry::sign(&b_id, 3, 12, &Record::MemberUpdate(info(&b_id, "b3"))).unwrap();
    assert_eq!(
        repl::apply_batch(&node, vec![b3]).await.unwrap().rejected,
        1
    );
    // ...and once trusted a admits b, the parked entry applies.
    let a1 = WireEntry::sign(&a_id, 1, 20, &Record::MemberAdd(info(&b_id, "b-by-a"))).unwrap();
    let st = repl::apply_batch(&node, vec![a1]).await.unwrap();
    assert_eq!(st.applied, 2, "{st:?}");
    let rows = members::all(&node.store).await.unwrap();
    let b = rows.iter().find(|m| m.id == b_id.id).unwrap();
    assert!(b.active);
    assert_eq!(b.name, "b", "self-description wins over the sponsor's");
    let heads = repl::heads(&node.store).await.unwrap();
    assert_eq!(repl::head_in(&heads, &b_id.id), 1);
}
