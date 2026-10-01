//! Multi-node tests: several in-process nodes on localhost.
use peephole::cluster::{self, Node, identity::Identity, identity::NodeId};
use peephole::config::{ClusterConfig, PeerConfig, Roles};
use std::sync::Arc;

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

fn cluster_cfg(me: &Addr, peers: &[&Addr]) -> ClusterConfig {
    ClusterConfig {
        node_name: me.name.into(),
        listen: me.address().parse().unwrap(),
        advertise: Some(me.address()),
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
    }
}

/// Start a node; the returned sender keeps it running until dropped.
async fn boot(
    identity: Identity,
    me: &Addr,
    peers: &[&Addr],
    proto: Option<(u32, u32)>,
) -> (Arc<Node>, tokio::sync::watch::Sender<bool>) {
    let cc = cluster_cfg(me, peers);
    let node = match proto {
        Some(p) => Node::with_proto(identity, cc, Roles::default(), p),
        None => Node::new(identity, cc, Roles::default()),
    }
    .unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    cluster::start(node.clone(), rx).await.unwrap();
    (node, tx)
}

#[tokio::test]
async fn members_greet_each_other_over_pinned_mtls() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (na, _ta) = boot(ia, &a, &[&b], None).await;
    let (nb, _tb) = boot(ib, &b, &[&a], None).await;
    assert_eq!(na.hello(b.id, &b.address()).await.unwrap().node_name, "b");
    assert_eq!(nb.hello(a.id, &a.address()).await.unwrap().node_name, "a");
}

#[tokio::test]
async fn non_member_key_is_refused() {
    let (ia, a) = new_node("a");
    let (ix, x) = new_node("x");
    let (_na, _ta) = boot(ia, &a, &[], None).await;
    // x pins a's key, but a does not know x.
    let (nx, _tx) = boot(ix, &x, &[&a], None).await;
    let e = nx.hello(a.id, &a.address()).await.unwrap_err();
    assert!(format!("{e:#}").contains("not a member"), "{e:#}");
}

#[tokio::test]
async fn client_refuses_a_server_with_another_key() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let impostor = Identity::generate().unwrap().id;
    let (_na, _ta) = boot(ia, &a, &[&b], None).await;
    let (nb, _tb) = boot(ib, &b, &[&a], None).await;
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
    let (na, _ta) = boot(ia, &a, &[&b], Some((1, 1))).await;
    let (_nb, _tb) = boot(ib, &b, &[&a], Some((2, 3))).await;
    let e = na.hello(b.id, &b.address()).await.unwrap_err();
    let msg = format!("{e:#}");
    assert!(msg.contains("incompatible protocol"), "{msg}");
    assert!(msg.contains("2..=3"), "{msg}");
}
