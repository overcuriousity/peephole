//! Multi-node tests: several in-process nodes on localhost.
use peephole::cluster::record::{Record, WireEntry};
use peephole::cluster::{self, Node, NodeParams, identity::Identity, identity::NodeId};
use peephole::cluster::{invite, members, repl};
use peephole::config::{ClusterConfig, PeerConfig, Roles};
use peephole::store::Store;
use std::sync::Arc;
use std::time::Duration;

fn free_port() -> u16 {
    // Tests run in parallel: the OS may hand the same ephemeral port to two
    // of them once the probe socket is closed, so never give one out twice.
    static TAKEN: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    loop {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut taken = TAKEN.lock().unwrap();
        if !taken.contains(&port) {
            taken.push(port);
            return port;
        }
    }
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
    dir: tempfile::TempDir,
    _stop: tokio::sync::watch::Sender<bool>,
    pace: peephole::scan::pace::SharedPace,
    workers: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for TestNode {
    fn drop(&mut self) {
        if let Some(w) = self.workers.take() {
            w.abort();
        }
    }
}

impl std::ops::Deref for TestNode {
    type Target = Node;
    fn deref(&self) -> &Node {
        &self.node
    }
}

#[derive(Clone)]
struct Opts {
    proto: Option<(u32, u32)>,
    /// false: outbound-only (no advertise address).
    advertise: bool,
    lease_secs: u64,
    takeover_hours: f64,
    never_scan: Vec<String>,
    /// Run scan workers with this fake nmap.
    scanner: Option<std::path::PathBuf>,
    workers: usize,
}

const DEFAULT: Opts = Opts {
    proto: None,
    advertise: true,
    lease_secs: 120,
    takeover_hours: 6.0,
    never_scan: vec![],
    scanner: None,
    workers: 1,
};

async fn boot(identity: Identity, me: &Addr, peers: &[&Addr], o: Opts) -> TestNode {
    boot_in(tempfile::tempdir().unwrap(), identity, me, peers, o).await
}

/// Like [`boot`], on an existing data dir (standalone history is adopted,
/// as `peephole::run` does).
async fn boot_in(
    dir: tempfile::TempDir,
    identity: Identity,
    me: &Addr,
    peers: &[&Addr],
    o: Opts,
) -> TestNode {
    let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let cluster = ClusterConfig {
        node_name: me.name.into(),
        listen: me.address().parse().unwrap(),
        advertise: o.advertise.then(|| me.address()),
        key_path: None,
        takeover_hours: o.takeover_hours,
        lease_secs: o.lease_secs,
        peers: peers
            .iter()
            .map(|p| PeerConfig {
                name: p.name.into(),
                address: p.address(),
                public_key: p.id.to_string(),
            })
            .collect(),
    };
    let roles = Roles {
        listener: true,
        scanner: o.scanner.is_some(),
        web: false,
    };
    let node = Node::open(NodeParams {
        identity,
        cluster,
        roles,
        store,
        proto: o.proto.unwrap_or((
            cluster::rpc::proto::PROTO_MIN,
            cluster::rpc::proto::PROTO_VERSION,
        )),
        has_maxmind: false,
        data_dir: dir.path().to_path_buf(),
    })
    .await
    .unwrap();
    cluster::adopt::adopt_history(&node).await.unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    peephole::scan::arbiter::Arbiter::start(node.clone(), rx.clone())
        .await
        .unwrap();
    let pace = peephole::scan::pace::SharedPace::new(peephole::scan::pace::Pace {
        max_workers: o.workers,
        max_scans_per_hour: 3600,
        timeout_secs: 60,
    });
    let workers = o.scanner.as_ref().map(|nmap| {
        peephole::scan::pace::serve_remote(&node, pace.clone());
        tokio::spawn(peephole::scan::arbiter::takeover_loop(
            node.clone(),
            rx.clone(),
        ));
        tokio::spawn(peephole::scan::run_workers(
            peephole::store::recorder::Recorder::Cluster(node.clone()),
            scan_config(&o.never_scan),
            pace.clone(),
            nmap.clone(),
            rx.clone(),
            peephole::events::Notifier::new(),
        ))
    });
    cluster::start(node.clone(), rx).await.unwrap();
    TestNode {
        node,
        dir,
        _stop: tx,
        pace,
        workers,
    }
}

/// Config for the scan workers (argv presets, never_scan, cooldown).
fn scan_config(never_scan: &[String]) -> peephole::config::Config {
    let list = never_scan
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(",");
    toml::from_str(&format!(
        "database_path = \"/x\"\ndata_dir = \"/x\"\n[scan]\nnever_scan = [{list}]\n"
    ))
    .unwrap()
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
            .any(|m| m.id == b.id && m.info_hlc > 0 && m.roles == ["listener"])
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
    let token = invite::create(&nb, &Default::default()).await.unwrap();
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
    let token = invite::create(&nb, &Default::default()).await.unwrap();
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
    let rec = Record::MemberAdd(peephole::cluster::record::MemberInfo {
        id: d.id,
        name: "d".into(),
        address: None,
        roles: vec![],
        proto_min: 0,
        proto_max: 0,
    });
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
async fn invites_are_reusable_until_limited_expired_or_revoked() {
    use invite::InviteOpts;
    let boot1 = |name: &'static str| async move {
        let (i, a) = new_node(name);
        boot(i, &a, &[], DEFAULT).await
    };
    let nb = boot1("b").await;
    let (nc, nd, ne, nf, ng) = (
        boot1("c").await,
        boot1("d").await,
        boot1("e").await,
        boot1("f").await,
        boot1("g").await,
    );
    let refused = |e: anyhow::Error| {
        let m = format!("{e:#}");
        assert!(m.contains("invalid, revoked, exhausted or expired"), "{m}");
    };

    // One invite, handed to a peer group, redeemed one by one.
    let token = invite::create(
        &nb,
        &InviteOpts {
            label: "peer group".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    invite::join(&nc, &token).await.unwrap();
    invite::join(&nd, &token).await.unwrap();
    let rows = invite::list(&nb.store).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].label, "peer group");
    assert_eq!((rows[0].uses, rows[0].usable), (2, true));
    assert_eq!(rows[0].joined.len(), 2);
    assert!(rows[0].joined.contains(&nc.id()) && rows[0].joined.contains(&nd.id()));

    // Revoked: no further joins; revoking twice reports nothing to do.
    assert!(invite::revoke(&nb.store, rows[0].id).await.unwrap());
    assert!(!invite::revoke(&nb.store, rows[0].id).await.unwrap());
    refused(invite::join(&ne, &token).await.unwrap_err());

    // Use limit.
    let token = invite::create(
        &nb,
        &InviteOpts {
            max_uses: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    invite::join(&ne, &token).await.unwrap();
    refused(invite::join(&nf, &token).await.unwrap_err());

    // Expiry.
    let token = invite::create(
        &nb,
        &InviteOpts {
            ttl_hours: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invites SET expires_at = datetime('now','-1 minute')
         WHERE id = (SELECT MAX(id) FROM invites)",
    )
    .execute(&nb.store.pool)
    .await
    .unwrap();
    refused(invite::join(&nf, &token).await.unwrap_err());
    assert!(!knows(&nb, nf.id(), true).await);

    // A member of one cluster refuses an invite into an unrelated one.
    let token = invite::create(&ng, &InviteOpts::default()).await.unwrap();
    let e = invite::join(&nc, &token).await.unwrap_err();
    assert!(format!("{e:#}").contains("already belongs"), "{e:#}");

    // Nonsense options are refused.
    for bad in [
        InviteOpts {
            ttl_hours: Some(0),
            ..Default::default()
        },
        InviteOpts {
            max_uses: Some(0),
            ..Default::default()
        },
    ] {
        assert!(invite::create(&nb, &bad).await.is_err());
    }
}

/// Nobody can remove another node; a node removes itself by leaving, and
/// comes back with an invite.
#[tokio::test]
async fn only_a_node_itself_can_leave() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let nc = boot(ic, &c, &[], DEFAULT).await;
    let token = invite::create(&nb, &Default::default()).await.unwrap();
    invite::join(&nc, &token).await.unwrap();
    eventually("a admits c", || knows(&na, c.id, true)).await;

    // B tries to revoke C: every node ignores it.
    repl::append(&nb, &[Record::MemberRevoke { id: c.id }])
        .await
        .unwrap();
    eventually("a holds b's newest entry", || async {
        let on_a = repl::heads(&na.store).await.unwrap();
        let on_b = repl::heads(&nb.store).await.unwrap();
        repl::head_in(&on_a, &b.id) == repl::head_in(&on_b, &b.id)
    })
    .await;
    assert!(knows(&na, c.id, true).await && knows(&nb, c.id, true).await);
    assert!(nc.hello(a.id, &a.address()).await.is_ok());

    // C leaves by itself.
    let told = cluster::leave(&nc).await.unwrap();
    assert!(told >= 1, "at least the inviter heard it");
    assert_eq!(nc.detached(), Some(cluster::Detached::Left));
    assert!(
        nc.dial_targets().is_empty(),
        "a node that left stops dialling"
    );
    eventually("a sees c gone", || knows(&na, c.id, false)).await;
    let e = nc.hello(a.id, &a.address()).await.unwrap_err();
    assert!(format!("{e:#}").contains("not a cluster member"), "{e:#}");

    // Rejoining takes an invite.
    let token = invite::create(&na, &Default::default()).await.unwrap();
    invite::join(&nc, &token).await.unwrap();
    assert_eq!(nc.detached(), None);
    eventually("a re-admits c", || knows(&na, c.id, true)).await;
}

/// Leaving with nobody reachable still detaches the node.
#[tokio::test]
async fn leaving_without_reachable_peers_still_detaches() {
    let (_, a) = new_node("a");
    let (x, _dx) = offline_node(&[&a]).await;
    assert_eq!(cluster::leave(&x).await.unwrap(), 0);
    assert_eq!(x.detached(), Some(cluster::Detached::Left));
}

/// What a member recorded stays acceptable after it left: a node that
/// syncs later still applies all of it.
#[tokio::test]
async fn entries_of_a_departed_member_still_apply() {
    let a_id = Identity::generate().unwrap();
    let a = Addr {
        name: "a",
        id: a_id.id,
        port: 1,
    };
    let (x, _dx) = offline_node(&[&a]).await;
    let info = |name: &str| peephole::cluster::record::MemberInfo {
        id: a_id.id,
        name: name.into(),
        address: None,
        roles: vec![],
        proto_min: 2,
        proto_max: 2,
    };
    let entries = vec![
        WireEntry::sign(&a_id, 1, 10, &Record::MemberUpdate(info("a"))).unwrap(),
        WireEntry::sign(&a_id, 2, 20, &Record::MemberRevoke { id: a_id.id }).unwrap(),
        WireEntry::sign(&a_id, 3, 30, &Record::MemberUpdate(info("late"))).unwrap(),
    ];
    let st = repl::apply_batch(&x, entries).await.unwrap();
    assert_eq!((st.applied, st.parked), (3, 0), "{st:?}");
    let rows = members::all(&x.store).await.unwrap();
    let row = rows.iter().find(|m| m.id == a_id.id).unwrap();
    assert_eq!(row.name, "late");
}

/// An HLC `days` in the past (`n` keeps values distinct).
fn hlc_days_ago(days: u64, n: u64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    ((now - days * 24 * 3600 * 1000) << 16) + n
}

#[tokio::test]
async fn members_silent_for_30_days_are_pruned_and_revive_with_a_sign_of_life() {
    let a_id = Identity::generate().unwrap();
    let b_id = Identity::generate().unwrap();
    let a = Addr {
        name: "a",
        id: a_id.id,
        port: 1,
    };
    let (x, _dx) = offline_node(&[&a]).await;
    let info = |id: &Identity| peephole::cluster::record::MemberInfo {
        id: id.id,
        name: "b".into(),
        address: Some("127.0.0.1:2".into()),
        roles: vec![],
        proto_min: 2,
        proto_max: 2,
    };
    // A admitted B 40 days ago; B described itself then and went silent.
    let st = repl::apply_batch(
        &x,
        vec![
            WireEntry::sign(
                &a_id,
                1,
                hlc_days_ago(40, 1),
                &Record::MemberAdd(info(&b_id)),
            )
            .unwrap(),
            WireEntry::sign(
                &b_id,
                1,
                hlc_days_ago(40, 2),
                &Record::MemberUpdate(info(&b_id)),
            )
            .unwrap(),
        ],
    )
    .await
    .unwrap();
    assert_eq!(
        st.applied, 2,
        "a pruned member's records are still applied: {st:?}"
    );
    let row = |rows: Vec<members::MemberRow>| rows.into_iter().find(|m| m.id == b_id.id).unwrap();
    let b = row(members::all(&x.store).await.unwrap());
    assert_eq!(b.standing, members::Standing::Pruned);
    assert!(!b.active && !x.is_member(&b_id.id));
    assert_eq!(x.standing_of(&b_id.id), Some(members::Standing::Pruned));
    assert!(x.dial_targets().iter().all(|t| t.0 != b_id.id));
    // A fresh entry signed by B, relayed by anyone, revives it.
    repl::apply_batch(
        &x,
        vec![
            WireEntry::sign(
                &b_id,
                2,
                hlc_days_ago(0, 3),
                &Record::MemberUpdate(info(&b_id)),
            )
            .unwrap(),
        ],
    )
    .await
    .unwrap();
    assert!(row(members::all(&x.store).await.unwrap()).active);
    assert!(x.is_member(&b_id.id));
}

#[tokio::test]
async fn a_running_node_leaves_a_sign_of_life_once_a_day() {
    let (_, a) = new_node("a");
    let (x, _dx) = offline_node(&[&a]).await;
    assert!(
        !x.keepalive().await.unwrap(),
        "fresh entries: nothing to do"
    );
    sqlx::query("UPDATE repl_log SET hlc = ? WHERE origin = ?")
        .bind(hlc_days_ago(2, 0) as i64)
        .bind(&x.id().0[..])
        .execute(&x.store.pool)
        .await
        .unwrap();
    assert!(x.keepalive().await.unwrap());
    assert!(!x.keepalive().await.unwrap());
}

/// A node that was offline longer than the prune window knows it was
/// dropped, instead of judging everyone else by its outdated log.
#[tokio::test]
async fn a_node_offline_for_over_30_days_starts_detached() {
    let (_, a) = new_node("a");
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("node.key");
    Identity::load_or_create(&key).unwrap();
    let open = || async {
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        Node::open(NodeParams {
            identity: Identity::load(&key).unwrap(),
            cluster: ClusterConfig {
                node_name: "x".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: None,
                key_path: None,
                takeover_hours: 6.0,
                lease_secs: 120,
                peers: vec![PeerConfig {
                    name: "a".into(),
                    address: a.address(),
                    public_key: a.id.to_string(),
                }],
            },
            roles: Roles::default(),
            store,
            proto: (2, 2),
            has_maxmind: false,
            data_dir: dir.path().to_path_buf(),
        })
        .await
        .unwrap()
    };
    let x = open().await;
    x.bootstrap().await.unwrap();
    assert_eq!(x.detached(), None);
    sqlx::query("UPDATE repl_log SET hlc = ? WHERE origin = ?")
        .bind(hlc_days_ago(31, 0) as i64)
        .bind(&x.id().0[..])
        .execute(&x.store.pool)
        .await
        .unwrap();
    drop(x);
    let x = open().await;
    assert_eq!(x.detached(), Some(cluster::Detached::Pruned));
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
            takeover_hours: 6.0,
            lease_secs: 120,
            peers: vec![PeerConfig {
                name: "a".into(),
                address: "127.0.0.1:1".into(),
                public_key: a_id.id.to_string(),
            }],
        },
        roles: Roles::default(),
        store,
        proto: (1, 1),
        has_maxmind: false,
        data_dir: dir.path().to_path_buf(),
    })
    .await
    .unwrap();
    node.bootstrap().await.unwrap();

    let info = |id: &Identity, name: &str| peephole::cluster::record::MemberInfo {
        id: id.id,
        name: name.into(),
        address: None,
        roles: vec![],
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
    let b1 = WireEntry::sign(
        &b_id,
        1,
        hlc_days_ago(0, 10),
        &Record::MemberUpdate(info(&b_id, "b")),
    )
    .unwrap();
    let st = repl::apply_batch(&node, vec![b1]).await.unwrap();
    assert_eq!((st.applied, st.parked), (0, 1));
    // ...a gap is rejected...
    let b3 = WireEntry::sign(
        &b_id,
        3,
        hlc_days_ago(0, 12),
        &Record::MemberUpdate(info(&b_id, "b3")),
    )
    .unwrap();
    assert_eq!(
        repl::apply_batch(&node, vec![b3]).await.unwrap().rejected,
        1
    );
    // ...and once trusted a admits b, the parked entry applies.
    let a1 = WireEntry::sign(
        &a_id,
        1,
        hlc_days_ago(0, 20),
        &Record::MemberAdd(info(&b_id, "b-by-a")),
    )
    .unwrap();
    let st = repl::apply_batch(&node, vec![a1]).await.unwrap();
    assert_eq!(st.applied, 2, "{st:?}");
    let rows = members::all(&node.store).await.unwrap();
    let b = rows.iter().find(|m| m.id == b_id.id).unwrap();
    assert!(b.active);
    assert_eq!(b.name, "b", "self-description wins over the sponsor's");
    let heads = repl::heads(&node.store).await.unwrap();
    assert_eq!(repl::head_in(&heads, &b_id.id), 1);
}

// ---------------------------------------------------------------- data

use peephole::store::recorder::Recorder;
use peephole::store::requests::NewRequest;

fn rec(n: &TestNode) -> Recorder {
    Recorder::Cluster(n.node.clone())
}

fn new_request(ip_id: i64, path: &str) -> NewRequest {
    NewRequest {
        ip_id,
        method: "POST".into(),
        path: path.into(),
        query: Some("q=1".into()),
        headers_json: r#"[["user-agent","sqlmap/1.7"]]"#.into(),
        body: Some(b"user=admin&pass=' OR 1=1--".to_vec()),
        labels_json: r#"["sqli"]"#.into(),
        severity: 4,
        scan_level: 3,
        is_fp_claim: false,
        page_token: Some("tok-1".into()),
    }
}

async fn count(n: &Node, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .fetch_one(&n.store.pool)
        .await
        .unwrap()
}

fn fixture_scan() -> peephole::scan::nmap_xml::ScanResult {
    peephole::scan::nmap_xml::parse_nmap_xml(
        &std::fs::read("tests/fixtures/nmap-basic.xml").unwrap(),
    )
    .unwrap()
}

/// Everything recorded on A reaches C (which joined via B), byte for byte;
/// large records travel without being stored twice.
#[tokio::test]
async fn data_replicates_cluster_wide() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let nc = boot(ic, &c, &[], DEFAULT).await;
    invite::join(
        &nc,
        &invite::create(&nb, &Default::default()).await.unwrap(),
    )
    .await
    .unwrap();

    let r = rec(&na);
    let ip = na
        .store
        .upsert_ip("198.51.100.77".parse().unwrap())
        .await
        .unwrap();
    r.enrich_ip(ip.id, Some("DE"), Some(64500), Some("Example AS"), true)
        .await
        .unwrap();
    let req = r
        .insert_request(&new_request(ip.id, "/login"))
        .await
        .unwrap();
    r.insert_fp_claim(ip.id, req, Some("me@example.org"), "Mozilla")
        .await
        .unwrap();
    r.insert_fingerprint(Some(req), ip.id, "fp1", Some("v1"), "{}", "{}", b"events")
        .await
        .unwrap();
    let job = match r.enqueue_scan(ip.id, 3, 24).await.unwrap() {
        peephole::store::scans::EnqueueOutcome::Queued(j) => j,
        o => panic!("{o:?}"),
    };
    assert_eq!(r.next_queued_job().await.unwrap().unwrap().id, job);
    r.finish_job(job, Some(&fixture_scan()), None)
        .await
        .unwrap();

    eventually("c has the scan", || async {
        count(&nc, "SELECT COUNT(*) FROM ports").await == 3
    })
    .await;
    let row: (String, Vec<u8>, String, Option<String>, i64) = sqlx::query_as(
        "SELECT r.path, r.body, i.ip, i.country, i.is_tor_exit
         FROM requests r JOIN ips i ON i.id = r.ip_id",
    )
    .fetch_one(&nc.store.pool)
    .await
    .unwrap();
    assert_eq!(row.0, "/login");
    assert_eq!(row.1, b"user=admin&pass=' OR 1=1--");
    assert_eq!(row.2, "198.51.100.77");
    assert_eq!(row.3.as_deref(), Some("DE"));
    assert_eq!(row.4, 1);
    assert_eq!(count(&nc, "SELECT COUNT(*) FROM fp_claims").await, 1);
    assert_eq!(count(&nc, "SELECT COUNT(*) FROM fingerprints").await, 1);
    assert_eq!(
        count(&nc, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await,
        1
    );
    for n in [&na, &nc] {
        assert_eq!(
            count(
                n,
                "SELECT COUNT(*) FROM repl_log
                 WHERE kind IN ('request','fingerprint','scan_result') AND payload IS NOT NULL"
            )
            .await,
            0,
            "row-backed payloads are rebuilt, not stored"
        );
    }
    // C's copy is attributed to A.
    let origin: Vec<u8> = sqlx::query_scalar("SELECT origin FROM requests")
        .fetch_one(&nc.store.pool)
        .await
        .unwrap();
    assert_eq!(origin, a.id.0.to_vec());
    // C does not scan A's jobs (A arbitrates them).
    assert!(rec(&nc).next_queued_job().await.unwrap().is_none());
}

/// A node with the given trusted peers that never touches the network.
async fn offline_node(peers: &[&Addr]) -> (Arc<Node>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let node = Node::open(NodeParams {
        identity: Identity::generate().unwrap(),
        cluster: ClusterConfig {
            node_name: "offline".into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            advertise: None,
            key_path: None,
            takeover_hours: 6.0,
            lease_secs: 120,
            peers: peers
                .iter()
                .map(|p| PeerConfig {
                    name: p.name.into(),
                    address: p.address(),
                    public_key: p.id.to_string(),
                })
                .collect(),
        },
        roles: Roles::default(),
        store,
        proto: (1, 1),
        has_maxmind: false,
        data_dir: dir.path().to_path_buf(),
    })
    .await
    .unwrap();
    node.bootstrap().await.unwrap();
    (node, dir)
}

async fn batch_of(n: &Node, origin: NodeId) -> peephole::cluster::sync::Batch {
    repl::entries_after(&n.store, &[(origin, 0)], 10_000, usize::MAX)
        .await
        .unwrap()
}

/// How far `n` holds `origin`'s log.
async fn head_of(n: &Node, origin: NodeId) -> u64 {
    repl::head_in(&repl::heads(&n.store).await.unwrap(), &origin)
}

async fn request_uid(n: &Node, path: &str) -> String {
    sqlx::query_scalar("SELECT uid FROM requests WHERE path = ?")
        .bind(path)
        .fetch_one(&n.store.pool)
        .await
        .unwrap()
}

/// Request paths in `n`'s tables, sorted.
async fn paths(n: &Node) -> Vec<String> {
    let mut p: Vec<String> = sqlx::query_scalar("SELECT path FROM requests")
        .fetch_all(&n.store.pool)
        .await
        .unwrap();
    p.sort();
    p
}

/// An erased entry is accepted only with the origin's own tombstone: a
/// relay cannot make other nodes drop somebody's records.
#[tokio::test]
async fn erased_stubs_need_the_origins_tombstone() {
    use peephole::cluster::sync::Batch;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let _nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip = na
        .store
        .upsert_ip("203.0.113.70".parse().unwrap())
        .await
        .unwrap();
    let r1 = rec(&na)
        .insert_request(&new_request(ip.id, "/one"))
        .await
        .unwrap();
    rec(&na)
        .insert_request(&new_request(ip.id, "/two"))
        .await
        .unwrap();
    let (one, two) = (
        request_uid(&na, "/one").await,
        request_uid(&na, "/two").await,
    );
    let before = batch_of(&na, a.id).await;
    assert!(before.proofs.is_empty());
    rec(&na).delete_request(r1).await.unwrap();
    let after = batch_of(&na, a.id).await;
    assert_eq!(after.proofs.len(), 1, "the stub travels with its tombstone");
    let tomb = after.proofs[0].uid.clone().unwrap();
    let a_head = head_of(&na, a.id).await;
    let strip = |batch: &mut Batch, uid: &str, by: Option<String>| {
        let e = batch
            .entries
            .iter_mut()
            .find(|e| e.uid.as_deref() == Some(uid))
            .unwrap();
        e.payload = None;
        e.sig = None;
        e.erased_by = by;
    };

    // A relay strips /two and claims A's tombstone erased it.
    let (x, _dx) = offline_node(&[&a, &b]).await;
    let mut forged = Batch {
        entries: before.entries.clone(),
        proofs: after.proofs.clone(),
    };
    strip(&mut forged, &two, Some(tomb.clone()));
    let st = repl::apply_batch(&x, forged).await.unwrap();
    assert!(st.rejected >= 1, "{st:?}");
    assert!(
        head_of(&x, a.id).await < a_head,
        "the stream stops at the forgery"
    );
    assert_eq!(
        count(&x, "SELECT COUNT(*) FROM requests WHERE path = '/two'").await,
        0
    );
    // The honest stream still applies afterwards.
    let st = repl::apply_batch(&x, batch_of(&na, a.id).await)
        .await
        .unwrap();
    assert_eq!(st.rejected, 0, "{st:?}");
    assert_eq!(head_of(&x, a.id).await, a_head);
    assert_eq!(paths(&x).await, ["/two"]);
    // X can pass the erasure on with its proof.
    assert_eq!(batch_of(&x, a.id).await.proofs.len(), 1);

    // No proof, a proof from another origin, a stub without a uid: rejected.
    let stub_only = Batch {
        entries: after.entries.clone(),
        proofs: vec![],
    };
    let other = Identity::generate().unwrap();
    let wrong_origin = Batch {
        entries: after.entries.clone(),
        proofs: vec![
            WireEntry::sign(
                &other,
                1,
                1,
                &Record::Tombstone(peephole::cluster::record::TombstoneRec {
                    uid: tomb.clone(),
                    uids: vec![one.clone()],
                }),
            )
            .unwrap(),
        ],
    };
    let mut no_uid = Batch {
        entries: after.entries.clone(),
        proofs: after.proofs.clone(),
    };
    no_uid
        .entries
        .iter_mut()
        .find(|e| e.payload.is_none())
        .unwrap()
        .uid = None;
    for (what, bad) in [
        ("no proof", stub_only),
        ("foreign proof", wrong_origin),
        ("stub without uid", no_uid),
    ] {
        let (y, _dy) = offline_node(&[&a, &b]).await;
        let st = repl::apply_batch(&y, bad).await.unwrap();
        assert!(st.rejected >= 1, "{what}: {st:?}");
        assert!(head_of(&y, a.id).await < a_head, "{what}");
    }
}

#[tokio::test]
async fn deletes_reach_only_the_deleters_own_records() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip_a = na
        .store
        .upsert_ip("203.0.113.66".parse().unwrap())
        .await
        .unwrap();
    let r1 = rec(&na)
        .insert_request(&new_request(ip_a.id, "/one"))
        .await
        .unwrap();
    rec(&na)
        .insert_request(&new_request(ip_a.id, "/two"))
        .await
        .unwrap();
    rec(&na)
        .insert_fp_claim(ip_a.id, r1, None, "ua")
        .await
        .unwrap();
    let ip_b = nb
        .store
        .upsert_ip("203.0.113.66".parse().unwrap())
        .await
        .unwrap();
    rec(&nb)
        .insert_request(&new_request(ip_b.id, "/three"))
        .await
        .unwrap();
    eventually("both have three requests", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 3
            && count(&nb, "SELECT COUNT(*) FROM requests").await == 3
    })
    .await;
    eventually("b has the claim", || async {
        count(&nb, "SELECT COUNT(*) FROM fp_claims").await == 1
    })
    .await;

    // B cannot delete A's request for the cluster: it only hides it locally.
    let one_on_b: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/one'")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    let out = rec(&nb).delete_request(one_on_b).await.unwrap();
    assert_eq!((out.deleted, out.hidden), (0, 1));
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM requests").await, 2);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(count(&na, "SELECT COUNT(*) FROM requests").await, 3);

    // A deletes its own: gone everywhere, with its claim, and erased from
    // every log, also where it was only hidden.
    let out = rec(&na).delete_request(r1).await.unwrap();
    assert_eq!(out.deleted, 1);
    eventually("b erased /one and its claim from its log", || async {
        count(
            &nb,
            "SELECT COUNT(*) FROM repl_log WHERE erased_by IS NOT NULL",
        )
        .await
            == 2
    })
    .await;
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM fp_claims").await, 0);

    // Deleting the IP on A removes what A recorded everywhere. B's request
    // for that IP stays in the cluster; A only hides it for itself.
    let out = rec(&na).delete_ips(&[ip_a.id]).await.unwrap();
    assert_eq!((out.deleted, out.hidden), (1, 1));
    assert_eq!(count(&na, "SELECT COUNT(*) FROM requests").await, 0);
    assert_eq!(count(&na, "SELECT COUNT(*) FROM ips").await, 0);
    eventually("only b's request is left on b", || async {
        paths(&nb).await == ["/three"]
    })
    .await;

    // B deletes the IP: now it is gone on both.
    assert!(rec(&nb).delete_ip(ip_b.id).await.unwrap());
    eventually("ip gone everywhere", || async {
        count(&na, "SELECT COUNT(*) FROM ips").await == 0
            && count(&nb, "SELECT COUNT(*) FROM ips").await == 0
    })
    .await;
}

/// Deleting another node's record hides it here and nowhere else, and this
/// node keeps relaying it.
#[tokio::test]
async fn foreign_delete_hides_locally_and_keeps_relaying() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip = na
        .store
        .upsert_ip("203.0.113.71".parse().unwrap())
        .await
        .unwrap();
    for path in ["/one", "/two"] {
        rec(&na)
            .insert_request(&new_request(ip.id, path))
            .await
            .unwrap();
    }
    eventually("b has both", || async {
        count(&nb, "SELECT COUNT(*) FROM requests").await == 2
    })
    .await;
    let one_on_b: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/one'")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    let out = rec(&nb).delete_request(one_on_b).await.unwrap();
    assert_eq!((out.deleted, out.hidden), (0, 1));
    // Repeating it finds nothing and fails nothing.
    let again = rec(&nb).delete_request(one_on_b).await.unwrap();
    assert_eq!((again.deleted, again.hidden), (0, 0));
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM requests").await, 1);
    assert_eq!(count(&na, "SELECT COUNT(*) FROM requests").await, 2);

    // A node fed only from B's copy still gets all of A's records, signed.
    let from_b = batch_of(&nb, a.id).await;
    assert!(from_b.proofs.is_empty());
    assert!(from_b.entries.iter().all(|e| e.verify()), "payloads intact");
    let (x, _dx) = offline_node(&[&a, &b]).await;
    repl::apply_batch(&x, from_b).await.unwrap();
    assert_eq!(count(&x, "SELECT COUNT(*) FROM requests").await, 2);

    // Hidden stays hidden, also across a re-application of the log.
    repl::rematerialize(&nb).await.unwrap();
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM requests").await, 1);
}

/// Record a request for `ip` on `n`.
async fn record(n: &TestNode, ip: &str, path: &str) {
    let row = n.store.upsert_ip(ip.parse().unwrap()).await.unwrap();
    rec(n)
        .insert_request(&new_request(row.id, path))
        .await
        .unwrap();
}

/// Blocking a peer takes its records out of this node's view, keeps them
/// flowing to others, and is undone by unblocking.
#[tokio::test]
async fn blocking_a_peer_hides_its_records_until_unblocked() {
    use peephole::cluster::block;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    record(&na, "203.0.113.72", "/a1").await;
    record(&nb, "203.0.113.73", "/b1").await;
    eventually("everyone has both", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 2
            && count(&nb, "SELECT COUNT(*) FROM requests").await == 2
            && count(&nc, "SELECT COUNT(*) FROM requests").await == 2
    })
    .await;

    assert!(block::block(&nb, nb.id()).await.is_err(), "not oneself");
    assert_eq!(block::block(&nb, a.id).await.unwrap(), 1);
    assert_eq!(
        block::block(&nb, a.id).await.unwrap(),
        0,
        "repeat is harmless"
    );
    assert!(nb.is_blocked(&a.id));
    assert!(nb.dial_targets().iter().all(|t| t.0 != a.id));
    assert_eq!(paths(&nb).await, ["/b1"]);
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM ips").await, 1);
    let e = na.hello(b.id, &b.address()).await.unwrap_err();
    assert!(format!("{e:#}").contains("blocked"), "{e:#}");

    // A keeps recording. B receives it through C, stores it for relaying,
    // and does not show it.
    record(&na, "203.0.113.72", "/a2").await;
    eventually("b holds a's stream via c", || async {
        head_of(&nb, a.id).await == head_of(&na, a.id).await
    })
    .await;
    assert_eq!(paths(&nb).await, ["/b1"]);
    assert_eq!(paths(&nc).await, ["/a1", "/a2", "/b1"]);
    assert!(
        batch_of(&nb, a.id).await.entries.iter().all(|e| e.verify()),
        "b can still relay a's records"
    );

    assert!(block::unblock(&nb, a.id).await.unwrap());
    assert!(
        !block::unblock(&nb, a.id).await.unwrap(),
        "repeat is harmless"
    );
    assert_eq!(paths(&nb).await, ["/a1", "/a2", "/b1"]);
    assert!(!nb.is_blocked(&a.id));
}

/// The admin is told what a delete did: cluster-wide or local only.
#[tokio::test]
async fn admin_delete_reports_hidden_records() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip = na
        .store
        .upsert_ip("203.0.113.74".parse().unwrap())
        .await
        .unwrap();
    rec(&na)
        .insert_request(&new_request(ip.id, "/one"))
        .await
        .unwrap();
    eventually("b has it", || async {
        count(&nb, "SELECT COUNT(*) FROM requests").await == 1
    })
    .await;
    let id: i64 = sqlx::query_scalar("SELECT id FROM requests")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    let (admin, base) = admin_on(&nb).await;
    let r = admin
        .post(format!("{base}/admin/requests/{id}/delete"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM requests").await, 0);
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM hidden").await, 1);
}

/// A standalone install that switches to distributed mode brings its
/// history along; a new member backfills all of it.
#[tokio::test]
async fn standalone_history_is_adopted_and_backfilled() {
    let dir = tempfile::tempdir().unwrap();
    {
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = s.upsert_ip("192.0.2.200".parse().unwrap()).await.unwrap();
        s.set_ip_geo(ip.id, Some("NL"), Some(1), Some("x"))
            .await
            .unwrap();
        for i in 0..150 {
            s.insert_request(&new_request(ip.id, &format!("/p{i}")))
                .await
                .unwrap();
        }
        let job = match s.enqueue_scan(ip.id, 2, 24).await.unwrap() {
            peephole::store::scans::EnqueueOutcome::Queued(j) => j,
            o => panic!("{o:?}"),
        };
        s.next_queued_job().await.unwrap();
        s.finish_job(job, Some(&fixture_scan()), None)
            .await
            .unwrap();
        s.pool.close().await;
    }
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot_in(dir, ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    eventually("b backfilled everything", || async {
        count(&nb, "SELECT COUNT(*) FROM requests").await == 150
            && count(&nb, "SELECT COUNT(*) FROM ports").await == 3
    })
    .await;
    assert_eq!(
        count(&nb, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await,
        1
    );
    let country: Option<String> = sqlx::query_scalar("SELECT country FROM ips")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    assert_eq!(country.as_deref(), Some("NL"));
    assert_eq!(
        count(&na, "SELECT COUNT(*) FROM requests WHERE origin IS NULL").await,
        0
    );
    // A restart adopts nothing twice.
    assert_eq!(cluster::adopt::adopt_history(&na).await.unwrap(), 0);
}

/// Only a job's arbiter may change its state.
#[tokio::test]
async fn job_status_from_a_non_arbiter_is_ignored() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip = na
        .store
        .upsert_ip("203.0.113.9".parse().unwrap())
        .await
        .unwrap();
    rec(&na).enqueue_scan(ip.id, 2, 24).await.unwrap();
    eventually("b has the job", || async {
        count(&nb, "SELECT COUNT(*) FROM scan_jobs").await == 1
    })
    .await;
    let uid: String = sqlx::query_scalar("SELECT uid FROM scan_jobs")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    repl::append(
        &nb,
        &[Record::JobStatus(peephole::cluster::record::JobStatusRec {
            job_uid: uid,
            status: "done".into(),
            started_at: None,
            finished_at: None,
            error: None,
            attempts: 9,
            scanner: None,
        })],
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    for n in [&na, &nb] {
        assert_eq!(
            count(n, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued'").await,
            1
        );
    }
}

// ---------------------------------------------------------- scan queue

/// A fake nmap that prints the fixture after `secs`, and logs each target.
fn fake_nmap(dir: &std::path::Path, secs: f64) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let xml = dir.join("nmap.xml");
    std::fs::copy("tests/fixtures/nmap-basic.xml", &xml).unwrap();
    let log = dir.join("targets.log");
    let p = dir.join(format!("fake-nmap-{secs}"));
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh\nfor a; do t=$a; done\necho $t >> {log}\nsleep {secs}\ncat {xml}\n",
            log = log.display(),
            xml = xml.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

async fn enqueue(n: &TestNode, ip: &str, level: u8) {
    let row = n.store.upsert_ip(ip.parse().unwrap()).await.unwrap();
    let out = rec(n).enqueue_scan(row.id, level, 24).await.unwrap();
    assert!(
        matches!(out, peephole::store::scans::EnqueueOutcome::Queued(_)),
        "{out:?}"
    );
}

async fn scans_by(n: &Node, scanner: NodeId) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs WHERE status = 'done' AND scanner = ?")
        .bind(&scanner.0[..])
        .fetch_one(&n.store.pool)
        .await
        .unwrap()
}

/// A listener without a scanner fills the queue; two scanners drain it
/// and share it about evenly.
#[tokio::test]
async fn scanners_share_a_listeners_queue() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.5);
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let scan = Opts {
        scanner: Some(nmap),
        ..DEFAULT
    };
    let _nb = boot(ib, &b, &[&a, &c], scan.clone()).await;
    let _nc = boot(ic, &c, &[&a, &b], scan).await;
    for i in 0..6 {
        enqueue(&na, &format!("198.51.100.{}", 10 + i), 2).await;
    }
    eventually_for(Duration::from_secs(40), "all six scanned", || async {
        count(&na, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await == 6
    })
    .await;
    let (by_b, by_c) = (scans_by(&na, b.id).await, scans_by(&na, c.id).await);
    assert_eq!(by_b + by_c, 6);
    assert!(by_b >= 2 && by_c >= 2, "uneven: b={by_b} c={by_c}");
    // Results come from the scanners, attributed to them.
    eventually("a has all results", || async {
        count(&na, "SELECT COUNT(*) FROM scans").await == 6
    })
    .await;
    let origins: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT origin) FROM scans")
        .fetch_one(&na.store.pool)
        .await
        .unwrap();
    assert_eq!(origins, 2);
}

/// Poll `f` until it holds or `limit` passes.
async fn eventually_for<F, Fut>(limit: Duration, what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + limit;
    while !f().await {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A scanner that dies mid-scan stops renewing; the lease expires and
/// another scanner finishes the job.
#[tokio::test]
async fn expired_lease_moves_the_job_to_another_scanner() {
    let tools = tempfile::tempdir().unwrap();
    let hang = fake_nmap(tools.path(), 60.0);
    let quick = fake_nmap(tools.path(), 0.2);
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(
        ia,
        &a,
        &[&b, &c],
        Opts {
            lease_secs: 2,
            ..DEFAULT
        },
    )
    .await;
    let mut nb = boot(
        ib,
        &b,
        &[&a, &c],
        Opts {
            scanner: Some(hang),
            ..DEFAULT
        },
    )
    .await;
    enqueue(&na, "203.0.113.50", 2).await;
    eventually("b runs the job", || async {
        count(
            &na,
            "SELECT COUNT(*) FROM scan_jobs WHERE status = 'running'",
        )
        .await
            == 1
    })
    .await;
    // B's scanner dies (nmap is killed with it).
    nb.workers.take().unwrap().abort();
    let _nc = boot(
        ic,
        &c,
        &[&a, &b],
        Opts {
            scanner: Some(quick),
            ..DEFAULT
        },
    )
    .await;
    eventually_for(Duration::from_secs(20), "c finished it", || async {
        scans_by(&na, c.id).await == 1
    })
    .await;
    let attempts: i64 = sqlx::query_scalar("SELECT attempts FROM scan_jobs")
        .fetch_one(&na.store.pool)
        .await
        .unwrap();
    assert_eq!(attempts, 2);
}

/// Queued jobs of an arbiter that went silent are adopted and scanned.
#[tokio::test]
async fn silent_arbiters_queue_is_taken_over() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.2);
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[&a],
        Opts {
            scanner: Some(nmap),
            workers: 0, // paused: nothing is claimed while A is up
            takeover_hours: 3.0 / 3600.0,
            ..DEFAULT
        },
    )
    .await;
    enqueue(&na, "203.0.113.70", 3).await;
    eventually("b sees a's job and heartbeat", || async {
        count(&nb, "SELECT COUNT(*) FROM scan_jobs").await == 1 && nb.status.known(&a.id).is_some()
    })
    .await;
    drop(na); // A goes silent
    eventually_for(Duration::from_secs(20), "b adopted the job", || async {
        let arb: Option<Vec<u8>> = sqlx::query_scalar("SELECT arbiter FROM scan_jobs")
            .fetch_one(&nb.store.pool)
            .await
            .unwrap();
        arb == Some(b.id.0.to_vec())
    })
    .await;
    nb.pace
        .set(
            &nb.store,
            peephole::scan::pace::Pace {
                max_workers: 1,
                max_scans_per_hour: 3600,
                timeout_secs: 60,
            },
        )
        .await
        .unwrap()
        .unwrap();
    eventually_for(Duration::from_secs(20), "b scanned it", || async {
        scans_by(&nb, b.id).await == 1
    })
    .await;
}

async fn knows_scanner(n: &Node, id: NodeId) -> bool {
    members::all(&n.store)
        .await
        .unwrap()
        .iter()
        .any(|m| m.id == id && m.roles.iter().any(|r| r == "scanner"))
}

/// never_scan is local: B leaves the target alone, C scans it.
#[tokio::test]
async fn never_scan_is_local_to_its_scanner() {
    let (tools_b, tools_c) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let _nb = boot(
        ib,
        &b,
        &[&a, &c],
        Opts {
            never_scan: vec!["192.0.2.0/24".into()],
            scanner: Some(fake_nmap(tools_b.path(), 0.1)),
            ..DEFAULT
        },
    )
    .await;
    let _nc = boot(
        ic,
        &c,
        &[&a, &b],
        Opts {
            scanner: Some(fake_nmap(tools_c.path(), 0.1)),
            ..DEFAULT
        },
    )
    .await;
    eventually("a knows both scanners", || async {
        knows_scanner(&na, b.id).await && knows_scanner(&na, c.id).await
    })
    .await;
    enqueue(&na, "192.0.2.10", 2).await;
    eventually_for(Duration::from_secs(30), "c scanned it", || async {
        scans_by(&na, c.id).await == 1
    })
    .await;
    assert!(
        !tools_b.path().join("targets.log").exists(),
        "b's nmap must not run"
    );
}

/// When every scanner declines, the job ends as refused instead of
/// circling in the queue.
#[tokio::test]
async fn job_declined_by_every_scanner_is_refused() {
    let tools = tempfile::tempdir().unwrap();
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let _nb = boot(
        ib,
        &b,
        &[&a],
        Opts {
            never_scan: vec!["192.0.2.0/24".into()],
            scanner: Some(fake_nmap(tools.path(), 0.1)),
            ..DEFAULT
        },
    )
    .await;
    eventually("a knows the scanner", || knows_scanner(&na, b.id)).await;
    enqueue(&na, "192.0.2.10", 2).await;
    eventually_for(Duration::from_secs(30), "job refused", || async {
        count(
            &na,
            "SELECT COUNT(*) FROM scan_jobs WHERE status = 'refused'",
        )
        .await
            == 1
    })
    .await;
    assert!(
        !tools.path().join("targets.log").exists(),
        "nmap must not run"
    );
}

/// Two listeners queue the same IP before they hear of each other's job:
/// one scan runs, the other job is superseded.
#[tokio::test]
async fn duplicate_jobs_are_superseded() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.5);
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let ip = "198.51.100.200";
    enqueue(&na, ip, 2).await;
    // B queues the same IP as if it had not seen A's job yet.
    nb.store.upsert_ip(ip.parse().unwrap()).await.unwrap();
    rec(&nb)
        .write(vec![Record::ScanJob(
            peephole::cluster::record::ScanJobRec {
                uid: "dup-job".into(),
                ip: ip.into(),
                level: 2,
                queued_at: peephole::store::data::now_ts(),
            },
        )])
        .await
        .unwrap();
    let _nc = boot(
        ic,
        &c,
        &[&a, &b],
        Opts {
            scanner: Some(nmap),
            ..DEFAULT
        },
    )
    .await;
    eventually_for(
        Duration::from_secs(20),
        "one done, one superseded",
        || async {
            count(&na, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await == 1
                && count(
                    &na,
                    "SELECT COUNT(*) FROM scan_jobs WHERE status = 'superseded'",
                )
                .await
                    == 1
        },
    )
    .await;
    let runs = std::fs::read_to_string(tools.path().join("targets.log")).unwrap();
    assert_eq!(runs.lines().count(), 1, "{runs}");
}

/// A scanner nobody can dial still gets jobs and reports back (answers
/// travel through the arbiter's outbox it long-polls).
#[tokio::test]
async fn outbound_only_scanner_drains_the_queue() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.1);
    let (ia, a) = new_node("a");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[], DEFAULT).await;
    let nc = boot(
        ic,
        &c,
        &[],
        Opts {
            advertise: false,
            scanner: Some(nmap),
            ..DEFAULT
        },
    )
    .await;
    invite::join(
        &nc,
        &invite::create(&na, &Default::default()).await.unwrap(),
    )
    .await
    .unwrap();
    enqueue(&na, "203.0.113.90", 2).await;
    eventually_for(Duration::from_secs(20), "c scanned a's job", || async {
        scans_by(&na, c.id).await == 1
    })
    .await;
}

/// A web node changes a headless scanner's pace; it is applied, persisted
/// there and visible in the scanner's heartbeat.
#[tokio::test]
async fn pace_is_set_remotely() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.1);
    let (ia, a) = new_node("a");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&c], DEFAULT).await;
    let nc = boot(
        ic,
        &c,
        &[&a],
        Opts {
            scanner: Some(nmap),
            ..DEFAULT
        },
    )
    .await;
    let new = peephole::scan::pace::Pace {
        max_workers: 3,
        max_scans_per_hour: 42,
        timeout_secs: 600,
    };
    peephole::scan::pace::set_remote(&na.node, c.id, new)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(nc.pace.get(), new);
    let saved = nc
        .store
        .setting_get("scan.max_scans_per_hour")
        .await
        .unwrap();
    assert_eq!(saved.as_deref(), Some("42"));
    // Invalid values are refused by the scanner, which keeps its pace.
    let bad = peephole::scan::pace::Pace {
        max_workers: 999,
        ..new
    };
    assert!(
        peephole::scan::pace::set_remote(&na.node, c.id, bad)
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(nc.pace.get(), new);
    eventually_for(Duration::from_secs(40), "a sees c's new pace", || async {
        na.status
            .known(&c.id)
            .and_then(|k| k.hb.pace)
            .is_some_and(|p| p.max_scans_per_hour == 42)
    })
    .await;
}

// --------------------------------------------------------------- intel

use peephole::intel::share;

/// A fetches the GeoLite2 databases; B copies them by hash from A, C from
/// whichever peer still holds that exact version.
#[tokio::test]
async fn intel_files_are_shared_by_hash() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    for f in ["GeoLite2-City", "GeoLite2-ASN"] {
        std::fs::copy(
            format!("tests/fixtures/{f}-Test.mmdb"),
            na.dir.path().join(format!("{f}.mmdb")),
        )
        .unwrap();
    }
    share::publish(&na, na.dir.path(), &[share::CITY, share::ASN])
        .await
        .unwrap();
    eventually("b knows the manifests", || async {
        share::manifests(&nb.store).await.unwrap().len() == 2
    })
    .await;
    let mut got = share::sync_files(&nb, nb.dir.path()).await.unwrap();
    got.sort();
    assert_eq!(got, [share::ASN, share::CITY]);
    let g = peephole::intel::geo::GeoIp::load(nb.dir.path()).unwrap();
    assert_eq!(
        g.lookup(&"2.125.160.216".parse().unwrap())
            .country
            .as_deref(),
        Some("GB")
    );
    assert!(
        share::sync_files(&nb, nb.dir.path())
            .await
            .unwrap()
            .is_empty()
    );

    // A's copy changes without a new announcement: A no longer serves it,
    // B still does.
    std::fs::write(na.dir.path().join("GeoLite2-City.mmdb"), b"tampered").unwrap();
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    eventually("c knows the manifests", || async {
        share::manifests(&nc.store).await.unwrap().len() == 2
    })
    .await;
    eventually("c knows b", || async { nc.status.reached_recently(&b.id) }).await;
    let got = share::sync_files(&nc, nc.dir.path()).await.unwrap();
    assert_eq!(got.len(), 2, "{got:?}");
    let (sha, _) = share::file_hash(&nc.dir.path().join("GeoLite2-City.mmdb")).unwrap();
    let (want, _) = share::file_hash(&nb.dir.path().join("GeoLite2-City.mmdb")).unwrap();
    assert_eq!(sha, want);
}

// ---------------------------------------------------------------- admin UI

/// The admin router of `n` (cluster recorder) on an ephemeral port, with an
/// enrolled soft passkey. Returns the logged-in client and base URL.
async fn admin_on(n: &TestNode) -> (reqwest::Client, String) {
    use webauthn_authenticator_rs::AuthenticatorBackend;
    use webauthn_authenticator_rs::prelude::Url;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    let cfg: peephole::config::Config = toml::from_str(
        r#"
database_path = "/x"
data_dir = "/x"
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
secure_cookies = false
"#,
    )
    .unwrap();
    let token = peephole::admin::auth::ensure_setup_token(&n.store, n.dir.path())
        .await
        .unwrap()
        .expect("setup token");
    let state = Arc::new(
        peephole::admin::AdminState::new(
            n.store.clone(),
            cfg,
            peephole::events::Notifier::new(),
            n.pace.clone(),
        )
        .with_recorder(Recorder::Cluster(n.node.clone())),
    );
    let app = peephole::admin::full_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let mut soft = SoftPasskey::new(true);
    let cco: serde_json::Value = client
        .post(format!("{base}/enroll/start"))
        .json(&serde_json::json!({"setup_token": token, "label": "k"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let options: webauthn_rs_proto::PublicKeyCredentialCreationOptions =
        serde_json::from_value(cco["publicKey"].clone()).unwrap();
    let cred = soft
        .perform_register(Url::parse("https://localhost").unwrap(), options, 60_000)
        .unwrap();
    let r = client
        .post(format!("{base}/enroll/finish"))
        .json(&serde_json::json!({"credential": cred}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    (client, base)
}

async fn text(c: &reqwest::Client, url: String) -> String {
    let r = c.get(&url).send().await.unwrap();
    assert!(r.status().is_success(), "{url}: {}", r.status());
    r.text().await.unwrap()
}

#[tokio::test]
async fn admin_cluster_page_and_private_attribution() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.1);
    let (ia, a) = new_node("sensor-alpha");
    let (ib, b) = new_node("sensor-bravo");
    let (ic, c) = new_node("sensor-charlie");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[&a, &c],
        Opts {
            scanner: Some(nmap),
            ..DEFAULT
        },
    )
    .await;
    let _nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    // A records a request and queues a scan; B scans it.
    let mut job_events = na.job_events.subscribe();
    let ip = na
        .store
        .upsert_ip("198.51.100.150".parse().unwrap())
        .await
        .unwrap();
    rec(&na)
        .insert_request(&new_request(ip.id, "/admin.php"))
        .await
        .unwrap();
    rec(&na).enqueue_scan(ip.id, 2, 24).await.unwrap();
    eventually_for(Duration::from_secs(20), "b scanned", || async {
        scans_by(&na, b.id).await == 1 && count(&na, "SELECT COUNT(*) FROM scans").await == 1
    })
    .await;
    // The live queue hears about the job's changes, including B's remote
    // progress applied on A.
    let mut seen = 0;
    while job_events.try_recv().is_ok() {
        seen += 1;
    }
    assert!(seen >= 3, "queued, running, done: {seen}");
    eventually_for(
        Duration::from_secs(40),
        "a has b's heartbeat with pace",
        || async { na.status.known(&b.id).is_some_and(|k| k.hb.pace.is_some()) },
    )
    .await;

    let (admin, base) = admin_on(&na).await;
    let page = text(&admin, format!("{base}/admin/cluster")).await;
    for want in [
        "sensor-alpha",
        "sensor-bravo",
        "sensor-charlie",
        &b.id.short(),
        "Scanner pace",
    ] {
        assert!(page.contains(want), "cluster page lacks {want}");
    }
    // Remote pace from the UI.
    let r = admin
        .post(format!("{base}/admin/cluster/pace"))
        .form(&[
            ("key", b.id.to_string()),
            ("max_workers", "2".into()),
            ("max_scans_per_hour", "77".into()),
            ("timeout_minutes", "15".into()),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(nb.pace.get().max_scans_per_hour, 77);
    // Invites are shown once.
    let r = admin
        .post(format!("{base}/admin/cluster/invite"))
        .form(&[("ttl_hours", "2")])
        .send()
        .await
        .unwrap();
    assert!(r.text().await.unwrap().contains("peephole1:"));
    // Attribution on admin views.
    let queue = text(&admin, format!("{base}/admin/queue")).await;
    assert!(
        queue.contains("sensor-bravo") && queue.contains("via sensor-alpha"),
        "queue"
    );
    let scans = text(&admin, format!("{base}/admin/scans")).await;
    assert!(scans.contains("sensor-bravo"), "scans");
    let reqs = text(&admin, format!("{base}/requests?node=sensor-alpha")).await;
    assert!(
        reqs.contains("/admin.php") && reqs.contains("<th>Node</th>"),
        "requests"
    );
    let none = text(&admin, format!("{base}/requests?node=sensor-charlie")).await;
    assert!(!none.contains("/admin.php"), "node filter");
    // Removing another node is not offered.
    let r = admin
        .post(format!("{base}/admin/cluster/revoke"))
        .form(&[("key", c.id.to_string())])
        .send()
        .await
        .unwrap();
    assert!(!r.status().is_success(), "revoke route is gone");
    assert!(knows(&na, c.id, true).await);
    assert!(page.contains("Leave cluster"), "leave button");

    // Nothing about the cluster leaks to the public.
    let public = reqwest::Client::new();
    let secrets = [
        "sensor-alpha".to_string(),
        "sensor-bravo".into(),
        "sensor-charlie".into(),
        a.id.short(),
        b.id.short(),
        a.id.to_string(),
        b.id.to_string(),
    ];
    for path in [
        "/".to_string(),
        "/ips".into(),
        "/ip/198.51.100.150".into(),
        "/api/stats".into(),
        "/api/map".into(),
        "/api/countries".into(),
    ] {
        let body = text(&public, format!("{base}{path}")).await;
        for s in &secrets {
            assert!(!body.contains(s.as_str()), "{path} leaks {s}");
        }
    }
    // Request search (and its node filter) is admin-only.
    let noredir = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    for path in ["/requests", "/requests?node=sensor-alpha", "/admin/cluster"] {
        let resp = noredir.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 303, "{path} should require a session");
        assert_eq!(resp.headers().get("location").unwrap(), "/login", "{path}");
    }
}
