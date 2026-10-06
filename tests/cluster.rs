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
    settings: peephole::settings::Settings,
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
    /// Let config key holders change this node's settings.
    remote_config: bool,
    /// Days of history kept (0: all).
    retention_days: u32,
}

const DEFAULT: Opts = Opts {
    proto: None,
    advertise: true,
    lease_secs: 120,
    takeover_hours: 6.0,
    never_scan: vec![],
    scanner: None,
    workers: 1,
    remote_config: false,
    retention_days: 0,
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
        remote_config: o.remote_config,
        origin_quota_mb: 20 * 1024,
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
        data_dir: dir.path().to_path_buf(),
        retention_days: o.retention_days,
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
    let settings = peephole::settings::Settings::with_pace(
        node.store.clone(),
        &scan_config(&o.never_scan),
        pace.clone(),
    );
    if o.remote_config {
        cluster::confkey::ensure(&node.store, node.id())
            .await
            .unwrap();
    }
    cluster::confkey::serve(&node, settings.clone());
    let workers = o.scanner.as_ref().map(|nmap| {
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
            peephole::classify::Classifier::builtin(),
        ))
    });
    cluster::start(node.clone(), rx).await.unwrap();
    TestNode {
        node,
        dir,
        _stop: tx,
        pace,
        settings,
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
    // No Tor list and no DNS in tests: neither check may hold scans back.
    toml::from_str(&format!(
        "database_path = \"/x\"\ndata_dir = \"/x\"\n[scan]\nnever_scan = [{list}]\n\
         tor_unknown = \"scan\"\nverify_crawlers = false\n"
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
        remote_config: false,
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

/// A node that left admits nobody: leaving revokes its invites, and it
/// refuses to redeem any invite while detached. Before, a joiner could
/// still redeem an old token and be vouched for by a node that was gone.
#[tokio::test]
async fn a_node_that_left_admits_nobody() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (id, d) = new_node("d");
    let _na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let nd = boot(id, &d, &[], DEFAULT).await;
    let old = invite::create(&nb, &Default::default()).await.unwrap();
    cluster::leave(&nb).await.unwrap();
    assert!(
        invite::list(&nb.store)
            .await
            .unwrap()
            .iter()
            .all(|i| i.revoked)
    );
    // An invite made after leaving does not admit anyone either.
    let new = invite::create(&nb, &Default::default()).await.unwrap();
    for token in [old, new] {
        let e = invite::join(&nd, &token).await.unwrap_err();
        assert!(
            format!("{e:#}").contains("not in a cluster any more"),
            "{e:#}"
        );
    }
    assert!(!members::can_admit(&nb, &d.id).await.unwrap());
    assert!(!knows(&nb, d.id, true).await);
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
        remote_config: false,
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
        remote_config: false,
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
                remote_config: false,
                origin_quota_mb: 20 * 1024,
                peers: vec![PeerConfig {
                    name: "a".into(),
                    address: a.address(),
                    public_key: a.id.to_string(),
                }],
            },
            roles: Roles::default(),
            store,
            proto: (2, 2),
            data_dir: dir.path().to_path_buf(),
            retention_days: 0,
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

/// A record's uid is bound to the node that created it. Nobody can create
/// a record under another node's uid, so nobody can delete or shadow it.
#[tokio::test]
async fn a_uid_not_bound_to_its_origin_is_rejected() {
    let (a_id, b_id) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (a, b) = (
        Addr {
            name: "a",
            id: a_id.id,
            port: 1,
        },
        Addr {
            name: "b",
            id: b_id.id,
            port: 2,
        },
    );
    let (x, _dx) = offline_node(&[&a, &b]).await;
    let request = |uid: String| {
        Record::Request(Box::new(peephole::cluster::record::RequestRec {
            uid,
            ts: "2026-01-01 00:00:00".into(),
            ip: "203.0.113.80".into(),
            method: "GET".into(),
            path: "/x".into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: "[]".into(),
            severity: 1,
            scan_level: 0,
            is_fp_claim: false,
            page_token: None,
            ..Default::default()
        }))
    };
    let a_uid = format!("{}one", a_id.id.uid_prefix());
    let st = repl::apply_batch(
        &x,
        vec![WireEntry::sign(&a_id, 1, hlc_days_ago(0, 1), &request(a_uid.clone())).unwrap()],
    )
    .await
    .unwrap();
    assert_eq!(st.applied, 1, "{st:?}");
    // B signs a record under A's uid, then one under an unbound uid.
    for uid in [a_uid, "plain".to_string()] {
        let st = repl::apply_batch(
            &x,
            vec![WireEntry::sign(&b_id, 1, hlc_days_ago(0, 2), &request(uid)).unwrap()],
        )
        .await
        .unwrap();
        assert_eq!((st.applied, st.rejected), (0, 1), "{st:?}");
    }
    assert_eq!(head_of(&x, b_id.id).await, 0);
    assert_eq!(count(&x, "SELECT COUNT(*) FROM requests").await, 1);
}

/// A sponsor cannot keep a node from leaving by dating its admission into
/// the future.
#[tokio::test]
async fn a_future_dated_admission_cannot_keep_a_node_from_leaving() {
    let (a_id, w_id) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let a = Addr {
        name: "a",
        id: a_id.id,
        port: 1,
    };
    let (x, _dx) = offline_node(&[&a]).await;
    let info = peephole::cluster::record::MemberInfo {
        id: w_id.id,
        name: "w".into(),
        address: None,
        roles: vec![],
        proto_min: 2,
        proto_max: 2,
        remote_config: false,
    };
    // A admits W, then dates a re-admission far ahead: that one is not
    // taken before its time (A's stream waits there).
    let far = hlc_days_ago(0, 4) + ((400u64 * 24 * 3600 * 1000) << 16);
    let st = repl::apply_batch(
        &x,
        vec![
            WireEntry::sign(
                &a_id,
                1,
                hlc_days_ago(0, 1),
                &Record::MemberAdd(info.clone()),
            )
            .unwrap(),
            WireEntry::sign(&a_id, 2, far, &Record::MemberAdd(info.clone())).unwrap(),
        ],
    )
    .await
    .unwrap();
    assert_eq!((st.applied, st.rejected), (1, 1), "{st:?}");
    repl::apply_batch(
        &x,
        vec![
            WireEntry::sign(&w_id, 1, hlc_days_ago(0, 2), &Record::MemberUpdate(info)).unwrap(),
            WireEntry::sign(
                &w_id,
                2,
                hlc_days_ago(0, 3),
                &Record::MemberRevoke { id: w_id.id },
            )
            .unwrap(),
        ],
    )
    .await
    .unwrap();
    let rows = members::all(&x.store).await.unwrap();
    let w = rows.iter().find(|m| m.id == w_id.id).unwrap();
    assert_eq!(w.standing, members::Standing::Left);
}

/// A node that kept running but was cut off for 30 days keeps probing the
/// members it believes pruned, and learns from them that it is the one
/// that was pruned.
#[tokio::test]
async fn a_node_cut_off_for_30_days_learns_it_was_pruned() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    eventually("everyone knows everyone", || async {
        knows(&na, c.id, true).await
            && knows(&nb, c.id, true).await
            && knows(&nc, a.id, true).await
            && knows(&nc, b.id, true).await
    })
    .await;
    // Let every log reach every node first, so no late admission arrives
    // after the clocks are turned back below.
    eventually("logs converged", || async {
        let mut same = true;
        for origin in [a.id, b.id, c.id] {
            let h = head_of(&na, origin).await;
            same &= h > 0 && h == head_of(&nb, origin).await && h == head_of(&nc, origin).await;
        }
        same
    })
    .await;
    // 40 days without contact, as each side sees the other.
    let forget = |n: &TestNode, who: NodeId| {
        let pool = n.store.pool.clone();
        async move {
            let old = hlc_days_ago(40, 0) as i64;
            sqlx::query("UPDATE repl_log SET hlc = ? WHERE origin = ?")
                .bind(old)
                .bind(&who.0[..])
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("UPDATE members SET admitted_hlc = ? WHERE id = ?")
                .bind(old)
                .bind(&who.0[..])
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    forget(&na, c.id).await;
    forget(&nb, c.id).await;
    forget(&nc, a.id).await;
    forget(&nc, b.id).await;
    eventually_for(
        Duration::from_secs(90),
        "c learns it was pruned",
        || async { nc.detached() == Some(cluster::Detached::Pruned) },
    )
    .await;
    assert_eq!(na.detached(), None);
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
            remote_config: false,
            origin_quota_mb: 20 * 1024,
            peers: vec![PeerConfig {
                name: "a".into(),
                address: "127.0.0.1:1".into(),
                public_key: a_id.id.to_string(),
            }],
        },
        roles: Roles::default(),
        store,
        proto: (1, 1),
        data_dir: dir.path().to_path_buf(),
        retention_days: 0,
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
        remote_config: false,
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
        ..Default::default()
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
    r.record_geo(ip.id, None, Some("DE"), Some(64500), Some("Example AS"))
        .await
        .unwrap();
    r.record_tor(ip.id, true).await.unwrap();
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

/// A canary served on A and used on B: both nodes find the same reuse.
#[tokio::test]
async fn canary_reuse_is_found_on_every_node() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip_a = na
        .store
        .upsert_ip("198.51.100.10".parse().unwrap())
        .await
        .unwrap();
    rec(&na)
        .insert_request(&NewRequest {
            ip_id: ip_a.id,
            method: "GET".into(),
            path: "/.git/config".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            page_token: Some("served-on-a".into()),
            answer: Some("decoy:git-config".into()),
            decoy_v: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    let token = peephole::canary::value("served-on-a", peephole::canary::Kind::GitToken);
    let auth = data_encoding::BASE64.encode(format!("deploy:{token}").as_bytes());
    let ip_b = nb
        .store
        .upsert_ip("198.51.100.11".parse().unwrap())
        .await
        .unwrap();
    rec(&nb)
        .insert_request(&NewRequest {
            ip_id: ip_b.id,
            method: "GET".into(),
            path: "/x".into(),
            headers_json: format!(r#"[["authorization","Basic {auth}"]]"#),
            labels_json: "[]".into(),
            page_token: Some("used-on-b".into()),
            answer: Some("not-found".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let sql =
        "SELECT COUNT(*) FROM request_tokens t JOIN canaries c ON c.value_hash = t.value_hash";
    for n in [&na, &nb] {
        eventually("reuse found", || async { count(n, sql).await == 1 }).await;
    }
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
            remote_config: false,
            origin_quota_mb: 20 * 1024,
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
        data_dir: dir.path().to_path_buf(),
        retention_days: 0,
    })
    .await
    .unwrap();
    node.bootstrap().await.unwrap();
    (node, dir)
}

async fn batch_of(n: &Node, origin: NodeId) -> peephole::cluster::sync::Batch {
    repl::entries_after(&n.store, &[(origin, 0)], 0, 10_000, usize::MAX)
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
        bounds: vec![],
        floors: vec![],
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

    // A relay relabels the live /two entry as the erased /one: the proof
    // names /one's own position in A's log, so it does not cover this one.
    let (w, _dw) = offline_node(&[&a, &b]).await;
    let mut relabel = Batch {
        bounds: vec![],
        floors: vec![],
        entries: after.entries.clone(),
        proofs: after.proofs.clone(),
    };
    let e = relabel
        .entries
        .iter_mut()
        .find(|e| e.uid.as_deref() == Some(two.as_str()))
        .unwrap();
    e.payload = None;
    e.sig = None;
    e.uid = Some(one.clone());
    e.erased_by = Some(tomb.clone());
    let st = repl::apply_batch(&w, relabel).await.unwrap();
    assert!(st.rejected >= 1, "relabelled entry: {st:?}");
    assert!(head_of(&w, a.id).await < a_head);

    // No proof, a proof from another origin, a stub without a uid: rejected.
    let stub_only = Batch {
        bounds: vec![],
        floors: vec![],
        entries: after.entries.clone(),
        proofs: vec![],
    };
    let other = Identity::generate().unwrap();
    let wrong_origin = Batch {
        bounds: vec![],
        floors: vec![],
        entries: after.entries.clone(),
        proofs: vec![
            WireEntry::sign(
                &other,
                1,
                1,
                &Record::Tombstone(peephole::cluster::record::TombstoneRec {
                    uid: tomb.clone(),
                    uids: vec![one.clone()],
                    seqs: vec![1],
                }),
            )
            .unwrap(),
        ],
    };
    let mut no_uid = Batch {
        bounds: vec![],
        floors: vec![],
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
    let mut first = None;
    for path in ["/one", "/two"] {
        let id = rec(&na)
            .insert_request(&new_request(ip.id, path))
            .await
            .unwrap();
        first.get_or_insert(id);
    }
    // /one comes with a browser fingerprint.
    rec(&na)
        .insert_fingerprint(first, ip.id, "fp1", Some("v1"), "{}", "{}", b"events")
        .await
        .unwrap();
    eventually("b has both, and the fingerprint", || async {
        count(&nb, "SELECT COUNT(*) FROM requests").await == 2
            && count(&nb, "SELECT COUNT(*) FROM fingerprints").await == 1
    })
    .await;
    let one_on_b: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/one'")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    let out = rec(&nb).delete_request(one_on_b).await.unwrap();
    assert_eq!((out.deleted, out.hidden), (0, 1));
    assert_eq!(
        count(&nb, "SELECT COUNT(*) FROM fingerprints").await,
        0,
        "the hidden request's fingerprint is hidden with it"
    );
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
    rec(&na)
        .insert_skip_batch(
            "203.0.113.72",
            1,
            vec![peephole::cluster::record::SkipRow {
                ts_ms: 1,
                method: "GET".into(),
                path: "/a0".into(),
                ..Default::default()
            }],
        )
        .await
        .unwrap();
    eventually("everyone has both", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 2
            && count(&nb, "SELECT COUNT(*) FROM requests").await == 2
            && count(&nc, "SELECT COUNT(*) FROM requests").await == 2
            && count(&nb, "SELECT COUNT(*) FROM skipped_requests").await == 1
    })
    .await;

    assert!(block::block(&nb, nb.id()).await.is_err(), "not oneself");
    assert_eq!(
        block::block(&nb, a.id).await.unwrap(),
        2,
        "its request and light rows"
    );
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM skipped_batches").await, 0);
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
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM skipped_requests").await, 1);
    assert!(!nb.is_blocked(&a.id));
}

/// A cluster node's admin cannot delete records: the data belongs to the
/// cluster, and retention prunes it.
#[tokio::test]
async fn admin_cannot_delete_on_a_cluster_node() {
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
    let page = admin
        .get(format!("{base}/admin/requests/{id}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!page.contains("/delete"), "no delete button");
    let r = admin
        .post(format!("{base}/admin/requests/{id}/delete"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM requests").await, 1);
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM hidden").await, 0);
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
        // Two API lookups while standalone: both are history.
        for score in [10, 20] {
            s.local()
                .record_lookup(
                    "192.0.2.200",
                    peephole::intel::ABUSEIPDB,
                    None,
                    serde_json::json!({ "score": score }),
                )
                .await
                .unwrap();
        }
        for i in 0..150 {
            s.insert_request(&new_request(ip.id, &format!("/p{i}")))
                .await
                .unwrap();
        }
        let light = |path: &str| peephole::cluster::record::SkipRow {
            ts_ms: 1,
            method: "GET".into(),
            path: path.into(),
            ..Default::default()
        };
        s.local()
            .insert_skip_batch("192.0.2.200", 3, vec![light("/s1"), light("/s2")])
            .await
            .unwrap();
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
            && count(&nb, "SELECT COUNT(*) FROM skipped_requests").await == 2
            && count(&nb, "SELECT COUNT(*) FROM ports").await == 3
            && count(
                &nb,
                "SELECT COUNT(*) FROM ip_intel_log WHERE provider = 'abuseipdb'",
            )
            .await
                == 2
    })
    .await;
    assert_eq!(
        count(&na, "SELECT COUNT(*) FROM ip_intel_log WHERE origin = x''").await
            + count(&na, "SELECT COUNT(*) FROM ip_intel WHERE origin = x''").await,
        0,
        "every standalone result is now a's"
    );
    let score: Option<i64> = sqlx::query_scalar("SELECT abuse_score FROM ips")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    assert_eq!(score, Some(20), "the newest lookup wins");
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
    // Scanners only run jobs the IP's requests back (three, so the level
    // is not capped as thin evidence).
    for i in 0..3 {
        rec(n)
            .insert_request(&new_request(row.id, &format!("/probe{i}")))
            .await
            .unwrap();
    }
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
                max_workers: peephole::scan::pace::MIN_WORKERS,
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
                uid: format!("{}dup-job", b.id.uid_prefix()),
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

/// A config key holder changes another node's settings; nobody else can.
#[tokio::test]
async fn config_key_holders_change_a_nodes_settings() {
    use peephole::cluster::confkey;
    use peephole::settings::Changes;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[&a, &c],
        Opts {
            remote_config: true,
            ..DEFAULT
        },
    )
    .await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    eventually("a sees that b is open", || async {
        members::all(&na.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == b.id && m.remote_config)
    })
    .await;

    // Anyone may look.
    let state = confkey::get(&na.node, b.id).await.unwrap();
    assert!(state.open);
    assert_eq!(state.version, 0);
    let faster = Changes {
        max_scans_per_hour: Some(77),
        ..Default::default()
    };

    // Without the key: refused, before any message is sent.
    let e = confkey::set(&na.node, b.id, 0, &faster)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("no config key"), "{e}");

    // B's operator hands A the key.
    let key = confkey::own(&nb.store, b.id).await.unwrap().unwrap();
    assert_eq!(
        confkey::add(&na.store, a.id, &key.encode()).await.unwrap(),
        b.id
    );
    assert_eq!(
        confkey::set(&na.node, b.id, 0, &faster).await.unwrap(),
        Ok(1)
    );
    assert_eq!(nb.pace.get().max_scans_per_hour, 77);
    let audit = nb.settings.audit(10).await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].by, Some(a.id));

    // A stale version (a second editor, or a replay) changes nothing.
    let e = confkey::set(&na.node, b.id, 0, &faster)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("changed meanwhile"), "{e}");

    // Invalid values are refused by the same rules as locally.
    let e = confkey::set(
        &na.node,
        b.id,
        1,
        &Changes {
            listener: Some(false),
            scanner: Some(false),
            web: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(e.contains("at least one role"), "{e}");

    // C holds a wrong key for B.
    let wrong = confkey::ConfigKey {
        id: b.id,
        key: [0u8; 32],
    };
    confkey::add(&nc.store, c.id, &wrong.encode())
        .await
        .unwrap();
    let e = confkey::set(&nc.node, b.id, 1, &faster)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("not accepted"), "{e}");

    // Rotation cuts A off.
    confkey::rotate(&nb.store, b.id).await.unwrap();
    let e = confkey::set(&na.node, b.id, 1, &faster)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("not accepted"), "{e}");
    assert_eq!(nb.settings.snapshot().version, 1);

    // A locked node refuses even a correct key.
    confkey::ensure(&na.store, a.id).await.unwrap();
    let a_key = confkey::own(&na.store, a.id).await.unwrap().unwrap();
    confkey::add(&nb.store, b.id, &a_key.encode())
        .await
        .unwrap();
    assert!(!confkey::get(&nb.node, a.id).await.unwrap().open);
    let e = confkey::set(&nb.node, a.id, 0, &faster)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("switched off"), "{e}");
}

use peephole::intel::share;

/// The Tor exit list is shared as a file; GeoLite2 databases are not.
#[tokio::test]
async fn only_the_tor_list_is_shared_as_a_file() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    std::fs::write(na.dir.path().join("tor-exit.txt"), tor_list(200)).unwrap();
    std::fs::copy(
        "tests/fixtures/GeoLite2-City-Test.mmdb",
        na.dir.path().join("GeoLite2-City.mmdb"),
    )
    .unwrap();
    share::publish(&na, na.dir.path(), &[share::TOR])
        .await
        .unwrap();
    assert!(
        share::publish(&na, na.dir.path(), &["geolite2-city"])
            .await
            .is_err(),
        "a database is never announced"
    );
    eventually("b knows the manifest", || async {
        share::manifests(&nb.store).await.unwrap().len() == 1
    })
    .await;
    assert_eq!(
        share::sync_files(&nb, nb.dir.path()).await.unwrap(),
        [share::TOR]
    );
    assert!(nb.dir.path().join("tor-exit.txt").exists());
    assert!(!nb.dir.path().join("GeoLite2-City.mmdb").exists());
    // The copy carries the fetcher's time, which the stale-intel warning reads.
    let m = share::manifests(&nb.store).await.unwrap();
    peephole::intel::note_cluster_intel(&nb, nb.dir.path(), true, &m)
        .await
        .unwrap();
    assert_eq!(
        nb.store.intel_get("tor_last_fetch").await.unwrap(),
        m[share::TOR].fetched_rfc3339()
    );
    // A manifest for a database, written by a peer on its own, is ignored.
    repl::append(
        &na,
        &[Record::IntelManifest(
            peephole::cluster::record::IntelManifestRec {
                kind: "geolite2-city".into(),
                sha256: "00".into(),
                size: 1,
                fetched_at: peephole::store::data::now_ts(),
            },
        )],
    )
    .await
    .unwrap();
    eventually("b holds a's newest entry", || async {
        head_of(&nb, a.id).await == head_of(&na, a.id).await
    })
    .await;
    assert_eq!(share::manifests(&nb.store).await.unwrap().len(), 1);
}

/// An exit list with `n` addresses.
fn tor_list(n: u32) -> String {
    (0..n)
        .map(|i| format!("198.18.{}.{}\n", i / 250, i % 250 + 1))
        .collect()
}

/// A peer's exit list passes the same sanity check as a downloaded one,
/// and an announcement older than three days is not copied.
#[tokio::test]
async fn a_tiny_or_stale_tor_list_is_not_copied_from_a_peer() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let good = tor_list(200);
    std::fs::write(nb.dir.path().join("tor-exit.txt"), &good).unwrap();
    // Tiny list, freshly announced: hash matches, content does not pass.
    std::fs::write(na.dir.path().join("tor-exit.txt"), "192.0.2.1\n192.0.2.2\n").unwrap();
    share::publish(&na, na.dir.path(), &[share::TOR])
        .await
        .unwrap();
    eventually("b knows the manifest", || async {
        share::manifests(&nb.store).await.unwrap().len() == 1
    })
    .await;
    assert!(
        share::sync_files(&nb, nb.dir.path())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        std::fs::read_to_string(nb.dir.path().join("tor-exit.txt")).unwrap(),
        good,
        "b keeps its own list"
    );
    // A big list announced as fetched four days ago.
    std::fs::write(na.dir.path().join("tor-exit.txt"), tor_list(300)).unwrap();
    let (sha256, size) = share::file_hash(&na.dir.path().join("tor-exit.txt")).unwrap();
    let old = (chrono::Utc::now() - chrono::Duration::days(4))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    repl::append(
        &na,
        &[Record::IntelManifest(
            peephole::cluster::record::IntelManifestRec {
                kind: share::TOR.into(),
                sha256: sha256.clone(),
                size,
                fetched_at: old,
            },
        )],
    )
    .await
    .unwrap();
    eventually("b knows the old manifest", || async {
        share::manifests(&nb.store).await.unwrap()[share::TOR].sha256 == sha256
    })
    .await;
    assert!(
        share::sync_files(&nb, nb.dir.path())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        std::fs::read_to_string(nb.dir.path().join("tor-exit.txt")).unwrap(),
        good
    );
}

/// A node without the databases gets GeoIP facts from one that has them;
/// the database itself does not travel.
#[tokio::test]
async fn geo_results_come_from_a_node_that_has_the_database() {
    use peephole::intel::provider::MaxMind;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    for f in ["GeoLite2-City", "GeoLite2-ASN"] {
        std::fs::copy(
            format!("tests/fixtures/{f}-Test.mmdb"),
            na.dir.path().join(format!("{f}.mmdb")),
        )
        .unwrap();
    }
    let geo: peephole::intel::SharedGeo = Default::default();
    *geo.write().unwrap() = Some(peephole::intel::geo::GeoIp::load(na.dir.path()).unwrap());
    let providers: peephole::intel::Providers = vec![Arc::new(MaxMind(geo))];
    // B, which cannot look anything up, records a request.
    record(&nb, "2.125.160.216", "/x").await;
    let nothing: peephole::intel::Providers = vec![Arc::new(MaxMind(Default::default()))];
    assert_eq!(
        peephole::intel::enrich_once(&rec(&nb), &nothing)
            .await
            .unwrap(),
        0
    );
    eventually("a has b's request", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 1
    })
    .await;
    assert_eq!(
        peephole::intel::enrich_once(&rec(&na), &providers)
            .await
            .unwrap(),
        1
    );
    assert_eq!(na.providers(), [peephole::intel::MAXMIND]);
    eventually("b shows the country", || async {
        sqlx::query_scalar::<_, Option<String>>("SELECT country FROM ips")
            .fetch_one(&nb.store.pool)
            .await
            .unwrap()
            .as_deref()
            == Some("GB")
    })
    .await;
    assert!(!nb.dir.path().join("GeoLite2-City.mmdb").exists());
    // Asked once: a second pass has nothing to do.
    assert_eq!(
        peephole::intel::enrich_once(&rec(&na), &providers)
            .await
            .unwrap(),
        0
    );
}

/// A peer this node blocked does not take a turn in the lookup order.
#[tokio::test]
async fn a_blocked_peer_does_not_hold_up_enrichment() {
    use peephole::cluster::block;
    use peephole::intel::provider::MaxMind;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    for f in ["GeoLite2-City", "GeoLite2-ASN"] {
        std::fs::copy(
            format!("tests/fixtures/{f}-Test.mmdb"),
            na.dir.path().join(format!("{f}.mmdb")),
        )
        .unwrap();
    }
    let geo: peephole::intel::SharedGeo = Default::default();
    *geo.write().unwrap() = Some(peephole::intel::geo::GeoIp::load(na.dir.path()).unwrap());
    let providers: peephole::intel::Providers = vec![Arc::new(MaxMind(geo))];
    // Both can look up; the lower key goes first.
    let (first, second) = if a.id < b.id { (&na, &nb) } else { (&nb, &na) };
    assert_eq!(
        peephole::intel::enrich_once(&rec(first), &providers)
            .await
            .unwrap(),
        0
    );
    eventually("second knows first can look up", || async {
        second
            .status
            .known(&first.id())
            .is_some_and(|k| k.hb.providers == [peephole::intel::MAXMIND])
    })
    .await;
    record(second, "2.125.160.216", "/x").await;
    assert_eq!(
        peephole::intel::enrich_once(&rec(second), &providers)
            .await
            .unwrap(),
        0,
        "first's turn"
    );
    block::block(second, first.id()).await.unwrap();
    assert_eq!(
        peephole::intel::enrich_once(&rec(second), &providers)
            .await
            .unwrap(),
        1
    );
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
        .with_recorder(Recorder::Cluster(n.node.clone()))
        .with_settings(n.settings.clone()),
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

/// The Members page and every node page it links to, as one string.
async fn cluster_pages(admin: &reqwest::Client, base: &str) -> String {
    let mut all = text(admin, format!("{base}/admin/cluster")).await;
    let keys: Vec<String> = all
        .split("href=\"/admin/cluster/node/")
        .skip(1)
        .filter_map(|s| s.split('"').next().map(str::to_string))
        .collect();
    for k in keys {
        all.push_str(&text(admin, format!("{base}/admin/cluster/node/{k}")).await);
    }
    all
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
    let page = cluster_pages(&admin, &base).await;
    for want in [
        "sensor-alpha",
        "sensor-bravo",
        "sensor-charlie",
        &b.id.short(),
        // B and C recorded nothing to classify again, and run no trap.
        "no requests to compare",
        "none recorded",
    ] {
        assert!(page.contains(want), "cluster page lacks {want}");
    }
    let members = text(&admin, format!("{base}/admin/cluster")).await;
    let head = members
        .split("<thead>")
        .nth(1)
        .unwrap()
        .split("</thead>")
        .next()
        .unwrap();
    assert_eq!(head.matches("<th>").count(), 5, "five columns: {head}");
    let sys = text(&admin, format!("{base}/admin/system")).await;
    assert!(
        sys.contains("built in")
            && sys.contains(&peephole::classify::Classifier::builtin().fingerprint()[..12])
    );
    // Unknown and malformed keys are 404.
    for bad in ["zz".to_string(), "00".repeat(32)] {
        let r = admin
            .get(format!("{base}/admin/cluster/node/{bad}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "{bad}");
    }
    let scans = text(&admin, format!("{base}/admin/scans")).await;
    assert!(
        scans.contains("id=\"scanners\"") && scans.contains(&b.id.short()),
        "scanner pace on the Scans page"
    );
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
    assert_ne!(
        nb.pace.get().max_scans_per_hour,
        77,
        "no config key: the pace of another node cannot be changed"
    );
    // Invites are shown once.
    let r = admin
        .post(format!("{base}/admin/cluster/invite"))
        .form(&[("ttl_hours", "2")])
        .send()
        .await
        .unwrap();
    assert!(r.text().await.unwrap().contains("peephole1:"));
    // Attribution on admin views.
    let scans = text(&admin, format!("{base}/admin/scans")).await;
    assert!(
        scans.contains("sensor-bravo") && scans.contains("via sensor-alpha"),
        "scan history names scanner and arbiter"
    );
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
    let access = text(&admin, format!("{base}/admin/cluster/access")).await;
    assert!(
        access.contains("Leave cluster") && access.contains("Create invite"),
        "access page"
    );
    assert!(!page.contains("Create invite"), "invites left Members");
    let r = admin
        .post(format!("{base}/admin/cluster/block"))
        .form(&[("key", c.id.to_string())])
        .send()
        .await
        .unwrap();
    assert!(
        r.url().path().starts_with("/admin/cluster/node/"),
        "back to the node page: {}",
        r.url()
    );

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

/// The admin of A configures B through the UI once B's key is added.
#[tokio::test]
async fn admin_configures_another_node_with_its_key() {
    use peephole::cluster::confkey;
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[&a],
        Opts {
            remote_config: true,
            ..DEFAULT
        },
    )
    .await;
    eventually("a sees that b is open", || async {
        members::all(&na.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == b.id && m.remote_config)
    })
    .await;
    let (admin, base) = admin_on(&na).await;
    let mut page = cluster_pages(&admin, &base).await;
    page.push_str(&text(&admin, format!("{base}/admin/cluster/access")).await);
    assert!(page.contains("open to key holders"), "b is shown as open");
    assert!(page.contains("locked"), "a itself is locked");
    assert!(
        !page.contains("peephole-cfg1:"),
        "a locked node shows no key"
    );

    // Add B's key, then change B from A's node page.
    let key = confkey::own(&nb.store, b.id).await.unwrap().unwrap();
    let r = admin
        .post(format!("{base}/admin/cluster/config-key/add"))
        .form(&[("key", key.encode())])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let node_page = text(&admin, format!("{base}/admin/cluster/node/{}", b.id)).await;
    assert!(node_page.contains("node-bravo"));
    assert!(
        node_page.contains("name=\"base_version\" value=\"0\""),
        "{node_page}"
    );
    let r = admin
        .post(format!("{base}/admin/cluster/node/{}", b.id))
        .form(&[
            ("base_version", "0"),
            ("max_workers", "3"),
            ("max_scans_per_hour", "55"),
            ("timeout_minutes", "20"),
            ("cooldown_hours", "12"),
            ("listener", "on"),
            ("web", "on"),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let s = nb.settings.snapshot();
    assert_eq!((s.pace.max_workers, s.pace.max_scans_per_hour), (3, 55));
    assert_eq!(s.pace.timeout_secs, 1200);
    assert_eq!(s.cooldown_hours, 12);
    assert!(
        s.roles.listener && s.roles.web && !s.roles.scanner,
        "unchecked role is off"
    );

    // The pace row cannot change B behind the version check.
    let r = admin
        .post(format!("{base}/admin/cluster/pace"))
        .form(&[
            ("key", b.id.to_string()),
            ("max_workers", "1".into()),
            ("max_scans_per_hour", "11".into()),
            ("timeout_minutes", "5".into()),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(nb.settings.snapshot().pace.max_scans_per_hour, 55);

    // This node's own settings from its own page, which carries the version
    // it showed.
    let page = text(&admin, format!("{base}/admin/system/settings")).await;
    let shown = na.settings.snapshot().version;
    assert!(
        page.contains(&format!("name=\"base_version\" value=\"{shown}\"")),
        "own form carries the version"
    );
    let own = |base_version: u64, cooldown: &'static str| {
        admin
            .post(format!("{base}/admin/cluster/settings"))
            .form(&[
                ("base_version", base_version.to_string()),
                ("cooldown_hours", cooldown.into()),
                ("listener", "on".into()),
                ("scanner", "on".into()),
                ("web", "on".into()),
            ])
            .send()
    };
    assert!(own(shown, "6").await.unwrap().status().is_success());
    assert_eq!(na.settings.snapshot().cooldown_hours, 6);
    // A change made elsewhere after the page was loaded is not overwritten.
    na.settings
        .apply(
            &peephole::settings::Changes {
                scanner: Some(false),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(own(shown + 1, "7").await.unwrap().status().is_success());
    let s = na.settings.snapshot();
    assert!(
        !s.roles.scanner,
        "a stale form does not switch the scanner back on"
    );
    assert_eq!(s.cooldown_hours, 6);

    // B stops answering: only the settings card says so.
    drop(nb);
    let r = admin
        .get(format!("{base}/admin/cluster/node/{}", b.id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let html = r.text().await.unwrap();
    assert!(
        html.contains("did not answer") && html.contains("Contributions"),
        "{html}"
    );
    let r = admin
        .post(format!("{base}/admin/cluster/config-key/forget"))
        .form(&[("key", b.id.to_string())])
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.url().path(),
        format!("/admin/cluster/node/{}", b.id),
        "forgetting a key stays on the node page"
    );
}

/// Enrichment results replicate with their origin; a blocked peer's results
/// stop counting and come back on unblock.
#[tokio::test]
async fn enrichment_results_replicate_and_follow_blocks() {
    use peephole::cluster::block;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    record(&nb, "203.0.113.90", "/x").await;
    rec(&na)
        .record_intel(
            "203.0.113.90",
            peephole::intel::MAXMIND,
            Some("2026-09-30"),
            serde_json::json!({"country": "NL", "asn": 1}),
        )
        .await
        .unwrap();
    let country = |n: &TestNode| {
        let pool = n.store.pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT country FROM ips WHERE ip = '203.0.113.90'",
            )
            .fetch_optional(&pool)
            .await
            .unwrap()
            .flatten()
        }
    };
    eventually("b shows a's result", || async {
        country(&nb).await.as_deref() == Some("NL")
    })
    .await;
    let origin: Vec<u8> = sqlx::query_scalar("SELECT origin FROM ip_intel")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    assert_eq!(origin, a.id.0.to_vec(), "provenance is kept");
    // The same result again writes nothing.
    let head = head_of(&na, a.id).await;
    rec(&na)
        .record_intel(
            "203.0.113.90",
            peephole::intel::MAXMIND,
            Some("2026-09-30"),
            serde_json::json!({"country": "NL", "asn": 1}),
        )
        .await
        .unwrap();
    assert_eq!(head_of(&na, a.id).await, head);

    block::block(&nb, a.id).await.unwrap();
    assert_eq!(
        country(&nb).await,
        None,
        "a blocked peer's results do not count"
    );
    block::unblock(&nb, a.id).await.unwrap();
    assert_eq!(country(&nb).await.as_deref(), Some("NL"));
}

/// API lookups are each kept: the history replicates, follows blocks, and
/// exports with UTC times; the admin-only score never reaches public pages.
#[tokio::test]
async fn api_lookup_history_replicates_and_follows_blocks() {
    use peephole::cluster::block;
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    record(&nb, "203.0.113.92", "/x").await;
    for _ in 0..2 {
        rec(&na)
            .record_lookup(
                "203.0.113.92",
                peephole::intel::ABUSEIPDB,
                None,
                serde_json::json!({"score": 77, "categories": ["SSH"]}),
            )
            .await
            .unwrap();
    }
    let history = "SELECT COUNT(*) FROM ip_intel_log WHERE ip = '203.0.113.92'";
    eventually("b has both lookups", || async {
        count(&nb, history).await == 2
    })
    .await;
    let score = |n: &TestNode| {
        let pool = n.store.pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<i64>>(
                "SELECT abuse_score FROM ips WHERE ip = '203.0.113.92'",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert_eq!(score(&nb).await, Some(77));
    let (admin, base) = admin_on(&nb).await;
    let body = text(&admin, format!("{base}/admin/export/download?format=jsonl")).await;
    let row: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
    let lookups: Vec<&serde_json::Value> = row["intel"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["provider"] == "abuseipdb")
        .collect();
    assert_eq!(lookups.len(), 2, "{body}");
    assert_eq!(lookups[0]["node"], "node-alpha");
    assert!(
        lookups[0]["fetched_at"]
            .as_str()
            .unwrap()
            .ends_with("+00:00"),
        "{body}"
    );
    let html = text(&admin, format!("{base}/ips?tag=abuseipdb:SSH&min_abuse=50")).await;
    assert!(html.contains("203.0.113.92"));
    let anon = reqwest::Client::new();
    let public = anon
        .get(format!("{base}/ip/203.0.113.92"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !public.contains("AbuseIPDB"),
        "admin-only provider on a public page"
    );

    block::block(&nb, a.id).await.unwrap();
    assert_eq!(count(&nb, history).await, 0, "a blocked peer's lookups go");
    assert_eq!(score(&nb).await, None);
    block::unblock(&nb, a.id).await.unwrap();
    assert_eq!(count(&nb, history).await, 2);
    assert_eq!(score(&nb).await, Some(77));
}

/// A node that consulted only GeoIP writes no Tor result of its own and
/// leaves another node's Tor result alone.
#[tokio::test]
async fn a_geo_only_write_leaves_tor_alone() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    record(&nb, "203.0.113.91", "/x").await;
    rec(&na)
        .record_intel(
            "203.0.113.91",
            peephole::intel::TOR,
            None,
            serde_json::json!({"exit": true}),
        )
        .await
        .unwrap();
    let tor = |n: &TestNode| {
        let pool = n.store.pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>("SELECT is_tor_exit FROM ips WHERE ip = '203.0.113.91'")
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    eventually("b shows a's tor result", || async { tor(&nb).await }).await;
    let ip_id: i64 = sqlx::query_scalar("SELECT id FROM ips WHERE ip = '203.0.113.91'")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    rec(&nb)
        .record_geo(ip_id, Some("2026-09-30"), Some("NL"), Some(1), None)
        .await
        .unwrap();
    let mine: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ip_intel WHERE provider = 'tor-exits' AND origin = ?",
    )
    .bind(&b.id.0[..])
    .fetch_one(&nb.store.pool)
    .await
    .unwrap();
    assert_eq!(mine, 0, "no Tor row of its own");
    assert!(tor(&nb).await, "a's Tor result still shows");
}

/// Enrichment results go out with each request, with their provenance.
#[tokio::test]
async fn enrichment_results_are_exported_with_provenance() {
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    record(&nb, "203.0.113.91", "/x").await;
    rec(&nb)
        .record_intel(
            "203.0.113.91",
            peephole::intel::MAXMIND,
            Some("2026-09-30"),
            serde_json::json!({"country": "NL"}),
        )
        .await
        .unwrap();
    eventually("a has the result", || async {
        count(&na, "SELECT COUNT(*) FROM ip_intel").await == 1
    })
    .await;
    // A result whose IP has no row any more is not exported.
    sqlx::query(
        "INSERT INTO ip_intel (ip, provider, origin, hlc, fetched_at, source_version, data_json)
         VALUES ('198.51.100.7', 'maxmind-geolite2', x'', 0, '2026-01-01T00:00:00Z', NULL, '{}')",
    )
    .execute(&na.store.pool)
    .await
    .unwrap();
    let (admin, base) = admin_on(&na).await;
    let body = text(&admin, format!("{base}/admin/export/download?format=jsonl")).await;
    assert_eq!(body.lines().count(), 1, "{body}");
    let row: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
    assert_eq!(row["ip"], "203.0.113.91");
    assert_eq!(row["node"], "node-bravo");
    // Full provenance: the creating node's key and the build it ran.
    assert_eq!(row["node_id"], b.id.to_string());
    assert_eq!(row["build"], peephole::COMMIT);
    let geo = row["intel"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["provider"] == "maxmind-geolite2")
        .unwrap();
    assert_eq!(geo["source_version"], "2026-09-30");
    assert_eq!(geo["node"], "node-bravo");
    assert_eq!(geo["node_id"], b.id.to_string());
    assert_eq!(geo["build"], peephole::COMMIT);
    assert_eq!(geo["data"]["country"], "NL");
    assert!(
        !body.contains("198.51.100.7"),
        "results without a request stay out"
    );
    // Not public.
    let anon = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let r = anon
        .get(format!("{base}/admin/export/download?format=jsonl"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
}

/// A node outside the test cluster, signing entries by hand (admitted by a
/// member, never dialled: it has no address).
struct Writer {
    id: Identity,
    seq: u64,
}

impl Writer {
    fn new() -> Self {
        Self {
            id: Identity::generate().unwrap(),
            seq: 0,
        }
    }

    fn at(&mut self, days_ago: u64, r: Record) -> WireEntry {
        self.seq += 1;
        WireEntry::sign(&self.id, self.seq, hlc_days_ago(days_ago, self.seq), &r).unwrap()
    }

    fn info(&self, name: &str) -> peephole::cluster::record::MemberInfo {
        peephole::cluster::record::MemberInfo {
            id: self.id.id,
            name: name.into(),
            address: None,
            roles: vec![],
            proto_min: cluster::rpc::proto::PROTO_MIN,
            proto_max: cluster::rpc::proto::PROTO_VERSION,
            remote_config: false,
        }
    }

    fn request(&self, path: &str) -> Record {
        Record::Request(Box::new(peephole::cluster::record::RequestRec {
            uid: format!(
                "{}{}",
                self.id.id.uid_prefix(),
                path.trim_start_matches('/')
            ),
            ts: "2026-09-01 00:00:00".into(),
            ip: "203.0.113.66".into(),
            method: "GET".into(),
            path: path.into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            severity: 1,
            ..Default::default()
        }))
    }

    /// A description, two records far outside a week and one inside.
    fn history(&mut self) -> Vec<WireEntry> {
        vec![
            self.at(40, Record::MemberUpdate(self.info("writer"))),
            self.at(40, self.request("/old1")),
            self.at(30, self.request("/old2")),
            self.at(0, self.request("/new1")),
        ]
    }
}

/// `o`'s sequences held by `n`.
async fn seqs_of(n: &Node, o: NodeId) -> Vec<i64> {
    sqlx::query_scalar("SELECT seq FROM repl_log WHERE origin = ? ORDER BY seq")
        .bind(&o.0[..])
        .fetch_all(&n.store.pool)
        .await
        .unwrap()
}

/// Sync rounds all of `nodes` run over a few quiet seconds. A loop that
/// re-syncs without pause runs hundreds, even on a slow machine.
async fn quiet_rounds(nodes: &[&Node]) -> u64 {
    let total = || {
        nodes
            .iter()
            .map(|n| n.sync_rounds.load(std::sync::atomic::Ordering::Relaxed))
            .sum::<u64>()
    };
    let before = total();
    tokio::time::sleep(Duration::from_secs(3)).await;
    total() - before
}

/// One node keeps a week: old history leaves it and only it, new records
/// keep reaching it, a node joining later with the full history gets it
/// from the full members, one joining with a window gets only its window,
/// and nobody re-syncs without pause.
#[tokio::test]
async fn a_history_floor_is_local() {
    let (ia, a) = new_node("full-a");
    let (ib, b) = new_node("full-b");
    let (ip, p) = new_node("window-p");
    let week = Opts {
        retention_days: 7,
        ..DEFAULT
    };
    let na = boot(ia, &a, &[&b, &p], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &p], DEFAULT).await;
    let np = boot(ip, &p, &[&a, &b], week.clone()).await;
    let mut o = Writer::new();
    repl::append(&na, &[Record::MemberAdd(o.info("writer"))])
        .await
        .unwrap();
    let st = repl::apply_batch(&na, o.history()).await.unwrap();
    assert_eq!(st.applied, 4, "{st:?}");
    eventually("b has o's history", || async {
        seqs_of(&nb, o.id.id).await.len() == 4
    })
    .await;
    // p asks only for its window (and the membership before it).
    eventually("p has o's window", || async {
        seqs_of(&np, o.id.id).await == [1, 4]
    })
    .await;
    assert_eq!(cluster::history::prune(&np).await.unwrap(), 0);
    assert_eq!(paths(&np).await, ["/new1"]);
    assert_eq!(paths(&nb).await, ["/new1", "/old1", "/old2"]);
    // New records keep coming.
    let late = o.at(0, o.request("/new2"));
    repl::apply_batch(&na, vec![late]).await.unwrap();
    eventually("p gets new records", || async {
        paths(&np).await == ["/new1", "/new2"]
    })
    .await;
    // The others learn where p's history starts.
    np.reload_floors().await.unwrap();
    np.publish_status();
    eventually("a knows p's floor", || async {
        na.peer_floor(&p.id, &o.id.id) == 4
    })
    .await;

    // A node keeping everything joins through p: the history comes from
    // the full members.
    let (i_f, f) = new_node("full-f");
    let nf = boot(i_f, &f, &[], DEFAULT).await;
    invite::join(
        &nf,
        &invite::create(&np, &Default::default()).await.unwrap(),
    )
    .await
    .unwrap();
    eventually("f backfills everything", || async {
        seqs_of(&nf, o.id.id).await == [1, 2, 3, 4, 5]
    })
    .await;
    // A node keeping a week joins: only its window, and the membership.
    let (iw, w) = new_node("window-w");
    let nw = boot(iw, &w, &[], week).await;
    invite::join(
        &nw,
        &invite::create(&na, &Default::default()).await.unwrap(),
    )
    .await
    .unwrap();
    eventually("w gets its window", || async {
        paths(&nw).await == ["/new1", "/new2"]
    })
    .await;
    assert_eq!(seqs_of(&nw, o.id.id).await, [1, 4, 5]);
    assert!(
        members::all(&nw.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == o.id.id && m.name == "writer")
    );

    let rounds = quiet_rounds(&[&na, &nb, &np, &nf, &nw]).await;
    assert!(rounds <= 30, "{rounds} sync rounds in 3 s");

    // The admin page says who keeps what.
    let (admin, base) = admin_on(&na).await;
    let page = cluster_pages(&admin, &base).await;
    for want in ["keeps 7 days", "full history"] {
        assert!(page.contains(want), "cluster page lacks {want}");
    }
}

/// A node keeping everything whose only reachable peer keeps a window, and
/// a node that purged an origin its peer still has: neither re-syncs
/// without pause, and the first says it waits for a full member.
#[tokio::test]
async fn unservable_history_does_not_make_peers_spin() {
    let (ia, a) = new_node("full-a");
    let (ip, p) = new_node("window-p");
    let na = boot(ia, &a, &[&p], DEFAULT).await;
    let np = boot(
        ip,
        &p,
        &[&a],
        Opts {
            retention_days: 7,
            ..DEFAULT
        },
    )
    .await;
    let mut o = Writer::new();
    repl::append(&na, &[Record::MemberAdd(o.info("writer"))])
        .await
        .unwrap();
    repl::apply_batch(&na, o.history()).await.unwrap();
    eventually("p has o's window", || async {
        seqs_of(&np, o.id.id).await == [1, 4]
    })
    .await;
    np.reload_floors().await.unwrap();
    np.publish_status();

    // a purges o while p still has it, and gets ahead: p's next entry of o.
    peephole::cluster::block::block(&na, o.id.id).await.unwrap();
    peephole::cluster::block::purge(&na, o.id.id).await.unwrap();
    repl::apply_batch(&np, vec![o.at(0, o.request("/new2"))])
        .await
        .unwrap();
    let rounds = quiet_rounds(&[&na, &np]).await;
    assert!(
        rounds <= 15,
        "{rounds} sync rounds in 3 s with a purged origin"
    );

    // A full node joins while only p is up.
    drop(na);
    let (i_f, f) = new_node("full-f");
    let nf = boot(i_f, &f, &[], DEFAULT).await;
    invite::join(
        &nf,
        &invite::create(&np, &Default::default()).await.unwrap(),
    )
    .await
    .unwrap();
    eventually("f knows p's floor", || async {
        nf.peer_floor(&p.id, &o.id.id) == 4
    })
    .await;
    let rounds = quiet_rounds(&[&nf, &np]).await;
    assert!(rounds <= 15, "{rounds} sync rounds in 3 s next to a window");
    assert!(seqs_of(&nf, o.id.id).await.is_empty() || seqs_of(&nf, o.id.id).await == [1]);
    let (admin, base) = admin_on(&nf).await;
    let page = text(&admin, format!("{base}/admin/cluster")).await;
    assert!(
        page.contains("waiting for a full member"),
        "cluster page lacks the warning"
    );
}

/// The cluster page counts what each member contributed, by data type.
#[tokio::test]
async fn admin_page_shows_contributions_per_node() {
    let (ia, a) = new_node("counter-a");
    let na = boot(ia, &a, &[], DEFAULT).await;
    let mut o = Writer::new();
    repl::append(&na, &[Record::MemberAdd(o.info("writer"))])
        .await
        .unwrap();
    let batch = vec![
        o.at(0, o.request("/one")),
        o.at(0, o.request("/two")),
        o.at(0, o.request("/three")),
    ];
    repl::apply_batch(&na, batch).await.unwrap();
    let (admin, base) = admin_on(&na).await;
    let page = text(&admin, format!("{base}/admin/cluster/node/{}", o.id.id)).await;
    let section = page
        .split("<h2>Contributions</h2>")
        .nth(1)
        .expect("contributions section")
        .split("</table>")
        .next()
        .unwrap();
    assert!(
        section.contains(r#"<td class="num">3</td>"#),
        "writer's three requests: {section}"
    );
    let own = text(&admin, format!("{base}/admin/cluster/node/{}", a.id)).await;
    assert!(
        own.contains("<h2>Contributions</h2>") && own.contains("this node"),
        "{own}"
    );
    // The members table shows each node's share at a glance.
    let members = text(&admin, format!("{base}/admin/cluster")).await;
    let row = members
        .split(&format!("/admin/cluster/node/{}\"", o.id.id))
        .nth(1)
        .expect("writer row")
        .split("</tr>")
        .next()
        .unwrap();
    assert!(
        row.contains(r#"<td class="num">3 · 100 %</td>"#),
        "writer's share: {row}"
    );
}
